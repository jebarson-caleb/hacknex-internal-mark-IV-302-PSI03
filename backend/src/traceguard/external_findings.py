"""Bounded local import adapters for selected external findings; never canonical events."""
import csv
import hashlib
import io
import json
import re
from datetime import datetime, timezone
from uuid import uuid4

from .ingest import digest, json_bytes

MAX_EXTERNAL_BYTES = 5 * 1024 * 1024
MAX_EXTERNAL_ROWS = 10000
MAX_EXTERNAL_ROW_BYTES = 64 * 1024
WAZUH_PROFILE = "wazuh-alerts-jsonl-v1"
HAYABUSA_PROFILE = "hayabusa-minimal-csv-v1"
WAZUH_DOC = "https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/journald.html"
HAYABUSA_DOC = "https://github.com/Yamato-Security/hayabusa/blob/main/website/docs/output/index.md"
PROFILES = {
    WAZUH_PROFILE: {"tool": "Wazuh", "profile": "alerts.json JSONL selected alerts", "source": WAZUH_DOC},
    HAYABUSA_PROFILE: {"tool": "Hayabusa", "profile": "minimal CSV timeline", "source": HAYABUSA_DOC},
}


def ensure_tables(store):
    with store.connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS external_artifacts (
                id TEXT PRIMARY KEY, tool TEXT NOT NULL, profile TEXT NOT NULL,
                filename TEXT NOT NULL, upload_sha256 TEXT NOT NULL, raw_bytes BLOB NOT NULL,
                body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS external_findings (
                id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL REFERENCES external_artifacts(id),
                source_position INTEGER NOT NULL, stable_source_key TEXT, raw_row TEXT NOT NULL,
                raw_row_sha256 TEXT NOT NULL, validation_status TEXT NOT NULL, body TEXT NOT NULL,
                UNIQUE(artifact_id,source_position));
            CREATE INDEX IF NOT EXISTS external_findings_artifact_position
                ON external_findings(artifact_id,source_position);
            CREATE INDEX IF NOT EXISTS external_findings_time
                ON external_findings(artifact_id,validation_status);
            CREATE TRIGGER IF NOT EXISTS external_artifacts_no_update
                BEFORE UPDATE ON external_artifacts BEGIN SELECT RAISE(ABORT,'external artifacts are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS external_artifacts_no_delete
                BEFORE DELETE ON external_artifacts BEGIN SELECT RAISE(ABORT,'external artifacts are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS external_findings_no_update
                BEFORE UPDATE ON external_findings BEGIN SELECT RAISE(ABORT,'external findings are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS external_findings_no_delete
                BEFORE DELETE ON external_findings BEGIN SELECT RAISE(ABORT,'external findings are immutable'); END;
        """)
        conn.execute("INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(5,?)",
                     (datetime.now(timezone.utc).isoformat(),))


def _text(value, label, maximum=2000, allow_empty=False):
    if not isinstance(value, str) or len(value) > maximum or (not allow_empty and not value.strip()):
        raise ValueError(f"{label} must be {'at most' if allow_empty else 'nonblank and at most'} {maximum} characters")
    if "\x00" in value:
        raise ValueError(f"{label} contains an unsupported NUL character")
    return value


def _timestamp(value):
    if value is None or value == "":
        return None, "accepted_timestamp_unknown"
    if not isinstance(value, str) or len(value) > 100:
        raise ValueError("timestamp must be a timezone-bearing ISO/RFC date string")
    try:
        normalized = re.sub(r"^(\d{4}-\d\d-\d\d)[ T](\d\d:\d\d:\d\d(?:\.\d+)?)[ ]([+-]\d\d:\d\d)$",
                            r"\1T\2\3", value)
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp is malformed; expected an ISO/RFC value with explicit timezone") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None, "accepted_timestamp_unknown_timezone"
    return parsed.astimezone(timezone.utc).isoformat(), "accepted"


def _json_object_pairs(pairs):
    item = {}
    for key, value in pairs:
        if key in item:
            raise ValueError(f"duplicate JSON key: {key}")
        item[key] = value
    return item


def _wazuh_row(value):
    if not isinstance(value, dict):
        raise ValueError("Wazuh JSONL row must be an object")
    rule, agent = value.get("rule"), value.get("agent")
    if not isinstance(rule, dict) or not isinstance(agent, dict):
        raise ValueError("Wazuh alerts profile requires nested rule and agent objects")
    alert_id = _text(value.get("id"), "Wazuh alert id", 200)
    rule_id = _text(rule.get("id"), "Wazuh rule id", 100)
    description = _text(rule.get("description"), "Wazuh rule description", 1000)
    level = rule.get("level")
    if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= 16:
        raise ValueError("Wazuh rule.level must be an integer from 0 through 16")
    host = agent.get("name")
    if host is not None:
        host = _text(host, "Wazuh agent.name", 255)
    rule_tags = rule.get("mitre", {})
    if rule_tags is None:
        rule_tags = {}
    if not isinstance(rule_tags, dict):
        raise ValueError("Wazuh rule.mitre must be an object when present")
    tags = rule_tags.get("id", [])
    if not isinstance(tags, list) or len(tags) > 100 or any(not isinstance(item, str) for item in tags):
        raise ValueError("Wazuh rule.mitre.id must be a list of strings")
    data = value.get("data", {})
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise ValueError("Wazuh data must be an object when present")
    observables = {}
    for target, aliases in (("src_ip", ("srcip", "src_ip")), ("dst_ip", ("dstip", "dst_ip")),
                            ("domain", ("domain", "hostname")), ("sha256", ("sha256", "file_hash"))):
        values = [data[key] for key in aliases if key in data and data[key] not in (None, "")]
        if values:
            if any(not isinstance(item, str) for item in values):
                raise ValueError(f"Wazuh {target} extraction fields must be strings")
            observables[target] = values[0]
    timestamp, timestamp_status = _timestamp(value.get("timestamp"))
    return {"original_timestamp": value.get("timestamp"), "parsed_timestamp_utc": timestamp,
        "timestamp_status": timestamp_status, "upstream_alert_id": alert_id, "upstream_rule_id": rule_id,
        "upstream_rule_title": description, "original_severity": level, "host": host,
        "observables": observables, "upstream_technique_labels": sorted(set(tags)),
        "stable_source_key": alert_id, "mapping_provenance": "Wazuh documented alerts.json nested fields; allowlisted scalar extraction only"}


HAYABUSA_HEADERS = ("Timestamp", "Computer", "Channel", "EventID", "Level", "RecordID", "RuleTitle", "Details")


def _hayabusa_row(row):
    timestamp, timestamp_status = _timestamp(row.get("Timestamp"))
    required = ("Computer", "Channel", "EventID", "Level", "RecordID", "RuleTitle")
    for name in required:
        _text(row.get(name), f"Hayabusa {name}", 1000)
    severity = row["Level"]
    if severity.casefold() not in {"informational", "low", "medium", "high", "critical", "unknown"}:
        raise ValueError("Hayabusa minimal CSV Level is outside the documented severity labels")
    source_key = "|".join((row["Computer"], row["Channel"], row["EventID"], row["RecordID"], row.get("Timestamp", "")))
    return {"original_timestamp": row.get("Timestamp"), "parsed_timestamp_utc": timestamp,
        "timestamp_status": timestamp_status, "upstream_alert_id": row["RecordID"],
        "upstream_rule_id": None, "upstream_rule_title": row["RuleTitle"],
        "original_severity": severity, "host": row["Computer"], "channel": row["Channel"],
        "upstream_event_id": row["EventID"], "details": row.get("Details", ""),
        "observables": {}, "upstream_technique_labels": [], "stable_source_key": source_key,
        "mapping_provenance": "Hayabusa documented minimal CSV fields; Details is retained as text and not mined for observables"}


def parse_external(content, profile):
    if profile not in PROFILES:
        raise ValueError("Unsupported external profile; choose wazuh-alerts-jsonl-v1 or hayabusa-minimal-csv-v1")
    if not isinstance(content, bytes) or not content or len(content) > MAX_EXTERNAL_BYTES:
        raise ValueError("External upload must be nonempty and no larger than 5 MiB")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("External upload must be UTF-8 text") from exc
    rows = []
    if profile == WAZUH_PROFILE:
        physical_rows = text.splitlines(keepends=True)
        if len(physical_rows) > MAX_EXTERNAL_ROWS:
            raise ValueError("External upload exceeds 10,000 source lines")
        for line_number, original in enumerate(physical_rows, start=1):
            source_row = original.rstrip("\r\n")
            if not source_row.strip():
                continue
            raw_hash = digest(source_row.encode("utf-8"))
            parsed = None
            error = None
            try:
                if len(source_row.encode("utf-8")) > MAX_EXTERNAL_ROW_BYTES:
                    raise ValueError("source row exceeds 64 KiB")
                value = json.loads(source_row, object_pairs_hook=_json_object_pairs)
                parsed = _wazuh_row(value)
            except (json.JSONDecodeError, ValueError) as exc:
                error = str(exc) if isinstance(exc, ValueError) else f"invalid Wazuh JSONL: {exc.msg}"
            rows.append({"source_position": line_number, "raw_row": source_row, "raw_row_sha256": raw_hash,
                         "parsed": parsed, "error": error})
    else:
        stream = io.StringIO(text, newline="")
        physical_rows = text.splitlines(keepends=True)
        try:
            reader = csv.DictReader(stream, strict=True)
            headers = reader.fieldnames or []
            if tuple(headers) != HAYABUSA_HEADERS:
                raise ValueError("Unsupported Hayabusa CSV profile: expected the exact documented minimal columns Timestamp,Computer,Channel,EventID,Level,RecordID,RuleTitle,Details")
            previous_line = reader.line_num
            for row in reader:
                end_line = reader.line_num
                raw_source = "".join(physical_rows[previous_line:end_line]).rstrip("\r\n")
                line_number = previous_line + 1
                previous_line = end_line
                raw_hash = digest(raw_source.encode("utf-8"))
                parsed = None
                error = None
                try:
                    if len(raw_source.encode("utf-8")) > MAX_EXTERNAL_ROW_BYTES:
                        raise ValueError("source row exceeds 64 KiB")
                    if None in row or any(not isinstance(value, str) for value in row.values()):
                        raise ValueError("Hayabusa CSV row has missing or extra columns")
                    parsed = _hayabusa_row(row)
                except ValueError as exc:
                    error = str(exc)
                rows.append({"source_position": line_number, "raw_row": raw_source, "raw_fields": row,
                             "raw_row_sha256": raw_hash, "parsed": parsed, "error": error})
                if len(rows) > MAX_EXTERNAL_ROWS:
                    raise ValueError("External upload exceeds 10,000 source rows")
        except csv.Error as exc:
            raise ValueError(f"Malformed Hayabusa CSV: {exc}") from exc
    if len(rows) > MAX_EXTERNAL_ROWS:
        raise ValueError("External upload exceeds 10,000 source rows")
    return rows


def preview_external(content, filename, profile):
    rows = parse_external(content, profile)
    seen = set()
    accepted = rejected = duplicates = context_only = 0
    sample = []
    for row in rows:
        parsed = row["parsed"]
        status = "rejected" if parsed is None else parsed["timestamp_status"]
        duplicate = False
        if parsed is None:
            rejected += 1
        else:
            key = (parsed["stable_source_key"], row["raw_row_sha256"])
            duplicate = key in seen
            seen.add(key)
            if duplicate:
                duplicates += 1
                status = "duplicate"
            else:
                accepted += 1
            context_only += 1
        if len(sample) < 25:
            sample.append({"source_position": row["source_position"], "validation_status": status,
                "validation_error": row["error"], "finding": parsed,
                "raw_row": row["raw_row"][:2000], "duplicate": duplicate})
    return {"profile": profile, "filename": _safe_filename(filename), "size_bytes": len(content),
        "upload_sha256": digest(content), "accepted": accepted, "rejected": rejected,
        "duplicates": duplicates, "context_only": context_only, "total_rows": len(rows), "sample": sample,
        "interpretation": "This preview maps to external context only; no canonical observations, incidents, stages, or risk inputs are created."}


def _safe_filename(filename):
    basename = (filename or "external-upload").replace("\\", "/").split("/")[-1]
    safe = "".join(character if character.isalnum() or character in "._ -" else "_" for character in basename)[:120]
    return safe or "external-upload"


def import_external(store, content, filename, profile):
    rows = parse_external(content, profile)
    descriptor = PROFILES[profile]
    artifact_id = uuid4().hex
    upload_hash = digest(content)
    seen = {}
    findings = []
    counts = {"accepted": 0, "rejected": 0, "duplicates": 0, "context_only": 0}
    for row in rows:
        parsed = row["parsed"]
        status = "rejected" if parsed is None else parsed["timestamp_status"]
        duplicate_of = None
        if parsed is not None:
            key = (parsed["stable_source_key"], row["raw_row_sha256"])
            duplicate_of = seen.get(key)
            if duplicate_of:
                status = "duplicate"
                counts["duplicates"] += 1
            else:
                seen[key] = None
                counts["accepted"] += 1
            counts["context_only"] += 1
        else:
            counts["rejected"] += 1
        finding_id = uuid4().hex
        if parsed is not None:
            key = (parsed["stable_source_key"], row["raw_row_sha256"])
            if seen.get(key) is None:
                seen[key] = finding_id
            parsed = {**parsed, "finding_id": finding_id, "artifact_id": artifact_id,
                "tool": descriptor["tool"], "profile": profile, "upload_sha256": upload_hash,
                "source_position": row["source_position"], "raw_row": row["raw_row"],
                "raw_fields": row.get("raw_fields"), "raw_row_sha256": row["raw_row_sha256"],
                "validation_status": status, "duplicate_of": duplicate_of,
                "interpretation": "External finding only; not a canonical observation, native incident, stage, or risk input.",
                "mapping_provenance": parsed["mapping_provenance"],
                "upstream_source_url": descriptor["source"]}
            body = parsed
        else:
            body = {"finding_id": finding_id, "artifact_id": artifact_id, "tool": descriptor["tool"],
                "profile": profile, "upload_sha256": upload_hash, "source_position": row["source_position"],
                "raw_row": row["raw_row"], "raw_fields": row.get("raw_fields"),
                "raw_row_sha256": row["raw_row_sha256"], "validation_status": "rejected",
                "validation_error": row["error"], "duplicate_of": None,
                "interpretation": "Rejected external row; it is not a canonical observation, incident, stage, or risk input.",
                "upstream_source_url": descriptor["source"]}
        findings.append((finding_id, row, status, body))
    quality = {**counts, "total_rows": len(rows), "upload_sha256": upload_hash,
        "interpretation": "All accepted records remain external context. Wazuh alert exports are selected alerts, not a complete event population."}
    artifact = {"artifact_id": artifact_id, "tool": descriptor["tool"], "profile": profile,
        "profile_label": descriptor["profile"], "source_url": descriptor["source"],
        "producer_version": "not recorded in the selected export", "filename": _safe_filename(filename),
        "upload_sha256": upload_hash, "size_bytes": len(content), "ingested_at_utc": datetime.now(timezone.utc).isoformat(),
        "quality": quality, "context_only": True}
    ensure_tables(store)
    with store.connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("INSERT INTO external_artifacts VALUES(?,?,?,?,?,?,?)", (artifact_id, descriptor["tool"],
            profile, artifact["filename"], upload_hash, content, json.dumps(artifact, ensure_ascii=False, separators=(",", ":"))))
        for finding_id, row, status, body in findings:
            conn.execute("INSERT INTO external_findings VALUES(?,?,?,?,?,?,?,?)", (finding_id, artifact_id,
                row["source_position"], (body.get("stable_source_key") if body.get("validation_status") != "rejected" else None),
                row["raw_row"], row["raw_row_sha256"], status, json.dumps(body, ensure_ascii=False, separators=(",", ":"))))
    return {"artifact": artifact, "quality": quality, "preview": [body for _, _, _, body in findings[:25]]}


def list_artifacts(store, cursor=0, limit=20):
    if cursor < 0 or not 1 <= limit <= 100:
        raise ValueError("External artifact page exceeds limits")
    ensure_tables(store)
    with store.connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM external_artifacts").fetchone()[0]
        rows = conn.execute("SELECT body FROM external_artifacts ORDER BY rowid DESC LIMIT ? OFFSET ?", (limit, cursor)).fetchall()
    return {"items": [json.loads(row[0]) for row in rows], "total": total,
        "next_cursor": cursor + limit if cursor + limit < total else None}


def artifact_detail(store, artifact_id):
    ensure_tables(store)
    with store.connection() as conn:
        row = conn.execute("SELECT * FROM external_artifacts WHERE id=?", (artifact_id,)).fetchone()
    if row is None:
        raise KeyError("external artifact not found")
    body = json.loads(row["body"])
    if digest(row["raw_bytes"]) != row["upload_sha256"] or body.get("artifact_id") != artifact_id:
        raise ValueError("External original bytes or artifact metadata failed integrity verification")
    return body


def get_finding(store, finding_id):
    ensure_tables(store)
    with store.connection() as conn:
        row = conn.execute("SELECT * FROM external_findings WHERE id=?", (finding_id,)).fetchone()
    if row is None:
        raise KeyError("external finding not found")
    artifact = artifact_detail(store, row["artifact_id"])
    body = json.loads(row["body"])
    if (body.get("finding_id") != finding_id or body.get("artifact_id") != row["artifact_id"]
            or body.get("source_position") != row["source_position"] or body.get("raw_row") != row["raw_row"]
            or body.get("raw_row_sha256") != row["raw_row_sha256"]
            or digest(body["raw_row"].encode("utf-8")) != row["raw_row_sha256"]
            or body.get("upload_sha256") != artifact["upload_sha256"]):
        raise ValueError("External finding differs from its immutable uploaded source row")
    return body


def list_findings(store, artifact_id=None, query="", cursor=0, limit=50):
    if len(query) > 200 or cursor < 0 or not 1 <= limit <= 200:
        raise ValueError("External finding search/page exceeds limits")
    if artifact_id:
        artifact_detail(store, artifact_id)
    ensure_tables(store)
    clauses, args = [], []
    if artifact_id:
        clauses.append("artifact_id=?"); args.append(artifact_id)
    if query:
        clauses.append("instr(lower(raw_row || ' ' || body),lower(?))>0"); args.append(query)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with store.connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM external_findings" + where, args).fetchone()[0]
        rows = conn.execute("SELECT id FROM external_findings" + where + " ORDER BY source_position ASC,id LIMIT ? OFFSET ?", (*args, limit, cursor)).fetchall()
    items = [get_finding(store, row["id"]) for row in rows]
    return {"items": items, "total": total, "next_cursor": cursor + limit if cursor + limit < total else None}


def _csv_safe(value):
    text = "" if value is None else str(value)
    stripped = text.lstrip(" \t\r\n")
    if stripped.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def csv_export(store, artifact_id):
    artifact = artifact_detail(store, artifact_id)
    findings = []
    cursor = 0
    while True:
        page = list_findings(store, artifact_id, cursor=cursor, limit=200)
        findings.extend(page["items"])
        if page["next_cursor"] is None:
            break
        cursor = page["next_cursor"]
    output = io.StringIO(newline="")
    fields = ("finding_id", "source_position", "validation_status", "parsed_timestamp_utc", "host",
              "upstream_alert_id", "upstream_rule_id", "upstream_rule_title", "original_severity",
              "interpretation", "raw_row")
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for finding in findings:
        writer.writerow({key: _csv_safe(finding.get(key)) for key in fields})
    return artifact, output.getvalue()
