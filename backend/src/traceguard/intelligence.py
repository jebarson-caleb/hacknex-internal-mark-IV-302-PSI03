"""Local, source-attributed typed indicators; exact matches remain sidecar context."""
import csv
import io
import json
import re
from datetime import datetime, timezone
from ipaddress import ip_address
from uuid import uuid4

import idna

from .ingest import digest, json_bytes
from .replay import guard_run

MAX_INDICATORS = 1000
MAX_MATCH_PAIRS = 10000
MAX_PAGE = 200
MAX_IMPORT_BYTES = 1024 * 1024
COLLECTION_VERSION = "traceguard-local-indicators-v1"
EXTRACTOR_VERSION = "traceguard-exact-indicator-extractor-v1"
STRUCTURED_FIELDS = {"ip": ("src_ip", "dst_ip"), "domain": ("domain",), "sha256": ("file_hash",)}


def normalize_ioc(kind, value):
    if not isinstance(value, str) or not value or len(value) > 1000 or value != value.strip():
        raise ValueError("Indicator value must be a nonblank string without surrounding whitespace")
    if kind == "ip":
        try: return str(ip_address(value))
        except ValueError as exc: raise ValueError("IP indicators must be exact IPv4 or IPv6 values") from exc
    if kind == "domain":
        if "*" in value or "/" in value or "@" in value or value.endswith(".."):
            raise ValueError("Domain indicators must be host names without wildcards or URL/path syntax")
        try: ip_address(value)
        except ValueError: pass
        else: raise ValueError("Use indicator type ip for IPv4 or IPv6 values")
        without_dot = value[:-1] if value.endswith(".") else value
        if not without_dot: raise ValueError("Domain indicator cannot be empty")
        try:
            normalized = idna.encode(without_dot, uts46=True, std3_rules=True, transitional=False).decode("ascii").lower()
        except idna.IDNAError as exc:
            raise ValueError("Domain indicator is invalid under IDNA UTS #46 strict rules") from exc
        if len(normalized) > 253: raise ValueError("Normalized domain exceeds 253 ASCII characters")
        return normalized
    if kind == "sha256":
        if not re.fullmatch(r"[0-9a-fA-F]{64}", value):
            raise ValueError("SHA-256 indicators must contain exactly 64 hexadecimal characters")
        return value.lower()
    raise ValueError("Indicator type must be ip, domain, or sha256")


def _text(value, label, maximum, empty=False):
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value.strip()):
        raise ValueError(f"{label} must be {'at most' if empty else 'nonblank and at most'} {maximum} characters")
    if "<script" in value.lower() or "javascript:" in value.lower(): raise ValueError(f"{label} cannot contain script-bearing text")
    return value


def _optional_time(value, label):
    if value is None or value == "": return None
    if not isinstance(value, str) or len(value) > 64: raise ValueError(f"{label} must be an ISO 8601 timestamp with an explicit UTC offset")
    try: parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc: raise ValueError(f"{label} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None: raise ValueError(f"{label} must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat()


def _entry(item, prior=None):
    if not isinstance(item, dict) or set(item) - {"type", "value", "source", "source_reference", "description", "notes", "enabled",
                                                    "indicator_id", "source_confidence", "effective_from_utc", "effective_until_utc"}:
        raise ValueError("Each indicator requires typed value, source, source reference and description; only documented optional fields are supported")
    kind = item.get("type")
    original = _text(item.get("value"), "indicator value", 1000)
    normalized = normalize_ioc(kind, original)
    source = _text(item.get("source"), "indicator source", 120)
    source_reference = _text(item.get("source_reference"), "indicator source reference", 500)
    description = _text(item.get("description"), "indicator description", 1000)
    notes = _text(item.get("notes", ""), "indicator notes", 1000, empty=True)
    enabled = item.get("enabled", True)
    if not isinstance(enabled, bool): raise ValueError("Indicator enabled state must be boolean")
    confidence = item.get("source_confidence")
    if confidence is not None and (isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1):
        raise ValueError("Source confidence must be a numeric assertion between 0 and 1")
    effective_from = _optional_time(item.get("effective_from_utc"), "effective_from_utc")
    effective_until = _optional_time(item.get("effective_until_utc"), "effective_until_utc")
    if effective_from and effective_until and datetime.fromisoformat(effective_from) >= datetime.fromisoformat(effective_until):
        raise ValueError("Indicator effective time interval must increase")
    indicator_id = item.get("indicator_id") or (prior or {}).get("indicator_id") or uuid4().hex
    if not isinstance(indicator_id, str) or not re.fullmatch(r"[a-f0-9]{32}", indicator_id): raise ValueError("Indicator ID is invalid")
    return {"indicator_id": indicator_id, "type": kind, "value": original, "normalized_value": normalized,
        "source": source, "source_reference": source_reference, "description": description, "notes": notes,
        "source_confidence": float(confidence) if confidence is not None else None,
        "effective_from_utc": effective_from, "effective_until_utc": effective_until,
        "enabled": enabled, "recorded_at_utc": (prior or {}).get("recorded_at_utc") or datetime.now(timezone.utc).isoformat()}


def _entries(items, previous=None):
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_INDICATORS:
        raise ValueError("Indicator collection must contain 1 to 1,000 entries")
    old = {(entry["type"], entry["normalized_value"], entry["source"], entry["source_reference"]): entry for entry in (previous or [])}
    normalized, seen = [], set()
    for item in items:
        if not isinstance(item, dict): raise ValueError("Each indicator must be an object")
        kind, value = item.get("type"), item.get("value")
        key = (kind, normalize_ioc(kind, value))
        assertion_key = (*key, item.get("source"), item.get("source_reference"))
        if assertion_key in seen: raise ValueError("Indicator collection contains a duplicate source assertion")
        seen.add(assertion_key)
        normalized.append(_entry(item, old.get(assertion_key)))
    return normalized


def ensure_tables(store):
    with store.connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS indicator_collections (
                id TEXT PRIMARY KEY, revision INTEGER NOT NULL, updated TEXT NOT NULL, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS indicator_revisions (
                collection_id TEXT NOT NULL, revision INTEGER NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY(collection_id,revision));
            CREATE TABLE IF NOT EXISTS indicator_matches (
                id TEXT PRIMARY KEY, collection_id TEXT NOT NULL, revision INTEGER NOT NULL,
                analysis_run_id TEXT NOT NULL, result_sha256 TEXT NOT NULL, body TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS indicator_revisions_no_update
                BEFORE UPDATE ON indicator_revisions BEGIN SELECT RAISE(ABORT,'indicator revisions are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS indicator_revisions_no_delete
                BEFORE DELETE ON indicator_revisions BEGIN SELECT RAISE(ABORT,'indicator revisions are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS indicator_matches_no_update
                BEFORE UPDATE ON indicator_matches BEGIN SELECT RAISE(ABORT,'indicator matches are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS indicator_matches_no_delete
                BEFORE DELETE ON indicator_matches BEGIN SELECT RAISE(ABORT,'indicator matches are immutable'); END;
        """)
        conn.execute("INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(4,?)",
                     (datetime.now(timezone.utc).isoformat(),))


def _load(store, collection_id, revision=None):
    ensure_tables(store)
    with store.connection() as conn:
        current = conn.execute("SELECT revision,body FROM indicator_collections WHERE id=?", (collection_id,)).fetchone() if revision is None else None
        target_revision = current["revision"] if current else revision
        row = conn.execute("SELECT body FROM indicator_revisions WHERE collection_id=? AND revision=?",
                           (collection_id, target_revision)).fetchone()
    if row is None: raise KeyError("indicator collection or immutable revision not found")
    body = json.loads(row[0])
    if body.get("revision") != target_revision: raise ValueError("Indicator revision identity is invalid")
    if current is not None and current["body"] != row["body"]:
        raise ValueError("Current indicator collection differs from its latest immutable revision")
    return body


def _save(store, before, after):
    ensure_tables(store)
    revision = 1 if before is None else before["revision"] + 1
    now = datetime.now(timezone.utc).isoformat()
    after["revision"] = revision
    after["updated_at_utc"] = now
    encoded = json.dumps(after, ensure_ascii=False, separators=(",", ":"))
    with store.connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if before is None:
            conn.execute("INSERT INTO indicator_collections VALUES(?,?,?,?)", (after["collection_id"], revision, now, encoded))
        else:
            current = conn.execute("SELECT revision,body FROM indicator_collections WHERE id=?", (before["collection_id"],)).fetchone()
            if current is None or current["revision"] != before["revision"] or json.loads(current["body"]) != before:
                raise ValueError("Indicator collection changed; reload before editing")
            conn.execute("UPDATE indicator_collections SET revision=?,updated=?,body=? WHERE id=?",
                         (revision, now, encoded, after["collection_id"]))
        conn.execute("INSERT INTO indicator_revisions VALUES(?,?,?)", (after["collection_id"], revision, encoded))
    return after


def create_collection(store, name, provenance, source_reference, indicators, description="", import_metadata=None):
    name = _text(name, "collection name", 120)
    provenance = _text(provenance, "collection provenance", 1000)
    source_reference = _text(source_reference, "collection source reference", 500)
    description = _text(description, "collection description", 1000, empty=True)
    entries = _entries(indicators)
    now = datetime.now(timezone.utc).isoformat()
    body = {"collection_version": COLLECTION_VERSION, "collection_id": uuid4().hex, "name": name,
        "description": description, "provenance": provenance, "source_reference": source_reference,
        "source_claim": "Operator-supplied provenance; not independently authenticated.",
        "indicators": entries, "created_at_utc": now, "updated_at_utc": "", "revision": 0}
    if import_metadata is not None:
        if (not isinstance(import_metadata, dict) or set(import_metadata) != {"format", "filename", "sha256"}
                or import_metadata["format"] not in {"json", "csv"}
                or not re.fullmatch(r"[0-9a-f]{64}", import_metadata["sha256"])):
            raise ValueError("Indicator import metadata is invalid")
        body["import"] = dict(import_metadata)
    else:
        body["import"] = {"format": "manual", "filename": None, "sha256": None}
    return _save(store, None, body)


def parse_indicator_import(content, format_name):
    if not isinstance(content, bytes) or len(content) > MAX_IMPORT_BYTES:
        raise ValueError("Indicator import file must be no larger than 1 MiB")
    try: text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc: raise ValueError("Indicator import must be UTF-8 text") from exc
    if format_name == "json":
        def unique_pairs(pairs):
            value = {}
            for key, item in pairs:
                if key in value: raise ValueError(f"Duplicate JSON key in indicator import: {key}")
                value[key] = item
            return value
        try: entries = json.loads(text, object_pairs_hook=unique_pairs)
        except json.JSONDecodeError as exc: raise ValueError(f"Invalid indicator JSON: {exc}") from exc
        if not isinstance(entries, list): raise ValueError("Indicator JSON import must be a top-level array")
    elif format_name == "csv":
        stream = io.StringIO(text, newline="")
        try:
            reader = csv.DictReader(stream, strict=True)
            fields = reader.fieldnames or []
            required = {"type", "value", "source", "source_reference", "description"}
            allowed = required | {"notes", "source_confidence", "effective_from_utc", "effective_until_utc", "enabled"}
            if len(fields) != len(set(fields)): raise ValueError("Indicator CSV has duplicate column names")
            if not required <= set(fields) or set(fields) - allowed:
                raise ValueError("Indicator CSV requires type,value,source,source_reference,description and only documented optional columns")
            entries = []
            for row in reader:
                if None in row: raise ValueError("Indicator CSV row has more values than its header")
                item = {key: value for key, value in row.items() if key in allowed}
                if "source_confidence" in item and item["source_confidence"] != "":
                    try: item["source_confidence"] = float(item["source_confidence"])
                    except ValueError as exc: raise ValueError("source_confidence CSV values must be numbers from 0 to 1") from exc
                elif item.get("source_confidence") == "": item["source_confidence"] = None
                for key in ("effective_from_utc", "effective_until_utc"):
                    if item.get(key) == "": item[key] = None
                if "enabled" in item:
                    if item["enabled"].casefold() not in {"true", "false", "1", "0"}:
                        raise ValueError("enabled CSV values must be true/false or 1/0")
                    item["enabled"] = item["enabled"].casefold() in {"true", "1"}
                entries.append(item)
                if len(entries) > MAX_INDICATORS: raise ValueError("Indicator CSV exceeds 1,000 rows")
        except csv.Error as exc: raise ValueError(f"Malformed indicator CSV: {exc}") from exc
    else:
        raise ValueError("Indicator import format must be json or csv")
    if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_INDICATORS:
        raise ValueError("Indicator import must contain 1 to 1,000 records")
    # Validate the entire file before a collection is created.  Keep the
    # operator supplied records here; create_collection assigns the canonical
    # immutable IDs and recorded-at timestamps exactly once.
    _entries(entries)
    return entries


def update_collection(store, collection_id, expected_revision, changes):
    before = _load(store, collection_id)
    if before["revision"] != expected_revision: raise ValueError("Stale indicator collection revision; reload before editing")
    if not isinstance(changes, dict) or not changes or not set(changes) <= {"name", "description", "provenance", "source_reference", "indicators"}:
        raise ValueError("Collection edit has unsupported or empty fields")
    after = dict(before)
    for key, maximum in (("name", 120), ("description", 1000), ("provenance", 1000), ("source_reference", 500)):
        if key in changes: after[key] = _text(changes[key], f"collection {key}", maximum, empty=(key == "description"))
    if "indicators" in changes: after["indicators"] = _entries(changes["indicators"], before["indicators"])
    return _save(store, before, after)


def list_collections(store, cursor=0, limit=20):
    if cursor < 0 or not 1 <= limit <= 100: raise ValueError("Indicator collection page exceeds limits")
    ensure_tables(store)
    with store.connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM indicator_collections").fetchone()[0]
        rows = conn.execute("SELECT body FROM indicator_collections ORDER BY updated DESC,id LIMIT ? OFFSET ?", (limit, cursor)).fetchall()
    return {"items": [json.loads(row[0]) for row in rows], "total": total,
            "next_cursor": cursor + limit if cursor + limit < total else None}


def _match_events(store, run, collection):
    index = {}
    for item in collection["indicators"]:
        if item["enabled"]: index.setdefault((item["type"], item["normalized_value"]), []).append(item)
    events = store.events_by_ids(sorted(set(run["event_ids"])))
    grouped = {}
    for event in events:
        for kind, fields in STRUCTURED_FIELDS.items():
            for field in fields:
                observed = getattr(event, field)
                if observed is None: continue
                try: normalized = normalize_ioc(kind, observed)
                except ValueError: continue
                assertions = index.get((kind, normalized), [])
                if not assertions: continue
                states = []
                for indicator in assertions:
                    starts = datetime.fromisoformat(indicator["effective_from_utc"]) if indicator["effective_from_utc"] else None
                    ends = datetime.fromisoformat(indicator["effective_until_utc"]) if indicator["effective_until_utc"] else None
                    if starts and event.event_time_utc < starts: validity = "not_yet_effective_at_event_time"
                    elif ends and event.event_time_utc >= ends: validity = "expired_at_event_time"
                    elif starts or ends: validity = "effective_at_event_time"
                    else: validity = "unspecified"
                    states.append(validity)
                intervals = {(item["effective_from_utc"], item["effective_until_utc"]) for item in assertions}
                source_count = len(assertions)
                source_status = "single_source" if source_count == 1 else (
                    "conflicting_sources" if len(intervals) > 1 else "corroborated_sources")
                validity_status = states[0] if len(set(states)) == 1 else "conflicting_validity"
                grouped[(event.event_id, field, kind, normalized)] = {
                    "event_id": event.event_id, "event_time_utc": event.event_time_utc.isoformat(),
                    "indicator_type": kind, "indicator_normalized_value": normalized,
                    "match_field": field, "observed_value": observed,
                    "matched_indicator_ids": sorted(item["indicator_id"] for item in assertions),
                    "source_status": source_status, "validity_status": validity_status,
                    "source_assertions": [{"indicator_id": item["indicator_id"], "value": item["value"],
                        "source": item["source"], "source_reference": item["source_reference"],
                        "description": item["description"], "source_confidence": item["source_confidence"],
                        "effective_from_utc": item["effective_from_utc"], "effective_until_utc": item["effective_until_utc"],
                        "validity_at_event_time": state, "recorded_at_utc": item["recorded_at_utc"]}
                        for item, state in zip(assertions, states)]}
                if len(grouped) > MAX_MATCH_PAIRS:
                    raise ValueError("Local indicator matching exceeds the 10,000 unique event-field match bound; narrow the collection")
    time = {event.event_id: event.event_time_utc for event in events}
    pairs = list(grouped.values())
    pairs.sort(key=lambda hit: (time[hit["event_id"]], hit["event_id"], hit["indicator_normalized_value"], hit["match_field"]))
    return pairs


def match_collection(store, collection_id, analysis_run_id, revision=None):
    collection = _load(store, collection_id, revision)
    run = store.analysis(analysis_run_id)
    guard_run(store, run)
    pairs = _match_events(store, run, collection)
    execution_id = uuid4().hex
    result_hash = digest(json_bytes(pairs))
    body = {"match_id": execution_id, "collection_id": collection_id, "collection_revision": collection["revision"],
        "analysis_run_id": analysis_run_id, "view_id": analysis_run_id, "scope": "retained_run",
        "run_branch_kind": run.get("branch_kind", "legacy"), "view_cutoff_utc": run["cutoff"],
        "dataset_fingerprint": run["dataset_fingerprint"], "effective_observation_count": len(set(run["event_ids"])),
        "effective_observation_ids_sha256": digest(json_bytes(sorted(set(run["event_ids"])))),
        "extractor_version": EXTRACTOR_VERSION,
        "matched_indicator_ids": sorted({item for hit in pairs for item in hit["matched_indicator_ids"]}),
        "matched_pair_count": len(pairs), "matched_event_count": len({hit["event_id"] for hit in pairs}),
        "matches": pairs, "result_sha256": result_hash, "matched_fields": sorted({hit["match_field"] for hit in pairs}),
        "knowledge_interpretation": "This is a present-day intelligence overlay on the selected retained event-time view. Source validity is evaluated at each event time; it does not show what was known at the event time.",
        "interpretation": "Exact matches in structured canonical fields are analyst context, not native stages, incidents, risk, or proof of maliciousness. Duplicate source assertions are grouped into one event-field match.",
        "matched_at_utc": datetime.now(timezone.utc).isoformat()}
    with store.connection() as conn:
        conn.execute("INSERT INTO indicator_matches VALUES(?,?,?,?,?,?)", (execution_id, collection_id,
            collection["revision"], analysis_run_id, result_hash, json.dumps(body, ensure_ascii=False, separators=(",", ":"))))
    return body


def match_page(store, match_id, cursor=0, limit=50):
    if cursor < 0 or not 1 <= limit <= MAX_PAGE: raise ValueError("Indicator match page exceeds limits")
    ensure_tables(store)
    with store.connection() as conn:
        row = conn.execute("SELECT * FROM indicator_matches WHERE id=?", (match_id,)).fetchone()
    if row is None: raise KeyError("indicator match result not found")
    body = json.loads(row["body"])
    run = store.analysis(body["analysis_run_id"])
    guard_run(store, run)
    collection = _load(store, body["collection_id"], body["collection_revision"])
    expected = _match_events(store, run, collection)
    if (body["match_id"] != row["id"] or body["analysis_run_id"] != row["analysis_run_id"]
            or body["collection_id"] != row["collection_id"] or body["collection_revision"] != row["revision"]
            or body["result_sha256"] != row["result_sha256"] or body["matches"] != expected
            or digest(json_bytes(expected)) != row["result_sha256"] or cursor > len(expected)):
        raise ValueError("Indicator matches differ from the immutable collection and guarded retained view")
    next_cursor = cursor + limit if cursor + limit < len(expected) else None
    return {**body, "matches": expected[cursor:cursor + limit], "cursor": cursor, "next_cursor": next_cursor,
            "page_count": len(expected[cursor:cursor + limit])}


def list_matches(store, collection_id, cursor=0, limit=20):
    _load(store, collection_id)
    if cursor < 0 or not 1 <= limit <= 100: raise ValueError("Indicator match history page exceeds limits")
    ensure_tables(store)
    with store.connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM indicator_matches WHERE collection_id=?", (collection_id,)).fetchone()[0]
        rows = conn.execute("SELECT id,body FROM indicator_matches WHERE collection_id=? ORDER BY rowid DESC LIMIT ? OFFSET ?",
                            (collection_id, limit, cursor)).fetchall()
    items = [json.loads(row["body"]) for row in rows]
    for item in items: match_page(store, item["match_id"], 0, 1)
    return {"items": [{key: value for key, value in item.items() if key != "matches"} for item in items],
            "total": total, "next_cursor": cursor + limit if cursor + limit < total else None}
