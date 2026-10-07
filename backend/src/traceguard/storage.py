import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .ingest import ACTIONS, digest, event_content, json_bytes, normalize_record, parse_file
from .schemas import AuthorizationContext, AliasContext, Event, ResourceContext, SourceContext


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS datasets (
                    id TEXT PRIMARY KEY, name TEXT NOT NULL, environment TEXT NOT NULL,
                    origin TEXT NOT NULL, seed INTEGER, created TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS uploads (
                    id TEXT PRIMARY KEY, dataset_id TEXT REFERENCES datasets(id),
                    filename TEXT, source_id TEXT, source_type TEXT, sha256 TEXT, content BLOB);
                CREATE TABLE IF NOT EXISTS sources (
                    dataset_id TEXT REFERENCES datasets(id), source_id TEXT,
                    source_type TEXT NOT NULL, PRIMARY KEY(dataset_id, source_id));
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY, dataset_id TEXT REFERENCES datasets(id),
                    event_time TEXT NOT NULL, body TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS events_dataset_time ON events(dataset_id, event_time, id);
                CREATE TABLE IF NOT EXISTS records (
                    ref TEXT PRIMARY KEY, upload_id TEXT REFERENCES uploads(id),
                    row_number INTEGER, raw TEXT NOT NULL, raw_sha256 TEXT NOT NULL,
                    event_id TEXT REFERENCES events(id), status TEXT NOT NULL, error TEXT);
                CREATE INDEX IF NOT EXISTS records_event ON records(event_id);
                CREATE TABLE IF NOT EXISTS resources (
                    dataset_id TEXT REFERENCES datasets(id), resource_id TEXT,
                    body TEXT NOT NULL, PRIMARY KEY(dataset_id, resource_id));
                CREATE TABLE IF NOT EXISTS analyses (
                    id TEXT PRIMARY KEY, dataset_id TEXT REFERENCES datasets(id),
                    created TEXT NOT NULL, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY, analysis_id TEXT REFERENCES analyses(id), body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS baselines (
                    id TEXT PRIMARY KEY, metadata TEXT NOT NULL, model BLOB NOT NULL, sha256 TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS aliases (
                    environment TEXT NOT NULL, id TEXT NOT NULL, body TEXT NOT NULL,
                    PRIMARY KEY(environment,id));
                CREATE TABLE IF NOT EXISTS authorizations (
                    dataset_id TEXT REFERENCES datasets(id), id TEXT NOT NULL, body TEXT NOT NULL,
                    PRIMARY KEY(dataset_id,id));
                CREATE TABLE IF NOT EXISTS evaluations (
                    id TEXT PRIMARY KEY, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sensitivities (
                    id TEXT PRIMARY KEY, parent_id TEXT REFERENCES analyses(id),
                    child_id TEXT REFERENCES analyses(id), body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS lookalikes (
                    id TEXT PRIMARY KEY, left_id TEXT REFERENCES analyses(id),
                    right_id TEXT REFERENCES analyses(id), body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS lookalike_annotations (
                    id TEXT PRIMARY KEY REFERENCES lookalikes(id), body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL,
                    priority TEXT NOT NULL, revision INTEGER NOT NULL, updated TEXT NOT NULL,
                    body TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS cases_status_priority_updated
                    ON cases(status, priority, updated DESC);
                CREATE TABLE IF NOT EXISTS case_revisions (
                    case_id TEXT NOT NULL REFERENCES cases(id), revision INTEGER NOT NULL,
                    body TEXT NOT NULL, PRIMARY KEY(case_id, revision));
                CREATE TABLE IF NOT EXISTS case_audit (
                    id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
                    revision INTEGER NOT NULL, occurred TEXT NOT NULL, operation TEXT NOT NULL,
                    author TEXT NOT NULL, reason TEXT NOT NULL, previous_body TEXT,
                    new_body TEXT NOT NULL, UNIQUE(case_id, revision));
                CREATE TRIGGER IF NOT EXISTS case_revisions_no_update
                    BEFORE UPDATE ON case_revisions BEGIN SELECT RAISE(ABORT,'case revisions are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS case_revisions_no_delete
                    BEFORE DELETE ON case_revisions BEGIN SELECT RAISE(ABORT,'case revisions are immutable'); END;
                CREATE TABLE IF NOT EXISTS saved_hunts (
                    id TEXT PRIMARY KEY, revision INTEGER NOT NULL, updated TEXT NOT NULL, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS hunt_revisions (
                    hunt_id TEXT NOT NULL REFERENCES saved_hunts(id), revision INTEGER NOT NULL, body TEXT NOT NULL,
                    PRIMARY KEY(hunt_id,revision));
                CREATE TABLE IF NOT EXISTS hunt_executions (
                    id TEXT PRIMARY KEY, hunt_id TEXT NOT NULL REFERENCES saved_hunts(id), revision INTEGER NOT NULL,
                    analysis_run_id TEXT NOT NULL, executed TEXT NOT NULL, result_sha256 TEXT NOT NULL, body TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS hunt_execution_lookup ON hunt_executions(hunt_id,executed DESC);
                CREATE TRIGGER IF NOT EXISTS hunt_revisions_no_update
                    BEFORE UPDATE ON hunt_revisions BEGIN SELECT RAISE(ABORT,'hunt revisions are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS hunt_revisions_no_delete
                    BEFORE DELETE ON hunt_revisions BEGIN SELECT RAISE(ABORT,'hunt revisions are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS hunt_executions_no_update
                    BEFORE UPDATE ON hunt_executions BEGIN SELECT RAISE(ABORT,'hunt executions are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS hunt_executions_no_delete
                    BEFORE DELETE ON hunt_executions BEGIN SELECT RAISE(ABORT,'hunt executions are immutable'); END;
                CREATE TABLE IF NOT EXISTS sigma_rules (
                    id TEXT PRIMARY KEY, revision INTEGER NOT NULL, updated TEXT NOT NULL, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sigma_rule_revisions (
                    rule_id TEXT NOT NULL REFERENCES sigma_rules(id), revision INTEGER NOT NULL,
                    rule_sha256 TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY(rule_id,revision));
                CREATE TABLE IF NOT EXISTS sigma_hunt_executions (
                    id TEXT PRIMARY KEY, rule_id TEXT NOT NULL REFERENCES sigma_rules(id), revision INTEGER NOT NULL,
                    analysis_run_id TEXT NOT NULL, result_sha256 TEXT NOT NULL, body TEXT NOT NULL);
                CREATE TRIGGER IF NOT EXISTS sigma_rule_revisions_no_update
                    BEFORE UPDATE ON sigma_rule_revisions BEGIN SELECT RAISE(ABORT,'Sigma rule revisions are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS sigma_rule_revisions_no_delete
                    BEFORE DELETE ON sigma_rule_revisions BEGIN SELECT RAISE(ABORT,'Sigma rule revisions are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS sigma_hunt_executions_no_update
                    BEFORE UPDATE ON sigma_hunt_executions BEGIN SELECT RAISE(ABORT,'Sigma hunt executions are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS sigma_hunt_executions_no_delete
                    BEFORE DELETE ON sigma_hunt_executions BEGIN SELECT RAISE(ABORT,'Sigma hunt executions are immutable'); END;
                CREATE TABLE IF NOT EXISTS indicator_collections (
                    id TEXT PRIMARY KEY, revision INTEGER NOT NULL, updated TEXT NOT NULL, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS indicator_revisions (
                    collection_id TEXT NOT NULL REFERENCES indicator_collections(id), revision INTEGER NOT NULL,
                    body TEXT NOT NULL, PRIMARY KEY(collection_id,revision));
                CREATE TABLE IF NOT EXISTS indicator_matches (
                    id TEXT PRIMARY KEY, collection_id TEXT NOT NULL REFERENCES indicator_collections(id),
                    revision INTEGER NOT NULL, analysis_run_id TEXT NOT NULL, result_sha256 TEXT NOT NULL, body TEXT NOT NULL);
                CREATE TRIGGER IF NOT EXISTS indicator_revisions_no_update
                    BEFORE UPDATE ON indicator_revisions BEGIN SELECT RAISE(ABORT,'indicator revisions are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS indicator_revisions_no_delete
                    BEFORE DELETE ON indicator_revisions BEGIN SELECT RAISE(ABORT,'indicator revisions are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS indicator_matches_no_update
                    BEFORE UPDATE ON indicator_matches BEGIN SELECT RAISE(ABORT,'indicator matches are immutable'); END;
                CREATE TRIGGER IF NOT EXISTS indicator_matches_no_delete
                    BEFORE DELETE ON indicator_matches BEGIN SELECT RAISE(ABORT,'indicator matches are immutable'); END;
            """)
            conn.execute("INSERT OR IGNORE INTO schema_migrations VALUES(1,?)",
                         (datetime.now(timezone.utc).isoformat(),))
            conn.execute("INSERT OR IGNORE INTO schema_migrations VALUES(2,?)",
                         (datetime.now(timezone.utc).isoformat(),))
            conn.execute("INSERT OR IGNORE INTO schema_migrations VALUES(3,?)",
                         (datetime.now(timezone.utc).isoformat(),))
            conn.execute("INSERT OR IGNORE INTO schema_migrations VALUES(4,?)",
                         (datetime.now(timezone.utc).isoformat(),))

    @contextmanager
    def connection(self):
        conn = sqlite3.connect(self.path, timeout=20)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def create_dataset(self, name: str, environment: str, origin="upload", seed=None) -> str:
        dataset_id = uuid4().hex
        with self.connection() as conn:
            conn.execute("INSERT INTO datasets VALUES(?,?,?,?,?,?)", (
                dataset_id, name, environment, origin, seed, datetime.now(timezone.utc).isoformat()))
        return dataset_id

    def dataset(self, dataset_id: str) -> dict:
        with self.connection() as conn:
            row = conn.execute("SELECT * FROM datasets WHERE id=?", (dataset_id,)).fetchone()
        if row is None:
            raise KeyError("dataset not found")
        return dict(row)

    def datasets(self) -> list[dict]:
        with self.connection() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM datasets ORDER BY created DESC")]

    def ingest(self, dataset_id: str, content: bytes, filename: str, source_id: str,
               source_type: str, declared_timezone: str | None = None) -> dict:
        dataset = self.dataset(dataset_id)
        context = SourceContext(dataset_id=dataset_id, environment_id=dataset["environment"],
                                source_id=source_id, source_type=source_type, timezone=declared_timezone)
        rows = parse_file(content, filename)
        upload_id, file_hash = uuid4().hex, digest(content)
        with self.connection() as conn:
            previous = conn.execute("SELECT source_type FROM sources WHERE dataset_id=? AND source_id=?",
                                    (dataset_id, source_id)).fetchone()
            if previous and previous[0] != source_type:
                raise ValueError("source_id is already bound to a different adapter")
            conn.execute("INSERT OR IGNORE INTO sources VALUES(?,?,?)", (dataset_id, source_id, source_type))
            conn.execute("INSERT INTO uploads VALUES(?,?,?,?,?,?,?)",
                         (upload_id, dataset_id, filename, source_id, source_type, file_hash, content))
            for number, record, error in rows:
                ref = f"{upload_id}:{number}"
                result = normalize_record(record, context, row=number, file_hash=file_hash, raw_ref=ref) if not error else None
                error = error or result.error
                event = result.event if result else None
                status, event_id = "rejected", None
                if event and not error:
                    existing = conn.execute("SELECT body FROM events WHERE id=?", (event.event_id,)).fetchone()
                    if existing:
                        old = Event.model_validate_json(existing[0])
                        if event_content(old) != event_content(event):
                            error = "conflicting source_event_id; record quarantined"
                        else:
                            status, event_id = "duplicate", event.event_id
                    else:
                        count = conn.execute("SELECT COUNT(*) FROM events WHERE dataset_id=?", (dataset_id,)).fetchone()[0]
                        if count >= 50000:
                            raise ValueError("dataset limit is 50,000 unique events; this import was rolled back")
                        conn.execute("INSERT INTO events VALUES(?,?,?,?)", (
                            event.event_id, dataset_id, event.event_time_utc.isoformat(), event.model_dump_json()))
                        status, event_id = "accepted", event.event_id
                raw = record if record is not None else {}
                conn.execute("INSERT INTO records VALUES(?,?,?,?,?,?,?,?)", (
                    ref, upload_id, number, json.dumps(raw, ensure_ascii=False),
                    digest(json_bytes(raw)), event_id, status, error))
        return self.quality(dataset_id)

    def quality(self, dataset_id: str) -> dict:
        self.dataset(dataset_id)
        with self.connection() as conn:
            counts = dict(conn.execute("""SELECT r.status, COUNT(*) FROM records r JOIN uploads u
                ON r.upload_id=u.id WHERE u.dataset_id=? GROUP BY r.status""", (dataset_id,)).fetchall())
            errors = [dict(row) for row in conn.execute("""SELECT u.filename, r.row_number, r.error,
                r.ref FROM records r JOIN uploads u ON r.upload_id=u.id
                WHERE u.dataset_id=? AND r.error IS NOT NULL ORDER BY r.ref LIMIT 20""", (dataset_id,))]
            files = [dict(row) for row in conn.execute("""SELECT id, filename, source_id, source_type, sha256
                FROM uploads WHERE dataset_id=? ORDER BY id""", (dataset_id,))]
        events = self.events(dataset_id)
        unsupported = sum(e.action not in ACTIONS[e.source_type] for e in events)
        return {"accepted": counts.get("accepted", 0), "rejected": counts.get("rejected", 0),
                "duplicates": counts.get("duplicate", 0), "unsupported": unsupported,
                "errors": errors, "files": files,
                "timezone_assumptions": sorted({e.timezone_assumption for e in events if e.timezone_assumption}),
                "warnings": sorted({w for e in events for w in e.normalization_warnings})}

    def events(self, dataset_id: str) -> list[Event]:
        with self.connection() as conn:
            return [Event.model_validate_json(row[0]) for row in conn.execute(
                "SELECT body FROM events WHERE dataset_id=? ORDER BY event_time,id", (dataset_id,))]

    def events_by_ids(self, ids: list[str]) -> list[Event]:
        by_id = {}
        with self.connection() as conn:
            for start in range(0,len(ids),500):
                batch = ids[start:start+500]
                marks = ",".join("?" for _ in batch)
                for row in conn.execute(f"SELECT id,body FROM events WHERE id IN ({marks})",batch):
                    by_id[row["id"]] = Event.model_validate_json(row["body"])
        if any(eid not in by_id for eid in ids):
            raise ValueError("retained run references missing events")
        return [by_id[eid] for eid in ids]

    def event(self, event_id: str) -> Event:
        with self.connection() as conn:
            row = conn.execute("SELECT body FROM events WHERE id=?", (event_id,)).fetchone()
        if not row:
            raise KeyError("event not found")
        return Event.model_validate_json(row[0])

    def evidence(self, event_id: str, file_cache: dict | None = None) -> dict:
        event = self.event(event_id)
        with self.connection() as conn:
            records = [dict(row) for row in conn.execute("""SELECT r.*, u.filename, u.sha256 AS file_sha256,
                u.source_id, u.source_type, u.content FROM records r JOIN uploads u ON u.id=r.upload_id
                WHERE r.event_id=? ORDER BY r.ref""", (event_id,))]
        for row in records:
            row["raw"] = json.loads(row["raw"])
            row["hash_valid"] = digest(json_bytes(row["raw"])) == row["raw_sha256"]
            content = row.pop("content")
            row["file_hash_valid"] = digest(content) == row["file_sha256"]
            key = row["upload_id"]
            if file_cache is not None:
                if key not in file_cache:
                    file_cache[key] = parse_file(content, row["filename"])
                original_rows = file_cache[key]
            else:
                original_rows = parse_file(content, row["filename"])
            row["file_row_valid"] = any(number == row["row_number"] and record == row["raw"]
                                        for number, record, _ in original_rows)
        return {"event": event.model_dump(mode="json"), "source_records": records}

    def provenance_errors(self, event_id: str) -> list[str]:
        evidence = self.evidence(event_id)
        event = self.event(event_id)
        errors = []
        refs = evidence["source_records"]
        if not refs or event.raw_record_ref not in {r["ref"] for r in refs}:
            errors.append(f"unresolvable primary source reference: {event_id}")
        for record in refs:
            if not record["hash_valid"] or not record["file_hash_valid"] or not record["file_row_valid"]:
                errors.append(f"source hash mismatch: {record['ref']}")
            normalized = normalize_record(record["raw"], SourceContext(
                dataset_id=event.dataset_id, environment_id=event.environment_id,
                source_id=record["source_id"], source_type=record["source_type"], timezone=event.timezone_assumption))
            if not normalized.event or event_content(normalized.event) != event_content(event):
                errors.append(f"source does not support normalized event: {record['ref']}")
            if record["ref"] == event.raw_record_ref and (
                    record["raw_sha256"] != event.raw_record_sha256 or record["file_sha256"] != event.source_file_sha256
                    or record["row_number"] != event.source_record_number):
                errors.append(f"canonical provenance mismatch: {event_id}")
        return errors

    def set_resources(self, dataset_id: str, resources: list[ResourceContext]):
        self.dataset(dataset_id)
        if len(resources)>1000:
            raise ValueError("at most 1,000 trusted resource labels")
        for resource in resources:
            if not resource.provenance.strip():
                raise ValueError("resource provenance must be nonblank")
            from .ingest import entity_id
            if not resource.resource_id.startswith(entity_id(self.dataset(dataset_id)["environment"], "file", "")):
                raise ValueError("resource identifier must belong to this environment's file namespace")
            if resource.effective_from.tzinfo is None or (resource.effective_until and resource.effective_until.tzinfo is None):
                raise ValueError("trusted-context times must have explicit offsets")
            if resource.effective_until and resource.effective_until <= resource.effective_from:
                raise ValueError("trusted-context interval must increase")
        with self.connection() as conn:
            for resource in resources:
                conn.execute("INSERT OR REPLACE INTO resources VALUES(?,?,?)",
                             (dataset_id, resource.resource_id, resource.model_dump_json()))

    def resources(self, dataset_id: str) -> list[dict]:
        with self.connection() as conn:
            return [json.loads(row[0]) for row in conn.execute(
                "SELECT body FROM resources WHERE dataset_id=? ORDER BY resource_id", (dataset_id,))]

    def save_analysis(self, analysis: dict, incidents: list, *, connection=None):
        from .views import freeze_run
        freeze_run(self, analysis)
        def write(conn):
            selected = {eid for item in incidents for eid in item.selected_evidence}
            selected |= {eid for item in incidents for stage in item.stages for eid in (stage.historical_comparison or {}).get("history_event_ids", [])}
            refs = {}
            for eid in sorted(selected):
                refs[eid] = [r[0] for r in conn.execute("SELECT ref FROM records WHERE event_id=? ORDER BY ref", (eid,))]
            analysis.setdefault("evidence_reference_snapshot", refs)
            conn.execute("INSERT INTO analyses VALUES(?,?,?,?)", (
                analysis["analysis_run_id"], analysis["dataset_id"], datetime.now(timezone.utc).isoformat(), json.dumps(analysis)))
            for incident in incidents:
                conn.execute("INSERT INTO incidents VALUES(?,?,?)", (
                    incident.incident_id, analysis["analysis_run_id"], incident.model_dump_json()))
        if connection is not None:
            write(connection)
        else:
            with self.connection() as conn:
                write(conn)

    def analysis(self, analysis_id: str) -> dict:
        with self.connection() as conn:
            row = conn.execute("SELECT body FROM analyses WHERE id=?", (analysis_id,)).fetchone()
        if not row:
            raise KeyError("analysis not found")
        return json.loads(row[0])

    def provenance_batch(self, events: list[Event], reference_snapshot: dict | None = None) -> dict[str, list[str]]:
        """Validate each original file once per operation; no stale global cache."""
        selected = {e.event_id for e in events}
        datasets = {e.dataset_id for e in events}
        by_id, files, records = {}, {}, []
        with self.connection() as conn:
            for dataset in sorted(datasets):
                for row in conn.execute("SELECT body FROM events WHERE dataset_id=?", (dataset,)):
                    event = Event.model_validate_json(row[0])
                    if event.event_id in selected:
                        by_id[event.event_id] = event
                records.extend(dict(row) for row in conn.execute("""SELECT r.* FROM records r JOIN uploads u ON u.id=r.upload_id
                    WHERE u.dataset_id=? AND r.event_id IS NOT NULL""", (dataset,)) if row["event_id"] in selected
                    and (reference_snapshot is None or row["ref"] in reference_snapshot.get(row["event_id"], [])))
            for upload_id in sorted({r["upload_id"] for r in records}):
                upload = dict(conn.execute("SELECT * FROM uploads WHERE id=?", (upload_id,)).fetchone())
                parsed = {number: raw for number, raw, _ in parse_file(upload["content"],upload["filename"])}
                files[upload_id] = (upload, parsed, digest(upload["content"]) == upload["sha256"])
        errors = {eid:[] for eid in selected}
        refs = set()
        refs_by_event = {eid: set() for eid in selected}
        for record in records:
            eid = record["event_id"]; event = by_id[eid]
            upload, parsed, file_valid = files[record["upload_id"]]
            raw = json.loads(record["raw"]); refs.add(record["ref"])
            refs_by_event[eid].add(record["ref"])
            if not file_valid or digest(json_bytes(raw)) != record["raw_sha256"] or parsed.get(record["row_number"]) != raw:
                errors[eid].append(f"source file/row/hash mismatch: {record['ref']}")
            normalized = normalize_record(raw, SourceContext(dataset_id=event.dataset_id, environment_id=event.environment_id,
                source_id=upload["source_id"],source_type=upload["source_type"],timezone=event.timezone_assumption))
            if not normalized.event or event_content(normalized.event) != event_content(event):
                errors[eid].append(f"source predicate mismatch: {record['ref']}")
            if record["ref"] == event.raw_record_ref and (record["raw_sha256"] != event.raw_record_sha256
                    or upload["sha256"] != event.source_file_sha256 or record["row_number"] != event.source_record_number):
                errors[eid].append(f"primary provenance mismatch: {eid}")
        for eid in selected:
            if reference_snapshot is not None and set(reference_snapshot.get(eid, [])) != refs_by_event[eid]:
                errors[eid].append(f"frozen source reference missing: {eid}")
            if eid not in by_id or by_id[eid].raw_record_ref not in refs:
                errors[eid].append(f"primary reference missing: {eid}")
        return errors

    def incidents(self, analysis_id: str) -> list[dict]:
        self.analysis(analysis_id)
        with self.connection() as conn:
            return [json.loads(row[0]) for row in conn.execute(
                "SELECT body FROM incidents WHERE analysis_id=? ORDER BY id", (analysis_id,))]

    def incident(self, incident_id: str) -> dict:
        with self.connection() as conn:
            row = conn.execute("SELECT body FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not row:
            raise KeyError("incident not found")
        return json.loads(row[0])

    def set_aliases(self, environment: str, aliases: list[AliasContext]):
        from .ingest import entity_id
        prefix = entity_id(environment, "user", "")
        if len(aliases) > 1000:
            raise ValueError("at most 1,000 alias entries")
        for alias in aliases:
            if not alias.provenance.strip():
                raise ValueError("alias provenance must be nonblank")
            if not alias.alias_user_id.startswith(prefix) or not alias.canonical_user_id.startswith(prefix):
                raise ValueError("alias identifiers must be user entities in this environment")
            if alias.alias_user_id == alias.canonical_user_id:
                raise ValueError("alias must refer to a distinct canonical account")
            if alias.effective_from.tzinfo is None or (alias.effective_until and alias.effective_until.tzinfo is None):
                raise ValueError("alias times require explicit offsets")
            if alias.effective_until and alias.effective_until <= alias.effective_from:
                raise ValueError("alias interval must increase")
        with self.connection() as conn:
            for alias in aliases:
                body = alias.model_dump_json()
                conn.execute("INSERT OR IGNORE INTO aliases VALUES(?,?,?)",
                             (environment, digest(body.encode()), body))

    def aliases(self, environment: str) -> list[dict]:
        with self.connection() as conn:
            return [json.loads(row[0]) for row in conn.execute(
                "SELECT body FROM aliases WHERE environment=? ORDER BY id", (environment,))]

    def save_baseline(self, metadata: dict, model: bytes):
        metadata["model_sha256"] = digest(model)
        with self.connection() as conn:
            conn.execute("INSERT INTO baselines VALUES(?,?,?,?)",
                         (metadata["baseline_id"], json.dumps(metadata), model, digest(model)))

    def baseline(self, baseline_id: str) -> tuple[dict, bytes]:
        with self.connection() as conn:
            row = conn.execute("SELECT metadata,model,sha256 FROM baselines WHERE id=?", (baseline_id,)).fetchone()
        if not row:
            raise KeyError("baseline not found")
        if digest(row[1]) != row[2]:
            raise ValueError("local baseline artifact hash mismatch")
        return json.loads(row[0]), row[1]

    def baselines(self) -> list[dict]:
        with self.connection() as conn:
            return [json.loads(row[0]) for row in conn.execute("SELECT metadata FROM baselines ORDER BY id")]

    def save_evaluation(self, result: dict):
        with self.connection() as conn:
            conn.execute("INSERT INTO evaluations VALUES(?,?)", (result["evaluation_id"], json.dumps(result)))

    def evaluation(self, evaluation_id: str) -> dict:
        with self.connection() as conn:
            row = conn.execute("SELECT body FROM evaluations WHERE id=?", (evaluation_id,)).fetchone()
        if not row:
            raise KeyError("evaluation not found")
        return json.loads(row[0])

    def set_authorizations(self, dataset_id: str, entries: list[AuthorizationContext]):
        from .ingest import entity_id
        environment = self.dataset(dataset_id)["environment"]
        if len(entries) > 1000:
            raise ValueError("at most 1,000 authorizations")
        if len({e.authorization_id for e in entries}) != len(entries):
            raise ValueError("authorization IDs must be unique")
        for entry in entries:
            for field, kind in (("user_id","user"),("device_id","endpoint"),("resource_id","file")):
                identifier = getattr(entry, field)
                prefix = entity_id(environment,kind,"")
                if not identifier.startswith(prefix) or identifier == prefix:
                    raise ValueError("authorization identifiers require exact environment-scoped actor, endpoint and resource")
            if not entry.provenance.strip():
                raise ValueError("authorization provenance must be nonblank")
            if entry.effective_from.tzinfo is None or entry.effective_until.tzinfo is None:
                raise ValueError("authorization times require explicit offsets")
            if entry.effective_until <= entry.effective_from:
                raise ValueError("authorization interval must increase")
        with self.connection() as conn:
            conn.execute("DELETE FROM authorizations WHERE dataset_id=?", (dataset_id,))
            for entry in entries:
                conn.execute("INSERT INTO authorizations VALUES(?,?,?)", (dataset_id,entry.authorization_id,entry.model_dump_json()))

    def authorizations(self, dataset_id: str) -> list[dict]:
        self.dataset(dataset_id)
        with self.connection() as conn:
            return [json.loads(r[0]) for r in conn.execute("SELECT body FROM authorizations WHERE dataset_id=? ORDER BY id",(dataset_id,))]

    def analyses(self, dataset_id: str) -> list[dict]:
        self.dataset(dataset_id)
        with self.connection() as conn:
            return [{key:value for key,value in json.loads(r[0]).items() if key in {
                "analysis_run_id","dataset_id","mode","cutoff","status","baseline_id","dataset_fingerprint",
                "incident_count","partial_count","review_count","event_count","warnings","branch_kind","parent_run_id","comparison_id"}}
                for r in conn.execute("SELECT body FROM analyses WHERE dataset_id=? ORDER BY created DESC LIMIT 200",(dataset_id,))]
