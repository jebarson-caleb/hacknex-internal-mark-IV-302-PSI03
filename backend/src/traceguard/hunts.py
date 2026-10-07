"""Saved, run-scoped observation hunts kept outside native detector state."""
import copy
import json
from datetime import datetime, timezone
from uuid import uuid4

from .ingest import digest, json_bytes
from .replay import guard_run

FILTER_SCHEMA = "traceguard-hunt-filter-v1"
FIELDS = {"source_type", "action", "user_id", "device_id", "resource_id", "src_ip", "dst_ip", "domain",
          "file_path", "file_hash", "process_name", "destination_type", "outcome"}
TEXT_FIELDS = FIELDS - {"file_hash"}
COLUMNS = {"event_id", "event_time_utc", *FIELDS}
MAX_FILTERS = 20
MAX_COLUMNS = 20


def ensure_tables(store):
    with store.connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS saved_hunts (
                id TEXT PRIMARY KEY, revision INTEGER NOT NULL, updated TEXT NOT NULL, body TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS hunt_revisions (
                hunt_id TEXT NOT NULL, revision INTEGER NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY(hunt_id,revision)
            );
            CREATE TABLE IF NOT EXISTS hunt_executions (
                id TEXT PRIMARY KEY, hunt_id TEXT NOT NULL, revision INTEGER NOT NULL,
                analysis_run_id TEXT NOT NULL, executed TEXT NOT NULL, result_sha256 TEXT NOT NULL, body TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS hunt_execution_lookup ON hunt_executions(hunt_id,executed DESC);
            CREATE TRIGGER IF NOT EXISTS hunt_revisions_no_update
                BEFORE UPDATE ON hunt_revisions BEGIN SELECT RAISE(ABORT,'hunt revisions are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS hunt_revisions_no_delete
                BEFORE DELETE ON hunt_revisions BEGIN SELECT RAISE(ABORT,'hunt revisions are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS hunt_executions_no_update
                BEFORE UPDATE ON hunt_executions BEGIN SELECT RAISE(ABORT,'hunt executions are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS hunt_executions_no_delete
                BEFORE DELETE ON hunt_executions BEGIN SELECT RAISE(ABORT,'hunt executions are immutable'); END;
        """)
        conn.execute("INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(2,?)",
                     (datetime.now(timezone.utc).isoformat(),))


def _now():
    return datetime.now(timezone.utc).isoformat()


def _text(value, label, limit, empty=False):
    if not isinstance(value, str) or len(value) > limit or (not empty and not value.strip()):
        raise ValueError(f"{label} must be {'at most' if empty else 'nonblank and at most'} {limit} characters")
    if "<script" in value.lower() or "javascript:" in value.lower():
        raise ValueError(f"{label} cannot contain script-bearing text")
    return value


def _time(value, label):
    if value is None:
        return None
    _text(value, label, 64)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{label} must include a UTC offset")
    return parsed


def _validate_query(query, columns):
    if not isinstance(query, dict) or set(query) - {"filters", "start_time_utc", "end_time_utc"}:
        raise ValueError("Hunt query must contain only filters and optional time bounds")
    filters = query.get("filters", [])
    if not isinstance(filters, list) or len(filters) > MAX_FILTERS:
        raise ValueError("Hunt filters must be a list of at most 20 conditions")
    checked = []
    for item in filters:
        if not isinstance(item, dict) or set(item) != {"field", "op", "value"}:
            raise ValueError("Each hunt filter requires exactly field, op, and value")
        field, op, value = item["field"], item["op"], item["value"]
        if field not in FIELDS or op not in {"eq", "in", "contains"}:
            raise ValueError("Unsupported hunt field or operation")
        if op == "in":
            if not isinstance(value, list) or not 1 <= len(value) <= 25 or any(not isinstance(v, str) for v in value):
                raise ValueError("Membership values must contain 1 to 25 strings")
            if len(set(value)) != len(value):
                raise ValueError("Membership values must be unique")
            value = [_text(v, "membership value", 500) for v in value]
        else:
            if not isinstance(value, str):
                raise ValueError("Hunt comparison values must be strings")
            value = _text(value, "filter value", 500)
        if op == "contains" and (field not in TEXT_FIELDS or len(value) < 2):
            raise ValueError("Substring filters require an allowlisted text field and at least two characters")
        checked.append({"field": field, "op": op, "value": value})
    start, end = _time(query.get("start_time_utc"), "start_time_utc"), _time(query.get("end_time_utc"), "end_time_utc")
    if start and end and start >= end:
        raise ValueError("Hunt time range must have start before end")
    if not isinstance(columns, list) or not 1 <= len(columns) <= MAX_COLUMNS or len(set(columns)) != len(columns):
        raise ValueError("Displayed columns must be a unique nonempty list of at most 20 fields")
    if any(col not in COLUMNS for col in columns):
        raise ValueError("Displayed columns contain an unsupported field")
    normalized = {"filters": checked}
    if query.get("start_time_utc") is not None: normalized["start_time_utc"] = _time(query["start_time_utc"], "start_time_utc").isoformat()
    if query.get("end_time_utc") is not None: normalized["end_time_utc"] = _time(query["end_time_utc"], "end_time_utc").isoformat()
    return normalized, list(columns)


def _load(store, hunt_id, revision=None):
    ensure_tables(store)
    with store.connection() as conn:
        current = conn.execute("SELECT revision,body FROM saved_hunts WHERE id=?", (hunt_id,)).fetchone() if revision is None else None
        target_revision = current["revision"] if current else revision
        row = conn.execute("SELECT body FROM hunt_revisions WHERE hunt_id=? AND revision=?",
                           (hunt_id, target_revision)).fetchone()
    if row is None:
        raise KeyError("saved hunt or revision not found")
    if current is not None and current["body"] != row["body"]:
        raise ValueError("Current saved hunt differs from its latest immutable revision")
    return json.loads(row["body"])


def _save_revision(store, before, after):
    ensure_tables(store)
    now = _now()
    after["revision"] = 1 if before is None else before["revision"] + 1
    after["updated_at_utc"] = now
    encoded = json.dumps(after, ensure_ascii=False, separators=(",", ":"))
    with store.connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if before is None:
            conn.execute("INSERT INTO saved_hunts VALUES(?,?,?,?)", (after["hunt_id"], after["revision"], now, encoded))
        else:
            row = conn.execute("SELECT revision,body FROM saved_hunts WHERE id=?", (before["hunt_id"],)).fetchone()
            if row is None or row["revision"] != before["revision"] or json.loads(row["body"]) != before:
                raise ValueError("Saved hunt changed; reload before editing")
            conn.execute("UPDATE saved_hunts SET revision=?,updated=?,body=? WHERE id=?",
                         (after["revision"], now, encoded, after["hunt_id"]))
        conn.execute("INSERT INTO hunt_revisions VALUES(?,?,?)", (after["hunt_id"], after["revision"], encoded))
    return after


def create_hunt(store, name, description="", query=None, columns=None, scope="retained_run", tags=None):
    name = _text(name, "hunt name", 120)
    description = _text(description, "hunt description", 1000, empty=True)
    if scope != "retained_run": raise ValueError("Saved hunts must have explicit retained_run scope")
    query, columns = _validate_query(query or {"filters": []}, columns or ["event_time_utc", "source_type", "action", "user_id", "device_id", "event_id"])
    tags = tags or []
    if not isinstance(tags, list) or len(tags) > 30 or len(set(tags)) != len(tags):
        raise ValueError("Hunt tags must be unique labels (maximum 30)")
    tags = [_text(t, "tag", 50) for t in tags]
    body = {"hunt_version": "traceguard-saved-hunt-v1", "hunt_id": uuid4().hex, "name": name,
        "description": description, "scope": scope, "filter_schema": FILTER_SCHEMA, "query": query,
        "columns": columns, "tags": tags, "starred": False, "notes": [], "created_at_utc": _now(),
        "updated_at_utc": "", "revision": 0}
    return _save_revision(store, None, body)


def update_hunt(store, hunt_id, expected_revision, changes):
    before = _load(store, hunt_id)
    if before["revision"] != expected_revision: raise ValueError("Stale hunt revision; reload before editing")
    if not isinstance(changes, dict) or not changes or not set(changes) <= {"name", "description", "query", "columns", "tags", "starred"}:
        raise ValueError("Hunt edit contains unsupported or empty fields")
    after = copy.deepcopy(before)
    if "name" in changes: after["name"] = _text(changes["name"], "hunt name", 120)
    if "description" in changes: after["description"] = _text(changes["description"], "hunt description", 1000, empty=True)
    if "query" in changes or "columns" in changes:
        after["query"], after["columns"] = _validate_query(changes.get("query", after["query"]), changes.get("columns", after["columns"]))
    if "tags" in changes:
        tags = changes["tags"]
        if not isinstance(tags, list) or len(tags) > 30 or len(set(tags)) != len(tags): raise ValueError("Hunt tags must be unique (maximum 30)")
        after["tags"] = [_text(t, "tag", 50) for t in tags]
    if "starred" in changes:
        if not isinstance(changes["starred"], bool): raise ValueError("Star state must be boolean")
        after["starred"] = changes["starred"]
    return _save_revision(store, before, after)


def add_hunt_note(store, hunt_id, expected_revision, note, author="operator"):
    note = _text(note, "hunt note", 1000)
    author = _text(author, "author label", 100)
    before = _load(store, hunt_id)
    if before["revision"] != expected_revision: raise ValueError("Stale hunt revision; reload before adding a note")
    after = copy.deepcopy(before)
    after["notes"].append({"note_id": uuid4().hex, "text": note, "author_label": author, "created_at_utc": _now()})
    return _save_revision(store, before, after)


def _matches(event, query):
    value = event.model_dump(mode="json")
    instant = event.event_time_utc
    start, end = _time(query.get("start_time_utc"), "start_time_utc"), _time(query.get("end_time_utc"), "end_time_utc")
    if start and instant < start: return False
    if end and instant >= end: return False
    for condition in query["filters"]:
        current, expected = value.get(condition["field"]), condition["value"]
        if current is None: return False
        if condition["op"] == "eq" and current != expected: return False
        if condition["op"] == "in" and current not in expected: return False
        if condition["op"] == "contains" and expected.casefold() not in current.casefold(): return False
    return True


def execute_hunt(store, hunt_id, analysis_run_id, revision=None):
    hunt = _load(store, hunt_id, revision)
    run = store.analysis(analysis_run_id)
    guard_run(store, run)
    # Replay run membership and source snapshots have just been recomputed by guard_run.
    events = store.events_by_ids(sorted(set(run["event_ids"])))
    matched = [event for event in events if _matches(event, hunt["query"])]
    matched.sort(key=lambda event: (event.event_time_utc, event.event_id))
    event_ids = [event.event_id for event in matched]
    execution_id = uuid4().hex
    body = {"execution_id": execution_id, "hunt_id": hunt_id, "hunt_revision": hunt["revision"],
        "analysis_run_id": analysis_run_id, "view_id": analysis_run_id, "scope": hunt["scope"],
        "filter_schema": FILTER_SCHEMA, "query_snapshot": hunt["query"], "columns": hunt["columns"],
        "event_ids": event_ids, "result_count": len(event_ids), "result_sha256": digest(json_bytes(event_ids)),
        "executed_at_utc": _now(), "interpretation": "Hunt matches are observation links, not native incidents, attack stages, or risk inputs."}
    ensure_tables(store)
    with store.connection() as conn:
        conn.execute("INSERT INTO hunt_executions VALUES(?,?,?,?,?,?,?)", (execution_id, hunt_id, hunt["revision"],
            analysis_run_id, body["executed_at_utc"], body["result_sha256"], json.dumps(body, ensure_ascii=False, separators=(",", ":"))))
    return body


def list_hunts(store, cursor=0, limit=20):
    if cursor < 0 or not 1 <= limit <= 100: raise ValueError("Hunt page exceeds limits")
    ensure_tables(store)
    with store.connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM saved_hunts").fetchone()[0]
        rows = conn.execute("SELECT body FROM saved_hunts ORDER BY updated DESC,id LIMIT ? OFFSET ?", (limit, cursor)).fetchall()
    return {"items": [json.loads(row[0]) for row in rows], "total": total,
            "next_cursor": cursor + limit if cursor + limit < total else None}


def hunt_executions(store, hunt_id, cursor=0, limit=20):
    _load(store, hunt_id)
    if cursor < 0 or not 1 <= limit <= 100: raise ValueError("Hunt execution page exceeds limits")
    ensure_tables(store)
    with store.connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM hunt_executions WHERE hunt_id=?", (hunt_id,)).fetchone()[0]
        rows = conn.execute("SELECT body FROM hunt_executions WHERE hunt_id=? ORDER BY executed DESC,id LIMIT ? OFFSET ?",
                            (hunt_id, limit, cursor)).fetchall()
    items = [json.loads(row[0]) for row in rows]
    # Listing executions is also a read of each linked run; enforce its persisted replay guard here.
    for item in items:
        execution_page(store, hunt_id, item["execution_id"], 0, 1)
    return {"items": items, "total": total,
            "next_cursor": cursor + limit if cursor + limit < total else None}


def execution_page(store, hunt_id, execution_id, cursor=0, limit=50):
    if cursor < 0 or not 1 <= limit <= 200: raise ValueError("Hunt result page exceeds limits")
    ensure_tables(store)
    with store.connection() as conn:
        row = conn.execute("SELECT body,result_sha256,revision,analysis_run_id FROM hunt_executions WHERE id=? AND hunt_id=?",
                            (execution_id, hunt_id)).fetchone()
    if row is None: raise KeyError("hunt execution not found")
    body = json.loads(row["body"])
    run = store.analysis(body["analysis_run_id"])
    guard_run(store, run)
    if (body["view_id"] != run["analysis_run_id"] or body["scope"] != "retained_run"
            or body["analysis_run_id"] != row["analysis_run_id"] or body["hunt_revision"] != row["revision"]
            or body["result_sha256"] != row["result_sha256"]):
        raise ValueError("Saved hunt view identity is invalid")
    revision = _load(store, hunt_id, body["hunt_revision"])
    if (revision["revision"] != body["hunt_revision"] or revision["filter_schema"] != body["filter_schema"]
            or revision["scope"] != body["scope"] or revision["query"] != body["query_snapshot"]
            or revision["columns"] != body["columns"]):
        raise ValueError("Saved hunt execution differs from its immutable query revision")
    event_ids = body["event_ids"]
    if (cursor > len(event_ids) or body["result_count"] != len(event_ids) or len(event_ids) != len(set(event_ids))
            or digest(json_bytes(event_ids)) != body["result_sha256"] or not set(event_ids) <= set(run["event_ids"])):
        raise ValueError("Saved hunt result identity or retained view membership failed verification")
    current = store.events_by_ids(sorted(set(run["event_ids"])))
    expected = [event.event_id for event in sorted((event for event in current if _matches(event, body["query_snapshot"])),
                                                    key=lambda event: (event.event_time_utc, event.event_id))]
    if expected != event_ids:
        raise ValueError("Saved hunt matches differ from reevaluation over the guarded retained view")
    page_ids = event_ids[cursor:cursor + limit]
    events = store.events_by_ids(page_ids)
    next_cursor = cursor + limit if cursor + limit < len(event_ids) else None
    return {**body, "items": [event.model_dump(mode="json") for event in events], "cursor": cursor,
            "next_cursor": next_cursor, "page_count": len(events), "result_count": len(event_ids)}
