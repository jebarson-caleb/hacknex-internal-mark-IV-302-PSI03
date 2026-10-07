"""Small safe Sigma-compatible subset evaluated over guarded retained observations."""
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid4

import yaml
from yaml.events import AliasEvent
from yaml.nodes import MappingNode, ScalarNode

from .ingest import digest, json_bytes
from .replay import guard_run

MAX_RULE_BYTES = 64 * 1024
MAX_YAML_DEPTH = 20
MAX_YAML_NODES = 2000
MAX_SELECTION_FIELDS = 40
MAX_LIST_VALUES = 50
LOGSOURCE = {"product": "traceguard", "service": "canonical_observation"}
TEXT_FIELDS = {"source_type", "action", "outcome", "user_id", "device_id", "app_id", "session_id", "src_ip", "dst_ip",
    "domain", "file_path", "file_hash", "resource_id", "resource_scope", "destination_type", "removable_device_id",
    "process_name", "geo_country"}
INTEGER_FIELDS = {"bytes_read", "bytes_written", "bytes_sent", "process_id"}
SIGMA_FIELDS = TEXT_FIELDS | INTEGER_FIELDS
MODIFIERS = {"contains", "startswith", "endswith"}
TOP_LEVEL = {"title", "id", "related", "status", "description", "license", "references", "author", "date", "modified",
    "logsource", "detection", "fields", "falsepositives", "level", "tags", "scope", "timeframe", "correlation", "rule"}
REQUIRED = {"title", "id", "status", "description", "author", "references", "logsource", "detection", "level"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
STATUSES = {"experimental", "test", "stable", "deprecated", "unsupported"}


class BoundedSafeLoader(yaml.SafeLoader):
    """SafeLoader with a closed alias policy, duplicate-key rejection and tree limits."""
    def __init__(self, stream):
        super().__init__(stream)
        self._traceguard_depth = 0
        self._traceguard_nodes = 0

    def compose_node(self, parent, index):
        if self.check_event(AliasEvent):
            raise ValueError("YAML aliases are unsupported")
        self._traceguard_nodes += 1
        self._traceguard_depth += 1
        if self._traceguard_nodes > MAX_YAML_NODES:
            raise ValueError("YAML exceeds the 2,000-node limit")
        if self._traceguard_depth > MAX_YAML_DEPTH:
            raise ValueError("YAML exceeds the 20-level nesting limit")
        try:
            return super().compose_node(parent, index)
        finally:
            self._traceguard_depth -= 1

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, MappingNode):
            raise ValueError("Expected a YAML mapping")
        seen = set()
        for key_node, _ in node.value:
            if not isinstance(key_node, ScalarNode):
                raise ValueError("YAML mapping keys must be scalar strings")
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise ValueError("YAML mapping keys must be strings")
            if key == "<<":
                raise ValueError("YAML merge keys are unsupported")
            if key in seen:
                raise ValueError(f"Duplicate YAML key: {key}")
            seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _text(value, label, maximum):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise ValueError(f"Sigma {label} must be nonblank and at most {maximum} characters")
    return value


def parse_rule(yaml_text):
    if not isinstance(yaml_text, str) or len(yaml_text.encode("utf-8")) > MAX_RULE_BYTES:
        raise ValueError("Sigma YAML must be UTF-8 text no larger than 64 KiB")
    if "\x00" in yaml_text:
        raise ValueError("Sigma YAML cannot contain NUL bytes")
    try:
        rule = yaml.load(yaml_text, Loader=BoundedSafeLoader)
    except ValueError:
        raise
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid safe YAML: {exc}") from exc
    if not isinstance(rule, dict):
        raise ValueError("Sigma rule root must be a mapping")
    unknown = set(rule) - TOP_LEVEL
    missing = REQUIRED - set(rule)
    if unknown: raise ValueError("Unsupported Sigma rule fields: " + ", ".join(sorted(unknown)))
    if missing: raise ValueError("Sigma rule is missing required fields: " + ", ".join(sorted(missing)))
    title = _text(rule["title"], "title", 120)
    description = _text(rule["description"], "description", 1000)
    author = _text(rule["author"], "author", 120)
    rule_id = _text(rule["id"], "ID", 36)
    try:
        if str(UUID(rule_id)) != rule_id.lower(): raise ValueError()
    except (ValueError, AttributeError) as exc:
        raise ValueError("Sigma id must be a UUID") from exc
    if not isinstance(rule["status"], str) or rule["status"] not in STATUSES: raise ValueError("Unsupported Sigma rule status")
    if not isinstance(rule["level"], str) or rule["level"] not in LEVELS: raise ValueError("Unsupported Sigma rule level")
    references = rule["references"]
    if not isinstance(references, list) or not references or len(references) > 20 or any(not isinstance(ref, str) or not ref.strip() for ref in references):
        raise ValueError("Sigma references must contain 1 to 20 nonblank source strings")
    logsource = rule["logsource"]
    if not isinstance(logsource, dict) or logsource != LOGSOURCE:
        raise ValueError("Unsupported Sigma logsource; map explicitly to product=traceguard, service=canonical_observation")
    detection = rule["detection"]
    if not isinstance(detection, dict) or set(detection) != {"selection", "condition"}:
        raise ValueError("Supported Sigma detection requires one selection and one condition")
    if detection["condition"] != "selection":
        raise ValueError("Sigma condition must be exactly the single name 'selection'")
    selection = detection["selection"]
    if not isinstance(selection, dict) or not 1 <= len(selection) <= MAX_SELECTION_FIELDS:
        raise ValueError("Sigma selection must contain 1 to 40 allowlisted fields")
    normalized = []
    for expression, expected in selection.items():
        if not isinstance(expression, str): raise ValueError("Sigma field expressions must be strings")
        parts = expression.split("|")
        if len(parts) > 2 or parts[0] not in SIGMA_FIELDS:
            raise ValueError(f"Unsupported Sigma canonical field expression: {expression}")
        field, modifier = parts[0], (parts[1] if len(parts) == 2 else None)
        if modifier is not None and (modifier not in MODIFIERS or field not in TEXT_FIELDS):
            raise ValueError(f"Unsupported Sigma modifier or field combination: {expression}")
        values = expected if isinstance(expected, list) else [expected]
        if not 1 <= len(values) <= MAX_LIST_VALUES:
            raise ValueError("Sigma OR lists must contain 1 to 50 scalar values")
        typed = []
        for item in values:
            if field in INTEGER_FIELDS:
                if isinstance(item, bool) or not isinstance(item, int): raise ValueError(f"{field} requires an integer equality value")
                typed.append(item)
            else:
                if not isinstance(item, str): raise ValueError(f"{field} requires a string equality value")
                if "*" in item or "?" in item or "\\" in item:
                    raise ValueError("Sigma wildcards and escaping are unsupported")
                typed.append(_text(item, "selection value", 500))
        normalized.append({"expression": expression, "field": field, "modifier": modifier, "values": typed})
    # Validate known optional metadata so ignored fields cannot silently broaden rule meaning.
    for key in ("tags", "fields", "falsepositives"):
        if key in rule and (not isinstance(rule[key], list) or len(rule[key]) > 50 or any(not isinstance(v, str) for v in rule[key])):
            raise ValueError(f"Sigma {key} metadata must be a list of at most 50 strings")
    for key in ("license", "date", "modified", "scope", "timeframe"):
        if key in rule and not isinstance(rule[key], str): raise ValueError(f"Sigma {key} metadata must be a string")
    if "related" in rule and not isinstance(rule["related"], list): raise ValueError("Sigma related metadata must be a list")
    if any(key in rule for key in ("correlation", "rule", "scope", "timeframe")):
        raise ValueError("Sigma correlations, nested rule expressions, scopes, and timeframes are unsupported")
    canonical = {"id": rule_id, "title": title, "description": description, "author": author,
        "status": rule["status"], "references": references, "logsource": LOGSOURCE, "level": rule["level"],
        "selection": normalized}
    return {"rule": canonical, "yaml_text": yaml_text, "rule_sha256": digest(yaml_text.encode("utf-8"))}


def ensure_tables(store):
    with store.connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS sigma_rules (
                id TEXT PRIMARY KEY, revision INTEGER NOT NULL, updated TEXT NOT NULL, body TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS sigma_rule_revisions (
                rule_id TEXT NOT NULL, revision INTEGER NOT NULL, rule_sha256 TEXT NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY(rule_id,revision));
            CREATE TABLE IF NOT EXISTS sigma_hunt_executions (
                id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, revision INTEGER NOT NULL,
                analysis_run_id TEXT NOT NULL, result_sha256 TEXT NOT NULL, body TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS sigma_rule_revisions_no_update
                BEFORE UPDATE ON sigma_rule_revisions BEGIN SELECT RAISE(ABORT,'Sigma rule revisions are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS sigma_rule_revisions_no_delete
                BEFORE DELETE ON sigma_rule_revisions BEGIN SELECT RAISE(ABORT,'Sigma rule revisions are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS sigma_hunt_executions_no_update
                BEFORE UPDATE ON sigma_hunt_executions BEGIN SELECT RAISE(ABORT,'Sigma hunt executions are immutable'); END;
            CREATE TRIGGER IF NOT EXISTS sigma_hunt_executions_no_delete
                BEFORE DELETE ON sigma_hunt_executions BEGIN SELECT RAISE(ABORT,'Sigma hunt executions are immutable'); END;
        """)
        conn.execute("INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(3,?)",
                     (datetime.now(timezone.utc).isoformat(),))


def _body(parsed, revision, origin):
    return {**parsed, "revision": revision, "origin": origin, "rule_version": "traceguard-sigma-subset-v1"}


def _bundled():
    folder = Path(__file__).parent / "rules" / "sigma"
    return [(path.read_text(encoding="utf-8"), path.name) for path in sorted(folder.glob("*.yml"))]


def register_builtins(store):
    ensure_tables(store)
    for yaml_text, filename in _bundled():
        parsed = parse_rule(yaml_text)
        with store.connection() as conn:
            existing = conn.execute("SELECT 1 FROM sigma_rules WHERE id=?", (parsed["rule"]["id"],)).fetchone()
            if existing: continue
            body = _body(parsed, 1, "bundled-original")
            body["filename"] = filename
            now = datetime.now(timezone.utc).isoformat()
            encoded = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
            conn.execute("INSERT INTO sigma_rules VALUES(?,?,?,?)", (body["rule"]["id"], 1, now, encoded))
            conn.execute("INSERT INTO sigma_rule_revisions VALUES(?,?,?,?)", (body["rule"]["id"], 1, body["rule_sha256"], encoded))


def list_rules(store):
    register_builtins(store)
    with store.connection() as conn:
        ids = [row[0] for row in conn.execute("SELECT id FROM sigma_rules ORDER BY id")]
    return [get_rule(store, rule_id) for rule_id in ids]


def get_rule(store, rule_id, revision=None):
    register_builtins(store)
    with store.connection() as conn:
        current = conn.execute("SELECT revision,body FROM sigma_rules WHERE id=?", (rule_id,)).fetchone() if revision is None else None
        target_revision = current["revision"] if current else revision
        row = conn.execute("SELECT body,rule_sha256 FROM sigma_rule_revisions WHERE rule_id=? AND revision=?",
                           (rule_id, target_revision)).fetchone()
    if row is None: raise KeyError("Sigma rule or immutable revision not found")
    body = json.loads(row["body"])
    parsed = parse_rule(body.get("yaml_text"))
    if (body.get("revision") != target_revision or body.get("rule_sha256") != row["rule_sha256"]
            or parsed["rule_sha256"] != row["rule_sha256"] or parsed["rule"] != body.get("rule")
            or (current is not None and json.loads(current["body"]) != body)):
        raise ValueError("Stored Sigma rule differs from its immutable revision/hash")
    return body


def _store_revision(store, parsed, origin, before=None):
    ensure_tables(store)
    rule_id = parsed["rule"]["id"]
    now = datetime.now(timezone.utc).isoformat()
    with store.connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if before is None:
            row = conn.execute("SELECT id FROM sigma_rules WHERE id=?", (rule_id,)).fetchone()
            if row: raise ValueError("Sigma rule ID already exists; create an explicit new revision instead")
            revision = 1
            body = _body(parsed, revision, origin)
            encoded = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
            conn.execute("INSERT INTO sigma_rules VALUES(?,?,?,?)", (rule_id, revision, now, encoded))
        else:
            current = conn.execute("SELECT revision,body FROM sigma_rules WHERE id=?", (rule_id,)).fetchone()
            if rule_id != before["rule"]["id"]: raise ValueError("A Sigma revision must retain the rule's original ID")
            if current is None or current["revision"] != before["revision"] or json.loads(current["body"]) != before:
                raise ValueError("Sigma rule changed; reload before creating a revision")
            revision = before["revision"] + 1
            body = _body(parsed, revision, origin)
            body["filename"] = before.get("filename")
            encoded = json.dumps(body, ensure_ascii=False, separators=(",", ":"))
            conn.execute("UPDATE sigma_rules SET revision=?,updated=?,body=? WHERE id=?", (revision, now, encoded, rule_id))
        conn.execute("INSERT INTO sigma_rule_revisions VALUES(?,?,?,?)", (rule_id, revision, body["rule_sha256"], encoded))
    return body


def create_rule(store, yaml_text):
    register_builtins(store)
    return _store_revision(store, parse_rule(yaml_text), "locally-authored")


def revise_rule(store, rule_id, expected_revision, yaml_text):
    before = get_rule(store, rule_id)
    if before["revision"] != expected_revision: raise ValueError("Stale Sigma rule revision; reload before editing")
    parsed = parse_rule(yaml_text)
    if parsed["rule"]["id"] != rule_id: raise ValueError("A Sigma revision must keep the original rule ID")
    return _store_revision(store, parsed, before["origin"], before)


def _match_event(event, selection):
    fields = event.model_dump(mode="json")
    matched = {}
    for condition in selection:
        actual = fields.get(condition["field"])
        if actual is None: return None
        def one(expected):
            if condition["modifier"]:
                if not isinstance(actual, str): return False
                left, right = actual.casefold(), expected.casefold()
                return {"contains": lambda: right in left, "startswith": lambda: left.startswith(right),
                        "endswith": lambda: left.endswith(right)}[condition["modifier"]]()
            if isinstance(actual, str) and isinstance(expected, str): return actual.casefold() == expected.casefold()
            return type(actual) is type(expected) and actual == expected
        if not any(one(expected) for expected in condition["values"]): return None
        matched[condition["expression"]] = actual
    return matched


def _hits_for(store, run, rule_body):
    events = store.events_by_ids(sorted(set(run["event_ids"])))
    hits = []
    for event in events:
        fields = _match_event(event, rule_body["rule"]["selection"])
        if fields is not None: hits.append((event, fields))
    hits.sort(key=lambda item: (item[0].event_time_utc, item[0].event_id))
    return [{"event_id": event.event_id, "matched_fields": fields} for event, fields in hits]


def execute_rule(store, rule_id, analysis_run_id, revision=None):
    rule_body = get_rule(store, rule_id, revision)
    run = store.analysis(analysis_run_id)
    guard_run(store, run)
    hits = _hits_for(store, run, rule_body)
    execution_id = uuid4().hex
    hit_hash = digest(json_bytes(hits))
    body = {"execution_id": execution_id, "rule_id": rule_id, "rule_revision": rule_body["revision"],
        "rule_sha256": rule_body["rule_sha256"], "rule_title": rule_body["rule"]["title"],
        "analysis_run_id": analysis_run_id, "view_id": analysis_run_id,
        "scope": "retained_run", "hit_count": len(hits), "hits": hits, "result_sha256": hit_hash,
        "executed_at_utc": datetime.now(timezone.utc).isoformat(),
        "interpretation": "A single-event Sigma-subset hunt match is not a native incident, attack stage, risk score, or probability."}
    with store.connection() as conn:
        conn.execute("INSERT INTO sigma_hunt_executions VALUES(?,?,?,?,?,?)", (execution_id, rule_id,
            rule_body["revision"], analysis_run_id, hit_hash, json.dumps(body, ensure_ascii=False, separators=(",", ":"))))
    return body


def get_execution(store, execution_id):
    ensure_tables(store)
    with store.connection() as conn:
        row = conn.execute("SELECT * FROM sigma_hunt_executions WHERE id=?", (execution_id,)).fetchone()
    if row is None: raise KeyError("Sigma hunt execution not found")
    body = json.loads(row["body"])
    run = store.analysis(body["analysis_run_id"])
    guard_run(store, run)
    rule = get_rule(store, body["rule_id"], body["rule_revision"])
    if (body["analysis_run_id"] != row["analysis_run_id"] or body["rule_id"] != row["rule_id"]
            or body["rule_revision"] != row["revision"] or body["result_sha256"] != row["result_sha256"]
            or rule["rule_sha256"] != body["rule_sha256"] or body["view_id"] != run["analysis_run_id"]):
        raise ValueError("Sigma execution identity or immutable rule revision failed verification")
    expected = _hits_for(store, run, rule)
    if body["hits"] != expected or body["hit_count"] != len(expected) or digest(json_bytes(expected)) != body["result_sha256"]:
        raise ValueError("Sigma hits differ from reevaluation over the guarded retained view")
    return body
