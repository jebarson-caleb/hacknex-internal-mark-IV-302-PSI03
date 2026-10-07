"""Local case workflow as audited sidecar state, separate from detector outputs."""
import copy
import json
import re
from datetime import datetime, timezone
from uuid import uuid4

from .ingest import digest, json_bytes
from .reports import build_report, verify_report

CASE_VERSION = "traceguard-case-v1"
EXPORT_VERSION = "traceguard-case-export-v1"
STATUSES = ("open", "investigating", "resolved", "closed")
PRIORITIES = ("low", "normal", "high", "urgent")
DISPOSITIONS = ("undetermined", "suspicious", "benign", "insufficient_evidence")
TASK_STATUSES = ("todo", "in_progress", "done")
MAX_CASE_PAGE = 100
MAX_LIST_ITEMS = 500


class RevisionConflict(ValueError):
    """An optimistic revision check failed; retry from the displayed record."""


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def _validate_text(value, label, maximum, *, empty=False):
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value.strip()):
        raise ValueError(f"{label} must be {'at most' if empty else 'nonblank and at most'} {maximum} characters")
    if re.search(r"<\s*/?\s*script\b|javascript\s*:", value, re.IGNORECASE):
        raise ValueError(f"{label} cannot contain script-bearing text")
    return value


def _guard_run(store, run_id):
    run = store.analysis(run_id)
    from .replay import guard_run
    guard_run(store, run)
    return run


def _guard_case_body(store, body):
    """Recheck each run/frame before returning any evidence-linked sidecar."""
    runs = {item["analysis_run_id"] for item in body.get("linked_incidents", [])}
    runs.update(item["analysis_run_id"] for item in body.get("bookmarks", []))
    for run_id in sorted(runs):
        _guard_run(store, run_id)
    from .external_findings import get_finding
    for item in body.get("external_findings", []):
        retained = get_finding(store, item["finding_id"])
        if retained["artifact_id"] != item["artifact_id"] or retained["raw_row_sha256"] != item["raw_row_sha256"]:
            raise ValueError("Case external finding reference differs from its retained source artifact")
    return body


def _create_revision(conn, before, after, operation, author, reason):
    after["revision"] = 1 if before is None else before["revision"] + 1
    after["updated_at_utc"] = utcnow()
    encoded = json.dumps(after, ensure_ascii=False, separators=(",", ":"))
    if before is None:
        conn.execute("INSERT INTO cases VALUES(?,?,?,?,?,?,?)", (after["case_id"], after["title"], after["status"],
            after["priority"], after["revision"], after["updated_at_utc"], encoded))
    conn.execute("INSERT INTO case_revisions VALUES(?,?,?)", (after["case_id"], after["revision"], encoded))
    conn.execute("""INSERT INTO case_audit
        (id,case_id,revision,occurred,operation,author,reason,previous_body,new_body)
        VALUES(?,?,?,?,?,?,?,?,?)""", (uuid4().hex, after["case_id"], after["revision"], after["updated_at_utc"],
        operation, author, reason, json.dumps(before, ensure_ascii=False) if before is not None else None, encoded))
    if before is not None:
        conn.execute("UPDATE cases SET title=?,status=?,priority=?,revision=?,updated=?,body=? WHERE id=?",
            (after["title"], after["status"], after["priority"], after["revision"], after["updated_at_utc"], encoded, after["case_id"]))
    return after


def _load(store, case_id, revision=None):
    with store.connection() as conn:
        if revision is None:
            current = conn.execute("SELECT revision,body FROM cases WHERE id=?", (case_id,)).fetchone()
            row = (conn.execute("SELECT body FROM case_revisions WHERE case_id=? AND revision=?",
                                (case_id, current["revision"])).fetchone() if current else None)
            if current and (row is None or row["body"] != current["body"]):
                raise ValueError("Current case state differs from its latest immutable revision")
        else:
            row = conn.execute("SELECT body FROM case_revisions WHERE case_id=? AND revision=?", (case_id, revision)).fetchone()
    if row is None:
        raise KeyError("case or case revision not found")
    return _guard_case_body(store, json.loads(row[0]))


def _commit(store, before, after, expected_revision, operation, author, reason):
    with store.connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT revision,body FROM cases WHERE id=?", (before["case_id"],)).fetchone()
        if row is None:
            raise KeyError("case not found")
        if row["revision"] != expected_revision:
            raise RevisionConflict(f"Stale case revision {expected_revision}; current revision is {row['revision']}")
        if json.loads(row["body"]) != before:
            raise RevisionConflict("Case changed while this operation was being prepared; reload the case")
        return _create_revision(conn, before, after, operation, author, reason)


def create_case(store, title, description="", priority="normal", assignee="", author="operator"):
    title = _validate_text(title, "title", 200)
    description = _validate_text(description, "description", 4000, empty=True)
    assignee = _validate_text(assignee, "assignee label", 100, empty=True)
    author = _validate_text(author, "author label", 100)
    if priority not in PRIORITIES:
        raise ValueError("Unsupported case priority")
    now = utcnow()
    body = {"case_version": CASE_VERSION, "case_id": uuid4().hex, "title": title, "description": description,
        "priority": priority, "status": "open", "disposition": "undetermined", "closure_rationale": "",
        "assignee": assignee, "tags": [], "created_at_utc": now, "updated_at_utc": now, "revision": 0,
        "linked_incidents": [], "tasks": [], "notes": [], "bookmarks": [], "external_findings": []}
    with store.connection() as conn:
        return _create_revision(conn, None, body, "case_created", author, "Created local investigation case")


def _incident_link(store, incident_id):
    incident = store.incident(incident_id)
    run = _guard_run(store, incident["analysis_run_id"])
    # This validates the actual stage/source predicates before a case can claim a native link.
    report = build_report(store, incident_id, include_raw=False)
    if not report["validation"]["valid"]:
        raise ValueError("Incident report verification failed")
    return {"analysis_run_id": run["analysis_run_id"], "incident_id": incident_id,
        "origin": run.get("origin", "unknown"), "branch_kind": run.get("branch_kind", "legacy"),
        "dataset_id": run["dataset_id"], "summary": incident["summary"],
        "decision": incident["decision"], "linked_at_utc": utcnow(),
        "subreport_sha256": digest(json_bytes(report))}


def create_from_incident(store, incident_id, title="", description="", priority="high", assignee="", author="operator"):
    link = _incident_link(store, incident_id)
    incident = store.incident(incident_id)
    value = create_case(store, title.strip() or incident["summary"], description, priority, assignee, author)
    before = _load(store, value["case_id"])
    after = copy.deepcopy(before)
    after["linked_incidents"].append(link)
    return _commit(store, before, after, before["revision"], "incident_linked", author,
        "Created from a verified immutable incident")


def get_case(store, case_id, revision=None):
    return _load(store, case_id, revision)


def list_cases(store, query="", status=None, priority=None, cursor=0, limit=20):
    if len(query) > 200 or cursor < 0 or not 1 <= limit <= MAX_CASE_PAGE:
        raise ValueError("Case search/page values exceed limits")
    if status is not None and status not in STATUSES:
        raise ValueError("Unsupported case status filter")
    if priority is not None and priority not in PRIORITIES:
        raise ValueError("Unsupported case priority filter")
    clauses, args = [], []
    if status:
        clauses.append("status=?"); args.append(status)
    if priority:
        clauses.append("priority=?"); args.append(priority)
    if query:
        clauses.append("instr(lower(title || ' ' || body), lower(?))>0"); args.append(query)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with store.connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM cases" + where, args).fetchone()[0]
        rows = conn.execute("SELECT body FROM cases" + where + " ORDER BY updated DESC,id LIMIT ? OFFSET ?",
                            (*args, limit, cursor)).fetchall()
    items = [_guard_case_body(store, json.loads(row[0])) for row in rows]
    return {"items": items, "total": total, "next_cursor": cursor + limit if cursor + limit < total else None}


def update_case(store, case_id, expected_revision, changes, author="operator", rationale=""):
    author = _validate_text(author, "author label", 100)
    rationale = _validate_text(rationale, "change rationale", 1000, empty=True)
    before = _load(store, case_id)
    if before["revision"] != expected_revision:
        raise RevisionConflict(f"Stale case revision {expected_revision}; current revision is {before['revision']}")
    after = copy.deepcopy(before)
    allowed = {"title", "description", "priority", "status", "disposition", "assignee", "tags"}
    if not isinstance(changes, dict) or not changes or not set(changes) <= allowed:
        raise ValueError("Case edit must contain only supported, nonempty fields")
    if "title" in changes: after["title"] = _validate_text(changes["title"], "title", 200)
    if "description" in changes: after["description"] = _validate_text(changes["description"], "description", 4000, empty=True)
    if "assignee" in changes: after["assignee"] = _validate_text(changes["assignee"], "assignee label", 100, empty=True)
    if "priority" in changes:
        if changes["priority"] not in PRIORITIES: raise ValueError("Unsupported case priority")
        after["priority"] = changes["priority"]
    if "disposition" in changes:
        if changes["disposition"] not in DISPOSITIONS: raise ValueError("Unsupported human case disposition")
        after["disposition"] = changes["disposition"]
    if "tags" in changes:
        tags = changes["tags"]
        if not isinstance(tags, list) or len(tags) > 30 or len(set(tags)) != len(tags):
            raise ValueError("Tags must be a unique list of at most 30 labels")
        after["tags"] = [_validate_text(tag, "tag", 50) for tag in tags]
    if "status" in changes:
        next_status = changes["status"]
        if next_status not in STATUSES: raise ValueError("Unsupported case status")
        if before["status"] == "closed": raise ValueError("Closed cases require the explicit reopen action")
        allowed_next = {"open": {"open", "investigating"}, "investigating": {"investigating", "resolved"},
                        "resolved": {"resolved", "closed"}}
        if next_status not in allowed_next[before["status"]]:
            raise ValueError("Case workflow transition is not allowed; use the explicit reopen action when reopening")
        if next_status == "closed":
            if not rationale.strip(): raise ValueError("Closing a case requires a human-entered rationale")
            if after["disposition"] == "undetermined":
                raise ValueError("Choose a human disposition before closing the case")
            after["closure_rationale"] = rationale
        after["status"] = next_status
    operation = "case_closed" if after["status"] == "closed" and before["status"] != "closed" else "case_updated"
    return _commit(store, before, after, expected_revision, operation, author,
                   rationale or "Updated case fields")


def reopen_case(store, case_id, expected_revision, reason, author="operator"):
    reason = _validate_text(reason, "reopen rationale", 1000)
    author = _validate_text(author, "author label", 100)
    before = _load(store, case_id)
    if before["revision"] != expected_revision:
        raise RevisionConflict(f"Stale case revision {expected_revision}; current revision is {before['revision']}")
    if before["status"] not in ("resolved", "closed"):
        raise ValueError("Only resolved or closed cases can be explicitly reopened")
    after = copy.deepcopy(before)
    after["status"] = "investigating"
    after["closure_rationale"] = ""
    return _commit(store, before, after, expected_revision, "case_reopened", author, reason)


def add_note(store, case_id, expected_revision, text, author="operator"):
    text = _validate_text(text, "note", 4000)
    author = _validate_text(author, "author label", 100)
    before = _load(store, case_id)
    if len(before["notes"]) >= MAX_LIST_ITEMS: raise ValueError("Case note limit reached")
    after = copy.deepcopy(before)
    after["notes"].append({"note_id": uuid4().hex, "text": text, "author_label": author, "created_at_utc": utcnow()})
    return _commit(store, before, after, expected_revision, "note_added", author, "Added analyst-authored note")


def add_task(store, case_id, expected_revision, title, description="", assignee="", author="operator"):
    title = _validate_text(title, "task title", 200)
    description = _validate_text(description, "task description", 2000, empty=True)
    assignee = _validate_text(assignee, "assignee label", 100, empty=True)
    author = _validate_text(author, "author label", 100)
    before = _load(store, case_id)
    if len(before["tasks"]) >= MAX_LIST_ITEMS: raise ValueError("Case task limit reached")
    after = copy.deepcopy(before)
    after["tasks"].append({"task_id": uuid4().hex, "title": title, "description": description,
        "assignee": assignee, "status": "todo", "completion_note": "", "created_at_utc": utcnow(),
        "updated_at_utc": utcnow()})
    return _commit(store, before, after, expected_revision, "task_added", author, "Added manual review task")


def update_task(store, case_id, task_id, expected_revision, status, completion_note="", author="operator"):
    if status not in TASK_STATUSES: raise ValueError("Unsupported task status")
    completion_note = _validate_text(completion_note, "task completion note", 1000, empty=True)
    author = _validate_text(author, "author label", 100)
    before = _load(store, case_id)
    after = copy.deepcopy(before)
    task = next((item for item in after["tasks"] if item["task_id"] == task_id), None)
    if task is None: raise KeyError("case task not found")
    task.update(status=status, completion_note=completion_note, updated_at_utc=utcnow())
    return _commit(store, before, after, expected_revision, "task_updated", author,
                   "Recorded manual task status; no remediation was executed")


def _source_manifest(store, run, event_id):
    allowed = set(run.get("event_ids", [])) | set(run.get("history_event_ids", []))
    if event_id not in allowed:
        raise ValueError("Bookmark observation is outside the selected run/frame")
    refs = run.get("view_snapshot", {}).get("source_references", {}).get(event_id)
    if not refs:
        raise ValueError("Frozen source references unavailable for this observation")
    event = store.event(event_id)
    errors = store.provenance_batch([event], {event_id: refs})
    if errors.get(event_id):
        raise ValueError("Bookmark source verification failed: " + str(errors[event_id]))
    evidence = store.evidence(event_id)
    records = [row for row in evidence["source_records"] if row["ref"] in refs]
    if sorted(row["ref"] for row in records) != sorted(refs):
        raise ValueError("Frozen bookmark source references are incomplete")
    return [{"source_ref": row["ref"], "source_position": row["row_number"],
        "raw_sha256": row["raw_sha256"], "upload_sha256": row["file_sha256"]} for row in records]


def add_bookmark(store, case_id, expected_revision, run_id, event_id, note="", incident_id="", author="operator"):
    note = _validate_text(note, "bookmark explanation", 1000, empty=True)
    author = _validate_text(author, "author label", 100)
    run = _guard_run(store, run_id)
    source_records = _source_manifest(store, run, event_id)
    if incident_id:
        incident = store.incident(incident_id)
        if incident["analysis_run_id"] != run_id:
            raise ValueError("Bookmark incident and selected run/frame do not match")
    else:
        incident = None
    before = _load(store, case_id)
    if len(before["bookmarks"]) >= MAX_LIST_ITEMS: raise ValueError("Case bookmark limit reached")
    after = copy.deepcopy(before)
    after["bookmarks"].append({"bookmark_id": uuid4().hex, "analysis_run_id": run_id, "dataset_id": run["dataset_id"],
        "incident_id": incident_id or None, "event_id": event_id, "origin": run.get("origin", "unknown"),
        "branch_kind": run.get("branch_kind", "legacy"), "interpretation": "analyst bookmark; not detector evidence",
        "source_records": source_records, "source_manifest_sha256": digest(json_bytes(source_records)),
        "note": note, "author_label": author, "created_at_utc": utcnow()})
    return _commit(store, before, after, expected_revision, "evidence_bookmarked", author,
                   "Bookmarked a verified source observation")


def link_incident(store, case_id, expected_revision, incident_id, author="operator"):
    author = _validate_text(author, "author label", 100)
    link = _incident_link(store, incident_id)
    before = _load(store, case_id)
    if any(item["incident_id"] == incident_id for item in before["linked_incidents"]):
        raise ValueError("Incident is already linked to this case")
    after = copy.deepcopy(before)
    after["linked_incidents"].append(link)
    return _commit(store, before, after, expected_revision, "incident_linked", author,
                   "Linked one immutable report; run graphs remain separate")


def link_external_finding(store, case_id, expected_revision, finding_id, note="", author="operator"):
    from .external_findings import get_finding
    finding = get_finding(store, finding_id)
    note = _validate_text(note, "external finding note", 1000, empty=True)
    author = _validate_text(author, "author label", 100)
    before = _load(store, case_id)
    if any(item["finding_id"] == finding_id for item in before.get("external_findings", [])):
        raise ValueError("External finding is already linked to this case")
    if len(before.get("external_findings", [])) >= MAX_LIST_ITEMS:
        raise ValueError("Case external finding link limit reached")
    after = copy.deepcopy(before)
    after.setdefault("external_findings", []).append({"finding_id": finding_id,
        "artifact_id": finding["artifact_id"], "tool": finding["tool"], "profile": finding["profile"],
        "source_position": finding["source_position"], "raw_row_sha256": finding["raw_row_sha256"],
        "upstream_rule_title": finding.get("upstream_rule_title"), "linked_at_utc": utcnow(),
        "note": note, "author_label": author,
        "interpretation": "External context link; not a canonical observation or detector evidence."})
    return _commit(store, before, after, expected_revision, "external_finding_linked", author,
                   "Linked one retained external source row as analyst context")


def case_audit(store, case_id, cursor=0, limit=50):
    if cursor < 0 or not 1 <= limit <= 100: raise ValueError("Audit page exceeds limits")
    _load(store, case_id)
    with store.connection() as conn:
        total = conn.execute("SELECT COUNT(*) FROM case_audit WHERE case_id=?", (case_id,)).fetchone()[0]
        rows = conn.execute("SELECT * FROM case_audit WHERE case_id=? ORDER BY revision DESC LIMIT ? OFFSET ?",
                            (case_id, limit, cursor)).fetchall()
    items = []
    for row in rows:
        for key in ("previous_body", "new_body"):
            if row[key]: _guard_case_body(store, json.loads(row[key]))
        items.append({"entry_id": row["id"], "case_id": case_id, "revision": row["revision"],
            "occurred_at_utc": row["occurred"], "operation": row["operation"], "author_label": row["author"],
            "reason": row["reason"], "previous": json.loads(row["previous_body"]) if row["previous_body"] else None,
            "current": json.loads(row["new_body"])})
    return {"items": items, "total": total, "next_cursor": cursor + limit if cursor + limit < total else None}


def export_case(store, case_id, revision=None):
    snapshot = _load(store, case_id, revision)
    reports = [build_report(store, link["incident_id"], include_raw=False) for link in snapshot["linked_incidents"]]
    from .external_findings import get_finding
    external = [{key: value for key, value in get_finding(store, link["finding_id"]).items()
                 if key not in {"raw_row", "raw_fields"}} for link in snapshot.get("external_findings", [])]
    return {"export_version": EXPORT_VERSION, "exported_at_utc": utcnow(), "case_snapshot": snapshot,
        "incident_reports": reports, "external_context": external, "privacy": {"include_raw": False,
            "note_truth": "Analyst-authored text is preserved as a statement, not independently verified truth.",
            "reference_scope": "Frozen case revision and individually verified immutable run/frame reports."},
        "validation": {"case_revision_retained": True, "incident_report_count": len(reports),
            "scope": "Local consistency and per-report detector verification; not a signature or external truth proof."}}


def case_markdown(exported):
    snapshot = exported["case_snapshot"]
    lines = ["# TraceGuard case export", "", "Analyst disposition and notes are human statements, not ground truth.",
        "", f"Case: {snapshot['case_id']} · revision {snapshot['revision']}",
        f"Status: {snapshot['status']} · priority: {snapshot['priority']} · disposition: {snapshot['disposition']}",
        f"Linked immutable reports: {len(exported['incident_reports'])}", "",
        "## Verifiable case payload", "", "```traceguard-case-json",
        json.dumps(exported, ensure_ascii=True, indent=2).replace("`", "\\u0060").replace("<", "\\u003c").replace(">", "\\u003e"),
        "```", ""]
    return "\n".join(lines)


def read_case_export(text):
    if text.lstrip().startswith("{"):
        value = json.loads(text)
    else:
        marker = "```traceguard-case-json\n"
        if text.count(marker) != 1: raise ValueError("Markdown requires one verifiable case payload")
        _, payload = text.split(marker, 1)
        raw, suffix = payload.split("\n```", 1)
        value = json.loads(raw)
        if case_markdown(value) != text: raise ValueError("Markdown case claims differ from its payload")
    return value


def verify_case_export(store, submitted):
    errors = []
    try:
        if not isinstance(submitted, dict) or submitted.get("export_version") != EXPORT_VERSION:
            raise ValueError("unsupported case export version")
        snapshot = submitted["case_snapshot"]
        retained = _load(store, snapshot["case_id"], snapshot["revision"])
        if retained != snapshot: errors.append("Submitted case snapshot differs from retained immutable revision")
        _guard_case_body(store, snapshot)
        expected_ids = [link["incident_id"] for link in snapshot["linked_incidents"]]
        reports = submitted.get("incident_reports")
        if not isinstance(reports, list) or [r.get("incident", {}).get("incident_id") for r in reports] != expected_ids:
            errors.append("Case export incident report links differ from the frozen case revision")
        else:
            for report in reports:
                result = verify_report(store, report)
                if not result["valid"]: errors.extend("Incident subreport: " + e for e in result["errors"])
        from .external_findings import get_finding
        expected_external = [{key: value for key, value in get_finding(store, link["finding_id"]).items()
                              if key not in {"raw_row", "raw_fields"}} for link in snapshot.get("external_findings", [])]
        if submitted.get("external_context") != expected_external:
            errors.append("Case export external source rows differ from their retained artifact uploads")
        for bookmark in snapshot.get("bookmarks", []):
            run = _guard_run(store, bookmark["analysis_run_id"])
            sources = _source_manifest(store, run, bookmark["event_id"])
            if sources != bookmark.get("source_records") or digest(json_bytes(sources)) != bookmark.get("source_manifest_sha256"):
                errors.append("Bookmarked source references differ from retained records")
        if submitted.get("privacy", {}).get("include_raw") is not False:
            errors.append("Case exports must keep raw records omitted")
    except (KeyError, ValueError, TypeError) as exc:
        errors.append(str(exc))
    return {"valid": not errors, "errors": errors, "checked_at_utc": utcnow(),
        "scope": "Retained case revision, bookmark source rows, replay guards, and independently verified detector subreports"}
