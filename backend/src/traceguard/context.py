"""Operator context decisions; never read approval from uploaded log fields."""
from datetime import datetime


def authorization_checks(candidate, events, entries):
    transfer = next((s for s in candidate.stages if s.stage_id == "transfer"), None)
    by_id = {e.event_id:e for e in events}
    event = by_id[transfer.evidence_event_ids[0]] if transfer else None
    checks = []
    for entry in entries:
        predicates = {"explicit_copy":event is not None,
            "actor":bool(event and entry["user_id"] == event.user_id),
            "endpoint":bool(event and entry["device_id"] == event.device_id),
            "resource":bool(event and entry["resource_id"] == event.resource_id),
            "action":bool(event and entry["action"] == event.action),
            "effective_interval":bool(event and datetime.fromisoformat(entry["effective_from"]) <= event.event_time_utc < datetime.fromisoformat(entry["effective_until"]))}
        checks.append({"context":entry,"predicates":predicates,"matched":all(predicates.values()),
            "evidence_event_ids":[event.event_id] if event else []})
    return {"policy_version":"scoped-copy-v1","checks":checks,"matched":any(c["matched"] for c in checks),
        "reduction":20.0 if any(c["matched"] for c in checks) else 0.0,
        "trust":"Operator-supplied declaration; source not independently verified",
        "policy":"Hybrid subtracts 20 once for an exact time-valid copy authorization; rules-only score is preserved"}


def calibration_status(metadata):
    if not metadata:
        return {"percentile":{"status":"unavailable","sample_count":None},
                "incident_threshold":{"status":"rules_only_structural","threshold_origin":"rules-only structural policy","population_guarantee":False}}
    # Old artifacts remain unchanged. Missing explicit status is unknown.
    risk = metadata.get("risk_calibration", {})
    return {"percentile":metadata.get("percentile_calibration", {"status":"unknown", "sample_count":metadata.get("calibration_sample_size"),"method":metadata.get("percentile_method")}),
        "incident_threshold":{**risk,"status":risk.get("status","unknown"),
            "threshold_origin":risk.get("threshold_origin","unknown"),"population_guarantee":False}}


def recommendations(candidate):
    stages = {s.stage_id:s for s in candidate.stages}
    items = []
    for kind, text in (("authentication","Review the account's sessions and confirm the observed authentication with the account owner"),
                       ("collection","Contact the relevant asset owner and verify business authorization for the observed sensitive-resource access"),
                       ("transfer","Verify authorization for the explicit matching copy to removable media")):
        if kind in stages:
            stage = stages[kind]
            items.append({"suggestion":text,"supporting_observation":stage.stage_name,
                "evidence_event_ids":stage.evidence_event_ids,"requires_authorized_human_review":True,"approval_status":"not_recorded"})
    items.append({"suggestion":"Preserve the cited source records through the organization's evidence process",
        "supporting_observation":"Retained records support the asserted stages", "evidence_event_ids":candidate.selected_evidence,
        "requires_authorized_human_review":True,"approval_status":"not_recorded"})
    return items
