"""Evidence-gated ATT&CK summaries and Navigator v4.3 export."""
from datetime import datetime, timezone

from .ingest import digest, json_bytes
from .reports import build_report
from .replay import guard_run

MAPPING_VERSION = "traceguard-evidence-attack-map-2026-10-07-r1"
NAVIGATOR_VERSION = {"navigator": "4.6.5", "layer": "4.3"}
MITRE_ATTRIBUTION = "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."
TECHNIQUES = {
    "T1005": {"name": "Data from Local System", "tactic": "collection",
        "url": "https://attack.mitre.org/techniques/T1005/",
        "condition": "A verified native collection stage with matching file_read evidence in the selected run/frame."},
    "T1052.001": {"name": "Exfiltration over USB", "tactic": "exfiltration",
        "url": "https://attack.mitre.org/techniques/T1052/001/",
        "condition": "A verified complete native chain whose transfer stage contains an explicit matching file_copy_to_usb event."},
}


def _supporting_rows(report, event_ids):
    selected = set(event_ids)
    rows = []
    for evidence in report["evidence"]:
        event = evidence["event"]
        if event["event_id"] not in selected:
            continue
        rows.append({"event_id": event["event_id"], "event_time_utc": event["event_time_utc"],
            "action": event["action"], "source_rows": [{"source_position": source["row_number"],
                "source_row_sha256": source["raw_sha256"], "source_file_sha256": source["file_sha256"]}
                for source in evidence["source_records"]]})
    return rows


def build_attack_view(store, analysis_id):
    run = store.analysis(analysis_id)
    guard_run(store, run)
    eligible = set(run["event_ids"])
    events = {item.event_id: item for item in store.events_by_ids(sorted(eligible))}
    if len(events) != len(eligible):
        raise ValueError("ATT&CK selected run/frame contains missing canonical observations")
    mappings = []
    unrecognized_stages = []
    for incident in store.incidents(analysis_id):
        report = build_report(store, incident["incident_id"], include_raw=False)
        if not report["validation"]["valid"]:
            raise ValueError("ATT&CK evidence mapping requires a valid native incident report")
        stages = {stage["stage_id"]: stage for stage in incident["stages"]}
        for stage_id in stages:
            if stage_id not in {"authentication", "collection", "transfer"}:
                unrecognized_stages.append({"incident_id": incident["incident_id"], "stage_id": stage_id,
                    "interpretation": "Native stage is visible but this release has no ATT&CK mapping for it."})
        collection = stages.get("collection")
        if collection and collection["claim_status"] == "supported_inference":
            ids = sorted(set(collection["evidence_event_ids"]) & eligible)
            supported = [event_id for event_id in ids if events.get(event_id) and events[event_id].action == "file_read"]
            if supported:
                mappings.append({"technique_id": "T1005", "technique_name": TECHNIQUES["T1005"]["name"],
                    "tactic": TECHNIQUES["T1005"]["tactic"], "analysis_run_id": analysis_id,
                    "incident_id": incident["incident_id"], "supporting_stage_ids": ["collection"],
                    "supporting_observation_count": len(set(supported)),
                    "evidence": _supporting_rows(report, supported),
                    "interpretation": "Evidence-linked mapping from a verified native supported local collection stage; not a claim of framework-wide coverage.",
                    "mapping_version": MAPPING_VERSION, "source_url": TECHNIQUES["T1005"]["url"],
                    "source_retrieved_on": "2026-10-07", "criteria": TECHNIQUES["T1005"]["condition"]})
        transfer = stages.get("transfer")
        if incident["decision"] == "incident" and len(stages) == 3 and transfer:
            ids = sorted(set(transfer["evidence_event_ids"]) & eligible)
            supported = [event_id for event_id in ids if events.get(event_id)
                and events[event_id].action == "file_copy_to_usb"
                and events[event_id].destination_type == "removable_media"]
            if supported:
                mappings.append({"technique_id": "T1052.001", "technique_name": TECHNIQUES["T1052.001"]["name"],
                    "tactic": TECHNIQUES["T1052.001"]["tactic"], "analysis_run_id": analysis_id,
                    "incident_id": incident["incident_id"], "supporting_stage_ids": ["authentication", "collection", "transfer"],
                    "supporting_observation_count": len(set(supported)),
                    "evidence": _supporting_rows(report, supported),
                    "interpretation": "Evidence-linked mapping from verified matching transfer evidence inside a complete native chain; a USB mount alone is insufficient.",
                    "mapping_version": MAPPING_VERSION, "source_url": TECHNIQUES["T1052.001"]["url"],
                    "source_retrieved_on": "2026-10-07", "criteria": TECHNIQUES["T1052.001"]["condition"]})
    mappings.sort(key=lambda item: (item["technique_id"], item["incident_id"]))
    present = {item["technique_id"] for item in mappings}
    missing = []
    for technique_id, spec in TECHNIQUES.items():
        if technique_id not in present:
            missing.append({"technique_id": technique_id, "technique_name": spec["name"],
                "reason": "No qualifying verified native evidence in the selected run/frame.", "criteria": spec["condition"]})
    result = {"view_id": analysis_id, "analysis_run_id": analysis_id,
        "branch_kind": run.get("branch_kind", "legacy"), "cutoff_utc": run["cutoff"],
        "mapping_version": MAPPING_VERSION, "mapping_retrieved_on": "2026-10-07",
        "mappings": mappings, "missing_support": missing, "unmapped_native_stages": unrecognized_stages,
        "external_upstream_labels": {"included": False,
            "interpretation": "Technique labels from external artifacts are retained only on those external findings; they do not create or expand native evidence mappings."},
        "interpretation": "This is a narrow evidence-linked view of selected TraceGuard native findings, not ATT&CK framework coverage or probability.",
        "attribution": MITRE_ATTRIBUTION}
    result["result_sha256"] = digest(json_bytes(result))
    return result


def navigator_layer(store, analysis_id):
    view = build_attack_view(store, analysis_id)
    techniques = []
    for item in view["mappings"]:
        support = item["supporting_observation_count"]
        comment = (f"TraceGuard supporting observation count: {support}; verified native stage(s): "
            f"{', '.join(item['supporting_stage_ids'])}. Navigator score is a capped display count, not risk or confidence. "
            f"Selected view: {analysis_id}; mapping: {item['mapping_version']}; source row hashes are available in TraceGuard.")
        techniques.append({"techniqueID": item["technique_id"], "tactic": item["tactic"],
            "score": min(support, 100), "comment": comment,
            "links": [{"label": "MITRE ATT&CK technique", "url": item["source_url"]}]})
    layer = {"name": "TraceGuard evidence-linked selected view", "versions": dict(NAVIGATOR_VERSION),
        "domain": "enterprise-attack",
        "description": f"Evidence-linked native mappings only. View {analysis_id}; cutoff {view['cutoff_utc']}. Navigator score is capped supporting-observation count, not detection confidence or risk. {MITRE_ATTRIBUTION}",
        "sorting": 3, "layout": {"layout": "side", "showName": True, "showID": True,
            "showAggregateScores": False}, "hideDisabled": False,
        "techniques": techniques,
        "metadata": [{"name": "TraceGuard mapping version", "value": MAPPING_VERSION},
            {"name": "View branch", "value": view["branch_kind"]},
            {"name": "Selected cutoff UTC", "value": view["cutoff_utc"]},
            {"name": "Score semantics", "value": "Capped distinct supporting observation count; not probability, detection confidence, or risk."}]}
    return layer
