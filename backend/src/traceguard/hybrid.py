"""Phase 2 orchestration. No evaluation imports and no automatic fitting."""
from datetime import datetime, timezone
from uuid import uuid4

from .context import authorization_checks, calibration_status, recommendations
from .baseline import closed_cutoff, load_baseline, score_windows
from .detection import CONFIG, analyze, correlate, validate_evidence
from .features import build_features
from .graph import build_graph, graph_payload, validate_graph
from .ingest import digest, event_content, json_bytes
from .resolution import resolve_events
from .risk import score_candidate
from .schemas import Incident
from .storage import Store


def run_analysis(store: Store, dataset_id: str, *, mode: str = "rules-only",
                 baseline_id: str | None = None, cutoff: datetime | None = None) -> dict:
    if mode not in {"rules-only","hybrid"}:
        raise ValueError("analysis mode must be rules-only or hybrid")
    if mode == "hybrid" and not baseline_id:
        raise ValueError("hybrid mode requires an explicitly selected fitted baseline; use rules-only instead")
    if baseline_id is None:
        return analyze(store,dataset_id,cutoff)
    artifact = load_baseline(store,baseline_id)
    metadata = artifact.metadata
    dataset = store.dataset(dataset_id)
    if dataset["environment"] != metadata["environment"]:
        raise ValueError("baseline environment does not match dataset")
    raw_events = store.events(dataset_id)
    cutoff = cutoff or closed_cutoff(raw_events)
    if cutoff.tzinfo is None:
        raise ValueError("analysis cutoff requires an explicit timezone")
    calibration_end = datetime.fromisoformat(metadata["calibration_end"])
    if cutoff < calibration_end or any(e.event_time_utc < calibration_end for e in raw_events if e.event_time_utc <= cutoff):
        raise ValueError("future-trained/calibrated baseline cannot analyze earlier or overlapping data")
    raw_events = [e for e in raw_events if e.event_time_utc <= cutoff]
    raw_history = store.events_by_ids(metadata["training_event_ids"])
    aliases = store.aliases(dataset["environment"])
    events,links,resolution_warnings = resolve_events(raw_events,aliases)
    # Freeze training identity interpretation with the fitted artifact.
    history,_,_ = resolve_events(raw_history,metadata["alias_snapshot"])
    resources = store.resources(dataset_id)
    authorizations = store.authorizations(dataset_id)
    batch = build_features(events,metadata["history_snapshot"],cutoff,resources)
    windows = score_windows(batch,artifact) if mode == "hybrid" else []
    graph = build_graph(events,links)
    run_id = uuid4().hex
    candidates = correlate(events,resources,dataset_id,run_id,history,baseline_id)
    source_cache = store.provenance_batch(raw_events+raw_history)
    warnings = sorted(set(batch.warnings+resolution_warnings+[
        "Heuristic risk and synthetic calibration are not compromise probabilities or real-world guarantees",
        "Log self-approval is ignored; scoped authorization is operator-declared, not independently verified"]))
    quality = store.quality(dataset_id)
    if quality["rejected"]:
        warnings.append(f"{quality['rejected']} source records quarantined")
    if not raw_events:
        warnings.append("Empty dataset at analysis cutoff")
    for candidate in candidates:
        candidate.mode = mode
        candidate.risk["baseline_version"] = baseline_id
        candidate.entity_resolution = [link for link in links if link["event_id"] in candidate.selected_evidence]
        candidate.validation = validate_evidence(candidate,events,resources,store,history,baseline_id,source_cache)
        graph_result = validate_graph(candidate,graph,events)
        candidate.validation["graph"] = graph_result
        if not candidate.validation["valid"] or not graph_result["valid"]:
            raise ValueError("candidate evidence or required typed graph linkage failed validation")
        candidate.authorization = authorization_checks(candidate,events,authorizations)
        candidate.recommendations = recommendations(candidate)
        if mode == "hybrid":
            threshold = metadata["risk_calibration"]["threshold"]
            candidate.risk = score_candidate(candidate,windows,link_strength=0.9 if candidate.entity_resolution else 1.0,
                                             threshold=threshold,baseline_id=baseline_id,authorization=candidate.authorization,calibration=calibration_status(metadata))
            if len(candidate.stages)==3 and (candidate.risk["score"] < threshold or candidate.risk["missing_components"]):
                candidate.decision = "review"
                candidate.decision_reason = "Complete supported observations retained below threshold or without a closed scored window"
        candidate.warnings = warnings
    result = {"schema_version":"2","analysis_run_id":run_id,"dataset_id":dataset_id,"mode":mode,"status":"completed",
              "dataset_fingerprint":digest(json_bytes([event_content(e) for e in raw_events])),
              "origin":dataset["origin"],"seed":dataset["seed"],"cutoff":cutoff.isoformat(),
              "baseline_id":baseline_id,"baseline_snapshot":metadata,"history_event_ids":metadata["training_event_ids"],
              "calibration":calibration_status(metadata), "context_policy_version":"scoped-copy-v1",
              "authorization_context_snapshot":authorizations, "alias_context_snapshot":aliases,"resource_context_snapshot":resources,
              "rule_version":"phase1-v1","config":{**CONFIG,"mode":mode,"history_policy":"frozen selected benign baseline",
                 "risk_policy":"hybrid-v2" if mode=="hybrid" else CONFIG["risk_policy"],
                 "threshold":metadata["risk_calibration"]["threshold"] if mode=="hybrid" else 100},
              "event_ids":[e.event_id for e in raw_events],"event_count":len(raw_events),"window_scores":windows,
              "graph_summary":{"nodes":len(graph.nodes),"edges":len(graph.edges),"kind":"correlation/provenance"},
              "incident_count":sum(c.decision=="incident" for c in candidates),
              "partial_count":sum(c.decision=="partial_observation" for c in candidates),
              "review_count":sum(c.decision=="review" for c in candidates),"warnings":warnings}
    store.save_analysis(result,candidates)
    return result


def incident_graph(store: Store, incident_id: str, limit: int = 200) -> dict:
    incident = store.incident(incident_id)
    run = store.analysis(incident["analysis_run_id"])
    raw = [store.event(eid) for eid in incident["selected_evidence"]]
    events,links,_ = resolve_events(raw,run.get("alias_context_snapshot",[]))
    return graph_payload(build_graph(events,links),limit)


def verify_incident(store: Store, incident_id: str) -> dict:
    candidate = Incident.model_validate(store.incident(incident_id))
    run = store.analysis(candidate.analysis_run_id)
    raw_events = store.events_by_ids(run["event_ids"])
    events,links,_ = resolve_events(raw_events,run.get("alias_context_snapshot",[]))
    metadata = run.get("baseline_snapshot")
    history = None
    version = "prior-UTC-days-v1"
    if metadata:
        history,_,_ = resolve_events(store.events_by_ids(metadata["training_event_ids"]),metadata["alias_snapshot"])
        version = metadata["baseline_id"]
    result = validate_evidence(candidate,events,run["resource_context_snapshot"],store,history,version,
                               store.provenance_batch(events+(history or []), run.get('view_snapshot',{}).get('source_references')))
    if digest(json_bytes([event_content(e) for e in raw_events])) != run["dataset_fingerprint"]:
        result["errors"].append("dataset fingerprint differs from immutable run")
    result["graph"] = validate_graph(candidate,build_graph(events,links),events)
    if candidate.mode == "hybrid":
        kwargs = {}
        if candidate.risk.get("policy_version") == "hybrid-v2":
            kwargs = {"authorization":authorization_checks(candidate,events,run.get("authorization_context_snapshot",[])),
                      "calibration":calibration_status(metadata)}
        expected = score_candidate(candidate,run["window_scores"],link_strength=0.9 if candidate.entity_resolution else 1.0,
                                   threshold=metadata["risk_calibration"]["threshold"],baseline_id=version,**kwargs)
        if candidate.risk.get("policy_version") == "hybrid-v1":
            expected["calibrated"] = True
            expected["benign_policy"] = "B=0; scoped authorization reduction is Phase 3"
        expected_decision = "partial_observation" if len(candidate.stages)<3 else "review" if expected["score"]<expected["threshold"] or expected["missing_components"] else "incident"
        if candidate.decision != expected_decision:
            result["errors"].append("decision differs from evidence and threshold policy")
        if expected != candidate.risk:
            result["errors"].append("risk breakdown differs from immutable run")
    if candidate.mode == "rules-only":
        rebuilt = correlate(events,run["resource_context_snapshot"],candidate.dataset_id,candidate.analysis_run_id,history,version)
        matching = next((c for c in rebuilt if c.selected_evidence==candidate.selected_evidence),None)
        if matching:
            matching.risk["baseline_version"] = run.get("baseline_id")
        if not matching or matching.risk != candidate.risk:
            result["errors"].append("rules-only risk differs from structured facts")
    if run.get("context_policy_version"):
        if candidate.authorization != authorization_checks(candidate,events,run.get("authorization_context_snapshot",[])):
            result["errors"].append("authorization differs from immutable context snapshot")
        if candidate.recommendations != recommendations(candidate):
            result["errors"].append("recommendations differ from verified structured facts")
    result["valid"] = not result["errors"] and result["graph"]["valid"]
    return result
