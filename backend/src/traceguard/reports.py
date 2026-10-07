"""Reports rebuilt from immutable runs. Verification compares submitted claims, not just IDs."""
import copy
import json
from datetime import datetime, timezone

from .context import calibration_status
from .hybrid import verify_incident

REPORT_VERSION = "traceguard-report-v1"
LIMITATIONS = ["Narrow known USB chain; synthetic evaluation does not establish generalization",
    "Account involvement does not identify a human attacker or prove intent",
    "Hashes check consistency with retained material, not source-system truthfulness",
    "Authorizations are operator declarations; no remediation is executed",
    "Anomaly percentiles are rarity measures, not compromise probabilities"]
OMITTED = ["file_path","process_name","src_ip","dst_ip","domain","geo_country","geo_latitude","geo_longitude"]


def build_report(store, incident_id, include_raw=False):
    item = store.incident(incident_id)
    run = store.analysis(item["analysis_run_id"])
    from .replay import guard_run
    guard_run(store, run)
    validation = verify_incident(store, incident_id)
    if not validation["valid"]:
        raise ValueError("Report evidence verification failed: " + str(validation["errors"] + validation.get("graph",{}).get("errors",[])))
    history = sorted({eid for s in item["stages"] for eid in (s["historical_comparison"] or {}).get("history_event_ids",[])})
    evidence = []
    cache = {}
    for eid in sorted(set(item["selected_evidence"]) | set(history)):
        record = store.evidence(eid,cache)
        snapshot_refs = run.get("evidence_reference_snapshot",{}).get(eid)
        if snapshot_refs is not None:
            record["source_records"] = [r for r in record["source_records"] if r["ref"] in snapshot_refs]
            if sorted(r["ref"] for r in record["source_records"]) != sorted(snapshot_refs):
                raise ValueError("Retained run source reference missing")
        if not include_raw:
            for field in OMITTED:
                record["event"].pop(field,None)
            for source in record["source_records"]:
                source.pop("raw",None)
                source.pop("filename",None)
        evidence.append(record)
    metadata = run.get("baseline_snapshot")
    result = {"report_version":REPORT_VERSION,"incident":item,
        "run":{key:run.get(key) for key in ("schema_version","analysis_run_id","dataset_id","dataset_fingerprint","cutoff","origin","seed","mode","baseline_id","rule_version","config","resource_context_snapshot","alias_context_snapshot","authorization_context_snapshot","context_policy_version")},
        "baseline":{k:metadata.get(k) for k in ("baseline_id","model_version","feature_version","feature_names","preprocessing","versions","training_start","training_end","calibration_start","calibration_end","training_fingerprint","calibration_fingerprint","training_window_count","calibration_sample_size","model_sha256")} if metadata else None,
        "calibration":run.get("calibration",calibration_status(metadata)),
        "evidence":evidence,"history_event_ids":history,
        "privacy":{"include_raw":include_raw,"omitted_fields":[] if include_raw else ["source_records.raw","source_records.filename"]+OMITTED,
            "verification_implications":"Omitted raw/private fields cannot be independently inspected in this file; local verification resolves full retained originals. Scoped canonical IDs remain necessary for claim verification.",
            "reference_scope":"frozen run references" if "evidence_reference_snapshot" in run else "legacy run: reference snapshot unavailable; current retained references"},
        "validation":{**validation,"checked_at_utc":datetime.now(timezone.utc).isoformat(),"scope":"stage/source/risk/context checks against retained local material"},
        "limitations":LIMITATIONS}
    if run.get('branch_kind') == 'retrospective_replay':
        result['replay_manifest'] = copy.deepcopy(run['replay_manifest'])
        result['limitations'] = LIMITATIONS + ['Retrospective event-time replay with fixed parent context; not historical analyst knowledge or live monitoring']
    return result


def verify_report(store, submitted):
    if isinstance(submitted, dict) and submitted.get("report_version") == "traceguard-sensitivity-v1":
        from .sensitivity import verify_comparison
        return verify_comparison(store, submitted)
    errors = []
    try:
        if not isinstance(submitted,dict):
            raise ValueError("report must be a JSON object")
        if submitted.get("report_version") != REPORT_VERSION:
            raise ValueError("unsupported report version")
        privacy = submitted["privacy"]
        if type(privacy["include_raw"]) is not bool:
            raise ValueError("include_raw must be boolean")
        stamp = datetime.fromisoformat(submitted["validation"]["checked_at_utc"])
        if stamp.tzinfo is None or stamp > datetime.now(timezone.utc):
            raise ValueError("invalid verification check time")
        expected = build_report(store,submitted["incident"]["incident_id"],privacy["include_raw"])
        actual = copy.deepcopy(submitted)
        expected["validation"].pop("checked_at_utc")
        actual["validation"].pop("checked_at_utc")
        if actual != expected:
            errors.append("Submitted report claims, evidence, run, context, risk, recommendations or metadata differ from retained snapshot")
    except (KeyError,ValueError,TypeError) as exc:
        errors.append(str(exc))
    return {"valid":not errors,"errors":errors,"checked_at_utc":datetime.now(timezone.utc).isoformat()}


def markdown_report(report):
    # Literal JSON blocks escape all untrusted strings and make the Markdown a verifiable container.
    # Backticks become JSON unicode escapes so log content cannot close the code fence.
    item = report["incident"]
    lines = ["# TraceGuard incident report", "", "Account involvement is not proof of human identity or intent.",
        "", "## Observed stages"]
    for stage in item["stages"]:
        lines.append("- " + stage["stage_id"] + ": " + stage["claim_status"] + " at " + stage["start_time_utc"])
    lines += ["", "## Run and decision", "",
        "Incident: " + item["incident_id"], "Run: " + report["run"]["analysis_run_id"],
        "Mode: " + item["mode"] + "; decision: " + item["decision"],
        "Cutoff UTC: " + report["run"]["cutoff"],
        "Heuristic risk: " + str(item["risk"]["score"]) + "; threshold: " + str(item["risk"].get("threshold")),
        "Incident threshold status: " + report["calibration"]["incident_threshold"]["status"],
        "Evidence checks: passed at " + report["validation"]["checked_at_utc"],
        "", "## Interpretation and unknowns", "", "Supported suspected chain; human intent and credential compromise are unknown.",
        "", "## Response review", "", "Every suggestion requires an authorized human; no approval or execution is recorded.",
        "", "## Verifiable report payload", "", "```traceguard-json",
        json.dumps(report,ensure_ascii=True,indent=2).replace("`", "\\u0060").replace("<", "\\u003c").replace(">", "\\u003e"), "```", ""]
    response_lines = []
    for suggestion in item.get("recommendations",[]):
        response_lines.append("- " + suggestion["suggestion"] + ". Support: " + suggestion["supporting_observation"] + "; cited events: " + ", ".join(suggestion["evidence_event_ids"]))
    response_lines += ["", "## Limitations", ""] + ["- " + value for value in report["limitations"]]
    index = lines.index("## Verifiable report payload")
    lines[index:index] = response_lines + [""]
    return "\n".join(lines)


def read_report(text):
    if text.lstrip().startswith("{"):
        return json.loads(text)
    marker = "```traceguard-json\n"
    if text.count(marker) != 1:
        raise ValueError("Markdown requires one verifiable report payload")
    prefix, payload = text.split(marker)
    raw, suffix = payload.split("\n```",1)
    report = json.loads(raw)
    # Verify surrounding prose too; an altered Markdown stage claim must fail.
    if markdown_report(report) != text:
        raise ValueError("Markdown claims differ from its report payload")
    return report
