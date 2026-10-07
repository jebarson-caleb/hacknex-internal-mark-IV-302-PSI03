"""Inspectible heuristic. Structural/evidence gates always precede numeric risk."""
from .schemas import Incident


def score_candidate(candidate: Incident, windows: list[dict], *, link_strength: float = 1.0,
                    threshold: float = 80.0, baseline_id: str | None = None, authorization: dict | None = None,
                    calibration: dict | None = None) -> dict:
    relevant = [w for w in windows if set(w["event_ids"]) & set(candidate.selected_evidence) and w.get("anomaly_percentile") is not None]
    anomaly = max((w["anomaly_percentile"] for w in relevant), default=0.0)
    complete = len(candidate.stages) == 3
    copy = candidate.stages[-1].matched_fields if complete else {}
    impact = min((copy.get("bytes_written") or 0) / (1024 * 1024),1.0) if complete else 0.0
    reduction = authorization["reduction"] if authorization else 0.0
    components = {"C":len(candidate.stages)/3,"A":anomaly,"L":link_strength,"I":impact,"B":reduction}
    terms = {"completeness":50*components["C"],"anomaly":20*anomaly,"linkage":20*link_strength,"impact":10*impact,"benign_reduction":-reduction}
    score = max(0.0,min(100.0,sum(terms.values())))
    return {"label":"heuristic; not a probability", "policy_version":"hybrid-v2" if authorization is not None else "hybrid-v1", "components":components,
            "weighted_terms":terms,"score":score,"threshold":threshold,"calibrated": bool(calibration and calibration["incident_threshold"].get("status") == "empirical_budget_met"),
            "anomaly_score":None,"anomaly_percentile":anomaly if relevant else None,
            "baseline_version":baseline_id,"window_evidence":[w for w in relevant],
            "impact_policy":"bytes transferred from matching trusted sensitive resource; capped bytes / 1 MiB",
            "benign_policy":authorization["policy"] if authorization else "B=0; no scoped context supplied",
            **({"calibration":calibration} if calibration is not None else {}),
            "missing_components":[] if relevant else ["No closed non-cold-start scored window"]}
