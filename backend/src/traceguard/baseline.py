"""Explicit local fitting; no inference imports evaluation labels or datasets."""
import importlib.metadata
import pickle
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import numpy as np
import sklearn
from sklearn.ensemble import IsolationForest

from .context import authorization_checks
from .detection import correlate, validate_evidence
from .features import FEATURE_NAMES, FEATURE_VERSION, LOG_FEATURES, FeatureBatch, build_features, history_snapshot, window_start
from .ingest import digest, event_content, json_bytes
from .graph import build_graph, validate_graph
from .resolution import resolve_events
from .risk import score_candidate
from .storage import Store


@dataclass
class BaselineArtifact:
    metadata: dict
    model: IsolationForest


def closed_cutoff(events) -> datetime:
    return max((window_start(e.event_time_utc)+timedelta(minutes=15) for e in events), default=datetime.now(timezone.utc))


def score_windows(batch: FeatureBatch, artifact: BaselineArtifact) -> list[dict]:
    windows = [{**w,"raw_anomaly_score":None,"anomaly_percentile":None} for w in batch.windows]
    selected = [i for i,w in enumerate(windows) if not w["cold_start"] and not w["provisional"]]
    if selected:
        raw = -artifact.model.score_samples(batch.values[selected])
        calibration = np.asarray(artifact.metadata["calibration_distribution"])
        for index,value in zip(selected,raw):
            # Midrank empirical CDF, deterministic with ties; not attack probability.
            left,right = np.searchsorted(calibration,value,side="left"),np.searchsorted(calibration,value,side="right")
            windows[index].update(raw_anomaly_score=float(value),anomaly_percentile=float((left+right)/(2*len(calibration))))
    return windows


def fit_baseline(store: Store, training_dataset_id: str, calibration_dataset_id: str,
                 benign_provenance: str, seed: int = 17) -> dict:
    if not benign_provenance.strip():
        raise ValueError("explicit provenance declaring selected training/calibration data benign is required")
    train_data,cal_data = store.dataset(training_dataset_id),store.dataset(calibration_dataset_id)
    if train_data["environment"] != cal_data["environment"]:
        raise ValueError("training/calibration environment namespaces must match")
    train_raw,cal_raw = store.events(training_dataset_id),store.events(calibration_dataset_id)
    if not train_raw or not cal_raw:
        raise ValueError("insufficient training/calibration data: datasets must be nonempty")
    if closed_cutoff(train_raw) > min(e.event_time_utc for e in cal_raw):
        raise ValueError("training must end before calibration, with non-overlapping closed windows")
    aliases = store.aliases(train_data["environment"])
    train,train_links,train_warnings = resolve_events(train_raw,aliases)
    cal,cal_links,cal_warnings = resolve_events(cal_raw,aliases)
    snapshot = history_snapshot(train)
    calibration_authorizations = store.authorizations(calibration_dataset_id)
    train_resources,cal_resources = store.resources(training_dataset_id),store.resources(calibration_dataset_id)
    train_batch = build_features(train,snapshot,closed_cutoff(train),train_resources)
    cal_batch = build_features(cal,snapshot,closed_cutoff(cal),cal_resources)
    train_indices = [i for i,w in enumerate(train_batch.windows) if not w["cold_start"] and not w["provisional"]]
    cal_indices = [i for i,w in enumerate(cal_batch.windows) if not w["cold_start"] and not w["provisional"]]
    if len(train_indices) < 20 or len(cal_indices) < 20:
        raise ValueError("insufficient history: require at least 20 established closed training and calibration windows")
    source_errors = store.provenance_batch(train_raw+cal_raw)
    if any(source_errors.values()):
        raise ValueError("baseline source validation failed; inspect retained provenance")
    model = IsolationForest(n_estimators=200,max_samples="auto",contamination="auto",random_state=seed,n_jobs=1)
    model.fit(train_batch.values[train_indices])
    distribution = sorted(float(value) for value in -model.score_samples(cal_batch.values[cal_indices]))
    baseline_id = uuid4().hex
    metadata = {"baseline_id":baseline_id,"model_version":"iforest-v1","feature_version":FEATURE_VERSION,
                "feature_names":FEATURE_NAMES,"preprocessing":{"log1p":sorted(LOG_FEATURES),"imputation":"none: explicit missing/cold-start gates"},
                "environment":train_data["environment"],"seed":seed,"benign_provenance":benign_provenance,
                "training_dataset_id":training_dataset_id,"calibration_dataset_id":calibration_dataset_id,
                "training_start":min(e.event_time_utc for e in train).isoformat(),"training_end":closed_cutoff(train).isoformat(),
                "calibration_start":min(e.event_time_utc for e in cal).isoformat(),"calibration_end":closed_cutoff(cal).isoformat(),
                "training_event_ids":[e.event_id for e in train_raw],"calibration_event_ids":[e.event_id for e in cal_raw],
                "training_fingerprint":digest(json_bytes([event_content(e) for e in train_raw])),
                "calibration_fingerprint":digest(json_bytes([event_content(e) for e in cal_raw])),
                "history_snapshot":snapshot,"alias_snapshot":aliases,"training_resource_snapshot":train_resources,
                "calibration_resource_snapshot":cal_resources,"calibration_authorization_snapshot":calibration_authorizations,"training_window_count":len(train_indices),
                "calibration_sample_size":len(distribution),"calibration_distribution":distribution,
                "percentile_method":"midrank empirical CDF of negative score_samples on declared benign calibration windows",
                "model_parameters":model.get_params(), "versions":{"scikit-learn":sklearn.__version__,"numpy":np.__version__,
                    "networkx":importlib.metadata.version("networkx"),"python":sys.version.split()[0]},
                "warnings":sorted(set(train_warnings+cal_warnings+cal_batch.warnings))}
    artifact = BaselineArtifact(metadata,model)
    windows = score_windows(cal_batch,artifact)
    candidates = correlate(cal,cal_resources,calibration_dataset_id,"calibration",train,baseline_id)
    calibration_graph = build_graph(cal,cal_links)
    for candidate in candidates:
        evidence_check = validate_evidence(candidate,cal,cal_resources,store,train,baseline_id,source_errors)
        graph_check = validate_graph(candidate,calibration_graph,cal)
        if not evidence_check["valid"] or not graph_check["valid"]:
            raise ValueError("calibration prediction failed evidence/graph validation")
    clean_units = {(e.user_id,e.device_id,e.event_time_utc.date().isoformat()) for e in cal if e.user_id and e.device_id}
    candidate_scores = [(c,score_candidate(c,windows,baseline_id=baseline_id,authorization=authorization_checks(c,cal,calibration_authorizations),
                        link_strength=0.9 if any(link["event_id"] in c.selected_evidence for link in cal_links) else 1.0))
                        for c in candidates if len(c.stages)==3]
    choices = sorted({80.0} | {r["score"]+1e-8 for _,r in candidate_scores if r["score"] < 100})
    threshold,budget_met = 80.0,False
    def false_units(cut):
        emitted = [c for c,r in candidate_scores if r["score"]>=cut]
        selected = {eid for c in emitted for eid in c.selected_evidence}
        return {(e.user_id,e.device_id,e.event_time_utc.date().isoformat()) for e in cal if e.event_id in selected}
    for choice in choices:
        if len(false_units(choice))/len(clean_units) <= 0.01:
            threshold,budget_met = choice,True; break
    # Never declare a useful threshold by eliminating every candidate when
    # calibration supplies evidence that all complete chains would be suppressed.
    if candidate_scores and not any(r["score"]>=threshold for _,r in candidate_scores):
        threshold,budget_met = 80.0,False
    metadata["risk_calibration"] = {"threshold":threshold,"target_fpr":0.01,"budget_met":budget_met if candidate_scores else None,
        "empirical_rate_within_target":budget_met,
        "benign_units":len(clean_units),"false_positive_units":len(false_units(threshold)),
        "complete_candidates":len(candidate_scores),"selection":"lowest >=80 candidate boundary meeting proposed 1% budget; never hide all complete candidates",
        "warning":"Synthetic/operator-declared benign calibration; not a population guarantee"}
    if not candidate_scores:
        metadata["risk_calibration"]["warning"] += "; no complete benign calibration candidates, so structural floor 80 is retained"
    metadata["percentile_calibration"] = {"status":"available", "sample_count":len(distribution),
        "method":metadata["percentile_method"]}
    metadata["risk_calibration"].update(
        status="insufficient_complete_candidates" if not candidate_scores else ("empirical_budget_met" if budget_met else "budget_not_met"),
        threshold_origin="structural_fallback" if not candidate_scores or not budget_met else "benign_calibration_candidate_boundary",
        fallback_reason="Insufficient complete benign candidates; structural fallback threshold used" if not candidate_scores
            else (None if budget_met else "No useful candidate threshold meets proposed budget"),
        population_guarantee=False)
    metadata["anomaly_threshold"] = float(np.quantile(distribution,0.99,method="higher"))
    store.save_baseline(metadata,pickle.dumps(model,protocol=5))
    return metadata


def load_baseline(store: Store, baseline_id: str) -> BaselineArtifact:
    metadata,blob = store.baseline(baseline_id)
    if (metadata["versions"]["scikit-learn"] != sklearn.__version__ or metadata["versions"]["numpy"] != np.__version__
            or metadata["feature_names"] != FEATURE_NAMES or metadata["feature_version"] != FEATURE_VERSION):
        raise ValueError("baseline library/feature version incompatible; refit locally")
    # Only the app-created, hash-checked local SQLite artifact is accepted.
    model = pickle.loads(blob)
    if not isinstance(model,IsolationForest) or not hasattr(model,"estimators_"):
        raise ValueError("local baseline is not a fitted IsolationForest")
    return BaselineArtifact(metadata,model)
