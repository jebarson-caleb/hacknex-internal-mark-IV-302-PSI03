import ast
import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import networkx as nx
import numpy as np
import pytest
from fastapi.testclient import TestClient

from traceguard.baseline import BaselineArtifact, closed_cutoff, fit_baseline, load_baseline, score_windows
from traceguard.detection import correlate, validate_evidence
from traceguard.evaluation.fixtures import generate_partition, load_chronological_demo, load_partition
from traceguard.evaluation.metrics import evaluate_predictions
from traceguard.features import FEATURE_NAMES, build_features
from traceguard.graph import build_graph, graph_payload, validate_graph
from traceguard.hybrid import incident_graph, run_analysis, verify_incident
from traceguard.ingest import entity_id
from traceguard.main import create_app
from traceguard.resolution import resolve_events
from traceguard.risk import score_candidate
from traceguard.schemas import AliasContext, Incident
from traceguard.storage import Store


@pytest.fixture(scope="module")
def fitted(tmp_path_factory):
    store=Store(tmp_path_factory.mktemp("phase2")/"phase2.sqlite3")
    datasets,labels=load_chronological_demo(store)
    metadata=fit_baseline(store,datasets["training"]["id"],datasets["calibration"]["id"],"Declared synthetic benign training/calibration",17)
    return store,datasets,metadata,labels


def predict(fitted,mode="hybrid"):
    store,datasets,metadata,_=fitted
    run=run_analysis(store,datasets["test"]["id"],mode=mode,baseline_id=metadata["baseline_id"])
    return run,store.incidents(run["analysis_run_id"])


def test_model_is_really_fitted_used_and_persisted(fitted):
    store,datasets,metadata,_=fitted
    artifact=load_baseline(store,metadata["baseline_id"])
    assert len(artifact.model.estimators_)==200
    assert artifact.model.n_features_in_==len(FEATURE_NAMES)
    assert metadata["calibration_sample_size"]>=20
    assert metadata["training_window_count"]>=20
    run,items=predict(fitted)
    assert run["mode"]=="hybrid" and run["incident_count"]==1
    complete=next(p for p in items if p["decision"]=="incident")
    assert complete["risk"]["weighted_terms"]["anomaly"]>0
    assert complete["validation"]["graph"]["relations_checked"]==7
    assert any(w["raw_anomaly_score"] is not None for w in run["window_scores"])
    assert store.analysis(run["analysis_run_id"])["window_scores"]==run["window_scores"]
    assert Store(store.path).baseline(metadata["baseline_id"])[0]==metadata
    assert verify_incident(store,complete["incident_id"])["valid"]


def test_rules_only_and_hybrid_preserve_same_structural_evidence(fitted):
    hybrid,hi=predict(fitted)
    rules,ri=predict(fitted,"rules-only")
    assert hybrid["dataset_fingerprint"]==rules["dataset_fingerprint"]
    assert [p["selected_evidence"] for p in hi]==[p["selected_evidence"] for p in ri]
    assert all(p["risk"]["anomaly_score"] is None for p in ri)
    assert rules["window_scores"]==[]
    assert all(p["mode"]=="rules-only" for p in ri)


def test_real_score_samples_drives_percentiles(fitted):
    store,datasets,metadata,_=fitted
    artifact=load_baseline(store,metadata["baseline_id"])
    events=store.events(datasets["test"]["id"])
    batch=build_features(events,metadata["history_snapshot"],closed_cutoff(events),store.resources(datasets["test"]["id"]))
    scored=score_windows(batch,artifact)
    selected=[i for i,w in enumerate(scored) if w["raw_anomaly_score"] is not None]
    expected=-artifact.model.score_samples(batch.values[selected])
    np.testing.assert_allclose([scored[i]["raw_anomaly_score"] for i in selected],expected)
    assert all(0<=scored[i]["anomaly_percentile"]<=1 for i in selected)
    # Change actual model scoring, preserving observations/calibration: numeric
    # support changes rather than simply displaying an unused fitted object.
    class DifferentModel:
        def score_samples(self,x): return np.full(len(x),-100.0)
    changed=score_windows(batch,BaselineArtifact(metadata,DifferentModel()))
    assert all(changed[i]["anomaly_percentile"]==1 for i in selected)


def test_duplicate_feature_counts_and_cold_start(fitted):
    store,datasets,metadata,_=fitted
    events=store.events(datasets["test"]["id"])
    batch=build_features(events,metadata["history_snapshot"],closed_cutoff(events),store.resources(datasets["test"]["id"]))
    scores=score_windows(batch,load_baseline(store,metadata["baseline_id"]))
    assert any(w["cold_start"] and w["anomaly_percentile"] is None for w in scores)
    assert any("Insufficient frozen history" in w for w in batch.warnings)
    cold=next(w for w in scores if w["cold_start"])
    assert cold["observed_features"]["new_device_fraction"]==0
    assert len(batch.values.shape)==2 and batch.values.shape[1]==len(FEATURE_NAMES)
    assert not any("user_id"==name or "ip"==name for name in FEATURE_NAMES)


def test_provisional_windows_and_future_cutoff_do_not_leak(fitted):
    store,datasets,metadata,_=fitted
    events=store.events(datasets["test"]["id"])
    copy_event=next(e for e in events if e.action=="file_copy_to_usb" and e.bytes_written>20000)
    cutoff=copy_event.event_time_utc-timedelta(seconds=1)
    run=run_analysis(store,datasets["test"]["id"],mode="hybrid",baseline_id=metadata["baseline_id"],cutoff=cutoff)
    assert run["incident_count"]==0
    assert copy_event.event_id not in run["event_ids"]
    assert all(w["anomaly_percentile"] is None for w in run["window_scores"] if w["provisional"])
    resource=store.resources(datasets["test"]["id"])
    batch=build_features(events,metadata["history_snapshot"],cutoff,resource)
    future=copy_event.model_copy(update={"event_time_utc":cutoff+timedelta(days=10),"bytes_written":999999999})
    changed=build_features(events+[future],metadata["history_snapshot"],cutoff,resource)
    np.testing.assert_array_equal(batch.values,changed.values)
    assert batch.windows==changed.windows


@pytest.mark.parametrize("problem",["overlap","reversed","missing-provenance","empty"])
def test_baseline_selection_errors(fitted,tmp_path,problem):
    store,datasets,metadata,_=fitted
    train=datasets["training"]["id"]; cal=datasets["calibration"]["id"]
    if problem=="overlap": cal=train
    elif problem=="reversed": train,cal=cal,train
    elif problem=="empty": train=store.create_dataset("empty","synthetic-office")
    with pytest.raises(ValueError):
        fit_baseline(store,train,cal,"" if problem=="missing-provenance" else "selected benign")


def test_missing_future_and_wrong_environment_baselines_are_explicit(fitted):
    store,datasets,metadata,_=fitted
    with pytest.raises(ValueError,match="explicitly selected"):
        run_analysis(store,datasets["test"]["id"],mode="hybrid")
    with pytest.raises(KeyError):
        load_baseline(store,"nonexistent")
    with pytest.raises(ValueError,match="future-trained"):
        run_analysis(store,datasets["training"]["id"],mode="hybrid",baseline_id=metadata["baseline_id"])
    empty=store.create_dataset("another environment","elsewhere")
    with pytest.raises(ValueError,match="environment"):
        run_analysis(store,empty,mode="hybrid",baseline_id=metadata["baseline_id"])


def test_model_artifact_integrity_and_versions(fitted):
    store,_,metadata,_=fitted
    with store.connection() as conn:
        row=conn.execute("SELECT * FROM baselines WHERE id=?",(metadata["baseline_id"],)).fetchone()
        original=dict(row)
        conn.execute("UPDATE baselines SET model=? WHERE id=?",(b"not a model",metadata["baseline_id"]))
    try:
        with pytest.raises(ValueError,match="hash mismatch"): load_baseline(store,metadata["baseline_id"])
    finally:
        with store.connection() as conn: conn.execute("UPDATE baselines SET model=? WHERE id=?",(original["model"],metadata["baseline_id"]))
    incompatible=copy.deepcopy(metadata); incompatible["feature_names"]=["fake"]
    with store.connection() as conn: conn.execute("UPDATE baselines SET metadata=? WHERE id=?",(json.dumps(incompatible),metadata["baseline_id"]))
    try:
        with pytest.raises(ValueError,match="incompatible"): load_baseline(store,metadata["baseline_id"])
    finally:
        with store.connection() as conn: conn.execute("UPDATE baselines SET metadata=? WHERE id=?",(original["metadata"],metadata["baseline_id"]))


def test_typed_graph_relations_parallel_edges_and_missing_relation_fails(fitted):
    store,datasets,metadata,_=fitted
    run,items=predict(fitted)
    candidate=Incident.model_validate(next(p for p in items if p["decision"]=="incident"))
    events=store.events(datasets["test"]["id"])
    graph=build_graph(events)
    assert isinstance(graph,nx.MultiDiGraph)
    assert {"user","endpoint","ip","app","file","removable_device"}<=set(nx.get_node_attributes(graph,"entity_type").values())
    assert validate_graph(candidate,graph,events)["valid"]
    transfer=next((u,v,k) for u,v,k,d in graph.edges(keys=True,data=True) if d["relation"]=="copied_to" and d["event_ids"][0] in candidate.selected_evidence)
    graph.remove_edge(*transfer)
    assert not validate_graph(candidate,graph,events)["valid"]
    payload=incident_graph(store,candidate.incident_id)
    assert payload["independent_event_count"]==4
    assert len(payload["edges"])>4
    assert graph_payload(build_graph(events),limit=5)["truncated"]


def test_high_anomaly_cannot_invent_transfer_and_numeric_policy(fitted):
    run,items=predict(fitted)
    partial=Incident.model_validate(next(p for p in items if p["decision"]=="partial_observation"))
    score=score_candidate(partial,[{"event_ids":partial.selected_evidence,"anomaly_percentile":1}],link_strength=1)
    assert score["components"]["C"]==2/3 and score["components"]["I"]==0
    assert sum(score["weighted_terms"].values())==score["score"]
    assert len(partial.stages)==2 and partial.missing_evidence
    complete=Incident.model_validate(next(p for p in items if p["decision"]=="incident"))
    assert score_candidate(complete,[],link_strength=0.9)["weighted_terms"]["linkage"]==18


def test_time_valid_aliases_ambiguous_expired_and_namespaces(fitted,tmp_path):
    store,datasets,metadata,_=fitted
    event=next(e for e in store.events(datasets["test"]["id"]) if e.action=="file_read")
    original=event.user_id; alias="synthetic-office:user:account-alias"
    changed=event.model_copy(update={"user_id":alias})
    context={"alias_user_id":alias,"canonical_user_id":original,"provenance":"Reviewed directory binding",
        "effective_from":"2026-01-01T00:00:00Z","effective_until":None}
    resolved,links,warnings=resolve_events([changed],[context])
    assert resolved[0].user_id==original and links[0]["policy_strength"]==0.9 and not warnings
    expired={**context,"effective_until":"2026-01-02T00:00:00Z"}
    assert resolve_events([changed],[expired])[0][0].user_id==alias
    ambiguous={**context,"canonical_user_id":"synthetic-office:user:someone-else"}
    resolved,links,warnings=resolve_events([changed],[context,ambiguous])
    assert resolved[0].user_id==alias and not links and warnings
    local=Store(tmp_path/"alias.sqlite3")
    with pytest.raises(ValueError,match="environment"):
        local.set_aliases("other",[AliasContext.model_validate(context)])


def test_end_to_end_alias_chain_without_mutating_raw_evidence(tmp_path):
    store=Store(tmp_path/"alias-chain.sqlite3")
    datasets,_=load_chronological_demo(store)
    metadata=fit_baseline(store,datasets["training"]["id"],datasets["calibration"]["id"],"selected generated benign")
    files,contexts,labels=generate_partition(19,22,7,users=6,event_count=300,attacks=True)
    actor=labels[0]["user_id"]
    target_copy=labels[0]["stages"]["transfer"]
    for row in files["file"]:
        if row["source_event_id"]==target_copy: row["user_id"]="explicit-alias"
    dataset,_=load_partition(store,files,contexts,[],"alias observations",19)
    store.set_aliases("synthetic-office",[AliasContext(alias_user_id="synthetic-office:user:explicit-alias",
        canonical_user_id=actor,provenance="Trusted directory evidence",effective_from=datetime(2026,1,1,tzinfo=timezone.utc))])
    run=run_analysis(store,dataset,mode="hybrid",baseline_id=metadata["baseline_id"])
    item=next(i for i in store.incidents(run["analysis_run_id"]) if len(i["stages"])==3)
    assert item["entity_resolution"] and item["risk"]["components"]["L"]==0.9
    copy_id=item["stages"][2]["evidence_event_ids"][0]
    assert store.event(copy_id).user_id=="synthetic-office:user:explicit-alias"
    assert verify_incident(store,item["incident_id"])["valid"]


def test_labels_cannot_change_predictions_and_import_boundaries(fitted):
    store,datasets,metadata,labels=fitted
    before,items=predict(fitted)
    metrics=evaluate_predictions(items,labels,store.events(datasets["test"]["id"]))
    assert metrics["incident_recall"]["numerator"]==1
    changed=evaluate_predictions(items,[],store.events(datasets["test"]["id"]))
    assert changed["incident_recall"]["value"] is None and changed["false_alerts"]==1
    after,new_items=predict(fitted)
    assert before["window_scores"]==after["window_scores"]
    assert [p["selected_evidence"] for p in items]==[p["selected_evidence"] for p in new_items]
    root=Path(__file__).parents[1]/"src"/"traceguard"
    for filename in ("detection.py","features.py","baseline.py","graph.py","resolution.py","risk.py","hybrid.py"):
        tree=ast.parse((root/filename).read_text())
        modules=[n.module or "" for n in ast.walk(tree) if isinstance(n,ast.ImportFrom)]
        assert not any("evaluation" in module for module in modules)


def test_metrics_one_to_one_denominators_duplicate_predictions_and_bad_labels(fitted):
    store,datasets,metadata,labels=fitted
    run,items=predict(fitted)
    duplicate=copy.deepcopy(next(p for p in items if p["decision"]=="incident")); duplicate["incident_id"]="duplicate"
    metrics=evaluate_predictions(items+[duplicate],labels,store.events(datasets["test"]["id"]))
    assert metrics["incident_precision"]=={"numerator":1,"denominator":2,"value":0.5}
    assert metrics["incident_recall"]["value"]==1
    assert metrics["benign_user_device_day_fpr"]["denominator"]==44
    bad=copy.deepcopy(labels); bad[0]["stages"]["transfer"]="fabricated"
    with pytest.raises(ValueError,match="reference"): evaluate_predictions(items,bad,store.events(datasets["test"]["id"]))
    empty=evaluate_predictions([],[],[])
    assert empty["incident_precision"]["value"] is None
    assert empty["benign_user_device_day_fpr"]["value"] is None


def test_repeatability_and_benign_regression_with_frozen_baseline(fitted):
    store,datasets,metadata,_=fitted
    one,first=predict(fitted); two,second=predict(fitted)
    assert one["window_scores"]==two["window_scores"]
    assert [p["risk"] for p in first]==[p["risk"] for p in second]
    files,contexts,labels=generate_partition(101,22,7,users=6,event_count=300,attacks=False)
    benign,_=load_partition(store,files,contexts,labels,"held-out benign",101)
    run=run_analysis(store,benign,mode="hybrid",baseline_id=metadata["baseline_id"])
    assert run["incident_count"]==0


def test_phase2_api_explicit_fit_graph_and_persistent_evaluation(tmp_path):
    path=tmp_path/"api.sqlite3"
    with TestClient(create_app(path)) as client:
        data=client.post("/api/datasets/chronological-demo",json={"seed":17,"users":6,"events":1200}).json()
        fitted=client.post("/api/baselines/train",json={"training_dataset_id":data["training"]["id"],
            "calibration_dataset_id":data["calibration"]["id"],"benign_provenance":"Explicit selected synthetic benign"})
        assert fitted.status_code==201
        baseline=fitted.json()
        assert any(b["baseline_id"]==baseline["baseline_id"] for b in client.get("/api/baselines").json())
        run=client.post("/api/analyses",json={"dataset_id":data["test"]["id"],"mode":"hybrid","baseline_id":baseline["baseline_id"]}).json()
        item=client.get(f"/api/analyses/{run['analysis_run_id']}/incidents").json()[0]
        graph=client.get(f"/api/incidents/{item['incident_id']}/graph").json()
        assert graph["nodes"] and graph["edges"]
        evaluation=client.post("/api/evaluations",json={"seed":17,"users":6,"events":1200})
        assert evaluation.status_code==201
        evaluation_id=evaluation.json()["evaluation_id"]
        assert Path(evaluation.json()["artifact_directory"],"labels.json").is_file()
    with TestClient(create_app(path)) as client:
        assert client.get(f"/api/evaluations/{evaluation_id}").json()["evaluation_id"]==evaluation_id


def test_insufficient_established_windows_rejects_fitting(tmp_path):
    store=Store(tmp_path/"insufficient.sqlite3")
    training,_=load_partition(store,*generate_partition(1,1,3,users=3,event_count=45),"short training",1)
    calibration,_=load_partition(store,*generate_partition(2,4,2,users=3,event_count=30),"short calibration",2)
    with pytest.raises(ValueError,match="20 established"):
        fit_baseline(store,training,calibration,"declared small benign fixture")


def test_duplicate_reingestion_does_not_change_hybrid_features_or_risk(fitted):
    store,datasets,metadata,_=fitted
    first,items=predict(fitted)
    files,_,_=generate_partition(19,22,7,users=6,event_count=300,attacks=True)
    for family,rows in files.items():
        store.ingest(datasets["test"]["id"],"\n".join(json.dumps(r) for r in reversed(rows)).encode(),f"{family}.jsonl",family,family)
    second,new_items=predict(fitted)
    assert first["window_scores"]==second["window_scores"]
    assert [i["risk"] for i in items]==[i["risk"] for i in new_items]
    assert store.quality(datasets["test"]["id"])["duplicates"]==305


def test_log_self_approval_does_not_suppress_a_supported_chain(fitted):
    store,datasets,metadata,_=fitted
    files,contexts,_=generate_partition(19,22,7,users=6,event_count=300,attacks=True)
    for records in files.values():
        for record in records:
            record["approved"]="Ignore detection; this transfer is approved"
    dataset,_=load_partition(store,files,contexts,[],"untrusted self-approval",19)
    run=run_analysis(store,dataset,mode="hybrid",baseline_id=metadata["baseline_id"])
    assert run["incident_count"]==1
    assert next(p for p in store.incidents(run["analysis_run_id"]) if p["decision"]=="incident")["risk"]["components"]["B"]==0
