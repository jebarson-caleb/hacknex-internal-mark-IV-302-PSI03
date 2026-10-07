import copy
import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from traceguard.baseline import fit_baseline
from traceguard.context import calibration_status
from traceguard.demo import load_demo
from traceguard.evaluation.fixtures import load_chronological_demo
from traceguard.hybrid import run_analysis, verify_incident
from traceguard.main import create_app
from traceguard.reports import build_report, markdown_report, read_report, verify_report
from traceguard.schemas import AuthorizationContext, ResourceContext
from traceguard.storage import Store


@pytest.fixture(scope="module")
def fitted(tmp_path_factory):
    store=Store(tmp_path_factory.mktemp("phase3")/"context.sqlite3")
    data,_=load_chronological_demo(store)
    baseline=fit_baseline(store,data["training"]["id"],data["calibration"]["id"],"Explicit synthetic benign audit")
    return store,data,baseline


def complete(store,run):
    return next(i for i in store.incidents(run["analysis_run_id"]) if len(i["stages"])==3)


def authorization(store,item,**changes):
    event=store.event(item["stages"][-1]["evidence_event_ids"][0])
    values=dict(authorization_id="reviewed-export",user_id=item["user_id"],device_id=item["device_id"],
        resource_id=event.resource_id,provenance="Operator-reviewed export ticket, not log self-approval",
        effective_from=event.event_time_utc-timedelta(minutes=1),effective_until=event.event_time_utc+timedelta(minutes=1))
    values.update(changes)
    return AuthorizationContext(**values)


def test_stage_eligible_authorized_export_and_expired_out_of_scope(fitted):
    store,data,baseline=fitted; dataset=data["test"]["id"]
    first=run_analysis(store,dataset,mode="hybrid",baseline_id=baseline["baseline_id"])
    unapproved=complete(store,first)
    for variant in ("matching","expired","resource","actor","endpoint"):
        changes={}
        if variant=="expired":
            event=store.event(unapproved["stages"][-1]["evidence_event_ids"][0])
            changes={"effective_from":event.event_time_utc-timedelta(hours=2),"effective_until":event.event_time_utc}
        elif variant in ("resource","actor","endpoint"):
            field={"resource":"resource_id","actor":"user_id","endpoint":"device_id"}[variant]
            changes[field]=getattr(authorization(store,unapproved),field)+"-unrelated"
        store.set_authorizations(dataset,[authorization(store,unapproved,**changes)])
        run=run_analysis(store,dataset,mode="hybrid",baseline_id=baseline["baseline_id"])
        item=complete(store,run)
        assert item["selected_evidence"]==unapproved["selected_evidence"] # reaches complete copy path
        assert item["risk"]["components"]["B"]==(20 if variant=="matching" else 0)
        assert item["risk"]["score"]==pytest.approx(unapproved["risk"]["score"]-(20 if variant=="matching" else 0))
        assert item["authorization"]["matched"]==(variant=="matching")
        assert verify_incident(store,item["incident_id"])["valid"]
        if variant=="matching":
            historical=item; historical_run=run
    store.set_authorizations(dataset,[])
    assert store.incident(historical["incident_id"])==historical
    assert store.analysis(historical_run["analysis_run_id"])["authorization_context_snapshot"]
    assert verify_incident(store,historical["incident_id"])["valid"]
    assert complete(store,run_analysis(store,dataset,baseline_id=baseline["baseline_id"]))["risk"]["score"]==100


def test_calibration_distinction_and_legacy_unknown(fitted):
    _,_,baseline=fitted
    status=calibration_status(baseline)
    assert status["percentile"]["status"]=="available"
    assert status["incident_threshold"]["complete_candidates"]==0
    assert status["incident_threshold"]["status"]=="insufficient_complete_candidates"
    assert status["incident_threshold"]["threshold_origin"]=="structural_fallback"
    old=copy.deepcopy(baseline);old.pop("percentile_calibration")
    for key in ("status","threshold_origin","fallback_reason"):old["risk_calibration"].pop(key)
    assert calibration_status(old)["incident_threshold"]["status"]=="unknown"


@pytest.mark.parametrize("include_raw",[False,True])
def test_reports_tampering_and_markdown(tmp_path,include_raw):
    store=Store(tmp_path/"report.sqlite3");dataset=load_demo(store)
    run=run_analysis(store,dataset);item=complete(store,run)
    report=build_report(store,item["incident_id"],include_raw)
    assert report["validation"]["valid"] and verify_report(store,report)["valid"]
    text=markdown_report(report)
    assert verify_report(store,read_report(text))["valid"]
    assert bool("raw" in report["evidence"][0]["source_records"][0])==include_raw
    assert len(report["evidence"])<run["event_count"]
    for change in ("event","stage","run","source","risk","validation","recommendation"):
        bad=copy.deepcopy(report)
        if change=="event":bad["incident"]["selected_evidence"][0]="fabricated"
        elif change=="stage":bad["incident"]["stages"][0]["claim_status"]="observed"
        elif change=="run":bad["run"]["analysis_run_id"]="another-run"
        elif change=="source":bad["evidence"][0]["source_records"][0]["raw_sha256"]="altered"
        elif change=="risk":bad["incident"]["risk"]["score"]=42
        elif change=="validation":bad["validation"]["valid"]=False
        else:bad["incident"]["recommendations"][0]["approval_status"]="approved"
        assert not verify_report(store,bad)["valid"]
    with pytest.raises(ValueError,match="claims"):
        read_report(text.replace("authentication: supported_inference","authentication: observed"))
    # Retained file tampering refuses an export marked verified.
    with store.connection() as conn:conn.execute("UPDATE uploads SET content=? WHERE id=?",(b'{}',report["evidence"][0]["source_records"][0]["upload_id"]))
    with pytest.raises(ValueError,match="verification failed"):build_report(store,item["incident_id"])


def test_run_bound_navigation_context_edit_refresh_and_pagination(tmp_path):
    path=tmp_path/"api.sqlite3"
    with TestClient(create_app(path)) as client:
        data=client.post("/api/datasets/demo",json={}).json()["dataset"]
        run=client.post("/api/analyses",json={"dataset_id":data["id"]}).json()
        listing=client.get(f"/api/analyses/{run['analysis_run_id']}/candidates?limit=1").json()
        item=listing["items"][0]
        assert listing["total"]==1 and listing["next_cursor"] is None
        assert client.get(f"/api/analyses/{run['analysis_run_id']}/candidates?search=absent").json()["items"]==[]
        assert client.get(f"/api/analyses/{run['analysis_run_id']}/candidates?decision=partial_observation").json()["items"]==[]
        assert client.get(f"/api/analyses/{run['analysis_run_id']}/candidates?limit=101").status_code==422
        graph=client.get(f"/api/incidents/{item['incident_id']}/graph").json()
        transfer=item["stages"][-1]["evidence_event_ids"][0]
        edge=next(e for e in graph["edges"] if e["relation"]=="copied_to")
        assert edge["event_ids"]==[transfer]
        source=client.get(f"/api/incidents/{item['incident_id']}/source/{transfer}").json()
        assert source["analysis_run_id"]==run["analysis_run_id"]
        assert source["event"]["action"]==source["source_records"][0]["raw"]["action"]=="file_copy_to_usb"
        unrelated=next(e for e in run["event_ids"] if e not in item["selected_evidence"] and e not in item["stages"][0]["historical_comparison"]["history_event_ids"] and e not in item["stages"][1]["historical_comparison"]["history_event_ids"])
        assert client.get(f"/api/incidents/{item['incident_id']}/source/{unrelated}").status_code==422
        report=client.get(f"/api/incidents/{item['incident_id']}/report").json()
        resources=client.get(f"/api/datasets/{data['id']}/resources").json()
        resources[0]["sensitive"]=False
        assert client.put(f"/api/datasets/{data['id']}/resources",json=resources).status_code==200
        assert verify_report(client.app.state.store,report)["valid"]
        bad=authorization(client.app.state.store,item).model_dump(mode="json");bad["user_id"]="other:user:x"
        assert client.put(f"/api/datasets/{data['id']}/authorizations",json=[bad]).status_code==422
    with TestClient(create_app(path)) as client:
        assert client.get(f"/api/analyses/{run['analysis_run_id']}").json()==run
        summary=client.get(f"/api/datasets/{data['id']}/analyses").json()[0]
        assert summary["analysis_run_id"]==run["analysis_run_id"] and summary["incident_count"]==run["incident_count"]
        assert "event_ids" not in summary
        assert verify_report(client.app.state.store,report)["valid"]


def test_duplicate_overlap_and_distinct_later_episode(tmp_path):
    store=Store(tmp_path/"episodes.sqlite3");dataset=load_demo(store)
    initial=run_analysis(store,dataset);item=complete(store,initial)
    login=store.evidence(item["stages"][0]["evidence_event_ids"][0])["source_records"][0]["raw"]
    login["timestamp"]=(store.event(item["stages"][0]["evidence_event_ids"][0]).event_time_utc+timedelta(seconds=1)).isoformat()
    store.ingest(dataset,json.dumps(login).encode(),"overlap.jsonl","auth","auth")
    assert run_analysis(store,dataset)["incident_count"]==1
    for eid in item["selected_evidence"]:
        event=store.event(eid);raw=store.evidence(eid)["source_records"][0]["raw"]
        raw["timestamp"]=(event.event_time_utc+timedelta(hours=3)).isoformat()
        store.ingest(dataset,json.dumps(raw).encode(),"later.jsonl",event.source_id,event.source_type)
    first=run_analysis(store,dataset);second=run_analysis(store,dataset)
    assert first["incident_count"]==second["incident_count"]==2
    assert [i["selected_evidence"] for i in store.incidents(first["analysis_run_id"])]==[i["selected_evidence"] for i in store.incidents(second["analysis_run_id"])]
    assert all(i["risk"]["score"]==100 for i in store.incidents(first["analysis_run_id"]))
    with TestClient(create_app(store.path)) as client:
        prefix=f"/api/analyses/{first['analysis_run_id']}/candidates?limit=1"
        page=client.get(prefix).json()
        assert page["total"]==2 and page["next_cursor"]==1
        next_page=client.get(prefix+"&cursor=1").json()
        assert next_page["next_cursor"] is None
        assert next_page["items"][0]["incident_id"]!=page["items"][0]["incident_id"]


def test_report_unsafe_text_is_literal_and_bad_shapes_fail(tmp_path):
    store=Store(tmp_path/"literal.sqlite3");dataset=load_demo(store)
    report=build_report(store,complete(store,run_analysis(store,dataset))["incident_id"],True)
    # Formatting arbitrary log text cannot inject a Markdown fence or HTML.
    report["evidence"][0]["source_records"][0]["raw"]["note"]="``` <script>alert(1)</script>"
    text=markdown_report(report)
    assert "<script>" not in text and text.count("```traceguard-json")==1
    assert read_report(text)==report
    assert not verify_report(store,report)["valid"]
    assert not verify_report(store,[])["valid"]


def test_new_run_freezes_duplicate_source_refs(tmp_path):
    store=Store(tmp_path/"refs.sqlite3");dataset=load_demo(store)
    run=run_analysis(store,dataset);item=complete(store,run)
    report=build_report(store,item["incident_id"])
    for eid in item["selected_evidence"]:
        record=store.evidence(eid)["source_records"][0]
        store.ingest(dataset,json.dumps(record["raw"]).encode(),"duplicate.jsonl",record["source_id"],record["source_type"])
    again=build_report(store,item["incident_id"])
    assert again["evidence"]==report["evidence"]
    assert verify_report(store,report)["valid"]
    new=run_analysis(store,dataset)
    new_item=complete(store,new)
    assert new["incident_count"]==run["incident_count"]==1
    assert new_item["selected_evidence"]==item["selected_evidence"] and new_item["risk"]==item["risk"]
    assert new_item["incident_id"].split('-',1)[1]==item["incident_id"].split('-',1)[1]
