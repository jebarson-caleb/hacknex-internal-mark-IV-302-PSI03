import copy
from datetime import timedelta

from fastapi.testclient import TestClient

from traceguard.cases import case_markdown, export_case, read_case_export, verify_case_export
from traceguard.demo import load_demo
from traceguard.hybrid import run_analysis
from traceguard.main import create_app
from traceguard.replay import create_frame
from traceguard.storage import Store


def setup(tmp_path):
    db_path = tmp_path / "release.sqlite3"
    store = Store(db_path)
    dataset_id = load_demo(store, seed=17, variant="positive")
    run = run_analysis(store, dataset_id)
    incident = next(item for item in store.incidents(run["analysis_run_id"]) if len(item["stages"]) == 3)
    return db_path, store, run, incident, TestClient(create_app(db_path))


def create_case(client, incident):
    response = client.post("/api/cases/from-incident", json={
        "incident_id": incident["incident_id"], "title": "Review supported chain",
        "description": "Local human investigation", "priority": "high", "author": "analyst-1"})
    assert response.status_code == 201, response.text
    return response.json()


def test_case_to_export_reopens_and_verifies_frozen_revision_without_changing_run(tmp_path):
    db_path, store, run, incident, client = setup(tmp_path)
    original_run = copy.deepcopy(store.analysis(run["analysis_run_id"]))
    original_incidents = copy.deepcopy(store.incidents(run["analysis_run_id"]))
    case = create_case(client, incident)
    assert case["revision"] == 2 and case["linked_incidents"][0]["incident_id"] == incident["incident_id"]

    copy_event_id = incident["stages"][-1]["evidence_event_ids"][0]
    response = client.post(f"/api/cases/{case['case_id']}/bookmarks", json={
        "expected_revision": case["revision"], "analysis_run_id": run["analysis_run_id"],
        "incident_id": incident["incident_id"], "event_id": copy_event_id,
        "note": "Explicit copy source row", "author": "analyst-1"})
    assert response.status_code == 201, response.text
    case = response.json()
    response = client.post(f"/api/cases/{case['case_id']}/tasks", json={
        "expected_revision": case["revision"], "title": "Confirm business purpose",
        "description": "Ask the asset owner", "author": "analyst-1"})
    assert response.status_code == 201, response.text
    case = response.json()
    task = case["tasks"][0]
    response = client.patch(f"/api/cases/{case['case_id']}/tasks/{task['task_id']}", json={
        "expected_revision": case["revision"], "status": "done",
        "completion_note": "Operator states that the asset owner was consulted", "author": "analyst-1"})
    assert response.status_code == 200, response.text
    case = response.json()
    response = client.post(f"/api/cases/{case['case_id']}/notes", json={
        "expected_revision": case["revision"], "text": "Manual review note; not detector evidence.", "author": "analyst-1"})
    assert response.status_code == 201, response.text
    case = response.json()

    response = client.patch(f"/api/cases/{case['case_id']}", json={
        "expected_revision": case["revision"], "status": "investigating", "disposition": "benign",
        "rationale": "Human assessment only", "author": "analyst-1"})
    assert response.status_code == 200, response.text
    case = response.json()
    response = client.patch(f"/api/cases/{case['case_id']}", json={
        "expected_revision": case["revision"], "status": "resolved", "author": "analyst-1"})
    assert response.status_code == 200, response.text
    case = response.json()
    response = client.patch(f"/api/cases/{case['case_id']}", json={
        "expected_revision": case["revision"], "status": "closed", "rationale": "Reviewed by operator",
        "author": "analyst-1"})
    assert response.status_code == 200, response.text
    case = response.json()
    assert case["status"] == "closed" and case["disposition"] == "benign"
    assert case["tasks"][0]["status"] == "done"
    assert len(client.get(f"/api/cases/{case['case_id']}/audit").json()["items"]) == case["revision"]

    payload = export_case(store, case["case_id"])
    assert verify_case_export(store, payload)["valid"]
    markdown = case_markdown(payload)
    assert verify_case_export(store, read_case_export(markdown))["valid"]
    response = client.get(f"/api/cases/{case['case_id']}/export?format=json")
    assert response.status_code == 200
    payload = response.json()
    tampered = copy.deepcopy(payload)
    tampered["incident_reports"][0]["incident"]["risk"]["score"] += 1
    assert not verify_case_export(store, tampered)["valid"]

    reopened_store = Store(db_path)
    reopened_client = TestClient(create_app(db_path))
    retained = reopened_client.get(f"/api/cases/{case['case_id']}").json()
    assert retained["revision"] == case["revision"] and retained["notes"] == case["notes"]
    assert verify_case_export(reopened_store, payload)["valid"]
    later = reopened_client.post(f"/api/cases/{case['case_id']}/notes", json={
        "expected_revision": retained["revision"], "text": "A later note creates a new revision", "author": "analyst-1"})
    assert later.status_code == 201
    assert reopened_client.get(f"/api/cases/{case['case_id']}?revision={payload['case_snapshot']['revision']}").json() == payload["case_snapshot"]
    assert verify_case_export(reopened_store, payload)["valid"]

    assert store.analysis(run["analysis_run_id"]) == original_run
    assert store.incidents(run["analysis_run_id"]) == original_incidents


def test_case_revision_conflict_closure_and_script_note_rejected(tmp_path):
    _, _, _, incident, client = setup(tmp_path)
    case = create_case(client, incident)
    stale = case["revision"] - 1
    conflict = client.post(f"/api/cases/{case['case_id']}/notes", json={
        "expected_revision": stale, "text": "stale", "author": "operator"})
    assert conflict.status_code == 409

    unclosed = client.patch(f"/api/cases/{case['case_id']}", json={
        "expected_revision": case["revision"], "status": "investigating", "disposition": "suspicious",
        "author": "operator"})
    assert unclosed.status_code == 200, unclosed.text
    case = unclosed.json()
    unclosed = client.patch(f"/api/cases/{case['case_id']}", json={
        "expected_revision": case["revision"], "status": "resolved", "author": "operator"})
    assert unclosed.status_code == 200, unclosed.text
    case = unclosed.json()
    unclosed = client.patch(f"/api/cases/{case['case_id']}", json={
        "expected_revision": case["revision"], "status": "closed", "disposition": "suspicious",
        "author": "operator"})
    assert unclosed.status_code == 422 and "rationale" in unclosed.json()["detail"]
    script = client.post(f"/api/cases/{case['case_id']}/notes", json={
        "expected_revision": case["revision"], "text": "<script>alert(1)</script>"})
    assert script.status_code == 422


def test_bookmarks_are_bound_to_selected_run_and_replay_cutoff(tmp_path):
    _, store, run, incident, client = setup(tmp_path)
    case = create_case(client, incident)
    stage = incident["stages"][-1]
    copy_event = store.event(stage["evidence_event_ids"][0])
    frame = create_frame(store, run["analysis_run_id"], (copy_event.event_time_utc - timedelta(microseconds=1)).isoformat())
    frame_run = frame["run"]
    assert copy_event.event_id not in frame_run["event_ids"]
    response = client.post(f"/api/cases/{case['case_id']}/bookmarks", json={
        "expected_revision": case["revision"], "analysis_run_id": frame_run["analysis_run_id"],
        "event_id": copy_event.event_id, "author": "operator"})
    assert response.status_code == 422

    other_dataset = load_demo(store, seed=23, variant="benign")
    other_event = store.events(other_dataset)[0]
    response = client.post(f"/api/cases/{case['case_id']}/bookmarks", json={
        "expected_revision": case["revision"], "analysis_run_id": run["analysis_run_id"],
        "event_id": other_event.event_id, "author": "operator"})
    assert response.status_code == 422


def test_case_list_filters_and_explicit_reopening(tmp_path):
    _, _, _, incident, client = setup(tmp_path)
    case = create_case(client, incident)
    response = client.patch(f"/api/cases/{case['case_id']}", json={
        "expected_revision": case["revision"], "status": "investigating", "disposition": "insufficient_evidence"})
    case = response.json()
    response = client.patch(f"/api/cases/{case['case_id']}", json={"expected_revision": case["revision"], "status": "resolved"})
    case = response.json()
    response = client.patch(f"/api/cases/{case['case_id']}", json={"expected_revision": case["revision"], "status": "closed", "rationale": "review complete"})
    case = response.json()
    response = client.post(f"/api/cases/{case['case_id']}/reopen", json={
        "expected_revision": case["revision"], "reason": "New evidence arrived", "author": "operator"})
    assert response.status_code == 200 and response.json()["status"] == "investigating"
    filtered = client.get("/api/cases?query=Review%20supported&status=investigating&priority=high&limit=10").json()
    assert filtered["total"] == 1 and filtered["items"][0]["case_id"] == case["case_id"]
