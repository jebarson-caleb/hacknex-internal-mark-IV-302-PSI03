from datetime import timedelta

from fastapi.testclient import TestClient

from traceguard.demo import load_demo
from traceguard.hybrid import run_analysis
from traceguard.main import create_app
from traceguard.replay import create_frame
from traceguard.storage import Store


def setup(tmp_path):
    db_path = tmp_path / "hunts.sqlite3"
    store = Store(db_path)
    dataset_id = load_demo(store, seed=17, variant="positive")
    run = run_analysis(store, dataset_id)
    client = TestClient(create_app(db_path))
    return db_path, store, run, client


def test_saved_hunt_freezes_run_identity_and_paginates_across_restart(tmp_path):
    db_path, store, run, client = setup(tmp_path)
    incident_ids = {item["incident_id"] for item in store.incidents(run["analysis_run_id"])}
    native_before = [(item["incident_id"], item["risk"]["score"]) for item in store.incidents(run["analysis_run_id"])]
    event = next(item for item in store.events_by_ids(run["event_ids"]) if item.action == "file_copy_to_usb")
    response = client.post("/api/hunts", json={
        "name": "Explicit copy observations", "description": "Locate canonical copy telemetry",
        "query": {"filters": [{"field": "action", "op": "eq", "value": "file_copy_to_usb"}]},
        "columns": ["event_time_utc", "action", "user_id", "device_id", "event_id"], "tags": ["triage"]})
    assert response.status_code == 201, response.text
    hunt = response.json()
    response = client.post(f"/api/hunts/{hunt['hunt_id']}/notes", json={
        "expected_revision": hunt["revision"], "note": "Hunt note is analyst context, not detector output"})
    assert response.status_code == 201, response.text
    hunt = response.json()
    response = client.patch(f"/api/hunts/{hunt['hunt_id']}", json={
        "expected_revision": hunt["revision"], "starred": True})
    assert response.status_code == 200, response.text
    hunt = response.json()
    response = client.post(f"/api/hunts/{hunt['hunt_id']}/execute", json={"analysis_run_id": run["analysis_run_id"]})
    assert response.status_code == 201, response.text
    execution = response.json()
    assert execution["hunt_revision"] == hunt["revision"]
    assert execution["event_ids"] == [event.event_id]
    assert execution["result_sha256"]

    # A later upload is outside the retained run, and the old execution reopens with the same result identity.
    load_demo(store, seed=23, variant="benign")
    client.close()
    client = TestClient(create_app(db_path))
    response = client.get(f"/api/hunts/{hunt['hunt_id']}/executions/{execution['execution_id']}?cursor=0&limit=1")
    assert response.status_code == 200, response.text
    page = response.json()
    assert page["result_sha256"] == execution["result_sha256"]
    assert page["items"][0]["event_id"] == event.event_id
    assert page["page_count"] == 1 and page["result_count"] == 1 and page["next_cursor"] is None
    edited = client.patch(f"/api/hunts/{hunt['hunt_id']}", json={
        "expected_revision": hunt["revision"], "query": {"filters": [
            {"field": "action", "op": "eq", "value": "login_success"}]}})
    assert edited.status_code == 200 and edited.json()["revision"] == hunt["revision"] + 1
    assert client.get(f"/api/hunts/{hunt['hunt_id']}?revision={hunt['revision']}").json() == hunt
    old_again = client.get(f"/api/hunts/{hunt['hunt_id']}/executions/{execution['execution_id']}").json()
    assert old_again["result_sha256"] == execution["result_sha256"] and old_again["query_snapshot"] == hunt["query"]
    assert {item["incident_id"] for item in store.incidents(run["analysis_run_id"])} == incident_ids
    assert [(item["incident_id"], item["risk"]["score"]) for item in store.incidents(run["analysis_run_id"])] == native_before

    all_hunt = client.post("/api/hunts", json={"name": "All observations", "query": {"filters": []}}).json()
    all_execution = client.post(f"/api/hunts/{all_hunt['hunt_id']}/execute", json={
        "analysis_run_id": run["analysis_run_id"]}).json()
    assert all_execution["result_count"] == len(run["event_ids"]) > 50
    first = client.get(f"/api/hunts/{all_hunt['hunt_id']}/executions/{all_execution['execution_id']}?cursor=0&limit=50").json()
    second = client.get(f"/api/hunts/{all_hunt['hunt_id']}/executions/{all_execution['execution_id']}?cursor=50&limit=50").json()
    assert first["page_count"] == 50 and first["next_cursor"] == 50
    assert second["page_count"] == len(run["event_ids"]) - 50
    assert [item["event_id"] for item in first["items"] + second["items"]] == all_execution["event_ids"]


def test_hunt_replay_cutoff_rejects_future_observation_and_filter_language_is_bounded(tmp_path):
    _, store, run, client = setup(tmp_path)
    event = next(item for item in store.events_by_ids(run["event_ids"]) if item.action == "file_copy_to_usb")
    frame = create_frame(store, run["analysis_run_id"], (event.event_time_utc - timedelta(microseconds=1)).isoformat())
    hunt = client.post("/api/hunts", json={"name": "Copy hunt", "query": {"filters": [
        {"field": "action", "op": "eq", "value": "file_copy_to_usb"}]}}).json()
    response = client.post(f"/api/hunts/{hunt['hunt_id']}/execute", json={"analysis_run_id": frame["run"]["analysis_run_id"]})
    assert response.status_code == 201, response.text
    assert response.json()["event_ids"] == []
    unsupported = client.post("/api/hunts", json={"name": "Bad", "query": {"filters": [
        {"field": "raw_record", "op": "contains", "value": "copy"}]}})
    assert unsupported.status_code == 422
    regex = client.post("/api/hunts", json={"name": "Bad operator", "query": {"filters": [
        {"field": "action", "op": "regex", "value": ".*"}]}})
    assert regex.status_code == 422
