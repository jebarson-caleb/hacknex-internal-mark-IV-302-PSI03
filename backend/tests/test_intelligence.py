import json
import hashlib
import sqlite3
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from traceguard.hybrid import run_analysis
from traceguard.main import create_app
from traceguard.replay import create_frame
from traceguard.storage import Store


def structured_network_run(tmp_path):
    db_path = tmp_path / "indicators.sqlite3"
    store = Store(db_path)
    dataset = store.create_dataset("Structured indicator fixture", "intel-lab")
    event = {"timestamp": "2026-01-01T00:00:00Z", "action": "network_connect", "user_id": "analyst",
        "device_id": "workstation", "src_ip": "192.0.2.10", "dst_ip": "2001:0db8:0:0:0:0:0:1",
        "domain": "Exämple.COM.", "file_hash": "A" * 64}
    store.ingest(dataset, (json.dumps(event) + "\n").encode(), "network.jsonl", "net-sensor", "network")
    run = run_analysis(store, dataset)
    return db_path, store, run, store.events(dataset)[0], TestClient(create_app(db_path))


def indicator_payload():
    return {"name": "Local source-backed collection", "description": "Synthetic exact-match fixture",
        "provenance": "Manually entered from a local exercise note; source authenticity not checked.",
        "source_reference": "exercise-record-42", "indicators": [
            {"type": "ip", "value": "2001:db8::1", "source": "Exercise note", "source_reference": "exercise-record-42#ip", "description": "Synthetic IPv6 assertion"},
            {"type": "domain", "value": "xn--exmple-cua.com.", "source": "Exercise note", "source_reference": "exercise-record-42#domain", "description": "Synthetic domain assertion"},
            {"type": "sha256", "value": "a" * 64, "source": "Exercise note", "source_reference": "exercise-record-42#sha256", "description": "Synthetic file hash assertion"},
            {"type": "ip", "value": "192.0.2.1", "source": "Exercise note", "source_reference": "exercise-record-42#near-ip", "description": "Near-prefix nonmatch"},
        ]}


def test_source_attributed_exact_typed_matches_and_restart_persistence(tmp_path):
    db_path, store, run, event, client = structured_network_run(tmp_path)
    original_run = store.analysis(run["analysis_run_id"])
    original_incidents = store.incidents(run["analysis_run_id"])
    response = client.post("/api/intelligence/collections", json=indicator_payload())
    assert response.status_code == 201, response.text
    collection = response.json()
    values = {item["normalized_value"] for item in collection["indicators"]}
    assert "2001:db8::1" in values and "xn--exmple-cua.com" in values and "a" * 64 in values
    matched = client.post(f"/api/intelligence/collections/{collection['collection_id']}/match", json={
        "analysis_run_id": run["analysis_run_id"]})
    assert matched.status_code == 201, matched.text
    result = matched.json()
    assert result["matched_pair_count"] == 3 and result["matched_event_count"] == 1
    assert {row["match_field"] for row in result["matches"]} == {"dst_ip", "domain", "file_hash"}
    assert all(row["source_assertions"][0]["source_reference"].startswith("exercise-record-42#") for row in result["matches"])
    assert all(row["event_id"] == event.event_id for row in result["matches"])
    assert "not native stages" in result["interpretation"]
    assert all(row["validity_status"] == "unspecified" for row in result["matches"])
    page = client.get(f"/api/intelligence/matches/{result['match_id']}?cursor=0&limit=2").json()
    assert page["page_count"] == 2 and page["next_cursor"] == 2 and page["matched_pair_count"] == 3

    restarted = TestClient(create_app(db_path))
    retained = restarted.get(f"/api/intelligence/matches/{result['match_id']}").json()
    assert retained["result_sha256"] == result["result_sha256"]
    assert restarted.get(f"/api/intelligence/collections/{collection['collection_id']}").json() == collection
    history = restarted.get(f"/api/intelligence/collections/{collection['collection_id']}/matches").json()
    assert history["total"] == 1 and history["items"][0]["match_id"] == result["match_id"]
    with store.connection() as conn:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            conn.execute("UPDATE indicator_matches SET body='{}' WHERE id=?", (result["match_id"],))
    assert store.analysis(run["analysis_run_id"]) == original_run
    assert store.incidents(run["analysis_run_id"]) == original_incidents


@pytest.mark.parametrize("kind,value", [
    ("ip", "999.1.1.1"), ("sha256", "abcd"), ("domain", "*.example.com"), ("domain", "https://example.com/path")
])
def test_indicator_collection_rejects_invalid_typed_values(tmp_path, kind, value):
    _, _, _, _, client = structured_network_run(tmp_path)
    payload = indicator_payload()
    payload["indicators"] = [{"type": kind, "value": value, "source": "Manual", "source_reference": "record-1", "description": "Test assertion"}]
    response = client.post("/api/intelligence/collections", json=payload)
    assert response.status_code == 422


def test_indicator_collection_groups_multiple_source_assertions_for_one_exact_match(tmp_path):
    _, _, run, _, client = structured_network_run(tmp_path)
    payload = indicator_payload()
    payload["indicators"] = [
        {"type": "domain", "value": "Exämple.COM.", "source": "Manual", "source_reference": "record-1", "description": "Source A", "effective_from_utc": "2025-01-01T00:00:00Z", "effective_until_utc": "2027-01-01T00:00:00Z", "source_confidence": 0.7},
        {"type": "domain", "value": "xn--exmple-cua.com", "source": "Manual B", "source_reference": "record-2", "description": "Source B", "effective_until_utc": "2025-01-01T00:00:00Z", "source_confidence": 0.4},
    ]
    response = client.post("/api/intelligence/collections", json=payload)
    assert response.status_code == 201, response.text
    match = client.post(f"/api/intelligence/collections/{response.json()['collection_id']}/match", json={"analysis_run_id": run["analysis_run_id"]})
    # The fixture's event time is 2026-01-01: one assertion is effective and
    # the other expired. Both source claims are displayed in a single pair.
    assert match.status_code == 201, match.text
    domain = next(hit for hit in match.json()["matches"] if hit["indicator_type"] == "domain")
    assert domain["source_status"] == "conflicting_sources"
    assert domain["validity_status"] == "conflicting_validity"
    assert len(domain["source_assertions"]) == 2
    assert {item["validity_at_event_time"] for item in domain["source_assertions"]} == {"effective_at_event_time", "expired_at_event_time"}


def test_indicator_collection_rejects_duplicate_source_assertion_and_bad_intervals(tmp_path):
    _, _, _, _, client = structured_network_run(tmp_path)
    payload = indicator_payload()
    payload["indicators"] = [
        {"type": "domain", "value": "Example.COM.", "source": "Manual", "source_reference": "record-1", "description": "A"},
        {"type": "domain", "value": "example.com", "source": "Manual", "source_reference": "record-1", "description": "Duplicate"},
    ]
    response = client.post("/api/intelligence/collections", json=payload)
    assert response.status_code == 422 and "duplicate source assertion" in response.json()["detail"]
    payload["indicators"] = [{"type": "ip", "value": "192.0.2.1", "source": "Manual", "source_reference": "record-2", "description": "Bad interval", "effective_from_utc": "2026-02-01", "effective_until_utc": "2026-01-01T00:00:00Z"}]
    response = client.post("/api/intelligence/collections", json=payload)
    assert response.status_code == 422


def test_bounded_csv_and_json_indicator_imports_keep_safe_provenance(tmp_path):
    _, _, _, _, client = structured_network_run(tmp_path)
    csv_content = ("type,value,source,source_reference,description,source_confidence,effective_from_utc\n"
                   "ip,192.0.2.10,Exercise,record-1#ip,Synthetic reserved test value,0.65,2025-01-01T00:00:00Z\n").encode()
    response = client.post("/api/intelligence/collections/import", data={
        "import_format": "csv", "name": "CSV fixture", "description": "Bounded import",
        "provenance": "Synthetic locally authored fixture", "source_reference": "record-1"},
        files={"file": ("../../unsafe.csv", csv_content, "text/csv")})
    assert response.status_code == 201, response.text
    collection = response.json()
    assert collection["import"] == {"format": "csv", "filename": "unsafe.csv", "sha256": hashlib.sha256(csv_content).hexdigest()}
    assert collection["indicators"][0]["recorded_at_utc"]
    assert collection["indicators"][0]["source_confidence"] == 0.65

    json_content = json.dumps([{"type": "domain", "value": "example.com", "source": "Exercise",
        "source_reference": "record-2#domain", "description": "Synthetic domain"}]).encode()
    response = client.post("/api/intelligence/collections/import", data={
        "import_format": "json", "name": "JSON fixture", "provenance": "Local fixture", "source_reference": "record-2"},
        files={"file": ("indicators.json", json_content, "application/json")})
    assert response.status_code == 201, response.text
    assert response.json()["indicators"][0]["normalized_value"] == "example.com"

    duplicate_key = b'[{"type":"ip","type":"domain","value":"example.com","source":"S","source_reference":"r","description":"d"}]'
    response = client.post("/api/intelligence/collections/import", data={
        "import_format": "json", "name": "Bad fixture", "provenance": "Local fixture", "source_reference": "record-3"},
        files={"file": ("bad.json", duplicate_key, "application/json")})
    assert response.status_code == 422 and "Duplicate JSON key" in response.json()["detail"]


def test_indicator_import_enforces_file_and_record_bounds(tmp_path):
    _, _, _, _, client = structured_network_run(tmp_path)
    response = client.post("/api/intelligence/collections/import", data={
        "import_format": "csv", "name": "Too large", "provenance": "Local", "source_reference": "r"},
        files={"file": ("large.csv", b"x" * (1024 * 1024 + 1), "text/csv")})
    assert response.status_code == 413


def test_indicator_match_is_scoped_by_replay_cutoff_and_only_exact_structured_fields(tmp_path):
    _, store, run, event, client = structured_network_run(tmp_path)
    collection = client.post("/api/intelligence/collections", json=indicator_payload()).json()
    frame = create_frame(store, run["analysis_run_id"], (event.event_time_utc - timedelta(microseconds=1)).isoformat())
    response = client.post(f"/api/intelligence/collections/{collection['collection_id']}/match", json={
        "analysis_run_id": frame["run"]["analysis_run_id"]})
    assert response.status_code == 201 and response.json()["matches"] == []

    # The near-prefix IPv4 value cannot match the longer structured source address.
    revised_payload = {**indicator_payload(), "indicators": [
        {"type": "ip", "value": "192.0.2.1", "source": "Manual", "source_reference": "record-ip", "description": "Near-prefix"}]}
    revised = client.patch(f"/api/intelligence/collections/{collection['collection_id']}", json={
        "expected_revision": collection["revision"], "indicators": revised_payload["indicators"]})
    assert revised.status_code == 200, revised.text
    exact = client.post(f"/api/intelligence/collections/{collection['collection_id']}/match", json={
        "analysis_run_id": run["analysis_run_id"]}).json()
    assert exact["matches"] == []
