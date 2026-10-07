import json
from datetime import timedelta

from fastapi.testclient import TestClient

from traceguard.demo import load_demo
from traceguard.hybrid import run_analysis
from traceguard.main import create_app
from traceguard.replay import create_frame
from traceguard.storage import Store


def test_attack_mapping_and_navigator_layer_follow_current_verified_frame(tmp_path):
    db_path = tmp_path / "attack.sqlite3"
    store = Store(db_path)
    dataset_id = load_demo(store, seed=17, variant="positive")
    run = run_analysis(store, dataset_id)
    parent = store.analysis(run["analysis_run_id"])
    rows = store.events_by_ids(parent["event_ids"])
    copy_event = next(event for event in rows if event.action == "file_copy_to_usb")
    before_copy = create_frame(store, parent["analysis_run_id"],
        (copy_event.event_time_utc - timedelta(microseconds=1)).isoformat())["run"]
    client = TestClient(create_app(db_path))

    full = client.get(f"/api/analyses/{parent['analysis_run_id']}/attack")
    assert full.status_code == 200, full.text
    view = full.json()
    assert {item["technique_id"] for item in view["mappings"]} == {"T1005", "T1052.001"}
    transfer = next(item for item in view["mappings"] if item["technique_id"] == "T1052.001")
    assert transfer["supporting_stage_ids"] == ["authentication", "collection", "transfer"]
    assert transfer["evidence"][0]["action"] == "file_copy_to_usb"
    assert transfer["evidence"][0]["source_rows"]

    early = client.get(f"/api/analyses/{before_copy['analysis_run_id']}/attack").json()
    assert "T1005" in {item["technique_id"] for item in early["mappings"]}
    assert "T1052.001" not in {item["technique_id"] for item in early["mappings"]}
    assert any(item["technique_id"] == "T1052.001" for item in early["missing_support"])

    layer_response = client.get(f"/api/analyses/{parent['analysis_run_id']}/navigator-layer")
    assert layer_response.status_code == 200
    layer = layer_response.json()
    assert layer["versions"] == {"navigator": "4.6.5", "layer": "4.3"}
    assert layer["domain"] == "enterprise-attack"
    assert {item["techniqueID"] for item in layer["techniques"]} == {"T1005", "T1052.001"}
    assert all("observation count" in item["comment"] and "not risk or confidence" in item["comment"] for item in layer["techniques"])
    serialized = json.dumps(layer)
    assert "/data/quarterly.csv" not in serialized
    assert "MITRE Corporation" in layer["description"]

    restarted = TestClient(create_app(db_path))
    assert restarted.get(f"/api/analyses/{before_copy['analysis_run_id']}/attack").json() == early
