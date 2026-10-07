import copy
import sqlite3

import pytest
from fastapi.testclient import TestClient

from traceguard.demo import load_demo
from traceguard.hybrid import run_analysis
from traceguard.main import create_app
from traceguard.storage import Store


def setup(tmp_path):
    db_path = tmp_path / "sigma.sqlite3"
    store = Store(db_path)
    dataset = load_demo(store, seed=17, variant="positive")
    run = run_analysis(store, dataset)
    return db_path, store, run, TestClient(create_app(db_path))


def test_original_sigma_hunt_finds_retained_record_without_changing_native_outcomes(tmp_path):
    db_path, store, run, client = setup(tmp_path)
    rule_response = client.get("/api/sigma/rules")
    assert rule_response.status_code == 200, rule_response.text
    rules = rule_response.json()
    assert len([rule for rule in rules if rule["origin"] == "bundled-original"]) == 6
    rule = next(item for item in rules if item["rule"]["title"].endswith("explicit file copy to removable media"))
    original_run = copy.deepcopy(store.analysis(run["analysis_run_id"]))
    original_incidents = copy.deepcopy(store.incidents(run["analysis_run_id"]))
    expected_event = next(event for event in store.events_by_ids(run["event_ids"]) if event.action == "file_copy_to_usb")
    response = client.post(f"/api/sigma/rules/{rule['rule']['id']}/execute", json={"analysis_run_id": run["analysis_run_id"]})
    assert response.status_code == 201, response.text
    execution = response.json()
    assert execution["hit_count"] == 1 and execution["hits"] == [{
        "event_id": expected_event.event_id,
        "matched_fields": {"action": "file_copy_to_usb", "destination_type": "removable_media"}}]
    assert "not a native incident" in execution["interpretation"]
    assert client.get(f"/api/sigma/executions/{execution['execution_id']}").json() == execution
    assert store.analysis(run["analysis_run_id"]) == original_run
    assert store.incidents(run["analysis_run_id"]) == original_incidents
    with store.connection() as conn:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            conn.execute("UPDATE sigma_hunt_executions SET body='{}' WHERE id=?", (execution["execution_id"],))
    reopened = TestClient(create_app(db_path))
    assert reopened.get(f"/api/sigma/executions/{execution['execution_id']}").json() == execution


def test_sigma_scalar_or_list_and_explicit_modifier_subset_evaluates_canonical_fields(tmp_path):
    _, store, run, client = setup(tmp_path)
    yaml_text = """title: Local traceguard success hunt
id: c16166bc-ed2f-4f51-8dae-b45d0925ca01
status: experimental
description: Test OR values and a contains modifier over canonical observations.
author: Test author
references:
  - local-test-fixture
logsource:
  product: traceguard
  service: canonical_observation
detection:
  selection:
    source_type: [auth, file]
    action: [login_success, file_read]
    user_id|contains: user
  condition: selection
level: low
"""
    created = client.post("/api/sigma/rules", json={"yaml_text": yaml_text})
    assert created.status_code == 201, created.text
    rule = created.json()
    original_hash = rule["rule_sha256"]
    events = store.events_by_ids(run["event_ids"])
    expected = {event.event_id for event in events if event.source_type in {"auth", "file"}
                and event.action in {"login_success", "file_read"} and "user" in event.user_id.casefold()}
    execution = client.post(f"/api/sigma/rules/{rule['rule']['id']}/execute", json={
        "analysis_run_id": run["analysis_run_id"], "revision": rule["revision"]}).json()
    assert {item["event_id"] for item in execution["hits"]} == expected
    assert all(item["matched_fields"]["user_id|contains"].casefold().find("user") >= 0 for item in execution["hits"])

    revised_yaml = yaml_text.replace("Test OR values", "Revised OR values").replace("action: [login_success, file_read]", "action: [login_success]")
    revised = client.post(f"/api/sigma/rules/{rule['rule']['id']}/revisions", json={
        "expected_revision": rule["revision"], "yaml_text": revised_yaml})
    assert revised.status_code == 200 and revised.json()["revision"] == 2
    assert revised.json()["rule_sha256"] != original_hash
    assert client.get(f"/api/sigma/rules/{rule['rule']['id']}?revision=1").json()["rule_sha256"] == original_hash
    assert client.get(f"/api/sigma/executions/{execution['execution_id']}").json()["rule_revision"] == 1


@pytest.mark.parametrize("yaml_text, message", [
    ("title: first\ntitle: second\n", "Duplicate YAML key"),
    ("base: &x {action: login_failure}\ndetection: *x\n", "aliases"),
    ("title: x\nid: bad\n", "missing required fields"),
])
def test_sigma_safe_yaml_and_required_metadata_reject_invalid_inputs(tmp_path, yaml_text, message):
    _, _, _, client = setup(tmp_path)
    response = client.post("/api/sigma/rules", json={"yaml_text": yaml_text})
    assert response.status_code == 422
    assert message.casefold() in response.json()["detail"].casefold()


def test_sigma_rejects_unsupported_mappings_conditions_modifiers_and_wildcards(tmp_path):
    _, _, _, client = setup(tmp_path)
    valid = """title: Unsupported case
id: c16166bc-ed2f-4f51-8dae-b45d0925ca02
status: experimental
description: Unsupported Sigma behavior is rejected.
author: Test author
references: [local-test]
logsource: {product: traceguard, service: canonical_observation}
detection:
  selection:
    action|re: login.*
  condition: selection and not other
level: low
"""
    response = client.post("/api/sigma/rules", json={"yaml_text": valid})
    assert response.status_code == 422
    assert "condition" in response.json()["detail"] or "modifier" in response.json()["detail"]
    wildcard = valid.replace("action|re: login.*", "action: login_*").replace("selection and not other", "selection")
    response = client.post("/api/sigma/rules", json={"yaml_text": wildcard})
    assert response.status_code == 422 and "wildcards" in response.json()["detail"]
    wrong_logsource = wildcard.replace("login_*", "login_success").replace("service: canonical_observation", "service: sysmon")
    response = client.post("/api/sigma/rules", json={"yaml_text": wrong_logsource})
    assert response.status_code == 422 and "logsource" in response.json()["detail"]


def test_sigma_rejects_yaml_alias_expansion(tmp_path):
    _, _, _, client = setup(tmp_path)
    alias = """title: alias test
id: c16166bc-ed2f-4f51-8dae-b45d0925ca03
status: experimental
description: Alias expansion is disabled.
author: Test author
references: [local-test]
logsource: {product: traceguard, service: canonical_observation}
detection:
  selection: &selection {action: login_failure}
  condition: selection
copy: *selection
level: low
"""
    response = client.post("/api/sigma/rules", json={"yaml_text": alias})
    assert response.status_code == 422 and "aliases" in response.json()["detail"]


def test_native_rule_catalog_is_read_only_and_explains_gates():
    from traceguard.rule_catalog import native_rule_catalog
    catalog = native_rule_catalog()
    assert catalog["read_only"] is True
    assert [item["stage_id"] for item in catalog["stages"]] == ["authentication", "collection", "transfer"]
    assert any("IP and display-name" in item for item in catalog["identity_and_time_gates"])
    assert "indicator match" in catalog["risk_and_limits"]["never_native_stage"]
