import copy
import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from traceguard.demo import load_demo
from traceguard.hybrid import run_analysis
from traceguard.main import create_app
from traceguard.storage import Store
from traceguard.external_findings import parse_external


def wazuh_alert(alert_id="1716206454.722325", timestamp="2024-05-20T12:00:54.149+0000"):
    return {"timestamp": timestamp, "rule": {"level": 12, "description": "Synthetic alert: file copy to USB",
        "id": "40101", "mitre": {"id": ["T1052.001"]}},
        "agent": {"id": "001", "name": "fixture-host", "ip": "192.0.2.15"}, "id": alert_id,
        "data": {"srcip": "198.51.100.22", "dstuser": "synthetic-user"}, "location": "fixture"}


def test_wazuh_import_retains_rows_is_context_only_and_links_case_across_restart(tmp_path):
    db_path = tmp_path / "external.sqlite3"
    store = Store(db_path)
    dataset_id = load_demo(store, variant="positive")
    run = run_analysis(store, dataset_id)
    before_run = store.analysis(run["analysis_run_id"])
    before_incidents = store.incidents(run["analysis_run_id"])
    unknown_time = wazuh_alert("unknown-time", None)
    unknown_time.pop("timestamp")
    content = ("\n".join(json.dumps(row) for row in (wazuh_alert(), wazuh_alert(), unknown_time))
               + "\n{broken json}\n").encode()
    client = TestClient(create_app(db_path))
    data = {"profile": "wazuh-alerts-jsonl-v1"}
    files = {"file": ("../../alerts.json", content, "application/x-ndjson")}
    preview = client.post("/api/external/preview", data=data, files=files)
    assert preview.status_code == 200, preview.text
    assert (preview.json()["accepted"], preview.json()["duplicates"], preview.json()["rejected"],
            preview.json()["context_only"]) == (2, 1, 1, 3)

    imported = client.post("/api/external/import", data=data, files=files)
    assert imported.status_code == 201, imported.text
    result = imported.json()
    artifact = result["artifact"]
    assert artifact["filename"] == "alerts.json"
    for key in ("accepted", "rejected", "duplicates", "context_only", "total_rows", "upload_sha256"):
        assert result["quality"][key] == preview.json()[key]
    findings = client.get(f"/api/external/findings?artifact_id={artifact['artifact_id']}&limit=20").json()
    assert findings["total"] == 4
    duplicate = next(item for item in findings["items"] if item["validation_status"] == "duplicate")
    assert duplicate["duplicate_of"]
    assert duplicate["interpretation"].startswith("External finding only")
    unknown = next(item for item in findings["items"] if item.get("upstream_alert_id") == "unknown-time")
    assert unknown["parsed_timestamp_utc"] is None
    assert unknown["timestamp_status"] == "accepted_timestamp_unknown"
    assert unknown["observables"]["src_ip"] == "198.51.100.22"
    assert unknown["upstream_technique_labels"] == ["T1052.001"]

    new_case = client.post("/api/cases", json={"title": "External source context", "author": "operator"})
    assert new_case.status_code == 201, new_case.text
    linked = client.post(f"/api/cases/{new_case.json()['case_id']}/external-findings", json={
        "expected_revision": new_case.json()["revision"], "finding_id": unknown["finding_id"],
        "note": "External source row only; verify independently."})
    assert linked.status_code == 201, linked.text
    export = client.get(f"/api/cases/{new_case.json()['case_id']}/export?format=json").json()
    assert len(export["external_context"]) == 1
    assert "raw_row" not in export["external_context"][0] and "raw_fields" not in export["external_context"][0]
    assert client.post("/api/cases/verify", json=export).json()["valid"]
    tampered = copy.deepcopy(export)
    tampered["external_context"][0]["raw_row_sha256"] = "0" * 64
    assert not client.post("/api/cases/verify", json=tampered).json()["valid"]

    after = TestClient(create_app(db_path))
    assert after.get(f"/api/external/findings/{unknown['finding_id']}").json() == unknown
    with store.connection() as conn:
        retained = conn.execute("SELECT raw_bytes FROM external_artifacts WHERE id=?", (artifact["artifact_id"],)).fetchone()[0]
        assert retained == content
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            conn.execute("UPDATE external_findings SET body='{}' WHERE id=?", (unknown["finding_id"],))
    assert store.analysis(run["analysis_run_id"]) == before_run
    assert store.incidents(run["analysis_run_id"]) == before_incidents
    assert len(store.events(dataset_id)) == len(before_run["event_ids"])


def test_hayabusa_minimal_csv_profile_is_exact_and_formula_safe_on_export(tmp_path):
    store = Store(tmp_path / "hayabusa.sqlite3")
    client = TestClient(create_app(store.path))
    content = ("Timestamp,Computer,Channel,EventID,Level,RecordID,RuleTitle,Details\r\n"
        '2026-05-01 09:10:11.123 +00:00,fixture-host,Security,4663,high,77,"=1+1","quoted, detail"\r\n'
        "2026-05-01 09:11:11.123,fixture-host,Security,4663,medium,78,Second title,No explicit timezone\r\n").encode()
    form = {"profile": "hayabusa-minimal-csv-v1"}
    upload = {"file": ("timeline.csv", content, "text/csv")}
    preview = client.post("/api/external/preview", data=form, files=upload)
    assert preview.status_code == 200, preview.text
    assert preview.json()["accepted"] == 2 and preview.json()["context_only"] == 2, preview.text
    imported = client.post("/api/external/import", data=form, files=upload)
    assert imported.status_code == 201, imported.text
    artifact = imported.json()["artifact"]
    details = client.get(f"/api/external/findings?artifact_id={artifact['artifact_id']}").json()["items"]
    assert details[0]["details"] == "quoted, detail"
    assert details[1]["timestamp_status"] == "accepted_timestamp_unknown_timezone"
    assert details[0]["observables"] == {}  # No prose extraction from Details.
    exported = client.get(f"/api/external/artifacts/{artifact['artifact_id']}/export.csv")
    assert exported.status_code == 200
    assert "'=1+1" in exported.text
    with store.connection() as conn:
        raw = conn.execute("SELECT raw_bytes FROM external_artifacts WHERE id=?", (artifact["artifact_id"],)).fetchone()[0]
        assert raw == content

    unsupported = client.post("/api/external/preview", data=form,
        files={"file": ("not-minimal.csv", b"Timestamp,Computer,Custom\n", "text/csv")})
    assert unsupported.status_code == 422 and "exact documented minimal columns" in unsupported.json()["detail"]
    evtx = client.post("/api/external/preview", data=form,
        files={"file": ("raw.evtx", b"\x00\x01\xff", "application/octet-stream")})
    assert evtx.status_code == 422 and "UTF-8" in evtx.json()["detail"]


def test_external_upload_bounds_and_malformed_timestamp_errors(tmp_path):
    client = TestClient(create_app(tmp_path / "bounds.sqlite3"))
    huge = client.post("/api/external/preview", data={"profile": "wazuh-alerts-jsonl-v1"},
        files={"file": ("large.jsonl", b"x" * (5 * 1024 * 1024 + 1), "application/x-ndjson")})
    assert huge.status_code == 413
    malformed = wazuh_alert()
    malformed["timestamp"] = "tomorrow-ish"
    response = client.post("/api/external/preview", data={"profile": "wazuh-alerts-jsonl-v1"},
        files={"file": ("bad.jsonl", (json.dumps(malformed) + "\n").encode(), "application/x-ndjson")})
    assert response.status_code == 200
    assert response.json()["rejected"] == 1
    assert "malformed" in response.json()["sample"][0]["validation_error"]


def test_checked_in_synthetic_external_schema_fixtures_match_the_declared_profiles():
    root = Path(__file__).resolve().parents[2]
    examples = root / "data" / "samples" / "external"
    wazuh = parse_external((examples / "wazuh-alerts-schema.jsonl").read_bytes(), "wazuh-alerts-jsonl-v1")
    hayabusa = parse_external((examples / "hayabusa-minimal-schema.csv").read_bytes(), "hayabusa-minimal-csv-v1")
    assert len(wazuh) == len(hayabusa) == 1
    assert wazuh[0]["parsed"]["upstream_technique_labels"] == ["T1052.001"]
    assert hayabusa[0]["parsed"]["upstream_rule_title"] == "Synthetic minimal-profile row"
