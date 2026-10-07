import csv
import io
import json
import random
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from traceguard.demo import generate_demo, load_demo
from traceguard.detection import analyze, correlate, validate_evidence
from traceguard.ingest import MAX_FILE_BYTES, entity_id, normalize_record, parse_file
from traceguard.main import create_app
from traceguard.schemas import Incident, ResourceContext, SourceContext
from traceguard.storage import Store


@pytest.fixture
def store(tmp_path):
    return Store(tmp_path / "evidence.sqlite3")


def fixture(store, variant="positive", edit=None, duplicate=False, seed=17):
    files, resources = generate_demo(seed, variant)
    if edit:
        edit(files)
    dataset = store.create_dataset("test", "synthetic-office")
    for family, rows in files.items():
        random.Random(42).shuffle(rows)
        if duplicate:
            rows = rows + rows
        store.ingest(dataset, ("\n".join(json.dumps(r) for r in rows)).encode(),
                     f"{family}.jsonl", family, family)
    store.set_resources(dataset, [ResourceContext.model_validate(r) for r in resources])
    return dataset


def candidates(store, dataset):
    return correlate(store.events(dataset), store.resources(dataset), dataset, "fixed-run")


def test_supported_chain_and_resolvable_provenance(store):
    dataset = fixture(store)
    result = analyze(store, dataset)
    assert (result["mode"], result["incident_count"], result["partial_count"]) == ("rules-only", 1, 0)
    item = Incident.model_validate(store.incidents(result["analysis_run_id"])[0])
    assert [s.stage_id for s in item.stages] == ["authentication", "collection", "transfer"]
    assert item.stages[0].end_time_utc < item.stages[1].start_time_utc < item.stages[2].start_time_utc
    assert item.validation["valid"] and item.validation["provenance_events_checked"] == 24
    for eid in item.selected_evidence:
        evidence = store.evidence(eid)
        assert all(r["hash_valid"] and r["file_hash_valid"] for r in evidence["source_records"])
        assert not store.provenance_errors(eid)
    assert item.risk["anomaly_score"] is None


@pytest.mark.parametrize("variant,alerts,partials", [("positive", 1, 0), ("benign", 0, 0), ("missing-transfer", 0, 1)])
def test_seeded_scenarios(store, variant, alerts, partials):
    for seed in (2, 17, 99):
        dataset = load_demo(store, seed, variant)
        run = analyze(store, dataset)
        assert (run["incident_count"], run["partial_count"]) == (alerts, partials)
        if partials:
            item = store.incidents(run["analysis_run_id"])[0]
            assert item["missing_evidence"]
            assert "transfer" not in [s["stage_id"] for s in item["stages"]]


def test_shuffle_duplicates_and_repeated_analysis(store):
    dataset = fixture(store)
    before = candidates(store, dataset)
    before_bytes = sum(e.bytes_written or 0 for e in store.events(dataset))
    for family, rows in generate_demo()[0].items():
        random.Random(70).shuffle(rows)
        content = "\n".join(json.dumps(r) for r in rows).encode()
        store.ingest(dataset, content, f"{family}.jsonl", family, family)
    assert store.quality(dataset)["duplicates"] == 79
    assert candidates(store, dataset) == before
    assert sum(e.bytes_written or 0 for e in store.events(dataset)) == before_bytes
    assert len(before[0].selected_evidence) == 4
    for eid in before[0].selected_evidence:
        assert len(store.evidence(eid)["source_records"]) == 2
    one, two = analyze(store, dataset), analyze(store, dataset)
    assert one["dataset_fingerprint"] == two["dataset_fingerprint"]
    assert one["analysis_run_id"] != two["analysis_run_id"]


@pytest.mark.parametrize("change", ["actor", "endpoint", "resource", "usb", "ordering", "equal-time", "unmount", "no-mount", "zero-bytes"])
def test_incompatible_transfer_is_not_asserted(store, change):
    def edit(files):
        copy = files["file"][-1]
        if change == "actor": copy["user_id"] = "someone-else"
        elif change == "endpoint": copy["device_id"] = "other-endpoint"
        elif change == "resource": copy["resource_id"] = "unrelated-file"
        elif change == "usb": copy["removable_device_id"] = "other-usb"
        elif change == "ordering": copy["timestamp"] = files["auth"][-1]["timestamp"]
        elif change == "equal-time": copy["timestamp"] = files["file"][-2]["timestamp"]
        elif change == "unmount":
            row = {**files["device"][0], "action": "usb_unmount", "timestamp": copy["timestamp"]}
            files["device"].append(row)
        elif change == "no-mount": files["device"] = []
        else: copy["bytes_written"] = 0
    dataset = fixture(store, edit=edit)
    items = candidates(store, dataset)
    assert len(items) == 1 and items[0].decision == "partial_observation"
    assert len(items[0].stages) == 2
    assert validate_evidence(items[0], store.events(dataset), store.resources(dataset), store)["valid"]


def test_mount_can_precede_collection(store):
    def edit(files):
        time = datetime.fromisoformat(files["auth"][-1]["timestamp"])
        files["device"][0]["timestamp"] = (time - timedelta(minutes=2)).isoformat()
    dataset = fixture(store, edit=edit)
    assert candidates(store, dataset)[0].decision == "incident"


@pytest.mark.parametrize("family,index,partials", [("auth", -1, 0), ("file", -2, 0), ("file", -1, 1), ("device", 0, 1)])
def test_failed_observations_cannot_support_completed_stages(store, family, index, partials):
    def edit(files):
        files[family][index]["outcome"] = "failure"
    items = candidates(store, fixture(store, edit=edit))
    assert len(items) == partials
    assert all(item.decision == "partial_observation" for item in items)


def test_cutoff_and_future_events(store):
    dataset = fixture(store)
    copy = next(e for e in store.events(dataset) if e.action == "file_copy_to_usb")
    cutoff = copy.event_time_utc - timedelta(seconds=1)
    before = analyze(store, dataset, cutoff)
    assert before["incident_count"] == 0 and before["partial_count"] == 1
    future = {"timestamp": "2027-01-01T01:00:00Z", "action": "login_success", "user_id": "future", "device_id": "future", "app_id": "future"}
    store.ingest(dataset, json.dumps(future).encode(), "later.jsonl", "auth", "auth")
    after = analyze(store, dataset, cutoff)
    assert after["dataset_fingerprint"] == before["dataset_fingerprint"]
    assert after["incident_count"] == before["incident_count"]
    with pytest.raises(ValueError, match="explicit timezone"):
        analyze(store, dataset, datetime(2026, 1, 1))


def test_fabricated_unrelated_and_changed_predicate_citations_fail(store):
    dataset = fixture(store)
    original = candidates(store, dataset)[0]
    for kind in ("unknown", "unrelated", "predicate", "history", "identity"):
        item = original.model_copy(deep=True)
        if kind == "unknown": item.stages[2].evidence_event_ids = ["fabricated"]
        elif kind == "unrelated": item.stages[2].evidence_event_ids = [store.events(dataset)[0].event_id]
        elif kind == "predicate": item.stages[2].matched_fields["bytes_written"] = 999999
        elif kind == "history": item.stages[0].historical_comparison["prior_successful_logins"] = 999
        else: item.user_id = "other-account"
        assert not validate_evidence(item, store.events(dataset), store.resources(dataset), store)["valid"]


def test_provenance_tampering_fails(store):
    dataset = fixture(store)
    item = candidates(store, dataset)[0]
    with store.connection() as conn:
        conn.execute("UPDATE records SET raw=? WHERE event_id=?", ('{"action":"fake"}', item.selected_evidence[0]))
    assert not validate_evidence(item, store.events(dataset), store.resources(dataset), store)["valid"]
    with pytest.raises(ValueError, match="evidence validation failed"):
        analyze(store, dataset)


@pytest.mark.parametrize("source_type,row,field", [
    ("auth", {"action":"login_success", "app_id":"a"}, "app_id"),
    ("file", {"action":"file_read", "resource_id":"r"}, "resource_id"),
    ("device", {"action":"usb_mount", "removable_device_id":"r"}, "removable_device_id"),
    ("network", {"action":"network_connect", "dst_ip":"192.0.2.1"}, "dst_ip"),
])
def test_four_adapters(source_type, row, field):
    context = SourceContext(dataset_id="d", environment_id="env", source_id="s", source_type=source_type)
    record = {"timestamp":"2026-01-02T05:30:00+05:30", "user_id":"u", "device_id":"d", **row}
    normalized = normalize_record(record, context)
    assert not normalized.error and normalized.event.event_time_utc.hour == 0
    assert normalized.event.user_id == "env:user:u"
    assert normalized.event.original_timestamp == record["timestamp"]
    record.pop(field)
    assert normalize_record(record, context).error


def test_naive_missing_and_dst_timestamps():
    context = SourceContext(dataset_id="d", environment_id="e", source_id="a", source_type="auth")
    record = {"timestamp":"2026-01-02T12:00:00", "action":"login_success", "user_id":"u", "device_id":"d", "app_id":"a"}
    assert "declared source timezone" in normalize_record(record, context).error
    context.timezone = "Asia/Kolkata"
    event = normalize_record(record, context).event
    assert event.event_time_utc.hour == 6 and event.event_time_utc.minute == 30
    assert event.timezone_assumption == "Asia/Kolkata"
    context.timezone = "America/New_York"
    for value in ("2026-11-01T01:30:00", "2026-03-08T02:30:00"):
        assert normalize_record({**record, "timestamp":value}, context).error
    assert normalize_record({**record, "timestamp":"bad"}, context).error
    assert normalize_record({**record, "timestamp":None}, context).error


def test_csv_jsonl_quality_and_conflicting_vendor_ids(store):
    dataset = store.create_dataset("uploaded", "local")
    row = {"timestamp":"2026-01-01T00:00:00Z", "action":"login_success", "user_id":"u", "device_id":"d", "app_id":"a", "source_event_id":"vendor-1"}
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=list(row)); writer.writeheader(); writer.writerow(row)
    store.ingest(dataset, stream.getvalue().encode(), "auth.csv", "a", "auth")
    body = "\n".join([json.dumps(row), json.dumps({**row, "device_id":"other"}), "{broken", "[]",
                      json.dumps({**row, "source_event_id":"vendor-2", "action":"future_action"})])
    quality = store.ingest(dataset, body.encode(), "auth.jsonl", "a", "auth")
    assert (quality["accepted"], quality["duplicates"], quality["rejected"], quality["unsupported"]) == (2, 1, 3, 1)
    assert len(store.evidence(store.events(dataset)[0].event_id)["source_records"]) >= 1
    with pytest.raises(ValueError, match="different adapter"):
        store.ingest(dataset, b"", "device.jsonl", "a", "device")
    assert parse_file(b"", "empty.csv") == []
    with pytest.raises(ValueError): parse_file(b"a,a\n1,2", "bad.csv")
    with pytest.raises(ValueError): parse_file(b"a", "bad.zip")


def test_namespaces_no_implicit_alias_or_nat_merge(store):
    first = entity_id("env1", "user", "u")
    second = entity_id("env2", "user", "u")
    assert first != second
    assert entity_id("env:a", "user", "u") != entity_id("env", "user", "a:u")
    def edit(files):
        files["file"][-2]["user_id"] = "unrelated-with-same-IP"
    assert candidates(store, fixture(store, edit=edit)) == []


def test_insufficient_history_empty_and_untrusted_sensitivity(store):
    empty = store.create_dataset("empty", "local")
    result = analyze(store, empty)
    assert result["event_count"] == 0 and result["incident_count"] == 0
    assert any("Empty dataset" in w for w in result["warnings"])
    def edit(files):
        files["auth"] = files["auth"][-1:]
    dataset = fixture(store, edit=edit)
    assert analyze(store, dataset)["incident_count"] == 0
    assert any("Insufficient" in w for w in analyze(store, dataset)["warnings"])
    dataset = fixture(store)
    with store.connection() as conn: conn.execute("DELETE FROM resources WHERE dataset_id=?", (dataset,))
    assert candidates(store, dataset) == []
    assert any("trusted sensitivity" in w for w in analyze(store, dataset)["warnings"])


def test_expired_sensitivity_and_immutable_context_snapshot(store):
    dataset = fixture(store)
    run = analyze(store, dataset)
    resource = store.resources(dataset)[0]
    resource["effective_until"] = "2026-01-02T00:00:00+00:00"
    store.set_resources(dataset, [ResourceContext.model_validate(resource)])
    assert candidates(store, dataset) == []
    assert store.analysis(run["analysis_run_id"])["resource_context_snapshot"][0]["effective_until"] is None


def test_api_persistence_end_to_end_and_errors(tmp_path):
    path = tmp_path / "api.sqlite3"
    with TestClient(create_app(path)) as client:
        assert client.get("/api/health").json()["ml_implemented"] is True
        loaded = client.post("/api/datasets/demo", json={"variant":"positive", "seed":17}).json()
        dataset = loaded["dataset"]["id"]
        result = client.post("/api/analyses", json={"dataset_id":dataset}).json()
        assert result["incident_count"] == 1
        item = client.get(f"/api/analyses/{result['analysis_run_id']}/incidents").json()[0]
        incident_id = item["incident_id"]
        evidence = client.get(f"/api/incidents/{incident_id}/evidence").json()
        assert len(evidence["selected"]) == 4 and len(evidence["history"]) == 20
        events = client.get("/api/events", params={"dataset_id":dataset, "limit":2}).json()
        assert len(events["items"]) == 2 and events["next_cursor"] == 2
        assert client.get("/api/events", params={"dataset_id":dataset, "limit":201}).status_code == 422
        assert client.get("/api/events/fake").status_code == 404
        assert client.get("/api/unknown").status_code == 404
        assert client.post("/api/analyses", json={"dataset_id":dataset, "mode":"hybrid"}).status_code == 422
        assert client.post("/api/analyses", json={"dataset_id":dataset, "cutoff":"2026-01-01T00:00:00"}).status_code == 422
    with TestClient(create_app(path)) as client:
        assert client.get(f"/api/incidents/{incident_id}").json()["incident_id"] == incident_id


def test_upload_rejects_archives_limits_and_treats_filename_sql_as_data(tmp_path):
    app = create_app(tmp_path / "api.sqlite3")
    with TestClient(app) as client:
        params = {"source_type":"auth", "source_id":"a", "environment_id":"local"}
        assert client.post("/api/datasets/upload", data=params, files={"file":("evil.zip", b"stuff")}).status_code == 422
        assert client.get("/api/datasets").json() == []
        huge = client.post("/api/datasets/upload", data=params, files={"file":("huge.jsonl", b"x" * (MAX_FILE_BYTES + 300000))})
        assert huge.status_code == 413
        row = {"timestamp":"2026-01-01T00:00:00Z", "action":"login_success", "user_id":"';DROP TABLE events;--", "device_id":"d", "app_id":"<script>alert(1)</script>"}
        result = client.post("/api/datasets/upload", data=params, files={"file":("../../evil.jsonl", json.dumps(row).encode())})
        assert result.status_code == 201
        dataset = result.json()["dataset"]["id"]
        assert client.get("/api/events", params={"dataset_id":dataset}).json()["total"] == 1
        assert result.json()["quality"]["accepted"] == 1
        assert len(app.state.store.datasets()) == 1


def test_input_record_limits_and_negative_bytes():
    with pytest.raises(ValueError, match="10,000"):
        parse_file(b"{}\n" * 10001, "many.jsonl")
    rows = parse_file((json.dumps({"x":"a" * 66000}) + "\n").encode(), "large.jsonl")
    assert rows[0][2] == "record exceeds 64 KiB"
    context = SourceContext(dataset_id="d", environment_id="e", source_id="f", source_type="file")
    result = normalize_record({"timestamp":"2026-01-01T00:00:00Z", "action":"file_read", "resource_id":"r",
                               "user_id":"u", "device_id":"d", "bytes_read":-1}, context)
    assert result.error


def test_static_build_does_not_swallow_api_errors(tmp_path):
    built = tmp_path / "dist"; built.mkdir(); (built / "index.html").write_text("<html>TraceGuard</html>")
    with TestClient(create_app(tmp_path / "api.sqlite3", built)) as client:
        assert "TraceGuard" in client.get("/").text
        response = client.get("/api/missing")
        assert response.status_code == 404 and response.headers["content-type"] == "application/json"
