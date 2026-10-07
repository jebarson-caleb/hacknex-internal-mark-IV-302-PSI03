import asyncio
import json

import pytest

from traceguard.ingest import MAX_FILE_BYTES, digest, json_bytes, parse_file
from traceguard.main import create_app
from traceguard.storage import Store
from traceguard.ingest import normalize_record
from traceguard.schemas import SourceContext


def test_chunked_upload_size_limit_without_content_length(tmp_path):
    app = create_app(tmp_path / "chunked.sqlite3")
    messages = []
    chunks = [
        b'--boundary\r\nContent-Disposition: form-data; name="file"; filename="huge.jsonl"\r\n\r\n',
        b"x" * (MAX_FILE_BYTES + 300000),
        b"\r\n--boundary--\r\n",
    ]

    async def receive():
        body = chunks.pop(0)
        return {"type": "http.request", "body": body, "more_body": bool(chunks)}

    async def send(message):
        messages.append(message)

    scope = {"type":"http", "asgi":{"version":"3.0"}, "method":"POST", "scheme":"http",
             "path":"/api/datasets/upload", "raw_path":b"/api/datasets/upload", "query_string":b"",
             "root_path":"", "headers":[(b"content-type", b"multipart/form-data; boundary=boundary")],
             "client":("127.0.0.1",1234), "server":("127.0.0.1",8000), "http_version":"1.1"}
    asyncio.run(app(scope, receive, send))
    start = next(m for m in messages if m["type"] == "http.response.start")
    assert start["status"] == 413


def test_malformed_csv_extra_and_missing_columns_are_quarantined(tmp_path):
    store = Store(tmp_path / "malformed.sqlite3")
    dataset = store.create_dataset("bad rows", "local")
    content = b"timestamp,action,user_id,device_id,app_id\n2026-01-01T00:00:00Z,login_success,u,d,a,extra\n2026-01-01T00:00:00Z,login_success,u\n"
    quality = store.ingest(dataset, content, "bad.csv", "auth", "auth")
    assert quality["rejected"] == 2 and quality["accepted"] == 0
    assert all("column count mismatch" in e["error"] for e in quality["errors"])


def test_different_timestamps_do_not_deduplicate(tmp_path):
    store = Store(tmp_path / "repeated.sqlite3")
    dataset = store.create_dataset("repeat", "local")
    row = {"action":"login_success", "user_id":"u", "device_id":"d", "app_id":"a"}
    rows = [{**row,"timestamp":time} for time in ("2026-01-01T00:00:00Z", "2026-01-01T00:00:01Z")]
    quality = store.ingest(dataset, "\n".join(json.dumps(r) for r in rows).encode(), "auth.jsonl", "auth", "auth")
    assert quality["accepted"] == 2 and quality["duplicates"] == 0


def test_a_raw_row_with_recomputed_hash_must_still_match_original_file(tmp_path):
    store = Store(tmp_path / "tamper.sqlite3")
    dataset = store.create_dataset("provenance", "local")
    row = {"timestamp":"2026-01-01T00:00:00Z", "action":"login_success", "user_id":"u", "device_id":"d", "app_id":"a"}
    store.ingest(dataset, json.dumps(row).encode(), "auth.jsonl", "auth", "auth")
    event = store.events(dataset)[0]
    # Even unchanged recognized fields cannot mask a forged raw source record.
    row["invented_note"] = "not in the original file"
    with store.connection() as conn:
        conn.execute("UPDATE records SET raw=?, raw_sha256=? WHERE event_id=?",
                     (json.dumps(row), digest(json_bytes(row)), event.event_id))
    assert not store.evidence(event.event_id)["source_records"][0]["file_row_valid"]
    assert store.provenance_errors(event.event_id)


@pytest.mark.parametrize("invalid",[True,10**400])
def test_invalid_numeric_bytes_are_quarantined_before_feature_transforms(invalid):
    record={"timestamp":"2026-01-01T00:00:00Z","action":"file_read","user_id":"u","device_id":"d","resource_id":"r","bytes_read":invalid}
    result=normalize_record(record,SourceContext(dataset_id="d",environment_id="e",source_id="f",source_type="file"))
    assert result.error and result.event is None
