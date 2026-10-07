from fastapi.testclient import TestClient

from traceguard.main import create_app


def test_state_changing_browser_requests_require_same_origin_when_origin_is_present(tmp_path):
    client = TestClient(create_app(tmp_path / "origin.sqlite3"))
    denied = client.post("/api/datasets/demo", json={"variant": "positive", "seed": 17},
        headers={"Origin": "https://attacker.invalid"})
    assert denied.status_code == 403
    assert client.get("/api/datasets").json() == []

    same_origin = client.post("/api/datasets/demo", json={"variant": "positive", "seed": 17},
        headers={"Origin": "http://testserver"})
    assert same_origin.status_code == 201, same_origin.text


def test_referer_and_fetch_metadata_cannot_bypass_origin_check(tmp_path):
    client = TestClient(create_app(tmp_path / "origin-referer.sqlite3"))
    referer = client.post("/api/datasets/demo", json={"variant": "positive", "seed": 17},
        headers={"Referer": "http://attacker.invalid/form"})
    assert referer.status_code == 403
    fetch_site = client.post("/api/datasets/demo", json={"variant": "positive", "seed": 17},
        headers={"Origin": "http://testserver", "Sec-Fetch-Site": "cross-site"})
    assert fetch_site.status_code == 403
    assert client.get("/api/datasets").json() == []
