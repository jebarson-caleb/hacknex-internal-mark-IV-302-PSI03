"""Exercise a clean native install with outbound connections blocked."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone


OFFLINE_GUARD = r'''import socket
_gai = socket.getaddrinfo
_connect = socket.socket.connect
_connect_ex = socket.socket.connect_ex
def _loopback(host):
    return str(host).strip("[]").lower() in {"localhost", "127.0.0.1", "::1"}
def _guard_gai(host, *args, **kwargs):
    if not _loopback(host):
        raise OSError("release offline guard blocked non-loopback name resolution")
    return _gai(host, *args, **kwargs)
def _guard_connect(self, address):
    if not isinstance(address, tuple) or not _loopback(address[0]):
        raise OSError("release offline guard blocked non-loopback connection")
    return _connect(self, address)
def _guard_connect_ex(self, address):
    if not isinstance(address, tuple) or not _loopback(address[0]):
        raise OSError("release offline guard blocked non-loopback connection")
    return _connect_ex(self, address)
socket.getaddrinfo = _guard_gai
socket.socket.connect = _guard_connect
socket.socket.connect_ex = _guard_connect_ex
'''


def _api(base: str, path: str, method: str = "GET", body=None, content_type="application/json"):
    payload = None if body is None else body if isinstance(body, bytes) else json.dumps(body).encode()
    headers = {} if payload is None else {"Content-Type": content_type}
    request = urllib.request.Request(base + path, data=payload, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=90) as response:
        return response.status, response.read(), dict(response.headers)


def _multipart(profile: str, filename: str, payload: bytes):
    boundary = "TraceGuardReleaseBoundary7c021d"
    sections = [
        f"--{boundary}\r\nContent-Disposition: form-data; name=\"profile\"\r\n\r\n{profile}\r\n".encode(),
        (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{filename}\"\r\n"
         "Content-Type: application/x-ndjson\r\n\r\n").encode(),
        payload,
        f"\r\n--{boundary}--\r\n".encode(),
    ]
    return f"multipart/form-data; boundary={boundary}", b"".join(sections)


def _start(root: Path, db: Path, port: int, guard_dir: Path, logs_dir: Path):
    env = os.environ.copy()
    env["TRACEGUARD_DB"] = str(db)
    env["PYTHONPATH"] = str(guard_dir) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(name, None)
    stdout = (logs_dir / f"server-{port}.log").open("ab")
    process = subprocess.Popen([sys.executable, str(root / "scripts" / "run_demo.py"), "--port", str(port)],
        cwd=root, env=env, stdout=stdout, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    for _ in range(120):
        if process.poll() is not None:
            stdout.close()
            raise RuntimeError(f"fresh server exited early; see {logs_dir / f'server-{port}.log'}")
        try:
            status, body, _ = _api(base, "/api/health")
            if status == 200 and json.loads(body).get("status") == "ok":
                return process, stdout, base
        except (OSError, urllib.error.URLError):
            time.sleep(.15)
    process.terminate(); process.wait(timeout=15); stdout.close()
    raise RuntimeError("fresh server did not become healthy")


def _stop(process, log):
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=20)
    log.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    root = Path(__file__).resolve().parents[1]
    # The acceptance client has no proxy settings; the subprocess guard below blocks all non-loopback DNS and sockets.
    urllib.request.install_opener(urllib.request.build_opener(urllib.request.ProxyHandler({})))
    logs_dir = output / "server-logs"
    logs_dir.mkdir()
    guard_dir = output / "offline-guard"
    guard_dir.mkdir()
    (guard_dir / "sitecustomize.py").write_text(OFFLINE_GUARD, encoding="utf-8")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(guard_dir) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    probe = subprocess.run([sys.executable, "-c", "import socket; socket.getaddrinfo('203.0.113.77', 443)"],
        cwd=root, env=env, capture_output=True, text=True, timeout=15)
    if probe.returncode == 0 or "offline guard blocked" not in (probe.stdout + probe.stderr):
        raise RuntimeError("offline guard self-test did not reject non-loopback name resolution")

    with socket.socket() as candidate:
        candidate.bind(("127.0.0.1", 0))
        port = candidate.getsockname()[1]
    db_path = output / "fresh-native.sqlite3"
    started = time.perf_counter()
    process, server_log, base = _start(root, db_path, port, guard_dir, logs_dir)
    try:
        status, home, _ = _api(base, "/")
        assert status == 200 and b"<div id=\"root\"></div>" in home
        _, body, _ = _api(base, "/api/datasets/demo", "POST", {"variant": "positive", "seed": 17})
        dataset_id = json.loads(body)["dataset"]["id"]
        _, body, _ = _api(base, "/api/analyses", "POST", {"dataset_id": dataset_id, "mode": "rules-only"})
        run = json.loads(body)
        run_id = run["analysis_run_id"]
        _, body, _ = _api(base, f"/api/analyses/{run_id}/incidents")
        incidents = json.loads(body)
        incident = next(item for item in incidents if len(item.get("stages", [])) == 3)
        original_incidents = incidents

        _, body, _ = _api(base, "/api/cases/from-incident", "POST", {
            "incident_id": incident["incident_id"], "title": "Fresh offline release case",
            "description": "Synthetic native acceptance", "priority": "high", "author": "operator"})
        case = json.loads(body)
        _, body, _ = _api(base, f"/api/cases/{case['case_id']}/notes", "POST", {
            "expected_revision": case["revision"], "text": "Persisted across restart; human context only.", "author": "operator"})
        case = json.loads(body)

        fixture_path = root / "data" / "samples" / "external" / "wazuh-alerts-schema.jsonl"
        mime, multipart = _multipart("wazuh-alerts-jsonl-v1", fixture_path.name, fixture_path.read_bytes())
        _, body, _ = _api(base, "/api/external/import", "POST", multipart, mime)
        imported = json.loads(body)
        artifact_id = imported["artifact"]["artifact_id"]
        _, body, _ = _api(base, f"/api/external/findings?artifact_id={artifact_id}&limit=20")
        finding = next(item for item in json.loads(body)["items"] if item["validation_status"] == "accepted")
        _, body, _ = _api(base, f"/api/cases/{case['case_id']}/external-findings", "POST", {
            "expected_revision": case["revision"], "finding_id": finding["finding_id"],
            "note": "External source context", "author": "operator"})
        case = json.loads(body)

        _, layer_bytes, _ = _api(base, f"/api/analyses/{run_id}/navigator-layer")
        layer = json.loads(layer_bytes)
        assert {item["techniqueID"] for item in layer["techniques"]} == {"T1005", "T1052.001"}
        _, csv_bytes, _ = _api(base, f"/api/external/artifacts/{artifact_id}/export.csv")
        assert b"synthetic-alert-0001" in csv_bytes and b"fixture-host" in csv_bytes
        _, export_bytes, _ = _api(base, f"/api/cases/{case['case_id']}/export?format=json")
        export = json.loads(export_bytes)
        assert len(export["external_context"]) == 1
        assert "raw_row" not in export["external_context"][0]
        _, verified_bytes, _ = _api(base, "/api/cases/verify", "POST", export)
        verified = json.loads(verified_bytes)
        if not verified["valid"]:
            raise RuntimeError(f"fresh case export verification failed: {verified['errors']}")
        tampered = json.loads(json.dumps(export))
        tampered["external_context"][0]["raw_row_sha256"] = "0" * 64
        _, tamper_bytes, _ = _api(base, "/api/cases/verify", "POST", tampered)
        tamper = json.loads(tamper_bytes)
        assert not tamper["valid"]
        _, run_bytes, _ = _api(base, f"/api/analyses/{run_id}")
        run_before_restart = json.loads(run_bytes)
        assert json.loads(_api(base, f"/api/analyses/{run_id}/incidents")[1]) == original_incidents

        _stop(process, server_log)
        process = server_log = None
        process, server_log, base = _start(root, db_path, port, guard_dir, logs_dir)
        _, body, _ = _api(base, f"/api/cases/{case['case_id']}")
        reopened = json.loads(body)
        assert reopened["notes"] and len(reopened["external_findings"]) == 1
        _, body, _ = _api(base, f"/api/external/findings/{finding['finding_id']}")
        assert json.loads(body)["finding_id"] == finding["finding_id"]
        _, body, _ = _api(base, f"/api/analyses/{run_id}")
        assert json.loads(body) == run_before_restart
        _, body, _ = _api(base, f"/api/analyses/{run_id}/incidents")
        assert json.loads(body) == original_incidents
        result = {"fresh_native_install": True, "offline_guard": "loopback allowed; external DNS/socket calls blocked; self-test passed",
            "restart_persistence": True, "case_export_valid": verified["valid"], "tamper_rejected": not tamper["valid"],
            "navigator_export_techniques": sorted(item["techniqueID"] for item in layer["techniques"]),
            "external_csv_bytes": len(csv_bytes), "native_incident_count": len(original_incidents),
            "external_accepted": imported["quality"]["accepted"], "external_context_only": imported["quality"]["context_only"],
            "elapsed_seconds": round(time.perf_counter() - started, 3), "database": "fresh-native.sqlite3",
            "completed_at_utc": datetime.now(timezone.utc).isoformat()}
        (output / "acceptance.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2))
    finally:
        if process is not None and server_log is not None:
            _stop(process, server_log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
