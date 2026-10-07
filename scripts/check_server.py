"""Start the documented loopback demo in a subprocess; check real API/static assets and restart persistence."""
import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path


def main():
    parser=argparse.ArgumentParser();parser.add_argument("--db",required=True);args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    with socket.socket() as listener:
        listener.bind(("127.0.0.1",0));port=listener.getsockname()[1]
    url=f"http://127.0.0.1:{port}"
    env={**os.environ,"TRACEGUARD_DB":str(Path(args.db).resolve())}
    def request(path,body=None):
        data=json.dumps(body).encode() if body is not None else None
        with urllib.request.urlopen(urllib.request.Request(url+path,data=data,headers={"Content-Type":"application/json"}),timeout=15) as response:
            return response.read()
    def start():
        process=subprocess.Popen([sys.executable,str(root/"scripts/run_demo.py"),"--port",str(port)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(100):
            if process.poll() is not None:raise RuntimeError("demo server exited before health")
            try:
                assert json.loads(request("/api/health"))["status"]=="ok"
                return process
            except (OSError,AssertionError):time.sleep(0.1)
        process.terminate();process.wait();raise RuntimeError("demo startup timeout")
    process=start()
    try:
        assert b'<div id="root"></div>' in request("/")
        data=json.loads(request("/api/datasets/demo",{"variant":"positive"}))
        run=json.loads(request("/api/analyses",{"dataset_id":data["dataset"]["id"]}))
        item=json.loads(request(f"/api/analyses/{run['analysis_run_id']}/incidents"))[0]
        report=json.loads(request(f"/api/incidents/{item['incident_id']}/report"))
        assert report["validation"]["valid"]
    finally:process.terminate();process.wait(timeout=15)
    process=start()
    try:
        assert json.loads(request(f"/api/analyses/{run['analysis_run_id']}"))==run
        saved=json.loads(request(f"/api/incidents/{item['incident_id']}/report"))
        assert saved["incident"]==report["incident"] and saved["validation"]["valid"]
        print(json.dumps({"health":"ok","built_ui":"served","restart_persistence":"passed","run":run["analysis_run_id"],"db":env["TRACEGUARD_DB"]},indent=2))
    finally:process.terminate();process.wait(timeout=15)


if __name__=="__main__":main()
