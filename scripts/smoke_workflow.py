"""Offline native setup smoke: fresh DB, explicit fit, persisted sources, reports, restart and CLI verification."""
import argparse
import json
import subprocess
import sys
from pathlib import Path

from traceguard.baseline import fit_baseline
from traceguard.demo import load_demo
from traceguard.evaluation.fixtures import load_chronological_demo
from traceguard.hybrid import incident_graph, run_analysis
from traceguard.reports import build_report, markdown_report, verify_report
from traceguard.storage import Store


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",required=True,help="New directory; existing output is never overwritten")
    args=parser.parse_args()
    output=Path(args.output).resolve();output.mkdir(parents=True,exist_ok=False)
    store=Store(output/"traceguard.sqlite3")
    clean=run_analysis(store,load_demo(store,variant="benign"))
    assert clean["incident_count"]==0
    data,_=load_chronological_demo(store)
    baseline=fit_baseline(store,data["training"]["id"],data["calibration"]["id"],"Explicit generated benign native-setup smoke selections")
    runs=[]
    for mode in ("rules-only","hybrid"):
        run=run_analysis(store,data["test"]["id"],mode=mode,baseline_id=baseline["baseline_id"])
        item=next(i for i in store.incidents(run["analysis_run_id"]) if i["decision"]=="incident")
        assert len(item["stages"])==3
        graph=incident_graph(store,item["incident_id"])
        assert any(e["relation"]=="copied_to" for e in graph["edges"])
        assert store.evidence(item["stages"][-1]["evidence_event_ids"][0])["source_records"][0]["file_row_valid"]
        report=build_report(store,item["incident_id"])
        for extension,format in (("json","json"),("md","markdown")):
            path=output/f"{mode}.{extension}"
            subprocess.run([sys.executable,"-m","traceguard.cli","--db",str(store.path),"export",item["incident_id"],"--format",format,"--output",str(path)],check=True)
            subprocess.run([sys.executable,"-m","traceguard.cli","--db",str(store.path),"verify-report",str(path)],check=True)
        assert verify_report(Store(store.path),report)["valid"]
        runs.append(run["analysis_run_id"])
    tampered=json.loads((output/"hybrid.json").read_text(encoding="utf-8"))
    tampered["incident"]["stages"][-1]["evidence_event_ids"]=["fabricated"]
    tamper_path=output/"tampered.json";tamper_path.write_text(json.dumps(tampered),encoding="utf-8")
    rejected=subprocess.run([sys.executable,"-m","traceguard.cli","--db",str(store.path),"verify-report",str(tamper_path)],capture_output=True,text=True)
    assert rejected.returncode==1
    summary={"tampered_report_rejected":True,"clean_alerts":clean["incident_count"],"verified_modes":["rules-only","hybrid"],"runs":runs,
             "baseline_id":baseline["baseline_id"],"output":str(output),"credentials_required":False}
    (output/"smoke.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
    print(json.dumps(summary,indent=2))


if __name__=="__main__":main()
