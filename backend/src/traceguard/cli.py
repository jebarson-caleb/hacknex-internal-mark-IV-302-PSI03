import argparse
import json
from pathlib import Path
from .reports import build_report, markdown_report, read_report, verify_report
from .cases import export_case, case_markdown, read_case_export, verify_case_export

from .demo import load_demo
from .detection import analyze
from .hybrid import run_analysis, verify_incident
from .baseline import fit_baseline
from .storage import Store


def main():
    parser = argparse.ArgumentParser(description="TraceGuard local rules-only/hybrid CLI")
    parser.add_argument("--db", default="runtime/traceguard.sqlite3")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo", help="Generate, persist and analyze a synthetic fixture")
    demo.add_argument("--seed", type=int, default=17)
    demo.add_argument("--variant", choices=["positive", "benign", "missing-transfer"], default="positive")
    analyze_parser = commands.add_parser("analyze")
    analyze_parser.add_argument("dataset_id")
    analyze_parser.add_argument("--baseline-id")
    analyze_parser.add_argument("--mode",choices=["rules-only","hybrid"],default="rules-only")
    train = commands.add_parser("train")
    train.add_argument("training_dataset_id")
    train.add_argument("calibration_dataset_id")
    train.add_argument("--benign-provenance",required=True)
    train.add_argument("--seed",type=int,default=17)
    chronology = commands.add_parser("chronological-demo")
    chronology.add_argument("--seed",type=int,default=17)
    verify = commands.add_parser("verify", help="Recheck a persisted incident and its source provenance")
    verify.add_argument("incident_id")
    export = commands.add_parser("export", help="Export verified immutable incident JSON/Markdown")
    export.add_argument("incident_id")
    export.add_argument("--format",choices=["json","markdown"],default="json")
    export.add_argument("--include-raw",action="store_true")
    export.add_argument("--output",required=True)
    verify_export = commands.add_parser("verify-report",help="Check submitted report claims against local immutable run and originals")
    verify_export.add_argument("path")
    case_export_parser = commands.add_parser("export-case", help="Export a frozen case revision and verified incident reports")
    case_export_parser.add_argument("case_id")
    case_export_parser.add_argument("--revision", type=int)
    case_export_parser.add_argument("--format", choices=["json", "markdown"], default="json")
    case_export_parser.add_argument("--output", required=True)
    verify_case_parser = commands.add_parser("verify-case-report", help="Verify a case envelope and its retained report references")
    verify_case_parser.add_argument("path")
    args = parser.parse_args()
    store = Store(args.db)
    if args.command == "demo":
        result = analyze(store, load_demo(store, args.seed, args.variant))
        result["incidents"] = store.incidents(result["analysis_run_id"])
    elif args.command == "analyze":
        result = run_analysis(store,args.dataset_id,mode=args.mode,baseline_id=args.baseline_id)
    elif args.command == "train":
        result = fit_baseline(store,args.training_dataset_id,args.calibration_dataset_id,args.benign_provenance,args.seed)
    elif args.command == "chronological-demo":
        from .evaluation.fixtures import load_chronological_demo
        result,_labels = load_chronological_demo(store,args.seed)
    elif args.command == "export":
        report = build_report(store,args.incident_id,args.include_raw)
        path = Path(args.output)
        path.parent.mkdir(parents=True,exist_ok=True)
        # Never overwrite an existing report silently.
        with path.open("x",encoding="utf-8",newline="\n") as handle:
            handle.write(markdown_report(report) if args.format=="markdown" else json.dumps(report,indent=2))
        result = {"output":str(path.resolve()),"valid":report["validation"]["valid"]}
    elif args.command == "verify-report":
        try:
            result = verify_report(store,read_report(Path(args.path).read_text(encoding="utf-8")))
        except (ValueError,KeyError,TypeError) as exc:
            result = {"valid":False,"errors":[str(exc)]}
        print(json.dumps(result,indent=2))
        raise SystemExit(0 if result["valid"] else 1)
    elif args.command == "export-case":
        exported = export_case(store, args.case_id, args.revision)
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(case_markdown(exported) if args.format == "markdown" else json.dumps(exported, ensure_ascii=True, indent=2))
        result = {"output": str(path.resolve()), "case_id": exported["case_snapshot"]["case_id"],
                  "revision": exported["case_snapshot"]["revision"], "verified_subreports": len(exported["incident_reports"])}
    elif args.command == "verify-case-report":
        try:
            result = verify_case_export(store, read_case_export(Path(args.path).read_text(encoding="utf-8")))
        except (ValueError, KeyError, TypeError) as exc:
            result = {"valid": False, "errors": [str(exc)]}
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["valid"] else 1)
    else:
        result = verify_incident(store,args.incident_id)
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["valid"] else 1)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
