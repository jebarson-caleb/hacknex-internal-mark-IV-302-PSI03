import json
import platform
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from ..context import calibration_status
from ..baseline import fit_baseline
from ..hybrid import run_analysis
from ..storage import Store
from .fixtures import load_chronological_demo
from .metrics import evaluate_predictions


def run_benchmark(store: Store, *, seed: int = 17, users: int = 30, events: int = 20000,
                  output: Path | None = None) -> dict:
    started=perf_counter()
    datasets,labels=load_chronological_demo(store,seed,users,events)
    fit_started=perf_counter()
    baseline=fit_baseline(store,datasets["training"]["id"],datasets["calibration"]["id"],
                          "Explicitly selected generated benign days 1–14 and 15–21; separate seeds",seed)
    fit_seconds=perf_counter()-fit_started
    test_id=datasets["test"]["id"]
    runs,metrics,timings = {},{},{}
    for mode in ("rules-only","hybrid"):
        tick=perf_counter()
        run=run_analysis(store,test_id,mode=mode,baseline_id=baseline["baseline_id"])
        predictions=store.incidents(run["analysis_run_id"])
        timings[mode]=perf_counter()-tick
        runs[mode]={"analysis_run_id":run["analysis_run_id"],"dataset_fingerprint":run["dataset_fingerprint"]}
        # Labels first enter scoring here, after the independent predictions.
        metrics[mode]=evaluate_predictions(predictions,labels,store.events(test_id))
    result={"evaluation_id":uuid4().hex,"schema_version":"2","seed":seed,"partition_seeds":[seed,seed+1,seed+2],
            "requested_profile_events":events,"users":users,"baseline_id":baseline["baseline_id"],
            "partitions":{name:{"dataset_id":value["id"],"origin":value["origin"],"accepted_events":len(store.events(value["id"])),
                "fingerprint":baseline["training_fingerprint"] if name=="training" else baseline["calibration_fingerprint"] if name=="calibration" else runs["hybrid"]["dataset_fingerprint"]} for name,value in datasets.items()},
            "split":"UTC days 1–14 training; 15–21 declared benign calibration; 22–28 held-out",
            "runs":runs,"metrics":metrics,"calibration":baseline["risk_calibration"],"calibration_status":calibration_status(baseline),
            "policy_versions":{"rules":"phase1-v1","hybrid":"hybrid-v2","context":"scoped-copy-v1"},
            "processing_seconds":{"fitting_including_source_validation":fit_seconds,**timings,"total":perf_counter()-started},
            "hardware":{"platform":platform.platform(),"processor":platform.processor(),"python":platform.python_version(),
                        "memory_measurement":None},
            "comparison":"Hybrid retains the same structural rule gates. Compare measured metrics below; no improvement is assumed.",
            "not_implemented":["anomaly-only ablation (Phase 4)","real-world validation","process memory measurement"]}
    destination = (output or Path(store.path).parent/"evaluations")/result["evaluation_id"]
    destination.mkdir(parents=True,exist_ok=True)
    result["artifact_directory"] = str(destination.resolve())
    store.save_evaluation(result)
    (destination/"evaluation.json").write_text(json.dumps(result,indent=2),encoding="utf-8")
    (destination/"labels.json").write_text(json.dumps(labels,indent=2),encoding="utf-8")
    return result
