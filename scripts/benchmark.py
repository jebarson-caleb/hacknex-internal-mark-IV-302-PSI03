import argparse
import json
from pathlib import Path

from traceguard.evaluation.benchmark import run_benchmark
from traceguard.storage import Store

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description="Phase 2 chronological synthetic rules-only/hybrid benchmark")
    parser.add_argument("--db",default="runtime/benchmark.sqlite3")
    parser.add_argument("--seed",type=int,default=17)
    parser.add_argument("--users",type=int,default=30)
    parser.add_argument("--events",type=int,default=20000)
    parser.add_argument("--output",type=Path,default=Path("runtime/benchmark"))
    args=parser.parse_args()
    result=run_benchmark(Store(args.db),seed=args.seed,users=args.users,events=args.events,output=args.output)
    print(json.dumps(result,indent=2))
