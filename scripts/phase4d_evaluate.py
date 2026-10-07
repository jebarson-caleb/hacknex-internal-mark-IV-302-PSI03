"""Run the separate evaluation-first checkpoint; existing benchmark CLI is unchanged."""
import argparse
import json
import sys
from pathlib import Path
from time import perf_counter
from traceguard.evaluation.expanded import run_expanded

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Frozen Phase 4D synthetic evaluation')
    parser.add_argument('--profile', choices=['smoke','full'],default='smoke')
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    fresh = not args.output.exists()
    started = perf_counter()
    execution = {'argv':[sys.executable,*sys.argv], 'exit_status':1}
    try:
        result = run_expanded(args.output,args.profile)
        execution['exit_status'] = 0
        print(json.dumps({'output':str(args.output),'totals':result['totals'],'total_seconds':result['total_seconds']},indent=2))
    except Exception as exc:
        execution['error'] = repr(exc)
        raise
    finally:
        execution['elapsed_seconds'] = perf_counter()-started
        if fresh and args.output.is_dir():
            (args.output/'execution.json').write_text(json.dumps(execution,indent=2),encoding='utf-8')
