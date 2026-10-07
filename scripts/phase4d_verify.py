"""Reopen expanded artifacts in a fresh process and recompute evaluation counts."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

from traceguard.evaluation.expanded import aggregate, anomaly_metrics, neutralized, population
from traceguard.evaluation.metrics import evaluate_predictions
from traceguard.ingest import digest
from traceguard.resolution import resolve_events
from traceguard.storage import Store


def verify(directory):
    started = perf_counter()
    read = lambda p: json.loads(p.read_text(encoding='utf-8'))
    result = read(directory/'evaluation.json')
    assert digest((directory/'protocol.json').read_bytes())==result['protocol_sha256']==read(directory/'freeze.json')['protocol_sha256']
    for name,value in read(directory/'freeze.json')['source_sha256'].items():
        path = Path(__file__).resolve().parents[1]/'backend/src/traceguard/evaluation'/name
        assert digest(path.read_bytes())==value, f'evaluator source changed: {name}'
    findings = []
    for profile in result['profiles']:
        folder = directory/f"seed-{profile['seed']}"
        store = Store(folder/'traceguard.sqlite3')
        predictions, runs, truth = (read(folder/name) for name in ('predictions.json','runs.json','truth.json'))
        baseline,blob = store.baseline(runs['hybrid']['baseline_id'])
        assert digest(blob)==profile['model_sha256']==read(folder/'selected-artifact.json')['model_sha256']
        assert runs['rules-only']['baseline_snapshot']==runs['hybrid']['baseline_snapshot']==baseline
        assert runs['rules-only']['dataset_fingerprint']==runs['hybrid']['dataset_fingerprint']
        events,_,_ = resolve_events(store.events(profile['datasets']['test']),baseline['alias_snapshot'])
        labels = [dict(c,scenario_id=c['case_id']) for c in truth['test'] if c['category']=='supported_attack']
        refs = {e for c in truth['test'] if c['category']!='benign' for e in c['observed_refs']}
        for mode in ('rules-only','hybrid'):
            assert store.analysis(runs[mode]['analysis_run_id'])==runs[mode]
            assert store.incidents(runs[mode]['analysis_run_id'])==predictions[mode]
            assert evaluate_predictions(predictions[mode],labels,events,attack_event_ids=refs)==profile['metrics'][mode]
        assert neutralized(predictions['hybrid'])==predictions['neutralized-diagnostic']
        assert evaluate_predictions(predictions['neutralized-diagnostic'],labels,events,attack_event_ids=refs)==profile['metrics']['neutralized-diagnostic']
        alarms,m = anomaly_metrics(read(folder/'windows.json'),events,refs,baseline['anomaly_threshold'])
        assert alarms==predictions['anomaly-only'] and m==profile['metrics']['anomaly-only']
        assert all(x['valid'] for group in read(folder/'validation.json').values() for x in group)
        benign = [list(u) for u in sorted(population(events,refs)[0])]
        assert benign==profile['benign_population']
        assert all(v['benign_user_device_day_fpr']['denominator']==len(benign) for v in profile['metrics'].values())
        cal = read(folder/'calibration.json')
        complete = [c for c in cal['candidates'] if len(c['stages'])==3]
        alerts = [c for c in complete if c['risk']['score']>=c['risk']['threshold'] and not c['risk']['missing_components']]
        assert len(alerts)==cal['actual_alerts_at_threshold']
        assert len(complete)==cal['complete_candidate_count']==baseline['risk_calibration']['complete_candidates']
        findings.append(dict(seed=profile['seed'],persisted_predictions_equal=True,metrics_recomputed=True,model_unchanged=True,
            complete_calibration_candidates=len(complete),calibration_alerts=len(alerts),
            calibration_candidate_semantics='Audit candidates retain prethreshold structural decision/mode; emitted hybrid decisions are derived from score, threshold and missing-window gates',
            applied_calibration_decisions=[dict(incident_id=c['incident_id'],structural_decision=c['decision'],
                applied_hybrid_decision='partial_observation' if len(c['stages'])<3 else 'review' if c['risk']['score']<c['risk']['threshold'] or c['risk']['missing_components'] else 'incident') for c in cal['candidates']]))
    assert aggregate(result['profiles'])==result['totals']
    return dict(valid=True,checked_at_utc=datetime.now(timezone.utc).isoformat(),profiles=findings,
                elapsed_seconds=perf_counter()-started,scope='Fresh process: persisted runs/model equality, saved predictions, recomputed matching/counts/common populations and calibration decision audit; original independent source checks retained in validation.json')


if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    result = verify(args.directory)
    with args.output.open('x',encoding='utf-8') as stream:
        json.dump(result,stream,indent=2)
    print(json.dumps(dict(valid=result['valid'],profiles=len(result['profiles']),elapsed_seconds=result['elapsed_seconds'])))
