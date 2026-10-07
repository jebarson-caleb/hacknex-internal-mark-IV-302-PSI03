"""Frozen Phase 4D CLI experiment. No application inference imports this module."""
import copy
import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

from ..baseline import fit_baseline, load_baseline, closed_cutoff, score_windows
from ..context import authorization_checks, calibration_status
from ..detection import correlate, validate_evidence
from ..features import build_features
from ..hybrid import run_analysis, verify_incident
from ..ingest import digest, json_bytes
from ..resolution import resolve_events
from ..risk import score_candidate
from ..sensitivity import create_sensitivity, verify_comparison
from ..storage import Store
from .expanded_fixtures import ATTACKS, BENIGN, NEGATIVES, VERSION, aliases, load_expanded
from .metrics import evaluate_predictions, ratio

PROTOCOL_VERSION = 'phase4d-v1'


def protocol(profile):
    return dict(version=PROTOCOL_VERSION, generator_version=VERSION, profile=profile,
                seeds=[17] if profile=='smoke' else [41, 53, 67],
                users=6 if profile=='smoke' else 30, requested_records_per_profile=1600 if profile=='smoke' else 20000,
                split={'training': [1,14], 'calibration': [15,21], 'test': [22,28]},
                epoch='2026-01-01T00:00:00Z', partition_seed_offsets=[0,1,2],
                baseline='one newly fitted artifact per profile; fixed across all comparisons',
                development='existing fixtures and 4B lab; no final-result selection',
                attacks=ATTACKS, attacks_per_profile=4, benign_complete_templates=BENIGN,
                observational_templates=NEGATIVES, benign_export_cases_per_partition=8,
                malformed_row_per_calibration_test=1, dataset_cap=50000,
                populations='established u0..users-1, routine d(user%20), new endpoints d((actor+7)%20), cold-start user; exact environment synthetic-office',
                context='operator asset catalog and exact/direct aliases; exact/withheld/expired/future/wrong/repeated authorization, benign truth retained',
                versions={'model':'iforest-v1','features':'window-v1','rules':'phase1-v1','risk':'hybrid-v2','authorization':'scoped-copy-v1'},
                fitting='unchanged 200-tree IsolationForest/preprocessing/hyperparameters',
                incident_threshold='native lowest >=80 benign candidate boundary meeting 1% active-unit budget; existing never-suppress-all fallback',
                anomaly_threshold='existing raw-score calibration quantile 0.99 method=higher; inclusive >=; ties may exceed 1%',
                eligible_windows='existing closed 15-minute, established history; cold-start/provisional omitted with counts',
                units='UTC active resolved user-device-day with accepted observation, excluding every labeled malicious event unit, including insufficient/out-of-scope attacks',
                alarm_units='one anomaly-only alarm per eligible scored window; selected window evidence implicates units',
                episode_matching='existing exact scoped identities, required-stage evidence overlap and strict order; one-to-one; oversized/ambiguous gets no credit',
                stage_metrics='all supported candidates including partial/review, independently evidence validated; separate from alert episode recall',
                zero_denominators='null; anomaly-only chain/stage metrics not applicable',
                diagnostic='evaluation-only copy of full hybrid output; recompute risk with only A=0 while retaining scored windows/missing flags, B, L, I, C, threshold and structural gates; never persist as production run',
                exposure='freeze local protocol before smoke/full predictions; smoke is development exposure, not independent preregistration',
                costs='single measurement per seed; monotonic; fresh DB/model with warm installed libraries/OS caches; process resident memory unmeasured',
                scope='supported suspected USB chain only; no replay, remediation, deployment, model replacement or final-test tuning')


def save(path, value):
    path.write_text(json.dumps(value, indent=2), encoding='utf-8')


def population(events, attack_refs):
    by_id = {e.event_id:e for e in events}
    unit = lambda e: (e.user_id,e.device_id,e.event_time_utc.date().isoformat())
    active = {unit(e) for e in events if e.user_id and e.device_id}
    malicious = {unit(by_id[eid]) for eid in attack_refs}
    return active-malicious, by_id


def anomaly_metrics(windows, events, attack_refs, threshold):
    benign, by_id = population(events, attack_refs)
    eligible = [w for w in windows if w['raw_anomaly_score'] is not None]
    alarms = [dict(w, alarm_id=f'window-{i}') for i,w in enumerate(eligible) if w['raw_anomaly_score']>=threshold]
    false_units, false_alarms = set(), 0
    for alarm in alarms:
        implicated = {(by_id[e].user_id,by_id[e].device_id,by_id[e].event_time_utc.date().isoformat()) for e in alarm['event_ids']}
        if implicated & benign: false_alarms += 1
        false_units |= implicated & benign
    return alarms, dict(output_unit='window_alarm', alert_count=len(alarms), eligible_windows=len(eligible),
        missing_windows=len(windows)-len(eligible), threshold=threshold, threshold_ties=sum(w['raw_anomaly_score']==threshold for w in eligible),
        benign_user_device_day_fpr=dict(numerator=len(false_units),denominator=len(benign),value=ratio(len(false_units),len(benign))),
        benign_false_alerts_per_1000_events=dict(numerator=false_alarms,accepted_events=len(events),value=1000*ratio(false_alarms,len(events)) if events else None),
        incident_precision=None,incident_recall=None,required_stage_recall=None,
        reason='Window alarms do not reconstruct chains or stage evidence')


def neutralized(predictions):
    result = copy.deepcopy(predictions)
    for p in result:
        risk = p['risk']
        risk['components']['A'] = 0.0
        risk['weighted_terms']['anomaly'] = 0.0
        risk['score'] = max(0.,min(100.,sum(risk['weighted_terms'].values())))
        risk['diagnostic_intervention'] = 'A=0 only; actual raw scores/windows and missing flags retained'
        if len(p['stages']) == 3:
            p['decision'] = 'review' if risk['score']<risk['threshold'] or risk['missing_components'] else 'incident'
        p['experimental_diagnostic'] = True
    return result


def calibration_audit(store, metadata):
    artifact = load_baseline(store,metadata['baseline_id'])
    raw = store.events(metadata['calibration_dataset_id'])
    events, links, _ = resolve_events(raw,metadata['alias_snapshot'])
    history, _, _ = resolve_events(store.events_by_ids(metadata['training_event_ids']),metadata['alias_snapshot'])
    resources = metadata['calibration_resource_snapshot']
    windows = score_windows(build_features(events,metadata['history_snapshot'],closed_cutoff(events),resources),artifact)
    candidates = correlate(events,resources,metadata['calibration_dataset_id'],'calibration-audit',history,metadata['baseline_id'])
    source_cache = store.provenance_batch(raw+store.events_by_ids(metadata['training_event_ids']))
    rows = []
    for c in candidates:
        c.validation = validate_evidence(c,events,resources,store,history,metadata['baseline_id'],source_cache)
        c.authorization = authorization_checks(c,events,metadata['calibration_authorization_snapshot'])
        c.risk = score_candidate(c,windows,baseline_id=metadata['baseline_id'],threshold=metadata['risk_calibration']['threshold'],
            link_strength=0.9 if any(l['event_id'] in c.selected_evidence for l in links) else 1., authorization=c.authorization,
            calibration=calibration_status(metadata))
        rows.append(c.model_dump(mode='json'))
    complete = [r for r in rows if len(r['stages'])==3]
    # Explicit cutoff gates in the real hybrid decision, not numeric threshold alone.
    alerts = [r for r in complete if r['risk']['score']>=r['risk']['threshold'] and not r['risk']['missing_components']]
    scored_windows = [w for w in windows if w['raw_anomaly_score'] is not None]
    _,alarm_burden = anomaly_metrics(windows,events,[],metadata['anomaly_threshold'])
    return dict(metadata=metadata,candidates=rows,complete_candidate_count=len(complete),
        complete_candidate_scores=sorted(r['risk']['score'] for r in complete),actual_alerts_at_threshold=len(alerts),
        benign_units=len(population(events,[])[0]),percentile_sample_count=len(scored_windows),
        window_alarm_count=sum(w['raw_anomaly_score']>=metadata['anomaly_threshold'] for w in scored_windows),
        anomaly_threshold_ties=sum(w['raw_anomaly_score']==metadata['anomaly_threshold'] for w in scored_windows),
        anomaly_calibration_burden=alarm_burden)


def outcomes(cases, predictions):
    return [dict(case_id=c['case_id'], category=c['category'], variant=c['variant'],
        related_predictions=[dict(incident_id=p['incident_id'],decision=p['decision'],score=p['risk']['score'],
            stages=[s['stage_id'] for s in p['stages']]) for p in predictions if set(c['observed_refs']) & set(p['selected_evidence'])]) for c in cases]


def aggregate(profiles):
    totals = {}
    for mode in profiles[0]['metrics']:
        source = [p['metrics'][mode] for p in profiles]
        combined = {'output_unit': 'window_alarm' if mode=='anomaly-only' else 'incident'}
        for key in source[0]:
            if isinstance(source[0][key],dict) and 'numerator' in source[0][key]:
                denominator_key = 'denominator' if 'denominator' in source[0][key] else 'accepted_events'
                n,d = sum(s[key]['numerator'] for s in source), sum(s[key][denominator_key] for s in source)
                combined[key] = dict(numerator=n,**{denominator_key:d},value=ratio(n,d))
                if denominator_key=='accepted_events' and combined[key]['value'] is not None: combined[key]['value'] *= 1000
        for key in ('alert_count','false_alerts','missed_episodes','candidate_count'):
            if key in source[0]: combined[key] = sum(s[key] for s in source)
        totals[mode] = combined
    return totals


def run_expanded(output: Path, profile='smoke'):
    output = Path(output)
    output.mkdir(parents=True,exist_ok=False)  # Refuse overwrite, including failed/exposed runs.
    plan = protocol(profile)
    save(output/'protocol.json',plan)
    protocol_hash = digest((output/'protocol.json').read_bytes())
    source_paths = [Path(__file__),Path(__file__).with_name('expanded_fixtures.py'),Path(__file__).with_name('metrics.py')]
    save(output/'freeze.json',dict(protocol_sha256=protocol_hash,frozen_at_utc=datetime.now(timezone.utc).isoformat(),
        source_sha256={p.name:digest(p.read_bytes()) for p in source_paths}))
    (output/'PROTOCOL.md').write_text('# Frozen Phase 4D protocol\n\n'+json.dumps(plan,indent=2)+'\n',encoding='utf-8')
    started = perf_counter()
    profiles = []
    for seed in plan['seeds']:
        directory = output/f'seed-{seed}'
        directory.mkdir()
        store = Store(directory/'traceguard.sqlite3')
        store.set_aliases('synthetic-office',aliases())
        tick = perf_counter()
        datasets, truth, quality = {}, {}, {}
        for role, offset, fraction in [('training',0,2),('calibration',1,4),('test',2,4)]:
            datasets[role],truth[role],quality[role] = load_expanded(store,seed+offset,role,plan['users'],plan['requested_records_per_profile']//fraction)
        generation_ingestion = perf_counter()-tick
        save(directory/'truth.json',truth)
        save(directory/'ingestion.json',quality)
        tick = perf_counter()
        metadata = fit_baseline(store,datasets['training'],datasets['calibration'],
            'Explicit synthetic benign historical training and stage-complete legitimate calibration; frozen Phase 4D protocol',seed)
        fitting = perf_counter()-tick
        _, model = store.baseline(metadata['baseline_id'])
        model_hash = digest(model)
        tick = perf_counter()
        audit = calibration_audit(store,metadata)
        audit['case_outcomes'] = outcomes(truth['calibration'],audit['candidates'])
        calibration_audit_seconds = perf_counter()-tick
        save(directory/'calibration.json',audit)
        # Freeze applied thresholds/artifact before any final inference.
        save(directory/'selected-artifact.json',dict(baseline_id=metadata['baseline_id'],model_sha256=model_hash,
            incident_threshold=metadata['risk_calibration'],anomaly_threshold=metadata['anomaly_threshold'],protocol_sha256=protocol_hash))
        raw = store.events(datasets['test'])
        events,_,resolution_warnings = resolve_events(raw,metadata['alias_snapshot'])
        cases = truth['test']
        labels = [dict(c,scenario_id=c['case_id']) for c in cases if c['category']=='supported_attack']
        attack_refs = {e for c in cases if c['category']!='benign' for e in c['observed_refs']}
        predictions,runs,timings,verification = {},{},{},{}
        for mode in ('rules-only','hybrid'):
            tick = perf_counter()
            runs[mode] = run_analysis(store,datasets['test'],mode=mode,baseline_id=metadata['baseline_id'])
            predictions[mode] = store.incidents(runs[mode]['analysis_run_id'])
            timings[mode+'_inference_and_persistence'] = perf_counter()-tick
            tick = perf_counter()
            verification[mode] = [dict(incident_id=p['incident_id'],**verify_incident(store,p['incident_id'])) for p in predictions[mode]]
            if not all(v['valid'] for v in verification[mode]): raise ValueError('independent prediction verification failed')
            timings[mode+'_verification'] = perf_counter()-tick
        tick = perf_counter()
        artifact = load_baseline(store,metadata['baseline_id'])
        windows = score_windows(build_features(events,metadata['history_snapshot'],closed_cutoff(events),store.resources(datasets['test'])),artifact)
        timings['anomaly-only_scoring'] = perf_counter()-tick
        predictions['anomaly-only'], anomaly = anomaly_metrics(windows,events,attack_refs,metadata['anomaly_threshold'])
        predictions['neutralized-diagnostic'] = neutralized(predictions['hybrid'])
        tick = perf_counter()
        metrics = {mode:evaluate_predictions(predictions[mode],labels,events,attack_event_ids=attack_refs)
                   for mode in ('rules-only','hybrid','neutralized-diagnostic')}
        metrics['anomaly-only'] = anomaly
        timings['evaluation'] = perf_counter()-tick
        tick = perf_counter()
        sensitivity = create_sensitivity(store,runs['hybrid']['analysis_run_id'],[], 'Phase 4D measured no-op, frozen artifacts')
        check = verify_comparison(store,sensitivity)
        if not check['valid']: raise ValueError('sensitivity verification failed')
        timings['sensitivity_noop_and_verification'] = perf_counter()-tick
        save(directory/'sensitivity.json',dict(comparison_id=sensitivity['comparison_id'],verification=check))
        _, after_model = store.baseline(metadata['baseline_id'])
        if digest(after_model)!=model_hash: raise ValueError('model mutated during comparison')
        save(directory/'predictions.json',predictions)
        save(directory/'runs.json',runs)
        save(directory/'windows.json',windows)
        save(directory/'validation.json',verification)
        case_outcomes = {mode:outcomes(cases,predictions[mode]) for mode in ('rules-only','hybrid','neutralized-diagnostic')}
        save(directory/'case-outcomes.json',case_outcomes)
        result = dict(seed=seed,metrics=metrics,calibration=metadata['risk_calibration'],datasets=datasets,quality=quality,
            model_sha256=model_hash,model_unchanged=True,processing_seconds=dict(generation_ingestion=generation_ingestion,fitting=fitting,calibration_audit=calibration_audit_seconds,**timings),
            resolution_warnings=resolution_warnings,malicious_insufficient_or_out_of_scope_cases=2,
            excluded_pairless_observations=sum(not e.user_id or not e.device_id for e in events),
            supported_attack_episodes=len(labels),benign_population=[list(u) for u in sorted(population(events,attack_refs)[0])])
        save(directory/'result.json',result)
        profiles.append(result)
    if digest((output/'protocol.json').read_bytes())!=protocol_hash: raise ValueError('protocol changed')
    result = dict(protocol_sha256=protocol_hash,protocol=plan,profiles=profiles,totals=aggregate(profiles),
        total_seconds=perf_counter()-started,hardware=dict(platform=platform.platform(),processor=platform.processor(),
            python=platform.python_version(),process_memory=None,measurement='unmeasured; no allocation/RSS equivalence'),
        limitations=['Correlated synthetic scenarios, no real-world gain claim','Authorization effect is policy, not forest',
            'Diagnostic fixes threshold/gates; not independently optimized or production mode','Single measurement per seed; fresh DB/model, warm installed runtime',
            'Replay deferred to Phase 4C; final submission checks remain'])
    save(output/'evaluation.json',result)
    lines = ['# Phase 4D measured synthetic evaluation', '', f'Protocol SHA256: `{protocol_hash}`', '',
        '| Output | Matched/emitted | Recovered/labeled | Benign false-positive units | Benign false outputs / accepted events |',
        '|---|---|---|---|---|']
    for mode,m in result['totals'].items():
        fmt = lambda k: f"{m[k]['numerator']}/{m[k].get('denominator',m[k].get('accepted_events'))}" if k in m else 'N/A (window alarms)'
        lines.append(f"| {mode} | {fmt('incident_precision')} | {fmt('incident_recall')} | {fmt('benign_user_device_day_fpr')} | {fmt('benign_false_alerts_per_1000_events')} |")
    lines += ['', 'Counts are summed across profiles. False outputs per 1,000 observations are distinct from active-unit FPR.',
        'Predictions, review/partial items, unmatched truth, matching decisions and case outcomes remain in seed directories.',
        'Authorization changes are operator policy effects. Neutralization measures fixed-policy sensitivity to A only.',
        'No threshold/model tuning follows final results. No real-world independence or improvement is established.', '',
        'Phase 4C replay plus final submission checks remaining.']
    (output/'REPORT.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    return result
