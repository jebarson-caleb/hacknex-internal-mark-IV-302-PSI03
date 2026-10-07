import copy
import json
from datetime import datetime, timezone

import pytest

from traceguard.baseline import fit_baseline, closed_cutoff
from traceguard.evaluation.expanded import anomaly_metrics, calibration_audit, neutralized, population, protocol, run_expanded
from traceguard.evaluation.expanded_fixtures import aliases, load_expanded
from traceguard.evaluation.metrics import evaluate_predictions
from traceguard.hybrid import run_analysis
from traceguard.resolution import resolve_events
from traceguard.schemas import AuthorizationContext
from traceguard.sensitivity import semantic
from traceguard.storage import Store


@pytest.fixture(scope='module')
def expanded(tmp_path_factory):
    store = Store(tmp_path_factory.mktemp('4d')/'test.sqlite3')
    store.set_aliases('synthetic-office',aliases())
    train,_,_ = load_expanded(store,17,'training',6,800)
    cal,_,_ = load_expanded(store,18,'calibration',6,400)
    test,cases,quality = load_expanded(store,19,'test',6,400)
    metadata = fit_baseline(store,train,cal,'Explicit generated benign training/calibration',17)
    run = run_analysis(store,test,mode='hybrid',baseline_id=metadata['baseline_id'])
    events,_,_ = resolve_events(store.events(test),metadata['alias_snapshot'])
    labels = [dict(c,scenario_id=c['case_id']) for c in cases if c['category']=='supported_attack']
    refs = {e for c in cases if c['category']!='benign' for e in c['observed_refs']}
    return store,test,cases,quality,metadata,run,events,labels,refs


def test_protocol_fixed_populations_and_disjoint_splits():
    p = protocol('full')
    assert p['seeds']==[41,53,67] and p['attacks_per_profile']*len(p['seeds'])==12
    assert p['split']['training'][1]<p['split']['calibration'][0]<p['split']['test'][0]
    assert p['benign_export_cases_per_partition']==8


def test_real_calibration_complete_candidates_and_rejected_rows(expanded):
    store,_,_,quality,metadata,*_ = expanded
    audit = calibration_audit(store,metadata)
    assert audit['complete_candidate_count']==7
    assert audit['complete_candidate_count']==metadata['risk_calibration']['complete_candidates']
    assert all(c['validation']['valid'] for c in audit['candidates'])
    assert audit['percentile_sample_count']==metadata['calibration_sample_size']
    assert quality['rejected']==quality['quarantined']==1
    assert quality['generated_records']==quality['accepted']+quality['rejected']+quality['duplicates']


def test_truth_does_not_change_real_inference_and_unobservable_units_not_benign(expanded):
    store,test,cases,_,metadata,run,events,labels,refs = expanded
    before = store.incidents(run['analysis_run_id'])
    metrics = evaluate_predictions(before,labels,events,attack_event_ids=refs)
    no_truth = evaluate_predictions(before,[],events)
    assert no_truth['incident_recall']['value'] is None
    assert metrics['incident_recall']['denominator']==4
    assert metrics['benign_user_device_day_fpr']['denominator']<no_truth['benign_user_device_day_fpr']['denominator']
    changed = copy.deepcopy(cases)
    for c in changed: c['category']='benign'
    again = run_analysis(store,test,mode='hybrid',baseline_id=metadata['baseline_id'])
    assert semantic(before)==semantic(store.incidents(again['analysis_run_id']))


def test_duplicate_and_oversized_prediction_cannot_earn_episode_credit(expanded):
    store,_,_,_,_,run,events,labels,refs = expanded
    # Matcher is also tested independent of numeric threshold: make actual complete review items emitted.
    predictions = copy.deepcopy(store.incidents(run['analysis_run_id']))
    for p in predictions:
        if len(p['stages'])==3: p['decision']='incident'
    original = evaluate_predictions(predictions,labels,events,attack_event_ids=refs)
    matched_id = original['matches'][0]['incident_id']
    duplicate = copy.deepcopy(next(p for p in predictions if p['incident_id']==matched_id))
    duplicate['incident_id']='duplicate'
    repeated = evaluate_predictions(predictions+[duplicate],labels,events,attack_event_ids=refs)
    assert repeated['incident_recall']['numerator']==original['incident_recall']['numerator']
    assert repeated['incident_precision']['denominator']==original['incident_precision']['denominator']+1
    same_actor = [l for l in labels if l['user_id']==labels[0]['user_id']]
    oversized = copy.deepcopy(next(p for p in predictions if p['user_id']==same_actor[0]['user_id'] and len(p['stages'])==3))
    for stage in oversized['stages']:
        stage['evidence_event_ids'] = [l['stages'][stage['stage_id']] for l in same_actor]
    oversized['selected_evidence'] = list({e for l in same_actor for e in list(l['stages'].values())+l['context']})
    result = evaluate_predictions([oversized],same_actor,events)
    assert result['matches']==[] and result['matching_decisions'][0]['status']=='oversized_or_ambiguous'


def test_window_alarm_threshold_ties_common_units_no_chain_metrics(expanded):
    _,_,_,_,_,run,events,_,refs = expanded
    windows = run['window_scores']
    threshold = max(w['raw_anomaly_score'] for w in windows if w['raw_anomaly_score'] is not None)
    alarms,metrics = anomaly_metrics(windows,events,refs,threshold)
    assert alarms and metrics['threshold_ties']==len(alarms)
    assert metrics['incident_precision'] is metrics['incident_recall'] is None
    assert metrics['benign_user_device_day_fpr']['denominator']==len(population(events,refs)[0])
    _,empty = anomaly_metrics([],[],[],threshold)
    assert empty['benign_user_device_day_fpr']['value'] is None


def test_diagnostic_only_changes_anomaly_term_no_production_mutation(expanded):
    store,_,_,_,_,run,*_ = expanded
    predictions = store.incidents(run['analysis_run_id'])
    frozen = copy.deepcopy(predictions)
    diagnostic = neutralized(predictions)
    assert predictions==frozen==store.incidents(run['analysis_run_id'])
    for a,b in zip(predictions,diagnostic):
        assert a['stages']==b['stages'] and a['authorization']==b['authorization']
        assert a['risk']['missing_components']==b['risk']['missing_components']
        assert a['risk']['threshold']==b['risk']['threshold']
        assert a['risk']['window_evidence']==b['risk']['window_evidence']
        assert b['risk']['weighted_terms']['anomaly']==0
        assert all(a['risk']['weighted_terms'][k]==v for k,v in b['risk']['weighted_terms'].items() if k!='anomaly')


def test_source_reordering_duplicates_and_cutoff_do_not_leak(expanded):
    store,test,_,_,metadata,_,_,_,_ = expanded
    cutoff = datetime(2026,1,22,2,tzinfo=timezone.utc)
    before = run_analysis(store,test,mode='hybrid',baseline_id=metadata['baseline_id'],cutoff=cutoff)
    # Reingest all retained input in reverse order, preserving all duplicate source references.
    with store.connection() as conn:
        uploads = [dict(r) for r in conn.execute('SELECT * FROM uploads WHERE dataset_id=?',(test,))]
    for upload in uploads:
        records = list(reversed(upload['content'].decode().strip().splitlines()))
        store.ingest(test,('\n'.join(records)+'\n').encode(),upload['filename'],upload['source_id'],upload['source_type'])
    after = run_analysis(store,test,mode='hybrid',baseline_id=metadata['baseline_id'],cutoff=cutoff)
    assert before['dataset_fingerprint']==after['dataset_fingerprint']
    assert before['window_scores']==after['window_scores']
    # Dataset quality warning legitimately changes when a rejected row is ingested twice.
    # Compare supported claims/scores/decisions; do not erase retained provenance/quality.
    substantive = lambda rid: [{k:v for k,v in p.items() if k!='warnings'} for p in semantic(store.incidents(rid))]
    assert substantive(before['analysis_run_id'])==substantive(after['analysis_run_id'])
    assert store.quality(test)['rejected']==2
    store.ingest(test,b'{"timestamp":"2026-01-29T12:00:00Z","action":"login_success","user_id":"u1","device_id":"d8","app_id":"later"}\n','later.jsonl','later','auth')
    later = run_analysis(store,test,mode='hybrid',baseline_id=metadata['baseline_id'],cutoff=cutoff)
    assert later['window_scores']==after['window_scores'] and later['dataset_fingerprint']==after['dataset_fingerprint']


def test_invalid_context_is_rejected_instead_of_failed_match(expanded):
    store,test,*_ = expanded
    with pytest.raises(ValueError,match='environment-scoped'):
        store.set_authorizations(test,[AuthorizationContext(authorization_id='bad',user_id='raw',device_id='raw',resource_id='raw',
            provenance='operator',effective_from='2026-01-22T00:00:00Z',effective_until='2026-01-23T00:00:00Z')])


def test_output_refuses_historical_overwrite(tmp_path):
    marker = tmp_path/'protocol.json'
    marker.write_text('retained')
    with pytest.raises(FileExistsError): run_expanded(tmp_path)
    assert marker.read_text()=='retained'
