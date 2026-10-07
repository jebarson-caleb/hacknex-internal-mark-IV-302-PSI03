import copy
import json
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sklearn.ensemble import IsolationForest

from traceguard.baseline import fit_baseline
from traceguard.context import authorization_checks
from traceguard.evaluation.fixtures import load_chronological_demo
from traceguard.evaluation.lookalikes import controlled_pair, declaration, load_lab
from traceguard.hybrid import run_analysis
from traceguard.lookalikes import create_comparison, retained_comparison, correspondence
from traceguard.main import create_app
from traceguard.reports import build_report, verify_report
from traceguard.risk import score_candidate
from traceguard.schemas import AuthorizationContext, Incident
from traceguard.sensitivity import create_sensitivity, export_comparison, verify_comparison
from traceguard.storage import Store


@pytest.fixture(scope='module')
def lab(tmp_path_factory):
    store = Store(tmp_path_factory.mktemp('lookalikes')/'store.sqlite3')
    datasets, _ = load_chronological_demo(store)
    baseline = fit_baseline(store, datasets['training']['id'], datasets['calibration']['id'], 'Explicit benign test setup')
    library = load_lab(store, baseline['baseline_id'])
    return store, baseline, library


def pair(lab, name):
    store, _, library = lab
    return retained_comparison(store, next(p['comparison_id'] for p in library['pairs'] if p['name'] == name))


def item(store, arm):
    return store.incidents(arm['analysis_run_id'])[0]


def test_real_controlled_contract_effect_truth_and_reports(lab, monkeypatch):
    store, baseline, _ = lab
    blob = store.baseline(baseline['baseline_id'])
    monkeypatch.setattr(IsolationForest, 'fit', lambda *a, **k: pytest.fail('Comparison fitted model'))
    monkeypatch.setattr('traceguard.baseline.fit_baseline', lambda *a, **k: pytest.fail('Comparison recalibrated'))
    value = pair(lab, 'Withheld versus exact declaration')
    before, after = item(store, value['left']), item(store, value['right'])
    assert value['actual_changed_inputs'] == ['authorization_context_snapshot']
    assert all(value['compatibility'].values())
    assert before['stages'] == after['stages'] and before['selected_evidence'] == after['selected_evidence']
    assert before['risk']['anomaly_percentile'] == after['risk']['anomaly_percentile']
    assert after['risk']['score'] == before['risk']['score']-20
    assert before['authorization']['reduction'] == 0 and after['authorization']['reduction'] == 20
    assert value['evaluation_annotation']['left'] == value['evaluation_annotation']['right'] == 'benign'
    assert before['decision'] == 'incident'  # Retained false positive on a declared benign fixture.
    assert before['risk']['score'] >= before['risk']['threshold']
    create_comparison(store, value['left_run_id'], value['right_run_id'], declared_changes=['authorization_context_snapshot'])
    assert store.baseline(baseline['baseline_id']) == blob
    for candidate in (before, after):
        report = build_report(store, candidate['incident_id'])
        assert verify_report(store, report)['valid']
        bad = copy.deepcopy(report); bad['incident']['risk']['score'] += 1
        assert not verify_report(store, bad)['valid']
    assert store.quality(value['left']['dataset_id'])['duplicates'] == 1
    copy_id = before['stages'][-1]['evidence_event_ids'][0]
    assert len(store.evidence(copy_id)['source_records']) == 2
    assert 'approved by myself' in json.dumps(store.evidence(copy_id))
    assert not before['authorization']['matched']


@pytest.mark.parametrize('name,predicate', [('Expired','effective_interval'), ('Not yet effective','effective_interval'),
                                          ('Wrong actor','actor'), ('Wrong endpoint','endpoint'), ('Wrong resource','resource')])
def test_scope_and_time_real_cases(lab, name, predicate):
    store, _, _ = lab
    value = pair(lab, name)
    candidate = item(store, value['right'])
    assert not candidate['authorization']['checks'][0]['predicates'][predicate]
    assert candidate['authorization']['reduction'] == 0 and candidate['decision'] == 'incident'
    assert candidate['stages'] == item(store, value['left'])['stages']


@pytest.mark.parametrize('offset,expected', [(0,True), (-.000001,False), (60,False), (61,False)])
def test_copy_interval_boundaries_and_unrelated_login(lab, offset, expected):
    store, _, _ = lab
    value = pair(lab, 'Withheld versus exact declaration')
    candidate = Incident.model_validate(item(store, value['right']))
    events = copy.deepcopy(store.events_by_ids(store.analysis(value['right_run_id'])['event_ids']))
    entry = store.analysis(value['right_run_id'])['authorization_context_snapshot'][0]
    transfer = next(e for e in events if e.action == 'file_copy_to_usb')
    transfer.event_time_utc = datetime.fromisoformat(entry['effective_from'])+timedelta(seconds=offset)
    login = next(e for e in events if e.action == 'login_success')
    login.event_time_utc = datetime.fromisoformat(entry['effective_from'])
    check = authorization_checks(candidate, events, [entry])
    assert check['matched'] == expected
    assert check['checks'][0]['evidence_event_ids'] == [transfer.event_id]


def test_threshold_equality_one_time_and_rules_only(lab):
    store, baseline, _ = lab
    value = pair(lab, 'Multiple matching declarations')
    before, after = item(store, value['left']), item(store, value['right'])
    assert len(after['authorization']['checks']) == 2
    assert after['risk']['score'] == before['risk']['score']
    assert after['authorization']['reduction'] == 20
    rules = pair(lab, 'Rules-only preservation')
    a, b = item(store, rules['left']), item(store, rules['right'])
    assert a['risk'] == b['risk'] and a['decision'] == b['decision'] == 'incident'
    assert a['risk']['score'] == 100
    candidate = Incident.model_validate(after)
    windows = copy.deepcopy(after['risk']['window_evidence'])
    for window in windows:
        window['anomaly_percentile'] = 1.0
    boundary = score_candidate(candidate, windows, threshold=80, baseline_id=baseline['baseline_id'], authorization=after['authorization'])
    assert boundary['score'] == boundary['threshold'] == 80 and not boundary['missing_components']
    # Exercise the real orchestrator comparator at equality without replacing detection or policy.
    import traceguard.hybrid as hybrid
    original = hybrid.score_windows
    def at_boundary(batch, artifact):
        result = original(batch, artifact)
        for w in result:
            if w['anomaly_percentile'] is not None:
                w['anomaly_percentile'] = 1.0
        return result
    from unittest.mock import patch
    with patch.object(hybrid, 'score_windows', at_boundary):
        run = run_analysis(store, value['right']['dataset_id'], mode='hybrid', baseline_id=baseline['baseline_id'])
    result = item(store, run)
    assert len(result['stages']) == 3 and result['risk']['score'] == 80 and result['decision'] == 'incident'


def test_missing_history_and_validation_cases(lab):
    store, _, library = lab
    missing = pair(lab, 'Missing transfer')
    candidate = item(store, missing['right'])
    assert candidate['decision'] == 'partial_observation' and all(s['stage_id'] != 'transfer' for s in candidate['stages'])
    history = pair(lab, 'Historical familiarity')
    assert history['right']['incident_count'] == 0 and store.incidents(history['right_run_id']) == []
    familiar = history['right']['history_probes'][0]
    unusual = history['left']['history_probes'][0]
    assert not familiar['authentication']['unusual'] and unusual['authentication']['unusual']
    assert familiar['collection']['same_resource_count'] > 0 and unusual['collection']['same_resource_count'] == 0
    assert history['right']['window_scores'][0]['anomaly_percentile'] is not None
    assert {c['case'] for c in library['validation_cases']} == {'Wrong environment', 'Wrong action', 'Invalid provenance'}
    assert all(c['outcome'] == 'schema/storage rejected' for c in library['validation_cases'])
    assert pair(lab, 'Declared attack versus business export')['evaluation_annotation']['left'] == 'attack'


def test_frozen_reopen_context_upload_edits_truth_isolation_and_4a(lab):
    store, baseline, _ = lab
    value = pair(lab, 'Withheld versus exact declaration')
    parent = store.analysis(value['left_run_id'])
    original = copy.deepcopy(store.incidents(value['left_run_id']))
    report = build_report(store, original[0]['incident_id'])
    noop = create_sensitivity(store, value['left_run_id'], [])
    store.set_authorizations(parent['dataset_id'], [])
    store.set_resources(parent['dataset_id'], [])
    copy_id = original[0]['stages'][-1]['evidence_event_ids'][0]
    source = store.evidence(copy_id)['source_records'][0]
    store.ingest(parent['dataset_id'], json.dumps(source['raw']).encode(), 'later.jsonl', source['source_id'], source['source_type'])
    assert retained_comparison(Store(store.path), value['comparison_id']) == value
    response = TestClient(create_app(store.path)).get(f"/api/analyses/{parent['analysis_run_id']}/source/{copy_id}")
    assert response.status_code == 200 and len(response.json()['source_records']) == 2
    assert store.analysis(value['left_run_id']) == parent and store.incidents(value['left_run_id']) == original
    assert verify_report(store, report)['valid'] and verify_comparison(store, export_comparison(store, noop['comparison_id']))['valid']
    with store.connection() as conn:
        conn.execute('UPDATE lookalike_annotations SET body=? WHERE id=?', (json.dumps({'left':'attack','right':'attack','provenance':'Changed evaluator only'}), value['comparison_id']))
    updated = retained_comparison(store, value['comparison_id'])
    assert updated['correspondence'] == value['correspondence'] and updated['compatibility'] == value['compatibility']
    assert updated['left'] == value['left'] and updated['right'] == value['right']
    assert store.incidents(value['left_run_id']) == original
    # Reversed preparation cannot contaminate withheld authorization.
    _, _, reversed_runs = controlled_pair(store, baseline['baseline_id'], authorized_first=True)
    a = store.incidents(reversed_runs['withheld']['analysis_run_id'])[0]
    b = store.incidents(reversed_runs['valid']['analysis_run_id'])[0]
    assert a['authorization']['reduction'] == 0 and b['authorization']['reduction'] == 20


def test_api_bounds_incompatibility_and_candidate_correspondence(lab):
    store, _, _ = lab
    client = TestClient(create_app(store.path))
    value = pair(lab, 'Historical familiarity')
    response = client.post('/api/lookalikes', json={'left_run_id':value['left_run_id'],'right_run_id':value['right_run_id']})
    assert response.status_code == 422 and 'Incompatible controlled' in response.text
    assert client.get('/api/lookalikes?limit=101').status_code == 422
    assert client.get('/api/lookalikes/'+value['comparison_id']+'?cursor=-1').status_code == 422
    assert client.post('/api/lookalikes', json={'left_run_id':value['left_run_id'],'right_run_id':value['left_run_id'],'risk_delta':-20}).status_code == 422
    actual = item(store, value['left'])
    another = copy.deepcopy(actual); another['incident_id'] = 'separate'; another['user_id'] = 'synthetic-office:user:another'
    assert all(r['risk_delta'] is None for r in correspondence([actual], [another]))
    twin = copy.deepcopy(actual); twin['incident_id'] = 'ambiguous'
    rows = correspondence([actual], [actual, twin])
    assert rows[0]['status'] == 'ambiguous' and rows[0]['risk_delta'] is None
    assert correspondence([], []) == [] and correspondence([], [actual])[0]['left_incident_id'] is None


@pytest.mark.parametrize('change', ['cutoff', 'resources', 'mode', 'sources'])
def test_controlled_rejects_real_non_authorization_differences(lab, change):
    store, baseline, _ = lab
    dataset, _, runs = controlled_pair(store, baseline['baseline_id'])
    left = runs['withheld']
    store.set_authorizations(dataset, [])
    kwargs = {'mode':'hybrid', 'baseline_id':baseline['baseline_id']}
    if change == 'cutoff':
        kwargs['cutoff'] = datetime.fromisoformat(left['cutoff'])+timedelta(minutes=15)
    elif change == 'resources':
        from traceguard.schemas import ResourceContext
        entries = store.resources(dataset)
        entries[0]['provenance'] = 'Different non-authorization provenance'
        store.set_resources(dataset, [ResourceContext(**r) for r in entries])
    elif change == 'mode':
        kwargs['mode'] = 'rules-only'
    else:
        event = next(e for e in store.events(dataset) if e.action == 'file_copy_to_usb')
        source = store.evidence(event.event_id)['source_records'][0]
        store.ingest(dataset, json.dumps(source['raw']).encode(), 'later-duplicate.jsonl', source['source_id'], source['source_type'])
    right = run_analysis(store, dataset, **kwargs)
    with pytest.raises(ValueError, match='Incompatible controlled comparison'):
        create_comparison(store, left['analysis_run_id'], right['analysis_run_id'], declared_changes=['authorization_context_snapshot'])
