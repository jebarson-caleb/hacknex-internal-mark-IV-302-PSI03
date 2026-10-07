import copy
import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from traceguard.baseline import fit_baseline
from traceguard.demo import load_demo
from traceguard.evaluation.fixtures import load_chronological_demo
from traceguard.hybrid import run_analysis
from traceguard.main import create_app
from traceguard.reports import build_report, verify_report
from traceguard.schemas import AliasContext, AuthorizationContext, ResourceContext
from traceguard.sensitivity import create_sensitivity, export_comparison, retained_comparison, semantic, verify_comparison
from traceguard.storage import Store


def setup(tmp_path):
    store = Store(tmp_path / 'sensitivity.sqlite3')
    dataset = load_demo(store)
    return store, dataset


def parent(store, dataset):
    run = run_analysis(store, dataset)
    item = next(i for i in store.incidents(run['analysis_run_id']) if len(i['stages']) == 3)
    return run, item


def append_copy(store, dataset, event_id, independent=False):
    source = store.evidence(event_id)['source_records'][0]
    raw = copy.deepcopy(source['raw'])
    if independent:
        raw['timestamp'] = (store.event(event_id).event_time_utc + timedelta(minutes=1)).isoformat()
    store.ingest(dataset, json.dumps(raw).encode(), 'extra.jsonl', source['source_id'], source['source_type'])


def test_noop_unique_copy_duplicate_exclusion_and_unchanged_report(tmp_path):
    store, dataset = setup(tmp_path)
    first, item = parent(store, dataset)
    copy_id = item['stages'][-1]['evidence_event_ids'][0]
    append_copy(store, dataset, copy_id)
    run, item = parent(store, dataset)
    frozen = copy.deepcopy(run)
    report = build_report(store, item['incident_id'])
    noop = create_sensitivity(store, run['analysis_run_id'], [])
    assert semantic(noop['before_candidates']) == semantic(noop['after_candidates'])
    assert noop['after_candidates'] == store.incidents(noop['manifest']['child_run_id'])
    result = create_sensitivity(store, run['analysis_run_id'], [copy_id, copy_id])
    assert result['manifest']['excluded_event_ids'] == [copy_id]
    assert all('transfer' not in [s['stage_id'] for s in i['stages']] for i in result['after_candidates'])
    assert all(i['decision'] != 'incident' and copy_id not in i['selected_evidence'] for i in result['after_candidates'])
    assert result['differences'][0]['lost_stages'] == ['transfer']
    child = store.analysis(result['manifest']['child_run_id'])
    assert copy_id not in child['event_ids']
    assert len(store.evidence(copy_id)['source_records']) == 2
    assert store.analysis(run['analysis_run_id']) == frozen
    again = build_report(store, item['incident_id'])
    again['validation']['checked_at_utc'] = report['validation']['checked_at_utc']
    assert again == report and verify_report(store, report)['valid']
    assert verify_comparison(store, noop)['valid'] and verify_comparison(store, result)['valid']
    reopened = Store(store.path)
    assert retained_comparison(reopened, result['comparison_id']) == result
    assert export_comparison(reopened, result['comparison_id']) == result
    assert any(r.get('branch_kind') == 'evidence_sensitivity' for r in reopened.analyses(dataset))


def test_independent_copy_can_preserve_stage(tmp_path):
    store, dataset = setup(tmp_path)
    _, item = parent(store, dataset)
    copy_id = item['stages'][-1]['evidence_event_ids'][0]
    append_copy(store, dataset, copy_id, independent=True)
    run, item = parent(store, dataset)
    result = create_sensitivity(store, run['analysis_run_id'], [copy_id])
    child = next(i for i in result['after_candidates'] if len(i['stages']) == 3)
    remaining = child['stages'][-1]['evidence_event_ids'][0]
    assert remaining != copy_id and store.event(remaining).action == 'file_copy_to_usb'
    assert result['differences'][0]['supported_stages'] == ['authentication', 'collection', 'transfer']
    assert copy_id not in child['selected_evidence'] and verify_comparison(store, result)['valid']


@pytest.mark.parametrize('required', ['authentication', 'mount'])
def test_required_observation_exclusion(tmp_path, required):
    store, dataset = setup(tmp_path)
    run, item = parent(store, dataset)
    eid = item['context_event_ids'][0] if required == 'mount' else item['stages'][0]['evidence_event_ids'][0]
    result = create_sensitivity(store, run['analysis_run_id'], [eid])
    assert not any(len(i['stages']) == 3 for i in result['after_candidates'])
    if required == 'authentication':
        assert result['empty_result'] and result['after_candidates'] == []
        assert result['differences'][0]['after'] is None
    assert verify_report(store, export_comparison(store, result['comparison_id']))['valid']


def test_later_upload_context_and_repeat_requests_use_parent(tmp_path):
    store, dataset = setup(tmp_path)
    run, item = parent(store, dataset)
    eid = item['stages'][-1]['evidence_event_ids'][0]
    first = create_sensitivity(store, run['analysis_run_id'], [eid])
    append_copy(store, dataset, eid, independent=True)
    append_copy(store, dataset, eid)
    resources = [ResourceContext.model_validate({**r, 'sensitive': False}) for r in store.resources(dataset)]
    store.set_resources(dataset, resources)
    event = store.event(eid)
    store.set_authorizations(dataset, [AuthorizationContext(authorization_id='later-context', user_id=item['user_id'],
        device_id=item['device_id'], resource_id=event.resource_id, provenance='Later operator declaration',
        effective_from=event.event_time_utc-timedelta(minutes=1), effective_until=event.event_time_utc+timedelta(minutes=1))])
    store.set_aliases(store.dataset(dataset)['environment'], [AliasContext(alias_user_id=item['user_id'],
        canonical_user_id=item['user_id']+'-later', provenance='Later directory binding', effective_from=event.event_time_utc-timedelta(days=1))])
    second = create_sensitivity(store, run['analysis_run_id'], [eid])
    assert semantic(first['after_candidates']) == semantic(second['after_candidates'])
    assert first['manifest']['effective_fingerprint'] == second['manifest']['effective_fingerprint']
    assert verify_comparison(store, first)['valid'] and verify_comparison(store, second)['valid']


@pytest.mark.parametrize('field', ['excluded', 'parent', 'child', 'risk', 'evidence', 'differences'])
def test_comparison_tampering_fails(tmp_path, field):
    store, dataset = setup(tmp_path)
    run, item = parent(store, dataset)
    result = create_sensitivity(store, run['analysis_run_id'], item['stages'][-1]['evidence_event_ids'])
    changed = copy.deepcopy(result)
    if field == 'excluded': changed['manifest']['excluded_event_ids'] = []
    elif field in ('parent', 'child'): changed['manifest'][field + '_run_id'] = 'other'
    elif field == 'risk': changed['after_candidates'][0]['risk']['score'] = 0
    elif field == 'evidence': changed['after_candidates'][0]['selected_evidence'] = []
    else: changed['differences'][0]['lost_stages'] = []
    assert not verify_report(store, changed)['valid']


def test_invalid_requests_legacy_nested_and_policy(tmp_path):
    store, dataset = setup(tmp_path)
    run, item = parent(store, dataset)
    with pytest.raises(ValueError, match='membership'): create_sensitivity(store, run['analysis_run_id'], ['outside'])
    client = TestClient(create_app(store.path))
    route = '/api/analyses/' + run['analysis_run_id'] + '/sensitivity'
    for body in ({'excluded_event_ids': ['x'] * 101}, {'excluded_event_ids': [None]},
                 {'excluded_event_ids': [], 'cutoff': run['cutoff']}, {'analyst_note': 'x' * 501}):
        assert client.post(route, json=body).status_code == 422
    result = create_sensitivity(store, run['analysis_run_id'], [])
    with pytest.raises(ValueError, match='Nested'): create_sensitivity(store, result['manifest']['child_run_id'], [])
    for mutation in ('legacy', 'policy'):
        altered = copy.deepcopy(run)
        if mutation == 'legacy': altered.pop('view_snapshot')
        else: altered['view_snapshot']['policy_identity'] = {}
        with store.connection() as conn:
            conn.execute('UPDATE analyses SET body=? WHERE id=?', (json.dumps(altered), run['analysis_run_id']))
        with pytest.raises(ValueError, match='Unsupported parent'): create_sensitivity(store, run['analysis_run_id'], [])


def test_hybrid_recomputes_windows_fixed_model_and_never_fits(tmp_path, monkeypatch):
    store = Store(tmp_path / 'hybrid.sqlite3')
    data, _ = load_chronological_demo(store)
    fitted = fit_baseline(store, data['training']['id'], data['calibration']['id'], 'Explicit synthetic benign fixture')
    run = run_analysis(store, data['test']['id'], mode='hybrid', baseline_id=fitted['baseline_id'])
    model_before = store.baseline(fitted['baseline_id'])
    monkeypatch.setattr('traceguard.baseline.fit_baseline', lambda *a, **k: pytest.fail('Sensitivity must not fit'))
    item = next(i for i in store.incidents(run['analysis_run_id']) if len(i['stages']) == 3)
    eid = item['stages'][-1]['evidence_event_ids'][0]
    noop = create_sensitivity(store, run['analysis_run_id'], [])
    assert semantic(noop['before_candidates']) == semantic(noop['after_candidates'])
    result = create_sensitivity(store, run['analysis_run_id'], [eid])
    child = store.analysis(result['manifest']['child_run_id'])
    assert child['window_scores'] != run['window_scores']
    assert all(eid not in w['event_ids'] for w in child['window_scores'])
    assert sum(w['observed_features']['usb_bytes'] for w in child['window_scores']) == (
        sum(w['observed_features']['usb_bytes'] for w in run['window_scores']) - store.event(eid).bytes_written)
    assert child['baseline_snapshot'] == run['baseline_snapshot']
    assert store.baseline(fitted['baseline_id']) == model_before
    assert all(eid not in edge['event_ids'] for d in result['differences'] for edge in (d.get('graph_after') or {}).get('edges', []))
    assert not any(len(i['stages']) == 3 for i in result['after_candidates'])
    assert verify_comparison(store, result)['valid']
    assert verify_comparison(store, noop)['valid'], verify_comparison(store, noop)
    # A changed BLOB plus changed SQLite integrity hash must still fail the parent's frozen model hash.
    from traceguard.ingest import digest
    changed_blob = model_before[1] + b'changed-artifact'
    with store.connection() as conn:
        conn.execute('UPDATE baselines SET model=?,sha256=? WHERE id=?', (changed_blob, digest(changed_blob), fitted['baseline_id']))
    assert not verify_comparison(store, result)['valid']


def test_retained_child_or_source_corruption_fails(tmp_path):
    store, dataset = setup(tmp_path)
    run, item = parent(store, dataset)
    result = create_sensitivity(store, run['analysis_run_id'], [])
    child_id = result['after_candidates'][0]['incident_id']
    modified = copy.deepcopy(result['after_candidates'][0]); modified['risk']['score'] = 0
    with store.connection() as conn:
        conn.execute('UPDATE incidents SET body=? WHERE id=?', (json.dumps(modified), child_id))
    assert not verify_comparison(store, result)['valid']
    with store.connection() as conn:
        conn.execute('UPDATE incidents SET body=? WHERE id=?', (json.dumps(result['after_candidates'][0]), child_id))
        conn.execute("UPDATE records SET raw_sha256='tampered' WHERE event_id=?", (item['selected_evidence'][0],))
    assert not verify_comparison(store, result)['valid']
    with pytest.raises(ValueError, match='verification failed'): export_comparison(store, result['comparison_id'])


def test_episode_correspondence_does_not_merge_later_episode(tmp_path):
    store, dataset = setup(tmp_path)
    _, initial = parent(store, dataset)
    # Add a distinct later episode through ordinary ingestion, same actor/endpoint/resources.
    for eid in initial['selected_evidence']:
        source = store.evidence(eid)['source_records'][0]
        raw = copy.deepcopy(source['raw'])
        raw['timestamp'] = (store.event(eid).event_time_utc + timedelta(hours=2)).isoformat()
        store.ingest(dataset, json.dumps(raw).encode(), 'later.jsonl', source['source_id'], source['source_type'])
    run, _ = parent(store, dataset)
    before = sorted(store.incidents(run['analysis_run_id']), key=lambda i:i['stages'][0]['start_time_utc'])
    assert len(before) == 2
    result = create_sensitivity(store, run['analysis_run_id'], before[0]['selected_evidence'])
    lost = next(d for d in result['differences'] if d['parent_incident_id'] == before[0]['incident_id'])
    survived = next(d for d in result['differences'] if d['parent_incident_id'] == before[1]['incident_id'])
    assert lost['status'] == 'lost' and lost['after'] is None
    assert survived['status'] == 'matched' and survived['after']['selected_evidence'] == before[1]['selected_evidence']
    assert verify_comparison(store, result)['valid']


def test_changed_episode_selection_and_ambiguous_correspondence(tmp_path):
    from traceguard.sensitivity import differences
    store, dataset = setup(tmp_path)
    _, original = parent(store, dataset)
    eid = original['stages'][0]['evidence_event_ids'][0]
    source = store.evidence(eid)['source_records'][0]
    raw = copy.deepcopy(source['raw'])
    raw['timestamp'] = (store.event(eid).event_time_utc + timedelta(minutes=1)).isoformat()
    store.ingest(dataset, json.dumps(raw).encode(), 'alternative-auth.jsonl', source['source_id'], source['source_type'])
    run, item = parent(store, dataset)
    result = create_sensitivity(store, run['analysis_run_id'], [eid])
    changed = result['after_candidates'][0]
    assert changed['stages'][0]['evidence_event_ids'] != item['stages'][0]['evidence_event_ids']
    assert len(changed['stages']) == 3 and result['differences'][0]['status'] == 'matched'
    # Correspondence unit check: multiple plausible candidates must be disclosed, never guessed.
    alternative = copy.deepcopy(changed); alternative['incident_id'] += '-alternative'
    diff = differences(store, run, store.analysis(result['manifest']['child_run_id']), [item], [changed, alternative])
    assert diff[0]['status'] == 'ambiguous' and len(diff[0]['possible_child_ids']) == 2
    assert verify_comparison(store, result)['valid']
