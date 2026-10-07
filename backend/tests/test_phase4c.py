import copy
import json
from datetime import timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sklearn.ensemble import IsolationForest

from traceguard.baseline import fit_baseline
from traceguard.demo import load_demo
from traceguard.evaluation.fixtures import load_chronological_demo
from traceguard.features import window_start
from traceguard.hybrid import incident_graph, run_analysis
from traceguard.main import create_app
from traceguard.replay import ReplayView, core, create_frame, get_frame, navigation
from traceguard.reports import build_report, markdown_report, read_report, verify_report
from traceguard.schemas import AuthorizationContext, ResourceContext
from traceguard.sensitivity import semantic
from traceguard.storage import Store


def setup(tmp_path, hybrid=False):
    store = Store(tmp_path / 'replay.sqlite3')
    if hybrid:
        data, _ = load_chronological_demo(store)
        fitted = fit_baseline(store, data['training']['id'], data['calibration']['id'], 'Explicit benign development setup')
        run = run_analysis(store, data['test']['id'], mode='hybrid', baseline_id=fitted['baseline_id'])
    else:
        run = run_analysis(store, load_demo(store))
    item = next(i for i in store.incidents(run['analysis_run_id']) if len(i['stages']) == 3)
    return store, run, item


def frame(store, run, time):
    return create_frame(store, run['analysis_run_id'], time.isoformat())['run']


@pytest.mark.parametrize('hybrid', [False, True])
def test_boundaries_backward_final_sources_reports_and_never_fit(tmp_path, monkeypatch, hybrid):
    store, parent, item = setup(tmp_path, hybrid)
    model = store.baseline(parent['baseline_id']) if hybrid else None
    monkeypatch.setattr(IsolationForest, 'fit', lambda *a, **k: pytest.fail('Replay must never fit/recalibrate'))
    monkeypatch.setattr('traceguard.baseline.fit_baseline', lambda *a, **k: pytest.fail('No fitting'))
    original = copy.deepcopy(parent)
    nav = navigation(store, parent['analysis_run_id'])
    early = create_frame(store, parent['analysis_run_id'], nav['start'])['run']
    assert early['event_count'] == 0 and store.incidents(early['analysis_run_id']) == []
    copy_event = store.event(item['stages'][2]['evidence_event_ids'][0])
    cutoff = copy_event.event_time_utc
    before = frame(store, parent, cutoff-timedelta(microseconds=1))
    assert all(len(i['stages']) < 3 for i in store.incidents(before['analysis_run_id']))
    partial = next(i for i in store.incidents(before['analysis_run_id']) if len(i['stages']) == 2)
    partial_report = build_report(store, partial['incident_id'])
    assert copy_event.event_id not in [r['event']['event_id'] for r in partial_report['evidence']]
    future_claim = copy.deepcopy(partial_report)
    future_claim['incident']['selected_evidence'].append(copy_event.event_id)
    future_claim['evidence'].append(store.evidence(copy_event.event_id))
    assert not verify_report(store, future_claim)['valid']
    client = TestClient(create_app(store.path))
    assert client.get(f"/api/analyses/{before['analysis_run_id']}/source/{copy_event.event_id}").status_code == 422
    at = frame(store, parent, cutoff)
    complete = next(i for i in store.incidents(at['analysis_run_id']) if len(i['stages']) == 3)
    if hybrid:
        assert complete['decision'] == 'review' and complete['risk']['missing_components']
        assert any(w['provisional'] and w['anomaly_percentile'] is None for w in at['window_scores'])
        close = frame(store, parent, window_start(cutoff)+timedelta(minutes=15))
        closed_item = next(i for i in store.incidents(close['analysis_run_id']) if len(i['stages']) == 3)
        assert closed_item['risk']['anomaly_percentile'] is not None
        assert store.baseline(parent['baseline_id']) == model
    for candidate in store.incidents(at['analysis_run_id']):
        assert all(store.event(eid).event_time_utc <= cutoff for eid in candidate['selected_evidence'])
        assert all(store.event(eid).event_time_utc <= cutoff for edge in incident_graph(store, candidate['incident_id'])['edges'] for eid in edge['event_ids'])
        report = build_report(store, candidate['incident_id'])
        assert report['replay_manifest']['effective_cutoff'] == at['cutoff']
        assert verify_report(store, report)['valid']
        assert verify_report(store, read_report(markdown_report(report)))['valid']
        forged = copy.deepcopy(report); forged['run']['cutoff'] = '2027-01-01T00:00:00Z'
        assert not verify_report(store, forged)['valid']
    for stage in item['stages'][:2]:
        boundary = store.event(stage['evidence_event_ids'][0]).event_time_utc
        prior = frame(store, parent, boundary-timedelta(microseconds=1))
        assert all(stage['stage_id'] not in [s['stage_id'] for s in i['stages']] for i in store.incidents(prior['analysis_run_id']))
    mount_time = store.event(item['context_event_ids'][0]).event_time_utc
    mounted = frame(store, parent, mount_time)
    assert all(len(i['stages']) < 3 for i in store.incidents(mounted['analysis_run_id']))
    final = create_frame(store, parent['analysis_run_id'], parent['cutoff'])['run']
    assert core(final) == core(parent)
    assert semantic(store.incidents(final['analysis_run_id'])) == semantic(store.incidents(parent['analysis_run_id']))
    assert frame(store, parent, cutoff-timedelta(microseconds=1)) == before
    assert get_frame(Store(store.path), at['analysis_run_id'])['run'] == at
    assert store.analysis(parent['analysis_run_id']) == original


@pytest.mark.parametrize('value', ['2026-01-01T09:00:00', 'bad', '2025-01-01T00:00:00Z', '2027-01-01T00:00:00Z'])
def test_invalid_cutoffs(tmp_path, value):
    store, parent, _ = setup(tmp_path)
    with pytest.raises(ValueError, match='cutoff'):
        create_frame(store, parent['analysis_run_id'], value)


def test_api_scope_empty_override_nested_and_historical_parent(tmp_path):
    store, parent, item = setup(tmp_path)
    client = TestClient(create_app(store.path))
    nav = navigation(store, parent['analysis_run_id'])
    path = f"/api/analyses/{parent['analysis_run_id']}/replay"
    for key in ('mode', 'baseline_id', 'policy', 'context', 'excluded_event_ids'):
        assert client.post(path, json={'cutoff':nav['start'], key:None}).status_code == 422
    early = client.post(path, json={'cutoff':nav['start']}).json()['run']
    assert client.get(f"/api/analyses/{early['analysis_run_id']}/observations").json()['items'] == []
    assert client.get(f"/api/analyses/{early['analysis_run_id']}/source/{item['selected_evidence'][0]}").status_code == 422
    assert client.post(f"/api/analyses/{early['analysis_run_id']}/replay", json={'cutoff':nav['start']}).status_code == 422
    incompatible = copy.deepcopy(parent)
    incompatible['view_snapshot']['policy_identity']['views'] = 'historical'
    with store.connection() as conn:
        conn.execute('UPDATE analyses SET body=? WHERE id=?', (json.dumps(incompatible),parent['analysis_run_id']))
    response = client.post(path, json={'cutoff':nav['start']})
    assert response.status_code == 422 and 'ordinary new analysis' in response.text
    assert store.analysis(parent['analysis_run_id']) == incompatible


@pytest.mark.parametrize('field', ['cutoff', 'event_ids', 'parent_run_id', 'baseline_id', 'view_snapshot', 'branch_kind', 'disguise'])
def test_tampered_frame_is_rejected_by_api_and_report(tmp_path, field):
    store, parent, _ = setup(tmp_path)
    child = create_frame(store, parent['analysis_run_id'], parent['cutoff'])['run']
    item = store.incidents(child['analysis_run_id'])[0]
    forged = copy.deepcopy(child)
    if field == 'disguise':
        forged.pop('replay_manifest'); forged['branch_kind'] = 'ordinary'
    else:
        forged[field] = [] if field == 'event_ids' else {} if field == 'view_snapshot' else 'tampered'
    with store.connection() as conn:
        conn.execute('UPDATE analyses SET body=? WHERE id=?', (json.dumps(forged),child['analysis_run_id']))
    with pytest.raises(ValueError):
        get_frame(store, child['analysis_run_id'])
    with pytest.raises(ValueError):
        build_report(store, item['incident_id'])
    client = TestClient(create_app(store.path))
    assert client.get(f"/api/analyses/{child['analysis_run_id']}/candidates").status_code == 422


def test_mutable_uploads_context_duplicates_and_retained_corruption(tmp_path):
    store, parent, item = setup(tmp_path)
    child = create_frame(store, parent['analysis_run_id'], parent['cutoff'])
    event = store.event(item['selected_evidence'][-1])
    source = store.evidence(event.event_id)['source_records'][0]
    store.ingest(parent['dataset_id'], json.dumps(source['raw']).encode(), 'duplicate.jsonl', source['source_id'], source['source_type'])
    raw = copy.deepcopy(source['raw']); raw['timestamp'] = (event.event_time_utc+timedelta(days=1)).isoformat()
    store.ingest(parent['dataset_id'], json.dumps(raw).encode(), 'later.jsonl', source['source_id'], source['source_type'])
    store.set_resources(parent['dataset_id'], [ResourceContext.model_validate({**r,'sensitive':False}) for r in store.resources(parent['dataset_id'])])
    assert get_frame(store, child['run']['analysis_run_id']) == child
    assert store.analysis(parent['analysis_run_id']) == parent
    client = TestClient(create_app(store.path))
    response = client.get(f"/api/analyses/{child['run']['analysis_run_id']}/source/{event.event_id}")
    assert len(response.json()['source_records']) == 1
    with store.connection() as conn:
        conn.execute("UPDATE records SET raw_sha256='tampered' WHERE event_id=?", (event.event_id,))
    with pytest.raises(ValueError, match='verification failed'):
        get_frame(store, child['run']['analysis_run_id'])


@pytest.mark.parametrize('kind', ['training', 'calibration'])
def test_missing_and_overlapping_fitted_intervals(tmp_path, kind):
    store, parent, _ = setup(tmp_path, True)
    from traceguard.replay import replay_range
    start, _ = replay_range(store, parent)
    for invalid in ('missing', 'overlap'):
        altered = copy.deepcopy(parent)
        metadata = altered['baseline_snapshot']
        if invalid == 'missing':
            del metadata[kind+'_end']
        else:
            metadata[kind+'_end'] = (start+timedelta(seconds=1)).isoformat()
        # Retain the baseline/parent equality, so the replay interval check is the decisive guard.
        with store.connection() as conn:
            conn.execute('UPDATE baselines SET metadata=? WHERE id=?', (json.dumps(metadata),parent['baseline_id']))
        with pytest.raises(ValueError, match='interval'):
            ReplayView(store, altered, start)


def normalized(items, store):
    """Compare supported content across independently ingested dataset namespaces."""
    replacements = {}
    for item in items:
        replacements[item['incident_id']] = 'incident'
        replacements[item['analysis_run_id']] = 'run'
        replacements[item['dataset_id']] = 'dataset'
        for eid in item['selected_evidence']:
            e = store.event(eid)
            replacements[eid] = f'{e.source_id}:{e.source_event_id}:{e.event_time_utc.isoformat()}'
    def walk(value):
        if isinstance(value,dict):
            return {replacements.get(k,k):walk(v) for k,v in value.items()}
        if isinstance(value,list):
            return sorted(walk(v) for v in value) if all(isinstance(v,str) for v in value) else [walk(v) for v in value]
        return replacements.get(value,value) if isinstance(value,str) else value
    return semantic(walk(items))


def test_valid_future_alternatives_identical_prefix_hybrid(tmp_path):
    store, parent, item = setup(tmp_path, True)
    copy_time = store.event(item['stages'][2]['evidence_event_ids'][0]).event_time_utc
    first = frame(store, parent, copy_time)
    other = store.create_dataset('Independent later alternative', store.dataset(parent['dataset_id'])['environment'])
    # Identical prefix, valid retained source rows, changed later window contents.
    for event in store.events_by_ids(parent['event_ids']):
        if event.event_time_utc > copy_time:
            continue
        source = store.evidence(event.event_id)['source_records'][0]
        store.ingest(other, json.dumps(source['raw']).encode(), 'prefix.jsonl', source['source_id'], source['source_type'])
    source = store.evidence(item['stages'][2]['evidence_event_ids'][0])['source_records'][0]
    raw = copy.deepcopy(source['raw']);raw['timestamp'] = (copy_time+timedelta(minutes=1)).isoformat();raw['bytes_written'] = 987654321
    raw['source_event_id'] = 'independent-future'
    store.ingest(other,json.dumps(raw).encode(),'future.jsonl',source['source_id'],source['source_type'])
    store.set_resources(other,[ResourceContext.model_validate(r) for r in parent['resource_context_snapshot']])
    alternative = run_analysis(store,other,mode='hybrid',baseline_id=parent['baseline_id'])
    second = frame(store,alternative,copy_time)
    assert normalized(store.incidents(first['analysis_run_id']),store) == normalized(store.incidents(second['analysis_run_id']),store)
    def windows(run):
        return [{k:v for k,v in w.items() if k!='event_ids'} for w in run['window_scores']]
    assert windows(first) == windows(second)


def test_multiple_episodes_preserved_with_changed_candidate_selection(tmp_path):
    store, parent, item = setup(tmp_path)
    for eid in item['selected_evidence']:
        event = store.event(eid);source = store.evidence(eid)['source_records'][0]
        raw = copy.deepcopy(source['raw']);raw['timestamp'] = (event.event_time_utc+timedelta(hours=2)).isoformat()
        store.ingest(parent['dataset_id'],json.dumps(raw).encode(),'later-episode.jsonl',source['source_id'],source['source_type'])
    parent = run_analysis(store,parent['dataset_id'])
    end = create_frame(store,parent['analysis_run_id'],parent['cutoff'])['run']
    earlier = frame(store,parent,store.event(item['stages'][2]['evidence_event_ids'][0]).event_time_utc)
    assert len(store.incidents(end['analysis_run_id'])) == 2
    assert len(store.incidents(earlier['analysis_run_id'])) == 1


def test_bounded_atomic_concurrent_reuse(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    store, parent, _ = setup(tmp_path)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: create_frame(store,parent['analysis_run_id'],parent['cutoff']),range(2)))
    assert results[0] == results[1]
    monkeypatch.setattr('traceguard.replay.MAX_FRAMES', 1)
    assert create_frame(store,parent['analysis_run_id'],parent['cutoff']) == results[0]
    with pytest.raises(ValueError,match='Replay limit'):
        create_frame(store,parent['analysis_run_id'],navigation(store,parent['analysis_run_id'])['start'])
    assert store.analysis(parent['analysis_run_id']) == parent


def test_offset_parent_final_reproduction_and_equivalent_requests(tmp_path):
    store, original, _ = setup(tmp_path)
    from traceguard.replay import instant
    cutoff = instant(original['cutoff']).astimezone(timezone(timedelta(hours=5,minutes=30)))
    parent = run_analysis(store,original['dataset_id'],cutoff=cutoff)
    result = create_frame(store,parent['analysis_run_id'],parent['cutoff'])
    assert core(result['run']) == core(parent)
    assert create_frame(store,parent['analysis_run_id'],instant(parent['cutoff']).isoformat()) == result


def test_copy_time_authorization_and_baseline_selected_rules_history(tmp_path):
    store, parent, item = setup(tmp_path, True)
    event = store.event(item['stages'][2]['evidence_event_ids'][0])
    ticket = AuthorizationContext(authorization_id='copy-time-ticket',user_id=event.user_id,device_id=event.device_id,
        resource_id=event.resource_id,action='file_copy_to_usb',provenance='Explicit operator regression context',
        effective_from=event.event_time_utc-timedelta(minutes=1),effective_until=event.event_time_utc+timedelta(minutes=1))
    store.set_authorizations(parent['dataset_id'],[ticket])
    parent = run_analysis(store,parent['dataset_id'],mode='hybrid',baseline_id=parent['baseline_id'])
    close = frame(store,parent,window_start(event.event_time_utc)+timedelta(minutes=15))
    candidate = next(i for i in store.incidents(close['analysis_run_id']) if len(i['stages']) == 3)
    ordinary = next(i for i in store.incidents(parent['analysis_run_id']) if len(i['stages']) == 3)
    assert candidate['authorization'] == ordinary['authorization']
    assert candidate['risk']['components']['B'] == 20
    store.set_authorizations(parent['dataset_id'],[])
    assert get_frame(store,close['analysis_run_id'])['run'] == close
    rules = run_analysis(store,parent['dataset_id'],mode='rules-only',baseline_id=parent['baseline_id'])
    final = create_frame(store,rules['analysis_run_id'],rules['cutoff'])['run']
    assert core(final) == core(rules) and not final['window_scores']


@pytest.mark.parametrize('variant', ['failed', 'zero', 'wrong-resource', 'equal-time', 'other-actor-shared-ip', 'missing-copy'])
def test_replay_preserves_copy_strict_order_and_identity_gates(tmp_path, variant):
    store, parent, item = setup(tmp_path)
    other = store.create_dataset('Real predicate regression', store.dataset(parent['dataset_id'])['environment'])
    collection_time = store.event(item['stages'][1]['evidence_event_ids'][0]).event_time_utc
    for event in store.events_by_ids(parent['event_ids']):
        source = store.evidence(event.event_id)['source_records'][0]
        raw = copy.deepcopy(source['raw'])
        if event.action == 'file_copy_to_usb':
            if variant == 'missing-copy':
                continue
            if variant == 'failed': raw['outcome'] = 'failure'
            if variant == 'zero': raw['bytes_written'] = 0
            if variant == 'wrong-resource': raw['resource_id'] = 'different-resource'
            if variant == 'equal-time': raw['timestamp'] = collection_time.isoformat()
            if variant == 'other-actor-shared-ip': raw['user_id'] = 'someone-else'
        store.ingest(other,json.dumps(raw).encode(),'predicate.jsonl',source['source_id'],source['source_type'])
    store.set_resources(other,[ResourceContext.model_validate(r) for r in parent['resource_context_snapshot']])
    run = run_analysis(store,other)
    child = create_frame(store,run['analysis_run_id'],run['cutoff'])['run']
    assert not any(len(i['stages']) == 3 for i in store.incidents(child['analysis_run_id']))
    assert semantic(store.incidents(child['analysis_run_id'])) == semantic(store.incidents(run['analysis_run_id']))
