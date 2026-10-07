"""Persisted evidence-availability experiments and independently rebuilt comparisons."""
import copy
import json
from datetime import datetime, timezone
from time import perf_counter
from uuid import uuid4

from .graph import build_graph, graph_payload
from .ingest import digest, json_bytes
from .resolution import resolve_events
from .views import AnalysisView

VERSION = 'traceguard-sensitivity-v1'


def semantic(items):
    return sorted([{k: v for k, v in item.items() if k not in ('incident_id', 'analysis_run_id')}
                   for item in items], key=lambda item: json.dumps(item, sort_keys=True))


def findings(run):
    return {k: v for k, v in run.items() if k not in (
        'analysis_run_id', 'branch_kind', 'parent_run_id', 'comparison_id', 'view_snapshot',
        'evidence_reference_snapshot')}


def graph_for(store, run, item):
    events, links, _ = resolve_events(store.events_by_ids(item['selected_evidence']),
                                     run.get('alias_context_snapshot', []))
    return graph_payload(build_graph(events, links), 500)


def differences(store, parent, child, before, after):
    def related(a, b):
        # Same family and scoped identities, overlapping episode intervals AND evidence.
        if (a['user_id'], a['device_id'], a['stages'][0]['rule_id']) != (
                b['user_id'], b['device_id'], b['stages'][0]['rule_id']):
            return False
        overlap = max(a['stages'][0]['start_time_utc'], b['stages'][0]['start_time_utc']) <= min(
            a['stages'][-1]['end_time_utc'], b['stages'][-1]['end_time_utc'])
        return overlap and bool(set(a['selected_evidence']) & set(b['selected_evidence']))
    pairs = [(a['incident_id'], b['incident_id']) for a in before for b in after if related(a, b)]
    rows = []
    used = set()
    for a in before:
        matches = [b for b in after if (a['incident_id'], b['incident_id']) in pairs]
        ambiguous = len(matches) > 1 or any(sum(cid == b['incident_id'] for _, cid in pairs) > 1 for b in matches)
        if ambiguous:
            used.update(b['incident_id'] for b in matches)
            rows.append({'status': 'ambiguous', 'parent_incident_id': a['incident_id'],
                'possible_child_ids': [b['incident_id'] for b in matches],
                'reason': 'Multiple overlapping evidence correspondences; no forced match'})
            continue
        b = matches[0] if matches else None
        if b:
            used.add(b['incident_id'])
        stages_a = {s['stage_id'] for s in a['stages']}
        stages_b = {s['stage_id'] for s in b['stages']} if b else set()
        rows.append({'status': 'matched' if b else 'lost', 'parent_incident_id': a['incident_id'],
            'child_incident_id': b['incident_id'] if b else None,
            'supported_stages': sorted(stages_b), 'lost_stages': sorted(stages_a - stages_b),
            'new_stages': sorted(stages_b - stages_a),
            'surviving_evidence': sorted(set(a['selected_evidence']) & set(b['selected_evidence'])) if b else [],
            'removed_support': sorted(set(a['selected_evidence']) - set(b['selected_evidence'] if b else [])),
            'new_support': sorted(set(b['selected_evidence']) - set(a['selected_evidence'])) if b else [],
            'before': a, 'after': b,
            'graph_before': graph_for(store, parent, a),
            'graph_after': graph_for(store, child, b) if b else None})
    rows.extend({'status': 'new', 'parent_incident_id': None, 'child_incident_id': b['incident_id'],
        'after': b, 'graph_after': graph_for(store, child, b)} for b in after if b['incident_id'] not in used)
    return rows


def manifest(parent, child, excluded):
    return {'version': 'analysis-view-v1', 'branch_kind': 'evidence_sensitivity',
        'parent_run_id': parent['analysis_run_id'], 'child_run_id': child['analysis_run_id'],
        'dataset_id': parent['dataset_id'], 'parent_fingerprint': parent['dataset_fingerprint'],
        'parent_event_ids': parent['event_ids'], 'effective_event_ids': child['event_ids'],
        'effective_fingerprint': child['dataset_fingerprint'], 'cutoff': parent['cutoff'],
        'excluded_event_ids': sorted(set(excluded)), 'baseline_id': parent['baseline_id'],
        'artifact_identity': digest(json_bytes(parent.get('baseline_snapshot'))),
        'policy_identity': parent['view_snapshot']['policy_identity'],
        'context_identity': digest(json_bytes({k: parent.get(k) for k in (
            'config', 'resource_context_snapshot', 'alias_context_snapshot', 'authorization_context_snapshot')})),
        'source_reference_identity': digest(json_bytes(parent['view_snapshot']['source_references']))}


def create_sensitivity(store, parent_id, excluded, note=''):
    if not isinstance(excluded, list) or len(excluded) > 100 or any(not isinstance(e, str) or not e or len(e) > 200 for e in excluded):
        raise ValueError('Select at most 100 canonical event IDs (1–200 characters each)')
    if not isinstance(note, str) or len(note) > 500:
        raise ValueError('Analyst note is limited to 500 characters')
    start = perf_counter()
    parent = store.analysis(parent_id)
    before = store.incidents(parent_id)
    # No-op reproduction also validates that stored parent claims are supported by this implementation.
    noop, original = AnalysisView(store, parent).rerun()
    if findings(noop) != findings(parent) or semantic([c.model_dump(mode='json') for c in original]) != semantic(before):
        raise ValueError('Parent semantic reproduction failed; use an ordinary new analysis')
    child, candidates = AnalysisView(store, parent, excluded).rerun()
    cid = uuid4().hex
    child.update(branch_kind='evidence_sensitivity', parent_run_id=parent_id, comparison_id=cid)
    after = sorted([c.model_dump(mode='json') for c in candidates], key=lambda item: item['incident_id'])
    comparison = {'report_version': VERSION, 'comparison_id': cid,
        'manifest': manifest(parent, child, excluded), 'analyst_note': note,
        'created_at_utc': datetime.now(timezone.utc).isoformat(), 'duration_seconds': perf_counter() - start,
        'before_candidates': before, 'after_candidates': after,
        'differences': differences(store, parent, child, before, after),
        'empty_result': not after, 'validation': {'valid': True, 'scope': 'frozen parent no-op and real excluded detector rerun'},
        'limitations': ['Evidence availability experiment; not causality, prevention, safe endpoint status or remediation',
            'Fitted training/calibration remain fixed; no retraining or machine unlearning',
            'Raw records and private source text omitted; local retained originals are verification authority',
            'Hashes establish retained consistency, not source authenticity']}
    with store.connection() as conn:
        store.save_analysis(child, candidates, connection=conn)
        conn.execute('INSERT INTO sensitivities VALUES(?,?,?,?)', (cid, parent_id, child['analysis_run_id'], json.dumps(comparison)))
    return comparison


def retained_comparison(store, cid):
    with store.connection() as conn:
        row = conn.execute('SELECT body FROM sensitivities WHERE id=?', (cid,)).fetchone()
    if not row:
        raise KeyError('Sensitivity comparison not found')
    return json.loads(row[0])


def verify_comparison(store, submitted):
    errors = []
    try:
        if not isinstance(submitted, dict) or submitted.get('report_version') != VERSION:
            raise ValueError('Unsupported sensitivity comparison')
        retained = retained_comparison(store, submitted['comparison_id'])
        if submitted != retained:
            raise ValueError('Submitted sensitivity lineage/claims/differences differ from retained comparison')
        m = retained['manifest']
        parent, child = store.analysis(m['parent_run_id']), store.analysis(m['child_run_id'])
        if child.get('parent_run_id') != parent['analysis_run_id'] or child.get('comparison_id') != retained['comparison_id'] or child.get('branch_kind') != 'evidence_sensitivity':
            raise ValueError('Child lineage mismatch')
        if manifest(parent, child, m['excluded_event_ids']) != m:
            raise ValueError('Immutable view manifest differs')
        before, after = store.incidents(parent['analysis_run_id']), store.incidents(child['analysis_run_id'])
        for run, items, exclusions in ((parent, before, []), (child, after, m['excluded_event_ids'])):
            expected_run, candidates = AnalysisView(store, parent, exclusions).rerun()
            if findings(expected_run) != findings(run) or semantic([c.model_dump(mode='json') for c in candidates]) != semantic(items):
                raise ValueError('Recomputed observations/windows/scores/claims differ from retained run')
        if before != retained['before_candidates'] or after != retained['after_candidates'] or differences(store, parent, child, before, after) != retained['differences'] or retained['empty_result'] != (not after):
            raise ValueError('Displayed sensitivity differences differ from retained claims')
    except (KeyError, ValueError, TypeError) as exc:
        errors.append(str(exc))
    return {'valid': not errors, 'errors': errors, 'checked_at_utc': datetime.now(timezone.utc).isoformat()}


def export_comparison(store, cid):
    result = retained_comparison(store, cid)
    validation = verify_comparison(store, result)
    if not validation['valid']:
        raise ValueError('Sensitivity verification failed: ' + str(validation['errors']))
    return copy.deepcopy(result)
