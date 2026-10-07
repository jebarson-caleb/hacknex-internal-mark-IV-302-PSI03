"""Frozen ordinary-run comparisons. No inference truth, fitting, or context overrides."""
import json
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from .detection import HistoryIndex, auth_comparison, collection_comparison
from .ingest import digest, json_bytes
from .resolution import resolve_events
from .sensitivity import findings, semantic
from .views import AnalysisView

VERSION = 'lookalike-comparison-v1'
INPUTS = ('dataset_id', 'event_ids', 'dataset_fingerprint', 'cutoff', 'mode', 'baseline_id',
          'baseline_snapshot', 'history_event_ids', 'config', 'rule_version', 'calibration',
          'context_policy_version', 'resource_context_snapshot', 'alias_context_snapshot',
          'authorization_context_snapshot')


def identity(run):
    return {**{key: digest(json_bytes(run.get(key))) for key in INPUTS},
            'policy_identity': digest(json_bytes(run['view_snapshot']['policy_identity'])),
            'source_references': digest(json_bytes(run['view_snapshot']['source_references']))}


def validate_run(store, run):
    reproduced, candidates = AnalysisView(store, run).rerun()
    if findings(reproduced) != findings(run) or semantic([c.model_dump(mode='json') for c in candidates]) != semantic(store.incidents(run['analysis_run_id'])):
        raise ValueError('Frozen run reproduction failed; create an ordinary new analysis')


def upstream(items):
    # Authorization policy is downstream of observations, stage eligibility and linkage.
    return sorted([{'user_id': i['user_id'], 'device_id': i['device_id'], 'stages': i['stages'],
                    'selected_evidence': i['selected_evidence'], 'context_event_ids': i['context_event_ids'],
                    'entity_resolution': i['entity_resolution'],
                    'risk': {k: v for k, v in i['risk'].items() if k not in
                             ('score', 'components', 'weighted_terms')},
                    'components': {k: v for k, v in i['risk'].get('components', {}).items() if k != 'B'},
                    'weighted_terms': {k: v for k, v in i['risk'].get('weighted_terms', {}).items() if k != 'benign_reduction'}}
                   for i in items], key=lambda item: json.dumps(item, sort_keys=True))


def correspondence(left, right):
    def related(a, b):
        return ((a['user_id'], a['device_id'], a['stages'][0]['rule_id']) ==
                (b['user_id'], b['device_id'], b['stages'][0]['rule_id']) and
                max(a['stages'][0]['start_time_utc'], b['stages'][0]['start_time_utc']) <=
                min(a['stages'][-1]['end_time_utc'], b['stages'][-1]['end_time_utc']) and
                bool(set(a['selected_evidence']) & set(b['selected_evidence'])))
    by_subject = {}
    for b in right:
        key = (b['user_id'], b['device_id'], b['stages'][0]['rule_id'])
        by_subject.setdefault(key, []).append(b)
    edges = [(a['incident_id'], b['incident_id']) for a in left
             for b in by_subject.get((a['user_id'], a['device_id'], a['stages'][0]['rule_id']), []) if related(a, b)]
    rows = []
    for a in left:
        matches = [b for b in right if (a['incident_id'], b['incident_id']) in edges]
        b = matches[0] if len(matches) == 1 and sum(y == matches[0]['incident_id'] for _, y in edges) == 1 else None
        rows.append({'left_incident_id': a['incident_id'], 'right_incident_id': b['incident_id'] if b else None,
            'possible_right_ids': [m['incident_id'] for m in matches],
            'status': 'matched' if b else 'ambiguous' if matches else 'unmatched',
            'risk_delta': b['risk']['score']-a['risk']['score'] if b else None,
            'decision_changed': a['decision'] != b['decision'] if b else None,
            'explanation': ('Supporting observations and historical/model signals are unchanged. '
                'The applied context reduction changed; the decision '+('changed.' if a['decision'] != b['decision'] else 'stayed unchanged.'))
                if b and a['stages'] == b['stages'] and a['risk'].get('anomaly_percentile') == b['risk'].get('anomaly_percentile')
                and a['risk'].get('components', {}).get('B') != b['risk'].get('components', {}).get('B')
                else 'Retained outcomes are shown without attributing a difference to a single cause.'})
    rows.extend({'left_incident_id': None, 'right_incident_id': b['incident_id'], 'status': 'unmatched',
                 'risk_delta': None, 'decision_changed': None} for b in right if not any(y == b['incident_id'] for _, y in edges))
    return rows


def create_comparison(store, left_id, right_id, kind='context-only', declared_changes=None, note='', *, annotation=None, case_version=None):
    if kind not in ('context-only', 'scenario') or len(note) > 500:
        raise ValueError('Choose context-only or scenario; note maximum 500 characters')
    declared_changes = declared_changes or []
    if len(declared_changes) > 20 or any(k not in (*INPUTS, 'source_references', 'policy_identity') for k in declared_changes):
        raise ValueError('Unknown or excessive declared changed inputs')
    left, right = store.analysis(left_id), store.analysis(right_id)
    for run in (left, right):
        validate_run(store, run)
    identities = [identity(r) for r in (left, right)]
    changed = [k for k in identities[0] if identities[0][k] != identities[1][k]]
    before, after = store.incidents(left_id), store.incidents(right_id)
    upstream_equal = upstream(before) == upstream(after) and left.get('window_scores') == right.get('window_scores')
    if kind == 'context-only' and (set(changed)-{'authorization_context_snapshot'} or not upstream_equal):
        raise ValueError('Incompatible controlled comparison: '+', '.join(changed)+'; observations, sources, cutoff, policy, artifacts and non-authorization context must match. Select compatible ordinary runs or explicitly choose scenario.')
    if set(changed)-set(declared_changes):
        raise ValueError('Undeclared changed inputs: '+', '.join(sorted(set(changed)-set(declared_changes))))
    record = {'comparison_id': uuid4().hex, 'version': VERSION, 'kind': kind,
        'left_run_id': left_id, 'right_run_id': right_id, 'created_at_utc': datetime.now(timezone.utc).isoformat(),
        'case_version': case_version, 'analyst_note': note, 'declared_changed_inputs': declared_changes,
        'actual_changed_inputs': changed, 'frozen_identities': identities,
        'compatibility': {'controlled_inputs_equal_except_authorization': not bool(set(changed)-{'authorization_context_snapshot'}),
                          'upstream_equal': upstream_equal, 'ordinary_runs_reproduced': True},
        'correspondence': correspondence(before, after)}
    with store.connection() as conn:
        conn.execute('INSERT INTO lookalikes VALUES(?,?,?,?)', (record['comparison_id'], left_id, right_id, json.dumps(record)))
        if annotation is not None:
            conn.execute('INSERT INTO lookalike_annotations VALUES(?,?)', (record['comparison_id'], json.dumps(annotation)))
    return retained_comparison(store, record['comparison_id'])


def arm(store, run_id):
    run = store.analysis(run_id)
    result = {k: run.get(k) for k in ('analysis_run_id', 'dataset_id', 'origin', 'mode', 'cutoff', 'baseline_id',
              'dataset_fingerprint', 'config', 'calibration', 'authorization_context_snapshot', 'warnings',
              'event_count', 'incident_count', 'review_count', 'partial_count')}
    # Reveal real eligibility even where correlation emits no candidate (familiar/cold start).
    events, _, _ = resolve_events(store.events_by_ids(run['event_ids']), run.get('alias_context_snapshot', []))
    result['observations'] = [{k: e.model_dump(mode='json')[k] for k in
        ('event_id', 'event_time_utc', 'action', 'user_id', 'device_id', 'app_id', 'resource_id',
         'removable_device_id', 'bytes_read', 'bytes_written', 'source_id', 'source_file_sha256')} for e in events[:20]]
    metadata = run.get('baseline_snapshot')
    history, _, _ = resolve_events(store.events_by_ids(run.get('history_event_ids', [])), metadata['alias_snapshot']) if metadata else (events, [], [])
    index = HistoryIndex(history, run['baseline_id'] or 'prior-UTC-days-v1')
    result['history_probes'] = []
    for login in [e for e in events if e.action == 'login_success'][:20]:
        reads = [e for e in events if e.action == 'file_read' and (e.user_id, e.device_id) == (login.user_id, login.device_id)
                 and login.event_time_utc < e.event_time_utc <= login.event_time_utc+timedelta(minutes=60)]
        result['history_probes'].append({'event_id': login.event_id, 'user_id': login.user_id, 'device_id': login.device_id,
            'authentication': auth_comparison(index, login),
            'collection': collection_comparison(index, login, reads[0]) if reads else None})
    result['window_scores'] = run.get('window_scores', [])[:20]
    result['signal_display_limit'] = 'First 20 observations, login probes and windows; complete findings via retained run'
    return result


def retained_comparison(store, cid, cursor=0, limit=20):
    if cursor < 0 or not 1 <= limit <= 100:
        raise ValueError('Invalid pagination')
    with store.connection() as conn:
        row = conn.execute('SELECT body FROM lookalikes WHERE id=?', (cid,)).fetchone()
        annotation = conn.execute('SELECT body FROM lookalike_annotations WHERE id=?', (cid,)).fetchone()
    if not row:
        raise KeyError('Look-alike comparison not found')
    record = json.loads(row[0])
    runs = [store.analysis(record[k]) for k in ('left_run_id', 'right_run_id')]
    if [identity(r) for r in runs] != record['frozen_identities']:
        raise ValueError('Saved run identities changed; comparison is unavailable')
    rows = record.pop('correspondence')
    return {**record, 'left': arm(store, record['left_run_id']), 'right': arm(store, record['right_run_id']),
            'correspondence': rows[cursor:cursor+limit], 'total': len(rows),
            'next_cursor': cursor+limit if cursor+limit < len(rows) else None,
            'evaluation_annotation': json.loads(annotation[0]) if annotation else None,
            'limits': 'Missing authorization does not prove intent. Operator declarations are not independently authenticated. Curated truth is outside inference; no accuracy percentage.'}
