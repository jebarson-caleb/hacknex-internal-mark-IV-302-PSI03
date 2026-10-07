"""Retrospective cutoff views. No fitting, evaluation inputs, or mutable context."""
import copy
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
from time import perf_counter

from .features import window_start
from .hybrid import run_analysis
from .ingest import digest, json_bytes
from .sensitivity import findings, semantic
from .views import AnalysisView, fingerprint

VERSION = 'retrospective-event-time-v1'
MAX_FRAMES = 200


def instant(value):
    try:
        stamp = datetime.fromisoformat(value) if isinstance(value, str) else value
        if not isinstance(stamp, datetime) or stamp.tzinfo is None or stamp.utcoffset() is None:
            raise ValueError()
        return stamp.astimezone(timezone.utc)
    except (ValueError, TypeError, OverflowError):
        raise ValueError('Replay cutoff requires a valid explicit timezone-bearing timestamp') from None


def replay_range(store, parent):
    events = store.events_by_ids(parent['event_ids'])
    end = instant(parent['cutoff'])
    start = min((e.event_time_utc for e in events), default=end) - timedelta(microseconds=1)
    return start, end


class ReplayView(AnalysisView):
    def __init__(self, store, parent, cutoff):
        super().__init__(store, parent)  # Preserve all historical compatibility and integrity checks.
        self.cutoff = instant(cutoff)
        start, end = replay_range(store, parent)
        if not start <= self.cutoff <= end:
            raise ValueError(f'Replay cutoff outside parent range {start.isoformat()} through {end.isoformat()}')
        metadata = parent.get('baseline_snapshot')
        if metadata:
            for kind in ('training', 'calibration'):
                try:
                    declared_start = instant(metadata[kind + '_start'])
                    declared_end = instant(metadata[kind + '_end'])
                    ids = metadata[kind + '_event_ids']
                    events = store.events_by_ids(ids)
                    if not events or len(events) != len(ids) or declared_start > min(e.event_time_utc for e in events):
                        raise ValueError('missing/inconsistent observations')
                    if declared_end < max(e.event_time_utc for e in events) or declared_start > declared_end:
                        raise ValueError('inconsistent interval')
                    if declared_end >= start or any(e.event_time_utc >= start for e in events):
                        raise ValueError('training/calibration must precede the entire replay interval')
                    if fingerprint(events) != metadata[kind + '_fingerprint']:
                        raise ValueError('fitted observation fingerprint differs')
                    errors = store.provenance_batch(events)
                    if any(errors.values()):
                        raise ValueError('fitted source integrity failed')
                except (KeyError, TypeError, ValueError) as exc:
                    raise ValueError(f'Unsupported replay {kind} interval: {exc}; create a compatible ordinary analysis') from exc
        self.active = [e for e in self.active if e.event_time_utc <= self.cutoff]

    def quality(self, dataset_id):
        self.events(dataset_id)
        if self.cutoff == instant(self.parent['cutoff']):
            return super().quality(dataset_id)
        # Parent-wide quality is retrospective metadata, never an early-frame finding.
        return {'accepted': len(self.active), 'rejected': 0, 'duplicates': 0, 'unsupported': 0,
                'errors': [], 'warnings': [], 'files': [], 'timezone_assumptions': []}

    def save_analysis(self, run, candidates):
        super().save_analysis(run, candidates)
        allowed = set(run['event_ids']) | set(run.get('history_event_ids', []))
        refs = {eid: refs for eid, refs in self.parent['view_snapshot']['source_references'].items() if eid in allowed}
        run['view_snapshot']['source_references'] = refs
        run['evidence_reference_snapshot'] = copy.deepcopy(refs)

    def rerun(self):
        run_analysis(self, self.parent['dataset_id'], mode=self.parent['mode'],
                     baseline_id=self.parent['baseline_id'], cutoff=self.cutoff)
        run, candidates = self.captured
        for key in ('config', 'rule_version', 'calibration', 'context_policy_version'):
            if run.get(key) != self.parent.get(key):
                raise ValueError('Unsupported frozen parent configuration: ' + key)
        return run, candidates


def core(run):
    result = {k: v for k, v in findings(run).items() if k != 'replay_manifest'}
    # Equal instants with different UTC offset spellings are the same semantic cutoff.
    result['cutoff'] = instant(result['cutoff']).isoformat()
    return result


def manifest(parent, child):
    return {'version': VERSION, 'branch_kind': 'retrospective_replay',
        'parent_run_id': parent['analysis_run_id'], 'frame_run_id': child['analysis_run_id'],
        'dataset_id': parent['dataset_id'], 'parent_cutoff': parent['cutoff'],
        'requested_cutoff': child['cutoff'], 'effective_cutoff': child['cutoff'],
        'parent_event_ids': parent['event_ids'], 'parent_fingerprint': parent['dataset_fingerprint'],
        'effective_event_ids': child['event_ids'], 'effective_fingerprint': child['dataset_fingerprint'],
        'mode': parent['mode'], 'baseline_id': parent['baseline_id'],
        'artifact_identity': digest(json_bytes(parent.get('baseline_snapshot'))),
        'policy_identity': parent['view_snapshot']['policy_identity'],
        'replay_implementation': digest(Path(__file__).read_bytes()),
        'context_identity': digest(json_bytes({k: parent.get(k) for k in (
            'config', 'resource_context_snapshot', 'alias_context_snapshot', 'authorization_context_snapshot')})),
        'source_reference_identity': digest(json_bytes(child['evidence_reference_snapshot']))}


def table(store):
    with store.connection() as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS replay_frames (id TEXT PRIMARY KEY, parent_id TEXT NOT NULL, cutoff TEXT NOT NULL, body TEXT NOT NULL, UNIQUE(parent_id,cutoff))')


def create_frame(store, parent_id, cutoff):
    started = perf_counter()
    parent = store.analysis(parent_id)
    view = ReplayView(store, parent, cutoff)
    # Independently reproduce the parent's supported findings before deriving any frame.
    noop, candidates = AnalysisView(store, parent).rerun()
    if findings(noop) != findings(parent) or semantic([c.model_dump(mode='json') for c in candidates]) != semantic(store.incidents(parent_id)):
        raise ValueError('Parent semantic reproduction failed; create an ordinary new analysis')
    table(store)
    with store.connection() as conn:
        existing = conn.execute('SELECT id FROM replay_frames WHERE parent_id=? AND cutoff=?',
                                (parent_id, view.cutoff.isoformat())).fetchone()
    if existing:
        return get_frame(store, existing[0])
    run, candidates = view.rerun()
    if view.cutoff == instant(parent['cutoff']) and (core(run) != core(noop) or
            semantic([c.model_dump(mode='json') for c in candidates]) != semantic(store.incidents(parent_id))):
        raise ValueError('Final replay semantic reproduction failed')
    run.update(branch_kind='retrospective_replay', parent_run_id=parent_id)
    run['replay_manifest'] = manifest(parent, run)
    frame = {'manifest': run['replay_manifest'], 'created_at_utc': datetime.now(timezone.utc).isoformat(),
        'duration_seconds': perf_counter() - started, 'validation': {'valid': True,
        'scope': 'parent integrity/no-op and cutoff-bound real detector'}, 'empty_result': not candidates}
    with store.connection() as conn:
        conn.execute('BEGIN IMMEDIATE')
        existing = conn.execute('SELECT id FROM replay_frames WHERE parent_id=? AND cutoff=?',
                                (parent_id, run['cutoff'])).fetchone()
        if existing:
            # A concurrent identical request completed while inference was running.
            return get_frame(store, existing[0])
        if conn.execute('SELECT COUNT(*) FROM replay_frames WHERE parent_id=?', (parent_id,)).fetchone()[0] >= MAX_FRAMES:
            raise ValueError('Replay limit: 200 retained distinct frames per parent; reopen an existing cutoff (nothing deleted)')
        store.save_analysis(run, candidates, connection=conn)
        conn.execute('INSERT INTO replay_frames VALUES(?,?,?,?)', (run['analysis_run_id'], parent_id, run['cutoff'], json.dumps(frame)))
    return {**frame, 'run': run}


def verify_frame(store, frame_id):
    table(store)
    with store.connection() as conn:
        row = conn.execute('SELECT parent_id,cutoff,body FROM replay_frames WHERE id=?', (frame_id,)).fetchone()
    if not row:
        raise KeyError('Replay frame not found')
    retained = json.loads(row[2])
    parent, run = store.analysis(row[0]), store.analysis(frame_id)
    view = ReplayView(store, parent, row[1])
    expected, candidates = view.rerun()
    if (run.get('branch_kind') != 'retrospective_replay' or run.get('parent_run_id') != row[0]
            or manifest(parent, run) != retained['manifest'] or run.get('replay_manifest') != retained['manifest']
            or core(run) != core(expected) or run['view_snapshot'] != expected['view_snapshot']
            or run['evidence_reference_snapshot'] != expected['evidence_reference_snapshot']
            or semantic(store.incidents(frame_id)) != semantic([c.model_dump(mode='json') for c in candidates])
            or retained['empty_result'] != (not candidates)):
        raise ValueError('Replay frame lineage/membership/cutoff/source/model/claims differ from recomputed view')
    return retained


def get_frame(store, frame_id):
    return {**verify_frame(store, frame_id), 'run': store.analysis(frame_id)}


def guard_run(store, run):
    marked = run.get('branch_kind') == 'retrospective_replay' or 'replay_manifest' in run
    # Stored lineage is authoritative even if a tampered run removes both labels.
    with store.connection() as conn:
        exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='replay_frames'").fetchone()
        retained = exists and conn.execute('SELECT 1 FROM replay_frames WHERE id=?', (run['analysis_run_id'],)).fetchone()
    if marked or retained:
        verify_frame(store, run['analysis_run_id'])


def navigation(store, parent_id):
    parent = store.analysis(parent_id)
    AnalysisView(store, parent)
    start, end = replay_range(store, parent)
    ReplayView(store, parent, start)  # Unsupported history fails before offering controls.
    stops = {start, end}
    for event in store.events_by_ids(parent['event_ids']):
        stops.add(event.event_time_utc)
        closure = window_start(event.event_time_utc) + timedelta(minutes=15)
        if closure <= end:
            stops.add(closure)
    table(store)
    with store.connection() as conn:
        frames = [dict(row) for row in conn.execute('SELECT id,cutoff FROM replay_frames WHERE parent_id=? ORDER BY cutoff', (parent_id,))]
    return {'parent_run_id': parent_id, 'start': start.isoformat(), 'end': end.isoformat(),
            'stops': [t.isoformat() for t in sorted(stops)], 'frames': frames, 'max_frames': MAX_FRAMES,
            'scope': 'Retrospective parent overview; markers are not current detector observations'}
