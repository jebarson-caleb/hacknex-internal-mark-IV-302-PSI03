"""Frozen inference input adapter; calls the ordinary detector without fitting or writes."""
import copy
from datetime import datetime
from pathlib import Path
from importlib.metadata import version

from .ingest import digest, event_content, json_bytes


def policy_identity():
    # Fail closed when the historical implementation is unavailable, including constants.
    names = ('detection', 'hybrid', 'features', 'risk', 'context', 'resolution',
             'graph', 'baseline', 'ingest', 'schemas', 'views')
    return {**{name: digest(Path(__file__).with_name(name + '.py').read_bytes()) for name in names},
            'libraries': {name: version(name) for name in ('scikit-learn', 'numpy', 'networkx', 'pydantic')}}


def fingerprint(events):
    return digest(json_bytes([event_content(e) for e in events]))


def freeze_run(store, run):
    if 'view_snapshot' in run:
        return
    ids = sorted(set(run['event_ids']) | set(run.get('history_event_ids', [])))
    with store.connection() as conn:
        refs = {eid: [r[0] for r in conn.execute(
            'SELECT ref FROM records WHERE event_id=? ORDER BY ref', (eid,))] for eid in ids}
    run['branch_kind'] = 'ordinary'
    run['view_snapshot'] = {'version': 'analysis-view-v1', 'policy_identity': policy_identity(),
        'dataset': store.dataset(run['dataset_id']), 'quality': store.quality(run['dataset_id']),
        'source_references': refs}


class AnalysisView:
    """Read-only store projection with a single captured, unsaved detector result."""
    def __init__(self, store, parent, excluded=()):
        snapshot = parent.get('view_snapshot')
        if not snapshot or snapshot.get('policy_identity') != policy_identity():
            raise ValueError('Unsupported parent: frozen view/current policy unavailable or incompatible; create an ordinary new analysis')
        if parent.get('branch_kind') != 'ordinary':
            raise ValueError('Nested sensitivity is unsupported; select an ordinary parent')
        if len(parent['event_ids']) > 50000 or len(set(parent['event_ids'])) != len(parent['event_ids']):
            raise ValueError('Invalid or excessive parent membership')
        self.store, self.parent = store, parent
        self.excluded = sorted(set(excluded))
        if not set(self.excluded) <= set(parent['event_ids']):
            raise ValueError('Excluded canonical IDs must belong to the frozen parent inference membership')
        metadata = parent.get('baseline_snapshot')
        if metadata:
            fitted_ids = set(metadata['training_event_ids']) | set(metadata.get('calibration_event_ids', []))
            if set(self.excluded) & fitted_ids:
                raise ValueError('Training/calibration observations cannot be excluded')
            current, blob = store.baseline(parent['baseline_id'])
            if current != metadata or digest(blob) != metadata.get('model_sha256'):
                raise ValueError('Frozen baseline metadata/model hash differs from retained artifact')
        raw = store.events_by_ids(parent['event_ids'])
        if fingerprint(raw) != parent['dataset_fingerprint']:
            raise ValueError('Parent observation fingerprint differs from retained material')
        cutoff = datetime.fromisoformat(parent['cutoff'])
        self.active = [e for e in raw if e.event_time_utc <= cutoff and e.event_id not in self.excluded]
        if len(raw) != len([e for e in raw if e.event_time_utc <= cutoff]):
            raise ValueError('Parent membership includes future observations')
        history = store.events_by_ids(parent.get('history_event_ids', []))
        if metadata and fingerprint(history) != metadata['training_fingerprint']:
            raise ValueError('Frozen training observation fingerprint differs')
        errors = store.provenance_batch(raw + history, snapshot['source_references'])
        if any(errors.values()):
            raise ValueError('Frozen source verification failed: ' + str({eid: e for eid, e in errors.items() if e}))
        self.captured = None

    def events(self, dataset_id):
        if dataset_id != self.parent['dataset_id']:
            raise ValueError('View dataset mismatch')
        return self.active

    def dataset(self, dataset_id):
        self.events(dataset_id)
        return copy.deepcopy(self.parent['view_snapshot']['dataset'])

    def quality(self, dataset_id):
        self.events(dataset_id)
        return copy.deepcopy(self.parent['view_snapshot']['quality'])

    def resources(self, _):
        return copy.deepcopy(self.parent['resource_context_snapshot'])

    def authorizations(self, _):
        return copy.deepcopy(self.parent['authorization_context_snapshot'])

    def aliases(self, _):
        return copy.deepcopy(self.parent.get('alias_context_snapshot', []))

    def baseline(self, baseline_id):
        if baseline_id != self.parent['baseline_id']:
            raise ValueError('View baseline mismatch')
        return self.store.baseline(baseline_id)

    def events_by_ids(self, ids):
        allowed = set(self.parent.get('history_event_ids', [])) | {e.event_id for e in self.active}
        if not set(ids) <= allowed:
            raise ValueError('Events outside active/fitted view')
        return self.store.events_by_ids(ids)

    def provenance_batch(self, events):
        return self.store.provenance_batch(events, self.parent['view_snapshot']['source_references'])

    def provenance_errors(self, event_id):
        return self.provenance_batch(self.store.events_by_ids([event_id]))[event_id]

    def save_analysis(self, run, candidates):
        # Capture only. Creation persists child and comparison in one transaction.
        run['view_snapshot'] = copy.deepcopy(self.parent['view_snapshot'])
        run['evidence_reference_snapshot'] = {eid: refs for eid, refs in
            self.parent['view_snapshot']['source_references'].items() if eid not in self.excluded}
        self.captured = (run, candidates)

    def rerun(self):
        from .hybrid import run_analysis
        run_analysis(self, self.parent['dataset_id'], mode=self.parent['mode'],
            baseline_id=self.parent['baseline_id'], cutoff=datetime.fromisoformat(self.parent['cutoff']))
        run, candidates = self.captured
        for key in ('config', 'rule_version', 'calibration', 'context_policy_version'):
            if run.get(key) != self.parent.get(key):
                raise ValueError('Unsupported frozen parent configuration: ' + key)
        return run, candidates
