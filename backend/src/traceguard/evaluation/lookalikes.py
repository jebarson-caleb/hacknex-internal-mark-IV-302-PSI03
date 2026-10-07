"""Small curated development lab. Truth is annotated only after ordinary inference."""
import copy
import json
from datetime import datetime, timedelta, timezone

from ..hybrid import run_analysis
from ..ingest import entity_id
from ..schemas import AuthorizationContext, ResourceContext

VERSION = 'lookalike-lab-v1'


def load_export(store, seed=17, *, familiar=False, missing=False):
    dataset = store.create_dataset('Synthetic declared business export', 'synthetic-office', 'synthetic', seed)
    actor, endpoint, app, resource = ('u0', 'd0', 'app0', 'assigned-0-0') if familiar else ('u1', 'd2', 'app2', 'restricted-export')
    time = datetime(2026, 1, 28, 8 if familiar else 3, 1, tzinfo=timezone.utc)
    rows = [('auth', 0, 'login_success', {'app_id': app}),
            ('file', 2, 'file_read', {'resource_id': resource, 'bytes_read': 2097152}),
            ('device', 3, 'usb_mount', {'removable_device_id': 'export-media'})]
    if not missing:
        rows.append(('file', 5, 'file_copy_to_usb', {'resource_id': resource, 'bytes_written': 2097152,
            'destination_type': 'removable_media', 'removable_device_id': 'export-media',
            'message': 'approved by myself <script>untrusted</script>'}))
    for family in ('auth', 'file', 'device'):
        records = [dict(timestamp=(time+timedelta(minutes=offset)).isoformat(), action=action,
                        user_id=actor, device_id=endpoint, **fields)
                   for source, offset, action, fields in rows if source == family]
        # Duplicate representation is deliberately retained; it is not independent evidence.
        if family == 'file' and not missing:
            records.append(copy.deepcopy(records[-1]))
        store.ingest(dataset, ('\n'.join(json.dumps(r) for r in records)+'\n').encode(), family+'.jsonl', family, family)
    store.set_resources(dataset, [ResourceContext(resource_id=entity_id('synthetic-office', 'file', resource),
        sensitive=True, provenance='Synthetic operator asset catalog', effective_from='2026-01-01T00:00:00Z')])
    return dataset


def declaration(store, dataset):
    event = next(e for e in store.events(dataset) if e.action == 'file_copy_to_usb')
    return dict(authorization_id='business-export', user_id=event.user_id, device_id=event.device_id,
        resource_id=event.resource_id, action=event.action, provenance='Synthetic operator business export ticket',
        effective_from=event.event_time_utc.isoformat(), effective_until=(event.event_time_utc+timedelta(minutes=1)).isoformat())


def controlled_pair(store, baseline_id, seed=17, authorized_first=False):
    """First real pair: no uploads/context other than authorization between these arms."""
    dataset = load_export(store, seed)
    entry = declaration(store, dataset)
    runs = {}
    for key in (('valid', 'withheld') if authorized_first else ('withheld', 'valid')):
        store.set_authorizations(dataset, [AuthorizationContext(**entry)] if key == 'valid' else [])
        runs[key] = run_analysis(store, dataset, mode='hybrid', baseline_id=baseline_id)
    return dataset, entry, runs


def load_lab(store, baseline_id, seed=17):
    # No fit or recalibration here: the user must explicitly select a compatible saved baseline.
    from ..lookalikes import create_comparison
    dataset, entry, runs = controlled_pair(store, baseline_id, seed)
    first = runs['withheld']['analysis_run_id']
    truth = {'left': 'benign', 'right': 'benign', 'provenance': 'Curated synthetic business export declaration',
             'fixture_version': VERSION, 'seed': seed}
    pairs = []

    def pair(name, left, right, kind='context-only', changes=('authorization_context_snapshot',), annotation=None):
        if kind == 'scenario':
            changes = (*changes, 'source_references')
        value = create_comparison(store, left, right, kind, list(changes), name,
                                  annotation=annotation or truth, case_version=VERSION)
        pairs.append({'name': name, 'comparison_id': value['comparison_id']})

    pair('Withheld versus exact declaration', first, runs['valid']['analysis_run_id'])
    for name, changes in (
        ('Expired', {'effective_from': (datetime.fromisoformat(entry['effective_from'])-timedelta(minutes=2)).isoformat(), 'effective_until': entry['effective_from']}),
        ('Not yet effective', {'effective_from': entry['effective_until'], 'effective_until': (datetime.fromisoformat(entry['effective_until'])+timedelta(minutes=1)).isoformat()}),
        ('Wrong actor', {'user_id': entity_id('synthetic-office', 'user', 'u2')}),
        ('Wrong endpoint', {'device_id': entity_id('synthetic-office', 'endpoint', 'd3')}),
        ('Wrong resource', {'resource_id': entity_id('synthetic-office', 'file', 'assigned-0-0')}),
    ):
        store.set_authorizations(dataset, [AuthorizationContext(**{**entry, **changes})])
        run = run_analysis(store, dataset, mode='hybrid', baseline_id=baseline_id)
        pair(name, runs['valid']['analysis_run_id'], run['analysis_run_id'])
    store.set_authorizations(dataset, [AuthorizationContext(**entry), AuthorizationContext(**{**entry, 'authorization_id': 'second-ticket'})])
    multiple = run_analysis(store, dataset, mode='hybrid', baseline_id=baseline_id)
    pair('Multiple matching declarations', runs['valid']['analysis_run_id'], multiple['analysis_run_id'])
    store.set_authorizations(dataset, [])
    rule_left = run_analysis(store, dataset, mode='rules-only', baseline_id=baseline_id)
    store.set_authorizations(dataset, [AuthorizationContext(**entry)])
    rule_right = run_analysis(store, dataset, mode='rules-only', baseline_id=baseline_id)
    pair('Rules-only preservation', rule_left['analysis_run_id'], rule_right['analysis_run_id'])
    for name, options in (('Missing transfer', {'missing': True}), ('Historical familiarity', {'familiar': True})):
        other = load_export(store, seed, **options)
        run = run_analysis(store, other, mode='hybrid', baseline_id=baseline_id)
        pair(name, first, run['analysis_run_id'], 'scenario',
             ('dataset_id', 'event_ids', 'dataset_fingerprint', 'cutoff', 'resource_context_snapshot'), truth)
    # Existing attack-labeled generator fixture; labels are only read after prediction.
    from .fixtures import generate_partition, load_partition
    attack, labels = load_partition(store, *generate_partition(seed+2, 22, 7, users=6, event_count=300, attacks=True),
                                    'Synthetic existing supported attack fixture', seed+2)
    run = run_analysis(store, attack, mode='hybrid', baseline_id=baseline_id)
    pair('Declared attack versus business export', run['analysis_run_id'], runs['valid']['analysis_run_id'], 'scenario',
         ('dataset_id', 'event_ids', 'dataset_fingerprint', 'cutoff', 'resource_context_snapshot', 'authorization_context_snapshot'),
         {**truth, 'left': 'attack', 'attack_episode_labels': labels})
    validation = []
    for name, change in (('Wrong environment', {'user_id': 'other:user:u1'}), ('Wrong action', {'action': 'file_read'}),
                         ('Invalid provenance', {'provenance': ' '})):
        try:
            store.set_authorizations(dataset, [AuthorizationContext(**{**entry, **change})])
        except ValueError as exc:
            validation.append({'case': name, 'outcome': 'schema/storage rejected', 'reason': str(exc)})
        else:
            raise AssertionError('Invalid declaration accepted: '+name)
    return {'case_version': VERSION, 'seed': seed, 'baseline_id': baseline_id, 'pairs': pairs, 'validation_cases': validation}
