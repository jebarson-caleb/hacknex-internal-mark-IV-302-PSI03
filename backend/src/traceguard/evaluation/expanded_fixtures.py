"""Phase 4D extensions to the chronological generator; truth never enters inference."""
import json
import random
from datetime import datetime, timedelta, timezone

from ..ingest import entity_id
from ..schemas import AliasContext, AuthorizationContext
from .fixtures import ENVIRONMENT, generate_partition, load_partition

VERSION = 'expanded-usb-v1'
BENIGN = ['exact', 'withheld', 'expired', 'future', 'wrong_scope', 'repeated', 'shared_ip', 'familiar']
NEGATIVES = ['mount_only', 'access_only', 'missing_copy', 'failed_copy', 'zero_bytes',
             'wrong_resource', 'wrong_device', 'ambiguous_identity', 'out_of_window']
ATTACKS = ['compact', 'spanning_windows', 'alias_corroborated', 'repeat_actor']


def scoped(kind, value):
    return entity_id(ENVIRONMENT, kind, value)


def aliases():
    values = [('alternate-u3', 'u3'), ('ambiguous-account', 'u1'), ('ambiguous-account', 'u2')]
    return [AliasContext(alias_user_id=scoped('user', a), canonical_user_id=scoped('user', c),
                        provenance='Synthetic operator identity directory', effective_from='2026-01-01T00:00:00Z')
            for a, c in values]


def generate_expanded(seed, role, users, requested):
    start, days = {'training': (1, 14), 'calibration': (15, 7), 'test': (22, 7)}[role]
    files, resources, _ = generate_partition(seed, start, days, users=users, event_count=requested)
    cases, declarations = [], []
    rng = random.Random(seed)
    if role == 'training':
        return files, resources, cases, declarations

    def episode(name, index, category, variant):
        # New schedules/resources/media/amounts, not copies of the 4B fixtures.
        actor = (index % (users-1))+1
        if category == 'supported_attack':
            actor = [1, 2, 3, 1][index]
        device = (actor+7) % 20
        day = start + index % 6
        hour = 1 + index // 6
        time = datetime(2026, 1, day, hour, rng.randrange(0, 4), tzinfo=timezone.utc)
        resource = f'restricted-{seed}-{role}-{index}'
        if variant == 'familiar':
            actor, device, resource = 0, 0, 'assigned-0-0'
            time = time.replace(hour=8)
        media = f'media-{seed}-{index}'
        amount = [524288, 2097152, 4194304, 1572864][index % 4] + rng.randrange(1, 4096)
        delays = (6, 11, 24) if variant == 'spanning_windows' else (2, 4, 7)
        if variant == 'out_of_window':
            delays = (2, 4, 75)
        refs, stage_refs, order = [], {}, []

        def add(family, offset, action, **fields):
            # Neutral source IDs carry no truth/case string.
            vendor = f'observation-{100000+index*20+len(refs)}'
            user = f'u{actor}'
            if variant == 'alias_corroborated' and action != 'login_success':
                user = 'alternate-u3'
            if variant == 'ambiguous_identity' and action != 'login_success':
                user = 'ambiguous-account'
            files[family].append(dict(source_event_id=vendor, timestamp=(time+timedelta(minutes=offset)).isoformat(),
                                      action=action, user_id=user, device_id=f'd{device}', **fields))
            refs.append(vendor)
            return vendor

        if variant != 'mount_only':
            stage_refs['authentication'] = add('auth', 0, 'login_success', app_id='app0' if variant == 'familiar' else 'export-app', src_ip='10.0.0.5')
            stage_refs['collection'] = add('file', delays[0], 'file_read', resource_id=resource, bytes_read=amount)
        if variant != 'access_only':
            mount = add('device', delays[1], 'usb_mount', removable_device_id=media)
        else:
            mount = None
        if variant not in ('mount_only', 'access_only', 'missing_copy'):
            fields = dict(resource_id=resource, removable_device_id=media, destination_type='removable_media', bytes_written=amount)
            if variant == 'failed_copy': fields['outcome'] = 'failure'
            if variant == 'zero_bytes': fields['bytes_written'] = 0
            if variant == 'wrong_resource': fields['resource_id'] = resource+'-other'
            if variant == 'wrong_device': fields['removable_device_id'] = media+'-other'
            stage_refs['transfer'] = add('file', delays[2], 'file_copy_to_usb', **fields)
            if variant == 'alias_corroborated':
                add('file', delays[2]+1, 'file_copy_to_usb', **fields)
        resources.append(dict(resource_id=scoped('file', resource), sensitive=True,
                              provenance='Synthetic operator asset catalog', effective_from='2026-01-01T00:00:00Z', effective_until=None))
        if variant in BENIGN and variant not in ('withheld', 'shared_ip', 'familiar'):
            copy_time = time+timedelta(minutes=delays[2])
            effective_from, effective_until = copy_time, copy_time+timedelta(minutes=2)
            if variant == 'expired': effective_from, effective_until = copy_time-timedelta(hours=1), copy_time
            if variant == 'future': effective_from, effective_until = copy_time+timedelta(minutes=1), copy_time+timedelta(minutes=3)
            item = dict(authorization_id=f'ticket-{index}', user_id=scoped('user', f'u{actor}'),
                        device_id=scoped('endpoint', f'd{device}'), resource_id=scoped('file', resource),
                        provenance='Synthetic operator export ticket; legitimate truth retained even if unavailable/nonmatching',
                        effective_from=effective_from.isoformat(), effective_until=effective_until.isoformat())
            if variant == 'wrong_scope': item['resource_id'] = scoped('file', resource+'-other')
            declarations.append(item)
            if variant == 'repeated': declarations.append({**item, 'authorization_id': f'ticket-repeat-{index}'})
        if len(stage_refs) == 3 and mount:
            a, r, c = (stage_refs[k] for k in ('authentication', 'collection', 'transfer'))
            order = [[a, r], [r, c], [mount, c]]
        cases.append(dict(case_id=name, category=category, variant=variant, user_id=scoped('user', f'u{actor}'),
                          device_id=scoped('endpoint', f'd{device}'), observed_refs=refs, stages=stage_refs,
                          context=[mount] if mount else [], order_constraints=order,
                          changed_inputs=dict(actor=actor, endpoint=device, time=time.isoformat(), amount=amount,
                                              delays=delays, alias=variant == 'alias_corroborated', corroboration=variant == 'alias_corroborated')))

    if role == 'test':
        for i, variant in enumerate(ATTACKS): episode(f'attack-{seed}-{i}', i, 'supported_attack', variant)
    for i, variant in enumerate(BENIGN, 10): episode(f'benign-{seed}-{variant}', i, 'benign', variant)
    for i, variant in enumerate(NEGATIVES, 30):
        category = 'malicious_insufficient_or_out_of_scope' if role == 'test' and variant in ('missing_copy', 'out_of_window') else 'benign'
        episode(f'observational-{seed}-{variant}', i, category, variant)
    # Explicitly rejected timestamp row, retained in quality. No silent omission.
    files['auth'].append(dict(timestamp='not-a-time', action='login_success', user_id='u1', device_id='d1'))
    return files, resources, cases, declarations


def load_expanded(store, seed, role, users, requested):
    files, resources, cases, declarations = generate_expanded(seed, role, users, requested)
    dataset, _ = load_partition(store, files, resources, [], f'Expanded {role}', seed)
    store.set_authorizations(dataset, [AuthorizationContext(**c) for c in declarations])
    event_ids = {e.source_event_id: e.event_id for e in store.events(dataset)}
    for case in cases:
        case['observed_refs'] = [event_ids[e] for e in case['observed_refs']]
        case['stages'] = {k: event_ids[v] for k, v in case['stages'].items()}
        case['context'] = [event_ids[e] for e in case['context']]
        case['order_constraints'] = [[event_ids[a], event_ids[b]] for a, b in case['order_constraints']]
    quality = store.quality(dataset)
    quality.update(requested_background_records=requested, generated_records=sum(map(len, files.values())),
                   quarantined=quality['rejected'])
    return dataset, cases, quality
