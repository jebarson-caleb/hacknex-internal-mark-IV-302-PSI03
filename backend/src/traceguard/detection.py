"""Deterministic bounded known-chain rules. No trained model or probabilities."""
from bisect import bisect_left, bisect_right
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from .ingest import digest, event_content, json_bytes
from .schemas import Event, Incident, Stage
from .storage import Store

RULE_VERSION = "phase1-v1"
CONFIG = {"version": "phase1-v1", "window_minutes": 60, "minimum_history_count": 3,
          "history_policy": "strictly before authentication UTC day",
          "risk_policy": "60 * required-stage fraction + 20 exact links + 20 supported transfer",
          "threshold": 100, "calibrated": False, "mode": "rules-only"}


def completed(event: Event) -> bool:
    # In this adapter contract an omitted outcome uses the action's literal
    # completed-observation meaning; an explicit failure must never support it.
    return event.outcome in {None, "success"}


class HistoryIndex:
    """Actor/action time index and per-day frozen count cache for the small slice."""
    def __init__(self, events: list[Event], version: str = "prior-UTC-days-v1"):
        self.version = version
        self.groups = defaultdict(list)
        for event in sorted(events, key=lambda e: (e.event_time_utc, e.event_id)):
            if not completed(event):
                continue
            self.groups[(event.user_id, event.action)].append(event)
        self.times = {key: [e.event_time_utc for e in group] for key, group in self.groups.items()}
        self.cache = {}

    def before_day(self, login: Event, action: str) -> list[Event]:
        boundary = login.event_time_utc.replace(hour=0, minute=0, second=0, microsecond=0)
        key = (login.user_id, action)
        cache_key = (key, boundary)
        if cache_key not in self.cache:
            self.cache[cache_key] = self.groups[key][:bisect_left(self.times.get(key, []), boundary)]
        return self.cache[cache_key]


class MountIndex:
    def __init__(self, events: list[Event]):
        self.groups = defaultdict(list)
        for event in sorted(events, key=lambda e: (e.event_time_utc, e.event_id)):
            if event.action in {"usb_mount", "usb_unmount"} and completed(event):
                self.groups[(event.device_id, event.removable_device_id)].append(event)
        self.times = {key: [e.event_time_utc for e in group] for key, group in self.groups.items()}

    def window(self, copy: Event) -> list[Event]:
        key = (copy.device_id, copy.removable_device_id)
        times = self.times.get(key, [])
        start = copy.event_time_utc - timedelta(minutes=60)
        return self.groups[key][bisect_left(times, start):bisect_right(times, copy.event_time_utc)]


def auth_comparison(events: list[Event] | HistoryIndex, login: Event) -> dict:
    index = events if isinstance(events, HistoryIndex) else HistoryIndex(events)
    history = index.before_day(login, "login_success")
    counts = {"prior_successful_logins": len(history),
              "same_device_count": sum(e.device_id == login.device_id for e in history),
              "same_app_count": sum(e.app_id == login.app_id for e in history),
              "same_utc_hour_count": sum(e.event_time_utc.hour == login.event_time_utc.hour for e in history)}
    return {**counts, "history_event_ids": [e.event_id for e in history],
            "history_version": index.version, "unusual": completed(login) and len(history) >= 3 and
            any(counts[key] == 0 for key in ("same_device_count", "same_app_count", "same_utc_hour_count"))}


def collection_comparison(events: list[Event] | HistoryIndex, login: Event, read: Event) -> dict:
    index = events if isinstance(events, HistoryIndex) else HistoryIndex(events)
    history = index.before_day(login, "file_read")
    count = sum(e.resource_id == read.resource_id for e in history)
    return {"prior_file_reads": len(history), "same_resource_count": count,
            "history_event_ids": [e.event_id for e in history], "history_version": index.version,
            "unusual": len(history) >= 3 and count == 0}


def sensitivity(resources: list[dict], read: Event) -> dict | None:
    for resource in resources:
        start = datetime.fromisoformat(resource["effective_from"])
        end = datetime.fromisoformat(resource["effective_until"]) if resource["effective_until"] else None
        if (resource["resource_id"] == read.resource_id and resource["sensitive"]
                and start <= read.event_time_utc and (end is None or read.event_time_utc < end)):
            return resource
    return None


def stage(kind: str, event: Event, comparison=None, context=None) -> Stage:
    names = {"authentication": "Unusual successful authentication",
             "collection": "Unusual sensitive local-file collection",
             "transfer": "Observed transfer to removable media"}
    fields = {"action": event.action, "user_id": event.user_id, "device_id": event.device_id}
    if kind == "authentication":
        fields["app_id"] = event.app_id
    else:
        fields["resource_id"] = event.resource_id
    if context:
        fields["trusted_resource_context"] = context
    if kind == "transfer":
        fields.update(removable_device_id=event.removable_device_id,
                      destination_type=event.destination_type, bytes_written=event.bytes_written)
    return Stage(stage_id=kind, stage_name=names[kind], rule_id=f"known-usb-chain.{kind}",
                 start_time_utc=event.event_time_utc, end_time_utc=event.event_time_utc,
                 claim_status="observed" if kind == "transfer" else "supported_inference",
                 evidence_event_ids=[event.event_id], matched_fields=fields,
                 predicate_results={"action_and_fields": True, "history_and_context": True},
                 historical_comparison=comparison,
                 entity_link_reasons=["Exact environment-scoped account and endpoint identifiers; IP is not a join key"])


def active_mount(events: list[Event] | MountIndex, copy: Event) -> Event | None:
    window = (events if isinstance(events, MountIndex) else MountIndex(events)).window(copy)
    mounts = [e for e in window if e.action == "usb_mount" and e.user_id == copy.user_id
              and e.device_id == copy.device_id and e.removable_device_id == copy.removable_device_id
              and copy.event_time_utc - timedelta(minutes=60) <= e.event_time_utc < copy.event_time_utc]
    for mount in reversed(mounts):
        # Equal-time unmount is conservatively treated as contradictory context.
        if not any(e.action == "usb_unmount" and e.device_id == copy.device_id
                   and e.removable_device_id == copy.removable_device_id
                   and mount.event_time_utc <= e.event_time_utc <= copy.event_time_utc for e in window):
            return mount
    return None


def correlate(events: list[Event], resources: list[dict], dataset_id: str, run_id: str,
              history_events: list[Event] | None = None, baseline_version: str = "prior-UTC-days-v1") -> list[Incident]:
    groups = defaultdict(list)
    history_index = HistoryIndex(events if history_events is None else history_events, baseline_version)
    mount_index = MountIndex(events)
    for event in sorted(events, key=lambda e: (e.event_time_utc, e.event_id)):
        if event.user_id and event.device_id:
            groups[(event.user_id, event.device_id)].append(event)
    candidates = []
    for (user, device), group in sorted(groups.items()):
        times = [e.event_time_utc for e in group]
        consumed_until = datetime.min.replace(tzinfo=timezone.utc)
        for login in group:
            if login.action != "login_success" or login.event_time_utc <= consumed_until:
                continue
            auth = auth_comparison(history_index, login)
            if not auth["unusual"]:
                continue
            end = login.event_time_utc + timedelta(minutes=CONFIG["window_minutes"])
            window = group[bisect_right(times, login.event_time_utc):bisect_right(times, end)]
            reads = [(e, collection_comparison(history_index, login, e), sensitivity(resources, e))
                     for e in window if e.action == "file_read" and completed(e)]
            reads = [(e, c, s) for e, c, s in reads if c["unusual"] and s]
            if not reads:
                continue
            read, comparison, sensitive = reads[0]
            copy, mount = None, None
            for possible in window:
                if (possible.action == "file_copy_to_usb" and possible.destination_type == "removable_media"
                        and completed(possible) and (possible.bytes_written or 0) > 0):
                    matching = next(((e, c, s) for e, c, s in reads
                                     if e.resource_id == possible.resource_id
                                     and e.event_time_utc < possible.event_time_utc), None)
                    attached = active_mount(mount_index, possible)
                    if matching and attached:
                        read, comparison, sensitive = matching
                        copy, mount = possible, attached
                        break
            stages = [stage("authentication", login, auth), stage("collection", read, comparison, sensitive)]
            context_ids = []
            missing = ["Compatible explicit file-copy telemetry and prior active USB mount"]
            if copy:
                stages.append(stage("transfer", copy))
                context_ids = [mount.event_id]
                missing = []
            selected = sorted({eid for s in stages for eid in s.evidence_event_ids} | set(context_ids))
            complete = copy is not None
            identity = digest(json_bytes([RULE_VERSION, user, device, selected]))[:24]
            risk = {"label": "heuristic; not a probability", "stage_completeness": len(stages) / 3,
                    "exact_entity_links": 20, "supported_transfer": 20 if complete else 0,
                    "score": 100 if complete else 60, "threshold": 100, "calibrated": False,
                    "anomaly_score": None, "baseline_version": None,
                    "weighted_terms":{"completeness":60*len(stages)/3,"linkage":20,"transfer":20 if complete else 0}}
            candidates.append(Incident(incident_id=f"{run_id}-{identity}", dataset_id=dataset_id,
                analysis_run_id=run_id, user_id=user, device_id=device, stages=stages,
                context_event_ids=context_ids, selected_evidence=selected, missing_evidence=missing,
                decision="incident" if complete else "partial_observation", risk=risk,
                decision_reason="All three required stages, exact identities, strict ordering, matching resource and active mount verified"
                if complete else "Incomplete chain retained for review; no USB-transfer claim or attack alert",
                summary="Observed transfer to removable media; suspected exfiltration in this chain. Intent and credential compromise are unknown."
                if complete else "Unusual authentication and sensitive-file access; transfer evidence is missing."))
            consumed_until = copy.event_time_utc if copy else read.event_time_utc
    return candidates


def validate_evidence(candidate: Incident, events: list[Event], resources: list[dict], store: Store | None = None,
                      history_events: list[Event] | None = None, baseline_version: str = "prior-UTC-days-v1",
                      provenance_cache: dict[str,list[str]] | None = None) -> dict:
    errors = []
    history_index = HistoryIndex(events if history_events is None else history_events, baseline_version)
    by_id = {e.event_id: e for e in events}
    types = [s.stage_id for s in candidate.stages]
    if types not in [["authentication", "collection"], ["authentication", "collection", "transfer"]]:
        return {"valid": False, "errors": ["invalid required-stage structure"]}
    resolved = []
    for s in candidate.stages:
        if len(s.evidence_event_ids) != 1 or s.evidence_event_ids[0] not in by_id:
            errors.append(f"unresolvable or fabricated evidence for {s.stage_id}")
            continue
        resolved.append(by_id[s.evidence_event_ids[0]])
    if errors:
        return {"valid": False, "errors": errors}
    login, read = resolved[:2]
    for event in resolved:
        if event.dataset_id != candidate.dataset_id or event.user_id != candidate.user_id or event.device_id != candidate.device_id:
            errors.append("required actor/endpoint/dataset linkage failed")
    if login.action != "login_success" or not login.app_id or not auth_comparison(history_index, login)["unusual"]:
        errors.append("authentication predicate failed")
    sensitive = sensitivity(resources, read)
    comparison = collection_comparison(history_index, login, read)
    if read.action != "file_read" or not completed(read) or not sensitive or not comparison["unusual"]:
        errors.append("collection predicate failed")
    if not login.event_time_utc < read.event_time_utc <= login.event_time_utc + timedelta(minutes=60):
        errors.append("strict authentication/collection ordering failed")
    expected = [stage("authentication", login, auth_comparison(history_index, login)),
                stage("collection", read, comparison, sensitive)]
    if len(resolved) == 3:
        copy = resolved[2]
        if (copy.action != "file_copy_to_usb" or not completed(copy) or copy.destination_type != "removable_media"
                or not copy.removable_device_id or (copy.bytes_written or 0) <= 0 or copy.resource_id != read.resource_id):
            errors.append("explicit compatible transfer predicate failed")
        if not read.event_time_utc < copy.event_time_utc <= login.event_time_utc + timedelta(minutes=60):
            errors.append("strict collection/transfer ordering or correlation window failed")
        mount = active_mount(events, copy)
        if not mount or candidate.context_event_ids != [mount.event_id]:
            errors.append("active mount context failed")
        expected.append(stage("transfer", copy))
    elif candidate.context_event_ids:
        errors.append("unexpected context on incomplete chain")
    if candidate.decision not in (["incident", "review"] if len(resolved) == 3 else ["partial_observation"]):
        errors.append("decision does not match stage completeness")
    for actual, exp in zip(candidate.stages, expected):
        if actual.model_dump(mode="json") != exp.model_dump(mode="json"):
            errors.append(f"stage metadata or historical comparison mismatch: {actual.stage_id}")
    selected = sorted({e.event_id for e in resolved} | set(candidate.context_event_ids))
    if candidate.selected_evidence != selected:
        errors.append("selected evidence differs from stage/context references")
    history_refs = {eid for s in candidate.stages for eid in (s.historical_comparison or {}).get("history_event_ids", [])}
    provenance_ids = set(by_id) | {e.event_id for e in (history_events or [])}
    for eid in set(selected) | history_refs:
        if eid not in provenance_ids:
            errors.append(f"reference outside analysis snapshot: {eid}")
        elif store:
            errors.extend(provenance_cache[eid] if provenance_cache is not None else store.provenance_errors(eid))
    return {"valid": not errors, "errors": errors,
            "asserted_stages_checked": len(candidate.stages), "provenance_events_checked": len(set(selected) | history_refs)}


def analyze(store: Store, dataset_id: str, cutoff: datetime | None = None) -> dict:
    dataset = store.dataset(dataset_id)
    all_events = store.events(dataset_id)
    if cutoff is not None and cutoff.tzinfo is None:
        raise ValueError("analysis cutoff requires an explicit timezone")
    cutoff = cutoff or max((e.event_time_utc for e in all_events), default=datetime.now(timezone.utc))
    events = [e for e in all_events if e.event_time_utc <= cutoff]
    from .context import authorization_checks, calibration_status, recommendations
    resources = store.resources(dataset_id)
    authorizations = store.authorizations(dataset_id)
    run_id = uuid4().hex
    candidates = correlate(events, resources, dataset_id, run_id)
    for candidate in candidates:
        candidate.validation = validate_evidence(candidate, events, resources, store)
        if not candidate.validation["valid"]:
            raise ValueError(f"evidence validation failed: {candidate.validation['errors']}")
    fingerprint = digest(json_bytes([event_content(e) for e in events]))
    history_index = HistoryIndex(events)
    users = {e.user_id for e in events if e.user_id}
    established = {e.user_id for e in events if e.action == "login_success" and len(history_index.before_day(e, "login_success")) >= 3}
    warnings = ["Rules-only: no fitted ML model or percentile calibration; structural score unchanged by authorization; no real-world accuracy claim"]
    if users - established:
        warnings.append(f"Insufficient prior-day authentication history for {len(users - established)} account(s); no automatic unusual-login claim")
    if not resources:
        warnings.append("No trusted sensitivity metadata: sensitive collection cannot be asserted")
    if not events:
        warnings.append("Empty dataset at analysis cutoff")
    quality = store.quality(dataset_id)
    if quality["rejected"]:
        warnings.append(f"{quality['rejected']} source records quarantined; inspect ingestion errors")
    warnings.extend(quality["warnings"])
    for candidate in candidates:
        candidate.warnings = warnings
        candidate.authorization = authorization_checks(candidate, events, authorizations)
        candidate.recommendations = recommendations(candidate)
    result = {"schema_version": "1", "analysis_run_id": run_id, "dataset_id": dataset_id,
              "dataset_fingerprint": fingerprint, "origin": dataset["origin"], "seed": dataset["seed"],
              "mode": "rules-only", "status": "completed", "cutoff": cutoff.isoformat(),
              "config": dict(CONFIG), "rule_version": RULE_VERSION, "baseline_id": None,
              "event_ids": [e.event_id for e in events], "resource_context_snapshot": resources,
              "authorization_context_snapshot":authorizations, "context_policy_version":"scoped-copy-v1",
              "calibration":calibration_status(None), "event_count": len(events), "incident_count": sum(c.decision == "incident" for c in candidates),
              "partial_count": sum(c.decision == "partial_observation" for c in candidates), "warnings": warnings}
    store.save_analysis(result, candidates)
    return result
