"""Frozen historical lookups + 15-minute UTC observations. No identity encoding."""
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from math import log1p

import numpy as np

from .detection import completed, sensitivity
from .schemas import Event

FEATURE_VERSION = "window-v1"
FEATURE_NAMES = ["login_failures", "successful_logins", "new_device_fraction", "new_app_fraction",
                 "unusual_hour_fraction", "distinct_resources", "rare_resource_fraction", "sensitive_reads",
                 "bytes_read", "bytes_written", "usb_bytes", "distinct_destinations"]
LOG_FEATURES = {"login_failures", "successful_logins", "distinct_resources", "sensitive_reads",
                "bytes_read", "bytes_written", "usb_bytes", "distinct_destinations"}


def window_start(time: datetime) -> datetime:
    time = time.astimezone(timezone.utc)
    return time.replace(minute=(time.minute // 15) * 15, second=0, microsecond=0)


def history_snapshot(events: list[Event]) -> dict:
    users = defaultdict(lambda: {"logins":0, "reads":0, "devices":set(), "apps":set(), "hours":set(), "resources":set()})
    for e in events:
        if not e.user_id or not completed(e):
            continue
        user = users[e.user_id]
        if e.action == "login_success":
            user["logins"] += 1; user["devices"].add(e.device_id); user["apps"].add(e.app_id); user["hours"].add(e.event_time_utc.hour)
        if e.action == "file_read":
            user["reads"] += 1; user["resources"].add(e.resource_id)
    return {key: {name: sorted(value) if isinstance(value, set) else value for name, value in user.items()} for key, user in sorted(users.items())}


@dataclass
class FeatureBatch:
    windows: list[dict]
    values: np.ndarray
    warnings: list[str]


def build_features(events: list[Event], snapshot: dict, as_of: datetime, resources: list[dict]) -> FeatureBatch:
    if as_of.tzinfo is None:
        raise ValueError("feature cutoff requires an explicit timezone")
    groups = defaultdict(list)
    for e in events:
        if e.event_time_utc <= as_of and e.user_id and e.device_id:
            groups[(e.user_id, e.device_id, window_start(e.event_time_utc))].append(e)
    windows, values, warnings = [], [], set()
    for (user, device, start), group in sorted(groups.items()):
        history = snapshot.get(user, {})
        enough = history.get("logins", 0) >= 3 and history.get("reads", 0) >= 3
        if not enough:
            warnings.add(f"Insufficient frozen history: {user}; anomaly score omitted")
        logins = [e for e in group if e.action == "login_success" and completed(e)]
        reads = [e for e in group if e.action == "file_read" and completed(e)]
        raw = {"login_failures":sum(e.action == "login_failure" for e in group), "successful_logins":len(logins),
               "new_device_fraction": float(device not in history.get("devices", [])) if enough else 0.0,
               "new_app_fraction": sum(e.app_id not in history.get("apps", []) for e in logins) / max(1, len(logins)) if enough else 0.0,
               "unusual_hour_fraction": float(start.hour not in history.get("hours", [])) if enough else 0.0,
               "distinct_resources":len({e.resource_id for e in reads}),
               "rare_resource_fraction":sum(e.resource_id not in history.get("resources", []) for e in reads) / max(1,len(reads)) if enough else 0.0,
               "sensitive_reads":sum(sensitivity(resources,e) is not None for e in reads),
               "bytes_read":sum(e.bytes_read or 0 for e in group if completed(e)),
               "bytes_written":sum(e.bytes_written or 0 for e in group if completed(e)),
               "usb_bytes":sum(e.bytes_written or 0 for e in group if e.action == "file_copy_to_usb" and completed(e)),
               "distinct_destinations":len({e.dst_ip for e in group if e.dst_ip and completed(e)})}
        end = start + timedelta(minutes=15)
        windows.append({"user_id":user, "device_id":device, "start":start.isoformat(), "end":end.isoformat(),
                        "event_ids":sorted(e.event_id for e in group), "observed_features":raw,
                        "cold_start":not enough, "provisional":end > as_of})
        values.append([log1p(raw[name]) if name in LOG_FEATURES else raw[name] for name in FEATURE_NAMES])
    return FeatureBatch(windows, np.asarray(values, dtype=float).reshape((-1,len(FEATURE_NAMES))), sorted(warnings))
