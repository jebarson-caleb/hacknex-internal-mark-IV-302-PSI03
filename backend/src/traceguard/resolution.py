"""Only explicit, time-valid, same-environment user aliases can join accounts."""
from datetime import datetime

from .schemas import Event


def resolve_events(events: list[Event], aliases: list[dict]) -> tuple[list[Event], list[dict], list[str]]:
    resolved, links, warnings = [], [], set()
    sources = {a["alias_user_id"] for a in aliases}
    for event in events:
        active = [a for a in aliases if a["alias_user_id"] == event.user_id
                  and datetime.fromisoformat(a["effective_from"]) <= event.event_time_utc
                  and (not a["effective_until"] or event.event_time_utc < datetime.fromisoformat(a["effective_until"]))]
        targets = {a["canonical_user_id"] for a in active}
        if len(targets) > 1 or (targets and next(iter(targets)) in sources):
            warnings.add(f"Ambiguous or chained alias excluded: {event.user_id}")
            resolved.append(event)
        elif len(targets) == 1:
            canonical = next(iter(targets))
            resolved.append(event.model_copy(update={"user_id": canonical}))
            links.append({"event_id": event.event_id, "original_user_id": event.user_id,
                          "canonical_user_id": canonical, "policy_strength": 0.9,
                          "explanation": "Explicit trusted, time-valid account alias; not a probability",
                          "context": active})
        else:
            resolved.append(event)
    return resolved, links, sorted(warnings)
