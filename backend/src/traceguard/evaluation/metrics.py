"""Metrics are computed only after immutable predictions exist."""
from math import sqrt

from ..schemas import Event


def ratio(numerator,denominator):
    return numerator/denominator if denominator else None


def wilson(successes: int, total: int) -> list[float] | None:
    if not total:
        return None
    z=1.96; p=successes/total; divisor=1+z*z/total
    center=(p+z*z/(2*total))/divisor
    half=z*sqrt(p*(1-p)/total+z*z/(4*total*total))/divisor
    return [max(0.0,center-half),min(1.0,center+half)]


def evaluate_predictions(predictions: list[dict], labels: list[dict], events: list[Event], *, attack_event_ids=()) -> dict:
    by_id={e.event_id:e for e in events}
    # Validate label contract; malformed sidecars are errors rather than silently
    # earning credit from predictions or changing the denominator.
    for label in labels:
        if set(label["stages"]) != {"authentication","collection","transfer"}:
            raise ValueError("evaluation label requires all three stage references")
        refs=list(label["stages"].values())+label.get("context",[])
        if any(eid not in by_id for eid in refs):
            raise ValueError("evaluation label reference outside test dataset")
        if any(by_id[eid].user_id != label["user_id"] or by_id[eid].device_id != label["device_id"] for eid in refs):
            raise ValueError("label actor/endpoint mismatch")
        if any(a not in by_id or b not in by_id or by_id[a].event_time_utc>=by_id[b].event_time_utc for a,b in label["order_constraints"]):
            raise ValueError("invalid label ordering")
    alerts=[p for p in predictions if p["decision"]=="incident"]
    for prediction in predictions:
        if any(eid not in by_id for eid in prediction["selected_evidence"]):
            raise ValueError("prediction references outside evaluation dataset")
    matches,used,matching_decisions = [],set(),[]
    for prediction in sorted(alerts,key=lambda p:p["incident_id"]):
        stages={s["stage_id"]:set(s["evidence_event_ids"]) for s in prediction["stages"]}
        eligible = []
        for index,label in enumerate(labels):
            overlap=all(label["stages"][kind] in stages.get(kind,set()) for kind in label["stages"])
            selected=set(prediction["selected_evidence"])
            order=all(a in selected and b in selected and by_id[a].event_time_utc<by_id[b].event_time_utc for a,b in label["order_constraints"])
            if (prediction["user_id"]==label["user_id"] and prediction["device_id"]==label["device_id"] and overlap and order):
                eligible.append(index)
        available = [i for i in eligible if i not in used]
        status = 'oversized_or_ambiguous' if len(eligible)>1 else 'duplicate_credit_rejected' if eligible and not available else 'unmatched'
        if len(eligible)==1 and available:
            index = available[0]
            matches.append({"incident_id":prediction["incident_id"],"scenario_id":labels[index]["scenario_id"]})
            used.add(index)
            status = 'matched'
        matching_decisions.append(dict(incident_id=prediction['incident_id'], status=status,
                                      eligible_episodes=[labels[i]['scenario_id'] for i in eligible]))
    units={(e.user_id,e.device_id,e.event_time_utc.date().isoformat()) for e in events if e.user_id and e.device_id}
    attack_refs={eid for label in labels for eid in list(label["stages"].values())+label.get("context",[])} | set(attack_event_ids)
    if attack_refs-set(by_id):
        raise ValueError('attack reference outside test dataset')
    attack_units={(by_id[eid].user_id,by_id[eid].device_id,by_id[eid].event_time_utc.date().isoformat()) for eid in attack_refs}
    benign=units-attack_units
    false_units=set(); benign_false_alerts=0
    matched_ids={m["incident_id"] for m in matches}
    for alert in alerts:
        refs=[by_id[eid] for eid in alert["selected_evidence"] if eid in by_id]
        implicated={(e.user_id,e.device_id,e.event_time_utc.date().isoformat()) for e in refs}
        false_units |= implicated & benign
        if alert["incident_id"] not in matched_ids and implicated & benign:
            benign_false_alerts += 1
    asserted=sum(len(p["stages"]) for p in predictions)
    validated=sum(sum(all(eid in by_id for eid in s["evidence_event_ids"]) for s in p["stages"])
                  for p in predictions if p["validation"]["valid"])
    covered=set()
    for p in predictions:
        if p["validation"]["valid"]:
            covered.update((s["stage_id"],eid) for s in p["stages"] for eid in s["evidence_event_ids"])
    recalled=sum((stage,eid) in covered for label in labels for stage,eid in label["stages"].items())
    constraints=[(a,b) for label in labels for a,b in label["order_constraints"]]
    order_correct=sum(any(a in p["selected_evidence"] and b in p["selected_evidence"] and p["validation"]["valid"] for p in predictions) for a,b in constraints)
    predicted_constraints=[]
    for p in predictions:
        selected_stages={s["stage_id"]:s["evidence_event_ids"][0] for s in p["stages"]}
        if "authentication" in selected_stages and "collection" in selected_stages:
            predicted_constraints.append((selected_stages["authentication"],selected_stages["collection"]))
        if "transfer" in selected_stages and "collection" in selected_stages:
            predicted_constraints.append((selected_stages["collection"],selected_stages["transfer"]))
            predicted_constraints.extend((mount,selected_stages["transfer"]) for mount in p["context_event_ids"])
    valid_order=sum(a in by_id and b in by_id and by_id[a].event_time_utc<by_id[b].event_time_utc for a,b in predicted_constraints)
    return {"incident_precision":{"numerator":len(matches),"denominator":len(alerts),"value":ratio(len(matches),len(alerts))},
            "incident_recall":{"numerator":len(matches),"denominator":len(labels),"value":ratio(len(matches),len(labels))},
            "benign_user_device_day_fpr":{"numerator":len(false_units),"denominator":len(benign),"value":ratio(len(false_units),len(benign)),"wilson_95":wilson(len(false_units),len(benign))},
            "benign_false_alerts_per_1000_events":{"numerator":benign_false_alerts,"accepted_events":len(events),"value":1000*benign_false_alerts/len(events) if events else None},
            "asserted_stage_evidence_coverage":{"numerator":validated,"denominator":asserted,"value":ratio(validated,asserted)},
            "required_stage_recall":{"numerator":recalled,"denominator":3*len(labels),"value":ratio(recalled,3*len(labels))},
            "ordering_constraint_coverage":{"numerator":order_correct,"denominator":len(constraints),"value":ratio(order_correct,len(constraints))},
            "ordering_constraint_accuracy":{"numerator":valid_order,"denominator":len(predicted_constraints),"value":ratio(valid_order,len(predicted_constraints))},
            "matches":matches,"matching_decisions":matching_decisions,
            "unmatched_predictions":[p['incident_id'] for p in alerts if p['incident_id'] not in matched_ids],
            "unmatched_truth":[label['scenario_id'] for i,label in enumerate(labels) if i not in used],
            "false_alerts":len(alerts)-len(matches),"missed_episodes":len(labels)-len(matches),
            "alert_count":len(alerts),"candidate_count":len(predictions),"active_user_device_days":len(units),
            "warning":"Synthetic holdout metrics; one-to-one episode matches, no real-world guarantee"}
