"""Typed directed provenance graph; connectivity alone never declares an attack."""
from datetime import timezone

import networkx as nx

from .detection import completed
from .ingest import digest, entity_id, json_bytes
from .schemas import Event, Incident


def build_graph(events: list[Event], resolutions: list[dict] | None = None) -> nx.MultiDiGraph:
    graph = nx.MultiDiGraph()

    def node(identifier, kind):
        if identifier:
            graph.add_node(identifier, entity_type=kind, label=identifier)

    def edge(left, right, relation, event, **attributes):
        if not left or not right:
            return
        key = digest(json_bytes([event.event_id,relation,left,right]))
        graph.add_edge(left, right, key=key, edge_id=key, relation=relation,
                       event_ids=[event.event_id], timestamp=event.event_time_utc.isoformat(),
                       source_id=event.source_id, source_type=event.source_type, status="observed",
                       explanation="Exact identifiers in the same retained observation; not causal proof",
                       actor=event.user_id, endpoint=event.device_id, **attributes)

    for e in sorted(events, key=lambda e: (e.event_time_utc,e.event_id)):
        for identifier, kind in ((e.user_id,"user"),(e.device_id,"endpoint"),(e.app_id,"app"),
                                 (e.resource_id,"file"),(e.removable_device_id,"removable_device")):
            node(identifier,kind)
        if not completed(e):
            continue
        if e.action == "login_success":
            edge(e.user_id,e.app_id,"authenticated_to",e)
            edge(e.user_id,e.device_id,"session_on",e)
        if e.action == "file_read":
            edge(e.user_id,e.resource_id,"read_file",e)
            edge(e.resource_id,e.device_id,"local_file_on",e)
        if e.action == "usb_mount":
            edge(e.removable_device_id,e.device_id,"mounted_on",e)
        if e.action == "file_copy_to_usb" and e.destination_type == "removable_media" and (e.bytes_written or 0) > 0:
            edge(e.resource_id,e.removable_device_id,"copied_to",e,bytes_written=e.bytes_written)
            edge(e.user_id,e.device_id,"copy_on",e)
        for address, relation in ((e.src_ip,"connected_from"),(e.dst_ip,"connected_to")):
            if address:
                # An IP is context for one observation, not a durable actor identity.
                ip = entity_id(e.environment_id,"ip",f"{address}@{e.event_time_utc.astimezone(timezone.utc).isoformat()}")
                node(ip,"ip"); edge(e.device_id,ip,relation,e)
    for link in resolutions or []:
        event = next((e for e in events if e.event_id == link["event_id"]), None)
        if event:
            node(link["original_user_id"],"user"); node(link["canonical_user_id"],"user")
            edge(link["original_user_id"],link["canonical_user_id"],"trusted_alias",event,
                 alias_provenance=link["context"], policy_strength=0.9)
            data = graph[link["original_user_id"]][link["canonical_user_id"]]
            for attrs in data.values():
                if attrs["relation"] == "trusted_alias":
                    attrs["status"] = "supported_inference"
                    attrs["explanation"] = link["explanation"]
    return graph


def validate_graph(candidate: Incident, graph: nx.MultiDiGraph, events: list[Event]) -> dict:
    by_id = {e.event_id:e for e in events}
    requirements = []
    for stage in candidate.stages:
        e = by_id.get(stage.evidence_event_ids[0])
        if not e:
            return {"valid":False,"errors":["graph evidence missing"]}
        if stage.stage_id == "authentication":
            requirements.extend([(e.user_id,e.app_id,"authenticated_to",e),(e.user_id,e.device_id,"session_on",e)])
        elif stage.stage_id == "collection":
            requirements.extend([(e.user_id,e.resource_id,"read_file",e),(e.resource_id,e.device_id,"local_file_on",e)])
        elif stage.stage_id == "transfer":
            requirements.extend([(e.resource_id,e.removable_device_id,"copied_to",e),(e.user_id,e.device_id,"copy_on",e)])
    for eid in candidate.context_event_ids:
        e = by_id.get(eid)
        if e:
            requirements.append((e.removable_device_id,e.device_id,"mounted_on",e))
        else:
            return {"valid":False,"errors":["graph mount evidence missing"]}
    errors = []
    for left,right,relation,e in requirements:
        relations = graph.get_edge_data(left,right,default={}).values()
        if not any(d["relation"] == relation and d["event_ids"] == [e.event_id]
                   and d["actor"] == candidate.user_id and d["endpoint"] == candidate.device_id
                   and d["timestamp"] == e.event_time_utc.isoformat() for d in relations):
            errors.append(f"required graph relation failed: {relation}:{e.event_id}")
    return {"valid":not errors,"errors":errors,"relations_checked":len(requirements)}


def graph_payload(graph: nx.MultiDiGraph, limit: int = 200) -> dict:
    nodes = sorted(graph.nodes)[:limit]
    subgraph = graph.subgraph(nodes)
    return {"schema_version":"1", "kind":"correlation/provenance; not causality",
            "nodes":[{"id":n,**subgraph.nodes[n]} for n in nodes],
            "edges":[{"source":u,"target":v,**d} for u,v,_,d in sorted(subgraph.edges(keys=True,data=True),key=lambda e:e[2])],
            "truncated":len(graph.nodes)>limit, "total_nodes":len(graph.nodes),
            "independent_event_count":len({eid for _,_,d in subgraph.edges(data=True) for eid in d["event_ids"]})}
