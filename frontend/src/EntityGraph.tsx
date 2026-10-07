import type { EntityGraph as Graph } from './types';



export function EntityGraph({graph, eventIds, onEvidence}: {graph: Graph; eventIds: string[]; onEvidence:(id:string)=>void}) {

  const selected = new Set(eventIds);

  const activeEdges = graph.edges.filter(e => e.event_ids.some(id => selected.has(id)));

  const activeNodes = new Set(activeEdges.flatMap(e => [e.source,e.target]));

  const positions = new Map(graph.nodes.map((n,i) => {

    const angle = 2*Math.PI*i/graph.nodes.length;

    return [n.id,{x:400+260*Math.cos(angle),y:220+155*Math.sin(angle)}];

  }));

  return <section id="entity-graph" tabIndex={-1} aria-label="Entity graph"><h2>Typed entity graph</h2>

    <p>Correlation/provenance, not causality. {graph.independent_event_count} independent event records; multiple edges may come from one record.</p>

    <p>Legend: circles = accounts/apps/IP context; squares = endpoints/files/media. Solid = observed; dashed = supported inference. Blue = selected stage evidence. Mount is context; IP never joins accounts.</p>

    {graph.truncated && <p className="missing">Graph truncated: {graph.nodes.length}/{graph.total_nodes} nodes. Limit 500; relation list uses the same bounded graph.</p>}

    <svg viewBox="0 0 800 440" role="img" aria-label="Linked provenance diagram">

      <defs><marker id="edge-arrow" markerWidth="8" markerHeight="8" refX="19" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 Z" fill="#54657d"/></marker></defs>
      {graph.edges.map(e => {const a=positions.get(e.source)!,b=positions.get(e.target)!; return <g key={e.edge_id}>

        <line markerEnd="url(#edge-arrow)" x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke={activeEdges.includes(e) ? '#2164db' : '#8794a8'} strokeWidth={activeEdges.includes(e) ? 4 : 1.5} strokeDasharray={e.status==='observed' ? undefined : '6 5'}/>

        <title>{e.relation}: {e.status}</title>

      </g>;})}

      {graph.nodes.map(n => {const p=positions.get(n.id)!; return <g key={n.id}>

        {['user','app','ip'].includes(n.entity_type) ? <circle cx={p.x} cy={p.y} r={23} fill={activeNodes.has(n.id) ? '#c8ddff' : '#edf0f5'} stroke="#334155"/> : <rect x={p.x-24} y={p.y-20} width={48} height={40} rx={4} fill={activeNodes.has(n.id) ? '#c8ddff' : '#edf0f5'} stroke="#334155"/>}

        <text x={p.x} y={p.y+4} textAnchor="middle" fontSize="11">{n.entity_type}</text>

        <text x={p.x} y={p.y+38} textAnchor="middle" fontSize="11">{n.id.length>42 ? n.id.slice(0,39)+'…' : n.id}</text><title>{n.id}</title>

      </g>;})}

    </svg>

    <div className="table-wrap"><table><thead><tr><th>Entity</th><th>Type</th></tr></thead><tbody>{graph.nodes.map(n => <tr key={n.id} className={activeNodes.has(n.id) ? 'linked' : ''}><td>{n.id}</td><td>{n.entity_type}</td></tr>)}</tbody></table>

    <table><thead><tr><th>Source</th><th>Relation</th><th>Target</th><th>Support and original record</th></tr></thead><tbody>{graph.edges.map(e => <tr key={e.edge_id} className={activeEdges.includes(e) ? 'linked' : ''} data-event-ids={e.event_ids.join(',')}>

      <td>{e.source}</td><td>{e.relation}</td><td>{e.target}</td><td>{e.status}{e.event_ids.map(id => <button key={id} onClick={() => onEvidence(id)}>Open {e.relation} source</button>)}</td>

    </tr>)}</tbody></table></div>

  </section>;

}

