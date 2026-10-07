import { useEffect, useMemo, useState } from 'react';
import { post, request } from './api';
import type { Analysis, EventRow } from './types';

type HuntQuery = {filters:{field:string;op:'eq'|'contains'|'in';value:string|string[]}[];start_time_utc?:string;end_time_utc?:string};
type Hunt = {hunt_id:string;name:string;description:string;revision:number;query:HuntQuery;columns:string[];tags:string[];starred:boolean;notes:{note_id:string;text:string;author_label:string}[];scope:string;filter_schema:string};
type HuntPage = {items:Hunt[];total:number;next_cursor:number|null};
type HuntExecution = {execution_id:string;hunt_revision:number;analysis_run_id:string;view_id:string;result_count:number;result_sha256:string;executed_at_utc:string;query_snapshot:HuntQuery};
type ExecutionPage = HuntExecution & {items:(EventRow & Record<string,unknown>)[];cursor:number;next_cursor:number|null;page_count:number};
const columns=['event_time_utc','source_type','action','user_id','device_id','src_ip','dst_ip','domain','resource_id','process_name','event_id'];
const fieldOptions=['source_type','action','user_id','device_id','resource_id','src_ip','dst_ip','domain','file_path','process_name','outcome'];

function asUtc(value:string) { return value ? new Date(value).toISOString() : undefined; }
function asLocal(value?:string) { if(!value)return '';const date=new Date(value);return `${date.getFullYear()}-${String(date.getMonth()+1).padStart(2,'0')}-${String(date.getDate()).padStart(2,'0')}T${String(date.getHours()).padStart(2,'0')}:${String(date.getMinutes()).padStart(2,'0')}`; }

export function Hunts({run,onInspect}:{run:Analysis|null;onInspect:(runId:string,eventId:string)=>void}) {
  const [hunts,setHunts]=useState<Hunt[]>([]);const [selectedId,setSelectedId]=useState('');const [cursor,setCursor]=useState(0);const [next,setNext]=useState<number|null>(null);const [total,setTotal]=useState(0);
  const [name,setName]=useState('');const [description,setDescription]=useState('');const [field,setField]=useState('action');const [operator,setOperator]=useState<'eq'|'contains'|'in'>('eq');const [value,setValue]=useState('');const [start,setStart]=useState('');const [end,setEnd]=useState('');const [tag,setTag]=useState('');const [note,setNote]=useState('');
  const [sourceTypeFilter,setSourceTypeFilter]=useState('');const [actionFilter,setActionFilter]=useState('');const [actorFilter,setActorFilter]=useState('');const [endpointFilter,setEndpointFilter]=useState('');const [resourceFilter,setResourceFilter]=useState('');const [srcIpFilter,setSrcIpFilter]=useState('');const [dstIpFilter,setDstIpFilter]=useState('');
  const [executions,setExecutions]=useState<HuntExecution[]>([]);const [results,setResults]=useState<ExecutionPage|null>(null);const [error,setError]=useState('');const [busy,setBusy]=useState(false);
  const selected=useMemo(()=>hunts.find(item=>item.hunt_id===selectedId)||null,[hunts,selectedId]);
  async function loadList(offset=0) {const page=await request<HuntPage>(`/hunts?cursor=${offset}&limit=20`);setHunts(page.items);setTotal(page.total);setNext(page.next_cursor);setCursor(offset);if(!selectedId&&page.items.length)setSelectedId(page.items[0].hunt_id);}
  async function loadExecutions(huntId=selectedId) {if(!huntId){setExecutions([]);return;}const page=await request<{items:HuntExecution[];total:number}>(`/hunts/${huntId}/executions?cursor=0&limit=20`);setExecutions(page.items);}
  async function act(work:()=>Promise<void>) {setBusy(true);setError('');try{await work();}catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}
  useEffect(()=>{void act(()=>loadList());},[]);
  useEffect(()=>{setResults(null);void act(()=>loadExecutions(selectedId));},[selectedId]);
  useEffect(()=>{if(!selected)return;const exact=(key:string)=>String(selected.query.filters.find(item=>item.field===key&&item.op==='eq')?.value??'');setSourceTypeFilter(exact('source_type'));setActionFilter(exact('action'));setActorFilter(exact('user_id'));setEndpointFilter(exact('device_id'));setResourceFilter(exact('resource_id'));setSrcIpFilter(exact('src_ip'));setDstIpFilter(exact('dst_ip'));const generic=selected.query.filters.find(item=>!['source_type','action','user_id','device_id','resource_id','src_ip','dst_ip'].includes(item.field));setField(generic?.field??'action');setOperator(generic?.op??'eq');setValue(Array.isArray(generic?.value)?generic.value.join(', '):generic?.value??'');setStart(asLocal(selected.query.start_time_utc));setEnd(asLocal(selected.query.end_time_utc));},[selected?.hunt_id,selected?.revision]);
  function makeQuery():HuntQuery {
    const filters:HuntQuery['filters']=[];
    const exactFields:[string,string][]=[['source_type',sourceTypeFilter],['action',actionFilter],['user_id',actorFilter],['device_id',endpointFilter],['resource_id',resourceFilter],['src_ip',srcIpFilter],['dst_ip',dstIpFilter]];
    for(const [key,filter] of exactFields)if(filter.trim())filters.push({field:key,op:'eq',value:filter.trim()});
    const filterValue=operator==='in'?value.split(',').map(part=>part.trim()).filter(Boolean):value.trim();
    if(typeof filterValue==='string'&&filterValue)filters.push({field,op:operator,value:filterValue});
    if(Array.isArray(filterValue)&&filterValue.length)filters.push({field,op:operator,value:filterValue});
    const query:HuntQuery={filters};const from=asUtc(start),to=asUtc(end);if(from)query.start_time_utc=from;if(to)query.end_time_utc=to;return query;
  }
  async function create() {if(!name.trim())throw new Error('Name the saved hunt first');const hunt=await post<Hunt>('/hunts',{name,description,query:makeQuery(),columns,tags:tag.trim()?[tag.trim()]:[],scope:'retained_run'});setHunts(prev=>[hunt,...prev]);setSelectedId(hunt.hunt_id);setName('');setDescription('');setTag('');}
  async function update(changes:Partial<Pick<Hunt,'query'|'tags'|'starred'>>) {if(!selected)return;const value=await request<Hunt>(`/hunts/${selected.hunt_id}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({expected_revision:selected.revision,...changes})});setHunts(prev=>prev.map(item=>item.hunt_id===value.hunt_id?value:item));}
  async function saveFilters() {await update({query:makeQuery()});}
  async function addTag() {if(!selected||!tag.trim())return;await update({tags:[...new Set([...selected.tags,tag.trim()])]});setTag('');}
  async function toggleStar() {if(selected)await update({starred:!selected.starred});}
  async function addNote() {if(!selected||!note.trim())return;const value=await post<Hunt>(`/hunts/${selected.hunt_id}/notes`,{expected_revision:selected.revision,note,author:'operator'});setHunts(prev=>prev.map(item=>item.hunt_id===value.hunt_id?value:item));setNote('');}
  async function execute() {if(!selected||!run)throw new Error('Select a retained analysis run before executing a saved hunt');const value=await post<HuntExecution>(`/hunts/${selected.hunt_id}/execute`,{analysis_run_id:run.analysis_run_id,revision:selected.revision});await loadExecutions();await loadResult(value.execution_id,0);}
  async function loadResult(id:string,offset:number) {if(!selected)return;const value=await request<ExecutionPage>(`/hunts/${selected.hunt_id}/executions/${id}?cursor=${offset}&limit=50`);setResults(value);}

  return <section id="saved-hunts" aria-label="Saved observation hunts">
    <h2>Saved hunts · retained observations</h2>
    <p className="muted">A saved hunt is a bounded filter template. Each execution freezes the selected run, query revision, matching observation IDs, and result hash. Hunt matches are not incidents, attack stages, probabilities, or risk modifiers.</p>
    <div className="hunt-grid"><div>
      <form onSubmit={e=>{e.preventDefault();void act(create);}}><label>New saved hunt name<input value={name} onChange={e=>setName(e.target.value)} maxLength={120}/></label><label>Description<input value={description} onChange={e=>setDescription(e.target.value)} maxLength={1000}/></label>
        <label>Source family<select value={sourceTypeFilter} onChange={e=>setSourceTypeFilter(e.target.value)}><option value="">Any source family</option>{['auth','file','device','network'].map(item=><option key={item}>{item}</option>)}</select></label><label>Canonical action<input value={actionFilter} onChange={e=>setActionFilter(e.target.value)} maxLength={120}/></label><label>Exact scoped actor ID<input value={actorFilter} onChange={e=>setActorFilter(e.target.value)} maxLength={500}/></label><label>Exact scoped endpoint ID<input value={endpointFilter} onChange={e=>setEndpointFilter(e.target.value)} maxLength={500}/></label><label>Exact resource ID<input value={resourceFilter} onChange={e=>setResourceFilter(e.target.value)} maxLength={500}/></label><label>Exact source IP<input value={srcIpFilter} onChange={e=>setSrcIpFilter(e.target.value)} maxLength={100}/></label><label>Exact destination IP<input value={dstIpFilter} onChange={e=>setDstIpFilter(e.target.value)} maxLength={100}/></label>
        <label>Additional structured field<select value={field} onChange={e=>setField(e.target.value)}>{fieldOptions.map(item=><option key={item}>{item}</option>)}</select></label><label>Operation<select value={operator} onChange={e=>setOperator(e.target.value as typeof operator)}><option value="eq">Equals</option><option value="in">One of comma-separated values</option><option value="contains">Contains literal text</option></select></label><label>Additional literal value<input value={value} onChange={e=>setValue(e.target.value)} maxLength={500}/></label>
        <label>Start time (optional, local input)<input type="datetime-local" value={start} onChange={e=>setStart(e.target.value)}/></label><label>End time (optional, exclusive)<input type="datetime-local" value={end} onChange={e=>setEnd(e.target.value)}/></label><label>Analyst tag (optional)<input value={tag} onChange={e=>setTag(e.target.value)} maxLength={50}/></label><button disabled={busy}>Save filter template</button>
      </form>
      <hr/><p>{total} saved hunt templates · 20 per page.</p>{hunts.map(item=><button key={item.hunt_id} className={`incident ${selectedId===item.hunt_id?'selected':''}`} onClick={()=>setSelectedId(item.hunt_id)}><strong>{item.starred?'★ ':''}{item.name}</strong><span>Revision {item.revision} · {item.scope}</span></button>)}{next!==null&&<button disabled={busy} onClick={()=>void act(()=>loadList(next))}>Next saved hunt page</button>}{cursor>0&&<button disabled={busy} onClick={()=>void act(()=>loadList(0))}>First saved hunt page</button>}
    </div><div>
      {selected?<><h3>{selected.name} · revision {selected.revision}</h3><p>{selected.description||'No description.'}</p><button disabled={busy} onClick={()=>void act(toggleStar)}>{selected.starred?'Remove star':'Star hunt'}</button><p>Tags: {selected.tags.join(', ')||'None'}</p><form onSubmit={e=>{e.preventDefault();void act(addTag);}}><label>Add analyst tag<input value={tag} onChange={e=>setTag(e.target.value)} maxLength={50}/></label><button disabled={busy}>Save tag as revision</button></form>
        <details><summary>Saved structured filter and columns</summary><pre>{JSON.stringify({filter_schema:selected.filter_schema,query:selected.query,columns:selected.columns,scope:selected.scope},null,2)}</pre></details>
        <button disabled={busy} onClick={()=>void act(saveFilters)}>Save current filter as a new revision</button>
        {run?<p>Selected view: {run.analysis_run_id} · {run.branch_kind||'ordinary'} · cutoff {run.cutoff}</p>:<p>Select a retained run to execute this hunt.</p>}<button disabled={busy||!run} onClick={()=>void act(execute)}>Execute saved query on selected run</button>
        <form onSubmit={e=>{e.preventDefault();void act(addNote);}}><label>Analyst note<textarea value={note} onChange={e=>setNote(e.target.value)} maxLength={1000}/></label><button disabled={busy}>Save analyst note</button></form>{selected.notes.map(item=><blockquote key={item.note_id}>{item.text}</blockquote>)}
        <h3>Prior executions · {executions.length}</h3>{executions.map(item=><button key={item.execution_id} onClick={()=>void act(()=>loadResult(item.execution_id,0))}>{item.executed_at_utc} · {item.result_count} matches · run {item.analysis_run_id}</button>)}
      </>:<p>Create or select a saved hunt.</p>}
      {results&&<article><h3>Hunt matches · {results.result_count}</h3><p>Page shows {results.page_count}; this is not the full population when more pages remain.</p><p>Run/view {results.view_id} · query revision {results.hunt_revision} · result SHA-256 <code>{results.result_sha256}</code></p><p className="muted">Each result is a canonical retained observation. Its source records can be inspected; a match alone does not support a TraceGuard incident.</p>
        <div className="table-wrap"><table><thead><tr>{selected?.columns.map(col=><th key={col}>{col}</th>)}<th>Source</th></tr></thead><tbody>{results.items.map(item=><tr key={item.event_id}>{selected?.columns.map(col=><td key={col}>{String((item as Record<string,unknown>)[col]??'—')}</td>)}<td><button disabled={busy} onClick={()=>onInspect(results.analysis_run_id,item.event_id)}>Inspect exact observation</button></td></tr>)}</tbody></table></div>
        {results.cursor>0&&<button disabled={busy} onClick={()=>void act(()=>loadResult(results.execution_id,0))}>First result page</button>}{results.next_cursor!==null&&<button disabled={busy} onClick={()=>void act(()=>loadResult(results.execution_id,results.next_cursor!))}>Next result page</button>}
      </article>}
    </div></div>{error&&<p role="alert" className="error">{error}</p>}
  </section>;
}
