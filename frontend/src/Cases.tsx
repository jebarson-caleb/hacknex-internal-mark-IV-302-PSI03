import { useEffect, useMemo, useState } from 'react';
import { post, request } from './api';
import type { Analysis, Incident } from './types';

type CaseTask = {task_id:string;title:string;description:string;status:'todo'|'in_progress'|'done';completion_note:string};
type CaseRecord = {case_id:string;title:string;description:string;priority:string;status:string;disposition:string;closure_rationale:string;revision:number;linked_incidents:{incident_id:string;analysis_run_id:string;summary:string}[];tasks:CaseTask[];notes:{note_id:string;text:string;author_label:string}[];bookmarks:{bookmark_id:string;analysis_run_id:string;event_id:string;note:string;source_records:{source_ref:string;raw_sha256:string}[]}[];external_findings?:{finding_id:string;artifact_id:string;tool:string;profile:string;source_position:number;raw_row_sha256:string;upstream_rule_title?:string;note:string;interpretation:string}[]};
type CasePage = {items:CaseRecord[];total:number;next_cursor:number|null};

function saveBlob(blob:Blob, name:string) {
  const url=URL.createObjectURL(blob); const anchor=document.createElement('a'); anchor.href=url; anchor.download=name; anchor.click(); setTimeout(()=>URL.revokeObjectURL(url),1000);
}

export function Cases({run,incident,onInspect}:{run:Analysis|null;incident:Incident|null;onInspect:(runId:string,eventId:string)=>void}) {
  const [items,setItems]=useState<CaseRecord[]>([]); const [selected,setSelected]=useState<CaseRecord|null>(null);
  const [query,setQuery]=useState(''); const [status,setStatus]=useState(''); const [cursor,setCursor]=useState(0); const [next,setNext]=useState<number|null>(null); const [total,setTotal]=useState(0);
  const [title,setTitle]=useState(''); const [note,setNote]=useState(''); const [taskTitle,setTaskTitle]=useState(''); const [bookmarkId,setBookmarkId]=useState(''); const [bookmarkNote,setBookmarkNote]=useState(''); const [disposition,setDisposition]=useState('undetermined'); const [nextStatus,setNextStatus]=useState('investigating'); const [rationale,setRationale]=useState(''); const [error,setError]=useState(''); const [busy,setBusy]=useState(false); const [verification,setVerification]=useState('');
  const evidenceIds=useMemo(()=>incident ? [...new Set([...incident.stages.flatMap(s=>s.evidence_event_ids),...incident.context_event_ids,...incident.selected_evidence])] : [],[incident]);

  async function loadList(offset=0) {
    const params=new URLSearchParams({cursor:String(offset),limit:'20'}); if(query.trim()) params.set('query',query.trim()); if(status) params.set('status',status);
    const page=await request<CasePage>(`/cases?${params}`); setItems(page.items);setTotal(page.total);setNext(page.next_cursor);setCursor(offset);
  }
  async function reloadCase(id:string) { const result=await request<CaseRecord>(`/cases/${id}`);setSelected(result);setDisposition(result.disposition);setNextStatus(result.status==='open'?'investigating':result.status==='investigating'?'resolved':'closed'); }
  async function act(work:()=>Promise<void>) {setBusy(true);setError('');try{await work();}catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}
  useEffect(()=>{void act(()=>loadList());},[]);
  useEffect(()=>{if(incident && !title) setTitle(incident.summary);},[incident]);

  async function refresh(id=selected?.case_id) { await loadList(cursor); if(id) await reloadCase(id); }
  async function create() {
    if(!incident) throw new Error('Select a retained incident before creating a linked case');
    const value=await post<CaseRecord>('/cases/from-incident',{incident_id:incident.incident_id,title:title||incident.summary,description:'',priority:'high',author:'operator'});
    setTitle(''); await loadList(0); await reloadCase(value.case_id);
  }
  async function addNote() {if(!selected||!note.trim())return;const value=await post<CaseRecord>(`/cases/${selected.case_id}/notes`,{expected_revision:selected.revision,text:note,author:'operator'});setNote('');setSelected(value);await loadList(cursor);}
  async function addTask() {if(!selected||!taskTitle.trim())return;const value=await post<CaseRecord>(`/cases/${selected.case_id}/tasks`,{expected_revision:selected.revision,title:taskTitle,description:'',author:'operator'});setTaskTitle('');setSelected(value);await loadList(cursor);}
  async function updateTask(task:CaseTask) {if(!selected)return;const value=await request<CaseRecord>(`/cases/${selected.case_id}/tasks/${task.task_id}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({expected_revision:selected.revision,status:task.status==='done'?'todo':'done',completion_note:task.status==='done'?'':'Manually completed by operator',author:'operator'})});setSelected(value);await loadList(cursor);}
  async function saveStatus() {if(!selected)return;const value=await request<CaseRecord>(`/cases/${selected.case_id}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({expected_revision:selected.revision,status:nextStatus,disposition,rationale,author:'operator'})});setRationale('');setSelected(value);await loadList(cursor);}
  async function reopen() {if(!selected)return;const value=await post<CaseRecord>(`/cases/${selected.case_id}/reopen`,{expected_revision:selected.revision,reason:rationale||'Reopened for additional human review',author:'operator'});setRationale('');setSelected(value);await loadList(cursor);}
  async function bookmark() {if(!selected||!run||!bookmarkId)throw new Error('Choose an eligible observation from the selected incident');const value=await post<CaseRecord>(`/cases/${selected.case_id}/bookmarks`,{expected_revision:selected.revision,analysis_run_id:run.analysis_run_id,incident_id:incident?.incident_id??'',event_id:bookmarkId,note:bookmarkNote,author:'operator'});setBookmarkNote('');setSelected(value);await loadList(cursor);}
  async function download(format:'json'|'markdown') {if(!selected)return;const response=await fetch(`/api/cases/${selected.case_id}/export?format=${format}&revision=${selected.revision}`);if(!response.ok)throw new Error(String((await response.json()).detail));const blob=await response.blob();saveBlob(blob,`traceguard-case-${selected.case_id}-r${selected.revision}.${format==='json'?'json':'md'}`);if(format==='json'){const payload=await blob.text();const result=await post<{valid:boolean;errors:string[]}>('/cases/verify',JSON.parse(payload));setVerification(result.valid?'Valid: retained case revision and linked report checks passed.':`Invalid: ${result.errors.join('; ')}`);}}

  return <section id="cases-workbench" aria-label="Cases and investigation notes">
    <h2>Cases · analyst workflow</h2>
    <p className="muted">Cases, dispositions, tasks, notes, and bookmarks are audited analyst records. They do not alter incident risk or model evaluation.</p>
    {incident&&<form onSubmit={e=>{e.preventDefault();void act(create);}}><label>Create from selected retained incident<input value={title} onChange={e=>setTitle(e.target.value)} maxLength={200}/></label><button disabled={busy}>Create linked case</button><span className="muted"> {incident.incident_id}</span></form>}
    <form className="case-filters" onSubmit={e=>{e.preventDefault();void act(()=>loadList(0));}}><label>Search cases<input value={query} onChange={e=>setQuery(e.target.value)} maxLength={200}/></label><label>Status<select value={status} onChange={e=>setStatus(e.target.value)}><option value="">All statuses</option>{['open','investigating','resolved','closed'].map(v=><option key={v}>{v}</option>)}</select></label><button disabled={busy}>Filter cases</button></form>
    <p>{total} matching cases · 20 per page.</p>{items.map(item=><button key={item.case_id} className={`incident ${selected?.case_id===item.case_id?'selected':''}`} onClick={()=>void act(()=>reloadCase(item.case_id))}><strong>{item.title}</strong><span>{item.status} · {item.priority} · {item.revision} revisions</span></button>)}
    {next!==null&&<button disabled={busy} onClick={()=>void act(()=>loadList(next))}>Next case page</button>}{cursor>0&&<button disabled={busy} onClick={()=>void act(()=>loadList(0))}>First case page</button>}
    {selected&&<article className="case-detail"><h3>{selected.title} · revision {selected.revision}</h3><p>{selected.description||'No description.'}</p><p>Disposition: <strong>{selected.disposition}</strong> · status: <strong>{selected.status}</strong></p>
      <h3>Human assessment and workflow</h3><label>Disposition<select value={disposition} onChange={e=>setDisposition(e.target.value)}>{['undetermined','suspicious','benign','insufficient_evidence'].map(v=><option key={v} value={v}>{v}</option>)}</select></label>
      {selected.status!=='closed'&&<><label>Next status<select value={nextStatus} onChange={e=>setNextStatus(e.target.value)}>{(selected.status==='open'?['open','investigating']:selected.status==='investigating'?['investigating','resolved']:['resolved','closed']).map(v=><option key={v}>{v}</option>)}</select></label>{nextStatus==='closed'&&<label>Closure rationale<input value={rationale} onChange={e=>setRationale(e.target.value)} maxLength={1000}/></label>}<button disabled={busy} onClick={()=>void act(saveStatus)}>Save case assessment</button></>}
      {(selected.status==='resolved'||selected.status==='closed')&&<><label>Reopen rationale<input value={rationale} onChange={e=>setRationale(e.target.value)} maxLength={1000}/></label><button disabled={busy} onClick={()=>void act(reopen)}>Reopen for review</button></>}
      <h3>Tasks</h3>{selected.tasks.map(task=><p key={task.task_id}><button disabled={busy} onClick={()=>void act(()=>updateTask(task))}>{task.status==='done'?'Reopen task':'Complete task'}</button> {task.title} · {task.status}{task.completion_note&&<span className="muted"> · {task.completion_note}</span>}</p>)}
      <form onSubmit={e=>{e.preventDefault();void act(addTask);}}><label>Manual review task<input value={taskTitle} onChange={e=>setTaskTitle(e.target.value)} maxLength={200}/></label><button disabled={busy}>Add task</button></form>
      <h3>Notes</h3><p className="muted">Analyst-authored statements are preserved as statements; their truth is not independently verified.</p>{selected.notes.map(item=><blockquote key={item.note_id}>{item.text}</blockquote>)}<form onSubmit={e=>{e.preventDefault();void act(addNote);}}><label>Add note<textarea value={note} onChange={e=>setNote(e.target.value)} maxLength={4000}/></label><button disabled={busy}>Save note</button></form>
      <h3>Evidence bookmarks</h3>{selected.bookmarks.map(mark=><article key={mark.bookmark_id}><p>Run {mark.analysis_run_id} · observation {mark.event_id}</p><p>{mark.note||'No note'} · {mark.source_records.length} retained source reference(s)</p><button onClick={()=>onInspect(mark.analysis_run_id,mark.event_id)}>Inspect bookmarked observation</button></article>)}
      <h3>Linked external source rows</h3>{(selected.external_findings??[]).map(item=><article key={item.finding_id}><span className="pill">EXTERNAL CONTEXT</span><p>{item.tool} · source row {item.source_position} · {item.upstream_rule_title??'untitled source finding'}</p><p>{item.note} · row SHA-256 <code>{item.raw_row_sha256}</code></p><p className="muted">{item.interpretation}</p></article>)}
      {run&&incident&&<><label>Observation from selected incident<select value={bookmarkId} onChange={e=>setBookmarkId(e.target.value)}><option value="">Choose evidence observation</option>{evidenceIds.map(id=><option key={id} value={id}>{id}</option>)}</select></label><label>Bookmark note<input value={bookmarkNote} onChange={e=>setBookmarkNote(e.target.value)} maxLength={1000}/></label><button disabled={busy} onClick={()=>void act(bookmark)}>Bookmark verified source row</button></>}
      <h3>Frozen exports</h3><button disabled={busy} onClick={()=>void act(()=>download('json'))}>Export JSON and verify</button><button disabled={busy} onClick={()=>void act(()=>download('markdown'))}>Export readable Markdown</button>{verification&&<p role="status">{verification}</p>}
      <details><summary>Linked native reports</summary>{selected.linked_incidents.map(link=><p key={link.incident_id}>{link.summary} · run {link.analysis_run_id} · {link.incident_id}</p>)}</details>
    </article>}
    {error&&<p role="alert" className="error">{error}</p>}
  </section>;
}
