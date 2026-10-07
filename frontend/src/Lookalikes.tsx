import { useEffect, useRef, useState } from 'react';
import { post, request } from './api';
import type { Analysis, Baseline, Incident } from './types';

type Page = {items: Incident[]; total: number; next_cursor: number|null};
type Saved = {comparison_id:string; analyst_note:string; kind:string};
type Arm = Analysis & {dataset_id:string; origin:string; authorization_context_snapshot:unknown; history_probes:unknown; window_scores:unknown;
  observations:{event_id:string;action:string;event_time_utc:string}[];signal_display_limit:string};
type Result = {comparison_id:string; kind:string; analyst_note:string; left:Arm; right:Arm;
  actual_changed_inputs:string[]; declared_changed_inputs:string[]; compatibility:unknown; limits:string;
  evaluation_annotation:{left?:string;right?:string;provenance?:string;fixture_version?:string}|null;
  correspondence:{left_incident_id:string|null;right_incident_id:string|null;possible_right_ids?:string[];status:string;risk_delta:number|null;decision_changed:boolean|null;explanation?:string}[];
  total:number;next_cursor:number|null};

export function Lookalikes({baselines, onEvidence, onRunEvidence, onOpen}: {baselines:Baseline[];
  onEvidence:(incidentId:string,eventId:string)=>void; onRunEvidence:(runId:string,eventId:string)=>void; onOpen:(runId:string,incidentId?:string)=>void}) {
  const [saved,setSaved]=useState<Saved[]>([]);
  const [listCursor,setListCursor]=useState<number|null>(null);
  const [selection,setSelection]=useState('');
  const [result,setResult]=useState<Result|null>(null);
  const [pages,setPages]=useState<[Page|null,Page|null]>([null,null]);
  const [busy,setBusy]=useState(false);
  const [error,setError]=useState('');
  const [baseline,setBaseline]=useState('');
  const [left,setLeft]=useState(''); const [right,setRight]=useState('');
  const [kind,setKind]=useState('context-only'); const [changes,setChanges]=useState('authorization_context_snapshot');
  const [validation,setValidation]=useState<unknown>(null);
  const generation=useRef(0);

  async function refresh(cursor=0) {
    const value=await request<{items:Saved[];next_cursor:number|null}>(`/lookalikes?cursor=${cursor}`);
    setSaved(old=>cursor ? [...old,...(value.items ?? [])] : value.items ?? []); setListCursor(value.next_cursor ?? null);
  }
  async function open(id:string) {
    const token=++generation.current;
    setSelection(id); setResult(null); setPages([null,null]); setError(''); setBusy(true);
    const params=new URLSearchParams(window.location.search);
    if(id) params.set('lookalike',id); else params.delete('lookalike');
    window.history.replaceState(null,'',window.location.pathname+(params.size ? '?'+params : ''));
    if(!id) {setBusy(false);return;}
    try {
      const value=await request<Result>(`/lookalikes/${encodeURIComponent(id)}`);
      const candidates=await Promise.all([value.left,value.right].map(arm=>request<Page>(`/analyses/${arm.analysis_run_id}/candidates`)));
      if(token!==generation.current) return;
      setResult(value); setPages([candidates[0],candidates[1]]);
    } catch(e) {if(token===generation.current) setError(e instanceof Error ? e.message : String(e));}
    finally {if(token===generation.current) setBusy(false);}
  }
  async function action(work:()=>Promise<void>) {
    const token=generation.current;
    setBusy(true);setError('');
    try {await work();} catch(e) {if(token===generation.current) setError(e instanceof Error ? e.message : String(e));}
    finally {if(token===generation.current) setBusy(false);}
  }
  useEffect(()=>{
    void refresh().catch(e=>setError(String(e)));
    const id=new URLSearchParams(window.location.search).get('lookalike');
    if(id) void open(id);
    return ()=>{++generation.current;};
  },[]);

  async function candidatePage(index:number, arm:Arm, cursor=0) {
    const token=generation.current;
    const value=await request<Page>(`/analyses/${arm.analysis_run_id}/candidates?cursor=${cursor}`);
    if(token===generation.current) setPages(old=>index===0 ? [value,old[1]] : [old[0],value]);
  }
  return <section aria-label="Benign look-alikes"><h2>Benign look-alikes</h2>
    <p>Compare retained observations, declarations and actual decisions. Missing authorization does not prove malicious intent. Synthetic truth is separate from detection.</p>
    <label>Lab baseline<select value={baseline} disabled={busy} onChange={e=>setBaseline(e.target.value)}><option value="">Explicitly select a fitted baseline</option>
      {baselines.map(b=><option key={b.baseline_id} value={b.baseline_id}>{b.baseline_id}</option>)}</select></label>
    <button disabled={busy || !baseline} onClick={()=>void action(async()=>{
      const token=generation.current;
      setResult(null);setPages([null,null]);setValidation(null);
      const lab=await post<{pairs:{comparison_id:string}[];validation_cases:unknown}>('/lookalike-labs',{baseline_id:baseline,seed:17});
      if(token!==generation.current) return;
      await refresh();
      if(token!==generation.current) return;
      setValidation(lab.validation_cases);await open(lab.pairs[0].comparison_id);
    })}>Load synthetic look-alike lab (no fitting)</button>
    <label>Saved look-alike comparison<select value={selection} onChange={e=>void open(e.target.value)}>
      <option value="">Choose a retained pair</option>{selection && !saved.some(s=>s.comparison_id===selection) && <option value={selection}>{selection}</option>}
      {saved.map(s=><option key={s.comparison_id} value={s.comparison_id}>{s.analyst_note || s.comparison_id} · {s.kind}</option>)}</select></label>
    {listCursor!==null && <button disabled={busy} onClick={()=>void action(()=>refresh(listCursor))}>More saved comparisons</button>}
    <details><summary>Compare selected ordinary run IDs</summary>
      <label>Left retained run<input value={left} maxLength={100} onChange={e=>setLeft(e.target.value)}/></label>
      <label>Right retained run<input value={right} maxLength={100} onChange={e=>setRight(e.target.value)}/></label>
      <label>Comparison kind<select value={kind} onChange={e=>setKind(e.target.value)}><option value="context-only">Controlled context</option><option value="scenario">Scenario</option></select></label>
      <label>Declared changed input fields (comma separated)<input value={changes} onChange={e=>setChanges(e.target.value)} maxLength={500}/></label>
      <button disabled={busy || !left || !right} onClick={()=>void action(async()=>{
        const token=generation.current;
        setResult(null);setPages([null,null]);
        const value=await post<Result>('/lookalikes',{left_run_id:left,right_run_id:right,kind,declared_changed_inputs:changes.split(',').map(s=>s.trim()).filter(Boolean)});
        if(token!==generation.current) return;
        await refresh();
        if(token!==generation.current) return;
        await open(value.comparison_id);
      })}>Create retained comparison</button>
    </details>
    {busy && <p role="status">Loading comparison…</p>}
    {error && <p role="alert">{error} <button disabled={busy} onClick={()=>void (selection ? open(selection) : action(()=>refresh()))}>Retry comparison</button></p>}
    {validation!==null && <details><summary>Lab validation outcomes</summary><pre>{JSON.stringify(validation,null,2)}</pre></details>}
    {result && <>
      <p>{result.analyst_note} · {result.kind} · comparison {result.comparison_id}</p>
      <p>Actual changed inputs: {result.actual_changed_inputs.join(', ') || 'None'}.</p>
      <details><summary>Controlled compatibility and declared changes</summary><pre>{JSON.stringify({checks:result.compatibility,declared:result.declared_changed_inputs},null,2)}</pre></details>
      {result.evaluation_annotation && <aside aria-label="Synthetic evaluation annotation"><strong>Synthetic evaluation annotation · outside inference</strong>
        <p>{result.evaluation_annotation.provenance} · {result.evaluation_annotation.fixture_version}. Curated development cases; no FPR or accuracy percentage.</p></aside>}
      <div className="panels">{([result.left,result.right] as const).map((arm,index)=><section key={`${result.comparison_id}-${index}`} aria-label={index===0 ? 'Left comparison arm' : 'Right comparison arm'}>
        <h3>{index===0 ? 'Left' : 'Right'} retained analysis</h3>
        <p>{arm.analysis_run_id} · {arm.mode} · {arm.origin} · dataset {arm.dataset_id}</p>
        <p>Frozen cutoff {arm.cutoff} · baseline {arm.baseline_id || 'Unavailable; rules-only history'}.</p>
        <button disabled={busy} onClick={()=>onOpen(arm.analysis_run_id)}>Open {index===0 ? 'left' : 'right'} retained run</button>
        <p>{arm.incident_count} alerts · {arm.review_count ?? 0} review items · {arm.partial_count} partial observations.</p>
        <details><summary>Frozen policy, threshold and calibration</summary><pre>{JSON.stringify({config:arm.config,calibration:arm.calibration},null,2)}</pre></details>
        <details><summary>Actual historical eligibility and model windows</summary><pre>{JSON.stringify({history:arm.history_probes,windows:arm.window_scores},null,2)}</pre></details>
        <details><summary>Frozen observed inputs and source contents</summary><p>{arm.signal_display_limit}</p><pre>{JSON.stringify(arm.observations,null,2)}</pre>
          {arm.observations.map(event=><button key={event.event_id} disabled={busy} onClick={()=>onRunEvidence(arm.analysis_run_id,event.event_id)}>Inspect {index===0 ? 'left' : 'right'} observed {event.action} at {event.event_time_utc}</button>)}
        </details>
        <details><summary>Frozen operator declarations</summary><pre>{JSON.stringify(arm.authorization_context_snapshot,null,2)}</pre></details>
        {pages[index]?.total===0 && <p>Absent candidate: incident risk unavailable. This does not establish safety.</p>}
        {pages[index]?.items.map(item=><article key={item.incident_id}>
          <p><strong>{item.decision}</strong> · {item.stages.length}/3 supported stages · risk {item.risk.score} · threshold {item.risk.threshold ?? 'See structural policy'}</p>
          {result.evaluation_annotation?.[index===0 ? 'left' : 'right']==='benign' && item.decision==='incident' && <p>Remaining false-positive alert on this declared benign synthetic fixture.</p>}
          <p>{item.user_id} / {item.device_id} · {item.decision_reason}</p><p>{item.missing_evidence.join('; ')}</p>
          <details><summary>Actual copy context match predicates and event time</summary><pre>{JSON.stringify({authorization:item.authorization,copy:item.stages.find(s=>s.stage_id==='transfer')},null,2)}</pre></details>
          <details><summary>Risk components and anomaly availability</summary><pre>{JSON.stringify(item.risk,null,2)}</pre></details>
          {item.stages.map(stage=><div key={stage.stage_id}><p>{stage.stage_name} · {stage.start_time_utc}</p>{stage.evidence_event_ids.map(id=><button key={id} disabled={busy} onClick={()=>onEvidence(item.incident_id,id)}>Inspect {index===0 ? 'left' : 'right'} {stage.stage_id} source</button>)}</div>)}
          {item.context_event_ids.map(id=><button key={id} disabled={busy} onClick={()=>onEvidence(item.incident_id,id)}>Inspect {index===0 ? 'left' : 'right'} corroborating mount source</button>)}
          <button disabled={busy} onClick={()=>onOpen(arm.analysis_run_id,item.incident_id)}>Open {index===0 ? 'left' : 'right'} timeline and graph</button>
          <a href={`/api/incidents/${item.incident_id}/report`} download>JSON incident report</a>{' · '}
          <a href={`/api/incidents/${item.incident_id}/report?format=markdown`} download>Markdown incident report</a>
        </article>)}
        <p>{pages[index]?.total ?? 0} retained candidates · 20 per page.</p>
        {pages[index]?.next_cursor!=null && <button disabled={busy} onClick={()=>void action(()=>candidatePage(index,arm,pages[index]!.next_cursor!))}>Next {index===0 ? 'left' : 'right'} candidate page</button>}
        <button disabled={busy} onClick={()=>void action(()=>candidatePage(index,arm))}>First {index===0 ? 'left' : 'right'} candidate page</button>
      </section>)}</div>
      <h3>Verified episode correspondence</h3><p>Shared episode identity requires family, scoped identities, overlapping time and evidence. Different scenario subjects remain unmatched.</p>
      {result.correspondence.map((row,i)=><p key={`${row.left_incident_id}-${row.right_incident_id}-${i}`}>{row.status} · left {row.left_incident_id ?? 'Absent'} · right {row.right_incident_id ?? 'Absent'} · possible matches {row.possible_right_ids?.join(', ') || 'None'} · risk delta {row.risk_delta ?? 'Unavailable'} · decision {row.decision_changed===null ? 'Unavailable' : row.decision_changed ? 'changed' : 'unchanged'}. {row.explanation}</p>)}
      {result.next_cursor!==null && <button disabled={busy} onClick={()=>void action(async()=>{
        const token=generation.current;const value=await request<Result>(`/lookalikes/${result.comparison_id}?cursor=${result.next_cursor}`);
        if(token===generation.current) setResult(value);
      })}>Next correspondence page</button>}
      <p>{result.limits}</p>
    </>}
  </section>;
}
