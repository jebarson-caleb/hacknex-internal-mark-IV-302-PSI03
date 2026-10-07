import {useEffect, useRef, useState} from 'react';
import {post, request} from './api';
import type {Analysis} from './types';

interface Navigation {start:string;end:string;stops:string[];frames:{id:string;cutoff:string}[];max_frames:number}
function epochMicros(value:string) {
  const millis=Date.parse(value);
  if(!Number.isFinite(millis)) return null;
  const fraction=(value.match(/T\d{2}:\d{2}:\d{2}\.(\d+)/)?.[1] ?? '').padEnd(6,'0');
  return BigInt(millis)*1000n+BigInt(fraction.slice(3,6));
}
export function Replay({run,onOpen}:{run:Analysis;onOpen:(run:Analysis)=>Promise<void>}) {
  const parentId=run.branch_kind==='retrospective_replay' ? run.parent_run_id! : run.analysis_run_id;
  const [nav,setNav]=useState<Navigation|null>(null);
  const [cutoff,setCutoff]=useState(run.cutoff);
  const [pending,setPending]=useState(false);
  const [error,setError]=useState('');
  const [duration,setDuration]=useState<number|null>(null);
  const generation=useRef(0);
  useEffect(()=>{++generation.current;setPending(false);setCutoff(run.cutoff);},[run.analysis_run_id]);
  useEffect(()=>{
    const id=++generation.current;
    void request<Navigation>(`/analyses/${parentId}/replay`).then(value=>{if(id===generation.current) setNav(value);})
      .catch(e=>{if(id===generation.current) setError(String(e.message));});
    return ()=>{++generation.current;};
  },[parentId]);
  function select(value:string) {++generation.current;setPending(false);setCutoff(value);setError('');}
  async function load(frameId?:string, original=false) {
    const id=++generation.current;setPending(true);setError('');
    try {
      const result=original ? {run:await request<Analysis>(`/analyses/${parentId}`),duration_seconds:null} :
        frameId ? await request<{run:Analysis;duration_seconds:number}>(`/replay-frames/${frameId}`) :
        await post<{run:Analysis;duration_seconds:number}>(`/analyses/${parentId}/replay`,{cutoff});
      if(id!==generation.current) return;
      const refreshed=await request<Navigation>(`/analyses/${parentId}/replay`);
      if(id!==generation.current) return;
      setNav(refreshed);setDuration(result.duration_seconds);setCutoff(result.run.cutoff);
      await onOpen(result.run);
    } catch(e) {if(id===generation.current) setError(e instanceof Error ? e.message : String(e));}
    finally {if(id===generation.current) setPending(false);}
  }
  const selectedTime=epochMicros(cutoff);
  const previous=nav?.stops.filter(t=>selectedTime!==null && epochMicros(t)!<selectedTime).at(-1);
  const next=nav?.stops.find(t=>selectedTime!==null && epochMicros(t)!>selectedTime);
  return <section aria-label="Retrospective event-time replay">
    <h2>Retrospective event-time replay</h2>
    <p>Fixed parent model, calibration, policy and operator context. This reconstructs event-time observations, not live monitoring or what an analyst knew historically.</p>
    <p>Currently displayed cutoff: <strong>{run.cutoff}</strong> · {run.branch_kind==='retrospective_replay' ? 'Retained replay frame' : 'Original parent'}</p>
    {nav && <>
      <p>Retrospective parent overview: {nav.start} → {nav.end}. Navigation includes distinct event times and 15-minute window closures; markers do not assert observed stages.</p>
      <label>Requested UTC cutoff<input value={cutoff} onChange={e=>select(e.target.value)} /></label>
      <button disabled={!previous} onClick={()=>select(previous!)}>Previous replay stop</button>
      <button disabled={!next} onClick={()=>select(next!)}>Next replay stop</button>
      <button disabled={pending} onClick={()=>void load()}>Run frame</button>
      <label>Retained replay frames<select value={run.branch_kind==='retrospective_replay' ? run.analysis_run_id : ''} onChange={e=>{if(e.target.value) void load(e.target.value);}}>
        <option value="">Choose retained frame</option>{nav.frames.map(f=><option key={f.id} value={f.id}>{f.cutoff}</option>)}
      </select></label>
      <p>Up to {nav.max_frames} distinct frames per parent, with equivalent requests reopened; no evidence is deleted.</p>
    </>}
    {pending && <p role="status">Requested cutoff {cutoff} pending. Findings below still belong to displayed cutoff {run.cutoff}.</p>}
    {error && <p role="alert">{error}</p>}
    {duration!==null && <p>Creation including source validation and inference: {duration.toFixed(3)} seconds. Reopening performs fresh verification.</p>}
    {run.branch_kind==='retrospective_replay' && <>
      <button onClick={()=>void load(undefined,true)}>Return to original replay parent</button>
      <details><summary>Persisted replay manifest</summary><pre>{JSON.stringify(run.replay_manifest,null,2)}</pre></details>
      <p>Unavailable anomaly windows remain unavailable until closure. No candidate means incident risk unavailable; it does not establish a safe endpoint.</p>
    </>}
  </section>;
}
