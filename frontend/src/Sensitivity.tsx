import { useState } from 'react';
import type { Analysis, Incident, Sensitivity as Comparison } from './types';

export function EvidenceSelection({run,item,busy,onRun}:{run:Analysis;item:Incident;busy:boolean;onRun:(ids:string[],note:string)=>void}) {
  const [ids,setIds]=useState<string[]>([]);
  const [note,setNote]=useState('');
  return <details><summary>Evidence sensitivity</summary>
    <p>What would this detector conclude without selected evidence? Excluding a canonical observation excludes every duplicate source reference. Originals and fitted training/calibration remain intact. This tests evidence availability, not causality or prevention.</p>
    {run.branch_kind==='evidence_sensitivity' ? <p>Nested exclusions are unavailable. Open the ordinary parent to start another experiment.</p> : <>
      {item.selected_evidence.map(id => {
        const stage=item.stages.find(s => s.evidence_event_ids.includes(id));
        const label=stage?.stage_id ?? 'mount';
        return <label className="check" key={id}><input type="checkbox" disabled={busy} checked={ids.includes(id)}
          onChange={e => setIds(e.target.checked ? [...ids,id] : ids.filter(value => value!==id))}/>Exclude {label} observation {id}</label>;
      })}
      <label>Experiment note<input value={note} maxLength={500} disabled={busy} onChange={e=>setNote(e.target.value)}/></label>
      <button disabled={busy || ids.length>100} onClick={()=>onRun(ids,note)}>Rerun without selected evidence</button>
      <p>Cutoff, model, calibration, policy and operator context are fixed by this parent. An empty selection performs a no-op reproduction.</p>
    </>}
  </details>;
}

export function SensitivityResult({result,busy,onOpen,onDownload}:{result:Comparison;busy:boolean;onOpen:(run:string,incident?:string)=>void;onDownload:()=>void}) {
  const m=result.manifest;
  function candidate(item:Incident|null|undefined, run:string) {
    if (!item) return <p>No candidate; incident risk unavailable. This does not establish a safe endpoint.</p>;
    return <><p>{item.decision} · heuristic risk {item.risk.score} · {item.decision_reason}</p>
      <p>Supported stages: {item.stages.map(s=>s.stage_id).join(', ')}</p>
      <p>Current evidence: {item.selected_evidence.join(', ')}</p>
      <details><summary>Predicates, risk components and anomaly availability</summary><pre>{JSON.stringify({stages:item.stages,risk:item.risk,missing:item.missing_evidence},null,2)}</pre></details>
      <button disabled={busy} onClick={()=>onOpen(run,item.incident_id)}>Open {run===m.parent_run_id ? 'parent' : 'child'} candidate and evidence</button>
    </>;
  }
  return <section className="sensitivity-result" aria-label="Evidence sensitivity comparison"><h2>Evidence sensitivity · before / after</h2>
    <p>Experimental child {m.child_run_id} · parent {m.parent_run_id} · fixed cutoff {m.cutoff} · analysis/validation duration {result.duration_seconds.toFixed(3)}s</p>
    <p>Excluded canonical observations: {m.excluded_event_ids.join(', ') || 'None'}. Effective fingerprint {m.effective_fingerprint}</p>
    {result.empty_result && <p>No complete chain reconstructed from the remaining observations. No child candidate or incident risk is available; this does not establish a safe endpoint.</p>}
    {result.differences.map((diff,index)=><article key={index}><h3>Correspondence: {diff.status}</h3>
      {diff.status==='ambiguous' ? <p>Ambiguous overlapping episodes: {diff.possible_child_ids?.join(', ')}. No forced match.</p> : <>
        <p>Lost stages: {diff.lost_stages?.join(', ') || 'None'} · new stages: {diff.new_stages?.join(', ') || 'None'}</p>
        <p>Surviving evidence: {diff.surviving_evidence?.join(', ') || 'None'} · removed support: {diff.removed_support?.join(', ') || 'None'} · new support: {diff.new_support?.join(', ') || 'None'}</p>
        <div className="panels"><div><h3>Before</h3>{candidate(diff.before,m.parent_run_id)}</div><div><h3>After</h3>{candidate(diff.after,m.child_run_id)}</div></div>
        <details><summary>Before / after graph and links</summary><pre>{JSON.stringify({before:diff.graph_before,after:diff.graph_after},null,2)}</pre></details>
      </>}
    </article>)}
    <button disabled={busy} onClick={()=>onOpen(m.parent_run_id,result.before_candidates[0]?.incident_id)}>Return to unchanged parent</button>
    <button disabled={busy} onClick={onDownload}>Download sensitivity comparison</button>
    <p>Evidence availability experiment. Training/calibration are fixed. Scores may increase, decrease or become unavailable. Raw source records are omitted from export; verification resolves retained originals. No source authenticity or causal proof is claimed.</p>
  </section>;
}
