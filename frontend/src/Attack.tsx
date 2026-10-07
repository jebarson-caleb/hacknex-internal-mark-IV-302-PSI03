import { useEffect, useState } from 'react';
import { request } from './api';
import type { Analysis } from './types';

type SourceRow={source_position:number;source_row_sha256:string;source_file_sha256:string};
type Mapping={technique_id:string;technique_name:string;tactic:string;analysis_run_id:string;incident_id:string;supporting_stage_ids:string[];supporting_observation_count:number;evidence:{event_id:string;event_time_utc:string;action:string;source_rows:SourceRow[]}[];interpretation:string;mapping_version:string;source_url:string;criteria:string};
type View={view_id:string;analysis_run_id:string;branch_kind:string;cutoff_utc:string;mapping_version:string;result_sha256:string;mappings:Mapping[];missing_support:{technique_id:string;technique_name:string;reason:string;criteria:string}[];unmapped_native_stages:{incident_id:string;stage_id:string;interpretation:string}[];external_upstream_labels:{included:boolean;interpretation:string};interpretation:string;attribution:string};

function download(blob:Blob,name:string){const url=URL.createObjectURL(blob);const anchor=document.createElement('a');anchor.href=url;anchor.download=name;anchor.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}

export function Attack({run,onInspect}:{run:Analysis|null;onInspect:(runId:string,eventId:string)=>void}){
  const [view,setView]=useState<View|null>(null);const [busy,setBusy]=useState(false);const [error,setError]=useState('');
  useEffect(()=>{let active=true;setView(null);setError('');if(run){setBusy(true);void request<View>(`/analyses/${encodeURIComponent(run.analysis_run_id)}/attack`).then(value=>{if(active)setView(value);}).catch(reason=>{if(active)setError(reason instanceof Error?reason.message:String(reason));}).finally(()=>{if(active)setBusy(false);});}return()=>{active=false;};},[run?.analysis_run_id]);
  async function exportLayer(){if(!run)throw new Error('Select a retained run or replay frame');const response=await fetch(`/api/analyses/${encodeURIComponent(run.analysis_run_id)}/navigator-layer`);if(!response.ok){const body=await response.json().catch(()=>({detail:response.statusText}));throw new Error(body.detail??response.statusText);}download(await response.blob(),`traceguard-navigator-layer-${run.analysis_run_id}.json`);}
  return <section id="attack-view" aria-label="Evidence-linked ATT&CK view"><h2>ATT&amp;CK · evidence-linked technique view</h2>
    <p className="muted">Only verified native evidence in the selected run/frame can create these two mappings. External ATT&amp;CK labels remain attached to their source findings and do not expand this view.</p>
    {!run&&<p>Select a retained run or replay frame to review its evidence-linked techniques.</p>}{busy&&<p role="status">Verifying selected-view evidence…</p>}{error&&<p role="alert" className="error">{error}</p>}
    {view&&<><p>View {view.view_id} · {view.branch_kind} · cutoff {view.cutoff_utc} · mapping {view.mapping_version}</p><p>{view.interpretation}</p><button onClick={()=>void exportLayer()}>Export current-view Navigator v4.3 layer JSON</button><p className="muted">Navigator score is capped distinct supporting-observation count, not risk, attack probability, or detection confidence. Export omits user names, paths, and raw log text. {view.attribution}</p>
      {view.mappings.map(item=><article key={`${item.technique_id}-${item.incident_id}`}><h3>{item.technique_id} · {item.technique_name}</h3><p>Tactic: {item.tactic} · native stages: {item.supporting_stage_ids.join(', ')} · distinct supporting observations: {item.supporting_observation_count}</p><p>{item.interpretation}</p><p>Criteria: {item.criteria}</p><p>Mapping source: <a href={item.source_url} target="_blank" rel="noreferrer">MITRE ATT&amp;CK technique reference</a> · {item.mapping_version}</p>{item.evidence.map(evidence=><article key={evidence.event_id}><p>{evidence.action} · {evidence.event_time_utc} · event <code>{evidence.event_id}</code></p>{evidence.source_rows.map(source=><p key={`${source.source_file_sha256}-${source.source_position}`}>Verified source row {source.source_position} · source SHA-256 <code>{source.source_row_sha256}</code></p>)}<button onClick={()=>onInspect(view.analysis_run_id,evidence.event_id)}>Inspect linked native evidence</button></article>)}</article>)}
      {view.missing_support.map(item=><article key={item.technique_id}><h3>{item.technique_id} · {item.technique_name} · not mapped</h3><p>{item.reason}</p><p className="muted">{item.criteria}</p></article>)}
      {view.unmapped_native_stages.map((item,index)=><p key={`${item.incident_id}-${index}`} className="muted">Unmapped native stage {item.stage_id}: {item.interpretation}</p>)}
      <details><summary>External label boundary and view hash</summary><p>{view.external_upstream_labels.interpretation}</p><p>Mapping view SHA-256 <code>{view.result_sha256}</code></p></details>
    </>}
  </section>;
}
