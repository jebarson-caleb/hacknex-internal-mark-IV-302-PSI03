import { useEffect, useState } from 'react';
import { post, request } from './api';
import type { Analysis } from './types';

type NativeCatalog={catalog_version:string;read_only:boolean;distinction:string;policy_versions:Record<string,unknown>;supported_actions_by_source:Record<string,string[]>;identity_and_time_gates:string[];stages:{stage_id:string;display_name:string;required_source_family:string;required_fields:string[];predicate:string;claim:string;missing_behavior:string;example:Record<string,unknown>}[];risk_and_limits:Record<string,unknown>};
type SigmaRule={rule:{id:string;title:string;description:string;status:string;author:string;references:string[];logsource:Record<string,string>;level:string;selection:unknown[]};yaml_text:string;rule_sha256:string;revision:number;origin:string;filename?:string};
type SigmaHit={event_id:string;matched_fields:Record<string,unknown>};
type SigmaExecution={execution_id:string;rule_id:string;rule_revision:number;rule_sha256:string;rule_title:string;analysis_run_id:string;hit_count:number;hits:SigmaHit[];result_sha256:string;interpretation:string};

export function Rules({run,onInspect}:{run:Analysis|null;onInspect:(runId:string,eventId:string)=>void}) {
  const [catalog,setCatalog]=useState<NativeCatalog|null>(null);const [rules,setRules]=useState<SigmaRule[]>([]);const [ruleId,setRuleId]=useState('');const [yamlText,setYamlText]=useState('');const [execution,setExecution]=useState<SigmaExecution|null>(null);const [error,setError]=useState('');const [busy,setBusy]=useState(false);
  const selected=rules.find(item=>item.rule.id===ruleId)||null;
  async function act(work:()=>Promise<void>) {setBusy(true);setError('');try{await work();}catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}
  async function load() {const [policy,items]=await Promise.all([request<NativeCatalog>('/rules/catalog'),request<SigmaRule[]>('/sigma/rules')]);setCatalog(policy);setRules(items);if(!ruleId&&items.length){setRuleId(items[0].rule.id);setYamlText(items[0].yaml_text);}}
  useEffect(()=>{void act(load);},[]);
  async function choose(id:string) {setRuleId(id);setExecution(null);if(!id){setYamlText('');return;}const item=await request<SigmaRule>(`/sigma/rules/${id}`);setYamlText(item.yaml_text);}
  async function saveRevision() {if(!selected)throw new Error('Choose a rule to revise');const value=await post<SigmaRule>(`/sigma/rules/${selected.rule.id}/revisions`,{expected_revision:selected.revision,yaml_text:yamlText});setRules(prev=>prev.map(item=>item.rule.id===value.rule.id?value:item));setYamlText(value.yaml_text);}
  async function createRule() {const value=await post<SigmaRule>('/sigma/rules',{yaml_text:yamlText});setRules(prev=>[value,...prev]);setRuleId(value.rule.id);setYamlText(value.yaml_text);setExecution(null);}
  async function execute() {if(!selected||!run)throw new Error('Select a retained run and Sigma-subset rule');setExecution(await post<SigmaExecution>(`/sigma/rules/${selected.rule.id}/execute`,{analysis_run_id:run.analysis_run_id,revision:selected.revision}));}

  return <>
    <section id="native-rule-catalog" aria-label="Native rule catalog"><h2>Native rule catalog · read only</h2>{catalog?<><p>{catalog.distinction}</p><p>Catalog {catalog.catalog_version} · native detector rule {String(catalog.policy_versions.detector_rule)} · feature policy {String(catalog.policy_versions.feature)}</p>
      <details><summary>Policy versions, supported source actions, and gates</summary><pre>{JSON.stringify({policy_versions:catalog.policy_versions,supported_actions_by_source:catalog.supported_actions_by_source,identity_and_time_gates:catalog.identity_and_time_gates,risk_and_limits:catalog.risk_and_limits},null,2)}</pre></details>
      {catalog.stages.map(stage=><article key={stage.stage_id}><h3>{stage.display_name} · {stage.claim}</h3><p>Source family: {stage.required_source_family}</p><p>Required fields: {stage.required_fields.join(', ')}</p><p>{stage.predicate}</p><p className="muted">Missing evidence: {stage.missing_behavior}</p><details><summary>Example canonical record</summary><pre>{JSON.stringify(stage.example,null,2)}</pre></details></article>)}
      <p className="muted">Native settings are not editable here. A single-event hunt match cannot satisfy a missing native stage.</p></>:<p>Loading read-only native policy catalog.</p>}</section>
    <section aria-label="Sigma subset hunt tester"><h2>Sigma subset · retained observation hunts</h2><p className="muted">TraceGuard implements the documented canonical-observation subset. It does not evaluate arbitrary Sigma rules or raw Windows/Sysmon logs.</p>
      <label>Original and local Sigma rules<select value={ruleId} onChange={e=>void act(()=>choose(e.target.value))}><option value="">Choose a rule</option>{rules.map(item=><option key={item.rule.id} value={item.rule.id}>{item.rule.title} · r{item.revision} · {item.origin}</option>)}</select></label>
      <button disabled={busy} onClick={()=>{setRuleId('');setYamlText('');setExecution(null);}}>Start a new local rule</button>
      {selected&&<><p>{selected.rule.description}</p><p>Author {selected.rule.author} · {selected.rule.status} · level {selected.rule.level} · revision {selected.revision} · SHA-256 <code>{selected.rule_sha256}</code></p><p>Log source: {selected.rule.logsource.product}/{selected.rule.logsource.service}. The six bundled rules are original TraceGuard hunting rules.</p></>}
      <label>Sigma YAML<textarea aria-label="Sigma YAML rule" value={yamlText} onChange={e=>setYamlText(e.target.value)} maxLength={65536} rows={18}/></label>
      {selected?<button disabled={busy} onClick={()=>void act(saveRevision)}>Save as immutable rule revision</button>:<button disabled={busy} onClick={()=>void act(createRule)}>Add local Sigma-subset rule</button>}
      <button disabled={busy||!run||!selected} onClick={()=>void act(execute)}>Run Sigma hunt on selected retained run</button>{run&&<p>Selected view: {run.analysis_run_id} · {run.branch_kind||'ordinary'} · cutoff {run.cutoff}</p>}
      {execution&&<article><h3>Hunt matches · {execution.hit_count}</h3><p>Rule {execution.rule_title} · revision {execution.rule_revision} · run {execution.analysis_run_id}</p><p>Result SHA-256 <code>{execution.result_sha256}</code></p><p className="muted">{execution.interpretation}</p>{execution.hits.map(hit=><article key={hit.event_id}><p>Hunt match · observation <code>{hit.event_id}</code></p><pre>{JSON.stringify(hit.matched_fields,null,2)}</pre><button disabled={busy} onClick={()=>onInspect(execution.analysis_run_id,hit.event_id)}>Inspect exact observation and source rows</button></article>)}</article>}
      {error&&<p role="alert" className="error">{error}</p>}
    </section>
  </>;
}
