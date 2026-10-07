import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { post, request } from './api';
import type { Analysis, Baseline, Dataset, EntityGraph, Evaluation, EventRow, Evidence, Incident, Quality, Stage, Sensitivity } from './types';
import './style.css';
import { EntityGraph as LinkedGraph } from './EntityGraph';
import { EvidenceSelection, SensitivityResult } from './Sensitivity';
import { Lookalikes } from './Lookalikes';
import { Replay } from './Replay';
import { Cases } from './Cases';
import { Hunts } from './Hunts';
import { Rules } from './Rules';
import { Intelligence } from './Intelligence';
import { ExternalFindings } from './ExternalFindings';
import { Attack } from './Attack';
import { EvaluationReview } from './EvaluationReview';

export default function App() {
  const [datasets, setDatasets] = useState<Dataset[]>([]);
  const [dataset, setDataset] = useState<Dataset | null>(null);
  const [quality, setQuality] = useState<Quality | null>(null);
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selected, setSelected] = useState<Incident | null>(null);
  const [evidence, setEvidence] = useState<Evidence | null>(null);
  const [mounts, setMounts] = useState<EventRow[]>([]);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [cursor, setCursor] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [context, setContext] = useState('[]');
  const [sourceType, setSourceType] = useState('auth');
  const [sourceId, setSourceId] = useState('auth');
  const [environment, setEnvironment] = useState('local');
  const [timezone, setTimezone] = useState('');
  const [append, setAppend] = useState(true);
  const [baselines,setBaselines] = useState<Baseline[]>([]);
  const [baselineId,setBaselineId] = useState('');
  const [mode,setMode] = useState('rules-only');
  const [trainingId,setTrainingId] = useState('');
  const [calibrationId,setCalibrationId] = useState('');
  const [provenance,setProvenance] = useState('');
  const [graph,setGraph] = useState<EntityGraph|null>(null);
  const [runHistory,setRunHistory] = useState<Analysis[]>([]);
  const [authorization,setAuthorization] = useState('[]');
  const [aliasContext,setAliasContext] = useState('[]');
  const [search,setSearch] = useState('');
  const [decision,setDecision] = useState('');
  const [candidateCursor,setCandidateCursor] = useState<number|null>(null);
  const [candidateTotal,setCandidateTotal] = useState(0);
  const [stageIds,setStageIds] = useState<string[]>([]);
  const [includeRaw,setIncludeRaw] = useState(false);
  const [evaluation,setEvaluation] = useState<Evaluation|null>(null);
  const [comparison,setComparison] = useState<Sensitivity|null>(null);
  const [actionMessage,setActionMessage] = useState('');

  const selectionGeneration=useRef(0);
  const [replayNavigationEpoch,setReplayNavigationEpoch]=useState(0);

  async function refresh() {
    const [data,models] = await Promise.all([request<Dataset[]>('/datasets'),request<Baseline[]>('/baselines')]);
    setDatasets(data); setBaselines(models);
  }
  async function perform(work: () => Promise<void>) {
    setBusy(true); setError('');
    try { await work(); } catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }
  useEffect(() => { void perform(async () => {
    await refresh();
    const params = new URLSearchParams(window.location.search);
    const runId = params.get('run');
    if (runId) {
      const saved = await request<Analysis & {dataset_id:string}>(`/analyses/${encodeURIComponent(runId)}`);
      const all = await request<Dataset[]>('/datasets');
      const value = all.find(d => d.id===saved.dataset_id);
      if (!value) throw new Error('Saved run dataset unavailable');
      await choose(value); await openRun(saved);
      const incidentId=params.get('incident');
      if (incidentId) await openIncident(await request<Incident>(`/incidents/${encodeURIComponent(incidentId)}`),saved.analysis_run_id);
      const comparisonId=params.get('comparison') ?? saved.comparison_id;
      if (comparisonId) {
        const result=await request<Sensitivity>(`/sensitivities/${encodeURIComponent(comparisonId)}`);
        if (![result.manifest.parent_run_id,result.manifest.child_run_id].includes(runId)) throw new Error('Comparison does not belong to selected run');
        setComparison(result); remember(runId,incidentId ?? undefined,comparisonId);
      }
    }
  }); }, []);

  function remember(runId?:string, incidentId?:string, comparisonId?:string) {
    const params=new URLSearchParams();
    const lookalike=new URLSearchParams(window.location.search).get('lookalike');
    if(lookalike) params.set('lookalike',lookalike);
    if (runId) params.set('run',runId);
    if (incidentId) params.set('incident',incidentId);
    if (comparisonId) params.set('comparison',comparisonId);
    window.history.replaceState(null,'',window.location.pathname+(params.size ? '?'+params : ''));
  }
  async function candidates(runId:string, offset=0, query=search, filter=decision) {
    const generation=selectionGeneration.current;
    const result = await request<{items:Incident[];total:number;next_cursor:number|null}>(`/analyses/${runId}/candidates?cursor=${offset}&limit=20&search=${encodeURIComponent(query)}${filter ? '&decision='+filter : ''}`);
    if(generation!==selectionGeneration.current) return;
    setIncidents(result.items); setCandidateTotal(result.total); setCandidateCursor(result.next_cursor);
  }
  async function openRun(saved:Analysis) {
    const generation=++selectionGeneration.current;
    setEvidence(null);
    const observationPath=saved.branch_kind==='retrospective_replay' ? `/analyses/${saved.analysis_run_id}/observations` : `/events?dataset_id=${encodeURIComponent(saved.dataset_id ?? dataset?.id ?? '')}`;
    const [result,rows,retainedComparison]=await Promise.all([
      request<{items:Incident[];total:number;next_cursor:number|null}>(`/analyses/${saved.analysis_run_id}/candidates?cursor=0&limit=20&search=`),
      request<{items:EventRow[];next_cursor:number|null}>(observationPath),
      saved.comparison_id ? request<Sensitivity>(`/sensitivities/${saved.comparison_id}`) : Promise.resolve(null),
    ]);
    if(generation!==selectionGeneration.current) return;
    setComparison(retainedComparison);setEvaluation(null);setMode(saved.mode);setBaselineId(saved.baseline_id ?? '');
    setAnalysis(saved);setSelected(null);setEvidence(null);setGraph(null);setMounts([]);setStageIds([]);setSearch('');setDecision('');
    setIncidents(result.items);setCandidateTotal(result.total);setCandidateCursor(result.next_cursor);
    setEvents(rows.items);setCursor(rows.next_cursor);remember(saved.analysis_run_id);
  }
  async function openIncident(item:Incident, runId=analysis?.analysis_run_id) {
    if (item.analysis_run_id!==runId) throw new Error('Incident does not belong to selected retained run');
    const generation=++selectionGeneration.current;
    setSelected(item); setEvidence(null); setMounts([]); setGraph(null); setStageIds([]);
    const contextEvents=await Promise.all(item.context_event_ids.map(id => request<Evidence>(`/incidents/${item.incident_id}/source/${encodeURIComponent(id)}`)));
    if(generation!==selectionGeneration.current) return;
    setMounts(contextEvents.map(e => e.event)); remember(runId,item.incident_id,comparison?.comparison_id);
  }
  async function loadGraph(item:Incident,limit=200) {
    const generation=selectionGeneration.current;
    const result=await request<EntityGraph>(`/incidents/${item.incident_id}/graph${limit===200 ? '' : '?limit='+limit}`);
    if(generation===selectionGeneration.current) setGraph(result);
  }
  async function selectStage(stage:Stage) {
    if (!selected) return;
    const generation=selectionGeneration.current;
    setStageIds(stage.evidence_event_ids);
    await loadGraph(selected,500);
    if(generation===selectionGeneration.current) await inspect(stage.evidence_event_ids[0]);
  }
  async function download(format:string) {
    if (!selected) return;
    await perform(async () => {
      const response=await fetch(`/api/incidents/${selected.incident_id}/report?format=${format}&include_raw=${includeRaw}`);
      if (!response.ok) {const body=await response.json(); throw new Error(String(body.detail));}
      const url=URL.createObjectURL(await response.blob());
      const anchor=document.createElement('a'); anchor.href=url; anchor.download=`traceguard-${selected.incident_id}.${format==='markdown' ? 'md' : 'json'}`;
      anchor.click(); setTimeout(() => URL.revokeObjectURL(url),1000);
    });
  }

  async function page(datasetId: string, offset = 0) {
    const generation=selectionGeneration.current;
    const result = await request<{items: EventRow[]; next_cursor: number | null}>(`/events?dataset_id=${encodeURIComponent(datasetId)}&cursor=${offset}`);
    if(generation===selectionGeneration.current) {setEvents(result.items); setCursor(result.next_cursor);}
  }
  async function retainedPage(runId:string, offset=0) {
    const generation=selectionGeneration.current;
    const result=await request<{items:EventRow[];next_cursor:number|null}>(`/analyses/${runId}/observations?cursor=${offset}`);
    if(generation===selectionGeneration.current) {setEvents(result.items);setCursor(result.next_cursor);}
  }
  async function choose(value: Dataset) {
    ++selectionGeneration.current;
    setComparison(null); setActionMessage('');
    setDataset(value); setEnvironment(value.environment); setAnalysis(null); setIncidents([]); setSelected(null); setEvidence(null); setMounts([]); setGraph(null);
    setQuality(null); setEvents([]); setCursor(null); setContext('[]'); setEvaluation(null); setRunHistory([]); remember();
    const [q, resources, savedRuns, auth, aliases] = await Promise.all([
      request<Quality>(`/datasets/${value.id}/quality`), request<unknown>(`/datasets/${value.id}/resources`),
      request<Analysis[]>(`/datasets/${value.id}/analyses`), request<unknown>(`/datasets/${value.id}/authorizations`),request<unknown>(`/environments/${encodeURIComponent(value.environment)}/aliases`),
    ]);
    setRunHistory(savedRuns); setAuthorization(JSON.stringify(auth,null,2)); setAliasContext(JSON.stringify(aliases,null,2)); setQuality(q); setContext(JSON.stringify(resources, null, 2)); await page(value.id);
  }
  async function demo(variant: string) {
    setActionMessage('');
    await perform(async () => {
      const result = await post<{dataset: Dataset}>('/datasets/demo', {variant, seed: 17});
      setMode('rules-only'); setBaselineId('');
      await refresh(); await choose(result.dataset);
    });
  }
  async function chronologicalDemo() {
    setActionMessage('');
    await perform(async () => {
      const data = await post<{training:Dataset;calibration:Dataset;test:Dataset}>('/datasets/chronological-demo',{seed:17,users:6,events:1200});
      setTrainingId(data.training.id); setCalibrationId(data.calibration.id);
      setProvenance('Explicitly selected generated benign days 1–14 and 15–21; operator declaration');
      setMode('rules-only'); setBaselineId(''); await refresh(); await choose(data.test);
    });
  }
  async function upload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = new FormData(event.currentTarget);
    form.set('source_type', sourceType); form.set('source_id', sourceId); form.set('environment_id', environment);
    if (timezone) form.set('source_timezone', timezone);
    if (append && dataset) form.set('dataset_id', dataset.id);
    await perform(async () => {
      const result = await request<{dataset: Dataset}>('/datasets/upload', {method: 'POST', body: form});
      await refresh(); await choose(result.dataset);
    });
  }
  async function run() {
    if (!dataset) return;
    await perform(async () => {
      setSelected(null); setEvidence(null); setAnalysis(null); setIncidents([]);
      setGraph(null);
      const result = await post<Analysis>('/analyses', {dataset_id: dataset.id, mode, baseline_id:baselineId || null});
      await openRun(result); setRunHistory(await request<Analysis[]>(`/datasets/${dataset.id}/analyses`));
    });
  }
  async function openGraphFromTop() {
    setActionMessage('');
    await perform(async () => {
      if (!dataset && !analysis) {
        setActionMessage('Choose a seeded dataset or upload logs before opening a graph.');
        return;
      }
      let activeRun: Analysis;
      if (analysis) {
        activeRun = analysis;
      } else {
        activeRun = await post<Analysis>('/analyses', {dataset_id:dataset!.id,mode,baseline_id:baselineId || null});
        await openRun(activeRun);
        setRunHistory(await request<Analysis[]>(`/datasets/${dataset!.id}/analyses`));
      }
      const result = await request<{items:Incident[];total:number;next_cursor:number|null}>(`/analyses/${encodeURIComponent(activeRun.analysis_run_id)}/candidates?cursor=0&limit=20&search=`);
      setIncidents(result.items); setCandidateTotal(result.total); setCandidateCursor(result.next_cursor);
      const item = selected?.analysis_run_id === activeRun.analysis_run_id ? selected : result.items[0];
      if (!item) {
        setActionMessage('This run has no incident or review candidates, so there is no incident graph to display.');
        return;
      }
      await openIncident(item,activeRun.analysis_run_id);
      await loadGraph(item);
      setActionMessage(`Opened the entity graph for ${item.user_id} on ${item.device_id}.`);
    });
  }
  async function showEvidence(path:string) {
    const generation=selectionGeneration.current;
    setEvidence(null);const result=await request<Evidence>(path);
    if(generation===selectionGeneration.current) setEvidence(result);
  }
  async function inspect(id: string) {
    const generation=selectionGeneration.current;
    await perform(async () => { setEvidence(null); const result=await request<Evidence>(selected ? `/incidents/${selected.incident_id}/source/${encodeURIComponent(id)}` : analysis?.branch_kind==='retrospective_replay' ? `/analyses/${analysis.analysis_run_id}/source/${encodeURIComponent(id)}` : `/events/${encodeURIComponent(id)}`); if(generation===selectionGeneration.current) setEvidence(result); });
  }
  const timeline: {time: string; stage?: Stage; mount?: EventRow}[] = selected ? [
    ...selected.stages.map(stage => ({time: stage.start_time_utc, stage})),
    ...mounts.map(mount => ({time: mount.event_time_utc, mount})),
  ].sort((a, b) => Date.parse(a.time) - Date.parse(b.time)) : [];
  const selectedBaseline = baselines.find(b => b.baseline_id === baselineId);
  useEffect(() => {
    if (!graph) return;
    const target = document.getElementById('entity-graph');
    if (!target) return;
    const reducedMotion = typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (typeof target.scrollIntoView === 'function') target.scrollIntoView({behavior:reducedMotion ? 'auto' : 'smooth',block:'start'});
    target.focus({preventScroll:true});
  },[graph]);

  const sidebar = <aside className="app-sidebar" aria-label="Data sources and setup">
    <div className="brand"><span className="brand-mark" aria-hidden="true">TG</span><span>TraceGuard</span></div>
    <p className="sidebar-caption">Evidence workbench</p>
    <p className="pill">Phase 4C · {mode}</p>
    <p className="muted">Evidence-backed reconstruction from local logs.</p>
    <hr/><h2>Data sources</h2>
    <label>Saved datasets<select value={dataset?.id ?? ''} disabled={busy} onChange={e => {
      const value = datasets.find(d => d.id === e.target.value); if (value) void perform(() => choose(value));
    }}><option value="">Choose dataset</option>{datasets.map(d => <option key={d.id} value={d.id}>{d.name}</option>)}</select></label>
    <details><summary>Upload compatible logs</summary><form onSubmit={upload}>
      <label>Source adapter<select value={sourceType} onChange={e => {setSourceType(e.target.value); setSourceId(e.target.value);}}>
        {['auth', 'file', 'device', 'network'].map(s => <option key={s}>{s}</option>)}</select></label>
      <label>Source ID<input value={sourceId} required maxLength={100} onChange={e => setSourceId(e.target.value)}/></label>
      <label>Environment namespace<input value={environment} required maxLength={100} onChange={e => setEnvironment(e.target.value)}/></label>
      <label>Timezone for naive times<input value={timezone} placeholder="e.g. Asia/Kolkata" onChange={e => setTimezone(e.target.value)}/></label>
      <label className="check"><input type="checkbox" checked={append} onChange={e => setAppend(e.target.checked)}/>Append to selected dataset</label>
      <label>CSV or JSONL<input type="file" name="file" accept=".csv,.jsonl" required/></label>
      <p className="muted">5 MiB / 10,000 rows per file. Choose one adapter per file. Times require offsets or a declared timezone.</p>
      <button disabled={busy}>Upload and normalize</button>
    </form></details>
    <p className="muted">Hybrid mode requires a fitted benign baseline. Reports require verified retained evidence. All response suggestions require an authorized human.</p>
  </aside>;

  return <div className="workbench">
    <a className="skip-link" href="#main-content">Skip to main content</a>
    <main id="main-content" tabIndex={-1}>
      <header className="page-header"><div><p className="eyebrow">LOCAL ANALYST WORKBENCH</p><h1>Inspect the evidence.</h1><p className="header-description">Review source-backed observations, timelines, and analysis results.</p></div>
        <button className="primary" disabled={!dataset || busy || (mode==='hybrid' && !baselineId)} onClick={() => void run()}>Analyze {mode}</button></header>
      <section className="quick-actions" aria-label="Seed scenarios and graph access">
        <div className="quick-actions-heading"><div><h2>Choose a seed scenario</h2><p>Load a sample dataset to explore the workbench. Select Analyze to build its incident review.</p></div>
          <button className="graph-shortcut" disabled={!dataset || busy || (mode==='hybrid' && !baselineId)} aria-describedby="graph-shortcut-help" onClick={() => void openGraphFromTop()}>Open entity graph</button></div>
        <div className="seed-triggers" role="group" aria-label="Load a seeded dataset">
          <button disabled={busy} onClick={() => void demo('benign')}>Load benign demo</button>
          <button disabled={busy} onClick={() => void demo('positive')}>Load positive demo</button>
          <button disabled={busy} onClick={() => void demo('missing-transfer')}>Load missing-transfer demo</button>
          <button disabled={busy} onClick={() => void chronologicalDemo()}>Load chronological demo</button>
        </div>
        <p id="graph-shortcut-help" className="quick-actions-help">The graph action analyzes the selected dataset when needed, then opens the first retained incident or review item.</p>
        {actionMessage && <p className="quick-actions-message" role="status" aria-live="polite">{actionMessage}</p>}
      </section>
      <nav className="workbench-nav" aria-label="Workbench sections">{[['overview','Overview'],['quality-review','Evaluation'],['cases-workbench','Cases'],['saved-hunts','Hunts'],['native-rule-catalog','Rules'],['local-indicators','Intelligence'],['external-findings','External findings'],['attack-view','ATT&CK']].map(([id,label])=><a key={id} href={`#${id}`}>{label}</a>)}</nav>
      <EvaluationReview/>
      <div className="workspace-status" role="status" aria-live="polite" aria-atomic="true" aria-busy={busy}>{busy ? 'Working…' : dataset ? `${dataset.name} · ${dataset.origin}` : 'Load a demo or upload logs to begin.'}</div>
      {error && <div className="error" role="alert">{error} <button disabled={busy} onClick={() => void perform(refresh)}>Retry dataset connection</button></div>}
      <details><summary>Frozen baseline & analysis mode</summary>
        <label>Analysis mode<select value={mode} disabled={busy} onChange={e => setMode(e.target.value)}><option value="rules-only">Rules-only</option><option value="hybrid">Hybrid (Isolation Forest + rules + graph)</option></select></label>
        <label>Fitted baseline<select value={baselineId} disabled={busy} onChange={e => setBaselineId(e.target.value)}><option value="">No baseline selected · hybrid unavailable</option>
          {baselines.map(b => <option key={b.baseline_id} value={b.baseline_id}>{b.baseline_id.slice(0,12)} · {b.model_version} · seed {b.seed}</option>)}</select></label>
        {selectedBaseline && <p className="muted">Frozen training {selectedBaseline.training_start} → {selectedBaseline.training_end}. Calibration ends {selectedBaseline.calibration_end}. {selectedBaseline.training_window_count} fitted windows / {selectedBaseline.calibration_sample_size} calibration windows. Feature version {selectedBaseline.feature_version ?? 'Unknown'}. Percentile calibration {String(selectedBaseline.percentile_calibration?.status ?? 'Unknown')} / {selectedBaseline.calibration_sample_size} samples. Incident threshold {selectedBaseline.risk_calibration.threshold}; status {selectedBaseline.risk_calibration.status ?? 'Unknown'}; origin {selectedBaseline.risk_calibration.threshold_origin ?? 'Unknown'}; {selectedBaseline.risk_calibration.complete_candidates ?? 'Unknown'} complete benign candidates. {selectedBaseline.risk_calibration.fallback_reason} {selectedBaseline.risk_calibration.warning}</p>}
        <h2>Explicit benign baseline fitting</h2>
        <p>Select separate chronological benign datasets; uploads never implicitly train. Declare their provenance.</p>
        <label>Training dataset<select value={trainingId} disabled={busy} onChange={e => setTrainingId(e.target.value)}><option value="">Choose training data</option>{datasets.map(d => <option value={d.id} key={d.id}>{d.name}</option>)}</select></label>
        <label>Calibration dataset<select value={calibrationId} disabled={busy} onChange={e => setCalibrationId(e.target.value)}><option value="">Choose calibration data</option>{datasets.map(d => <option value={d.id} key={d.id}>{d.name}</option>)}</select></label>
        <label>Benign data provenance<input value={provenance} maxLength={500} onChange={e => setProvenance(e.target.value)}/></label>
        <button disabled={busy || !trainingId || !calibrationId || !provenance.trim()} onClick={() => void perform(async () => {
          const result = await post<Baseline>('/baselines/train',{training_dataset_id:trainingId,calibration_dataset_id:calibrationId,benign_provenance:provenance,seed:17});
          await refresh(); setBaselineId(result.baseline_id); setMode('hybrid');
        })}>Fit selected benign baseline</button>
      </details>
      {analysis?.branch_kind==='retrospective_replay' && <p>Ingestion and editable context are parent-level retrospective metadata. Findings use the fixed frame snapshot.</p>}
      {quality && analysis?.branch_kind!=='retrospective_replay' && <section aria-label="Ingestion quality" className="quality">
        {(['accepted','rejected','duplicates','unsupported'] as const).map(key => <div key={key}><strong>{quality[key]}</strong><span>{key}</span></div>)}
      </section>}
      {dataset && <p className="muted">Dataset {dataset.id} · {dataset.origin} · source families {Array.from(new Set(quality?.files?.map(f => f.source_type) ?? [])).join(', ') || 'None'}. Ground truth unavailable for this selected dataset; accuracy metrics belong only to separate labeled benchmarks.</p>}
      {dataset && <label>Retained analysis run (latest 200)<select value={analysis?.analysis_run_id ?? ''} disabled={busy} onChange={e => {const saved=runHistory.find(r => r.analysis_run_id===e.target.value); if(saved) {++selectionGeneration.current;setEvidence(null);setReplayNavigationEpoch(v=>v+1);void perform(async () => openRun(await request<Analysis>(`/analyses/${saved.analysis_run_id}`)));}}}><option value="">Choose saved run</option>{runHistory.map(r => <option key={r.analysis_run_id} value={r.analysis_run_id}>{r.analysis_run_id} · {r.branch_kind ?? 'ordinary (legacy)'} · {r.mode} · {r.cutoff}</option>)}</select></label>}
      {quality && (quality.errors.length > 0 || quality.warnings.length > 0) && <details><summary>Ingestion warnings and errors</summary>
        {quality.warnings.map(w => <p key={w}>{w}</p>)}{quality.errors.map((e, i) => <p key={i}>{e.filename} · row {e.row_number}: {e.error}</p>)}</details>}
      {dataset && <details><summary>Trusted resource sensitivity metadata</summary>
        <p>Operator-supplied context, separate from logs. Only matching, time-valid sensitive resource labels support collection. Resource IDs use <code>environment:file:identifier</code> with URI-encoded parts. See DATA_SCHEMA.md.</p>
        <label>Resource context JSON<textarea rows={7} value={context} onChange={e => setContext(e.target.value)}/></label>
        <button disabled={busy} onClick={() => void perform(async () => {
          const result = await request<unknown>(`/datasets/${dataset.id}/resources`, {method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify(JSON.parse(context))});
          setContext(JSON.stringify(result, null, 2));
        })}>Apply trusted resource labels</button>
      </details>}
      {dataset && <details><summary>Trusted authorization and account aliases</summary>
        <p>Explicit operator declarations, separate from logs. New context affects future analyses; retained runs keep their snapshots. Authorization requires exact actor, endpoint, resource, copy action, [from, until), ID and provenance. Hybrid subtracts 20 once; structural gates remain required. Sources are not independently verified.</p>
        <label>Scoped authorization JSON<textarea rows={8} value={authorization} onChange={e => setAuthorization(e.target.value)}/></label>
        <button disabled={busy} onClick={() => void perform(async () => {const result=await request(`/datasets/${dataset.id}/authorizations`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(JSON.parse(authorization))});setAuthorization(JSON.stringify(result,null,2));})}>Save scoped authorizations for next run</button>
        <p>Saving replaces the current authorization list; [] clears future-run context. Existing evidence and runs are preserved.</p>
        <label>Direct account alias JSON<textarea rows={6} value={aliasContext} onChange={e => setAliasContext(e.target.value)}/></label>
        <button disabled={busy} onClick={() => void perform(async () => {const result=await request(`/environments/${encodeURIComponent(dataset.environment)}/aliases`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(JSON.parse(aliasContext))});setAliasContext(JSON.stringify(result,null,2));})}>Add trusted account aliases for next run</button>
      </details>}
      {analysis && <section className="run" id="overview"><h2>Analysis result · {analysis.mode}</h2>
        <p>Run kind: {analysis.branch_kind ?? 'ordinary (legacy)'}{analysis.parent_run_id && ` · parent ${analysis.parent_run_id}`}</p>
        <p><strong>{analysis.incident_count} incidents</strong> · {analysis.review_count ?? 0} below-threshold observations · {analysis.partial_count} partial observations · {analysis.event_count} accepted events</p>
        <p className="muted">Run {analysis.analysis_run_id} · {analysis.status} · Cutoff {analysis.cutoff} UTC · fingerprint <code>{analysis.dataset_fingerprint}</code></p>
        <details><summary>Immutable run configuration and calibration</summary><pre>{JSON.stringify({config:analysis.config,calibration:analysis.calibration,baseline:analysis.baseline_snapshot},null,2)}</pre></details>
        {analysis.warnings.map(w => <p key={w} className="muted">{w}</p>)}
        {analysis.incident_count + analysis.partial_count + (analysis.review_count ?? 0) === 0 && <p>No supported chain found. Mounting USB media does not establish copying.</p>}
      </section>}
      {analysis && ['ordinary','retrospective_replay'].includes(analysis.branch_kind ?? '') && <Replay key={`${analysis.parent_run_id ?? analysis.analysis_run_id}:${replayNavigationEpoch}`} run={analysis} onOpen={openRun}/>}
      <details id="evaluation-run"><summary>Measured synthetic evaluation</summary><p>Runs a separate seeded 1,200-event requested profile with days 1–14 fit, 15–21 calibration, 22–28 holdout. Results belong to that generated labeled fixture, not arbitrary uploads.</p>
        <button disabled={busy} onClick={() => void perform(async () => {setEvaluation(await post<Evaluation>('/evaluations',{seed:17,users:6,events:1200})); await refresh();})}>Run held-out synthetic benchmark</button>
        {evaluation && <><p>{evaluation.split}. Evaluation {evaluation.evaluation_id} · synthetic origin · seed {evaluation.seed}</p><div className="table-wrap"><table><thead><tr><th>Mode</th><th>Alerts</th><th>Incident precision</th><th>Incident recall</th><th>Benign unit FPR</th></tr></thead><tbody>
          {Object.entries(evaluation.metrics).map(([kind,m]) => <tr key={kind}><td>{kind}</td><td>{m.alert_count}</td><td>{m.incident_precision.numerator}/{m.incident_precision.denominator} {m.incident_precision.value === null ? '(undefined)' : ''}</td><td>{m.incident_recall.numerator}/{m.incident_recall.denominator}</td><td>{m.benign_user_device_day_fpr.numerator}/{m.benign_user_device_day_fpr.denominator}</td></tr>)}
        </tbody></table></div><pre>{JSON.stringify({partitions:evaluation.partitions,runs:evaluation.runs},null,2)}</pre><p className="muted">One-to-one episode matching; explicit denominators. No detection improvement was measured when these results are equal.</p><p className="muted">Counts are measured. Synthetic holdouts do not establish real-world generalization; equal results do not show an ML improvement.</p></>}
      </details>
      <Lookalikes baselines={baselines} onEvidence={(incidentId,eventId)=>void perform(async()=>{
        await showEvidence(`/incidents/${incidentId}/source/${encodeURIComponent(eventId)}`);
      })} onRunEvidence={(runId,eventId)=>void perform(async()=>{
        await showEvidence(`/analyses/${runId}/source/${encodeURIComponent(eventId)}`);
      })} onOpen={(runId,incidentId)=>void perform(async()=>{
        const saved=await request<Analysis & {dataset_id:string}>(`/analyses/${runId}`);
        const value=(await request<Dataset[]>('/datasets')).find(d=>d.id===saved.dataset_id);
        if(!value) throw new Error('Retained dataset unavailable');
        await choose(value);await openRun(saved);
        if(incidentId) await openIncident(await request<Incident>(`/incidents/${incidentId}`),runId);
      })}/>
      <div className="panels"><section><h2>Incidents & review items</h2>
        {!analysis && <p className="muted">Run analysis to reconstruct supported stages.</p>}
        {analysis && <form onSubmit={e => {e.preventDefault(); void perform(() => candidates(analysis.analysis_run_id));}}>
          <label>Search account, endpoint, ID or explanation<input value={search} onChange={e => setSearch(e.target.value)} maxLength={200}/></label>
          <label>Candidate decision<select value={decision} onChange={e => setDecision(e.target.value)}><option value="">All retained candidates</option><option value="incident">Complete alerts</option><option value="review">Below-threshold observations</option><option value="partial_observation">Incomplete review items</option></select></label>
          <button disabled={busy}>Apply candidate filters</button><p>{candidateTotal} matching candidates · 20 per page; no top-k alert suppression.</p>
          <button type="button" disabled={busy} onClick={() => void perform(() => candidates(analysis.analysis_run_id))}>First candidate page</button>
          {candidateCursor!==null && <button type="button" disabled={busy} onClick={() => void perform(() => candidates(analysis.analysis_run_id,candidateCursor))}>Next candidate page</button>}
        </form>}
        {incidents.map(item => <button disabled={busy} className={`incident ${selected?.incident_id === item.incident_id ? 'selected' : ''}`} key={item.incident_id}
          onClick={() => void perform(() => openIncident(item))}>
          <span className="pill">{item.decision === 'incident' ? 'Suspected chain' : item.decision==='review' ? 'Below-threshold review' : 'Partial observation'}</span>
          <strong>{item.user_id} / {item.device_id}</strong><span>{item.stages.length}/3 stages · heuristic risk {item.risk.score.toFixed(1)}</span>
        </button>)}
      </section><section><h2>Timeline · UTC</h2>
        {selected ? <><p>{selected.summary}</p><p className="muted">Evidence validation: {selected.validation.valid ? 'passed' : 'failed'} · {selected.validation.asserted_stages_checked} stages checked</p>
          {timeline.map(entry => entry.stage ? <article className="stage" key={entry.stage.stage_id}><time>{entry.time}</time><h3>{entry.stage.stage_name}</h3>
            <p className="muted">{entry.stage.claim_status.replaceAll('_', ' ')}</p>
            <button disabled={busy} onClick={() => void perform(() => selectStage(entry.stage!))}>Open {entry.stage.stage_id} evidence</button>
            <details><summary>Stage predicates and entity linkage</summary><pre>{JSON.stringify({predicates:entry.stage.predicate_results,matched_fields:entry.stage.matched_fields,entity_link_reasons:entry.stage.entity_link_reasons},null,2)}</pre></details>
            {entry.stage.historical_comparison && <details><summary>Prior-day count comparison</summary><pre>{JSON.stringify(entry.stage.historical_comparison, null, 2)}</pre></details>}
          </article> : <article className="stage" key={entry.mount!.event_id}><time>{entry.time}</time><h3>USB mounted · corroborating context</h3>
            <p className="muted">Observed mount; copying requires separate telemetry.</p><button disabled={busy} onClick={() => void inspect(entry.mount!.event_id)}>Open corroborating USB mount</button></article>)}
          {selected.missing_evidence.map(m => <p className="missing" key={m}>Missing: {m}</p>)}
          <p className="muted">{selected.risk.label}. Human intent is unknown; context matches are operator declarations. A human must review the source evidence.</p>
          {selected.risk.components && <details><summary>Reproducible hybrid risk breakdown</summary><pre>{JSON.stringify({components:selected.risk.components,weighted_terms:selected.risk.weighted_terms,threshold:selected.risk.threshold,anomaly_percentile:selected.risk.anomaly_percentile ?? 'Unavailable',missing_components:selected.risk.missing_components},null,2)}</pre><p className="muted">Anomaly percentile measures rarity relative to benign calibration, not probability of compromise.</p></details>}
          <details><summary>Applied identity resolution</summary><pre>{JSON.stringify(selected.entity_resolution ?? [],null,2)}</pre><p>Raw identities remain unchanged. Direct trusted aliases require a compatible selected baseline; IPs never join identities.</p></details>
          <details><summary>Scoped context checks and risk effect</summary><pre>{JSON.stringify(selected.authorization,null,2)}</pre></details>
          <h3>Response suggestions · authorized human review required</h3>
          {selected.recommendations?.map((r,i) => <article key={i}><p>{r.suggestion}</p><p className="muted">Support: {r.supporting_observation} · approval {r.approval_status}</p>{r.evidence_event_ids.map(id => <button key={id} disabled={busy} onClick={() => void inspect(id)}>Inspect recommendation evidence</button>)}</article>)}
          <label className="check"><input type="checkbox" checked={includeRaw} onChange={e => setIncludeRaw(e.target.checked)}/>Include raw/private evidence fields (default omitted)</label>
          <button disabled={busy} onClick={() => void download('json')}>Download JSON report</button><button disabled={busy} onClick={() => void download('markdown')}>Download Markdown report</button>
          {analysis && analysis.branch_kind!=='retrospective_replay' && <EvidenceSelection key={selected.incident_id} run={analysis} item={selected} busy={busy} onRun={(ids,note)=>void perform(async()=>{
            const result=await post<Sensitivity>(`/analyses/${analysis.analysis_run_id}/sensitivity`,{excluded_event_ids:ids,analyst_note:note});
            setComparison(result); remember(analysis.analysis_run_id,selected.incident_id,result.comparison_id);
            if(dataset) setRunHistory(await request<Analysis[]>(`/datasets/${dataset.id}/analyses`));
          })}/>}
          <button disabled={busy} onClick={() => void perform(async () => {await loadGraph(selected);})}>Inspect typed entity graph</button>
        </> : <p className="muted">Choose an incident or partial observation.</p>}
      </section></div>
      <Cases run={analysis} incident={selected} onInspect={(runId,eventId)=>void perform(()=>showEvidence(`/analyses/${encodeURIComponent(runId)}/source/${encodeURIComponent(eventId)}`))}/>
      <Hunts run={analysis} onInspect={(runId,eventId)=>void perform(()=>showEvidence(`/analyses/${encodeURIComponent(runId)}/source/${encodeURIComponent(eventId)}`))}/>
      <Rules run={analysis} onInspect={(runId,eventId)=>void perform(()=>showEvidence(`/analyses/${encodeURIComponent(runId)}/source/${encodeURIComponent(eventId)}`))}/>
      <Intelligence run={analysis} onInspect={(runId,eventId)=>void perform(()=>showEvidence(`/analyses/${encodeURIComponent(runId)}/source/${encodeURIComponent(eventId)}`))}/>
      <ExternalFindings/>
      <Attack run={analysis} onInspect={(runId,eventId)=>void perform(()=>showEvidence(`/analyses/${encodeURIComponent(runId)}/source/${encodeURIComponent(eventId)}`))}/>
      {comparison && <SensitivityResult result={comparison} busy={busy} onOpen={(runId,incidentId)=>void perform(async()=>{
        const retained=comparison;
        await openRun(await request<Analysis>(`/analyses/${runId}`));
        if(incidentId) await openIncident(await request<Incident>(`/incidents/${incidentId}`),runId);
        setComparison(retained); remember(runId,incidentId,retained.comparison_id);
      })} onDownload={()=>void perform(async()=>{
        const response=await fetch(`/api/sensitivities/${comparison.comparison_id}/report`);
        if(!response.ok) throw new Error(String((await response.json()).detail));
        const url=URL.createObjectURL(await response.blob()); const anchor=document.createElement('a');
        anchor.href=url; anchor.download=`sensitivity-${comparison.comparison_id}.json`; anchor.click(); setTimeout(()=>URL.revokeObjectURL(url),1000);
      })}/>}
      {graph && <><LinkedGraph graph={graph} eventIds={stageIds} onEvidence={id => {setStageIds([id]); void inspect(id);}}/>
        {graph.truncated && graph.nodes.length<500 && <button disabled={busy} onClick={() => void perform(async () => {if(selected) await loadGraph(selected,500);})}>Expand graph to 500 nodes</button>}</>}
      {evidence && <section className="evidence" aria-label="Raw evidence"><h2>Raw evidence</h2><button onClick={() => setEvidence(null)}>Close evidence</button>
        <p>{evidence.analysis_run_id ? evidence.analysis_run_id===analysis?.analysis_run_id ?
          `Source scoped to displayed run ${evidence.analysis_run_id}. ${analysis.history_event_ids?.includes(evidence.event.event_id) ? 'Frozen baseline history citation; not a current inference observation.' : 'Retained cutoff-eligible observation.'}` :
          `Source from separate retained run ${evidence.analysis_run_id}; it does not support the displayed replay frame or incident.` :
          'Dataset source inspection, separate from selected incident support.'}</p>
        <details><summary>Canonical normalized event</summary><pre>{JSON.stringify(evidence.event, null, 2)}</pre></details>
        {evidence.source_records.map(r => <article key={r.ref}><h3>{r.filename} · row {r.row_number} · {r.status}</h3>
          <p>Retained hashes and source row: {r.hash_valid && r.file_hash_valid && r.file_row_valid ? 'verified' : 'FAILED'}. Hashes check consistency, not source authenticity.</p>
          <p className="muted">Source reference <code>{r.ref}</code><br/>File SHA-256 <code>{r.file_sha256}</code><br/>Record SHA-256 <code>{r.raw_sha256}</code></p>
          <pre>{JSON.stringify(r.raw, null, 2)}</pre></article>)}
      </section>}
      {dataset && <section><h2>{analysis?.branch_kind==='retrospective_replay' ? 'Frame observations through cutoff' : 'Normalized event preview'}</h2><div className="table-wrap"><table><thead><tr><th>Time (UTC)</th><th>Action</th><th>Account</th><th>Endpoint</th><th>Source</th></tr></thead>
        <tbody>{events.map(e => <tr key={e.event_id}><td>{e.event_time_utc}</td><td>{e.action}</td><td>{e.user_id ?? 'Unavailable'}</td><td>{e.device_id ?? 'Unavailable'}</td>
          <td><button disabled={busy} onClick={() => void perform(()=>showEvidence(analysis?.branch_kind==='retrospective_replay' ? `/analyses/${analysis.analysis_run_id}/source/${encodeURIComponent(e.event_id)}` : `/events/${encodeURIComponent(e.event_id)}`))}>Inspect row</button></td></tr>)}</tbody></table></div>
        <button disabled={busy} onClick={() => void perform(() => analysis?.branch_kind==='retrospective_replay' ? retainedPage(analysis.analysis_run_id) : page(dataset.id))}>First page</button>{cursor !== null && <button disabled={busy} onClick={() => void perform(() => analysis?.branch_kind==='retrospective_replay' ? retainedPage(analysis.analysis_run_id,cursor) : page(dataset.id,cursor))}>Next page</button>}
      </section>}
    </main>
    {sidebar}
  </div>;
}
