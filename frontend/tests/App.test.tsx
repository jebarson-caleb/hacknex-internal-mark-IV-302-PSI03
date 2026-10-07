import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import App from '../src/App';

const dataset = {id: 'd1', name: 'Synthetic fixture', environment:'synthetic-office', origin:'synthetic', seed:17};
const quality = {accepted:79, rejected:0, duplicates:0, unsupported:0, errors:[], warnings:[], timezone_assumptions:[]};
const stages = ['authentication','collection','transfer'].map((id, index) => ({
  stage_id:id, stage_name: `Supported ${id}`, start_time_utc:`2026-01-07T09:${10 + index * 4}:00Z`,
  evidence_event_ids:[id], claim_status:'observed', historical_comparison:null,
}));

function backend(partial = false) {
  const incident = {incident_id:'i1', analysis_run_id:'r1', user_id:'env:user:u', device_id:'env:endpoint:d', decision:partial ? 'partial_observation' : 'incident',
    stages:partial ? stages.slice(0,2) : stages, context_event_ids:[], selected_evidence:[],
    missing_evidence:partial ? ['Explicit copy telemetry'] : [], summary:'Observed evidence; intent is unknown.',
    risk:{score:partial ? 60 : 100, label:'heuristic; not a probability'}, validation:{valid:true, asserted_stages_checked:partial ? 2 : 3}};
  const mock = vi.fn(async (url: string) => {
    let body: unknown;
    if (url === '/api/datasets') body = [dataset];
    else if (url === '/api/baselines') body = [];
    else if (url === '/api/datasets/demo') body = {dataset,quality};
    else if (url.endsWith('/quality')) body = quality;
    else if (url.endsWith('/authorizations') || url.endsWith('/aliases') || (url.startsWith('/api/datasets/') && url.endsWith('/analyses'))) body = [];
    else if (url.endsWith('/resources')) body = [];
    else if (url.startsWith('/api/events?')) body = {items:[], next_cursor:null};
    else if (url === '/api/analyses') body = {analysis_run_id:'r1', mode:'rules-only', incident_count:partial ? 0 : 1, partial_count:partial ? 1 : 0, event_count:79, warnings:['Rules-only'], cutoff:'2026-01-07T10:00:00Z', dataset_fingerprint:'abc'};
    else if (url.startsWith('/api/analyses/r1/candidates?')) body = {items:[incident],total:1,next_cursor:null};
    else if (url.includes('/graph?')) body = {nodes:[],edges:[],independent_event_count:0,truncated:false,total_nodes:0};
    else if (url.startsWith('/api/events/') || url.includes('/source/')) body = {event:{action:'file_copy_to_usb'},source_records:[{
      ref:'row1', filename:'file.jsonl', row_number:47, status:'accepted', hash_valid:true, file_hash_valid:true, file_row_valid:true,
      file_sha256:'abc', raw_sha256:'def', raw:{file_path:'<img src=x onerror="alert(1)">'}
    }]};
    else if (url.startsWith('/api/lookalikes?')) body = {items:[],total:0,next_cursor:null};
    else throw new Error(`Unexpected request ${url}`);
    return {ok:true, json:async () => body};
  });
  vi.stubGlobal('fetch', mock);
  return mock;
}

describe('Phase 1 workbench', () => {
  it('shows an honest empty state and disables analysis', async () => {
    vi.stubGlobal('fetch', vi.fn(async (input:string) => {
      const url=String(input);let body:unknown=[];
      if(url.startsWith('/api/cases?')||url.startsWith('/api/hunts?')||url.startsWith('/api/intelligence/collections?')||url.startsWith('/api/external/artifacts?'))body={items:[],total:0,next_cursor:null};
      else if(url==='/api/rules/catalog')body={catalog_version:'test',read_only:true,kind:'native',distinction:'read only',policy_versions:{},supported_actions_by_source:{},identity_and_time_gates:[],stages:[],risk_and_limits:{}};
      return {ok:true,json:async () => body};
    }));
    render(<App/>);
    await waitFor(() => expect(screen.getByRole('button',{name:'Load positive demo'})).toBeEnabled());
    expect(screen.getByRole('button', {name:'Analyze rules-only'})).toBeDisabled();
    expect(screen.getByText('Phase 4C · rules-only')).toBeInTheDocument();
    expect(screen.getByText('Load a demo or upload logs to begin.')).toBeInTheDocument();
  });

  it('loads, analyzes, opens timeline and safely displays raw source text', async () => {
    backend(); render(<App/>);
    await waitFor(() => expect(screen.getByRole('button',{name:'Load positive demo'})).toBeEnabled());
    fireEvent.click(screen.getByRole('button',{name:'Load positive demo'}));
    await waitFor(() => expect(screen.getByRole('button',{name:'Analyze rules-only'})).toBeEnabled());
    fireEvent.click(screen.getByRole('button',{name:'Analyze rules-only'}));
    await screen.findByText('1 incidents');
    fireEvent.click(await screen.findByRole('button',{name:/Suspected chain/}));
    fireEvent.click(await screen.findByRole('button',{name:'Open transfer evidence'}));
    const drawer = await screen.findByRole('region',{name:'Raw evidence'});
    expect(drawer.textContent).toContain('<img src=x onerror=');
    expect(drawer.querySelector('img')).toBeNull();
    expect(drawer.textContent).toContain('file.jsonl · row 47');
    fireEvent.click(screen.getByRole('button',{name:'Close evidence'}));
    expect(screen.queryByRole('region',{name:'Raw evidence'})).toBeNull();
  });

  it('keeps missing transfer as a partial observation', async () => {
    backend(true); render(<App/>);
    await waitFor(() => expect(screen.getByRole('button',{name:'Load positive demo'})).toBeEnabled());
    fireEvent.click(screen.getByRole('button',{name:'Load missing-transfer demo'}));
    await waitFor(() => expect(screen.getByRole('button',{name:'Analyze rules-only'})).toBeEnabled());
    fireEvent.click(screen.getByRole('button',{name:'Analyze rules-only'}));
    await screen.findByText('0 incidents');
    fireEvent.click(await screen.findByRole('button',{name:/Partial observation/}));
    expect(await screen.findByText('Missing: Explicit copy telemetry')).toBeInTheDocument();
    expect(screen.queryByRole('button',{name:'Open transfer evidence'})).toBeNull();
  });

  it('displays backend errors and restores usable controls', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => ['/api/datasets','/api/baselines'].includes(url)
      ? {ok:true,json:async () => []} : {ok:false,json:async () => ({detail:'Storage unavailable'})}));
    render(<App/>);
    await waitFor(() => expect(screen.getByRole('button',{name:'Load positive demo'})).toBeEnabled());
    fireEvent.click(screen.getByRole('button',{name:'Load positive demo'}));
    await waitFor(() => expect(screen.getAllByRole('alert').some(element=>element.textContent?.includes('Storage unavailable'))).toBeTruthy());
    expect(screen.getByRole('button',{name:'Load positive demo'})).toBeEnabled();
  });

  it('requires a fitted baseline before enabling hybrid analysis', async () => {
    backend(); render(<App/>);
    await waitFor(() => expect(screen.getByRole('button',{name:'Load positive demo'})).toBeEnabled());
    fireEvent.click(screen.getByRole('button',{name:'Load positive demo'}));
    await waitFor(() => expect(screen.getByRole('button',{name:'Analyze rules-only'})).toBeEnabled());
    fireEvent.click(screen.getByText('Frozen baseline & analysis mode'));
    fireEvent.change(screen.getByLabelText('Analysis mode'),{target:{value:'hybrid'}});
    expect(screen.getByRole('button',{name:'Analyze hybrid'})).toBeDisabled();
    expect(screen.getByText('Phase 4C · hybrid')).toBeInTheDocument();
  });

  it('fetches and displays typed graph relations from an incident', async () => {
    const original=backend();
    vi.stubGlobal('fetch',vi.fn(async (url:string) => url.endsWith('/graph') ? {ok:true,json:async () => ({
      nodes:[{id:'env:file:f',entity_type:'file',label:'f'},{id:'env:removable_device:m',entity_type:'removable_device',label:'m'}],
      edges:[{edge_id:'edge1',source:'env:file:f',target:'env:removable_device:m',relation:'copied_to',status:'observed',event_ids:['transfer']}],
      truncated:false,total_nodes:2,independent_event_count:1,
    })} : original(url)));
    render(<App/>);
    await waitFor(() => expect(screen.getByRole('button',{name:'Load positive demo'})).toBeEnabled());
    fireEvent.click(screen.getByRole('button',{name:'Load positive demo'}));
    await waitFor(() => expect(screen.getByRole('button',{name:'Analyze rules-only'})).toBeEnabled());
    fireEvent.click(screen.getByRole('button',{name:'Analyze rules-only'}));
    fireEvent.click(await screen.findByRole('button',{name:/Suspected chain/}));
    fireEvent.click(await screen.findByRole('button',{name:'Inspect typed entity graph'}));
    expect(await screen.findByRole('region',{name:'Entity graph'})).toHaveTextContent('copied_to');
  });
});
