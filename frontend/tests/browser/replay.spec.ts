import {test,expect} from '@playwright/test';
import {resolve} from 'node:path';

test('real hybrid cutoff/window transition, backwards evidence, refresh and unchanged parent',async({page,request})=>{
  test.setTimeout(120000);
  const data=await (await request.post('/api/datasets/chronological-demo',{data:{seed:17,users:6,events:1200}})).json();
  const baseline=await (await request.post('/api/baselines/train',{data:{training_dataset_id:data.training.id,calibration_dataset_id:data.calibration.id,benign_provenance:'Explicit generated development browser setup'}})).json();
  const parent=await (await request.post('/api/analyses',{data:{dataset_id:data.test.id,mode:'hybrid',baseline_id:baseline.baseline_id}})).json();
  const items=await (await request.get(`/api/analyses/${parent.analysis_run_id}/incidents`)).json();
  const complete=items.find((i:{stages:unknown[]})=>i.stages.length===3);
  const source=await (await request.get(`/api/incidents/${complete.incident_id}/source/${complete.stages[2].evidence_event_ids[0]}`)).json();
  const nav=await (await request.get(`/api/analyses/${parent.analysis_run_id}/replay`)).json();
  const time=new Date(source.event.event_time_utc);
  const closure=new Date(time);closure.setUTCMinutes(Math.floor(time.getUTCMinutes()/15)*15+15,0,0);
  await page.goto(`/?run=${parent.analysis_run_id}`);
  const region=page.getByRole('region',{name:'Retrospective event-time replay'});
  const cutoff=region.getByLabel('Requested UTC cutoff');
  await expect(cutoff).toBeVisible();
  await cutoff.fill(nav.start);await region.getByRole('button',{name:'Run frame',exact:true}).click();
  await expect(page.getByText('Run kind: retrospective_replay',{exact:false})).toBeVisible();
  await expect(page.getByText(/No supported chain found/)).toBeVisible();
  expect(new URL(page.url()).searchParams.get('run')).not.toBe(parent.analysis_run_id);
  await cutoff.fill(time.toISOString());await region.getByRole('button',{name:'Run frame',exact:true}).click();
  await expect(region.getByText(/Currently displayed cutoff/)).toContainText(time.toISOString().replace('Z','+00:00').replace('.000',''));
  await page.getByRole('button',{name:/Below-threshold review/}).first().click();
  await expect(page.getByRole('button',{name:'Open transfer evidence'})).toBeVisible();
  await page.getByText('Reproducible hybrid risk breakdown',{exact:true}).click();
  await expect(page.getByText(/"anomaly_percentile": "Unavailable"/)).toBeVisible();
  await region.getByRole('button',{name:'Next replay stop'}).click();
  expect(await cutoff.inputValue()).toBe(closure.toISOString().replace('Z','+00:00').replace('.000',''));
  await region.getByRole('button',{name:'Run frame',exact:true}).click();
  await expect(region.getByText(/Currently displayed cutoff/)).toContainText(await cutoff.inputValue());
  const closedId=new URL(page.url()).searchParams.get('run')!;
  const candidates=await (await request.get(`/api/analyses/${closedId}/incidents`)).json();
  expect(candidates.find((i:{stages:unknown[]})=>i.stages.length===3).risk.anomaly_percentile).not.toBeNull();
  await region.getByRole('button',{name:'Previous replay stop'}).click();
  await region.getByRole('button',{name:'Previous replay stop'}).click();
  await region.getByRole('button',{name:'Run frame',exact:true}).click();
  await expect(page.getByRole('button',{name:/Partial observation/}).first()).toBeVisible();
  await page.getByRole('button',{name:/Partial observation/}).first().click();
  await expect(page.getByRole('button',{name:'Open transfer evidence'})).toHaveCount(0);
  await page.getByRole('button',{name:'Open collection evidence'}).click();
  await expect(page.getByRole('region',{name:'Raw evidence'})).toBeVisible();
  const frameId=new URL(page.url()).searchParams.get('run');
  await page.reload();await expect(region).toBeVisible();
  expect(new URL(page.url()).searchParams.get('run')).toBe(frameId);
  await region.getByRole('button',{name:'Return to original replay parent'}).click();
  await expect(region.getByText(/Original parent/)).toBeVisible();
  expect(await (await request.get(`/api/analyses/${parent.analysis_run_id}`)).json()).toEqual(parent);
  await page.screenshot({path:resolve('../runtime/phase4c-browser.png'),fullPage:true});
});

test('late cutoff response and error cannot replace current frame; retry recovers',async({page,request})=>{
  await page.goto('/');await page.getByRole('button',{name:'Load positive demo'}).click();
  await page.getByRole('button',{name:'Analyze rules-only'}).click();
  const region=page.getByRole('region',{name:'Retrospective event-time replay'});
  const cutoff=region.getByLabel('Requested UTC cutoff');await expect(cutoff).toBeVisible();
  const parentId=new URL(page.url()).searchParams.get('run')!;
  const nav=await (await request.get(`/api/analyses/${parentId}/replay`)).json();
  let release!:()=>void;
  const blocked=new Promise<void>(resolve=>{release=resolve;});
  let entered!:()=>void;const seen=new Promise<void>(resolve=>{entered=resolve;});
  await page.route('**/api/analyses/*/replay',async route=>{
    if(route.request().method()!=='POST') return route.continue();
    const response=await route.fetch();entered();await blocked;await route.fulfill({response});
  });
  await cutoff.fill(nav.start);await region.getByRole('button',{name:'Run frame',exact:true}).click();await seen;
  await expect(region.getByRole('status')).toContainText('Findings below still belong');
  await cutoff.fill(nav.end);release();
  await expect(region.getByText(/Original parent/)).toBeVisible();
  expect(new URL(page.url()).searchParams.get('run')).toBe(parentId);
  await page.unroute('**/api/analyses/*/replay');
  await page.route('**/api/analyses/*/replay',route=>route.request().method()==='POST' ? route.fulfill({status:422,contentType:'application/json',body:JSON.stringify({detail:'Unsupported replay parent test error'})}) : route.continue());
  await region.getByRole('button',{name:'Run frame',exact:true}).click();
  await expect(region.getByRole('alert')).toContainText('Unsupported replay parent');
  await expect(region.getByRole('button',{name:'Run frame',exact:true})).toBeEnabled();
  await page.unroute('**/api/analyses/*/replay');
  await cutoff.fill(nav.start);await region.getByRole('button',{name:'Run frame',exact:true}).click();
  await expect(page.getByText(/No supported chain found/)).toBeVisible();
});

test('switching parents discards the previous parent pending frame',async({page,request})=>{
  const first=await (await request.post('/api/datasets/demo',{data:{variant:'positive'}})).json();
  const second=await (await request.post('/api/datasets/demo',{data:{variant:'missing-transfer'}})).json();
  const parent=await (await request.post('/api/analyses',{data:{dataset_id:first.dataset.id}})).json();
  await page.goto(`/?run=${parent.analysis_run_id}`);
  const region=page.getByRole('region',{name:'Retrospective event-time replay'});
  await expect(region.getByLabel('Requested UTC cutoff')).toBeVisible();
  let release!:()=>void;const blocked=new Promise<void>(resolve=>{release=resolve;});
  let entered!:()=>void;const seen=new Promise<void>(resolve=>{entered=resolve;});
  await page.route('**/api/analyses/*/replay',async route=>{
    if(route.request().method()!=='POST') return route.continue();
    const response=await route.fetch();entered();await blocked;await route.fulfill({response});
  });
  await region.getByRole('button',{name:'Run frame',exact:true}).click();await seen;
  await page.getByLabel('Saved datasets').selectOption(second.dataset.id);
  release();
  await expect(region).toHaveCount(0);
  await expect(page.getByText(/Run kind: retrospective_replay/)).toHaveCount(0);
});

test('late future source drawer cannot enter an earlier frame',async({page,request})=>{
  await page.goto('/');await page.getByRole('button',{name:'Load positive demo'}).click();
  await page.getByRole('button',{name:'Analyze rules-only'}).click();
  await page.getByRole('button',{name:/Suspected chain/}).click();
  const parentId=new URL(page.url()).searchParams.get('run')!;
  const nav=await (await request.get(`/api/analyses/${parentId}/replay`)).json();
  let release!:()=>void;const blocked=new Promise<void>(resolve=>{release=resolve;});
  let entered!:()=>void;const seen=new Promise<void>(resolve=>{entered=resolve;});
  await page.route('**/api/incidents/*/source/*',async route=>{
    const response=await route.fetch();entered();await blocked;await route.fulfill({response});
  });
  await page.getByRole('button',{name:'Open transfer evidence'}).click();await seen;
  const region=page.getByRole('region',{name:'Retrospective event-time replay'});
  await region.getByLabel('Requested UTC cutoff').fill(nav.start);
  await region.getByRole('button',{name:'Run frame',exact:true}).click();
  await expect(page.getByText(/No supported chain found/)).toBeVisible();
  release();await expect(page.getByRole('button',{name:'Analyze rules-only'})).toBeEnabled();
  await expect(page.getByRole('region',{name:'Raw evidence'})).toHaveCount(0);
  await expect(page.getByRole('region',{name:'Entity graph'})).toHaveCount(0);
});

test('selecting a different retained parent immediately invalidates a pending replay',async({page,request})=>{
  const data=await (await request.post('/api/datasets/demo',{data:{variant:'positive'}})).json();
  const first=await (await request.post('/api/analyses',{data:{dataset_id:data.dataset.id}})).json();
  const second=await (await request.post('/api/analyses',{data:{dataset_id:data.dataset.id}})).json();
  await page.goto(`/?run=${first.analysis_run_id}`);
  const region=page.getByRole('region',{name:'Retrospective event-time replay'});
  await expect(region.getByLabel('Requested UTC cutoff')).toBeVisible();
  let releaseFrame!:()=>void;const blockedFrame=new Promise<void>(resolve=>{releaseFrame=resolve;});
  let entered!:()=>void;const seen=new Promise<void>(resolve=>{entered=resolve;});
  let releaseParent!:()=>void;const blockedParent=new Promise<void>(resolve=>{releaseParent=resolve;});
  await page.route('**/api/analyses/*/replay',async route=>{
    if(route.request().method()!=='POST') return route.continue();
    const response=await route.fetch();entered();await blockedFrame;await route.fulfill({response});
  });
  await page.route(`**/api/analyses/${second.analysis_run_id}`,async route=>{
    const response=await route.fetch();await blockedParent;await route.fulfill({response});
  });
  await region.getByRole('button',{name:'Run frame',exact:true}).click();await seen;
  await page.getByLabel('Retained analysis run (latest 200)').selectOption(second.analysis_run_id);
  releaseFrame();
  await expect(page.getByText(/Run kind: retrospective_replay/)).toHaveCount(0);
  releaseParent();await expect(page).toHaveURL(new RegExp(`run=${second.analysis_run_id}`));
  await expect(region.getByText(/Original parent/)).toBeVisible();
});

test('dataset row inspection stays independent of an incident and replay rows stay frame scoped',async({page,request})=>{
  test.setTimeout(90000);
  await page.goto('/');await page.getByRole('button',{name:'Load positive demo'}).click();
  await page.getByRole('button',{name:'Analyze rules-only'}).click();
  await page.getByRole('button',{name:/Suspected chain/}).click();
  await page.getByRole('button',{name:'Inspect row',exact:true}).first().click();
  const evidence=page.getByRole('region',{name:'Raw evidence'});
  await expect(evidence.getByText('Dataset source inspection, separate from selected incident support.')).toBeVisible();
  await evidence.getByRole('button',{name:'Close evidence'}).click();
  const parentId=new URL(page.url()).searchParams.get('run')!;
  const parent=await (await request.get(`/api/analyses/${parentId}`)).json();
  const region=page.getByRole('region',{name:'Retrospective event-time replay'});
  await region.getByLabel('Requested UTC cutoff').fill(parent.cutoff);
  await region.getByRole('button',{name:'Run frame',exact:true}).click();
  await expect(page.getByText(/Run kind: retrospective_replay/)).toBeVisible({timeout:60000});
  await page.getByRole('button',{name:/Suspected chain/}).click();
  await page.getByRole('button',{name:'Inspect row',exact:true}).first().click();
  await expect(evidence.getByText(/Source scoped to displayed run/)).toBeVisible();
  const frameId=new URL(page.url()).searchParams.get('run')!;
  await expect(evidence.getByText(/Source scoped to displayed run/)).toContainText(frameId);
});
