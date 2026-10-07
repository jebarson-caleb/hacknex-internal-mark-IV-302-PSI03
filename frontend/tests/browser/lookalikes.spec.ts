import { test, expect } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { resolve } from 'node:path';

test('real look-alike lab, per-arm sources, policy outcomes and refresh', async ({page,request})=>{
  test.setTimeout(90000);
  const setup=await request.post('/api/datasets/chronological-demo',{data:{seed:17,users:6,events:1200}});
  expect(setup.ok(),await setup.text()).toBeTruthy();const datasets=await setup.json();
  const fitting=await request.post('/api/baselines/train',{data:{training_dataset_id:datasets.training.id,calibration_dataset_id:datasets.calibration.id,benign_provenance:'Explicit benign browser setup'}});
  expect(fitting.ok(),await fitting.text()).toBeTruthy();const baseline=await fitting.json();
  await page.goto('/');
  const lab=page.getByRole('region',{name:'Benign look-alikes'});
  await lab.getByRole('combobox',{name:'Lab baseline',exact:true}).selectOption(baseline.baseline_id);
  const response=page.waitForResponse(r=>r.url().endsWith('/api/lookalike-labs') && r.status()===201);
  await lab.getByRole('button',{name:'Load synthetic look-alike lab (no fitting)'}).click();
  const library=await (await response).json();
  const first=library.pairs[0].comparison_id;
  await expect(lab.getByText('Withheld versus exact declaration · context-only · comparison '+first)).toBeVisible();
  const saved=await (await request.get('/api/lookalikes/'+first)).json();
  await expect(lab.getByRole('region',{name:'Left comparison arm'}).getByText(/Remaining false-positive alert/)).toBeVisible();
  for(const side of ['left','right']) {
    await lab.getByRole('button',{name:`Inspect ${side} transfer source`,exact:true}).click();
    const evidence=page.getByRole('region',{name:'Raw evidence'});
    await expect(evidence.locator('pre').last()).toContainText('approved by myself <script>untrusted</script>');
    await expect(evidence.locator('script')).toHaveCount(0);
    const run=saved[side].analysis_run_id;
    const candidates=await (await request.get(`/api/analyses/${run}/candidates`)).json();
    const source=await (await request.get(`/api/incidents/${candidates.items[0].incident_id}/source/${candidates.items[0].stages[2].evidence_event_ids[0]}`)).json();
    expect(source.analysis_run_id).toBe(run);
    await page.getByRole('button',{name:'Close evidence'}).click();
  }
  await lab.getByRole('region',{name:'Right comparison arm'}).getByText('Actual copy context match predicates and event time').click();
  await expect(lab.getByRole('region',{name:'Right comparison arm'}).locator('pre').filter({hasText:'"matched": true'})).toBeVisible();
  await page.reload();
  await expect(lab.getByText('Withheld versus exact declaration · context-only · comparison '+first)).toBeVisible();
  const rules=library.pairs.find((p:{name:string})=>p.name==='Rules-only preservation');
  await lab.getByLabel('Saved look-alike comparison').selectOption(rules.comparison_id);
  await expect(lab.getByText(/decision unchanged/)).toBeVisible();
  await expect(lab.getByText(/Remaining false-positive alert/)).toHaveCount(2);
  const missing=library.pairs.find((p:{name:string})=>p.name==='Missing transfer');
  await lab.getByLabel('Saved look-alike comparison').selectOption(missing.comparison_id);
  await expect(lab.getByRole('region',{name:'Right comparison arm'}).getByText(/partial_observation/)).toBeVisible();
  await expect(lab.getByRole('button',{name:'Inspect right transfer source',exact:true})).toHaveCount(0);
  const familiar=library.pairs.find((p:{name:string})=>p.name==='Historical familiarity');
  await lab.getByLabel('Saved look-alike comparison').selectOption(familiar.comparison_id);
  await expect(lab.getByText(/Absent candidate: incident risk unavailable/)).toBeVisible();
  const output=resolve('../runtime/phase4b-browser-reports');mkdirSync(output,{recursive:true});
  await page.screenshot({path:resolve(output,first+'-familiar.png'),fullPage:true});
});

test('late real response and failed selection cannot display a previous pair', async ({page,request})=>{
  const entries=await (await request.get('/api/lookalikes?limit=100')).json();
  const first=entries.items.find((p:{analyst_note:string})=>p.analyst_note==='Withheld versus exact declaration');
  const second=entries.items.find((p:{analyst_note:string})=>p.analyst_note==='Historical familiarity');
  expect(first).toBeTruthy();expect(second).toBeTruthy();
  await page.goto('/?lookalike='+first.comparison_id);
  const lab=page.getByRole('region',{name:'Benign look-alikes'});
  await expect(lab.getByText(/Withheld versus exact declaration · context-only · comparison/)).toBeVisible();
  let release!:()=>void;
  const gate=new Promise<void>(resolve=>{release=resolve;});
  let arrived!:()=>void;const pending=new Promise<void>(resolve=>{arrived=resolve;});
  await page.route('**/api/lookalikes/'+first.comparison_id,async route=>{
    const actual=await route.fetch();arrived();await gate;await route.fulfill({response:actual});
  });
  await lab.getByLabel('Saved look-alike comparison').selectOption(second.comparison_id);
  await expect(lab.getByText(/Historical familiarity · scenario · comparison/)).toBeVisible();
  await lab.getByLabel('Saved look-alike comparison').selectOption(first.comparison_id);await pending;
  await expect(lab.getByRole('region',{name:'Left comparison arm'})).toHaveCount(0);
  await lab.getByLabel('Saved look-alike comparison').selectOption(second.comparison_id);
  await expect(lab.getByText(/Historical familiarity · scenario · comparison/)).toBeVisible();release();
  await expect(lab.getByText(/Withheld versus exact declaration · context-only · comparison/)).toHaveCount(0);
  await page.unrouteAll({behavior:'wait'});
  await page.goto('/?lookalike=not-found');
  await expect(lab.getByRole('alert')).toContainText('Look-alike comparison not found');
  await expect(lab.getByRole('region',{name:'Left comparison arm'})).toHaveCount(0);
  await expect(lab.getByRole('button',{name:'Retry comparison'})).toBeEnabled();
});
