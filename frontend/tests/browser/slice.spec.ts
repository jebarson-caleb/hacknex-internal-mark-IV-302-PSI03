import { test, expect } from '@playwright/test';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

test('real benign and positive demo through API, timeline and raw evidence', async ({ page }) => {
  const failures: string[] = [];
  page.on('pageerror', e => failures.push(e.message));
  await page.goto('/');
  await expect(page.getByText('Phase 4C · rules-only')).toBeVisible();
  await page.getByRole('button',{name:'Load benign demo'}).click();
  await expect(page.getByRole('button',{name:'Analyze rules-only'})).toBeEnabled();
  await page.getByRole('button',{name:'Analyze rules-only'}).click();
  await expect(page.getByText('0 incidents')).toBeVisible();
  await expect(page.getByText(/No supported chain found/)).toBeVisible();
  await page.getByRole('button',{name:'Load positive demo'}).click();
  await expect(page.getByRole('button',{name:'Analyze rules-only'})).toBeEnabled();
  await page.getByRole('button',{name:'Analyze rules-only'}).click();
  await expect(page.getByText('1 incidents')).toBeVisible();
  await page.getByRole('button',{name:/Suspected chain/}).click();
  await expect(page.getByText('USB mounted · corroborating context')).toBeVisible();
  const stages = page.locator('article.stage h3');
  await expect(stages).toHaveText(['Unusual successful authentication','Unusual sensitive local-file collection',
    'USB mounted · corroborating context','Observed transfer to removable media']);
  await page.getByRole('button',{name:'Open transfer evidence'}).click();
  const evidence = page.getByRole('region',{name:'Raw evidence'});
  await expect(evidence.getByText(/Retained hashes and source row: verified/)).toBeVisible();
  await expect(evidence.locator('pre').last()).toContainText('file_copy_to_usb');
  await page.getByRole('button',{name:'Close evidence'}).click();
  await expect(evidence).toHaveCount(0);
  await page.getByRole('button',{name:'Load missing-transfer demo'}).click();
  await expect(page.getByRole('button',{name:'Analyze rules-only'})).toBeEnabled();
  await page.getByRole('button',{name:'Analyze rules-only'}).click();
  await page.getByRole('button',{name:/Partial observation/}).click();
  await expect(page.getByText(/Missing: Compatible explicit/)).toBeVisible();
  await expect(page.getByRole('button',{name:'Open transfer evidence'})).toHaveCount(0);
  expect(failures).toEqual([]);
});

test('uploaded CSV source families plus separate trusted context reconstruct the chain', async ({ page }) => {
  await page.goto('/');
  await page.getByText('Upload compatible logs', {exact:true}).click();
  await page.getByLabel('Environment namespace').fill('synthetic-office');
  for (const family of ['auth','file','device','network']) {
    await page.getByLabel('Source adapter').selectOption(family);
    await page.getByLabel('CSV or JSONL').setInputFiles(resolve(`../data/samples/positive/${family}.csv`));
    await Promise.all([
      page.waitForResponse(r => r.url().endsWith('/api/datasets/upload') && r.status() === 201),
      page.getByRole('button',{name:'Upload and normalize'}).click(),
    ]);
    await expect(page.getByRole('button',{name:'Upload and normalize'})).toBeEnabled();
  }
  await page.getByText('Trusted resource sensitivity metadata',{exact:true}).click();
  await page.getByLabel('Resource context JSON').fill(readFileSync(resolve('../data/samples/positive/trusted_resources.json'),'utf8'));
  await page.getByRole('button',{name:'Apply trusted resource labels'}).click();
  await expect(page.getByRole('button',{name:'Analyze rules-only'})).toBeEnabled();
  await page.getByRole('button',{name:'Analyze rules-only'}).click();
  await expect(page.getByText('1 incidents')).toBeVisible();
  await page.getByRole('button',{name:/Suspected chain/}).click();
  await page.getByRole('button',{name:'Open transfer evidence'}).click();
  await expect(page.getByRole('region',{name:'Raw evidence'}).getByText('file.csv · row 48 · accepted')).toBeVisible();
});

test('explicit baseline fitting, real hybrid risk, graph and measured benchmark', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('button',{name:'Load chronological demo'}).click();
  await expect(page.getByRole('button',{name:'Load chronological demo'})).toBeEnabled();
  await page.getByText('Frozen baseline & analysis mode',{exact:true}).click();
  await page.getByRole('button',{name:'Fit selected benign baseline'}).click();
  await expect(page.getByText('Phase 4C · hybrid')).toBeVisible();
  await expect(page.getByRole('button',{name:'Analyze hybrid'})).toBeEnabled();
  await page.getByRole('button',{name:'Analyze hybrid'}).click();
  await expect(page.getByText('1 incidents')).toBeVisible();
  await page.getByRole('button',{name:/Suspected chain/}).click();
  await page.getByText('Reproducible hybrid risk breakdown',{exact:true}).click();
  await expect(page.locator('pre').filter({hasText:'anomaly_percentile'})).toContainText('weighted_terms');
  await page.getByRole('button',{name:'Inspect typed entity graph'}).click();
  const graph=page.getByRole('region',{name:'Entity graph'});
  await expect(graph.getByRole('cell',{name:'copied_to',exact:true})).toBeVisible();
  await expect(graph.getByRole('cell',{name:'removable_device',exact:true})).toBeVisible();
  await page.getByText('Measured synthetic evaluation',{exact:true}).click();
  await page.getByRole('button',{name:'Run held-out synthetic benchmark'}).click();
  await expect(page.getByText(/Counts are measured. Synthetic holdouts/)).toBeVisible();
});


test('linked retained-run evidence, real JSON/Markdown downloads, filters and refresh', async ({page,request}) => {
  await page.goto('/');
  await page.getByRole('button',{name:'Load positive demo'}).click();
  await page.getByRole('button',{name:'Analyze rules-only'}).click();
  await page.getByRole('button',{name:/Suspected chain/}).click();
  await expect(page).toHaveURL(/incident=/);
  const params=new URLSearchParams(new URL(page.url()).search);
  const runId=params.get('run')!,incidentId=params.get('incident')!;
  const incident=await (await request.get(`/api/incidents/${incidentId}`)).json();
  await page.getByRole('button',{name:'Open transfer evidence'}).click();
  const graph=page.getByRole('region',{name:'Entity graph'});
  const linked=graph.locator('tr.linked').filter({has:page.getByRole('cell',{name:'copied_to',exact:true})});
  await expect(linked).toHaveAttribute('data-event-ids',incident.stages[2].evidence_event_ids[0]);
  await linked.getByRole('button',{name:'Open copied_to source'}).click();
  await expect(page.getByRole('region',{name:'Raw evidence'}).locator('pre').last()).toContainText('file_copy_to_usb');
  for (const format of ['JSON','Markdown']) {
    const waiting=page.waitForEvent('download');
    await page.getByRole('button',{name:`Download ${format} report`}).click();
    const download=await waiting;
    const file=resolve(`../runtime/browser-reports/${download.suggestedFilename()}`);
    await download.saveAs(file);
    const text=readFileSync(file,'utf8');
    const report=format==='JSON' ? JSON.parse(text) : JSON.parse(text.split('```traceguard-json\n')[1].split('\n```')[0]);
    expect(report.incident.incident_id).toBe(incidentId);
    expect(report.run.analysis_run_id).toBe(runId);
    expect(report.incident.stages).toEqual(incident.stages);
    expect(report.validation.valid).toBe(true);
    const command=spawnSync(resolve(process.platform==='win32' ? '../.venv/Scripts/python.exe' : '../.venv/bin/python'),
      ['-m','traceguard.cli','--db',resolve('../runtime/browser-test.sqlite3'),'verify-report',file],{encoding:'utf8'});
    expect(command.status,command.stdout+command.stderr).toBe(0);
  }
  await page.screenshot({path:resolve('../runtime/phase3-workbench.png'),fullPage:true});
  await page.reload();
  await expect(page.getByRole('button',{name:'Download JSON report'})).toBeVisible();
  expect(new URL(page.url()).searchParams.get('run')).toBe(runId);
  await page.getByLabel('Search account, endpoint, ID or explanation').fill('does-not-exist');
  await page.getByRole('button',{name:'Apply candidate filters'}).click();
  await expect(page.getByText(/0 matching candidates/)).toBeVisible();
  await page.getByLabel('Search account, endpoint, ID or explanation').fill('');
  await page.getByLabel('Candidate decision').selectOption('partial_observation');
  await page.getByRole('button',{name:'Apply candidate filters'}).click();
  await expect(page.getByText(/0 matching candidates/)).toBeVisible();
  // Neither filters nor context edits recompute the retained incident.
  await page.getByText('Trusted resource sensitivity metadata',{exact:true}).click();
  const resources=JSON.parse(await page.getByLabel('Resource context JSON').inputValue());
  resources.forEach((r: {sensitive:boolean}) => {r.sensitive=false;});
  await page.getByLabel('Resource context JSON').fill(JSON.stringify(resources));
  await page.getByRole('button',{name:'Apply trusted resource labels'}).click();
  await expect(page.getByRole('button',{name:'Download JSON report'})).toBeEnabled();
  const response=await request.get(`/api/incidents/${incidentId}/report`);
  expect(response.ok()).toBe(true);
  expect((await response.json()).incident).toEqual(incident);
  await page.getByText('Measured synthetic evaluation',{exact:true}).click();
  await page.getByRole('button',{name:'Run held-out synthetic benchmark'}).click();
  await expect(page.getByText(/Counts are measured/)).toBeVisible();
  await page.getByRole('button',{name:'Load benign demo'}).click();
  await expect(page.getByText(/Ground truth unavailable/)).toBeVisible();
  await expect(page.getByText(/Counts are measured/)).toHaveCount(0);
});


test('real incident pagination keeps later episodes separate', async ({page,request}) => {
  await page.goto('/');
  await page.getByRole('button',{name:'Load positive demo'}).click();
  await page.getByRole('button',{name:'Analyze rules-only'}).click();
  await expect(page.getByRole('button',{name:/Suspected chain/})).toBeVisible();
  const runId=new URL(page.url()).searchParams.get('run')!;
  const run=await (await request.get(`/api/analyses/${runId}`)).json();
  const item=(await (await request.get(`/api/analyses/${runId}/incidents`)).json())[0];
  const families=new Map<string,{source_id:string;records:Record<string,unknown>[]}>();
  for (const id of item.selected_evidence) {
    const evidence=await (await request.get(`/api/events/${id}`)).json();
    const event=evidence.event;
    if(!families.has(event.source_type)) families.set(event.source_type,{source_id:event.source_id,records:[]});
    for(let index=1;index<=21;index++) {
      const raw={...evidence.source_records[0].raw};
      raw.timestamp=new Date(Date.parse(event.event_time_utc)+index*20*60*1000).toISOString();
      if(raw.source_event_id) raw.source_event_id=String(raw.source_event_id)+'-episode-'+index;
      families.get(event.source_type)!.records.push(raw);
    }
  }
  for (const [family, data] of families) {
    const result=await request.post('/api/datasets/upload',{multipart:{dataset_id:run.dataset_id,environment_id:'synthetic-office',source_type:family,source_id:data.source_id,
      file:{name:`later-${family}.jsonl`,mimeType:'application/x-ndjson',buffer:Buffer.from(data.records.map(r => JSON.stringify(r)).join('\n'))}}});
    expect(result.ok(),await result.text()).toBe(true);
  }
  await page.getByRole('button',{name:'Analyze rules-only'}).click();
  await expect(page.getByText(/22 matching candidates/)).toBeVisible();
  await expect(page.getByRole('button',{name:/Suspected chain/})).toHaveCount(20);
  await page.getByRole('button',{name:'Next candidate page'}).click();
  await expect(page.getByRole('button',{name:/Suspected chain/})).toHaveCount(2);
  await expect(page.getByRole('button',{name:'Next candidate page'})).toHaveCount(0);
});
