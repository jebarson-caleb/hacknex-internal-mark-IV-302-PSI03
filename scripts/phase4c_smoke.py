"""Explicit setup, cutoff reruns, exports, fixed artifacts, real server restart."""
import argparse
import copy
import json
import os
import platform
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import timedelta
from pathlib import Path

from traceguard.features import window_start
from traceguard.storage import Store


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve();output.mkdir(parents=True, exist_ok=False)
    db = output/'traceguard.sqlite3'
    root = Path(__file__).resolve().parents[1]
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));port = listener.getsockname()[1]
    url = f'http://127.0.0.1:{port}'
    def request(path,body=None):
        data = json.dumps(body).encode() if body is not None else None
        with urllib.request.urlopen(urllib.request.Request(url+path,data=data,headers={'Content-Type':'application/json'}),timeout=120) as response:
            raw = response.read()
            return json.loads(raw) if response.headers.get_content_type() == 'application/json' else raw
    def start():
        process = subprocess.Popen([sys.executable,str(root/'scripts/run_demo.py'),'--port',str(port)],
            env={**os.environ,'TRACEGUARD_DB':str(db)},stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(100):
            if process.poll() is not None: raise RuntimeError('Demo process exited')
            try:
                assert request('/api/health')['status'] == 'ok'
                return process
            except OSError: time.sleep(.1)
        process.terminate();process.wait(timeout=15)
        raise RuntimeError('Startup timeout')
    def save(name,value):
        (output/name).write_text(json.dumps(value,indent=2),encoding='utf-8')
    started = time.perf_counter();process = start()
    frames = [];timings = [];reports = []
    try:
        assert b'<div id="root"></div>' in request('/')
        data = request('/api/datasets/chronological-demo',{'seed':17,'users':6,'events':1200})
        model = request('/api/baselines/train',{'training_dataset_id':data['training']['id'],
            'calibration_dataset_id':data['calibration']['id'],'benign_provenance':'Explicit generated benign replay smoke setup'})
        parent = request('/api/analyses',{'dataset_id':data['test']['id'],'mode':'hybrid','baseline_id':model['baseline_id']})
        store = Store(db);artifact = store.baseline(model['baseline_id'])
        items = request(f"/api/analyses/{parent['analysis_run_id']}/incidents")
        complete = next(i for i in items if len(i['stages']) == 3)
        nav = request(f"/api/analyses/{parent['analysis_run_id']}/replay")
        copy_time = store.event(complete['stages'][2]['evidence_event_ids'][0]).event_time_utc
        stops = [nav['start'],(copy_time-timedelta(microseconds=1)).isoformat(),copy_time.isoformat(),
            (window_start(copy_time)+timedelta(minutes=15)).isoformat(),parent['cutoff']]
        for index,cutoff in enumerate(stops):
            clock = time.perf_counter()
            result = request(f"/api/analyses/{parent['analysis_run_id']}/replay",{'cutoff':cutoff})
            wall = time.perf_counter()-clock;run = result['run'];fid = run['analysis_run_id']
            candidates = request(f'/api/analyses/{fid}/candidates')['items']
            if index == 0: assert not candidates and run['event_count'] == 0
            if index == 1: assert all(len(i['stages']) < 3 for i in candidates)
            if index in (2,3):
                item = next(i for i in candidates if len(i['stages']) == 3)
                assert (item['risk']['anomaly_percentile'] is None) == (index == 2)
                for fmt in ('json','markdown'):
                    report = request(f"/api/incidents/{item['incident_id']}/report?format={fmt}")
                    name = f'frame-{index}-report.{fmt}'
                    if fmt == 'json': save(name,report)
                    else: (output/name).write_bytes(report)
                    check = subprocess.run([sys.executable,'-m','traceguard.cli','--db',str(db),'verify-report',str(output/name)],capture_output=True,text=True)
                    assert check.returncode == 0, check.stdout+check.stderr
                    reports.append({'path':name,'valid':True})
            save(f'frame-{index}.json',result);frames.append(result)
            timings.append({'cutoff':cutoff,'request_seconds':wall,'creation_seconds':result['duration_seconds'],
                'active_observations':run['event_count'],'candidates':len(candidates),'mode':run['mode'],'baseline_id':run['baseline_id']})
        clock = time.perf_counter()
        repeated = request(f"/api/analyses/{parent['analysis_run_id']}/replay",{'cutoff':stops[1]})
        repeat_seconds = time.perf_counter()-clock
        assert repeated == frames[1]
        assert request(f"/api/analyses/{parent['analysis_run_id']}") == parent
        assert store.baseline(model['baseline_id']) == artifact
        forged = copy.deepcopy(frames[2]['run']);forged['cutoff'] = parent['cutoff']
        with store.connection() as conn:
            conn.execute('UPDATE analyses SET body=? WHERE id=?',(json.dumps(forged),forged['analysis_run_id']))
        try:
            request(f"/api/replay-frames/{forged['analysis_run_id']}")
            raise AssertionError('Tampered cutoff accepted')
        except urllib.error.HTTPError as exc: assert exc.code == 422
        with store.connection() as conn:
            conn.execute('UPDATE analyses SET body=? WHERE id=?',(json.dumps(frames[2]['run']),forged['analysis_run_id']))
        save('parent.json',parent);save('model-metadata.json',model)
    finally:
        process.terminate();process.wait(timeout=15)
    process = start();clock = time.perf_counter()
    try:
        for result in frames:
            assert request(f"/api/replay-frames/{result['run']['analysis_run_id']}") == result
        assert request(f"/api/analyses/{parent['analysis_run_id']}") == parent
    finally:
        process.terminate();process.wait(timeout=15)
    summary = {'argv':sys.argv,'host':platform.platform(),'processor':platform.processor(),'python':platform.python_version(),
        'timings':timings,'repeat_request_seconds':repeat_seconds,'restart_verification_seconds':time.perf_counter()-clock,
        'total_seconds':time.perf_counter()-started,'reports':reports,'model_parent_unchanged':True,'tamper_rejected':True,
        'restart_verified':True,'built_ui_served':True,'resident_memory':'unmeasured',
        'limits':'Fresh small development fixture; bounded synchronous verification; host contention uncontrolled; no streaming guarantee'}
    save('smoke.json',summary);print(json.dumps(summary,indent=2))


if __name__ == '__main__': main()
