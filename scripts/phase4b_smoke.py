"""Native retained comparison/report checks across a real process restart."""
import argparse
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import urllib.request

from traceguard.ingest import digest
from traceguard.reports import read_report, verify_report
from traceguard.storage import Store


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    db = output/'traceguard.sqlite3'
    root = Path(__file__).resolve().parents[1]
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]
    url = f'http://127.0.0.1:{port}'

    def request(path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        with urllib.request.urlopen(urllib.request.Request(url+path, data=data,
                headers={'Content-Type':'application/json'}), timeout=60) as response:
            raw = response.read()
            return json.loads(raw) if response.headers.get_content_type() == 'application/json' else raw

    def start():
        process = subprocess.Popen([sys.executable, str(root/'scripts/run_demo.py'), '--port', str(port)],
            env={**os.environ, 'TRACEGUARD_DB':str(db)}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError('Native demo exited before health')
            try:
                assert request('/api/health')['status'] == 'ok'
                return process
            except OSError:
                time.sleep(.1)
        process.terminate();process.wait(timeout=15)
        raise RuntimeError('Native startup timeout')

    def save(name, body):
        with (output/name).open('x', encoding='utf-8', newline='\n') as handle:
            handle.write(body if isinstance(body,str) else json.dumps(body,indent=2))

    process = start()
    try:
        assert b'<div id="root"></div>' in request('/')
        datasets = request('/api/datasets/chronological-demo', {'seed':17,'users':6,'events':1200})
        # Separate explicit fitting, completed before any lab/comparison action.
        baseline = request('/api/baselines/train', {'training_dataset_id':datasets['training']['id'],
            'calibration_dataset_id':datasets['calibration']['id'], 'benign_provenance':'Explicit synthetic benign native 4B setup'})
        store = Store(db)
        model_before = store.baseline(baseline['baseline_id'])
        library = request('/api/lookalike-labs', {'baseline_id':baseline['baseline_id'],'seed':17})
        save('library.json', library)
        results, frozen, reports = [], {}, []
        for pair in library['pairs']:
            value = request('/api/lookalikes/'+pair['comparison_id'])
            save(pair['comparison_id']+'.json', value)
            frozen[pair['comparison_id']] = value
            arms = []
            for side in ('left','right'):
                arm = value[side]
                candidates = request(f"/api/analyses/{arm['analysis_run_id']}/candidates")
                outcomes = []
                for candidate in candidates['items']:
                    for eid in candidate['selected_evidence']:
                        source = request(f"/api/incidents/{candidate['incident_id']}/source/{eid}")
                        assert source['analysis_run_id'] == arm['analysis_run_id']
                        assert all(r['hash_valid'] and r['file_hash_valid'] and r['file_row_valid'] for r in source['source_records'])
                    report = request(f"/api/incidents/{candidate['incident_id']}/report")
                    markdown = request(f"/api/incidents/{candidate['incident_id']}/report?format=markdown").decode()
                    assert verify_report(store,report)['valid'] and verify_report(store,read_report(markdown))['valid']
                    bad = copy.deepcopy(report);bad['incident']['risk']['score'] += 1
                    assert not verify_report(store,bad)['valid']
                    name = candidate['incident_id']+'.json'
                    if not (output/name).exists():
                        save(name,report);save(candidate['incident_id']+'.md',markdown)
                        reports.append(name)
                    outcomes.append({'incident_id':candidate['incident_id'],'decision':candidate['decision'],
                        'risk':candidate['risk']['score'],'threshold':candidate['risk'].get('threshold'),
                        'reduction':candidate['authorization']['reduction'], 'stages':[s['stage_id'] for s in candidate['stages']],
                        'false_positive_on_declared_benign':value['evaluation_annotation'][side]=='benign' and candidate['decision']=='incident'})
                arms.append({'side':side,'run_id':arm['analysis_run_id'],'outcomes':outcomes,
                             'history_probes':arm['history_probes'],'model_windows':arm['window_scores']})
            results.append({'case':pair['name'],'comparison_id':value['comparison_id'],
                'case_version':value['case_version'],'compatibility':value['compatibility'],
                'actual_changed_inputs':value['actual_changed_inputs'],'arms':arms,'correspondence':value['correspondence']})
        first = frozen[library['pairs'][0]['comparison_id']]
        sensitivity = request(f"/api/analyses/{first['left_run_id']}/sensitivity", {'excluded_event_ids':[]})
        sensitivity_report = request('/api/sensitivities/'+sensitivity['comparison_id']+'/report')
        assert request('/api/sensitivity-verifications', sensitivity_report)['valid']
        save('sensitivity-noop.json', sensitivity_report)
        bad = copy.deepcopy(sensitivity_report);bad['manifest']['parent_run_id'] = 'tampered'
        assert not request('/api/sensitivity-verifications',bad)['valid']
        save('sensitivity-tampered.json',bad)
        model_after = store.baseline(baseline['baseline_id'])
        assert model_before == model_after
        cli = subprocess.run([sys.executable,'-m','traceguard.cli','--db',str(db),'verify-report',str(output/reports[0])],capture_output=True,text=True)
        assert cli.returncode == 0, cli.stdout+cli.stderr
        save('cli-incident-verification.json',json.loads(cli.stdout))
        cli4a = subprocess.run([sys.executable,'-m','traceguard.cli','--db',str(db),'verify-report',str(output/'sensitivity-noop.json')],capture_output=True,text=True)
        assert cli4a.returncode == 0, cli4a.stdout+cli4a.stderr
        save('cli-sensitivity-verification.json',json.loads(cli4a.stdout))
        process.terminate();process.wait(timeout=15)
        process = start()
        for cid, value in frozen.items():
            assert request('/api/lookalikes/'+cid) == value
        assert request('/api/sensitivity-verifications', sensitivity_report)['valid']
        for name in reports:
            assert verify_report(Store(db),read_report((output/name).read_text(encoding='utf-8')))['valid']
        assert store.baseline(baseline['baseline_id']) == model_before
        summary = {'output':str(output),'db':str(db),'case_version':library['case_version'],
            'baseline_id':baseline['baseline_id'],'model_sha256':digest(model_before[1]),
            'model_integrity_unchanged':True,'built_ui_served':True,'restart_verified':True,
            'existing_incident_json_markdown_verified':True,'existing_sensitivity_verified':True,
            'tamper_rejected':True,'explicit_baseline_setup_separate':True,'results':results,
            'limits':'Curated development observations; no accuracy study, generalization or source authenticity claim'}
        save('smoke.json',summary)
        print(json.dumps({k:v for k,v in summary.items() if k!='results'},indent=2))
    finally:
        process.terminate();process.wait(timeout=15)


if __name__ == '__main__':
    main()
