"""Fresh native evidence-sensitivity artifacts and real process-restart verification."""
import argparse
import copy
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from datetime import timedelta
from pathlib import Path

from traceguard.ingest import digest
from traceguard.storage import Store


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    db = output / 'traceguard.sqlite3'
    root = Path(__file__).resolve().parents[1]
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0)); port = listener.getsockname()[1]
    url = f'http://127.0.0.1:{port}'

    def request(path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        with urllib.request.urlopen(urllib.request.Request(url + path, data=data,
                headers={'Content-Type': 'application/json'}), timeout=60) as response:
            raw = response.read()
            return json.loads(raw) if response.headers.get_content_type() == 'application/json' else raw

    def start():
        process = subprocess.Popen([sys.executable, str(root / 'scripts/run_demo.py'), '--port', str(port)],
            env={**os.environ, 'TRACEGUARD_DB': str(db)}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError('Native demo exited before health')
            try:
                assert request('/api/health')['status'] == 'ok'
                return process
            except OSError:
                time.sleep(.1)
        process.terminate(); process.wait(timeout=15)
        raise RuntimeError('Native demo startup timeout')

    def save(name, body):
        with (output / name).open('x', encoding='utf-8', newline='\n') as handle:
            handle.write(json.dumps(body, indent=2, ensure_ascii=True))

    results = []
    process = start()
    try:
        assert b'<div id="root"></div>' in request('/')
        store = Store(db)
        for case in ('unique-copy', 'independent-copy', 'hybrid-copy'):
            baseline_id = None
            if case == 'hybrid-copy':
                datasets = request('/api/datasets/chronological-demo', {'seed': 17, 'users': 6, 'events': 1200})
                fitted = request('/api/baselines/train', {'training_dataset_id': datasets['training']['id'],
                    'calibration_dataset_id': datasets['calibration']['id'], 'benign_provenance': 'Explicit generated benign smoke selection'})
                baseline_id = fitted['baseline_id']
                dataset_id = datasets['test']['id']
            else:
                dataset_id = request('/api/datasets/demo', {'variant': 'positive', 'seed': 17})['dataset']['id']
                event = next(e for e in store.events(dataset_id) if e.action == 'file_copy_to_usb')
                source = store.evidence(event.event_id)['source_records'][0]
                # Duplicate representation is retained, never independent evidence.
                store.ingest(dataset_id, json.dumps(source['raw']).encode(), 'duplicate.jsonl', source['source_id'], source['source_type'])
                if case == 'independent-copy':
                    raw = copy.deepcopy(source['raw'])
                    raw['timestamp'] = (event.event_time_utc + timedelta(minutes=1)).isoformat()
                    store.ingest(dataset_id, json.dumps(raw).encode(), 'independent.jsonl', source['source_id'], source['source_type'])
            parent = request('/api/analyses', {'dataset_id': dataset_id, 'mode': 'hybrid' if baseline_id else 'rules-only', 'baseline_id': baseline_id})
            incident = next(i for i in request(f"/api/analyses/{parent['analysis_run_id']}/incidents") if len(i['stages']) == 3)
            report = request(f"/api/incidents/{incident['incident_id']}/report")
            save(case + '-parent.json', report)
            report_hash = digest((output / (case + '-parent.json')).read_bytes())
            model = store.baseline(baseline_id) if baseline_id else None
            noop = request(f"/api/analyses/{parent['analysis_run_id']}/sensitivity", {'excluded_event_ids': []})
            noop_export = request(f"/api/sensitivities/{noop['comparison_id']}/report")
            assert request('/api/sensitivity-verifications', noop_export)['valid']
            save(case + '-noop.json', noop_export)
            excluded = incident['stages'][-1]['evidence_event_ids']
            comparison = request(f"/api/analyses/{parent['analysis_run_id']}/sensitivity", {'excluded_event_ids': excluded})
            complete = any(len(i['stages']) == 3 for i in comparison['after_candidates'])
            assert complete == (case == 'independent-copy')
            assert all(not set(excluded) & set(i['selected_evidence']) for i in comparison['after_candidates'])
            exported = request(f"/api/sensitivities/{comparison['comparison_id']}/report")
            assert request('/api/sensitivity-verifications', exported)['valid']
            save(case + '-comparison.json', exported)
            tampered = copy.deepcopy(exported); tampered['manifest']['excluded_event_ids'] = []
            assert not request('/api/sensitivity-verifications', tampered)['valid']
            save(case + '-tampered.json', tampered)
            assert request(f"/api/analyses/{parent['analysis_run_id']}") == parent
            after_report = request(f"/api/incidents/{incident['incident_id']}/report")
            after_report['validation']['checked_at_utc'] = report['validation']['checked_at_utc']
            assert after_report == report
            assert digest((output / (case + '-parent.json')).read_bytes()) == report_hash
            if baseline_id:
                assert store.baseline(baseline_id) == model
            results.append({'case': case, 'comparison_id': comparison['comparison_id'],
                'noop_comparison_id': noop['comparison_id'],
                'parent_run_id': parent['analysis_run_id'], 'child_run_id': comparison['manifest']['child_run_id'],
                'parent_report_sha256': report_hash, 'complete_after': complete,
                'duration_seconds': comparison['duration_seconds'], 'model_unchanged': True if baseline_id else None})
    finally:
        process.terminate(); process.wait(timeout=15)
    process = start()
    try:
        for result in results:
            exported = request(f"/api/sensitivities/{result['comparison_id']}/report")
            assert exported == json.loads((output / (result['case'] + '-comparison.json')).read_text())
            assert request('/api/sensitivity-verifications', exported)['valid']
            noop = request(f"/api/sensitivities/{result['noop_comparison_id']}/report")
            assert noop == json.loads((output / (result['case'] + '-noop.json')).read_text())
            assert request('/api/sensitivity-verifications', noop)['valid']
            result['restart_verified'] = True
    finally:
        process.terminate(); process.wait(timeout=15)
    summary = {'output': str(output), 'db': str(db), 'built_ui': 'served', 'results': results,
        'limits': 'Generated regression cases; not broader evaluation, causal proof or generalization'}
    save('smoke.json', summary)
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
