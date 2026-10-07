"""Privacy-minimal representative report derived only from saved evaluation evidence."""
import argparse
import json
from pathlib import Path
from statistics import median


def report(directory):
    d = json.loads((directory/'evaluation.json').read_text())
    text = ['# Phase 4D representative synthetic evaluation report', '',
        f"Protocol `{d['protocol']['version']}` / generator `{d['protocol']['generator_version']}`; SHA256 `{d['protocol_sha256']}`.", '',
        f"Evaluation-first checkpoint, before replay. {len(d['profiles'])} predefined seed profile(s) have distinct chronological benign training, benign calibration and final-test observations. Four supported attacks per profile vary timing, identity, resource, amount, direct alias/corroboration and later repeat actor. Legitimate exports remain benign without matching authorization. No final-test tuning or model replacement.", '',
        '| Output | Matched / emitted | Matched / supported episodes | Benign FP units / active benign units | Benign false outputs / accepted test observations |',
        '|---|---:|---:|---:|---:|']
    for mode,m in d['totals'].items():
        fmt = lambda k: f"{m[k]['numerator']}/{m[k].get('denominator',m[k].get('accepted_events'))}" if k in m else 'N/A: windows'
        text.append(f"| {mode} | {fmt('incident_precision')} | {fmt('incident_recall')} | {fmt('benign_user_device_day_fpr')} | {fmt('benign_false_alerts_per_1000_events')} |")
    text += ['', 'Window alarms do not reconstruct stages; their chain metrics are not applicable. All modes use the same alias-resolved accepted active user-device-day population; every labeled malicious observed unit is excluded, including missing-copy/out-of-window cases. Units without candidates count. Evidence spanning days implicates each selected day. Benign false outputs per1000 observations and active-unit FPR are separate quantities. A false unmatched incident on a malicious unit is not a benign-unit false positive.', '',
        '| Seed | Accepted training / calibration / test | Rejected train / calibration / test | Calibration complete / alerts / units | Applied threshold / status |',
        '|---|---|---|---|---|']
    for p in d['profiles']:
        folder = directory/f"seed-{p['seed']}"
        cal = json.loads((folder/'calibration.json').read_text())
        counts = lambda key: '/'.join(str(p['quality'][r][key]) for r in ('training','calibration','test'))
        text.append(f"| {p['seed']} | {counts('accepted')} | {counts('rejected')} | {cal['complete_candidate_count']}/{cal['actual_alerts_at_threshold']}/{cal['benign_units']} | {p['calibration']['threshold']}/{p['calibration']['status']} |")
    text += ['', f"Each {d['protocol']['profile']} profile requests {d['protocol']['requested_records_per_profile']} background observations; complete routine groups and added scenario records determine actual counts. Generated/accepted/rejected/quarantined/duplicate/source hashes are retained per partition. Calibration contains eight benign export templates, seven complete candidates. The familiar case does not meet novelty. Calibration audit candidate decision/mode is the prethreshold structural correlator output; actual hybrid emission is independently counted using applied risk/threshold/scored-window gates. Fresh verification records both structural and applied decisions.", '',
        '| Seed | Mode | Matches / alerts | Benign false-positive units | Required stages / labeled stages | Valid asserted stages | Order coverage / accuracy |',
        '|---|---|---|---|---|---|---|']
    for p in d['profiles']:
        for mode,m in p['metrics'].items():
            fmt = lambda k: f"{m[k]['numerator']}/{m[k]['denominator']}" if isinstance(m.get(k),dict) else 'N/A'
            text.append(f"| {p['seed']} | {mode} | {fmt('incident_precision')} | {fmt('benign_user_device_day_fpr')} | {fmt('required_stage_recall')} | {fmt('asserted_stage_evidence_coverage')} | {fmt('ordering_constraint_coverage')} / {fmt('ordering_constraint_accuracy')} |")
    text += ['', 'Stage and ordering coverage include validated supported partial/review candidates; they are distinct from alert episode recall. Saved independent source/stage/graph checks determine evidence validity. One-to-one matches retain eligible-match decisions, duplicate/oversized rejection and unmatched truth/predictions. Partial/review output is not a safety judgment. Missing-copy/out-of-window malicious cases stay separately labeled and outside supported full-observability recall.', '',
        'Full hybrid versus rules-only is a whole-pipeline comparison. Exact/repeated authorization subtracts20 once in hybrid; this policy effect cannot be credited to the forest. A=0 diagnostic fixes all observations, context, model bytes, other terms, availability gates and threshold. Its different outputs measure sensitivity to that term, not an independently optimized detector or real-world model benefit. Remaining benign alerts and missed supported episodes remain inspectable.', '',
        '| Seed | Benign case | Ordinary rules-only decisions | Ordinary hybrid decisions |',
        '|---|---|---|---|']
    for p in d['profiles']:
        cases = json.loads((directory/f"seed-{p['seed']}"/'case-outcomes.json').read_text())
        for a,b in zip(cases['rules-only'],cases['hybrid']):
            if a['category']=='benign' and a['variant'] in d['protocol']['benign_complete_templates']:
                fmt = lambda c: ','.join(x['decision'] for x in c['related_predictions']) or 'absent'
                text.append(f"| {p['seed']} | {a['variant']} | {fmt(a)} | {fmt(b)} |")
    text += ['', 'Proposed1% target: compare the recorded unit fractions with0.01; it is an engineering target, not an organizer rule or deployment guarantee. Native calibration may report budget_not_met and retain80 when no useful candidate boundary meets the budget. Raw-score window quantile selection is separate from incident calibration. Calibration percentile sample counts and threshold ties are recorded per seed; ties can exceed the nominal window1% tail.', '',
        '| Measured operation | Seed run count | Median seconds | Range seconds |',
        '|---|---:|---:|---:|']
    for key in d['profiles'][0]['processing_seconds']:
        values = [p['processing_seconds'][key] for p in d['profiles']]
        text.append(f"| {key} | {len(values)} | {median(values):.4f} | {min(values):.4f}–{max(values):.4f} |")
    text += ['', f"Total wrapper time {d['total_seconds']:.4f}s. One measurement per distinct seed workload; the table describes different profiles, not repeated identical trials. Fresh DB/models, warm installed libraries/OS caches, concurrent host checks and contention uncontrolled. Hardware: {d['hardware']['platform']}; {d['hardware']['processor']}; Python {d['hardware']['python']}. Process resident memory unmeasured. Inference workload is accepted test observations only. No streaming or speed-superiority claim.", '',
        'The bounded sample is correlated and synthetic. No confidence/independence, generalization, production readiness, human intent or source authenticity claim. No credentials, raw logs, private paths, databases or cache content are included in this representative report. Reproduction uses the documented CLI with a new local output directory; runtime evidence stays local.', '',
        '**Phase 4C replay plus final submission checks remaining.**']
    return '\n'.join(text)+'\n'


if __name__=='__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('directory',type=Path)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    content = report(args.directory)
    with args.output.open('x',encoding='utf-8') as stream: stream.write(content)
    print(str(args.output))
