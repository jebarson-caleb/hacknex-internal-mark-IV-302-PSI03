# Phase 4D checkpoint - evaluation-first gate passed

Date:2026-10-07, Asia/Calcutta. User explicitly selected4D before4C despite the older4B handoff. Completed Phase1–3,4A,4B retained. Prior BUILD_STATUS preserved byte-for-byte in PHASE4B_BUILD_STATUS.md. No replay, model replacement, inference policy edit, dependency upgrade, publication, deployment, push or remediation. Whole Phase4 is not complete.

Read AGENTS.md, root prompt, current status, schema/model/evaluation/limits/scope and actual Downloads/phase4_prompt.md section4D plus supplied phase4d_prompt.md. The attachment is supporting instructions within the user's explicitly selected4D scope. Existing source directories remain untracked and preserved. Inspected historical4B acceptance-summary/smoke and retained pair references: source SHA matches,11 IDs agree, historical model/restart outcomes agree, no discrepancy. This inspection is not a fresh4B run; the fresh native regression commands below are separate. Historical audit is saved in phase4d-full-20261007/historical-audit.json.

Delivered evaluation/expanded_fixtures.py, evaluation/expanded.py, phase4d_evaluate/verify/report scripts, nine focused tests and additive evaluator matching/unmatched records. Existing chronological generator, real ingestion, frozen forest/features, production rules-only/hybrid, actual window scorer, source/stage/graph validation and4A path are reused. Diagnostic A=0 alters only copied evaluation risk at fixed threshold/gates; never production mode/predictions. No UI change. Protocol/selected artifacts precede final analysis. Full results were not used to tune anything. Reports preserve false positives and calibrated fallback.

## Actual checks and commands

All from the project root; exact machine checklist is `runtime/phase4d-full-20261007/regression-checks.json`. Detailed evaluator argv/status/timer is each output's execution.json.

| Command | Actual result |
|---|---|
| `.\.venv\Scripts\python.exe -m pytest backend/tests -q` initial |105 passed39.17s |
| `.\.venv\Scripts\python.exe -m pytest backend/tests/test_phase4d.py -q` corrected |9 passed3.31s |
| `.\.venv\Scripts\python.exe -m pytest backend/tests -q` final |114 passed53.49s; existing Starlette/HTTPX deprecation warning |
| `npm --prefix frontend test` |6 passed1.78s |
| `npm --prefix frontend run build` |TypeScript/Vite passed20 modules; UI unchanged |
| `npm --prefix frontend run test:browser` |9 passed1.1m; real backend including4A/4B |
| `.\.venv\Scripts\python.exe scripts/phase4a_smoke.py --output runtime/phase4a-regression-4d-20261007` |Three exclusion/no-op/source/report/tamper/model/restart flows passed |
| `.\.venv\Scripts\python.exe scripts/phase4b_smoke.py --output runtime/phase4b-regression-4d-20261007` |11 comparisons, JSON/Markdown/sensitivity/tamper, model integrity, real process restart passed |
| `.\.venv\Scripts\python.exe scripts/phase4d_evaluate.py --profile smoke --output runtime/phase4d-smoke-20261007` |exit0;7.3702s wall,7.3224s experiment; four real comparisons |
| `.\.venv\Scripts\python.exe scripts/phase4d_evaluate.py --profile full --output runtime/phase4d-full-20261007` |exit0;299.8918s wall,299.7986s experiment; three full profiles |
| `.\.venv\Scripts\python.exe scripts/phase4d_verify.py runtime/phase4d-smoke-20261007 --output runtime/phase4d-smoke-20261007/fresh-verification.json` |exit0/valid=true, fresh process, one profile;0.0414s measured verification |
| `.\.venv\Scripts\python.exe scripts/phase4d_verify.py runtime/phase4d-full-20261007 --output runtime/phase4d-full-20261007/fresh-verification.json` |exit0/valid=true, fresh process, three profiles;0.6626s measured verification |
| `.\.venv\Scripts\python.exe scripts/phase4d_report.py runtime/phase4d-full-20261007 --output docs/PHASE4D_REPORT.md` |exit0; compact report generated from saved actual results |
| `.\.venv\Scripts\python.exe scripts/benchmark.py --seed 41 --users 30 --events 20000 --db runtime/phase4d-legacy-regression.sqlite3 --output runtime/phase4d-legacy-regression` |exit0; existing command1/1 recovery,0/212 benign units both modes;14.8539s total; unchanged old-workload limitation |
| `.\.venv\Scripts\python.exe -m pip check` |No broken requirements |
| `.\.venv\Scripts\python.exe -m compileall -q backend/src scripts` |Passed |

## Failures and interpretation corrections

Initial focused run8 passed/1 failed6.98s; focused verbose reproduction failed2.70s. Duplicate reingestion correctly doubled the intentionally rejected row and changed the dataset quarantine warning. Stable claims/scores/decisions/windows did not change; corrected assertion preserves the warning and checks substantive outputs. No policy/model/data selection changed. The next focused9 and final114 tests passed. Two documentation patch context misses were corrected at actual doc locations (DEMO.md exists; DEMO_SCRIPT.md does not). Calibration audit objects retain prethreshold structural correlator decision/mode, rather than claiming an ordinary hybrid run; actual emitted counts use risk/threshold/missing-window gates, and fresh-verification saves separately derived applied decisions. The initial smoke representative helper reused generic full-profile prose; its report is retained with a correction addendum, while full representative prose matches the executed full profile. No final-test prediction or threshold bug fix/tuning occurred.

## Results, artifacts and remaining work

User-selected 4D before 4C; no replay or inference/model/policy redesign. Frozen protocol and readable definitions: PHASE4D_PROTOCOL.md; compact privacy-reviewed representative results: PHASE4D_REPORT.md. Full machine protocol SHA256 `14f6aebaa0c37c02751dc2e8e4b49dc45f07d78ccc41b72f5f04b0dbbd060739`, version phase4d-v1 / expanded-usb-v1. Runtime evidence is under `runtime/phase4d-full-20261007`, with smoke under `runtime/phase4d-smoke-20261007`. Protocol/source hashes were saved before final inference; selected model/threshold hashes were saved after benign calibration and before test inference. No final-test tuning. Development smoke is exposed; the full three-seed experiment was executed once.

Each of seeds41/53/67 requested20000 background records, partitioned10000/5000/5000. Actual accepted training/calibration/test9664/4896/4913 per profile (19473 total); generated9664/4897/4914, rejected/quarantined0/1/1, duplicates0/0/0. Full accepted inference workload14739 test observations; total accepted across all partitions58419. Four supported episodes per profile,12 total; eight legitimate export cases in both calibration and test, plus nine observational cases. Two malicious missing-copy/out-of-window cases per test profile are separately retained, excluded from benign units and not counted as fully observable supported episodes. Truth is isolated from detector inputs; alias-resolved common active benign population226 units per seed,678 total, includes no-candidate units.

| Output | Matched / emitted | Matched / supported episodes | Benign FP units | Benign false outputs per1000 accepted test observations |
|---|---:|---:|---:|---:|
| Ordinary rules-only | 12/33 | 12/12 | 21/678 (3.097%) | 21/14739 x1000 =1.4248 incidents |
| Ordinary hybrid | 12/27 | 12/12 | 15/678 (2.212%) | 15/14739 x1000 =1.0177 incidents |
| Anomaly-only | N/A:46 window alarms | N/A: no reconstructed chains | 31/678 (4.572%) | 31/14739 x1000 =2.1033 window alarms |
| Experimental A=0 | 6/15 | 6/12 | 9/678 (1.327%) | 9/14739 x1000 =0.6106 diagnostic incidents |

Both ordinary modes retain all12 supported attack episodes, with no supported-episode false negatives. Hybrid's six fewer benign incidents correspond to exact/repeated authorization reductions; this is a policy effect, not demonstrated forest improvement. Withheld, expired/future, wrong-scope and shared-IP legitimate exports still alert. Familiar prior activity has no candidate. Partial/review outputs and deliberate unobservable attacks remain inspectable. A=0 removes the fixed-term margin for compact/alias attack variants (six missed supported episodes) and some benign outputs; it is sensitivity at the same threshold/gates, not an optimized production mode or real-world model benefit.

All ordinary and diagnostic supported candidates: required-stage recall36/36, independently asserted-stage evidence141/141, ordering coverage36/36 and predicted strict-order accuracy120/120. Those denominators include validated partial/review candidates and are distinct from alert recall. Existing one-to-one matcher now additionally records matching decisions/unmatched items and rejects oversized multi-episode credit; historical files remain unchanged.

Calibration per full seed:227 percentile samples,228 benign active units,7 complete benign candidates,5 actual hybrid alerts (5/228=2.193%). The native procedure reports `budget_not_met`, retains80 with `structural_fallback`, and `population_guarantee=false`; no useful candidate boundary met1% without the existing all-suppression guard. Complete score distributions remain saved. Anomaly raw99th-percentile quantile has9 calibration ties and11 calibration window alarms; final scores have12 threshold ties and15/16/15 total window alarms,232 eligible and2 missing windows per seed. Window threshold calibration is not incident discrimination. All four test unit rates exceed the proposed1% target. Smoke: rules/hybrid4/4 recall, benign units6/55 and5/55; diagnostic2/4 recall,3/55; anomaly1 window alarm,1/55.

Single smoke experiment7.3224s; full three-profile experiment299.7986s (wall7.3702/299.8918s). Median across distinct full seed workloads: fitting2.0827s, rules inference/persistence2.8850s, hybrid3.0735s, anomaly scoring0.0690s, rules verification28.6001s, hybrid verification32.4227s, real4A no-op plus verification18.6380s. See representative report for all ranges/operations. These are single measurements per seed on Windows11/Intel64 Family6 Model154/Python3.12.14, with warm installed libraries/OS caches, fresh DB/model and concurrent checks. Expensive independent verification is disclosed; no streaming/speed-superiority claim. Resident process memory remains unmeasured.

Fresh-process verification reopened all three databases, checked persisted predictions/run/model equality, common populations, saved matching and recomputed metrics; valid=true. `fresh-verification.json` additionally records actual applied calibration decisions separately from the audit's prethreshold structural candidate decision/mode. The CLI audit candidate objects are not ordinary production hybrid runs. Saved validations contain actual independent source/stage/graph checks. All predictions/windows, isolated truth, per-case outcomes, calibration, ingestion counts/fingerprints, matching/unmatched records and costs remain local. Public-facing report omits raw logs, private paths, credentials, DBs and caches. Synthetic correlated scenarios do not establish generalization or production readiness.

**Phase 4C replay plus final submission checks remaining.** No deployment, publication, push, remediation or optional Phase5 work.


Interval disclosure: per-profile incident metrics retain the existing evaluator's `wilson_95` fields. These use the Wilson score formula with z=1.96, assuming independent Bernoulli units and a fixed population. Correlated synthetic actor-days and hand-authored episodes violate the independence/generalization assumptions; these fields are illustrative arithmetic only, not evidence of population reliability. Aggregates and representative tables deliberately report counts without intervals. No deployment guarantee follows.
