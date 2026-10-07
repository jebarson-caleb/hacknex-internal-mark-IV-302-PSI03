# Phase 2 measured evaluation

All results here come from actual independent predictions on generated observations. No hidden evaluation data, real logs or public datasets were accessed. Label sidecars live only in evaluation output. Inference modules have tested import boundaries; changing labels changes metrics, not predictions.

Chronology: UTC days 1–14 benign fitting, 15–21 declared benign calibration, 22–28 held-out input. Train/calibration/test use seeds 41/42/43 in the larger executed run. Stable trusted environment identities cross partitions, while routine byte counts, times and scenario actor/media/resource/delays vary by seed. The generator supplies background work/shift patterns, routine USB backup, a VPN login, a cold-start employee, one supported known-chain episode and one missing-transfer confounder. This is a narrow implementation benchmark, not a broad security corpus.

Actual command:

```powershell
.\.venv\Scripts\python.exe scripts/benchmark.py --seed 41 --users 30 --events 20000 --db runtime/phase2-benchmark.sqlite3 --output runtime/phase2-benchmark
```

Requested 20,000 events; actual accepted counts are 9,664 training + 4,834 calibration + 4,841 test = **19,339**. Routines are generated as complete groups rather than padded to an exact arbitrary row target. The two detector modes use the same held-out dataset fingerprint and frozen selected history. Phase 2 comparison is rules-only vs hybrid; anomaly-only ablation is Phase 4.

| Metric | Rules-only | Hybrid |
|---|---:|---:|
| Incident precision | 1 matched / 1 emitted | 1 / 1 |
| Incident recall | 1 matched / 1 labeled episode | 1 / 1 |
| False-positive benign user-device-days | 0 / 212 | 0 / 212 |
| Benign false alerts per 1,000 accepted test events | 0 / 4,841 × 1,000 | 0 / 4,841 × 1,000 |
| Asserted stage evidence coverage | 5 / 5 | 5 / 5 |
| Required labeled stage recall | 3 / 3 | 3 / 3 |
| Labeled ordering-constraint coverage | 3 / 3 | 3 / 3 |
| Predicted ordering-constraint accuracy | 4 / 4 | 4 / 4 |
| Candidates retained | 2 (one partial) | 2 (one partial) |

**No measured detection improvement from ML on this holdout.** Forest scores participate in risk/ranking, but both modes retain the same structural rule gates. One labeled attack is too small a sample to support strong recall/precision claims. Wilson 95% interval for the observed benign-unit FPR is approximately [0, 1.78%], even though the point estimate is zero. It does not establish a real-world 1% budget.

Calibration: 0 false-positive units / 211 active benign units, no complete benign candidates. Threshold remains structural floor 80 with an explicit warning; this is not evidence of discriminatory threshold optimization. The 1% target is a proposed engineering choice, not an organizer threshold. Scoped authorized sensitive-export policies and richer labeled development attacks are not implemented yet.

Measured runtime in the recorded final large run: fitting including source validation **1.75s**, rules-only prediction **4.57s**, hybrid prediction **4.56s**, total including generation, ingestion and evaluation **23.05s**. Hardware reported by the running host: Windows 11 10.0.26300, Intel64 Family 6 Model 154 Stepping 3, Python 3.12.14. These are one-run measurements with other checks running concurrently; no relative speed claim. Process memory was not measured and is recorded as null.

Output for this run: `runtime/phase2-benchmark/ed3e9840f3c342e9a592190f584afb77/evaluation.json` and separate `labels.json`. Earlier measured runs were preserved in separate evaluation directories. SQLite contains immutable baseline/run/evaluation metadata. Seed 17 small profile was also executed: 592 training, 298 calibration, 305 test events; both modes matched 1/1 episodes and had 0/44 benign-unit false positives. The UI evaluates fresh generated data and displays that run's actual denominators.

Definitions: precision/recall use one-to-one episode matching with actor/endpoint equality, per-stage evidence overlap and strict allowed ordering. Duplicating a prediction increases the prediction denominator without increasing recall. A benign active user-device-day is a UTC day with accepted activity but no labeled attack event for that pair. All such units count, including those without candidates. Selected incident evidence implicates units; only incident decisions are alerts. Zero denominators are null, not fabricated 100%/0% success. Ordering coverage measures recovered label constraints; accuracy separately checks strict order of asserted predicted constraints. Metrics do not claim entity-link accuracy without corresponding reference links.

## Phase 3 audit and fresh regression benchmark - 2026-10-07

The prior Phase 2 values above were first inspected as saved reported artifacts, not treated as fresh checks. Seed-41 saved evaluation fingerprints matched persisted runs; old rules-only/hybrid complete/partial objects passed fresh source/stage/numeric/graph verification. No numerical discrepancy was found. A metadata discrepancy was found: sparse calibration recorded budget_met=true despite zero complete benign candidates. Old metadata remains intact; new fits report budget_met=null, explicit insufficient_complete_candidates status, structural_fallback origin and no population guarantee, separately from available anomaly-percentile calibration.

Fresh command (new DB/output; old artifacts preserved):

```powershell
.\.venv\Scripts\python.exe scripts/benchmark.py --seed 41 --users 30 --events 20000 --db runtime/phase3-benchmark.sqlite3 --output runtime/phase3-benchmark
```

Actual evaluation: `runtime/phase3-benchmark/afb56b5a280042fa85e963615b5d3c0b/evaluation.json`, schema2, policies phase1-v1/hybrid-v2/scoped-copy-v1. Split seeds41/42/43; accepted counts9664/4834/4841 (19339 total). Both modes: precision1/1, recall1/1, benign-unit false positives0/212 (95% Wilson upper bound1.78%), asserted stage evidence5/5, required-stage recall3/3, ordering coverage3/3 and asserted-order accuracy4/4; one complete alert and one partial. **No measured detection improvement.** Calibration:210 percentile samples,0/211 false-positive units,0 complete candidates, structural threshold80. This is one narrow synthetic episode, not a production operating-point guarantee.

Measured times for this fresh run: fit/source validation1.7483s, rules-only1.6660s, hybrid1.6222s, total11.2626s; Windows11/Python3.12.14, concurrent work on host. No speed superiority claim or new performance study. Memory remains unmeasured/null. These benchmark findings are separate from test passes. Scoped-authorization regression fixtures test policy effects, not accuracy or a new calibration dataset; no held-out tuning or label-driven inference was introduced.

## Phase 4A regression only - 2026-10-07

No expanded protocol, new scenarios, anomaly-only experiment or held-out tuning was implemented. The existing seed-41 benchmark was rerun unchanged as regression, with new DB/output:

```powershell
.\.venv\Scripts\python.exe scripts/benchmark.py --seed 41 --users 30 --events 20000 --db runtime/phase4a-regression.sqlite3 --output runtime/phase4a-regression
```

Actual saved schema2 evaluation: `runtime/phase4a-regression/6d45e55c10fe4778ae6df3b2ca628d67/evaluation.json`; DB `runtime/phase4a-regression.sqlite3`. Accepted train/calibration/test9664/4834/4841, total19339. Both modes retain precision1/1, recall1/1, benign-unit false positives0/212 (Wilson95% upper bound1.78%), evidence5/5, required stages3/3, ordering coverage3/3, asserted-order accuracy4/4; one complete alert and one partial. **No measured ML detection improvement.** Calibration210 percentile samples,0 complete benign candidates, threshold80 structural fallback, budget_met=null; no population guarantee.

Actual one-run times under concurrent host work: fit/source1.771052s, rules2.281512s, hybrid2.342741s, total12.727737s. Windows11/Python3.12.14; memory null/unmeasured. This is an existing regression benchmark, not a Phase4D performance study. Earlier Phase2/3 artifacts remain retained.

Phase4A smoke cases are evidence-availability acceptance checks, not new accuracy measurements: sole-copy removal loses transfer, separate sufficient copy preserves it, duplicates do not bypass exclusion, and frozen hybrid windows/model/parent reports are verified. See `runtime/phase4a-smoke-gate-20261007/smoke.json` for actual IDs/hashes/durations and restart results. Historical Phase3 benchmark fingerprints and four retained incident/report claims were freshly inspected/reverified in `historical-audit.json`; their reported metrics were not relabeled as new results.
# Phase 4B curated development observations - 2026-10-07

This is a context/evidence regression lab, not a new held-out accuracy/calibration study. Actual acceptance is retained in `runtime/phase4b-smoke-final-20261007/acceptance-summary.json`, linked by source hash to the full native/restart `smoke.json`. No lab truth enters inference and no library/comparison action fits or recalibrates.

Seed17 stage-complete declared business export: withheld exact declaration yields99.5238/incident versus79.5238/review with exact declaration, same three stages and same anomaly percentile0.9761904761904762. Withheld context does not change its benign truth; that emitted alert is retained as a fixture false positive. Wrong/expired/future declaration cases retain alerts; repeated matches apply20 once and both arms remain review. Selected-history rules-only arms remain100/incident, with both benign false-positive alerts preserved. Missing transfer stays a two-stage partial, not a false-positive alert. Familiarity uses actual prior successful logins14/15 and same-resource reads0/28; the familiar side has no candidate/incident risk, while both forest percentiles are equal. This does not demonstrate ML detection improvement or justify a causal history-only explanation. Existing attack-labeled scenario remains inspectable with its complete alert plus partial item.

New baseline setup has42 percentile samples,0 complete benign calibration candidates, threshold80 structural fallback and budget_met=null. It is separate explicit chronological benign preparation, not repaired calibration. No FPR/accuracy percentage is computed for the curated lab or arbitrary uploads. Existing historical benchmark conclusions and sparse-calibration limitations remain; fresh105 backend/6 frontend/9 browser checks and preserved4A native/export/restart verification are recorded in BUILD_STATUS.



## Phase 4D evaluation-first checkpoint - 2026-10-07

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
