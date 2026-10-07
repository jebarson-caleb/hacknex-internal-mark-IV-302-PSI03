# Build status — Phase 2 checkpoint

Date: 2026-10-07, Asia/Calcutta. Phase 2 is implemented. Default rules-only behavior is preserved; hybrid uses a real locally fitted model and typed graph. Exact Phase 1 checkpoint preserved in docs/PHASE1_BUILD_STATUS.md.

## Implemented

- Extended the existing engine, adapters, SQLite, API, CLI and React workbench. Existing fixtures, source records, databases and analyses remain intact. Tables are added non-destructively; no repository publication or deployment.

- Explicit benign training/calibration dataset selection and provenance; disjoint chronological closed windows and matching trusted namespace; minimum 20 established windows per split. Empty/insufficient/missing/future/incompatible/corrupt artifacts fail explicitly.

- Frozen selected training history, 15-minute UTC count/novelty/resource/byte features, documented log1p, no numeric identity encoding, cold-start/provisional score omission. Actual 200-tree Isolation Forest fitting and negative score_samples with empirical benign midrank percentiles.

- Local model/calibration artifacts store hashes, exact versions, seed, feature order/transforms, selected event IDs, fingerprints, intervals, frozen history/context and calibration distribution. No arbitrary serialized model uploads or inference credentials.

- NetworkX typed directed multigraph, observed edge provenance, time-scoped IP context and required graph relations that gate candidates. Multiple edges from one record do not inflate independent evidence.

- Trusted direct account aliases with provenance/effective intervals; ambiguous/chained/expired mappings do not force merges. Retained raw canonical observations remain unchanged and every run snapshots interpretation.

- Hybrid risk implements 50*C + 20*A + 20*L + 10*I - B with explicit terms/supporting scored windows. Exact links=1, aliases=0.9, B=0 pending Phase 3. Structural/evidence/graph gates remain mandatory. Incomplete and below-threshold candidates stay visible.

- Chronological seed-separated train/calibration/test fixtures; evaluation-only labels; independent immutable predictions; rules-only/hybrid benchmark with one-to-one episode metrics, full active benign user-device-day denominator, operational alert rate, stage/order metrics and uncertainty.

- UI/API explicit fitting, baseline selection, hybrid risk, graph relations and measured synthetic evaluation; CLI chronological-demo/train/analyze/verify and benchmark. No incident report bundle, Docker, interactive replay, counterfactual, anomaly-only ablation or optional stretch work.

New modules: baseline.py, features.py, resolution.py, graph.py, risk.py, hybrid.py, evaluation/. Existing schemas/detection/storage/main/CLI were extended. Frontend controls and tests were extended; backend transitive versions locked. Model/evaluation/schema/architecture/scope/resource docs updated.

## Exact installation and run commands

Run from <LOCAL_PATH_REDACTED>

    .\.venv\Scripts\python.exe -m pip install -r backend/requirements.lock

    .\.venv\Scripts\python.exe -m pip install --no-deps -e backend

    npm --prefix frontend ci

    npm --prefix frontend run build

    .\.venv\Scripts\python.exe scripts/run_demo.py

Open http://127.0.0.1:8000; API docs http://127.0.0.1:8000/docs. Existing simple demos still run rules-only. For hybrid: Load chronological demo → Frozen baseline & analysis mode → review selections/provenance → Fit selected benign baseline → Analyze hybrid → open risk/graph/evidence. Measured synthetic evaluation runs a separate labeled profile, never invented metrics for arbitrary uploads.

Clean-checkout bootstrap uses Python 3.12:

    python -m venv .venv

This host's system python aliases remain Windows Store stubs. The actual working bootstrap is preserved from Phase 1:

    & '<LOCAL_PATH_REDACTED>' -m venv .venv

Do not recreate the current working venv unnecessarily. POSIX substitutes .venv/bin/python and python3.12; independent POSIX/second-machine installation was not tested. Default database remains runtime/traceguard.sqlite3; set TRACEGUARD_DB explicitly for another file. .env.example is documentation, not auto-loaded.

Phase 2 CLI commands actually exercised:

    $phase2Datasets = .\.venv\Scripts\python.exe -m traceguard.cli --db runtime/phase2-cli.sqlite3 chronological-demo --seed 17 | ConvertFrom-Json

    $phase2Baseline = .\.venv\Scripts\python.exe -m traceguard.cli --db runtime/phase2-cli.sqlite3 train $phase2Datasets.training.id $phase2Datasets.calibration.id --benign-provenance 'Explicit selected generated benign training and calibration' | ConvertFrom-Json

    $phase2Run = .\.venv\Scripts\python.exe -m traceguard.cli --db runtime/phase2-cli.sqlite3 analyze $phase2Datasets.test.id --mode hybrid --baseline-id $phase2Baseline.baseline_id | ConvertFrom-Json

    .\.venv\Scripts\python.exe -m traceguard.cli --db runtime/phase2-cli.sqlite3 verify INCIDENT_ID

Replace INCIDENT_ID with a real persisted ID from GET /api/analyses/{analysis_run_id}/incidents. Actual CLI analysis returned one incident, one partial and a graph summary of 130 nodes / 611 edges. CLI verification passed for both: partial (two stages / 86 provenance references / four graph relations) and complete (three stages / 88 provenance references / seven graph relations), including the persisted numeric score. Existing no-baseline demo/analyze/verify still work.

Benchmark:

    .\.venv\Scripts\python.exe scripts/benchmark.py --seed 41 --users 30 --events 20000 --db runtime/phase2-benchmark.sqlite3 --output runtime/phase2-benchmark

Fresh output directories preserve prior runs. Final recorded artifacts: runtime/phase2-benchmark/ed3e9840f3c342e9a592190f584afb77/evaluation.json and separate labels.json. Inputs, independent runs and baseline artifacts remain in the selected SQLite DB.

## Actual checks and results

Host: Windows 11 10.0.26300, Intel64 Family 6 Model 154 Stepping 3, Python 3.12.14, Node 26.7.0, npm 11.19.0. Installed/tested additions: scikit-learn 1.9.1, NumPy 2.5.3, NetworkX 3.7. Exact transitive pins are in backend/requirements.lock; frontend lockfile remains intact.

| Command executed | Result |

|---|---|

| `.\.venv\Scripts\python.exe -m pip install scikit-learn==1.9.1 networkx==3.7` | Succeeded; resolved additions were pinned/locked. |

| `.\.venv\Scripts\python.exe -m pip install --no-deps -e backend` | Succeeded with updated dependency pins. |

| `.\.venv\Scripts\python.exe -m pip install -r backend/requirements.lock` | Succeeded in the existing venv with all locked dependencies satisfied. |

| `.\.venv\Scripts\python.exe -m pytest backend/tests -q` | 63 passed; final run 16.22s; one non-failing Starlette/HTTPX deprecation warning. |

| `npm --prefix frontend test` | 6 passed; final recorded run 19.64s including jsdom startup. |

| `npm --prefix frontend run build` | TypeScript and Vite production build passed, 17 modules. |

| `npm --prefix frontend run test:browser` | 3 passed in 10.0s: original demos, CSV upload/context, explicit fit/hybrid risk/graph/benchmark. |

| `.\.venv\Scripts\python.exe scripts/benchmark.py --seed 17 --users 6 --events 1200 --output runtime/benchmark-small` | Executed: 592 fit / 298 calibration / 305 test; both modes match 1/1 episodes and 0/44 benign false-positive units. |

| `Larger seed-41 benchmark above` | Executed and repeated after calibration/metric changes: 9,664 fit / 4,834 calibration / 4,841 test = 19,339 accepted events. |

| `Explicit chronological-demo / train / hybrid analyze CLI above` | Succeeded with real persisted model, one incident / one partial. |

| `CLI verify with an actually persisted hybrid incident ID` | Stage/source, numeric terms and graph checks passed. |

| `.\.venv\Scripts\python.exe -m pip check` | Passed, no broken requirements. |

| `.\.venv\Scripts\python.exe -m compileall -q backend/src scripts` | Passed. |

| `Local server /api/health after restart` | status=ok, default rules-only, both rules-only/hybrid supported, ml_implemented=true. |

All 39 prior backend checks remain (health ML-capability assertion updated to the now-real capability; default remains rules-only). New tests cover actual fit/use/persistence and score agreement, feature order, cold/provisional windows, chronology/leakage/insufficient-data errors, artifact integrity/versions, graph gates/independent events/truncation, numeric terms, high-anomaly missing transfer, aliases/expiry/ambiguity/environment constraints, source-preserving alias chains, inference import/label isolation, one-to-one metric matching/denominators, duplicated predictions/reingestion, ignored self-approval, benign regression, repeatability, API/evaluation sidecars and invalid numeric byte values before feature transforms.

Frontend tests retain empty/demo/timeline/raw HTML escaping/missing-transfer/errors and add baseline gating and graph fetching. Live browser checks use actual built assets/API and fitted/scored model. No browser detector output is mocked.

No test failure was skipped. Documentation patch validation errors (unmatched context and duplicate file operations) were corrected without dropping work. Starlette/HTTPX deprecation and Playwright color-environment warnings remain visible and non-failing.

## Measured findings and remaining issues

- Both larger-run modes: precision 1/1, recall 1/1, benign false-positive units 0/212, asserted evidence 5/5, required stages 3/3, label ordering coverage 3/3, predicted order accuracy 4/4. No measured ML detection improvement. The model changes numeric risk; a narrow one-episode synthetic holdout cannot show broad benefit.

- Calibration: 0/211 benign false-positive units, zero complete benign candidates, structural threshold floor 80 retained explicitly. This is sparse calibration, not a proven useful production operating point. Test FPR Wilson 95% upper bound is approximately 1.78%, despite the zero point estimate.

- Measured final larger-run fit/source validation 1.75s, rules-only prediction 4.57s, hybrid 4.56s, total generation/ingestion/evaluation 23.05s. Other checks ran concurrently; no speed superiority claim. Process memory was not measured and is null.

- No unresolved Phase 2 execution blocker. Known limitations: synthetic-only/single-episode coverage, no independent positive development subset selecting a useful threshold, scoped authorization B=0, basic relation-table graph UI, no independent clean-machine/POSIX verification and existing test-client deprecation.

- Organizer PDF unavailable. Supplied booklet analysis was read as source context; optional recommendations did not authorize later phases. No hidden data accessed.

## Next phase

Phase 3 when requested: fuller analyst workbench, linked graph/timeline/evidence, scoped authorization, human-reviewed responses, run/dedup refinements, reproducible incident JSON/Markdown reports, clean local packaging/Docker and submission demonstration. Counterfactuals, replay, anomaly-only ablations and optional narrator/public-dataset/slow-chain work remain later phases.

