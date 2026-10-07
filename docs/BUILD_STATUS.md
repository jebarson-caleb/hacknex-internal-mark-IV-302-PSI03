# Phase 4C checkpoint - retrospective replay gate passed

Date: 2026-10-07, Asia/Calcutta. Implemented only the requested remaining replay checkpoint after Phase 4D. Phase 1-3, 4A sensitivity, 4B comparisons, ordinary commands and saved 4D findings are preserved. Prior BUILD_STATUS is retained byte-for-byte in `docs/PHASE4D_BUILD_STATUS.md`. No deployment, publication, remediation, tuning, model replacement or Phase 5.

**The proposed 1% false-positive target remains unmet.** Saved 4D rules-only/hybrid results remain 21/678 (3.097%) and 15/678 (2.212%) benign units. Calibration retains threshold80 with `budget_not_met`, seven complete candidates and five false-positive units among228 per seed. Replay does not improve these findings or establish real-world generalization. The full evaluation was not restarted.

## Inputs and implementation

Read AGENTS.md, root prompt.md, current status, Downloads/phase4c_prompt.md, and Downloads/phase4_prompt.md section4C at the location documented in the 4B status, plus architecture/schema/model/limitations/scope/demo and the current view/detector/features/baseline/source/persistence/API/UI/tests. The attached brief supports the explicit user request; its broader/older phase instructions do not restart 4D or authorize other phases. Git status showed the existing project directories untracked; no staging, commit, reset or deletion was performed. Used the React review skill for component/hooks/accessibility/async review; no dependencies changed.

`replay.py` subclasses the immutable AnalysisView without changing any fingerprinted ordinary inference/view module. Each frame filters frozen parent membership inclusively through an exact offset-bearing cutoff, normalizes UTC while preserving microseconds, checks actual fitted observations and declared training/calibration boundaries before the whole replay range, and reuses the real detector. Fixed model, calibration, policy, identities and captured context remain unchanged. Prior-day comparisons, strict equal-time limits, active prior mount, matching positive-byte copy, aliases and scoped copy-time authorization remain ordinary detector behavior. Forest features/windows/scores, all candidates, graphs, risk and decisions are recomputed; open windows stay unavailable. Parent-wide ingestion/navigation/context are retrospective metadata rather than early detector support.

Frames persist atomically with analysis/candidates and a lineage manifest. A unique parent/cutoff key, serialized final insert and full identity/source/claim verification handle concurrent equivalent requests. Maximum200 distinct cutoffs per parent, no eviction/deletion. Retained frames reopen after refresh/restart; all outcomes remain paginated. Frame source/graph/report routes verify cutoff membership and supported claims. Read guards consult persisted replay lineage even when a tampered run removes its branch label and manifest. JSON/Markdown exports use the existing verified incident report with an added replay manifest; empty frames expose retained manifests/results with no invented incident/risk. Requests forbid context/mode/baseline/policy/exclusion overrides and nested branches.

Workbench controls use explicit Run actions, exact UTC previous/next event/window stops, requested versus displayed cutoff labels, recoverable pending/error/unsupported/empty states, retained frame selection and parent return. New run findings load atomically. Generation guards cover cutoffs, dataset/retained-parent switches, source drawers, graphs and candidates; late responses cannot populate the current frame. Existing URL run selection reopens frames.

## Executed checks

All commands below run from the project root. The exact argv, wall duration, exit and full stdout/stderr are retained in `runtime/phase4c-gate-20261007/*.json` and `*.log`; `acceptance-summary.json` selects the final checks. A small subprocess runner in that output directory captured native commands without changing them. The wrapper wall timer includes process startup; suite timers are separately reported.

| Command | Actual result | Wrapper wall seconds |
|---|---|---:|
| `.\.venv\Scripts\python.exe -m pytest backend/tests -q` | 142 passed; pytest78.93s | 79.517 |
| `.\.venv\Scripts\python.exe -m pytest backend/tests/test_phase4c.py -q` | 28 passed; pytest37.41s | 37.976 |
| `npm --prefix frontend test` | 6 passed; final Vitest suite | 2.397 |
| `npm --prefix frontend run build` | TypeScript/Vite passed,21 modules | 0.826 |
| `npm --prefix frontend run test:browser` | 14 passed; full Playwright1.8m | 106.700 |
| `npm --prefix frontend run test:browser -- --grep real hybrid cutoff|late cutoff|switching parents|late future source|selecting a different retained parent` | 5 passed; final replay flows after lineage guard | 43.315 |
| `npm --prefix frontend run test:browser -- --grep dataset row inspection` | 1 passed; final independent ordinary/frame source flow | 12.691 |
| `.\.venv\Scripts\python.exe scripts/phase4a_smoke.py --output runtime/phase4a-regression-4c-20261007` | Three sensitivity flows/reports/model/tamper/restart passed | 13.751 |
| `.\.venv\Scripts\python.exe scripts/phase4b_smoke.py --output runtime/phase4b-regression-4c-20261007` | 11 pairs/sources/reports/model/tamper/restart passed | 38.022 |
| `.\.venv\Scripts\python.exe scripts/phase4c_smoke.py --output runtime/phase4c-smoke-final-20261007` | Five cutoff frames/reports/CLI/model/parent/tamper/restart passed | 20.463 |
| `.\.venv\Scripts\python.exe scripts/phase4d_verify.py runtime/phase4d-full-20261007 --output runtime/phase4c-gate-20261007/saved-4d-verification-result.json` | valid=true, saved full three-profile artifacts | 2.033 |
| `.\.venv\Scripts\python.exe scripts/phase4d_verify.py runtime/phase4d-smoke-20261007 --output runtime/phase4c-gate-20261007/saved-4d-smoke-verification-result.json` | valid=true, saved smoke artifacts | 1.361 |
| `.\.venv\Scripts\python.exe -m pip check` | No broken requirements | 0.372 |
| `.\.venv\Scripts\python.exe -m compileall -q backend/src scripts` | Passed | 0.072 |

The original full4D experiment/protocol/report was inspected and independently verified, not rerun. Saved full and smoke verification outputs went into the new4C gate directory. The existing ordinary 1,200-requested-event benchmark runs in the browser regression; this is exposed development regression, not a new held-out expanded4D evaluation. The legacy20k benchmark and a new full4D workload were not rerun because the fingerprinted inference modules/policy/model are unchanged. Existing 4D evaluate/report commands and artifacts remain intact.

## Failures fixed and earlier runs

- Initial replay suite: 2 failed/15 passed in22.05s. The forged rules-only report used the unchanged final cutoff, and independent dataset IDs produced different evidence-list ordering. Corrected the test to actually alter its cutoff and compare stable supported content/relationships across dataset namespaces. A focused rerun of prefix invariance passed7.66s; the next17 tests passed23.02s. Added real copy/order/identity, concurrent reuse/bounds, UTC offset, copy-time authorization, baseline-selected rules-only and future-report/source assertions. The later lineage audit adds two removed-label/disguised-frame cases; final28 focused tests and142 full backend tests pass. No model/policy/fixture outcome tuning.
- First three-flow browser run: 2 failed/1 passed46.9s. Findings rendered before their saved URL update, and the parent-switch test used the wrong label. Made run/candidate/observation display atomic and used the actual Saved datasets selector. Three-flow rerun passed32.7s.
- First full140-predecessor regression had138 backend tests pass72.51s. The UTC and future-evidence additions brought the suite to140 passed78.24s and focused26 passed34.56s. The final lineage guard then passed142 backend tests78.93s and28 focused tests37.41s.
- Frontend regression initially5 passed/1 failed1.79s because a graph helper changed the ordinary default endpoint spelling and the existing test intercepted `/graph`. Restored that ordinary endpoint while retaining generation guards; final6 tests pass.
- The first full browser run passed12 flows1.5m. The next13-flow run had11 pass/2 fail1.8m solely because old tests still expected the Phase4B badge after the intentional Phase4C label update. Updated those presentation assertions. Added late future-source and delayed retained-parent tests; final14 browser flows pass1.8m.
- A final-cutoff review identified non-UTC parent timestamp spelling as a semantic equality issue. Normalize equal instants in replay semantic comparison without modifying ordinary cutoff storage/compatibility. Explicit UTC+05:30/equivalent-request tests pass.
- Early native4C smoke (`runtime/phase4c-smoke-20261007`) passed before this isolated replay normalization change. It remains retained under its interim replay implementation hash; it is not silently migrated. The UTC-corrected `runtime/phase4c-smoke-gate-20261007` also passed but preceded the final lineage guard. Both interim implementations remain retained without hash migration. Final current-implementation acceptance artifacts are in `runtime/phase4c-smoke-final-20261007`.
- Final tamper review found that removed branch labels/manifests could avoid the read guard. Added a read-only persisted-lineage lookup and two actual SQLite tamper cases;142 full and28 focused backend tests plus final native replay pass. Frontend code/build is unchanged; the five replay browser flows then passed against the final backend (43.315s wrapper). No ordinary fingerprinted module or4D artifact changed.
- Final source inspection review restored ordinary normalized-row browsing independent of the selected incident, retained frame-scoped row access, and labeled source owner/history/separate-run roles. Final frontend tests/build pass, and a real targeted browser source flow passed12.0s (wrapper12.691s). The earlier14-flow full suite and final five-flow replay suite remain executed regression evidence; they were not represented as a new15-flow full run.
- Existing Starlette/HTTPX deprecation and Playwright NO_COLOR/FORCE_COLOR warnings are non-failing. No dependencies/system software/Docker retries were introduced.

## Measured replay cost and artifacts

Final native setup: seed17, six users,1,200 requested background events, separately explicit fitted baseline. Final inference membership305, not the requested generator size. Hybrid baseline `00da3b7f489e46e9ac0235573e3ee2e0`. Parent/model integrity, four report exports/CLI verification, cutoff tamper rejection, backward equivalent reuse, built UI and real server restart passed. Host Windows-11-10.0.26300-SP0 / Intel64 Family 6 Model 154 Stepping 3, GenuineIntel / Python3.12.14. CPU/OS/library cache contention uncontrolled; memory unmeasured.

| Cutoff UTC | Active observations | Candidates | HTTP request seconds | Creation verification/inference seconds |
|---|---:|---:|---:|---:|
| 2026-01-22T07:59:59.999999+00:00 | 0 | 0 | 0.4974 | 0.4624 |
| 2026-01-28T03:04:59.999999+00:00 | 255 | 1 | 0.5421 | 0.5055 |
| 2026-01-28T03:05:00+00:00 | 256 | 1 | 0.5404 | 0.5022 |
| 2026-01-28T03:15:00+00:00 | 256 | 1 | 0.5895 | 0.4664 |
| 2026-01-28T13:15:00+00:00 | 305 | 2 | 0.5378 | 0.5002 |

First request is the first replay action in the fresh database after explicit fitting/ordinary analysis; library/model/OS caches are warm. Creation timer includes source checks, parent no-op and cutoff inference before final INSERT/HTTP serialization. Repeated earlier-cutoff request with fresh validation: 0.7072s. Restart verification of all five frames including shutdown cleanup: 1.6692s. Total native smoke including setup, exports/CLI, tamper and restart: 20.2119s (wrapper20.463s). Reports were independently verified but verification was not individually timed. Larger frame latency and memory are unmeasured; the old299.89s evaluation is not frame latency.

Artifacts:

- `runtime/phase4c-smoke-final-20261007`: retained SQLite originals, parent/model metadata, five frames, copy/open-window and closed-window JSON/Markdown reports, `smoke.json` costs/checks. Earlier development smoke directories are preserved under their recorded replay implementation hashes.
- `runtime/phase4c-gate-20261007`: `acceptance-summary.json`, exact command/timing/log files, fresh saved4D verification outputs, protected hashes/verification and historical policy inspection. `runtime/phase4c-prefix-failure.txt` retains the independently rerun prefix test (passed).
- `runtime/phase4a-regression-4c-20261007` and `runtime/phase4b-regression-4c-20261007`: fresh native prior-phase checks including restart/export/tamper/model integrity.
- `runtime/phase4c-browser.png`: actual built workbench after backward inspection and parent return, visually inspected. Prior browser reports/screenshots remain.

## Compatibility, limitations and stop

All71 protected4D protocol/report/runtime files match the saved precheck SHA256 values. Six saved full4D ordinary run policy/library identities were inspected and remain compatible with current fingerprinted modules; this identity inspection is not a new expanded evaluation or replay timing. Historical parents with absent/different frozen policy/source metadata still fail actionably with ordinary-reanalysis guidance. Never rewrite hashes, bypass guards or claim an old run used a new implementation. Calibration/training source and interval failures remain explicit. A separately new ordinary run is distinguished from exact historical replay.

Only compatible ordinary parents; no sensitivity/replay nesting, exclusions, history refitting, context overrides, dedicated empty-frame download, historical-version executor or incremental streaming. The parent operator snapshot records context effective-time scope, not historical analyst knowledge. Repeated reads perform full validation and may be expensive. Synthetic fixtures do not establish source authenticity, human intent or generalization. Existing Docker-engine and independent POSIX/second-machine limitations remain; no retry or deployment was attempted.

Updated README, SCOPE, ARCHITECTURE, DATA_SCHEMA/API, DECISIONS, NOVELTY, LIMITATIONS and DEMO. Saved4D protocol/report/findings remain unchanged. Existing 4A and4B workflows are used without expansion.

**4C gate passed. No required 4C task remained unfinished at that checkpoint.** Subsequent release preparation and public source publication are recorded in the addenda below. Clean-checkout demonstration and unresolved detection-quality limitations remain. Future model/policy tuning needs a separate request/development-calibration task and newly reserved evaluation data; the already exposed4D results remain exposed. No Phase5 work was started.

## Final-release addendum — 2026-10-07

The current user-authorized release brief extends the previous 4C stop point. Phases 1–3 and 4A–4D remain preserved. Implemented the five bounded bundles: cases/tasks/notes/evidence and external bookmarks; saved hunts/native rule catalog/Sigma-shaped subset; exact source-backed local indicators; bounded Wazuh JSONL and Hayabusa minimal CSV context imports; evidence-linked T1005/T1052.001 views and Navigator JSON. The additions are integrated into the workbench and stored outside native detector evidence/risk.

The requested repository research and submission checklist files were not found in the repository or Downloads; the inspected references/attribution and release checklist are recorded in `docs/THIRD_PARTY_SOURCES.json`, `docs/THIRD_PARTY.md`, and `docs/FINAL_RELEASE_CHECKLIST.md`. No platform or upstream rule pack was installed/copied. No detector, model, threshold, training history, evaluation metric or saved 4D outcome file was intentionally changed. The 1% false-positive target remains unmet.

Implementation checkpoints R0–R4 are complete. The passing R5 gate is `runtime/release-final-20261007-rerun1`; all final suites, fresh native install/offline/restart/export/tamper checks, fresh 4A/4B/4C regressions and copied 4D verification passed. The earlier first-gate schema side effect on three saved 4D SQLite files is disclosed in `docs/RELEASE_STATUS.md`: twelve new tables are empty; 44 other 4D files remained byte-identical; exact original SQLite bytes cannot be restored. The 4C record above is historical. Final release results and limitations are recorded in the addendum below.

Submission preparation passed: `\.venv\Scripts\python.exe scripts/prepare_submission.py --output submission/traceguard-final-release` → 156 manifested source/document files, 11 historical local-path replacements in the copy, and zero private path/credential/database/runtime-log scan hits. The directory is `submission/traceguard-final-release`; its `SUBMISSION_MANIFEST.json` records per-file hashes and byte lengths, and its `SUBMISSION_PRIVACY_REVIEW.md` records the scan and owner-license follow-up. No publication or deployment had occurred at the time of this gate.

Final native release gate: `\.venv\Scripts\python.exe scripts/release_gate.py --output runtime/release-final-20261007-rerun1` → passed. It records 175 backend tests, 6 frontend tests, a successful 28-module production build, 16 browser flows, clean native install with outbound access blocked, restart persistence, verified exports/tamper rejection, successful 4A/4B/4C fresh regressions, and valid saved 4D verification against a copy. All47 original 4D files were unchanged during that passing rerun. Exact command logs, elapsed seconds, and output hashes are in `runtime/release-final-20261007-rerun1/`.

The first gate used the saved 4D database paths directly before its mutation was understood. It created twelve empty additive release tables in each of the three profile SQLite files; the first-gate log retains original and post-open hashes. No saved prediction/label/report/metric file changed, all twelve tables are empty, and the verifier recomputed identical counts. The first-gate failure and irrecoverable loss of the original three database byte streams are explicitly recorded. Subsequent verification used a full copy and left source hashes unchanged. Do not report the original 4D SQLite file hashes as preserved.

Final repository suites: backend175 passed with one existing Starlette/HTTPX deprecation warning; frontend6 passed; TypeScript/Vite build passed; browser16 passed. The release acceptance smoke measured7.311s for the fresh API/export/restart flow with process RSS unmeasured. The project owner later selected MIT for public release; confirming contributor rights remains the team's responsibility. POSIX install, Docker engine, Navigator UI compatibility and production efficacy are unverified/unclaimed.

## Post-release UI accessibility refresh - 2026-10-07

Reworked the shared React workbench presentation only: added a skip-to-main link and named setup landmark, increased body/control sizing, refreshed contrast and focus treatment, clarified the workspace header/status, and added responsive, reduced-motion, high-contrast, and forced-color styles. Updated the browser title. Existing detection, evaluation, API, and evidence behavior were not changed. No automated tests or build were run for this visual-only request; prior release-gate results above predate this refresh and are not current verification of it.

Follow-up UI behavior: moved benign, positive, missing-transfer, and chronological seed actions into a sticky main-workspace quick-action panel. Added a persistent graph shortcut that analyzes the selected dataset when needed, opens the selected or first retained candidate graph, and focuses/scrolls to the graph. A run with no incident/review candidate gets a clear explanation because the graph API is incident-scoped. The setup rail now follows main content in document order. No build or tests were run for this follow-up.

## Public repository publication — 2026-10-07

At the project owner's request, the allowlisted source copy was published as the public repository [hacknex-internal-mark-IV](https://github.com/jebarson-caleb/hacknex-internal-mark-IV) on branch `main`. The owner selected MIT; `LICENSE` and updated project/setup documentation are included. The first published commit is `f4f1d4f775f6145da0e12849ec081c80a6a49ed2`.

The final allowlisted preparation reported 159 manifested files, 11 historical local-path replacements, and zero private-path, credential-pattern, database, or runtime-log hits. The committed tree also contains the manifest itself. The allowlist excludes local runtime data, environments, caches, internal build prompts, and the previous submission copies. This scan covers common leakage patterns and is not a guarantee of ownership or licensing completeness.

No application tests were run as part of the README, license, packaging, and publication work. The recorded release-gate results above predate the post-release UI refresh and are not fresh verification of it. A separate clean-checkout demo remains outstanding; no deployment or remediation was performed.
