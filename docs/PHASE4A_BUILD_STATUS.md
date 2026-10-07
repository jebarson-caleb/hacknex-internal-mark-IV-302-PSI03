# Phase 4A checkpoint - evidence sensitivity gate passed

Date: 2026-10-07, Asia/Calcutta. **Phase 4A only is implemented and freshly verified.** Phase 1–3 workflows, sources, fitted artifacts, original incident reports and historical analyses remain retained. Phase 3 status was preserved byte-for-byte once in `docs/PHASE3_BUILD_STATUS.md` before this update. Phase 4B–4D are unimplemented; whole Phase4 is not complete. No publication, deployment, remediation, model replacement, dependency upgrade or held-out tuning.

## Starting state and authority

Read AGENTS.md, prompt.md (including Phase4/evidence requirements), current status, Downloads/phase4_prompt.md and existing inference/features/baseline/context/persistence/reports/API/UI and architecture/model/schema/scope/evaluation/limitations docs. The attached brief was supporting specification; the user's explicit Phase4A boundary governed execution. Repository started with untracked working files; they were preserved. Historical transcript numbers were inspected as reported evidence, not new checks or test-count targets.

Fresh pre-change baseline commands below: backend71 passed16.87s; frontend6 passed1.69s; build passed18 modules; browser5 passed18.0s. Inspected saved Phase3 seed41 evaluation `runtime/phase3-benchmark/afb56b5a280042fa85e963615b5d3c0b/evaluation.json`: saved fingerprints match retained rules/hybrid runs. Freshly reverified all four complete/partial incident objects and reconstructed/verified reports against originals. Audit saved as `runtime/phase4a-smoke-gate-20261007/historical-audit.json`; this is historical-artifact inspection, not a rerun of that benchmark. No discrepancy was found in those claims.

## Implemented mechanism and UI

- `views.py`: minimal read-only projection of an ordinary parent's frozen membership, cutoff, dataset/quality, context, source references and baseline. Canonical exclusions remove every duplicate representation from active inference while keeping all originals. Fixed fitted training/history/calibration stay separate. Exact implementation/library identities, baseline metadata/model hash and no-op semantic reproduction refuse unsupported historical parents. No fitting occurs.
- Existing detector recomputes actual counts/windows/forest scores, chains, predicates, graph links, risk and decisions from retained active events. No cached parent aggregates, fabricated score delta, safe status or incident risk0. No-op comparison excludes only new IDs and bookkeeping; evidence/order/predicates/numeric decisions/window findings must match.
- `sensitivity.py`: atomic persisted child/comparison lineage, sorted exclusions, effective membership/fingerprint, unchanged artifact/context/source identities, real duration and validation. All child candidates retained in SQLite order. Matching requires exact rule family/scoped actor/endpoint, overlapping episode time and evidence overlap; later unrelated episodes stay separate and ambiguity is explicit. Experimental counts belong to the child, never the parent.
- API analysis-scoped POST, retained comparison GET, verified JSON export and submitted verification; max100 exclusions/500-character note/50k parent observations. Extra fields/context/cutoff changes, out-of-parent IDs, nested branches and incompatible policy/snapshots rejected. CLI `verify-report` dispatches the explicit sensitivity subtype; original JSON/Markdown and legacy formats remain verified.
- Workbench evidence selection, pending/error recovery, before/after stage/evidence/graph/predicate/risk/percentile/reason inspection, parent/child evidence links, visible experimental run kind, retained URL refresh and JSON download. Empty child explicitly means no candidate/no incident risk, not safe. No replay or benign comparison lab controls.
- Updated README, architecture/schema/API/CLI, scope/limits/decisions/demo, NOVELTY and executed regression notes in EVALUATION. Native setup retained.

## Exact commands and fresh gate results

Run from `<LOCAL_PATH_REDACTED>

| Executed command | Actual result |
|---|---|
| `.\.venv\Scripts\python.exe -m pytest backend/tests -q` | **87 passed**, final26.78s; one existing Starlette/HTTPX deprecation warning. All71 prior tests retained plus16 Phase4A cases. |
| `.\.venv\Scripts\python.exe -m pytest backend/tests/test_phase4a.py -q` | Focused16-case suite exercised during development; final all16 pass inside full suite. Intermediate ordering failure described below. |
| `npm --prefix frontend test` | **6 passed**, final1.70s. Existing assertions retained; phase badge adjusted. |
| `npm --prefix frontend run build` | TypeScript + Vite passed,19 modules. Current assets `index-CJi1O7L4.js` / `index-CGKD628d.css`. |
| `npm --prefix frontend run test:browser` | **7 passed**, final34.9s. Five original flows plus actual sensitivity removal/refresh/download/CLI/API/tamper checks and error recovery/empty child. |
| `.\.venv\Scripts\python.exe scripts/phase4a_smoke.py --output runtime/phase4a-smoke-gate-20261007` | Passed: real built UI served; rules-only/hybrid no-op and exclusion comparisons; duplicate-vs-independent evidence; parent/report/model immutability; API tamper failure; terminate/restart own native server and verify all six comparisons. |
| `.\.venv\Scripts\python.exe -m pip check` | No broken requirements. |
| `.\.venv\Scripts\python.exe -m compileall -q backend/src scripts` | Passed. |
| CLI valid/tampered commands below | Valid comparison and hybrid no-op exit0; intentionally altered exclusions exit1, valid=false with retained-comparison mismatch. |
| Seed41 benchmark command below | Existing regression completed; actual findings below. |

```powershell
.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/phase4a-smoke-gate-20261007/traceguard.sqlite3 verify-report runtime/phase4a-smoke-gate-20261007/unique-copy-comparison.json
.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/phase4a-smoke-gate-20261007/traceguard.sqlite3 verify-report runtime/phase4a-smoke-gate-20261007/hybrid-copy-noop.json
# Expected rejection, exit 1:
.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/phase4a-smoke-gate-20261007/traceguard.sqlite3 verify-report runtime/phase4a-smoke-gate-20261007/unique-copy-tampered.json
.\.venv\Scripts\python.exe scripts/benchmark.py --seed 41 --users 30 --events 20000 --db runtime/phase4a-regression.sqlite3 --output runtime/phase4a-regression
```

Smoke output directory creation and report writes refuse overwrite. For another smoke run choose a new output directory. Native startup remains `.\.venv\Scripts\python.exe scripts/run_demo.py`, serving the built UI on loopback. No installer/environment reset or Docker retry was required. Phase3 isolated install/POSIX/container history remains in the preserved checkpoint; these were not newly claimed as verified.

## Acceptance evidence, failures corrected and artifacts

Sole-copy removal produces real two-stage partial output without transfer; duplicate source representations cannot preserve it. Independent matching copy can preserve transfer with a different remaining event ID. Removing required auth yields an empty child; mount removal follows the existing predicate and cannot complete transfer. USB-byte features decrease by exactly the excluded telemetry's bytes; excluded IDs leave all inference windows/child graphs. Baseline bytes and metadata stay identical, fit entry point is guarded, and even altered model bytes plus altered SQLite integrity hash fail the parent's frozen model hash. No-op rules/hybrid match semantically. Later source uploads and resource/authorization/alias edits cannot enter frozen branches. Repeat requests match semantically. Later unrelated episodes remain separate; changed episode evidence and ambiguous correspondence are covered.

Parent run and reconstructed report contents remain equal (only fresh validation timestamps differ); saved report file hashes are unchanged. Store reopen and actual process restart preserve lineage and exports. Tampered exclusion/parent/child/risk/evidence/differences, retained child/source and model alterations fail verification. Source refs include all frozen observations/history; later duplicate/unrelated uploads do not participate in frozen provenance reads. Minimal exports keep original raw records local.

Intermediate failures corrected, never hidden: two browser regressions still asserted the Phase3 badge after the UI advanced to4A (updated only badge assertions, preserved behavioral checks). A stronger hybrid no-op verification exposed differing candidate order between correlation and SQLite ID sorting; creation now uses retained order and the regression asserts persisted comparison equality. No score/policy/model tuning was used to fix these. Existing NO_COLOR/FORCE_COLOR and Starlette/HTTPX warnings remain non-failing.

Gate artifacts:

- `runtime/phase4a-smoke-gate-20261007/traceguard.sqlite3`, `smoke.json`, `historical-audit.json`, and `{unique-copy,independent-copy,hybrid-copy}-{parent,noop,comparison,tampered}.json`.
- Unique-copy parent `99481f0c3e64424f862039d95d09a9f3` -> child `848826af60e848128e32ff05d6690893`, comparison `8bc62d050e7547718772c2f9f0d7cb38`; complete_after=false.
- Independent-copy parent `e086b3fa69734c5fb7c8a4432d90339d` -> child `a89ea0e09c4f4d9880361e224ce6c191`, comparison `6b7c563584af4cca8d50deb64f79474d`; complete_after=true, remaining copy cited.
- Hybrid-copy parent `0af9dc178b11425db38abc48db1ffabd` -> child `0b1f21811b194c22823d5480a5123c93`, comparison `b0841525f47e47cfa230ed8c21f2d3b2`; complete_after=false, model_unchanged=true.
- Actual smoke validation/inference durations0.111291/0.122731/0.414858s respectively. These single-run checks include parent no-op/source validation and child inference before comparison assembly/persistence; not a performance study/throughput guarantee.
- Real downloaded browser comparisons/screenshots under `runtime/phase4a-browser-reports`, associated `runtime/browser-test.sqlite3`. Final comparison screenshot `3f4e262db65e45d8af6fabd11dde2d58-comparison.png` and its JSON were actually captured and visually inspected; before risk100/three stages, after risk60/two stages, no transfer. Screenshot is evidence of UI output, not proof of accuracy.
- Intermediate smoke directories `runtime/phase4a-smoke-20261007` and `runtime/phase4a-smoke-final-20261007` retained. Their earlier strict policy identities may be incompatible with the final implementation; use the gate directory for current verification. Previous reports/original sources remain inspectable, never silently reinterpreted.

Fresh existing benchmark regression: `runtime/phase4a-regression/6d45e55c10fe4778ae6df3b2ca628d67/evaluation.json`, matching DB `runtime/phase4a-regression.sqlite3`. Accepted9664/4834/4841=19339, both modes precision1/1, recall1/1, benign false-positive units0/212, evidence5/5, stages3/3, order coverage3/3 and asserted-order accuracy4/4; one alert/one partial. **No measured hybrid detection improvement.** Calibration210 percentile samples/0 complete candidates/threshold80 structural fallback/budget_met=null. Test Wilson95% upper bound1.78%, no population1% guarantee. One-run concurrent-host times fit1.771052s/rules2.281512s/hybrid2.342741s/total12.727737s, memory null. This unchanged regression is separate from Phase4D, which remains unimplemented.

## Limitations and next checkpoint

Phase4A gate passed; no unfinished Phase4A task remains. Historical parents without sufficient snapshots or available exact implementation are unsupported for sensitivity; create an ordinary new run. Conservative code/library identities can reject harmless source edits. Maximum100 exclusions, synchronous full reruns; no nested exclusions, context/cutoff edits, incremental caching, source authenticity signatures, causal inference, safe endpoint status, unlearning or automatic fitting. The local SQLite/operator remains the trust boundary. Scores may increase, decrease or become unavailable. Synthetic cases and sparse calibration do not establish production generalization; memory and POSIX/container operation remain unverified.

**Stop here.** Next user-selected checkpoint is Phase4B: genuine benign look-alike comparison using existing scoped context and frozen policy, retaining actual unchanged decisions/false positives. Do not start it automatically. Phase4C replay and Phase4D broader evaluation/performance remain deferred. Docker engine follow-up from Phase3 stays independently pending; it was not retried or claimed passed.
