# Phase 4B checkpoint - benign look-alike gate passed

Date: 2026-10-07, Asia/Calcutta. **Phase 4B only is implemented and freshly verified.** Phase 1–3 and completed 4A workflows remain retained. Previous status was preserved byte-for-byte in `docs/PHASE4A_BUILD_STATUS.md`; earlier Phase 1–3 checkpoint files remain. Phase 4C replay and 4D expanded evaluation are unimplemented. No publishing, deployment, remediation, model replacement, policy/threshold tuning or dependency upgrade.

## Starting state and first controlled comparison

Read AGENTS.md, prompt.md, BUILD_STATUS, the actual Downloads/phase4_prompt.md sections1–3/4B (no root phase4_prompt.md exists), Downloads/phase4b_prompt.md, schema/architecture/decisions/model/limits/scope/demo and current code. The user's explicit4B request governs; the supporting4A default does not restart4A or authorize4C/4D. All previously untracked working files were preserved.

Inspected `runtime/phase4a-smoke-gate-20261007/smoke.json` and its retained IDs/outcomes as historical evidence. Fresh initial baseline: backend87 passed27.82s; frontend6 passed2.26s; build19 modules passed; browser7 passed36.9s. Earlier transcript/benchmark values remain historical, not a new4B accuracy result. Saved4A unique-copy and hybrid-noop exports were freshly CLI-verified; saved tampered exclusions were rejected (exit1).

First real pair was established before the comparison resource/UI: `runtime/phase4b-first-pair-20261007/{traceguard.sqlite3,pair.json}`. Separate explicit training/calibration setup used existing chronological benign fixtures. Two ordinary hybrid runs used the same canonical observations/source content, selected baseline, cutoff, policy and non-authorization context, with withheld versus exact declared authorization. Actual risk99.52380952380952/incident versus79.52380952380952/review, each with three supported stages. No model fit/calibration occurred between arms. These observations were not forced to reproduce the illustrative100→80 arithmetic.

## Delivered

- `lookalikes.py`: validation through ordinary frozen no-op reproduction, per-field membership/content/artifact/source/context/config identities, strict server-side context-only contract including unchanged stages/linkage/history/model/non-context risk, declared scenario input differences, persisted run references and actual correspondence/deltas. Matching uses rule family, exact scoped actor/endpoint, overlapping episode time and shared evidence; ambiguity/unmatched outcomes retain unavailable deltas. No index pairing or invented incident risk0.
- Additive SQLite comparison and separate evaluator-annotation tables. Both ordinary arms retain their original context/run fingerprints. Current uploads/resource/authorization/alias edits do not enter saved runs. Authorized-first and withheld-first preparations are isolated. Legacy/incompatible runs receive ordinary-reanalysis guidance.
- Existing operator policy remains untouched: hybrid subtracts20 once for exact copy scope and [effective_from,effective_until), using the copy event time. Inclusive numeric threshold with required structural/closed-window gates remains. Rules-only is unchanged. No context override was added to4A sensitivity; no inference policy module was edited.
- Evaluation-only `evaluation/lookalikes.py`: isolated ordinary ingestion/analysis, truth annotation only after predictions, lab-v1/seed17,11 retained pairs. Scope/time/repeated declaration cases, raw self-approval plus duplicate copy reference, missing-copy partial, real selected-history familiarity and existing attack-labeled supported generator fixture. Wrong environment/action/provenance are validation rejections, not stored failed matches. Library loading requires an explicitly selected saved baseline and never fits/recalibrates.
- Existing workbench `Lookalikes.tsx`: aligned retained-arm findings/predicates/history/model/threshold/calibration, actual changes/correspondence, separately styled synthetic truth, retained benign alerts, all candidate pages, loading/error/retry and generation guards against late responses. Stable lookalike URL refresh/restart. Each arm links to exact sources, mount, timeline/graph and existing JSON/Markdown reports. Frozen run source API supports absent candidates; first20 observation/history/model samples are explicitly labeled and complete findings stay accessible by original run/candidate navigation.
- README, schema/API, architecture/decisions, scope/demo/novelty/limits and evaluation notes updated. Optional standalone4B comparison download/verification subtype is deliberately omitted; no unverified download labeled verified.

## Exact executed checks

All commands below ran from `<LOCAL_PATH_REDACTED>

| Command | Actual final result |
|---|---|
| `.\.venv\Scripts\python.exe -m pytest backend/tests/test_phase4b.py -q` | 18 passed12.76s. Initially14 passed10.44s before four real non-authorization mismatch cases were added. |
| `.\.venv\Scripts\python.exe -m pytest backend/tests -q` | **105 passed46.51s**, including all87 existing tests and18 new4B cases; one existing Starlette/HTTPX deprecation warning. Intermediate full run101 passed38.54s before final cases. |
| `npm --prefix frontend test` | **6 passed1.79s**, original behavioral assertions retained; badge expectations advanced to4B and new saved-list request handled. |
| `npm --prefix frontend run build` | TypeScript/Vite passed20 modules; final assets `index-ClCHaAHE.js`/`index-CGKD628d.css`. |
| `npm --prefix frontend run test:browser` | **9 passed1.0m**: seven existing real backend flows plus lab/source/refresh/outcomes and stale-response/error tests. |
| `npm --prefix frontend run test:browser -- lookalikes.spec.ts` | Intermediate focused run: first real flow passed12.9s; second locator failure corrected as described below, then both passed in final full suite. After the final guard against selection changes during saved-list refresh, focused2-flow browser rerun passed17.0s (13.9s/0.572s); TypeScript/Vite and6 frontend tests passed again. |
| `.\.venv\Scripts\python.exe scripts/phase4b_smoke.py --output runtime/phase4b-smoke-gate-20261007` | Passed native built-UI/API,11 real comparisons, both sources, reports/tamper, model integrity and process restart. Intermediate acceptance retained. |
| `.\.venv\Scripts\python.exe scripts/phase4b_smoke.py --output runtime/phase4b-smoke-final-20261007` | Passed final source-navigation version; all11 saved comparisons reopened byte-equivalent after real helper-process restart. |
| `.\.venv\Scripts\python.exe scripts/phase4a_smoke.py --output runtime/phase4a-regression-4b-20261007` | Passed preserved4A unique/duplicate versus independent copy/noop/hybrid/source/report/model immutability/tamper/restart gate in new artifacts. |
| `.\.venv\Scripts\python.exe -m pip check` | No broken requirements. |
| `.\.venv\Scripts\python.exe -m compileall -q backend/src scripts` | Passed, repeated after final source changes. |

Fresh saved4A commands (first two exit0/valid=true; last deliberately exit1/valid=false):
```powershell
.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/phase4a-smoke-gate-20261007/traceguard.sqlite3 verify-report runtime/phase4a-smoke-gate-20261007/unique-copy-comparison.json
.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/phase4a-smoke-gate-20261007/traceguard.sqlite3 verify-report runtime/phase4a-smoke-gate-20261007/hybrid-copy-noop.json
.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/phase4a-smoke-gate-20261007/traceguard.sqlite3 verify-report runtime/phase4a-smoke-gate-20261007/unique-copy-tampered.json
```

The4B native helper separately and explicitly fits benign setup before the library call, hashes/model-compares before/after, verifies every existing incident JSON/Markdown report and tampered risk rejection, creates/verifies a4A no-op export, rejects altered4A parent identity and CLI-verifies an incident plus sensitivity report. It restarts only its own loopback server and checks all saved comparisons/reports again. Exact CLI invocations are in the helper; verification results are saved as `cli-{incident,sensitivity}-verification.json`. No Docker retry, new isolated install, POSIX claim or expanded benchmark was performed.

## Observed outcomes and acceptance artifacts

Final native database: `runtime/phase4b-smoke-final-20261007/traceguard.sqlite3`. Full record: `smoke.json`; compact26,743-byte acceptance record: `acceptance-summary.json`, derived from that executed smoke record with its source hash, omitting repeated history/window payloads. It is an acceptance record, not a standalone authenticity signature. Full comparison snapshots and per-arm JSON/Markdown remain alongside it; `library.json` includes fixture version/seed/baseline, all pair IDs and validation outcomes.

- Controlled comparison `32828030047c45c4bff56a874fb3e920`: left run `99a29e304065447e939af7074dd16156`, right run `2c4524ab9c4341ecabeeb61c64c1474c`. Three stages and anomaly percentile0.9761904761904762 unchanged; risk99.5238→79.5238, reduction0→20, incident→review. Both truth annotations remain benign. The left alert is retained as a remaining fixture-level false positive; the review item is not a false-positive alert or verified safety.
- Expired/future/wrong actor/endpoint/resource: failed exact relevant predicate, reduction0, risk99.5238/incident; benign alerts remain. Multiple declarations: two matches, reduction20 only once, risk79.5238/review on both arms; decision unchanged.
- Rules-only comparison `9f328dba798b43b9ae45e594d4d9c8fd`: selected frozen-history baseline but no forest inference, risk100/incident on both arms, no score/decision change. Both benign alerts are retained false positives. Missing-transfer comparison `5316f7128f8d4bd5a59a7ed7f3d6707e`: right partial risk72.6190/two stages, no transfer claim.
- Familiarity comparison `7cf4c45967644d53ba8cbe471db3f5b0`: right run `c714949379304b088f9b41ab85c36c2c` has no candidate, so no incident score. Actual left/right prior successful logins14/15; same-resource prior reads0/28; authentication eligibility unusual versus familiar. Both model percentiles are0.9761904761904762: do not invent a smaller familiar anomaly. Actor/endpoint/app/resource/time/source changes are visible. The shared baseline is disclosed; no single-cause/model-gain claim.
- Existing attack versus business export comparison `527e2022ab83497c97759ad768d2da31`: existing attack fixture has one complete alert risk96.1915 plus one partial; benign exact-export arm remains review79.5238. Distinct datasets/evidence mean unmatched correspondence, not artificial episode pairing.
- Baseline `96d03f5877174ff6a61e22590e58909c`, model SHA256 `c2fe6f9f67fb39a49aa88c8743bbaf571c8ca8233991f2f2338c69c92d3b339f`, byte-identical before/after and restart. Calibration42 percentile samples,0 complete benign candidates, threshold80 structural fallback, budget_met=null. No model detection improvement or accuracy estimate follows from this curated library.
- Fresh4A regression comparisons unique `ecc0db48383b4bcebbc0ba9cb7aed1cc` / independent `5c93719d7d944ecc86e0f9672c02ff48` / hybrid `615adda8368743ce960ad38a063fc449`, saved under `runtime/phase4a-regression-4b-20261007`; actual restart_verified true for all, model unchanged for hybrid.
- Final browser screenshot `runtime/phase4b-browser-reports/489ed1c077a340a591a9332e6f85a318-familiar.png` was captured and visually inspected. Associated saved pairs are in `runtime/browser-test.sqlite3`. Screenshot shows real retained arms/absent risk, not proof of accuracy.

Compact summary derivation command actually executed:
```powershell
.\.venv\Scripts\python.exe -c "import json; from pathlib import Path; from traceguard.ingest import digest; p=Path('runtime/phase4b-smoke-final-20261007'); raw=(p/'smoke.json').read_bytes(); d=json.loads(raw); d['source_acceptance_record']={'path':str((p/'smoke.json').resolve()),'sha256':digest(raw)}; [a.pop(k,None) for r in d['results'] for a in r['arms'] for k in ('history_probes','model_windows')]; f=(p/'acceptance-summary.json').open('x',encoding='utf-8'); json.dump(d,f,indent=2); f.close(); print((p/'acceptance-summary.json').stat().st_size)"
```

## Failures, limits and stopping point

No failures were hidden: the first browser full run had7 old tests passing and2 new failures. Exact `getByLabel('Lab baseline')` could not resolve the select in that test; using its accessible combobox role fixed it. The dependent race test had no library because setup had timed out. The next focused run passed the real lab flow but an imprecise text locator matched both a hidden dropdown option and the result paragraph; anchoring on the full comparison paragraph fixed it. Final full9-flow run passed. No policy/model/threshold adjustment was used to fix tests.

The inclusive80 numeric boundary is tested with deterministic scored-window percentile1 supplied to the real orchestrator:100–20=80 remains an alert with all other gates met. This is a regression boundary, not a measured new native fixture outcome. Exact start/just-before/start-exclusive-end/after-expiry copy-time cases, irrelevant login timing, duplicate sources, repeated declarations, actual non-authorization incompatibilities, truth isolation, immutable edits/reopen/order, absent/multiple/ambiguous outcomes and no fitting are covered.

Sparse calibration and absent measured hybrid detection gain remain limitations. The lab is not a population accuracy/FPR study or proof of benign source authenticity/human intent. Current SQLite/operator is the trust boundary. Ordinary compatible runs only; synchronous full no-op validation; first20 displayed signals with bounded candidate/source navigation; no context-override sensitivity, causal attribution, automatic suppression/safe status, standalone4B verified export, replay or expanded evaluation. Existing deprecation/NO_COLOR warnings are non-failing. Docker engine and independent POSIX/second-machine verification remain inherited unverified limitations.

**4B gate passed. No unfinished required4B task remains. Stop here.** Next requested checkpoint is4C;4D remains separate. No deployment, publication, push or remediation.
