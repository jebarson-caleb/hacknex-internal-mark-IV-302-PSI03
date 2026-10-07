# Phase 3 checkpoint - native MVP gate passed

Date: 2026-10-07, Asia/Calcutta. Phase 3 required native workflow is implemented and verified on this Windows host. Phase 1 default rules-only and Phase 2 explicit hybrid flows remain working. Docker configuration is delivered, but container execution is blocked by the unavailable Docker Desktop Linux engine. POSIX/second-machine installation is unverified. Phase 4 has not started. Historical checkpoints: PHASE1_BUILD_STATUS.md and PHASE2_BUILD_STATUS.md; their results are historical evidence, not current verification.

## Checkpoint A: bounded Phase 2 audit

- Read AGENTS.md, root prompt.md requirements, prior status, user Downloads/phase3_prompt.md and existing implementation/configuration/documents. Repository began with untracked working files; all were preserved. No commits, publication, deployment or remediation execution.
- Fresh pre-change checks: backend63 passed (16.25s), frontend6 passed, production build passed, browser3 passed (9.1s), using the commands below. No previous transcript test count was treated as verification or a target.
- Real persisted forest/score_samples, frozen history/feature order/preprocessing, chronological closed windows, source/model fingerprints/versions and label isolation are present. Existing strict identity/event-time/copy/mount/graph gates remain intact.
- Inspected seed-41 Phase 2 saved evaluation `runtime/phase2-benchmark/ed3e9840f3c342e9a592190f584afb77/evaluation.json` and its SQLite runs. Test count4841 and fingerprints matched. Freshly reverified complete and partial objects in both stored modes against sources/graph/numeric terms. This inspection was not a new benchmark run.
- Found misleading calibration metadata: old sparse calibration recorded budget_met=true with zero complete benign candidates, and hybrid risk used calibrated=true. Preserved those artifacts; new fits distinguish percentile availability/count/method from final threshold status/origin/fallback. Sparse budget_met is now null, structural threshold80 retained, no population guarantee. Missing old fields display unknown. No held-out tuning, model replacement or changed denominators.

## Checkpoint B: workbench, context and reports

- Overview retains synthetic/upload origin, actual quality counts/source families, source/timezone validation and normalized preview. Uploads never train automatically. Arbitrary selected data shows ground truth unavailable; labeled benchmark metrics are separate and clear on dataset/run changes.
- Historical run selector (latest200) and retained run/incident URL restore detail across refresh. Run summaries avoid full model/window payload; detail fetches the selected persisted snapshot. Search supports actor, endpoint, ID, summary/reason; decision filters and20-item pages retain all alert/review/partial candidates (API max100).
- Stage selection highlights real graph edges/nodes through event IDs and opens original source rows from the same incident/run. Locally bundled SVG extends the existing typed relation renderer; accessible relation/source list, type/status legend, directed arrows and bounded expansion (max500). Mount and IP context never substitute for copy/identity evidence; independent event counts do not inflate with edge count.
- Scoped copy authorizations extend operator context storage: exact namespace/user/endpoint/resource/action, bounded effective interval, ID and nonblank provenance. Hybrid-v2 subtracts20 once for a match; rules-only scores are unchanged. Matching/failed predicates, alias reasons, risk components, unavailable ML, threshold/calibration and immutable run context are inspectable. Log self-approval is ignored. Context edits affect future runs only.
- Deterministic recommendations cite verified structured observations and require authorized-human review. Approval status is not_recorded. No approval, intent, human attacker identity or action execution is invented.
- Existing overlapping episode/duplicate policy is retained and tested; unrelated later episodes remain distinct. New runs freeze all source references for stage/mount/history evidence; duplicate reimports cannot change historical reports.
- Backend JSON/Markdown downloads contain report/schema/run IDs, fingerprint/cutoff, relevant normalized events/source references and hashes, predicate/history/context/risk/version/calibration facts, suggestions/limits, actual validation and UTC check time. Minimal privacy defaults omit raw records/filenames/paths/IPs and selected free-text/location fields; include_raw is explicit. Full originals stay local; unrelated whole source files/datasets are not exported.
- CLI `export`, `verify-report` and existing `verify` work. Submitted-report verification compares all claims/evidence/context/risk/references against the retained run and rechecks source predicates/hashes. Markdown prose/payload are both checked. Altered claims/source/run/approval fail; invalid retained evidence refuses a falsely verified report. Hashes establish retained consistency, not source-system truth/signatures. Legacy missing calibration/reference metadata is disclosed.

## Exact local setup and commands

Run from `<LOCAL_PATH_REDACTED>

```powershell
# New checkout only; preserve an existing working venv.
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.lock
.\.venv\Scripts\python.exe -m pip install --no-deps -e backend
npm --prefix frontend ci
npm --prefix frontend run build
.\.venv\Scripts\python.exe scripts/run_demo.py
```

This host's system Python aliases are Store stubs. Working bootstrap, when needed:

```powershell
& '<LOCAL_PATH_REDACTED>' -m venv .venv
```

Open http://127.0.0.1:8000 (loopback), API docs /docs. Default DB: runtime/traceguard.sqlite3; TRACEGUARD_DB selects another file; .env.example is documentation and is not auto-loaded. POSIX: `python3.12 -m venv .venv`; substitute `.venv/bin/python` in remaining commands. POSIX is documented, not executed here.

```powershell
# Retained incident/report IDs must belong to the same DB.
.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/traceguard.sqlite3 export INCIDENT_ID --format json --output runtime/reports/NEW.json
.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/traceguard.sqlite3 export INCIDENT_ID --format markdown --output runtime/reports/NEW.md
.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/traceguard.sqlite3 verify-report runtime/reports/NEW.json
.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/traceguard.sqlite3 verify INCIDENT_ID
.\.venv\Scripts\python.exe scripts/smoke_workflow.py --output runtime/native-smoke-NEW
.\.venv\Scripts\python.exe scripts/check_server.py --db runtime/server-smoke-NEW.sqlite3
```

Exports/smoke output directories refuse silent overwrite. Use README's explicit chronological-demo/train/analyze commands for hybrid, or the UI: load chronological data -> review benign selections/provenance -> fit selected baseline -> Analyze hybrid. Loading data never fits a model.

## Actual final checks

| Executed command | Actual result |
|---|---|
| `.\.venv\Scripts\python.exe -m pytest backend/tests -q` |71 passed, final16.62s; one Starlette/HTTPX deprecation warning. All prior tests retained.|
| `npm --prefix frontend test` |6 passed, final1.64s; original empty/demo/evidence/error/partial/baseline/graph assertions preserved and adapted to new real routes.|
| `npm --prefix frontend run build` |TypeScript and production Vite build passed,18 modules; final root assets index-DH7GtE5y.js.|
| `npm --prefix frontend run test:browser` |5 passed, final17.4s, actual built UI/API and model; clean/positive/partial, CSV upload/context, explicit hybrid fitting/graph/evaluation, linked original rows, real JSON/Markdown download+CLI verification, refresh/context immutability/stale-metric clearing and real22-episode pagination.|
| `.\.venv\Scripts\python.exe -m pip check` |No broken requirements.|
| `.\.venv\Scripts\python.exe -m compileall -q backend/src scripts` |Passed.|
| Seed41 benchmark command below |New schema2 evaluation actually executed; findings below.|
| Isolated Windows setup/install/build/workflow/restart commands below |Succeeded; no user environment/data removed.|
| `docker info --format '{{.ServerVersion}}'` |Failed: npipe DockerDesktopLinuxEngine unavailable, system cannot find the file. Build/start not claimed passed.|

Focused new backend coverage: stage-eligible declared export versus expired/out-of-scope actor/endpoint/resource; risk policy and unchanged rules-only behavior; context edits/history; new/legacy calibration disclosure; submitted JSON/Markdown tampering, literal untrusted text, minimal/full privacy, retained-source corruption refusal; run-bound stage/graph/source navigation; filter/real cursor pagination; process/store reopen; overlapping/later episodes, repeat analysis and frozen duplicate references. Browser screenshots were actually captured and inspected at runtime/phase3-workbench.png.

Intermediate failed checks were corrected, not skipped: Windows locale writes produced mixed UTF-8 in new UI symbols (fixed explicit UTF-8), initial component mocks intercepted the new analyses route incorrectly and clicked during loading (corrected fixtures/waits), and the first new browser test read the URL before asynchronous incident selection finished (waited for retained incident URL). Final checks pass. Playwright's NO_COLOR/FORCE_COLOR and Starlette/HTTPX warnings remain non-failing; no dependency upgrade was used to hide them.

## Checkpoint C: isolated native setup and packaging

Fresh source copy: `runtime/phase3-clean-setup-260247b1`, with separate .venv/node_modules. No original runtime data/model was copied into it. Exact commands executed from root:

```powershell
$phase3Setup = '<LOCAL_PATH_REDACTED>'
.\.venv\Scripts\python.exe -m venv "$phase3Setup\.venv"
& "$phase3Setup\.venv\Scripts\python.exe" -m pip install -r "$phase3Setup\backend\requirements.lock"
& "$phase3Setup\.venv\Scripts\python.exe" -m pip install --no-deps -e "$phase3Setup\backend"
npm --prefix "$phase3Setup\frontend" ci
npm --prefix "$phase3Setup\frontend" run build
& "$phase3Setup\.venv\Scripts\python.exe" "$phase3Setup\scripts\smoke_workflow.py" --output "$phase3Setup\runtime\final-smoke"
& "$phase3Setup\.venv\Scripts\python.exe" "$phase3Setup\scripts\check_server.py" --db "$phase3Setup\runtime\final-server.sqlite3"
& "$phase3Setup\.venv\Scripts\python.exe" -m pip check
& "$phase3Setup\.venv\Scripts\python.exe" -m traceguard.cli --db "$phase3Setup\runtime\final-smoke\traceguard.sqlite3" verify-report "$phase3Setup\runtime\final-smoke\hybrid.json"
```

Initial fresh install succeeded using locked dependencies; npm ci106 packages, audit0 vulnerabilities. Latest source was synced into the isolated copy without reinstalling/deleting its venv/data and the build/report verification/server-restart checks repeated successfully. Smoke exercised actual CLI export/verify for both modes and formats, rejected an intentionally tampered report (exit1), explicit fitting, clean zero alerts and real source/graph inspection. Reports/DB/summary remain under final-smoke; native server check served built assets and fetched the same persisted run after terminating/restarting only its own helper process. API/docs/static checks succeeded without credentials or runtime external connections. Package download installation is distinct from offline application operation.

Dockerfile and .dockerignore provide frontend-build/backend-serving, nonroot UID10001 and external runtime persistence while excluding secrets/private runtime/dev caches. Container commands are pending, not passed:

```powershell
docker build -t traceguard:phase3 .
docker volume create traceguard-data
docker run --rm --name traceguard-demo -p 127.0.0.1:8000:8000 -v traceguard-data:/app/runtime traceguard:phase3
Invoke-RestMethod http://127.0.0.1:8000/api/health
```

Then run clean/positive/partial and explicit hybrid demo/export flows inside the container through the UI. POSIX uses the same Docker commands and curl for health. Default host access remains loopback; no cloud publication, repository push or remediation execution.

## Fresh measured benchmark and artifacts

```powershell
.\.venv\Scripts\python.exe scripts/benchmark.py --seed 41 --users 30 --events 20000 --db runtime/phase3-benchmark.sqlite3 --output runtime/phase3-benchmark
```

Actual schema2 evaluation `runtime/phase3-benchmark/afb56b5a280042fa85e963615b5d3c0b/evaluation.json` (labels separate) and runtime/phase3-benchmark.sqlite3. Accepted train/cal/test9664/4834/4841=19339. Both modes: precision1/1, recall1/1, benign false-positive units0/212, asserted evidence5/5, required stages3/3, ordering coverage3/3, asserted-order accuracy4/4. One alert/one partial; **no measured ML detection improvement**. Test FPR95% Wilson upper bound1.78%, not a population1% guarantee. Calibration210 percentile samples,0/211 false-positive units,0 complete candidates; threshold80 structural fallback, budget_met=null. No held-out threshold tuning. Historical Phase2 outputs remain intact.

Measured fit/source1.7483s, rules1.6660s, hybrid1.6222s, total11.2626s; concurrent host work, no speed superiority claim. Memory remains null/unmeasured. Host Windows11 10.0.26300, Python3.12.14, Node26.7.0/npm11.19.0; library locks retained. UI benchmarks are separate actual labeled runs; arbitrary uploads do not inherit their accuracy.

Other artifacts: runtime/browser-reports (real downloaded incident reports), runtime/browser-test.sqlite3, runtime/phase3-workbench.png, isolated final-smoke JSON/Markdown/SQLite/smoke.json. None contains real uploaded personal data from a user; these checks used generated synthetic fixtures. Runtime artifacts are ignored by Git.

## Remaining limitations and next checkpoint

Native Phase3 MVP gate passed. Optional Docker execution blocked as above; POSIX/second-machine installation, production generalization and process memory are unverified. Calibration is sparse/synthetic, one held-out episode, no demonstrated ML detection gain. Matching authorization may reduce but not suppress a complete alert; rules-only is unchanged. Local unauthenticated loopback API, synchronous bounded SQLite; no source-system authenticity proof/signatures. Legacy runs lack explicit calibration status/reference snapshots, disclosed as unknown/unavailable. Human authorization approval/team review and public repository submission remain human steps, not tool-claimed completion. Organizer PDF unavailable; docs/DEMO.md checklist maps the supplied booklet summary.

Next concrete checkpoint: when a Docker engine is available, execute the pending build/start/health and full container demonstration, record actual results. Human team reviews code/resources and follows docs/DEMO.md before manual submission/publication. Do not automatically start Phase4. Replay, sensitivity reruns, dedicated benign comparison, expanded ablations/robustness and performance study remain Phase4 scope.
