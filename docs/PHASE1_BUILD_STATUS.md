# Build status — Phase 1 checkpoint

Date: 2026-10-06 (user timezone: Asia/Calcutta). **Phase 1 implemented and verified. Rules-only. ML is not implemented.**

## Implemented

- Initial repository inspection found only `.git`, no commits, tracked files or uncommitted application work. Copied `<LOCAL_PATH_REDACTED> to the requested repository root. Both copies have SHA-256 `E255D6EA70C59C54664B27BF9A8327AC5A5FCEEBF527E8DB40C351FCA5E0DB90`.
- Typed canonical event/source/stage/incident models, four synthetic CSV/JSONL source-family adapters, UTC normalization and explicit-zone handling, DST ambiguity rejection, action-specific required fields, environment/type identity namespaces, stable event IDs, duplicate references and conflicting-ID quarantine.
- SQLite persistence of original uploaded bytes, raw records and hashes, canonical events, trusted sensitivity labels, ingestion errors/quality, and immutable config/context/event snapshots for completed analyses.
- Seeded small background history and three real observation fixtures: positive, benign mount-only, missing transfer. Checked-in CSV/JSONL examples for positive and benign; generator can produce all variants.
- Prior-day historical counts and a bounded deterministic three-stage matcher. Exact account/endpoint/resource/removable-media linkage, strict event-time order, matching explicit positive-byte copy, active prior mount, 60-minute window. IPs do not join actors. Cold-start, partial and missing-evidence states are explicit.
- Evidence validation independently rechecks cited events, predicates, historical comparisons, stage metadata, identities, timing, mount context, source-file/record hashes and original source row. The positive case validates three asserted stages and 24 event provenance references including history.
- FastAPI API; real React UI for demo/load/upload/append, quality, context configuration, analysis, incident/review list, UTC timeline with mount context, source evidence and paginated event preview. All visible buttons call implemented functionality. Built assets are served locally.
- CLI `demo`, `analyze`, `verify`; cross-platform small generator and demo-server script; pinned backend requirements and frontend lockfile; setup, schema, architecture, scope, decisions, limitations and resource documentation.

No trained baseline, Isolation Forest, graph, calibration, full metrics/benchmark, authorization reduction, report bundle, replay or counterfactual feature is claimed complete. No optional features, external deployment, public repository publication or remediation were implemented.

## Exact install and run commands

Working directory for commands below:

```powershell
Set-Location '<LOCAL_PATH_REDACTED>'
```

This machine's `python`/`python3` commands are Microsoft Store stubs and `py` is absent. The actual working environment was bootstrapped with the supplied runtime:

```powershell
& '<LOCAL_PATH_REDACTED>' -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e './backend[test]'
```

After versions were resolved, pinned and locked, these installation commands were also executed successfully in that environment:

```powershell
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.lock
.\.venv\Scripts\python.exe -m pip install --no-deps -e backend
npm --prefix frontend ci
npm --prefix frontend run build
```

Standard clean-checkout setup on a system with Python 3.12 is `python -m venv .venv`, followed by the four commands above. No independent second-machine/POSIX clean install was performed. The backend editable reinstall and npm clean lockfile install both succeeded here.

Single local demo server, serving the built React UI and API:

```powershell
.\.venv\Scripts\python.exe scripts/run_demo.py
```

Open http://127.0.0.1:8000, load a demo, then click **Analyze rules-only**. Swagger docs: http://127.0.0.1:8000/docs. Data persists in `runtime/traceguard.sqlite3`. No network or credentials are needed after dependency installation. This command was also started on port 8000 and `/api/health` returned `status=ok`, `mode=rules-only`, `ml_implemented=false`. The same entry point was exercised by the browser suite on port 8001.

Development, in two terminals:

```powershell
.\.venv\Scripts\python.exe -m uvicorn traceguard.main:app --host 127.0.0.1 --port 8000 --reload
npm --prefix frontend run dev
```

The production/demo-server path was verified; the interactive Vite development-server path is provided but was not separately browser-tested.

Deterministic source generation and command-line analysis:

```powershell
.\.venv\Scripts\python.exe scripts/generate_demo.py --seed 17 --variant positive --output runtime/demo
.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/cli.sqlite3 demo --seed 17 --variant positive
.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/cli.sqlite3 demo --seed 17 --variant benign
.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/cli.sqlite3 analyze DATASET_ID
.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/cli.sqlite3 verify INCIDENT_ID
```

Replace `DATASET_ID`/`INCIDENT_ID` with values printed by `demo`; these are placeholders, not literal arguments. `verify` checks a retained local incident against its original run/context and source files. It is not the future exported-bundle command.

## Tests and checks actually executed

Tested environment: Windows, Python 3.12.14, Node 26.7.0, npm 11.19.0. Package versions are recorded in the lockfiles, including FastAPI 0.142.2, Pydantic 2.13.5, Uvicorn 0.54.0, pytest 9.1.1, HTTPX 0.28.1, React 19.3.0, Vite 8.3.3, TypeScript 7.0.2, Vitest 5.0.3 and Playwright 1.63.0.

| Actual command | Result |
|---|---|
| `.\.venv\Scripts\python.exe -m pytest backend/tests -q` | **39 passed**, final run 4.98s; one non-failing Starlette/HTTPX deprecation warning. |
| `npm test` from `frontend` (equivalent to `npm --prefix frontend test`) | **4 passed**; final UI run 1.25s. |
| `npm --prefix frontend run build` | **Passed** TypeScript and Vite production build; 17 modules, output in `frontend/dist`. |
| `npx playwright install chromium` from `frontend` | **Succeeded**; installed Chromium 153.0.8010.12, Playwright build v1243 and headless shell. |
| `npm --prefix frontend run test:browser` | **2 passed**, final rerun 3.8s including local server setup, after the failed-outcome guard was added. |
| `.\.venv\Scripts\python.exe scripts/generate_demo.py --seed 17 --variant positive --output data/samples/positive` | **Succeeded**, 79 records; matching CSV/JSONL plus separate context. |
| `.\.venv\Scripts\python.exe scripts/generate_demo.py --seed 17 --variant benign --output data/samples/benign` | **Succeeded**, 77 records. |
| `.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/cli.sqlite3 demo --seed 17 --variant positive` | **Succeeded**, 79 events / 1 incident / 0 partials. |
| `.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/cli.sqlite3 demo --seed 17 --variant benign` | **Succeeded**, 77 events / 0 incidents / 0 partials. |
| `.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/cli.sqlite3 analyze c31a9b65fe8c47e8a38385991040f46e` | **Succeeded**, repeated persisted positive dataset: 79 events / 1 incident / 0 partials. |
| `.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/cli.sqlite3 verify $positiveRun.incidents[0].incident_id` | **Succeeded**, valid source-backed evidence, 3 asserted stages / 24 provenance references; `$positiveRun` comes from the real demo command below. |
| `.\.venv\Scripts\python.exe -m pip check` | **Passed**, no broken requirements. |
| `.\.venv\Scripts\python.exe -m compileall -q backend/src scripts` | **Passed**. |
| `git diff --check` | **Passed**; checkout had only new untracked source files, so this is not claimed as a full tracked-diff audit. |

Exact verification invocation executed in PowerShell:

```powershell
$positiveRun = .\.venv\Scripts\python.exe -m traceguard.cli --db runtime/cli.sqlite3 demo --seed 17 --variant positive | ConvertFrom-Json
.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/cli.sqlite3 verify $positiveRun.incidents[0].incident_id
```

Result: `valid: true`, `errors: []`, `asserted_stages_checked: 3`, `provenance_events_checked: 24`.

Backend coverage includes four adapters, UTC/explicit-zone/DST errors, missing fields, malformed CSV/JSONL, empty and cold-start data, duplicate ingestion and byte/evidence non-inflation, shuffled and repeat analysis, missing/mismatched transfer, zero-byte copy, active mount/unmount, equal-time/invalid ordering, mount before collection, explicit failed login/read/mount/copy outcomes, shared-NAT unrelated users, namespace collisions, source/vendor conflicts, fabricated/unrelated/changed evidence, source tampering, expired sensitivity and immutable run context, future cutoff isolation, persistent API retrieval, pagination, upload/path/SQL-like inputs, unknown API routes and both declared-length and chunked oversize requests.

Frontend checks cover empty state and explicit rules-only labeling, demo/analyze/timeline/evidence interactions, escaped log HTML, missing-transfer partials and actionable errors. Browser checks use the actual built frontend and live API: benign → positive → partial demos, ordered mount context, real raw evidence, and all four CSV uploads followed by separate trusted context and a real source-row inspection. No mocks are used in the browser suite.

Failures fixed during this phase: oversized multipart upload initially returned 400 instead of 413; request bounds and correct status handling were fixed and checked for chunked uploads too. Initial TypeScript production build failed to resolve the CSS side-effect import; `vite-env.d.ts` fixed that. No test failures remain.

## Remaining blockers and limitations

- **No unresolved Phase 1 execution blocker.** System Python alias issue was resolved through the local venv bootstrap above.
- Non-failing dependency warning: Starlette 1.7.0 deprecates its HTTPX TestClient backend in favor of HTTPX2. Current pinned tests pass; plan the test-client migration when updating dependencies.
- Organizer PDF unavailable; supplied prompt's authority references have not been independently verified.
- No second-machine/POSIX reproducibility test, real-log generalization, calibrated FPR, larger benchmark or machine-memory measurement. Fixture counts above are regression results, not population accuracy claims.
- Dataset cap is 10,000 unique events; larger default profile, frozen ML baseline, graph, scoped authorization, exports and later-phase work remain in `docs/SCOPE.md`.

## Artifact locations and next phase

Source: `backend/src/traceguard`, `frontend/src`. Tests: `backend/tests`, `frontend/tests`. Small reproducible inputs: `data/samples/positive` and `data/samples/benign`. Specification: root `prompt.md`. Dependencies: `backend/requirements.lock`, `frontend/package-lock.json`. Ignored local state: `.venv`, `runtime/*.sqlite3`, `frontend/dist`, browser/test caches.

**Next is Phase 2 only when requested:** real frozen baseline fitting and Isolation Forest scoring, rolling features and calibration, typed entity graph/conservative resolution, hybrid risk, chronological evaluation splits and isolated labels, benchmark CLI and expanded negatives. Do not label that model finished merely because rules-only detection works.
