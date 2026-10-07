# HackNex Internal Mark IV — TraceGuard

TraceGuard is a local-first workbench for reconstructing a suspected security incident from retained logs. It links supported observations into an inspectable timeline, shows the source evidence and uncertainty behind each stage, and keeps analyst notes and external context separate from detector results.

The primary chain is **unusual login → sensitive-file collection → matching copy to mounted removable media**. TraceGuard reports observed behavior; it does not establish who acted or why.

## Project status

This release preserves the rules-only default and the completed Phases 1–4D, with local investigation tools for cases, saved hunts, indicators, selected external alert formats, and evidence-linked ATT&CK views. Hybrid analysis is optional and requires an explicitly fitted local benign baseline.

The proposed 1% benign false-positive target remains unmet. The saved synthetic evaluation does not show a detection gain from the anomaly model over rules-only analysis. See [evaluation results](docs/EVALUATION.md), the [Phase 4D report](docs/PHASE4D_REPORT.md), and [limitations](docs/LIMITATIONS.md) for the measured outcomes and their boundaries.

## What it includes

- CSV and JSONL ingestion for authentication, file, device, and network observations, with UTC normalization, deduplication, and retained source-row provenance.
- Evidence-gated timeline reconstruction, typed entity links, risk breakdowns, partial observations, and verified JSON/Markdown reports.
- Rules-only analysis by default; an optional Isolation Forest component using an explicitly selected and locally fitted baseline.
- Evidence sensitivity, benign look-alike comparisons, retrospective event-time replay, and a separate synthetic evaluation workflow.
- Local cases, tasks, notes, bookmarks, saved observation hunts, a bounded Sigma-shaped rule tester, and exact local indicators.
- Bounded Wazuh alert JSONL and Hayabusa minimal CSV imports as **context only**. They do not become canonical telemetry or create detector stages or risk.
- Evidence-linked ATT&CK views for two scoped techniques and a Navigator-compatible JSON export.

## Setup and run

### Requirements

- Python 3.12 (supported range: 3.12–3.13).
- Node.js 22.12 or newer and npm.
- Internet access to install dependencies, unless they are already available locally. After installation, the app and synthetic demos run without API credentials or remote runtime services.

Run commands from the repository root.

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.lock
.\.venv\Scripts\python.exe -m pip install --no-deps -e backend
npm --prefix frontend ci
npm --prefix frontend run build
.\.venv\Scripts\python.exe scripts/run_demo.py
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The API reference is at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs). Stop the server with **Ctrl+C** in its terminal.

If `py -3.12` is unavailable, install Python 3.12 and use `python -m venv .venv`. If `python` opens the Microsoft Store, use the Python launcher or the Python 3.12 installation path.

### macOS and Linux

The POSIX commands are documented here; the final release was verified on Windows, not on a separate POSIX machine.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.lock
.venv/bin/python -m pip install --no-deps -e backend
npm --prefix frontend ci
npm --prefix frontend run build
.venv/bin/python scripts/run_demo.py
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000); stop the process with **Ctrl+C**.

### Choose a local database path

By default, SQLite data and retained source records are written to `runtime/traceguard.sqlite3`. The `runtime/` directory is ignored by Git. To use another path, set `TRACEGUARD_DB` before starting the server:

```powershell
$env:TRACEGUARD_DB = 'runtime/another.sqlite3'
```

```bash
export TRACEGUARD_DB=runtime/another.sqlite3
```

`.env.example` documents this setting. The app does not automatically load a `.env` file.

## First run

The built workbench has quick actions for seeded demo datasets:

1. Load the **benign demo** and analyze in rules-only mode. It includes ordinary activity and a removable-media mount without a supported transfer claim.
2. Load the **positive demo** and analyze. Inspect the resulting suspected chain, timeline, entity links, risk, and original source rows.
3. Load the **missing-transfer demo**. It demonstrates a partial observation where required copy evidence is absent.

These are small synthetic examples, not real incident data. Each load creates another dataset; it does not reset previously retained data. For a guided walkthrough, see [demo.md](demo.md).

### Try hybrid analysis

Select **Load chronological demo**, then open **Frozen baseline & analysis mode**. Review and explicitly fit the selected synthetic benign training and calibration datasets. After a successful fit, analyze the held-out dataset in hybrid mode. The baseline is local and versioned; the detector does not use evaluation labels. The detailed workflow and boundaries are in the [full guide](full_guide.md).

## Upload compatible logs

TraceGuard's canonical adapters accept documented CSV or JSONL profiles for four source families: `auth`, `file`, `device`, and `network`. These are explicit schemas, not universal vendor adapters. Upload one source family as a new dataset, then append the remaining families to that same dataset. Keep source IDs stable for duplicate detection and specify a timezone when timestamps have no offset.

To reproduce the synthetic positive example through upload, use the files in `data/samples/positive/` in this order: `auth.jsonl`, `file.jsonl`, `device.jsonl`, and `network.jsonl`. Select the matching adapter, use environment `synthetic-office`, and append after the first file. Paste `trusted_resources.json` into the trusted resource sensitivity metadata field before labeling and analysis.

Operator-supplied context controls trusted resource labels and copy authorizations. A log field that says “sensitive,” “approved,” or “administrator” does not establish trust or authorization. See [data schema and input formats](docs/DATA_SCHEMA.md).

## How analysis works

TraceGuard normalizes source records, retains their provenance in SQLite, computes historical behavior features when available, applies temporal rules, and validates candidate evidence before saving an incident. Required joins use exact environment-scoped actor, endpoint, resource, and removable-media identifiers with strict event-time ordering. A transfer requires matching positive-byte copy telemetry and an active prior mount. IP address context never merges actors.

Rules-only analysis remains the default. Hybrid risk combines structural completeness, a calibrated anomaly percentile, link strength, observed byte impact, and an explicit authorization reduction. Percentiles and risk scores are not probabilities. A model score cannot supply missing transfer evidence, and cold-start windows may have no anomaly score. See the [model card](docs/MODEL_CARD.md) and [architecture](docs/ARCHITECTURE.md).

## Analyst tools and reports

The workbench can preserve case workflow and human notes, search retained observations with saved hunts, inspect its native predicate catalog, try a bounded Sigma-shaped subset, compare exact local indicators, and review selected external alert formats. These are separate analyst context; they do not alter native incident evidence, risk, or historical metrics.

Incident JSON and Markdown reports are generated from retained run snapshots and can be checked with the CLI. Private raw fields are omitted by default; `--include-raw` is an explicit export choice. Report hashes establish consistency with retained local content, not source authenticity.

Additional operator details—including case exports, source profiles, replay, evidence sensitivity, persistence, and backup—are in [docs/FINAL_RELEASE_GUIDE.md](docs/FINAL_RELEASE_GUIDE.md) and [full_guide.md](full_guide.md).

## Development and verification commands

For live frontend development, start these from separate terminals after installation:

```powershell
.\.venv\Scripts\python.exe -m uvicorn traceguard.main:app --host 127.0.0.1 --port 8000 --reload
npm --prefix frontend run dev
```

On macOS/Linux, substitute `.venv/bin/python` for the Windows Python path. The Vite development server uses the configured `/api` proxy.

The repository's verification commands are:

```powershell
.\.venv\Scripts\python.exe -m pytest backend/tests -q
npm --prefix frontend test
npm --prefix frontend run build
npm --prefix frontend exec -- playwright install chromium
npm --prefix frontend run test:browser
```

For a new deterministic dataset, use `scripts/generate_demo.py`. To keep benchmark output separate from other local evidence, use a fresh database and output directory:

```powershell
.\.venv\Scripts\python.exe scripts/benchmark.py --seed 41 --users 30 --events 20000 --db runtime/phase2-benchmark.sqlite3 --output runtime/phase2-benchmark
```

Historical release results and exact environment details are recorded in [docs/RELEASE_STATUS.md](docs/RELEASE_STATUS.md); those results are not a fresh test run for a later checkout.

## Docker

A Dockerfile is included, but container execution was not verified for this release. The native setup above is the documented quick start. See [release status](docs/RELEASE_STATUS.md) for the verification boundary.

## Data handling and scope

Uploaded logs and analyst context are retained in the local SQLite database and runtime files. Use only data you are authorized to analyze, keep the service on loopback, and protect or remove local runtime data according to your handling requirements. No endpoint agents or external inference services are required.

TraceGuard is a single-operator defensive analysis prototype. It does not prove intent, identify the human behind an account, provide universal log support, guarantee detection quality, execute response actions, or replace a production SIEM. Missing telemetry may prevent a stage from being supported; the workbench preserves partial observations instead of inventing evidence.

## Repository map

| Path | Contents |
|---|---|
| `backend/src/traceguard/` | FastAPI service, ingestion, storage, detection, reports, CLI, and analyst workflows |
| `backend/tests/` | Backend test suite |
| `frontend/src/` | React and TypeScript workbench |
| `frontend/tests/` | Frontend and browser coverage |
| `data/samples/` | Seeded synthetic canonical and context-only examples |
| `scripts/` | Demo, benchmark, release, backup, and verification helpers |
| `docs/` | Architecture, schemas, model/evaluation records, scope, and release notes |

Useful references: [five-minute demo](docs/DEMO.md), [full operator guide](full_guide.md), [final-release scope](docs/FINAL_RELEASE_GUIDE.md), [requirements](docs/REQUIREMENTS.md), [limitations](docs/LIMITATIONS.md), and [third-party sources and licenses](docs/THIRD_PARTY.md).

## Sources, assistance, and license

Bundled sample logs are synthetic and generated for this project. No real personal logs or pretrained models are included. Third-party references, attribution, dependencies, and material used are documented in [docs/THIRD_PARTY.md](docs/THIRD_PARTY.md). Codex assisted with implementation and documentation; the project team is responsible for reviewing the source and release contents.

Original TraceGuard materials are released under the [MIT License](LICENSE). Dependency and referenced-material terms remain governed by their respective licenses and attribution requirements.
