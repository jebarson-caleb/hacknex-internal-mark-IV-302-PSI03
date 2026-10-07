# TraceGuard full guide

**Status snapshot:** this guide describes the local final-release workbench recorded on 2026-10-07. The repository's current documentation and implementation are the source of truth for later changes.

## 1. What TraceGuard does

TraceGuard is a local, evidence-backed workbench for reconstructing one bounded type of suspected cyber incident from retained security observations. Its primary chain is:

1. A successful login is unusual for an established account.
2. The same actor and endpoint access sensitive resources outside their prior history.
3. Matching files are explicitly copied to a mounted removable device.

TraceGuard presents supported observations as a time-ordered incident with evidence, entity links, risk components, uncertainty, and human-review suggestions. It is defensive and read-only: it does not deploy endpoint agents, execute attacks, disable accounts, or carry out response actions.

An incident is a claim about observed records. It is not proof of theft, compromise, a person's identity, or intent. The interface uses suspected-chain language for that reason.

## 2. Local setup and operation

### Requirements

- Python 3.12
- Node.js 22.12 or newer and npm
- Package access during installation unless dependencies are already available

Once installed, the workbench, seeded demos, and local workflows run without credentials or remote runtime services. The server binds to loopback by default.

### Windows PowerShell

From the repository root:

~~~powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.lock
.\.venv\Scripts\python.exe -m pip install --no-deps -e backend
npm --prefix frontend ci
npm --prefix frontend run build
.\.venv\Scripts\python.exe scripts/run_demo.py
~~~

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). If **python** resolves to the Microsoft Store stub, install Python 3.12 or use the bundled-runtime procedure recorded in [docs/BUILD_STATUS.md](docs/BUILD_STATUS.md).

### POSIX

Create the environment with **python3.12 -m venv .venv**, use **.venv/bin/python** in place of the Windows executable, then run the npm commands above. POSIX commands are documented but a clean POSIX installation was not independently verified for this release.

### Development mode and API

Start the backend and frontend in separate terminals:

~~~powershell
.\.venv\Scripts\python.exe -m uvicorn traceguard.main:app --host 127.0.0.1 --port 8000 --reload
npm --prefix frontend run dev
~~~

The local API documentation is at **/docs**. The default SQLite database is **runtime/traceguard.sqlite3**; set **TRACEGUARD_DB** before starting the process to choose another path. The application does not automatically load **.env**.

## 3. Main workflow

~~~mermaid
flowchart LR
    A[CSV or JSONL and trusted context] --> B[Validation and normalization]
    B --> C[Retained source rows and canonical events]
    C --> D[Frozen history and event-time features]
    D --> E[Rules, optional anomaly scoring, typed graph]
    E --> F[Evidence and risk validation]
    F --> G[Timeline, sources, reports, analyst tools]
~~~

1. Load a reproducible synthetic dataset or upload compatible source records.
2. Review ingestion quality and trusted context.
3. Choose rules-only analysis or explicitly fit/select a compatible benign baseline and choose hybrid analysis.
4. Inspect complete, partial, alert, and review outcomes with their source evidence.
5. Use reports and analyst tools to preserve findings and review context.

Every demo load creates a new dataset. Existing datasets and analyses remain available after a restart. New context affects future runs; saved runs retain their snapshots. Reanalysis creates another immutable run rather than overwriting the previous one.

## 4. Data ingestion and trust

### Supported source families

The canonical adapters accept documented CSV and JSONL shapes for authentication, file, device, and network observations. Actions include successful/failed login, logout, file read/write, removable-device mount/unmount, file copy to USB, and network connection.

These are explicit source profiles, not universal vendor adapters. The external Wazuh and Hayabusa profiles described later are stored separately and do not become canonical security events.

### What is retained

An accepted observation has a dataset/source-scoped identity, environment and source identifiers, original and normalized timestamps, action/outcome, available user/device/app/session/network/resource fields, and a reference to the raw source row. Source-file and raw-record hashes, duplicate references, and normalization warnings preserve the route from a claim back to the uploaded material.

Hashes show that retained material is consistent with a report. They do not establish that the logging system was authentic or correct.

### Time and identity rules

- Timestamps with offsets are normalized to UTC. Naive timestamps need an explicitly declared timezone; ambiguous or invalid local times are rejected or quarantined according to the adapter.
- Event time controls ordering and analysis cutoffs. Ingestion time is stored separately.
- Equal event times do not establish strict causal order without sequence evidence.
- Event and entity IDs are namespaced. Explicit, same-environment, time-valid account aliases may link identities when unambiguous.
- IP addresses, shared NAT, and VPN context never merge user identities.
- Duplicate source rows retain all source references. Legitimate repeated events are not deduplicated solely because their other fields match.

### Trusted context

Resource sensitivity labels, account aliases, and copy authorizations are operator-supplied context stored separately from log text. A log field containing words such as “sensitive”, “approved”, or “admin” does not grant trust or authorization.

A copy authorization must name the exact environment, user, endpoint, resource, action, effective interval, authorization ID, and source provenance. It applies only to future analysis snapshots; previous runs retain the context they used.

## 5. The supported incident logic

The initial correlation window is 60 minutes. A complete candidate requires more than events that happen close together.

### Authentication

The successful login must be unusual relative to at least three prior UTC days of successful logins for the same scoped actor. A new device, application, or UTC hour can support the unusual-login predicate. Without adequate history, the claim is unavailable rather than automatically suspicious.

### Sensitive collection

File access is compared with prior history for that actor. The supported collection predicate requires prior-day reads, a resource not previously read by that actor, and an effective trusted sensitivity label. Text inside the event cannot assign the label.

### Removable-media transfer

The transfer stage requires explicit **file_copy_to_usb** telemetry with positive bytes, a matching resource, the same scoped actor and endpoint, an active prior mount for the removable device, and strict event-time order. Authentication precedes collection; collection precedes copy; the mount precedes copy. The mount may occur before or after collection as long as it is active before the copy. IP-only linkage is insufficient.

If matching copy telemetry is absent, the output remains partial and explains which evidence is missing. An anomaly score, graph edge, nearby network event, or device mount cannot fill the gap.

## 6. Rules-only and hybrid analysis

### Rules-only

Rules-only is the default. It preserves the structural gates and initial risk behavior without requiring a fitted model. The historical structural score is 100 for a complete chain and 60 for a two-stage review candidate; scores are heuristics, not probabilities.

### Explicit local baseline

Hybrid analysis requires an app-created baseline fitted from explicitly selected benign data. The current model is a fixed-seed scikit-learn Isolation Forest with 200 estimators. It uses 15-minute UTC user/device windows and features such as login counts, device/app/hour novelty, resource counts and rarity, trusted sensitive reads, byte counts, and network destination counts.

Identity values are used for grouping and novelty, not as arbitrary numeric features. History is frozen from the selected training input. Calibration and test data do not refit the estimator or history. Future, overlapping, incompatible, corrupt, or environment-mismatched baselines are rejected. Cold-start users and provisional windows do not receive invented anomaly scores.

In the chronological demo, days 1–14 supply training history, days 15–21 supply benign calibration windows, and days 22–28 are held out for analysis. A model artifact records its training/calibration intervals, event membership, feature order, seed, library identity, frozen history, and context snapshot.

The model uses negative **score_samples** so larger raw values mean more unusual behavior. That score is transformed to an empirical midrank percentile using the selected benign calibration distribution. A higher percentile means greater behavioral rarity under that distribution. It is not the probability that an account is compromised. The workbench does not claim SHAP or an exact feature-level explanation for a forest score.

### Hybrid risk

The hybrid score is an inspectable heuristic:

~~~text
50 × C + 20 × A + 20 × L + 10 × I − B
~~~

- **C:** completeness of supported stages.
- **A:** calibrated anomaly percentile for eligible closed windows.
- **L:** strength of exact or explicitly authorized identity linkage.
- **I:** observed byte impact under the existing policy.
- **B:** a 20-point reduction once for an exact, effective-time copy authorization; otherwise zero.

The graph and predicate checks still gate the claim. The anomaly score cannot create a missing stage. A full chain below threshold or without an eligible closed window remains available for review. Alias strengths and all risk terms are heuristic values, not probabilities or guarantees.

## 7. Evidence graph, timeline, and reports

The typed graph records event-backed relationships among scoped users, endpoints, applications, resources, sessions, IP observations, and removable devices. A graph connection is not by itself a causal link. Each required relation is revalidated against source observations before a candidate is saved. Multiple edges generated from one event do not count as independent observations.

The incident view connects each stage to its timeline entry, supporting graph relation, predicate, and source row. Original evidence remains local. You can export a minimal JSON or readable Markdown report; private source values and unrelated rows are omitted by default. Explicit options can include private/raw fields.

**verify-report** checks report contents against the retained analysis, stage predicates, risk, context, source references, and original rows. The verifier rejects altered claims. This is consistency verification against the local database, not a digital signature or proof of the source system.

~~~powershell
.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/traceguard.sqlite3 verify-report "C:\path\to\incident.json"
~~~

Use the same database selected by the running server.

## 8. Evidence and comparison workflows

These workflows create retained branches or comparisons. Their outputs should not be mistaken for new ordinary runs.

### Evidence sensitivity (Phase 4A)

Choose canonical supporting observations in a compatible ordinary run and rerun with those observations excluded. The analyzer recomputes features, scores, graph, candidates, stages, and risk using the parent's frozen view and context. All source duplicates of an excluded canonical observation leave inference; the original parent and source rows remain unchanged. This measures evidence availability, not causality, prevention, or a safe state.

### Benign look-alikes (Phase 4B)

Compare two ordinary analyses of a curated synthetic scenario. A controlled context-only pair requires matching observations, sources, baseline/calibration, cutoff, policy, and non-authorization context. Other scenario pairs disclose their differences. The lab does not fit or recalibrate its selected baseline and does not generate an accuracy or false-positive percentage.

### Retrospective event-time replay (Phase 4C)

Select a compatible ordinary retained parent and a UTC cutoff. TraceGuard filters the parent's frozen membership through that cutoff and reruns the existing detector using the same baseline, calibration, policy, and captured context. Features, candidates, graph, risk, and decisions are recomputed; future observations are excluded and open anomaly windows remain unavailable. Frames have retained lineage and bounded reuse.

Replay is retrospective. Captured context describes the stored run; it does not reconstruct what an analyst knew at an earlier time. It is not a live feed or streaming detector.

### Expanded synthetic evaluation (Phase 4D)

This is a separate evaluation workflow. It uses frozen chronological partitions and isolated labels; labels are consulted only after predictions. It measures synthetic episode matching, stage evidence, order, benign active user-device-day false positives, and anomaly-window output. Arbitrary uploads do not receive invented accuracy metrics.

## 9. Investigation and context tools

### Cases

Local cases can link to a retained incident or begin as an unlinked review. They support workflow state, human disposition, tags, tasks, notes, verified evidence bookmarks, and links to external findings. Revisions and audit entries are retained. Closing a case requires rationale. Case records do not change detector evidence, risk, or evaluation.

The workbench is single-operator local storage. It does not provide accounts, roles, teams, notifications, service-level tracking, or an external case-management integration.

### Saved hunts and rule catalog

Saved hunts are bounded literal/structured filters over retained observations. Their executions retain the selected run/frame, hunt revision, result identity, and hash. The native rule catalog describes implemented TraceGuard predicates.

The Sigma-shaped tester supports one constrained local subset: a TraceGuard canonical-observation source, one named selection, scalar equality or limited OR lists, and **contains**, **startswith**, or **endswith** text modifiers. It rejects general Sigma conditions, correlation/timeframe constructs, aliases, arbitrary vendor fields, and other unsupported YAML. It is not a full Sigma engine and never adds hits to native analysis.

### Local indicator collections

CSV or JSON collections accept exact IPv4/IPv6, IDNA-normalized domain, and SHA-256 assertions with source, provenance, description, and optional validity dates. Matching compares these values only with canonical structured **src_ip**, **dst_ip**, **domain**, and **file_hash** fields in a selected retained run/frame.

Matches and source assertions are stored separately. They do not add risk, stages, model features, or historical evaluation results. No feed, reputation service, DNS lookup, attribution, substring search, or raw-text extraction is performed.

### External findings

Two bounded file profiles are supported:

- Wazuh **alerts.json** JSONL with the selected nested rule/agent alert shape.
- Hayabusa **minimal** CSV with its exact documented header.

Original bytes, row positions, hashes, parse status, and counts remain in separate external-artifact storage. Accepted rows are context only; they do not become canonical telemetry or affect stages and risk. There is no live connector, service query, **.evtx** support, archive import, or arbitrary CSV support.

### ATT&CK view

The current evidence-linked view supports two explicitly gated Enterprise ATT&CK mappings: T1005 (Data from Local System) and T1052.001 (Exfiltration over USB). T1005 requires a verified collection stage and file read; T1052.001 requires a complete native chain and verified matching USB copy. External labels, case tags, hunts, indicators, and mount-only events cannot create these mappings.

The optional Navigator layer is generated from the selected verified run/frame. Navigator scores count distinct supporting observations; they are not risk, probability, or confidence. Application compatibility was not separately exercised, and this is not framework-wide ATT&CK coverage.

## 10. Storage and backup

SQLite stores datasets, source rows, canonical events, context snapshots, baselines, analyses, branches, cases, hunts, rule revisions, indicator assertions, external artifacts, and reports' verification material. Keep the selected database and its SQLite journal/WAL files together while the server is running.

Make a consistent snapshot through the supplied helper, which uses SQLite's backup API and refuses to overwrite an existing destination:

~~~powershell
.\.venv\Scripts\python.exe scripts/db_snapshot.py snapshot runtime/traceguard.sqlite3 runtime/backups/traceguard.sqlite3
~~~

Restore into a new database path:

~~~powershell
.\.venv\Scripts\python.exe scripts/db_snapshot.py restore runtime/backups/traceguard.sqlite3 runtime/restore/traceguard.sqlite3
~~~

Stop the server before changing which database it uses. The helper checks SQLite integrity and foreign keys; it is not automated off-device backup, encryption, retention management, or multi-user database merging.

## 11. Synthetic evaluation and present limitations

The recorded Phase 4D full evaluation used three chronological synthetic profiles and 12 supported episodes. Both ordinary modes recovered 12/12 supported episodes. Rules-only produced 21 false-positive benign user-device-day units out of 678 (3.097%); hybrid produced 15/678 (2.212%). Seven complete benign calibration candidates per seed included five false-positive units among 228, so the 1% target was not met and threshold 80 remained a structural fallback without a population guarantee.

The six fewer hybrid false positives correspond to the scoped authorization policy reduction. They are not evidence that the Isolation Forest improved detection. The fixed-threshold A=0 diagnostic recovered 6/12 episodes and produced 9/678 benign false-positive units; it is a sensitivity diagnostic, not an optimized alternative. Anomaly-only produced 46 window alarms and does not reconstruct incidents. Synthetic, correlated scenarios do not demonstrate real-world accuracy, generalization, or unknown-attack coverage.

Other release boundaries:

- No endpoint collection, automatic remediation, deployment, public service, or multi-user access-control boundary.
- Imported events/findings are not independently authenticated.
- Arbitrary uploaded data has no ground-truth labels or computed accuracy metrics.
- POSIX clean installation and Docker engine execution were not verified.
- Process resident memory was not measured.
- Navigator application compatibility was not separately tested.
- Root project license/ownership review remains an open submission item.
- The organizer PDF was not available for independent verification; requirements rely on the supplied project prompt and its booklet summary.

The first final-release gate opened saved Phase 4D SQLite databases before an additive-schema side effect was understood. Twelve new release tables were created and empty in three files; the exact original SQLite byte streams are not preserved. Saved predictions, labels, reports, and metrics remained unchanged and were independently verified. The passing final rerun verified a copy and left all 47 source files unchanged during that rerun. The full disclosure is in [docs/RELEASE_STATUS.md](docs/RELEASE_STATUS.md).

## 12. Verification record

The final release gate recorded:

- 175 backend tests passed, with one existing Starlette/HTTPX deprecation warning.
- 6 frontend tests passed.
- Production TypeScript/Vite build passed with 28 modules.
- 16 browser flows passed.
- Fresh native install, offline runtime, restart persistence, export verification, and tamper rejection passed.
- Fresh 4A/4B/4C regressions passed; saved 4D artifacts verified on a copy.

Exact commands, output, and limitations are in [docs/BUILD_STATUS.md](docs/BUILD_STATUS.md) and [docs/RELEASE_STATUS.md](docs/RELEASE_STATUS.md). These are recorded results, not a claim that the checks were rerun while writing this guide.

## 13. Useful files

| File | What it covers |
|---|---|
| [README.md](README.md) | Setup, primary workflow, CLI, uploads, reports, and benchmark entry point |
| [prompt.md](prompt.md) | Product specification and engineering constraints |
| [docs/BUILD_STATUS.md](docs/BUILD_STATUS.md) | Current phase and exact executed commands/results |
| [docs/RELEASE_STATUS.md](docs/RELEASE_STATUS.md) | Final-release checklist, preservation disclosure, and open review items |
| [docs/FINAL_RELEASE_GUIDE.md](docs/FINAL_RELEASE_GUIDE.md) | Detailed final-release features and import boundaries |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Module and persistence design |
| [docs/DATA_SCHEMA.md](docs/DATA_SCHEMA.md) | Canonical input formats, fields, and provenance |
| [docs/MODEL_CARD.md](docs/MODEL_CARD.md) | Baseline, feature, score, and calibration semantics |
| [docs/EVALUATION.md](docs/EVALUATION.md) | Methodology, denominators, measured results, and uncertainty |
| [docs/PHASE4D_PROTOCOL.md](docs/PHASE4D_PROTOCOL.md) | Frozen expanded-evaluation protocol |
| [docs/PHASE4D_REPORT.md](docs/PHASE4D_REPORT.md) | Representative synthetic evaluation report |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | Known detector and deployment boundaries |
| [docs/THIRD_PARTY.md](docs/THIRD_PARTY.md) | References, dependency declarations, and ownership review |

## 14. Handy commands

Generate small synthetic source files:

~~~powershell
.\.venv\Scripts\python.exe scripts/generate_demo.py --seed 17 --variant positive --output runtime/demo
~~~

Create and analyze a seeded CLI dataset:

~~~powershell
.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/cli.sqlite3 demo --seed 17 --variant positive
~~~

Check a report against the same retained database:

~~~powershell
.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/cli.sqlite3 verify-report runtime/reports/incident.json
~~~

Run the recorded repository suites when an implementation change calls for verification:

~~~powershell
.\.venv\Scripts\python.exe -m pytest backend/tests -q
npm --prefix frontend test
npm --prefix frontend run build
npm --prefix frontend run test:browser
~~~

The authoritative final-release results are already recorded in the status files; the commands above are instructions to run checks, not evidence that they were rerun during documentation work.
