# TraceGuard final-release scope and operator guide

Date: 2026-10-07. This guide documents the five bounded workbench additions. It does not claim native integration with Wazuh, Hayabusa, Sigma tooling, ATT&CK Navigator, or a case-management platform. TraceGuard remains a local synthetic-evidence analysis workbench; imports and annotations are separate context.

## Feature and support matrix

| Bundle | Supported behavior | Explicit boundary |
|---|---|---|
| Cases | Local cases, workflow and human disposition, tags, tasks, notes, verified native-evidence bookmarks, external-finding links, immutable revisions/audit and verified JSON/Markdown exports | Single local operator; no identity, role, team, SLA, notification, or external case-system integration |
| Hunts and rules | Read-only catalog of TraceGuard predicates; saved literal filters over retained observations; six original local Sigma-shaped rules evaluated against guarded selected-view observations | The Sigma parser implements only the subset below; no Sigma conversion, correlation, backend engine, event normalization, alerting, or rule-pack import |
| Intelligence | Versioned local CSV/JSON collections of exact IPv4/IPv6, IDNA-normalized domains, and SHA-256 indicators; exact comparisons on four canonical structured fields; source assertions and validity-at-event-time | No feed, reputation, DNS, network request, substring/raw-text extraction, attribution, risk, stage, model, or historical-metric effect |
| External findings | Bounded Wazuh `alerts.json` JSONL selected-alert profile and Hayabusa `minimal` CSV profile; original bytes, rows, positions, hashes, parse status and counts retained; search, case link and formula-safe CSV view | No `.evtx`, arbitrary profile/CSV, archive, connector, service, live query, native event creation, stage/risk effect, or completeness claim |
| ATT&CK | Two explicitly gated evidence mappings on an ordinary retained run or guarded replay frame; per-mapping source-row hashes; current-view Navigator layer JSON | T1005 and T1052.001 only; not a framework coverage claim; Navigator application compatibility was not exercised |

All writes remain on the local SQLite database. `SameOriginWriteGuard` rejects explicit cross-site or mismatched browser origins on state-changing `/api/` requests; origin-less command-line clients remain supported. `BodyLimit` caps request bodies, and each importer applies its stricter profile limit. The demo server binds loopback by default.

The main local interfaces are `GET /api/cases`, `GET /api/hunts`, `GET /api/rules/catalog`, `GET /api/sigma/rules`, `GET /api/intelligence/collections`, `POST /api/external/preview`, and `POST /api/external/import`. Case/hunt/Sigma/intelligence writes and execution have corresponding `/api/cases/...`, `/api/hunts/...`, `/api/sigma/...`, and `/api/intelligence/...` routes. `GET /api/analyses/{run_id}/attack` returns the evidence-linked view, and `GET /api/analyses/{run_id}/navigator-layer` exports the current verified selection. Route details are also visible through the local `/docs` API page.

## Case and hunt behavior

Cases start from a retained incident or as an unlinked review. Workflow and analyst disposition are separate fields. Closing requires rationale. Tasks, notes, tags and external links are human context. Bookmarks must resolve to a source observation in the selected incident and run/frame; a replay bookmark cannot point past its cutoff. Revisions and audit entries are append-only. The export verifier recomputes retained report claims, case envelope, source references, and linked external provenance; export omits raw external rows by default. These records cannot change an analysis.

Saved hunts accept a small set of allowlisted structured filters and safe literal matching. Execution stores the selected run/frame, saved revision, result identity and result hash. The native catalog displays implemented predicates rather than translating them into another vendor's syntax. All read/execute paths use current persisted replay-lineage validation.

The Sigma-shaped local tester accepts one YAML mapping with required `title`, UUID `id`, `status`, `description`, `author`, nonempty `references`, exact TraceGuard `logsource` (`product: traceguard`, `service: canonical_observation`), `level`, and a `detection` containing exactly one named `selection` and `condition: selection`. It supports 1–40 allowlisted canonical fields, scalar equality or 1–50 OR-list values, and text modifiers `contains`, `startswith`, and `endswith`. Limits: 64 KiB UTF-8, 20 YAML nesting levels, 2,000 YAML nodes, no aliases, merge keys, duplicate keys, wildcards, escaping, arbitrary conditions, correlations, timeframes, scopes, or backend-specific fields. Original local rule IDs and revisions are retained. Hunts are read-only queries; their hits never enter native analysis.

## Local indicator collection format

CSV headers: `type,value,source,source_reference,description`; optional columns are `notes,source_confidence,effective_from_utc,effective_until_utc,enabled`. JSON is a bounded list of typed indicator objects using those names. Maximum upload: 1 MiB and 1,000 indicators. Types are `ip` (IPv4 or IPv6), `domain` (IDNA UTS #46 canonicalization), and `sha256` (64 hex digits). Values compare for equality only against `src_ip`, `dst_ip`, `domain`, or `file_hash` on retained structured observations. Unknown validity dates remain unknown; interval comparisons are in UTC. Conflicting sources are grouped without selecting a winning assertion. Duplicate indicators remain source-attributed assertions. Imported raw bytes are not persisted; the collection records a SHA-256 of the upload and normalized assertions. Original run/source observations remain in the evidence store.

## External import profiles

### Wazuh `alerts.json` JSONL

One UTF-8 JSON object per nonblank line. Required fields are `id`, nested `rule.id`, integer `rule.level` from 0 through 16, `rule.description`, and nested `agent` object. Optional `timestamp`, `rule.mitre.id`, `agent.name`, and whitelisted `data` indicators (`srcip`/`src_ip`, `dstip`/`dst_ip`, `domain`/`hostname`, `sha256`/`file_hash`) are retained in the parsed context. Missing or timezone-naive timestamps are accepted as explicitly unknown; malformed timestamps reject the row. Duplicate source alerts remain represented and counted. Upstream MITRE labels are labels from the external source only.

### Hayabusa `minimal` timeline CSV

The exact header is `Timestamp,Computer,Channel,EventID,Level,RecordID,RuleTitle,Details`. Timestamp is retained as supplied; timezone-naive values are accepted with unknown timezone status. Details are not searched for indicators or stages. Other Hayabusa output profiles, renamed/extra columns, `.evtx`, and arbitrary CSV are unsupported.

Both external profiles have 5 MiB file, 10,000-row, and 64 KiB-per-row caps. The adapter preserves original bytes and raw row strings in local SQLite, assigns stable source positions and hashes, and reports accepted/rejected/duplicate/context-only counts. Accepted rows remain external context-only even when source tags name ATT&CK techniques. CSV exports escape formula-leading values; the original artifact remains unchanged. Reviewed synthetic schema fixtures are under `data/samples/external/`. Upstream references and retrieval/attribution notes are in `docs/THIRD_PARTY.md` and `docs/THIRD_PARTY_SOURCES.json`.

### ATT&CK and Navigator

Mapping rules are versioned in code and use MITRE ATT&CK Enterprise technique references. T1005 is mapped only from a verified supported native collection stage with a verified `file_read`; T1052.001 requires a complete native chain and the verified matching `file_copy_to_usb` to `removable_media`. A mount alone, external tags, case labels, hunts, intelligence, or a pre-copy replay frame cannot create transfer mapping. Each result is linked to run/frame, incident, stage, source position and source hashes. Navigator layer version fields describe the output schema; no ATT&CK release version is asserted. Scores are capped counts of supporting observations, never risk, likelihood, or confidence. Export omits user IDs, paths and raw rows by default.

## Persistence, backup and restore

Schema additions are additive SQLite tables/migrations. Reopening the same database restores cases, revisions, hunts, Sigma revisions/executions, indicator collections/matches, external artifacts/findings, and analyses. Keep the database and adjacent SQLite journal/WAL files together while the app is running; take snapshots through SQLite's backup API rather than copying a live database file.

Create a consistent, integrity-checked snapshot to a new path:

```powershell
.\.venv\Scripts\python.exe scripts/db_snapshot.py snapshot runtime/traceguard.sqlite3 runtime/backups/traceguard-20261007.sqlite3
```

Restore a validated snapshot to a new path (existing destinations are refused):

```powershell
.\.venv\Scripts\python.exe scripts/db_snapshot.py restore runtime/backups/traceguard-20261007.sqlite3 runtime/restore/traceguard.sqlite3
```

Stop the demo process before switching the application to a recovered database. Preserve the current database separately; verify the restored database and its retained reports before using it. The helper checks SQLite integrity and foreign keys on both source and destination. It does not make an off-device copy, encrypt backups, rotate retention, merge concurrent databases, or provide disaster recovery automation.

## Native install and offline operation

On Windows PowerShell, from the source directory:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.lock
npm --prefix frontend ci
npm --prefix frontend run build
.\.venv\Scripts\python.exe -m pip install --no-deps -e backend
.\.venv\Scripts\python.exe scripts/run_demo.py
```

The lock and npm lock install dependencies during setup. After setup, the application flow, demo data, saved hunts, local imports, evidence views, reports, ATT&CK view and exports require no upstream service or network request. Local install may need package access unless dependencies are already cached. POSIX command equivalents appear in `README.md`; POSIX installation was not independently verified for this release. Docker configuration is not a final-release execution target and no Docker engine integration is claimed.

## Preserved evaluation and limitations

The original detector, model and model bytes, risk weights, threshold, policies, training/calibration history, and Phase 4D report/artifacts are frozen. The 1% benign active user-device-day target remains unmet: saved Phase 4D full results show rules-only 21/678 (3.097%) and hybrid 15/678 (2.212%) units, with threshold 80 and calibration status `budget_not_met`. The hybrid difference includes the existing authorization policy effect and is not a measured forest gain. See `docs/FALSE_POSITIVE_REVIEW.md` and `docs/PHASE4D_REPORT.md`; the review does not alter the saved evaluation.

The tool is single-operator and local. Synthetic schemas and test fixtures do not establish real-world source compatibility or efficacy. Imported evidence is not independently authenticated. No production generalization, automated response, endpoint collection, platform integration, access-control boundary, legal review, or false-positive target attainment is claimed. See `docs/RELEASE_STATUS.md` for exact verification results and unresolved items.
