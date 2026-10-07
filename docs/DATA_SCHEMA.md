# Synthetic adapter contract v1

Accept UTF-8 CSV (header required) or JSONL (one JSON object per nonblank line). Each file has one source ID/family and one operator-selected environment. CSV empty cells become null; JSON fields may be omitted/null when optional. Unknown fields remain in raw evidence and never confer trust. Timestamp/action and all identifiers must be strings. Byte counts must be nonnegative integers. IPs must be parseable addresses.

Byte counts are bounded at 2^63−1 and reject boolean values, preventing numeric overflow in feature transforms. Missing byte counts remain null; they are not fabricated.

| Family | Supported actions | Required fields beyond timestamp/action |
|---|---|---|
| auth | login_success, login_failure | user_id, device_id, app_id |
| auth | logout | user_id, device_id |
| file | file_read, file_write | user_id, device_id, resource_id |
| file | file_copy_to_usb | user_id, device_id, resource_id, removable_device_id, destination_type=`removable_media`, bytes_written |
| device | usb_mount, usb_unmount | user_id, device_id, removable_device_id |
| network | network_connect | user_id, device_id, dst_ip |

Unknown actions may be browsed but do not support a stage. Known actions assigned to the wrong family are rejected. File adapter observations describe local files in this synthetic format; no remote/cloud collection inference is supported. A file write or mount alone does not prove copying. Copy bytes must be positive to support a transfer claim. Outcome, IP, file path/hash and session/app context remain nullable when unavailable. No geolocation is fabricated or used in scoring.

In this synthetic contract these actions describe completed observations. An optional `outcome` of `success` supports that meaning; any other explicit outcome (including `failure` or `denied`) is retained but excluded from completed-stage predicates and history. Missing outcome relies on the literal completed action name, not an invented outcome field. Vendor formats require a dedicated future mapping rather than guessed outcome semantics.

```json
{"timestamp":"2026-01-07T09:28:00Z","action":"file_copy_to_usb","user_id":"u17","device_id":"d6","resource_id":"resource-468","removable_device_id":"media-8","destination_type":"removable_media","bytes_written":125000}
```

`schemas.py:Event` defines the full canonical fields in the prompt, with `schema_version=1`. `event_time_utc` and `ingested_at_utc` are separate. Original timestamp, explicit timezone assumption, warnings, dataset/environment/source, record number, original-file SHA-256, deterministic JSON-record SHA-256 and primary raw reference are retained. Additional duplicate references are returned alongside the event. A raw-record hash uses UTF-8 JSON with sorted keys and compact separators; it is not a hash of the original textual line. The file hash covers the original uploaded bytes.

CSV row references use the physical ending line number reported by the CSV reader (normally header=1, first data row=2); JSONL references use original line numbers including blank lines. Multiline CSV rows retain the complete parsed record and original file. Parse/required-field failures are quarantined with source reference and representative errors (up to 20 in the quality response). Empty inputs are explicitly accepted as empty datasets. Whole-file encoding/type/limit failures reject the import.

IDs are `URI-encode(environment):type:URI-encode(raw identifier)`, e.g. `synthetic-office:user:u17`. `endpoint`, `app`, `file`, and `removable_device` are separate types. Explicit time-valid account aliases are supported in Phase 2; device handoffs and fuzzy aliases are not. `source_event_id` is an optional vendor ID; otherwise event identity derives from normalized semantic fields within dataset/source. Source IDs must be stable across reimports. Original references survive duplicates; bytes/counts do not inflate. Different timestamps do not collapse.

## Trusted resource context

Load separately through the UI JSON field or `PUT /api/datasets/{id}/resources`. Entries are upserted by canonical resource ID and snapshotted on each analysis. This is operator configuration, not an upload-derived declaration. Phase 1 supports sensitivity, not authorization.

```json
[{"resource_id":"synthetic-office:file:resource-468","sensitive":true,"provenance":"Manually reviewed asset catalog","effective_from":"2026-01-01T00:00:00Z","effective_until":null}]
```

Effective intervals are `[from, until)` and require explicit timezone offsets. Labels outside their time/resource scope do not establish sensitivity. Every asserted collection stage carries the context provenance. API docs expose typed request/response fields at `/docs`.

## Limits

Only CSV/JSONL, 5 MiB/file, 64 KiB/record, 10,000 records/file, 50,000 unique events/dataset, 1,000 context labels/aliases. Events API pages default to 50 and cap at 200 with a nonnegative offset cursor. Raw text is rendered through React text nodes, not HTML. Uploaded names are never opened as paths; archives are rejected. Uploading does not train a baseline or implicitly analyze.

## Phase 2 account resolution

`PUT /api/environments/{environment}/aliases` accepts a list with `alias_user_id`, `canonical_user_id`, nonempty `provenance`, offset-bearing `effective_from` and optional `effective_until`. Both IDs must belong to this environment's `user` namespace. Intervals are `[from,until)`. Entries are additive, immutable context records; overlapping different targets and transitive alias chains are flagged and excluded from strict resolution. Expired aliases do not merge accounts. Raw canonical records remain unchanged; each analysis snapshots aliases, and the incident records each applied alias and source event. Training identity interpretation is frozen in the baseline artifact. IPs and display-name similarity never resolve identities.

```json
[{"alias_user_id":"synthetic-office:user:local-account","canonical_user_id":"synthetic-office:user:u17","provenance":"Reviewed directory account binding","effective_from":"2026-01-01T00:00:00Z","effective_until":null}]
```

## Phase 2 run additions

`POST /api/baselines/train`: explicit training/calibration dataset IDs, seed and benign-provenance declaration. No artifact-upload/deserialization endpoint exists. `POST /api/analyses`: mode (`rules-only` default or `hybrid`), optional `baseline_id`, optional offset-bearing cutoff. Hybrid requires a compatible frozen baseline and disjoint later input; otherwise it returns an actionable error. A baseline may also be used for frozen-history rules-only comparisons.

Hybrid run metadata stores feature/estimator versions, frozen history IDs, calibration distribution, config/alias/resource snapshots, actual scored windows, provisional/cold-start states and graph summary. `GET /api/incidents/{id}/graph` exposes typed node/edge provenance and truncation; graph connectivity alone is not a stage predicate. `POST /api/evaluations` generates a separate explicitly labeled synthetic benchmark; it does not manufacture labels or accuracy for arbitrary uploads.

## Phase 3 operator authorization and reporting

`GET/PUT /api/datasets/{id}/authorizations` uses the existing operator context boundary. PUT replaces the current list (max 1,000 unique IDs), preserving historical snapshots. Example:

```json
[{"authorization_id":"export-ticket-17","user_id":"synthetic-office:user:u17","device_id":"synthetic-office:endpoint:d4","resource_id":"synthetic-office:file:resource-468","action":"file_copy_to_usb","provenance":"Operator-reviewed ticket; source not independently verified","effective_from":"2026-01-07T09:00:00Z","effective_until":"2026-01-07T10:00:00Z"}]
```

Exact namespace/actor/endpoint/resource/action and a bounded offset-bearing interval are required. No administrator/IP wildcard or log self-approval. Hybrid-v2 subtracts 20 once if all predicates match; rules-only score unchanged. Sensitivity labels remain separate and time-scoped. Alias interpretation is available in baseline-selected analyses; default prior-day rules-only retains exact original account identity.

`GET /api/datasets/{id}/analyses` returns latest 200 runs. Existing incident-list route is preserved; `GET /api/analyses/{run}/candidates` adds search (account/endpoint/ID/summary/reason), decision filter, offset and limit (default20/max100), total and next_cursor. No candidate is dropped to improve alert counts.

`GET /api/incidents/{id}/source/{event}` restricts evidence to that retained incident's selected/context/history references. Graph edges share those event IDs. `GET /api/incidents/{id}/report?format=json|markdown&include_raw=false` downloads report-v1 after fresh validation. Privacy omissions are listed; originals remain in SQLite. New runs freeze evidence source refs, while legacy runs disclose unavailable snapshots. Reports carry incident/run/cutoff/fingerprint/config, relevant normalized records/source hashes, stage predicates/history, risk/threshold/calibration, version metadata, operator context checks and unapproved human-review suggestions. Markdown's payload and readable surrounding claims are both checked by CLI `verify-report`.

## Phase 4A schema / API / CLI

New ordinary analyses have `branch_kind=ordinary` and `view_snapshot` version `analysis-view-v1`, containing policy implementation/library identity, frozen dataset/quality, and all inference/history source-reference lists. Existing run fields fix membership, cutoff, context, config and baseline. Legacy rows are preserved without backfilling. Children add `branch_kind=evidence_sensitivity`, `parent_run_id` and `comparison_id`, new run/incident IDs and effective membership/fingerprint. SQLite `sensitivities` stores comparison ID, parent/child foreign keys and immutable JSON. Child and comparison insert in one transaction; no UPDATE/delete API exists.

- `POST /api/analyses/{parent}/sensitivity`: `{ "excluded_event_ids": ["CANONICAL_ID"], "analyst_note": "optional" }`. Empty list is a no-op. Max100 IDs (1–200 chars)/500-char note, max50k parent observations. Extra request fields rejected; frozen inference membership only. Ordinary compatible parents only, no nested context/cutoff changes. 201 returns persisted comparison; malformed/incompatible/out-of-parent requests give 422, missing parent gives 404.
- `GET /api/sensitivities/{id}` restores comparison; `GET /api/sensitivities/{id}/report` revalidates and downloads JSON.
- `POST /api/sensitivity-verifications`: submitted comparison JSON -> `{valid, errors, checked_at_utc}`. CLI `verify-report FILE` dispatches this subtype, returning exit0/1 for valid/invalid. Existing incident exports remain unchanged.

`traceguard-sensitivity-v1` carries manifest parent/child/dataset IDs, original/effective observation IDs/fingerprints, sorted deduplicated exclusions, fixed cutoff/baseline and artifact/policy/context/source identities; actual before/after candidates/differences; empty-result state, note, creation UTC, validation and measured inference/validation duration. No child candidate has no invented risk value. Privacy-minimal export omits original raw records/private source text; full reference snapshots remain in local runs. Verification checks retained lineage, original source predicates/hashes and fixed artifacts, reruns both views, and checks membership/windows/stages/risk/evidence/graphs/differences. Hashes are consistency checks, not signatures.
# Phase 4B retained comparison API

`POST /api/lookalikes` accepts bounded `left_run_id`, `right_run_id`, `kind` (`context-only` or `scenario`), up to20 `declared_changed_inputs` from the documented frozen run fields and optional500-character `analyst_note`; extra fields are rejected. It never accepts browser risk deltas, truth or conclusions. Incompatible/legacy runs produce422 ordinary-reanalysis guidance; incompatible controlled pairs are rejected, never silently relabeled.

`GET /api/lookalikes` pages saved references; `GET /api/lookalikes/{id}?cursor=0&limit=20` returns run summaries, frozen identity hashes, actual/declared input differences, validated compatibility, bounded correspondence and separate optional evaluator annotation. Limits1–100 and nonnegative cursor. Original `/api/analyses/{id}/candidates` retains all decisions with its existing pagination. `GET /api/analyses/{id}/source/{event_id}` requires frozen inference/history membership and filters to that run's frozen source-reference list. Missing legacy snapshots fail explicitly. First20 observation/history/model samples are labeled, with complete retained-run navigation.

`POST /api/lookalike-labs` accepts an explicit `baseline_id` and bounded seed (default17), loads isolated synthetic datasets and11 saved pairs, and returns manifest version/seed/references plus invalid declaration validation outcomes. No fitting or calibration. Truth is kept separately in `lookalike_annotations`, versioned/provenanced after ordinary predictions. Comparison `lookalike-comparison-v1` stores both stable run IDs, per-field observation/source/context/artifact/config identities, kind, declared/actual changes, compatibility, episode correspondence, case version and creation metadata; raw files stay in existing evidence storage. No dedicated 4B download/report subtype exists at this checkpoint.



## Phase 4D evaluation CLI artifacts

`phase4d_evaluate.py --profile smoke|full --output NEW_DIRECTORY` exclusively creates the output and a database per seed; existing benchmark commands/API and production schemas stay unchanged. `protocol.json`, readable protocol and `freeze.json` precede predictions; selected-artifact records freeze calibration/model thresholds. Each seed saves `ingestion.json` (requested background, generated, accepted/rejected/quarantined/duplicates/files), isolated `truth.json` (supported attack/benign/malicious insufficient cases and evidence refs), calibration metadata/candidates/score distribution, production `runs.json`/`predictions.json`, actual `windows.json`, independent `validation.json`, `case-outcomes.json`, `sensitivity.json` and `result.json`. Aggregate `evaluation.json`, `REPORT.md` and `execution.json` retain counts/protocol hash/costs/exact argv/status. Runtime DBs hold originals and immutable runs.

Production matcher output gains matching_decisions, unmatched_predictions and unmatched_truth. Expanded metrics use effective alias-resolved event identities and all malicious observed refs for one common active-unit denominator. Anomaly-only output unit is window_alarm, with null chain metrics. Evaluation-only neutralized-diagnostic is a copied output, never an Incident.mode/API/ordinary saved run. Calibration audit rows retain structural prethreshold decisions; actual emitted counts and fresh-verification applied_hybrid_decision apply the fixed hybrid risk/gates. `phase4d_verify.py DIRECTORY --output NEW_JSON` reopens saved DBs and recomputes counts; `phase4d_report.py DIRECTORY --output NEW_MARKDOWN` builds a privacy-minimal readable report. No evaluator sidecars enter inference.

## Phase 4C replay API and persistence

- `GET /api/analyses/{ordinary_parent}/replay`: validated retrospective overview, exact UTC `start`/`end`, sorted distinct event/window-closure `stops`, retained `{id,cutoff}` references and maximum 200 frames.
- `POST` on the same route: only a timezone-bearing `cutoff` string (1-100 characters). Extra mode/baseline/context/policy/exclusion fields are forbidden. Missing/incompatible/nested/overlapping history fails actionably; no fallback mode or refitting. UTC eligibility is inclusive; strict detector ordering is unchanged.
- `GET /api/replay-frames/{frame_run_id}`: fresh validation plus persisted manifest, creation time/duration, validation scope, empty-result flag and actual analysis. Current replay implementation hash must match; historical replay implementations are not reconstructed.
- `GET /api/analyses/{run}/observations?cursor=0&limit=50`: frozen inference membership only, default50/max200. The existing candidate pages retain all alert/review/partial outcomes. Existing analysis and incident source routes reject observations outside the frame/incident and filter frozen references. Historical citations remain fixed baseline material, distinct from current observations.

SQLite `replay_frames` links parent ID and UTC cutoff to frame/run ID and retained JSON, with a unique parent/cutoff constraint. Creation inserts analysis, every candidate and frame in one transaction. `branch_kind=retrospective_replay` and `parent_run_id` visibly distinguish experiments from ordinary runs. Manifest `retrospective-event-time-v1` records parent/effective memberships and fingerprints, normalized requested/effective cutoff (timezone and microseconds preserved), mode/baseline, artifact, policy, context, replay implementation and effective source-reference identities. Equivalent offset spellings normalize to the same UTC instant; reuse revalidates all identities and recomputes claims. Storage is bounded without deletion.

Report-v1 adds `replay_manifest` only for replay candidates; ordinary/4A/4B report formats stay unchanged. JSON and Markdown contain genuine frame evidence/cutoff/decisions and are freshly verified. Empty frames expose persisted manifests/results without invented incident/risk or a dedicated report subtype. `verify-report` rejects altered cutoff, lineage, evidence or prose via fresh report/frame validation. Hashes establish retained consistency, not source authenticity.

Source responses already identify their retained `analysis_run_id`; the workbench labels displayed-run observations, frozen baseline history, separate comparison-run sources and ordinary dataset inspection distinctly. Dataset preview keeps its existing independent source route; replay preview uses only the retained frame source route, including when another candidate is selected.

## Final-release local formats

The release adds separate local investigation, hunt, intelligence and external-artifact tables. They do not extend the canonical event schemas above.

- Case notes, tasks, dispositions, tags and external links are analyst-authored metadata with immutable case revisions/audit. A native bookmark must point to a verified selected run/frame source. Case exports preserve report and source verification; external raw rows are excluded by default.
- Saved observation hunts use bounded structured filters over retained source observations. Sigma-shaped rules use `product=traceguard`, `service=canonical_observation`, one `selection`, and exact named `condition: selection`; the safe parser limits accepted fields/modifiers and rejects general Sigma features. See [FINAL_RELEASE_GUIDE.md](FINAL_RELEASE_GUIDE.md).
- Local intelligence imports use CSV (`type,value,source,source_reference,description`, with optional provenance/confidence/validity columns) or JSON indicator objects. Exact types are IPv4/IPv6, domain, and SHA-256. Matching only reads canonical `src_ip`, `dst_ip`, `domain`, and `file_hash` values, remains run/frame scoped, and is persisted separately from native results.
- External profile `wazuh-alerts-jsonl-v1` accepts Wazuh selected-alert JSONL with nested rule/agent fields. Profile `hayabusa-minimal-csv-v1` accepts exactly `Timestamp,Computer,Channel,EventID,Level,RecordID,RuleTitle,Details`. Both retain source bytes/rows separately; neither becomes canonical telemetry. Synthetic examples are in `data/samples/external/`.
- ATT&CK results are derived from verified run/frame stages; only T1005 and T1052.001 have explicit mapping predicates. Navigator output does not include private paths/raw log text. These mappings do not add evidence to the canonical schemas.
