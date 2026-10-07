# Final release acceptance checklist

The implementation and acceptance rows below were completed against the user-provided final-release scope. Exact outputs and the initial 4D SQLite schema-side-effect disclosure are in `docs/RELEASE_STATUS.md` and `runtime/release-final-20261007-rerun1/`.

## Existing phases and evidence boundary

- [x] Preserve Phases 1–3 and 4A–4D, saved evaluation outcomes, detector/model/threshold and persisted replay-lineage guard. The first gate applied empty additive feature tables to three saved 4D SQLite files; hashes, empty table counts, unchanged evaluation files, and the limitation are documented. The passing gate verified a copy and confirmed current source bytes stayed unchanged.
- [x] No detector/model/threshold/risk-weight/evidence-predicate/identity/training-data change for these additions.
- [x] Human notes/tasks/bookmarks, hunt hits, IOC matches, external alerts and upstream ATT&CK labels remain outside native stages, risk and historical metrics.
- [x] All added run/frame reads and exports call the existing persisted replay-lineage guard.

## Bundle A — cases and annotations

- [x] Bounded searchable/paginated cases, create-from-incident, workflow and separate human disposition.
- [x] Revision-checked edits, append-only audit history, tasks, notes, tags and verified evidence bookmarks.
- [x] In-scope run/frame/source validation; replay bookmarks cannot cite future parent events.
- [x] JSON/Markdown frozen case exports, detector report subverification, case-envelope verification and restart persistence.
- [x] Closing requires rationale; human disposition does not change detector output or evaluation results.

## Bundle B — hunts and rules

- [x] Bounded retained-run filters, literal matching, pagination, frozen execution identity and restart persistence.
- [x] Read-only native predicate/policy catalog.
- [x] Six original Sigma-shaped rules; safe-YAML limits; positive, negative, alias, duplicate-key and unsupported-syntax tests.
- [x] Hunt/Sigma hits are separate from native incidents/stages and use replay-scoped observations.

## Bundle C — local intelligence

- [x] Versioned local CSV/JSON collections, typed exact IPv4/IPv6/domain/SHA-256 matching and source provenance.
- [x] Validity/unknown dates, duplicate/conflicting assertions, IDNA normalization, replay scope and immutable saved match output.
- [x] No network feed, automatic attribution, risk/stage changes or model fitting.

## Bundle D — external findings

- [x] Wazuh `alerts.json` JSONL fields checked against upstream documentation and a synthetic representative fixture.
- [x] Exact Hayabusa `minimal` CSV header/profile checked against its upstream output guide and synthetic fixture.
- [x] Raw upload bytes/rows and source provenance retained; size/row limits and accepted/rejected/duplicate/context-only counts exposed.
- [x] Search/case linking is separate from canonical events, native incidents and transfer evidence.
- [x] Unsupported `.evtx`, non-minimal CSV, malformed input/time behavior, source hashes and formula-safe export are covered.

## Bundle E — ATT&CK and Navigator

- [x] Selected-view T1005/T1052.001 mappings require their specific verified native evidence; mount-only, external tags and pre-copy frames do not map transfer.
- [x] Versioned mapping metadata and exact evidence/source links are included separately from detector facts.
- [x] Navigator layer export tests its documented v4.3 structure, score semantics and private-data omissions. Navigator application/UI compatibility was not run.
- [x] External technique tags remain on their external source findings only.

## Workbench, safety and reporting

- [x] Existing timeline/graph/evidence, replay, sensitivity and benign-comparison flows remain usable; full 16-flow browser regression passed.
- [x] Saved 4D metrics/`budget_not_met` and the unmet 1% FP target remain visible; no metrics are synthesized for unlabeled uploads or case labels.
- [x] False-positive review cites retained outcomes/policy without editing saved metric files.
- [x] Same-origin write guard, typed/size bounds, safe filenames, parameterized SQL, safe YAML and escaped output coverage passed.
- [x] Additive versioned SQLite tables, restart behavior, and explicit validated backup/restore procedure are documented/tested.

## Release evidence and package

- [x] Final backend (175 passed), frontend (6 passed), production build and full browser (16 passed) suites passed after the last functional change.
- [x] Fresh 4A/4B/4C regressions and isolated saved 4D verification passed. The final gate confirms the saved 4D source files did not change during that rerun.
- [x] Fresh source install excluded `.venv`, `node_modules`, `runtime`, local DB and cache; offline guard, restart persistence, exports and tamper rejection passed.
- [x] Real case JSON/Markdown, external CSV, and Navigator layer exports were exercised; tampered case payload rejection was confirmed.
- [x] `scripts/release_gate.py` captures exact argv, exit status, stdout/stderr and duration. `runtime/release-final-20261007-rerun1/SUMMARY.md` is the passing gate summary.
- [x] Workload timings and adapter counts are recorded. Process RSS is explicitly **unmeasured**.
- [x] `submission/traceguard-final-release` is allowlisted and scanned; it excludes credentials, runtime DBs/raw user logs, caches, third-party binaries and private machine paths.
- [x] README, adapter matrix, model/evaluation limitations, attribution, demo/runbook, feature guide and release status are updated.
- [x] No deployment, remediation, endpoint collection, upstream platform install, Docker execution or optional Phase 5 work occurred.
- [x] After the implementation gate, the user-authorized MIT release was published as the public `hacknex-internal-mark-IV` repository; see `docs/RELEASE_STATUS.md`.

## Owner follow-up

- [x] Add the root MIT license selected by the project owner. The owner/team remains responsible for confirming rights to distribute all contributed material and for honoring third-party terms in `docs/THIRD_PARTY.md`.
