# Requirements checkpoint

Authority: user request to implement **Phase 1 only**, plus `prompt.md` §16. The full MVP in the prompt is future scope. The organizer booklet is referenced through the supplied specification; its PDF is not available for independent review here.

| Phase 1 requirement | Implementation |
|---|---|
| Inspect and preserve existing work | Initial checkout contained only `.git`, no tracked files or commits. Downloads prompt copied to root unchanged. |
| Canonical schema and four source adapters | `schemas.py`, `ingest.py`: UTF-8 synthetic CSV/JSONL; offset/explicit-zone normalization, action-specific validation, namespacing, quarantine. |
| Provenance and duplicate storage | `storage.py`: original file BLOBs, row references, raw JSON/hash, canonical events, every duplicate reference. Conflicting vendor IDs rejected. |
| Seeded small positive and benign data | `demo.py`, `scripts/generate_demo.py`, `data/samples/`: 79 positive / 77 benign records at seed 17. |
| Simple historical comparisons | Prior UTC-day login and file counts, minimum history gate, novel device/app/hour and resource checks. |
| Known-chain rules | Strict auth-before-read-before-copy; prior active mount can precede collection; exact actor/endpoint/resource/media; 60-minute window. |
| Stage evidence validation | Re-resolve events, repeat predicates/comparisons/timing, verify retained hashes and original source row. All historical evidence is retained. |
| Minimal API and basic UI | Upload/append, demos, ingestion quality, real analysis, incidents/partials, UTC timeline, raw evidence, event preview. |
| Required tests and run commands | Backend, frontend and actual browser checks; results in BUILD_STATUS.md. |

Missing transfer or mount → a review item with missing evidence, never a complete attack alert. Mount-only → no chain. No ML scores are fabricated. Later-phase requirements are listed in SCOPE.md.

## Phase 2 checkpoint

The current user request authorizes the next phase in prompt.md §16, not later optional recommendations.

| Requirement | Working implementation |
|---|---|
| Explicit baseline fitting | baseline.py: benign provenance, disjoint chronological windows, local fitted artifacts and metadata. |
| Real features and Isolation Forest | features.py: frozen-history 15-minute observations, transforms and cold/provisional gates; 200 fitted trees actually score windows. |
| Calibration | Separate benign score distribution, empirical percentile method, threshold population and sparse-calibration warning. |
| Typed graph and conservative resolution | NetworkX MultiDiGraph gates required relations; same-environment time-valid aliases with ambiguous/expired cases excluded. |
| Hybrid risk | Persisted weighted terms and scored-window support, structural/evidence/graph gates, retained partial/review states. |
| Honest chronological evaluation | Separate partition seeds, predictions before labels, evaluation-only sidecars, one-to-one episodes and complete benign denominators. |
| Benchmark and negative regressions | Actual roughly 20k profile and both modes on identical holdout; expanded model/leakage/graph/alias/metric tests. |
| End-to-end participation | UI/API explicit fit → hybrid analysis → numeric risk → graph/evidence; real browser flow. |

Current measured detection matches rules-only; no ML improvement is claimed. Sparse calibration and synthetic generalization limits are explicit. Phase 3 and stretch work remain outside this turn.
