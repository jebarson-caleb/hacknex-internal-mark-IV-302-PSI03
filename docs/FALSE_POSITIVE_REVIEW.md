# Phase 4D false-positive review

Status: **the proposed 1% benign active user-device-day target remains unmet**. This is an inspection of the already exposed synthetic Phase 4D results; it is not a new evaluation, new label source, threshold experiment, or detector change.

## Measured outcomes

The three fixed final-test profiles retain 21 rules-only incident outputs over 678 active benign user-device-day units (3.097%) and 15 hybrid incident outputs over the same 678 units (2.212%). The hybrid count is lower by six because two fixture cases per seed moved from `incident` to `review` after an exact/repeated authorization-context check subtracted the existing fixed 20-point policy term. Those candidates remain for human review. This observed change is a context-policy effect; it is not evidence that the forest improved detection.

The six supported attack episodes per-profile total across three seeds remain 12/12 recalled by each ordinary mode. Precision in the representative aggregate is 12/33 for rules-only and 12/27 for hybrid. The saved threshold remains 80 with `budget_not_met`; seven complete benign calibration candidates and five actual alerted benign units among 228 are retained per seed. No alternative threshold was selected.

## Available explanations in the authored cases

For each seed, the machine-readable `case-outcomes.json` records seven full-chain benign fixture cases under both the rules-only and hybrid paths:

| Fixture category | What the saved inputs say | Rules-only | Hybrid | Interpretation limit |
|---|---|---|---|---|
| `exact` | A matching scoped, time-valid operator authorization is present | `incident` | `review` | The policy changes the hybrid risk term; this does not certify the activity as safe. |
| `repeated` | Repeated matching authorization context is present | `incident` | `review` | The exact-match discount is applied once; repeated context is not extra proof. |
| `withheld` | No matching authorization was supplied | `incident` | `incident` | Missing context is not evidence of malicious intent. |
| `expired` | The authorization window ended before the event | `incident` | `incident` | Expired context cannot authorize this event; the records do not prove intent. |
| `future` | The authorization begins after the event | `incident` | `incident` | Future context cannot authorize this event; the records do not prove intent. |
| `wrong_scope` | The context does not match the exact scoped actor/endpoint/resource/action | `incident` | `incident` | A nonmatching declaration cannot suppress the finding; this is not an attribution verdict. |
| `shared_ip` | A network address is shared in the fixture while the chain retains exact actor/endpoint and event evidence | `incident` | `incident` | IP addresses do not join identities in TraceGuard; shared-address context alone cannot distinguish the activity. |

These are hand-authored synthetic benign contexts that deliberately contain a complete detector-supported chain. They do not establish how often these categories occur in real operations. The same source outcomes retain `familiar` and `mount_only` without a complete candidate. `access_only`, `failed_copy`, `zero_bytes`, `wrong_resource`, and `wrong_device` remain partial observations rather than incident alerts. Two missing-copy/out-of-window malicious cases are separately labeled insufficient or out-of-scope and remain partial; they are not benign false positives.

The current data therefore distinguishes complete matching telemetry from missing/invalid context, but does not establish business intent, source authenticity, or whether an unusual chain was authorized outside the supplied context. Reviewers should verify the source rows and ask the asset owner; closing a case as benign does not alter any metric or historical prediction.

## Fixed-threshold diagnostic

The saved `A=0` evaluation diagnostic emits 9/678 benign units (1.327%) and recalls 6/12 supported attack episodes. It is a sensitivity check with the same fixed threshold and gates, not an optimized operating point or a validated model-free comparator. It also exceeds the proposed 1% target and loses half of the supported episodes. It does not justify changing the release policy.

## Reproducible source records

- `runtime/phase4d-full-20261007/seed-41/case-outcomes.json` — SHA-256 `25cd36a5bae960fb0e3d7eb0999ee54df24393a858c76c9632c96bb13063f208`
- `runtime/phase4d-full-20261007/seed-53/case-outcomes.json` — SHA-256 `5be4bb0b87e330e3edc228ebea24c363cbe7419782dd3822aaa1917fc2f0596d`
- `runtime/phase4d-full-20261007/seed-67/case-outcomes.json` — SHA-256 `637de27f25d5bca24c1cf34a9a4f83b0a801bd8aa1a5825cc994641f40047be7`
- `runtime/phase4d-full-20261007/REPORT.md` and `evaluation.json` — saved three-seed aggregate and matching denominators.
- `runtime/phase4d-full-20261007/fresh-verification.json` — fresh reopen and saved-prediction verification; not a new untouched holdout.
- `docs/PHASE4D_REPORT.md` — privacy-reviewed representative report, SHA-256 `3078efd7d738bbe1f1ad3f673b93316dbe8ecb283e7574b8038b598a36b4a839`.

The release additions keep notes, hunts, indicator matches, external findings, ATT&CK mappings, and case dispositions outside inference and these denominators. The saved Phase 4D bytes are preserved; no metric was recomputed or tuned to improve the stated results.
