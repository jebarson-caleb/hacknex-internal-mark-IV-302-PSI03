# Phase 2 model card

Purpose: a supporting behavioral-rarity signal for the known-chain detector, trained locally on explicitly selected benign synthetic or operator-declared compatible logs. It does not determine human intent or invent stages.

Estimator: scikit-learn 1.9.1 `IsolationForest`, 200 estimators, `max_samples="auto"`, `contamination="auto"`, fixed random seed, `n_jobs=1`. Training and calibration datasets must share trusted identity namespace and have strictly separate chronological closed windows. At least 20 established training and 20 calibration windows are required. Training is explicit; uploads and analyses never silently fit or update a model.

Features (ordered, version `window-v1`): login failure/success counts, device/app novelty fractions, UTC-hour novelty, distinct read resources, rare-resource fraction, trusted sensitive reads, bytes read/written/transferred to USB and distinct network destinations. Counts/bytes use documented `log1p`; novelty fractions remain bounded. Raw observations are persisted beside scores. Identities only group/look up history; they are not ordered numeric features. No SHAP or exact forest feature attribution is claimed.

History is frozen from selected training only. Training-window lookup uses that selected training snapshot; it does not consume calibration/test. Calibration and test never refit preprocessing or history. New users with fewer than three historical successful logins or reads receive cold-start warnings and no forest score. Provisional windows at explicit cutoffs are not scored. Default retrospective hybrid cutoff closes the latest observed 15-minute window and is recorded.

Score: `-model.score_samples(X)` (larger = more unusual). Calibration stores an empirical distribution over separate declared benign windows. Percentile is the midrank empirical CDF, including deterministic tie handling. Neither raw score, percentile, forest contamination nor alias policy strength is an attack probability or final false-positive guarantee.

Persistence: app-created fitted estimator in local SQLite BLOB, artifact hash, exact library/feature versions, feature names/transforms, dataset fingerprints, selected event IDs, intervals, frozen history, context and seed. Incompatible/corrupt artifacts fail explicitly. Arbitrary pickle/joblib uploads are unsupported. The local operator/database is trusted; hashes establish consistency, not authenticity or safety of externally supplied serialized code.

Hybrid policy has evidence/graph structure gates plus a numeric heuristic. Calibrating a 1% benign user-device-day target on small clean fixtures provides limited evidence. Recorded benchmark calibration has no complete benign candidates, so floor 80 is retained explicitly. There is no independent positive-development subset selecting the most useful operating threshold yet. Test data never tunes the threshold.

Measured findings: see EVALUATION.md. Real fitting and scoring participate in analysis and ranking; the current narrow holdout shows the same episode detection and false alerts as rules-only. The model has not demonstrated additional recall or false-positive improvement. Synthetic evaluations do not establish real-world generalization, slow/unknown attack detection or adequacy for production use.

## Phase 3 calibration disclosure and scoped policy

No forest/feature redesign or held-out tuning. New artifacts explicitly distinguish available percentile distribution from insufficient complete benign candidate threshold calibration. The structural fallback threshold remains 80; population_guarantee is false and sparse budget_met is null. Older artifacts keep their original fields; absent status/origin is unknown in current views/reports. Model hash is persisted for new fits.

Hybrid-v2 uses existing terms and gates with B=20 once for an exact time-valid operator-declared copy authorization (otherwise B=0). Calibration authorization context is frozen from its selected dataset and used consistently in calibration prediction; inference snapshots its own current declared context. This heuristic reduction is not a newly tuned model or guarantee of benignness. Historical hybrid-v1 results remain verifiable under their original B=0 policy.


## Phase 4D measured calibration and attribution

The existing forest, hyperparameters, preprocessing/features, history and production risk policy are unchanged. Three new chronological benign fits each have227 percentile samples and7 complete benign calibration candidates. Unlike historical sparse fits, these expose5/228 false-positive units, `budget_not_met`, threshold80 structural fallback and no population guarantee. Full rules-only/hybrid recover12/12 supported synthetic attacks, with21/678 versus15/678 benign-unit false positives. That six-alert difference follows exact/repeated authorization policy; do not credit it to IsolationForest. Experimental fixed-threshold A=0 recovers6/12 with9/678 benign units; it measures sensitivity to the anomaly term while retaining other gates, not an optimized model-free detector. Anomaly-only emits46 real window alarms and has no stage reconstruction metrics. All exceed the proposed1% test-unit target. See EVALUATION and PHASE4D_REPORT; no real-world improvement is established.
