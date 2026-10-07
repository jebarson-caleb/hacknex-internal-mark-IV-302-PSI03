# Phase 4D representative synthetic evaluation report

Protocol `phase4d-v1` / generator `expanded-usb-v1`; SHA256 `14f6aebaa0c37c02751dc2e8e4b49dc45f07d78ccc41b72f5f04b0dbbd060739`.

Evaluation-first checkpoint, before replay. Three predefined seeds have distinct chronological benign training, benign calibration and final-test observations. Four supported attacks per profile vary timing, identity, resource, amount, direct alias/corroboration and later repeat actor. Legitimate exports remain benign without matching authorization. No final-test tuning or model replacement.

| Output | Matched / emitted | Matched / supported episodes | Benign FP units / active benign units | Benign false outputs / accepted test observations |
|---|---:|---:|---:|---:|
| rules-only | 12/33 | 12/12 | 21/678 | 21/14739 |
| hybrid | 12/27 | 12/12 | 15/678 | 15/14739 |
| neutralized-diagnostic | 6/15 | 6/12 | 9/678 | 9/14739 |
| anomaly-only | N/A: windows | N/A: windows | 31/678 | 31/14739 |

Window alarms do not reconstruct stages; their chain metrics are not applicable. All modes use the same alias-resolved accepted active user-device-day population; every labeled malicious observed unit is excluded, including missing-copy/out-of-window cases. Units without candidates count. Evidence spanning days implicates each selected day. Benign false outputs per1000 observations and active-unit FPR are separate quantities. A false unmatched incident on a malicious unit is not a benign-unit false positive.

| Seed | Accepted training / calibration / test | Rejected train / calibration / test | Calibration complete / alerts / units | Applied threshold / status |
|---|---|---|---|---|
| 41 | 9664/4896/4913 | 0/1/1 | 7/5/228 | 80.0/budget_not_met |
| 53 | 9664/4896/4913 | 0/1/1 | 7/5/228 | 80.0/budget_not_met |
| 67 | 9664/4896/4913 | 0/1/1 | 7/5/228 | 80.0/budget_not_met |

Each full profile requests20000 background observations; complete routine groups and added scenario records determine actual counts. Generated/accepted/rejected/quarantined/duplicate/source hashes are retained per partition. Calibration contains eight benign export templates, seven complete candidates. The familiar case does not meet novelty. Calibration audit candidate decision/mode is the prethreshold structural correlator output; actual hybrid emission is independently counted using applied risk/threshold/scored-window gates. Fresh verification records both structural and applied decisions.

| Seed | Mode | Matches / alerts | Benign false-positive units | Required stages / labeled stages | Valid asserted stages | Order coverage / accuracy |
|---|---|---|---|---|---|---|
| 41 | rules-only | 4/11 | 7/226 | 12/12 | 47/47 | 12/12 / 40/40 |
| 41 | hybrid | 4/9 | 5/226 | 12/12 | 47/47 | 12/12 / 40/40 |
| 41 | neutralized-diagnostic | 2/5 | 3/226 | 12/12 | 47/47 | 12/12 / 40/40 |
| 41 | anomaly-only | N/A | 10/226 | N/A | N/A | N/A / N/A |
| 53 | rules-only | 4/11 | 7/226 | 12/12 | 47/47 | 12/12 / 40/40 |
| 53 | hybrid | 4/9 | 5/226 | 12/12 | 47/47 | 12/12 / 40/40 |
| 53 | neutralized-diagnostic | 2/5 | 3/226 | 12/12 | 47/47 | 12/12 / 40/40 |
| 53 | anomaly-only | N/A | 11/226 | N/A | N/A | N/A / N/A |
| 67 | rules-only | 4/11 | 7/226 | 12/12 | 47/47 | 12/12 / 40/40 |
| 67 | hybrid | 4/9 | 5/226 | 12/12 | 47/47 | 12/12 / 40/40 |
| 67 | neutralized-diagnostic | 2/5 | 3/226 | 12/12 | 47/47 | 12/12 / 40/40 |
| 67 | anomaly-only | N/A | 10/226 | N/A | N/A | N/A / N/A |

Stage and ordering coverage include validated supported partial/review candidates; they are distinct from alert episode recall. Saved independent source/stage/graph checks determine evidence validity. One-to-one matches retain eligible-match decisions, duplicate/oversized rejection and unmatched truth/predictions. Partial/review output is not a safety judgment. Missing-copy/out-of-window malicious cases stay separately labeled and outside supported full-observability recall.

Full hybrid versus rules-only is a whole-pipeline comparison. Exact/repeated authorization subtracts20 once in hybrid; this policy effect cannot be credited to the forest. A=0 diagnostic fixes all observations, context, model bytes, other terms, availability gates and threshold. Its different outputs measure sensitivity to that term, not an independently optimized detector or real-world model benefit. Remaining benign alerts and missed supported episodes remain inspectable.

| Seed | Benign case | Ordinary rules-only decisions | Ordinary hybrid decisions |
|---|---|---|---|
| 41 | exact | incident | review |
| 41 | withheld | incident | incident |
| 41 | expired | incident | incident |
| 41 | future | incident | incident |
| 41 | wrong_scope | incident | incident |
| 41 | repeated | incident | review |
| 41 | shared_ip | incident | incident |
| 41 | familiar | absent | absent |
| 53 | exact | incident | review |
| 53 | withheld | incident | incident |
| 53 | expired | incident | incident |
| 53 | future | incident | incident |
| 53 | wrong_scope | incident | incident |
| 53 | repeated | incident | review |
| 53 | shared_ip | incident | incident |
| 53 | familiar | absent | absent |
| 67 | exact | incident | review |
| 67 | withheld | incident | incident |
| 67 | expired | incident | incident |
| 67 | future | incident | incident |
| 67 | wrong_scope | incident | incident |
| 67 | repeated | incident | review |
| 67 | shared_ip | incident | incident |
| 67 | familiar | absent | absent |

Proposed1% target: compare the recorded unit fractions with0.01; it is an engineering target, not an organizer rule or deployment guarantee. Native calibration may report budget_not_met and retain80 when no useful candidate boundary meets the budget. Raw-score window quantile selection is separate from incident calibration. Calibration percentile sample counts and threshold ties are recorded per seed; ties can exceed the nominal window1% tail.

| Measured operation | Seed run count | Median seconds | Range seconds |
|---|---:|---:|---:|
| generation_ingestion | 3 | 6.5797 | 6.5065–6.6950 |
| fitting | 3 | 2.0827 | 2.0268–2.0868 |
| calibration_audit | 3 | 1.9914 | 1.8616–2.0349 |
| rules-only_inference_and_persistence | 3 | 2.8850 | 2.8028–3.1556 |
| rules-only_verification | 3 | 28.6001 | 28.4992–39.0921 |
| hybrid_inference_and_persistence | 3 | 3.0735 | 2.8771–3.4384 |
| hybrid_verification | 3 | 32.4227 | 31.8517–33.6661 |
| anomaly-only_scoring | 3 | 0.0690 | 0.0607–0.0827 |
| evaluation | 3 | 0.0159 | 0.0094–0.0160 |
| sensitivity_noop_and_verification | 3 | 18.6380 | 15.9340–19.6499 |

Total wrapper time 299.7986s. One measurement per distinct seed workload; the table describes different profiles, not repeated identical trials. Fresh DB/models, warm installed libraries/OS caches, concurrent host checks and contention uncontrolled. Hardware: Windows-11-10.0.26300-SP0; Intel64 Family 6 Model 154 Stepping 3, GenuineIntel; Python 3.12.14. Process resident memory unmeasured. Inference workload is accepted test observations only. No streaming or speed-superiority claim.

The bounded sample is correlated and synthetic. No confidence/independence, generalization, production readiness, human intent or source authenticity claim. No credentials, raw logs, private paths, databases or cache content are included in this representative report. Reproduction uses the documented CLI with a new local output directory; runtime evidence stays local.

**Phase 4C replay plus final submission checks remaining.**
