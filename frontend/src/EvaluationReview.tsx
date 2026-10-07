export function EvaluationReview(){
  return <section id="quality-review" aria-label="Saved expanded evaluation and false-positive review">
    <h2>Saved expanded evaluation · false-positive target unmet</h2>
    <p className="notice"><strong>Historical, synthetic result:</strong> the proposed 1% benign active user-device-day target remains unmet. This read-only summary reflects the saved Phase 4D evaluation; it is not a run of this page and case labels do not change it.</p>
    <div className="table-wrap"><table><caption>Three saved seeds · common denominator 678 active benign user-device-day units</caption><thead><tr><th>Mode</th><th>Incident precision</th><th>Supported recall</th><th>Benign-unit false positives</th><th>Calibration</th></tr></thead><tbody>
      <tr><th scope="row">Rules-only</th><td>12 / 33 · 36.36%</td><td>12 / 12</td><td>21 / 678 · 3.097%</td><td>—</td></tr>
      <tr><th scope="row">Hybrid</th><td>12 / 27 · 44.44%</td><td>12 / 12</td><td>15 / 678 · 2.212%</td><td>threshold 80 · budget_not_met</td></tr>
      <tr><th scope="row">Anomaly-only</th><td>Not applicable to chains</td><td>Not applicable to chains</td><td>31 / 678 · 4.572%</td><td>46 window alarms</td></tr>
      <tr><th scope="row">A=0 diagnostic</th><td>6 / 15 · 40%</td><td>6 / 12</td><td>9 / 678 · 1.327%</td><td>Not a tuned operating point</td></tr>
    </tbody></table></div>
    <p>The six-alert rules-only/hybrid difference corresponds to the existing exact/repeated authorization policy term, not a measured forest gain. The A=0 diagnostic misses six supported episodes and still exceeds the proposed target.</p>
    <details><summary>Saved report references and review limits</summary><p>Machine-readable artifacts: <code>runtime/phase4d-full-20261007/evaluation.json</code>, <code>fresh-verification.json</code>, and per-seed <code>case-outcomes.json</code>. Narrative review: <code>docs/FALSE_POSITIVE_REVIEW.md</code>; metric definitions and exact results: <code>docs/PHASE4D_REPORT.md</code>.</p><p>Three correlated synthetic seeds do not establish real-world accuracy or generalization. `fresh-verification.json` verifies saved outputs; it is not a new untouched holdout.</p><p>Closing an investigation as benign, adding a hunt, matching an indicator, or importing an external alert does not change this table or the saved denominators.</p></details>
  </section>;
}
