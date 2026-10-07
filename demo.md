# TraceGuard demo guide

This is a practical local walkthrough of the current TraceGuard workbench. It uses seeded synthetic events and makes no network calls after dependencies are installed.

## Start the workbench

From the repository root, build the UI once and start the local server:

~~~powershell
npm --prefix frontend run build
.\.venv\Scripts\python.exe scripts/run_demo.py
~~~

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). If dependencies are not installed, use the setup instructions in [README.md](README.md). The API reference is at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs). The demo binds to loopback and uses **runtime/traceguard.sqlite3** by default.

## 8–10 minute walkthrough

### 1. Show a clean fixture

1. Select **Load benign demo**.
2. Select **Analyze rules-only**.
3. Review accepted, rejected, duplicate, and unsupported record counts.
4. Point out that this fixture includes ordinary activity and USB mounting but no supported transfer claim.

Say: “This is one small synthetic fixture, not a general false-positive guarantee. A USB mount by itself does not prove that files were copied.”

### 2. Inspect a supported chain

1. Select **Load positive demo**, then **Analyze rules-only**.
2. Open the resulting suspected incident.
3. Walk the timeline in UTC: unusual successful authentication, unusual sensitive-file collection, removable-device mount context, and explicit file-copy telemetry.
4. Select the transfer stage and inspect its predicate, entity links, source row, canonical event, source references, and hashes.
5. Open the graph relation's source link and show that it resolves to the retained source observation.

Explain that the chain requires the same environment-scoped actor and endpoint, compatible resource and removable-device identities, positive copy bytes, an active mount, and strict event-time ordering. An IP address or graph connection alone cannot join the chain. The incident describes observed behavior and a suspected exfiltration chain; it does not prove who controlled an account or why they acted.

### 3. Show why missing telemetry stays missing

1. Select **Load missing-transfer demo** and analyze it.
2. Open the partial result and show the supported authentication and collection evidence.
3. Show the missing-evidence explanation.

Say: “Without explicit matching copy telemetry, TraceGuard keeps this as a partial observation. An anomaly score, mount, or nearby network event cannot create a transfer stage.”

### 4. Fit and use a local baseline

1. Select **Load chronological demo**.
2. Expand **Frozen baseline & analysis mode**.
3. Review the selected training and calibration datasets and benign-provenance declaration.
4. Select **Fit selected benign baseline**. This is an explicit local fitting action; ordinary analysis never trains itself.
5. Analyze the held-out test dataset in hybrid mode.
6. Inspect the selected baseline, model and feature versions, calibration sample count, anomaly percentile, and risk breakdown.

The model is a locally fitted 200-tree Isolation Forest over 15-minute UTC windows. Its percentile means behavioral rarity within the recorded calibration distribution; it is not a probability of compromise. Current calibration evidence is sparse, so threshold 80 is a structural fallback with no population guarantee.

### 5. Demonstrate one evidence experiment

Choose one branch that fits the audience:

- **Evidence sensitivity:** open the Evidence sensitivity control, exclude the transfer observation, and rerun. Show that the original parent stays intact while the child loses its transfer stage. Duplicate representations of an excluded canonical observation are excluded together.
- **Benign look-alikes:** open **Benign look-alikes** after explicitly fitting and selecting a baseline. Compare the withheld-authorization and exact-declaration arms. The declaration is scoped operator context and changes the hybrid policy; it does not establish benign intent.
- **Retrospective event-time replay:** open **Retrospective event-time replay**, choose an earlier UTC cutoff, and run a frame. Show that the frame uses only eligible parent observations and fixed baseline/context. It is a historical recomputation, not live monitoring or knowledge of what an analyst knew at that time.

Each experiment is retained with lineage and can be reopened. Describe its result as that experiment's output, not as a new ordinary analysis.

### 6. Show reports and analyst context

1. Download the selected incident as JSON or Markdown.
2. Verify the downloaded report using the same SQLite database:

~~~powershell
.\.venv\Scripts\python.exe -m traceguard.cli --db runtime/traceguard.sqlite3 verify-report "C:\path\to\downloaded-report.json"
~~~

Replace the example path with the actual download path. If the server uses another database, pass that database instead. Verification recomputes supported claims against retained records; hashes show consistency with those records, not authenticity of the original logging system.

3. Open **Cases** to show a local case, tasks, notes, disposition, or verified evidence bookmark. These are audited analyst records and do not change the detector result.
4. If time permits, show **Hunts**, **Rules**, **Intelligence**, **External findings**, and **ATT&CK**. The full support boundaries are in [full_guide.md](full_guide.md).

### 7. End with the measured limits

The frozen Phase 4D synthetic evaluation recovered 12 of 12 supported episodes in both ordinary rules-only and hybrid modes. It also recorded 21 false-positive benign user-device-day units out of 678 for rules-only and 15 out of 678 for hybrid. The six-alert difference comes from the existing scoped-authorization policy reduction; it is not a demonstrated Isolation Forest gain. The proposed 1% false-positive target remains unmet. These correlated synthetic results do not establish production accuracy or real-world generalization.

## Suggested wording

- “Observed transfer to removable media; suspected exfiltration in this chain.”
- “This stage is supported by these retained source rows and predicates.”
- “The percentile is rarity under this local baseline and calibration.”
- “This is one synthetic evaluation with these denominators.”

Avoid saying that TraceGuard proves theft, identifies the human attacker, catches unknown attacks, or has met the 1% target. No automatic remediation is implemented.

## Detailed references

- [Full guide](full_guide.md) — setup, data flow, inference, analyst tools, exports, and limitations.
- [Existing demo script](docs/DEMO.md) — the longer Phase 1–4D demonstration and replay cutoffs.
- [Final-release operator guide](docs/FINAL_RELEASE_GUIDE.md) — detailed feature boundaries and import profiles.
- [Release status](docs/RELEASE_STATUS.md) and [evaluation](docs/EVALUATION.md) — verified checks and measured results.
