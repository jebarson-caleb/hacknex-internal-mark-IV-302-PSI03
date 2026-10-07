# External adapter schema fixtures

These two files are independently authored synthetic format fixtures. They are shaped to the documented upstream field/profile layouts; neither Wazuh nor Hayabusa was run to generate them.

- `wazuh-alerts-schema.jsonl`: selected Wazuh `alerts.json` alert objects, one JSON object per line. Uses documentation-only IP ranges and synthetic host/rule IDs. An imported Wazuh file is an alert selection, never a complete benign/event population.
- `hayabusa-minimal-schema.csv`: the exact documented Hayabusa `minimal` output columns: `Timestamp,Computer,Channel,EventID,Level,RecordID,RuleTitle,Details`. Timestamp includes a timezone offset. This adapter does not support other profiles, `.evtx`, or detail-text extraction.

Import profile IDs are `wazuh-alerts-jsonl-v1` and `hayabusa-minimal-csv-v1`. Both uploads are capped at 5 MiB and 10,000 records. Raw bytes and row values are retained in the local SQLite store. Every accepted row is external context only; it cannot become a canonical event or native stage.

Upstream format references, retrieval date, observed licensing, modifications and limits are in `docs/THIRD_PARTY_SOURCES.json` and `docs/FINAL_RELEASE_GUIDE.md`.
