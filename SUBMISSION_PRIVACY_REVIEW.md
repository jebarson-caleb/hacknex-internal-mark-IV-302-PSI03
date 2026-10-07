# Submission copy privacy review

Status: local allowlisted review passed on creation. The project owner selected the MIT License; the owner/team should review and explain the submission before delivery.

- Included source, tests, pinned Python/npm locks, documentation, original bounded rule fixtures, and synthetic sample inputs.
- Replaced historical machine-specific absolute paths in the copied text with `<LOCAL_PATH_REDACTED>`; original workspace records remain untouched. Current run commands are documented relative to the repository root.
- Excluded local `.venv`, `node_modules`, build/test output, runtime SQLite databases, saved private source rows, caches, `.git`, `.env`, and non-sample user data.
- Scanned included UTF-8 text for common private Windows/Linux home paths and common private-key/API-token forms; checked for runtime database/log/EVTX types and generated/cache path components.
- `SUBMISSION_MANIFEST.json` records SHA-256 and byte length for each copied source file. It intentionally does not self-hash.
- The root project license is MIT, selected by the project owner. Confirm that contributed material can be distributed and honor the third-party terms recorded in `docs/THIRD_PARTY.md`.
- Wazuh/Hayabusa inputs in `data/samples/external/` are independently authored synthetic schema fixtures; no platform, vendor binary, raw user log, or upstream rule pack is included.
- The historical 4D runtime databases remain in the working repository's ignored `runtime/` tree and are not copied. Readable protocol/report and the release status remain in `docs/`.

The scan is a practical local review, not a guarantee that every sensitive datum or licensing obligation has been found.
