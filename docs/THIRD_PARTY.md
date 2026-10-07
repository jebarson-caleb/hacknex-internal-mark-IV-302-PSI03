# Third-party sources and licenses

## Source use in this release

TraceGuard's release additions are original code written against documented behavior. The upstream platforms below are references for workflow and data-format concepts only; this repository does not copy their application code, brands, screenshots, detection packs, rules, or binaries. No upstream platform is installed, launched, or contacted by the application. Import fixtures are independently authored schema fixtures and are labeled as such.

| Project/reference | What informed TraceGuard | Observed project license | Material reused here |
|---|---|---|---|
| [Google Timesketch](https://timesketch.org/guides/user/search-query-guide/) | Saved searches, query views, event annotations | Apache-2.0 for the project | None; workflow inspiration only |
| [DFIR-IRIS](https://docs.dfir-iris.org/latest/operations/cases/tasks/) | Cases, tasks, notes and audit-oriented investigation workflow | LGPL-3.0 for `iris-web` | None; workflow inspiration only |
| [Sigma specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html) | YAML rule shape and bounded field/modifier semantics | Specification is public domain; SigmaHQ detection rules use DRL 1.1 | No SigmaHQ rules or pySigma code; TraceGuard ships original rules |
| [OpenCTI](https://docs.opencti.io/latest/usage/exploring-observations/) | Observable/indicator distinction and validity/provenance concepts | Community Edition Apache-2.0; Enterprise Edition has a separate license | None; concept inspiration only |
| [Wazuh](https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/journald.html) | File-based Wazuh `alerts.json` structure and nested alert fields | Wazuh source includes GPL-2.0 components and other file-specific licenses; documentation license was not separately reviewed | No Wazuh code, rules, or runtime; independently authored schema fixture and allowlisted mapper |
| [Hayabusa](https://github.com/Yamato-Security/hayabusa/blob/main/website/docs/output/index.md) | The documented `minimal` CSV timeline profile and its exact column aliases | Hayabusa software AGPL-3.0; its rules use DRL 1.1 | No Hayabusa code or rules; independently authored schema fixture and exact-header mapper |
| [MITRE ATT&CK](https://attack.mitre.org/resources/terms-of-use/) | T1005, T1052.001 and their technique names | MITRE terms grant use with required attribution | Only the two scoped IDs/names and linked source references; no images or rule content |
| [ATT&CK Navigator layer format](https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.3/layerformat.md) | Navigator-compatible JSON structure | Apache-2.0 for Navigator | TraceGuard-generated JSON from the documented v4.3 contract; no Navigator code |

The MITRE attribution included in technique views and Navigator exports is: “© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.” The ATT&CK trademark is not used to imply MITRE affiliation or endorsement.

## Dependencies

Runtime and development dependencies remain pinned in `backend/pyproject.toml`, `backend/requirements.lock`, and `frontend/package-lock.json`. This release adds PyYAML 6.0.3 (MIT) for bounded `SafeLoader` parsing of the explicitly supported Sigma subset and idna 3.20 (BSD-3-Clause) for strict IDNA UTS #46 domain normalization. TraceGuard rejects YAML aliases, custom/unknown tags, duplicate keys, excess nesting and unsupported syntax before rule evaluation. Neither dependency is vendored into the submission copy.

## TraceGuard ownership and AI assistance

The root `LICENSE` applies the MIT License to original TraceGuard project materials, following the project owner's selection for this release. It does not replace the terms of dependencies or third-party materials listed above. Project contributors remain responsible for confirming they have the rights to distribute material they contribute. Codex assisted with implementation and documentation; the team must review and take responsibility for the final source, formats, metrics and disclosures before submission.

## Research record

The requested `REPOSITORY_RESEARCH.md` and `SUBMISSION_CHECKLIST.md` were absent from the repository and Downloads when searched on 2026-10-07. References actually inspected for this release, retrieval dates, format boundaries, and available content hashes are recorded in `docs/THIRD_PARTY_SOURCES.json`. The Navigator v4.3 Markdown spec was retrieved and hashed as SHA-256 `57ccdb...d33705a` in the private R0 runtime research cache; it is not copied into the submission directory. Mutable upstream pages without an immutable version are recorded by URL and retrieval date rather than assigned an invented revision.
