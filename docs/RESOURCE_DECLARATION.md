# Resource declaration — Phase 3

Data: entirely repository-generated synthetic records, seed 17 checked in. No external datasets, evaluation labels, organizer PDF copy, pretrained model, paid API or inference credentials.

Libraries: Python standard library (including SQLite, CSV, JSON and zoneinfo), FastAPI, Pydantic, Uvicorn, python-multipart, tzdata; NumPy, scikit-learn and NetworkX for Phase 2 features/Isolation Forest/typed graph; pytest and HTTPX for backend checks. React, React DOM, TypeScript, Vite, Vitest, Testing Library, jsdom and Playwright for frontend/build/browser checks. Exact installed versions and transitive dependencies are in `backend/requirements.lock` and `frontend/package-lock.json`. Models are trained locally from explicitly selected benign inputs; no pretrained weights, paid inference service or credential is required.

Development assistance: OpenAI Codex generated code, tests and documentation and ran the recorded local checks. Team review and understanding are required before submission; no team review has been claimed by the tool.

Requirements source: supplied `prompt.md`, referencing *HackNex 2026 - Internal Qualifier PS.pdf* pages 3, 4 and 7. The PDF was unavailable for independent verification here.

Additional context: user-provided `booklet_analysis.md` from Downloads was read. It distinguishes source requirements from recommendations; its optional differentiators were not treated as an instruction to exceed Phase 2.

API references checked during implementation: [FastAPI file uploads](https://fastapi.tiangolo.com/tutorial/request-files/) (multipart requirements and UploadFile); [Vite setup](https://vite.dev/guide/) (runtime setup). Package versions were resolved from the actual pip/npm registries and exercised by the checks, not invented from the spec. React code review used the installed Vercel React best-practices skill.

Phase 2 API references: [IsolationForest](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html) for actual fitting/scoring semantics; [NetworkX MultiDiGraph](https://networkx.org/documentation/stable/reference/classes/multidigraph.html) for directed parallel event relations. Versions were resolved from registries and exercised before pinning. No optional dataset/model download or external inference was added.

Phase 3: no new runtime library/model/data service. The existing graph payload/relation renderer now includes a small local SVG projection; Cytoscape/Tailwind were not added. Python/Node Docker base images are referenced by major/minor tags but not pulled or tested because the local engine is unavailable. All tests/sample/evaluation inputs remain synthetic. The user-supplied phase3_prompt.md is an engineering continuation brief, not an organizer source. Codex assistance and local React skill review are disclosed; human team review/publication remain pending.
