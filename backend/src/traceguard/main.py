import os
from datetime import datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .demo import load_demo
from .baseline import fit_baseline
from .hybrid import incident_graph, run_analysis
from .ingest import MAX_FILE_BYTES
from .schemas import AliasContext, AuthorizationContext, ResourceContext
from .storage import Store

ROOT = Path(__file__).resolve().parents[3]


class BodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        total = 0
        headers = dict(scope.get("headers", []))
        if int(headers.get(b"content-length", b"0")) > MAX_FILE_BYTES + 256 * 1024:
            return await JSONResponse({"detail": "request exceeds upload size limit"}, status_code=413)(scope, receive, send)

        async def bounded_receive():
            nonlocal total
            message = await receive()
            total += len(message.get("body", b""))
            if total > MAX_FILE_BYTES + 256 * 1024:
                raise HTTPException(413, "request exceeds upload size limit")
            return message

        await self.app(scope, bounded_receive, send)


class SameOriginWriteGuard:
    """Reject browser state changes carrying an explicit cross-origin context."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not scope.get("path", "").startswith("/api/") or scope.get("method") not in {"POST", "PUT", "PATCH", "DELETE"}:
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        site = headers.get(b"sec-fetch-site", b"").decode("ascii", errors="ignore").lower()
        if site in {"cross-site", "same-site"}:
            return await JSONResponse({"detail": "cross-origin state-changing request rejected"}, status_code=403)(scope, receive, send)
        origin = headers.get(b"origin")
        referer = headers.get(b"referer")
        candidate = origin.decode("latin1") if origin else referer.decode("latin1") if referer else None
        if candidate:
            try:
                actual = urlsplit(candidate)
                expected_host = dict(scope.get("headers", [])).get(b"host", b"").decode("latin1")
                expected = urlsplit(f"{scope.get('scheme', 'http')}://{expected_host}")
                def authority(parsed):
                    scheme = parsed.scheme.lower()
                    port = parsed.port or (443 if scheme == "https" else 80)
                    return (scheme, (parsed.hostname or "").lower(), port)
                same = (actual.scheme in {"http", "https"} and actual.hostname and not actual.username and not actual.password
                    and expected.hostname and authority(actual) == authority(expected))
                if not same:
                    raise ValueError("origin mismatch")
            except (ValueError, UnicodeError):
                return await JSONResponse({"detail": "cross-origin state-changing request rejected"}, status_code=403)(scope, receive, send)
        await self.app(scope, receive, send)


class DemoRequest(BaseModel):
    variant: Literal["positive", "benign", "missing-transfer"] = "positive"
    seed: int = Field(default=17, ge=0, le=2147483647)


class AnalysisRequest(BaseModel):
    dataset_id: str
    cutoff: datetime | None = None
    mode: Literal["rules-only", "hybrid"] = "rules-only"
    baseline_id: str | None = None


class TrainRequest(BaseModel):
    training_dataset_id: str
    calibration_dataset_id: str
    benign_provenance: str = Field(min_length=1,max_length=500)
    seed: int = Field(default=17,ge=0,le=2147483647)


class SensitivityRequest(BaseModel):
    model_config = {"extra": "forbid"}
    excluded_event_ids: list[str] = Field(default_factory=list, max_length=100)
    analyst_note: str = Field(default="", max_length=500)


class ReplayRequest(BaseModel):
    model_config = {'extra': 'forbid'}
    cutoff: str = Field(min_length=1, max_length=100)


class BenchmarkRequest(BaseModel):
    seed: int = Field(default=17,ge=0,le=2147483645)
    users: int = Field(default=6,ge=3,le=30)
    events: int = Field(default=1200,ge=1000,le=20000)


class LookalikeRequest(BaseModel):
    model_config = {'extra': 'forbid'}
    left_run_id: str = Field(min_length=1, max_length=100)
    right_run_id: str = Field(min_length=1, max_length=100)
    kind: Literal['context-only', 'scenario'] = 'context-only'
    declared_changed_inputs: list[str] = Field(default_factory=lambda: ['authorization_context_snapshot'], max_length=20)
    analyst_note: str = Field(default='', max_length=500)


class LabRequest(BaseModel):
    model_config = {'extra': 'forbid'}
    baseline_id: str = Field(min_length=1, max_length=100)
    seed: int = Field(default=17, ge=0, le=2147483645)


class CaseCreateRequest(BaseModel):
    model_config = {"extra": "forbid"}
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)
    priority: Literal["low", "normal", "high", "urgent"] = "normal"
    assignee: str = Field(default="", max_length=100)
    author: str = Field(default="operator", min_length=1, max_length=100)


class CaseFromIncidentRequest(CaseCreateRequest):
    incident_id: str = Field(min_length=1, max_length=100)


class CaseUpdateRequest(BaseModel):
    model_config = {"extra": "forbid"}
    expected_revision: int = Field(ge=1)
    title: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    priority: Literal["low", "normal", "high", "urgent"] | None = None
    status: Literal["open", "investigating", "resolved", "closed"] | None = None
    disposition: Literal["undetermined", "suspicious", "benign", "insufficient_evidence"] | None = None
    assignee: str | None = Field(default=None, max_length=100)
    tags: list[str] | None = Field(default=None, max_length=30)
    author: str = Field(default="operator", min_length=1, max_length=100)
    rationale: str = Field(default="", max_length=1000)


class CaseNoteRequest(BaseModel):
    model_config = {"extra": "forbid"}
    expected_revision: int = Field(ge=1)
    text: str = Field(min_length=1, max_length=4000)
    author: str = Field(default="operator", min_length=1, max_length=100)


class CaseTaskRequest(BaseModel):
    model_config = {"extra": "forbid"}
    expected_revision: int = Field(ge=1)
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    assignee: str = Field(default="", max_length=100)
    author: str = Field(default="operator", min_length=1, max_length=100)


class CaseTaskUpdateRequest(BaseModel):
    model_config = {"extra": "forbid"}
    expected_revision: int = Field(ge=1)
    status: Literal["todo", "in_progress", "done"]
    completion_note: str = Field(default="", max_length=1000)
    author: str = Field(default="operator", min_length=1, max_length=100)


class CaseBookmarkRequest(BaseModel):
    model_config = {"extra": "forbid"}
    expected_revision: int = Field(ge=1)
    analysis_run_id: str = Field(min_length=1, max_length=100)
    event_id: str = Field(min_length=1, max_length=200)
    incident_id: str = Field(default="", max_length=100)
    note: str = Field(default="", max_length=1000)
    author: str = Field(default="operator", min_length=1, max_length=100)


class CaseReopenRequest(BaseModel):
    model_config = {"extra": "forbid"}
    expected_revision: int = Field(ge=1)
    reason: str = Field(min_length=1, max_length=1000)
    author: str = Field(default="operator", min_length=1, max_length=100)


class CaseIncidentLinkRequest(BaseModel):
    model_config = {"extra": "forbid"}
    expected_revision: int = Field(ge=1)
    incident_id: str = Field(min_length=1, max_length=100)
    author: str = Field(default="operator", min_length=1, max_length=100)


class CaseExternalFindingRequest(BaseModel):
    model_config = {"extra": "forbid"}
    expected_revision: int = Field(ge=1)
    finding_id: str = Field(min_length=1, max_length=100)
    note: str = Field(default="", max_length=1000)
    author: str = Field(default="operator", min_length=1, max_length=100)


class HuntCreateRequest(BaseModel):
    model_config = {"extra": "forbid"}
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=1000)
    query: dict = Field(default_factory=lambda: {"filters": []})
    columns: list[str] = Field(default_factory=lambda: ["event_time_utc", "source_type", "action", "user_id", "device_id", "event_id"], max_length=20)
    scope: Literal["retained_run"] = "retained_run"
    tags: list[str] = Field(default_factory=list, max_length=30)


class HuntUpdateRequest(BaseModel):
    model_config = {"extra": "forbid"}
    expected_revision: int = Field(ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=1000)
    query: dict | None = None
    columns: list[str] | None = Field(default=None, max_length=20)
    tags: list[str] | None = Field(default=None, max_length=30)
    starred: bool | None = None


class HuntNoteRequest(BaseModel):
    model_config = {"extra": "forbid"}
    expected_revision: int = Field(ge=1)
    note: str = Field(min_length=1, max_length=1000)
    author: str = Field(default="operator", min_length=1, max_length=100)


class HuntExecuteRequest(BaseModel):
    model_config = {"extra": "forbid"}
    analysis_run_id: str = Field(min_length=1, max_length=100)
    revision: int | None = Field(default=None, ge=1)


class SigmaYamlRequest(BaseModel):
    model_config = {"extra": "forbid"}
    yaml_text: str = Field(min_length=1, max_length=65536)


class SigmaRevisionRequest(SigmaYamlRequest):
    expected_revision: int = Field(ge=1)


class SigmaExecuteRequest(BaseModel):
    model_config = {"extra": "forbid"}
    analysis_run_id: str = Field(min_length=1, max_length=100)
    revision: int | None = Field(default=None, ge=1)


class IndicatorEntryRequest(BaseModel):
    model_config = {"extra": "forbid"}
    type: Literal["ip", "domain", "sha256"]
    value: str = Field(min_length=1, max_length=1000)
    source: str = Field(min_length=1, max_length=120)
    source_reference: str = Field(min_length=1, max_length=500)
    description: str = Field(min_length=1, max_length=1000)
    notes: str = Field(default="", max_length=1000)
    source_confidence: float | None = Field(default=None, ge=0, le=1)
    effective_from_utc: str | None = Field(default=None, max_length=64)
    effective_until_utc: str | None = Field(default=None, max_length=64)
    enabled: bool = True
    indicator_id: str | None = Field(default=None, max_length=32)


class IndicatorCollectionRequest(BaseModel):
    model_config = {"extra": "forbid"}
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=1000)
    provenance: str = Field(min_length=1, max_length=1000)
    source_reference: str = Field(min_length=1, max_length=500)
    indicators: list[IndicatorEntryRequest] = Field(min_length=1, max_length=1000)


class IndicatorCollectionImportRequest(BaseModel):
    model_config = {"extra": "forbid"}
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=1000)
    provenance: str = Field(min_length=1, max_length=1000)
    source_reference: str = Field(min_length=1, max_length=500)


class IndicatorCollectionUpdateRequest(BaseModel):
    model_config = {"extra": "forbid"}
    expected_revision: int = Field(ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=1000)
    provenance: str | None = Field(default=None, min_length=1, max_length=1000)
    source_reference: str | None = Field(default=None, min_length=1, max_length=500)
    indicators: list[IndicatorEntryRequest] | None = Field(default=None, min_length=1, max_length=1000)


class IndicatorMatchRequest(BaseModel):
    model_config = {"extra": "forbid"}
    analysis_run_id: str = Field(min_length=1, max_length=100)
    revision: int | None = Field(default=None, ge=1)


def create_app(db_path: str | Path | None = None, static_dir: Path | None = None) -> FastAPI:
    store = Store(db_path or os.environ.get("TRACEGUARD_DB", ROOT / "runtime" / "traceguard.sqlite3"))
    app = FastAPI(title="TraceGuard — Phase 2", version="0.2.0")
    app.add_middleware(BodyLimit)
    app.add_middleware(SameOriginWriteGuard)
    app.state.store = store

    @app.exception_handler(KeyError)
    async def missing(_request, exc):
        return JSONResponse({"detail": str(exc.args[0])}, status_code=404)

    @app.exception_handler(ValueError)
    async def invalid(_request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=422)

    from .cases import RevisionConflict

    @app.exception_handler(RevisionConflict)
    async def stale_case_revision(_request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.get("/api/health")
    def health():
        return {"status":"ok","mode":"rules-only","supported_modes":["rules-only","hybrid"],"ml_implemented":True}

    @app.get("/api/datasets")
    def datasets():
        return store.datasets()

    @app.post("/api/datasets/demo", status_code=201)
    def demo(request: DemoRequest):
        dataset_id = load_demo(store, request.seed, request.variant)
        return {"dataset": store.dataset(dataset_id), "quality": store.quality(dataset_id)}

    @app.post("/api/datasets/chronological-demo",status_code=201)
    def chronological_demo(request: BenchmarkRequest):
        from .evaluation.fixtures import load_chronological_demo
        datasets,_labels = load_chronological_demo(store,request.seed,request.users,request.events)
        return datasets

    @app.get("/api/baselines")
    def baselines():
        return store.baselines()

    @app.post("/api/baselines/train",status_code=201)
    def train(request: TrainRequest):
        return fit_baseline(store,request.training_dataset_id,request.calibration_dataset_id,request.benign_provenance,request.seed)

    @app.get("/api/environments/{environment}/aliases")
    def aliases(environment: str):
        return store.aliases(environment)

    @app.put("/api/environments/{environment}/aliases")
    def configure_aliases(environment: str, aliases: list[AliasContext]):
        store.set_aliases(environment,aliases)
        return store.aliases(environment)

    @app.post("/api/evaluations",status_code=201)
    def evaluate(request: BenchmarkRequest):
        from .evaluation.benchmark import run_benchmark
        return run_benchmark(store,seed=request.seed,users=request.users,events=request.events)

    @app.get("/api/evaluations/{evaluation_id}")
    def evaluation(evaluation_id: str):
        return store.evaluation(evaluation_id)

    @app.post("/api/datasets/upload", status_code=201)
    async def upload(file: UploadFile = File(...), source_type: Literal["auth", "file", "device", "network"] = Form(...),
                     source_id: str = Form(..., min_length=1, max_length=100),
                     environment_id: str = Form("local", min_length=1, max_length=100),
                     dataset_id: str | None = Form(None), source_timezone: str | None = Form(None)):
        content = await file.read(MAX_FILE_BYTES + 1)
        await file.close()
        if len(content) > MAX_FILE_BYTES:
            raise HTTPException(413, "file exceeds 5 MiB")
        from .ingest import parse_file
        parse_file(content, file.filename or "")  # Validate format before creating a dataset.
        if dataset_id:
            if store.dataset(dataset_id)["environment"] != environment_id:
                raise ValueError("environment_id must match the existing dataset")
        else:
            dataset_id = store.create_dataset(file.filename or "upload", environment_id)
        quality = store.ingest(dataset_id, content, file.filename or "", source_id, source_type, source_timezone or None)
        return {"dataset": store.dataset(dataset_id), "quality": quality}

    @app.get("/api/datasets/{dataset_id}/analyses")
    def saved_analyses(dataset_id: str):
        return store.analyses(dataset_id)

    @app.get("/api/datasets/{dataset_id}/authorizations")
    def authorizations(dataset_id: str):
        return store.authorizations(dataset_id)

    @app.put("/api/datasets/{dataset_id}/authorizations")
    def configure_authorizations(dataset_id: str, entries: list[AuthorizationContext]):
        store.set_authorizations(dataset_id,entries)
        return store.authorizations(dataset_id)

    @app.get("/api/datasets/{dataset_id}/quality")
    def quality(dataset_id: str):
        return store.quality(dataset_id)

    @app.get("/api/datasets/{dataset_id}/resources")
    def resources(dataset_id: str):
        store.dataset(dataset_id)
        return store.resources(dataset_id)

    @app.put("/api/datasets/{dataset_id}/resources")
    def configure_resources(dataset_id: str, resources: list[ResourceContext]):
        if len(resources) > 1000:
            raise ValueError("at most 1,000 trusted resource labels")
        store.set_resources(dataset_id, resources)
        return store.resources(dataset_id)

    @app.get("/api/events")
    def events(dataset_id: str, cursor: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200)):
        store.dataset(dataset_id)
        records = store.events(dataset_id)
        return {"items": [e.model_dump(mode="json") for e in records[cursor:cursor + limit]],
                "next_cursor": cursor + limit if cursor + limit < len(records) else None, "total": len(records)}

    @app.get("/api/events/{event_id}")
    def event(event_id: str):
        return store.evidence(event_id)

    @app.post("/api/analyses", status_code=201)
    def analysis(request: AnalysisRequest):
        return run_analysis(store,request.dataset_id,mode=request.mode,baseline_id=request.baseline_id,cutoff=request.cutoff)

    @app.get("/api/analyses/{analysis_id}")
    def get_analysis(analysis_id: str):
        run = store.analysis(analysis_id)
        from .replay import guard_run
        guard_run(store, run)
        return run

    @app.get("/api/analyses/{analysis_id}/attack")
    def attack_view(analysis_id: str):
        from .attack_view import build_attack_view
        return build_attack_view(store, analysis_id)

    @app.get("/api/analyses/{analysis_id}/navigator-layer")
    def navigator_layer_export(analysis_id: str):
        import json
        from .attack_view import navigator_layer
        layer = navigator_layer(store, analysis_id)
        return Response(json.dumps(layer, ensure_ascii=True, indent=2), media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="traceguard-attack-layer-{analysis_id}.json"'})

    @app.get('/api/analyses/{analysis_id}/replay')
    def replay_navigation(analysis_id: str):
        from .replay import navigation
        return navigation(store, analysis_id)

    @app.post('/api/analyses/{analysis_id}/replay', status_code=201)
    def replay(analysis_id: str, request: ReplayRequest):
        from .replay import create_frame
        return create_frame(store, analysis_id, request.cutoff)

    @app.get('/api/replay-frames/{frame_id}')
    def replay_frame(frame_id: str):
        from .replay import get_frame
        return get_frame(store, frame_id)

    @app.get('/api/analyses/{analysis_id}/observations')
    def retained_observations(analysis_id: str, cursor: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200)):
        run = get_analysis(analysis_id)
        records = store.events_by_ids(run['event_ids'])
        return {'items': [e.model_dump(mode='json') for e in records[cursor:cursor+limit]],
                'total': len(records), 'next_cursor': cursor+limit if cursor+limit < len(records) else None}

    @app.get('/api/analyses/{analysis_id}/source/{event_id}')
    def analysis_source(analysis_id: str, event_id: str):
        run = get_analysis(analysis_id)
        if event_id not in set(run['event_ids']) | set(run.get('history_event_ids', [])):
            raise ValueError('Event is outside this retained run')
        refs = run.get('view_snapshot', {}).get('source_references', {}).get(event_id)
        if refs is None:
            raise ValueError('Frozen source references unavailable; create an ordinary new analysis')
        result = store.evidence(event_id)
        result['source_records'] = [r for r in result['source_records'] if r['ref'] in refs]
        result['analysis_run_id'] = analysis_id
        return result

    @app.post('/api/lookalikes', status_code=201)
    def create_lookalike(request: LookalikeRequest):
        from .lookalikes import create_comparison
        return create_comparison(store, request.left_run_id, request.right_run_id, request.kind,
                                 request.declared_changed_inputs, request.analyst_note)

    @app.get('/api/lookalikes')
    def saved_lookalikes(cursor: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)):
        import json
        with store.connection() as conn:
            total = conn.execute('SELECT COUNT(*) FROM lookalikes').fetchone()[0]
            rows = conn.execute('SELECT body FROM lookalikes ORDER BY rowid DESC LIMIT ? OFFSET ?', (limit, cursor)).fetchall()
        return {'items': [{k: v for k, v in json.loads(r[0]).items() if k in ('comparison_id', 'kind', 'analyst_note', 'case_version', 'created_at_utc')} for r in rows],
                'total': total, 'next_cursor': cursor+limit if cursor+limit < total else None}

    @app.get('/api/lookalikes/{comparison_id}')
    def get_lookalike(comparison_id: str, cursor: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)):
        from .lookalikes import retained_comparison
        return retained_comparison(store, comparison_id, cursor, limit)

    @app.post('/api/lookalike-labs', status_code=201)
    def lookalike_lab(request: LabRequest):
        from .evaluation.lookalikes import load_lab
        return load_lab(store, request.baseline_id, request.seed)

    @app.post("/api/analyses/{analysis_id}/sensitivity", status_code=201)
    def sensitivity(analysis_id: str, request: SensitivityRequest):
        from .sensitivity import create_sensitivity
        return create_sensitivity(store, analysis_id, request.excluded_event_ids, request.analyst_note)

    @app.get("/api/sensitivities/{comparison_id}")
    def comparison(comparison_id: str):
        from .sensitivity import retained_comparison
        return retained_comparison(store, comparison_id)

    @app.get("/api/sensitivities/{comparison_id}/report")
    def comparison_report(comparison_id: str):
        import json
        from .sensitivity import export_comparison
        return Response(json.dumps(export_comparison(store, comparison_id), ensure_ascii=True, indent=2),
            media_type="application/json", headers={"Content-Disposition": f'attachment; filename="sensitivity-{comparison_id}.json"'})

    @app.post("/api/sensitivity-verifications")
    def comparison_verification(submitted: dict):
        from .sensitivity import verify_comparison
        return verify_comparison(store, submitted)

    @app.get("/api/analyses/{analysis_id}/incidents")
    def incidents(analysis_id: str):
        get_analysis(analysis_id)
        return store.incidents(analysis_id)

    @app.get("/api/analyses/{analysis_id}/candidates")
    def candidate_page(analysis_id: str, search: str = Query("",max_length=200),
                       decision: Literal["incident","review","partial_observation"] | None = None,
                       cursor: int = Query(0,ge=0), limit: int = Query(20,ge=1,le=100)):
        get_analysis(analysis_id)
        items = store.incidents(analysis_id)
        if decision:
            items = [i for i in items if i["decision"]==decision]
        if search:
            items = [i for i in items if search.casefold() in " ".join(str(i[k]) for k in ("user_id","device_id","incident_id","summary","decision_reason")).casefold()]
        return {"items":items[cursor:cursor+limit],"total":len(items),"next_cursor":cursor+limit if cursor+limit<len(items) else None}

    @app.get("/api/incidents/{incident_id}/source/{event_id}")
    def run_source(incident_id: str, event_id: str):
        item = store.incident(incident_id)
        run = get_analysis(item["analysis_run_id"])
        history = {eid for s in item["stages"] for eid in (s["historical_comparison"] or {}).get("history_event_ids", [])}
        if event_id not in set(item["selected_evidence"]) | history:
            raise ValueError("event is not evidence for this retained incident")
        result = store.evidence(event_id)
        refs = run.get("evidence_reference_snapshot",{}).get(event_id)
        if refs is not None:
            result["source_records"] = [r for r in result["source_records"] if r["ref"] in refs]
        result["analysis_run_id"] = item["analysis_run_id"]
        return result

    @app.get("/api/incidents/{incident_id}/report")
    def report(incident_id: str, format: Literal["json","markdown"] = "json", include_raw: bool = False):
        import json
        from .reports import build_report, markdown_report
        result = build_report(store,incident_id,include_raw)
        content = markdown_report(result) if format=="markdown" else json.dumps(result,ensure_ascii=True,indent=2)
        return Response(content,media_type="text/markdown" if format=="markdown" else "application/json",
                        headers={"Content-Disposition":f'attachment; filename="traceguard-{incident_id}.{"md" if format=="markdown" else "json"}"'})

    @app.get("/api/incidents/{incident_id}")
    def incident(incident_id: str):
        item = store.incident(incident_id)
        get_analysis(item['analysis_run_id'])
        return item

    @app.get("/api/incidents/{incident_id}/graph")
    def graph(incident_id: str, limit: int = Query(200,ge=5,le=500)):
        incident(incident_id)
        return incident_graph(store,incident_id,limit)

    @app.get("/api/incidents/{incident_id}/evidence")
    def evidence(incident_id: str):
        incident = store.incident(incident_id)
        get_analysis(incident['analysis_run_id'])
        history = {eid for s in incident["stages"] for eid in (s["historical_comparison"] or {}).get("history_event_ids", [])}
        return {"selected": [run_source(incident_id, eid) for eid in incident["selected_evidence"]],
                "history": [run_source(incident_id, eid) for eid in sorted(history)]}

    @app.get("/api/cases")
    def cases(query: str = Query("", max_length=200), status: Literal["open", "investigating", "resolved", "closed"] | None = None,
              priority: Literal["low", "normal", "high", "urgent"] | None = None,
              cursor: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)):
        from .cases import list_cases
        return list_cases(store, query, status, priority, cursor, limit)

    @app.get("/api/hunts")
    def saved_hunts(cursor: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)):
        from .hunts import list_hunts
        return list_hunts(store, cursor, limit)

    @app.get("/api/rules/catalog")
    def native_rules_catalog():
        from .rule_catalog import native_rule_catalog
        return native_rule_catalog()

    @app.get("/api/sigma/rules")
    def sigma_rules():
        from .sigma_hunts import list_rules
        return list_rules(store)

    @app.get("/api/intelligence/collections")
    def indicator_collections(cursor: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)):
        from .intelligence import list_collections
        return list_collections(store, cursor, limit)

    @app.post("/api/external/preview")
    async def preview_external_file(file: UploadFile = File(...), profile: Literal["wazuh-alerts-jsonl-v1", "hayabusa-minimal-csv-v1"] = Form(...)):
        from .external_findings import MAX_EXTERNAL_BYTES, preview_external
        content = await file.read(MAX_EXTERNAL_BYTES + 1)
        await file.close()
        if len(content) > MAX_EXTERNAL_BYTES:
            raise HTTPException(413, "external artifact exceeds 5 MiB")
        return preview_external(content, file.filename or "external-upload", profile)

    @app.post("/api/external/import", status_code=201)
    async def import_external_file(file: UploadFile = File(...), profile: Literal["wazuh-alerts-jsonl-v1", "hayabusa-minimal-csv-v1"] = Form(...)):
        from .external_findings import MAX_EXTERNAL_BYTES, import_external
        content = await file.read(MAX_EXTERNAL_BYTES + 1)
        await file.close()
        if len(content) > MAX_EXTERNAL_BYTES:
            raise HTTPException(413, "external artifact exceeds 5 MiB")
        return import_external(store, content, file.filename or "external-upload", profile)

    @app.get("/api/external/artifacts")
    def external_artifacts(cursor: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)):
        from .external_findings import list_artifacts
        return list_artifacts(store, cursor, limit)

    @app.get("/api/external/artifacts/{artifact_id}")
    def external_artifact(artifact_id: str):
        from .external_findings import artifact_detail
        return artifact_detail(store, artifact_id)

    @app.get("/api/external/artifacts/{artifact_id}/export.csv")
    def export_external_csv(artifact_id: str):
        from .external_findings import csv_export
        _artifact, content = csv_export(store, artifact_id)
        return Response(content, media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="traceguard-external-{artifact_id}.csv"',
                "X-TraceGuard-Export-Escaping": "Spreadsheet formula-leading cells are prefixed with apostrophe; retained originals are unchanged."})

    @app.get("/api/external/findings")
    def external_findings(artifact_id: str | None = None, query: str = Query("", max_length=200),
                          cursor: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200)):
        from .external_findings import list_findings
        return list_findings(store, artifact_id, query, cursor, limit)

    @app.get("/api/external/findings/{finding_id}")
    def external_finding(finding_id: str):
        from .external_findings import get_finding
        return get_finding(store, finding_id)

    @app.post("/api/intelligence/collections", status_code=201)
    def create_indicator_collection(request: IndicatorCollectionRequest):
        from .intelligence import create_collection
        return create_collection(store, request.name, request.provenance, request.source_reference,
                                 [item.model_dump() for item in request.indicators], request.description)

    @app.post("/api/intelligence/collections/import", status_code=201)
    async def import_indicator_collection(file: UploadFile = File(...), import_format: Literal["csv", "json"] = Form(...),
                                          name: str = Form(..., min_length=1, max_length=120),
                                          description: str = Form("", max_length=1000),
                                          provenance: str = Form(..., min_length=1, max_length=1000),
                                          source_reference: str = Form(..., min_length=1, max_length=500)):
        from .intelligence import MAX_IMPORT_BYTES, create_collection, parse_indicator_import
        from .ingest import digest
        content = await file.read(MAX_IMPORT_BYTES + 1)
        await file.close()
        if len(content) > MAX_IMPORT_BYTES:
            raise HTTPException(413, "indicator import file exceeds 1 MiB")
        indicators = parse_indicator_import(content, import_format)
        unsafe_name = (file.filename or "indicators").replace("\\", "/").split("/")[-1]
        safe_name = "".join(char if char.isalnum() or char in "._ -" else "_" for char in unsafe_name)[:120] or "indicators"
        metadata = {"format": import_format, "filename": safe_name, "sha256": digest(content)}
        return create_collection(store, name, provenance, source_reference, indicators, description, metadata)

    @app.get("/api/intelligence/collections/{collection_id}")
    def get_indicator_collection(collection_id: str, revision: int | None = Query(None, ge=1)):
        from .intelligence import _load
        return _load(store, collection_id, revision)

    @app.patch("/api/intelligence/collections/{collection_id}")
    def update_indicator_collection(collection_id: str, request: IndicatorCollectionUpdateRequest):
        from .intelligence import update_collection
        changes = request.model_dump(exclude={"expected_revision"}, exclude_unset=True)
        if "indicators" in changes and changes["indicators"] is not None:
            changes["indicators"] = [item.model_dump() for item in request.indicators]
        return update_collection(store, collection_id, request.expected_revision, changes)

    @app.post("/api/intelligence/collections/{collection_id}/match", status_code=201)
    def match_indicators(collection_id: str, request: IndicatorMatchRequest):
        from .intelligence import match_collection, match_page
        result = match_collection(store, collection_id, request.analysis_run_id, request.revision)
        return match_page(store, result["match_id"], 0, 50)

    @app.get("/api/intelligence/collections/{collection_id}/matches")
    def indicator_match_history(collection_id: str, cursor: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)):
        from .intelligence import list_matches
        return list_matches(store, collection_id, cursor, limit)

    @app.get("/api/intelligence/matches/{match_id}")
    def get_indicator_matches(match_id: str, cursor: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200)):
        from .intelligence import match_page
        return match_page(store, match_id, cursor, limit)

    @app.post("/api/sigma/rules", status_code=201)
    def create_sigma_rule(request: SigmaYamlRequest):
        from .sigma_hunts import create_rule
        return create_rule(store, request.yaml_text)

    @app.get("/api/sigma/rules/{rule_id}")
    def get_sigma_rule(rule_id: str, revision: int | None = Query(None, ge=1)):
        from .sigma_hunts import get_rule
        return get_rule(store, rule_id, revision)

    @app.post("/api/sigma/rules/{rule_id}/revisions")
    def revise_sigma_rule(rule_id: str, request: SigmaRevisionRequest):
        from .sigma_hunts import revise_rule
        return revise_rule(store, rule_id, request.expected_revision, request.yaml_text)

    @app.post("/api/sigma/rules/{rule_id}/execute", status_code=201)
    def execute_sigma_rule(rule_id: str, request: SigmaExecuteRequest):
        from .sigma_hunts import execute_rule
        return execute_rule(store, rule_id, request.analysis_run_id, request.revision)

    @app.get("/api/sigma/executions/{execution_id}")
    def get_sigma_execution(execution_id: str):
        from .sigma_hunts import get_execution
        return get_execution(store, execution_id)

    @app.post("/api/hunts", status_code=201)
    def create_hunt(request: HuntCreateRequest):
        from .hunts import create_hunt as save_hunt
        return save_hunt(store, request.name, request.description, request.query, request.columns, request.scope, request.tags)

    @app.get("/api/hunts/{hunt_id}")
    def get_hunt(hunt_id: str, revision: int | None = Query(None, ge=1)):
        from .hunts import _load
        return _load(store, hunt_id, revision)

    @app.patch("/api/hunts/{hunt_id}")
    def update_hunt(hunt_id: str, request: HuntUpdateRequest):
        from .hunts import update_hunt as save_hunt
        changes = request.model_dump(exclude={"expected_revision"}, exclude_unset=True)
        return save_hunt(store, hunt_id, request.expected_revision, changes)

    @app.post("/api/hunts/{hunt_id}/notes", status_code=201)
    def hunt_note(hunt_id: str, request: HuntNoteRequest):
        from .hunts import add_hunt_note
        return add_hunt_note(store, hunt_id, request.expected_revision, request.note, request.author)

    @app.post("/api/hunts/{hunt_id}/execute", status_code=201)
    def execute_saved_hunt(hunt_id: str, request: HuntExecuteRequest):
        from .hunts import execute_hunt
        return execute_hunt(store, hunt_id, request.analysis_run_id, request.revision)

    @app.get("/api/hunts/{hunt_id}/executions")
    def saved_hunt_executions(hunt_id: str, cursor: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)):
        from .hunts import hunt_executions
        return hunt_executions(store, hunt_id, cursor, limit)

    @app.get("/api/hunts/{hunt_id}/executions/{execution_id}")
    def saved_hunt_results(hunt_id: str, execution_id: str, cursor: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=200)):
        from .hunts import execution_page
        return execution_page(store, hunt_id, execution_id, cursor, limit)

    @app.post("/api/cases", status_code=201)
    def create_case(request: CaseCreateRequest):
        from .cases import create_case as create_local_case
        return create_local_case(store, request.title, request.description, request.priority, request.assignee, request.author)

    @app.post("/api/cases/from-incident", status_code=201)
    def create_case_from_incident(request: CaseFromIncidentRequest):
        from .cases import create_from_incident
        return create_from_incident(store, request.incident_id, request.title, request.description,
                                    request.priority, request.assignee, request.author)

    @app.get("/api/cases/{case_id}")
    def get_case(case_id: str, revision: int | None = Query(None, ge=1)):
        from .cases import get_case as read_case
        return read_case(store, case_id, revision)

    @app.patch("/api/cases/{case_id}")
    def update_case(case_id: str, request: CaseUpdateRequest):
        from .cases import update_case as save_case
        body = request.model_dump(exclude={"expected_revision", "author", "rationale"}, exclude_unset=True)
        return save_case(store, case_id, request.expected_revision, body, request.author, request.rationale)

    @app.post("/api/cases/{case_id}/reopen")
    def reopen_case(case_id: str, request: CaseReopenRequest):
        from .cases import reopen_case as reopen
        return reopen(store, case_id, request.expected_revision, request.reason, request.author)

    @app.post("/api/cases/{case_id}/notes", status_code=201)
    def case_note(case_id: str, request: CaseNoteRequest):
        from .cases import add_note
        return add_note(store, case_id, request.expected_revision, request.text, request.author)

    @app.post("/api/cases/{case_id}/tasks", status_code=201)
    def case_task(case_id: str, request: CaseTaskRequest):
        from .cases import add_task
        return add_task(store, case_id, request.expected_revision, request.title, request.description,
                        request.assignee, request.author)

    @app.patch("/api/cases/{case_id}/tasks/{task_id}")
    def update_case_task(case_id: str, task_id: str, request: CaseTaskUpdateRequest):
        from .cases import update_task
        return update_task(store, case_id, task_id, request.expected_revision, request.status,
                           request.completion_note, request.author)

    @app.post("/api/cases/{case_id}/bookmarks", status_code=201)
    def case_bookmark(case_id: str, request: CaseBookmarkRequest):
        from .cases import add_bookmark
        return add_bookmark(store, case_id, request.expected_revision, request.analysis_run_id,
                            request.event_id, request.note, request.incident_id, request.author)

    @app.post("/api/cases/{case_id}/incidents", status_code=201)
    def link_case_incident(case_id: str, request: CaseIncidentLinkRequest):
        from .cases import link_incident
        return link_incident(store, case_id, request.expected_revision, request.incident_id, request.author)

    @app.post("/api/cases/{case_id}/external-findings", status_code=201)
    def link_case_external_finding(case_id: str, request: CaseExternalFindingRequest):
        from .cases import link_external_finding
        return link_external_finding(store, case_id, request.expected_revision,
            request.finding_id, request.note, request.author)

    @app.get("/api/cases/{case_id}/audit")
    def case_audit_log(case_id: str, cursor: int = Query(0, ge=0), limit: int = Query(50, ge=1, le=100)):
        from .cases import case_audit
        return case_audit(store, case_id, cursor, limit)

    @app.get("/api/cases/{case_id}/export")
    def case_export(case_id: str, format: Literal["json", "markdown"] = "json", revision: int | None = Query(None, ge=1)):
        from .cases import export_case, case_markdown
        import json
        result = export_case(store, case_id, revision)
        content = case_markdown(result) if format == "markdown" else json.dumps(result, ensure_ascii=True, indent=2)
        extension = "md" if format == "markdown" else "json"
        return Response(content, media_type="text/markdown" if format == "markdown" else "application/json",
                        headers={"Content-Disposition": f'attachment; filename="traceguard-case-{case_id}-r{result["case_snapshot"]["revision"]}.{extension}"'})

    @app.post("/api/cases/verify")
    def verify_case(submitted: dict):
        from .cases import verify_case_export
        return verify_case_export(store, submitted)

    # Explicit API catchall before the static mount: unknown APIs never return SPA HTML.
    @app.api_route("/api/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    def unknown_api(path: str):
        raise HTTPException(404, "API route not implemented")

    built = static_dir or ROOT / "frontend" / "dist"
    if built.is_dir():
        app.mount("/", StaticFiles(directory=built, html=True), name="frontend")
    else:
        @app.get("/")
        def build_instructions():
            return {"message": "Build the UI: npm --prefix frontend ci; npm --prefix frontend run build",
                    "api_docs": "/docs", "mode": "rules-only"}
    return app


app = create_app()
