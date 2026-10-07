from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: str = "1"
    event_id: str
    source_event_id: str | None = None
    dataset_id: str
    environment_id: str
    source_id: str
    source_type: Literal["auth", "file", "device", "network"]
    source_record_number: int
    source_file_sha256: str
    raw_record_sha256: str
    original_timestamp: str
    event_time_utc: datetime
    ingested_at_utc: datetime
    timezone_assumption: str | None = None
    action: str
    outcome: str | None = None
    user_id: str | None = None
    device_id: str | None = None
    app_id: str | None = None
    session_id: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    domain: str | None = None
    file_path: str | None = None
    file_hash: str | None = None
    resource_id: str | None = None
    resource_scope: str | None = None
    bytes_read: int | None = Field(default=None, ge=0, le=2**63-1)
    bytes_written: int | None = Field(default=None, ge=0, le=2**63-1)
    bytes_sent: int | None = Field(default=None, ge=0, le=2**63-1)
    removable_device_id: str | None = None
    destination_type: str | None = None
    process_id: str | None = None
    process_name: str | None = None
    geo_country: str | None = None
    geo_latitude: float | None = Field(default=None, ge=-90, le=90)
    geo_longitude: float | None = Field(default=None, ge=-180, le=180)
    raw_record_ref: str
    normalization_warnings: list[str] = Field(default_factory=list)


class SourceContext(BaseModel):
    dataset_id: str
    environment_id: str
    source_id: str
    source_type: Literal["auth", "file", "device", "network"]
    timezone: str | None = None


class NormalizationResult(BaseModel):
    event: Event | None = None
    error: str | None = None


class ResourceContext(BaseModel):
    resource_id: str
    sensitive: bool
    provenance: str = Field(min_length=1, max_length=500)
    effective_from: datetime
    effective_until: datetime | None = None


class Stage(BaseModel):
    stage_id: str
    stage_name: str
    rule_id: str
    rule_version: str = "phase1-v1"
    start_time_utc: datetime
    end_time_utc: datetime
    claim_status: Literal["observed", "supported_inference"]
    evidence_event_ids: list[str]
    matched_fields: dict
    predicate_results: dict[str, bool]
    historical_comparison: dict | None = None
    entity_link_reasons: list[str]


class Incident(BaseModel):
    incident_id: str
    dataset_id: str
    analysis_run_id: str
    mode: Literal["rules-only", "hybrid"] = "rules-only"
    user_id: str
    device_id: str
    stages: list[Stage]
    context_event_ids: list[str]
    selected_evidence: list[str]
    missing_evidence: list[str]
    decision: Literal["incident", "partial_observation", "review"]
    decision_reason: str
    risk: dict
    validation: dict = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    summary: str
    authorization: dict = Field(default_factory=dict)
    recommendations: list[dict] = Field(default_factory=list)
    entity_resolution: list[dict] = Field(default_factory=list)


class AliasContext(BaseModel):
    alias_user_id: str
    canonical_user_id: str
    provenance: str = Field(min_length=1, max_length=500)
    effective_from: datetime
    effective_until: datetime | None = None


class AuthorizationContext(BaseModel):
    model_config = ConfigDict(extra="forbid")
    authorization_id: str = Field(min_length=1, max_length=100)
    user_id: str
    device_id: str
    resource_id: str
    action: Literal["file_copy_to_usb"] = "file_copy_to_usb"
    provenance: str = Field(min_length=1, max_length=500)
    effective_from: datetime
    effective_until: datetime
