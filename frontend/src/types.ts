export interface Dataset { id: string; name: string; environment: string; origin: string; seed: number | null }
export interface Quality {
  accepted: number; rejected: number; duplicates: number; unsupported: number;
  errors: {filename: string; row_number: number; error: string}[];
  files?: {filename:string;source_type:string;sha256:string}[]; timezone_assumptions: string[]; warnings: string[];
}
export interface Analysis {
  history_event_ids?:string[];
  dataset_id?:string;
  replay_manifest?:Record<string,unknown>;
  branch_kind?:string; parent_run_id?:string; comparison_id?:string;
  analysis_run_id: string; mode: string; incident_count: number; partial_count: number;
  event_count: number; warnings: string[]; cutoff: string; dataset_fingerprint: string;
  review_count?:number; status?:string; config?:Record<string,unknown>; calibration?:Record<string,unknown>; baseline_snapshot?:Record<string,unknown>; graph_summary?: {nodes:number; edges:number}; baseline_id?: string | null;
}
export interface Sensitivity {
  comparison_id:string; manifest:{parent_run_id:string;child_run_id:string;excluded_event_ids:string[];effective_fingerprint:string;cutoff:string};
  before_candidates:Incident[]; after_candidates:Incident[]; empty_result:boolean; duration_seconds:number;
  differences:{status:string;parent_incident_id:string|null;child_incident_id?:string|null;possible_child_ids?:string[];supported_stages?:string[];lost_stages?:string[];new_stages?:string[];surviving_evidence?:string[];removed_support?:string[];new_support?:string[];before?:Incident;after?:Incident;graph_before?:EntityGraph;graph_after?:EntityGraph|null}[];
}
export interface Stage {
  stage_id: string; stage_name: string; claim_status: string; start_time_utc: string;
  evidence_event_ids: string[]; historical_comparison: Record<string, unknown> | null;
  predicate_results:Record<string,boolean>; matched_fields: Record<string, unknown>; entity_link_reasons: string[];
}
export interface Incident {
  incident_id: string; analysis_run_id:string; decision_reason:string; entity_resolution?:Record<string,unknown>[]; authorization?:Record<string,unknown>; recommendations?:{suggestion:string; supporting_observation:string;evidence_event_ids:string[];requires_authorized_human_review:boolean;approval_status:string}[]; user_id: string; device_id: string; decision: string; stages: Stage[];
  context_event_ids: string[]; selected_evidence: string[]; missing_evidence: string[];
  summary: string; risk: {score: number; label: string; components?:Record<string,number>; weighted_terms?:Record<string,number>; anomaly_percentile?:number|null; threshold?:number; calibration?:Record<string,unknown>; missing_components?:string[]};
  validation: {valid: boolean; errors: string[]; asserted_stages_checked: number};
}
export interface Baseline {
  baseline_id:string; training_start:string; training_end:string; calibration_end:string;
  training_window_count:number; calibration_sample_size:number; seed:number; model_version:string;
  feature_version?:string; percentile_calibration?:Record<string,unknown>; risk_calibration:{status?:string; threshold_origin?:string; fallback_reason?:string|null; complete_candidates?:number; warning?:string; threshold:number; budget_met:boolean|null; benign_units:number; false_positive_units:number};
}
export interface EntityGraph {
  nodes:{id:string; entity_type:string; label:string}[];
  edges:{edge_id:string; source:string; target:string; relation:string; status:string; event_ids:string[]}[];
  truncated:boolean; total_nodes:number; independent_event_count:number;
}
export interface Evaluation {
  seed:number; partitions:Record<string,unknown>; runs:Record<string,unknown>; evaluation_id:string; split:string; baseline_id:string; processing_seconds:Record<string,number>;
  metrics:Record<string,{
    alert_count:number;
    incident_precision:{numerator:number;denominator:number;value:number|null};
    incident_recall:{numerator:number;denominator:number;value:number|null};
    benign_user_device_day_fpr:{numerator:number;denominator:number;value:number|null};
  }>;
}
export interface EventRow { event_id: string; event_time_utc: string; action: string; user_id: string | null; device_id: string | null; resource_id: string | null }
export interface Evidence {
  analysis_run_id?:string;
  event: EventRow & Record<string, unknown>;
  source_records: {ref: string; filename: string; row_number: number; raw: unknown;
    file_sha256: string; raw_sha256: string; status: string; hash_valid: boolean; file_hash_valid: boolean; file_row_valid: boolean}[];
}
