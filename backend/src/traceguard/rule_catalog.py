"""Read-only description assembled from the existing frozen native policy modules."""
from .context import authorization_checks
from .detection import CONFIG, RULE_VERSION
from .features import FEATURE_NAMES, FEATURE_VERSION
from .ingest import ACTIONS
from .risk import score_candidate


def native_rule_catalog():
    return {
        "catalog_version": "traceguard-native-rule-catalog-v1",
        "read_only": True,
        "kind": "native multi-stage detector policy",
        "distinction": "A native stage is a validated component of the supported chain. A single-event hunt only locates observations and cannot create a stage, incident, probability, authorization, or risk input.",
        "policy_versions": {
            "detector_rule": RULE_VERSION,
            "detector_config": dict(CONFIG),
            "feature": FEATURE_VERSION,
            "feature_names": list(FEATURE_NAMES),
            "hybrid_risk": "hybrid-v2",
            "scoped_copy_authorization": "scoped-copy-v1",
            "history": "prior-UTC-days-v1",
        },
        "supported_actions_by_source": {key: sorted(values) for key, values in ACTIONS.items()},
        "identity_and_time_gates": [
            "Exact environment-scoped actor and endpoint IDs group the native chain; IP and display-name matches never join actors.",
            "Authentication precedes collection; collection precedes explicit copy; the chain window is bounded to 60 minutes.",
            "Historical counts use events strictly before the authentication UTC day and the selected frozen baseline history where applicable.",
            "A matching active prior USB mount must use the same actor, endpoint, and removable-device ID and be within 60 minutes before copy; an intervening or equal-time unmount contradicts it.",
        ],
        "stages": [
            {
                "stage_id": "authentication", "display_name": "Unusual successful authentication",
                "required_source_family": "auth", "required_fields": ["timestamp", "action=login_success", "outcome (if present)", "user_id", "device_id", "app_id"],
                "predicate": "Completed login_success for exact actor/endpoint; at least three prior successful logins strictly before that UTC day; at least one of device, app, or UTC hour is new against that history.",
                "claim": "supported_inference", "missing_behavior": "No qualifying login means no native chain. Failed or explicit unsuccessful authentication cannot support this stage.",
                "example": {"action": "login_success", "user_id": "environment-scoped actor ID", "device_id": "environment-scoped endpoint ID", "app_id": "application ID"},
            },
            {
                "stage_id": "collection", "display_name": "Unusual sensitive local-file collection",
                "required_source_family": "file", "required_fields": ["timestamp", "action=file_read", "outcome (if present)", "user_id", "device_id", "resource_id"],
                "predicate": "Completed file_read follows authentication inside the bounded chain window, with exact actor/endpoint linkage; at least three prior reads exist strictly before the authentication UTC day and this exact resource is new; an active operator-supplied sensitivity label covers the exact environment-scoped resource at event time.",
                "claim": "supported_inference", "missing_behavior": "Without prior comparison or active trusted resource context, collection is not asserted as a native stage.",
                "example": {"action": "file_read", "resource_id": "environment-scoped resource ID", "event_time_utc": "after the qualifying authentication"},
            },
            {
                "stage_id": "transfer", "display_name": "Observed transfer to removable media",
                "required_source_family": "file", "required_fields": ["timestamp", "action=file_copy_to_usb", "outcome (if present)", "user_id", "device_id", "resource_id", "removable_device_id", "destination_type=removable_media", "bytes_written>0"],
                "predicate": "Explicit completed copy follows a matching collection read for the same actor, endpoint and resource, and a matching active prior USB mount exists.",
                "claim": "observed", "missing_behavior": "Without explicit matching copy and active mount evidence, the detector retains a partial observation and does not assert transfer.",
                "example": {"action": "file_copy_to_usb", "destination_type": "removable_media", "bytes_written": 1024},
            },
        ],
        "risk_and_limits": {
            "rules_only": "Structural heuristic score; no probability. Original Phase 1 risk is unchanged.",
            "hybrid": "Existing explicitly fitted local baseline, frozen feature history, threshold and calibrated policy; anomaly rarity is not compromise probability.",
            "authorization": "Only separate operator-supplied exact scoped copy context can affect hybrid risk under scoped-copy-v1; uploaded strings cannot grant trust. Rules-only score is preserved.",
            "never_native_stage": ["single-event hunt hit", "Sigma match", "indicator match", "external alert", "human note or disposition", "technique tag"],
        },
    }
