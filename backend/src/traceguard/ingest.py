"""Four explicitly documented synthetic adapters; records never confer trust."""
import csv
import hashlib
import io
import json
from datetime import datetime, timezone
from ipaddress import ip_address
from urllib.parse import quote
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import ValidationError

from .schemas import Event, NormalizationResult, SourceContext

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_RECORD_BYTES = 64 * 1024
MAX_ROWS = 10000
ACTIONS = {
    "auth": {"login_success", "login_failure", "logout"},
    "file": {"file_read", "file_write", "file_copy_to_usb"},
    "device": {"usb_mount", "usb_unmount"},
    "network": {"network_connect"},
}
IDENTITIES = {"user_id": "user", "device_id": "endpoint", "app_id": "app",
              "resource_id": "file", "removable_device_id": "removable_device"}


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def json_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def entity_id(environment: str, kind: str, value: str) -> str:
    return ":".join(quote(part, safe="") for part in (environment, kind, value))


def parse_time(value: str, declared_timezone: str | None = None) -> tuple[datetime, str | None]:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    assumption = None
    if parsed.tzinfo is None:
        if not declared_timezone:
            raise ValueError("naive timestamp requires a declared source timezone")
        zone = ZoneInfo(declared_timezone)
        a, b = parsed.replace(tzinfo=zone, fold=0), parsed.replace(tzinfo=zone, fold=1)
        if a.utcoffset() != b.utcoffset():
            raise ValueError("ambiguous or nonexistent local time; supply an explicit offset")
        if a.astimezone(timezone.utc).astimezone(zone).replace(tzinfo=None) != parsed:
            raise ValueError("nonexistent local time; supply an explicit offset")
        parsed, assumption = a, declared_timezone
    return parsed.astimezone(timezone.utc), assumption


def normalize_record(record: dict, context: SourceContext, *, row: int = 1,
                     file_hash: str = "", raw_ref: str = "") -> NormalizationResult:
    try:
        if not isinstance(record, dict):
            raise ValueError("record must be a JSON object")
        if len(json_bytes(record)) > MAX_RECORD_BYTES:
            raise ValueError("record exceeds 64 KiB")
        original = record.get("timestamp")
        if not isinstance(original, str) or not original:
            raise ValueError("timestamp is required as an ISO 8601 string")
        event_time, assumption = parse_time(original, context.timezone)
        action = record.get("action")
        if not isinstance(action, str) or not action.strip():
            raise ValueError("action is required")
        supported = action in ACTIONS[context.source_type]
        if any(action in actions for actions in ACTIONS.values()) and not supported:
            raise ValueError(f"action {action} does not belong to {context.source_type} adapter")
        required = ["user_id", "device_id"] if supported else []
        if action.startswith("login_"):
            required += ["app_id"]
        if action in {"file_read", "file_write", "file_copy_to_usb"}:
            required += ["resource_id"]
        if action in {"usb_mount", "usb_unmount", "file_copy_to_usb"}:
            required += ["removable_device_id"]
        if action == "file_copy_to_usb":
            required += ["bytes_written", "destination_type"]
            if record.get("destination_type") != "removable_media":
                raise ValueError("copy requires destination_type=removable_media")
        if action == "network_connect":
            required += ["dst_ip"]
        for key in required:
            if record.get(key) is None or record.get(key) == "":
                raise ValueError(f"{action} requires {key}")
        values = {key: value for key, value in record.items()
                  if key in Event.model_fields and key not in {
                      "event_id", "dataset_id", "environment_id", "source_id", "source_type",
                      "source_record_number", "source_file_sha256", "raw_record_sha256",
                      "original_timestamp", "event_time_utc", "ingested_at_utc", "timezone_assumption",
                      "raw_record_ref", "normalization_warnings", "schema_version"}}
        values = {key: (None if value == "" else value) for key, value in values.items()}
        for key in ("bytes_read", "bytes_written", "bytes_sent"):
            if isinstance(values.get(key), bool):
                raise ValueError(f"{key} must be an integer byte count, not a boolean")
        for key, kind in IDENTITIES.items():
            value = values.get(key)
            if value is not None:
                if not isinstance(value, str) or not value.strip():
                    raise ValueError(f"{key} must be a nonempty string")
                values[key] = entity_id(context.environment_id, kind, value)
        for key in ("src_ip", "dst_ip"):
            if values.get(key) is not None:
                values[key] = str(ip_address(values[key]))
        warnings = []
        if not supported:
            warnings.append("unsupported action retained for browsing; excluded from detection")
        if assumption:
            warnings.append(f"source timezone assumed explicitly: {assumption}")
        event = Event(**values, event_id="pending", dataset_id=context.dataset_id,
                      environment_id=context.environment_id, source_id=context.source_id,
                      source_type=context.source_type, source_record_number=row,
                      source_file_sha256=file_hash, raw_record_sha256=digest(json_bytes(record)),
                      original_timestamp=original, event_time_utc=event_time,
                      ingested_at_utc=datetime.now(timezone.utc), timezone_assumption=assumption,
                      raw_record_ref=raw_ref, normalization_warnings=warnings)
        vendor_id = event.source_event_id
        identity = vendor_id if vendor_id else digest(json_bytes(event_content(event)))
        event.event_id = digest(json_bytes([context.dataset_id, context.source_id, identity]))
        return NormalizationResult(event=event)
    except (ValueError, TypeError, ValidationError, ZoneInfoNotFoundError) as exc:
        return NormalizationResult(error=str(exc))


def event_content(event: Event) -> dict:
    omitted = {"event_id", "source_record_number", "source_file_sha256", "raw_record_sha256",
               "original_timestamp", "ingested_at_utc", "raw_record_ref", "normalization_warnings",
               "timezone_assumption"}
    return event.model_dump(mode="json", exclude=omitted)


def parse_file(content: bytes, filename: str) -> list[tuple[int, dict | None, str | None]]:
    if len(content) > MAX_FILE_BYTES:
        raise ValueError("file exceeds 5 MiB")
    # Filename is only format metadata: never used as a filesystem path.
    suffix = filename.rsplit(".", 1)[-1].lower()
    if suffix not in {"csv", "jsonl"}:
        raise ValueError("only UTF-8 CSV and JSONL uploads are supported; archives are rejected")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("file must be UTF-8") from exc
    rows = []
    if suffix == "jsonl":
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                if len(line.encode()) > MAX_RECORD_BYTES:
                    raise ValueError("record exceeds 64 KiB")
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError("record must be a JSON object")
                rows.append((number, record, None))
            except (ValueError, TypeError) as exc:
                rows.append((number, {"_unparsed": line[:MAX_RECORD_BYTES]}, str(exc)))
            if len(rows) > MAX_ROWS:
                raise ValueError("file exceeds 10,000 records")
    else:
        try:
            reader = csv.DictReader(io.StringIO(text), strict=True)
            if reader.fieldnames and (len(set(reader.fieldnames)) != len(reader.fieldnames)
                                      or any(not name for name in reader.fieldnames)):
                raise ValueError("CSV headers must be unique and nonempty")
            for record in reader:
                error = "CSV column count mismatch" if None in record or None in record.values() else None
                if None in record:
                    record["_extra_columns"] = record.pop(None)
                if len(json_bytes(record)) > MAX_RECORD_BYTES:
                    error = "record exceeds 64 KiB"
                rows.append((reader.line_num, record, error))
                if len(rows) > MAX_ROWS:
                    raise ValueError("file exceeds 10,000 records")
        except csv.Error as exc:
            raise ValueError(f"malformed CSV: {exc}") from exc
    return rows
