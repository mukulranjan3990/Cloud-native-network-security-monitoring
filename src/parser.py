"""Parse AWS VPC Flow Logs and selected CloudTrail events into one schema."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence


DEFAULT_FLOW_LOG_FIELDS = [
    "version",
    "account_id",
    "interface_id",
    "srcaddr",
    "dstaddr",
    "srcport",
    "dstport",
    "protocol",
    "packets",
    "bytes",
    "start",
    "end",
    "action",
    "log_status",
]


def _to_int(value: Any) -> Optional[int]:
    if value is None or value == "-" or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _iso_from_epoch(value: Any) -> Optional[str]:
    epoch = _to_int(value)
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


def _cloudwatch_timestamp(raw: Optional[Mapping[str, Any]]) -> Optional[str]:
    if not raw:
        return None
    timestamp_ms = raw.get("timestamp_ms")
    if timestamp_ms is None:
        return None
    try:
        return datetime.fromtimestamp(
            int(timestamp_ms) / 1000, tz=timezone.utc
        ).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def parse_flow_log(
    message: str,
    timestamp: Optional[str] = None,
    fields: Optional[Sequence[str]] = None,
    metadata: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Parse a whitespace-delimited VPC Flow Log record.

    `fields` must match the exact custom format configured for the flow log.
    Without it, the AWS standard version 2 field order is used.
    """
    if not isinstance(message, str):
        raise TypeError("Flow log message must be a string.")

    values = message.strip().split()
    if not values:
        raise ValueError("Flow log message is empty.")

    field_names = list(fields or DEFAULT_FLOW_LOG_FIELDS)
    if len(values) != len(field_names):
        raise ValueError(
            f"Flow log has {len(values)} values but {len(field_names)} fields "
            "were configured. Check the VPC Flow Logs format."
        )

    raw = dict(zip(field_names, values))
    start_epoch = _to_int(raw.get("start"))
    end_epoch = _to_int(raw.get("end"))
    event_timestamp = timestamp or _iso_from_epoch(end_epoch) or _iso_from_epoch(start_epoch)

    event: Dict[str, Any] = {
        "event_type": "NETWORK_FLOW",
        "timestamp": event_timestamp,
        "account_id": raw.get("account_id"),
        "interface_id": raw.get("interface_id"),
        "source_ip": raw.get("srcaddr"),
        "destination_ip": raw.get("dstaddr"),
        "source_port": _to_int(raw.get("srcport")),
        "destination_port": _to_int(raw.get("dstport")),
        "protocol": _to_int(raw.get("protocol")),
        "packets": _to_int(raw.get("packets")),
        "bytes": _to_int(raw.get("bytes")),
        "start_time": start_epoch,
        "end_time": end_epoch,
        "action": raw.get("action"),
        "log_status": raw.get("log_status"),
        "raw": raw,
    }

    if metadata:
        event["collector_metadata"] = dict(metadata)
    return event


def parse_cloudtrail_event(
    payload: Mapping[str, Any],
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Normalize one CloudTrail event without treating it as a network flow."""
    event_time = payload.get("eventTime")
    normalized_time = timestamp or (
        str(event_time) if event_time is not None else None
    )

    user_identity = payload.get("userIdentity") or {}
    source_ip = payload.get("sourceIPAddress")
    event_source = payload.get("eventSource")
    event_name = payload.get("eventName")

    return {
        "event_type": "AWS_API",
        "timestamp": normalized_time,
        "source_ip": source_ip,
        "destination_ip": None,
        "source_port": None,
        "destination_port": None,
        "protocol": None,
        "packets": None,
        "bytes": None,
        "action": None,
        "account_id": payload.get("recipientAccountId"),
        "interface_id": None,
        "event_source": event_source,
        "event_name": event_name,
        "aws_region": payload.get("awsRegion"),
        "user_arn": user_identity.get("arn"),
        "user_type": user_identity.get("type"),
        "resource": payload.get("requestParameters"),
        "raw": dict(payload),
    }


def parse_event(
    raw_event: Any,
    flow_log_fields: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Parse a CloudWatch collector record, JSON CloudTrail event, or flow line."""
    metadata: Optional[Mapping[str, Any]] = None
    timestamp: Optional[str] = None

    if isinstance(raw_event, Mapping):
        message = raw_event.get("message")
        metadata = {
            key: value
            for key, value in raw_event.items()
            if key != "message"
        }
        timestamp = _cloudwatch_timestamp(raw_event)
        if message is None:
            # A CloudTrail event may be passed directly as a decoded dictionary.
            if "eventSource" in raw_event or "eventName" in raw_event:
                return parse_cloudtrail_event(raw_event)
            raise ValueError("Mapping input must contain a 'message' field.")

        raw_text = str(message)
    elif isinstance(raw_event, str):
        raw_text = raw_event
    else:
        raise TypeError("raw_event must be a string or mapping.")

    stripped = raw_text.strip()
    if not stripped:
        raise ValueError("Raw event message is empty.")

    if stripped.startswith("{"):
        try:
            decoded = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError("Event looks like JSON but is invalid.") from exc
        if not isinstance(decoded, dict):
            raise ValueError("JSON event must be an object.")
        if "eventSource" in decoded or "eventName" in decoded:
            return parse_cloudtrail_event(decoded, timestamp=timestamp)
        # Some log envelopes wrap the actual CloudTrail record.
        if isinstance(decoded.get("Records"), list):
            raise ValueError(
                "This is a CloudTrail Records envelope. Pass individual Records "
                "entries to parse_event."
            )
        raise ValueError("JSON object is not a recognized CloudTrail event.")

    return parse_flow_log(
        stripped,
        timestamp=timestamp,
        fields=flow_log_fields,
        metadata=metadata,
    )


class EventParser:
    """Small object wrapper for parsing batches of collected log events."""

    def __init__(self, flow_log_fields: Optional[Sequence[str]] = None) -> None:
        self.flow_log_fields = list(flow_log_fields) if flow_log_fields else None

    def parse(self, raw_event: Any) -> Dict[str, Any]:
        return parse_event(raw_event, flow_log_fields=self.flow_log_fields)

    def parse_many(self, raw_events: Iterable[Any]) -> List[Dict[str, Any]]:
        parsed = []
        for raw_event in raw_events:
            parsed.append(self.parse(raw_event))
        return parsed
