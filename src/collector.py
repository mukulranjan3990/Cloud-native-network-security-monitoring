"""Collect VPC Flow Log events from Amazon CloudWatch Logs.

AWS credentials are resolved by the standard Boto3 credential chain. Do not
put access keys or secret keys in this file.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional


class CloudWatchLogCollector:
    """Read log events from one CloudWatch Logs log group.

    Example:
        collector = CloudWatchLogCollector(log_group_name="/aws/vpc/flow-logs")
        records = collector.fetch_events(start_time_ms, end_time_ms)
    """

    def __init__(
        self,
        log_group_name: Optional[str] = None,
        region_name: Optional[str] = None,
        client: Any = None,
    ) -> None:
        self.log_group_name = log_group_name or os.getenv("AWS_FLOW_LOG_GROUP")
        if not self.log_group_name:
            raise ValueError(
                "Provide log_group_name or set AWS_FLOW_LOG_GROUP."
            )

        self.region_name = region_name or os.getenv("AWS_REGION")
        self._client = client

    @property
    def client(self) -> Any:
        """Create the Boto3 client lazily, allowing tests to inject a fake."""
        if self._client is None:
            try:
                import boto3
            except ImportError as exc:
                raise RuntimeError(
                    "Boto3 is required for AWS collection. Install it with "
                    "'pip install boto3'."
                ) from exc

            kwargs = {}
            if self.region_name:
                kwargs["region_name"] = self.region_name
            self._client = boto3.client("logs", **kwargs)

        return self._client

    def fetch_events(
        self,
        start_time_ms: int,
        end_time_ms: int,
        filter_pattern: str = "",
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch events in the half-open CloudWatch time range.

        CloudWatch expects Unix timestamps in milliseconds. The returned
        dictionaries retain the original message and CloudWatch metadata.
        """
        if not isinstance(start_time_ms, int) or not isinstance(end_time_ms, int):
            raise TypeError("start_time_ms and end_time_ms must be integers.")
        if start_time_ms < 0 or end_time_ms <= start_time_ms:
            raise ValueError("The time range must be valid and end after start.")
        if limit is not None and limit <= 0:
            raise ValueError("limit must be greater than zero.")

        collected: List[Dict[str, Any]] = []
        next_token: Optional[str] = None

        while True:
            remaining = None if limit is None else limit - len(collected)
            if remaining is not None and remaining <= 0:
                break

            request: Dict[str, Any] = {
                "logGroupName": self.log_group_name,
                "startTime": start_time_ms,
                "endTime": end_time_ms,
            }
            if filter_pattern:
                request["filterPattern"] = filter_pattern
            if next_token:
                request["nextToken"] = next_token

            # CloudWatch FilterLogEvents accepts at most 10,000 events per call.
            request["limit"] = min(10000, remaining) if remaining else 10000
            response = self.client.filter_log_events(**request)

            for event in response.get("events", []):
                collected.append(
                    {
                        "timestamp_ms": event.get("timestamp"),
                        "ingestion_time_ms": event.get("ingestionTime"),
                        "log_stream": event.get("logStreamName"),
                        "event_id": event.get("eventId"),
                        "message": event.get("message", ""),
                    }
                )
                if limit is not None and len(collected) >= limit:
                    return collected

            new_token = response.get("nextToken")
            if not new_token or new_token == next_token:
                break
            next_token = new_token

        return collected

    def collect(
        self,
        start_time_ms: int,
        end_time_ms: int,
        filter_pattern: str = "",
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Alias for fetch_events, useful to pipeline callers."""
        return self.fetch_events(
            start_time_ms=start_time_ms,
            end_time_ms=end_time_ms,
            filter_pattern=filter_pattern,
            limit=limit,
        )
