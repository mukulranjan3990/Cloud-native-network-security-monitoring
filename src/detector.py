"""Explainable, threshold-based detections for normalized security events.

These detections are heuristics. A finding indicates suspicious activity, not
proof that an attack occurred. Tune thresholds against the project's lab data.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


SENSITIVE_PORTS = {22, 3389, 3306, 5432, 6379, 27017}
SECURITY_GROUP_CHANGE_EVENTS = {
    "AuthorizeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupIngress",
    "RevokeSecurityGroupEgress",
    "ModifySecurityGroupRules",
    "UpdateSecurityGroupRuleDescriptionsIngress",
    "UpdateSecurityGroupRuleDescriptionsEgress",
}
SUSPICIOUS_ADMIN_EVENTS = {
    "CreateAccessKey",
    "CreateLoginProfile",
    "PutUserPolicy",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutRolePolicy",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
}


def _event_epoch(event: Mapping[str, Any]) -> Optional[float]:
    """Return event time in seconds for window calculations."""
    for key in ("end_time", "start_time"):
        value = event.get(key)
        if isinstance(value, (int, float)):
            return float(value)

    value = event.get("timestamp")
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except ValueError:
        return None


def _finding(
    rule_id: str,
    title: str,
    description: str,
    event: Mapping[str, Any],
    evidence: Mapping[str, Any],
    recommendation: str,
    mitre_attack: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "rule_id": rule_id,
        "title": title,
        "description": description,
        "timestamp": event.get("timestamp"),
        "source_ip": event.get("source_ip"),
        "destination_ip": event.get("destination_ip"),
        "destination_port": event.get("destination_port"),
        "resource": event.get("interface_id") or event.get("resource"),
        "evidence": dict(evidence),
        "recommendation": recommendation,
        "mitre_attack": mitre_attack,
        "status": "OPEN",
    }


class ThreatDetector:
    """Evaluate normalized events against the project's initial rule set."""

    def __init__(
        self,
        port_scan_min_ports: int = 10,
        port_scan_window_seconds: int = 60,
        repeated_attempt_min_count: int = 20,
        repeated_attempt_window_seconds: int = 300,
        rejected_min_count: int = 100,
        rejected_window_seconds: int = 3600,
        high_traffic_bytes: int = 500 * 1024 * 1024,
        sensitive_ports: Optional[Iterable[int]] = None,
    ) -> None:
        if min(
            port_scan_min_ports,
            port_scan_window_seconds,
            repeated_attempt_min_count,
            repeated_attempt_window_seconds,
            rejected_min_count,
            rejected_window_seconds,
            high_traffic_bytes,
        ) <= 0:
            raise ValueError("Detection thresholds must all be positive.")

        self.port_scan_min_ports = port_scan_min_ports
        self.port_scan_window_seconds = port_scan_window_seconds
        self.repeated_attempt_min_count = repeated_attempt_min_count
        self.repeated_attempt_window_seconds = repeated_attempt_window_seconds
        self.rejected_min_count = rejected_min_count
        self.rejected_window_seconds = rejected_window_seconds
        self.high_traffic_bytes = high_traffic_bytes
        self.sensitive_ports = set(sensitive_ports or SENSITIVE_PORTS)

    def detect(self, events: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        """Return findings from a batch of normalized network/AWS API events."""
        batch = [dict(event) for event in events]
        findings: List[Dict[str, Any]] = []

        network_events = [
            event for event in batch if event.get("event_type") == "NETWORK_FLOW"
        ]
        api_events = [
            event for event in batch if event.get("event_type") == "AWS_API"
        ]

        findings.extend(self._detect_port_scans(network_events))
        findings.extend(self._detect_repeated_attempts(network_events))
        findings.extend(self._detect_rejected_traffic(network_events))
        findings.extend(self._detect_sensitive_ports(network_events))
        findings.extend(self._detect_high_traffic(network_events))
        findings.extend(self._detect_api_activity(api_events))

        return findings

    def _detect_port_scans(
        self, events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        by_source: Dict[str, List[Tuple[float, Dict[str, Any]]]] = defaultdict(list)
        for event in events:
            source = event.get("source_ip")
            epoch = _event_epoch(event)
            port = event.get("destination_port")
            if source and epoch is not None and isinstance(port, int):
                by_source[str(source)].append((epoch, event))

        findings = []
        for source, entries in by_source.items():
            entries.sort(key=lambda item: item[0])
            left = 0
            for right, (epoch, event) in enumerate(entries):
                while epoch - entries[left][0] > self.port_scan_window_seconds:
                    left += 1
                window = [item[1] for item in entries[left : right + 1]]
                ports = sorted({
                    item.get("destination_port")
                    for item in window
                    if isinstance(item.get("destination_port"), int)
                })
                hosts = sorted({
                    item.get("destination_ip")
                    for item in window
                    if item.get("destination_ip")
                })
                if len(ports) >= self.port_scan_min_ports:
                    findings.append(
                        _finding(
                            "NET-001",
                            "Possible Port Scan",
                            "One source contacted multiple destination ports in a short time window.",
                            event,
                            {
                                "source_ip": source,
                                "unique_destination_ports": len(ports),
                                "destination_ports": ports,
                                "destination_hosts": hosts,
                                "window_seconds": self.port_scan_window_seconds,
                            },
                            "Investigate the source and review exposed services and security-group rules.",
                            "T1046",
                        )
                    )
                    break  # One finding per source for this batch.
        return findings

    def _detect_repeated_attempts(
        self, events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        groups: Dict[Tuple[Any, Any, Any], List[Dict[str, Any]]] = defaultdict(list)
        for event in events:
            key = (
                event.get("source_ip"),
                event.get("destination_ip"),
                event.get("destination_port"),
            )
            if all(value is not None for value in key):
                groups[key].append(event)

        findings = []
        for (source, destination, port), group in groups.items():
            timed = [( _event_epoch(event), event) for event in group]
            timed = sorted(
                [(epoch, event) for epoch, event in timed if epoch is not None],
                key=lambda item: item[0],
            )
            if not timed:
                continue
            left = 0
            triggered = False
            for right, (epoch, event) in enumerate(timed):
                while epoch - timed[left][0] > self.repeated_attempt_window_seconds:
                    left += 1
                count = right - left + 1
                if count >= self.repeated_attempt_min_count:
                    findings.append(
                        _finding(
                            "NET-004",
                            "Suspicious Repeated Connection Activity",
                            "Repeated connections were observed from the same source to the same destination and port.",
                            event,
                            {
                                "source_ip": source,
                                "destination_ip": destination,
                                "destination_port": port,
                                "attempt_count": count,
                                "window_seconds": self.repeated_attempt_window_seconds,
                            },
                            "Review the destination service and relevant authentication/application logs. Repeated connections alone do not prove brute-force activity.",
                        )
                    )
                    triggered = True
                    break
            if triggered:
                continue
        return findings

    def _detect_rejected_traffic(
        self, events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        groups: Dict[str, List[Tuple[float, Dict[str, Any]]]] = defaultdict(list)
        for event in events:
            source = event.get("source_ip")
            epoch = _event_epoch(event)
            if source and epoch is not None and str(event.get("action", "")).upper() == "REJECT":
                groups[str(source)].append((epoch, event))

        findings = []
        for source, entries in groups.items():
            entries.sort(key=lambda item: item[0])
            left = 0
            for right, (epoch, event) in enumerate(entries):
                while epoch - entries[left][0] > self.rejected_window_seconds:
                    left += 1
                count = right - left + 1
                if count >= self.rejected_min_count:
                    findings.append(
                        _finding(
                            "NET-005",
                            "Excessive Rejected Traffic",
                            "A source generated an unusually high number of rejected network flows.",
                            event,
                            {
                                "source_ip": source,
                                "rejected_flow_count": count,
                                "window_seconds": self.rejected_window_seconds,
                            },
                            "Review flow records, security-group rules, and expected traffic patterns.",
                        )
                    )
                    break
        return findings

    def _detect_sensitive_ports(
        self, events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        findings = []
        seen = set()
        for event in events:
            port = event.get("destination_port")
            if port not in self.sensitive_ports:
                continue
            key = (event.get("source_ip"), event.get("destination_ip"), port)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                _finding(
                    "NET-006",
                    "Connection to Sensitive Administrative Port",
                    "Traffic targeted a commonly sensitive administrative or database port.",
                    event,
                    {
                        "source_ip": event.get("source_ip"),
                        "destination_ip": event.get("destination_ip"),
                        "destination_port": port,
                        "flow_action": event.get("action"),
                    },
                    "Confirm that the source is authorized and that the destination port is not unnecessarily exposed.",
                )
            )
        return findings

    def _detect_high_traffic(
        self, events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        findings = []
        for event in events:
            byte_count = event.get("bytes")
            if isinstance(byte_count, int) and byte_count >= self.high_traffic_bytes:
                findings.append(
                    _finding(
                        "NET-007",
                        "Unusually High Traffic Volume",
                        "A single flow exceeded the configured traffic-volume threshold.",
                        event,
                        {
                            "observed_bytes": byte_count,
                            "threshold_bytes": self.high_traffic_bytes,
                        },
                        "Validate the workload and investigate unexpected data transfer. This threshold is a simple heuristic, not a learned baseline.",
                    )
                )
        return findings

    def _detect_api_activity(
        self, events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        findings = []
        for event in events:
            event_name = event.get("event_name")
            if event_name in SECURITY_GROUP_CHANGE_EVENTS:
                findings.append(
                    _finding(
                        "NET-009",
                        "Security Group Modification",
                        "CloudTrail recorded a security-group rule modification event.",
                        event,
                        {
                            "event_name": event_name,
                            "event_source": event.get("event_source"),
                            "source_ip": event.get("source_ip"),
                            "request_parameters": event.get("resource"),
                        },
                        "Verify the change against an approved change request and inspect the resulting inbound/outbound rules.",
                    )
                )
            elif event_name in SUSPICIOUS_ADMIN_EVENTS:
                findings.append(
                    _finding(
                        "NET-008",
                        "Sensitive AWS Administrative Activity",
                        "CloudTrail recorded an IAM or access-management event that should be reviewed.",
                        event,
                        {
                            "event_name": event_name,
                            "event_source": event.get("event_source"),
                            "source_ip": event.get("source_ip"),
                            "user_arn": event.get("user_arn"),
                        },
                        "Confirm the actor, authorization, and business reason for the IAM change.",
                    )
                )
        return findings
