from src.detector import ThreatDetector


def flow(source, destination, port, epoch, action="ACCEPT", byte_count=100):
    return {
        "event_type": "NETWORK_FLOW",
        "timestamp": f"2025-01-01T00:00:{epoch:02d}+00:00",
        "start_time": epoch,
        "end_time": epoch,
        "source_ip": source,
        "destination_ip": destination,
        "destination_port": port,
        "action": action,
        "bytes": byte_count,
        "interface_id": "eni-test",
    }


def test_detects_possible_port_scan():
    events = [flow("198.51.100.7", "10.0.0.5", port, i)
              for i, port in enumerate((21, 22, 23, 25), start=1)]
    detector = ThreatDetector(port_scan_min_ports=4)

    findings = detector.detect(events)

    scan = [item for item in findings if item["rule_id"] == "NET-001"]
    assert len(scan) == 1
    assert scan[0]["evidence"]["unique_destination_ports"] == 4
    assert scan[0]["mitre_attack"] == "T1046"


def test_port_scan_does_not_trigger_below_threshold():
    events = [flow("198.51.100.7", "10.0.0.5", port, i)
              for i, port in enumerate((21, 22, 23), start=1)]
    findings = ThreatDetector(port_scan_min_ports=4).detect(events)
    assert not any(item["rule_id"] == "NET-001" for item in findings)


def test_detects_repeated_connections():
    events = [flow("198.51.100.8", "10.0.0.8", 443, i)
              for i in range(1, 5)]
    findings = ThreatDetector(
        repeated_attempt_min_count=4,
        port_scan_min_ports=20,
    ).detect(events)

    repeated = [item for item in findings if item["rule_id"] == "NET-004"]
    assert len(repeated) == 1
    assert repeated[0]["evidence"]["attempt_count"] == 4
    assert "do not prove brute-force" in repeated[0]["recommendation"]


def test_detects_rejected_traffic_threshold():
    events = [flow("203.0.113.9", "10.0.0.9", 8080, i, action="REJECT")
              for i in range(1, 4)]
    findings = ThreatDetector(
        rejected_min_count=3,
        port_scan_min_ports=20,
    ).detect(events)

    rejected = [item for item in findings if item["rule_id"] == "NET-005"]
    assert len(rejected) == 1
    assert rejected[0]["evidence"]["rejected_flow_count"] == 3


def test_detects_sensitive_destination_port_once_per_tuple():
    events = [
        flow("10.0.0.1", "10.0.0.2", 22, 1),
        flow("10.0.0.1", "10.0.0.2", 22, 2),
    ]
    findings = ThreatDetector(port_scan_min_ports=20).detect(events)
    sensitive = [item for item in findings if item["rule_id"] == "NET-006"]
    assert len(sensitive) == 1
    assert sensitive[0]["destination_port"] == 22


def test_detects_high_volume_single_flow():
    event = flow("10.0.0.1", "10.0.0.2", 443, 1, byte_count=2_000)
    findings = ThreatDetector(high_traffic_bytes=1_000).detect([event])
    assert any(item["rule_id"] == "NET-007" for item in findings)


def test_detects_security_group_cloudtrail_event():
    event = {
        "event_type": "AWS_API",
        "event_name": "AuthorizeSecurityGroupIngress",
        "event_source": "ec2.amazonaws.com",
        "source_ip": "198.51.100.4",
        "resource": {"ipPermissions": []},
    }
    findings = ThreatDetector().detect([event])
    assert any(item["rule_id"] == "NET-009" for item in findings)


def test_thresholds_must_be_positive():
    import pytest

    with pytest.raises(ValueError, match="positive"):
        ThreatDetector(port_scan_min_ports=0)
