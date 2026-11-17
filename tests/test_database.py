import pytest

from src.database import SecurityDatabase


@pytest.fixture
def database(tmp_path):
    return SecurityDatabase(str(tmp_path / "test_security.db"))


def sample_event(source_ip="10.0.0.1"):
    return {
        "event_type": "NETWORK_FLOW",
        "timestamp": "2025-01-01T00:00:00+00:00",
        "source_ip": source_ip,
        "destination_ip": "10.0.0.2",
        "destination_port": 443,
        "action": "ACCEPT",
        "bytes": 1200,
    }


def sample_finding(rule_id="NET-001", severity="MEDIUM", timestamp="2025-01-01T00:00:00Z"):
    return {
        "rule_id": rule_id,
        "title": "Possible Port Scan",
        "description": "Multiple destination ports contacted.",
        "timestamp": timestamp,
        "source_ip": "198.51.100.7",
        "destination_ip": "10.0.0.2",
        "destination_port": 443,
        "severity": severity,
        "risk_score": 55,
        "status": "OPEN",
        "recommendation": "Investigate the source.",
        "evidence": {"unique_destination_ports": 10},
    }


def test_database_initializes_and_inserts_one_event(database):
    event_id = database.insert_event(sample_event())
    assert event_id > 0
    events = database.get_recent_events()
    assert len(events) == 1
    assert events[0]["payload"]["source_ip"] == "10.0.0.1"


def test_insert_events_returns_inserted_count(database):
    count = database.insert_events([sample_event(), sample_event("10.0.0.3")])
    assert count == 2
    assert len(database.get_recent_events()) == 2


def test_empty_event_batch_returns_zero(database):
    assert database.insert_events([]) == 0


def test_finding_insert_is_idempotent(database):
    finding = sample_finding()
    first_id = database.insert_finding(finding)
    second_id = database.insert_finding(finding)

    assert first_id == second_id
    assert len(database.get_findings()) == 1
    assert database.insert_findings([finding]) == 0


def test_insert_findings_counts_new_rows(database):
    first = sample_finding()
    second = sample_finding(rule_id="NET-005", severity="HIGH")
    assert database.insert_findings([first, second]) == 2
    assert database.insert_findings([first, second]) == 0


def test_get_findings_filters_by_severity_and_status(database):
    database.insert_finding(sample_finding(severity="MEDIUM"))
    high = sample_finding(rule_id="NET-005", severity="HIGH")
    high["status"] = "INVESTIGATING"
    database.insert_finding(high)

    assert len(database.get_findings(severity="high")) == 1
    assert len(database.get_findings(status="investigating")) == 1
    assert len(database.get_findings(severity="MEDIUM", status="OPEN")) == 1


def test_update_finding_status_and_reject_invalid_status(database):
    finding_id = database.insert_finding(sample_finding())
    assert database.update_finding_status(finding_id, "investigating") is True
    assert database.get_findings()[0]["status"] == "INVESTIGATING"
    assert database.update_finding_status(99999, "CLOSED") is False

    with pytest.raises(ValueError, match="status"):
        database.update_finding_status(finding_id, "UNKNOWN")


def test_summary_counts_events_and_findings(database):
    database.insert_events([sample_event(), sample_event("10.0.0.3")])
    database.insert_finding(sample_finding(severity="MEDIUM"))
    database.insert_finding(sample_finding(rule_id="NET-009", severity="CRITICAL"))

    summary = database.get_summary()
    assert summary["total_events"] == 2
    assert summary["total_findings"] == 2
    assert summary["medium"] == 1
    assert summary["critical"] == 1
    assert summary["open"] == 2


@pytest.mark.parametrize("method_name", ["get_findings", "get_recent_events"])
def test_read_methods_reject_non_positive_limit(database, method_name):
    method = getattr(database, method_name)
    with pytest.raises(ValueError, match="limit"):
        method(limit=0)
