import pytest

from src.risk_scorer import RiskScorer


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, "INFORMATIONAL"),
        (19, "INFORMATIONAL"),
        (20, "LOW"),
        (39, "LOW"),
        (40, "MEDIUM"),
        (64, "MEDIUM"),
        (65, "HIGH"),
        (84, "HIGH"),
        (85, "CRITICAL"),
        (100, "CRITICAL"),
    ],
)
def test_severity_boundaries(score, expected):
    assert RiskScorer.severity_for(score) == expected


def test_scores_known_rule_and_does_not_mutate_input():
    finding = {"rule_id": "NET-001", "evidence": {"unique_destination_ports": 10}}
    scored = RiskScorer().score_finding(finding)

    assert scored["risk_score"] == 55
    assert scored["severity"] == "MEDIUM"
    assert "risk_score" not in finding
    assert scored["risk_factors"]


def test_adds_sensitive_port_adjustment():
    finding = {
        "rule_id": "NET-004",
        "destination_port": 22,
        "evidence": {"destination_port": 22},
    }
    scored = RiskScorer().score_finding(finding)
    assert scored["risk_score"] == 55
    assert scored["severity"] == "MEDIUM"


def test_adds_rejected_flow_adjustment():
    finding = {
        "rule_id": "NET-006",
        "evidence": {"destination_port": 443, "flow_action": "REJECT"},
    }
    scored = RiskScorer().score_finding(finding)
    assert scored["risk_score"] == 50


def test_score_is_capped_at_100():
    finding = {
        "rule_id": "NET-001",
        "evidence": {"unique_destination_ports": 25, "destination_port": 22,
                     "flow_action": "REJECT"},
    }
    scored = RiskScorer().score_finding(finding)
    assert scored["risk_score"] == 80  # 55 + 10 + 10 + 5
    assert scored["risk_score"] <= 100


def test_unknown_rule_uses_default_base_score():
    scored = RiskScorer().score_finding({"rule_id": "NET-UNKNOWN"})
    assert scored["risk_score"] == 30
    assert scored["severity"] == "LOW"


@pytest.mark.parametrize("invalid", [-1, 101, 2.5, "50"])
def test_custom_base_scores_must_be_integer_between_zero_and_100(invalid):
    with pytest.raises(ValueError):
        RiskScorer(rule_base_scores={"NET-X": invalid})
