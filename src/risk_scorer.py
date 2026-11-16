"""Transparent risk scoring for security findings."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping


RULE_BASE_SCORES = {
    "NET-001": 55,  # Possible port scan
    "NET-002": 75,  # Internet-exposed SSH (when a future rule supplies it)
    "NET-003": 75,  # Internet-exposed RDP (when a future rule supplies it)
    "NET-004": 45,  # Repeated connections
    "NET-005": 55,  # Excessive rejected traffic
    "NET-006": 45,  # Sensitive port targeted
    "NET-007": 50,  # High traffic
    "NET-008": 70,  # Sensitive AWS administrative activity
    "NET-009": 80,  # Security group modification
}


class RiskScorer:
    """Assign a 0-100 heuristic score and severity to each finding.

    The score is a project-defined prioritization heuristic, not an
    industry-standard risk score or a probability that an attack occurred.
    """

    def __init__(self, rule_base_scores: Mapping[str, int] | None = None) -> None:
        self.rule_base_scores = dict(RULE_BASE_SCORES)
        if rule_base_scores:
            for rule_id, score in rule_base_scores.items():
                if not isinstance(score, int) or not 0 <= score <= 100:
                    raise ValueError("Rule base scores must be integers from 0 to 100.")
                self.rule_base_scores[rule_id] = score

    @staticmethod
    def severity_for(score: int) -> str:
        if score >= 85:
            return "CRITICAL"
        if score >= 65:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        if score >= 20:
            return "LOW"
        return "INFORMATIONAL"

    def score_finding(self, finding: Mapping[str, Any]) -> Dict[str, Any]:
        """Return a copy of a finding enriched with score and severity."""
        scored = dict(finding)
        rule_id = str(scored.get("rule_id", ""))
        score = self.rule_base_scores.get(rule_id, 30)
        reasons = [f"Base score for {rule_id or 'unknown rule'}: {score}"]

        evidence = scored.get("evidence") or {}
        port = evidence.get("destination_port", scored.get("destination_port"))

        # Small, explicit context adjustments. Keep the result explainable.
        if port in {22, 3389}:
            score += 10
            reasons.append("Sensitive remote-administration port: +10")
        if str(evidence.get("flow_action", "")).upper() == "REJECT":
            score += 5
            reasons.append("Rejected flow evidence: +5")
        if rule_id == "NET-001" and evidence.get("unique_destination_ports", 0) >= 20:
            score += 10
            reasons.append("At least 20 unique destination ports: +10")
        if rule_id == "NET-009":
            params = evidence.get("request_parameters")
            params_text = str(params).replace(" ", "")
            if "0.0.0.0/0" in params_text or "::/0" in params_text:
                score += 10
                reasons.append("Request parameters include a world-open CIDR: +10")

        score = max(0, min(100, score))
        scored["risk_score"] = score
        scored["severity"] = self.severity_for(score)
        scored["risk_factors"] = reasons
        return scored

    def score_findings(
        self, findings: Iterable[Mapping[str, Any]]
    ) -> List[Dict[str, Any]]:
        return [self.score_finding(finding) for finding in findings]
