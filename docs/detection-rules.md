# Detection Rules

## 1. Purpose

This document describes the rule identifiers, evidence, thresholds, expected behavior, and limitations of the project detector.

All rules are explainable heuristics. A triggered rule means that observed data matches a configured condition; it does not prove malicious intent.

## 2. Implementation Status

| Rule | Name | Status in current detector | Required telemetry |
|---|---|---|---|
| NET-001 | Possible Port Scan | Implemented | VPC Flow Logs |
| NET-002 | Internet-Exposed SSH | Planned | EC2 Security Group configuration |
| NET-003 | Internet-Exposed RDP | Planned | EC2 Security Group configuration |
| NET-004 | Repeated Connection Attempts | Implemented | VPC Flow Logs |
| NET-005 | Excessive Rejected Traffic | Implemented | VPC Flow Logs |
| NET-006 | Suspicious Administrative Port | Implemented | VPC Flow Logs |
| NET-007 | Unusual Traffic Volume | Implemented with fixed single-flow threshold | VPC Flow Logs |
| NET-008 | Unusual AWS API Activity | Implemented for selected event names | CloudTrail management events |
| NET-009 | Security Group Modification | Implemented for selected event names | CloudTrail management events |
| NET-010 | Repeated Authentication Failure | Planned | OS/application authentication logs |

The YAML rule file is currently a declarative specification. The Python detector uses corresponding code defaults; it does not yet load the YAML file at runtime. Editing YAML alone will not change detector behavior.

## 3. Implemented Rules

### NET-001 — Possible Port Scan

- **Purpose:** Identify one source contacting many unique destination ports within a short time window.
- **Input:** `NETWORK_FLOW`.
- **Default threshold:** At least 10 unique destination ports from one source within 60 seconds.
- **Grouping:** Source IP.
- **Evidence:** Source IP, destination IP(s), destination ports, timestamps, unique-port count, and window.
- **Severity reference:** HIGH in the rule specification; final severity is derived from the risk score.
- **MITRE ATT&CK:** T1046 — Network Service Discovery.
- **Recommendation:** Investigate the source and review exposed services and security-group rules.
- **Limitations:** Scan-like traffic may be authorized inventory, health checking, or testing. The current implementation emits at most one NET-001 finding per source per batch.

### NET-004 — Repeated Connection Attempts

- **Purpose:** Identify repeated connections from one source to the same destination and port.
- **Input:** `NETWORK_FLOW`.
- **Default threshold:** At least 20 records within 300 seconds.
- **Grouping:** Source IP, destination IP, destination port.
- **Evidence:** Attempt count, source/destination, destination port, and time window.
- **Recommendation:** Review the destination service and relevant authentication/application logs.
- **Limitations:** Repeated network connections do not prove repeated login failures or brute-force activity. Authentication logs are needed to support that conclusion.

### NET-005 — Excessive Rejected Traffic

- **Purpose:** Identify a high number of rejected flow records from one source.
- **Input:** `NETWORK_FLOW` where action is `REJECT`.
- **Default threshold:** At least 100 rejected flow records within 3,600 seconds.
- **Grouping:** Source IP.
- **Evidence:** Rejected-flow count, source, and time window.
- **Recommendation:** Review flow records, security-group rules, network ACLs, and expected traffic.
- **Limitations:** The detector counts flow records, not individual packets. The threshold is an initial heuristic and should be tuned to the lab.

### NET-006 — Suspicious Administrative Port

- **Purpose:** Flag flows targeting selected sensitive administrative or database ports.
- **Input:** `NETWORK_FLOW`.
- **Ports:** 22 (SSH), 3389 (RDP), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 27017 (MongoDB).
- **Evidence:** Source IP, destination IP, destination port, and flow action.
- **Recommendation:** Confirm that the source is authorized and the destination service is not unnecessarily exposed.
- **Limitations:** A connection to one of these ports is not inherently malicious. Expected source, destination, and workload context matter.

### NET-007 — Unusual Traffic Volume

- **Purpose:** Flag an individual flow whose byte count exceeds a fixed threshold.
- **Input:** `NETWORK_FLOW`.
- **Default threshold:** 500 MiB (`524,288,000` bytes) for one flow.
- **Evidence:** Source, destination, byte count, and threshold.
- **Recommendation:** Validate the workload and investigate unexpected data transfer.
- **Limitations:** This is not an hourly aggregate, learned baseline, or machine-learning anomaly detector. A legitimate backup or data-processing task may exceed the threshold.

### NET-008 — Unusual AWS API Activity

- **Purpose:** Identify selected IAM/access-management API event names.
- **Input:** `AWS_API` derived from CloudTrail.
- **Selected event names:** `CreateAccessKey`, `CreateLoginProfile`, `PutUserPolicy`, `AttachUserPolicy`, `AttachRolePolicy`, `PutRolePolicy`, `CreatePolicyVersion`, `SetDefaultPolicyVersion`.
- **Evidence:** Event name, event source, source IP, and user identity where present.
- **Recommendation:** Confirm the actor, authorization, and business reason for the IAM change.
- **Limitations:** These events may be legitimate administrative work. CloudTrail collection/ingestion must be configured separately.

### NET-009 — Security Group Modification

- **Purpose:** Identify selected security-group modification API events.
- **Input:** `AWS_API` derived from CloudTrail.
- **Selected event names:** `AuthorizeSecurityGroupIngress`, `AuthorizeSecurityGroupEgress`, `RevokeSecurityGroupIngress`, `RevokeSecurityGroupEgress`, `ModifySecurityGroupRules`, `UpdateSecurityGroupRuleDescriptionsIngress`, `UpdateSecurityGroupRuleDescriptionsEgress`.
- **Evidence:** Event name, event source, source IP, and request parameters/resource details where present.
- **Recommendation:** Verify the change against an approved change request and inspect the resulting security-group rules.
- **Limitations:** Detecting a modification API event does not independently verify the final effective configuration. CloudTrail ingestion must be configured separately.

## 4. Planned Rules

### NET-002 — Internet-Exposed SSH

- **Condition:** Security-group ingress permits TCP port 22 from `0.0.0.0/0` or `::/0`.
- **Required data:** EC2 Security Group configuration.
- **Suggested severity:** HIGH; potentially CRITICAL depending on asset/context.
- **Status:** Not implemented in the current Flow Logs detector.

### NET-003 — Internet-Exposed RDP

- **Condition:** Security-group ingress permits TCP port 3389 from `0.0.0.0/0` or `::/0`.
- **Required data:** EC2 Security Group configuration.
- **Suggested severity:** HIGH; potentially CRITICAL depending on asset/context.
- **Status:** Not implemented in the current Flow Logs detector.

### NET-010 — Repeated Authentication Failure

- **Condition:** At least 10 authentication failures for an account/user and source within 300 seconds, as proposed in the YAML specification.
- **Required data:** Operating-system or application authentication logs.
- **MITRE ATT&CK:** T1110 — Brute Force, only when the evidence supports it.
- **Status:** Planned; VPC Flow Logs alone cannot establish authentication failures.

## 5. Risk Score and Severity

The scorer uses project-defined rule base scores:

| Rule | Base score |
|---|---:|
| NET-001 | 55 |
| NET-002 | 75 (reserved for planned rule) |
| NET-003 | 75 (reserved for planned rule) |
| NET-004 | 45 |
| NET-005 | 55 |
| NET-006 | 45 |
| NET-007 | 50 |
| NET-008 | 70 |
| NET-009 | 80 |
| Unknown rule | 30 |

Implemented context adjustments:

- Destination port 22 or 3389: +10.
- Evidence indicates a `REJECT` flow: +5.
- NET-001 with at least 20 unique destination ports: +10.
- NET-009 request parameters contain `0.0.0.0/0` or `::/0`: +10.

The final score is clamped to 0–100.

| Severity | Score range |
|---|---:|
| CRITICAL | 85–100 |
| HIGH | 65–84 |
| MEDIUM | 40–64 |
| LOW | 20–39 |
| INFORMATIONAL | 0–19 |

This score is a transparent project prioritization heuristic, not an industry-standard risk score and not a probability of compromise.

## 6. Rule Tuning and Governance

- Tune thresholds using both normal and suspicious controlled test data.
- Retain positive and negative test cases.
- Document each threshold change and its reason.
- Review false positives with workload context.
- Do not map a rule to MITRE ATT&CK unless the behavior and telemetry support the mapping.
- Keep the YAML specification and Python implementation aligned when runtime configuration support is added.
