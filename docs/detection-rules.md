# Detection Rules

## 1. Purpose

This document specifies the initial rule-based detections for the **Automated Cloud-Native Network Security Monitoring & Automated Threat Detection System**. Rules must be explainable, testable, and tied to telemetry that the project actually collects.

The target is approximately **8–10 detection rules**. A rule must not claim to detect behavior when the required fields or log sources are unavailable.

## 2. Common Rule Output

Each triggered finding should include, where available:

- Finding ID
- Rule ID
- Detection title
- Timestamp
- Source and destination
- Affected resource
- Severity
- Risk score
- Evidence and reason for triggering
- Recommended investigation or remediation
- Status

A rule match means that observed activity meets a detection condition. It does not automatically prove malicious intent.

## 3. Initial Rule Catalogue

### NET-001 — Possible Port Scan

**Purpose:** Identify a source contacting many destination ports or hosts within a defined time window.

- **Telemetry:** VPC Flow Logs.
- **Candidate fields:** source IP, destination IP, destination port, protocol, timestamp.
- **Logic:** Count distinct destination ports and/or destination hosts for a source within a configurable time window. Trigger when the configured threshold is exceeded.
- **Initial severity:** Medium or High depending on scope and context.
- **Evidence:** Source, time window, number of distinct ports/hosts, and relevant records.
- **Recommended action:** Review the source, target, exposed services, and security-group rules.
- **MITRE ATT&CK:** Potential mapping to T1046 (Network Service Discovery) when the observed behavior supports it.
- **Caution:** Thresholds must be tested against normal traffic.

### NET-002 — Internet-Exposed SSH

**Purpose:** Identify an SSH exposure condition that is broader than intended.

- **Telemetry:** Security-group configuration inspection and/or other suitable AWS configuration evidence.
- **Candidate fields:** protocol, port 22, source CIDR, target resource.
- **Logic:** Flag an SSH rule permitting broad public access when that access is not intended by the lab's policy.
- **Initial severity:** High; context may justify a different rating.
- **Evidence:** Security-group identifier, port, source range, and affected resource.
- **Recommended action:** Restrict the source range and verify the intended administration path.
- **Caution:** VPC Flow Logs alone do not prove that a security group is configured for public SSH access.

### NET-003 — Internet-Exposed RDP

**Purpose:** Identify an RDP exposure condition that is broader than intended.

- **Telemetry:** Security-group configuration inspection and/or other suitable AWS configuration evidence.
- **Candidate fields:** protocol, port 3389, source CIDR, target resource.
- **Logic:** Flag a broad public RDP rule when it violates the intended lab policy.
- **Initial severity:** High; context may justify a different rating.
- **Evidence:** Security-group identifier, port, source range, and affected resource.
- **Recommended action:** Restrict the source range or remove unnecessary exposure.
- **Caution:** Flow records alone do not establish the security-group configuration.

### NET-004 — Repeated Connection Attempts

**Purpose:** Identify repeated connections from the same source to the same destination within a defined time window.

- **Telemetry:** VPC Flow Logs.
- **Candidate fields:** source IP, destination IP, destination port, timestamp, action.
- **Logic:** Trigger when connection counts exceed a configurable threshold.
- **Initial severity:** Low to Medium, raised only when context supports it.
- **Evidence:** Count, time window, source/destination, and port.
- **Recommended action:** Review whether the pattern is expected application behavior or probing.
- **Caution:** Repeated connections are not automatically brute-force behavior.

### NET-005 — Excessive Rejected Traffic

**Purpose:** Identify unusually high rejected-flow counts.

- **Telemetry:** VPC Flow Logs.
- **Candidate fields:** source IP, destination IP, action, timestamp, packets/bytes where useful.
- **Logic:** Compare rejected-flow counts over a time window with a configured threshold or baseline.
- **Initial severity:** Medium; increase only with supporting context.
- **Evidence:** Rejected count, time window, and relevant source/destination information.
- **Recommended action:** Investigate sources, targets, and relevant network rules.
- **Caution:** High rejected traffic can have benign causes.

### NET-006 — Suspicious Administrative or Database Port

**Purpose:** Identify traffic to sensitive ports that is unexpected for the lab.

- **Telemetry:** VPC Flow Logs plus documented expected network relationships where possible.
- **Candidate ports:** 22, 3389, 3306, 5432, 6379, 27017.
- **Logic:** Flag traffic to selected ports when the source, destination, or direction is outside the expected policy.
- **Initial severity:** Medium; severity depends on exposure and resource sensitivity.
- **Evidence:** Source, destination, port, action, and policy context.
- **Recommended action:** Verify the service, source, and intended access.
- **Caution:** Port numbers alone do not prove that a service is running or that access is malicious.

### NET-007 — Unusual Traffic Volume

**Purpose:** Identify a significant increase in observed traffic volume.

- **Telemetry:** VPC Flow Logs.
- **Candidate fields:** source/destination, bytes, packets, start/end time.
- **Logic:** Compare traffic volume within a time window against a documented baseline or configurable threshold.
- **Initial severity:** Low to Medium until validated.
- **Evidence:** Observed volume, baseline/threshold, and time window.
- **Recommended action:** Check expected workload changes and investigate unexplained spikes.
- **Caution:** A meaningful baseline must be established; no universal threshold is assumed.

### NET-008 — Unusual AWS API Activity (Optional)

**Purpose:** Identify selected AWS control-plane actions that require review.

- **Telemetry:** CloudTrail, if configured and available.
- **Candidate events:** selected IAM, EC2, security-group, or S3 API activity.
- **Logic:** Match documented event names or conditions that violate the project's expected activity policy.
- **Initial severity:** Context-dependent.
- **Evidence:** Event name, time, principal, source information, and affected resource where available.
- **Recommended action:** Verify the actor and whether the change was authorized.
- **Caution:** CloudTrail is optional in the core project and must be explicitly implemented for this rule to operate.

### NET-009 — Risky Security-Group Modification (Optional)

**Purpose:** Detect a security-group change that broadens access beyond the intended policy.

- **Telemetry:** CloudTrail events and/or configuration inspection.
- **Candidate evidence:** changed ingress/egress permissions, affected group, source range, port, actor, timestamp.
- **Logic:** Flag a change that introduces a prohibited broad source range or exposes a sensitive port.
- **Initial severity:** High when a material exposure is confirmed by the available configuration evidence.
- **Recommended action:** Verify authorization and restore the intended rule if appropriate.
- **Caution:** The system must inspect actual configuration or suitable change evidence; flow logs alone are insufficient.

### NET-010 — Repeated Authentication Failure (Conditional)

**Purpose:** Identify repeated failed authentication attempts when a suitable log source is available.

- **Telemetry:** An appropriate authentication log source; VPC Flow Logs alone are insufficient.
- **Logic:** Count failures by relevant account/source/target over a defined time window.
- **Initial severity:** Context-dependent.
- **Evidence:** Failure count, account/target, source, and time window where recorded.
- **Recommended action:** Review the authentication events and account security.
- **MITRE ATT&CK:** Potential mapping to T1110 when the evidence supports brute-force behavior.
- **Caution:** Do not implement or claim this detection without the required authentication telemetry.

## 4. Rule Configuration

Each rule should document:

- Rule ID and title.
- Purpose.
- Required telemetry source.
- Required fields.
- Threshold or matching logic.
- Time window, if applicable.
- Severity logic.
- Finding evidence.
- Recommended action.
- Test cases.
- Known limitations.

Thresholds should be configurable rather than buried as unexplained constants in code.

## 5. Testing Each Rule

For every implemented rule:

1. Create a test case using synthetic records or controlled activity in the authorized lab.
2. Record the expected outcome.
3. Run the parser and detection engine.
4. Verify whether the rule triggers.
5. Inspect the generated evidence and severity.
6. Test a normal or non-matching case.
7. Record false positives, limitations, and threshold adjustments.

## 6. Implementation Status

Use this table to track the actual project status. Do not mark a rule as implemented until it has been tested.

| Rule ID | Rule | Required source | Status |
|---|---|---|---|
| NET-001 | Possible port scan | VPC Flow Logs | Planned |
| NET-002 | Internet-exposed SSH | Security-group configuration | Planned |
| NET-003 | Internet-exposed RDP | Security-group configuration | Planned |
| NET-004 | Repeated connection attempts | VPC Flow Logs | Planned |
| NET-005 | Excessive rejected traffic | VPC Flow Logs | Planned |
| NET-006 | Suspicious administrative/database port | Flow Logs + expected policy | Planned |
| NET-007 | Unusual traffic volume | VPC Flow Logs + baseline | Planned |
| NET-008 | Unusual AWS API activity | CloudTrail (optional) | Optional |
| NET-009 | Risky security-group modification | CloudTrail/configuration evidence | Optional |
| NET-010 | Repeated authentication failure | Authentication logs | Conditional |
