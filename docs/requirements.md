# Project Requirements

## 1. Purpose

This document defines the functional, non-functional, security, and validation requirements for the **Automated Cloud-Native Network Security Monitoring & Automated Threat Detection System**.

The project focuses on a controlled AWS environment and a Python-based platform that collects selected network telemetry, identifies suspicious activity using explainable rules, assigns risk, stores findings, and presents them through a centralized dashboard.

## 2. Project Scope

### 2.1 In Scope

- AWS VPC, subnets, EC2, and Security Groups.
- VPC Flow Logs as the primary network telemetry source.
- Amazon CloudWatch Logs for log collection.
- Python-based log parsing and normalization.
- A rule-based threat detection engine.
- Explainable severity and risk scoring.
- SQLite storage for findings.
- A Streamlit security dashboard.
- Controlled security testing and validation.
- MITRE ATT&CK mapping where technically justified.
- Project documentation and evidence.

### 2.2 Optional Scope

The following may be added after the core system is stable:

- AWS CloudTrail for selected AWS API/control-plane activity.
- Email or Amazon SNS alerts.
- AWS Lambda and Amazon EventBridge for event-driven workflows.
- Approval-based automated response.

### 2.3 Out of Scope

The core project does not require:

- Machine-learning or AI-based threat detection.
- Multi-cloud support.
- Kubernetes security.
- A full SIEM or SOAR platform.
- Commercial-grade CSPM.
- Hundreds of detection rules.
- A complex frontend.
- Automatic blocking of attackers.
- Terraform, Docker, Kubernetes, Jenkins, GitHub Actions, Helm, Argo CD, CI/CD, or DevSecOps implementation.

## 3. Functional Requirements

### FR-01 — AWS Test Environment

The system shall operate against a controlled AWS test environment containing the required network and compute resources, including a VPC, subnet(s), an EC2 instance, and security groups.

### FR-02 — Network Telemetry Collection

The system shall use VPC Flow Logs to collect selected network-flow information from the test environment.

Relevant fields may include source IP, destination IP, source port, destination port, protocol, packet count, byte count, start time, end time, traffic action, and network-interface identifier.

### FR-03 — Log Collection

The core implementation shall use Amazon CloudWatch Logs as the destination for the selected VPC Flow Logs.

### FR-04 — Log Parsing

The application shall parse raw log records and extract the fields required by the implemented detection rules.

### FR-05 — Event Normalization

The application shall convert parsed records into a consistent normalized event structure suitable for analysis.

### FR-06 — Input Validation and Error Handling

The parser shall handle malformed, incomplete, or unsupported records safely. Invalid records should be logged or counted without silently being treated as valid events.

### FR-07 — Rule-Based Detection

The detection engine shall evaluate normalized events against documented detection rules. The project target is approximately 8–10 rules, with at least eight security conditions demonstrated by completion.

Initial rule candidates include:

- Possible port scanning.
- Internet-exposed SSH.
- Internet-exposed RDP.
- Repeated connection attempts.
- Excessive rejected traffic.
- Suspicious administrative or database ports.
- Unusual traffic volume.
- Unusual AWS API activity, if the relevant telemetry is implemented.
- Security-group modifications, if the required configuration or CloudTrail evidence is available.
- Repeated authentication failures only when an appropriate authentication log source is available.

### FR-08 — Evidence-Based Findings

Each finding shall identify the detection rule and provide the available evidence supporting the result. A suspicious event shall not automatically be labelled a confirmed attack.

### FR-09 — Severity Classification

The system shall support the following finding severity levels:

- CRITICAL
- HIGH
- MEDIUM
- LOW
- INFORMATIONAL

### FR-10 — Risk Scoring

The system shall calculate an explainable risk score using documented factors. Potential factors include exposure, frequency, target sensitivity, destination port, event type, and source reputation where available.

The project shall document its scoring methodology and shall not describe it as an industry-standard score unless it implements a recognized standard.

### FR-11 — Findings Storage

The application shall store findings in SQLite for the core implementation.

A finding should support, where applicable:

- Finding ID
- Rule ID
- Timestamp
- Source
- Destination
- Resource
- Description
- Severity
- Risk score
- Evidence
- Recommended action
- Status

### FR-12 — Security Dashboard

The application shall provide a Streamlit dashboard that presents a centralized view of findings and security statistics.

### FR-13 — Dashboard Filtering

The dashboard should allow users to filter findings by available attributes such as timestamp, source IP, destination IP, port, protocol, severity, rule, and resource.

### FR-14 — Investigation Guidance

Each finding should include a human-readable explanation and a recommended investigation or remediation action.

### FR-15 — Alerting

The minimum viable product shall support at least one alert mechanism. Dashboard-based notifications are the recommended starting point. Email or SNS can be considered after the detection engine is stable.

### FR-16 — AWS API Activity Monitoring (Optional)

If CloudTrail is implemented, the system should be able to analyze selected AWS API/control-plane events, such as security-group or IAM changes. Network-flow events and AWS API events must be distinguished.

### FR-17 — MITRE ATT&CK Mapping

The project shall map selected detections to MITRE ATT&CK only where the available evidence supports the mapping. For example, a validated network-service-discovery detection may be mapped to T1046. Brute-force mapping requires suitable authentication evidence.

### FR-18 — Test Evidence

The project shall record test scenarios, expected results, observed results, and evidence for the implemented detection rules.

## 4. Non-Functional Requirements

### NFR-01 — Security

The application and AWS environment shall follow appropriate security practices, including least-privilege IAM permissions, secure credential handling, input validation, audit logging, and secure configuration.

### NFR-02 — Credential Protection

AWS credentials shall not be hard-coded in source code or committed to the repository. Use suitable AWS credential mechanisms and temporary credentials where practical.

### NFR-03 — Explainability

Detection results and risk scores shall be understandable to a reviewer. Each finding should identify the rule and evidence that caused it to be generated.

### NFR-04 — Reliability

The application should handle missing or malformed records gracefully and should avoid crashing because of an individual invalid event.

### NFR-05 — Maintainability

Detection rules, parsing logic, risk scoring, data storage, and dashboard presentation should be separated into understandable modules where practical.

### NFR-06 — Reproducibility

The project shall document the AWS environment, configuration, dependencies, setup steps, and test procedures sufficiently for another person to reproduce the demonstration, subject to AWS account permissions and costs.

### NFR-07 — Usability

The dashboard should present findings and severity clearly and provide practical filters for investigation.

### NFR-08 — Data Integrity

Stored findings should retain the information needed to understand and investigate each detection, including timestamps, rule identifiers, severity, and available evidence.

### NFR-09 — Scope Control

The implementation should prioritize core telemetry collection, detection correctness, risk scoring, findings storage, dashboard functionality, and validation over optional or advanced features.

### NFR-10 — Responsible Testing

All security tests and simulated suspicious traffic shall be limited to infrastructure owned by the project or explicitly authorized for testing.

## 5. Security Requirements

- Use least-privilege IAM policies.
- Prefer roles and temporary credentials where practical.
- Never hard-code AWS access keys or secrets.
- Keep the test environment separate from production systems.
- Validate and safely process incoming log data.
- Record application errors and security-relevant actions without exposing secrets.
- Protect stored data and credentials according to the environment's needs.
- Do not automatically block traffic during early development.
- If automated response is added later, require human approval initially and log each action.
- Destroy or shut down billable lab resources when they are no longer needed.

## 6. Detection and Validation Requirements

The system should be tested with:

1. Normal traffic to observe baseline behavior.
2. Controlled simulated port scanning against the authorized lab.
3. Suspicious connection patterns.
4. High rejected-traffic scenarios.
5. Test security-group changes where the relevant telemetry is available.
6. Malformed or incomplete log records.

For each applicable test, document:

- Test ID and purpose.
- Preconditions and data source.
- Steps or generated test input.
- Expected detection result.
- Actual result.
- Evidence or screenshot.
- Pass/fail status.
- Notes on false positives or limitations.

The project should tune detection thresholds based on results and document false positives. False negatives should be analyzed where they can be measured meaningfully.

## 7. Data Requirements

### 7.1 Network Event Data

The system may use these VPC Flow Log fields when present:

- Source and destination IP addresses.
- Source and destination ports.
- Protocol.
- Packet and byte counts.
- Start and end timestamps.
- ACCEPT/REJECT action.
- Network interface identifier.

The exact fields used by each rule must be documented.

### 7.2 Finding Data

Each stored finding should contain a unique identifier and enough context to explain the detection. Fields that are unavailable for a particular event should not be fabricated.

### 7.3 Sample and Test Data

Sample data may be used during development. Final validation should clearly distinguish synthetic sample records from telemetry actually collected from the AWS test environment.

## 8. Technology Requirements

| Component | Required or planned technology |
|---|---|
| Cloud environment | AWS |
| Network | VPC, subnets, route tables, Security Groups |
| Compute | EC2 |
| Network telemetry | VPC Flow Logs |
| Log destination | CloudWatch Logs |
| Processing and detection | Python |
| AWS integration | Boto3 where required |
| Findings database | SQLite |
| Dashboard | Streamlit |
| Threat behavior reference | MITRE ATT&CK |
| Optional AWS API telemetry | CloudTrail |
| Optional notifications | Email / Amazon SNS |

## 9. Acceptance Criteria

The core project may be considered complete when the following are demonstrated:

- [ ] A controlled AWS test environment is available or its configuration is documented.
- [ ] VPC Flow Logs are configured and sample records can be accessed.
- [ ] The Python parser processes supported records into normalized events.
- [ ] Invalid records are handled safely.
- [ ] At least eight security conditions are implemented and demonstrated, with the exact supported telemetry documented.
- [ ] Findings include rule identifiers, severity, evidence, and recommended actions where applicable.
- [ ] Risk scoring is documented and explainable.
- [ ] Findings are stored in SQLite.
- [ ] The Streamlit dashboard displays findings and relevant statistics.
- [ ] Users can filter findings using supported fields.
- [ ] Controlled tests include expected and observed results.
- [ ] False-positive observations and limitations are documented.
- [ ] Selected detections are mapped to MITRE ATT&CK where justified.
- [ ] AWS credentials are not hard-coded or committed.
- [ ] Project documentation, screenshots, and demonstration evidence are organized.

## 10. Assumptions and Limitations

- Access to an AWS account with permission to create and inspect the required resources is assumed for live AWS testing.
- AWS costs and service availability depend on the account, region, and configuration; resources should be monitored and removed when no longer needed.
- VPC Flow Logs describe network flows and do not, by themselves, prove application-level intent or confirm a brute-force attack.
- Authentication-related detections require a suitable authentication log source.
- Security-group exposure analysis may require inspecting configuration or using AWS API activity logs; it cannot always be concluded from flow records alone.
- The system is an academic MVP, not a replacement for a production SIEM or a complete managed security service.
- Performance targets and exact detection thresholds must be established through implementation and testing; no unverified throughput or accuracy guarantees are assumed.

## 11. Reference Documentation

Use official documentation as the primary technical authority:

- [Amazon VPC Documentation](https://docs.aws.amazon.com/vpc/latest/userguide/)
- [AWS VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [AWS VPC Flow Log Records](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html)
- [AWS Security Groups](https://docs.aws.amazon.com/vpc/latest/userguide/creating-security-groups.html)
- [Amazon CloudWatch Logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/)
- [AWS CloudTrail](https://docs.aws.amazon.com/cloudtrail/)
- [AWS IAM Security Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [MITRE ATT&CK: Network Service Discovery (T1046)](https://attack.mitre.org/techniques/T1046/)
- [MITRE ATT&CK: Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [NIST Cybersecurity Framework 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20)
- [Python Documentation](https://docs.python.org/3/)
- [Boto3 Documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [Streamlit Documentation](https://docs.streamlit.io/)
