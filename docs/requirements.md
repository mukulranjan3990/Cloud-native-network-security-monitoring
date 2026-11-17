# Project Requirements

## 1. Purpose

This document defines the functional, non-functional, data, security, and environment requirements for the Automated Cloud-Native Network Security Monitoring and Threat Detection System.

The requirements distinguish current MVP capabilities from planned capabilities. A planned requirement must not be represented as implemented until its integration and tests exist.

## 2. Stakeholders and Users

| Stakeholder | Responsibility / interest |
|---|---|
| Project developer | Builds, configures, tests, and documents the platform |
| Security administrator / analyst | Reviews events, investigates findings, and decides response |
| Project evaluator | Reviews architecture, implementation evidence, tests, and limitations |
| AWS account owner | Authorizes and controls the test environment and access |

## 3. Functional Requirements

| ID | Requirement | Priority | Current status |
|---|---|---:|---|
| FR-01 | The system shall accept standard VPC Flow Logs version 2 records. | Must | Implemented in parser |
| FR-02 | The system shall normalize source/destination IPs, ports, protocol, packet/byte counts, timestamps, action, and interface metadata. | Must | Implemented in parser |
| FR-03 | The system shall accept CloudWatch collector records and preserve collector metadata. | Must | Implemented in parser |
| FR-04 | The system shall retrieve records from a configured CloudWatch Logs log group using Boto3. | Must | Implemented in collector |
| FR-05 | The system shall parse selected CloudTrail JSON events as AWS API events, separate from network flows. | Should | Parser implemented; ingestion configured separately |
| FR-06 | The system shall detect possible port scanning using unique destination ports by source within a time window. | Must | Implemented |
| FR-07 | The system shall detect repeated connections from a source to a destination and port within a time window. | Must | Implemented |
| FR-08 | The system shall detect excessive rejected flow records by source within a time window. | Must | Implemented |
| FR-09 | The system shall identify traffic to selected sensitive destination ports. | Must | Implemented |
| FR-10 | The system shall identify an individual flow exceeding a configured byte threshold. | Should | Implemented; not a baseline model |
| FR-11 | The system shall detect selected sensitive IAM/access-management CloudTrail event names. | Should | Implemented in detector; CloudTrail feed separate |
| FR-12 | The system shall detect selected security-group modification CloudTrail event names. | Should | Implemented in detector; CloudTrail feed separate |
| FR-13 | The system shall assign each finding a project-defined score from 0 to 100 and a severity. | Must | Implemented |
| FR-14 | The system shall persist normalized events and findings in SQLite. | Must | Implemented |
| FR-15 | The system shall prevent duplicate finding insertion when the same finding key is reprocessed. | Should | Implemented |
| FR-16 | The system shall support finding status values OPEN, INVESTIGATING, and CLOSED. | Should | Implemented in database layer |
| FR-17 | The dashboard shall show event/finding summaries and support investigation filters. | Should | Dashboard application created; runtime integration should be verified |
| FR-18 | The system shall detect internet-exposed SSH/RDP by inspecting security-group configuration. | Could | Planned; not implemented by flow-log detector |
| FR-19 | The system shall detect repeated authentication failures from authentication logs. | Could | Planned; requires OS/application authentication telemetry |
| FR-20 | The system may send email/SNS/webhook alerts. | Could | Not part of the current core implementation |
| FR-21 | The system may support human-approved response actions. | Could | Future work; no automatic response in MVP |

## 4. Non-Functional Requirements

### NFR-01 — Security

- Do not hard-code AWS access keys or secret keys.
- Use the Boto3 credential provider chain, IAM roles, IAM Identity Center, or another approved credential source.
- Apply least-privilege permissions to the collector.
- Do not commit `.env`, credentials, local database files, or sensitive logs.
- Restrict testing to owned or explicitly authorized infrastructure.

### NFR-02 — Explainability

Every finding should identify its rule, observed evidence, severity, score, and recommended investigation action. A finding must not be described as a confirmed attack solely because a heuristic triggered.

### NFR-03 — Data Integrity

- Preserve raw event content where practical for traceability.
- Normalize missing values as missing/`None`, not as fabricated zero values.
- Keep network-flow events and AWS API events distinguishable by event type.
- Use stable finding identity to avoid duplicate finding rows.

### NFR-04 — Reproducibility

- Provide sample log files.
- Keep thresholds explicit and documented.
- Provide automated tests.
- Document environment variables and setup steps.
- Record the versions of Python and dependencies used for final submission.

### NFR-05 — Maintainability

Separate collection, parsing, detection, scoring, persistence, and presentation into modules with clear responsibilities.

### NFR-06 — Usability

The dashboard should present severity and findings clearly and allow an analyst to inspect evidence without needing to query SQLite manually.

### NFR-07 — Performance

The MVP should handle small academic test datasets and bounded CloudWatch queries. Large-scale throughput, distributed processing, and production capacity are outside the current acceptance claim and require separate benchmarking.

### NFR-08 — Reliability

Invalid records should be reported or skipped in a controlled manner. Collection and database errors should be visible to the operator; the system must not silently treat missing data as safe activity.

## 5. Input Data Requirements

### 5.1 VPC Flow Logs

The parser's default format is the standard version 2 order:

```text
version account-id interface-id srcaddr dstaddr srcport dstport protocol
packets bytes start end action log-status
```

Fields used by the current rules include:

| Field | Meaning / use |
|---|---|
| `srcaddr` | Source IP |
| `dstaddr` | Destination IP |
| `srcport` | Source port |
| `dstport` | Destination port |
| `protocol` | IP protocol number |
| `packets` | Packets in the flow |
| `bytes` | Bytes in the flow |
| `start`, `end` | Flow interval timestamps |
| `action` | ACCEPT or REJECT |
| `interface-id` | Network interface context |
| `log-status` | Flow-log record status |

If a custom Flow Logs format is configured, its exact ordered field list must be supplied to the parser.

### 5.2 CloudTrail Events

Selected CloudTrail events are normalized as `AWS_API` events. Relevant fields include `eventTime`, `eventSource`, `eventName`, `sourceIPAddress`, `recipientAccountId`, `awsRegion`, `userIdentity`, and `requestParameters`.

CloudTrail ingestion is separate from the current VPC Flow Logs collector.

## 6. Security and Access Requirements

The AWS collection identity should receive only the permissions needed to read the configured CloudWatch log group. The collector uses the CloudWatch Logs `FilterLogEvents` API; the required permission includes `logs:FilterLogEvents`, scoped as narrowly as supported.

The application must use approved AWS credentials and must not ask users to paste long-lived secrets into source files.

## 7. Environment Requirements

- Python 3.10 or newer, as stated in the project README.
- pip and a virtual environment.
- Project dependencies installed from `requirements.txt`.
- AWS account and configured CloudWatch log group only for live collection.
- pytest for automated tests.
- SQLite, included with standard Python installations.

## 8. Acceptance Criteria

A requirement is accepted only when there is evidence appropriate to its status:

- parser requirements: unit tests with valid, invalid, and missing-field records;
- detector requirements: positive and negative test cases for each implemented rule;
- scoring requirements: boundary and adjustment tests;
- database requirements: insertion, retrieval, duplicate, filtering, and status tests;
- AWS collection: controlled integration evidence from the configured log group;
- dashboard: successful launch against a database containing test events/findings;
- security: documented IAM policy and credential-handling review.

## 9. Scope Notes

The initial project brief describes FastAPI and PostgreSQL as possible backend/API and database options, while also permitting SQLite for early development and Streamlit for a simpler academic dashboard. The current implementation uses SQLite and Streamlit; FastAPI and PostgreSQL are not required for this MVP.

The initial technical brief also mentions Terraform, but the separate Gantt timeline explicitly excludes it from the core scope. Terraform remains deferred pending scope confirmation.
