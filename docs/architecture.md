# System Architecture

## 1. Purpose

This document describes the proposed architecture for the **Automated Cloud-Native Network Security Monitoring & Automated Threat Detection System**. The core design collects AWS network telemetry, processes it with Python, evaluates explainable detection rules, stores findings in SQLite, and presents them in a Streamlit dashboard.

## 2. Architecture Goals

- Collect useful network-security telemetry from a controlled AWS environment.
- Normalize raw events into a consistent format.
- Detect suspicious patterns with documented rules.
- Assign explainable severity and risk scores.
- Store findings for investigation.
- Provide centralized visibility through a dashboard.
- Keep the MVP manageable and reproducible.

## 3. High-Level Architecture

```text
Internet / Test Traffic
        |
        v
   AWS VPC / EC2
        |
        v
   VPC Flow Logs
        |
        v
 Amazon CloudWatch Logs
        |
        v
 Python Collector / Reader
        |
        v
   Log Parser
        |
        v
 Normalized Events
        |
        v
  Detection Engine <---- Detection Rules
        |
        v
   Risk Scoring
        |
        v
 Security Findings
        |
        v
   SQLite Database
        |
        v
 Streamlit Dashboard
        |
        v
 Investigation / Dashboard Alert
```

Optional CloudTrail telemetry can feed a separate AWS API-event processing path into the detection engine. Optional email/SNS notifications or approval-based response may be added after the core system works.

## 4. Main Components

### 4.1 AWS Network Environment

The controlled environment contains a VPC, subnets, an EC2 instance, and security groups. Testing must be limited to infrastructure owned by the project or explicitly authorized for testing.

### 4.2 VPC Flow Logs

VPC Flow Logs provide the primary network telemetry source. Useful fields may include source and destination IP addresses, ports, protocol, packet and byte counts, timestamps, traffic action, and network-interface identifier. The exact fields depend on the configured flow-log format.

### 4.3 CloudWatch Logs

CloudWatch Logs is the planned destination for the selected VPC Flow Logs. It provides a place from which the project can access records for processing and investigation.

### 4.4 Python Processing Layer

The Python processing layer reads records, validates and parses fields, handles malformed data, and converts supported records into normalized events.

### 4.5 Detection Engine

The engine evaluates normalized events against documented rules. A detection should produce an explainable result with rule ID, evidence, and context. A detection indicates suspicious behavior, not necessarily a confirmed attack.

### 4.6 Risk Scoring

The risk module assigns a documented score and severity using factors such as exposure, frequency, target sensitivity, destination port, and event type where those values are available.

### 4.7 SQLite Findings Store

SQLite stores findings and their investigation context. The schema should preserve identifiers, timestamps, rule IDs, severity, risk score, evidence, recommendations, and status where applicable.

### 4.8 Streamlit Dashboard

The dashboard presents finding counts, recent events, severity summaries, and network indicators. Filters should be provided for available fields such as timestamp, source/destination IP, port, protocol, severity, rule, and resource.

## 5. Data Flow

1. Network traffic occurs in the controlled AWS lab.
2. VPC Flow Logs record supported flow information.
3. Records are delivered to CloudWatch Logs.
4. The Python reader obtains records.
5. The parser validates and normalizes them.
6. Detection rules evaluate the normalized events.
7. Matching rules create findings with supporting evidence.
8. The risk module assigns a score and severity.
9. Findings are saved in SQLite.
10. The dashboard displays findings for review and investigation.

If CloudTrail is added, AWS API/control-plane events must be identified and handled distinctly from network-flow events.

## 6. Suggested Application Structure

```text
cloud-security-monitor/
├── README.md
├── docs/
│   ├── project-overview.md
│   ├── problem-statement.md
│   ├── objectives.md
│   ├── requirements.md
│   ├── architecture.md
│   ├── threat-model.md
│   ├── detection-rules.md
│   ├── risk-scoring.md
│   ├── testing-strategy.md
│   ├── limitations.md
│   └── references.md
├── src/
│   ├── collector/
│   ├── parser/
│   ├── detector/
│   ├── rules/
│   ├── risk/
│   ├── alerts/
│   └── database/
├── dashboard/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── test-data/
├── sample-data/
├── scripts/
└── requirements.txt
```

This is a suggested organization; folder names may be adjusted to the actual implementation.

## 7. Security Design Principles

- Apply least-privilege IAM permissions.
- Do not hard-code or commit AWS credentials.
- Prefer roles and temporary credentials where practical.
- Validate log input and handle parsing failures safely.
- Do not expose secrets in application logs.
- Keep the test environment separate from production.
- Do not automatically block traffic in the initial MVP.
- Record and review any future response action.

## 8. Deployment and Cost Considerations

AWS service availability, permissions, configuration, and costs depend on the selected account and region. Use a small controlled lab, monitor resource usage, and remove billable resources when testing is complete.

## 9. Architecture Acceptance Checks

- [ ] VPC Flow Logs are enabled for the selected test resources.
- [ ] Flow-log records can be accessed from CloudWatch Logs.
- [ ] Python can parse supported records into normalized events.
- [ ] Detection rules receive normalized events.
- [ ] Findings include evidence and a rule identifier.
- [ ] Findings are persisted in SQLite.
- [ ] Streamlit displays findings and supports useful filters.
- [ ] Optional data sources are clearly separated from core telemetry.
