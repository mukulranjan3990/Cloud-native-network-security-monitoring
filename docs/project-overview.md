# Project Overview

## 1. Project Identity

**Project title:** Automated Cloud-Native Network Security Monitoring and Threat Detection System  
**Domain:** Cloud security, network security, cybersecurity, and AWS  
**Primary cloud platform:** Amazon Web Services (AWS)  
**Primary programming language:** Python  
**Project type:** Academic minimum viable product (MVP)

## 2. Abstract

The project develops a Python-based monitoring and threat-detection application for selected AWS network and cloud activity. It uses Amazon VPC Flow Logs delivered to Amazon CloudWatch Logs as its primary network telemetry source. Selected AWS API activity can also be represented as CloudTrail events and evaluated by the detection engine when those events are supplied to it.

The processing workflow parses raw records into normalized events, evaluates explainable rule-based heuristics, assigns a project-defined risk score and severity, and stores events and findings in SQLite. A Streamlit dashboard provides a planned presentation and investigation layer for stored results.

The system is intended to help an administrator answer: **What activity is visible, which observations look suspicious, how should they be prioritized, and what should be investigated next?** A finding is an indicator requiring investigation; it is not automatically proof of a confirmed attack.

## 3. Problem Statement

Cloud environments generate network and administrative activity that can be difficult to review manually. Suspicious patterns may include:

- one source contacting many destination ports;
- repeated connections to a destination service;
- unusually high numbers of rejected flow records;
- connections to sensitive administrative or database ports;
- unexpectedly large individual flows;
- sensitive IAM or security-group API changes.

Without a structured process, an administrator may struggle to correlate this activity, prioritize investigation, and retain evidence of why an alert was generated.

## 4. Aim

Design and implement a small, reproducible AWS-focused security monitoring platform that collects selected telemetry, normalizes it, detects suspicious patterns with transparent rules, prioritizes findings, and makes the results reviewable.

## 5. Objectives

1. Establish a controlled AWS test environment using VPC, EC2, Security Groups, and IAM.
2. Enable VPC Flow Logs and deliver them to CloudWatch Logs.
3. Retrieve configured CloudWatch log events using Python and Boto3.
4. Parse standard VPC Flow Logs version 2 records into a normalized event structure.
5. Parse selected CloudTrail JSON events for AWS API activity.
6. Evaluate normalized events using explainable detection rules.
7. Assign a 0–100 project-defined risk score and severity label.
8. Store normalized events and findings in SQLite.
9. Present stored findings and network summaries through a dashboard.
10. Test the rules using normal and controlled suspicious-traffic examples.
11. Document evidence, limitations, and recommendations.

## 6. Scope

### Included in the current MVP

- AWS VPC and EC2 test-lab context.
- Security Groups and IAM as relevant AWS security controls.
- VPC Flow Logs as the primary network telemetry.
- CloudWatch Logs collection through Boto3.
- Python parsing and normalization.
- Selected CloudTrail event parsing and detection logic.
- Rule-based detection for selected network and AWS API events.
- Explainable risk scoring and severity classification.
- SQLite event and finding persistence.
- Synthetic sample data and automated tests.
- A Streamlit dashboard as the visualization layer.

### Not implemented in the current MVP

- A full SIEM or SOAR platform.
- Machine-learning or AI-based threat detection.
- A learned traffic baseline or statistical anomaly model.
- Automatic blocking, quarantine, or modification of AWS resources.
- Complete authentication-failure detection.
- Live security-group configuration inventory for public SSH/RDP exposure.
- Automatic CloudTrail trail discovery and ingestion.
- Multi-cloud monitoring.
- Production-grade high availability or multi-tenant operation.

### Infrastructure-as-code scope clarification

The main technical brief discusses Terraform as a way to reproduce AWS infrastructure. The separate 12-week project timeline explicitly says Terraform is excluded from the core scope. The current Python MVP does not provision AWS resources with Terraform. Treat Terraform as deferred/optional until the project supervisor or final approved scope resolves this planning difference.

## 7. High-Level Workflow

```text
AWS VPC / EC2 / Security Groups
             |
             v
        VPC Flow Logs
             |
             v
      Amazon CloudWatch Logs
             |
             v
       Boto3 Log Collector
             |
             v
        Event Parser
             |
             v
      Normalized Events
             |
             v
       Threat Detector <------ Selected CloudTrail JSON events
             |
             v
        Risk Scorer
             |
             v
      SQLite Events & Findings
             |
             v
       Streamlit Dashboard
```

CloudTrail event parsing and selected event detection are supported by the code, but the VPC Flow Logs collector does not automatically collect CloudTrail events. CloudTrail ingestion must be configured separately.

## 8. Technology Stack

| Area | Technology | Purpose |
|---|---|---|
| Cloud platform | AWS | Controlled network and cloud activity environment |
| Network telemetry | VPC Flow Logs | Network flow observations |
| Log destination | CloudWatch Logs | Centralized flow-log storage and retrieval |
| AWS activity source | CloudTrail | Selected AWS API/control-plane events |
| Programming | Python | Parsing, detection, scoring, persistence |
| AWS SDK | Boto3 | CloudWatch Logs API access |
| Database | SQLite | Local event and finding storage |
| Dashboard | Streamlit | Security overview and investigation interface |
| Tests | pytest | Automated unit and behavior checks |

## 9. Expected Outcomes

The MVP should demonstrate that it can:

- read sample flow-log records and, when configured, retrieve records from CloudWatch Logs;
- normalize supported network and selected AWS API events;
- generate findings for supported detection conditions;
- explain findings through rule identifiers and evidence;
- assign a risk score and severity;
- store events and findings without duplicating identical findings;
- display stored results for investigation;
- pass automated tests for parser, detector, scorer, and database behavior.

These outcomes describe intended and implemented project behavior; they do not imply that every proposed rule or AWS integration is complete.

## 10. Success Criteria

The project is considered a successful MVP when its implemented workflow is reproducible, supported detections have test cases, stored findings can be reviewed, and limitations are clearly documented. Detection accuracy must be evaluated against controlled data rather than asserted without evidence.

## 11. Key References

- [Amazon VPC documentation](https://docs.aws.amazon.com/vpc/latest/userguide/)
- [AWS VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [AWS VPC Flow Log records](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html)
- [Amazon CloudWatch Logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/)
- [AWS CloudTrail](https://docs.aws.amazon.com/cloudtrail/)
- [Boto3 documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [Python documentation](https://docs.python.org/3/)
- [Streamlit documentation](https://docs.streamlit.io/)
