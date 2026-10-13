# Project Overview

## Project Title

**Automated Cloud-Native Network Security Monitoring & Automated Threat
Detection System**

## 1. Introduction

The **Automated Cloud-Native Network Security Monitoring & Automated
Threat Detection System** is a cybersecurity project focused on
monitoring network and cloud security telemetry from an AWS environment,
analyzing security events using explainable detection rules, assigning
risk severity, generating security findings, and presenting those
findings through a centralized dashboard.

The project is designed as a practical AWS-based security monitoring
platform. Its primary focus is **Cloud Security, Network Security,
Cybersecurity, Security Monitoring, Threat Detection, and Security
Automation**.

The primary cloud platform is **Amazon Web Services (AWS)** and the
primary programming language is **Python**.

## 2. Purpose

Modern applications increasingly operate in cloud environments. Although
AWS provides security services and controls, organizations must still
configure, monitor, and investigate their cloud resources correctly.

This project provides a controlled security-monitoring environment where
network and AWS security telemetry can be collected, normalized,
analyzed, and converted into actionable security findings.

The central question addressed by the system is:

> **What is happening inside my AWS network, is the activity suspicious,
> how serious is it, and what should the security administrator do?**

## 3. Core Workflow

The proposed system follows this high-level workflow:

``` text
AWS VPC
   |
   v
VPC Flow Logs
   |
   v
CloudWatch Logs
   |
   v
Python Log Parser
   |
   v
Normalized Security Events
   |
   v
Detection Engine
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
Security Investigation / Alert
```

Selected AWS control-plane activity can additionally be monitored
through **CloudTrail**.

## 4. Main AWS Components

### Core Components

-   Amazon VPC
-   Amazon EC2
-   VPC Flow Logs
-   Amazon CloudWatch Logs
-   AWS IAM
-   Security Groups

### Optional Components

-   AWS CloudTrail
-   Amazon SNS
-   AWS Lambda
-   Amazon EventBridge
-   Amazon S3
-   AWS Security Hub
-   Amazon Athena

Optional services are not required for the minimum viable project.

## 5. Core Technology Stack

  Area                           Technology
  ------------------------------ ---------------------------------------------
  Cloud Platform                 AWS
  Network                        VPC, Subnets, Route Tables, Security Groups
  Compute                        EC2
  Network Telemetry              VPC Flow Logs
  Log Collection                 CloudWatch Logs
  AWS API Monitoring             CloudTrail (optional)
  Programming                    Python
  AWS SDK                        Boto3
  Database                       SQLite
  Dashboard                      Streamlit
  Threat Reference               MITRE ATT&CK
  Security Logging Guidance      OWASP Logging Cheat Sheet
  Security Framework Reference   NIST CSF 2.0

## 6. Major Functional Modules

1.  **AWS Security Lab** --- controlled VPC, subnet, EC2, and
    security-group environment.
2.  **Network Telemetry Collection** --- collection of VPC Flow Logs.
3.  **AWS Activity Monitoring** --- selected CloudTrail activity where
    implemented.
4.  **Python Log Parser** --- parsing and normalization of raw security
    events.
5.  **Detection Engine** --- evaluation of normalized events against
    predefined rules.
6.  **Risk Scoring** --- explainable severity and risk classification.
7.  **Findings Management** --- storage and management of security
    findings.
8.  **Security Dashboard** --- visualization, filtering, and
    investigation support.
9.  **Testing & Validation** --- controlled security scenarios and
    false-positive analysis.
10. **Optional Alerting/Response** --- notification or approval-based
    response after the core detection system is stable.

## 7. Initial Detection Scope

The project targets approximately **8--10 strong detection rules**.
Initial examples include:

-   Possible port scanning
-   Internet-exposed SSH
-   Internet-exposed RDP
-   Repeated connection attempts
-   Excessive rejected traffic
-   Suspicious administrative/database ports
-   Unusual traffic volume
-   Unusual AWS API activity
-   Security-group modification
-   Repeated authentication failure where an appropriate authentication
    log source exists

A suspicious event is not automatically treated as a confirmed attack.
Detection results are presented as security findings supported by
evidence.

## 8. Risk and Findings

Each security finding can contain:

-   Finding ID
-   Rule ID
-   Timestamp
-   Source
-   Destination
-   Resource
-   Description
-   Severity
-   Risk score
-   Evidence
-   Recommended action
-   Status

Severity levels are:

-   CRITICAL
-   HIGH
-   MEDIUM
-   LOW
-   INFORMATIONAL

The initial risk-scoring model is intended to be simple and explainable,
using factors such as exposure, frequency, target sensitivity,
destination port, event type, and source reputation where available.

## 9. Dashboard

The Streamlit dashboard is intended to provide:

### Security Overview

-   Overall risk score
-   Critical, high, medium, and low findings
-   Recent security events

### Network Monitoring

-   Top source IPs
-   Top destination IPs
-   Most targeted ports
-   Accepted and rejected traffic
-   Traffic volume
-   Suspicious events

### Threat Detection

-   Port-scan indicators
-   Suspicious administrative activity
-   Security-group changes
-   Traffic anomalies
-   Other validated detection results

### Investigation

Users should be able to filter findings by timestamp, source IP,
destination IP, port, protocol, severity, rule, and resource.

## 10. Security Approach

The project itself should follow secure development practices,
including:

-   IAM least privilege
-   Temporary credentials where practical
-   No hard-coded AWS credentials
-   Secure configuration
-   Authentication and authorization where required
-   Input validation
-   Audit logging
-   Secure API design
-   Encryption where appropriate

All testing must be performed only against infrastructure owned by the
project or explicitly authorized for testing.

## 11. Academic Project Scope

The core project intentionally focuses on:

-   AWS
-   VPC
-   EC2
-   Security Groups
-   VPC Flow Logs
-   CloudWatch Logs
-   Python
-   Boto3
-   Detection Rules
-   Risk Scoring
-   SQLite
-   Streamlit Dashboard
-   MITRE ATT&CK mapping

Terraform, Docker, Kubernetes, Jenkins, GitHub Actions, Helm, Argo CD,
CI/CD, DevSecOps, and multi-cloud CSPM are **not required for the core
project** according to the project scope plan.

## 12. Expected Outcome

At completion, the project should provide a working AWS
security-monitoring MVP that can:

1.  Deploy or use a controlled AWS test environment.
2.  Collect network telemetry.
3.  Parse and normalize security events.
4.  Detect at least eight security conditions.
5.  Generate structured findings.
6.  Assign severity and risk.
7.  Store findings.
8.  Display findings through a dashboard.
9.  Explain why findings were generated.
10. Provide remediation recommendations.
11. Map selected detections to appropriate MITRE ATT&CK techniques.
12. Demonstrate controlled security test scenarios.
13. Produce evidence and technical documentation.

## 13. Project Timeline

The planned duration is **12 weeks**:

1.  Project Research & Requirement Analysis
2.  AWS Network Security Lab Setup
3.  Network Telemetry Collection
4.  Python Log Processing
5.  Threat Detection Engine
6.  Risk Scoring & Finding Management
7.  Security Dashboard
8.  Testing & Attack Simulation
9.  Security Validation & False-Positive Analysis
10. Documentation & Final Report
11. Synopsis & Presentation
12. Final Demonstration & Submission

## 14. Project Value

The primary value of the project is not the dashboard itself. The core
value is the combination of:

**AWS telemetry + security engineering + network analysis + threat
detection + risk assessment + security automation.**

The implementation should prioritize **correctness, security,
explainability, reproducibility, testing, documentation, and practical
implementation**.
