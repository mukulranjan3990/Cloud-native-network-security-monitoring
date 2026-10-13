# Problem Statement

## 1. Background

Modern applications and services are increasingly deployed in cloud
environments. Cloud platforms such as AWS provide extensive security
mechanisms, but organizations remain responsible for correctly
configuring, monitoring, and investigating their cloud resources.

Large volumes of network and cloud activity can make manual security
monitoring difficult. Security-relevant events may be distributed across
network telemetry, logs, AWS API activity, and security-group
configurations.

## 2. Problem

Suspicious activity such as the following can be difficult to identify
manually:

-   Port scanning
-   Repeated connection attempts
-   Unauthorized network access
-   Brute-force behavior
-   Access to unusual or sensitive ports
-   Excessive rejected traffic
-   Suspicious AWS API activity
-   Unexpected administrative activity
-   Risky security-group modifications
-   Unusual traffic volumes

Without a focused monitoring and detection mechanism, security
administrators may have difficulty identifying abnormal behavior
quickly, understanding its severity, and determining what action should
be taken.

## 3. Proposed Problem Definition

The project addresses the problem of **automated identification and
analysis of suspicious network and cloud-security activity within a
controlled AWS environment**.

The system will collect selected AWS security telemetry, normalize the
raw events, evaluate them against predefined and explainable security
detection rules, assign risk severity, store security findings, and
present the results through a centralized dashboard.

The system is intended to answer:

> **What is happening inside the AWS environment, is the activity
> suspicious, how serious is it, and what should the security
> administrator investigate or do next?**

## 4. Key Challenges

The project addresses the following technical challenges:

### 4.1 High Volume of Security Events

Cloud environments can generate large quantities of network and API
activity. Manually examining every event is inefficient.

### 4.2 Identification of Suspicious Network Behavior

Patterns such as many destination ports being accessed by one source,
excessive rejected connections, or unusual traffic volume can indicate
suspicious activity but require rule-based analysis.

### 4.3 Separation of Normal and Suspicious Activity

Repeated connections or unusual traffic are not automatically malicious.
The detection system must therefore provide evidence-based findings
rather than automatically declaring every anomaly a confirmed attack.

### 4.4 Risk Prioritization

Security administrators need to know which findings require immediate
attention. The system therefore needs an explainable severity and
risk-scoring mechanism.

### 4.5 Centralized Investigation

Security findings should be stored and presented in a centralized
interface so that administrators can filter and investigate events using
relevant attributes such as source IP, destination IP, port, protocol,
timestamp, severity, and detection rule.

### 4.6 Security and Reproducibility

The monitoring system and its AWS environment must follow secure
practices, including least-privilege access, secure credential handling,
audit logging, and controlled testing.

## 5. Problem Scope

The problem is limited to a controlled AWS security-monitoring
environment. The core scope includes:

-   AWS VPC
-   EC2
-   Security Groups
-   VPC Flow Logs
-   CloudWatch Logs
-   Python-based processing
-   Detection rules
-   Risk scoring
-   SQLite findings storage
-   Streamlit dashboard
-   Controlled security testing
-   MITRE ATT&CK mapping where technically justified

Optional components such as CloudTrail, email/SNS alerts, and
approval-based automated response may be added after the core detection
system is stable.

## 6. Expected Solution

The project will provide a Python-based security monitoring and
threat-detection platform that transforms AWS telemetry into structured
security findings.

The expected processing flow is:

``` text
Raw AWS Telemetry
       ↓
Log Collection
       ↓
Parsing and Normalization
       ↓
Detection Rules
       ↓
Detection Result
       ↓
Risk Scoring
       ↓
Security Finding
       ↓
Database
       ↓
Dashboard / Investigation
```

The final system should demonstrate that selected suspicious behaviors
can be detected consistently, explained using available evidence,
prioritized by severity, and presented to a security administrator for
investigation.
