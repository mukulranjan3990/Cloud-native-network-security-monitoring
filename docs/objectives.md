# Project Objectives

## 1. Primary Objective

To develop a **Python-based AWS cloud-native network security monitoring
and threat detection platform** that collects cloud and network
telemetry, detects suspicious behavior using explainable security rules,
calculates risk, generates structured findings, and provides centralized
security visibility through a dashboard.

## 2. Specific Objectives

### Objective 1 --- Establish a Controlled AWS Security Environment

Create a controlled AWS test environment containing the required network
and compute components, including:

-   VPC
-   Subnets
-   EC2 instance
-   Security Groups
-   Required networking configuration

The environment must remain isolated from production systems.

### Objective 2 --- Collect Network Security Telemetry

Enable and collect **VPC Flow Logs** to obtain relevant network-traffic
information such as:

-   Source IP
-   Destination IP
-   Source port
-   Destination port
-   Protocol
-   Packet count
-   Byte count
-   Start and end time
-   ACCEPT/REJECT action
-   Network interface information

### Objective 3 --- Centralize Log Collection

Use **Amazon CloudWatch Logs** as the primary log destination for the
selected VPC Flow Log telemetry and support security-event
investigation.

### Objective 4 --- Process and Normalize Security Events

Develop a Python-based log-processing module that:

1.  Reads raw log records.
2.  Parses relevant fields.
3.  Validates the data.
4.  Converts records into a common normalized event structure.
5.  Produces data suitable for detection-rule evaluation.

### Objective 5 --- Develop a Threat Detection Engine

Build an explainable rule-based detection engine capable of identifying
approximately **8--10 security conditions**.

Initial detection objectives include:

-   Possible port scanning
-   Internet-exposed SSH
-   Internet-exposed RDP
-   Repeated connection attempts
-   Excessive rejected traffic
-   Suspicious administrative/database ports
-   Unusual traffic volume
-   Unusual AWS API activity where telemetry is available
-   Security-group modifications
-   Repeated authentication failures where an appropriate authentication
    log source exists

### Objective 6 --- Implement Risk Scoring

Develop a simple and explainable risk-scoring mechanism using relevant
factors such as:

-   Exposure
-   Frequency
-   Target sensitivity
-   Destination port
-   Event type
-   Source reputation where available

The system should classify findings into:

-   CRITICAL
-   HIGH
-   MEDIUM
-   LOW
-   INFORMATIONAL

The project should clearly document its scoring methodology and should
not claim that the score is an industry-standard score unless it follows
a recognized standard.

### Objective 7 --- Store Security Findings

Implement a lightweight findings database using **SQLite** during the
core project.

Findings should preserve important investigation information such as:

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

### Objective 8 --- Develop a Security Dashboard

Build a **Streamlit dashboard** that provides centralized visibility
into:

-   Overall risk
-   Critical/high/medium/low findings
-   Recent events
-   Top source IPs
-   Top destination IPs
-   Targeted ports
-   Accepted/rejected traffic
-   Traffic volume
-   Suspicious events
-   Detection results

The dashboard should also support investigation filters.

### Objective 9 --- Support Security Investigation

Allow security administrators to investigate findings using attributes
including:

-   Timestamp
-   Source IP
-   Destination IP
-   Port
-   Protocol
-   Severity
-   Detection rule
-   Resource

Each finding should explain why it was generated and provide an
appropriate recommended action.

### Objective 10 --- Validate Detection Rules

Conduct controlled security tests only against the project-owned or
explicitly authorized AWS lab.

Testing should include scenarios such as:

-   Simulated port scanning
-   Suspicious connection patterns
-   High rejected traffic
-   Test security-group changes
-   Normal traffic

The objective is to verify that the appropriate detection rules trigger
and that normal activity does not generate excessive false positives.

### Objective 11 --- Analyze False Positives and Detection Quality

Evaluate detection behavior by:

-   Reviewing false positives
-   Measuring false negatives where measurable
-   Tuning detection thresholds
-   Validating security findings
-   Documenting limitations and assumptions

### Objective 12 --- Apply MITRE ATT&CK Mapping

Map selected detection rules to appropriate MITRE ATT&CK techniques
where the observed behavior technically supports the mapping.

For example:

-   Possible network-service discovery → **T1046**
-   Brute-force-related detection → **T1110 family**, only where
    appropriate authentication evidence exists

MITRE ATT&CK should be used as a threat-behavior reference rather than
as a claim that every detection is an official MITRE detection.

### Objective 13 --- Apply Secure Development Practices

Secure the monitoring platform through:

-   IAM least privilege
-   Temporary credentials where practical
-   No hard-coded AWS credentials
-   Secure configuration
-   Authentication and authorization where required
-   Input validation
-   Audit logging
-   Secure API design
-   Encryption where appropriate

### Objective 14 --- Provide Security Alerts

Support at least one alert mechanism in the MVP. Dashboard-based
notifications should be implemented first.

Email, SNS, or other notification mechanisms may be added after the core
detection engine is stable.

### Objective 15 --- Document the Complete System

Prepare technical documentation covering:

-   Project overview
-   Problem statement
-   Objectives
-   Scope
-   Architecture
-   Threat model
-   Detection rules
-   Risk scoring
-   Testing methodology
-   Results
-   Limitations
-   Future work
-   Evidence
-   Final demonstration

## 3. Expected Objectives at Project Completion

The project should ultimately demonstrate that it can:

1.  Monitor a controlled AWS environment.
2.  Collect network telemetry.
3.  Process and normalize security events.
4.  Detect at least eight security conditions.
5.  Generate structured security findings.
6.  Assign explainable severity and risk.
7.  Store findings in a database.
8.  Display findings through a centralized dashboard.
9.  Explain the evidence behind detections.
10. Provide remediation recommendations.
11. Map selected detections to MITRE ATT&CK.
12. Demonstrate controlled security scenarios.
13. Analyze detection quality and false positives.
14. Produce complete project documentation and evidence.

## 4. Objective Boundaries

The core project does **not** require:

-   Machine-learning threat detection
-   AI threat detection
-   Multi-cloud support
-   Kubernetes security
-   Full SIEM
-   Full SOAR
-   Commercial-grade CSPM
-   100+ detection rules
-   Complex frontend development
-   Automatic blocking of attackers
-   CI/CD or DevSecOps implementation

These boundaries keep the project focused on practical AWS
network-security monitoring and explainable threat detection.
