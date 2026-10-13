# References

## 1. Purpose

This document lists the primary technical references for the **Automated Cloud-Native Network Security Monitoring & Automated Threat Detection System**. Official documentation should be the first source for AWS behavior, security configuration, API details, and implementation decisions.

## 2. AWS Networking

### 2.1 Amazon VPC Documentation

URL: https://docs.aws.amazon.com/vpc/latest/userguide/

Use for VPC concepts, subnets, route tables, network interfaces, and AWS network architecture.

### 2.2 AWS VPC Flow Logs

URL: https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html

Use for configuring VPC Flow Logs and understanding supported destinations and collection behavior.

### 2.3 AWS VPC Flow Log Records

URL: https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html

Use to verify available flow-log fields, including addresses, ports, protocol, packets, bytes, timestamps, action, and interface information.

### 2.4 AWS Security Groups

URL: https://docs.aws.amazon.com/vpc/latest/userguide/creating-security-groups.html

Use for inbound/outbound access rules, administrative-port exposure, and security-group configuration.

## 3. AWS Logging and Monitoring

### 3.1 Amazon CloudWatch Logs

URL: https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/

Use for centralized log collection, storage, searching, and investigation.

### 3.2 AWS CloudTrail

URL: https://docs.aws.amazon.com/cloudtrail/

### 3.3 AWS CloudTrail User Guide

URL: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/

Use these sources for AWS API activity, control-plane monitoring, trail configuration, and event investigation. CloudTrail-based detections are optional unless implemented by the project.

## 4. AWS Identity and Security

### 4.1 IAM Getting Started

URL: https://docs.aws.amazon.com/IAM/latest/UserGuide/getting-started.html

Use for IAM users, roles, policies, and permissions.

### 4.2 IAM Security Best Practices

URL: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html

Use for least privilege, temporary credentials, MFA, and secure AWS access.

## 5. Cybersecurity and Threat Detection

### 5.1 MITRE ATT&CK — Network Service Discovery (T1046)

URL: https://attack.mitre.org/techniques/T1046/

Use as a threat-behavior reference when mapping a supported possible port-scan or network-service-discovery detection.

### 5.2 MITRE ATT&CK — Brute Force (T1110)

URL: https://attack.mitre.org/techniques/T1110/

Use when authentication evidence supports a brute-force-related detection. VPC Flow Logs alone do not prove a brute-force attack.

## 6. Security Logging and Frameworks

### 6.1 OWASP Logging Cheat Sheet

URL: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html

Use for security-event logging practices, useful log fields, timestamps, severity, and investigation support.

### 6.2 NIST Cybersecurity Framework (CSF) 2.0

URL: https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20

Use as a reference for cybersecurity risk management and the Detect function. Referencing the framework does not mean the project is formally NIST-compliant.

## 7. Programming and Application Development

### 7.1 Python Documentation

URL: https://docs.python.org/3/

Use for Python language features and standard-library functionality.

### 7.2 Python Logging Documentation

URL: https://docs.python.org/3/library/logging.html

Use for application logging and operational diagnostics.

### 7.3 Boto3 Documentation

URL: https://boto3.amazonaws.com/v1/documentation/api/latest/index.html

Use for Python integration with AWS APIs and services.

### 7.4 Streamlit Documentation

URL: https://docs.streamlit.io/

Use for building the security dashboard, visualizing findings, and implementing filters.

## 8. Reference Use Policy

- Prefer official AWS documentation for AWS configuration and behavior.
- Prefer MITRE ATT&CK for threat-behavior terminology and technique references.
- Use OWASP and NIST as guidance, without claiming formal compliance.
- Third-party blogs and tutorials may help with learning but should not replace authoritative references for security claims.
- Verify technical claims against documentation and, where practical, test them in the controlled AWS environment.
- Record the date accessed if required by the academic submission format.
- Do not claim that a feature or detection is implemented merely because a reference describes it.
