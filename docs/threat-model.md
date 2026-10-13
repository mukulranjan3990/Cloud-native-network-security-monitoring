# Threat Model

## 1. Purpose

This threat model identifies the main assets, trust boundaries, potential threats, and safeguards for the **Automated Cloud-Native Network Security Monitoring & Automated Threat Detection System**. It is a working model for an academic MVP and should be updated when the implementation changes.

## 2. System Under Consideration

The system includes:

- A controlled AWS VPC, subnets, EC2 instance, and security groups.
- VPC Flow Logs and CloudWatch Logs.
- Python log collection, parsing, and detection code.
- Detection rules and risk-scoring logic.
- SQLite findings storage.
- A Streamlit dashboard.
- Optional CloudTrail and notification components.

## 3. Assets to Protect

| Asset | Why it matters |
|---|---|
| AWS account and resources | Unauthorized changes can expose resources or create costs. |
| IAM permissions and credentials | Compromise may enable access beyond the monitoring system. |
| Network and security logs | Logs support detection and investigation and may contain sensitive metadata. |
| Detection rules and configuration | Tampering can suppress or distort findings. |
| Findings database | Findings must remain accurate and available for review. |
| Dashboard and application | Unauthorized access may expose findings or alter investigation data. |
| Test environment | Must remain controlled and separate from production. |
| Project source code and evidence | Integrity is important for reproducibility and assessment. |

## 4. Trust Boundaries

1. **AWS account boundary:** access is controlled by AWS IAM and account configuration.
2. **Telemetry boundary:** log records pass from AWS logging services into the application.
3. **Application boundary:** parsers and detection modules process input that may be incomplete or malformed.
4. **Storage boundary:** findings are written to SQLite and must be protected from unauthorized modification.
5. **Dashboard boundary:** users interact with findings through the dashboard.
6. **External traffic boundary:** network activity from outside the test environment must be treated as untrusted.

## 5. Threat Scenarios

| ID | Threat | Potential impact | Safeguards / mitigations |
|---|---|---|---|
| TM-01 | Overly permissive IAM policy | Unauthorized access or resource changes | Apply least privilege; review permissions; use roles and temporary credentials where practical. |
| TM-02 | AWS credentials committed to source control | Account compromise | Never hard-code secrets; use approved credential providers; inspect repository history if exposure occurs. |
| TM-03 | Malformed or unexpected log records | Parser failure or incorrect findings | Validate fields, handle errors safely, test malformed records, and log failures without secrets. |
| TM-04 | Log loss or delayed delivery | Missed or late detection | Document source coverage and delivery limitations; monitor collection and test with known events. |
| TM-05 | Detection-rule tampering | Suspicious activity may go undetected | Restrict write access to rules; review changes; use version control. |
| TM-06 | False positives | Alert fatigue and wasted investigation time | Tune thresholds, retain evidence, and analyze false-positive test results. |
| TM-07 | False negatives | Suspicious activity may not be detected | Test known scenarios, document blind spots, and expand coverage based on evidence. |
| TM-08 | Unauthorized access to findings | Disclosure or alteration of security information | Restrict dashboard and database access; protect the host and stored files. |
| TM-09 | Unsafe automated response | Legitimate traffic or resources may be disrupted | Keep response optional; require human approval initially; log and verify any action. |
| TM-10 | Public exposure of administrative services | Increased attack surface | Review security-group rules; avoid unnecessary public exposure; use only controlled lab configurations. |
| TM-11 | Excessive AWS resource usage | Unexpected cost or resource exhaustion | Use a small lab, monitor resources and logs, and remove resources when finished. |
| TM-12 | Misleading threat labels | Incorrect incident conclusions | Call results detections or suspicious findings unless evidence confirms an attack. |

## 6. Security Assumptions

- Testing occurs only in a project-owned or explicitly authorized environment.
- AWS account access is managed by the project owner.
- The MVP is not assumed to have production-grade identity management or high availability unless these are implemented and tested.
- VPC Flow Logs alone do not establish application-level intent or prove brute-force activity.
- Authentication detections require an appropriate authentication log source.
- CloudTrail-based detection is optional and depends on enabling and accessing relevant events.

## 7. Mitigation Priorities

### Priority 1 — Essential

- Secure AWS credentials and IAM permissions.
- Keep the test environment controlled.
- Validate input and handle parser errors.
- Protect logs, findings, and rule configuration.
- Do not automatically block traffic during initial development.

### Priority 2 — Important

- Test detection logic using known scenarios.
- Review false positives and document detection gaps.
- Restrict dashboard access as appropriate.
- Maintain clear records of test results and rule changes.

### Priority 3 — Optional Enhancements

- Add notification integrations.
- Add approval-based response workflows.
- Add stronger audit and access controls if the application evolves beyond the academic lab.

## 8. Residual Risks

Even after safeguards are applied, the system may miss activity not represented in the collected telemetry, generate false positives, or produce delayed findings. These limitations must be documented. Findings should support human investigation rather than replace it.

## 9. Review Checklist

- [ ] Assets and trust boundaries match the actual implementation.
- [ ] IAM permissions have been reviewed.
- [ ] Credentials are not stored in source code.
- [ ] Malformed logs are tested.
- [ ] Detection rules are version-controlled.
- [ ] Findings and dashboard access are appropriately restricted.
- [ ] False-positive and false-negative limitations are documented.
- [ ] Any optional response action requires approval and is audited.
