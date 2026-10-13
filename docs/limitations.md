# Project Limitations

## 1. Purpose

This document records the known and expected limitations of the **Automated Cloud-Native Network Security Monitoring & Automated Threat Detection System**. Update it as implementation and testing reveal additional constraints.

## 2. Telemetry Coverage

The core system relies on AWS VPC Flow Logs delivered to CloudWatch Logs. Flow Logs provide network-flow metadata; they do not provide full packet contents or all application-level details.

Consequences:

- Some attack behavior may not be visible from flow metadata alone.
- The system cannot reliably infer user intent from a flow record.
- Detection depends on which resources are covered by flow logging and which fields are available.
- Delivery timing and configuration may affect how quickly events can be analyzed.

## 3. Authentication and Brute-Force Detection

VPC Flow Logs alone do not prove that an authentication attempt failed or that a brute-force attack occurred. Such detections require an appropriate authentication log source. If that source is not implemented, authentication-failure detection must remain out of scope or clearly marked as future work.

## 4. Security-Group Exposure Detection

Flow records do not, by themselves, describe the complete current security-group configuration. Detecting public SSH/RDP exposure or risky security-group changes requires configuration inspection or appropriate AWS API/change-event evidence. These detections must not be claimed as implemented unless the required evidence source is available.

## 5. Rule-Based Detection

The MVP uses predefined rules rather than a learned behavioral model. Therefore:

- Rules detect only conditions explicitly represented in their logic.
- Thresholds may require tuning for different traffic patterns.
- Legitimate activity may trigger false positives.
- Unseen or unmodeled behavior may be missed.
- Detection results are indicators for investigation, not proof of compromise.

## 6. Risk-Scoring Limitations

The proposed 0–100 risk score is a project-specific heuristic. Its usefulness depends on factor selection, weights, thresholds, and data quality. It is not an industry-standard score and should not be treated as a probability of compromise.

## 7. Source Reputation and Context

Source reputation may not be available or reliable in the project environment. Missing context must be recorded as unknown rather than fabricated. Private, internal, or lab IP addresses may not have meaningful external reputation information.

## 8. CloudTrail and Alerting Are Optional

CloudTrail-based AWS API monitoring and email/SNS alerting are optional extensions in the core project plan. Their functionality must not be claimed unless they have been configured, integrated, and tested.

## 9. Scale and Performance

The project is an academic MVP. No production-scale throughput, latency, availability, or retention guarantees are assumed. Performance should be measured if it becomes a project requirement.

## 10. Availability and Resilience

The MVP may not include high availability, distributed processing, automated failover, or production-grade backup and recovery. These capabilities should be treated as future enhancements unless specifically implemented and tested.

## 11. Storage and Data Retention

SQLite is suitable for a lightweight demonstration, but the project does not assume that it will meet the concurrency, retention, access-control, or operational requirements of a large production deployment. Retention and backup behavior should be documented for the actual implementation.

## 12. AWS Costs and Permissions

Live implementation depends on AWS account permissions, service availability, region, and configuration. Some resources and log ingestion can incur charges. Monitor costs and remove billable resources when no longer needed.

## 13. Automated Response

Automatic blocking, instance quarantine, or security-group modification is not part of the initial MVP. Such actions can disrupt legitimate traffic and should not be enabled without testing, human approval, audit logging, and a rollback plan.

## 14. Scope Boundaries

The core project does not require machine learning, multi-cloud support, Kubernetes, a full SIEM/SOAR platform, commercial-grade CSPM, or CI/CD/DevSecOps tooling. Adding these would expand scope and distract from validating core network telemetry, detection, risk scoring, storage, and dashboard functionality.

## 15. Testing and Evidence

Synthetic test data is useful for unit testing but does not prove that the AWS telemetry pipeline works end to end. Final reporting must distinguish synthetic results from tests performed against the controlled AWS environment.

Detection-rate, accuracy, or performance claims should only be made when supported by a defined dataset, repeatable methodology, and recorded results.

## 16. Future Improvements

Possible future improvements include:

- Additional telemetry sources.
- Better baselining and threshold calibration.
- More detection rules supported by evidence.
- Improved access control and auditability.
- Email/SNS alerting.
- Approval-based response workflows.
- More scalable storage and processing.
- Longer-term evaluation with a documented test dataset.
