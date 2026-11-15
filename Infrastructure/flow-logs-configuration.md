# AWS VPC Flow Logs Configuration

## 1. Purpose
This document describes the configuration and validation plan for VPC Flow Logs. Flow Logs are the project's primary network telemetry source; selected records are delivered to CloudWatch Logs for Python processing.

## 2. Objectives
- Enable Flow Logs for the selected AWS lab scope.
- Deliver records to CloudWatch Logs.
- Identify fields required by detection rules.
- Verify delivery and obtain sample records.
- Build the parser against the actual configured record format.

## 3. Data Flow

```text
VPC / Subnet / Network Interface
              |
          VPC Flow Logs
              |
        CloudWatch Logs
              |
      Python Collector
              |
          Log Parser
              |
      Normalized Events
              |
       Detection Engine
```

## 4. Select Flow Log Scope
Flow Logs can be configured for a supported scope such as a VPC, subnet, or network interface.
- Select the smallest scope that captures the demonstration traffic.
- Record the resource ID and scope.
- Confirm the EC2 test resource is covered.
- Avoid unnecessary logging that increases cost or creates irrelevant data.

## 5. Configuration Record

| Setting | Value to record |
|---|---|
| AWS Region | Actual selected Region |
| Flow Log ID | Actual ID after creation |
| Resource scope | VPC / subnet / network interface |
| Resource ID | Actual resource ID |
| Destination | CloudWatch Logs |
| Log group | Actual log-group name |
| Delivery role | Actual role name/ARN |
| Record format | Actual configured format |
| Traffic type | Actual selected option |
| Creation date | Actual date |

Do not invent IDs or claim deployment before verifying it in AWS.

## 6. Relevant Fields

| Field | Meaning |
|---|---|
| `srcaddr` | Source IP |
| `dstaddr` | Destination IP |
| `srcport` | Source port |
| `dstport` | Destination port |
| `protocol` | IP protocol number |
| `packets` | Packet count |
| `bytes` | Byte count |
| `start` | Start of recorded flow interval |
| `end` | End of recorded flow interval |
| `action` | Traffic action, such as ACCEPT or REJECT |
| `interface-id` | Network interface identifier |

The configured format may contain additional fields or different ordering. Confirm it against AWS documentation and actual records.

## 7. IAM and Delivery Permissions
The delivery configuration requires appropriate permissions and a correctly configured role for the selected destination. Follow current AWS documentation for the exact trust policy and permissions. Apply least privilege, do not hard-code credentials, and record the role used.

## 8. Configuration Procedure (Console Outline)
1. Open the Amazon VPC console in the intended Region.
2. Select the VPC, subnet, or network interface.
3. Open the Flow Logs section.
4. Create a Flow Log.
5. Select the required traffic type.
6. Choose CloudWatch Logs as destination.
7. Select or create the destination log group.
8. Configure the required delivery IAM role.
9. Choose or define the record format.
10. Review and create the Flow Log.
11. Open CloudWatch Logs and verify records arrive.

Console labels and available options may change; use current AWS documentation for exact steps.

## 9. Validation
1. Confirm the Flow Log exists and is associated with the intended resource.
2. Confirm the destination log group exists.
3. Generate ordinary network activity in the authorized lab.
4. Allow for service delivery timing.
5. Inspect records in CloudWatch Logs.
6. Confirm field names and ordering.
7. Save a small redacted sample for parser tests.
8. Record missing fields, delivery issues, or scope limitations.

If records do not appear immediately, check scope, traffic type, destination, permissions, status, and expected delivery delay.

## 10. Parser Requirements
The Python parser should:
- Parse the actual configured record format.
- Map fields into a documented normalized event.
- Validate addresses, ports, protocol, timestamps, and counters where applicable.
- Handle missing or malformed values safely.
- Preserve an appropriate reference to source evidence.
- Never treat missing values as confirmed facts.
- Log parsing failures without exposing secrets.

## 11. Detection Dependencies

| Rule | Required fields / evidence |
|---|---|
| NET-001 Possible port scan | Source/destination IP, destination port, protocol, time |
| NET-004 Repeated connections | Source/destination IP, destination port, time, action |
| NET-005 Excessive rejected traffic | Action, source/destination, time |
| NET-006 Sensitive port activity | Destination port, source/destination, time, expected policy |
| NET-007 Traffic volume anomaly | Bytes/packets, source/destination, time, baseline |

NET-002 and NET-003 require security-group configuration evidence. NET-008 and NET-009 require CloudTrail or other suitable AWS API/configuration evidence. NET-010 requires an authentication log source. Do not attribute these detections to Flow Logs alone.

## 12. Troubleshooting Checklist
- [ ] Correct AWS Region.
- [ ] Flow Log attached to intended resource.
- [ ] Correct traffic type.
- [ ] Correct CloudWatch destination.
- [ ] Delivery-role trust and permissions reviewed.
- [ ] Test traffic traverses monitored resource.
- [ ] Correct log group and time range.
- [ ] Flow Log status and service errors reviewed.
- [ ] Expected delivery delay has elapsed.

## 13. Evidence to Retain
Save redacted screenshots or outputs showing Flow Log status, resource scope, destination log group, delivery-role configuration (no secrets), sample records, and parser output.

## 14. Cost and Data Handling
Flow Logs and CloudWatch Logs may incur charges based on configuration, traffic, ingestion, retention, and Region. Use a limited lab scope, review pricing, set an appropriate retention period, and remove unneeded resources. Restrict access to log data because it contains network metadata.

## 15. Official References
- [AWS VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [AWS VPC Flow Log Records](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html)
- [Amazon CloudWatch Logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/)
- [AWS IAM Security Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
