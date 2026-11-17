# Threat Model

## 1. Purpose and Scope

This threat model identifies the security events the project intends to observe, the assets and trust boundaries involved, and the limitations of the available telemetry.

It is a project-level threat model for a controlled AWS lab. It is not a complete enterprise threat assessment or a claim of formal compliance.

## 2. Assets to Protect

| Asset | Security concern |
|---|---|
| AWS account and IAM identities | Unauthorized access, privilege changes, credential misuse |
| VPC and subnets | Unwanted network reachability and exposure |
| EC2 instances and network interfaces | Scanning, unwanted connections, service exposure |
| Security Groups | Overly permissive ingress/egress rules |
| CloudWatch log group | Unauthorized reading, deletion, or tampering with monitoring data |
| CloudTrail records | Loss of audit visibility or suspicious administrative activity |
| Local SQLite database | Exposure or modification of event and finding records |
| Application configuration and credentials | Secret leakage or excessive AWS permissions |
| Detection rules and risk thresholds | Tampering, weak thresholds, or misleading alerts |

## 3. Trust Boundaries

1. **Internet to AWS VPC:** traffic crosses the network boundary and is subject to routing, security-group, and network ACL controls.
2. **AWS workload to telemetry services:** Flow Logs and CloudTrail deliver observations to AWS logging services.
3. **AWS services to local collector:** the application authenticates to AWS using the configured Boto3 credential chain.
4. **Raw logs to parser:** raw event strings and JSON are untrusted input.
5. **Application to local database:** normalized data and findings are persisted locally.
6. **Database to dashboard/operator:** displayed records may contain infrastructure metadata and must be protected from unauthorized access.

## 4. Threat Scenarios

| ID | Threat scenario | Potential impact | Relevant telemetry / control |
|---|---|---|---|
| TM-01 | One source probes many destination ports | Service discovery and exposure mapping | VPC Flow Logs; NET-001 |
| TM-02 | Repeated connections target one service | Automated probing or possible abuse | VPC Flow Logs; NET-004 |
| TM-03 | A source generates many rejected flows | Scanning, misconfiguration, or hostile traffic | VPC Flow Logs; NET-005 |
| TM-04 | Traffic targets SSH/RDP/database/admin ports | Access attempt against sensitive services | VPC Flow Logs; NET-006 |
| TM-05 | A single flow transfers an unusually large number of bytes | Unexpected data transfer or legitimate bulk workload | VPC Flow Logs; NET-007 |
| TM-06 | IAM policy/access-key related API action occurs | Unexpected privilege or credential change | CloudTrail management events; NET-008 |
| TM-07 | Security-group ingress/egress rule is modified | Exposure or connectivity change | CloudTrail management events; NET-009 |
| TM-08 | SSH or RDP is unrestricted to the internet | Increased remote-access attack surface | EC2 Security Group configuration; NET-002/003 planned |
| TM-09 | Repeated login failures occur | Possible credential attack | OS/application authentication logs; NET-010 planned |
| TM-10 | Monitoring data or credentials are accessed improperly | Loss of confidentiality or monitoring integrity | IAM least privilege, secure credentials, local file protection |

## 5. Threat Actors and Causes

Potential sources of suspicious events include:

- external hosts scanning public-facing resources;
- compromised or misconfigured internal workloads;
- legitimate administrators performing unexpected changes;
- automated systems generating repeated connections;
- application clients retrying failed requests;
- accidental security-group or IAM misconfiguration.

The detector does not infer actor identity or intent from an IP address alone.

## 6. Detection Coverage and Evidence Quality

### Strongly observable from configured Flow Logs

Flow Logs provide records about network flows and fields such as source/destination address, ports, protocol, packets, bytes, timestamps, action, and interface. They can support network-pattern heuristics such as port diversity, repeated flow records, rejected-flow counts, and sensitive destination-port observations.

### Requires separate AWS API telemetry

IAM changes and security-group modifications require CloudTrail management-event records. The parser and detector support selected CloudTrail event shapes/names, but the current Flow Logs collector does not automatically gather CloudTrail events.

### Requires configuration inventory

Internet-exposed SSH/RDP is a property of security-group configuration and CIDR rules. A flow record to port 22 or 3389 does not, by itself, prove that the security group allows unrestricted internet access.

### Requires authentication telemetry

Repeated authentication failure requires OS or application authentication records. VPC Flow Logs alone cannot establish that a login failed and must not be used as proof of brute-force activity.

## 7. Risk and Impact Considerations

Potential impacts include unauthorized service access, increased attack surface, credential or privilege compromise, service disruption, data exposure, and loss of audit visibility. Actual impact depends on the affected resource, permissions, network path, workload purpose, and whether the activity was authorized.

## 8. Mitigations and Safeguards

- Use least-privilege IAM policies and temporary credentials where practical.
- Keep the lab isolated from production workloads.
- Limit security-group ingress to required source ranges and services.
- Protect CloudWatch log groups and audit data from unauthorized access.
- Keep credentials and local database/log artifacts out of version control.
- Validate and test all parser inputs.
- Review findings with contextual evidence before taking action.
- Require human approval for any future response action.
- Log and verify any approved response action.
- Tune thresholds against representative lab traffic and review false positives.

## 9. MITRE ATT&CK Mapping

- **NET-001 → T1046, Network Service Discovery:** appropriate mapping for a port-scan-like pattern.
- **NET-010 → T1110, Brute Force:** only appropriate when authentication telemetry provides evidence of repeated authentication failures. NET-004 repeated network connections alone do not establish this technique.

MITRE mappings describe behavioral alignment; they do not certify that an attack occurred.

## 10. Assumptions and Limitations

- The project operates in an authorized, controlled AWS environment.
- Flow Logs are enabled and delivered correctly.
- CloudWatch and CloudTrail retention/configuration are sufficient for the selected tests.
- The initial thresholds are heuristic and may not suit every workload.
- Flow Logs represent network-flow observations, not application payload or successful user authentication.
- A detection finding is a prompt for investigation, not a final incident verdict.
