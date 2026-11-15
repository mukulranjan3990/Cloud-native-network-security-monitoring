# AWS Security Groups

## 1. Purpose
This document defines security-group design considerations for the project. Security Groups control allowed inbound and outbound traffic for supported AWS resources. They also provide configuration evidence for selected exposure detections.

## 2. Design Principles
1. Allow only traffic required by the lab.
2. Restrict administrative access to an authorized source or approved access method.
3. Do not broadly expose SSH (TCP 22) or RDP (TCP 3389).
4. Do not expose database ports publicly.
5. Review outbound rules against actual requirements.
6. Remove temporary test rules after testing.
7. Record each rule's purpose and changes.

## 3. Illustrative Rule Plan

| Direction | Protocol | Port | Source/destination | Purpose |
|---|---|---:|---|---|
| Inbound | TCP | 22 | Authorized administrator CIDR only, if needed | SSH administration |
| Inbound | TCP | 3389 | Disabled by default | RDP only for a justified lab test |
| Inbound | TCP | Application port | Required trusted source only | Optional test application |
| Inbound | TCP | Database port | Not publicly exposed | Database access only if required |
| Outbound | As required | As required | As required | Updates and test traffic |

This is a planning example, not an instruction to open every port. Avoid `0.0.0.0/0` for administrative ports.

## 4. Ports of Interest

| Port | Common service | Monitoring consideration |
|---:|---|---|
| 22 | SSH | Verify expected administrative source |
| 3389 | RDP | Avoid broad public exposure |
| 3306 | MySQL | Restrict database access |
| 5432 | PostgreSQL | Restrict database access |
| 6379 | Redis | Avoid public exposure |
| 27017 | MongoDB | Restrict database access |
| 80 | HTTP | Open only if test app requires it |
| 443 | HTTPS | Open only if test app requires it |

A port number alone does not prove a service is running or that traffic is malicious.

## 5. Detection Integration
- **NET-002 — Internet-Exposed SSH:** inspect security-group configuration for broad inbound TCP 22 access. Flow Logs alone do not establish the configured rule.
- **NET-003 — Internet-Exposed RDP:** inspect security-group configuration for broad inbound TCP 3389 access.
- **NET-006 — Suspicious Administrative/Database Port:** compare observed traffic with the expected communication policy.
- **NET-009 — Risky Security-Group Modification (optional):** use CloudTrail or suitable configuration-change evidence to identify access-broadening changes.

## 6. Safe Test Procedure
1. Test only in the project-owned or explicitly authorized AWS lab.
2. Record the original security-group configuration.
3. Create a temporary test rule only when required.
4. Keep the test source narrowly scoped.
5. Verify that configuration evidence is collected.
6. Remove the temporary rule immediately after testing.
7. Confirm the intended safe configuration is restored.
8. Save redacted evidence.

Do not scan or attempt access against third-party systems.

## 7. Review Checklist
- [ ] Every inbound rule has a documented purpose.
- [ ] SSH is restricted or disabled.
- [ ] RDP is disabled unless required for a controlled test.
- [ ] Database ports are not broadly exposed.
- [ ] Application ports are limited to required sources.
- [ ] Outbound rules are reviewed.
- [ ] Temporary rules are removed.
- [ ] Configuration evidence is retained.
- [ ] Exposure detections use configuration evidence.

## 8. Limitations
Actual CIDRs and rule values must be selected during implementation. Security-group exposure analysis requires configuration inspection or suitable AWS API evidence; Flow Logs alone are insufficient.
