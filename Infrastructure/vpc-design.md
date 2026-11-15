# AWS VPC Design

## 1. Purpose
This document defines the proposed VPC design for the Automated Cloud-Native Network Security Monitoring & Automated Threat Detection System. It describes a small, controlled AWS lab for EC2 testing, security-group controls, and network telemetry collection. This is a proposed design, not confirmation that resources have been deployed.

## 2. Objectives
- Isolate project testing from production networks.
- Provide the network resources required by the test EC2 instance.
- Apply restricted traffic controls.
- Enable VPC Flow Logs and deliver records to CloudWatch Logs.
- Keep the MVP small, reproducible, and cost-conscious.

## 3. Logical Architecture

```text
Internet (only if required)
        |
 Internet Gateway
        |
    Route Table
        |
    Public Subnet
        |
  Security Group
        |
   Test EC2 Instance
        |
    VPC Flow Logs
        |
  CloudWatch Logs
        |
 Python Collector / Parser
        |
 Detection Engine
```

This is a logical example. The actual deployment depends on the test scenario.

## 4. Proposed Components

| Component | Purpose |
|---|---|
| VPC | Isolated virtual network for the lab |
| CIDR block | Private IPv4 address range |
| Subnet | Network segment for test resources |
| Route table | Controls subnet routing |
| Internet Gateway | Internet connectivity when required |
| EC2 | Controlled test resource |
| Security Group | Instance-level traffic control |
| VPC Flow Logs | Network-flow telemetry |
| CloudWatch Logs | Flow-log destination |

## 5. Illustrative Address Plan

| Resource | Example |
|---|---|
| VPC | `10.20.0.0/16` |
| Subnet | `10.20.1.0/24` |
| EC2 private IP | Assigned from the subnet |

These are examples only. Confirm that the selected CIDR does not overlap with networks that need to communicate with the lab.

## 6. Subnet and Routing
A single subnet may be sufficient for the initial MVP. If internet access is required, attach an Internet Gateway, configure the route table, and assign a public IPv4 address only when the chosen access design requires it. Restrict inbound access through security groups. A private subnet and NAT-based egress may be considered later but are not mandatory.

## 7. Security Considerations
- Use a dedicated lab VPC.
- Permit only traffic required for the test.
- Do not leave SSH or RDP broadly exposed.
- Use least-privilege IAM permissions.
- Do not store credentials in source code or user data.
- Record actual VPC, subnet, route-table, and security-group settings.
- Remove billable resources when testing is complete.

## 8. Flow-Log Integration
Enable VPC Flow Logs for the selected VPC, subnet, or network interface and deliver records to CloudWatch Logs. Document the monitored scope, destination log group, record format, selected fields, and delivery role. Build the parser against the actual configured format.

## 9. Deployment Checklist
- [ ] Select AWS Region.
- [ ] Check CIDR overlap.
- [ ] Create VPC and required subnet.
- [ ] Configure route table and routes.
- [ ] Attach Internet Gateway only if needed.
- [ ] Deploy test EC2 instance.
- [ ] Associate the intended security group.
- [ ] Enable VPC Flow Logs.
- [ ] Verify records in CloudWatch Logs.
- [ ] Save configuration evidence.
- [ ] Review costs and clean up resources.

## 10. Assumptions
Exact CIDR ranges, Region, Availability Zone, instance type, and subnet count must be chosen during implementation. A single-subnet lab is not a high-availability production design.
