# AWS Setup Guide

## 1. Purpose

This guide prepares a small, isolated AWS lab for the **Automated Cloud-Native Network Security Monitoring and Threat Detection System**.

The lab provides the AWS resources needed to generate and collect network telemetry:

- Amazon VPC
- Public subnet and route table
- Internet Gateway for controlled internet connectivity, if required
- Amazon EC2 test instance
- Security Group
- VPC Flow Logs
- Amazon CloudWatch Logs
- AWS IAM permissions for the log-delivery service and the Python collector

AWS CloudTrail is included as a recommended, separate source for AWS API/control-plane activity. It is not the same as VPC Flow Logs and is not automatically ingested by the current Flow Logs collector.

> **Safety:** Build this lab in an account and region you are authorized to use. Do not connect it to production networks. Never expose SSH/RDP or test services to the whole internet for convenience. Use your own public IP address as a `/32` source when remote SSH is genuinely needed, or use AWS Systems Manager Session Manager where configured.

## 2. Scope and Project Alignment

The project specification names VPC, EC2, Security Groups, VPC Flow Logs, CloudWatch Logs, CloudTrail, and IAM as core AWS components. The 12-week project timeline places the AWS lab in Weeks 2–3 and Flow Logs/CloudWatch configuration in Week 4.

The current codebase uses:

- Boto3 to retrieve events from a configured CloudWatch Logs log group;
- a parser for standard VPC Flow Logs version 2 records;
- a separate parser path for selected CloudTrail JSON events;
- local SQLite for findings.

The current collector is a CloudWatch Logs collector for the configured log group. It does not automatically create AWS resources, enable Flow Logs, configure CloudTrail, or discover security groups.

## 3. Before You Start

### 3.1 Required access

You need:

- An AWS account with permission to create the lab resources.
- Access to the AWS Management Console.
- A selected AWS Region. Use the same Region for the VPC, EC2 instance, CloudWatch log group, and Python collector unless you deliberately configure otherwise.
- A local Python environment for the project.
- A secure AWS credential method for the collector.

Use a non-production account if possible. Review your organization's policies before creating resources.

### 3.2 Choose a Region and network plan

For a simple lab, choose one Region and one VPC CIDR that does not overlap with any network you connect to.

Example lab plan (illustrative only):

| Resource | Example |
|---|---|
| Region | `ap-south-1` (Mumbai) |
| VPC name | `cloud-security-lab-vpc` |
| VPC IPv4 CIDR | `10.20.0.0/16` |
| Public subnet | `10.20.1.0/24` |
| Private subnet | `10.20.2.0/24` |
| EC2 name | `cloud-security-test-ec2` |
| Security Group | `cloud-security-lab-sg` |
| CloudWatch log group | `/aws/vpc/flowlogs/cloud-security-lab` |

These are example values. Check for CIDR overlap before using them. A private subnet is part of the intended lab design, but you do not need to launch a second EC2 instance merely to begin testing Flow Logs.

### 3.3 Cost awareness

AWS resources may incur charges. Potentially billable items include EC2 instance runtime, EBS storage, public IPv4 addresses, NAT Gateways, CloudWatch Logs ingestion/storage, and data transfer. Pricing varies by Region and configuration.

For a low-cost academic lab:

- use a small eligible instance type;
- avoid a NAT Gateway unless your design needs one;
- keep test windows short;
- set CloudWatch retention;
- stop or terminate resources when finished;
- delete unused volumes, snapshots, addresses, and log data when no longer needed.

Check current AWS pricing before deployment. Do not assume that an account is eligible for Free Tier pricing.

## 4. Create the VPC and Subnet

1. Sign in to the AWS Management Console.
2. Open **VPC** and select the chosen Region.
3. Open **Your VPCs** and choose **Create VPC**.
4. Create a VPC using the example name and CIDR from your lab plan, or use the VPC-and-more workflow if you want AWS to create subnets and routing resources together.
5. Create a public subnet in the VPC, using the planned subnet CIDR.
6. If the design requires a private subnet, create it separately. Do not assign a public IP to instances in the private subnet.
7. Create and attach an Internet Gateway only if the public subnet needs internet connectivity.
8. Add a default route (`0.0.0.0/0`) to the Internet Gateway in the public subnet's route table only when internet access is required.
9. Enable automatic public IPv4 assignment on the public subnet only if you intend to use public IPv4 addressing for the test instance.

A subnet is public because its route table has a route to an Internet Gateway; the subnet name alone does not make it public.

### 4.1 Verify the VPC

In the VPC console, confirm:

- the VPC is in the intended Region;
- the IPv4 CIDR is correct;
- the subnet belongs to this VPC;
- the public route table is associated with the public subnet;
- the Internet Gateway is attached if required.

## 5. Create a Security Group

1. Open **EC2 → Security Groups** or **VPC → Security Groups**.
2. Choose **Create security group**.
3. Name it `cloud-security-lab-sg`.
4. Select the lab VPC.
5. Add only the inbound rules needed for your lab.

Recommended starting policy:

| Traffic | Protocol / port | Source | Guidance |
|---|---|---|---|
| SSH administration | TCP 22 | Your current public IP `/32`, only if needed | Prefer Session Manager; never use `0.0.0.0/0` |
| HTTP test application | TCP 80 | Only the test client range that needs access | Add only if the lab hosts an HTTP service |
| HTTPS test application | TCP 443 | Only the test client range that needs access | Add only if the lab hosts an HTTPS service |
| Other ports | As required | Narrowest approved source | Document why each rule exists |

Security Groups are stateful virtual firewalls. Keep the default outbound rule only if it is appropriate for your lab policy; otherwise restrict outbound traffic to the destinations and ports required for the exercise.

Do not add public SSH, RDP, database, Redis, or other administrative service rules just to create test alerts. For planned exposure-detection work, inspect the security-group configuration as data and report the finding; do not leave a risky rule open unnecessarily.

## 6. Launch a Test EC2 Instance

1. Open **EC2 → Instances → Launch instances**.
2. Enter a name such as `cloud-security-test-ec2`.
3. Select a supported Amazon Machine Image (AMI), such as a current Amazon Linux image.
4. Choose a small instance type suitable for your test workload.
5. Select or create a key pair only if you will use SSH. Store the private key securely; never commit it to Git.
6. Under **Network settings**, select the lab VPC and public subnet if public connectivity is required.
7. Attach `cloud-security-lab-sg`.
8. Assign a public IP only if your access method requires it.
9. Configure an appropriately sized encrypted EBS root volume.
10. Launch the instance.

For a safer management path, configure Systems Manager prerequisites and use Session Manager instead of opening inbound SSH. Session Manager requires a suitable instance profile/permissions, a supported SSM Agent, and network connectivity to the Systems Manager service endpoints.

### 6.1 Verify the instance

Wait for the instance state and status checks to become healthy. Record:

- instance ID;
- VPC ID;
- subnet ID;
- network interface ID (`eni-...`);
- private IP;
- public IP, if assigned;
- attached Security Group ID.

The network interface ID is useful when investigating VPC Flow Logs.

## 7. Create a CloudWatch Log Group

1. Open **CloudWatch → Logs → Log groups**.
2. Choose **Create log group**.
3. Enter `/aws/vpc/flowlogs/cloud-security-lab`.
4. Set a retention period appropriate for the academic lab (for example, 7 or 14 days).
5. Create the log group in the same Region as the VPC.

Choose a retention period deliberately. Indefinite retention can increase storage costs and is usually unnecessary for a short lab.

## 8. Enable VPC Flow Logs to CloudWatch Logs

VPC Flow Logs are the primary network telemetry source for this project. They capture metadata about IP traffic to and from network interfaces in the selected scope. They do not capture packet payloads.

1. Open **VPC → Your VPCs**.
2. Select the lab VPC.
3. Open the **Flow logs** tab (or the Flow Logs section in the VPC details).
4. Choose **Create flow log**.
5. Set a descriptive name, such as `cloud-security-lab-vpc-flowlog`.
6. Select the traffic filter:
   - `ALL` records accepted and rejected traffic and is useful for this monitoring lab;
   - `REJECT` records only rejected traffic;
   - `ACCEPT` records only accepted traffic.
7. Select **CloudWatch Logs** as the destination.
8. Select the log group `/aws/vpc/flowlogs/cloud-security-lab`.
9. Select or create the IAM role that allows the VPC Flow Logs service to publish to the chosen CloudWatch Logs group.
10. Use the default VPC Flow Logs record format initially, unless you have updated the parser configuration to match a custom field order.
11. Create the flow log.

The VPC Flow Logs service-delivery role is distinct from the IAM identity used by your local Python collector. Do not reuse broad administrator permissions for either purpose.

### 8.1 Delivery and verification

Flow Logs are not an instantaneous packet capture. Allow time for records to be delivered.

1. Open the CloudWatch log group.
2. Open its log streams.
3. Confirm that records begin appearing.
4. Generate ordinary traffic to/from the test instance using authorized clients.
5. Refresh the log streams after the delivery interval.
6. Confirm that records contain the expected interface ID, source/destination addresses, ports, protocol, packet/byte counts, start/end times, action, and log status.

If no records appear, verify the flow-log status, IAM delivery role, destination log group Region, VPC/subnet/interface selection, and whether traffic has actually occurred.

## 9. Understand the Flow Log Format

The current parser expects the standard VPC Flow Logs version 2 field order:

```text
version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
```

Important fields:

| Field | Purpose in this project |
|---|---|
| `interface-id` | Identify the network interface |
| `srcaddr`, `dstaddr` | Source and destination addresses |
| `srcport`, `dstport` | Source and destination ports |
| `protocol` | IP protocol number |
| `packets`, `bytes` | Flow packet and byte counts |
| `start`, `end` | Flow interval timestamps |
| `action` | `ACCEPT` or `REJECT` |
| `log-status` | Flow log record status |

A custom Flow Logs format changes the field order/content. If you select a custom format, update the parser's configured field list to match exactly. Do not silently parse a custom format as version 2.

Flow Logs contain aggregated flow metadata, not application payload. A rejected flow is evidence of a rejected network flow, not proof of an intrusion attempt. Repeated connections do not prove authentication failures.

## 10. Configure IAM for the Python Collector

The local Python application needs permission to read events from the selected CloudWatch Logs group. It does not need permission to create or modify EC2 instances, VPCs, Security Groups, or Flow Logs.

Use an approved credential provider such as:

- IAM Identity Center / AWS CLI SSO;
- an assumed role;
- an EC2 instance profile when running the collector on EC2;
- another organization-approved temporary-credential mechanism.

Avoid long-lived IAM user access keys where possible. Never place access keys in Python source code, Git, screenshots, or a shared `.env` file.

### 10.1 Minimal collector permission example

The following is an illustrative identity policy for reading events from one log group. Replace the Region, account ID, and log-group name. Confirm the exact resource ARN and permissions against current AWS documentation and your account's policy requirements.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadProjectFlowLogs",
      "Effect": "Allow",
      "Action": [
        "logs:FilterLogEvents",
        "logs:DescribeLogStreams"
      ],
      "Resource": "arn:aws:logs:ap-south-1:123456789012:log-group:/aws/vpc/flowlogs/cloud-security-lab:*"
    }
  ]
}
```

The project collector's `FilterLogEvents` operation is the key read operation. `DescribeLogStreams` is included for operational inspection if required by your workflow; remove permissions that your actual code does not use. Do not attach `AdministratorAccess` to the collector.

The role used by the VPC Flow Logs service to publish records is a separate service role and needs the permissions required for CloudWatch Logs delivery. Follow the AWS VPC Flow Logs documentation when creating it.

## 11. Configure the Local Python Environment

From the repository root, create and activate a virtual environment:

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation due to execution policy, use an approved local policy or run the environment's Python executable directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

The project requirements include Boto3 and Streamlit. Install pytest separately if it is not listed in the current requirements file:

```bash
python -m pip install pytest
```

## 12. Configure AWS CLI Credentials

If using IAM Identity Center, configure an AWS CLI SSO profile according to your organization's setup:

```powershell
aws configure sso
aws sso login --profile cloud-security-lab
```

Set the profile for the current PowerShell session:

```powershell
$env:AWS_PROFILE = "cloud-security-lab"
$env:AWS_REGION = "ap-south-1"
$env:AWS_FLOW_LOG_GROUP = "/aws/vpc/flowlogs/cloud-security-lab"
```

For Linux/macOS:

```bash
export AWS_PROFILE=cloud-security-lab
export AWS_REGION=ap-south-1
export AWS_FLOW_LOG_GROUP=/aws/vpc/flowlogs/cloud-security-lab
```

Use your actual profile and Region values. The AWS SDK uses its standard credential provider chain; do not hard-code secrets in the application.

Verify the active identity:

```bash
aws sts get-caller-identity
```

This command should return the AWS account and principal associated with the active credentials. If it fails, resolve the credential/profile issue before running the collector.

## 13. Run the Project Pipeline

### 13.1 Test locally with sample data first

This does not require AWS credentials:

```powershell
python scripts/run_pipeline.py --source sample --dry-run
```

### 13.2 Collect from CloudWatch

After confirming that the log group contains records and the collector identity has the required permissions:

```powershell
python scripts/run_pipeline.py --source cloudwatch --hours 1 --dry-run
```

If the collector is working and you want to save events/findings to SQLite, omit `--dry-run`:

```powershell
python scripts/run_pipeline.py --source cloudwatch --hours 1
```

The default database path is `data/security_monitor.db`, unless you pass `--db-path`.

The collector's configured Region and log group should match the environment variables. If the current collector implementation does not accept a particular optional argument, use the environment variables supported by that implementation and verify with `python scripts/run_pipeline.py --help`.

## 14. CloudTrail — Separate AWS API Activity Source

The project brief also identifies CloudTrail as a source for AWS API/control-plane activity such as IAM changes and Security Group modifications.

CloudTrail is separate from VPC Flow Logs:

- VPC Flow Logs describe network-flow metadata.
- CloudTrail records AWS API activity.
- The current Python parser can normalize selected CloudTrail JSON events.
- The current VPC Flow Logs collector does not automatically retrieve CloudTrail events.

For an academic lab, first verify the CloudTrail event history in the AWS Console for the chosen Region. If you need a durable trail or delivery to CloudWatch Logs/S3, configure it separately using the CloudTrail User Guide. Confirm the event source and event names that your detector expects.

Do not claim CloudTrail ingestion is operational until a collection path has been implemented, tested, and evidenced.

## 15. Optional Services — Not Required for the Initial Lab

The project specification lists the following as recommended or optional, not mandatory for the initial MVP:

| Service | Potential future use |
|---|---|
| AWS Lambda | Run a bounded event-processing function |
| Amazon EventBridge | Route selected events to a processing workflow |
| Amazon S3 | Retain exported log data |
| Amazon Athena | Query log data stored in S3 |
| Amazon SNS | Send notifications |
| AWS Security Hub | Aggregate supported security findings |

Do not create these services merely to make the architecture look more complex. Add them only when a defined project requirement needs them.

## 16. Troubleshooting

| Symptom | Checks |
|---|---|
| No Flow Logs appear | Confirm Flow Logs are enabled on the intended VPC/subnet/ENI, traffic has occurred, delivery role is valid, log group Region matches, and delivery time has elapsed. |
| CloudWatch log group is empty | Check the VPC Flow Logs destination and delivery role; inspect Flow Log status/error information in the console. |
| `AccessDenied` from Boto3 | Confirm active identity with `aws sts get-caller-identity`, Region/profile, and scoped `logs:FilterLogEvents` permission. |
| `ResourceNotFoundException` | Check log group name, account, Region, and whether the group exists. |
| Parser rejects records | Inspect the exact record format and field count; check whether custom Flow Logs fields were selected. |
| Timestamps appear wrong | Verify that the parser uses the Flow Log `start`/`end` epoch values and converts them correctly. |
| No detections appear | Confirm that the relevant sample/live events satisfy the implemented threshold and time window. Check whether the rule is implemented or only planned. |
| Collector returns no events | Widen the bounded time window, verify that log records exist in the group, and confirm the collector's query window and Region. |
| AWS CLI works but Python fails | Confirm the Python process uses the same AWS profile/environment and that Boto3 is installed in the active virtual environment. |

## 17. Security Checklist

- [ ] Lab resources are isolated from production.
- [ ] No public SSH/RDP rule uses `0.0.0.0/0` or `::/0`.
- [ ] Security Groups allow only required traffic.
- [ ] AWS credentials are not hard-coded or committed.
- [ ] The collector identity follows least privilege.
- [ ] The VPC Flow Logs delivery role is separate from the collector identity.
- [ ] CloudWatch log retention is configured.
- [ ] Database files, raw logs, keys, and secrets are excluded from Git.
- [ ] Test traffic is generated only against owned or explicitly authorized resources.
- [ ] Findings are treated as indicators requiring investigation, not confirmed attacks.
- [ ] No automatic blocking is enabled during early development.

## 18. Evidence to Capture for the Project Report

Capture screenshots or sanitized command output for:

1. VPC details and CIDR.
2. Subnet and route table association.
3. Security Group inbound/outbound rules.
4. EC2 instance and network interface details.
5. VPC Flow Logs configuration and status.
6. CloudWatch log group and sample records.
7. `aws sts get-caller-identity` output with sensitive identifiers redacted as appropriate.
8. Successful sample-data pipeline run.
9. Successful bounded CloudWatch collection, if completed.
10. SQLite findings and dashboard output.

Do not include private keys, access keys, session tokens, or other secrets in evidence.

## 19. Cleanup

When the lab is no longer required:

1. Stop or terminate the EC2 test instance.
2. Confirm whether the EBS volume should be deleted; preserve it only if required for evidence.
3. Delete unused Elastic IP addresses or other billable networking resources.
4. Delete the VPC Flow Log after evidence collection if monitoring is no longer needed.
5. Delete unused CloudWatch log groups/streams after preserving required sanitized evidence and considering retention requirements.
6. Detach and delete the Internet Gateway if it is no longer needed.
7. Delete subnets, route tables, and the VPC after dependent resources are removed.
8. Remove temporary IAM roles/policies that were created only for the lab.
9. Review the AWS Billing console for remaining resources and charges.

Do not delete shared or pre-existing account resources. Verify resource ownership before cleanup.

## 20. Official References

The following official sources are the primary technical references identified for this project:

- [Amazon VPC User Guide](https://docs.aws.amazon.com/vpc/latest/userguide/)
- [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [VPC Flow Log records](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html)
- [Create and configure Security Groups](https://docs.aws.amazon.com/vpc/latest/userguide/creating-security-groups.html)
- [Amazon CloudWatch Logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/)
- [AWS CloudTrail](https://docs.aws.amazon.com/cloudtrail/)
- [AWS CloudTrail User Guide](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/)
- [IAM Getting Started](https://docs.aws.amazon.com/IAM/latest/UserGuide/getting-started.html)
- [IAM Security Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Boto3 documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)

Use AWS documentation as the authority for current console labels, supported features, IAM permissions, and service behavior. Console labels may change over time.
