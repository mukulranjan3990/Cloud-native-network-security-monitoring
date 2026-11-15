# Automated Cloud-Native Network Security Monitoring & Threat Detection System

A Python-based AWS security monitoring project that collects VPC Flow Logs from
Amazon CloudWatch Logs, normalizes events, evaluates explainable detection
rules, assigns a heuristic risk score, and stores security findings in SQLite.

The project is an academic MVP focused on AWS network security and threat
monitoring. It is not a full SIEM/SOAR platform and does not claim that a
suspicious event is proof of a confirmed attack.

## 1. Project objectives

The system is intended to help answer:

> What is happening in the AWS network, which activity looks suspicious, how
> should it be prioritized, and what should the administrator investigate?

The main processing flow is:

```text
AWS VPC
   |
   v
VPC Flow Logs
   |
   v
Amazon CloudWatch Logs
   |
   v
src/collector.py  ------> Collect raw log events
   |
   v
src/parser.py     ------> Normalize network / selected AWS API events
   |
   v
src/detector.py   ------> Evaluate detection heuristics
   |
   v
src/risk_scorer.py -----> Add risk score and severity
   |
   v
src/database.py   ------> Store events and findings in SQLite
   |
   v
Streamlit dashboard (planned application layer)
```

CloudTrail support is available in the parser and selected API-event detection
logic. CloudTrail collection and ingestion must be configured separately; it
is not automatically performed by the VPC Flow Logs collector.

## 2. Technology stack

| Area | Technology |
|---|---|
| Programming language | Python 3.10+ |
| AWS SDK | Boto3 |
| Network telemetry | Amazon VPC Flow Logs |
| Log destination | Amazon CloudWatch Logs |
| Optional AWS API telemetry | AWS CloudTrail |
| Detection | Python rule-based heuristics |
| Database | SQLite |
| Planned dashboard | Streamlit |

## 3. Repository structure

```text
cloud-native-network-security-monitoring/
│
├── README.md
├── requirements.txt
├── .gitignore
├── .env.example
│
├── src/
│   ├── __init__.py
│   ├── collector.py
│   ├── parser.py
│   ├── detector.py
│   ├── risk_scorer.py
│   └── database.py
│
├── rules/
│   └── detection-rules.yaml       # planned configuration file
│
├── sample-data/                   # safe, synthetic test records
├── tests/
│   ├── unit/
│   ├── integration/
│   └── test-data/
│
├── dashboard/                     # Streamlit dashboard (planned)
├── docs/
└── data/                           # local database; do not commit
```

Directories marked as planned should be added when their implementation phase
begins. The six Python modules in `src/` are the current core implementation.

## 4. Setup

### Prerequisites

- Python 3.10 or newer
- pip
- An AWS account only when collecting real AWS logs
- AWS credentials configured through an approved credential provider
- A CloudWatch Logs log group receiving VPC Flow Logs

### Create and activate a virtual environment

**Windows PowerShell**

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

**Linux / macOS**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
```

### Install dependencies

```bash
pip install -r requirements.txt
```

### Configure environment variables

Copy `.env.example` to `.env` and set the values for your environment.
The `.env` file is intentionally ignored by Git.

The current Python modules do not automatically load `.env`. Set the variables
in your terminal, IDE run configuration, or application entry point. Never put
AWS access keys in `.env` or commit credentials. Prefer an IAM role, AWS IAM
Identity Center, or another supported temporary-credential provider.

For Windows PowerShell, for example:

```powershell
$env:AWS_REGION = "ap-south-1"
$env:AWS_FLOW_LOG_GROUP = "/aws/vpc/flow-logs"
```

For Linux / macOS:

```bash
export AWS_REGION="ap-south-1"
export AWS_FLOW_LOG_GROUP="/aws/vpc/flow-logs"
```

The region and log group above are examples. Replace them with the values from
your own AWS environment.

## 5. AWS configuration

1. Create a dedicated, controlled test VPC and test resources.
2. Enable VPC Flow Logs for the intended VPC, subnet, or network interface.
3. Deliver the Flow Logs to a CloudWatch Logs log group.
4. Configure the collector's IAM identity with only the required read access.
5. Set `AWS_REGION` and `AWS_FLOW_LOG_GROUP`.
6. Confirm that records are arriving in the configured log group before
   running collection.

The collector uses the CloudWatch Logs `FilterLogEvents` API. The AWS identity
needs permission to read the selected log group (including
`logs:FilterLogEvents`). Scope permissions to the required resources wherever
AWS supports resource-level permissions.

### Flow Log format

The parser's default format is the standard VPC Flow Logs version 2 field
order:

```text
version account-id interface-id srcaddr dstaddr srcport dstport protocol
packets bytes start end action log-status
```

If you configure a custom VPC Flow Logs format, pass the exact ordered field
list to `EventParser(flow_log_fields=[...])`. The number and order of fields
must match the configured Flow Logs format.

`SKIPDATA` and other nonstandard or incomplete records should be handled as
data-quality cases; do not interpret missing fields as zero-valued observations.

## 6. Current Python module responsibilities

| File | Responsibility |
|---|---|
| `src/collector.py` | Reads events from a configured CloudWatch Logs log group using Boto3. |
| `src/parser.py` | Parses VPC Flow Log lines and selected CloudTrail JSON events into normalized dictionaries. |
| `src/detector.py` | Evaluates the current batch-based detection heuristics. |
| `src/risk_scorer.py` | Adds a transparent 0–100 project-defined score and severity. |
| `src/database.py` | Creates SQLite tables and persists normalized events and findings. |
| `src/__init__.py` | Exposes the core module classes and parser functions. |

## 7. Current detection coverage

The current detector implements these rules:

| Rule | Detection |
|---|---|
| NET-001 | Possible port scan: one source contacts multiple destination ports within a configured time window. |
| NET-004 | Repeated connections to the same destination and port. |
| NET-005 | Excessive rejected traffic from a source within a configured time window. |
| NET-006 | Traffic targeting selected sensitive administrative/database ports. |
| NET-007 | A single flow exceeding a configured byte threshold. |
| NET-008 | Selected sensitive IAM/access-management CloudTrail API events. |
| NET-009 | Selected security-group modification CloudTrail API events. |

Important scope notes:

- NET-002 (internet-exposed SSH) and NET-003 (internet-exposed RDP) require
  security-group configuration inspection. A flow record alone does not prove
  that a security group is unrestricted.
- Repeated connections do not by themselves prove brute-force activity.
  Authentication logs are needed to support an authentication-failure
  detection such as NET-010.
- NET-007 currently compares an individual flow against a fixed threshold; it
  is not yet a time-series baseline or anomaly-learning system.
- Detection thresholds are initial heuristics and must be validated and tuned
  using the controlled lab dataset.
- CloudTrail event parsing is implemented, but a CloudTrail collection
  integration is a separate task.

## 8. Example usage

Run commands from the repository root.

### Parse and detect a synthetic flow record

```python
from src.parser import EventParser
from src.detector import ThreatDetector
from src.risk_scorer import RiskScorer

parser = EventParser()

# Synthetic example only. It is not a real AWS observation.
sample_line = (
    "2 123456789012 eni-0123456789abcdef0 "
    "10.0.1.50 10.0.2.10 51514 22 6 10 1200 "
    "1730000000 1730000010 ACCEPT OK"
)

event = parser.parse(sample_line)

detector = ThreatDetector()
findings = detector.detect([event])

scorer = RiskScorer()
scored_findings = scorer.score_findings(findings)

for finding in scored_findings:
    print(finding)
```

A single record will not normally trigger NET-001 because port-scan detection
needs multiple distinct destination ports from the same source within the
configured window.

### Initialize the SQLite database

```python
from src.database import SecurityDatabase

database = SecurityDatabase("data/security_monitor.db")
print(database.get_summary())
```

### Collect CloudWatch events

```python
from src.collector import CloudWatchLogCollector

collector = CloudWatchLogCollector()
raw_events = collector.fetch_events(
    start_time_ms=1730000000000,
    end_time_ms=1730003600000,
    limit=1000,
)

print(f"Collected {len(raw_events)} log events")
```

Use a real time range appropriate to your AWS environment. CloudWatch API
times are Unix timestamps in milliseconds.

## 9. Risk scoring and severity

The risk scorer uses a project-defined, explainable heuristic. Its score is
for prioritizing investigation; it is not a recognized industry-standard
score and is not a probability of compromise.

Current severity bands:

| Score | Severity |
|---:|---|
| 85–100 | CRITICAL |
| 65–84 | HIGH |
| 40–64 | MEDIUM |
| 20–39 | LOW |
| 0–19 | INFORMATIONAL |

The final score is clamped to the 0–100 range. Each scored finding includes
risk-factor explanations.

## 10. Database

SQLite is used for the MVP. The database module creates:

- `events`: normalized event records and their original normalized payload.
- `findings`: detection results, score, severity, status, recommendation, and
  the complete finding payload.

The default database path is `data/security_monitor.db` when supplied by the
caller. The `data/` directory and database file should remain untracked.

## 11. Testing and validation

Before connecting a live AWS environment:

1. Test parsing with synthetic VPC Flow Log records.
2. Test malformed records and missing values.
3. Test each detection rule with both triggering and non-triggering examples.
4. Test risk-score boundaries and severity mapping.
5. Test SQLite inserts, duplicate-finding handling, filters, and status updates.
6. Compare results with expected behavior and document false positives and
   limitations.

Only generate security test traffic against infrastructure you own or are
explicitly authorized to test. Do not run scans against public or third-party
systems.

## 12. Security practices

- Never hard-code AWS access keys, passwords, or tokens.
- Never commit `.env`, credentials, local databases, or sensitive logs.
- Use least-privilege IAM permissions and temporary credentials where practical.
- Keep the AWS lab isolated from production resources.
- Treat source IPs and event payloads as untrusted input.
- Review findings before taking response actions.
- Do not automatically block traffic during the initial MVP.

## 13. Project references

Use official documentation as the primary technical authority:

- [Amazon VPC documentation](https://docs.aws.amazon.com/vpc/latest/userguide/)
- [VPC Flow Logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- [VPC Flow Log record fields](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html)
- [Amazon CloudWatch Logs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/)
- [AWS CloudTrail](https://docs.aws.amazon.com/cloudtrail/)
- [AWS IAM security best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Boto3 documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
- [MITRE ATT&CK: Network Service Discovery (T1046)](https://attack.mitre.org/techniques/T1046/)
- [MITRE ATT&CK: Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)
- [Python documentation](https://docs.python.org/3/)
- [Streamlit documentation](https://docs.streamlit.io/)

## 14. Development status

This repository is being developed in phases. The current `src/` modules
provide the initial collection, parsing, detection, risk-scoring, and SQLite
persistence building blocks. A complete end-to-end service, dashboard,
CloudTrail collector, configuration-driven rules, and comprehensive automated
test suite are separate implementation tasks and should not be described as
finished until implemented and tested.
