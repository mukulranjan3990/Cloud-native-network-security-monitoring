# System Architecture

## 1. Architecture Goal

The system follows a modular, event-processing architecture. It collects selected AWS telemetry, normalizes raw records, evaluates detection heuristics, scores findings, stores results, and exposes them for analyst review.

The design prioritizes correctness and explainability over complex infrastructure.

## 2. Logical Architecture

```text
                   AWS ACCOUNT (CONTROLLED TEST ENVIRONMENT)
  +----------------------------------------------------------------+
  |                                                                |
  |  VPC                                                           |
  |  +-------------------+         +----------------------------+  |
  |  | EC2 / ENIs        |         | Security Groups / IAM      |  |
  |  +---------+---------+         +--------------+-------------+  |
  |            |                                  |                |
  |            v                                  v                |
  |      VPC Flow Logs                      CloudTrail events      |
  |            |                                  |                |
  +------------|----------------------------------|----------------+
               v                                  |
       CloudWatch Logs                            | separately
               |                                  | configured feed
               v                                  v
       Boto3 CloudWatch collector           CloudTrail JSON input
               |                                  |
               +------------------+---------------+
                                  v
                           Event Parser
                                  |
                                  v
                         Normalized Events
                                  |
                                  v
                           Threat Detector
                                  |
                                  v
                            Risk Scorer
                                  |
                                  v
                         SQLite Database
                         /             \
                        v               v
                Findings / Events   Streamlit UI
                                        |
                                        v
                              Analyst investigation
```

## 3. Components and Responsibilities

| Component | File / service | Responsibility |
|---|---|---|
| AWS network environment | VPC, EC2, ENIs, Security Groups | Controlled source of network activity |
| Network telemetry | VPC Flow Logs | Records network flow observations |
| Log storage | CloudWatch Logs | Receives and stores Flow Log records |
| Collector | `src/collector.py` | Retrieves log events from a configured CloudWatch log group |
| Parser | `src/parser.py` | Converts Flow Log lines and selected CloudTrail JSON into normalized dictionaries |
| Detection engine | `src/detector.py` | Evaluates supported rules against a batch of normalized events |
| Risk scorer | `src/risk_scorer.py` | Adds base score, context adjustments, severity, and score explanations |
| Persistence | `src/database.py` | Stores events/findings and provides retrieval/status methods in SQLite |
| Pipeline entry point | `scripts/run_pipeline.py` | Connects input, parsing, detection, scoring, and persistence |
| Dashboard | `dashboard/app.py` | Reads SQLite data and presents summaries/findings |
| Rule specification | `rules/detection-rules.yaml` | Documents rule definitions and planned/implemented status |

## 4. Event Processing Sequence

1. The operator selects sample input or CloudWatch as the pipeline source.
2. For sample input, non-empty, non-comment records are read from `.log` files.
3. For CloudWatch input, the collector calls `FilterLogEvents` for a configured time range and log group.
4. The parser identifies the input type:
   - whitespace-delimited VPC Flow Log record;
   - CloudWatch wrapper containing a `message`;
   - selected CloudTrail JSON event.
5. The parser creates a normalized event with an `event_type` of `NETWORK_FLOW` or `AWS_API`.
6. The detector separates supported event types and evaluates rule-specific conditions.
7. The risk scorer attaches a score from 0 to 100, a severity, and explanatory risk factors.
8. The database stores normalized events and scored findings.
9. The dashboard reads the database and displays event/finding summaries.

## 5. Normalized Event Model

### 5.1 Network flow event

Typical fields:

```json
{
  "event_type": "NETWORK_FLOW",
  "timestamp": "UTC ISO-8601 timestamp",
  "account_id": "AWS account identifier",
  "interface_id": "eni identifier",
  "source_ip": "source address",
  "destination_ip": "destination address",
  "source_port": 51524,
  "destination_port": 443,
  "protocol": 6,
  "packets": 12,
  "bytes": 8420,
  "start_time": 1731501000,
  "end_time": 1731501060,
  "action": "ACCEPT",
  "log_status": "OK",
  "raw": {}
}
```

Missing or unavailable values remain `None` where appropriate. The example values are illustrative, not live AWS data.

### 5.2 AWS API event

Selected CloudTrail events use `event_type: AWS_API` and include timestamp, source IP, account, event source/name, region, user ARN/type, request parameters, and raw payload. Network-only fields are not fabricated for an AWS API event.

## 6. Detection and Scoring

The detector currently uses threshold-based, batch-oriented heuristics. Its default thresholds include:

| Rule | Current default condition |
|---|---|
| NET-001 | At least 10 unique destination ports from one source within 60 seconds |
| NET-004 | At least 20 connections to the same destination and port from one source within 300 seconds |
| NET-005 | At least 100 REJECT flow records from one source within 3,600 seconds |
| NET-006 | Destination port in 22, 3389, 3306, 5432, 6379, or 27017 |
| NET-007 | One flow has at least 500 MiB (`500 * 1024 * 1024`) |
| NET-008 | Event name matches selected IAM/access-management actions |
| NET-009 | Event name matches selected security-group modification actions |

Risk scoring starts with a rule base score, applies explicit context adjustments, and clamps the result to 0–100. Severity bands are:

| Severity | Score |
|---|---:|
| CRITICAL | 85–100 |
| HIGH | 65–84 |
| MEDIUM | 40–64 |
| LOW | 20–39 |
| INFORMATIONAL | 0–19 |

The score is a project-defined prioritization heuristic, not a recognized industry-standard score or attack probability.

## 7. Data Storage

SQLite currently stores two main tables:

- `events`: event type, timestamp, source/destination, destination port, action, serialized payload, and creation time.
- `findings`: stable finding key, rule, title, description, timestamp, source/destination, port, severity, risk score, status, recommendation, serialized payload, and creation time.

Indexes support timestamp, source IP, severity, and status queries. Finding statuses supported by the database layer are `OPEN`, `INVESTIGATING`, and `CLOSED`.

## 8. Trust Boundaries and Security Controls

- AWS account boundary: only a dedicated, authorized test environment should be used.
- IAM boundary: collector credentials should have least-privilege read access.
- Log-data boundary: log content is untrusted input and must be parsed/validated.
- Local storage boundary: database and raw log artifacts may contain sensitive infrastructure details; do not commit them.
- Analyst action boundary: the MVP reports and recommends; it does not automatically block or modify resources.

## 9. Deployment View

The current MVP can run locally from a Python virtual environment. Sample-data mode does not require AWS credentials. Live collection requires a configured AWS credential provider, region, and CloudWatch log group.

The dashboard is a separate Streamlit process that reads the configured SQLite database. Confirm the database path is consistent between pipeline and dashboard.

## 10. Known Architecture Gaps

- CloudTrail event parsing/detection exists, but CloudTrail collection and ingestion are separate work.
- Security-group configuration inspection for NET-002/003 is not implemented.
- Authentication telemetry for NET-010 is not integrated.
- The YAML rules file is a declarative specification; runtime YAML loading is not currently connected to `src/detector.py`.
- No automated response, distributed queue, or production-scale architecture is included.
- Terraform scope is deferred pending resolution of the difference between the main technical brief and the 12-week timeline.
