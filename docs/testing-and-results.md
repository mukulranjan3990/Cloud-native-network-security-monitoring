# Testing and Results

## 1. Purpose

This document describes the current test approach and the validation evidence available for the project. It distinguishes automated unit-test results from simulated-data demonstrations and from live AWS integration testing.

## 2. Testing Scope

Testing is organized around the project's processing stages:

1. Parser correctness.
2. Detection rule behavior.
3. Risk-score and severity calculations.
4. SQLite persistence and finding workflow.
5. End-to-end sample-data pipeline execution.
6. Live AWS collection and dashboard integration when the AWS environment is configured.

## 3. Test Environment

The automated tests use Python, pytest, the project's `src/` modules, and temporary SQLite databases. Sample VPC Flow Logs are synthetic and use documentation/example IP address ranges. They are not real AWS observations.

The current test files are:

```text
tests/
├── test_parser.py
├── test_detector.py
├── test_risk_scorer.py
└── test_database.py
```

## 4. Unit Test Coverage

### 4.1 Parser tests

The parser tests cover:

- standard VPC Flow Logs version 2 field parsing;
- integer fields and missing values represented by `-`;
- incorrect field counts;
- invalid input types;
- selected CloudTrail event normalization;
- JSON CloudTrail string parsing;
- CloudWatch metadata preservation;
- malformed JSON and empty messages.

### 4.2 Detector tests

The detector tests cover:

- possible port-scan detection at the configured threshold;
- no port-scan finding below the threshold;
- repeated-connection detection;
- excessive rejected-flow detection;
- sensitive destination-port detection;
- high-byte single-flow detection;
- selected security-group CloudTrail event detection;
- validation of positive thresholds.

### 4.3 Risk-scoring tests

The scoring tests cover:

- severity boundaries for INFORMATIONAL, LOW, MEDIUM, HIGH, and CRITICAL;
- known rule base scores;
- context adjustments;
- score bounds;
- unknown-rule fallback;
- validation of custom base scores;
- preservation of the input finding.

### 4.4 Database tests

The database tests cover:

- SQLite initialization;
- single and batch event insertion;
- empty batch behavior;
- finding insertion and duplicate prevention;
- batch finding insertion counts;
- severity/status filtering;
- finding status updates;
- summary counts;
- positive query limits.

## 5. Automated Test Result

**Recorded execution result:** 45 tests passed.

```text
45 passed in 0.24s
pytest exit code: 0
```

This result applies to the four current test modules and the source modules used during that test run. Re-run the suite in the final project environment before submission so the submitted repository state is the state being validated.

Command:

```powershell
python -m pytest tests/ -v
```

If pytest is not installed:

```powershell
pip install pytest
```

## 6. Synthetic Sample Dataset

The project sample-data directory contains:

| File | Intended behavior | Records |
|---|---|---:|
| `normal-traffic.log` | Routine accepted traffic | 8 |
| `port-scan.log` | One source contacts multiple destination ports | 12 |
| `rejected-traffic.log` | Repeated rejected flows from one source | 12 |

Each non-comment record uses the 14-field VPC Flow Logs version 2 format. The records are synthetic and are intended for parser and detection demonstrations.

## 7. Pipeline Demonstration

The pipeline script supports sample input by default and an explicit dry-run mode:

```powershell
python scripts/run_pipeline.py --source sample --dry-run
```

A recorded synthetic-data dry-run used lower rejected/repeated thresholds for demonstration and reported:

- 32 records parsed;
- 6 findings detected;
- 0 parse errors.

This is a demonstration result for the particular synthetic dataset and adjusted thresholds. It is not a detection-accuracy benchmark, not evidence of live AWS monitoring, and not a claim that six real attacks occurred.

For persistent local execution:

```powershell
python scripts/run_pipeline.py --source sample
```

The default SQLite database path is `data/security_monitor.db` unless overridden.

## 8. Recommended Test Scenarios and Expected Results

| Scenario | Input / action | Expected outcome | Status |
|---|---|---|---|
| Normal traffic | `normal-traffic.log` | Records parse; no broad scan/rejected-volume finding should be generated under defaults | Synthetic dataset available; verify with current detector |
| Possible port scan | `port-scan.log` | NET-001 should trigger if the source reaches the configured unique-port threshold within the 60-second window | Detector unit test covers threshold behavior |
| Excessive rejected flows | `rejected-traffic.log` | NET-005 should trigger when rejected-flow count meets configured threshold | Detector unit test covers threshold behavior |
| Sensitive port | Flow to port 22/3389/database port | NET-006 should trigger | Detector unit test covers |
| High-volume flow | One flow at or above 500 MiB | NET-007 should trigger | Detector unit test covers |
| IAM API activity | Selected CloudTrail IAM event | NET-008 should trigger | CloudTrail detector test coverage should be extended for all event names |
| Security-group change | Selected CloudTrail security-group event | NET-009 should trigger | Detector unit test covers |
| Internet-exposed SSH/RDP | Security group ingress open to public CIDR | NET-002/003 should trigger after configuration-inspection module exists | Planned; not implemented |
| Authentication failures | OS/application auth failure records | NET-010 should trigger after authentication parser/source exists | Planned; not implemented |
| Live CloudWatch collection | Configure AWS identity, region, log group | Collector retrieves authorized log records | Requires execution in configured AWS account |

## 9. False-Positive and False-Negative Analysis

A rule may trigger on legitimate activity:

- vulnerability scanning or approved inventory may resemble a port scan;
- application retries may resemble repeated connection attempts;
- misconfigured clients may generate rejected flows;
- administrators and applications may legitimately use sensitive ports;
- backups and bulk transfers may exceed a fixed byte threshold;
- approved IAM/security-group changes may match administrative event rules.

A rule may miss activity if:

- the relevant logs are not enabled or delivered;
- the event falls outside the selected time window;
- thresholds are too high;
- a custom Flow Logs format is parsed using the wrong field order;
- authentication or configuration telemetry is unavailable;
- the suspicious behavior does not match the current heuristic.

Thresholds should be tuned against representative normal and controlled test data. No precision, recall, false-positive rate, or false-negative rate should be reported until a labeled dataset and repeatable measurement method exist.

## 10. Live AWS Integration Checklist

Before claiming live collection:

- [ ] Use a dedicated test VPC and authorized resources.
- [ ] Enable VPC Flow Logs for the intended VPC/subnet/interface.
- [ ] Configure delivery to the selected CloudWatch Logs group.
- [ ] Verify records are arriving in CloudWatch Logs.
- [ ] Configure the AWS credential provider securely.
- [ ] Set `AWS_REGION` and `AWS_FLOW_LOG_GROUP`.
- [ ] Confirm the IAM identity can call `logs:FilterLogEvents` for the required log group.
- [ ] Run a bounded collection window.
- [ ] Preserve sanitized evidence of successful collection.
- [ ] Record any missing records, throttling, or permission errors.

CloudTrail events require a separately configured collection/ingestion path; the current Flow Logs collector does not automatically ingest CloudTrail.

## 11. Dashboard Validation Checklist

- [ ] Start the dashboard against the intended SQLite database.
- [ ] Confirm the dashboard can read the `events` and `findings` tables.
- [ ] Confirm event and finding totals match the database.
- [ ] Verify severity and status filters.
- [ ] Open a finding and inspect its evidence/recommendation.
- [ ] Test empty database and missing database behavior.
- [ ] Confirm the dashboard does not mutate findings unless a workflow action is explicitly implemented.

## 12. Security Testing Rules

All simulated network activity must be generated only against infrastructure owned by the project developer or explicitly authorized for testing. Do not scan public systems or third-party networks.

Do not enable automatic blocking during early development. Any future response workflow should require risk assessment, human approval, audit logging, and verification.

## 13. Current Limitations

- The 45-test result is unit-test evidence, not a complete integration or penetration-test result.
- Sample data is synthetic.
- Live AWS collection requires configuration and has not been established by the unit-test result.
- CloudTrail collection/ingestion is separate.
- NET-002, NET-003, and NET-010 remain planned.
- NET-007 uses a fixed per-flow byte threshold, not a traffic baseline.
- YAML rules are not yet loaded dynamically by the detector.
- Dashboard launch and data-path integration should be validated in the final assembled repository.
- No automated response is implemented.

## 14. Final Reporting Guidance

In the final report, state exactly which tests were executed, on what dataset, with which thresholds, and what output was observed. Distinguish:

- unit-test pass results;
- synthetic-data demonstration results;
- live AWS integration evidence;
- planned but unimplemented features.

Do not describe a suspicious finding as a confirmed attack unless independent evidence supports that conclusion.
