# Testing Strategy

## 1. Purpose

This document describes how to test the **Automated Cloud-Native Network Security Monitoring & Automated Threat Detection System**, from individual parsing functions through end-to-end detection and dashboard behavior.

All live security testing must be performed only against infrastructure owned by the project or explicitly authorized for testing.

## 2. Testing Objectives

- Verify that supported log records are parsed correctly.
- Verify that normalized events preserve the fields required by detection rules.
- Verify that each implemented detection triggers on matching test data.
- Verify that non-matching or normal cases do not trigger unnecessarily.
- Verify risk scores, severity bands, and stored findings.
- Verify dashboard display and filtering.
- Document false positives, limitations, and test evidence.

## 3. Test Levels

### 3.1 Unit Testing

Test individual components in isolation:

- Log parser and field validation.
- Event normalization.
- Detection-rule functions.
- Risk-score calculation.
- Severity mapping.
- Finding creation and database operations.

### 3.2 Integration Testing

Test the interaction between components:

- Log records to parser.
- Normalized events to detection rules.
- Detection results to risk scoring.
- Findings to SQLite.
- SQLite findings to Streamlit dashboard.

### 3.3 End-to-End Testing

Run a complete test path using sample records or controlled AWS lab telemetry, from event collection through dashboard display.

### 3.4 Security and Robustness Testing

Check malformed records, missing fields, unexpected values, unauthorized access paths where applicable, credential handling, and error logging.

### 3.5 User Interface Testing

Confirm that findings are readable, severity is visible, filters behave as expected, and empty/error states are understandable.

## 4. Test Environment

The intended live test environment is a controlled AWS lab with the required VPC, EC2, security groups, VPC Flow Logs, and CloudWatch Logs. Tests that do not require live AWS resources may use clearly labelled synthetic test records.

Record the AWS region, resource identifiers where appropriate, configuration assumptions, test date, and relevant software versions. Do not include credentials or secrets in test evidence.

## 5. Test Scenarios

| Test ID | Scenario | Expected result |
|---|---|---|
| TS-01 | Parse a valid supported flow-log record | Required fields are extracted correctly. |
| TS-02 | Parse a record with missing or malformed fields | Record is handled safely and error is recorded; application does not crash. |
| TS-03 | Normalize a valid event | Output follows the documented normalized-event structure. |
| TS-04 | Feed a matching possible port-scan dataset | NET-001 triggers with supporting evidence. |
| TS-05 | Feed a normal connection pattern | No port-scan finding unless the documented threshold is met. |
| TS-06 | Evaluate a test SSH exposure configuration | NET-002 triggers only when configuration evidence meets the rule. |
| TS-07 | Evaluate a test RDP exposure configuration | NET-003 triggers only when configuration evidence meets the rule. |
| TS-08 | Feed repeated connection records | NET-004 triggers when its configured condition is met. |
| TS-09 | Feed high rejected-traffic records | NET-005 triggers when the configured threshold is met. |
| TS-10 | Feed traffic to a sensitive port outside expected policy | NET-006 triggers when the policy context and evidence support it. |
| TS-11 | Feed traffic above a documented baseline | NET-007 triggers when the configured threshold is met. |
| TS-12 | Test optional CloudTrail event processing | Implemented API-event rules trigger only on supported matching events. |
| TS-13 | Calculate risk scores at boundary values | Scores remain in 0–100 and severity bands are correct. |
| TS-14 | Store and retrieve a finding | Stored fields remain consistent. |
| TS-15 | Open dashboard and apply filters | Relevant findings display and filters work correctly. |
| TS-16 | Run an end-to-end test | Test event can be traced through processing to a dashboard finding. |

Only mark a scenario as passed after it has actually been executed and evidence has been reviewed.

## 6. Detection Rule Test Procedure

For each implemented rule:

1. Document the rule ID, required telemetry, and threshold.
2. Create a positive test case that should trigger the rule.
3. Create a negative or normal case that should not trigger it.
4. Run the test through the actual parser and detector.
5. Verify the rule ID, evidence, severity, and risk score.
6. Record expected and observed results.
7. Analyze unexpected findings and adjust the rule only with a documented reason.

## 7. False-Positive and False-Negative Analysis

### False Positives

Review findings generated for benign activity. Record why the rule triggered, whether the threshold was appropriate, and what adjustment is justified.

### False Negatives

Where a test case is known to represent the behavior a rule should detect, check whether the rule missed it. Document the cause, such as missing telemetry, parsing errors, or a threshold that was too high.

Do not claim a detection rate or accuracy percentage unless the dataset, ground truth, calculation, and results support it.

## 8. Evidence Requirements

For each test, keep:

- Test ID and purpose.
- Preconditions.
- Data source (synthetic or live lab).
- Steps performed.
- Expected result.
- Actual result.
- Pass/fail status.
- Relevant output, screenshot, or log excerpt.
- Notes on false positives, false negatives, and limitations.

Redact credentials, tokens, and unrelated sensitive information from screenshots and logs.

## 9. Suggested Test Directory

```text
tests/
├── unit/
├── integration/
├── test-data/
└── README.md

evidence/
├── screenshots/
├── test-results/
└── validation-notes.md
```

This is a suggested layout; adapt it to the repository that is actually implemented.

## 10. Exit Criteria

Testing is ready for final review when:

- [ ] Parser unit tests pass for supported record formats.
- [ ] Malformed input is handled safely.
- [ ] Every implemented detection rule has positive and negative tests.
- [ ] Risk-score boundaries and severity mapping are tested.
- [ ] Findings can be stored and retrieved.
- [ ] Dashboard display and filters are checked.
- [ ] An end-to-end path is demonstrated.
- [ ] Test results and evidence are organized.
- [ ] False-positive observations and known limitations are documented.
- [ ] No unsupported accuracy or security claims are made.
