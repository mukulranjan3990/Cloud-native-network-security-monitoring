# Risk Scoring

## 1. Purpose

This document defines a proposed, explainable risk-scoring model for findings produced by the **Automated Cloud-Native Network Security Monitoring & Automated Threat Detection System**.

The model is a project-specific heuristic. It must not be described as an industry-standard score unless the implementation is changed to follow a recognized standard.

## 2. Design Principles

- Scores should be understandable and reproducible.
- A finding should retain the evidence and rule that produced it.
- Severity should consider context, not only a port number or event count.
- Missing information should not be treated as evidence of safety.
- Suspicious behavior should not automatically be called a confirmed attack.
- The scoring method and thresholds must be documented and tested.

## 3. Proposed Score

Use a score from **0 to 100** as a project-specific prioritization aid.

A possible initial weighted model is:

| Factor | Weight | Meaning |
|---|---:|---|
| Exposure | 25 | How broadly reachable or exposed is the target, based on available evidence? |
| Frequency | 20 | How often does the behavior occur within the chosen time window? |
| Target sensitivity | 20 | How sensitive or important is the affected resource? |
| Event type | 20 | How concerning is the observed behavior according to the documented rule? |
| Context / source reputation | 15 | Is there reliable contextual evidence that raises or lowers concern? |

**Total weight: 100**

Each factor may be rated from 0 to 5. Normalize the weighted result to a 0–100 scale:

```text
Risk Score = sum(weight_i * factor_rating_i / 5)
```

Here, each `factor_rating_i` is between 0 and 5, and the weights sum to 100. The resulting score is between 0 and 100.

This is a starting proposal, not a validated security standard. Adjust weights only after documenting the rationale and testing the impact.

## 4. Factor Rating Guidance

### Exposure (0–5)

- 0: No relevant exposure evidence.
- 1: Narrow or limited exposure.
- 2: Limited exposure with some concern.
- 3: Broader-than-expected access.
- 4: Broad exposure to a sensitive service.
- 5: Confirmed exposure that violates the lab's security policy.

Do not assign a high exposure rating from VPC Flow Logs alone if the required configuration evidence is unavailable.

### Frequency (0–5)

Rate event frequency against a documented baseline or rule threshold. The same count can have different meanings in different environments, so thresholds should be configurable and tested.

### Target Sensitivity (0–5)

Rate the affected resource according to documented project context. Avoid assuming that a resource is sensitive when its role is unknown.

### Event Type (0–5)

Use a documented rating for the relevant detection rule. A possible scan indicator, unexpected administrative access, and a validated high-risk configuration change may warrant different ratings.

### Context / Source Reputation (0–5)

Use only reliable, available context. If source reputation is unavailable, record it as unknown rather than inventing a value. The implementation should define how unknown factors are handled.

## 5. Severity Bands

Suggested initial bands:

| Score | Severity |
|---:|---|
| 80–100 | CRITICAL |
| 60–79 | HIGH |
| 40–59 | MEDIUM |
| 20–39 | LOW |
| 0–19 | INFORMATIONAL |

These bands are provisional and should be reviewed against test findings. A rule may also define a documented minimum severity for a confirmed configuration condition, but the rationale must be explicit.

## 6. Missing or Uncertain Data

- Preserve unknown values as unknown.
- Do not invent source reputation, target sensitivity, or exposure details.
- If a factor cannot be evaluated, define a consistent handling policy, such as calculating from available factors and recording the missing factor, or assigning a conservative default.
- Do not compare scores from different versions of the model without documenting the version and methodology.

## 7. Example

Suppose a possible port-scan finding has these illustrative ratings:

| Factor | Weight | Rating (0–5) | Weighted contribution |
|---|---:|---:|---:|
| Exposure | 25 | 3 | 15 |
| Frequency | 20 | 4 | 16 |
| Target sensitivity | 20 | 2 | 8 |
| Event type | 20 | 4 | 16 |
| Context / source reputation | 15 | 1 | 3 |
| **Total** | **100** | — | **58** |

Under the proposed bands, a score of 58 is **MEDIUM**. These values are illustrative only; actual ratings must be based on collected evidence and documented rules.

## 8. Finding Record

Store enough information to reproduce a score:

- Risk score.
- Severity.
- Model version.
- Factor ratings.
- Evidence and source fields used.
- Rule ID.
- Calculation timestamp.
- Any missing or unknown factor.

## 9. Validation

Validate the model using representative normal and suspicious test scenarios:

1. Confirm the score stays within 0–100.
2. Confirm identical inputs produce identical scores.
3. Verify severity bands at boundary values.
4. Verify missing fields follow the documented policy.
5. Review whether more concerning scenarios receive appropriately higher scores.
6. Record cases where the score does not match investigator expectations and explain any adjustment.

## 10. Limitations

A score is a prioritization aid, not proof of compromise. Results depend on telemetry quality, detection-rule design, chosen weights, thresholds, and available context. The model must be revised if testing shows that its output is misleading.
