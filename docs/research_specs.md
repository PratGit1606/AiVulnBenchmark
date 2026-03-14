# Security Benchmarking of AI-Generated Web Applications Under Concurrent Attack Conditions

## 1. Overview

This benchmark evaluates the **security characteristics of AI-generated web applications** across multiple technology stacks and prompt styles.  
The study specifically investigates whether **concurrency amplifies exploitability** of vulnerabilities present in AI-generated software.

All experiments are conducted in **isolated container environments** using locally generated applications.

---

# 2. Core Research Questions

**RQ1:** Do AI-generated web applications contain measurable security vulnerabilities across common web stacks?

**RQ2:** Does concurrency increase exploitability of vulnerabilities present in AI-generated applications?

**RQ3:** Does prompt style influence vulnerability density and severity in generated applications?

**RQ4:** Are AI-generated security patches as effective as canonical developer patches?

---

# 3. Hypotheses

| ID | Hypothesis |
|---|---|
| **H1** | Applications generated with **fast prototype prompts** will have higher vulnerability density than those generated with **secure prompts** |
| **H2** | Certain vulnerabilities will only become exploitable under **concurrent request conditions** |
| **H3** | Increasing concurrency increases exploit success rate for **race-condition or state-dependent vulnerabilities** |
| **H4** | AI-generated patches reduce vulnerability counts but introduce **more regressions** than canonical patches |

---

# 4. Experimental Variables

## Independent Variables

| Variable | Values |
|---|---|
| Prompt Type | Secure, Fast Prototype, Vague |
| Technology Stack | React, Express, Flask, PHP |
| Concurrency Level | 1, 10, 50, 200 |
| Patch Type | None, AI Patch, Canonical Patch |

---

## Dependent Variables

| Metric | Definition |
|---|---|
| Vulnerability Density | Number of confirmed vulnerabilities per application |
| Exploitability (Single) | Binary indicator if vulnerability can be exploited sequentially |
| Exploitability (Concurrent) | Binary indicator if vulnerability can be exploited under concurrency |
| Concurrency Amplification Factor (CAF) | `(EC + 1) / (ES + 1)` |
| Remediation Effectiveness | `1 − (vulns_after / vulns_before)` |
| Scanner False Positive Rate | `false_positives / scanner_reports` |

---

# 5. Vulnerability Classes

The benchmark evaluates the following vulnerability categories:

- Injection vulnerabilities  
  - XSS  
  - SQL Injection  
  - Command Injection

- Authentication flaws

- Authorization / Access Control  
  - IDOR

- CSRF

- File upload vulnerabilities

- Configuration vulnerabilities

- Dependency vulnerabilities

- Concurrency / Race condition vulnerabilities

- Information disclosure

---

# 6. Exploitability Scoring

| Score | Meaning |
|---|---|
| **0** | Not exploitable |
| **1** | Partially exploitable |
| **2** | Fully exploitable |

---

# 7. Concurrency Amplification Factor (CAF)

The Concurrency Amplification Factor measures whether concurrency increases exploitability.

```

CAF = (Exploitability_concurrent + 1) / (Exploitability_single + 1)

```

## Interpretation

| CAF Value | Meaning |
|---|---|
| = 1 | Concurrency has no effect |
| > 1 | Vulnerability amplified by concurrency |
| < 1 | Vulnerability suppressed by concurrency |

---

# 8. Dataset Size

| Item | Quantity |
|---|---|
| Generated Applications | 12 |
| Prompt Categories | 3 |
| Technology Stacks | 4 |
| Concurrency Levels | 4 |
| Runs Per Configuration | 3 |

### Total Benchmark Runs

```

12 applications × 4 concurrency levels × 3 repetitions = 144 executions

```

---

# 9. Output Dataset Schema

**File:** `benchmark_results.csv`

| Column | Description |
|---|---|
| app_id | Unique identifier for generated application |
| prompt_type | Prompt category used for generation |
| stack | Technology stack used |
| vulnerability_id | Unique vulnerability identifier |
| vulnerability_class | Type/category of vulnerability |
| severity | Vulnerability severity level |
| tool_detected | Scanner or tool that detected the issue |
| exploit_single | Exploitability score under sequential execution |
| exploit_concurrent | Exploitability score under concurrent execution |
| CAF | Concurrency Amplification Factor |
| patch_type | None, AI Patch, Canonical Patch |
| patch_success | Boolean indicator of successful remediation |
| notes | Additional experiment notes |
| timestamp | Experiment execution timestamp |

---

# 10. Experiment Acceptance Criteria

The experiment pipeline is considered **valid** when:

1. Generated applications deploy successfully in **isolated containers**.
2. Static and dynamic scanners produce **vulnerability reports**.
3. MCP concurrency scripts generate **parallel request traffic**.
4. Vulnerability exploits can be confirmed via **manual proof-of-concept (PoC)**.
5. Results aggregate into a **unified dataset**.

---

# 11. Ethical Scope

All testing occurs strictly within controlled environments:

- Locally generated applications
- Isolated container infrastructure
- Mock third-party services

**No external systems are targeted.**

---

# 12. Versioning

This specification must be maintained under version control.

## Example Repository Structure

```

thesis-benchmark/
│
├─ docs/
│   └─ research_spec.md
│
├─ prompts/
│
├─ generation/
│
├─ deployment/
│
├─ scanning/
│
├─ attacks/
│
└─ analysis/

```

---

# 13. Summary

This benchmark framework enables systematic evaluation of:

- Security quality of AI-generated applications
- Effects of concurrency on exploitability
- Impact of prompt engineering on vulnerability density
- Effectiveness of AI-generated patches

The resulting dataset provides a **quantitative foundation for studying AI-assisted software security.**
