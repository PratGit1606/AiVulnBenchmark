Title

Security Benchmarking of AI-Generated Web Applications Under Concurrent Attack Conditions

Core Research Questions

RQ1: Do AI-generated web applications contain measurable security vulnerabilities across common web stacks?

RQ2: Does concurrency increase exploitability of vulnerabilities present in AI-generated applications?

RQ3: Does prompt style influence vulnerability density and severity in generated applications?

RQ4: Are AI-generated security patches as effective as canonical developer patches?

Hypotheses

H1: Applications generated with fast prototype prompts will have higher vulnerability density than secure prompts.

H2: Certain vulnerabilities will only become exploitable under concurrent request conditions.

H3: Concurrency increases exploit success rate for race-condition or state-dependent vulnerabilities.

H4: AI-generated patches reduce vulnerability counts but introduce more regressions than canonical patches.

Independent Variables
Variable	Values
Prompt Type	Secure, Fast Prototype, Vague
Technology Stack	React, Express, Flask, PHP
Concurrency Level	1, 10, 50, 200
Patch Type	None, AI Patch, Canonical Patch
Dependent Variables
Metric	Definition
Vulnerability Density	Number of confirmed vulnerabilities per application
Exploitability (Single)	Binary indicator if vulnerability can be exploited sequentially
Exploitability (Concurrent)	Binary indicator if vulnerability can be exploited under concurrency
Concurrency Amplification Factor (CAF)	(EC+1)/(ES+1)
Remediation Effectiveness	1 − (vulns_after / vulns_before)
Scanner False Positive Rate	false_positives / scanner_reports
Vulnerability Classes

Injection (XSS, SQLi, command injection)

Authentication flaws

Authorization / access control (IDOR)

CSRF

File upload vulnerabilities

Configuration vulnerabilities

Dependency vulnerabilities

Concurrency / race condition vulnerabilities

Information disclosure

Exploitability Scoring
Value	Meaning
0	Not exploitable
1	Partially exploitable
2	Fully exploitable
Concurrency Amplification Factor

CAF = (Exploitability_concurrent + 1) / (Exploitability_single + 1)

Interpretation:

CAF	Meaning
=1	concurrency has no effect
>1	vulnerability amplified by concurrency
<1	vulnerability suppressed by concurrency
Dataset Size
Item	Quantity
Generated Applications	12
Prompt Categories	3
Stacks	4
Concurrency Levels	4
Runs Per Configuration	3

Total benchmark runs:

12 apps × 4 concurrency levels × 3 repetitions = 144 executions

Output Dataset Schema

File: benchmark_results.csv

Columns:

app_id
prompt_type
stack
vulnerability_id
vulnerability_class
severity
tool_detected
exploit_single
exploit_concurrent
CAF
patch_type
patch_success
notes
timestamp
Experiment Acceptance Criteria

The experiment pipeline is valid when:

Generated applications deploy successfully in isolated containers.

Static and dynamic scanners produce vulnerability reports.

MCP concurrency scripts generate parallel request traffic.

Vulnerability exploits can be confirmed via manual PoC.

Results aggregate into a unified dataset.

Ethical Scope

Testing only occurs against:

locally generated applications

isolated container environments

mock third-party services

No external systems are targeted.

Versioning

This document must be version controlled.

Repository structure example:

thesis-benchmark/
│
├─ docs/
│   └─ research_spec.md
│
├─ prompts/
├─ generation/
├─ deployment/
├─ scanning/
├─ attacks/
└─ analysis/