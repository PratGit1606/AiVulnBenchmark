# AI Web Application Security Benchmark

### Barrett Honors Thesis – Pratham Hegde (phegde9)
### Commitee Chair - Yan Shoshitaishvili
### Second Commitee Chair - Connor Nelson

This repository contains the benchmarking framework developed for my **Barrett Honors Thesis at Arizona State University**.

The project studies the **security characteristics of AI-generated web applications**, with a particular focus on how **concurrent request conditions influence vulnerability exploitability**.

Modern generative AI tools can rapidly produce full-stack applications, but the **security implications of AI-generated code remain largely unquantified**. This project builds a reproducible benchmarking pipeline that generates applications, deploys them in isolated environments, and evaluates their security using automated scanning and controlled attack simulations.

The benchmark produces a structured dataset that enables analysis of:

* Security weaknesses in AI-generated software
* The impact of **concurrency on vulnerability exploitability**
* The influence of **prompt engineering on security outcomes**
* The effectiveness of **AI-generated security patches**

For the complete experimental design and formal methodology, see:

```
docs/research_spec.md
```

---

### Directory Overview

| Directory     | Purpose                                                  |
| ------------- | -------------------------------------------------------- |
| `docs/`       | Detailed research specifications and experimental design |
| `prompts/`    | Prompt datasets and experiment configurations            |
| `apps/`       | AI-generated applications used in the benchmark          |
| `deployment/` | Scripts for containerized deployment                     |
| `scanning/`   | Security scanning integrations                           |
| `attacks/`    | Concurrency attack simulations and exploit scripts       |
| `analysis/`   | Aggregation and analysis of benchmark results            |

---

# Benchmark Workflow

The framework follows a repeatable pipeline designed to evaluate the security of generated applications.

### 1. Application Generation

Applications are generated from structured prompts defined in `prompts/prompt_bank.json`.

### 2. Deployment

Each application is deployed inside **isolated container environments** to ensure safe and reproducible experimentation.

### 3. Security Scanning

Static and dynamic scanners analyze the applications to identify potential vulnerabilities.

### 4. Attack Simulation

Attack scripts simulate adversarial behavior, including high-concurrency request patterns that may expose race conditions or state-related vulnerabilities.

### 5. Patch Evaluation

Identified vulnerabilities are tested under multiple remediation approaches to measure the effectiveness of different patching strategies.

### 6. Data Collection

Results are aggregated into structured datasets for statistical analysis.

---

# Key Goals of the Benchmark

This framework enables systematic study of:

* Vulnerability prevalence in AI-generated web applications
* The role of **concurrent request patterns** in vulnerability exploitation
* The effect of **prompt design on software security**
* The reliability of **AI-generated code fixes**

The benchmark aims to provide a **reproducible experimental dataset** that can support further research into **AI-assisted software development and security risk assessment**.

---

# Reproducibility

The project emphasizes reproducible security experimentation through:

* Containerized environments
* Deterministic prompt sets
* Version-controlled experiment specifications
* Automated benchmarking pipelines

---

# Author

**Pratham Hegde (phegde9)**
Barrett Honors College
Arizona State University

---

# Additional Documentation

For full research methodology, variables, hypotheses, and dataset definitions, refer to:

```
docs/research_spec.md
```
