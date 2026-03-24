<div align="center">

### *Benchmarking the security characteristics of AI-generated web applications.*

[![Barrett Honors Thesis](https://img.shields.io/badge/Barrett-Honors%20Thesis-8C1D40?style=for-the-badge&labelColor=1a1a1a)](https://barrett.asu.edu/)
[![Arizona State University](https://img.shields.io/badge/Arizona%20State-University-FFC627?style=for-the-badge&labelColor=1a1a1a)](https://www.asu.edu/)
[![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Docker-Containerized-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)

**Pratham Hegde (phegde9)**
Barrett, The Honors College · Arizona State University

**Committee Chair:** Yan Shoshitaishvili · **Committee Member:** Connor Nelson

</div>

---

## ✦ Overview

This repository contains the benchmarking framework developed for the **Barrett Honors Thesis at Arizona State University**.

The project studies the **security characteristics of AI-generated web applications**, with a particular focus on how **concurrent request conditions influence vulnerability exploitability**.

Generative AI systems are increasingly capable of producing full-stack applications. While these tools accelerate development, the **security properties of AI-generated software remain insufficiently studied**. This project introduces a **reproducible benchmarking framework** designed to evaluate the security of AI-generated applications under realistic attack conditions.

The benchmark generates applications, deploys them in **isolated container environments**, scans them for vulnerabilities, and evaluates exploitability under **controlled concurrency conditions**.

```
Generate  →  Deploy  →  Scan  →  Attack  →  Patch  →  Analyze  →  Dataset ✓
    ↑            ↑          ↑        ↑           ↑          ↑
    └────────────┴──────────┴────────┴───────────┴──────────┘
                    Benchmark pipeline covers every stage
```

The resulting dataset enables analysis of:

- Security weaknesses in AI-generated software
- The impact of **concurrent request conditions on exploitability**
- The influence of **prompt engineering on vulnerability density**
- The effectiveness of **AI-generated security patches**

For the complete experimental design and methodology, see the **[Research Specification](docs/research_spec.md)**.

---

## ✦ Repository Structure

```
HonorsThesis/                          (48 directories, 162 files)
│
├── README.md
├── run_benchmark.py                   ← master orchestrator
├── generate_apps.py                   ← app generation script
│
├── docs/
│   └── research_specs.md
│
├── prompts/
│   ├── prompt_bank.json
│   └── experiment_matrix.csv
│
├── config/
│   └── experiment_config.json
│
├── apps/                              ← 12 AI-generated applications
│   ├── APP01/                         (Python/Flask)
│   │   ├── Dockerfile
│   │   ├── app.py
│   │   ├── requirements.txt
│   │   └── templates/
│   ├── APP02/                         (Node.js/Express)
│   ├── APP03/                         (PHP)
│   ├── APP04/                         (Node.js + React)
│   ├── APP05/                         (Python/Flask)
│   ├── APP06/                         (Node.js)
│   ├── APP07/                         (PHP + MySQL)
│   ├── APP08/                         (Node.js + React)
│   ├── APP09/                         (Python/Flask)
│   ├── APP10/                         (Node.js/EJS)
│   ├── APP11/                         (PHP)
│   └── APP12/                         (Node.js + React)
│
├── generation/
│   ├── generation_manifest.json
│   └── responses/                     ← raw LLM request/response pairs
│       ├── request_APP01.json
│       ├── response_APP01.json
│       └── ...
│
├── attacks/
│   ├── run_mcp_scenario.py            ← concurrent attack runner
│   ├── playwright_verify.py           ← browser-based verification
│   ├── payloads/
│   │   ├── sqli_payloads.txt
│   │   ├── xss_payloads.txt
│   │   └── upload_payloads/
│   └── results/                       ← per-app attack result JSONs
│       ├── APP01_auth_storm_c1_r1.json
│       ├── APP01_auth_storm_c50_r1.json
│       └── ...
│
├── scanning/
│   └── aggregate_scans.py
│
├── scans/                             ← raw scanner output
│   ├── APP01_bandit.json
│   └── APP01_semgrep.json
│
├── triage/                            ← normalized findings
│   ├── APP01_candidates.json
│   ├── APP01_confirmed.csv
│   └── APP01_playwright.json
│
├── analysis/
│   ├── aggregate_results.py
│   └── benchmark_results.csv
│
├── orchestrator/
│   └── snapshot_run.py
│
├── artifacts/
│   └── APP01/
│       └── snapshot.json
│
├── logs/
│   ├── build_APP01.log
│   └── generate_APP01_error.log
│
├── patches/                           ← vulnerability patches
├── patch_results/                     ← patch evaluation output
├── pcaps/                             ← network captures
└── deployment/                        ← container setup
```

| Directory | Purpose |
|-----------|---------|
| `docs/` | Research specifications and experimental methodology |
| `prompts/` | Prompt datasets and benchmark configuration |
| `config/` | Experiment configuration |
| `apps/` | 12 AI-generated applications across Python, Node.js, and PHP stacks |
| `generation/` | LLM generation manifest and raw request/response pairs |
| `attacks/` | Concurrency attack runner, Playwright verifier, payloads, and results |
| `scanning/` | Scan aggregation scripts |
| `scans/` | Raw Bandit and Semgrep output per app |
| `triage/` | Normalized vulnerability candidates and confirmed findings |
| `analysis/` | Dataset aggregation and benchmark results CSV |
| `orchestrator/` | Run snapshot utilities |
| `artifacts/` | Per-app run snapshots |
| `patches/` | Vulnerability patches under evaluation |
| `patch_results/` | Patch evaluation output |
| `pcaps/` | Network traffic captures |
| `deployment/` | Container deployment and environment setup |

---

## ✦ Benchmark Pipeline

The benchmark follows a structured experimental pipeline.

### 1. Application Generation

Applications are generated using structured prompts defined in `prompts/prompt_bank.json`. These prompts represent different **prompt engineering strategies**.

### 2. Deployment

Generated applications are deployed inside **isolated container environments** to ensure safe experimentation, reproducibility, and consistent infrastructure across experiments.

### 3. Security Scanning

Applications are analyzed using a combination of **static and dynamic security analysis tools**, including:

| Tool | Type |
|------|------|
| Semgrep | Static analysis |
| Bandit | Static analysis (Python) |
| ESLint Security | Static analysis (JS) |
| OWASP ZAP | Dynamic analysis |
| Dependency scanners | Dependency vulnerability detection |

### 4. Attack Simulation

Controlled attack scenarios simulate adversarial behavior, including authentication request storms, race-condition exploitation, file upload races, input fuzzing, and timing probes. These attacks are executed under varying **concurrency levels** to evaluate exploitability.

### 5. Patch Evaluation

Detected vulnerabilities are evaluated under three remediation modes:

| Mode | Description |
|------|-------------|
| **None** | Original vulnerable application |
| **AI Patch** | Patch generated by a language model |
| **Canonical Patch** | Manually implemented secure fix |

This enables comparison between **AI-generated remediation and traditional developer fixes**.

### 6. Data Collection

All experiment results are aggregated into a structured dataset used for statistical analysis, stored in `analysis/`.

---

## ✦ Master Orchestrator

`run_benchmark.py` is the master pipeline script that runs the full benchmark for one app or all apps end-to-end.

```
python3 run_benchmark.py --app-id APP01 --port 8081
python3 run_benchmark.py --app-id APP02 --port 8082
python3 run_benchmark.py --all --start-port 8081
```

### Pipeline Stages

```
┌──────────────────────────────────────────────────────────┐
│  1. Verify       app was generated + matrix entry valid  │
│  2. Build        Docker image for the app                │
│  3. Deploy       container + health check                │
│  4. Scan         Bandit + Semgrep static analysis        │
│  5. Aggregate    normalize scan findings                 │
│  6. Attack       MCP scenarios × concurrency levels      │
│  7. Playwright   browser-based vulnerability verification│
│  8. Report       full vulnerability report to stdout     │
│  9. Save         confirmed.csv + run snapshot            │
└──────────────────────────────────────────────────────────┘
```

### Attack Scenarios × Concurrency Levels

| Scenario | Description |
|----------|-------------|
| `auth_storm` | Authentication request flooding, rate limit detection |
| `fuzz_inputs` | Input fuzzing for XSS and injection vectors |
| `timing_probe` | Timing delta analysis for user enumeration |
| `file_upload_race` | Race condition on file upload validation |
| `double_spend_race` | Concurrent transaction race conditions |

Each scenario is executed at concurrency levels **c=1, c=10, and c=50**. The **Concurrency Amplification Factor (CAF)** is computed as `success_rate(c=50) / success_rate(c=1)` to measure how much concurrency increases exploitability.

---

## ✦ Research Objectives

This benchmark framework enables systematic investigation of:

- The **security quality of AI-generated web applications**
- The relationship between **concurrency and vulnerability exploitability**
- The impact of **prompt design on security outcomes**
- The reliability of **AI-generated vulnerability remediation**

The resulting dataset provides a foundation for **empirical research on AI-assisted software development and security risk assessment**.

---

## ✦ Reproducibility

The benchmark is designed to support **reproducible security experiments**. Key principles include containerized infrastructure, deterministic prompt datasets, version-controlled experimental specifications, and automated benchmarking workflows.

---

## ✦ Ethical Scope

All experiments are conducted within **controlled research environments**. Testing is strictly limited to locally generated applications, isolated container infrastructure, and simulated attack traffic. No external systems or real-world services are targeted.

---

## ✦ Documentation

Detailed methodology, hypotheses, variables, and dataset definitions are available in the **[Research Specification](docs/research_spec.md)**.

---

<div align="center">

**Pratham Hegde (phegde9)**
Barrett, The Honors College · Arizona State University

*Barrett Honors Thesis · Academic Research Use Only*

</div>
