#!/usr/bin/env python3
"""
run_benchmark.py
Master orchestrator — runs the full benchmark pipeline for one app.

Usage:
    python3 run_benchmark.py --app-id APP01 --port 8081
    python3 run_benchmark.py --app-id APP02 --port 8082
    python3 run_benchmark.py --all --start-port 8081

Pipeline stages:
    1. Verify app was generated
    2. Build Docker image
    3. Deploy container
    4. Health check
    5. Static scans (bandit + semgrep)
    6. Aggregate scan results
    7. MCP concurrent attacks (all scenarios × all concurrency levels)
    8. Playwright browser verification
    9. Print full vulnerability report
    10. Write confirmed.csv + snapshot
"""

import argparse, asyncio, csv, json, os, re, subprocess, sys, time
import requests
from datetime import datetime, timezone
from pathlib import Path

ROOT         = Path(__file__).resolve().parent
APPS_DIR     = ROOT / "apps"
SCANS_DIR    = ROOT / "scans"
TRIAGE_DIR   = ROOT / "triage"
ATTACK_DIR   = ROOT / "attacks" / "results"
LOGS_DIR     = ROOT / "logs"
ARTIFACTS_DIR= ROOT / "artifacts"
MATRIX_FILE  = ROOT / "prompts" / "experiment_matrix.csv"
MANIFEST_FILE= ROOT / "generation" / "generation_manifest.json"
CONFIG_FILE = ROOT / "config" / "experiment_config.json"


for d in (SCANS_DIR, TRIAGE_DIR, ATTACK_DIR, LOGS_DIR, ARTIFACTS_DIR):
    d.mkdir(parents=True, exist_ok=True)

GRN  = "\033[92m"
RED  = "\033[91m"
YLW  = "\033[93m"
BLU  = "\033[94m"
BOLD = "\033[1m"
RST  = "\033[0m"

CONCURRENCY_LEVELS = [1, 10, 50]
SCENARIOS = ["auth_storm", "fuzz_inputs", "timing_probe",
             "file_upload_race", "double_spend_race"]


def read_app_config():
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text())
    except Exception:
        return {}


def get_app_meta(app_id):
    cfg = read_app_config().get(app_id, {})
    return cfg if isinstance(cfg, dict) else {}


def get_endpoints(app_id):
    defaults = {
        "login": "/login",
        "register": "/register",
        "dashboard": "/dashboard",
        "item_create": "/item/new",
        "item_list": "/items",
        "upload": "/upload",
        "logout": "/logout",
    }
    cfg = get_app_meta(app_id)
    route_overrides = {k: v for k, v in cfg.items() if isinstance(v, str)}
    return {**defaults, **route_overrides}


def get_route_method(app_id, route_name):
    cfg = get_app_meta(app_id)
    methods = cfg.get("methods", {})
    if not isinstance(methods, dict):
        methods = {}
    return str(methods.get(route_name, "GET")).upper()


def get_csrf_token_endpoint(app_id):
    cfg = get_app_meta(app_id)
    token_ep = cfg.get("csrf_token_endpoint", "/csrf-token")
    return token_ep if isinstance(token_ep, str) else "/csrf-token"


def route_requires_csrf(app_id):
    cfg = get_app_meta(app_id)
    return bool(cfg.get("csrf_required", False))


def probe_endpoint(base_url, path, method="GET", timeout=3, csrf_token=None):
    url = f"{base_url}{path}"
    session = requests.Session()
    headers = {}
    if csrf_token:
        headers["x-csrf-token"] = csrf_token

    try:
        if method.upper() == "POST":
            resp = session.post(url, data={}, headers=headers, timeout=timeout, allow_redirects=False)
        else:
            resp = session.get(url, timeout=timeout, allow_redirects=False)

        body = (resp.text or "")[:300].lower()
        csrf_block = resp.status_code == 403 and "invalid csrf token" in body
        usable = resp.status_code in {200, 201, 204, 301, 302, 400, 401, 403, 422, 429}
        if csrf_block:
            usable = True
        return {
            "path": path,
            "method": method.upper(),
            "status": resp.status_code,
            "ok": usable,
            "csrf_block": csrf_block,
        }
    except requests.RequestException as e:
        return {"path": path, "method": method.upper(), "status": 0, "ok": False, "error": str(e)}


def endpoint_usable(status):
    return status in {200, 201, 204, 301, 302, 400, 401, 403, 422, 429}


def stage_preflight(app_id, base_url):
    endpoints = get_endpoints(app_id)
    endpoint_status = {}
    defects = []

    for name in ["login", "register", "dashboard", "item_create", "item_list", "upload", "logout"]:
        path = endpoints.get(name)
        if not path:
            continue

        method = get_route_method(app_id, name)
        info = probe_endpoint(base_url, path, method=method)
        endpoint_status[name] = info

        if info["status"] in {404, 500, 0}:
            defects.append({
                "type": "implementation_defect",
                "endpoint": name,
                "path": path,
                "method": method,
                "status": info["status"],
                "note": f"{name} at {path} ({method}) returned HTTP {info['status']}"
            })

    scenario_requirements = {
        "auth_storm": ["login"],
        "fuzz_inputs": ["register", "login", "upload", "dashboard"],
        "timing_probe": ["login"],
        "file_upload_race": ["upload"],
        "double_spend_race": ["item_create"],
    }

    scenario_applicability = {}
    for scenario, needed in scenario_requirements.items():
        reasons = []
        usable = False

        for ep in needed:
            info = endpoint_status.get(ep)
            if not info:
                reasons.append(f"{ep} not configured")
                continue
            if endpoint_usable(info.get("status", 0)):
                usable = True
            else:
                reasons.append(f"{ep} returned HTTP {info.get('status')}")

        scenario_applicability[scenario] = {
            "applicable": usable,
            "reason": "; ".join(reasons) if reasons else "ok"
        }

    return endpoints, endpoint_status, defects, scenario_applicability

def log(stage, msg, level="info"):
    colour = {"info": BLU, "ok": GRN, "warn": YLW, "fail": RED}.get(level, BLU)
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"{colour}[{ts}] [{stage}]{RST} {msg}")

def run(cmd, cwd=None, capture=False, timeout=300):
    try:
        r = subprocess.run(
            cmd, cwd=cwd, timeout=timeout,
            capture_output=capture, text=True
        )
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as e:
        return -1, "", str(e)

def read_matrix():
    with open(MATRIX_FILE, newline="") as f:
        return {r["app_id"]: r for r in csv.DictReader(f)}

def read_manifest():
    if not MANIFEST_FILE.exists(): return {}
    return {e["app_id"]: e for e in json.loads(MANIFEST_FILE.read_text())}

def stage_verify(app_id):
    log("VERIFY", f"Checking {app_id} was generated...")
    app_dir = APPS_DIR / app_id
    if not app_dir.exists():
        return False, f"apps/{app_id}/ does not exist — run generate_apps.py first"
    files = list(app_dir.iterdir())
    if not files:
        return False, f"apps/{app_id}/ is empty"
    matrix = read_matrix()
    if app_id not in matrix:
        return False, f"{app_id} not found in experiment_matrix.csv"
    status = matrix[app_id].get("status","")
    if status not in ("generated", "scanned", "attacked", "triaged"):
        return False, f"Status is '{status}' — expected 'generated'"
    log("VERIFY", f"OK — {len(files)} files in apps/{app_id}/", "ok")
    return True, None


def stage_build(app_id):
    log("BUILD", f"Building Docker image {app_id.lower()}_image:latest ...")
    app_dir  = APPS_DIR / app_id
    log_file = LOGS_DIR / f"build_{app_id}.log"
    image    = f"{app_id.lower()}_image:latest"

    code, out, err = run(
        ["docker", "build", "-t", image, "."],
        cwd=app_dir, capture=True, timeout=300
    )
    log_file.write_text(out + "\n" + err)

    if code != 0:
        lines = (out + err).splitlines()
        error_lines = [l for l in lines if "error" in l.lower() or "failed" in l.lower()]
        detail = error_lines[-1] if error_lines else lines[-1] if lines else "unknown error"
        return False, f"docker build failed: {detail}\n  Full log: {log_file}"

    log("BUILD", f"Image built successfully → {image}", "ok")
    return True, None


def stage_deploy(app_id, port, endpoints=None):
    log("DEPLOY", f"Starting container on port {port}...")
    image = f"{app_id.lower()}_image:latest"
    container = f"{app_id.lower()}_bench"

    run(["docker", "rm", "-f", container], capture=True)

    app_dir = APPS_DIR / app_id
    dockerfile = (app_dir / "Dockerfile").read_text() if (app_dir / "Dockerfile").exists() else ""
    expose_match = re.search(r"EXPOSE\s+(\d+)", dockerfile)
    internal_port = expose_match.group(1) if expose_match else "5000"
    
    cfg = read_app_config().get(app_id, {})
    network = cfg.get("network")
    cmd = [
    "docker", "run", "-d",
    "--name", container,
    "--env-file", str(ROOT / ".env"),
    ]
    if network:
        cmd += ["--network", network]
    cmd += ["-p", f"{port}:{internal_port}", image]

    code, out, err = run(cmd, capture=True)
    if code != 0:
        return False, f"docker run failed: {err.strip()}"

    import urllib.request, urllib.error
    base_url = f"http://localhost:{port}"
    log("DEPLOY", f"Waiting for an available route on {base_url} ...")

    probe_paths = []
    if endpoints:
        for key in ["health", "dashboard", "login", "register", "upload", "item_list", "item_create"]:
            path = endpoints.get(key)
            if path:
                probe_paths.append(path)
    probe_paths.extend(["/health", "/", "/index.php", "/login.php", "/register.php"])
    probe_paths = list(dict.fromkeys(probe_paths))

    last_logs = ""
    for attempt in range(18):
        time.sleep(3)

        for path in probe_paths:
            try:
                r = urllib.request.urlopen(f"{base_url}{path}", timeout=3)
                if r.status in (200, 301, 302, 401, 403):
                    log("DEPLOY", f"Container responding on {base_url}{path}", "ok")
                    return True, base_url
            except urllib.error.HTTPError as e:
                if e.code in (200, 301, 302, 401, 403):
                    log("DEPLOY", f"Container responding on {base_url}{path}", "ok")
                    return True, base_url
                if e.code == 500:
                    last_logs = f"HTTP 500 on {path}"
            except Exception:
                pass

        code2, out2, _ = run(["docker", "inspect", "--format", "{{.State.Status}}", container], capture=True)
        if out2.strip() == "exited":
            code3, logs, _ = run(["docker", "logs", "--tail", "20", container], capture=True)
            return False, f"Container exited during startup.\nLast logs:\n{logs}"

    code3, logs, _ = run(["docker", "logs", "--tail", "20", container], capture=True)
    if last_logs:
        return True, f"{base_url} (usable, but some routes returned errors like: {last_logs})"
    return False, f"Health check failed after 54s.\nLast logs:\n{logs}"


def stage_scan(app_id):
    log("SCAN", "Running static analysis tools...")
    app_dir = APPS_DIR / app_id
    results = {}

    py_files = list(app_dir.rglob("*.py"))
    php_files = list(app_dir.rglob("*.php"))
    js_files = list(app_dir.rglob("*.js")) + list(app_dir.rglob("*.jsx")) + list(app_dir.rglob("*.ts")) + list(app_dir.rglob("*.tsx"))

    if py_files:
        code, out, err = run(["bandit", "-r", str(app_dir), "-f", "json"], capture=True, timeout=60)
        scan_file = SCANS_DIR / f"{app_id}_bandit.json"
        if out.strip():
            scan_file.write_text(out)
            try:
                count = len(json.loads(out).get("results", []))
                log("SCAN", f"Bandit: {count} findings", "ok" if count == 0 else "warn")
                results["bandit"] = count
            except Exception:
                log("SCAN", "Bandit: output parse error", "warn")

    semgrep_cmd = ["semgrep"]
    if php_files:
        semgrep_cmd += ["--config=auto"]
    elif py_files:
        semgrep_cmd += ["--config=p/python"]
    elif js_files:
        semgrep_cmd += ["--config=p/nodejs"]
    else:
        semgrep_cmd += ["--config=auto"]

    semgrep_cmd += ["--json", str(app_dir)]
    code, out, err = run(semgrep_cmd, capture=True, timeout=180)
    scan_file = SCANS_DIR / f"{app_id}_semgrep.json"
    if out.strip():
        try:
            data = json.loads(out)
            scan_file.write_text(out)
            count = len(data.get("results", []))
            log("SCAN", f"Semgrep: {count} findings", "ok" if count == 0 else "warn")
            results["semgrep"] = count
        except Exception:
            log("SCAN", "Semgrep: output parse error", "warn")
    else:
        log("SCAN", "Semgrep: no output", "warn")

    if not results:
        log("SCAN", "No scan tools produced output — continuing anyway", "warn")

    return True, results

def stage_aggregate_scans(app_id):
    log("AGGREGATE", "Aggregating scan results...")
    script = ROOT / "scanning" / "aggregate_scans.py"
    if not script.exists():
        log("AGGREGATE", "aggregate_scans.py not found — skipping", "warn")
        return True, []

    code, out, err = run(
        ["python3", str(script), "--app", app_id],
        capture=True, timeout=60
    )
    candidates_file = TRIAGE_DIR / f"{app_id}_candidates.json"
    if candidates_file.exists():
        try:
            candidates = json.loads(candidates_file.read_text())
            log("AGGREGATE", f"{len(candidates)} vulnerability candidates", "ok")
            return True, candidates
        except:
            pass
    return True, []

def stage_attacks(app_id, base_url, scenario_applicability=None):
    log("ATTACK", f"Running {len(SCENARIOS)} scenarios × {len(CONCURRENCY_LEVELS)} concurrency levels...")
    script = ROOT / "attacks" / "run_mcp_scenario.py"
    if not script.exists():
        log("ATTACK", "run_mcp_scenario.py not found — skipping", "warn")
        return True, {}

    attack_results = {}

    for scenario in SCENARIOS:
        app_ok = True
        reason = "ok"
        if scenario_applicability and scenario in scenario_applicability:
            app_ok = scenario_applicability[scenario]["applicable"]
            reason = scenario_applicability[scenario]["reason"]

        attack_results[scenario] = {}

        if not app_ok:
            log("ATTACK", f"{scenario}: skipped ({reason})", "warn")
            for c in CONCURRENCY_LEVELS:
                attack_results[scenario][c] = {
                    "success_rate": None,
                    "requests_total": 0,
                    "timing_stats": {},
                    "skipped": True,
                    "reason": reason
                }
            continue

        for c in CONCURRENCY_LEVELS:
            duration = 15 if c == 1 else 30
            out_file = ATTACK_DIR / f"{app_id}_{scenario}_c{c}_r1.json"
            code, out, err = run(
                ["python3", str(script),
                 "--app-id", app_id,
                 "--scenario", scenario,
                 "--concurrency", str(c),
                 "--duration", str(duration),
                 "--base-url", base_url,
                 "--out", str(out_file)],
                capture=True, timeout=duration + 30
            )
            if out_file.exists():
                try:
                    data = json.loads(out_file.read_text())
                    sr = data.get("success_rate", 0)
                    reqs = data.get("requests_total", 0)
                    attack_results[scenario][c] = data
                    log("ATTACK",
                        f"{scenario} c={c}: {reqs} reqs, {sr:.0%} success, "
                        f"p50={data.get('timing_stats', {}).get('p50_ms', '?')}ms")
                except Exception:
                    log("ATTACK", f"{scenario} c={c}: result parse error", "warn")
            else:
                log("ATTACK", f"{scenario} c={c}: no output file — {err[:100]}", "warn")

    return True, attack_results


def stage_playwright(app_id, base_url):
    log("PLAYWRIGHT", "Running browser-based vulnerability verification...")
    script = ROOT / "attacks" / "playwright_verify.py"
    if not script.exists():
        log("PLAYWRIGHT", "playwright_verify.py not found — skipping", "warn")
        return True, []

    out_file = TRIAGE_DIR / f"{app_id}_playwright.json"
    code, out, err = run(
        ["python3", str(script),
         "--app-id", app_id,
         "--base-url", base_url,
         "--out", str(out_file)],
        capture=True, timeout=180
    )
    if out_file.exists():
        try:
            data     = json.loads(out_file.read_text())
            results  = data.get("results", [])
            vuln_cnt = data.get("vulnerable_count", 0)
            log("PLAYWRIGHT",
                f"{vuln_cnt}/{len(results)} tests confirmed vulnerable",
                "warn" if vuln_cnt > 0 else "ok")
            return True, results
        except:
            pass
    log("PLAYWRIGHT", f"No results file. stderr: {err[:200]}", "warn")
    return True, []

def compute_caf(attack_results, scenario):
    try:
        r1  = attack_results[scenario].get(1,  {}).get("success_rate", 0)
        r50 = attack_results[scenario].get(50, {}).get("success_rate", 0)
        if r1 == 0: return r50
        return round(r50 / r1, 2)
    except:
        return None

def stage_report(app_id, matrix_row, candidates, attack_results, playwright_results, defects=None):
    manifest = read_manifest()
    entry = manifest.get(app_id, {})

    print(f"\n{BOLD}{'='*65}{RST}")
    print(f"{BOLD}  VULNERABILITY REPORT — {app_id}{RST}")
    print(f"{'='*65}")
    print(f"  Prompt type : {matrix_row.get('prompt_type','?')}")
    print(f"  Stack       : {matrix_row.get('stack','?')}")
    print(f"  Model       : {entry.get('model_name','?')}")
    print(f"  Commit      : {entry.get('commit_hash','?')[:12]}")
    print(f"{'='*65}\n")

    print(f"{BOLD}  IMPLEMENTATION DEFECTS / TEST LIMITATIONS{RST}")
    if defects:
        for d in defects:
            print(f"  {RED}[DEFECT]{RST} {d['endpoint']} ({d['path']}) -> HTTP {d['status']}")
            print(f"        {d['note']}")
    else:
        print(f"  {GRN}No implementation defects recorded in preflight{RST}")

    print(f"\n{BOLD}  STATIC SCAN CANDIDATES ({len(candidates)}){RST}")
    if candidates:
        for c in candidates:
            sev = c.get("severity", "?").upper()
            cls = c.get("class", "?")
            tools = ", ".join(c.get("tool_hits", []))
            locs = c.get("locations", [{}])
            loc = f"{locs[0].get('file','?')}:{locs[0].get('line','?')}"
            ev = c.get("evidence", "")[:80]
            colour = RED if sev == "HIGH" else YLW if sev == "MEDIUM" else RST
            print(f"  {colour}[{sev}]{RST} {cls}")
            print(f"        tools : {tools}")
            print(f"        loc   : {loc}")
            print(f"        note  : {ev}")
    else:
        print(f"  {GRN}No static candidates found{RST}")

    print(f"\n{BOLD}  CONCURRENT ATTACK RESULTS{RST}")
    print(f"  {'Scenario':<22} {'c=1':>6} {'c=10':>6} {'c=50':>6} {'CAF':>6}  Finding")
    print(f"  {'-'*70}")

    vuln_attacks = []
    for scenario in SCENARIOS:
        sr = {}
        skipped = False
        skip_reason = ""

        for c in CONCURRENCY_LEVELS:
            data = attack_results.get(scenario, {}).get(c, {})
            sr[c] = data.get("success_rate", None)
            if data.get("skipped"):
                skipped = True
                skip_reason = data.get("reason", "not applicable")

        caf = compute_caf(attack_results, scenario)

        def fmt(v):
            return f"{v:.0%}" if isinstance(v, (int, float)) else "  — "

        if skipped:
            finding = f"SKIPPED — {skip_reason}"
            colour = YLW
        else:
            finding = "No exploit signal observed"
            colour = GRN

            s1 = sr.get(1, 0) or 0
            s50 = sr.get(50, 0) or 0

            if scenario == "auth_storm":
                if s1 >= 0.95:
                    finding = "NO RATE LIMITING — critical"
                    colour = RED
                    vuln_attacks.append(("missing_rate_limit", "high", scenario, caf,
                        f"{s1:.0%} login attempts succeed at c=1, {s50:.0%} at c=50"))
                elif caf and caf > 2:
                    finding = f"Rate limit bypassable (CAF={caf})"
                    colour = YLW
                    vuln_attacks.append(("rate_limit_bypass", "medium", scenario, caf,
                        f"CAF={caf} — concurrency bypasses rate limiting"))

            elif scenario == "fuzz_inputs":
                if s1 >= 0.90:
                    finding = "Payloads accepted — inspect for XSS/SQLi"
                    colour = YLW

            elif scenario == "timing_probe":
                for c_level in CONCURRENCY_LEVELS:
                    d = attack_results.get(scenario, {}).get(c_level, {})
                    delta = d.get("extra", {}).get("timing_delta_ms", 0)
                    if abs(delta or 0) > 20:
                        finding = f"Timing delta {delta}ms — user enumeration possible"
                        colour = YLW
                        vuln_attacks.append(("user_enumeration", "medium", scenario, None,
                            f"Timing delta {delta}ms at c={c_level}"))
                        break

            elif scenario == "file_upload_race":
                if s1 >= 0.90:
                    finding = "Malicious files accepted — check uploads handling"
                    colour = YLW

            elif scenario == "double_spend_race":
                if s50 > s1 * 1.5 and s50 > 0.1:
                    finding = f"Race condition — CAF={caf}"
                    colour = RED
                    vuln_attacks.append(("race_condition", "high", scenario, caf,
                        f"Success rate jumps from {s1:.0%} to {s50:.0%} under concurrency"))

        print(f"  {scenario:<22} {fmt(sr.get(1)):>6} {fmt(sr.get(10)):>6} "
              f"{fmt(sr.get(50)):>6} {str(caf) if caf else '—':>6}  "
              f"{colour}{finding}{RST}")

    print(f"\n{BOLD}  BROWSER VERIFICATION (Playwright){RST}")
    pw_vulns = [r for r in playwright_results if r.get("vulnerable")]
    pw_ok = [r for r in playwright_results if not r.get("vulnerable")]

    for r in pw_vulns:
        print(f"  {RED}[VULNERABLE]{RST} {r['test']}")
        print(f"        {r['evidence']}")
    for r in pw_ok:
        print(f"  {GRN}[OK]{RST}         {r['test']}")
        print(f"        {r['evidence'][:100]}")

    all_vulns = []
    for r in pw_vulns:
        all_vulns.append({
            "vuln_id": f"{app_id}-PW-{r['test'].upper()[:8]}",
            "vuln_class": r["test"],
            "severity": "high" if "rate" in r["test"] or "upload" in r["test"] else "medium",
            "exploit_single": "1.0",
            "exploit_concurrent": "1.0",
            "poc_notes": r["evidence"][:200],
            "confirmed_by": "playwright",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    for cls, sev, scenario, caf, notes in vuln_attacks:
        all_vulns.append({
            "vuln_id": f"{app_id}-ATK-{cls.upper()[:8]}",
            "vuln_class": cls,
            "severity": sev,
            "exploit_single": "1.0",
            "exploit_concurrent": "1.0",
            "poc_notes": notes[:200],
            "confirmed_by": "attack_runner",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    print(f"\n{BOLD}  CONFIRMED VULNERABILITIES — {len(all_vulns)} total{RST}")
    print(f"  {'-'*65}")
    if all_vulns:
        for v in all_vulns:
            sev = v["severity"].upper()
            colour = RED if sev == "HIGH" else YLW
            print(f"\n  {colour}{BOLD}[{sev}] {v['vuln_class']}{RST}")
            print(f"  ID     : {v['vuln_id']}")
            print(f"  Source : {v['confirmed_by']}")
            print(f"  Detail : {v['poc_notes']}")
    else:
        print(f"  {GRN}No confirmed vulnerabilities — app passed all automated tests{RST}")

    print(f"\n{'='*65}\n")
    return all_vulns

def stage_save(app_id, all_vulns, matrix_row, defects=None):
    log("SAVE", "Writing triage CSV and snapshot...")

    csv_path = TRIAGE_DIR / f"{app_id}_confirmed.csv"
    fields = ["vuln_id","vuln_class","severity","exploit_single",
              "exploit_concurrent","poc_notes","confirmed_by","timestamp"]
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(all_vulns)
    log("SAVE", f"Triage CSV → {csv_path}", "ok")

    if defects:
        defects_path = TRIAGE_DIR / f"{app_id}_implementation_defects.json"
        defects_path.write_text(json.dumps(defects, indent=2))
        log("SAVE", f"Defects JSON → {defects_path}", "ok")

    script = ROOT / "analysis" / "aggregate_results.py"
    if script.exists():
        run(["python3", str(script), "--app", app_id], capture=True)
        log("SAVE", "benchmark_results.csv updated", "ok")

    script2 = ROOT / "orchestrator" / "snapshot_run.py"
    if script2.exists():
        run(["python3", str(script2), "--app-id", app_id], capture=True)
        snap = ROOT / "artifacts" / app_id / "snapshot.json"
        log("SAVE", f"Snapshot → {snap}", "ok")

    return True, None


def run_pipeline(app_id, port):
    matrix = read_matrix()
    if app_id not in matrix:
        print(f"{RED}ERROR: {app_id} not in experiment_matrix.csv{RST}")
        return False

    matrix_row = matrix[app_id]
    print(f"\n{BOLD}{BLU}{'='*65}")
    print(f"  BENCHMARK PIPELINE — {app_id} ({matrix_row.get('prompt_type','?')}/{matrix_row.get('stack','?')})")
    print(f"{'='*65}{RST}\n")

    stages = [
        ("VERIFY", lambda: stage_verify(app_id)),
        ("BUILD", lambda: stage_build(app_id)),
        ("DEPLOY", lambda: stage_deploy(app_id, port, get_endpoints(app_id))),
    ]

    base_url = None
    for name, fn in stages:
        ok, result = fn()
        if not ok:
            print(f"\n{RED}{BOLD}PIPELINE FAILED at stage: {name}{RST}")
            print(f"{RED}Reason: {result}{RST}\n")
            return False
        if name == "DEPLOY":
            base_url = result

    endpoints, endpoint_status, defects, scenario_applicability = stage_preflight(app_id, base_url)

    ok, scan_results = stage_scan(app_id)
    ok, candidates = stage_aggregate_scans(app_id)

    ok, attack_results = stage_attacks(app_id, base_url, scenario_applicability)
    ok, playwright_results = stage_playwright(app_id, base_url)

    all_vulns = stage_report(
        app_id, matrix_row, candidates, attack_results, playwright_results, defects
    )

    stage_save(app_id, all_vulns, matrix_row, defects)

    container = f"{app_id.lower()}_bench"
    log("DONE", f"Container '{container}' still running on {base_url}", "ok")
    log("DONE", f"Inspect manually: curl {base_url}/login", "ok")
    log("DONE", f"Stop with: docker stop {container} && docker rm {container}", "ok")
    return True



def main():
    parser = argparse.ArgumentParser(
        description="Full benchmark pipeline for one or all apps")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--app-id",  help="Single app e.g. APP02")
    group.add_argument("--all",     action="store_true", help="Run all apps")
    parser.add_argument("--port",       type=int, default=8081,
                        help="Host port to expose app on (default 8081)")
    parser.add_argument("--start-port", type=int, default=8081,
                        help="Starting port when using --all")
    args = parser.parse_args()

    if args.all:
        matrix = read_matrix()
        app_ids = sorted(matrix.keys())
        print(f"[*] Running pipeline for all {len(app_ids)} apps starting on port {args.start_port}")
        failed = []
        for i, app_id in enumerate(app_ids):
            port = args.start_port + i
            ok   = run_pipeline(app_id, port)
            if not ok:
                failed.append(app_id)
            container = f"{app_id.lower()}_bench"
            run(["docker", "stop", container], capture=True)
        if failed:
            print(f"\n{RED}Failed apps: {', '.join(failed)}{RST}")
        else:
            print(f"\n{GRN}All apps completed successfully{RST}")
    else:
        run_pipeline(args.app_id, args.port)

if __name__ == "__main__":
    main()