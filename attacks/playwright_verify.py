#!/usr/bin/env python3

import asyncio
import json
import argparse
import re
from pathlib import Path
from datetime import datetime, timezone

from playwright.async_api import async_playwright, Page

ROOT = Path(__file__).resolve().parents[1]
CONFIG_FILE = ROOT / "config" / "experiment_config.json"
NAV_TIMEOUT = 10_000

DEFAULT_ENDPOINTS = {
    "login": "/login",
    "register": "/register",
    "dashboard": "/",
    "item_create": "/items/new",
    "item_list": "/items",
    "upload": "/upload",
    "logout": "/logout",
}


def load_endpoints(app_id: str) -> dict:
    if CONFIG_FILE.exists():
        try:
            config = json.loads(CONFIG_FILE.read_text())
            if app_id in config and isinstance(config[app_id], dict):
                return {**DEFAULT_ENDPOINTS, **config[app_id]}
        except Exception:
            pass
    return DEFAULT_ENDPOINTS


async def fresh_page(browser) -> Page:
    page = await browser.new_page()
    page.set_default_timeout(NAV_TIMEOUT)
    return page


async def page_text(page: Page) -> str:
    try:
        return await page.locator("body").inner_text()
    except Exception:
        try:
            return await page.content()
        except Exception:
            return ""


async def goto(page: Page, base_url: str, path: str) -> None:
    await page.goto(f"{base_url}{path}", timeout=NAV_TIMEOUT)


async def fetch_csrf_token(page: Page, base_url: str) -> str | None:
    try:
        result = await page.evaluate(
            """async (url) => {
                const resp = await fetch(url, { credentials: 'include' });
                const text = await resp.text();
                return { status: resp.status, text };
            }""",
            f"{base_url}/csrf-token",
        )
        if result.get("status") != 200:
            return None
        data = json.loads(result.get("text") or "{}")
        token = data.get("csrfToken")
        return token if isinstance(token, str) else None
    except Exception:
        return None


async def inject_csrf_token(page: Page, token: str | None) -> None:
    if not token:
        return
    await page.evaluate(
        """(csrf) => {
            document.querySelectorAll('form').forEach((form) => {
                let input = form.querySelector('input[name="_csrf"]');
                if (!input) {
                    input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = '_csrf';
                    form.appendChild(input);
                }
                input.value = csrf;
            });
        }""",
        token,
    )


async def capture_alerts(page: Page) -> None:
    await page.evaluate(
        """() => {
            window.__lastAlert = '';
            window.alert = (msg) => { window.__lastAlert = String(msg); };
        }"""
    )


async def read_alert(page: Page) -> str:
    try:
        return await page.evaluate("() => window.__lastAlert || ''")
    except Exception:
        return ""


async def fill_first(page: Page, selector: str, value: str) -> bool:
    loc = page.locator(selector)
    if await loc.count() > 0:
        await loc.first.fill(value)
        return True
    return False


async def click_submit(page: Page, selector: str = 'form button[type="submit"], form input[type="submit"], button[type="submit"]') -> bool:
    submit = page.locator(selector)
    if await submit.count() > 0:
        await submit.first.click()
        try:
            await page.wait_for_load_state("networkidle", timeout=NAV_TIMEOUT)
        except Exception:
            pass
        return True
    return False


async def register_user(page: Page, base_url: str, endpoints: dict, username: str, email: str, password: str) -> None:
    await goto(page, base_url, endpoints["register"])
    for name, value in {
        "username": username,
        "email": email,
        "password": password,
        "confirm_password": password,
    }.items():
        await fill_first(page, f'input[name="{name}"]', value)
    await click_submit(page, '#registerForm button[type="submit"], #registerForm input[type="submit"], form button[type="submit"], form input[type="submit"], button[type="submit"]')


async def login_user(page: Page, base_url: str, endpoints: dict, username: str, password: str) -> None:
    await goto(page, base_url, endpoints["login"])
    await fill_first(page, 'input[name="username"], input[name="email"]', username)
    await fill_first(page, 'input[name="password"]', password)
    await click_submit(page, '#loginForm button[type="submit"], #loginForm input[type="submit"], form button[type="submit"], form input[type="submit"], button[type="submit"]')


async def response_text(page: Page) -> str:
    msg = (await read_alert(page)).strip().lower()
    body = (await page_text(page)).strip().lower()
    return f"{msg} {body}".strip()


async def test_rate_limit(browser, base_url: str, endpoints: dict) -> dict:
    result = {"test": "rate_limit", "vulnerable": False, "evidence": ""}
    attempts = 20
    blocked = 0
    page = await fresh_page(browser)

    try:
        ui_root = endpoints.get("dashboard", "/")
        for i in range(attempts):
            await goto(page, base_url, ui_root)
            token = await fetch_csrf_token(page, base_url)
            await inject_csrf_token(page, token)
            await capture_alerts(page)

            user = page.locator('input[name="username"], input[name="email"]')
            pw = page.locator('input[name="password"]')
            if await user.count() == 0 or await pw.count() == 0:
                result["evidence"] = "Login form not found"
                return result

            await user.first.fill(f"bruteforce{i}@test.com")
            await pw.first.fill(f"wrongpass{i}")
            await click_submit(page, '#loginForm button[type="submit"], #loginForm input[type="submit"], form button[type="submit"], form input[type="submit"], button[type="submit"]')
            await page.wait_for_timeout(350)

            text = await response_text(page)
            if any(k in text for k in ["too many", "rate limit", "locked", "blocked", "try again later", "429"]):
                blocked += 1
    except Exception as e:
        result["evidence"] = f"Error: {e}"
    finally:
        await page.close()

    if blocked == 0:
        result["vulnerable"] = True
        result["evidence"] = f"All {attempts} login attempts completed with no rate limit or lockout response"
    else:
        result["evidence"] = f"Rate limit triggered on {blocked}/{attempts} attempts"

    return result


async def test_xss(browser, base_url: str, endpoints: dict) -> dict:
    result = {"test": "xss_reflection", "vulnerable": False, "evidence": ""}
    payload = "<script>window.__xss=1</script>"
    page = await fresh_page(browser)

    try:
        await register_user(page, base_url, endpoints, "xss_user", "xss_user@test.com", "xsspass123")
        await login_user(page, base_url, endpoints, "xss_user@test.com", "xsspass123")

        surfaces = [
            endpoints["item_create"],
            endpoints["item_list"],
            endpoints["dashboard"],
        ]

        for path in surfaces:
            try:
                await goto(page, base_url, path)
            except Exception:
                continue

            await fill_first(page, 'input[name="name"], input[name="title"], textarea[name="name"], textarea[name="title"]', payload)
            await fill_first(page, 'input[name="description"], textarea[name="description"]', "xss-desc")
            await click_submit(page)

            try:
                await page.goto(f"{base_url}{path}?q={payload}&search={payload}", timeout=NAV_TIMEOUT)
            except Exception:
                pass

            content = await page.content()
            executed = 0
            try:
                executed = await page.evaluate("() => window.__xss || 0")
            except Exception:
                executed = 0

            if executed or payload in content:
                result["vulnerable"] = True
                result["evidence"] = f"XSS payload reflected or executed via {path}"
                return result

        result["evidence"] = "Payload not reflected or executed on tested surfaces"
    except Exception as e:
        result["evidence"] = f"Error: {e}"
    finally:
        await page.close()

    return result


async def test_file_upload(browser, base_url: str, endpoints: dict) -> dict:
    result = {"test": "file_upload_validation", "vulnerable": False, "evidence": ""}
    page = await fresh_page(browser)

    try:
        upload_path = endpoints.get("upload")
        if not upload_path:
            result["evidence"] = "Upload endpoint not configured"
            return result

        await goto(page, base_url, upload_path)
        file_input = page.locator('#uploadForm input[type="file"], input[type="file"]')
        if await file_input.count() == 0:
            result["evidence"] = f"No file input found at {upload_path}"
            return result

        await file_input.first.set_input_files({
            "name": "webshell.php.jpg",
            "mimeType": "image/jpeg",
            "buffer": b"<?php system($_GET['cmd']); ?>",
        })

        await click_submit(page, '#uploadForm button[type="submit"], #uploadForm input[type="submit"], form button[type="submit"], form input[type="submit"], button[type="submit"]')

        text = await response_text(page)
        if any(k in text for k in ["uploaded", "success", "file uploaded"]):
            result["vulnerable"] = True
            result["evidence"] = "Malicious file accepted by upload endpoint"
        elif any(k in text for k in ["invalid", "not allowed", "rejected", "error", "only images"]):
            result["evidence"] = "Server rejected the malicious file"
        else:
            result["evidence"] = f"Upload response ambiguous: {text[:120] or 'no text'}"
    except Exception as e:
        result["evidence"] = f"Error: {e}"
    finally:
        await page.close()

    return result


async def test_debug_mode(browser, base_url: str, endpoints: dict) -> dict:
    result = {"test": "debug_console_rce", "vulnerable": False, "evidence": ""}
    paths = ["/console", "/__debugger__", "/debugger", "/_debug_toolbar"]

    for path in paths:
        page = await fresh_page(browser)
        try:
            await goto(page, base_url, path)
            content = (await page.content()).lower()
            if "invalid csrf token" in content or "forbiddenerror" in content:
                continue
            if ("werkzeug" in content and "interactive console" in content) or \
               ("stack trace" in content and ("express" in content or "node" in content)) or \
               ("debugger" in content and "pin" in content and "traceback" in content):
                result["vulnerable"] = True
                result["evidence"] = f"Debug console or stack trace exposed at {path}"
                return result
        except Exception as e:
            result["evidence"] = f"Error checking {path}: {e}"
        finally:
            await page.close()

    page = await fresh_page(browser)
    try:
        await goto(page, base_url, "/this_route_does_not_exist_xyz")
        content = (await page.content()).lower()
        if "invalid csrf token" not in content and (
            ("werkzeug" in content and "interactive console" in content) or
            ("stack trace" in content and ("express" in content or "node" in content))
        ):
            result["vulnerable"] = True
            result["evidence"] = "Debug mode active on error page"
            return result
    except Exception:
        pass
    finally:
        await page.close()

    if not result["vulnerable"]:
        result["evidence"] = "Debug console not accessible on any known path"

    return result


async def test_user_enumeration(browser, base_url: str, endpoints: dict) -> dict:
    result = {"test": "user_enumeration", "vulnerable": False, "evidence": ""}
    page = await fresh_page(browser)

    async def login_message(user_value: str, pw: str) -> str:
        try:
            await goto(page, base_url, endpoints["dashboard"])
            token = await fetch_csrf_token(page, base_url)
            await inject_csrf_token(page, token)
            await capture_alerts(page)

            user = page.locator('#loginForm input[name="username"], #loginForm input[name="email"], input[name="username"], input[name="email"]')
            pwf = page.locator('#loginForm input[name="password"], input[name="password"]')
            if await user.count() == 0 or await pwf.count() == 0:
                return "login form not found"

            await user.first.fill(user_value)
            await pwf.first.fill(pw)
            await click_submit(page, '#loginForm button[type="submit"], #loginForm input[type="submit"], form button[type="submit"], form input[type="submit"], button[type="submit"]')
            await page.wait_for_timeout(350)

            return (await response_text(page)) or "no response text"
        except Exception as e:
            return f"error: {e}"

    try:
        existing = await login_message("admin@admin.com", "wrongpassword_xyz")
        missing = await login_message("zzznobody999@fake.com", "wrongpassword_xyz")

        if existing != missing:
            result["vulnerable"] = True
            result["evidence"] = (
                f"Different error messages for valid vs invalid user:\n"
                f"  real: {existing[:120]}\n"
                f"  fake: {missing[:120]}"
            )
        else:
            result["evidence"] = "Same error message for both"
    finally:
        await page.close()

    return result


async def test_idor(browser, base_url: str, endpoints: dict) -> dict:
    result = {"test": "idor_item_edit", "vulnerable": False, "evidence": ""}

    async def create_user_and_login(username: str, email: str, password: str) -> Page:
        page = await fresh_page(browser)
        await register_user(page, base_url, endpoints, username, email, password)
        await login_user(page, base_url, endpoints, username, password)
        return page

    page_a = None
    page_b = None

    try:
        page_a = await create_user_and_login("userA_idor", "userA_idor@test.com", "passA12345")
        await goto(page_a, base_url, endpoints["item_create"])

        name_field = page_a.locator('input[name="name"], input[name="title"], textarea[name="name"], textarea[name="title"]')
        if await name_field.count() == 0:
            result["evidence"] = f"Item creation form not found at {endpoints['item_create']}"
            return result

        await name_field.first.fill("UserA_Secret_Item")
        await fill_first(page_a, 'input[name="description"], textarea[name="description"]', "secret-note")
        await click_submit(page_a)

        await goto(page_a, base_url, endpoints["item_list"])
        content = await page_a.content()

        patterns = [
            r'/items/([a-zA-Z0-9_-]+)/edit',
            r'/items/([a-zA-Z0-9_-]+)',
            r'/item/([a-zA-Z0-9_-]+)/edit',
            r'data-id=["\']([a-zA-Z0-9_-]+)["\']',
            r'id=["\']item[-_]([a-zA-Z0-9_-]+)["\']',
            r'/items/edit/([a-zA-Z0-9_-]+)',
        ]

        item_id = None
        for pattern in patterns:
            m = re.search(pattern, content)
            if m:
                item_id = m.group(1)
                break

        if not item_id:
            result["evidence"] = "Could not find item ID after creation"
            return result

        try:
            await goto(page_a, base_url, endpoints.get("logout", "/logout"))
        except Exception:
            pass

        page_b = await create_user_and_login("userB_idor", "userB_idor@test.com", "passB12345")

        candidate_urls = [
            f"{base_url}/items/{item_id}",
            f"{base_url}/items/{item_id}/edit",
            f"{base_url}/item/{item_id}/edit",
            f"{base_url}/items/edit/{item_id}",
            f"{base_url}/item/edit/{item_id}",
            f"{base_url}/items/{item_id}/view",
        ]

        for url in candidate_urls:
            try:
                await page_b.goto(url, timeout=NAV_TIMEOUT)
                body = await page_text(page_b)
                if "UserA_Secret_Item" in body or "secret-note" in body:
                    result["vulnerable"] = True
                    result["evidence"] = f"User B accessed User A's item (id={item_id}) at {url}"
                    return result
            except Exception:
                continue

        result["evidence"] = f"Access denied or not exposed across candidate URLs for item {item_id}"
    except Exception as e:
        result["evidence"] = f"Error: {e}"
    finally:
        if page_a:
            await page_a.close()
        if page_b:
            await page_b.close()

    return result


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-id", required=True)
    parser.add_argument("--base-url", default="http://localhost:8081")
    parser.add_argument("--out", default=None)
    args = parser.parse_args()

    endpoints = load_endpoints(args.app_id)
    out_path = Path(args.out) if args.out else ROOT / "triage" / f"{args.app_id}_playwright.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Playwright verification: {args.app_id} @ {args.base_url}")
    print(f"[*] Endpoints: {json.dumps(endpoints, indent=2)}")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)

        tests = [
            test_xss(browser, args.base_url, endpoints),
            test_rate_limit(browser, args.base_url, endpoints),
            test_file_upload(browser, args.base_url, endpoints),
            test_debug_mode(browser, args.base_url, endpoints),
            test_user_enumeration(browser, args.base_url, endpoints),
            test_idor(browser, args.base_url, endpoints),
        ]

        results = []
        for coro in tests:
            r = await coro
            status = "VULNERABLE" if r["vulnerable"] else "OK"
            print(f"  [{status}] {r['test']}: {r['evidence'][:120]}")
            results.append(r)

        await browser.close()

    output = {
        "app_id": args.app_id,
        "base_url": args.base_url,
        "endpoints_used": endpoints,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "results": results,
        "vulnerable_count": sum(1 for r in results if r["vulnerable"]),
    }

    out_path.write_text(json.dumps(output, indent=2))
    print(f"\n[+] {output['vulnerable_count']}/{len(results)} tests confirmed vulnerable")
    print(f"[+] Results → {out_path}")


if __name__ == "__main__":
    asyncio.run(main())