#!/usr/bin/env python3
"""
Playwright-based vulnerability verifier.
Confirms findings from triage/APP01_candidates.json using a real browser.

Usage:
    python3 attacks/playwright_verify.py --app-id APP01 --base-url http://localhost:8081
"""

import asyncio, json, argparse
from pathlib import Path
from datetime import datetime, timezone

try:
    from playwright.async_api import async_playwright
except ImportError:
    print("pip install playwright --break-system-packages && playwright install chromium")
    exit(1)

ROOT = Path(__file__).resolve().parents[1]

async def test_xss(page, base_url):
    """Check if XSS payload reflects unescaped in register form."""
    result = {"test": "xss_reflection", "vulnerable": False, "evidence": ""}
    try:
        await page.goto(f"{base_url}/register")
        payload = "<script>window.__xss=1</script>"
        await page.fill('input[name="username"]', payload)
        await page.fill('input[name="email"]', "xsstest@test.com")
        await page.fill('input[name="password"]', "testpass123")
        await page.fill('input[name="confirm_password"]', "testpass123")
        await page.click('input[type="submit"], button[type="submit"]')
        content = await page.content()
        if "<script>window.__xss=1</script>" in content:
            result["vulnerable"] = True
            result["evidence"] = "XSS payload reflected unescaped in response HTML"
        elif "&lt;script&gt;" in content:
            result["evidence"] = "Payload escaped correctly — not vulnerable"
        else:
            result["evidence"] = "Payload not reflected"
    except Exception as e:
        result["evidence"] = f"Error: {e}"
    return result


async def test_idor(page, base_url):
    """Check if user B can edit user A's items."""
    result = {"test": "idor_item_edit", "vulnerable": False, "evidence": ""}
    try:
        # Register user A
        await page.goto(f"{base_url}/register")
        await page.fill('input[name="username"]', "userA_idor")
        await page.fill('input[name="email"]', "userA@idor.com")
        await page.fill('input[name="password"]', "passA12345")
        await page.fill('input[name="confirm_password"]', "passA12345")
        await page.click('input[type="submit"], button[type="submit"]')

        # Login as user A and create an item
        await page.goto(f"{base_url}/login")
        await page.fill('input[name="email"]', "userA@idor.com")
        await page.fill('input[name="password"]', "passA12345")
        await page.click('input[type="submit"], button[type="submit"]')
        await page.goto(f"{base_url}/item/new")
        await page.fill('input[name="name"]', "UserA Secret Item")
        await page.click('input[type="submit"], button[type="submit"]')

        # Get item ID from dashboard
        await page.goto(f"{base_url}/dashboard")
        content = await page.content()
        import re
        ids = re.findall(r'/item/edit/(\d+)', content)
        if not ids:
            result["evidence"] = "Could not create item or find item ID"
            return result
        item_id = ids[0]

        # Logout
        await page.goto(f"{base_url}/logout")

        # Register user B
        await page.goto(f"{base_url}/register")
        await page.fill('input[name="username"]', "userB_idor")
        await page.fill('input[name="email"]', "userB@idor.com")
        await page.fill('input[name="password"]', "passB12345")
        await page.fill('input[name="confirm_password"]', "passB12345")
        await page.click('input[type="submit"], button[type="submit"]')

        # Login as user B, try to access user A's item
        await page.goto(f"{base_url}/login")
        await page.fill('input[name="email"]', "userB@idor.com")
        await page.fill('input[name="password"]', "passB12345")
        await page.click('input[type="submit"], button[type="submit"]')
        await page.goto(f"{base_url}/item/edit/{item_id}")
        content = await page.content()

        if "UserA Secret Item" in content or "edit" in page.url.lower():
            result["vulnerable"] = True
            result["evidence"] = f"User B accessed User A item (id={item_id}) — IDOR confirmed"
        else:
            result["evidence"] = f"Access denied for item {item_id} — not vulnerable"

    except Exception as e:
        result["evidence"] = f"Error: {e}"
    return result


async def test_debug_mode(page, base_url):
    """Check if Werkzeug debugger console is accessible."""
    result = {"test": "debug_console_rce", "vulnerable": False, "evidence": ""}
    try:
        await page.goto(f"{base_url}/console")
        content = await page.content()
        if "Werkzeug" in content or "debugger" in content.lower() or "console" in content.lower():
            result["vulnerable"] = True
            result["evidence"] = "Werkzeug interactive debugger exposed at /console — RCE possible"
        else:
            result["evidence"] = "Debug console not accessible"
    except Exception as e:
        result["evidence"] = f"Error: {e}"
    return result


async def test_user_enumeration(page, base_url):
    """Check if login reveals whether email exists."""
    result = {"test": "user_enumeration", "vulnerable": False, "evidence": ""}
    try:
        # Try with likely-real email
        await page.goto(f"{base_url}/login")
        await page.fill('input[name="email"]', "admin@admin.com")
        await page.fill('input[name="password"]', "wrongpassword")
        await page.click('input[type="submit"], button[type="submit"]')
        msg_real = await page.text_content("body")

        # Try with obviously fake email
        await page.goto(f"{base_url}/login")
        await page.fill('input[name="email"]', "zzznobody999@fake.com")
        await page.fill('input[name="password"]', "wrongpassword")
        await page.click('input[type="submit"], button[type="submit"]')
        msg_fake = await page.text_content("body")

        # If messages differ, enumeration is possible
        if msg_real.strip() != msg_fake.strip():
            result["vulnerable"] = True
            result["evidence"] = "Different error messages for valid vs invalid email — user enumeration possible"
        else:
            result["evidence"] = "Same error message for both — not enumerable"
    except Exception as e:
        result["evidence"] = f"Error: {e}"
    return result


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-id",   required=True)
    parser.add_argument("--base-url", default="http://localhost:8081")
    parser.add_argument("--out",      default=None)
    args = parser.parse_args()

    out_path = Path(args.out) if args.out else \
        ROOT / "triage" / f"{args.app_id}_playwright.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[*] Playwright verification: {args.app_id} @ {args.base_url}")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page    = await browser.new_page()

        tests = [
            test_xss(page, args.base_url),
            test_debug_mode(page, args.base_url),
            test_user_enumeration(page, args.base_url),
            test_idor(page, args.base_url),
        ]

        results = []
        for coro in tests:
            r = await coro
            status = "VULNERABLE" if r["vulnerable"] else "OK"
            print(f"  [{status}] {r['test']}: {r['evidence'][:100]}")
            results.append(r)

        await browser.close()

    output = {
        "app_id":    args.app_id,
        "base_url":  args.base_url,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "results":   results,
        "vulnerable_count": sum(1 for r in results if r["vulnerable"]),
    }
    out_path.write_text(json.dumps(output, indent=2))
    print(f"\n[+] {output['vulnerable_count']}/{len(results)} tests confirmed vulnerable")
    print(f"[+] Results → {out_path}")

if __name__ == "__main__":
    asyncio.run(main())
