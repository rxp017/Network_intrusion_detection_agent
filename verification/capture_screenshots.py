"""Automated script to capture verification screenshots for Understand and Technical modes."""

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
DOCS_IMAGES = ROOT / "docs" / "images"
DOCS_IMAGES.mkdir(parents=True, exist_ok=True)


def get_free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run():
    port = get_free_port()
    url = f"http://127.0.0.1:{port}"
    print(f"Starting server on {url} (offline mode)...")

    server_env = os.environ.copy()
    server_env["LLM_PROVIDER"] = "none"
    server_env["GROQ_API_KEY"] = ""
    server_env["GEMINI_API_KEY"] = ""
    server_env["LLM_API_KEY"] = ""

    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=server_env,
    )

    try:
        for _ in range(100):
            try:
                if httpx.get(f"{url}/health", timeout=1).status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(0.1)
        else:
            raise RuntimeError("Server did not become ready")

        print("Server is ready. Launching Playwright browser...")
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)

            # -------------------------------------------------------------
            # 1. UNDERSTAND MODE - DESKTOP (1600 x 1050)
            # -------------------------------------------------------------
            page = browser.new_page(viewport={"width": 1600, "height": 1050}, device_scale_factor=1)
            page.goto(url)
            page.wait_for_selector("#flows tr:nth-child(4)", timeout=15000)
            page.locator("#pause").click()
            time.sleep(0.5)

            # Click Generic archetype to show an attack detection walkthrough
            page.locator("#archetype-generic").click()
            time.sleep(0.6)

            # Generate built-in plain-English explanation
            page.locator("#briefing-narrate-btn").click()
            page.wait_for_selector("#briefing-narrative-card.narrative-builtin", timeout=8000)
            time.sleep(0.5)
            page.evaluate("window.scrollTo(0, 0)")

            understand_desktop = DOCS_IMAGES / "understand_desktop.png"
            page.screenshot(path=str(understand_desktop), full_page=False)
            print(f"Captured {understand_desktop}")

            # -------------------------------------------------------------
            # 2. UNDERSTAND MODE - MOBILE (390 x 844)
            # -------------------------------------------------------------
            mobile_page = browser.new_page(viewport={"width": 390, "height": 844}, device_scale_factor=1)
            mobile_page.goto(url)
            mobile_page.wait_for_selector("#flows tr:nth-child(3)", timeout=15000)
            mobile_page.locator("#pause").click()
            time.sleep(0.5)

            mobile_page.locator("#archetype-generic").click()
            time.sleep(0.5)
            mobile_page.evaluate("window.scrollTo(0, 0)")

            understand_mobile = DOCS_IMAGES / "understand_mobile.png"
            mobile_page.screenshot(path=str(understand_mobile), full_page=False)
            print(f"Captured {understand_mobile}")
            mobile_page.close()

            page.locator("#theme-toggle").click()
            page.evaluate("window.scrollTo(0, 0)")
            understand_dark = DOCS_IMAGES / "understand_dark.png"
            page.screenshot(path=str(understand_dark), full_page=False)
            print(f"Captured {understand_dark}")
            page.locator("#theme-toggle").click()

            # -------------------------------------------------------------
            # 3. TECHNICAL MODE - DESKTOP (1600 x 1050)
            # -------------------------------------------------------------
            page.locator("#mode-technical-btn").click()
            time.sleep(0.5)

            # Select a flow to inspect full evidence dossier
            rows = page.locator("#flows tr")
            if rows.count() > 0:
                rows.first.click()
                time.sleep(0.5)
            page.evaluate("window.scrollTo(0, 0)")

            technical_desktop = DOCS_IMAGES / "technical_desktop.png"
            page.screenshot(path=str(technical_desktop), full_page=False)
            print(f"Captured {technical_desktop}")

            # -------------------------------------------------------------
            # 4. TECHNICAL MODE - MOBILE (390 x 844)
            # -------------------------------------------------------------
            mobile_tech_page = browser.new_page(viewport={"width": 390, "height": 844}, device_scale_factor=1)
            mobile_tech_page.goto(url)
            mobile_tech_page.wait_for_selector("#flows tr:nth-child(3)", timeout=15000)
            mobile_tech_page.locator("#pause").click()
            mobile_tech_page.locator("#mode-technical-btn").click()
            time.sleep(0.5)
            mobile_tech_page.evaluate("window.scrollTo(0, 0)")

            technical_mobile = DOCS_IMAGES / "technical_mobile.png"
            mobile_tech_page.screenshot(path=str(technical_mobile), full_page=False)
            print(f"Captured {technical_mobile}")
            mobile_tech_page.close()

            page.close()
            browser.close()

    finally:
        server.terminate()
        server.wait(timeout=5)


if __name__ == "__main__":
    run()
