"""Automated script to capture verification screenshots using Playwright."""

import json
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
DOCS_IMAGES = ROOT / "docs" / "images"
ARTIFACT_DIR = Path(r"C:\Users\rajashekar\.gemini\antigravity-ide\brain\07814b02-49e4-4f33-8277-7aa4e3f51bdb")
DOCS_IMAGES.mkdir(parents=True, exist_ok=True)


def get_free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run():
    port = get_free_port()
    url = f"http://127.0.0.1:{port}"
    print(f"Starting server on {url}...")

    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
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
            page = browser.new_page(viewport={"width": 1600, "height": 1050}, device_scale_factor=1)

            page.goto(url)
            page.wait_for_selector("#flows tr:nth-child(4)", timeout=15000)
            # Pause replay for stable inspection
            page.locator("#pause").click()
            time.sleep(0.5)

            # 1. Analyst View Screenshot
            page.locator("#flows tr").first.click()
            time.sleep(0.5)
            analyst_img = DOCS_IMAGES / "01_analyst_view.png"
            page.screenshot(path=str(analyst_img))
            print(f"Captured {analyst_img}")

            # 2. Switch to Briefing View
            page.locator("#view-briefing-btn").click()
            time.sleep(0.5)

            # Click "Explain in plain English" (no API key configured)
            page.locator("#briefing-narrate-btn").click()
            page.wait_for_selector("#briefing-narrative-card.narrative-unavailable", timeout=5000)
            time.sleep(0.5)
            fallback_img = DOCS_IMAGES / "02_briefing_fallback.png"
            page.screenshot(path=str(fallback_img))
            print(f"Captured {fallback_img}")

            # 3. Simulate narrative response for visual verification of loaded state
            mock_narrative = {
                "summary": (
                    "This network flow exhibits abnormal packet flooding consistent with Denial-of-Service (DoS) behavior, "
                    "characterized by extreme source byte volume (sbytes) and elevated packet arrival frequency. "
                    "The traffic pattern deviates significantly from baseline enterprise web protocols."
                ),
                "recommended_action": "Verify destination host availability and enforce upstream rate limiting.",
                "provider": "Groq (llama-3.3-70b-versatile)",
            }

            def handle_predict(route):
                if "narrate=true" in route.request.url:
                    route.fulfill(
                        status=200,
                        content_type="application/json",
                        body=json.dumps(
                            {
                                "predicted_attack_cat": "DoS",
                                "confidence": 0.942,
                                "risk_score": 78,
                                "risk_level": "critical",
                                "risk_components": {"classifier": 52.0, "anomaly": 26.0},
                                "review_recommended": True,
                                "recommended_action": "Verify destination host availability and enforce upstream rate limiting.",
                                "warnings": [],
                                "narrative": mock_narrative,
                                "narrative_status": "ok",
                                "inference_ms": 14.5,
                                "explanation": {
                                    "features": [
                                        {"feature": "sbytes", "contribution": 1.45, "encoded_value": 45000},
                                        {"feature": "rate", "contribution": 0.88, "encoded_value": 12000},
                                    ]
                                },
                            }
                        ),
                    )
                else:
                    route.continue_()

            page.route(lambda url: "narrate=true" in url, handle_predict)

            # Select another flow and explain to trigger narrative
            rows = page.locator("#flows tr")
            if rows.count() > 1:
                rows.nth(1).click()
                time.sleep(0.3)
            page.locator("#briefing-narrate-btn").click()
            page.locator("#briefing-provider-badge").filter(has_text="Groq").wait_for(timeout=5000)
            time.sleep(0.5)
            narrative_img = DOCS_IMAGES / "03_briefing_narrative.png"
            page.screenshot(path=str(narrative_img))
            print(f"Captured {narrative_img}")

            # 4. Expand technical evidence inside Briefing View
            page.locator("#briefing-evidence-details summary").click()
            time.sleep(0.5)
            evidence_img = DOCS_IMAGES / "04_briefing_expanded_evidence.png"
            page.screenshot(path=str(evidence_img))
            print(f"Captured {evidence_img}")

            browser.close()

            # Copy to artifacts directory
            for img in [analyst_img, fallback_img, narrative_img, evidence_img]:
                shutil.copy2(img, ARTIFACT_DIR / img.name)
            print("Copied screenshots to artifact directory.")

    finally:
        server.terminate()
        server.wait(timeout=5)


if __name__ == "__main__":
    run()
