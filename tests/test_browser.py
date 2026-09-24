"""Real browser smoke tests; start an isolated server and always clean it up."""

import json
import os
import re
import socket
import subprocess
import sys
import time

import httpx
import pytest
from playwright.sync_api import expect

from model import ROOT

pytestmark = [
    pytest.mark.browser,
    pytest.mark.skipif(
        os.getenv("NIDA_BROWSER_TESTS") != "1", reason="Set NIDA_BROWSER_TESTS=1 for Chromium tests"
    ),
]


@pytest.fixture(scope="module")
def browser_page(tmp_path_factory):
    from playwright.sync_api import sync_playwright

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    log_path = tmp_path_factory.mktemp("server") / "server.log"
    server_env = os.environ.copy()
    server_env["LLM_PROVIDER"] = "none"
    server_env["GROQ_API_KEY"] = ""
    server_env["GEMINI_API_KEY"] = ""
    server_env["LLM_API_KEY"] = ""
    with log_path.open("w") as log:
        server = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(port)],
            cwd=ROOT,
            stdout=log,
            stderr=log,
            env=server_env,
        )
        try:
            for _ in range(150):
                try:
                    if httpx.get(url + "/health", timeout=1).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                if server.poll() is not None:
                    raise RuntimeError(log_path.read_text())
                time.sleep(0.1)
            else:
                raise RuntimeError("Server did not become ready")
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page(viewport={"width": 1600, "height": 1120}, device_scale_factor=1)
                errors = []
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.on(
                    "console",
                    lambda message: errors.append(message.text) if message.type == "error" else None,
                )
                # Offline demo guarantee: abort every non-local network request.
                page.route(
                    "**/*",
                    lambda route: route.continue_() if route.request.url.startswith(url) else route.abort(),
                )
                page.goto(url)
                expect(page.locator("#total")).to_have_text(re.compile(r"^[3-9]$|^[1-9][0-9,]+$"))
                yield page, errors, url
                browser.close()
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)


def test_replay_controls_and_inspection(browser_page):
    page, errors, _ = browser_page
    page.get_by_role("button", name="Pause replay").click()
    count = page.locator("#total").inner_text()
    page.wait_for_timeout(800)
    assert page.locator("#total").inner_text() == count
    page.locator("#flows tr").first.focus()
    page.keyboard.press("Enter")
    assert page.locator("#contributions .contribution").count() == 6
    page.get_by_role("button", name="Resume replay").click()
    expect(page.locator("#total")).not_to_have_text(count)
    page.locator("#scenario").select_option("Generic")
    expect(page.locator("#flows tr td:last-child").first).to_have_text("Generic")
    page.get_by_role("button", name="Pause replay").click()
    page.locator("#search").fill("no-such-flow")
    assert page.locator("#empty").is_visible()
    page.locator("#search").fill("")
    with page.expect_download() as download:
        page.get_by_role("button", name="Export session").click()
    exported = json.loads(download.value.path().read_text())
    assert exported["source"] == "benchmark_replay"
    assert exported["retained_flows"]
    assert not errors


def test_custom_inference_and_validation(browser_page):
    page, errors, _ = browser_page
    if page.locator("#mode-technical-btn").is_visible():
        page.locator("#mode-technical-btn").click()
    page.locator("#sample-class").select_option("Normal")
    page.get_by_role("button", name="Load example").click()
    page.wait_for_function(
        "document.getElementById('input-status').textContent.includes('true label: Normal')"
    )
    features = json.loads(page.locator("#payload").input_value())
    page.get_by_role("button", name="Analyze flow").click()
    expect(page.locator("#input-status")).to_contain_text("evidence shown")
    assert "submitted flow" in page.locator("#selected-source").inner_text()
    page.locator("#payload").fill("{}")
    page.get_by_role("button", name="Analyze flow").click()
    expect(page.locator("#input-status")).to_contain_text("Flow rejected")

    # Missing service regression test through UI
    bad_features = dict(features)
    del bad_features["service"]
    page.locator("#payload").fill(json.dumps(bad_features))
    page.get_by_role("button", name="Analyze flow").click()
    expect(page.locator("#input-status")).to_contain_text("Flow rejected")

    # The browser logs the expected 422 request; not a JS application failure.
    errors[:] = [e for e in errors if "422" not in e]
    features["proto"] = "<img src=x onerror=alert(1)>"
    page.locator("#payload").fill(json.dumps(features))
    page.get_by_role("button", name="Analyze flow").click()
    expect(page.locator("#warnings")).to_contain_text("<img")
    assert page.locator("#warnings img").count() == 0
    assert not errors


def test_first_time_visitor_and_understand_journey(browser_page):
    page, errors, url = browser_page
    page.goto(url)
    page.evaluate("() => localStorage.clear()")
    page.goto(url)
    expect(page.locator("#view-understand")).to_be_visible()
    expect(page.locator("#view-technical")).to_be_hidden()

    expect(page.locator("#understand-hero-title")).to_have_text("Fewer false alarms. A clearer next step.")
    expect(page.locator("#hero-raw-fpr")).to_have_text("33.4%")
    expect(page.locator("#hero-queue-fpr")).to_have_text("4.5%")
    expect(page.locator(".understand-hero")).to_contain_text("human")
    expect(page.locator("#loading-screen")).to_be_hidden(timeout=12000)

    # Benchmark disclaimer notice is prominent
    expect(page.locator(".benchmark-disclaimer")).to_contain_text("Benchmark replay")
    expect(page.locator(".benchmark-disclaimer")).to_contain_text("UNSW-NB15")

    # Guided archetype selection
    page.locator("#archetype-generic").click()
    expect(page.locator("#guided-verdict-badge")).to_have_text("Generic")
    expect(page.locator(".uncertainty-callout")).to_contain_text("not proof of an attack")
    expect(page.locator("#guided-step-observation")).not_to_contain_text("standard byte count")

    # Plain English explanation (rule-based fallback when offline)
    page.locator("#briefing-narrate-btn").click()
    expect(page.locator("#briefing-narrate-status")).to_contain_text("AI not configured")
    expect(page.locator("#briefing-provider-badge")).to_contain_text("Built-in explanation (Rule-based)")
    expect(page.locator("#briefing-narrative-text")).not_to_be_empty()

    # Plain language glossary
    page.locator(".glossary-card summary").click()
    expect(page.locator(".glossary-card")).to_contain_text("Connection record")
    expect(page.locator(".glossary-card")).to_contain_text("Review recommended")
    expect(page.locator(".glossary-card")).to_contain_text("Anomaly candidate")
    assert not errors


def test_analyst_decision_is_logged_without_execution(browser_page):
    page, errors, url = browser_page
    page.goto(url)
    page.locator("#archetype-generic").click()
    expect(page.locator("#decision-proposal")).not_to_have_text("Choose a connection to review.")
    page.locator("#decision-note").fill("Verify with host logs")
    page.locator("#decision-approve").click()
    expect(page.locator("#decision-status")).to_contain_text("Follow-up approved")
    expect(page.locator("#decision-status")).to_contain_text("No action executed")
    with page.expect_download() as download:
        page.locator("#export").click()
    exported = json.loads(download.value.path().read_text())
    assert exported["analyst_decisions"][-1]["decision"] == "approved_for_follow_up"
    assert exported["analyst_decisions"][-1]["analyst_note"] == "Verify with host logs"
    assert exported["analyst_decisions"][-1]["execution"] == "none"
    page.reload()
    expect(page.locator("#decision-count")).to_have_text("(1)")
    assert not errors


def test_theme_persists_across_reload_and_loading_ends(browser_page):
    page, errors, url = browser_page
    page.goto(url)
    page.evaluate("() => localStorage.setItem('nida_theme', 'light')")
    page.reload()
    expect(page.locator("#loading-screen")).to_be_hidden(timeout=12000)
    page.locator("#theme-toggle").click()
    assert page.locator("html").get_attribute("data-theme") == "dark"
    assert (
        page.locator("#archetype-normal").evaluate("el => getComputedStyle(el).backgroundColor")
        != "rgb(255, 255, 255)"
    )
    page.reload()
    expect(page.locator("#loading-screen")).to_be_hidden(timeout=12000)
    assert page.locator("html").get_attribute("data-theme") == "dark"
    page.locator("#theme-toggle").click()
    assert page.locator("html").get_attribute("data-theme") == "light"
    assert not errors


def test_loading_screen_waits_for_startup(browser_page):
    page, errors, url = browser_page

    def slow_metrics(route):
        time.sleep(0.6)
        route.continue_()

    page.route("**/metrics", slow_metrics)
    page.goto(url, wait_until="domcontentloaded")
    expect(page.locator("#loading-screen")).to_be_visible()
    expect(page.locator("#loading-screen")).to_be_hidden(timeout=12000)
    page.unroute("**/metrics", slow_metrics)
    assert not errors


def test_mode_switching_preserves_selected_flow(browser_page):
    page, errors, url = browser_page
    page.goto(url)
    page.locator("#mode-understand-btn").click()
    page.wait_for_selector("#flows tr:nth-child(2)", timeout=10000)

    # Select the second flow row
    row = page.locator("#flows tr").nth(1)
    row.click()
    flow_id_text = page.locator("#guided-flow-id").inner_text()
    verdict_text = page.locator("#guided-verdict-badge").inner_text()
    assert flow_id_text != "—"

    # Switch to Technical mode
    page.locator("#mode-technical-btn").click()
    expect(page.locator("#view-technical")).to_be_visible()
    expect(page.locator("#view-understand")).to_be_hidden()

    # Evidence dossier reflects the exact same flow
    expect(page.locator("#selected-verdict")).to_have_text(verdict_text)
    assert page.locator("#contributions .contribution").count() == 6
    assert page.locator("#classifier-bar").is_visible()

    # Switch back to Understand mode
    page.locator("#mode-understand-btn").click()
    expect(page.locator("#view-understand")).to_be_visible()
    expect(page.locator("#view-technical")).to_be_hidden()
    expect(page.locator("#guided-flow-id")).to_have_text(flow_id_text)
    expect(page.locator("#guided-verdict-badge")).to_have_text(verdict_text)
    assert not errors


def test_evidence_and_responsive_layout(browser_page):
    page, errors, url = browser_page
    page.goto(url)
    expect(page.locator("#total")).to_have_text(re.compile(r"^[7-9]$|^[1-9][0-9,]+$"), timeout=15000)
    page.get_by_role("button", name="Pause replay").click()
    assert page.locator("#class-metrics tr").count() == 10
    assert page.locator("#eval-accuracy").inner_text() != "—"
    image_dir = ROOT / "docs" / "images"
    image_dir.mkdir(parents=True, exist_ok=True)
    page.screenshot(path=str(image_dir / "dashboard.png"), full_page=True)
    page.set_viewport_size({"width": 390, "height": 844})
    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
    assert page.get_by_role("button", name="Resume replay").is_visible()
    page.screenshot(path=str(image_dir / "mobile.png"), full_page=True)
    assert not errors
