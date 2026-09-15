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
    with log_path.open("w") as log:
        server = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(port)],
            cwd=ROOT,
            stdout=log,
            stderr=log,
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
    # The browser logs the expected 422 request; not a JS application failure.
    errors[:] = [e for e in errors if "422" not in e]
    features["proto"] = "<img src=x onerror=alert(1)>"
    page.locator("#payload").fill(json.dumps(features))
    page.get_by_role("button", name="Analyze flow").click()
    expect(page.locator("#warnings")).to_contain_text("<img")
    assert page.locator("#warnings img").count() == 0
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
