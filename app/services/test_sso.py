"""Automated test SSO (optional): sign a test user in through PingFederate in a
headless browser and capture the SAML response before it reaches the SP.

* Off unless TEST_SSO_ENABLED=true. Needs `pip install playwright` and
  `python -m playwright install chromium` on the machine that runs the tool,
  and that machine must reach PingFederate.
* Starts IdP-initiated SSO (TEST_SSO_START_URL), fills the PingFederate HTML
  form adapter, and intercepts the POST carrying SAMLResponse. The POST is
  answered locally, so the SP never receives it (no session is created there).
* Use a dedicated test account without MFA. Credentials come from the
  environment only and are never stored or logged.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

from app.config import Settings

log = logging.getLogger(__name__)


class TestSsoError(Exception):
    __test__ = False  # not a pytest class


@dataclass
class Capture:
    form_body: str        # "SAMLResponse=...&RelayState=..."
    posted_to: str
    screenshot: str | None = None


def start_url(settings: Settings, entity_id: str) -> str:
    return settings.test_sso_start_url.format(pf_base_url=settings.pf_base_url.rstrip("/"),
                                              entity_id=quote(entity_id, safe=""))


def capture(settings: Settings, entity_id: str, screenshot_dir: Path | None = None, url: str | None = None) -> Capture:
    if not settings.test_sso_enabled:
        raise TestSsoError("Automated test SSO is off (TEST_SSO_ENABLED=false)")
    try:
        from playwright.sync_api import TimeoutError as PwTimeout
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise TestSsoError("Playwright is not installed: pip install -r requirements-optional.txt "
                           "&& python -m playwright install chromium") from exc
    url = url or start_url(settings, entity_id)
    timeout = settings.test_sso_timeout_seconds * 1000
    got: dict = {}

    def on_route(route):
        req = route.request
        body = req.post_data or ""
        if req.method == "POST" and "SAMLResponse=" in body:
            got["body"], got["url"] = body, req.url
            route.fulfill(status=200, content_type="text/html",
                          body="<html><body>SAML response captured by the Migration Factory.</body></html>")
        else:
            route.continue_()

    shot = None
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        try:
            ctx = browser.new_context(ignore_https_errors=settings.test_sso_ignore_https_errors)
            page = ctx.new_page()
            page.route("**/*", on_route)
            page.goto(url, timeout=timeout)
            if not got:
                try:
                    page.wait_for_selector(settings.test_sso_username_selector, timeout=timeout)
                    page.fill(settings.test_sso_username_selector, settings.test_sso_username or "")
                    page.fill(settings.test_sso_password_selector,
                              settings.test_sso_password.get_secret_value() if settings.test_sso_password else "")
                    page.click(settings.test_sso_submit_selector)
                except PwTimeout:
                    pass  # maybe already signed in / no form; wait for the POST below
            waited = 0
            while not got and waited < timeout:
                page.wait_for_timeout(250)
                waited += 250
            if not got and screenshot_dir:
                screenshot_dir.mkdir(parents=True, exist_ok=True)
                shot = str(screenshot_dir / "test-sso-last-failure.png")
                page.screenshot(path=shot, full_page=True)
        finally:
            browser.close()
    if not got:
        raise TestSsoError("No SAML response was captured. The sign-in may need MFA, the selectors may not match "
                           "your PingFederate login template (TEST_SSO_*_SELECTOR), or the connection is disabled."
                           + (f" Screenshot: {shot}" if shot else ""))
    return Capture(form_body=got["body"], posted_to=got["url"], screenshot=shot)
