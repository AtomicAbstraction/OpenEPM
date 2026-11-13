#!/usr/bin/env python3
"""Qualify native first-password replacement in managed Chromium.

The exact private generation is started only for this qualification. A
run-owned native Keycloak identity receives a temporary password, changes it
inside a fresh headless Playwright Chromium context, and completes Authorization
Code + S256 PKCE for the public MCP client. The qualifier deletes that identity,
proves the captured refresh token is unusable and quiesces the private
generation. No owner credential, password, token, code, subject or login
identifier is written or printed.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
from pathlib import Path
import re
import secrets
import time
from urllib.parse import urlencode, urlsplit

import httpx2

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from scripts import enroll_programmable_private_identity as enrollment
from scripts import macos_pilot_owner_uat_controller as owner
from scripts import macos_pilot_programmable_replacement as replacement
from scripts.openepm_keycloak_bootstrap import KeycloakApi
from scripts.qualify_macos_pilot_mcp_oauth import receive_callback


class ChromeQualificationError(RuntimeError):
    pass


def _protected(root: Path, name: str, maximum: int = 4096) -> str:
    return replacement._read_protected(root / "keycloak-secrets" / name,
                                       maximum)


def _expect(status: int, allowed: tuple[int, ...], code: str) -> None:
    if status not in allowed:
        raise ChromeQualificationError(f"{code}:{status}")


def _admin_token(api: KeycloakApi, username: str, password: str) -> str:
    status, body = api.request(
        "POST", "/realms/master/protocol/openid-connect/token",
        body={"grant_type": "password", "client_id": "admin-cli",
              "username": username, "password": password}, form=True)
    if status != 200 or type(body) is not dict or not isinstance(
            body.get("access_token"), str):
        raise ChromeQualificationError("PRIVATE_CHROME_ADMIN_AUTH_FAILED")
    return body["access_token"]


def reset_owner_password(*, api: KeycloakApi, admin_token: str,
                         username: str, expected_subject: str,
                         temporary_password: str) -> None:
    """Restore the exact private fixture without disclosing its credential."""
    status, matches = api.request(
        "GET", "/admin/realms/openepm/users?" + urlencode({
            "username": username, "exact": "true"}), token=admin_token)
    _expect(status, (200,), "PRIVATE_CHROME_OWNER_LOOKUP_FAILED")
    if (type(matches) is not list or len(matches) != 1
            or matches[0].get("id") != expected_subject):
        raise ChromeQualificationError("PRIVATE_CHROME_OWNER_BINDING_MISMATCH")
    subject = matches[0]["id"]
    status, _ = api.request(
        "PUT", f"/admin/realms/openepm/users/{subject}/reset-password",
        body={"type": "password", "value": temporary_password,
              "temporary": True}, token=admin_token)
    _expect(status, (204,), "PRIVATE_CHROME_PASSWORD_RESET_FAILED")
    status, _ = api.request(
        "POST", f"/admin/realms/openepm/users/{subject}/logout",
        token=admin_token)
    _expect(status, (204,), "PRIVATE_CHROME_SESSION_REVOCATION_FAILED")


def create_run_owned_user(*, api: KeycloakApi, admin_token: str,
                          temporary_password: str) -> tuple[str, str]:
    """Create a disposable native user for one qualification run."""
    username = "openepm-qualification-" + secrets.token_hex(12)
    status, _ = api.request(
        "POST", "/admin/realms/openepm/users",
        body={"username": username, "enabled": True,
              "requiredActions": ["UPDATE_PASSWORD"],
              "credentials": [{"type": "password",
                               "value": temporary_password,
                               "temporary": True}]},
        token=admin_token)
    _expect(status, (201,), "QUALIFICATION_USER_CREATE_FAILED")
    status, matches = api.request(
        "GET", "/admin/realms/openepm/users?" + urlencode({
            "username": username, "exact": "true"}), token=admin_token)
    if (status != 200 or type(matches) is not list or len(matches) != 1
            or not isinstance(matches[0].get("id"), str)):
        raise ChromeQualificationError("QUALIFICATION_USER_BINDING_FAILED")
    return username, matches[0]["id"]


def delete_run_owned_user(*, api: KeycloakApi, admin_token: str,
                          subject: str) -> None:
    status, _ = api.request(
        "DELETE", f"/admin/realms/openepm/users/{subject}",
        token=admin_token)
    _expect(status, (204,), "QUALIFICATION_USER_DELETE_FAILED")


def chrome_first_password(url: str, *, username: str, password: str,
                          replacement_password: str) -> dict:
    """Drive only an isolated Playwright-managed Chromium context."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as error:
        raise ChromeQualificationError(
            "PRIVATE_CHROME_PLAYWRIGHT_UNAVAILABLE") from error
    stage = "launch"
    page = None
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                context = browser.new_context()
                page = context.new_page()
                stage = "authorization-navigation"
                page.goto(url, wait_until="domcontentloaded", timeout=60000)
                stage = "native-login-form"
                page.locator("#username").fill(username)
                page.locator("#password").fill(password)
                page.locator("#kc-login").click()
                stage = "first-password-form"
                page.locator("#password-new").wait_for(timeout=60000)
                page.locator("#password-new").fill(replacement_password)
                page.locator("#password-confirm").fill(replacement_password)
                form = page.locator("#kc-passwd-update-form")
                stage = "first-password-submit"
                form.locator('input[type="submit"],button[type="submit"]').click()
                page.wait_for_timeout(1500)
                if "/login-actions/required-action" in page.url:
                    messages = page.locator(
                        '[role="alert"],.alert-error,.pf-v5-c-alert__title,'
                        '[id^="input-error"]'
                    ).all_inner_texts()
                    diagnostic = " ".join(messages)
                    for secret_value in (username, password,
                                         replacement_password):
                        diagnostic = diagnostic.replace(
                            secret_value, "[redacted]")
                    diagnostic = re.sub(r"[^A-Za-z0-9 .,:;_()'/-]+", " ",
                                        diagnostic)
                    diagnostic = re.sub(r"\s+", " ", diagnostic).strip()
                    if not diagnostic:
                        diagnostic = "no-validation-message"
                    raise ChromeQualificationError(
                        "PRIVATE_CHROME_REQUIRED_ACTION_REJECTED:"
                        + diagnostic[:240])
                stage = "loopback-callback"
                page.get_by_text(
                    "Open EPM authorization received.", exact=False
                ).wait_for(timeout=60000)
                return {
                    "browser": "Playwright Chromium",
                    "browserVersion": browser.version,
                    "isolatedContext": True,
                    "firstPasswordReplacementCompleted": True,
                    "authorizationCallbackRendered": True,
                }
            finally:
                browser.close()
    except ChromeQualificationError:
        raise
    except Exception as error:
        location = "unavailable"
        if page is not None:
            try:
                parsed = urlsplit(page.url)
                if parsed.scheme in ("http", "https") and parsed.hostname:
                    location = parsed.scheme + "://" + parsed.netloc + parsed.path
            except Exception:
                pass
        raise ChromeQualificationError(
            "PRIVATE_CHROME_FIRST_PASSWORD_JOURNEY_FAILED:"
            + stage + ":" + location + ":" + type(error).__name__) from error


async def _exchange(*, callback, verifier: str) -> dict:
    async with httpx2.AsyncClient(timeout=30, follow_redirects=False) as client:
        response = await client.post(
            enrollment.LOCAL_IDENTITY_ORIGIN
            + "/realms/openepm/protocol/openid-connect/token",
            data={"grant_type": "authorization_code",
                  "client_id": enrollment.CLIENT_ID,
                  "code": callback.code,
                  "redirect_uri": enrollment.REDIRECT_URI,
                  "code_verifier": verifier})
    if response.status_code != 200:
        raise ChromeQualificationError("PRIVATE_CHROME_TOKEN_EXCHANGE_FAILED")
    try:
        body = response.json()
    except (ValueError, json.JSONDecodeError) as error:
        raise ChromeQualificationError(
            "PRIVATE_CHROME_TOKEN_EXCHANGE_FAILED") from error
    if (type(body) is not dict
            or not isinstance(body.get("access_token"), str)
            or not isinstance(body.get("refresh_token"), str)):
        raise ChromeQualificationError("PRIVATE_CHROME_TOKEN_EXCHANGE_FAILED")
    return body


async def _refresh_revoked(refresh_token: str) -> bool:
    async with httpx2.AsyncClient(timeout=30, follow_redirects=False) as client:
        response = await client.post(
            enrollment.LOCAL_IDENTITY_ORIGIN
            + "/realms/openepm/protocol/openid-connect/token",
            data={"grant_type": "refresh_token",
                  "client_id": enrollment.CLIENT_ID,
                  "refresh_token": refresh_token})
    return response.status_code in (400, 401)


async def qualify(root: Path) -> dict:
    value = enrollment.plan(root)
    command, environment = replacement.base(value["root"])
    secrets_root = value["root"]
    username = _protected(secrets_root, "keycloak_admin_username")
    admin_password = _protected(secrets_root, "keycloak_admin_password")
    temporary_password = "Qf!" + secrets.token_urlsafe(24) + "7a"
    api = KeycloakApi(enrollment.LOCAL_IDENTITY_ORIGIN)
    replacement_password = (
        "Qf!" + secrets.token_urlsafe(24) + "7a")
    callback = None
    token_body = None
    browser_result = None
    run_subject = None
    primary_failure = None
    owner.all_up(command, environment)
    try:
        readiness = await enrollment.wait_identity_ready(value)
        admin_token = _admin_token(api, username, admin_password)
        login_id, run_subject = create_run_owned_user(
            api=api, admin_token=admin_token,
            temporary_password=temporary_password)

        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(
            verifier.encode("ascii")).digest()).decode("ascii").rstrip("=")
        url = enrollment.authorization_url(value, state, challenge)
        callback_task = asyncio.create_task(receive_callback(
            timeout_seconds=300))
        await asyncio.sleep(0)
        browser_result = await asyncio.to_thread(
            chrome_first_password, url, username=login_id,
            password=temporary_password,
            replacement_password=replacement_password)
        callback = await callback_task
        if callback.state != state or callback.iss not in (None, value["issuer"]):
            raise ChromeQualificationError(
                "PRIVATE_CHROME_CALLBACK_BINDING_MISMATCH")
        token_body = await _exchange(callback=callback, verifier=verifier)
        binding = enrollment.validate_token(
            token_body["access_token"], {**value, "subject": run_subject})

        delete_run_owned_user(api=api, admin_token=admin_token,
                              subject=run_subject)
        run_subject = None
        if not await _refresh_revoked(token_body["refresh_token"]):
            raise ChromeQualificationError(
                "PRIVATE_CHROME_REVOKED_REFRESH_ACCEPTED")
        return {
            "format": "openepm-private-chrome-first-password-v1",
            "qualifiedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "identityReadiness": readiness,
            "browser": browser_result,
            "authorizationCodeFlow": True,
            "pkceMethod": "S256",
            "mcpAudienceVerified": binding["audience"] == "openepm-mcp",
            "subjectBindingVerified": True,
            "refreshRejectedAfterSessionRevocation": True,
            "runOwnedIdentityDeleted": True,
            "credentialPrinted": False,
            "credentialPersisted": False,
            "existingChromeSessionInspected": False,
            "publicPortsChanged": False,
            "activeGenerationMutation": False,
        }
    except Exception as error:
        primary_failure = error
        raise
    finally:
        cleanup_failure = None
        if run_subject is not None:
            try:
                admin_token = _admin_token(api, username, admin_password)
                delete_run_owned_user(api=api, admin_token=admin_token,
                                      subject=run_subject)
            except Exception as cleanup_error:
                cleanup_failure = cleanup_error
        try:
            replacement.quiesce_prepared(command, environment, "keycloak")
        finally:
            if cleanup_failure is not None:
                raise ChromeQualificationError(
                    "PRIVATE_CHROME_RUN_IDENTITY_CLEANUP_FAILED") from (
                        primary_failure or cleanup_failure)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, default=
                        replacement.ROOT / "deploy/macos-pilot/.runtime"
                        / "harmonized-next")
    arguments = parser.parse_args()
    try:
        result = asyncio.run(qualify(arguments.state_root.resolve()))
    except (ChromeQualificationError, enrollment.EnrollmentError,
            replacement.ReplacementError, OSError, ValueError) as error:
        parser.error(str(error) or type(error).__name__)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
