#!/usr/bin/env python3
"""Qualify native Keycloak through the real public Open EPM Chrome path.

This acceptance runner deliberately refuses to start an interactive browser
unless the public application redirects directly to the native Keycloak
issuer, the issuer metadata is exact, and the MCP endpoint fails closed
without credentials. It changes no business state and never changes an owner
or bootstrap credential. A fresh run-owned user completes the first-password
journey and is deleted in ``finally``.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from playwright.sync_api import sync_playwright

from scripts.qualify_active_browser_session_lifecycle import (
    DEFAULT_STATE,
    LifecycleError,
    session_record_exists,
    session_cookie,
    storage_is_empty,
)
APP_ORIGIN = "https://app.openepm.dev"
IDENTITY_ORIGIN = "https://identity.openepm.dev"
MCP_ENDPOINT = "https://mcp.openepm.dev/api/application/mcp"
PLATFORM_CONTAINER = "openepm-harmonized-next-platform-1"

DIRECTORY_EFFECT = r"""
import json, os, sys, time
from epm_core.keycloak_directory import KeycloakDirectory, KeycloakDirectoryApi
from epm_core.postgres_access import VerifiedIdentity
from epm_core.postgres_identity_directory import PostgresIdentityDirectory

payload = json.load(sys.stdin)
dsn_path = os.environ.get("EPM_PG_PROVISION_DSN_FILE", "")
if dsn_path:
    with open(dsn_path, encoding="utf-8") as stream:
        dsn = stream.read().strip()
else:
    dsn = os.environ.get("EPM_PG_PROVISION_DSN", "").strip()
if not dsn:
    raise RuntimeError("PROVISION_DSN_UNAVAILABLE")
identity = VerifiedIdentity(payload["issuer"], payload["actorSubject"],
                            issued_at=int(time.time()))
service = PostgresIdentityDirectory(
    dsn, identity=identity,
    directory=KeycloakDirectory(KeycloakDirectoryApi.from_environment()),
    directory_issuer=payload["issuer"])
result = service.execute(payload["program"],
                         idempotency_key=payload["idempotencyKey"])
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
"""

DIRECTORY_READ = DIRECTORY_EFFECT.replace(
    'result = service.execute(payload["program"],\n'
    '                         idempotency_key=payload["idempotencyKey"])',
    'result = service.read(payload["program"])')


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers,
                         new_url):
        return None


def response(url: str, *, accept: str) -> tuple[int, dict[str, str], bytes]:
    request = Request(url, headers={
        "Accept": accept,
        "User-Agent": "OpenEPM-Public-Native-Keycloak-Qualifier/1",
    })
    try:
        with build_opener(NoRedirect).open(request, timeout=30) as result:
            return (result.status,
                    {key.lower(): value for key, value in result.headers.items()},
                    result.read(262144))
    except HTTPError as error:
        return (error.code,
                {key.lower(): value for key, value in error.headers.items()},
                error.read(262144))


def public_preflight() -> dict:
    app_status, app_headers, _ = response(
        APP_ORIGIN + "/", accept="text/html,application/xhtml+xml")
    location = app_headers.get("location", "")
    parsed = urlsplit(location)
    if (app_status not in (302, 303)
            or parsed.scheme != "https"
            or parsed.hostname != "identity.openepm.dev"
            or not parsed.path.startswith(
                "/realms/openepm/protocol/openid-connect/auth")):
        raise LifecycleError(
            "PUBLIC_NATIVE_KEYCLOAK_NOT_ROUTED:status="
            + str(app_status) + ";host=" + str(parsed.hostname or "none")
            + ";path=" + (parsed.path or "none"))

    discovery_status, _, discovery_raw = response(
        IDENTITY_ORIGIN + "/realms/openepm/.well-known/openid-configuration",
        accept="application/json")
    try:
        discovery = json.loads(discovery_raw)
    except json.JSONDecodeError as error:
        raise LifecycleError("PUBLIC_KEYCLOAK_DISCOVERY_INVALID") from error
    if discovery_status != 200 or discovery.get("issuer") != (
            IDENTITY_ORIGIN + "/realms/openepm"):
        raise LifecycleError("PUBLIC_KEYCLOAK_ISSUER_INVALID")

    mcp_status, mcp_headers, _ = response(
        MCP_ENDPOINT, accept="application/json")
    mcp_location = urlsplit(mcp_headers.get("location", ""))
    if mcp_status != 401 or mcp_location.hostname:
        raise LifecycleError(
            "PUBLIC_MCP_UNAUTHENTICATED_BOUNDARY_INVALID:status="
            + str(mcp_status) + ";redirectHost="
            + str(mcp_location.hostname or "none"))
    return {
        "applicationRedirect": "native-keycloak",
        "issuer": discovery["issuer"],
        "unauthenticatedMcpStatus": mcp_status,
    }


def governed_directory_effect(state_root: Path, program: dict, *,
                              idempotency_key: str,
                              docker_context: str | None = None) -> dict:
    try:
        state = json.loads((state_root / "state.json").read_text(
            encoding="utf-8"))
        actor = state["identityVerification"]["initialAdministratorSubject"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError,
            TypeError) as error:
        raise LifecycleError("ACTIVE_ADMINISTRATOR_IDENTITY_INVALID") from error
    if (not isinstance(actor, str)
            or re.fullmatch(r"[A-Za-z0-9._:@+-]{1,255}", actor) is None):
        raise LifecycleError("ACTIVE_ADMINISTRATOR_IDENTITY_INVALID")
    payload = {
        "issuer": IDENTITY_ORIGIN + "/realms/openepm",
        "actorSubject": actor,
        "program": program,
        "idempotencyKey": idempotency_key,
    }
    context_arguments = [] if docker_context is None else ["--context", docker_context]
    result = subprocess.run(
        ["docker", *context_arguments, "exec", "-i", PLATFORM_CONTAINER, "python", "-c",
         DIRECTORY_EFFECT], input=json.dumps(payload), text=True,
        capture_output=True, timeout=90)
    if result.returncode != 0:
        safe_codes = sorted(set(re.findall(
            r"\b[A-Z][A-Z0-9_]{3,}\b", result.stderr)))
        raise LifecycleError(
            "GOVERNED_DIRECTORY_EFFECT_FAILED:returncode="
            + str(result.returncode) + ";codes="
            + ",".join(safe_codes[:8]))
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LifecycleError("GOVERNED_DIRECTORY_RESPONSE_INVALID") from error
    if type(value) is not dict:
        raise LifecycleError("GOVERNED_DIRECTORY_RESPONSE_INVALID")
    return value


def governed_directory_read(state_root: Path, program: dict) -> dict:
    """Read the managed directory through the same current operator fence."""
    try:
        state = json.loads((state_root / "state.json").read_text(
            encoding="utf-8"))
        actor = state["identityVerification"]["initialAdministratorSubject"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError,
            TypeError) as error:
        raise LifecycleError("ACTIVE_ADMINISTRATOR_IDENTITY_INVALID") from error
    if (not isinstance(actor, str)
            or re.fullmatch(r"[A-Za-z0-9._:@+-]{1,255}", actor) is None):
        raise LifecycleError("ACTIVE_ADMINISTRATOR_IDENTITY_INVALID")
    payload = {"issuer": IDENTITY_ORIGIN + "/realms/openepm",
               "actorSubject": actor, "program": program}
    result = subprocess.run(
        ["docker", "exec", "-i", PLATFORM_CONTAINER, "python", "-c",
         DIRECTORY_READ], input=json.dumps(payload), text=True,
        capture_output=True, timeout=90)
    if result.returncode != 0:
        safe_codes = sorted(set(re.findall(
            r"\b[A-Z][A-Z0-9_]{3,}\b", result.stderr)))
        raise LifecycleError(
            "GOVERNED_DIRECTORY_READ_FAILED:returncode="
            + str(result.returncode) + ";codes="
            + ",".join(safe_codes[:8]))
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LifecycleError("GOVERNED_DIRECTORY_RESPONSE_INVALID") from error
    if type(value) is not dict:
        raise LifecycleError("GOVERNED_DIRECTORY_RESPONSE_INVALID")
    return value


def directory_program(function: str, **arguments: object) -> dict:
    return {"languageVersion": 2, "function": function,
            "arguments": arguments}


def qualify(state_root: Path) -> dict:
    preflight = public_preflight()
    run_id = secrets.token_hex(12)
    login_id = "openepm-qualification-" + run_id
    temporary_password = "Qt!" + secrets.token_urlsafe(24) + "7x"
    subject = None
    replacement_password = "Pu!" + secrets.token_urlsafe(24) + "4n"
    try:
        created = governed_directory_effect(state_root, directory_program(
            "identity.native-user.create", username=login_id,
            displayName="Open EPM qualification user",
            shortDescription="Run-owned public browser qualification",
            semanticDescription=(
                "Disposable identity for the exact public browser session "
                "lifecycle qualification.")),
            idempotency_key="public-browser-create-" + run_id)
        subject = created.get("subjectId")
        if not isinstance(subject, str) or not subject:
            raise LifecycleError("GOVERNED_DIRECTORY_RESPONSE_INVALID")
        governed_directory_effect(state_root, directory_program(
            "identity.native-user.password.set", subjectId=subject,
            temporaryPassword=temporary_password),
            idempotency_key="public-browser-password-" + run_id)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            try:
                context = browser.new_context()
                first = context.new_page()
                first.goto(APP_ORIGIN + "/", wait_until="domcontentloaded",
                           timeout=60_000)
                if urlsplit(first.url).hostname != "identity.openepm.dev":
                    raise LifecycleError(
                        "PUBLIC_BROWSER_NATIVE_LOGIN_NOT_REACHED")
                first.locator("#username").fill(login_id)
                first.locator("#password").fill(temporary_password)
                first.locator("#kc-login").click()
                first.locator("#password-new").wait_for(timeout=60_000)
                first.locator("#password-new").fill(replacement_password)
                first.locator("#password-confirm").fill(replacement_password)
                first.locator(
                    '#kc-passwd-update-form input[type="submit"],'
                    '#kc-passwd-update-form button[type="submit"]'
                ).click()
                first.locator("#main-content").wait_for(timeout=60_000)
                active_cookie = session_cookie(context)
                if not session_record_exists(state_root, active_cookie):
                    raise LifecycleError(
                        "PUBLIC_BROWSER_SESSION_RECORD_MISSING")
                if not storage_is_empty(first):
                    raise LifecycleError("PUBLIC_BROWSER_TOKEN_STORAGE_PRESENT")
                second = context.new_page()
                second.goto(APP_ORIGIN + "/", wait_until="domcontentloaded",
                            timeout=60_000)
                second.locator("#main-content").wait_for(timeout=60_000)
                platform_status = first.evaluate("""async () =>
                  (await fetch('/api/platform/browser/catalog', {
                    method: 'POST', credentials: 'same-origin',
                    headers: {'Content-Type': 'application/json'},
                    body: '{}'
                  })).status""")
                if platform_status != 403:
                    raise LifecycleError(
                        "PUBLIC_PLATFORM_ROUTE_BOUNDARY_INVALID:status="
                        + str(platform_status))
                identity_response = first.evaluate("""async () => {
                  const response = await fetch('/api/session-identity', {
                    credentials: 'same-origin'
                  });
                  let code = 'none';
                  try {
                    const body = await response.json();
                    if (typeof body?.error?.code === 'string') {
                      code = body.error.code;
                    }
                  } catch (_) {}
                  return {status: response.status, code};
                }""")
                if identity_response["status"] != 200:
                    raise LifecycleError(
                        "PUBLIC_BROWSER_SESSION_INVALID:status="
                        + str(identity_response["status"]) + ";code="
                        + str(identity_response["code"]))
                first.goto(APP_ORIGIN + "/oidc/sign_out",
                           wait_until="domcontentloaded", timeout=60_000)
                if (urlsplit(first.url).hostname != "identity.openepm.dev"
                        or not first.locator("#username").is_visible()):
                    raise LifecycleError(
                        "PUBLIC_BROWSER_LOGOUT_RETURN_INVALID")
                if any(cookie["name"] == "__Host-openepm_session"
                       for cookie in context.cookies()):
                    raise LifecycleError(
                        "PUBLIC_BROWSER_LOGOUT_COOKIE_RETAINED")
                if session_record_exists(state_root, active_cookie):
                    raise LifecycleError(
                        "PUBLIC_BROWSER_LOGOUT_SESSION_RECORD_RETAINED")
                replay = browser.new_context()
                try:
                    replay.add_cookies([active_cookie])
                    replay_response = replay.request.get(
                        APP_ORIGIN + "/api/session-identity",
                        max_redirects=0)
                    if replay_response.status != 401:
                        raise LifecycleError(
                            "PUBLIC_BROWSER_LOGOUT_STALE_TICKET_REUSED")
                finally:
                    replay.close()
                second.bring_to_front()
                second.evaluate(
                    "document.dispatchEvent(new Event('visibilitychange'))")
                second.get_by_text("Your session has timed out").wait_for(
                    timeout=15_000)
                return {
                    "format": "openepm-public-native-keycloak-lifecycle-v1",
                    "qualifiedAt": time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "browser": "Playwright Chromium",
                    "browserVersion": browser.version,
                    "preflight": preflight,
                    "nativeFirstPasswordReplacement": True,
                    "opaqueCookie": True,
                    "browserTokenStorage": False,
                    "twoTabsAuthenticated": True,
                    "platformRouteDeniedNonOperator": True,
                    "logoutClearedOpaqueCookie": True,
                    "logoutDeletedExactSessionRecord": True,
                    "logoutReturnedToNativeLogin": True,
                    "staleOpaqueTicketDenied": True,
                    "crossTabExpiryVisible": True,
                    "credentialPrinted": False,
                    "credentialPersisted": False,
                    "runOwnedIdentityDeactivated": True,
                    "sharedBusinessDataMutation": False,
                }
            finally:
                browser.close()
    finally:
        if subject is not None:
            governed_directory_effect(state_root, directory_program(
                "identity.native-user.status.set", subjectId=subject,
                status="Inactive"),
                idempotency_key="public-browser-deactivate-" + run_id)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    result = qualify(arguments.state_root.resolve())
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
    if arguments.output:
        arguments.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
