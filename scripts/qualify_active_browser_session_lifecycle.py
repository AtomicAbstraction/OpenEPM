#!/usr/bin/env python3
"""Qualify the active native-Keycloak browser-session lifecycle in Chrome.

The qualifier starts a second, disposable instance of the exact browser
gateway image on the active private Docker network. It reuses the protected
production configuration but shortens only the refresh interval to five
seconds. A fresh Chrome context completes native first-password replacement,
loads the packaged application in two tabs, proves session rotation, clears
the server-side session through the real logout route, and proves that one
tab's revalidation expires both tabs. No token, cookie, password, subject or
login identifier is printed or persisted.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
from pathlib import Path
import re
import sys
import secrets
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

from scripts import macos_pilot_programmable_replacement as replacement
from scripts.audit_disposable_docker_cleanup_candidates import OwnedDockerRun


DEFAULT_STATE = ROOT / "deploy/macos-pilot/.runtime/harmonized-next"
GATEWAY_IMAGE = (
    "quay.io/oauth2-proxy/oauth2-proxy:v7.15.5@"
    "sha256:8498b0d0ef0a7b29686414000a08aee467f02d0299c9ed1e006a8f33fc017916"
)
GATEWAY_CONTAINER = "openepm-browser-lifecycle-qualifier"
BRIDGE_CONTAINER = "openepm-browser-lifecycle-https-bridge"
BRIDGE_IMAGE = (
    "traefik@sha256:"
    "1336e85aaed293bd63d005086e0dd013b04078b26aaeb1c18b26a2f928af7e65"
)
ACTIVE_GATEWAY_CONTAINER = "openepm-harmonized-next-browser-gateway-1"
ACTIVE_SESSION_STORE_CONTAINER = (
    "openepm-harmonized-next-browser-session-store-1")
GATEWAY_PORT = 5296
PUBLIC_ORIGIN = "https://app.openepm.dev"


class LifecycleError(RuntimeError):
    pass


def run(*args: str, check: bool = True,
        docker_context: str | None = None) -> subprocess.CompletedProcess[str]:
    if args and args[0] == "docker" and docker_context is not None:
        args = ("docker", "--context", docker_context, *args[1:])
    result = subprocess.run(args, text=True, capture_output=True, timeout=90)
    if check and result.returncode:
        raise LifecycleError(f"{args[0]} failed ({result.returncode})")
    return result


def docker(*arguments: str) -> str:
    return run("docker", *arguments).stdout.strip()


def protected(root: Path, name: str, maximum: int = 16384) -> str:
    return replacement._read_protected(root / "keycloak-secrets" / name,
                                       maximum)


def active_network(*, docker_context: str | None = None) -> str:
    raw = run("docker", "inspect", ACTIVE_GATEWAY_CONTAINER,
              "--format", "{{json .NetworkSettings.Networks}}",
              docker_context=docker_context)
    try:
        networks = json.loads(raw.stdout)
    except json.JSONDecodeError as error:
        raise LifecycleError("ACTIVE_BROWSER_NETWORK_INVALID") from error
    if not isinstance(networks, dict) or len(networks) != 1:
        raise LifecycleError("ACTIVE_BROWSER_NETWORK_AMBIGUOUS")
    return next(iter(networks))


def session_cookie(context):
    matches = [cookie for cookie in context.cookies()
               if cookie["name"] == "__Host-openepm_session"]
    if len(matches) != 1:
        raise LifecycleError("BROWSER_SESSION_COOKIE_COUNT_INVALID")
    cookie = matches[0]
    if not cookie["httpOnly"] or not cookie["secure"] \
            or cookie["sameSite"] != "Lax" or cookie["path"] != "/":
        raise LifecycleError("BROWSER_SESSION_COOKIE_FLAGS_INVALID")
    return cookie


def gateway_cookie_secret(state_root: Path) -> str:
    lines = protected(state_root, "browser_gateway.cfg").splitlines()
    matches = [line.split("=", 1)[1].strip() for line in lines
               if line.startswith("cookie_secret =")]
    if len(matches) != 1:
        raise LifecycleError("BROWSER_COOKIE_SECRET_INVALID")
    try:
        secret = json.loads(matches[0])
    except json.JSONDecodeError as error:
        raise LifecycleError("BROWSER_COOKIE_SECRET_INVALID") from error
    if not isinstance(secret, str) or not 16 <= len(secret) <= 256:
        raise LifecycleError("BROWSER_COOKIE_SECRET_INVALID")
    return secret


def redis_ticket_handle(cookie: dict, cookie_secret: str) -> str:
    value = cookie.get("value") if isinstance(cookie, dict) else None
    if not isinstance(value, str) or not isinstance(cookie_secret, str):
        raise LifecycleError("BROWSER_SESSION_TICKET_INVALID")
    parts = value.split("|")
    if len(parts) != 3 or not parts[1].isdigit():
        raise LifecycleError("BROWSER_SESSION_TICKET_INVALID")
    signature = hmac.new(cookie_secret.encode("utf-8"),
        ("__Host-openepm_session" + parts[0] + parts[1]).encode("utf-8"),
        hashlib.sha256).digest()
    try:
        observed_signature = base64.urlsafe_b64decode(parts[2])
        ticket = base64.urlsafe_b64decode(parts[0]).decode("ascii")
    except (ValueError, UnicodeDecodeError) as error:
        raise LifecycleError("BROWSER_SESSION_TICKET_INVALID") from error
    if not hmac.compare_digest(signature, observed_signature):
        raise LifecycleError("BROWSER_SESSION_TICKET_INVALID")
    ticket_parts = ticket.split(".")
    if len(ticket_parts) != 3 or ticket_parts[0] != "v2":
        raise LifecycleError("BROWSER_SESSION_TICKET_INVALID")
    try:
        handle = base64.urlsafe_b64decode(
            ticket_parts[1] + "=" * (-len(ticket_parts[1]) % 4)).decode(
                "ascii")
        ticket_secret = base64.urlsafe_b64decode(
            ticket_parts[2] + "=" * (-len(ticket_parts[2]) % 4))
    except (ValueError, UnicodeDecodeError) as error:
        raise LifecycleError("BROWSER_SESSION_TICKET_INVALID") from error
    if (not re.fullmatch(r"__Host-openepm_session-[0-9a-f]{32}", handle)
            or len(ticket_secret) != 16):
        raise LifecycleError("BROWSER_SESSION_TICKET_INVALID")
    return handle


def session_store_password(state_root: Path) -> str:
    lines = protected(state_root, "browser_session_store.conf").splitlines()
    matches = [line.removeprefix("requirepass ") for line in lines
               if line.startswith("requirepass ")]
    if (len(matches) != 1 or not 32 <= len(matches[0]) <= 256
            or any(character.isspace() for character in matches[0])):
        raise LifecycleError("BROWSER_SESSION_STORE_SECRET_INVALID")
    return matches[0]


def session_record_exists(state_root: Path, cookie: dict, *,
                          container: str = ACTIVE_SESSION_STORE_CONTAINER,
                          docker_context: str | None = None) -> bool:
    result = run(
        "docker", "exec", "-e",
        "REDISCLI_AUTH=" + session_store_password(state_root),
        container, "valkey-cli", "--raw", "EXISTS",
        redis_ticket_handle(cookie, gateway_cookie_secret(state_root)),
        docker_context=docker_context)
    if result.stdout.strip() not in ("0", "1"):
        raise LifecycleError(
            "BROWSER_SESSION_STORE_RESPONSE_INVALID:returncode="
            + str(result.returncode) + ";stdoutBytes="
            + str(len(result.stdout.encode("utf-8"))) + ";stderrBytes="
            + str(len(result.stderr.encode("utf-8"))))
    return result.stdout.strip() == "1"


def storage_is_empty(page) -> bool:
    return page.evaluate("""() => ({
      local: Object.keys(localStorage),
      session: Object.keys(sessionStorage)
    })""") == {"local": [], "session": []}


def qualify(state_root: Path) -> dict:
    from scripts.qualify_public_native_keycloak_lifecycle import PLATFORM_CONTAINER

    run_id = secrets.token_hex(12)
    manifest = (state_root / "qualification-runs" /
                ("browser-lifecycle-" + run_id + ".run.json")).resolve()
    with tempfile.TemporaryDirectory(
            prefix=".openepm-browser-lifecycle-", dir=ROOT) as raw:
        work = Path(raw)
        with OwnedDockerRun(manifest, purpose="browser-session-lifecycle",
                            command=docker) as owned:
            for container in (ACTIVE_GATEWAY_CONTAINER,
                              ACTIVE_SESSION_STORE_CONTAINER, PLATFORM_CONTAINER):
                owned.protect_container(container)
            result = _qualify(state_root, owned, run_id, work)
    result["cleanup"] = {**owned.report,
                         "temporaryCredentialsRemoved": not work.exists()}
    return result


def _qualify(state_root: Path, owned: OwnedDockerRun, run_id: str,
             work: Path) -> dict:
    # Imported lazily because the public qualifier shares the cookie/session
    # helpers in this module. Identity effects still use one governed helper.
    from scripts.qualify_public_native_keycloak_lifecycle import (
        directory_program, governed_directory_effect)

    secrets_root = state_root / "keycloak-secrets"
    config = secrets_root / "browser_gateway.cfg"
    alpha = secrets_root / "browser_gateway_alpha.yaml"
    web_secret = secrets_root / "keycloak_web_client_secret"
    identity_ca = secrets_root / "keycloak_internal_ca_certificate"
    login_id = "openepm-qualification-" + run_id
    temporary_password = "Qs!" + secrets.token_urlsafe(24) + "6v"
    subject = None
    replacement_password = "Ls!" + secrets.token_urlsafe(24) + "8q"
    docker_context = owned.manifest["context"]
    gateway = GATEWAY_CONTAINER + "-" + run_id
    bridge = BRIDGE_CONTAINER + "-" + run_id
    network = active_network(docker_context=docker_context)
    lifecycle_config = work / "browser_gateway.cfg"
    value = config.read_text(encoding="utf-8")
    if value.count('cookie_refresh = "5m"') != 1:
        raise LifecycleError("BROWSER_REFRESH_POLICY_UNEXPECTED")
    lifecycle_config.write_text(value.replace(
        'cookie_refresh = "5m"', 'cookie_refresh = "5s"'),
        encoding="utf-8")
    lifecycle_config.chmod(0o400)
    certificate = work / "browser-lifecycle.crt"
    private_key = work / "browser-lifecycle.key"
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-days", "1", "-keyout", str(private_key), "-out",
        str(certificate), "-subj", "/CN=app.openepm.dev", "-addext",
        "subjectAltName=DNS:app.openepm.dev,DNS:identity.openepm.dev")
    dynamic = work / "dynamic.yml"
    dynamic.write_text("""http:
  routers:
    application:
      rule: Host(`app.openepm.dev`)
      entryPoints: [websecure]
      service: application
      tls: {}
    identity:
      rule: Host(`identity.openepm.dev`)
      entryPoints: [websecure]
      service: identity
      tls: {}
  services:
    application:
      loadBalancer:
        servers: [{url: 'http://GATEWAY_HOST:4180'}]
    identity:
      loadBalancer:
        servers: [{url: 'https://identity:8443'}]
        serversTransport: identity-private-tls
  serversTransports:
    identity-private-tls:
      serverName: identity
      rootCAs: [/run/bridge/identity-ca.crt]
tls:
  certificates:
    - certFile: /run/bridge/tls.crt
      keyFile: /run/bridge/tls.key
""".replace("GATEWAY_HOST", gateway), encoding="utf-8")
    dynamic.chmod(0o400)
    primary_error = None
    try:
        created = governed_directory_effect(state_root, directory_program(
            "identity.native-user.create", username=login_id,
            displayName="Open EPM session-rotation qualification user",
            shortDescription="Run-owned browser rotation qualification",
            semanticDescription=(
                "Disposable identity for the exact browser session "
                "rotation and logout qualification.")),
            idempotency_key="active-browser-create-" + run_id,
            docker_context=docker_context)
        subject = created.get("subjectId")
        if not isinstance(subject, str) or not subject:
            raise LifecycleError("GOVERNED_DIRECTORY_RESPONSE_INVALID")
        governed_directory_effect(state_root, directory_program(
            "identity.native-user.password.set", subjectId=subject,
            temporaryPassword=temporary_password),
            idempotency_key="active-browser-password-" + run_id,
            docker_context=docker_context)
        gateway_id = owned.container(gateway,
            "--network", network, "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges=true", "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=32m", "-p",
            f"127.0.0.1:{GATEWAY_PORT}:4180", "-v",
            f"{lifecycle_config}:/run/secrets/browser_gateway_config:ro",
            "-v", f"{alpha}:"
            "/run/secrets/browser_gateway_alpha_config:ro",
            "-v", f"{web_secret}:/run/secrets/keycloak_web_client_secret:ro",
            GATEWAY_IMAGE,
            "--config=/run/secrets/browser_gateway_config",
            "--alpha-config=/run/secrets/browser_gateway_alpha_config")
        for _ in range(100):
            probe = run("curl", "--silent", "--output", "/dev/null",
                        "--write-out", "%{http_code}",
                        f"http://127.0.0.1:{GATEWAY_PORT}/ping", check=False)
            if probe.stdout == "200":
                break
            time.sleep(0.1)
        else:
            logs = run("docker", "logs", "--tail", "40",
                       gateway_id, check=False, docker_context=docker_context)
            raise LifecycleError(
                "BROWSER_LIFECYCLE_GATEWAY_NOT_READY: "
                + logs.stderr[-2000:])
        owned.container(bridge,
            "--network", network, "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges=true", "-p",
            "127.0.0.1:443:443", "-v",
            f"{dynamic}:/run/bridge/dynamic.yml:ro", "-v",
            f"{certificate}:/run/bridge/tls.crt:ro", "-v",
            f"{private_key}:/run/bridge/tls.key:ro", "-v",
            f"{identity_ca}:/run/bridge/identity-ca.crt:ro", BRIDGE_IMAGE,
            "--entryPoints.websecure.address=:443",
            "--providers.file.filename=/run/bridge/dynamic.yml",
            "--api.dashboard=false", "--log.level=ERROR")
        for _ in range(100):
            probe = run("curl", "--silent", "--insecure", "--resolve",
                        "app.openepm.dev:443:127.0.0.1", "--output",
                        "/dev/null", "--write-out", "%{http_code}",
                        "https://app.openepm.dev/ping", check=False)
            if probe.stdout == "200":
                break
            time.sleep(0.1)
        else:
            raise LifecycleError("BROWSER_LIFECYCLE_BRIDGE_NOT_READY")

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, args=[
                    "--host-resolver-rules="
                    "MAP app.openepm.dev 127.0.0.1,"
                    "MAP identity.openepm.dev 127.0.0.1",
                    "--ignore-certificate-errors",
                ])
            try:
                context = browser.new_context()
                first = context.new_page()
                first.goto(PUBLIC_ORIGIN + "/",
                           wait_until="domcontentloaded", timeout=60_000)
                first.locator("#username").fill(login_id)
                first.locator("#password").fill(temporary_password)
                first.locator("#kc-login").click()
                try:
                    first.locator("#password-new").wait_for(
                        timeout=15_000)
                except PlaywrightTimeoutError as error:
                    visible_error = ""
                    for selector in (
                            "#input-error", ".alert-error",
                            ".pf-v5-c-alert__title", ".kc-feedback-text"):
                        match = first.locator(selector).first
                        if match.count() and match.is_visible():
                            visible_error = match.inner_text()[:240]
                            break
                    if not visible_error:
                        visible_error = first.locator("body").inner_text()
                        visible_error = visible_error.replace(
                            login_id, "[redacted]")[:500]
                    raise LifecycleError(
                        "BROWSER_FIRST_PASSWORD_NOT_REACHED: path="
                        + urlsplit(first.url).path + "; title="
                        + first.title()[:120] + "; error="
                        + visible_error) from error
                first.locator("#password-new").fill(replacement_password)
                first.locator("#password-confirm").fill(
                    replacement_password)
                first.locator(
                    '#kc-passwd-update-form input[type="submit"],'
                    '#kc-passwd-update-form button[type="submit"]'
                ).click()
                first.locator("#main-content").wait_for(timeout=60_000)
                before = session_cookie(context)
                before_digest = hashlib.sha256(
                    before["value"].encode()).digest()
                if not storage_is_empty(first):
                    raise LifecycleError("BROWSER_TOKEN_STORAGE_PRESENT")
                second = context.new_page()
                second.goto(PUBLIC_ORIGIN + "/",
                            wait_until="domcontentloaded", timeout=60_000)
                second.locator("#main-content").wait_for(timeout=60_000)
                first.wait_for_timeout(7_000)
                status_code = first.evaluate("""async () =>
                  (await fetch('/api/session-identity', {
                    credentials: 'same-origin'
                  })).status""")
                if status_code != 200:
                    raise LifecycleError("BROWSER_SESSION_RENEWAL_FAILED")
                after = session_cookie(context)
                after_digest = hashlib.sha256(
                    after["value"].encode()).digest()
                if before_digest == after_digest:
                    raise LifecycleError("BROWSER_SESSION_NOT_ROTATED")
                if not session_record_exists(state_root, after,
                        docker_context=docker_context):
                    raise LifecycleError(
                        "BROWSER_SESSION_RECORD_MISSING_BEFORE_LOGOUT")

                logout = first.evaluate("""async () => {
                  const response = await fetch('/oidc/sign_out', {
                    credentials: 'same-origin', redirect: 'manual'
                  });
                  return {status: response.status, type: response.type};
                }""")
                if logout["status"] not in (0, 302, 303) \
                        and logout["type"] != "opaqueredirect":
                    raise LifecycleError("BROWSER_LOGOUT_FAILED")
                if any(cookie["name"] == "__Host-openepm_session"
                       for cookie in context.cookies()):
                    raise LifecycleError("BROWSER_LOGOUT_COOKIE_RETAINED")
                if session_record_exists(state_root, after,
                        docker_context=docker_context):
                    raise LifecycleError(
                        "BROWSER_LOGOUT_SESSION_RECORD_RETAINED")
                replay = browser.new_context()
                try:
                    replay.add_cookies([after])
                    replay_response = replay.request.get(
                        PUBLIC_ORIGIN + "/api/session-identity",
                        max_redirects=0)
                    if replay_response.status != 401:
                        raise LifecycleError(
                            "BROWSER_LOGOUT_STALE_TICKET_REUSED")
                finally:
                    replay.close()
                first.bring_to_front()
                first.evaluate(
                    "document.dispatchEvent(new Event('visibilitychange'))")
                first.get_by_text("Your session has timed out").wait_for(
                    timeout=15_000)
                second.get_by_text("Your session has timed out").wait_for(
                    timeout=15_000)
                return {
                    "format": "openepm-active-browser-lifecycle-v1",
                    "qualifiedAt": time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "browser": "Playwright Chromium",
                    "browserVersion": browser.version,
                    "exactGatewayImage": GATEWAY_IMAGE,
                    "nativeFirstPasswordReplacement": True,
                    "opaqueCookieFlags": "Secure; HttpOnly; SameSite=Lax; Path=/",
                    "serverSideRefresh": True,
                    "sessionIdentifierRotated": True,
                    "twoTabsAuthenticated": True,
                    "logoutClearedOpaqueCookie": True,
                    "logoutDeletedExactSessionRecord": True,
                    "staleOpaqueTicketDenied": True,
                    "crossTabExpiryVisible": True,
                    "browserTokenStorage": False,
                    "credentialPrinted": False,
                    "credentialPersisted": False,
                    "runOwnedIdentityDeactivated": True,
                    "sharedBusinessDataMutation": False,
                }
            finally:
                browser.close()
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            if subject is not None:
                governed_directory_effect(state_root, directory_program(
                    "identity.native-user.status.set", subjectId=subject,
                    status="Inactive"),
                    idempotency_key="active-browser-deactivate-" + run_id,
                    docker_context=docker_context)
        except BaseException as cleanup_error:
            if primary_error is None:
                raise
            primary_error.add_note("Run-owned identity deactivation failed: "
                                   + type(cleanup_error).__name__)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = qualify(args.state_root.resolve())
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
    if args.output:
        args.output.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
