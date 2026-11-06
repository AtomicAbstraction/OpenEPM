#!/usr/bin/env python3
"""Rendered clean-host browser probe for the Open EPM React presentation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import secrets
import stat
import urllib.error
import urllib.parse
import urllib.request


class ProbeError(ValueError):
    pass


WORKFLOW_JS = r"""async (prefix) => {
  const post = async (path, body) => {
    const response = await fetch(path, {
      method: 'POST', credentials: 'same-origin',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    });
    let value = null;
    try { value = await response.json(); } catch (_) {}
    if (!response.ok) throw new Error(`API_${path}_${response.status}`);
    return value;
  };
  const ws = `uat-w-${prefix}`;
  const app = `uat-a-${prefix}`;
  const workspace = await post('/api/platform/browser/write', {
    program: {languageVersion: 2, function: 'platform.workspace.create',
      arguments: {workspaceId: ws, name: `Qualification ${prefix}`}},
    idempotencyKey: `workspace-${prefix}`, confirmed: true
  });
  const application = await post('/api/workspace-application', {
    workspaceId: ws, confirmed: true, idempotencyKey: `application-${prefix}`,
    program: {languageVersion: 2, function: 'workspace.application.create',
      arguments: {applicationId: app, name: `Qualification ${prefix}`,
        kind: 'multidimensional'}}
  });
  const dimensions = ['Account', 'Entity', 'Year', 'Period', 'View', 'Value'];
  const coordinate = {};
  let revision = 1;
  for (const dimension of dimensions) {
    const member = `${dimension}-Qualification`;
    coordinate[dimension] = member;
    await post('/api/metadata-action', {
      workspaceId: ws, applicationId: app, confirmed: true,
      idempotencyKey: `member-${dimension}-${prefix}`,
      program: {languageVersion: 2, function: 'metadata.member.create',
        arguments: {dimensionId: dimension, memberId: member, name: member,
          expectedMetadataRevision: revision}}
    });
    revision += 1;
  }
  const program = {languageVersion: 2, function: 'facts.numeric.batch',
    arguments: {mutations: [{coordinate, op: 'set',
      value: {type: 'AmountLiteral', decimal: '17.25000000'},
      expectedChangeId: ''}]}};
  const preview = await post('/api/preview', {
    workspaceId: ws, applicationId: app, program
  });
  if (!preview || typeof preview.previewToken !== 'string')
    throw new Error('PREVIEW_TOKEN_MISSING');
  const submitted = await post('/api/submit', {
    workspaceId: ws, applicationId: app, program,
    idempotencyKey: `fact-${prefix}`, dependsOnJobIds: [],
    previewToken: preview.previewToken, confirmed: true
  });
  if (!submitted || typeof submitted.jobId !== 'string')
    throw new Error('JOB_ID_MISSING');
  let job = null;
  for (let attempt = 0; attempt < 120; attempt += 1) {
    job = await post('/api/job', {
      workspaceId: ws, applicationId: app, jobId: submitted.jobId
    });
    if (['published', 'failed', 'interrupted', 'cancelled',
         'needs_inspection'].includes(
        job.status)) break;
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  if (!job || job.status !== 'published')
    throw new Error(`JOB_NOT_SUCCEEDED_${job && job.status}`);
  const read = await post('/api/read', {
    workspaceId: ws, applicationId: app,
    program: {languageVersion: 2, function: 'facts.cube.scan',
      arguments: {members: coordinate, limit: 10}}
  });
  const rows = read && read.result && read.result.rows;
  const exact = Array.isArray(rows) && rows.length === 1 &&
    rows[0].amount === '17.25000000' &&
    rows[0].members && Object.keys(rows[0].members).length === dimensions.length &&
    dimensions.every(dimension =>
      rows[0].members[dimension] === coordinate[dimension]);
  const applicationsResponse = await fetch('/api/applications?limit=100', {
    credentials: 'same-origin'
  });
  const applications = await applicationsResponse.json();
  return {workspaceCreated: workspace.workspaceId === ws,
    applicationCreated: application.applicationId === app,
    blueprintDimensions: application.dimensions,
    memberCount: dimensions.length, jobStatus: job.status,
    exactReadback: exact, amount: exact ? rows[0].amount : null,
    applicationsStatus: applicationsResponse.status,
    applicationCount: Array.isArray(applications.applications)
      ? applications.applications.length : -1,
    applicationVisible: Array.isArray(applications.applications) &&
      applications.applications.some(item => item.workspaceId === ws &&
        item.applicationId === app)};
}"""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ProbeError(f"invalid browser probe configuration: {error}") from error
    expected = {"format", "webOrigin", "oidcIssuer", "expectedTitle",
                "expectedMarker"}
    if not isinstance(value, dict) or set(value) != expected \
            or value.get("format") != "openepm-browser-probe-v1" \
            or not isinstance(value.get("expectedTitle"), str) \
            or not value["expectedTitle"] \
            or not isinstance(value.get("expectedMarker"), str) \
            or not value["expectedMarker"]:
        raise ProbeError("browser probe configuration is invalid")
    for field in ("webOrigin", "oidcIssuer"):
        try:
            parsed = urllib.parse.urlsplit(value[field])
            port = parsed.port
        except (TypeError, ValueError) as error:
            raise ProbeError(f"{field} is invalid") from error
        if parsed.scheme != "https" or not parsed.hostname \
                or parsed.username is not None or parsed.password is not None \
                or parsed.fragment or port == 0:
            raise ProbeError(f"{field} must be credential-free HTTPS")
        if field == "webOrigin" and (parsed.path not in ("", "/") or parsed.query):
            raise ProbeError("webOrigin must be an HTTPS origin")
        if field == "oidcIssuer" and (parsed.path.rstrip("/") != "/realms/openepm"
                                      or parsed.query):
            raise ProbeError("oidcIssuer must identify the openepm realm")
    return value


def protected_secret(directory: Path, name: str, maximum: int = 4096) -> str:
    if not directory.is_absolute() or directory.is_symlink() \
            or not directory.is_dir():
        raise ProbeError("browser identity secrets directory is invalid")
    path = directory / name
    if path.is_symlink() or not path.is_file() \
            or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ProbeError(f"{name} must be protected, regular and non-symbolic")
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as error:
        raise ProbeError(f"{name} could not be read") from error
    if not value or len(value.encode()) > maximum or "\x00" in value:
        raise ProbeError(f"{name} is invalid")
    return value


def initial_identity(config: dict, secrets_directory: Path) -> tuple[str, str]:
    try:
        bootstrap = json.loads(protected_secret(
            secrets_directory, "keycloak_bootstrap_config.json", 16384))
    except json.JSONDecodeError as error:
        raise ProbeError("Keycloak bootstrap configuration is invalid") from error
    initial = bootstrap.get("initialAdministrator") \
        if isinstance(bootstrap, dict) else None
    login = initial.get("username") if isinstance(initial, dict) else None
    if not isinstance(login, str) or not login.startswith(
            "openepm-qualification-") or len(login) > 100:
        raise ProbeError("clean-host initial administrator is not run-owned")
    if bootstrap.get("webOrigin") != config["webOrigin"]:
        raise ProbeError("Keycloak bootstrap web origin differs from browser probe")
    return login, protected_secret(
        secrets_directory, "keycloak_initial_admin_password")


def unauthenticated(origin: str) -> dict:
    opener = urllib.request.build_opener(NoRedirect)
    request = urllib.request.Request(origin, method="GET")
    try:
        with opener.open(request, timeout=30) as response:
            return {"status": response.status, "redirectUrl": None}
    except urllib.error.HTTPError as error:
        location = error.headers.get("Location")
        return {"status": error.code, "redirectUrl": location}
    except OSError as error:
        raise ProbeError("unauthenticated browser endpoint request failed") from error


def authenticated_entry(page, origin: str):
    """Prove the browser gateway serves the application with the new session.

    The earlier Keycloak navigation response is not application evidence: it
    can be 200 even when the post-login browser route is unavailable.  Issue a
    fresh same-context navigation after the required action and bind the result
    to the configured application origin.
    """
    response = page.goto(origin, wait_until="networkidle", timeout=60000)
    actual = urllib.parse.urlsplit(page.url)
    expected = urllib.parse.urlsplit(origin)
    if response is None or response.status != 200:
        raise ProbeError("authenticated application page did not return 200")
    if (actual.scheme, actual.hostname, actual.port) != (
            expected.scheme, expected.hostname, expected.port):
        raise ProbeError("authenticated application navigation left configured origin")
    page.locator("#main-content").wait_for(timeout=60000)
    return response


def run(config: dict, secrets_directory: Path, *, playwright_factory=None) -> dict:
    if playwright_factory is None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as error:
            raise ProbeError("Playwright Python is unavailable on the qualification host") \
                from error
        playwright_factory = sync_playwright
    unauth = unauthenticated(config["webOrigin"])
    console_errors = []
    try:
        login, temporary_password = initial_identity(config, secrets_directory)
        replacement_password = "Qr!" + secrets.token_urlsafe(24) + "8y"
        with playwright_factory() as playwright:
            browser = playwright.chromium.launch(channel="chrome", headless=True)
            try:
                browser_version = browser.version
                context = browser.new_context()
                page = context.new_page()
                page.on("console", lambda message: console_errors.append(message.text)
                        if message.type == "error" else None)
                page.on("pageerror", lambda error: console_errors.append(str(error)))
                response = page.goto(config["webOrigin"],
                                     wait_until="domcontentloaded", timeout=60000)
                issuer_host = urllib.parse.urlsplit(config["oidcIssuer"]).hostname
                if urllib.parse.urlsplit(page.url).hostname != issuer_host:
                    raise ProbeError("native Keycloak login form was not reached")
                page.locator("#username").fill(login)
                page.locator("#password").fill(temporary_password)
                page.locator("#kc-login").click()
                page.locator("#password-new").wait_for(timeout=60000)
                page.locator("#password-new").fill(replacement_password)
                page.locator("#password-confirm").fill(replacement_password)
                page.locator(
                    '#kc-passwd-update-form input[type="submit"],'
                    '#kc-passwd-update-form button[type="submit"]'
                ).click()
                if "/login-actions/required-action" in page.url:
                    raise ProbeError("mandatory first-password replacement did not complete")
                response = authenticated_entry(page, config["webOrigin"])
                cookies = context.cookies()
                opaque_cookie = any(cookie.get("name") == "__Host-openepm_session"
                                    and cookie.get("httpOnly") is True
                                    and cookie.get("secure") is True
                                    for cookie in cookies)
                if not opaque_cookie:
                    raise ProbeError("opaque browser session cookie is missing")
                token_storage_empty = page.evaluate(
                    "() => localStorage.length === 0 && sessionStorage.length === 0")
                if token_storage_empty is not True:
                    raise ProbeError("browser token storage is not empty")
                page_title = page.title()
                marker = page.locator("h1").first.text_content() or ""
                bundle_loaded = page.locator(
                    'script[type="module"][src^="/ui/assets/"]').count() >= 1
                workflow = page.evaluate(WORKFLOW_JS, secrets.token_hex(8))
                if (not isinstance(workflow, dict)
                        or workflow.get("workspaceCreated") is not True
                        or workflow.get("applicationCreated") is not True
                        or workflow.get("blueprintDimensions") != [
                            "Account", "Entity", "Year", "Period", "View", "Value"]
                        or workflow.get("memberCount") != 6
                        or workflow.get("jobStatus") != "published"
                        or workflow.get("exactReadback") is not True
                        or workflow.get("amount") != "17.25000000"
                        or workflow.get("applicationsStatus") != 200
                        or not isinstance(workflow.get("applicationCount"), int)
                        or workflow["applicationCount"] < 1
                        or workflow.get("applicationVisible") is not True):
                    raise ProbeError("same-context end-to-end workflow is incomplete")
                authenticated = {"pageUrl": page.url, "pageTitle": page_title,
                    "markerObserved": marker,
                    "presentationBundleLoaded": bundle_loaded,
                    "applicationsStatus": workflow["applicationsStatus"],
                    "applicationCount": workflow["applicationCount"],
                    "workspaceCreated": True, "applicationCreated": True,
                    "metadataMemberCount": 6, "authorizedWrite": True,
                    "exactReadback": True, "readbackAmount": "17.25000000",
                    "sameContext": True,
                    "consoleErrorCount": len(console_errors),
                    "nativeLogin": True, "firstPasswordReplacement": True,
                    "opaqueSessionCookie": True, "browserTokenStorage": False}
            finally:
                browser.close()
    except ProbeError:
        raise
    except Exception as error:
        raise ProbeError("Playwright Chromium browser probe failed") from error
    return {"format": "openepm-browser-probe-result-v1",
        "engine": "Playwright", "browser": "Google Chrome",
        "browserVersion": browser_version, "headless": True,
        "unauthenticated": unauth, "authenticated": authenticated,
        "runOwnedInitialAdministrator": True,
        "qualificationCleanupRequired": True,
        "secretArtifactsWritten": False}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--identity-secrets-directory", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        result = run(load(arguments.config.resolve()),
                     arguments.identity_secrets_directory.absolute())
    except ProbeError as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
