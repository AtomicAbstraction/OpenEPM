#!/usr/bin/env python3
"""Qualify the installed AIcompanies Python Programs UI read-only.

The runner owns a disposable native identity and a fresh Playwright Chromium
context.  It never attaches to Chrome.  A signed, audited application grant is
created only for this journey, then revoked before the identity is deactivated.
The rule source is read before and after the UI journey to prove it did not
change.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import secrets
import sys
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from playwright.sync_api import Locator, sync_playwright

from scripts.qualify_active_browser_session_lifecycle import (
    DEFAULT_STATE, LifecycleError, storage_is_empty)
from scripts.qualify_public_native_keycloak_lifecycle import (
    APP_ORIGIN, IDENTITY_ORIGIN, directory_program,
    governed_directory_effect, public_preflight)


WORKSPACE_ID = "ws-pilot"
APPLICATION_ID = "AIcompanies"
PROGRAM_ID = "source-rule-aic.apportion.policy"
PROGRAM_NAME = "AIC Apportion Policy"

READ_PROGRAM = r"""async ({workspaceId, applicationId, programId}) => {
  const response = await fetch('/api/python-program', {
    method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
    body: JSON.stringify({workspaceId, applicationId, program: {
      languageVersion: 2, function: 'python.program.read',
      arguments: {programId}}})});
  const value = await response.json();
  if (!response.ok) throw new Error(`RULES_UI_ORACLE_${response.status}_${
    value && (value.code || value.error) || 'UNKNOWN'}`);
  return value;
}"""

ADMITTED_EFFECT = r"""async ({path, body}) => {
  const admissionResponse = await fetch('/api/operation-admission', {
    method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
    body: JSON.stringify({workspaceId: body.workspaceId,
      applicationId: body.applicationId, program: body.program})});
  let admission = null;
  try { admission = await admissionResponse.json(); } catch (_) {}
  if (!admissionResponse.ok) throw new Error(
    `RULES_UI_ADMISSION_${admissionResponse.status}_${
      admission && (admission.code || admission.error) || 'UNKNOWN'}`);
  if (!admission || typeof admission.operationId !== 'string' ||
      !admission.operationId.startsWith('oa1_')) {
    throw new Error('RULES_UI_ADMISSION_INVALID');
  }
  const response = await fetch(path, {
    method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
    body: JSON.stringify({...body, idempotencyKey: admission.operationId})});
  let value = null;
  try { value = await response.json(); } catch (_) {}
  if (!response.ok) throw new Error(`RULES_UI_EFFECT_${response.status}_${
    value && (value.code || value.error) || 'UNKNOWN'}`);
  return value;
}"""

READ_PROGRAM_DENIAL = r"""async ({workspaceId, applicationId, programId}) => {
  const response = await fetch('/api/python-program', {
    method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
    body: JSON.stringify({workspaceId, applicationId, program: {
      languageVersion: 2, function: 'python.program.read',
      arguments: {programId}}})});
  let value = null;
  try { value = await response.json(); } catch (_) {}
  return {ok: response.ok, status: response.status,
    code: value && (value.code || value.error) || null};
}"""


def application_access_program(subject: str, action: str) -> dict:
    return {
        "languageVersion": 2,
        "function": "security.application.access.set",
        "arguments": {
            "subjectId": subject,
            "action": action,
            "role": "Administrator" if action == "grant" else None,
        },
    }


def program_snapshot(value: dict) -> str:
    """Hash the complete authorized read, excluding no fields or failures."""
    return sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def rendered_source(editor: Locator) -> str:
    return editor.evaluate(r"""element => {
      const monaco = element.closest('.monaco-editor');
      if (!monaco) return element.value;
      return Array.from(monaco.querySelectorAll('.view-line'))
        .map(line => line.textContent || '').join('\n')
        .replaceAll('\u00a0', ' ');
    }""")


def visible_source_matches(visible: str, source: str) -> bool:
    """Find Monaco's substantial virtualized viewport in the full read."""
    visible_tokens = re.sub(r"\s+", "", visible)
    source_tokens = re.sub(r"\s+", "", source)
    return len(visible_tokens) >= 80 and visible_tokens in source_tokens


def wait_for_visible_source(page, editor: Locator, source: str) -> str:
    """Wait for React's external-value effect to reach an existing editor."""
    deadline = time.monotonic() + 60
    visible = ""
    while time.monotonic() < deadline:
        visible = rendered_source(editor)
        if visible_source_matches(visible, source):
            return visible
        page.wait_for_timeout(50)
    raise LifecycleError("RULES_UI_EDITOR_SOURCE_NOT_RENDERED")


def qualify(state_root: Path) -> dict:
    preflight = public_preflight()
    run_id = secrets.token_hex(8)
    username = "openepm-rules-ui-" + run_id
    temporary_password = "Qa!" + secrets.token_urlsafe(24) + "8v"
    replacement_password = "Pe!" + secrets.token_urlsafe(24) + "3m"
    subject = None
    application_access_granted = False
    result = None
    primary_error: BaseException | None = None
    try:
        created = governed_directory_effect(
            state_root,
            directory_program(
                "identity.native-user.create",
                username=username,
                displayName="Open EPM Rules UI qualifier",
                shortDescription="Run-owned installed Rules UI qualification",
                semanticDescription=(
                    "Disposable native identity for read-only installed "
                    "Python Programs presentation qualification.")),
            idempotency_key="rules-ui-user-create-" + run_id)
        subject = created.get("subjectId")
        if not isinstance(subject, str) or not subject:
            raise LifecycleError("RULES_UI_SUBJECT_INVALID")
        governed_directory_effect(
            state_root,
            directory_program(
                "identity.native-user.password.set",
                subjectId=subject, temporaryPassword=temporary_password),
            idempotency_key="rules-ui-user-password-" + run_id)
        print(json.dumps({
            "event": "awaiting-application-grant",
            "subjectId": subject,
            "workspaceId": WORKSPACE_ID,
            "applicationId": APPLICATION_ID,
        }, sort_keys=True), flush=True)
        if sys.stdin.readline().strip() != "application-grant-ready":
            raise LifecycleError("RULES_UI_APPLICATION_GRANT_HANDSHAKE_INVALID")
        application_access_granted = True

        with sync_playwright() as playwright:
            # The managed Chromium binary and fresh context belong only to this
            # run.  Never select a named browser channel or reuse an owner profile.
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context()
            page = context.new_page()
            errors: list[str] = []
            violations: list[dict] = []
            unexpected_requests: list[str] = []
            failed_responses: list[str] = []
            try:
                page.on("pageerror", lambda error: errors.append(str(error)))
                page.on("console", lambda message: errors.append(message.text)
                        if message.type == "error" else None)
                page.on(
                    "response",
                    lambda response: failed_responses.append(
                        f"{response.status}:{urlsplit(response.url).path}")
                    if response.status >= 400 else None)
                page.expose_function(
                    "recordRulesUiCspViolation",
                    lambda value: violations.append(value))
                page.add_init_script("""document.addEventListener(
                  'securitypolicyviolation', event =>
                    window.recordRulesUiCspViolation({
                      directive: event.violatedDirective,
                      blocked: event.blockedURI}));""")
                page.goto(APP_ORIGIN + "/", wait_until="domcontentloaded",
                          timeout=60_000)
                if urlsplit(page.url).hostname != "identity.openepm.dev":
                    raise LifecycleError("RULES_UI_NATIVE_LOGIN_NOT_REACHED")
                page.locator("#username").fill(username)
                page.locator("#password").fill(temporary_password)
                page.locator("#kc-login").click()
                page.locator("#password-new").wait_for(timeout=60_000)
                page.locator("#password-new").fill(replacement_password)
                page.locator("#password-confirm").fill(replacement_password)
                page.locator(
                    '#kc-passwd-update-form input[type="submit"],'
                    '#kc-passwd-update-form button[type="submit"]'
                ).click()
                page.locator("#main-content").wait_for(timeout=60_000)
                if not storage_is_empty(page):
                    raise LifecycleError("RULES_UI_BROWSER_TOKEN_STORAGE_PRESENT")
                identity_errors = list(errors)
                identity_violations = list(violations)
                errors.clear()
                violations.clear()
                failed_responses.clear()

                allowed_origins = (APP_ORIGIN + "/", IDENTITY_ORIGIN + "/")
                page.on(
                    "request",
                    lambda request: unexpected_requests.append(request.url)
                    if not request.url.startswith(allowed_origins) else None)
                route = (
                    f"{APP_ORIGIN}/#/rules/0?workspace={WORKSPACE_ID}"
                    f"&application={APPLICATION_ID}&section=python")
                page.goto(route, wait_until="domcontentloaded", timeout=60_000)
                page.wait_for_function("""() =>
                  Array.from(document.querySelectorAll('h1,h2,h3')).some(
                    item => item.textContent?.trim() === 'Python programs') ||
                  document.body.innerText.includes('Application unavailable') ||
                  document.body.innerText.includes('Access unavailable')
                """, timeout=60_000)
                heading = page.get_by_role(
                    "heading", name="Python programs", exact=True)
                if heading.count() != 1:
                    visible_headings = page.locator("h1,h2,h3").all_inner_texts()
                    safe = "_".join(visible_headings[:8])
                    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", safe)[:240]
                    raise LifecycleError(
                        "RULES_UI_ROUTE_UNAVAILABLE:" + (safe or "NO_HEADING"))
                page.get_by_text(PROGRAM_NAME, exact=True).wait_for(
                    timeout=60_000)

                oracle_response = page.evaluate(
                    READ_PROGRAM,
                    {"workspaceId": WORKSPACE_ID,
                     "applicationId": APPLICATION_ID,
                     "programId": PROGRAM_ID})
                oracle = (oracle_response.get("result")
                          if isinstance(oracle_response, dict) else None)
                if (not isinstance(oracle, dict)
                        or oracle.get("programId") != PROGRAM_ID
                        or not isinstance(oracle.get("sourceText"), str)
                        or not oracle["sourceText"]):
                    raise LifecycleError("RULES_UI_ORACLE_INVALID")
                before_program = program_snapshot(oracle)

                row = page.get_by_role("row").filter(has_text=PROGRAM_NAME)
                if row.count() != 1:
                    raise LifecycleError("RULES_UI_PROGRAM_ROW_INVALID")
                row.get_by_role("button", name="Open", exact=True).click()
                page.get_by_role(
                    "heading", name="Current source", exact=True
                ).wait_for(timeout=60_000)
                viewer = page.get_by_role(
                    "textbox", name="Authorized Python source", exact=True)
                viewer.wait_for(timeout=60_000)
                page.locator(".python-program-detail .monaco-editor").wait_for(
                    timeout=60_000)
                wait_for_visible_source(page, viewer, oracle["sourceText"])

                body = page.locator("body").inner_text()
                hidden_tokens = [
                    oracle.get("stateToken"), oracle.get("sourceToken"),
                    oracle.get("sourceDigest")]
                if any(isinstance(token, str) and token and token in body
                       for token in hidden_tokens):
                    raise LifecycleError("RULES_UI_TECHNICAL_TOKEN_VISIBLE")
                if re.search(r"\b[0-9a-f]{64}\b", body):
                    raise LifecycleError("RULES_UI_BACKEND_DIGEST_VISIBLE")

                page.get_by_role(
                    "button", name="Edit current source", exact=True).click()
                editor = page.get_by_role(
                    "textbox", name="Python program source", exact=True)
                editor.wait_for(timeout=60_000)
                page.locator(".python-authoring .monaco-editor").wait_for(
                    timeout=60_000)
                wait_for_visible_source(page, editor, oracle["sourceText"])
                save = page.get_by_role(
                    "button", name="Save and validate", exact=True)
                if save.is_enabled():
                    raise LifecycleError("RULES_UI_UNCHANGED_SOURCE_DIRTY")
                authoring = page.locator(".python-authoring")
                if not authoring.evaluate(
                        "element => element.contains(document.activeElement)"):
                    raise LifecycleError("RULES_UI_EDIT_FOCUS_MISSING")

                page.locator("summary").filter(
                    has_text="Edit " + PROGRAM_NAME).click()
                page.get_by_role(
                    "button", name="Calculation rules", exact=True).click()
                page.get_by_role(
                    "heading", name="Calculation rules", exact=True
                ).wait_for(timeout=60_000)
                if page.get_by_role("dialog").count():
                    raise LifecycleError("RULES_UI_FALSE_DIRTY_PROMPT")
                if errors:
                    diagnostic = re.sub(
                        r"[^A-Za-z0-9_./: -]+", "_", " | ".join(errors))
                    raise LifecycleError(
                        "RULES_UI_BROWSER_ERROR:" + diagnostic[:800] + ":"
                        + "_".join(failed_responses[:12]))
                if violations:
                    raise LifecycleError("RULES_UI_CSP_VIOLATION")
                if unexpected_requests:
                    raise LifecycleError("RULES_UI_EXTERNAL_REQUEST")
                after_response = page.evaluate(
                    READ_PROGRAM,
                    {"workspaceId": WORKSPACE_ID,
                     "applicationId": APPLICATION_ID,
                     "programId": PROGRAM_ID})
                after_program = (after_response.get("result")
                                 if isinstance(after_response, dict) else None)
                if (not isinstance(after_program, dict)
                        or program_snapshot(after_program) != before_program):
                    raise LifecycleError("RULES_UI_RULE_SOURCE_CHANGED")

                result = {
                    "browser": "Playwright Chromium",
                    "browserVersion": browser.version,
                    "workspaceId": WORKSPACE_ID,
                    "applicationId": APPLICATION_ID,
                    "programId": PROGRAM_ID,
                    "programName": PROGRAM_NAME,
                    "sourceSha256": sha256(
                        oracle["sourceText"].encode()).hexdigest(),
                    "sourceCharacters": len(oracle["sourceText"]),
                    "sourceVisible": True,
                    "visibleSourceMatchesAuthorizedRead": True,
                    "editPopulated": True,
                    "unchangedEditDirty": False,
                    "falseDirtyPrompt": False,
                    "technicalTokensRendered": 0,
                    "browserErrors": 0,
                    "cspViolations": 0,
                    "unexpectedExternalRequests": 0,
                    "identityLoginErrors": len(identity_errors),
                    "identityLoginCspViolations": len(identity_violations),
                    "identityLoginStaticResourceCacheDefectObserved": bool(
                        identity_errors),
                    "ruleSourceChanged": False,
                    "businessCalculationDataTouched": False,
                }
            finally:
                if application_access_granted:
                    try:
                        page.evaluate(ADMITTED_EFFECT, {
                            "path": "/api/security",
                            "body": {
                                "workspaceId": WORKSPACE_ID,
                                "applicationId": APPLICATION_ID,
                                "program": application_access_program(
                                    subject, "revoke"),
                                "confirmed": True,
                            },
                        })
                        application_access_granted = False
                        denial = page.evaluate(
                            READ_PROGRAM_DENIAL,
                            {"workspaceId": WORKSPACE_ID,
                             "applicationId": APPLICATION_ID,
                             "programId": PROGRAM_ID})
                        if (not isinstance(denial, dict)
                                or denial.get("ok") is not False
                                or denial.get("status") not in (403, 404)):
                            raise LifecycleError(
                                "RULES_UI_APPLICATION_ACCESS_REVOKE_UNPROVEN")
                    except BaseException as error:
                        if primary_error is None:
                            primary_error = error
                context.close()
                browser.close()
    except BaseException as error:
        primary_error = error
    finally:
        if subject is not None:
            try:
                governed_directory_effect(
                    state_root,
                    directory_program(
                        "identity.native-user.status.set",
                        subjectId=subject, status="Inactive"),
                    idempotency_key="rules-ui-user-deactivate-" + run_id)
            except BaseException as error:
                if primary_error is None:
                    primary_error = error
    if application_access_granted:
        raise LifecycleError("RULES_UI_APPLICATION_ACCESS_NOT_REVOKED")
    if primary_error is not None:
        raise primary_error
    if result is None:
        raise LifecycleError("RULES_UI_QUALIFICATION_INCOMPLETE")
    return {
        "format": "openepm-laptop-installed-rules-ui-v1",
        "qualifiedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "publicPreflight": preflight,
        **result,
        "governedRunOwnedIdentity": True,
        "temporaryApplicationAdministratorGranted": True,
        "temporaryApplicationAdministratorRevoked": True,
        "runOwnedIdentityDeactivated": True,
        "sharedApplicationEffects": [
            "temporary Administrator grant",
            "grant revocation",
            "durable security audit evidence",
        ],
        "credentialPrinted": False,
        "credentialPersisted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.output.exists() or not arguments.output.is_absolute():
        parser.error("output must be a new absolute path")
    result = qualify(arguments.state_root.resolve())
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    print(json.dumps({"status": "passed", "format": result["format"],
                      "output": str(arguments.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
