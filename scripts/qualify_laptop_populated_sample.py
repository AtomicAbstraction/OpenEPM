#!/usr/bin/env python3
"""Qualify one rich disposable sample through the public laptop browser API."""
from __future__ import annotations

import argparse
import asyncio
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import secrets
import sys
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from playwright.async_api import async_playwright

from scripts.programmable_uat_sample_contract import (
    build_substantial_application_rule, validate_sample_manifest)
from scripts.provision_programmable_uat_sample_contents import apply_sample
from scripts.qualify_active_browser_session_lifecycle import (
    DEFAULT_STATE, LifecycleError)
from scripts.qualify_laptop_application_journey import (
    OWNER_APPLICATIONS, OWNER_WORKSPACE, cleanup_workspace, owner_fingerprint,
    workspace_exists)
from scripts.qualify_public_native_keycloak_lifecycle import (
    APP_ORIGIN, IDENTITY_ORIGIN, directory_program,
    governed_directory_effect, public_preflight)


MANIFEST = ROOT / "deploy/macos-pilot/programmable-sample-contents.json"

_BROWSER_CALL = r"""async ({path, body}) => {
  const response = await fetch(path, {
    method: 'POST', credentials: 'same-origin', cache: 'no-store',
    headers: {'Accept': 'application/json', 'Content-Type': 'application/json'},
    body: JSON.stringify(body)
  });
  let value = null;
  try { value = await response.json(); } catch (_) {}
  if (!response.ok) {
    const code = value && (value.code || value.error);
    throw new Error(`BROWSER_API_${response.status}_${code || 'UNKNOWN'}`);
  }
  return value;
}"""


def browser_request(tool: str, arguments: dict) -> tuple[str, dict]:
    """Translate the shared MCP call shape to the authoritative browser route."""
    if not isinstance(arguments, dict):
        raise LifecycleError("LAPTOP_SAMPLE_ARGUMENTS_INVALID")
    try:
        workspace_id = arguments["workspace_id"]
        application_id = arguments["application_id"]
    except KeyError as error:
        raise LifecycleError("LAPTOP_SAMPLE_SCOPE_INVALID") from error
    scope = {"workspaceId": workspace_id, "applicationId": application_id}
    if tool == "execute_v2_metadata_program":
        return "/api/metadata-action", {**scope,
            "program": arguments["program"],
            "idempotencyKey": arguments["idempotency_key"],
            "confirmed": True}
    if tool == "execute_v2_expression_rule_program":
        return "/api/rule-action", {**scope,
            "program": arguments["program"],
            "idempotencyKey": arguments["idempotency_key"],
            "confirmed": True}
    if tool == "execute_v2_execution_delegation":
        return "/api/execution-delegation", {**scope,
            "program": arguments["program"],
            "idempotencyKey": arguments["idempotency_key"],
            "confirmed": True}
    if tool == "execute_v2_application_schedule":
        return "/api/application-schedule", {**scope,
            "program": arguments["program"],
            "idempotencyKey": arguments["idempotency_key"],
            "confirmed": True}
    if tool == "preview_v2_program":
        return "/api/preview", {**scope, "program": arguments["program"]}
    if tool == "submit_v2_program":
        return "/api/submit", {**scope, "program": arguments["program"],
            "idempotencyKey": arguments["idempotency_key"],
            "dependsOnJobIds": arguments.get("depends_on_job_ids", []),
            "previewToken": arguments["preview_token"], "confirmed": True}
    if tool == "read_v2_job":
        return "/api/job", {**scope, "jobId": arguments["job_id"]}
    if tool == "read_v2_program":
        return "/api/read", {**scope, "program": arguments["program"]}
    raise LifecycleError("LAPTOP_SAMPLE_TOOL_UNSUPPORTED")


async def post(page, path: str, body: dict) -> dict:
    value = await page.evaluate(_BROWSER_CALL, {"path": path, "body": body})
    if not isinstance(value, dict):
        raise LifecycleError("LAPTOP_SAMPLE_RESPONSE_INVALID")
    return value


async def qualify_draft_lifecycle(context, page, application_name: str,
                                  run_id: str) -> dict:
    """Prove one real editor draft survives blocking availability states."""
    draft_id = "Draft-" + run_id
    draft_name = "Unpublished draft " + run_id
    await page.reload(wait_until="domcontentloaded", timeout=60_000)
    await page.locator("#main-content").wait_for(timeout=60_000)
    await page.get_by_role("button", name="Applications", exact=True).click()
    await page.get_by_role(
        "button", name="Open " + application_name, exact=True).click()
    await page.get_by_role("button", name="Metadata", exact=True).click()
    dimension_id = page.get_by_role(
        "textbox", name="Dimension stable ID", exact=True)
    dimension_name = page.get_by_role(
        "textbox", name="Dimension name", exact=True)
    await dimension_id.wait_for(timeout=60_000)
    await dimension_id.fill(draft_id)
    await dimension_name.fill(draft_name)
    storage = await page.evaluate("""() => ({
      local: {...localStorage}, session: {...sessionStorage}
    })""")
    if (draft_id in json.dumps(storage, sort_keys=True)
            or storage.get("session") != {}):
        raise LifecycleError("LAPTOP_DRAFT_BROWSER_STORAGE_INVALID")

    await context.set_offline(True)
    await page.get_by_text("You are offline", exact=True).wait_for(
        timeout=15_000)
    await context.set_offline(False)
    await page.evaluate("window.dispatchEvent(new Event('online'))")
    await dimension_id.wait_for(timeout=30_000)
    if await dimension_id.input_value() != draft_id:
        raise LifecycleError("LAPTOP_DRAFT_OFFLINE_LOST")

    async def unavailable(route):
        await route.fulfill(status=503, content_type="application/json",
                            body='{"code":"SERVICE_UNAVAILABLE"}')

    await page.route("**/api/session-identity", unavailable)
    await page.evaluate(
        "document.dispatchEvent(new Event('visibilitychange'))")
    await page.get_by_text(
        "Open EPM is temporarily unavailable", exact=True).wait_for(
            timeout=15_000)
    await page.unroute("**/api/session-identity", unavailable)
    await page.evaluate(
        "document.dispatchEvent(new Event('visibilitychange'))")
    await dimension_id.wait_for(timeout=30_000)
    if await dimension_id.input_value() != draft_id:
        raise LifecycleError("LAPTOP_DRAFT_UNAVAILABLE_LOST")

    logout = await page.evaluate("""async () => {
      const response = await fetch('/oidc/sign_out', {
        credentials: 'same-origin', redirect: 'manual'
      });
      return {status: response.status, type: response.type};
    }""")
    if (logout["status"] not in (0, 302, 303)
            and logout["type"] != "opaqueredirect"):
        raise LifecycleError("LAPTOP_DRAFT_LOGOUT_FAILED")
    await page.evaluate(
        "document.dispatchEvent(new Event('visibilitychange'))")
    await page.get_by_text("Your session has timed out", exact=True).wait_for(
        timeout=15_000)
    pending = page.get_by_role("list", name="Unpublished browser work")
    await pending.get_by_text(
        "Unsaved dimension or member creation", exact=True).wait_for(
            timeout=15_000)
    await page.get_by_role(
        "button", name="Discard drafts and sign in", exact=True).click()
    await page.wait_for_timeout(2_000)
    host = urlsplit(page.url).hostname
    if host == "app.openepm.dev":
        await page.locator("#main-content").wait_for(timeout=30_000)
        await page.get_by_role("button", name="Metadata", exact=True).click()
        fresh = page.get_by_role(
            "textbox", name="Dimension stable ID", exact=True)
        await fresh.wait_for(timeout=30_000)
        if await fresh.input_value():
            raise LifecycleError("LAPTOP_DRAFT_EXPLICIT_DISCARD_FAILED")
    elif host != "identity.openepm.dev":
        raise LifecycleError("LAPTOP_DRAFT_REAUTH_DESTINATION_INVALID")
    return {"offlineBlocked": True, "offlineDraftRestored": True,
            "unavailableBlocked": True,
            "unavailableDraftRestored": True,
            "expiryDraftDecisionRequired": True,
            "draftPersistedInBrowserStorage": False}


async def qualify_due_schedule(page, application: dict,
                               workspace_id: str, application_id: str,
                               subject: str) -> dict:
    """Publish one due generic schedule and observe its worker task terminal."""
    scope = {"workspaceId": workspace_id, "applicationId": application_id}
    state = (await post(page, "/api/read", {**scope, "program": {
        "languageVersion": 2, "function": "application.state.read",
        "arguments": {}}}))["result"]
    schedule_id = application_id + ".live-worker"
    delegation_id = application_id + ".live-worker-authority"
    now = datetime.now(timezone.utc)
    full_definition, bindings = build_substantial_application_rule(application)
    scheduled_rule_id = application_id + ".live-worker-rule"
    scheduled_unit = deepcopy(full_definition["units"][-1])
    scheduled_unit["operations"][0]["arguments"]["resultKey"] = (
        application_id + ".live-worker.result")
    scheduled_definition = {"format": full_definition["format"],
        "name": application["name"] + " live worker rule",
        "parameters": full_definition["parameters"],
        "units": [scheduled_unit]}
    scheduled_saved = (await post(page, "/api/rule-action", {**scope,
        "program": {"languageVersion": 2,
            "function": "application.rule.save", "arguments": {
                "ruleId": scheduled_rule_id,
                "definition": scheduled_definition,
                "expectedMetadataRevision": state["metadataRevision"],
                "expectedPolicyRevision": state["policyRevision"]}},
        "idempotencyKey": "live-schedule-rule-save-" + application_id,
        "confirmed": True}))["result"]
    scheduled_activation = (await post(page, "/api/rule-action", {**scope,
        "program": {"languageVersion": 2,
            "function": "application.rule.activate", "arguments": {
                "ruleId": scheduled_rule_id,
                "expectedStateToken": scheduled_saved["stateToken"],
                "expectedMetadataRevision": state["metadataRevision"],
                "expectedPolicyRevision": state["policyRevision"]}},
        "idempotencyKey": "live-schedule-rule-publish-" + application_id,
        "confirmed": True}))["result"]
    state = (await post(page, "/api/read", {**scope, "program": {
        "languageVersion": 2, "function": "application.state.read",
        "arguments": {}}}))["result"]
    delegation = (await post(page, "/api/execution-delegation", {**scope,
        "program": {"languageVersion": 2,
            "function": "execution.delegation.create", "arguments": {
                "delegationId": delegation_id,
                "issuer": IDENTITY_ORIGIN + "/realms/openepm",
                "subjectId": subject,
                "operationScope": ["application.rule.run"],
                "validFrom": (now - timedelta(minutes=2)).isoformat(),
                "validUntil": (now + timedelta(hours=2)).isoformat(),
                "scheduleId": schedule_id,
                "expectedMetadataRevision": state["metadataRevision"],
                "expectedPolicyRevision": state["policyRevision"],
                "expectedSchemaEpoch": state["schemaEpoch"]}},
        "idempotencyKey": "live-schedule-delegation-" + application_id,
        "confirmed": True}))["result"]
    definition = {"format": "openepm-application-schedule-v1",
        "scheduleId": schedule_id,
        "target": {"kind": "ApplicationRule", "ruleId": scheduled_rule_id,
            "stateToken": scheduled_activation["stateToken"],
            "activatedRevision": scheduled_activation["activatedRevision"],
            "programDigest": scheduled_activation["programDigest"]},
        "bindings": bindings, "pov": [],
        "recurrence": {"kind": "FixedInterval", "intervalSeconds": 86400,
            "firstDueAt": (now - timedelta(minutes=1)).replace(
                second=0, microsecond=0).isoformat().replace("+00:00", "Z"),
            "catchUpPolicy": "latest", "maxCatchUp": 1},
        "retryPolicy": {"maxAttempts": 3, "backoffSeconds": 1,
            "needsInspectionAfter": True},
        "cancellationPolicy": "PreserveCommittedStopFuture",
        "delegation": {"delegationId": delegation_id,
            "stateToken": delegation["stateToken"]}}
    saved = (await post(page, "/api/application-schedule", {**scope,
        "program": {"languageVersion": 2, "function": "schedule.save",
            "arguments": {"definition": definition,
                "expectedMetadataRevision": state["metadataRevision"],
                "expectedPolicyRevision": delegation["policyRevision"],
                "expectedSchemaEpoch": state["schemaEpoch"]}},
        "idempotencyKey": "live-schedule-save-" + application_id,
        "confirmed": True}))["result"]
    saved_read = (await post(page, "/api/application-schedule", {**scope,
        "program": {"languageVersion": 2,
            "function": "schedule.read", "arguments": {
                "scheduleId": schedule_id}}}))["result"]
    saved_schedule = saved_read.get("schedule")
    if (not isinstance(saved_schedule, dict)
            or saved_schedule.get("status") != "Saved"
            or not isinstance(saved_schedule.get("stateToken"), str)):
        raise LifecycleError("LAPTOP_SCHEDULE_SAVE_READBACK_INVALID")
    published = (await post(page, "/api/application-schedule", {**scope,
        "program": {"languageVersion": 2,
            "function": "schedule.activate", "arguments": {
                "scheduleId": schedule_id,
                "expectedStateToken": saved_schedule["stateToken"],
                "expectedMetadataRevision": state["metadataRevision"],
                "expectedPolicyRevision": saved["policyRevision"],
                "expectedSchemaEpoch": state["schemaEpoch"]}},
        "idempotencyKey": "live-schedule-publish-" + application_id,
        "confirmed": True}))["result"]
    terminal = None
    for _ in range(240):
        tasks = await post(page, "/api/tasks", {**scope, "afterSequence": 0,
            "limit": 100, "attentionOnly": False})
        candidates = [item for item in tasks.get("tasks", [])
            if item.get("sourceFamily") == "ApplicationScheduleOccurrence"]
        if candidates and candidates[0].get("status") in (
                "Succeeded", "PartiallySucceeded", "Failed",
                "NeedsInspection", "Interrupted"):
            terminal = candidates[0]
            break
        await page.wait_for_timeout(500)
    if terminal is None:
        raise LifecycleError("LAPTOP_SCHEDULE_WORKER_TIMEOUT")
    if terminal.get("status") != "Succeeded":
        raise LifecycleError("LAPTOP_SCHEDULE_WORKER_" +
                             str(terminal.get("status")).upper())
    task = await post(page, "/api/task", {**scope,
        "taskId": terminal["taskId"], "afterEvent": 0, "eventLimit": 100})
    events = task.get("task", task).get("events", [])
    statuses = [item.get("status") for item in events]
    if not statuses or statuses[-1] != "Succeeded":
        raise LifecycleError("LAPTOP_SCHEDULE_TASK_HISTORY_INVALID")
    return {"scheduleId": schedule_id, "status": published.get("status"),
            "workerTaskId": terminal["taskId"],
            "workerTerminalStatus": terminal["status"],
            "workerLifecycleStatuses": statuses}


async def run_browser(login_id: str, temporary_password: str,
                      replacement_password: str, run_id: str,
                      application: dict, subject: str) -> dict:
    workspace_id = "uat-w-" + run_id
    application_id = "uat-a-" + run_id
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        try:
            context = await browser.new_context()
            page = await context.new_page()
            await page.goto(APP_ORIGIN + "/", wait_until="domcontentloaded",
                            timeout=60_000)
            if urlsplit(page.url).hostname != "identity.openepm.dev":
                raise LifecycleError("LAPTOP_SAMPLE_NATIVE_LOGIN_NOT_REACHED")
            await page.locator("#username").fill(login_id)
            await page.locator("#password").fill(temporary_password)
            await page.locator("#kc-login").click()
            await page.locator("#password-new").wait_for(timeout=60_000)
            await page.locator("#password-new").fill(replacement_password)
            await page.locator("#password-confirm").fill(replacement_password)
            await page.locator(
                '#kc-passwd-update-form input[type="submit"],'
                '#kc-passwd-update-form button[type="submit"]'
            ).click()
            await page.locator("#main-content").wait_for(timeout=60_000)
            storage = await page.evaluate("""() => ({
              local: Object.keys(localStorage),
              session: Object.keys(sessionStorage)
            })""")
            if storage != {"local": [], "session": []}:
                raise LifecycleError("LAPTOP_SAMPLE_BROWSER_TOKEN_STORAGE_PRESENT")
            await post(page, "/api/platform/browser/write", {
                "program": {"languageVersion": 2,
                    "function": "platform.workspace.create",
                    "arguments": {"workspaceId": workspace_id,
                                  "name": "Populated qualification " + run_id}},
                "idempotencyKey": "populated-workspace-" + run_id,
                "confirmed": True})
            created = await post(page, "/api/workspace-application", {
                "workspaceId": workspace_id, "confirmed": True,
                "idempotencyKey": "populated-application-" + run_id,
                "program": {"languageVersion": 2,
                    "function": "workspace.application.create",
                    "arguments": {"applicationId": application_id,
                                  "name": "Populated qualification " + run_id,
                                  "kind": "multidimensional"}}})
            if created.get("applicationId") != application_id:
                raise LifecycleError("LAPTOP_SAMPLE_APPLICATION_CREATE_INVALID")

            disposable = {**application, "applicationId": application_id,
                          "name": "Populated qualification " + run_id}

            async def call(tool: str, arguments: dict) -> dict:
                path, body = browser_request(tool, arguments)
                return await post(page, path, body)

            result = await apply_sample(disposable, workspace_id, call)
            receipt = await call("read_v2_program", {
                "workspace_id": workspace_id, "application_id": application_id,
                "program": {"languageVersion": 2,
                    "function": "application.operation.receipt.read",
                    "arguments": {"operationId":
                        result["ruleActivation"]["operationId"]}}})
            tasks = await post(page, "/api/tasks", {
                "workspaceId": workspace_id, "applicationId": application_id,
                "afterSequence": 0, "limit": 100, "attentionOnly": False})
            catalogue_response = await page.request.get(
                APP_ORIGIN + "/api/applications?limit=100")
            catalogue = await catalogue_response.json()
            visible = any(item.get("workspaceId") == workspace_id and
                          item.get("applicationId") == application_id
                          for item in catalogue.get("applications", []))
            if (result.get("metadataOperationCount", 0) < 20
                    or result.get("memberListResultCount") != 2
                    or result.get("calculatedResultCount") != 2
                    or result.get("rulePrimitiveCount") != 14
                    or result.get("workflowStatus") != "published"
                    or not result.get("exactReplayChecked")
                    or not isinstance(receipt.get("result"), dict)
                    or not isinstance(tasks.get("tasks"), list)
                    or not visible):
                raise LifecycleError("LAPTOP_SAMPLE_RESULT_INCOMPLETE")
            schedule_worker = await qualify_due_schedule(
                page, disposable, workspace_id, application_id,
                subject)
            draft_lifecycle = await qualify_draft_lifecycle(
                context, page, disposable["name"], run_id)
            await context.close()
            return {"browserVersion": browser.version, "sample": result,
                    "receiptVisible": True, "taskCount": len(tasks["tasks"]),
                    "applicationVisible": True,
                    "scheduleWorker": schedule_worker,
                    "draftLifecycle": draft_lifecycle}
        finally:
            await browser.close()


def qualify(state_root: Path) -> dict:
    preflight = public_preflight()
    before = owner_fingerprint()
    manifest_raw = MANIFEST.read_bytes()
    manifest = validate_sample_manifest(json.loads(manifest_raw))
    application = manifest["applications"][0]
    run_id = secrets.token_hex(8)
    workspace_id, application_id = "uat-w-" + run_id, "uat-a-" + run_id
    login_id = "openepm-qualification-" + run_id
    temporary_password = "Qa!" + secrets.token_urlsafe(24) + "8v"
    replacement_password = "Pe!" + secrets.token_urlsafe(24) + "3m"
    subject = None
    authority_granted = False
    workflow = None
    cleanup = None
    primary_error: BaseException | None = None
    try:
        created = governed_directory_effect(state_root, directory_program(
            "identity.native-user.create", username=login_id,
            displayName="Open EPM populated laptop qualification",
            shortDescription="Run-owned rich sample qualification",
            semanticDescription=("Disposable identity for public-browser "
                                 "sample application qualification.")),
            idempotency_key="populated-user-create-" + run_id)
        subject = created.get("subjectId")
        if not isinstance(subject, str) or not subject:
            raise LifecycleError("LAPTOP_SAMPLE_SUBJECT_INVALID")
        governed_directory_effect(state_root, directory_program(
            "identity.native-user.password.set", subjectId=subject,
            temporaryPassword=temporary_password),
            idempotency_key="populated-user-password-" + run_id)
        governed_directory_effect(state_root, directory_program(
            "identity.server-administrator.access.set", subjectId=subject,
            access="Grant"), idempotency_key="populated-admin-grant-" + run_id)
        authority_granted = True
        workflow = asyncio.run(run_browser(
            login_id, temporary_password, replacement_password, run_id,
            application, subject))
        time.sleep(1.05)
        cleanup = cleanup_workspace(
            state_root, workspace_id, application_id,
            IDENTITY_ORIGIN + "/realms/openepm", subject,
            int(time.time()), "populated-" + run_id)
    except BaseException as error:
        primary_error = error
    finally:
        if subject is not None:
            if cleanup is None and workspace_exists(workspace_id):
                try:
                    time.sleep(1.05)
                    cleanup = cleanup_workspace(
                        state_root, workspace_id, application_id,
                        IDENTITY_ORIGIN + "/realms/openepm", subject,
                        int(time.time()), "populated-" + run_id)
                except BaseException as error:
                    if primary_error is None:
                        primary_error = error
            if authority_granted:
                try:
                    governed_directory_effect(state_root, directory_program(
                        "identity.server-administrator.access.set",
                        subjectId=subject, access="Revoke"),
                        idempotency_key="populated-admin-revoke-" + run_id)
                except BaseException as error:
                    if primary_error is None:
                        primary_error = error
            try:
                governed_directory_effect(state_root, directory_program(
                    "identity.native-user.status.set", subjectId=subject,
                    status="Inactive"),
                    idempotency_key="populated-user-deactivate-" + run_id)
            except BaseException as error:
                if primary_error is None:
                    primary_error = error
    after = owner_fingerprint()
    if before != after:
        raise LifecycleError("OWNER_WORKSPACE_FINGERPRINT_CHANGED")
    if primary_error is not None:
        raise primary_error
    if workflow is None or cleanup is None or workspace_exists(workspace_id):
        raise LifecycleError("LAPTOP_SAMPLE_QUALIFICATION_INCOMPLETE")
    return {"format": "openepm-laptop-populated-sample-v1",
        "qualifiedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "preflight": preflight, "publicCloudflareJourney": True,
        "manifestSha256": sha256(manifest_raw).hexdigest(),
        "sampleContractApplication": application["applicationId"],
        "browserVersion": workflow["browserVersion"],
        "sample": workflow["sample"],
        "receiptVisible": workflow["receiptVisible"],
        "taskCount": workflow["taskCount"],
        "applicationVisible": workflow["applicationVisible"],
        "scheduleWorker": workflow["scheduleWorker"],
        "draftLifecycle": workflow["draftLifecycle"],
        "cleanup": cleanup, "ownerWorkspaceBefore": before,
        "ownerWorkspaceAfter": after, "ownerWorkspaceUnchanged": True,
        "temporaryServerAdministratorRevoked": True,
        "runOwnedIdentityDeactivated": True,
        "credentialPrinted": False, "credentialPersisted": False,
        "ownerWorkspaceId": OWNER_WORKSPACE,
        "ownerApplications": list(OWNER_APPLICATIONS)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.output.exists() or not arguments.output.is_absolute():
        parser.error("output must be a new absolute path")
    result = qualify(arguments.state_root.resolve())
    arguments.output.write_text(json.dumps(result, indent=2, sort_keys=True)
                                + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "output": str(arguments.output)},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
