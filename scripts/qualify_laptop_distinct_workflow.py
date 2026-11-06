#!/usr/bin/env python3
"""Qualify a distinct preparer/reviewer workflow through the public laptop UI."""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timedelta, timezone
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

from playwright.async_api import async_playwright

from scripts.qualify_active_browser_session_lifecycle import DEFAULT_STATE, LifecycleError
from scripts.qualify_laptop_application_journey import (
    cleanup_workspace, owner_fingerprint, psql, workspace_exists)
from scripts.qualify_public_native_keycloak_lifecycle import (
    APP_ORIGIN, IDENTITY_ORIGIN, directory_program, governed_directory_effect,
    governed_directory_read, public_preflight)


_CALL = r"""async ({path, body}) => {
  const response = await fetch(path, {method: 'POST', credentials: 'same-origin',
    cache: 'no-store', headers: {'Accept': 'application/json',
    'Content-Type': 'application/json'}, body: JSON.stringify(body)});
  let value = null; try { value = await response.json(); } catch (_) {}
  if (!response.ok) throw new Error(`BROWSER_API_${response.status}_${
    value && (value.code || value.error) || 'UNKNOWN'}`);
  return value;
}"""


async def post(page, path: str, body: dict) -> dict:
    value = await page.evaluate(_CALL, {"path": path, "body": body})
    if not isinstance(value, dict):
        raise LifecycleError("LAPTOP_WORKFLOW_RESPONSE_INVALID")
    return value


async def login(browser, username: str, temporary: str, replacement: str):
    context = await browser.new_context()
    page = await context.new_page()
    await page.goto(APP_ORIGIN + "/", wait_until="domcontentloaded", timeout=60_000)
    if urlsplit(page.url).hostname != "identity.openepm.dev":
        raise LifecycleError("LAPTOP_WORKFLOW_NATIVE_LOGIN_NOT_REACHED")
    await page.locator("#username").fill(username)
    await page.locator("#password").fill(temporary)
    await page.locator("#kc-login").click()
    await page.locator("#password-new").wait_for(timeout=60_000)
    await page.locator("#password-new").fill(replacement)
    await page.locator("#password-confirm").fill(replacement)
    await page.locator(
        '#kc-passwd-update-form input[type="submit"],'
        '#kc-passwd-update-form button[type="submit"]').click()
    await page.locator("#main-content").wait_for(timeout=60_000)
    storage = await page.evaluate("() => ({local:Object.keys(localStorage), session:Object.keys(sessionStorage)})")
    if storage != {"local": [], "session": []}:
        raise LifecycleError("LAPTOP_WORKFLOW_BROWSER_STORAGE_INVALID")
    return context, page


def program(function: str, arguments: dict) -> dict:
    return {"languageVersion": 2, "function": function, "arguments": arguments}


async def run_browser(preparer: dict, reviewer: dict, run_id: str) -> dict:
    workspace_id, application_id = "uat-w-" + run_id, "uat-a-" + run_id
    scope = {"workspaceId": workspace_id, "applicationId": application_id}
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(channel="chrome", headless=True)
        preparer_context = reviewer_context = None
        try:
            preparer_context, prep = await login(browser, **preparer["login"])
            await post(prep, "/api/platform/browser/write", {
                "program": program("platform.workspace.create", {
                    "workspaceId": workspace_id, "name": "Workflow qualification " + run_id}),
                "idempotencyKey": "workflow-workspace-" + run_id, "confirmed": True})
            await post(prep, "/api/workspace-application", {
                "workspaceId": workspace_id,
                "program": program("workspace.application.create", {
                    "applicationId": application_id,
                    "name": "Workflow qualification " + run_id,
                    "kind": "multidimensional"}),
                "idempotencyKey": "workflow-application-" + run_id, "confirmed": True})
            initial_state = (await post(prep, "/api/read", {**scope,
                "program": program("application.state.read", {})}))["result"]
            initial_metadata = initial_state["metadataRevision"]
            initial_dimensions = (await post(prep, "/api/read", {**scope,
                "program": program("metadata.dimension.list", {
                    "limit": 100, "expectedMetadataRevision":
                        initial_metadata})}))["result"]
            metadata_operations = []
            for dimension in initial_dimensions["rows"]:
                if dimension.get("status") != "Active":
                    continue
                dimension_id = dimension["dimension_id"]
                existing = (await post(prep, "/api/read", {**scope,
                    "program": program("metadata.member.list", {
                        "dimension": dimension_id, "limit": 1,
                        "expectedMetadataRevision": initial_metadata})}))["result"]
                if not any(item.get("status") == "Active"
                           for item in existing["rows"]):
                    metadata_operations.append(("metadata.member.create", {
                        "dimensionId": dimension_id,
                        "memberId": "Qualifier-" + sha256(
                            dimension_id.encode()).hexdigest()[:12],
                        "name": "Qualification member"}))
            metadata_operations.extend((
                ("metadata.dimension.create", {"dimensionId": "Work",
                 "name": "Work", "modelRole": "Custom"}),
                ("metadata.member.create", {"dimensionId": "Work",
                 "memberId": "Work.Item", "name": "Item"})))
            for offset, (function, arguments) in enumerate(metadata_operations):
                await post(prep, "/api/metadata-action", {**scope,
                    "program": program(function, {**arguments,
                        "expectedMetadataRevision": initial_metadata + offset}),
                    "idempotencyKey": f"workflow-metadata-{run_id}-{offset}",
                    "confirmed": True})
            state = (await post(prep, "/api/read", {**scope,
                "program": program("application.state.read", {})}))["result"]
            dimensions = (await post(prep, "/api/read", {**scope,
                "program": program("metadata.dimension.list", {
                    "limit": 100, "expectedMetadataRevision":
                        state["metadataRevision"]})}))["result"]
            coordinate = {}
            for dimension in dimensions["rows"]:
                if dimension.get("status") != "Active":
                    continue
                dimension_id = dimension["dimension_id"]
                members = (await post(prep, "/api/read", {**scope,
                    "program": program("metadata.member.list", {
                        "dimension": dimension_id, "limit": 100,
                        "expectedMetadataRevision": state["metadataRevision"]})}))["result"]
                active = [item["member_id"] for item in members["rows"]
                          if item.get("status") == "Active"]
                if not active:
                    raise LifecycleError("LAPTOP_WORKFLOW_ACTIVE_MEMBER_MISSING")
                coordinate[dimension_id] = active[0]
            await post(prep, "/api/security", {**scope,
                "program": program("security.application.access.set", {
                    "subjectId": reviewer["subject"], "action": "grant",
                    "role": "Reader"}),
                "idempotencyKey": "workflow-reviewer-access-" + run_id,
                "confirmed": True})
            state = (await post(prep, "/api/read", {**scope,
                "program": program("application.state.read", {})}))["result"]
            now = datetime.now(timezone.utc)
            assignment_id = "workflow-actors"
            definition = {"format": "openepm-application-assignment-set-v1",
                "workspaceId": workspace_id, "applicationId": application_id,
                "assignmentSetId": assignment_id, "version": 1,
                "name": "Distinct workflow actors",
                "effectiveFrom": (now - timedelta(minutes=1)).isoformat(),
                "effectiveTo": None, "assignments": []}
            controls = {"reassignable": False, "maxReassignments": 0,
                "delegationAllowed": False, "maxDelegationDepth": 0,
                "delegationExpiresAt": None}
            for assignment, subject, reviewer_subject in (
                    ("prepare", preparer["subject"], reviewer["subject"]),
                    ("review", reviewer["subject"], reviewer["subject"])):
                definition["assignments"].append({"assignmentId": assignment,
                    "name": assignment.title(), "subjects": [subject], "groups": [],
                    "memberSelectors": {key: [value]
                        for key, value in coordinate.items()},
                    "reviewerChain": [{"kind": "Subject", "id": reviewer_subject}],
                    "dueAt": (now + timedelta(days=1)).isoformat(),
                    "controls": controls})
            saved = (await post(prep, "/api/application-assignment", {**scope,
                "program": program("application.assignment.save", {
                    "definition": definition, "expectedStateRevision": 0,
                    "expectedMetadataRevision": state["metadataRevision"],
                    "expectedPolicyRevision": state["policyRevision"],
                    "expectedSchemaEpoch": state["schemaEpoch"]}),
                "idempotencyKey": "workflow-assignment-save-" + run_id,
                "confirmed": True}))["result"]
            published = (await post(prep, "/api/application-assignment", {**scope,
                "program": program("application.assignment.publish", {
                    "assignmentSetId": assignment_id, "version": 1,
                    "expectedStateRevision": saved["stateRevision"],
                    "expectedMetadataRevision": state["metadataRevision"],
                    "expectedPolicyRevision": saved["policyRevision"],
                    "expectedSchemaEpoch": state["schemaEpoch"]}),
                "idempotencyKey": "workflow-assignment-publish-" + run_id,
                "confirmed": True}))["result"]
            ref = {"assignmentSetId": assignment_id, "version": 1,
                "digest": saved["definitionDigest"]}
            destination = {"kind": "Function", "function": "application.state.read",
                "argumentsDigest": sha256(b"{}").hexdigest()}
            flow_id = "distinct-review"
            flow = {"format": "openepm-application-task-flow-v2",
                "workspaceId": workspace_id, "applicationId": application_id,
                "flowId": flow_id, "version": 1, "name": "Distinct review",
                "selection": {"format": "openepm-cube-selection-v1",
                    "metadataRevision": state["metadataRevision"],
                    "dimensions": [{"dimensionId": key,
                        "include": {"kind": "member", "memberId": value},
                        "exclude": None} for key, value in sorted(
                            coordinate.items())]},
                "activities": [
                    {"activityId": "prepare", "name": "Prepare", "kind": "Action",
                     "dependsOn": [], "returnTo": None,
                     "assignmentRef": {**ref, "assignmentId": "prepare"},
                     "destination": destination, "evidenceContract": {
                        "kind": "ManualAttestation", "statement": "Prepared and checked."}},
                    {"activityId": "review", "name": "Review", "kind": "Review",
                     "dependsOn": ["prepare"], "returnTo": "prepare",
                     "assignmentRef": {**ref, "assignmentId": "review"},
                     "destination": destination, "evidenceContract": {
                        "kind": "ManualAttestation", "statement": "Reviewed and accepted."}}]}
            flow_saved = (await post(prep, "/api/application-workflow", {**scope,
                "program": program("application.workflow.save", {
                    "definition": flow, "expectedStateRevision": 0,
                    "expectedMetadataRevision": state["metadataRevision"],
                    "expectedPolicyRevision": published["policyRevision"],
                    "expectedSchemaEpoch": state["schemaEpoch"]}),
                "idempotencyKey": "workflow-flow-save-" + run_id,
                "confirmed": True}))["result"]
            flow_published = (await post(prep, "/api/application-workflow", {**scope,
                "program": program("application.workflow.publish", {
                    "flowId": flow_id, "version": 1,
                    "expectedStateRevision": flow_saved["stateRevision"],
                    "expectedMetadataRevision": state["metadataRevision"],
                    "expectedPolicyRevision": flow_saved["policyRevision"],
                    "expectedSchemaEpoch": state["schemaEpoch"]}),
                "idempotencyKey": "workflow-flow-publish-" + run_id,
                "confirmed": True}))["result"]
            occurrence = (await post(prep, "/api/application-workflow-occurrence", {
                **scope, "program": program("application.workflow.occurrence.start", {
                    "flowId": flow_id, "version": 1, "expectedStateRevision": 2,
                    "expectedMetadataRevision": state["metadataRevision"],
                    "expectedPolicyRevision": flow_published["policyRevision"],
                    "expectedSchemaEpoch": state["schemaEpoch"]}),
                "idempotencyKey": "workflow-start-" + run_id, "confirmed": True}))["result"]
            first = (await post(prep, "/api/application-workflow-occurrence", {**scope,
                "program": program("application.workflow.activity.complete", {
                    "occurrenceId": occurrence["occurrenceId"], "activityId": "prepare",
                    "expectedActivityVersion": 1,
                    "evidence": {"kind": "ManualAttestation", "confirmed": True}}),
                "idempotencyKey": "workflow-prepare-one-" + run_id,
                "confirmed": True}))["result"]
            if first.get("readyActivityIds") != ["review"]:
                raise LifecycleError("LAPTOP_WORKFLOW_REVIEW_NOT_READY")
            reviewer_context, review = await login(browser, **reviewer["login"])
            worklist = (await post(review, "/api/read", {**scope,
                "program": program("application.workflow.worklist", {})}))["result"]
            if not any(item.get("activityId") == "review" for item in worklist["items"]):
                raise LifecycleError("LAPTOP_WORKFLOW_REVIEWER_WORKLIST_MISSING")
            returned = (await post(review, "/api/application-workflow-occurrence", {**scope,
                "program": program("application.workflow.activity.return", {
                    "occurrenceId": occurrence["occurrenceId"], "activityId": "review",
                    "expectedActivityVersion": 2, "reason": "Correct and resubmit"}),
                "idempotencyKey": "workflow-return-" + run_id,
                "confirmed": True}))["result"]
            if returned.get("returnedToActivityId") != "prepare":
                raise LifecycleError("LAPTOP_WORKFLOW_RETURN_INVALID")
            await post(prep, "/api/application-workflow-occurrence", {**scope,
                "program": program("application.workflow.activity.complete", {
                    "occurrenceId": occurrence["occurrenceId"], "activityId": "prepare",
                    "expectedActivityVersion": 3,
                    "evidence": {"kind": "ManualAttestation", "confirmed": True}}),
                "idempotencyKey": "workflow-prepare-two-" + run_id,
                "confirmed": True})
            completed = (await post(review, "/api/application-workflow-occurrence", {**scope,
                "program": program("application.workflow.activity.complete", {
                    "occurrenceId": occurrence["occurrenceId"], "activityId": "review",
                    "expectedActivityVersion": 4,
                    "evidence": {"kind": "ManualAttestation", "confirmed": True}}),
                "idempotencyKey": "workflow-review-complete-" + run_id,
                "confirmed": True}))["result"]
            history = (await post(review, "/api/read", {**scope,
                "program": program("application.workflow.occurrence.read", {
                    "occurrenceId": occurrence["occurrenceId"], "eventLimit": 100})}))["result"]
            events = [item["eventType"] for item in history["events"]]
            expected = ["OccurrenceStarted", "ActivityCompleted", "ActivityReturned",
                "ActivityCompleted", "ActivityCompleted", "OccurrenceCompleted"]
            if completed.get("status") != "Completed" or events != expected:
                raise LifecycleError("LAPTOP_WORKFLOW_HISTORY_INVALID")
            tasks = await post(review, "/api/tasks", {**scope,
                "afterSequence": 0, "limit": 100, "attentionOnly": False})
            return {"browserVersion": browser.version,
                "workspaceId": workspace_id, "applicationId": application_id,
                "occurrenceId": occurrence["occurrenceId"],
                "distinctSubjects": preparer["subject"] != reviewer["subject"],
                "returnReworkCompleted": True, "events": events,
                "taskCount": len(tasks["tasks"])}
        finally:
            if reviewer_context is not None:
                await reviewer_context.close()
            if preparer_context is not None:
                await preparer_context.close()
            await browser.close()


def qualify(state_root: Path) -> dict:
    preflight = public_preflight(); before = owner_fingerprint()
    run_id = secrets.token_hex(8); workspace_id = "uat-w-" + run_id
    application_id = "uat-a-" + run_id
    actors = []
    primary_error: BaseException | None = None
    result = cleanup = None
    try:
        for role in ("preparer", "reviewer"):
            username = f"openepm-workflow-{role}-{run_id}"
            temporary = "Qa!" + secrets.token_urlsafe(24) + "8v"
            replacement = "Pe!" + secrets.token_urlsafe(24) + "3m"
            created = governed_directory_effect(state_root, directory_program(
                "identity.native-user.create", username=username,
                displayName="Open EPM workflow " + role,
                shortDescription="Run-owned distinct workflow identity",
                semanticDescription="Disposable laptop workflow qualification identity."),
                idempotency_key=f"workflow-{role}-create-{run_id}")
            subject = created.get("subjectId")
            if not isinstance(subject, str) or not subject:
                raise LifecycleError("LAPTOP_WORKFLOW_SUBJECT_INVALID")
            governed_directory_effect(state_root, directory_program(
                "identity.native-user.password.set", subjectId=subject,
                temporaryPassword=temporary),
                idempotency_key=f"workflow-{role}-password-{run_id}")
            actors.append({"role": role, "subject": subject,
                "login": {"username": username, "temporary": temporary,
                          "replacement": replacement}})
        governed_directory_effect(state_root, directory_program(
            "identity.server-administrator.access.set",
            subjectId=actors[0]["subject"], access="Grant"),
            idempotency_key="workflow-preparer-admin-grant-" + run_id)
        result = asyncio.run(run_browser(actors[0], actors[1], run_id))
    except BaseException as error:
        primary_error = error
    finally:
        try:
            if workspace_exists(workspace_id):
                time.sleep(1.05)
                cleanup = cleanup_workspace(state_root, workspace_id,
                    application_id, IDENTITY_ORIGIN + "/realms/openepm",
                    actors[0]["subject"], int(time.time()), run_id)
            if actors:
                try:
                    governed_directory_effect(state_root, directory_program(
                        "identity.server-administrator.access.set",
                        subjectId=actors[0]["subject"], access="Revoke"),
                        idempotency_key="workflow-preparer-admin-revoke-" + run_id)
                except Exception:
                    if primary_error is None: raise
            for actor in reversed(actors):
                try:
                    governed_directory_effect(state_root, directory_program(
                        "identity.native-user.status.set",
                        subjectId=actor["subject"], status="Inactive"),
                        idempotency_key=f"workflow-{actor['role']}-deactivate-{run_id}")
                except Exception:
                    if primary_error is None: raise
        except BaseException as cleanup_error:
            if primary_error is None: primary_error = cleanup_error
    if primary_error is not None: raise primary_error
    time.sleep(1.05)
    after = owner_fingerprint()
    if result is None or cleanup is None or workspace_exists(workspace_id) or before != after:
        raise LifecycleError("LAPTOP_WORKFLOW_CLEANUP_INVALID")
    return {"format": "openepm-laptop-distinct-workflow-v1",
        "qualifiedAt": datetime.now(timezone.utc).isoformat(),
        "publicPreflight": preflight, "journey": result,
        "cleanup": cleanup, "ownerFingerprint": after,
        "runOwnedIdentitiesDeactivated": True}


def repair_owned_residuals(state_root: Path) -> dict:
    """Retire only validated residual scopes from this disposable qualifier."""
    rows = json.loads(psql("""SELECT coalesce(json_agg(x ORDER BY
      x->>'workspaceId'),'[]'::json) FROM (SELECT json_build_object(
      'workspaceId',w.workspace_id,'applicationId',a.application_id,
      'issuer',g.issuer,'subject',g.subject_id,'userStatus',u.status,
      'operator',EXISTS(SELECT 1 FROM epm.platform_operator_grant p WHERE
        (p.issuer,p.subject_id)=(g.issuer,g.subject_id))) x
      FROM epm.workspace w JOIN epm.application a USING(workspace_id)
      JOIN epm.workspace_access_grant g USING(workspace_id)
      JOIN epm.identity_user_directory_state u ON
        (u.issuer,u.subject_id)=(g.issuer,g.subject_id)
      WHERE w.workspace_id LIKE 'uat-w-%') q"""))
    if not isinstance(rows, list):
        raise LifecycleError("LAPTOP_WORKFLOW_REPAIR_SCOPE_INVALID")
    managed_users = []
    offset = 0
    while True:
        page = governed_directory_read(state_root, directory_program(
            "identity.native-user.list", offset=offset, limit=100))
        items, next_offset = page.get("items"), page.get("nextOffset")
        if (not isinstance(items, list)
                or (next_offset is not None
                    and (type(next_offset) is not int
                         or next_offset <= offset))):
            raise LifecycleError("LAPTOP_WORKFLOW_REPAIR_SCOPE_INVALID")
        managed_users.extend(items)
        if next_offset is None:
            break
        offset = next_offset
    residual_identities = []
    for item in managed_users:
        if not isinstance(item, dict):
            raise LifecycleError("LAPTOP_WORKFLOW_REPAIR_SCOPE_INVALID")
        username, subject = item.get("username"), item.get("subjectId")
        match = (re.fullmatch(
            r"openepm-workflow-(preparer|reviewer)-([0-9a-f]{16})",
            username) if isinstance(username, str) else None)
        if match is None or item.get("status") != "Active":
            continue
        if not isinstance(subject, str) or not subject:
            raise LifecycleError("LAPTOP_WORKFLOW_REPAIR_SCOPE_INVALID")
        residual_identities.append({"role": match.group(1),
            "runId": match.group(2), "username": username,
            "subjectId": subject})
    if not rows and not residual_identities:
        raise LifecycleError("LAPTOP_WORKFLOW_REPAIR_SCOPE_INVALID")
    before = owner_fingerprint(); repaired = []
    issuer = IDENTITY_ORIGIN + "/realms/openepm"
    for row in rows:
        workspace_id = row.get("workspaceId")
        match = (re.fullmatch(r"uat-w-([0-9a-f]{16})", workspace_id)
                 if isinstance(workspace_id, str) else None)
        subject = row.get("subject")
        if (match is None
                or row.get("applicationId") != "uat-a-" + match.group(1)
                or row.get("issuer") != issuer
                or not isinstance(subject, str) or not subject
                or row.get("userStatus") != "Active"
                or row.get("operator") is not True):
            raise LifecycleError("LAPTOP_WORKFLOW_REPAIR_SCOPE_INVALID")
        run_id = match.group(1); attempt = secrets.token_hex(4)
        primary: BaseException | None = None
        try:
            time.sleep(1.05)
            cleanup_workspace(state_root, workspace_id, row["applicationId"],
                issuer, subject, int(time.time()),
                "workflow-repair-" + run_id + "-" + attempt)
        except BaseException as error:
            primary = error
        finally:
            try:
                governed_directory_effect(state_root, directory_program(
                    "identity.server-administrator.access.set",
                    subjectId=subject, access="Revoke"), idempotency_key=
                    "workflow-repair-admin-revoke-" + run_id + "-" + attempt)
            except BaseException as error:
                if primary is None: primary = error
            try:
                governed_directory_effect(state_root, directory_program(
                    "identity.native-user.status.set", subjectId=subject,
                    status="Inactive"), idempotency_key=
                    "workflow-repair-deactivate-" + run_id + "-" + attempt)
            except BaseException as error:
                if primary is None: primary = error
        if primary is not None: raise primary
        repaired.append({"workspaceId": workspace_id,
            "applicationId": row["applicationId"], "identityInactive": True,
            "administratorRevoked": True})
    repaired_subjects = {row["subject"] for row in rows}
    identities_repaired = []
    for identity in residual_identities:
        if identity["subjectId"] in repaired_subjects:
            continue
        attempt = secrets.token_hex(4)
        result = governed_directory_effect(state_root, directory_program(
            "identity.native-user.status.set",
            subjectId=identity["subjectId"], status="Inactive"),
            idempotency_key=("workflow-repair-identity-deactivate-"
                + identity["runId"] + "-" + identity["role"] + "-" + attempt))
        if (result.get("subjectId") != identity["subjectId"]
                or result.get("status") != "Inactive"):
            raise LifecycleError("LAPTOP_WORKFLOW_REPAIR_CLEANUP_INVALID")
        identities_repaired.append({**identity, "identityInactive": True})
    after = owner_fingerprint()
    if before != after or any(workspace_exists(item["workspaceId"])
                              for item in repaired):
        raise LifecycleError("LAPTOP_WORKFLOW_REPAIR_CLEANUP_INVALID")
    return {"format": "openepm-laptop-distinct-workflow-repair-v1",
        "repaired": repaired, "identitiesRepaired": identities_repaired,
        "ownerFingerprint": after}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-root", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repair-owned-residuals", action="store_true")
    args = parser.parse_args()
    report = (repair_owned_residuals(args.state_root.resolve())
              if args.repair_owned_residuals else
              qualify(args.state_root.resolve()))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
