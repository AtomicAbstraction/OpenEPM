#!/usr/bin/env python3
"""Activate retained owner UAT governance after an interactive owner login.

The runner never accepts, reads or stores an owner password. It opens the
installed public application in visible Chrome, waits for the owner to finish
the normal Keycloak login, verifies that exact subject against the active
deployment state, and then uses only public browser contracts. A separately
created real reviewer subject is required; the runner does not invent or
impersonate a second human identity.
"""
from __future__ import annotations

import argparse
import asyncio
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from playwright.async_api import async_playwright

from scripts.programmable_uat_sample_contract import (
    build_substantial_application_rule, validate_sample_manifest)
from scripts.qualify_active_browser_session_lifecycle import LifecycleError
from scripts.qualify_laptop_distinct_workflow import post, program
from scripts.qualify_public_native_keycloak_lifecycle import APP_ORIGIN


STATE = ROOT / "deploy/macos-pilot/.runtime/harmonized-next/state.json"
MANIFEST = ROOT / "deploy/macos-pilot/programmable-sample-contents.json"
SUBJECT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,299}\Z")


def deployment_contract(state_path: Path) -> tuple[str, str]:
    value = json.loads(state_path.read_text(encoding="utf-8"))
    if (value.get("state") != "active" or value.get("verified") is not True
            or value.get("expectedSchema") != 281
            or value.get("expectedApplications") != 2):
        raise LifecycleError("OWNER_UAT_ACTIVE_STATE_INVALID")
    subject = value.get("identityVerification", {}).get(
        "initialAdministratorSubject")
    image = value.get("applicationImage")
    if (not isinstance(subject, str) or SUBJECT.fullmatch(subject) is None
            or not isinstance(image, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None):
        raise LifecycleError("OWNER_UAT_IDENTITY_INVALID")
    return subject, image


async def read(page, scope: dict, function: str, arguments: dict) -> dict:
    return (await post(page, "/api/read", {**scope,
        "program": program(function, arguments)}))["result"]


async def mutate(page, path: str, scope: dict, function: str,
                 arguments: dict, key: str) -> dict:
    return (await post(page, path, {**scope,
        "program": program(function, arguments), "idempotencyKey": key,
        "confirmed": True}))["result"]


async def activate_application(page, workspace_id: str, application: dict,
                               owner_subject: str,
                               reviewer_subject: str) -> dict:
    application_id = application["applicationId"]
    scope = {"workspaceId": workspace_id, "applicationId": application_id}
    prefix = "owner-uat-governance-v1-" + application_id
    state = await read(page, scope, "application.state.read", {})
    full_definition, bindings = build_substantial_application_rule(application)
    scheduled_rule_id = application_id + ".uat-scheduled-rule"
    unit = deepcopy(full_definition["units"][-1])
    unit["operations"][0]["arguments"]["resultKey"] = (
        application_id + ".uat-schedule.result")
    scheduled_definition = {"format": full_definition["format"],
        "name": application["name"] + " UAT scheduled rule",
        "parameters": full_definition["parameters"], "units": [unit]}
    await mutate(page, "/api/rule-action", scope,
        "application.rule.version.save", {"ruleId": scheduled_rule_id,
            "version": 1, "definition": scheduled_definition,
            "expectedMetadataRevision": state["metadataRevision"],
            "expectedPolicyRevision": state["policyRevision"]},
        prefix + "-rule-save")
    publication = await mutate(page, "/api/rule-action", scope,
        "application.rule.version.publish", {"ruleId": scheduled_rule_id,
            "version": 1,
            "expectedMetadataRevision": state["metadataRevision"],
            "expectedPolicyRevision": state["policyRevision"]},
        prefix + "-rule-publish")
    state = await read(page, scope, "application.state.read", {})

    now = datetime.now(timezone.utc)
    schedule_id = application_id + ".uat-daily"
    delegation_id = application_id + ".uat-schedule-authority"
    delegation = await mutate(page, "/api/execution-delegation", scope,
        "execution.delegation.create", {"delegationId": delegation_id,
            "version": 1,
            "issuer": "https://identity.openepm.dev/realms/openepm",
            "subjectId": owner_subject,
            "operationScope": ["application.rule.run"],
            "validFrom": (now - timedelta(minutes=1)).isoformat(),
            "validUntil": (now + timedelta(days=365)).isoformat(),
            "scheduleId": schedule_id, "scheduleVersion": 1,
            "expectedMetadataRevision": state["metadataRevision"],
            "expectedPolicyRevision": state["policyRevision"],
            "expectedSchemaEpoch": state["schemaEpoch"]},
        prefix + "-delegation")
    first_due = (now + timedelta(days=1)).replace(
        hour=6, minute=0, second=0, microsecond=0)
    schedule = {"format": "openepm-application-schedule-v1",
        "scheduleId": schedule_id, "version": 1,
        "target": {"kind": "ApplicationRule", "ruleId": scheduled_rule_id,
            "version": 1,
            "publicationOperationId": publication["operationId"],
            "publishedRevision": publication["committedRevision"],
            "programDigest": publication["programDigest"]},
        "bindings": bindings, "pov": [],
        "recurrence": {"kind": "FixedInterval", "intervalSeconds": 86400,
            "firstDueAt": first_due.isoformat().replace("+00:00", "Z"),
            "catchUpPolicy": "latest", "maxCatchUp": 1},
        "retryPolicy": {"maxAttempts": 3, "backoffSeconds": 60,
            "needsInspectionAfter": True},
        "cancellationPolicy": "PreserveCommittedStopFuture",
        "delegation": {"delegationId": delegation_id, "version": 1}}
    saved_schedule = await mutate(page, "/api/application-schedule", scope,
        "schedule.version.save", {"definition": schedule,
            "expectedStateRevision": 0,
            "expectedMetadataRevision": state["metadataRevision"],
            "expectedPolicyRevision": delegation["policyRevision"],
            "expectedSchemaEpoch": state["schemaEpoch"]},
        prefix + "-schedule-save")
    schedule_read = (await post(page, "/api/application-schedule", {**scope,
        "program": program("schedule.version.read", {
            "scheduleId": schedule_id, "version": 1})}))["result"]
    schedule_row = schedule_read.get("schedule")
    if (not isinstance(schedule_row, dict)
            or schedule_row.get("status") != "Saved"):
        raise LifecycleError("OWNER_UAT_SCHEDULE_SAVE_INVALID")
    published_schedule = await mutate(
        page, "/api/application-schedule", scope, "schedule.version.publish",
        {"scheduleId": schedule_id, "version": 1,
         "expectedStateRevision": schedule_row["stateRevision"],
         "expectedMetadataRevision": state["metadataRevision"],
         "expectedPolicyRevision": saved_schedule["policyRevision"],
         "expectedSchemaEpoch": state["schemaEpoch"]},
        prefix + "-schedule-publish")

    await mutate(page, "/api/security", scope,
        "security.application.access.set", {"subjectId": reviewer_subject,
            "action": "grant", "role": "Reader"},
        prefix + "-reviewer-access")
    state = await read(page, scope, "application.state.read", {})
    source = application["facts"]["numeric"][0]["coordinate"]
    assignment_id = application_id + ".uat-actors"
    controls = {"reassignable": False, "maxReassignments": 0,
        "delegationAllowed": False, "maxDelegationDepth": 0,
        "delegationExpiresAt": None}
    definition = {"format": "openepm-application-assignment-set-v1",
        "workspaceId": workspace_id, "applicationId": application_id,
        "assignmentSetId": assignment_id, "version": 1,
        "name": application["name"] + " UAT actors",
        "effectiveFrom": (now - timedelta(minutes=1)).isoformat(),
        "effectiveTo": None, "assignments": [
            {"assignmentId": "prepare", "name": "Prepare",
             "subjects": [owner_subject], "groups": [],
             "memberSelectors": {key: [value]
                 for key, value in source.items()},
             "reviewerChain": [{"kind": "Subject",
                                "id": reviewer_subject}],
             "dueAt": (now + timedelta(days=7)).isoformat(),
             "controls": controls},
            {"assignmentId": "review", "name": "Review",
             "subjects": [reviewer_subject], "groups": [],
             "memberSelectors": {key: [value]
                 for key, value in source.items()},
             "reviewerChain": [{"kind": "Subject",
                                "id": reviewer_subject}],
             "dueAt": (now + timedelta(days=7)).isoformat(),
             "controls": controls}]}
    saved_assignment = await mutate(page, "/api/application-assignment", scope,
        "application.assignment.save", {"definition": definition,
            "expectedStateRevision": 0,
            "expectedMetadataRevision": state["metadataRevision"],
            "expectedPolicyRevision": state["policyRevision"],
            "expectedSchemaEpoch": state["schemaEpoch"]},
        prefix + "-assignment-save")
    published_assignment = await mutate(
        page, "/api/application-assignment", scope,
        "application.assignment.publish", {"assignmentSetId": assignment_id,
            "version": 1,
            "expectedStateRevision": saved_assignment["stateRevision"],
            "expectedMetadataRevision": state["metadataRevision"],
            "expectedPolicyRevision": saved_assignment["policyRevision"],
            "expectedSchemaEpoch": state["schemaEpoch"]},
        prefix + "-assignment-publish")
    flow_id = application_id + ".uat-review"
    selection = {"format": "openepm-cube-selection-v1",
        "metadataRevision": state["metadataRevision"],
        "dimensions": [{"dimensionId": key,
            "include": {"kind": "member", "memberId": value},
            "exclude": None} for key, value in sorted(source.items())]}
    flow = {"format": "openepm-application-task-flow-v2",
        "workspaceId": workspace_id, "applicationId": application_id,
        "flowId": flow_id, "version": 1,
        "name": application["name"] + " UAT review", "selection": selection,
        "activities": [
            {"activityId": "prepare", "name": "Prepare", "kind": "Action",
             "dependsOn": [], "returnTo": None,
             "assignmentRef": {"assignmentSetId": assignment_id,
                "version": 1,
                "digest": saved_assignment["definitionDigest"],
                "assignmentId": "prepare"},
             "destination": {"kind": "Function",
                "function": "application.rule.run",
                "argumentsDigest": publication["programDigest"]},
             "evidenceContract": {"kind": "OperationReceipt",
                "allowedFunctions": ["application.rule.run"],
                "requireCurrent": False}},
            {"activityId": "review", "name": "Review", "kind": "Review",
             "dependsOn": ["prepare"], "returnTo": "prepare",
             "assignmentRef": {"assignmentSetId": assignment_id,
                "version": 1,
                "digest": saved_assignment["definitionDigest"],
                "assignmentId": "review"},
             "destination": {"kind": "Function",
                "function": "application.rule.run",
                "argumentsDigest": publication["programDigest"]},
             "evidenceContract": {"kind": "OperationReceipt",
                "allowedFunctions": ["application.rule.run"],
                "requireCurrent": False}}]}
    saved_flow = await mutate(page, "/api/application-workflow", scope,
        "application.workflow.save", {"definition": flow,
            "expectedStateRevision": 0,
            "expectedMetadataRevision": state["metadataRevision"],
            "expectedPolicyRevision": published_assignment["policyRevision"],
            "expectedSchemaEpoch": state["schemaEpoch"]},
        prefix + "-workflow-save")
    published_flow = await mutate(page, "/api/application-workflow", scope,
        "application.workflow.publish", {"flowId": flow_id, "version": 1,
            "expectedStateRevision": saved_flow["stateRevision"],
            "expectedMetadataRevision": state["metadataRevision"],
            "expectedPolicyRevision": saved_flow["policyRevision"],
            "expectedSchemaEpoch": state["schemaEpoch"]},
        prefix + "-workflow-publish")
    return {"applicationId": application_id, "scheduleId": schedule_id,
        "scheduleStatus": published_schedule.get("status"),
        "assignmentSetId": assignment_id, "flowId": flow_id,
        "workflowStatus": published_flow.get("status")}


async def activate(args) -> dict:
    owner_subject, image = deployment_contract(args.state.resolve())
    if (SUBJECT.fullmatch(args.reviewer_subject) is None
            or args.reviewer_subject == owner_subject):
        raise LifecycleError("OWNER_UAT_REVIEWER_SUBJECT_INVALID")
    manifest = validate_sample_manifest(json.loads(
        MANIFEST.read_text(encoding="utf-8")))
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(channel="chrome",
                                                    headless=False)
        try:
            context = await browser.new_context()
            page = await context.new_page()
            await page.goto(APP_ORIGIN + "/", wait_until="domcontentloaded",
                            timeout=60_000)
            print("Complete the normal owner login in the opened Chrome window.",
                  flush=True)
            await page.locator("#main-content").wait_for(
                timeout=args.login_timeout_seconds * 1000)
            identity = await page.evaluate("""async () => {
              const response=await fetch('/api/session-identity',
                {credentials:'same-origin',cache:'no-store'});
              if(!response.ok) throw new Error('SESSION_IDENTITY_UNAVAILABLE');
              return response.json();
            }""")
            if identity.get("subject") != owner_subject:
                raise LifecycleError("OWNER_UAT_SESSION_SUBJECT_MISMATCH")
            results = []
            for application in manifest["applications"]:
                results.append(await activate_application(
                    page, "ws-pilot", application, owner_subject,
                    args.reviewer_subject))
            return {"format": "openepm-owner-uat-governance-activation-v1",
                "status": "passed", "applicationImage": image,
                "workspaceId": "ws-pilot", "ownerSubject": owner_subject,
                "reviewerSubject": args.reviewer_subject,
                "applications": results, "ownerPasswordRead": False,
                "directDatabaseAccess": False}
        finally:
            await browser.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reviewer-subject", required=True)
    parser.add_argument("--state", type=Path, default=STATE)
    parser.add_argument("--login-timeout-seconds", type=int, default=600)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if (args.output.exists() or not args.output.is_absolute()
            or not 60 <= args.login_timeout_seconds <= 1800):
        parser.error("use a new absolute output and a 60..1800 second timeout")
    result = asyncio.run(activate(args))
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(json.dumps({"status": "passed", "output": str(args.output)},
                     sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
