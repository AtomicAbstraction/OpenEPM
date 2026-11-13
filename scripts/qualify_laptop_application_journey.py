#!/usr/bin/env python3
"""Qualify and completely retire one public laptop application journey.

The runner creates a run-owned native user, delegates bounded Server
Administrator authority through the fixed platform contract, and uses a
run-owned Playwright Chromium profile plus the public Cloudflare application
to create one workspace and one
eight-axis application, publish a worker job and read the exact value back.  It
then uses the governed workspace reset protocol to delete exactly that
run-owned workspace, revokes the temporary authority, deactivates the user and
proves every workspace-scoped row belonging to the two owner applications is
unchanged.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from playwright.sync_api import sync_playwright

from scripts import macos_pilot_programmable_replacement as replacement
from scripts.openepm_browser_probe import WORKFLOW_JS
from scripts.qualify_active_browser_session_lifecycle import (
    DEFAULT_STATE, LifecycleError, storage_is_empty)
from scripts.qualify_public_native_keycloak_lifecycle import (
    APP_ORIGIN, IDENTITY_ORIGIN, directory_program,
    governed_directory_effect, public_preflight)


DB_CONTAINER = "openepm-harmonized-next-db-1"
WORKSPACE_CONTAINER = "openepm-harmonized-next-workspace-1"
OWNER_WORKSPACE = "ws-pilot"
OWNER_APPLICATIONS = ("AIcompanies", "epm-rule-authoring-sample")
SAFE_RELATION = re.compile(r"[a-z][a-z0-9_]{0,62}\Z")

RESET_PREVIEW_EFFECT = r"""
import json, os, sys
from epm_core.postgres_access import VerifiedIdentity
from epm_core.postgres_workspace_reset import PostgresWorkspaceResetPreview

p=json.load(sys.stdin)
s=PostgresWorkspaceResetPreview(
    os.environ['EPM_PG_LIFECYCLE_DSN'],
    identity=VerifiedIdentity(p['issuer'],p['subject']),
    secret=bytes.fromhex(os.environ['EPM_PG_PREVIEW_SECRET_HEX']),
    endpoint_inventory_json=p['endpointInventory'])
if p['action']=='prepare':
    result=s.prepare(p['workspaceId'],{
      'languageVersion':2,'function':'workspace.reset.prepare',
      'arguments':{'scope':'workspace'}})
else:
    result=s.transition(p['workspaceId'],p['program'],
                        idempotency_key=p['idempotencyKey'])
print(json.dumps(result,sort_keys=True,separators=(',',':')))
"""

RESET_APPLY_EFFECT = r"""
import json, os, re, sys
from epm_core.postgres_access import VerifiedIdentity
from epm_core.postgres_workspace_reset import PostgresWorkspaceResetPreview
from epm_core.postgres_workspace_reset_apply import PostgresWorkspaceResetApply

try:
    p=json.load(sys.stdin)
    identity=VerifiedIdentity(p['issuer'],p['subject'])
    secret=bytes.fromhex(os.environ['EPM_PG_PREVIEW_SECRET_HEX'])
    inventory=os.environ['EPM_RESET_ENDPOINT_INVENTORY_JSON']
    preview=PostgresWorkspaceResetPreview(
        os.environ['EPM_POSTGRES_ADMIN_DSN'], identity=identity,
        secret=secret, endpoint_inventory_json=inventory)
    prepared=preview.prepare(os.environ['EPM_PG_WORKSPACE_ID'],{
        'languageVersion':2,'function':'workspace.reset.prepare',
        'arguments':{'scope':'workspace'}})
    blockers=set(prepared.get('applyBlockers',()))
    manifest=prepared.get('manifest',{})
    applications=manifest.get('applications',())
    expected_blockers={'DEDICATED_RESET_APPLY_LISTENER_REQUIRED',
                       'EXTERNAL_ENDPOINT_INVENTORY_REQUIRED'}
    if blockers != expected_blockers:
        raise ValueError('RESET_FINAL_PREVIEW_BLOCKERS_'+'_'.join(
            sorted(blockers - expected_blockers)))
    if manifest.get('workspace',{}).get('status') != 'Maintenance':
        raise ValueError('RESET_FINAL_PREVIEW_STATUS_MISMATCH')
    expected_application=p.get('applicationId')
    if expected_application is None:
        if applications:
            raise ValueError('RESET_FINAL_PREVIEW_APPLICATION_COUNT_MISMATCH')
    elif (len(applications) != 1
          or applications[0].get('application_id') != expected_application):
        raise ValueError('RESET_FINAL_PREVIEW_APPLICATION_ID_MISMATCH')
    program={'languageVersion':2,'function':'workspace.reset.apply',
             'arguments':{name:prepared[name] for name in
                          ('manifestDigest','expiresAt','signature')}}
    s=PostgresWorkspaceResetApply(
        os.environ['EPM_POSTGRES_ADMIN_DSN'],
        identity=identity, secret=secret, endpoint_inventory_json=inventory,
        replacement_ready=os.environ.get('EPM_RESET_REPLACEMENT_READY')=='1',
        endpoints_retired=os.environ.get('EPM_RESET_ENDPOINTS_RETIRED')=='1')
    result=s.apply(os.environ['EPM_PG_WORKSPACE_ID'],program,
                   idempotency_key=p['idempotencyKey'])
    print(json.dumps(result,sort_keys=True,separators=(',',':')))
except BaseException as error:
    codes=sorted(set(re.findall(r'\b[A-Z][A-Z0-9_]{3,}\b',str(error))))
    detail=re.sub(r'[^A-Za-z0-9]+','_',str(error)).strip('_').upper()[:160]
    print('RESET_APPLY_DIRECT_FAILED:'+type(error).__name__.upper()+':'
          +','.join(codes[:8])+':'+detail,file=sys.stderr)
    raise SystemExit(2)
"""


def run(arguments: list[str], *, input_text: str | None = None,
        environment: dict[str, str] | None = None,
        timeout: int = 180) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(arguments, input=input_text, text=True,
        capture_output=True, env=environment, timeout=timeout)
    if result.returncode:
        codes = sorted(set(re.findall(r"\b[A-Z][A-Z0-9_]{3,}\b",
                                      result.stderr)))
        raise LifecycleError(
            "LAPTOP_JOURNEY_COMMAND_FAILED:command="
            + Path(arguments[0]).name + ";returncode="
            + str(result.returncode) + ";codes=" + ",".join(codes[:12]))
    return result


def psql(statement: str) -> str:
    return run(["docker", "exec", DB_CONTAINER, "psql", "-U", "postgres",
                "-d", "postgres", "-AtX", "-v", "ON_ERROR_STOP=1",
                "-c", statement]).stdout.strip()


def workspace_exists(workspace_id: str) -> bool:
    if re.fullmatch(r"uat-w-[0-9a-f]{16}", workspace_id) is None:
        raise LifecycleError("LAPTOP_JOURNEY_WORKSPACE_ID_INVALID")
    return psql("SELECT EXISTS(SELECT 1 FROM epm.workspace WHERE workspace_id='"
                + workspace_id + "')") == "t"


def owner_fingerprint() -> dict:
    applications = psql("SELECT string_agg(application_id,',' ORDER BY "
        "application_id) FROM epm.application WHERE workspace_id='ws-pilot'")
    if applications != ",".join(OWNER_APPLICATIONS):
        raise LifecycleError("OWNER_APPLICATION_INVENTORY_CHANGED")
    relations = psql("""SELECT DISTINCT c.relname
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      JOIN pg_attribute a ON a.attrelid=c.oid
      WHERE n.nspname='epm' AND c.relkind IN ('r','p')
        AND a.attname='workspace_id' AND a.attnum>0 AND NOT a.attisdropped
      ORDER BY c.relname""").splitlines()
    if not relations or any(SAFE_RELATION.fullmatch(name) is None
                            for name in relations):
        raise LifecycleError("OWNER_FINGERPRINT_RELATIONS_INVALID")
    digests = {}
    for relation in relations:
        statement = ("COPY (SELECT payload FROM (SELECT row_to_json(t)::text "
            "AS payload FROM epm.\"" + relation + "\" t WHERE "
            "workspace_id='" + OWNER_WORKSPACE + "') canonical "
            "ORDER BY payload) TO STDOUT")
        process = subprocess.Popen(
            ["docker", "exec", DB_CONTAINER, "psql", "-U", "postgres",
             "-d", "postgres", "-AtX", "-v", "ON_ERROR_STOP=1", "-c",
             statement], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        digest = sha256()
        assert process.stdout is not None
        while block := process.stdout.read(1024 * 1024):
            digest.update(block)
        stderr = process.stderr.read() if process.stderr is not None else b""
        if process.wait() != 0:
            codes = sorted({value.decode("ascii", errors="ignore")
                            for value in re.findall(
                                rb"\b[A-Z][A-Z0-9_]{3,}\b", stderr)})
            raise LifecycleError("OWNER_FINGERPRINT_FAILED:" + relation + ":"
                                 + ",".join(codes[:12]))
        digests[relation] = digest.hexdigest()
    return {"workspaceId": OWNER_WORKSPACE,
            "applications": list(OWNER_APPLICATIONS),
            "relationCount": len(digests),
            "digest": sha256(json.dumps(digests, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()}


def endpoint_inventory(workspace_id: str, application_id: str | None) -> str:
    endpoints = [
        {"kind": "web_inspector", "url": "http://127.0.0.1:5195/",
         "workspaceId": "", "applicationId": ""},
        {"kind": "workspace_mcp", "url": "http://127.0.0.1:5192/api/workspace/mcp",
         "workspaceId": workspace_id, "applicationId": ""},
    ]
    if application_id is not None:
        endpoints.append({"kind": "application_mcp",
            "url": "http://127.0.0.1:5194/api/application/mcp",
            "workspaceId": workspace_id, "applicationId": application_id})
    value = {"endpoints": endpoints}
    value["endpoints"].sort(key=lambda item: (
        item["kind"], item["workspaceId"], item["applicationId"], item["url"]))
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def reset_call(payload: dict) -> dict:
    result = run(["docker", "exec", "-i", WORKSPACE_CONTAINER, "python",
                  "-c", RESET_PREVIEW_EFFECT],
                 input_text=json.dumps(payload), timeout=180)
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise LifecycleError("LAPTOP_RESET_RESPONSE_INVALID") from error
    if type(value) is not dict:
        raise LifecycleError("LAPTOP_RESET_RESPONSE_INVALID")
    return value


def triple(prepared: dict) -> dict:
    result = {name: prepared.get(name)
              for name in ("manifestDigest", "expiresAt", "signature")}
    if (not isinstance(result["manifestDigest"], str)
            or re.fullmatch(r"[0-9a-f]{64}", result["manifestDigest"]) is None
            or type(result["expiresAt"]) is not int
            or result["expiresAt"] <= int(time.time())
            or not isinstance(result["signature"], str)
            or re.fullmatch(r"[0-9a-f]{64}", result["signature"]) is None):
        raise LifecycleError("LAPTOP_RESET_TRIPLE_INVALID")
    return result


def transition(payload: dict, prepared: dict, function: str,
               key: str) -> dict:
    return reset_call({**payload, "action": "transition",
        "program": {"languageVersion": 2, "function": function,
                    "arguments": triple(prepared)},
        "idempotencyKey": key})


def cleanup_workspace(state_root: Path, workspace_id: str,
                      application_id: str | None, issuer: str, subject: str,
                      issued_at: int, run_id: str) -> dict:
    inventory = endpoint_inventory(workspace_id, application_id)
    payload = {"action": "prepare", "workspaceId": workspace_id,
               "issuer": issuer, "subject": subject, "issuedAt": issued_at,
               "endpointInventory": inventory}
    prepared = reset_call(payload)
    unknown = set(prepared.get("applyBlockers", ())) - {
        "DEDICATED_RESET_APPLY_LISTENER_REQUIRED",
        "EXTERNAL_ENDPOINT_INVENTORY_REQUIRED"}
    if unknown:
        raise LifecycleError("LAPTOP_RESET_UNEXPECTED_BLOCKER:" +
                             ",".join(sorted(unknown)))
    status = prepared.get("manifest", {}).get("workspace", {}).get("status")
    if status == "Active":
        transition(payload, prepared, "workspace.reset.quiesce",
                   "laptop-quiesce-" + run_id)
        maintenance = reset_call(payload)
    elif status == "Maintenance":
        maintenance = prepared
    else:
        raise LifecycleError("LAPTOP_RESET_WORKSPACE_STATE_INVALID")
    active = set(maintenance.get("applyBlockers", ())) - {
        "DEDICATED_RESET_APPLY_LISTENER_REQUIRED",
        "EXTERNAL_ENDPOINT_INVENTORY_REQUIRED"}
    if active:
        transition(payload, maintenance, "workspace.reset.settle",
                   "laptop-settle-" + run_id)
        maintenance = reset_call(payload)
    blockers = set(maintenance.get("applyBlockers", ()))
    if blockers != {"DEDICATED_RESET_APPLY_LISTENER_REQUIRED",
                    "EXTERNAL_ENDPOINT_INVENTORY_REQUIRED"}:
        raise LifecycleError("LAPTOP_RESET_BLOCKERS_REMAIN:" +
                             ",".join(sorted(blockers)))

    command, environment = replacement.base(state_root)
    stopped = ("browser-gateway", "workspace", "router", "web", "worker")
    replacement.compose(command, "stop", *stopped, environment=environment)
    try:
        reset_environment = dict(environment)
        reset_environment.update({
            "EPM_PG_WORKSPACE_ID": workspace_id,
            "EPM_RESET_ENDPOINT_INVENTORY_JSON": inventory,
            "EPM_RESET_APPLY_ENABLED": "1",
            "EPM_RESET_REPLACEMENT_READY": "1",
            "EPM_RESET_ENDPOINTS_RETIRED": "1",
        })
        apply_payload = {"issuer": issuer, "subject": subject,
                         "issuedAt": issued_at,
                         "applicationId": application_id,
                         "idempotencyKey": "laptop-apply-" + run_id}
        result = run([*command, "--profile", "reset-apply", "run", "--rm",
            "--no-deps", "reset-apply", "python", "-c", RESET_APPLY_EFFECT],
            input_text=json.dumps(apply_payload), environment=reset_environment,
            timeout=360)
        applied = json.loads(result.stdout)
    finally:
        replacement.owner.all_up(command, environment)
        replacement.start_browser_gateway(command, environment)
    expected_application_ids = ([] if application_id is None
                                else [application_id])
    if (applied.get("workspaceId") != workspace_id
            or applied.get("applicationIds") != expected_application_ids
            or applied.get("status") != "Deleted"
            or workspace_exists(workspace_id)):
        raise LifecycleError("LAPTOP_RESET_APPLY_MISMATCH")
    return {"workspaceId": workspace_id, "applicationId": application_id,
            "status": "Deleted", "manifestDigest": applied["manifestDigest"],
            "endpointsRetiredDuringApply": True,
            "servicesRestarted": True}


def qualify(state_root: Path) -> dict:
    preflight = public_preflight()
    before = owner_fingerprint()
    run_id = secrets.token_hex(8)
    login_id = "openepm-qualification-" + run_id
    workspace_id, application_id = "uat-w-" + run_id, "uat-a-" + run_id
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
            displayName="Open EPM laptop journey user",
            shortDescription="Run-owned end-to-end laptop qualification",
            semanticDescription=("Disposable native identity for governed "
                                 "application creation and publication.")),
            idempotency_key="laptop-user-create-" + run_id)
        subject = created.get("subjectId")
        if not isinstance(subject, str) or not subject:
            raise LifecycleError("LAPTOP_JOURNEY_SUBJECT_INVALID")
        governed_directory_effect(state_root, directory_program(
            "identity.native-user.password.set", subjectId=subject,
            temporaryPassword=temporary_password),
            idempotency_key="laptop-user-password-" + run_id)
        governed_directory_effect(state_root, directory_program(
            "identity.server-administrator.access.set", subjectId=subject,
            access="Grant"), idempotency_key="laptop-admin-grant-" + run_id)
        authority_granted = True

        with sync_playwright() as playwright:
            # Never attach to or reuse the owner's Chrome installation/profile.
            # Playwright's managed Chromium process and fresh context are owned
            # by this exact disposable qualification run.
            browser = playwright.chromium.launch(headless=True)
            try:
                context = browser.new_context()
                page = context.new_page()
                page.goto(APP_ORIGIN + "/", wait_until="domcontentloaded",
                          timeout=60_000)
                if urlsplit(page.url).hostname != "identity.openepm.dev":
                    raise LifecycleError("LAPTOP_NATIVE_LOGIN_NOT_REACHED")
                page.locator("#username").fill(login_id)
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
                    raise LifecycleError("LAPTOP_BROWSER_TOKEN_STORAGE_PRESENT")
                workflow = page.evaluate(WORKFLOW_JS, run_id)
                if (not isinstance(workflow, dict)
                        or workflow.get("workspaceCreated") is not True
                        or workflow.get("applicationCreated") is not True
                        or workflow.get("blueprintDimensions") != [
                            "Account", "Entity", "Year", "Period", "View", "Value", "Scenario", "DataType"]
                        or workflow.get("memberCount") != 8
                        or workflow.get("jobStatus") != "published"
                        or workflow.get("exactReadback") is not True
                        or workflow.get("amount") != "17.25000000"
                        or workflow.get("applicationVisible") is not True):
                    raise LifecycleError("LAPTOP_APPLICATION_WORKFLOW_INCOMPLETE")
                browser_version = browser.version
                context.close()
            finally:
                browser.close()
        # The direct reset adapter carries the same recently authenticated
        # run-owned identity. Wait past the password-reset epoch's whole-second
        # fence before using its current issued-at boundary.
        time.sleep(1.05)
        cleanup = cleanup_workspace(
            state_root, workspace_id, application_id,
            IDENTITY_ORIGIN + "/realms/openepm", subject,
            int(time.time()), run_id)
    except BaseException as error:
        primary_error = error
    finally:
        if subject is not None:
            # If the main path failed after workspace creation, make one exact
            # cleanup attempt before withdrawing the temporary authority.
            if cleanup is None and workspace_exists(workspace_id):
                try:
                    time.sleep(1.05)
                    cleanup = cleanup_workspace(
                        state_root, workspace_id, application_id,
                        IDENTITY_ORIGIN + "/realms/openepm", subject,
                        int(time.time()), run_id)
                except BaseException as cleanup_error:
                    if primary_error is None:
                        primary_error = cleanup_error
            if authority_granted:
                try:
                    governed_directory_effect(state_root, directory_program(
                        "identity.server-administrator.access.set",
                        subjectId=subject, access="Revoke"),
                        idempotency_key="laptop-admin-revoke-" + run_id)
                except BaseException as revoke_error:
                    if primary_error is None:
                        primary_error = revoke_error
            try:
                governed_directory_effect(state_root, directory_program(
                    "identity.native-user.status.set", subjectId=subject,
                    status="Inactive"),
                    idempotency_key="laptop-user-deactivate-" + run_id)
            except BaseException as deactivate_error:
                if primary_error is None:
                    primary_error = deactivate_error
    after = owner_fingerprint()
    if before != after:
        raise LifecycleError("OWNER_WORKSPACE_FINGERPRINT_CHANGED")
    if primary_error is not None:
        raise primary_error
    if workflow is None or cleanup is None:
        raise LifecycleError("LAPTOP_JOURNEY_INCOMPLETE")
    return {
        "format": "openepm-laptop-application-journey-v1",
        "qualifiedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "browser": "Playwright Chromium", "browserVersion": browser_version,
        "preflight": preflight,
        "governedRunOwnedIdentity": True,
        "temporaryServerAdministratorGranted": True,
        "temporaryServerAdministratorRevoked": True,
        "runOwnedIdentityDeactivated": True,
        "publicCloudflareJourney": True,
        "workspaceCreated": True, "applicationCreated": True,
        "blueprintDimensions": workflow["blueprintDimensions"],
        "metadataMemberCount": workflow["memberCount"],
        "workerPublicationStatus": workflow["jobStatus"],
        "exactReadback": workflow["exactReadback"],
        "readbackAmount": workflow["amount"],
        "diagnostics": {"applicationsStatus": workflow["applicationsStatus"],
                        "applicationVisible": workflow["applicationVisible"]},
        "cleanup": cleanup,
        "ownerWorkspaceBefore": before,
        "ownerWorkspaceAfter": after,
        "ownerWorkspaceUnchanged": True,
        "credentialPrinted": False, "credentialPersisted": False,
    }


def repair_owned_residual(state_root: Path) -> dict:
    """Retire exactly one failed run-owned qualifier scope, fail closed."""
    try:
        residual = json.loads(psql("""SELECT json_build_object(
          'workspaceId',w.workspace_id,'applicationId',a.application_id,
          'issuer',g.issuer,'subject',g.subject_id,'userStatus',u.status,
          'operator',EXISTS(SELECT 1 FROM epm.platform_operator_grant p
            WHERE (p.issuer,p.subject_id)=(g.issuer,g.subject_id)))
        FROM epm.workspace w LEFT JOIN epm.application a USING(workspace_id)
        JOIN epm.workspace_access_grant g USING(workspace_id)
        JOIN epm.identity_user_directory_state u
          ON (u.issuer,u.subject_id)=(g.issuer,g.subject_id)
        WHERE w.workspace_id LIKE 'uat-w-%'"""))
    except json.JSONDecodeError as error:
        raise LifecycleError("LAPTOP_REPAIR_SCOPE_INVALID") from error
    if type(residual) is not dict:
        raise LifecycleError("LAPTOP_REPAIR_SCOPE_INVALID")
    workspace_id = residual.get("workspaceId")
    application_id = residual.get("applicationId")
    issuer, subject = residual.get("issuer"), residual.get("subject")
    if (not isinstance(workspace_id, str)
            or re.fullmatch(r"uat-w-([0-9a-f]{16})", workspace_id) is None
            or application_id not in (
                None, "uat-a-" + workspace_id.removeprefix("uat-w-"))
            or issuer != IDENTITY_ORIGIN + "/realms/openepm"
            or not isinstance(subject, str) or not subject
            or residual.get("userStatus") != "Inactive"
            or residual.get("operator") is not False):
        raise LifecycleError("LAPTOP_REPAIR_SCOPE_INVALID")
    run_id = workspace_id.removeprefix("uat-w-")
    attempt_id = secrets.token_hex(4)
    before = owner_fingerprint()
    cleanup = None
    primary_error: BaseException | None = None
    try:
        governed_directory_effect(state_root, directory_program(
            "identity.native-user.status.set", subjectId=subject,
            status="Active"),
            idempotency_key=("laptop-repair-reactivate-" + run_id + "-"
                             + attempt_id))
        governed_directory_effect(state_root, directory_program(
            "identity.server-administrator.access.set", subjectId=subject,
            access="Grant"),
            idempotency_key=("laptop-repair-admin-grant-" + run_id + "-"
                             + attempt_id))
        time.sleep(1.05)
        cleanup = cleanup_workspace(
            state_root, workspace_id, application_id, issuer, subject,
            int(time.time()), "repair-" + run_id + "-" + attempt_id)
    except BaseException as error:
        primary_error = error
    finally:
        try:
            governed_directory_effect(state_root, directory_program(
                "identity.server-administrator.access.set", subjectId=subject,
                access="Revoke"),
                idempotency_key=("laptop-repair-admin-revoke-" + run_id + "-"
                                 + attempt_id))
        except BaseException as error:
            if primary_error is None:
                primary_error = error
        try:
            governed_directory_effect(state_root, directory_program(
                "identity.native-user.status.set", subjectId=subject,
                status="Inactive"),
                idempotency_key=("laptop-repair-deactivate-" + run_id + "-"
                                 + attempt_id))
        except BaseException as error:
            if primary_error is None:
                primary_error = error
    after = owner_fingerprint()
    if before != after:
        raise LifecycleError("OWNER_WORKSPACE_FINGERPRINT_CHANGED")
    if primary_error is not None:
        raise primary_error
    if cleanup is None or workspace_exists(workspace_id):
        raise LifecycleError("LAPTOP_REPAIR_INCOMPLETE")
    return {
        "format": "openepm-laptop-application-journey-repair-v1",
        "status": "Deleted", "governedRepair": True,
        "temporaryServerAdministratorRevoked": True,
        "runOwnedIdentityDeactivated": True,
        "cleanup": cleanup, "ownerWorkspaceBefore": before,
        "ownerWorkspaceAfter": after, "ownerWorkspaceUnchanged": True,
        "credentialPrinted": False, "credentialPersisted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, default=DEFAULT_STATE)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repair-owned-residual", action="store_true")
    arguments = parser.parse_args()
    if arguments.output.exists() or not arguments.output.is_absolute():
        parser.error("output must be a new absolute path")
    result = (repair_owned_residual(arguments.state_root.resolve())
              if arguments.repair_owned_residual
              else qualify(arguments.state_root.resolve()))
    arguments.output.write_text(json.dumps(result, indent=2, sort_keys=True)
                                + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "format": result["format"],
                      "output": str(arguments.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
