#!/usr/bin/env python3
"""Provision the exact two private UAT cubes through real Chrome and MCP.

This orchestrator automates only the private build-generation bootstrap user.
It uses a fresh isolated Google Chrome profile to complete the required native
password change and public-client S256 flow, hands the short-lived access token
to the existing governed private-MCP provisioner, removes that credential, and
restores the original temporary password for owner UAT.  It never connects to
PostgreSQL or prints/persists passwords, codes, refresh tokens or bearer values.
"""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import secrets
import threading

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
from scripts import provision_programmable_private_generation as private
from scripts import qualify_private_chrome_first_password as chrome
from scripts.openepm_keycloak_bootstrap import KeycloakApi


class ChromeProvisionError(RuntimeError):
    pass


class IsolatedChromeOpener:
    """Start one owned Chrome thread and surface its terminal result."""

    def __init__(self, *, username: str, password: str,
                 replacement_password: str) -> None:
        self.username = username
        self.password = password
        self.replacement_password = replacement_password
        self.thread: threading.Thread | None = None
        self.result: dict | None = None
        self.error: BaseException | None = None

    def __call__(self, url: str, *, new: int = 1,
                 autoraise: bool = True) -> bool:
        if (new != 1 or autoraise is not True or self.thread is not None):
            return False

        def run() -> None:
            try:
                self.result = chrome.chrome_first_password(
                    url, username=self.username, password=self.password,
                    replacement_password=self.replacement_password)
            except BaseException as error:
                self.error = error

        self.thread = threading.Thread(
            target=run, name="openepm-private-chrome-provision", daemon=True)
        self.thread.start()
        return True

    def finish(self, timeout_seconds: int = 120) -> dict:
        if self.thread is None:
            raise ChromeProvisionError("PRIVATE_CHROME_WAS_NOT_STARTED")
        self.thread.join(timeout_seconds)
        if self.thread.is_alive():
            raise ChromeProvisionError("PRIVATE_CHROME_DID_NOT_FINISH")
        if self.error is not None:
            raise ChromeProvisionError(
                "PRIVATE_CHROME_PROVISION_LOGIN_FAILED") from self.error
        if not isinstance(self.result, dict):
            raise ChromeProvisionError("PRIVATE_CHROME_RESULT_INVALID")
        return self.result


def _secrets(root: Path) -> tuple[str, str, str, str]:
    admin_username = chrome._protected(root, "keycloak_admin_username")
    admin_password = chrome._protected(root, "keycloak_admin_password")
    temporary_password = chrome._protected(
        root, "keycloak_initial_admin_password")
    config = json.loads(chrome._protected(
        root, "keycloak_bootstrap_config.json", 16384))
    login_id = config["initialAdministrator"]["username"]
    return admin_username, admin_password, temporary_password, login_id


def restore_owner(value: dict, command: list[str], environment: dict,
                  credentials: tuple[str, str, str, str]) -> None:
    admin_username, admin_password, temporary_password, login_id = credentials
    owner.all_up(command, environment)
    try:
        api = KeycloakApi(enrollment.LOCAL_IDENTITY_ORIGIN)
        admin_token = chrome._admin_token(
            api, admin_username, admin_password)
        chrome.reset_owner_password(
            api=api, admin_token=admin_token, username=login_id,
            expected_subject=value["subject"],
            temporary_password=temporary_password)
    finally:
        replacement.quiesce_prepared(command, environment, "keycloak")


async def execute(value: dict, arguments) -> dict:
    command, environment = replacement.base(value["root"])
    credentials = _secrets(value["root"])
    admin_username, admin_password, temporary_password, login_id = credentials
    replacement_password = "Qp!" + secrets.token_urlsafe(24) + "8b"
    opener = IsolatedChromeOpener(
        username=login_id, password=temporary_password,
        replacement_password=replacement_password)
    provisioned = None
    chrome_result = None
    primary_failure = None
    owner.all_up(command, environment)
    try:
        await enrollment.wait_identity_ready(value)
        api = KeycloakApi(enrollment.LOCAL_IDENTITY_ORIGIN)
        admin_token = chrome._admin_token(api, admin_username, admin_password)
        chrome.reset_owner_password(
            api=api, admin_token=admin_token, username=login_id,
            expected_subject=value["subject"],
            temporary_password=temporary_password)
        await enrollment.enroll(value, open_browser=opener)
        chrome_result = opener.finish()
        provisioned = await asyncio.to_thread(
            private.execute, argparse.Namespace(
                state_root=value["root"], credential=value["credential"],
                credential_record=value["record"],
                application_manifest=arguments.application_manifest,
                sample_manifest=arguments.sample_manifest,
                output=arguments.output))
    except BaseException as error:
        primary_failure = error
        raise
    finally:
        cleanup_failure = None
        # Remove any partially or fully written short-lived credential even
        # when enrollment failed before returning to this orchestrator.
        if value["credential"].exists() or value["record"].exists():
            try:
                enrollment._remove_pending_credential(value)
            except BaseException as error:
                cleanup_failure = error
        try:
            restore_owner(value, command, environment, credentials)
        except BaseException as error:
            cleanup_failure = cleanup_failure or error
        if cleanup_failure is not None:
            raise ChromeProvisionError(
                "PRIVATE_CHROME_PROVISION_CLEANUP_FAILED") from (
                    primary_failure or cleanup_failure)
    if provisioned is None or chrome_result is None:
        raise ChromeProvisionError("PRIVATE_CHROME_PROVISION_RESULT_INVALID")
    record = json.loads(arguments.output.read_text(encoding="utf-8"))
    record["chromeEnrollment"] = {
        **chrome_result,
        "nativeUserIdAndPassword": True,
        "pkceMethod": "S256",
        "credentialRetained": False,
        "originalTemporaryPasswordRestored": True,
        "existingChromeSessionInspected": False,
    }
    owner.write_json(arguments.output, record)
    return {
        "format": "openepm-private-chrome-provision-result-v1",
        "status": "provisioned",
        "applications": len(provisioned["applications"]),
        "chrome": chrome_result,
        "credentialRetained": False,
        "originalTemporaryPasswordRestored": True,
        "databaseAccess": False,
        "businessMutationBoundary": "authenticated fixed-core private MCP",
        "output": str(arguments.output),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, default=
                        replacement.ROOT / "deploy/macos-pilot/.runtime"
                        / "harmonized-next")
    parser.add_argument("--application-manifest", type=Path, default=
                        replacement.ROOT / "deploy/macos-pilot"
                        / "additional-applications.json")
    parser.add_argument("--sample-manifest", type=Path, default=
                        replacement.ROOT / "deploy/macos-pilot"
                        / "programmable-sample-contents.json")
    parser.add_argument("--output", type=Path, default=
                        replacement.ROOT / "docs/qualifications"
                        / "h13-private-keycloak-provision.json")
    arguments = parser.parse_args()
    try:
        value = enrollment.plan(arguments.state_root.resolve())
        result = asyncio.run(execute(value, arguments))
    except (ChromeProvisionError, chrome.ChromeQualificationError,
            enrollment.EnrollmentError, private.PrivateProvisionError,
            replacement.ReplacementError, OSError, ValueError) as error:
        parser.error(str(error) or type(error).__name__)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
