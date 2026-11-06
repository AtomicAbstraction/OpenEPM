#!/usr/bin/env python3
"""Enroll the prepared generation owner through Keycloak and provision it.

The command starts only the private generation, opens the system browser for
Keycloak Authorization Code + S256 PKCE, accepts one exact loopback callback,
and writes a short-lived access token to the owner-only generation directory.
It then immediately provisions the two sample applications through fixed-core
MCP and removes the credential. Passwords, authorization codes, refresh
tokens, login IDs and access tokens are never printed or retained.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from urllib.parse import urlencode

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

import httpx2

from scripts import macos_pilot_owner_uat_controller as owner
from scripts import macos_pilot_programmable_replacement as replacement
from scripts.provision_programmable_private_generation import (
    MINIMUM_CREDENTIAL_LIFETIME_SECONDS,
    PrivateProvisionError,
    credential_directory,
    execute as provision,
)
from scripts.enroll_macos_pilot_load_identity import write_protected_pair
from scripts.qualify_macos_pilot_mcp_oauth import REDIRECT_URI, receive_callback


CLIENT_ID = "openepm-mcp"
LOCAL_IDENTITY_ORIGIN = "http://127.0.0.1:5390"
MAX_TOKEN_BYTES = 16384
IDENTITY_READINESS_TIMEOUT_SECONDS = 120
IDENTITY_READINESS_INTERVAL_SECONDS = 2
ENROLLMENT_CALLBACK_TIMEOUT_SECONDS = 1800
CHROME_BINARY = Path(
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
_chrome_process: subprocess.Popen | None = None
_chrome_profile: Path | None = None


class EnrollmentError(ValueError):
    pass


def _jwt(token: str) -> tuple[dict, dict]:
    parts = token.split(".")
    if len(parts) != 3:
        raise EnrollmentError("PRIVATE_OIDC_TOKEN_NOT_JWT")
    try:
        header = json.loads(base64.urlsafe_b64decode(
            parts[0] + "=" * (-len(parts[0]) % 4)))
        claims = json.loads(base64.urlsafe_b64decode(
            parts[1] + "=" * (-len(parts[1]) % 4)))
    except (ValueError, UnicodeError, json.JSONDecodeError) as exc:
        raise EnrollmentError("PRIVATE_OIDC_TOKEN_INVALID") from exc
    if type(header) is not dict or type(claims) is not dict:
        raise EnrollmentError("PRIVATE_OIDC_TOKEN_INVALID")
    return header, claims


def validate_token(token: str, plan: dict, now: float | None = None) -> dict:
    if (not isinstance(token, str) or not token
            or len(token.encode("utf-8")) > MAX_TOKEN_BYTES
            or any(ord(character) < 33 or ord(character) > 126
                   for character in token)):
        raise EnrollmentError("PRIVATE_OIDC_TOKEN_INVALID")
    header, claims = _jwt(token)
    audiences = claims.get("aud")
    if isinstance(audiences, str):
        audiences = [audiences]
    current = time.time() if now is None else now
    login_id = claims.get("preferred_username")
    if (header.get("alg") != "RS256"
            or str(header.get("typ", "")).lower() != "at+jwt"
            or claims.get("iss") != plan["issuer"]
            or claims.get("sub") != plan["subject"]
            or not isinstance(audiences, list)
            or plan["audience"] not in audiences
            or claims.get("azp") != CLIENT_ID
            or not isinstance(login_id, str)
            or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._@+-]{0,199}", login_id)
            or isinstance(claims.get("exp"), bool)
            or not isinstance(claims.get("exp"), (int, float))
            or claims["exp"] <= current + MINIMUM_CREDENTIAL_LIFETIME_SECONDS):
        raise EnrollmentError("PRIVATE_OIDC_TOKEN_BINDING_MISMATCH")
    return {
        "subject": claims["sub"],
        "issuer": claims["iss"],
        "audience": plan["audience"],
        "clientId": CLIENT_ID,
        "loginIdSha256": hashlib.sha256(
            login_id.encode("utf-8")).hexdigest(),
        "credentialExpiresAt": int(claims["exp"]),
    }


def plan(state_root: Path) -> dict:
    root = state_root.resolve()
    state = replacement.status(argparse.Namespace(state_root=root))
    lifecycle = state.get("state")
    expected_applications = state.get("expectedApplications")
    resumable = (
        (lifecycle == "prepared-empty" and expected_applications == 0)
        or (lifecycle == "provisioning-failed"
            and expected_applications in (1, 2))
    )
    if (not resumable
            or state.get("verified") is not True
            or state.get("preparedRuntime", {}).get("quiesced") is not True):
        raise PrivateProvisionError(
            "private replacement is not quiesced and awaiting enrollment "
            "or an idempotent provisioning resume")
    _command, values = replacement.base(root)
    subject = values.get("EPM_PLATFORM_OPERATOR_SUBJECT")
    issuer = values.get("EPM_OIDC_ISSUER")
    audience = values.get("EPM_OIDC_AUD_MCP")
    if (not isinstance(subject, str) or not subject
            or replacement.oidc_origin(str(issuer))
               != "https://identity.openepm.dev"
            or audience != "openepm-mcp"):
        raise PrivateProvisionError("private OIDC binding differs")
    directory = credential_directory(root)
    credential = directory / "keycloak-access.jwt"
    record = directory / "keycloak-access.record.json"
    if credential.exists() or record.exists():
        raise PrivateProvisionError("private enrollment already exists")
    return {
        "root": root, "subject": subject, "issuer": issuer,
        "audience": audience, "credential": credential, "record": record,
    }


def authorization_url(value: dict, state: str, challenge: str) -> str:
    # Keep the entire browser login on the configured public issuer so
    # Keycloak's host-scoped restart and authentication-session cookies remain
    # valid. Only the final authorization response uses the loopback callback.
    return value["issuer"] + "/protocol/openid-connect/auth?" + urlencode({
        "client_id": CLIENT_ID, "response_type": "code",
        "scope": "openid profile", "redirect_uri": REDIRECT_URI,
        "state": state, "code_challenge": challenge,
        "code_challenge_method": "S256",
    })


async def wait_identity_ready(value: dict, *,
                              timeout_seconds: int =
                              IDENTITY_READINESS_TIMEOUT_SECONDS,
                              interval_seconds: float =
                              IDENTITY_READINESS_INTERVAL_SECONDS,
                              clock=time.monotonic) -> dict:
    if timeout_seconds <= 0 or interval_seconds <= 0:
        raise EnrollmentError("PRIVATE_OIDC_READINESS_TIMING_INVALID")
    deadline = clock() + timeout_seconds
    local = (LOCAL_IDENTITY_ORIGIN
             + "/realms/openepm/.well-known/openid-configuration")
    expected_authorization = (value["issuer"]
                              + "/protocol/openid-connect/auth")
    expected_token = value["issuer"] + "/protocol/openid-connect/token"
    last_error = None
    async with httpx2.AsyncClient(timeout=10, follow_redirects=False) as client:
        while True:
            try:
                response = await client.get(local)
                body = response.json() if response.status_code == 200 else None
                if (type(body) is dict
                        and body.get("issuer") == value["issuer"]
                        and body.get("authorization_endpoint") ==
                            expected_authorization
                        and body.get("token_endpoint") == expected_token
                        and "S256" in
                            body.get("code_challenge_methods_supported", [])):
                    return {"issuer": body["issuer"], "s256": True}
                last_error = EnrollmentError(
                    "PRIVATE_OIDC_DISCOVERY_BINDING_MISMATCH")
            except Exception as exc:
                last_error = exc
            remaining = deadline - clock()
            if remaining <= 0:
                raise EnrollmentError(
                    "PRIVATE_OIDC_READINESS_TIMEOUT") from last_error
            await asyncio.sleep(min(interval_seconds, remaining))


def open_fresh_chrome(url: str, *, new: int = 1,
                      autoraise: bool = True) -> bool:
    """Open the owner flow in a new isolated Chrome process.

    The Mac pilot is qualified only with Chrome. A unique profile makes the
    active enrollment window unambiguous and lets cleanup close only the
    process owned by this attempt.
    """
    global _chrome_process, _chrome_profile
    if (new != 1 or autoraise is not True or not CHROME_BINARY.is_file()
            or not os.access(CHROME_BINARY, os.X_OK)):
        return False
    close_fresh_chrome()
    profile = Path(tempfile.mkdtemp(
        prefix="openepm-enrollment-chrome-", dir="/private/tmp"))
    profile.chmod(0o700)
    try:
        process = subprocess.Popen(
            [str(CHROME_BINARY), "--user-data-dir=" + str(profile),
             "--incognito", "--no-first-run", "--no-default-browser-check",
             "--new-window", url],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        shutil.rmtree(profile, ignore_errors=True)
        return False
    _chrome_process = process
    _chrome_profile = profile
    return process.poll() is None


def close_fresh_chrome() -> None:
    """Close only the enrollment-owned Chrome and remove its local profile."""
    global _chrome_process, _chrome_profile
    process, profile = _chrome_process, _chrome_profile
    _chrome_process = None
    _chrome_profile = None
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if profile is not None:
        shutil.rmtree(profile, ignore_errors=True)


async def enroll(value: dict, *, open_browser=open_fresh_chrome) -> dict:
    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode("ascii").rstrip("=")
    url = authorization_url(value, state, challenge)
    if open_browser(url, new=1, autoraise=True) is not True:
        raise EnrollmentError("PRIVATE_OIDC_BROWSER_OPEN_FAILED")
    try:
        callback = await receive_callback(
            diagnostic=lambda diagnostic: print(
                "CALLBACK_DIAGNOSTIC=" + json.dumps(
                    diagnostic, sort_keys=True, separators=(",", ":")),
                flush=True),
            timeout_seconds=ENROLLMENT_CALLBACK_TIMEOUT_SECONDS)
        if (callback.state != state
                or callback.iss not in (None, value["issuer"])):
            raise EnrollmentError("PRIVATE_OIDC_CALLBACK_BINDING_MISMATCH")
        async with httpx2.AsyncClient(
                timeout=30, follow_redirects=False) as client:
            response = await client.post(
                LOCAL_IDENTITY_ORIGIN
                + "/realms/openepm/protocol/openid-connect/token",
                data={"grant_type": "authorization_code",
                      "client_id": CLIENT_ID, "code": callback.code,
                      "redirect_uri": REDIRECT_URI,
                      "code_verifier": verifier})
    finally:
        if open_browser is open_fresh_chrome:
            close_fresh_chrome()
    if response.status_code != 200:
        raise EnrollmentError("PRIVATE_OIDC_TOKEN_EXCHANGE_FAILED")
    try:
        body = response.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise EnrollmentError("PRIVATE_OIDC_TOKEN_EXCHANGE_FAILED") from exc
    token = body.get("access_token") if isinstance(body, dict) else None
    binding = validate_token(token, value)
    write_protected_pair(value["credential"], value["record"], token + "\n", {
        "format": "openepm-private-oidc-credential-v1",
        "credentialKind": "oidc_access_token", **binding})
    return {"status": "enrolled",
            "credentialRetainedForImmediateProvision": True,
            "credentialPrinted": False, "authorizationCodeRetained": False,
            "refreshTokenRetained": False, "existingSessionInspected": False,
            "subjectMatched": True}


def _remove_pending_credential(value: dict) -> None:
    for path in (value["credential"], value["record"]):
        if path.exists() and not path.is_symlink():
            path.unlink()


async def execute(value: dict, args) -> dict:
    command, environment = replacement.base(value["root"])
    owner.all_up(command, environment)
    enrolled = False
    try:
        readiness = await wait_identity_ready(value)
        enrollment = await enroll(value)
        enrolled = True
        result = provision(argparse.Namespace(
            state_root=value["root"], credential=value["credential"],
            credential_record=value["record"],
            application_manifest=args.application_manifest,
            sample_manifest=args.sample_manifest, output=args.output))
        return {"status": "provisioned", "identityReadiness": readiness,
                "enrollment": enrollment,
                "provisionEvidence": str(args.output),
                "applications": len(result["applications"])}
    finally:
        if enrolled and (value["credential"].exists()
                         or value["record"].exists()):
            _remove_pending_credential(value)
        replacement.quiesce_prepared(command, environment, "keycloak")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, default=
                        replacement.ROOT /
                        "deploy/macos-pilot/.runtime/harmonized-next")
    parser.add_argument("--application-manifest", type=Path, default=
                        replacement.ROOT / "deploy/macos-pilot" /
                        "additional-applications.json")
    parser.add_argument("--sample-manifest", type=Path, default=
                        replacement.ROOT / "deploy/macos-pilot" /
                        "programmable-sample-contents.json")
    parser.add_argument("--output", type=Path, default=
                        replacement.ROOT / "docs/qualifications" /
                        "h13-private-keycloak-provision.json")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    try:
        value = plan(args.state_root)
        result = asyncio.run(execute(value, args)) if args.execute else {
            "status": "prepared-not-run", "issuer": value["issuer"],
            "audience": value["audience"], "browserWillOpen": True,
            "existingSessionInspected": False, "credentialPrinted": False,
            "provisionImmediatelyAfterLogin": True}
    except (EnrollmentError, PrivateProvisionError, OSError,
            ValueError) as exc:
        parser.error(str(exc) or type(exc).__name__)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
