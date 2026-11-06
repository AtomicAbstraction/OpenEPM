#!/usr/bin/env python3
"""Enroll one real Mac-pilot load identity without exposing credentials."""
from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time
from urllib.parse import urlsplit

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

import httpx2
from mcp import ClientSession
from mcp.client.auth import OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import OAuthClientMetadata

from scripts.qualify_macos_pilot_mcp_oauth import (
    ENDPOINTS, MemoryStorage, REDIRECT_URI, receive_callback,
)


LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_MINIMUM_LIFETIME = 60 + 1800 + 120
TOKEN_BUNDLE_FORMAT = "openepm-oauth-token-bundle-v2"


class EnrollmentError(ValueError):
    pass


def _claims(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise EnrollmentError("PILOT_ENROLLMENT_TOKEN_NOT_JWT")
    try:
        value = json.loads(base64.urlsafe_b64decode(
            parts[1] + "=" * (-len(parts[1]) % 4)))
    except Exception as error:
        raise EnrollmentError("PILOT_ENROLLMENT_TOKEN_INVALID") from error
    if type(value) is not dict:
        raise EnrollmentError("PILOT_ENROLLMENT_TOKEN_INVALID")
    return value


def validate_claims(token: str, *, issuer: str, audience: str,
                    login_id_sha256: str, minimum_lifetime: int,
                    now: float | None = None) -> dict:
    claims = _claims(token)
    audiences = claims.get("aud")
    if not isinstance(audiences, list):
        audiences = [audiences]
    login_id = claims.get("preferred_username")
    observed_login_digest = (hashlib.sha256(login_id.encode()).hexdigest()
                             if isinstance(login_id, str) and login_id else None)
    current = time.time() if now is None else now
    if (claims.get("iss") != issuer or audience not in audiences
            or not isinstance(claims.get("sub"), str) or not claims["sub"]
            or observed_login_digest != login_id_sha256
            or not isinstance(claims.get("exp"), (int, float))
            or claims["exp"] <= current + minimum_lifetime):
        raise EnrollmentError("PILOT_ENROLLMENT_CLAIMS_MISMATCH")
    return claims


def validate_verified_identity(value: object, *, issuer: str, audience: str,
                               login_id_sha256: str) -> dict:
    if (type(value) is not dict
            or set(value) != {"issuer", "subject", "loginIdSha256", "audience"}
            or value.get("issuer") != issuer
            or value.get("audience") != audience
            or value.get("loginIdSha256") != login_id_sha256
            or not isinstance(value.get("subject"), str)
            or not 1 <= len(value["subject"]) <= 300
            or value["subject"] != value["subject"].strip()
            or any(ord(char) < 32 for char in value["subject"])):
        raise EnrollmentError("PILOT_ENROLLMENT_VERIFIED_IDENTITY_MISMATCH")
    return value


def _safe_output(path: Path) -> Path:
    if not path.is_absolute():
        raise EnrollmentError("PILOT_ENROLLMENT_OUTPUT_NOT_ABSOLUTE")
    parent = path.parent
    if (not parent.is_dir() or parent.is_symlink()
            or stat.S_IMODE(parent.stat().st_mode) & 0o077):
        raise EnrollmentError("PILOT_ENROLLMENT_PARENT_UNSAFE")
    if path.exists() or path.is_symlink():
        raise EnrollmentError("PILOT_ENROLLMENT_OUTPUT_EXISTS")
    return path


def _write_temp(target: Path, content: str) -> Path:
    temporary = target.with_name(
        "." + target.name + ".tmp-" + os.urandom(8).hex())
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    if stat.S_IMODE(temporary.stat().st_mode) != 0o600:
        temporary.unlink(missing_ok=True)
        raise EnrollmentError("PILOT_ENROLLMENT_MODE_INVALID")
    return temporary


def write_protected_pair(credential_path: Path, roster_path: Path,
                         credential: str, roster: dict) -> None:
    credential_path = _safe_output(credential_path)
    roster_path = _safe_output(roster_path)
    if credential_path == roster_path:
        raise EnrollmentError("PILOT_ENROLLMENT_OUTPUTS_COLLIDE")
    temporary: list[Path] = []
    committed: list[Path] = []
    try:
        temporary.append(_write_temp(credential_path, credential))
        temporary.append(_write_temp(
            roster_path, json.dumps(roster, indent=2, sort_keys=True) + "\n"))
        for source, destination in zip(temporary,
                                       (credential_path, roster_path)):
            # Hard-link creation is an atomic no-clobber commit because the
            # temporary file is in the same protected directory.  os.replace
            # would permit a race to overwrite a path created after validation.
            os.link(source, destination, follow_symlinks=False)
            source.unlink()
            committed.append(destination)
        temporary.clear()
        directories = {credential_path.parent, roster_path.parent}
        for directory in directories:
            descriptor = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except BaseException:
        for path in temporary:
            path.unlink(missing_ok=True)
        for path in committed:
            path.unlink(missing_ok=True)
        raise


def build_outputs(*, label: str, issuer: str, audience: str,
                  login_id_sha256: str, minimum_lifetime: int,
                  credential_path: Path, tokens, client_info,
                  token_endpoint: str | None,
                  verified_identity: dict | None = None,
                  token_received_at: float | None = None,
                  now: float | None = None
                  ) -> tuple[str, dict, str]:
    if LABEL.fullmatch(label) is None or SHA256.fullmatch(login_id_sha256) is None:
        raise EnrollmentError("PILOT_ENROLLMENT_IDENTITY_INVALID")
    if (not tokens or not isinstance(tokens.access_token, str)
            or not tokens.access_token):
        raise EnrollmentError("PILOT_ENROLLMENT_OAUTH_STATE_MISSING")
    current = time.time() if now is None else now
    endpoint = urlsplit(token_endpoint) if token_endpoint else None
    issuer_url = urlsplit(issuer)
    refreshable = bool(tokens.refresh_token and client_info
        and client_info.client_id and endpoint
        and endpoint.scheme == "https" and endpoint.netloc == issuer_url.netloc
        and not endpoint.username and not endpoint.password
        and not endpoint.fragment)
    verified = (validate_verified_identity(
        verified_identity, issuer=issuer, audience=audience,
        login_id_sha256=login_id_sha256) if verified_identity is not None else None)
    claims = None
    try:
        _claims(tokens.access_token)
    except EnrollmentError:
        # OAuth access tokens are allowed to be opaque even when their
        # alphabet happens to contain two dots. The server-verified
        # self-binding remains authoritative for an unparseable token.
        pass
    else:
        # Once the token has a parseable JWT claim object, claim mismatches
        # are security failures rather than a reason to relabel it opaque.
        claims = validate_claims(
            tokens.access_token, issuer=issuer, audience=audience,
            login_id_sha256=login_id_sha256,
            minimum_lifetime=60 if refreshable else minimum_lifetime,
            now=current)
    token_kind = "jwt" if claims is not None else "opaque"
    if claims is not None:
        if verified is not None and claims["sub"] != verified["subject"]:
            raise EnrollmentError("PILOT_ENROLLMENT_VERIFIED_IDENTITY_MISMATCH")
        subject = claims["sub"]
        access_expires_at = int(claims["exp"])
    else:
        if (verified is None or len(tokens.access_token) > 16384
                or any(ord(char) < 33 or ord(char) > 126
                       for char in tokens.access_token)
                or isinstance(tokens.expires_in, bool)
                or not isinstance(tokens.expires_in, int)
                or tokens.expires_in <= 0):
            raise EnrollmentError("PILOT_ENROLLMENT_OPAQUE_TOKEN_INVALID")
        subject = verified["subject"]
        received_at = (current if token_received_at is None
                       else token_received_at)
        if (isinstance(received_at, bool)
                or not isinstance(received_at, (int, float))
                or received_at > current or received_at <= 0):
            raise EnrollmentError("PILOT_ENROLLMENT_OPAQUE_TOKEN_INVALID")
        access_expires_at = int(received_at) + tokens.expires_in
        required = 60 if refreshable else minimum_lifetime
        if access_expires_at <= current + required:
            raise EnrollmentError("PILOT_ENROLLMENT_OPAQUE_TOKEN_LIFETIME")
    kind = "static_jwt"
    credential = tokens.access_token + "\n"
    if refreshable:
        kind = "refreshable_oauth_bundle_v2"
        credential = json.dumps({
            "format": TOKEN_BUNDLE_FORMAT,
            "tokenKind": token_kind,
            "accessToken": tokens.access_token,
            "accessExpiresAt": access_expires_at,
            "refresh": {"token": tokens.refresh_token,
                        "clientId": client_info.client_id,
                        "tokenEndpoint": token_endpoint},
        }, sort_keys=True) + "\n"
    elif token_kind == "opaque":
        kind = "static_opaque_bundle_v2"
        credential = json.dumps({
            "format": TOKEN_BUNDLE_FORMAT,
            "tokenKind": token_kind,
            "accessToken": tokens.access_token,
            "accessExpiresAt": access_expires_at,
            "refresh": None,
        }, sort_keys=True) + "\n"
    subject_digest = hashlib.sha256(subject.encode()).hexdigest()
    roster = {
        "format": "openepm-macos-pilot-load-identity-v1",
        "label": label,
        "subject": subject,
        "subjectSha256": subject_digest,
        "issuer": issuer,
        "audience": audience,
        "loginIdSha256": login_id_sha256,
        "credentialFile": str(credential_path),
        "credentialKind": kind,
        "expiresAt": access_expires_at,
    }
    return credential, roster, kind


async def enroll(*, label: str, issuer: str, audience: str,
                 login_id_sha256: str, minimum_lifetime: int,
                 credential_path: Path, roster_path: Path) -> dict:
    storage = MemoryStorage()

    async def redirect_handler(url: str) -> None:
        print("AUTHORIZATION_URL=" + url, flush=True)

    provider = OAuthClientProvider(
        ENDPOINTS["application"],
        OAuthClientMetadata(
            client_name="Open EPM pilot load identity enrollment",
            redirect_uris=[REDIRECT_URI],
            grant_types=["authorization_code", "refresh_token"],
            token_endpoint_auth_method="none"),
        storage, redirect_handler=redirect_handler,
        callback_handler=receive_callback)
    async with httpx2.AsyncClient(auth=provider, follow_redirects=True) as client:
        async with streamable_http_client(
                ENDPOINTS["application"], http_client=client) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                tools = {tool.name for tool in (await session.list_tools()).tools}
                if "read_v2_session_identity" not in tools:
                    raise EnrollmentError(
                        "PILOT_ENROLLMENT_IDENTITY_TOOL_UNAVAILABLE")
                identity_result = await session.call_tool(
                    "read_v2_session_identity", {})
                if identity_result.is_error:
                    raise EnrollmentError(
                        "PILOT_ENROLLMENT_IDENTITY_TOOL_FAILED")
                verified_identity = identity_result.structured_content
                if verified_identity is None:
                    try:
                        verified_identity = json.loads(
                            identity_result.content[0].text)
                    except (AttributeError, IndexError, TypeError,
                            json.JSONDecodeError) as error:
                        raise EnrollmentError(
                            "PILOT_ENROLLMENT_IDENTITY_TOOL_INVALID") from error
    metadata = provider.context.oauth_metadata
    token_endpoint = (str(metadata.token_endpoint)
                      if metadata and metadata.token_endpoint else None)
    credential, roster, kind = build_outputs(
        label=label, issuer=issuer, audience=audience,
        login_id_sha256=login_id_sha256, minimum_lifetime=minimum_lifetime,
        credential_path=credential_path, tokens=storage.tokens,
        client_info=storage.client_info, token_endpoint=token_endpoint,
        verified_identity=verified_identity,
        token_received_at=storage.tokens_received_at)
    write_protected_pair(credential_path, roster_path, credential, roster)
    return {"passed": True, "label": label, "credentialKind": kind,
            "subjectSha256": roster["subjectSha256"],
            "businessMutationPerformed": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--audience", required=True)
    parser.add_argument("--expected-login-id-sha256", required=True)
    parser.add_argument("--credential-output", required=True, type=Path)
    parser.add_argument("--roster-output", required=True, type=Path)
    parser.add_argument("--minimum-lifetime", type=int,
                        default=DEFAULT_MINIMUM_LIFETIME)
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    try:
        if arguments.minimum_lifetime < DEFAULT_MINIMUM_LIFETIME:
            raise EnrollmentError("PILOT_ENROLLMENT_LIFETIME_TOO_SHORT")
        _safe_output(arguments.credential_output)
        _safe_output(arguments.roster_output)
        if not arguments.execute:
            print(json.dumps({"execute": False, "label": arguments.label,
                              "businessMutationPerformed": False},
                             sort_keys=True))
            return 0
        result = asyncio.run(enroll(
            label=arguments.label, issuer=arguments.issuer,
            audience=arguments.audience,
            login_id_sha256=arguments.expected_login_id_sha256,
            minimum_lifetime=arguments.minimum_lifetime,
            credential_path=arguments.credential_output,
            roster_path=arguments.roster_output))
    except (EnrollmentError, OSError, RuntimeError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
