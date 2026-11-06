#!/usr/bin/env python3
"""Prepare or execute the authorized 10-identity Mac pilot load profile."""
from __future__ import annotations

import argparse
import asyncio
import base64
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from epm_core.macos_pilot_load import (MacPilotLoadContract, MacPilotLoadEngine,
                                       PilotLoadError, _at, _expand,
                                       _application_roles, AGENT_ROLES,
                                       HUMAN_ROLES)


def _write_evidence(path: Path, value: dict) -> None:
    """Create one immutable-at-run, owner-only qualification result.

    Qualification output must never replace earlier evidence or follow a path
    substituted after contract validation.  The caller can select a fresh
    filename for another attempt; preserving failed attempts is part of the
    evidence model.
    """
    path = Path(path)
    parent = path.parent
    if (not path.is_absolute() or path.suffix != ".json"
            or not parent.is_dir() or parent.is_symlink()):
        raise PilotLoadError("PILOT_EVIDENCE_PATH_UNSAFE")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, stat.S_IRUSR | stat.S_IWUSR)
    except FileExistsError as error:
        raise PilotLoadError("PILOT_EVIDENCE_ALREADY_EXISTS") from error
    except OSError as error:
        raise PilotLoadError("PILOT_EVIDENCE_CREATE_FAILED") from error
    payload = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        directory = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def _jwt_claims(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise PilotLoadError("PILOT_IDENTITY_TOKEN_NOT_JWT")
    try:
        return json.loads(base64.urlsafe_b64decode(
            parts[1] + "=" * (-len(parts[1]) % 4)))
    except Exception as error:
        raise PilotLoadError("PILOT_IDENTITY_TOKEN_INVALID") from error


@dataclass
class _CredentialState:
    subject: str
    access_token: str
    token_kind: str
    access_expires_at: float
    refresh_token: str | None
    client_id: str | None
    token_endpoint: str | None
    bundle_version: int
    clients: list[object] = field(default_factory=list)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


@dataclass
class _GatewaySession:
    stack: AsyncExitStack
    client: object
    http: object
    credential: _CredentialState


class PublicMcpGateway:
    def __init__(self, target: dict, *, required_session_seconds: float):
        self.target = target
        self.required_session_seconds = required_session_seconds
        self._subject_digests: dict[str, str] = {}
        self._digest_subjects: dict[str, str] = {}
        self._credentials: dict[str, _CredentialState] = {}

    def _validate_access(self, subject: str, token: str, *,
                         minimum_seconds: float | None) -> dict:
        claims = _jwt_claims(token)
        audience = claims.get("aud")
        audiences = audience if isinstance(audience, list) else [audience]
        if (claims.get("sub") != subject
                or claims.get("iss") != self.target["oidcIssuer"]
                or self.target["oidcAudience"] not in audiences
                or not isinstance(claims.get("exp"), (int, float))
                or (minimum_seconds is not None
                    and claims["exp"] <= time.time() + minimum_seconds)):
            raise PilotLoadError("PILOT_IDENTITY_CLAIMS_MISMATCH")
        return claims

    def _load_credential(self, subject: str, token_file: str) -> tuple[
            _CredentialState, str]:
        raw = Path(token_file).read_text().strip()
        digest = __import__("hashlib").sha256(raw.encode()).hexdigest()
        try:
            bundle = json.loads(raw)
        except json.JSONDecodeError:
            bundle = None
        if bundle is None:
            claims = self._validate_access(subject, raw,
                minimum_seconds=self.required_session_seconds)
            state = _CredentialState(subject, raw, "jwt", claims["exp"],
                                     None, None, None, 0)
        elif (type(bundle) is dict
              and bundle.get("format") == "openepm-oauth-token-bundle-v2"):
            expected = {"format", "tokenKind", "accessToken",
                        "accessExpiresAt", "refresh"}
            refresh = bundle.get("refresh")
            if (type(bundle) is not dict or set(bundle) != expected
                    or bundle["tokenKind"] not in {"jwt", "opaque"}
                    or not isinstance(bundle["accessToken"], str)
                    or not bundle["accessToken"]
                    or len(bundle["accessToken"]) > 16384
                    or any(ord(char) < 33 or ord(char) > 126
                           for char in bundle["accessToken"])
                    or isinstance(bundle["accessExpiresAt"], bool)
                    or not isinstance(bundle["accessExpiresAt"], int)
                    or (refresh is not None and (
                        type(refresh) is not dict
                        or set(refresh) != {"token", "clientId",
                                            "tokenEndpoint"}
                        or not all(isinstance(refresh[key], str)
                                   and refresh[key] for key in refresh)))):
                raise PilotLoadError("PILOT_IDENTITY_BUNDLE_INVALID")
            minimum = 60 if refresh else self.required_session_seconds
            if bundle["accessExpiresAt"] <= time.time() + minimum:
                raise PilotLoadError("PILOT_IDENTITY_CLAIMS_MISMATCH")
            if bundle["tokenKind"] == "jwt":
                claims = self._validate_access(
                    subject, bundle["accessToken"], minimum_seconds=minimum)
                if claims["exp"] != bundle["accessExpiresAt"]:
                    raise PilotLoadError("PILOT_IDENTITY_CLAIMS_MISMATCH")
            if refresh:
                self._validate_token_endpoint(refresh["tokenEndpoint"])
            state = _CredentialState(
                subject, bundle["accessToken"], bundle["tokenKind"],
                bundle["accessExpiresAt"],
                refresh["token"] if refresh else None,
                refresh["clientId"] if refresh else None,
                refresh["tokenEndpoint"] if refresh else None, 2)
        else:
            expected = {"format", "accessToken", "refreshToken", "clientId",
                        "tokenEndpoint"}
            if (type(bundle) is not dict or set(bundle) != expected
                    or bundle["format"] != "openepm-oidc-token-bundle-v1"
                    or not all(isinstance(bundle[key], str) and bundle[key]
                               for key in expected - {"format"})):
                raise PilotLoadError("PILOT_IDENTITY_BUNDLE_INVALID")
            self._validate_token_endpoint(bundle["tokenEndpoint"])
            claims = self._validate_access(subject, bundle["accessToken"],
                                           minimum_seconds=60)
            state = _CredentialState(subject, bundle["accessToken"], "jwt",
                claims["exp"], bundle["refreshToken"], bundle["clientId"],
                bundle["tokenEndpoint"], 1)
        return state, digest

    def _validate_token_endpoint(self, value: str) -> None:
        endpoint = urlsplit(value)
        issuer = urlsplit(self.target["oidcIssuer"])
        if (endpoint.scheme != "https" or endpoint.netloc != issuer.netloc
                or endpoint.username or endpoint.password or endpoint.fragment):
            raise PilotLoadError("PILOT_IDENTITY_TOKEN_ENDPOINT_INVALID")

    async def _session_identity(self, client, state: _CredentialState) -> None:
        result = await client.call_tool("read_v2_session_identity", {})
        if result.is_error:
            raise PilotLoadError("PILOT_IDENTITY_SELF_BINDING_FAILED")
        try:
            value = (result.structured_content
                     or json.loads(result.content[0].text))
        except (AttributeError, IndexError, TypeError,
                ValueError, json.JSONDecodeError) as error:
            raise PilotLoadError("PILOT_IDENTITY_SELF_BINDING_INVALID") from error
        expected = {"issuer", "subject", "loginIdSha256", "audience"}
        if (type(value) is not dict or set(value) != expected
                or value["issuer"] != self.target["oidcIssuer"]
                or value["audience"] != self.target["oidcAudience"]
                or value["subject"] != state.subject
                or not re.fullmatch(r"[0-9a-f]{64}",
                                    str(value["loginIdSha256"]))):
            raise PilotLoadError("PILOT_IDENTITY_SELF_BINDING_MISMATCH")

    async def _ensure_access(self, state: _CredentialState,
                             identity_client=None) -> None:
        async with state.lock:
            if state.token_kind == "jwt":
                claims = self._validate_access(
                    state.subject, state.access_token, minimum_seconds=None)
                if claims["exp"] != state.access_expires_at:
                    raise PilotLoadError("PILOT_IDENTITY_CLAIMS_MISMATCH")
            if state.access_expires_at > time.time() + 120:
                return
            if not state.refresh_token:
                raise PilotLoadError("PILOT_IDENTITY_REFRESH_REQUIRED")
            import httpx
            async with httpx.AsyncClient(timeout=30,
                                         follow_redirects=False) as client:
                response = await client.post(state.token_endpoint, data={
                    "grant_type": "refresh_token",
                    "refresh_token": state.refresh_token,
                    "client_id": state.client_id,
                }, headers={"Accept": "application/json"})
            if response.status_code != 200:
                raise PilotLoadError("PILOT_IDENTITY_REFRESH_FAILED")
            try:
                payload = response.json()
            except (TypeError, ValueError) as error:
                raise PilotLoadError("PILOT_IDENTITY_REFRESH_INVALID") from error
            if (type(payload) is not dict
                    or not isinstance(payload.get("access_token"), str)
                    or not payload["access_token"]
                    or (state.bundle_version == 2 and (
                        isinstance(payload.get("expires_in"), bool)
                        or not isinstance(payload.get("expires_in"), int)
                        or payload["expires_in"] <= 120))
                    or ("refresh_token" in payload and not isinstance(
                        payload["refresh_token"], str))
                    or ("refresh_token" in payload
                        and not payload["refresh_token"])):
                raise PilotLoadError("PILOT_IDENTITY_REFRESH_INVALID")
            if state.token_kind == "jwt":
                claims = self._validate_access(
                    state.subject, payload["access_token"], minimum_seconds=60)
                expires_at = claims["exp"]
                if state.bundle_version == 2 and abs(
                        expires_at - (time.time() + payload["expires_in"])) > 5:
                    raise PilotLoadError("PILOT_IDENTITY_REFRESH_INVALID")
            else:
                if identity_client is None:
                    raise PilotLoadError("PILOT_IDENTITY_SELF_BINDING_REQUIRED")
                expires_at = time.time() + payload["expires_in"]
            prior_headers = [(http, http.headers.get("Authorization"))
                             for http in state.clients]
            for http in state.clients:
                http.headers["Authorization"] = "Bearer " + payload["access_token"]
            try:
                if identity_client is not None:
                    await self._session_identity(identity_client, state)
            except BaseException:
                for http, previous in prior_headers:
                    if previous is None:
                        http.headers.pop("Authorization", None)
                    else:
                        http.headers["Authorization"] = previous
                raise
            state.access_token = payload["access_token"]
            state.access_expires_at = expires_at
            if payload.get("refresh_token"):
                state.refresh_token = payload["refresh_token"]

    async def open(self, subject: str, token_file: str):
        import httpx
        from mcp import ClientSession
        from mcp.client.streamable_http import streamable_http_client

        loaded, digest = self._load_credential(subject, token_file)
        if (subject in self._subject_digests and
                self._subject_digests[subject] != digest) or (
                digest in self._digest_subjects and
                self._digest_subjects[digest] != subject):
            raise PilotLoadError("PILOT_IDENTITY_CREDENTIAL_NOT_DISTINCT")
        state = self._credentials.get(subject, loaded)
        stack = AsyncExitStack()
        http = None
        try:
            http = await stack.enter_async_context(httpx.AsyncClient(
                headers={"Authorization": "Bearer " + state.access_token},
                timeout=120))
            state.clients.append(http)
            streams = await stack.enter_async_context(streamable_http_client(
                self.target["mcpUrl"], http_client=http))
            client = await stack.enter_async_context(
                ClientSession(streams[0], streams[1]))
            await client.initialize()
            await self._session_identity(client, state)
        except BaseException:
            if http in state.clients:
                state.clients.remove(http)
            await stack.aclose()
            raise
        # Commit the process-local distinctness maps only after the transport
        # and server-verified self-binding succeed. A transient failed open
        # must not poison a corrected retry in the same qualification process.
        self._subject_digests[subject] = digest
        self._digest_subjects[digest] = subject
        self._credentials.setdefault(subject, state)
        return _GatewaySession(stack, client, http, state)

    async def call(self, session, tool: str, arguments: dict) -> dict:
        await self._ensure_access(session.credential, session.client)
        result = await session.client.call_tool(tool, arguments)
        if result.is_error:
            raise RuntimeError(f"MCP {tool} failed: {result.content}")
        return result.structured_content or json.loads(result.content[0].text)

    async def call_expect_denied(self, session, tool: str, arguments: dict,
                                 contains: str) -> None:
        await self._ensure_access(session.credential, session.client)
        result = await session.client.call_tool(tool, arguments)
        messages = [getattr(item, "text", str(item)) for item in result.content]
        if not result.is_error or not any(contains in message for message in messages):
            raise RuntimeError("revoked identity retained access or wrong denial returned")

    async def tools(self, session) -> set[str]:
        await self._ensure_access(session.credential, session.client)
        result = await session.client.list_tools()
        return {item.name for item in result.tools}

    async def close(self, session) -> None:
        if session.http in session.credential.clients:
            session.credential.clients.remove(session.http)
        await session.stack.aclose()


class MacPilotSampler:
    def __init__(self, contract: MacPilotLoadContract, gateway: PublicMcpGateway):
        self.raw, self.gateway = contract.raw, gateway
        self._session = None
        self._seen_waits: set[str] = set()

    @staticmethod
    def _bytes(value: str) -> float:
        match = re.fullmatch(r"([0-9.]+)([KMGTP]?i?B)", value.strip())
        if not match:
            raise RuntimeError("Docker resource size is invalid")
        scale = {"B": 1, "KB": 1000, "MB": 1000**2, "GB": 1000**3,
            "TB": 1000**4, "KiB": 1024, "MiB": 1024**2,
            "GiB": 1024**3, "TiB": 1024**4}
        return float(match.group(1)) * scale[match.group(2)]

    async def _metrics_session(self):
        if self._session is None:
            subject = self.raw["controls"]["controlSubject"]
            identity = next(item for item in self.raw["identities"]
                            if item["subject"] == subject)
            self._session = await self.gateway.open(subject, identity["tokenFile"])
        return self._session

    async def sample(self) -> dict:
        target = self.raw["target"]
        prefix = ["docker", "compose", "--project-name", target["composeProject"],
                  "--file", target["composeFile"]]
        ids = []
        for service in target["sampleServices"]:
            rows = subprocess.check_output([*prefix, "ps", "-q", service],
                                           text=True).splitlines()
            if len(rows) != 1:
                raise RuntimeError("Mac pilot service inventory is incomplete")
            ids.extend(rows)
        if len(ids) != len(set(ids)):
            raise RuntimeError("Mac pilot service inventory contains duplicates")
        stats = [json.loads(line) for line in subprocess.check_output(
            ["docker", "stats", "--no-stream", "--format", "{{json .}}", *ids],
            text=True).splitlines()]
        if len(stats) != 6:
            raise RuntimeError("Mac pilot resource sample is incomplete")
        memory = sum(self._bytes(row["MemUsage"].split("/")[0]) for row in stats)
        cpu = sum(float(row["CPUPerc"].rstrip("%")) for row in stats)
        writable = 0
        for container in ids:
            size = subprocess.check_output(["docker", "inspect", "--size", "--format",
                "{{.SizeRw}}", container], text=True).strip()
            if not size.isdecimal():
                raise RuntimeError("Mac pilot writable-size sample is invalid")
            writable += int(size)

        session = await self._metrics_session()
        values = []
        for app in self.raw["applications"]:
            result = await self.gateway.call(session, "read_v2_capacity_metrics", {
                "workspace_id": app["workspaceId"],
                "application_id": app["applicationId"]})
            if not isinstance(result, dict) or result.get("scope") != {
                    "workspaceId": app["workspaceId"],
                    "applicationId": app["applicationId"]}:
                raise RuntimeError("application capacity metrics scope is invalid")
            values.append(result)
        queue_depths: dict[str, int] = {}
        queue_waits: dict[str, list[float]] = {}
        for value in values:
            for family, count in value["queueDepths"].items():
                queue_depths[family] = queue_depths.get(family, 0) + int(count)
            for family, rows in value["queueWaitSamples"].items():
                for row in rows:
                    sample_id = str(row["sampleId"])
                    if sample_id not in self._seen_waits:
                        self._seen_waits.add(sample_id)
                        queue_waits.setdefault(family, []).append(
                            int(row["microseconds"]) / 1_000_000)
        database_temp = max(int(value.get("databaseTempBytes", 0)) for value in values)
        return {"connections": max(int(value["connections"]) for value in values),
            "memoryGiB": memory / 1024**3,
            "temporaryDiskGiB": (writable + database_temp) / 1024**3,
            "cpuPercent": cpu, "queueDepths": queue_depths,
            "queueWaitSamples": queue_waits, "serviceCount": 6}

    async def close(self) -> None:
        if self._session is not None:
            await self.gateway.close(self._session)
            self._session = None


class PublicBrowserProbe:
    """Measure the rendered React presentation with one protected human token."""
    def __init__(self, profile: dict, *, required_session_seconds: float = 0):
        self.profile = profile
        self.required_session_seconds = required_session_seconds
        self._playwright = self._browser = self._context = self._page = None
        self._console_errors: list[str] = []

    @staticmethod
    def _token(path_value: str) -> str:
        path = Path(path_value)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                    or not 1 <= metadata.st_size <= 16384):
                raise PilotLoadError("PILOT_BROWSER_TOKEN_UNSAFE")
            raw = os.read(descriptor, 16385)
        finally:
            os.close(descriptor)
        try:
            value = raw.decode("utf-8").strip()
        except UnicodeError as error:
            raise PilotLoadError("PILOT_BROWSER_TOKEN_INVALID") from error
        if (not value or len(value) > 16384
                or any(character.isspace() for character in value)):
            raise PilotLoadError("PILOT_BROWSER_TOKEN_INVALID")
        return value

    async def open(self) -> None:
        if self._page is not None:
            raise PilotLoadError("PILOT_BROWSER_ALREADY_OPEN")
        try:
            from playwright.async_api import async_playwright
        except ImportError as error:
            raise PilotLoadError("PILOT_BROWSER_PLAYWRIGHT_UNAVAILABLE") from error
        token = self._token(self.profile["credentialFile"])
        self._playwright = await async_playwright().start()
        try:
            self._browser = await self._playwright.chromium.launch(headless=True)
            self._context = await self._browser.new_context(
                extra_http_headers={"Authorization": "Bearer " + token})
            self._page = await self._context.new_page()
            self._page.on("console", lambda message: self._console_errors.append(
                message.text) if message.type == "error" else None)
            self._page.on("pageerror", lambda error:
                self._console_errors.append(str(error)))
        except BaseException:
            await self.close()
            raise

    async def sample(self) -> dict:
        if self._page is None:
            raise PilotLoadError("PILOT_BROWSER_NOT_OPEN")
        self._console_errors.clear()
        started = time.monotonic()
        response = await self._page.goto(self.profile["webOrigin"],
            wait_until="domcontentloaded", timeout=60000)
        navigation = time.monotonic() - started
        if response is None or response.status != 200:
            raise PilotLoadError("PILOT_BROWSER_PAGE_FAILED")
        api_started = time.monotonic()
        api = await self._page.evaluate("""async () => {
          const response = await fetch('/api/applications', {
            credentials: 'same-origin'
          });
          let value = null;
          try { value = await response.json(); } catch (_) {}
          const identityResponse = await fetch('/api/session-identity', {
            credentials: 'same-origin'
          });
          let identity = null;
          try { identity = await identityResponse.json(); } catch (_) {}
          return {status: response.status, value,
            identityStatus: identityResponse.status, identity};
        }""")
        applications_elapsed = time.monotonic() - api_started
        applications = (api.get("value", {}).get("applications")
            if isinstance(api, dict) and isinstance(api.get("value"), dict)
            else None)
        identity = api.get("identity") if isinstance(api, dict) else None
        if (not isinstance(api, dict) or api.get("status") != 200
                or not isinstance(applications, list)
                or api.get("identityStatus") != 200
                or not isinstance(identity, dict)
                or set(identity) != {"issuer", "subject", "loginIdSha256",
                                     "audience"}
                or identity.get("subject") != self.profile["identitySubject"]
                or not isinstance(identity.get("issuer"), str)
                or not identity["issuer"]
                or not isinstance(identity.get("audience"), str)
                or not identity["audience"]
                or not re.fullmatch(r"[0-9a-f]{64}",
                                    str(identity.get("loginIdSha256")))):
            raise PilotLoadError("PILOT_BROWSER_APPLICATIONS_FAILED")
        return {"navigationSeconds": navigation,
            "applicationsSeconds": applications_elapsed,
            "applicationCount": len(applications),
            "identityMatched": True,
            "pageTitle": await self._page.title(),
            "markerObserved": (await self._page.locator("h1").first.text_content()
                               or ""),
            "presentationBundleLoaded": await self._page.locator(
                'script[type="module"][src^="/ui/assets/"]').count() >= 1,
            "consoleErrorCount": len(self._console_errors)}

    async def close(self) -> None:
        page, context, browser, playwright = (self._page, self._context,
            self._browser, self._playwright)
        self._page = self._context = self._browser = self._playwright = None
        for value in (page, context, browser):
            if value is not None:
                try:
                    await value.close()
                except Exception:
                    pass
        if playwright is not None:
            try:
                await playwright.stop()
            except Exception:
                pass


class CodexIabBrowserProbe:
    """Consume fresh privacy-safe observations from Codex's in-app browser."""
    REQUIRED = {"format", "sessionId", "sequence", "observedAt", "webOrigin",
        "identitySubjectSha256", "navigationSeconds", "applicationsSeconds",
        "applicationCount", "pageTitle", "markerObserved",
        "presentationBundleLoaded", "consoleErrorCount"}

    def __init__(self, profile: dict, *, clock=time.time):
        self.profile = profile
        self.clock = clock
        self._last_sequence = 0
        self._opened = False

    async def open(self) -> None:
        if self._opened:
            raise PilotLoadError("PILOT_CODEX_IAB_ALREADY_OPEN")
        path = Path(self.profile["sampleFeed"])
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                    or metadata.st_size > 4 * 1024 * 1024):
                raise PilotLoadError("PILOT_CODEX_IAB_FEED_UNSAFE")
        finally:
            os.close(descriptor)
        self._opened = True

    def _records(self) -> list[dict]:
        path = Path(self.profile["sampleFeed"])
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                    or metadata.st_size > 4 * 1024 * 1024):
                raise PilotLoadError("PILOT_CODEX_IAB_FEED_UNSAFE")
            raw = os.read(descriptor, 4 * 1024 * 1024 + 1)
        finally:
            os.close(descriptor)
        try:
            lines = raw.decode("utf-8").splitlines()
            return [json.loads(line) for line in lines if line.strip()]
        except (UnicodeError, json.JSONDecodeError) as error:
            raise PilotLoadError("PILOT_CODEX_IAB_FEED_INVALID") from error

    async def sample(self) -> dict:
        if not self._opened:
            raise PilotLoadError("PILOT_CODEX_IAB_NOT_OPEN")
        candidates = []
        for value in self._records():
            if type(value) is not dict or set(value) != self.REQUIRED:
                raise PilotLoadError("PILOT_CODEX_IAB_SAMPLE_INVALID")
            if (value["format"] != "openepm-codex-iab-browser-sample-v1"
                    or value["sessionId"] != self.profile["sessionId"]
                    or value["webOrigin"].rstrip("/") != self.profile[
                        "webOrigin"].rstrip("/")
                    or value["identitySubjectSha256"] != self.profile[
                        "identitySubjectSha256"]):
                raise PilotLoadError("PILOT_CODEX_IAB_SAMPLE_BINDING_INVALID")
            if type(value["sequence"]) is not int or value["sequence"] <= 0:
                raise PilotLoadError("PILOT_CODEX_IAB_SEQUENCE_INVALID")
            candidates.append(value)
        fresh = [value for value in candidates
                 if value["sequence"] > self._last_sequence]
        if not fresh:
            raise PilotLoadError("PILOT_CODEX_IAB_SAMPLE_MISSING")
        value = min(fresh, key=lambda item: item["sequence"])
        if any(item["sequence"] == value["sequence"] for item in fresh
               if item is not value):
            raise PilotLoadError("PILOT_CODEX_IAB_SEQUENCE_DUPLICATE")
        observed = value["observedAt"]
        if (type(observed) not in (int, float)
                or observed > self.clock() + 5
                or self.clock() - observed > self.profile[
                    "maximumSampleAgeSeconds"]):
            raise PilotLoadError("PILOT_CODEX_IAB_SAMPLE_STALE")
        if (type(value["applicationCount"]) is not int
                or type(value["presentationBundleLoaded"]) is not bool
                or type(value["consoleErrorCount"]) is not int
                or value["consoleErrorCount"] < 0
                or any(type(value[field]) not in (int, float)
                       or value[field] < 0 for field in (
                           "navigationSeconds", "applicationsSeconds"))):
            raise PilotLoadError("PILOT_CODEX_IAB_SAMPLE_INVALID")
        self._last_sequence = value["sequence"]
        return {"navigationSeconds": value["navigationSeconds"],
            "applicationsSeconds": value["applicationsSeconds"],
            "applicationCount": value["applicationCount"],
            "identityMatched": True, "pageTitle": value["pageTitle"],
            "markerObserved": value["markerObserved"],
            "presentationBundleLoaded": value["presentationBundleLoaded"],
            "consoleErrorCount": value["consoleErrorCount"]}

    async def close(self) -> None:
        self._opened = False


async def _preflight(contract: MacPilotLoadContract,
                     gateway: PublicMcpGateway,
                     browser) -> dict:
    """Authenticate and validate the real load surface without business effects."""
    raw = contract.raw
    sessions = {}
    try:
        await browser.open()
        browser_sample = await browser.sample()
        if (browser_sample["applicationCount"] != len(raw["applications"])
                or browser_sample["identityMatched"] is not True
                or browser_sample["pageTitle"] != raw["browser"]["expectedTitle"]
                or browser_sample["markerObserved"] != raw["browser"][
                    "expectedMarker"]
                or browser_sample["presentationBundleLoaded"] is not True
                or browser_sample["consoleErrorCount"] != 0):
            raise PilotLoadError("PILOT_PREFLIGHT_BROWSER_INVALID")
        for identity in raw["identities"]:
            sessions[identity["subject"]] = await gateway.open(
                identity["subject"], identity["tokenFile"])
        controller = raw["controls"]["controlSubject"]
        required_tools = {action["tool"] for actions in raw["workload"].values()
                          for action in actions}
        required_tools.add("list_v2_functions")
        public_tools = await gateway.tools(sessions[controller])
        missing_tools = sorted(required_tools - public_tools)
        if missing_tools:
            raise PilotLoadError("PILOT_PREFLIGHT_TOOLS_MISSING:" +
                                 ",".join(missing_tools))

        identity_results = []
        denied_index = raw["controls"]["isolationDeniedApplicationIndex"]
        denied_subject = raw["controls"]["isolationSubject"]
        for identity_index, identity in enumerate(raw["identities"]):
            roles = (AGENT_ROLES if identity["kind"] == "agent"
                     else HUMAN_ROLES)
            applications = []
            for app_index, app in enumerate(raw["applications"]):
                if (identity["subject"] == denied_subject
                        and app_index == denied_index):
                    continue
                admitted_roles = set(roles).intersection(
                    _application_roles(app))
                required_functions = sorted({
                    action["arguments"]["program"]["function"]
                    for role in admitted_roles
                    for action in raw["workload"][role]
                    if isinstance(action["arguments"].get("program"), dict)})
                catalog = await gateway.call(
                    sessions[identity["subject"]], "list_v2_functions", {
                        "workspace_id": app["workspaceId"],
                        "application_id": app["applicationId"]})
                functions = catalog.get("functions")
                digest = catalog.get("registryDigest")
                if (type(functions) is not dict
                        or not isinstance(digest, str)
                        or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                    raise PilotLoadError("PILOT_PREFLIGHT_CATALOG_INVALID")
                missing = sorted(set(required_functions) - set(functions))
                if missing:
                    raise PilotLoadError(
                        "PILOT_PREFLIGHT_FUNCTIONS_MISSING:" + ",".join(missing))
                applications.append({
                    "application": f"application-{app_index + 1:02d}",
                    "registryDigest": digest,
                    "requiredFunctions": required_functions})
            identity_results.append({
                "identity": f"identity-{identity_index + 1:02d}",
                "kind": identity["kind"], "applications": applications})

        denied_app = raw["applications"][denied_index]
        await gateway.call_expect_denied(sessions[denied_subject],
            "list_v2_functions", {
                "workspace_id": denied_app["workspaceId"],
                "application_id": denied_app["applicationId"]},
            "APPLICATION_GRANT_REQUIRED")

        sentinel_results = []
        action = raw["workload"]["invariant"][0]
        for app_index, app in enumerate(raw["applications"]):
            context = {**{key: str(value) for key, value in app.items()},
                "subject": controller,
                "targetSubject": raw["controls"]["revocationSubject"],
                "requestId": f"pilot-preflight-{app_index}"}
            arguments = _expand(action["arguments"], context)
            result = await gateway.call(
                sessions[controller], action["tool"], arguments)
            actual = _at(result, action["expectPath"])
            expected = _expand(action["expectTemplate"], context)
            if str(actual) != str(expected):
                raise PilotLoadError("PILOT_PREFLIGHT_SENTINEL_MISMATCH")
            sentinel_results.append({
                "application": f"application-{app_index + 1:02d}",
                "readSentinelMatched": True})
        return {
            "format": "openepm-macos-pilot-load-preflight-v2",
            "status": "passed", "qualificationClaimed": False,
            "businessEffectsCreated": False,
            "identityCount": len(identity_results),
            "applicationCount": len(raw["applications"]),
            "requiredPublicTools": sorted(required_tools),
            "identities": identity_results,
            "crossApplicationDenial": True,
            "browser": {"identity": "configured-human",
                "identityMatched": True, "rendered": True, "applicationCount":
                    browser_sample["applicationCount"],
                "consoleErrorCount": browser_sample["consoleErrorCount"]},
            "sentinels": sentinel_results,
            "rawSubjectsIncluded": False, "tokenPathsIncluded": False,
        }
    finally:
        await asyncio.gather(*(gateway.close(session)
            for session in sessions.values()), return_exceptions=True)
        await browser.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--run", action="store_true")
    args = parser.parse_args()
    contract = MacPilotLoadContract.load(args.config.resolve())
    if args.plan:
        print(json.dumps({"status": "prepared-not-run", **contract.redacted_plan()},
                         sort_keys=True, indent=2))
        return
    required_session_seconds = (contract.raw["load"]["warmupSeconds"]
        + contract.raw["load"]["durationSeconds"] + 120)
    gateway = PublicMcpGateway(
        contract.raw["target"],
        required_session_seconds=required_session_seconds)
    browser = (CodexIabBrowserProbe(contract.raw["browser"])
        if "sampleFeed" in contract.raw["browser"] else
        PublicBrowserProbe(contract.raw["browser"],
            required_session_seconds=required_session_seconds))
    if args.preflight:
        report = asyncio.run(_preflight(contract, gateway, browser))
        output = Path(contract.raw["evidence"]["output"])
        output = output.with_name(output.stem + ".preflight.json")
        _write_evidence(output, report)
        print(json.dumps({"status": report["status"],
                          "output": str(output)}, sort_keys=True))
        return
    if os.environ.get("EPM_MAC_PILOT_LOAD_RUN") != "EXCLUSIVE_WINDOW_GRANTED":
        raise SystemExit("real pilot load requires explicit exclusive-window authorization")
    if platform.system() != "Darwin":
        raise SystemExit("the phase-one Mac pilot run requires macOS")
    report = asyncio.run(MacPilotLoadEngine(
        contract, gateway, MacPilotSampler(contract, gateway), browser).run())
    output = Path(contract.raw["evidence"]["output"])
    _write_evidence(output, report)
    print(json.dumps({"status": report["status"], "output": str(output)},
                     sort_keys=True))
    if report["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
