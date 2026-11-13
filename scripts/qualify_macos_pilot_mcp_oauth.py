#!/usr/bin/env python3
"""Run a token-in-memory OAuth qualification against one public Mac MCP scope.

The operator opens the printed authorization URL in a separate browser.  A
single-purpose loopback listener receives the OAuth callback, validates it and
closes; the operator never copies an authorization code through the terminal.
Tokens, authorization codes, subject identifiers and emails are never written
to the evidence file.
"""
from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import time
from typing import Callable
from urllib.parse import parse_qs, urlsplit

import httpx2
from mcp import ClientSession
from mcp.client.auth import OAuthClientProvider
from mcp.client.streamable_http import streamable_http_client
from mcp.shared.auth import (
    AuthorizationCodeResult,
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthToken,
)


ENDPOINTS = {
    "platform": "https://mcp.openepm.dev/api/platform/mcp",
    "workspace": "https://mcp.openepm.dev/api/workspace/mcp",
    "application": "https://mcp.openepm.dev/api/application/mcp",
}
REDIRECT_URI = "http://127.0.0.1:8765/callback"
CALLBACK_HOST = "127.0.0.1"
CALLBACK_PORT = 8765
MAX_CALLBACK_LINE_BYTES = 8192
CALLBACK_TIMEOUT_SECONDS = 300


class MemoryStorage:
    def __init__(self) -> None:
        self.tokens: OAuthToken | None = None
        self.tokens_received_at: float | None = None
        self.client_info: OAuthClientInformationFull | None = None

    async def get_tokens(self) -> OAuthToken | None:
        return self.tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self.tokens = tokens
        self.tokens_received_at = time.time()

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self.client_info

    async def set_client_info(
            self, client_info: OAuthClientInformationFull) -> None:
        self.client_info = client_info


def parse_callback(raw: str) -> AuthorizationCodeResult:
    parsed = urlsplit(raw.strip())
    if (parsed.scheme != "http" or parsed.hostname not in
            ("127.0.0.1", "localhost") or parsed.port != 8765
            or parsed.path != "/callback" or parsed.fragment):
        raise ValueError("OAUTH_CALLBACK_URL_INVALID")
    values = parse_qs(parsed.query, strict_parsing=True)
    if set(values) - {"code", "state", "iss", "session_state"}:
        raise ValueError("OAUTH_CALLBACK_ARGUMENTS_INVALID")
    if "error" in values or len(values.get("code", [])) != 1 \
            or len(values.get("state", [])) != 1 \
            or len(values.get("iss", [])) > 1 \
            or len(values.get("session_state", [])) > 1:
        raise ValueError("OAUTH_CALLBACK_RESULT_INVALID")
    return AuthorizationCodeResult(
        code=values["code"][0], state=values["state"][0],
        iss=values.get("iss", [None])[0])


def parse_callback_request_line(raw: bytes) -> AuthorizationCodeResult:
    """Accept one bounded origin-form GET request for the exact callback."""
    if (not isinstance(raw, bytes) or not raw.endswith(b"\r\n")
            or len(raw) > MAX_CALLBACK_LINE_BYTES):
        raise ValueError("OAUTH_CALLBACK_REQUEST_INVALID")
    try:
        request_line = raw[:-2].decode("ascii", errors="strict")
    except UnicodeError as error:
        raise ValueError("OAUTH_CALLBACK_REQUEST_INVALID") from error
    parts = request_line.split(" ")
    if (len(parts) != 3 or parts[0] != "GET" or parts[2] != "HTTP/1.1"
            or not parts[1].startswith("/callback?")):
        raise ValueError("OAUTH_CALLBACK_REQUEST_INVALID")
    return parse_callback(
        f"http://{CALLBACK_HOST}:{CALLBACK_PORT}{parts[1]}")


def callback_shape(raw: bytes) -> dict:
    """Return a value-free diagnostic shape for a rejected request."""
    result = {"method": "invalid", "path": "invalid",
              "parameterNames": []}
    try:
        line = raw[:-2].decode("ascii", errors="strict")
        parts = line.split(" ")
        if len(parts) == 3:
            result["method"] = parts[0] if re.fullmatch(
                r"[A-Z]{1,12}", parts[0]) else "invalid"
            target = urlsplit(parts[1])
            result["path"] = target.path if target.path in (
                "/callback", "/favicon.ico") else "other"
            names = []
            for item in target.query.split("&") if target.query else ():
                name = item.split("=", 1)[0]
                if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", name):
                    names.append(name)
            result["parameterNames"] = sorted(set(names))
    except (UnicodeError, ValueError):
        pass
    return result


async def receive_callback(
        diagnostic: Callable[[dict], None] | None = None,
        timeout_seconds: int = CALLBACK_TIMEOUT_SECONDS,
) -> AuthorizationCodeResult:
    """Receive exactly one valid callback without persisting its secrets."""
    if (isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, int)
            or timeout_seconds < 1 or timeout_seconds > 3600):
        raise ValueError("OAUTH_CALLBACK_TIMEOUT_INVALID")
    loop = asyncio.get_running_loop()
    result: asyncio.Future[AuthorizationCodeResult] = loop.create_future()

    async def handle(reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter) -> None:
        status = "400 Bad Request"
        body = b"Open EPM OAuth callback rejected."
        line = b""
        total = 0
        try:
            line = await asyncio.wait_for(
                reader.readline(), timeout=5)
            callback = parse_callback_request_line(line)
            # Consume the bounded header section so a browser can reuse no
            # unread bytes.  Header values are intentionally ignored.
            total = len(line)
            while True:
                header = await asyncio.wait_for(reader.readline(), timeout=5)
                total += len(header)
                if total > MAX_CALLBACK_LINE_BYTES or not header:
                    raise ValueError("OAUTH_CALLBACK_REQUEST_INVALID")
                if header == b"\r\n":
                    break
            if not result.done():
                result.set_result(callback)
            status = "200 OK"
            body = (b"Open EPM authorization received. You may close this "
                    b"browser tab.")
        except (ValueError, asyncio.TimeoutError) as error:
            if diagnostic is not None:
                diagnostic({**callback_shape(line),
                            "error": str(error) or type(error).__name__,
                            "requestBytes": total})
        finally:
            writer.write(
                f"HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\n"
                f"Cache-Control: no-store\r\nContent-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n".encode("ascii") + body)
            try:
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

    server = await asyncio.start_server(
        handle, host=CALLBACK_HOST, port=CALLBACK_PORT, limit=MAX_CALLBACK_LINE_BYTES)
    async with server:
        try:
            try:
                return await asyncio.wait_for(
                    asyncio.shield(result), timeout=timeout_seconds)
            except asyncio.TimeoutError as error:
                raise ValueError("OAUTH_CALLBACK_TIMEOUT") from error
        finally:
            server.close()
            await server.wait_closed()


async def qualify(endpoint: str) -> dict:
    server_url = ENDPOINTS[endpoint]
    storage = MemoryStorage()

    async def redirect_handler(url: str) -> None:
        print("AUTHORIZATION_URL=" + url, flush=True)

    async def callback_handler() -> AuthorizationCodeResult:
        return await receive_callback()

    metadata = OAuthClientMetadata(
        client_name="Open EPM local qualification",
        redirect_uris=[REDIRECT_URI],
        grant_types=["authorization_code", "refresh_token"],
        token_endpoint_auth_method="none")
    provider = OAuthClientProvider(
        server_url, metadata, storage, redirect_handler=redirect_handler,
        callback_handler=callback_handler)
    async with httpx2.AsyncClient(
            auth=provider, follow_redirects=True) as client:
        async with streamable_http_client(
                server_url, http_client=client) as streams:
            read_stream, write_stream = streams
            async with ClientSession(read_stream, write_stream) as session:
                initialized = await session.initialize()
                tools = await session.list_tools()
    return {
        "format": "openepm-local-mac-mcp-oauth-v1",
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "status": "passed",
        "endpoint": endpoint,
        "serverUrl": server_url,
        "serverName": initialized.server_info.name,
        "toolCount": len(tools.tools),
        "tools": sorted(tool.name for tool in tools.tools),
        "oauthAuthorizationCodeRetained": False,
        "oauthTokenRetained": False,
        "identityValueRetained": False,
        "businessMutationPerformed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", choices=tuple(ENDPOINTS), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    arguments = parser.parse_args()
    if not arguments.output.is_absolute():
        parser.error("output must be absolute")
    output = arguments.output.resolve()
    if not arguments.execute:
        print(json.dumps({"endpoint": arguments.endpoint,
                          "serverUrl": ENDPOINTS[arguments.endpoint],
                          "output": str(output), "execute": False},
                         sort_keys=True))
        return 0
    evidence = asyncio.run(qualify(arguments.endpoint))
    output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": True, "endpoint": arguments.endpoint,
                      "toolCount": evidence["toolCount"],
                      "output": str(output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
