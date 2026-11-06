"""Dependency-free authenticated HTTPS transport for public Open EPM MCP.

The transport is deliberately small and synchronous to match :class:`EpmClient`.
It never accepts plaintext remote HTTP, disabled certificate verification, caller
headers, or credentials embedded in a URL.  OIDC token acquisition/refresh stays
with the host application and is exposed only through a token provider callable.
"""
from __future__ import annotations

import json
import re
import ssl
import threading
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (HTTPRedirectHandler, HTTPSHandler, Request,
                            build_opener)


_TOOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,199}$")
_PROTOCOL_VERSION = "2025-03-26"


class McpTransportError(RuntimeError):
    """A bounded, credential-free public transport failure."""


class _NoRedirect(HTTPRedirectHandler):
    # Bearer credentials must never follow a redirect to another origin.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpsMcpTransport:
    """Authenticated MCP Streamable-HTTP adapter for an HTTPS endpoint.

    ``token_provider`` is called for every request so the embedding client can
    refresh short-lived access tokens.  It must return only the access token,
    without the ``Bearer`` prefix.  The token is never stored on this object.
    """

    def __init__(self, endpoint: str, token_provider: Callable[[], str], *,
                 timeout_seconds: float = 30, max_response_bytes: int = 10_000_000,
                 ca_file: str | None = None):
        parsed = urlsplit(endpoint) if isinstance(endpoint, str) else None
        if (parsed is None or parsed.scheme != "https" or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or not parsed.path.startswith("/")):
            raise ValueError("MCP endpoint must be a credential-free HTTPS URL")
        if not callable(token_provider):
            raise ValueError("An access-token provider is required")
        if (isinstance(timeout_seconds, bool)
                or not isinstance(timeout_seconds, (int, float))
                or not 0 < float(timeout_seconds) <= 300):
            raise ValueError("timeout_seconds must be greater than zero and at most 300")
        if (type(max_response_bytes) is not int
                or not 1024 <= max_response_bytes <= 32 * 1024 * 1024):
            raise ValueError("max_response_bytes must be from 1 KiB through 32 MiB")
        context = ssl.create_default_context(cafile=ca_file)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._endpoint = endpoint
        self._token_provider = token_provider
        self._timeout = float(timeout_seconds)
        self._max_response = max_response_bytes
        self._opener = build_opener(_NoRedirect(), HTTPSHandler(context=context))
        self._lock = threading.RLock()
        self._next_id = 1
        self._initialized = False
        self._session_id: str | None = None

    def __repr__(self) -> str:
        return f"HttpsMcpTransport(endpoint={self._endpoint!r})"

    def call(self, tool: str, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(tool, str) or _TOOL.fullmatch(tool) is None:
            raise ValueError("MCP tool name is invalid")
        if not isinstance(arguments, Mapping):
            raise ValueError("MCP tool arguments must be a mapping")
        try:
            canonical = json.loads(json.dumps(arguments, sort_keys=True,
                separators=(",", ":"), ensure_ascii=True, allow_nan=False))
        except (TypeError, ValueError, UnicodeError) as error:
            raise ValueError("MCP tool arguments are not canonical JSON") from error
        if not isinstance(canonical, dict):
            raise ValueError("MCP tool arguments must be an object")
        with self._lock:
            self._initialize()
            response = self._rpc("tools/call", {"name": tool,
                                                 "arguments": canonical})
        result = response.get("result")
        if not isinstance(result, dict):
            raise McpTransportError("MCP tool returned an invalid result")
        if result.get("isError") is True:
            raise McpTransportError(self._error_text(result))
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            return structured
        content = result.get("content")
        if (not isinstance(content, list) or len(content) != 1
                or not isinstance(content[0], dict)
                or content[0].get("type") != "text"
                or not isinstance(content[0].get("text"), str)):
            raise McpTransportError("MCP tool returned no structured object")
        try:
            decoded = json.loads(content[0]["text"])
        except json.JSONDecodeError as error:
            raise McpTransportError("MCP tool returned invalid JSON text") from error
        if not isinstance(decoded, dict):
            raise McpTransportError("MCP tool returned no object")
        return decoded

    def _initialize(self) -> None:
        if self._initialized:
            return
        response = self._rpc("initialize", {
            "protocolVersion": _PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "openepm-sdk", "version": "0.1.0"}})
        result = response.get("result")
        if (not isinstance(result, dict)
                or not isinstance(result.get("protocolVersion"), str)):
            raise McpTransportError("MCP initialization returned an invalid result")
        self._notify("notifications/initialized", {})
        self._initialized = True

    def _rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        response = self._post({"jsonrpc": "2.0", "id": request_id,
                               "method": method, "params": params},
                              expect_body=True)
        if response.get("jsonrpc") != "2.0" or response.get("id") != request_id:
            raise McpTransportError("MCP JSON-RPC response identity mismatch")
        if "error" in response:
            error = response["error"]
            message = (error.get("message") if isinstance(error, dict) else None)
            raise McpTransportError(message if isinstance(message, str) and message
                                    else "MCP JSON-RPC request failed")
        return response

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        self._post({"jsonrpc": "2.0", "method": method, "params": params},
                   expect_body=False)

    def _post(self, payload: dict[str, Any], *, expect_body: bool) -> dict[str, Any]:
        token = self._token_provider()
        if (not isinstance(token, str) or not token or len(token) > 16384
                or any(character in token for character in "\r\n\x00")):
            raise McpTransportError("Access-token provider returned an invalid token")
        headers = {"Authorization": "Bearer " + token,
                   "Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream",
                   "MCP-Protocol-Version": _PROTOCOL_VERSION}
        if self._session_id is not None:
            headers["MCP-Session-Id"] = self._session_id
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
        request = Request(self._endpoint, data=body, headers=headers, method="POST")
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                session = response.headers.get("MCP-Session-Id")
                if session is not None:
                    if (not session or len(session) > 1024
                            or any(value in session for value in "\r\n\x00")):
                        raise McpTransportError("MCP session identifier is invalid")
                    self._session_id = session
                raw = response.read(self._max_response + 1)
        except HTTPError as error:
            # Do not echo bodies: proxies and identity providers can include
            # credential-adjacent diagnostics in an error response.
            raise McpTransportError(f"MCP HTTPS request failed with status {error.code}") from error
        except (URLError, TimeoutError, OSError) as error:
            raise McpTransportError("MCP HTTPS request failed") from error
        if len(raw) > self._max_response:
            raise McpTransportError("MCP HTTPS response exceeds the configured bound")
        if not raw:
            if expect_body:
                raise McpTransportError("MCP HTTPS response body is missing")
            return {}
        try:
            decoded = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise McpTransportError("MCP HTTPS response is not JSON") from error
        if not isinstance(decoded, dict):
            raise McpTransportError("MCP HTTPS response is not an object")
        return decoded

    @staticmethod
    def _error_text(result: dict[str, Any]) -> str:
        content = result.get("content")
        if (isinstance(content, list) and content
                and isinstance(content[0], dict)
                and isinstance(content[0].get("text"), str)
                and content[0]["text"]):
            return content[0]["text"][:2048]
        return "MCP tool rejected the request"
