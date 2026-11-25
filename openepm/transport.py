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

from ._client_identity import CLIENT_NAME, CLIENT_VERSION, USER_AGENT
from .public_diagnostics import REPAIR_CODES, repair_fields


_TOOL = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,199}$")
_MODERN_VERSION = "2026-07-28"
_LEGACY_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26")
_DISCOVER = "server/discover"
_ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{2,99}\Z")
_MAX_TEXT_DIAGNOSTIC_CHARS = 4096


class McpTransportError(RuntimeError):
    """A bounded, credential-free public transport failure."""

    def __init__(self, message: str, *, code: str | None = None,
                 http_status: int | None = None, rpc_code: int | None = None,
                 request_dispatched: bool = True, details: dict[str, str] | None = None):
        # Keep existing str(error) callers compatible; machine consumers use
        # these narrowly validated fields, never arbitrary upstream text.
        super().__init__(message)
        self.code = code if isinstance(code, str) and _ERROR_CODE.fullmatch(code) else None
        self.http_status = http_status if type(http_status) is int and 100 <= http_status <= 599 else None
        self.rpc_code = rpc_code if type(rpc_code) is int and -(2**31) <= rpc_code < 2**31 else None
        self.request_dispatched = request_dispatched
        self.details = details


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
        self._protocol_version: str | None = None
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
            try:
                self._initialize()
            except McpTransportError as error:
                error.request_dispatched = False
                raise
            response = self._rpc("tools/call", {"name": tool, "arguments": canonical},
                                 version=self._protocol_version)
        result = response.get("result")
        if not isinstance(result, dict):
            raise McpTransportError("MCP tool returned an invalid result")
        structured = result.get("structuredContent")
        text_content = self._single_text_content(result)
        if result.get("isError") is True:
            diagnostic = (structured if "structuredContent" in result
                          else self._text_diagnostic(text_content))
            code = self._tool_error_code(diagnostic, text_content, tool)
            if code in REPAIR_CODES:
                program = canonical.get("program")
                function = program.get("function") if isinstance(program, dict) else None
                details = repair_fields(diagnostic, requested_function=function)
                raise McpTransportError(code, code=code, details=details)
            raise McpTransportError(self._error_text(result), code=code)
        if isinstance(structured, dict):
            return structured
        if text_content is None:
            raise McpTransportError("MCP tool returned no structured object")
        try:
            decoded = json.loads(text_content)
        except json.JSONDecodeError as error:
            raise McpTransportError("MCP tool returned invalid JSON text") from error
        if not isinstance(decoded, dict):
            raise McpTransportError("MCP tool returned no object")
        return decoded

    def _initialize(self) -> None:
        if self._protocol_version is not None:
            return
        offer = self._probe_protocol()
        if offer == _MODERN_VERSION:
            self._protocol_version = offer
            return
        try:
            # Older servers can use their default for the initialize request.
            # The returned revision then governs every subsequent request.
            response = self._rpc("initialize", {
                "protocolVersion": offer, "capabilities": {},
                "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION}},
                version=None)
            result = response.get("result")
            accepted = result.get("protocolVersion") if isinstance(result, dict) else None
            if accepted not in _LEGACY_VERSIONS:
                raise McpTransportError("MCP initialization negotiated an unsupported protocol",
                                        code="MCP_PROTOCOL_UNSUPPORTED")
            self._post({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                       expect_body=False, version=accepted)
            self._protocol_version = accepted
        finally:
            if self._protocol_version is None:
                self._session_id = None

    def _probe_protocol(self) -> str:
        try:
            response = self._rpc(_DISCOVER, {}, version=_MODERN_VERSION)
        except McpTransportError as error:
            if error.code == "MCP_LEGACY_DISCOVERY" or error.rpc_code in (-32600, -32601):
                return _LEGACY_VERSIONS[0]
            raise
        result = response.get("result")
        if "error" in response:
            error = response["error"]
            data = error.get("data") if isinstance(error, dict) else None
            if (isinstance(data, dict) and error.get("code") == -32022
                    and data.get("requested") == _MODERN_VERSION
                    and isinstance(data.get("supported"), list)
                    and _MODERN_VERSION not in data["supported"]):
                for version in _LEGACY_VERSIONS:
                    if version in data["supported"]:
                        return version
            raise McpTransportError("MCP endpoint refused the preferred protocol",
                                    code="MCP_PROTOCOL_UNSUPPORTED",
                                    rpc_code=error.get("code") if isinstance(error, dict) else None)
        if (isinstance(result, dict) and isinstance(result.get("supportedVersions"), list)
                and _MODERN_VERSION in result["supportedVersions"]):
            return _MODERN_VERSION
        raise McpTransportError("MCP discovery did not confirm the requested protocol",
                                code="MCP_DISCOVERY_INVALID")

    def _rpc(self, method: str, params: dict[str, Any], *,
             version: str | None) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        if version == _MODERN_VERSION:
            params = {**params, "_meta": {
                "io.modelcontextprotocol/protocolVersion": version,
                "io.modelcontextprotocol/clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
                "io.modelcontextprotocol/clientCapabilities": {},
            }}
        response = self._post({"jsonrpc": "2.0", "id": request_id,
                               "method": method, "params": params},
                              expect_body=True, version=version)
        if (response.get("jsonrpc") != "2.0" or type(response.get("id")) is not int
                or response["id"] != request_id):
            raise McpTransportError("MCP JSON-RPC response identity mismatch")
        if "error" in response:
            error = response["error"]
            if method == _DISCOVER:
                code = error.get("code") if isinstance(error, dict) else None
                if code == -32022:
                    return response
                raise McpTransportError("MCP discovery was refused",
                                        code="MCP_DISCOVERY_REFUSED", rpc_code=code)
            message = (error.get("message") if isinstance(error, dict) else None)
            raise McpTransportError(message if isinstance(message, str) and message
                                    else "MCP JSON-RPC request failed",
                                    code=message if isinstance(message, str) and _ERROR_CODE.fullmatch(message)
                                        else "MCP_JSON_RPC_ERROR",
                                    rpc_code=error.get("code") if isinstance(error, dict) else None)
        return response

    def _post(self, payload: dict[str, Any], *, expect_body: bool,
              version: str | None) -> dict[str, Any]:
        token = self._token_provider()
        if (not isinstance(token, str) or not token or len(token) > 16384
                or any(character in token for character in "\r\n\x00")):
            raise McpTransportError("Access-token provider returned an invalid token")
        headers = {"Authorization": "Bearer " + token,
                   "Content-Type": "application/json",
                   "Accept": "application/json, text/event-stream",
                   "User-Agent": USER_AGENT}
        if version is not None:
            headers["MCP-Protocol-Version"] = version
        if version == _MODERN_VERSION:
            headers["Mcp-Method"] = payload["method"]
            if payload["method"] == "tools/call":
                headers["Mcp-Name"] = payload["params"]["name"]
        if self._session_id is not None:
            headers["MCP-Session-Id"] = self._session_id
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
        request = Request(self._endpoint, data=body, headers=headers, method="POST")
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                session = response.headers.get("MCP-Session-Id")
                if payload["method"] == "initialize" and session is not None:
                    if (not session or len(session) > 1024
                            or any(not 0x21 <= ord(value) <= 0x7e for value in session)):
                        raise McpTransportError("MCP session identifier is invalid")
                    self._session_id = session
                raw = response.read(self._max_response + 1)
        except HTTPError as error:
            # Do not echo bodies: proxies and identity providers can include
            # credential-adjacent diagnostics in an error response.
            if payload["method"] == _DISCOVER and error.code in (400, 404, 405):
                try:
                    with error:
                        raw = error.read(self._max_response + 1)
                except OSError as failure:
                    raise McpTransportError("MCP HTTPS discovery response could not be read") from failure
                if len(raw) > self._max_response:
                    raise McpTransportError("MCP HTTPS response exceeds the configured bound")
                try:
                    decoded = json.loads(raw)
                except (ValueError, RecursionError):
                    decoded = None
                if isinstance(decoded, dict) and decoded.get("jsonrpc") == "2.0":
                    if isinstance(decoded.get("error"), dict):
                        return decoded
                    raise McpTransportError("MCP discovery returned an invalid error envelope",
                                            code="MCP_DISCOVERY_INVALID")
                raise McpTransportError("MCP endpoint requires legacy initialization",
                                        code="MCP_LEGACY_DISCOVERY", http_status=error.code)
            error.close()
            if error.code == 404 and self._session_id is not None:
                self._session_id = None
                self._protocol_version = None
                raise McpTransportError("MCP session expired; the next explicit call can reconnect",
                                        code="MCP_SESSION_EXPIRED", http_status=404) from error
            raise McpTransportError(f"MCP HTTPS request failed with status {error.code}",
                code="MCP_HTTP_ERROR", http_status=error.code) from error
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
    def _single_text_content(result: dict[str, Any]) -> str | None:
        content = result.get("content")
        if (not isinstance(content, list) or len(content) != 1
                or not isinstance(content[0], dict)
                or content[0].get("type") != "text"
                or not isinstance(content[0].get("text"), str)):
            return None
        return content[0]["text"]

    @staticmethod
    def _text_diagnostic(message: str | None) -> dict[str, Any] | None:
        if (message is None or len(message) > _MAX_TEXT_DIAGNOSTIC_CHARS
                or not message.lstrip().startswith("{")):
            return None
        try:
            payload = json.loads(message)
        except (ValueError, RecursionError):
            return None
        code = payload.get("code") if isinstance(payload, dict) else None
        return payload if isinstance(code, str) and code in REPAIR_CODES else None

    @staticmethod
    def _tool_error_code(diagnostic: object, message: str | None, tool: str) -> str | None:
        if isinstance(diagnostic, dict):
            code = diagnostic.get("code")
            if isinstance(code, str) and _ERROR_CODE.fullmatch(code):
                return code
        if message is None:
            return None
        if _ERROR_CODE.fullmatch(message):
            return message
        # mcp 2.3.0 MCPServer Tool.run wraps deliberate ToolError messages in
        # this exact prefix. Bind it to the tool actually called; do not search
        # arbitrary text for apparent codes or print its argument values.
        prefix = f"Error executing tool {tool}: "
        if message.startswith(prefix):
            detail = message[len(prefix):]
            code = detail.split(";", 1)[0]
            if _ERROR_CODE.fullmatch(code):
                return code
            if re.match(r"[1-9][0-9]* validation errors? for [A-Za-z_][A-Za-z0-9_]*\n", detail):
                return "MCP_TOOL_ARGUMENTS_INVALID"
        if message == f"Unknown tool: {tool}":
            return "MCP_TOOL_NOT_FOUND"
        return None

    @staticmethod
    def _error_text(result: dict[str, Any]) -> str:
        content = result.get("content")
        if (isinstance(content, list) and content
                and isinstance(content[0], dict)
                and isinstance(content[0].get("text"), str)
                and content[0]["text"]):
            return content[0]["text"][:2048]
        return "MCP tool rejected the request"
