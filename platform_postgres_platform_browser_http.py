"""Bounded browser adapter for server-level identity administration.

The public browser receives neither a Keycloak Admin API credential nor a
database DSN.  Its web-audience identity is verified in a control worker, then
the fixed operation runs in a killable child against the same platform
application functions and receipts used by MCP.
"""
from __future__ import annotations

import json
import logging
import os
from urllib.parse import urlsplit

import psycopg
from mcp.server.mcpserver.exceptions import ToolError

from epm_core.keycloak_directory import KeycloakDirectoryError
from epm_core.deployment_secrets import configured_text
from epm_core.postgres_access import AccessDenied, VerifiedIdentity
from epm_core.postgres_auth import AuthError, access_token
from epm_core.postgres_execution_policy import HTTP_POST_SECONDS, TIMEOUT_RESPONSE_SECONDS
from epm_core.postgres_http_budget import bounded_request
from epm_core.postgres_mcp_execution import (
    PLATFORM_WEB_MODULE, execute_platform_web_request, verified_mcp_request,
)
from epm_core.postgres_platform_mcp_application import PostgresPlatformMCPApplication
from epm_core.postgres_verified_principal import principal_claims


LOG = logging.getLogger(__name__)
MAX_BODY = 65_536
READ_PATH = "/browser/read"
WRITE_PATH = "/browser/write"
CATALOG_PATH = "/browser/catalog"
PATHS = frozenset((READ_PATH, WRITE_PATH, CATALOG_PATH))


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    loopback = parsed.hostname in ("127.0.0.1", "localhost", "::1")
    if (parsed.scheme not in (("http", "https") if loopback else ("https",))
            or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise ValueError("EPM_PUBLIC_WEB_ORIGIN_INVALID")
    return value.rstrip("/")


class PlatformBrowserApp:
    def __init__(self, provision_dsn: str, public_origin: str):
        if not isinstance(provision_dsn, str) or not provision_dsn:
            raise ValueError("POSTGRES_PROVISION_SERVICE_NOT_CONFIGURED")
        self.provision_dsn = provision_dsn
        self.public_origin = _origin(public_origin)

    @staticmethod
    async def _json(send, status: int, value: object) -> None:
        await send({"type": "http.response.start", "status": status,
                    "headers": [(b"content-type", b"application/json; charset=utf-8"),
                                (b"cache-control", b"no-store"),
                                (b"x-content-type-options", b"nosniff")]})
        await send({"type": "http.response.body", "body": json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()})

    @staticmethod
    async def _body(receive) -> dict:
        data = bytearray()
        while True:
            message = await receive()
            if message.get("type") != "http.request":
                raise ValueError("REQUEST_INTERRUPTED")
            data.extend(message.get("body", b""))
            if len(data) > MAX_BODY:
                raise ValueError("REQUEST_TOO_LARGE")
            if not message.get("more_body", False):
                break
        try:
            value = json.loads(data)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("JSON_BODY_REQUIRED") from error
        if not isinstance(value, dict):
            raise ValueError("JSON_OBJECT_REQUIRED")
        return value

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self._json(send, 404, {"error": "UNKNOWN_ROUTE"})
            return
        if scope.get("method") != "POST" or scope.get("path") not in PATHS:
            await self._json(send, 404, {"error": "UNKNOWN_ROUTE"})
            return
        return await bounded_request(self._dispatch, scope, receive, send,
            seconds=HTTP_POST_SECONDS, response_seconds=TIMEOUT_RESPONSE_SECONDS)

    async def _dispatch(self, scope, receive, send):
        headers: dict[str, list[str]] = {}
        for key, value in scope.get("headers", []):
            headers.setdefault(key.decode("latin-1").lower(), []).append(
                value.decode("latin-1"))
        if headers.get("content-type", [""])[0].split(";", 1)[0].strip() != "application/json":
            await self._json(send, 415, {"error": "JSON_CONTENT_TYPE_REQUIRED"})
            return
        if scope["path"] == WRITE_PATH and headers.get("origin") != [self.public_origin]:
            await self._json(send, 403, {"error": "WEB_ORIGIN_REQUIRED"})
            return
        try:
            body = await self._body(receive)
            configuration = {"provisionDsn": self.provision_dsn,
                             "publicOrigin": self.public_origin}
            result = await execute_platform_web_request(
                {"configuration": configuration, "path": scope["path"], "body": body},
                {name: values[0] for name, values in headers.items()
                 if name in ("authorization", "origin")
                 and len(values) == 1})
            await self._json(send, result["status"], result["payload"])
        except ToolError:
            LOG.exception("Platform browser child operation unavailable")
            await self._json(send, 503, {"error": "PLATFORM_OPERATION_OUTCOME_UNKNOWN"})
        except ValueError as error:
            await self._json(send, 400, {"error": str(error)})


def _configured_application() -> PostgresPlatformMCPApplication:
    return PostgresPlatformMCPApplication(configured_text(
        os.environ, "EPM_PG_PROVISION_DSN", "EPM_PG_PROVISION_DSN_FILE"))


def _startup_role_check() -> None:
    _configured_application().assert_runtime_role()


def _web_request(arguments, headers):
    try:
        if (not isinstance(arguments, dict)
                or set(arguments) != {"configuration", "path", "body"}
                or not isinstance(arguments["configuration"], dict)
                or set(arguments["configuration"]) != {"provisionDsn", "publicOrigin"}
                or not isinstance(arguments["path"], str)
                or arguments["path"] not in PATHS
                or not isinstance(arguments["body"], dict)):
            raise ValueError("PLATFORM_WEB_OPERATION_INVALID")
        config = arguments["configuration"]
        if (not isinstance(config["provisionDsn"], str)
                or not config["provisionDsn"]
                or not isinstance(config["publicOrigin"], str)):
            raise ValueError("PLATFORM_WEB_CONFIGURATION_INVALID")
        public_origin = _origin(config["publicOrigin"])
        principal = principal_claims(access_token(headers), "web")
        identity = VerifiedIdentity(principal["issuer"], principal["subject"],
                                    principal.get("groups", ()),
                                    issued_at=principal["issuedAt"])
        application = PostgresPlatformMCPApplication(config["provisionDsn"])
        path, body = arguments["path"], arguments["body"]
        if path == CATALOG_PATH:
            if body:
                raise ValueError("PLATFORM_CATALOG_ARGUMENTS_INVALID")
            value = application.catalog_for_identity(identity)
        elif path == READ_PATH:
            if set(body) != {"program"}:
                raise ValueError("PLATFORM_READ_ARGUMENTS_INVALID")
            value = application.read_for_identity(identity, body["program"])
        else:
            if (set(body) != {"program", "idempotencyKey", "confirmed"}
                    or body.get("confirmed") is not True
                    or headers.get("origin") != public_origin):
                raise ValueError("PLATFORM_WRITE_ARGUMENTS_INVALID")
            value = application.create_for_identity(
                identity, body["program"], idempotency_key=body["idempotencyKey"])
        return {"status": 200, "payload": value}
    except AuthError as error:
        return {"status": error.status, "payload": {"error": str(error)}}
    except AccessDenied as error:
        return {"status": 403, "payload": {"error": str(error)}}
    except (KeycloakDirectoryError, ValueError) as error:
        return {"status": 400, "payload": {"error": str(error)}}
    except psycopg.Error:
        LOG.exception("PostgreSQL platform browser operation failed")
        return {"status": 503, "payload": {"error": "POSTGRES_OPERATION_FAILED"}}


def build_browser_app() -> PlatformBrowserApp:
    return PlatformBrowserApp(configured_text(
        os.environ, "EPM_PG_PROVISION_DSN", "EPM_PG_PROVISION_DSN_FILE"),
        os.environ.get("EPM_PUBLIC_WEB_ORIGIN", ""))
