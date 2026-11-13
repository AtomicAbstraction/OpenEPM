"""Maintained, serial JSON-lines client for authorized Open EPM MCP tools.

This module owns terminal framing and one in-memory native OAuth session only.
The caller owns durable intents, business idempotency keys and reconciliation.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import math
import re
import signal
import sys
from typing import BinaryIO, TextIO

from .oidc import OidcDeviceError, OidcDeviceTokenProvider
from .transport import HttpsMcpTransport, McpTransportError

PROTOCOL = "openepm-native-jsonl-v1"
MAX_REQUEST_BYTES = 32 * 1024 * 1024
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TOOL = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,199}\Z")
_ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{2,99}\Z")


class _Interrupted(KeyboardInterrupt):
    def __init__(self, signum: int):
        self.signum = signum


@contextmanager
def _termination_handlers():
    previous = {}
    interrupted = False

    def terminate(signum, frame):
        nonlocal interrupted
        if not interrupted:
            interrupted = True
            raise _Interrupted(signum)

    try:
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous[signum] = signal.signal(signum, terminate)
        def cleanup_started():
            nonlocal interrupted
            interrupted = True

        yield cleanup_started
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def _emit(stream: TextIO, value: dict) -> None:
    stream.write(json.dumps(value, ensure_ascii=True, allow_nan=False,
                            separators=(",", ":")) + "\n")
    stream.flush()


def _diagnostic(stream: TextIO, value: dict) -> None:
    # A closed consumer must not prevent credential cleanup.
    try:
        _emit(stream, value)
    except (OSError, ValueError):
        pass


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("nonfinite JSON number")


def _finite_float(value):
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("nonfinite JSON number")
    return result


def _request(raw: bytes) -> dict:
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                       parse_constant=_invalid_constant, parse_float=_finite_float)
    if (not isinstance(value, dict)
            or set(value) != {"id", "route", "tool", "arguments"}
            or not isinstance(value["id"], str)
            or _IDENTIFIER.fullmatch(value["id"]) is None
            or value["route"] not in ("workspace", "application")
            or not isinstance(value["tool"], str)
            or _TOOL.fullmatch(value["tool"]) is None
            or not isinstance(value["arguments"], dict)):
        raise ValueError("invalid request envelope")
    return value


def run_session(config: argparse.Namespace, *, input_stream: BinaryIO,
                output_stream: TextIO, diagnostic_stream: TextIO,
                provider_factory=None, transport_factory=None, _cleanup_started=None) -> int:
    """Run one session; factories permit isolated qualification without login."""
    provider_factory = provider_factory or OidcDeviceTokenProvider
    transport_factory = transport_factory or HttpsMcpTransport
    provider = None
    authenticated = False
    active_id = None
    exit_code = 0
    had_request_error = False
    try:
        provider = provider_factory(config.issuer, client_id=config.client_id)
        # Validate both destinations before issuing any device authorization.
        transports = {
            "workspace": transport_factory(config.workspace_endpoint, provider,
                timeout_seconds=config.timeout_seconds),
            "application": transport_factory(config.application_endpoint, provider,
                timeout_seconds=config.timeout_seconds),
        }
        prompt = provider.begin()
        _emit(diagnostic_stream, {"event": "device-authorization",
            "verificationUri": prompt.verification_uri, "userCode": prompt.user_code,
            "expiresIn": prompt.expires_in})
        provider.await_token()
        authenticated = True
        _emit(output_stream, {"event": "ready", "protocol": PROTOCOL})
        while True:
            raw = input_stream.readline(MAX_REQUEST_BYTES + 1)
            if not raw:
                break
            if len(raw) > MAX_REQUEST_BYTES:
                _emit(output_stream, {"id": None, "ok": False, "error": {
                    "code": "REQUEST_TOO_LARGE", "outcome": "not_dispatched"}})
                exit_code = 2
                break
            try:
                request = _request(raw)
            except (ValueError, RecursionError):
                _emit(output_stream, {"id": None, "ok": False, "error": {
                    "code": "INVALID_REQUEST", "outcome": "not_dispatched"}})
                had_request_error = True
                continue
            active_id = request["id"]
            try:
                result = transports[request["route"]].call(
                    request["tool"], request["arguments"])
            except McpTransportError as error:
                # Never echo arbitrary upstream text or arguments into diagnostics.
                # A lost response may follow a commit: the caller must reconcile.
                message = str(error)
                code = error.code or (message if _ERROR_CODE.fullmatch(message) else "MCP_REQUEST_FAILED")
                details = {"code": code, "outcome": "unconfirmed"}
                if error.http_status is not None:
                    details["httpStatus"] = error.http_status
                if error.rpc_code is not None:
                    details["rpcCode"] = error.rpc_code
                _emit(output_stream, {"id": active_id, "ok": False,
                    "error": details})
                had_request_error = True
            except ValueError:
                # Parsing a received JSON number can raise plain ValueError
                # after dispatch. Never infer non-execution from its type.
                _emit(output_stream, {"id": active_id, "ok": False,
                    "error": {"code": "MCP_RESPONSE_INVALID", "outcome": "unconfirmed"}})
                had_request_error = True
            else:
                _emit(output_stream, {"id": active_id, "ok": True, "result": result})
            active_id = None
    except _Interrupted as error:
        exit_code = 128 + error.signum
        _diagnostic(diagnostic_stream, {"event": "interrupted",
            "inFlightRequestId": active_id,
            "outcome": "unconfirmed" if active_id is not None else "no_request_in_flight"})
    except KeyboardInterrupt:
        exit_code = 130
        _diagnostic(diagnostic_stream, {"event": "interrupted",
            "inFlightRequestId": active_id,
            "outcome": "unconfirmed" if active_id is not None else "no_request_in_flight"})
    except OidcDeviceError as error:
        exit_code = 2
        _diagnostic(diagnostic_stream, {"event": "session-error", "code": "OIDC_SESSION_FAILED",
            **error.diagnostics(),
            "inFlightRequestId": active_id,
            "outcome": "unconfirmed" if active_id is not None else "no_request_in_flight"})
    except (ValueError, OSError):
        exit_code = 2
        _diagnostic(diagnostic_stream, {"event": "session-error", "code": "CLIENT_IO_OR_CONFIG_FAILED",
            "inFlightRequestId": active_id,
            "outcome": "unconfirmed" if active_id is not None else "no_request_in_flight"})
    except Exception:
        exit_code = 2
        _diagnostic(diagnostic_stream, {"event": "session-error", "code": "CLIENT_INTERNAL_ERROR",
            "inFlightRequestId": active_id,
            "outcome": "unconfirmed" if active_id is not None else "no_request_in_flight"})
    finally:
        if _cleanup_started is not None:
            _cleanup_started()
        if provider is not None:
            revoked = False
            revocation_error = None
            try:
                revoked = provider.revoke() is True
                if authenticated and not revoked:
                    exit_code = exit_code or 3
            except OidcDeviceError as error:
                revocation_error = error.diagnostics()
                exit_code = exit_code or 3
            finally:
                provider.close()
            _diagnostic(diagnostic_stream, {"event": "session-closed",
                "authenticated": authenticated,
                "remoteRevocation": ("confirmed" if authenticated and revoked else
                    "unconfirmed" if authenticated else "not_applicable"),
                "credentialsRetained": False,
                **({"revocationError": revocation_error} if revocation_error else {})})
    return exit_code or (1 if had_request_error else 0)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--client-id", default="openepm-mcp")
    parser.add_argument("--workspace-endpoint", required=True)
    parser.add_argument("--application-endpoint", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=30,
                        help="MCP request timeout, greater than 0 through 300 seconds")
    config = parser.parse_args(argv)
    with _termination_handlers() as cleanup_started:
        return run_session(config, input_stream=sys.stdin.buffer,
                           output_stream=sys.stdout, diagnostic_stream=sys.stderr,
                           _cleanup_started=cleanup_started)
