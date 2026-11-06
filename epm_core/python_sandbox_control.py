"""Authenticated narrow control plane for the host gVisor launcher.

The application worker talks only to a Unix socket.  The host service owns the
Docker client and resolves all image, network, command and mount choices from
its deployment-owned profile file.
"""
from __future__ import annotations

from collections import OrderedDict
from hashlib import sha256
import hmac
import json
import os
import secrets
import socket
import struct
import threading
import time

from .python_sandbox_launcher import SandboxBuildOutput


MAX_MESSAGE = 6 * 1024 * 1024
MAX_CLOCK_SKEW = 30
_ACTIONS = frozenset(("start", "collect", "terminate"))
_SAFE_ERROR_PREFIXES = ("PYTHON_SANDBOX_", "PYTHON_BUILD_", "BUILDER_")


def _safe_error_code(error: Exception) -> str:
    value = str(error)
    if (isinstance(error, ValueError)
            and value.startswith(_SAFE_ERROR_PREFIXES)
            and value.replace("_", "").isalnum()
            and value.upper() == value
            and len(value) <= 100):
        return value
    return "PYTHON_SANDBOX_CONTROL_COMMAND_FAILED"


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _signature(key: bytes, request: dict) -> str:
    unsigned = {name: value for name, value in request.items()
                if name != "signature"}
    return hmac.new(key, _canonical(unsigned), sha256).hexdigest()


class SandboxControlProtocol:
    """Verify fixed requests and dispatch only the three launcher methods."""

    def __init__(self, key: bytes, launcher, *, clock=None, nonce_limit=4096):
        if (type(key) is not bytes or len(key) < 32
                or not all(hasattr(launcher, name) for name in _ACTIONS)
                or type(nonce_limit) is not int or nonce_limit < 128):
            raise ValueError("PYTHON_SANDBOX_CONTROL_CONFIGURATION_INVALID")
        self.key, self.launcher = key, launcher
        self.clock = clock or (lambda: int(time.time()))
        self.nonce_limit = nonce_limit
        self._nonces: OrderedDict[str, int] = OrderedDict()
        self._nonce_lock = threading.Lock()

    def handle(self, request: object) -> dict:
        required = {"version", "action", "issuedAt", "nonce", "payload",
                    "signature"}
        if (type(request) is not dict or set(request) != required
                or request["version"] != 1
                or request["action"] not in _ACTIONS
                or type(request["issuedAt"]) is not int
                or type(request["nonce"]) is not str
                or len(request["nonce"]) != 32
                or type(request["payload"]) is not dict
                or type(request["signature"]) is not str):
            raise ValueError("PYTHON_SANDBOX_CONTROL_DENIED")
        now = self.clock()
        supplied = request["signature"]
        expected = _signature(self.key, request)
        if (type(now) is not int
                or abs(now - request["issuedAt"]) > MAX_CLOCK_SKEW
                or not hmac.compare_digest(supplied, expected)):
            raise ValueError("PYTHON_SANDBOX_CONTROL_DENIED")
        with self._nonce_lock:
            expired = [nonce for nonce, issued in self._nonces.items()
                       if issued < now - MAX_CLOCK_SKEW]
            for nonce in expired:
                self._nonces.pop(nonce, None)
            if request["nonce"] in self._nonces:
                raise ValueError("PYTHON_SANDBOX_CONTROL_DENIED")
            if len(self._nonces) >= self.nonce_limit:
                raise ValueError("PYTHON_SANDBOX_CONTROL_CAPACITY")
            self._nonces[request["nonce"]] = now
        payload = request["payload"]
        action = request["action"]
        if action == "start":
            required_payload = {"build_id", "environment_id",
                "environment_version", "capability_token", "claim_generation",
                "workspace_id", "application_id", "cpu_limit", "memory_mib",
                "wall_seconds"}
            if set(payload) != required_payload:
                raise ValueError("PYTHON_SANDBOX_CONTROL_DENIED")
            self.launcher.start(**payload)
            return {"ok": True}
        required_payload = {"build_id", "claim_generation"}
        if action == "collect":
            required_payload.add("wall_seconds")
        if set(payload) != required_payload:
            raise ValueError("PYTHON_SANDBOX_CONTROL_DENIED")
        result = getattr(self.launcher, action)(**payload)
        if action == "collect":
            return {"plan": result.proposed_plan, "sourceMap": result.source_map,
                    "buildLog": result.build_log}
        return {"ok": True}


class UnixSandboxControlClient:
    """Launcher-compatible client; it has no Docker or host-path interface."""

    def __init__(self, socket_path: str, key: bytes, *, clock=None,
                 nonce_factory=None, timeout_seconds=75):
        if (type(socket_path) is not str or not socket_path.startswith("/")
                or len(socket_path) > 200 or type(key) is not bytes
                or len(key) < 32 or type(timeout_seconds) is not int
                or not 10 <= timeout_seconds <= 120):
            raise ValueError("PYTHON_SANDBOX_CONTROL_CONFIGURATION_INVALID")
        self.socket_path, self.key = socket_path, key
        self.clock = clock or (lambda: int(time.time()))
        self.nonce_factory = nonce_factory or (lambda: secrets.token_hex(16))
        self.timeout_seconds = timeout_seconds

    def _call(self, action: str, payload: dict) -> dict:
        request = {"version": 1, "action": action,
                   "issuedAt": self.clock(), "nonce": self.nonce_factory(),
                   "payload": payload}
        request["signature"] = _signature(self.key, request)
        raw = _canonical(request)
        if len(raw) > MAX_MESSAGE:
            raise ValueError("PYTHON_SANDBOX_CONTROL_REQUEST_LIMIT")
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout_seconds)
                connection.connect(self.socket_path)
                connection.sendall(struct.pack("!I", len(raw)) + raw)
                size = self._receive(connection, 4)
                length = struct.unpack("!I", size)[0]
                if length < 2 or length > MAX_MESSAGE:
                    raise ValueError("PYTHON_SANDBOX_CONTROL_RESPONSE_INVALID")
                response = json.loads(self._receive(connection, length))
        except (OSError, UnicodeError, json.JSONDecodeError, struct.error) as error:
            raise ValueError("PYTHON_SANDBOX_CONTROL_UNAVAILABLE") from error
        if type(response) is not dict or set(response) not in (
                {"ok", "result"}, {"ok", "result", "errorCode"}):
            raise ValueError("PYTHON_SANDBOX_CONTROL_RESPONSE_INVALID")
        if response["ok"] is not True:
            code = response.get("errorCode")
            if (type(code) is not str
                    or not code.startswith(_SAFE_ERROR_PREFIXES)):
                raise ValueError("PYTHON_SANDBOX_CONTROL_COMMAND_FAILED")
            raise ValueError(code)
        if type(response["result"]) is not dict:
            raise ValueError("PYTHON_SANDBOX_CONTROL_RESPONSE_INVALID")
        return response["result"]

    @staticmethod
    def _receive(connection, count: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < count:
            chunk = connection.recv(count - len(chunks))
            if not chunk:
                raise OSError("short sandbox control response")
            chunks.extend(chunk)
        return bytes(chunks)

    def start(self, **values) -> None:
        self._call("start", values)

    def collect(self, *, build_id: str, claim_generation: int,
                wall_seconds: int = 60) -> SandboxBuildOutput:
        value = self._call("collect", {"build_id": build_id,
            "claim_generation": claim_generation, "wall_seconds": wall_seconds})
        if (set(value) != {"plan", "sourceMap", "buildLog"}
                or type(value["plan"]) is not dict
                or type(value["sourceMap"]) is not dict
                or type(value["buildLog"]) is not str):
            raise ValueError("PYTHON_SANDBOX_CONTROL_RESPONSE_INVALID")
        return SandboxBuildOutput(value["plan"], value["sourceMap"],
                                  value["buildLog"])

    def terminate(self, *, build_id: str, claim_generation: int) -> None:
        self._call("terminate", {"build_id": build_id,
            "claim_generation": claim_generation})


def serve_connection(connection, protocol: SandboxControlProtocol) -> None:
    """Serve one already-accepted Unix connection with generic errors only."""
    try:
        header = UnixSandboxControlClient._receive(connection, 4)
        length = struct.unpack("!I", header)[0]
        if length < 2 or length > MAX_MESSAGE:
            raise ValueError
        request = json.loads(UnixSandboxControlClient._receive(connection, length))
        result = protocol.handle(request)
        response = {"ok": True, "result": result}
    except Exception as error:
        response = {"ok": False, "result": {},
                    "errorCode": _safe_error_code(error)}
    raw = _canonical(response)
    if len(raw) > MAX_MESSAGE:
        raw = _canonical({"ok": False, "result": {}})
    connection.sendall(struct.pack("!I", len(raw)) + raw)
