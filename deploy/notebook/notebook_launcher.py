"""Trusted host launcher for managed JupyterHub single-user containers.

Only the signed, fixed-shape start/poll/stop protocol is accepted.  Docker
policy, image, network, mounts, limits and command are owned by this process.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time


MAX_MESSAGE = 64 * 1024
_USER = re.compile(r"u-([0-9a-f]{32})$")
_IMAGE = re.compile(r"[^@\s]+@sha256:[0-9a-f]{64}$")
_DOMAIN = re.compile(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$")
_AUTH = frozenset(("JUPYTERHUB_API_TOKEN", "JUPYTERHUB_CLIENT_ID",
    "JUPYTERHUB_API_URL", "JUPYTERHUB_ACTIVITY_URL", "JUPYTERHUB_BASE_URL",
    "JUPYTERHUB_SERVICE_URL",
    "JUPYTERHUB_SERVICE_PREFIX", "JUPYTERHUB_OAUTH_CALLBACK_URL",
    "JUPYTERHUB_OAUTH_SCOPES", "JUPYTERHUB_OAUTH_ACCESS_SCOPES",
    "JUPYTERHUB_OAUTH_CLIENT_ALLOWED_SCOPES", "JUPYTERHUB_USER",
    "JUPYTERHUB_SERVER_NAME", "JUPYTERHUB_COOKIE_OPTIONS",
    "JUPYTERHUB_COOKIE_HOST_PREFIX_ENABLED", "JUPYTERHUB_DEFAULT_URL",
    "JUPYTERHUB_DISABLE_USER_CONFIG", "JUPYTERHUB_ROOT_DIR",
    "JUPYTERHUB_COOKIE_NAME", "JUPYTERHUB_HOST", "JUPYTERHUB_PUBLIC_URL",
    "JUPYTERHUB_PUBLIC_HUB_URL"))
_STORAGE_ROOT = Path("/var/lib/openepm/notebooks/current")


@dataclass(frozen=True, slots=True)
class NotebookProfile:
    profile_id: str
    image: str
    network: str
    base_domain: str
    maximum_active: int = 10
    idle_seconds: int = 1800
    storage_root: str = str(_STORAGE_ROOT)

    def __post_init__(self):
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", self.profile_id)
                or not _IMAGE.fullmatch(self.image)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}", self.network)
                or not _DOMAIN.fullmatch(self.base_domain)
                or not 1 <= self.maximum_active <= 10
                or not 300 <= self.idle_seconds <= 86400
                or self.storage_root != str(_STORAGE_ROOT)):
            raise ValueError("MANAGED_NOTEBOOK_PROFILE_INVALID")


class NotebookStorage:
    """Prepare only server-derived user directories below the fixed root."""

    def __init__(self, root: Path = _STORAGE_ROOT, *, _expected_root=None,
                 _expected_uid: int = 0, _chown=os.chown):
        self.root = root
        self._chown = _chown
        expected = _STORAGE_ROOT if _expected_root is None else _expected_root
        if (root != expected or not root.is_dir() or root.is_symlink()
                or root.stat().st_uid != _expected_uid or root.stat().st_mode & 0o022):
            raise ValueError("MANAGED_NOTEBOOK_STORAGE_INVALID")

    def prepare(self, key: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{32}", key):
            raise ValueError("MANAGED_NOTEBOOK_STORAGE_INVALID")
        users = self.root / "users"
        users.mkdir(mode=0o700, exist_ok=True)
        if users.is_symlink() or not users.is_dir():
            raise ValueError("MANAGED_NOTEBOOK_STORAGE_INVALID")
        target = users / key
        target.mkdir(mode=0o700, exist_ok=True)
        for relative in (Path(".jupyter"), Path(".local/share/jupyter/runtime"),
                         Path(".ipython")):
            current = target
            for part in relative.parts:
                current = current / part
                if current.exists() and (current.is_symlink()
                                         or not current.is_dir()):
                    raise ValueError("MANAGED_NOTEBOOK_STORAGE_INVALID")
                current.mkdir(mode=0o700, exist_ok=True)
        # Restores deliberately discard archived ownership.  Re-establish the
        # fixed notebook uid/gid after rejecting every non-regular entry.
        for path in (target, *sorted(target.rglob("*"))):
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise ValueError("MANAGED_NOTEBOOK_STORAGE_INVALID")
            self._chown(path, 10001, 10001)
        os.chmod(target, 0o700)
        return str(target)

    def mount_spec(self, key: str) -> str:
        """Return the fixed Docker mount owned by this trusted backend."""
        return ("type=bind,src=" + self.prepare(key)
                + ",dst=/home/openepm/work,bind-propagation=rprivate")


class DockerExecutor:
    def run(self, arguments, *, check=True):
        return subprocess.run(arguments, check=check, capture_output=True,
                              text=True, timeout=30)


class NotebookLauncher:
    def __init__(self, key: bytes, profile: NotebookProfile, *, executor=None,
                 clock=time.time, storage=None, event_sink=None):
        if not isinstance(key, bytes) or not 32 <= len(key) <= 4096:
            raise ValueError("MANAGED_NOTEBOOK_CONFIGURATION_INVALID")
        self.key, self.profile = key, profile
        self.executor, self.clock = executor or DockerExecutor(), clock
        self.storage = storage or NotebookStorage(Path(profile.storage_root))
        if event_sink is not None and not callable(event_sink):
            raise ValueError("MANAGED_NOTEBOOK_CONFIGURATION_INVALID")
        self.event_sink = event_sink or (lambda _event: None)
        self._nonces, self._activity = {}, {}
        self._lock = threading.Lock()
        inventory = self.executor.run(["docker", "info", "--format",
                                       "{{json .Runtimes}}"])
        if "runsc" not in inventory.stdout:
            raise ValueError("MANAGED_NOTEBOOK_RUNSC_UNAVAILABLE")
        # Activity state is deliberately not trusted across launcher restarts.
        # Stop orphaned managed containers; Hub will create fresh authenticated
        # servers rather than allowing an environment to evade the idle limit.
        for name in self._active():
            self.executor.run(["docker", "rm", "-f", name], check=False)

    @staticmethod
    def _container(key): return "openepm-notebook-" + key

    def _verify(self, request):
        if type(request) is not dict or set(request) != {"version", "action",
                "issuedAt", "activityAt", "nonce", "assignment", "authentication", "signature"}:
            raise ValueError("MANAGED_NOTEBOOK_REQUEST_INVALID")
        signature = request["signature"]
        unsigned = {key: value for key, value in request.items() if key != "signature"}
        encoded = json.dumps(unsigned, sort_keys=True,
                             separators=(",", ":")).encode()
        expected = hmac.new(self.key, encoded, sha256).hexdigest()
        if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
            raise ValueError("MANAGED_NOTEBOOK_SIGNATURE_INVALID")
        now = int(self.clock())
        if (request["version"] != 1 or request["action"] not in
                ("start", "poll", "stop") or type(request["issuedAt"]) is not int
                or type(request["activityAt"]) is not int
                or not 0 <= request["activityAt"] <= now + 60
                or abs(now - request["issuedAt"]) > 60
                or not isinstance(request["nonce"], str)
                or not re.fullmatch(r"[0-9a-f]{32}", request["nonce"])):
            raise ValueError("MANAGED_NOTEBOOK_REQUEST_INVALID")
        with self._lock:
            self._nonces = {n: t for n, t in self._nonces.items() if now - t <= 60}
            if request["nonce"] in self._nonces:
                raise ValueError("MANAGED_NOTEBOOK_REPLAY_DENIED")
            self._nonces[request["nonce"]] = now
        assignment = self._assignment(request["assignment"])
        return assignment, self._authentication(request["action"],
                                                  request["authentication"], assignment)

    def _assignment(self, value):
        fields = {"userKey", "hubUsername", "profileId", "volumeName",
                  "hostName", "cpuLimit", "memoryMiB", "idleSeconds"}
        if type(value) is not dict or set(value) != fields:
            raise ValueError("MANAGED_NOTEBOOK_ASSIGNMENT_INVALID")
        match = _USER.fullmatch(value.get("hubUsername", ""))
        key = match.group(1) if match else ""
        expected = {"userKey": key, "hubUsername": "u-" + key,
            "profileId": self.profile.profile_id,
            "volumeName": "openepm-notebook-" + key,
            "hostName": key + "." + self.profile.base_domain,
            "cpuLimit": 1, "memoryMiB": 1024,
            "idleSeconds": self.profile.idle_seconds}
        if not key or value != expected:
            raise ValueError("MANAGED_NOTEBOOK_ASSIGNMENT_INVALID")
        return value

    @staticmethod
    def _authentication(action, value, assignment):
        if type(value) is not dict or not set(value).issubset(_AUTH):
            raise ValueError("MANAGED_NOTEBOOK_AUTHENTICATION_INVALID")
        if action != "start" and value:
            raise ValueError("MANAGED_NOTEBOOK_AUTHENTICATION_INVALID")
        for name, item in value.items():
            if (not isinstance(item, str) or len(item) > 8192 or "\x00" in item
                    or (not item and name != "JUPYTERHUB_SERVER_NAME")):
                raise ValueError("MANAGED_NOTEBOOK_AUTHENTICATION_INVALID")
        required = {"JUPYTERHUB_API_TOKEN", "JUPYTERHUB_API_URL",
                    "JUPYTERHUB_SERVICE_PREFIX", "JUPYTERHUB_SERVICE_URL",
                    "JUPYTERHUB_USER"}
        if action == "start" and not required.issubset(value):
            raise ValueError("MANAGED_NOTEBOOK_AUTHENTICATION_INVALID")
        if action == "start":
            username = assignment["hubUsername"]
            prefix = value["JUPYTERHUB_SERVICE_PREFIX"]
            # The launcher is the last trusted boundary before values become
            # kernel environment.  Bind all network-bearing values to the
            # server-owned Hub alias and the assigned user instead of trusting
            # a valid HMAC as authority for arbitrary destinations.
            if (value["JUPYTERHUB_USER"] != username
                    or value["JUPYTERHUB_API_URL"] !=
                    "http://hub:8081/hub/api"
                    or prefix != "/user/" + username + "/"
                    or value["JUPYTERHUB_SERVICE_URL"] !=
                    "http://0.0.0.0:8888" + prefix):
                raise ValueError("MANAGED_NOTEBOOK_AUTHENTICATION_INVALID")
            activity_url = value.get("JUPYTERHUB_ACTIVITY_URL")
            if (activity_url is not None and activity_url !=
                    "http://hub:8081/hub/api/users/" + username + "/activity"):
                raise ValueError("MANAGED_NOTEBOOK_AUTHENTICATION_INVALID")
        return value

    def _running(self, name):
        result = self.executor.run(["docker", "inspect", "--format",
            "{{.State.Running}}", name], check=False)
        return result.returncode == 0 and result.stdout.strip() == "true"

    def _active(self):
        result = self.executor.run(["docker", "ps", "-a", "--filter",
            "label=org.openepm.managed-notebook=true", "--format", "{{.Names}}"])
        return {line for line in result.stdout.splitlines() if line}

    def _hub_ip(self):
        """Resolve the one trusted Hub endpoint without caller-controlled DNS."""
        result = self.executor.run(["docker", "ps", "--filter",
            "label=org.openepm.managed-notebook-hub=true", "--filter",
            "network=" + self.profile.network, "--format", "{{.Names}}"])
        names = [line for line in result.stdout.splitlines() if line]
        if len(names) != 1:
            raise ValueError("MANAGED_NOTEBOOK_HUB_UNAVAILABLE")
        result = self.executor.run(["docker", "inspect", "--format",
            "{{with index .NetworkSettings.Networks \"" + self.profile.network
            + "\"}}{{.IPAddress}}{{end}}", names[0]])
        try:
            address = ipaddress.ip_address(result.stdout.strip())
        except ValueError as error:
            raise ValueError("MANAGED_NOTEBOOK_HUB_UNAVAILABLE") from error
        if address.version != 4 or not address.is_private:
            raise ValueError("MANAGED_NOTEBOOK_HUB_UNAVAILABLE")
        return str(address)

    def _expire_idle(self, now):
        for name, touched in tuple(self._activity.items()):
            if now - touched >= self.profile.idle_seconds:
                result = self.executor.run(["docker", "rm", "-f", name],
                                           check=False)
                # A temporary Docker failure must not disable later retries.
                if result.returncode != 0:
                    continue
                self._activity.pop(name, None)
                try:
                    self.event_sink({
                        "format": "openepm-notebook-launcher-event-v1",
                        "event": "idle-expired",
                        "container": name,
                        "lastActivityAt": touched,
                        "expiredAt": now,
                        "idleSeconds": self.profile.idle_seconds,
                    })
                except (OSError, ValueError):
                    # Journal failure cannot undo a completed security stop or
                    # terminate the autonomous reaper thread.
                    pass

    def expire_idle(self):
        """Enforce the idle limit without requiring an inbound Hub request."""
        with self._lock:
            self._expire_idle(int(self.clock()))

    def handle(self, request):
        assignment, authentication = self._verify(request)
        now, action = int(self.clock()), request["action"]
        name = self._container(assignment["userKey"])
        with self._lock:
            # A signed Hub activity observation belongs to the current server.
            # Apply it before the global expiry sweep so an active session is
            # not killed merely because its poll arrives at the boundary.
            if action in ("start", "poll") and self._running(name):
                self._activity[name] = max(self._activity.get(name, 0),
                                           request["activityAt"])
            self._expire_idle(now)
            if action == "poll":
                running = self._running(name)
                return {"ok": True, "running": running}
            if action == "stop":
                self.executor.run(["docker", "rm", "-f", name], check=False)
                self._activity.pop(name, None)
                return {"ok": True}
            if self._running(name):
                return {"ok": True, "url": "http://" + name + ":8888"}
            active = self._active()
            # A prior single-user process can exit before Hub observes it.  The
            # fixed name must be reclaimed before a fresh authenticated start.
            if name in active:
                removed = self.executor.run(["docker", "rm", "-f", name],
                                            check=False)
                if removed.returncode != 0:
                    raise ValueError("MANAGED_NOTEBOOK_STALE_CONTAINER")
                active.remove(name)
            if len(active) >= self.profile.maximum_active:
                raise ValueError("MANAGED_NOTEBOOK_CAPACITY_EXCEEDED")
            arguments = ["docker", "run", "-d", "--name", name,
                "--runtime", "runsc", "--user", "10001:10001", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
                "--pids-limit", "256", "--cpus", "1", "--memory", "1024m",
                "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m",
                "--network", self.profile.network, "--hostname", assignment["hostName"],
                "--add-host", "hub:" + self._hub_ip(),
                "--label", "org.openepm.managed-notebook=true",
                "--label", "org.openepm.notebook-user=" + assignment["userKey"],
                "--mount", self.storage.mount_spec(assignment["userKey"]),
                "--env", "HOME=/home/openepm/work",
                "--env", "JUPYTER_CONFIG_DIR=/home/openepm/work/.jupyter",
                "--env", "JUPYTER_DATA_DIR=/home/openepm/work/.local/share/jupyter",
                "--env", "IPYTHONDIR=/home/openepm/work/.ipython"]
            for key in sorted(authentication):
                arguments.extend(("--env", key + "=" + authentication[key]))
            arguments.extend((self.profile.image, "jupyterhub-singleuser"))
            self.executor.run(arguments)
            self._activity[name] = request["activityAt"]
            return {"ok": True, "url": "http://" + name + ":8888"}


def signed_request(key, payload):
    unsigned = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return {**payload, "signature": hmac.new(key, unsigned, sha256).hexdigest()}
