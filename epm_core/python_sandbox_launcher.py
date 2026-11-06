"""Fail-closed gVisor/Docker launcher for untrusted Python plan builders.

The launcher never receives source, database credentials, Docker arguments or
host paths from a caller.  It resolves an administrator-approved immutable
image profile and sends the short-lived build capability over container stdin,
keeping it out of process arguments, environment variables and mounts.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
import re
import selectors
import subprocess
import time
from typing import Mapping, Protocol, Sequence

from .python_program_execution import (MAX_BUILD_LOG_BYTES, MAX_PLAN_BYTES,
                                       MAX_SOURCE_MAP_BYTES)


_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_NETWORK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
# Both forms are immutable Docker content identities. Release bundles use the
# registry-qualified form; an owner-operated local build may have only its
# exact image ID until it is pushed to a registry.
_IMAGE = re.compile(r"^(?:[^@\s]+@)?sha256:[0-9a-f]{64}$")
_CONTAINER = re.compile(r"^[0-9a-f]{12,64}$")
_BROKER_URL = re.compile(
    r"^https?://[A-Za-z0-9][A-Za-z0-9.-]{0,252}:[0-9]{2,5}/internal/python-build/read$")
MAX_LAUNCH_INPUT_BYTES = 8 * 1024
MAX_LAUNCH_OUTPUT_BYTES = 8 * 1024
MAX_SANDBOX_OUTPUT_BYTES = (MAX_PLAN_BYTES + MAX_SOURCE_MAP_BYTES
                            + MAX_BUILD_LOG_BYTES + 64 * 1024)


@dataclass(frozen=True, slots=True)
class ApprovedSandboxEnvironment:
    environment_id: str
    version: int
    image: str
    network: str
    compiler_versions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (type(self.environment_id) is not str
                or _ID.fullmatch(self.environment_id) is None
                or type(self.version) is not int or self.version < 1
                or type(self.image) is not str or _IMAGE.fullmatch(self.image) is None
                or type(self.network) is not str
                or _NETWORK.fullmatch(self.network) is None
                or type(self.compiler_versions) is not tuple
                or len(self.compiler_versions) > 32
                or len(set(self.compiler_versions)) != len(
                    self.compiler_versions)
                or any(type(item) is not str
                       or _ID.fullmatch(item) is None
                       for item in self.compiler_versions)):
            raise ValueError("PYTHON_SANDBOX_PROFILE_INVALID")


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    output: bytes


class CommandExecutor(Protocol):
    def execute(self, arguments: Sequence[str], *, stdin: bytes = b"",
                timeout_seconds: int, max_output_bytes: int) -> CommandResult: ...


class BoundedCommandExecutor:
    """Execute a trusted command while bounding merged stdout/stderr."""

    def execute(self, arguments: Sequence[str], *, stdin: bytes = b"",
                timeout_seconds: int, max_output_bytes: int) -> CommandResult:
        if (not isinstance(arguments, (list, tuple)) or not arguments
                or any(type(value) is not str or not value for value in arguments)
                or type(stdin) is not bytes
                or type(timeout_seconds) is not int or timeout_seconds < 1
                or type(max_output_bytes) is not int or max_output_bytes < 1):
            raise ValueError("PYTHON_SANDBOX_COMMAND_INVALID")
        process = subprocess.Popen(list(arguments), stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
        assert process.stdin is not None and process.stdout is not None
        try:
            process.stdin.write(stdin)
            process.stdin.close()
            selector = selectors.DefaultSelector()
            selector.register(process.stdout, selectors.EVENT_READ)
            output = bytearray()
            deadline = time.monotonic() + timeout_seconds
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("PYTHON_SANDBOX_COMMAND_TIMEOUT")
                events = selector.select(min(remaining, 0.25))
                if not events and process.poll() is not None:
                    events = [(next(iter(selector.get_map().values())), 0)]
                for key, _ in events:
                    chunk = os.read(key.fd, min(65536,
                        max_output_bytes + 1 - len(output)))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output.extend(chunk)
                    if len(output) > max_output_bytes:
                        raise ValueError("PYTHON_SANDBOX_COMMAND_OUTPUT_LIMIT")
            remaining = max(0.001, deadline - time.monotonic())
            returncode = process.wait(timeout=remaining)
            return CommandResult(returncode, bytes(output))
        except Exception:
            process.kill()
            process.wait()
            raise
        finally:
            process.stdout.close()


@dataclass(frozen=True, slots=True)
class SandboxBuildOutput:
    proposed_plan: dict
    source_map: dict
    build_log: str


class GVisorDockerSandboxLauncher:
    """Launch only approved immutable images under Docker's runsc runtime."""

    def __init__(self, profiles: Sequence[ApprovedSandboxEnvironment], *,
                 executor: CommandExecutor | None = None,
                 docker_binary: str = "docker",
                 broker_url: str = "http://python-build-broker:5198/internal/python-build/read",
                 event_sink=None):
        if (not isinstance(profiles, (list, tuple)) or not profiles
                or any(not isinstance(profile, ApprovedSandboxEnvironment)
                       for profile in profiles)
                or type(docker_binary) is not str
                or docker_binary != "docker" or type(broker_url) is not str
                or _BROKER_URL.fullmatch(broker_url) is None
                or event_sink is not None and not callable(event_sink)):
            raise ValueError("PYTHON_SANDBOX_CONFIGURATION_INVALID")
        indexed = {(profile.environment_id, profile.version): profile
                   for profile in profiles}
        if len(indexed) != len(profiles):
            raise ValueError("PYTHON_SANDBOX_CONFIGURATION_INVALID")
        self._profiles: Mapping[tuple[str, int], ApprovedSandboxEnvironment] = indexed
        self._executor = executor or BoundedCommandExecutor()
        self._docker = docker_binary
        self._broker_url = broker_url
        self._event_sink = event_sink or (lambda _event: None)
        result = self._execute([self._docker, "info", "--format",
            "{{json .Runtimes}}"], timeout=10, maximum=64 * 1024)
        try:
            runtimes = json.loads(result.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("PYTHON_SANDBOX_RUNTIME_UNAVAILABLE") from error
        if type(runtimes) is not dict or "runsc" not in runtimes:
            raise ValueError("PYTHON_SANDBOX_RUNTIME_UNAVAILABLE")

    def _execute(self, arguments: Sequence[str], *, stdin: bytes = b"",
                 timeout: int, maximum: int) -> bytes:
        result = self._executor.execute(arguments, stdin=stdin,
            timeout_seconds=timeout, max_output_bytes=maximum)
        if result.returncode != 0:
            raise ValueError("PYTHON_SANDBOX_COMMAND_FAILED")
        return result.output

    @staticmethod
    def _name(build_id: str) -> str:
        if type(build_id) is not str or _HEX32.fullmatch(build_id) is None:
            raise ValueError("PYTHON_BUILD_ID_INVALID")
        return "openepm-build-" + build_id

    def _profile(self, environment_id: str,
                 environment_version: int) -> ApprovedSandboxEnvironment:
        if (type(environment_id) is not str or _ID.fullmatch(environment_id) is None
                or type(environment_version) is not int
                or environment_version < 1):
            raise ValueError("PYTHON_BUILD_ENVIRONMENT_INVALID")
        profile = self._profiles.get((environment_id, environment_version))
        if profile is None:
            raise ValueError("PYTHON_SANDBOX_PROFILE_UNAVAILABLE")
        return profile

    def start(self, *, build_id: str, environment_id: str,
              environment_version: int, capability_token: str,
              claim_generation: int, workspace_id: str, application_id: str,
              cpu_limit: int, memory_mib: int,
              wall_seconds: int) -> None:
        name = self._name(build_id)
        profile = self._profile(environment_id, environment_version)
        if (type(claim_generation) is not int or claim_generation < 1
                or cpu_limit != 1 or memory_mib != 512 or wall_seconds != 60
                or type(capability_token) is not str
                or type(workspace_id) is not str or not workspace_id
                or type(application_id) is not str or not application_id
                or not 1 <= len(capability_token.encode("utf-8")) <= 4096
                or any(ord(character) < 32 for character in capability_token)):
            raise ValueError("PYTHON_SANDBOX_LAUNCH_INVALID")
        request = json.dumps({"buildId": build_id,
            "claimGeneration": claim_generation,
            "capabilityToken": capability_token, "workspaceId": workspace_id,
            "applicationId": application_id, "brokerUrl": self._broker_url},
            sort_keys=True,
            separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
        if len(request) > MAX_LAUNCH_INPUT_BYTES:
            raise ValueError("PYTHON_SANDBOX_LAUNCH_INVALID")
        arguments = [self._docker, "run", "--detach", "--interactive",
            "--pull", "never", "--name", name,
            "--label", "openepm.python-build=true",
            "--label", "openepm.build-id=" + build_id,
            "--label", "openepm.claim-generation=" + str(claim_generation),
            "--label", "openepm.environment-id=" + environment_id,
            "--label", "openepm.environment-version=" + str(environment_version),
            "--runtime", "runsc", "--user", "10001:10001",
            "--read-only", "--cap-drop", "ALL", "--security-opt",
            "no-new-privileges:true", "--pids-limit", "128",
            "--cpus", "1", "--memory", "512m", "--stop-timeout", "5",
            "--network", profile.network,
            "--tmpfs", "/workspace:rw,noexec,nosuid,nodev,size=16m",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m",
            profile.image]
        # Detached `docker run --interactive` keeps PID 1's stdin open but the
        # CLI does not forward its own stdin in detached mode. Start first,
        # then attach only long enough to deliver the single framed request.
        # The capability never enters arguments, environment variables,
        # labels, files or mounts.
        output = self._execute(arguments, timeout=20,
                               maximum=MAX_LAUNCH_OUTPUT_BYTES)
        container_id = output.decode("ascii", "strict").strip()
        if _CONTAINER.fullmatch(container_id) is None:
            # A container may have started despite malformed CLI output.
            try:
                self._execute([self._docker, "rm", "--force", name],
                    timeout=20, maximum=MAX_LAUNCH_OUTPUT_BYTES)
            finally:
                raise ValueError("PYTHON_SANDBOX_CONTAINER_ID_INVALID")
        try:
            self._execute([self._docker, "attach", "--sig-proxy=false", name],
                stdin=request, timeout=wall_seconds + 5,
                maximum=MAX_SANDBOX_OUTPUT_BYTES)
        except TimeoutError as error:
            self.terminate(build_id=build_id,
                           claim_generation=claim_generation)
            raise ValueError("PYTHON_SANDBOX_WALL_TIME_LIMIT") from error
        except Exception:
            try:
                self.terminate(build_id=build_id,
                               claim_generation=claim_generation)
            finally:
                raise

    def collect(self, *, build_id: str, claim_generation: int,
                wall_seconds: int = 60) -> SandboxBuildOutput:
        name = self._name(build_id)
        if (type(claim_generation) is not int or claim_generation < 1
                or wall_seconds != 60):
            raise ValueError("PYTHON_SANDBOX_COLLECT_INVALID")
        try:
            observed = self._label(name, "openepm.claim-generation")
            if observed != str(claim_generation):
                raise ValueError("PYTHON_SANDBOX_STALE_CLAIM")
            attestation = self._runtime_attestation(name, build_id,
                                                    claim_generation)
            waited = self._execute([self._docker, "wait", name],
                timeout=wall_seconds + 5, maximum=1024).decode("ascii").strip()
            if waited != "0":
                raise ValueError("PYTHON_SANDBOX_BUILD_FAILED")
            raw = self._execute([self._docker, "logs", name], timeout=10,
                                maximum=MAX_SANDBOX_OUTPUT_BYTES)
            try:
                value = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError("PYTHON_SANDBOX_OUTPUT_INVALID") from error
            if (type(value) is not dict
                    or set(value) != {"plan", "sourceMap", "buildLog"}
                    or type(value["plan"]) is not dict
                    or type(value["sourceMap"]) is not dict
                    or type(value["buildLog"]) is not str):
                raise ValueError("PYTHON_SANDBOX_OUTPUT_INVALID")
            try:
                self._event_sink(attestation)
            except (OSError, ValueError):
                # Product completion is durable independently of host-journal
                # availability; release qualification requires the event.
                pass
            return SandboxBuildOutput(value["plan"], value["sourceMap"],
                                      value["buildLog"])
        except TimeoutError as error:
            self.terminate(build_id=build_id,
                           claim_generation=claim_generation)
            raise ValueError("PYTHON_SANDBOX_WALL_TIME_LIMIT") from error
        finally:
            # Successful and failed stopped containers retain no writable layer.
            try:
                self._remove_if_claim(name, claim_generation)
            except ValueError:
                pass

    def _label(self, name: str, label: str) -> str:
        return self._execute([self._docker, "inspect", "--format",
            "{{ index .Config.Labels \"" + label + "\" }}", name],
            timeout=10, maximum=1024).decode("utf-8").strip()

    def _runtime_attestation(self, name: str, build_id: str,
                             claim_generation: int) -> dict:
        raw = self._execute([self._docker, "inspect", "--format", "{{json .}}",
            name], timeout=10, maximum=64 * 1024)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("PYTHON_SANDBOX_RUNTIME_ATTESTATION_INVALID") from error
        config = value.get("Config") if isinstance(value, dict) else None
        host = value.get("HostConfig") if isinstance(value, dict) else None
        labels = config.get("Labels") if isinstance(config, dict) else None
        environment_id = labels.get("openepm.environment-id") \
            if isinstance(labels, dict) else None
        environment_version = labels.get("openepm.environment-version") \
            if isinstance(labels, dict) else None
        profile = self._profiles.get((environment_id,
            int(environment_version) if isinstance(environment_version, str)
            and environment_version.isdecimal() else -1))
        expected_labels = {"openepm.python-build": "true",
            "openepm.build-id": build_id,
            "openepm.claim-generation": str(claim_generation),
            "openepm.environment-id": environment_id,
            "openepm.environment-version": environment_version}
        container_id = value.get("Id") if isinstance(value, dict) else None
        if (profile is None or not isinstance(container_id, str)
                or _CONTAINER.fullmatch(container_id) is None
                or any(labels.get(key) != item
                       for key, item in expected_labels.items())
                or config.get("Image") != profile.image
                or not isinstance(host, dict)
                or host.get("Runtime") != "runsc"
                or host.get("ReadonlyRootfs") is not True
                or host.get("CapDrop") != ["ALL"]
                or "no-new-privileges:true" not in host.get("SecurityOpt", [])
                or host.get("PidsLimit") != 128
                or host.get("NanoCpus") != 1_000_000_000
                or host.get("Memory") != 512 * 1024 * 1024
                or host.get("NetworkMode") != profile.network):
            raise ValueError("PYTHON_SANDBOX_RUNTIME_ATTESTATION_INVALID")
        return {"format": "openepm-sandbox-launcher-event-v1",
            "event": "sandbox-build-collected", "buildId": build_id,
            "claimGeneration": claim_generation, "containerId": container_id,
            "runtime": "runsc", "image": profile.image,
            "environmentId": profile.environment_id,
            "environmentVersion": profile.version,
            "rootReadOnly": True, "capabilitiesDropped": True,
            "noNewPrivileges": True, "pidsLimit": 128,
            "cpuLimit": 1, "memoryMiB": 512, "network": profile.network}

    def _remove_if_claim(self, name: str, claim_generation: int) -> None:
        if self._label(name, "openepm.claim-generation") != str(claim_generation):
            raise ValueError("PYTHON_SANDBOX_STALE_CLAIM")
        self._execute([self._docker, "rm", "--force", name], timeout=20,
                      maximum=MAX_LAUNCH_OUTPUT_BYTES)

    def terminate(self, *, build_id: str, claim_generation: int) -> None:
        name = self._name(build_id)
        if type(claim_generation) is not int or claim_generation < 1:
            raise ValueError("PYTHON_BUILD_CLAIM_INVALID")
        self._remove_if_claim(name, claim_generation)

