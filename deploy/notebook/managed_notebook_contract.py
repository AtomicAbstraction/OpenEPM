"""Fail-closed contracts for managed, per-user notebook environments."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import re
from typing import Mapping
from urllib.parse import urlparse


_IMAGE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$")
_SUBJECT = re.compile(r"^[^\x00-\x1f\x7f]{1,300}$")


@dataclass(frozen=True, slots=True)
class ManagedNotebookPolicy:
    image_profile: str
    image: str
    base_domain: str
    control_socket: str
    maximum_active: int = 10
    idle_seconds: int = 1800
    cpu_limit: int = 1
    memory_mib: int = 1024

    def __post_init__(self) -> None:
        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}", self.image_profile)
                or not _IMAGE.fullmatch(self.image)
                or not _DOMAIN.fullmatch(self.base_domain)
                or not self.control_socket.startswith("/run/openepm/")
                or not 1 <= self.maximum_active <= 10
                or not 300 <= self.idle_seconds <= 86400
                or self.cpu_limit != 1 or self.memory_mib != 1024):
            raise ValueError("MANAGED_NOTEBOOK_POLICY_INVALID")


@dataclass(frozen=True, slots=True)
class NotebookUserIdentity:
    issuer: str
    subject: str

    def __post_init__(self) -> None:
        if (not _SUBJECT.fullmatch(self.issuer)
                or not _SUBJECT.fullmatch(self.subject)):
            raise ValueError("MANAGED_NOTEBOOK_IDENTITY_INVALID")

    @property
    def key(self) -> str:
        return sha256((self.issuer + "\x00" + self.subject).encode()).hexdigest()[:32]

    @property
    def hub_username(self) -> str:
        return "u-" + self.key


def notebook_assignment(policy: ManagedNotebookPolicy,
                        identity: NotebookUserIdentity) -> dict:
    """Return only server-owned launcher inputs; never tokens or credentials."""
    key = identity.key
    return {
        "userKey": key,
        "hubUsername": identity.hub_username,
        "profileId": policy.image_profile,
        "volumeName": "openepm-notebook-" + key,
        "hostName": key + "." + policy.base_domain,
        "cpuLimit": policy.cpu_limit,
        "memoryMiB": policy.memory_mib,
        "idleSeconds": policy.idle_seconds,
    }


def assignment_for_hub_username(policy: ManagedNotebookPolicy,
                                username: str) -> dict:
    if not isinstance(username, str) or not re.fullmatch(r"u-[0-9a-f]{32}", username):
        raise ValueError("MANAGED_NOTEBOOK_SUBJECT_MAPPING_INVALID")
    key = username[2:]
    return {"userKey": key, "hubUsername": username,
        "profileId": policy.image_profile,
        "volumeName": "openepm-notebook-" + key,
        "hostName": key + "." + policy.base_domain,
        "cpuLimit": policy.cpu_limit, "memoryMiB": policy.memory_mib,
        "idleSeconds": policy.idle_seconds}


def policy_from_environment(environment: Mapping[str, str]) -> ManagedNotebookPolicy:
    if not isinstance(environment, Mapping):
        raise ValueError("MANAGED_NOTEBOOK_POLICY_INVALID")
    try:
        maximum = int(environment.get("EPM_NOTEBOOK_MAX_ACTIVE", "10"))
        idle = int(environment.get("EPM_NOTEBOOK_IDLE_SECONDS", "1800"))
        return ManagedNotebookPolicy(
            environment["EPM_NOTEBOOK_PROFILE_ID"],
            environment["EPM_NOTEBOOK_IMAGE"],
            environment["EPM_NOTEBOOK_BASE_DOMAIN"].lower(),
            environment.get("EPM_NOTEBOOK_CONTROL_SOCKET",
                            "/run/openepm/notebook-launcher.sock"),
            maximum, idle)
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("MANAGED_NOTEBOOK_POLICY_INVALID") from error


def public_hub_url(policy: ManagedNotebookPolicy, value: str) -> str:
    """Validate the external Hub origin without assuming TCP port 443."""
    if not isinstance(value, str):
        raise ValueError("MANAGED_NOTEBOOK_PUBLIC_URL_INVALID")
    parsed = urlparse(value)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("MANAGED_NOTEBOOK_PUBLIC_URL_INVALID") from error
    if (parsed.scheme != "https" or parsed.hostname != policy.base_domain
            or parsed.username or parsed.password or parsed.path not in ("", "/")
            or parsed.params or parsed.query or parsed.fragment or port == 0):
        raise ValueError("MANAGED_NOTEBOOK_PUBLIC_URL_INVALID")
    return value.rstrip("/")
