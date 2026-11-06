"""Strict deployment-owned configuration for the Python build worker.

Parsing is kept separate from worker construction so tests and installers can
validate a release without connecting to PostgreSQL or Docker.  Secret file
contents are never returned by diagnostics or copied into sandbox profiles.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Mapping

from .python_sandbox_launcher import ApprovedSandboxEnvironment


@dataclass(frozen=True, slots=True)
class PythonBuildDeployment:
    coordinator_dsn: str
    capability_key: bytes
    profiles: tuple[ApprovedSandboxEnvironment, ...]
    broker_url: str


def load_approved_profiles_file(path: str) -> tuple[ApprovedSandboxEnvironment, ...]:
    target = Path(path)
    try:
        if not target.is_file() or target.is_symlink():
            raise ValueError
        value = target.read_bytes()
        if not value or len(value) > 1024 * 1024:
            raise ValueError
        raw = json.loads(value)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("PYTHON_BUILD_PROFILES_UNAVAILABLE") from error
    if (type(raw) is not dict or set(raw) != {"profiles"}
            or type(raw["profiles"]) is not list or not raw["profiles"]):
        raise ValueError("PYTHON_BUILD_PROFILES_INVALID")
    profiles = []
    for item in raw["profiles"]:
        if (type(item) is not dict
                or not {"environmentId", "environmentVersion", "image",
                        "network"}.issubset(item)
                or not set(item).issubset({"environmentId",
                    "environmentVersion", "image", "network",
                    "compilerVersions"})):
            raise ValueError("PYTHON_BUILD_PROFILES_INVALID")
        compilers = item.get("compilerVersions", [])
        if type(compilers) is not list:
            raise ValueError("PYTHON_BUILD_PROFILES_INVALID")
        profiles.append(ApprovedSandboxEnvironment(item["environmentId"],
            item["environmentVersion"], item["image"], item["network"],
            tuple(compilers)))
    identities = {(item.environment_id, item.version) for item in profiles}
    if len(identities) != len(profiles):
        raise ValueError("PYTHON_BUILD_PROFILES_INVALID")
    return tuple(profiles)


def load_python_build_deployment(environment: Mapping[str, str]) -> PythonBuildDeployment:
    names = ("EPM_PYTHON_COORDINATOR_DSN_FILE",
             "EPM_PYTHON_BUILD_CAPABILITY_KEY_FILE",
             "EPM_PYTHON_BUILDER_PROFILES_FILE")
    if (not isinstance(environment, Mapping)
            or any(type(environment.get(name)) is not str
                   or not environment.get(name) for name in names)):
        raise ValueError("PYTHON_BUILD_DEPLOYMENT_CONFIGURATION_INVALID")

    def read(name: str, maximum: int) -> bytes:
        path = Path(environment[name])
        try:
            if not path.is_file() or path.is_symlink():
                raise ValueError
            value = path.read_bytes()
        except (OSError, ValueError) as error:
            raise ValueError("PYTHON_BUILD_DEPLOYMENT_SECRET_UNAVAILABLE") from error
        if not value or len(value) > maximum:
            raise ValueError("PYTHON_BUILD_DEPLOYMENT_SECRET_INVALID")
        return value

    try:
        dsn = read(names[0], 8192).decode("utf-8").strip()
        key = read(names[1], 4096)
        profiles = load_approved_profiles_file(environment[names[2]])
    except UnicodeDecodeError as error:
        raise ValueError("PYTHON_BUILD_DEPLOYMENT_CONFIGURATION_INVALID") from error
    if not dsn or len(key) < 32:
        raise ValueError("PYTHON_BUILD_DEPLOYMENT_CONFIGURATION_INVALID")
    broker_url = environment.get('EPM_PYTHON_BUILD_BROKER_URL',
        'http://python-build-broker:5198/internal/python-build/read')
    if type(broker_url) is not str or not broker_url:
        raise ValueError("PYTHON_BUILD_DEPLOYMENT_CONFIGURATION_INVALID")
    return PythonBuildDeployment(dsn, key, profiles, broker_url)


def read_secret_text(environment: Mapping[str, str], name: str,
                     *, maximum: int = 8192) -> str:
    path = environment.get(name) if isinstance(environment, Mapping) else None
    if type(path) is not str or not path:
        raise ValueError("PYTHON_BUILD_DEPLOYMENT_CONFIGURATION_INVALID")
    try:
        value = Path(path).read_text('utf-8').strip()
    except (OSError, UnicodeError) as error:
        raise ValueError("PYTHON_BUILD_DEPLOYMENT_SECRET_UNAVAILABLE") from error
    if not value or len(value.encode('utf-8')) > maximum:
        raise ValueError("PYTHON_BUILD_DEPLOYMENT_SECRET_INVALID")
    return value
