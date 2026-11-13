"""Load deployment-owned Python environment profiles for public registration."""
from __future__ import annotations

from collections.abc import Mapping

from .postgres_python_environments import ApprovedPythonEnvironment
from .python_build_deployment import load_approved_profiles_file


def load_python_environment_profiles(
        environment: Mapping[str, str]) -> tuple[ApprovedPythonEnvironment, ...]:
    path = environment.get("EPM_PYTHON_BUILDER_PROFILES_FILE") \
        if isinstance(environment, Mapping) else None
    if type(path) is not str or not path:
        return ()
    profiles = load_approved_profiles_file(path)
    first_versions = {}
    for item in profiles:
        first_versions[item.environment_id] = min(item.version,
            first_versions.get(item.environment_id, item.version))
    result = []
    for item in profiles:
        manifest = {"environmentId": item.environment_id,
            "environmentVersion": item.version, "network": item.network,
            "image": item.image}
        if item.compiler_versions:
            manifest["compilerVersions"] = list(item.compiler_versions)
        result.append(ApprovedPythonEnvironment(
            item.environment_id
            if item.version == first_versions[item.environment_id]
            else f"{item.environment_id}:v{item.version}", item.image,
            manifest))
    return tuple(result)
