"""Storage-independent W08 planner for one coherent mixed read."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Iterable, Mapping

from .current_object_contract import is_state_token
from .resolved_cube_read_contract import ResolvedCubeReadPlan


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_UNIT = re.compile(r"[A-Za-z][A-Za-z0-9:._-]{0,199}\Z")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def _snapshot(value: object) -> dict[str, int]:
    keys = {"metadataRevision", "dataRevision", "policyRevision",
            "commitRevision", "securityRevision", "impactEpoch",
            "processedImpactEpoch"}
    if (not isinstance(value, Mapping) or set(value) != keys
            or any(type(item) is not int or item < 0
                   for item in value.values())
            or value["processedImpactEpoch"] > value["impactEpoch"]):
        raise ValueError("RESOLVED_READ_SNAPSHOT_INVALID")
    return dict(value)


def _binding(value: object, grain: list[str]) -> dict[str, object]:
    required = {"bindingId", "bindingStateToken", "stageId", "dependsOn",
                "targetMembers", "kind",
                "definitionDigest", "sourceDigest", "resultUnit",
                "currentness", "resultStateToken", "dynamicSupported",
                "lineage"}
    if (not isinstance(value, Mapping) or set(value) != required
            or not isinstance(value["bindingId"], str)
            or not value["bindingId"]
            or not is_state_token(value["bindingStateToken"])
            or not isinstance(value["stageId"], str)
            or not value["stageId"]
            or not isinstance(value["dependsOn"], list)
            or len(value["dependsOn"]) != len(set(value["dependsOn"]))
            or any(not isinstance(item, str) or not item
                   for item in value["dependsOn"])
            or (value["targetMembers"] is not None and (
                not isinstance(value["targetMembers"], Mapping)
                or set(value["targetMembers"]) != set(grain)
                or any(not isinstance(item, str) or not item
                       for item in value["targetMembers"].values())))
            or value["kind"] not in {"materialized", "dynamic", "hierarchy"}
            or not isinstance(value["definitionDigest"], str)
            or _DIGEST.fullmatch(value["definitionDigest"]) is None
            or not isinstance(value["sourceDigest"], str)
            or _DIGEST.fullmatch(value["sourceDigest"]) is None
            or not isinstance(value["resultUnit"], str)
            or _UNIT.fullmatch(value["resultUnit"]) is None
            or value["currentness"] not in {"current", "stale"}
            or (value["resultStateToken"] is not None
                and not is_state_token(value["resultStateToken"]))
            or not isinstance(value["dynamicSupported"], bool)
            or not isinstance(value["lineage"], list)):
        raise ValueError("RESOLVED_READ_BINDING_INVALID")
    if (value["kind"] in {"dynamic", "hierarchy"}
            and value["resultStateToken"] is not None):
        raise ValueError("RESOLVED_READ_BINDING_INVALID")
    # A targetless descriptor retains the authenticated stage and its
    # currentness when a resolved selection has no coordinates. It is never
    # a cell and never substitutes for a missing binding.
    return {**value, "targetMembers": (None if value["targetMembers"] is None
        else {axis: value["targetMembers"][axis] for axis in grain})}


@dataclass(frozen=True, slots=True)
class ResolvedCubeReadExecution:
    normalized: dict[str, object]

    @property
    def digest(self) -> str:
        return sha256(_canonical(self.normalized)).hexdigest()


def compile_resolved_read_execution(plan: ResolvedCubeReadPlan, *,
        snapshot: object, bindings: Iterable[object]) -> ResolvedCubeReadExecution:
    """Choose input/stored/dynamic/hierarchy stages without executing them."""
    if not isinstance(plan, ResolvedCubeReadPlan):
        raise ValueError("RESOLVED_READ_PLAN_INVALID")
    pinned_snapshot = _snapshot(snapshot)
    if (plan.normalized["source"]["semantics"] == "effective"
            and pinned_snapshot["processedImpactEpoch"] <
                pinned_snapshot["impactEpoch"]):
        raise ValueError("IMPACT_COVERAGE_PENDING")
    grain = plan.normalized["outputGrain"]
    values = [_binding(item, grain) for item in bindings]
    if plan.normalized["source"]["semantics"] == "own":
        if values:
            raise ValueError("RESOLVED_READ_OWN_BINDING_UNEXPECTED")
        stages = [{"stage": "input", "sourceDigest": plan.digest,
                   "bindingIds": [], "currentness": "current"}]
    else:
        expected = (plan.normalized["source"]["bindingId"],
                    plan.normalized["source"]["bindingStateToken"])
        if not values or any((item["bindingId"], item["bindingStateToken"])
                             != expected for item in values):
            raise ValueError("RESOLVED_READ_BINDING_MISMATCH")
        stage_dependencies: dict[str, tuple[str, ...]] = {}
        for item in values:
            dependencies = tuple(item["dependsOn"])
            prior = stage_dependencies.setdefault(item["stageId"], dependencies)
            if prior != dependencies:
                raise ValueError("RESOLVED_READ_BINDING_INVALID")
        visiting = set()
        dependency_closure: dict[str, set[str]] = {}

        def closure(stage_id: str) -> set[str]:
            if stage_id in dependency_closure:
                return dependency_closure[stage_id]
            if stage_id in visiting:
                raise ValueError("DEPENDENCY_CYCLE")
            visiting.add(stage_id)
            result = set(stage_dependencies.get(stage_id, ()))
            if any(item not in stage_dependencies for item in result):
                raise ValueError("RESOLVED_READ_BINDING_INVALID")
            for dependency in tuple(result):
                result.update(closure(dependency))
            visiting.remove(stage_id)
            dependency_closure[stage_id] = result
            return result

        for stage_id in stage_dependencies:
            closure(stage_id)
        selected_by_target: dict[tuple[str, ...], dict[str, object]] = {}
        targetless = []
        for item in values:
            mode = item["kind"]
            currentness = item["currentness"]
            state_token = item["resultStateToken"]
            if mode == "materialized" and currentness == "stale":
                if (plan.normalized["freshness"] == "current"
                        and plan.normalized["dynamicFallback"]
                        and item["dynamicSupported"]):
                    mode, currentness, state_token = "dynamic", "current", None
                elif plan.normalized["freshness"] == "current":
                    raise ValueError("CALCULATION_REQUIRED")
            candidate = {**item, "kind": mode,
                         "currentness": currentness,
                         "resultStateToken": state_token}
            if item["targetMembers"] is None:
                targetless.append(candidate)
                continue
            target = tuple(item["targetMembers"][axis] for axis in grain)
            prior = selected_by_target.get(target)
            if prior is None:
                selected_by_target[target] = candidate
            elif prior["stageId"] in dependency_closure[item["stageId"]]:
                selected_by_target[target] = candidate
            elif item["stageId"] not in dependency_closure[prior["stageId"]]:
                raise ValueError("TARGET_COLLISION")
        empty_stages = [item["stageId"] for item in targetless]
        if (len(empty_stages) != len(set(empty_stages))
                or set(empty_stages) & {item["stageId"] for item in values
                                      if item["targetMembers"] is not None}):
            raise ValueError("RESOLVED_READ_BINDING_INVALID")
        selected = [*selected_by_target.values(), *targetless]
        by_stage: dict[str, list[dict[str, object]]] = {}
        for item in selected:
            by_stage.setdefault(item["stageId"], []).append(item)
        if any(dependency not in by_stage for stage_id in by_stage
               for dependency in stage_dependencies[stage_id]):
            raise ValueError("RESOLVED_READ_BINDING_INVALID")
        grouped: dict[tuple, list[dict[str, object]]] = {}
        for stage_id, items in by_stage.items():
            signatures = {(item["kind"], item["sourceDigest"],
                           item["currentness"]) for item in items}
            if len(signatures) != 1:
                raise ValueError("RESOLVED_READ_BINDING_INVALID")
            signature = signatures.pop()
            key = (*signature, tuple(stage_dependencies[stage_id]),
                   len(dependency_closure[stage_id]))
            grouped.setdefault(key, []).extend(items)
        stages = [{"stage": "input", "sourceDigest": plan.digest,
            "bindingIds": [], "currentness": "current"}]
        for key, items in sorted(grouped.items(),
                key=lambda pair: (pair[0][4], pair[0])):
            kind, source_digest, currentness, dependencies, _ = key
            stages.append({"stage": kind, "sourceDigest": source_digest,
                "bindingIds": sorted({item["bindingId"] for item in items}),
                "stageIds": sorted({item["stageId"] for item in items}),
                "dependsOn": list(dependencies),
                "currentness": currentness,
                "stageTargets": {stage_id: sorted((
                    item["targetMembers"] for item in items
                    if item["stageId"] == stage_id
                    and item["targetMembers"] is not None),
                    key=lambda target: tuple(target[axis] for axis in grain))
                    for stage_id in sorted({item["stageId"]
                                            for item in items})},
                "targets": sorted((item["targetMembers"] for item in items
                    if item["targetMembers"] is not None),
                    key=lambda target: tuple(target[axis] for axis in grain)),
                "resultStateTokens": sorted({item["resultStateToken"]
                    for item in items
                    if item["resultStateToken"] is not None})})
    return ResolvedCubeReadExecution({
        "format": "openepm-resolved-cube-read-execution-v1",
        "requestDigest": plan.digest, "snapshot": pinned_snapshot,
        "stages": stages})
