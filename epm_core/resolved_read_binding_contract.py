"""One-current governed bindings for W08 effective cube reads."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Iterable

from .current_object_contract import require_state_token
from .hierarchy_node_contract import compile_hierarchy_node


FORMAT = "openepm-resolved-read-binding-v1"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def _id(value: object, code: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError(code)
    return value


def _target(value: object, dimensions: set[str]) -> dict[str, str]:
    if (not isinstance(value, dict)
            or set(value) != {"dimensionId", "memberId"}
            or value.get("dimensionId") not in dimensions):
        raise ValueError("RESOLVED_READ_BINDING_TARGET_INVALID")
    return {"dimensionId": value["dimensionId"],
        "memberId": _id(value.get("memberId"),
                         "RESOLVED_READ_BINDING_TARGET_INVALID")}


def _stage(value: object, dimensions: set[str]) -> dict[str, object]:
    if not isinstance(value, dict) or value.get("kind") not in {
            "calculated_member", "hierarchy_node"}:
        raise ValueError("RESOLVED_READ_BINDING_STAGE_INVALID")
    common = {"stageId", "kind", "target", "dependsOn"}
    stage_id = _id(value.get("stageId"),
                   "RESOLVED_READ_BINDING_STAGE_INVALID")
    target = _target(value.get("target"), dimensions)
    depends = value.get("dependsOn")
    if (not isinstance(depends, list) or len(depends) != len(set(depends))
            or any(not isinstance(item, str) or _ID.fullmatch(item) is None
                   for item in depends)):
        raise ValueError("RESOLVED_READ_BINDING_STAGE_INVALID")
    if value["kind"] == "calculated_member":
        if set(value) != common | {"definitionId", "definitionStateToken",
                                  "evaluation", "resultUnit"}:
            raise ValueError("RESOLVED_READ_BINDING_STAGE_INVALID")
        if (value["evaluation"] not in {"dynamic", "materialized"}
                or value["resultUnit"] not in {"amount", "ratio", "text"}):
            raise ValueError("RESOLVED_READ_BINDING_STAGE_INVALID")
        return {"stageId": stage_id, "kind": "calculated_member",
            "target": target, "dependsOn": sorted(depends),
            "definitionId": _id(value["definitionId"],
                "RESOLVED_READ_BINDING_STAGE_INVALID"),
            "definitionStateToken": require_state_token(
                value["definitionStateToken"],
                error="RESOLVED_READ_BINDING_STAGE_INVALID"),
            "evaluation": value["evaluation"],
            "resultUnit": value["resultUnit"]}
    if set(value) != common | {"rootMemberId", "definition"}:
        raise ValueError("RESOLVED_READ_BINDING_STAGE_INVALID")
    definition = compile_hierarchy_node(value["definition"]).normalized
    if (definition["dimensionId"] != target["dimensionId"]
            or value["rootMemberId"] != target["memberId"]):
        raise ValueError("RESOLVED_READ_BINDING_TARGET_INVALID")
    return {"stageId": stage_id, "kind": "hierarchy_node",
        "target": target, "dependsOn": sorted(depends),
        "rootMemberId": _id(value["rootMemberId"],
            "RESOLVED_READ_BINDING_STAGE_INVALID"),
        "definition": definition}


@dataclass(frozen=True, slots=True)
class ResolvedReadBinding:
    normalized: dict[str, object]

    @property
    def digest(self) -> str:
        return sha256(_canonical(self.normalized)).hexdigest()


def compile_resolved_read_binding(value: object, *,
        active_dimensions: Iterable[str]) -> ResolvedReadBinding:
    required = {"format", "bindingId", "name", "description",
                "stages"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("RESOLVED_READ_BINDING_INVALID")
    if value["format"] != FORMAT:
        raise ValueError("RESOLVED_READ_BINDING_FORMAT_UNSUPPORTED")
    dimensions = set(active_dimensions)
    if not dimensions:
        raise ValueError("RESOLVED_READ_BINDING_DIMENSIONS_INVALID")
    if (not isinstance(value["name"], str)
            or not 1 <= len(value["name"]) <= 200
            or not isinstance(value["description"], str)
            or len(value["description"]) > 2000
            or not isinstance(value["stages"], list)
            or not 1 <= len(value["stages"]) <= 256):
        raise ValueError("RESOLVED_READ_BINDING_INVALID")
    stages = [_stage(item, dimensions) for item in value["stages"]]
    by_id = {item["stageId"]: item for item in stages}
    if len(by_id) != len(stages):
        raise ValueError("RESOLVED_READ_BINDING_STAGE_DUPLICATE")
    if any(dependency not in by_id or dependency == stage_id
           for stage_id, stage in by_id.items()
           for dependency in stage["dependsOn"]):
        raise ValueError("RESOLVED_READ_BINDING_DEPENDENCY_INVALID")
    indegree = {stage_id: len(stage["dependsOn"])
                for stage_id, stage in by_id.items()}
    successors: dict[str, list[str]] = {}
    for stage_id, stage in by_id.items():
        for dependency in stage["dependsOn"]:
            successors.setdefault(dependency, []).append(stage_id)
    ready = sorted(stage_id for stage_id, degree in indegree.items()
                   if degree == 0)
    order = []
    while ready:
        stage_id = ready.pop(0)
        order.append(stage_id)
        for successor in sorted(successors.get(stage_id, [])):
            indegree[successor] -= 1
            if indegree[successor] == 0:
                ready.append(successor)
                ready.sort()
    if len(order) != len(stages):
        raise ValueError("DEPENDENCY_CYCLE")
    targets = [(item["target"]["dimensionId"],
                item["target"]["memberId"]) for item in stages]
    if len(targets) != len(set(targets)):
        raise ValueError("TARGET_COLLISION")
    return ResolvedReadBinding({"format": FORMAT,
        "bindingId": _id(value["bindingId"],
                         "RESOLVED_READ_BINDING_INVALID"),
        "name": value["name"],
        "description": value["description"],
        "stages": [by_id[stage_id] for stage_id in order]})
