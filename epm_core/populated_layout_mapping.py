"""Deterministic preflight contract for populated cube-layout replacement.

This module does not mutate metadata or facts.  It canonicalizes a complete,
explicit old-coordinate to new-coordinate mapping against pinned application
state so a later durable workflow can stage and publish exactly this plan.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Iterable, Mapping


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
MAX_COORDINATES = 100_000
MAX_TARGET_MEMBERS = 10_000


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError(f"{label}_INVALID")
    return value


def _integer(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label}_INVALID")
    return value


def _axes(raw: object, label: str) -> tuple[dict, ...]:
    if not isinstance(raw, list) or not raw:
        raise ValueError(f"{label}_INVALID")
    result = []
    seen = set()
    for item in raw:
        if not isinstance(item, Mapping) or set(item) != {"dimensionId", "valueKind"}:
            raise ValueError(f"{label}_INVALID")
        dimension = _identifier(item["dimensionId"], f"{label}_DIMENSION")
        kind = _identifier(item["valueKind"], f"{label}_VALUE_KIND")
        if dimension in seen:
            raise ValueError(f"{label}_DUPLICATE")
        seen.add(dimension)
        result.append({"dimensionId": dimension, "valueKind": kind})
    return tuple(result)


def _members(raw: object, dimensions: tuple[str, ...], label: str) -> dict[str, str]:
    if not isinstance(raw, Mapping) or set(raw) != set(dimensions):
        raise ValueError(f"{label}_GRAIN_MISMATCH")
    return {dimension: _identifier(raw[dimension], f"{label}_MEMBER")
            for dimension in dimensions}


def _target_metadata(raw: object, *, source_dimensions: tuple[str, ...],
                     target_dimensions: tuple[str, ...],
                     coordinate_mappings: object) -> dict | None:
    """Normalize one proposed Custom leaf axis for a populated plan v2."""
    if raw is None:
        return None
    if (not isinstance(raw, Mapping) or set(raw) != {"dimension"}
            or not isinstance(raw["dimension"], Mapping)):
        raise ValueError("TARGET_METADATA_INVALID")
    dimension = raw["dimension"]
    if set(dimension) != {"dimensionId", "name", "modelRole", "shortDescription",
                          "detailedDescription", "members"}:
        raise ValueError("TARGET_METADATA_INVALID")
    dimension_id = _identifier(dimension["dimensionId"], "TARGET_METADATA_DIMENSION")
    if (dimension_id in source_dimensions or dimension_id not in target_dimensions
            or dimension["modelRole"] != "Custom"):
        raise ValueError("TARGET_METADATA_AXIS_UNSUPPORTED")
    if set(target_dimensions) - set(source_dimensions) != {dimension_id}:
        raise ValueError("TARGET_METADATA_EXACTLY_ONE_NEW_AXIS_REQUIRED")
    for key, limit in (("name", 200), ("shortDescription", 500),
                       ("detailedDescription", 10_000)):
        value = dimension[key]
        if (not isinstance(value, str) or "\x00" in value
                or (key == "name" and not value) or len(value) > limit):
            raise ValueError("TARGET_METADATA_DESCRIPTION_INVALID")
    members = dimension["members"]
    if not isinstance(members, list) or not 1 <= len(members) <= MAX_TARGET_MEMBERS:
        raise ValueError("TARGET_METADATA_MEMBER_BOUND")
    normalized, seen_ids, seen_names = [], set(), set()
    for member in members:
        if (not isinstance(member, Mapping)
                or set(member) != {"memberId", "name", "shortDescription",
                                   "detailedDescription"}):
            raise ValueError("TARGET_METADATA_MEMBER_INVALID")
        member_id = _identifier(member["memberId"], "TARGET_METADATA_MEMBER")
        name = member["name"]
        if (member_id in seen_ids or not isinstance(name, str) or not name
                or "\x00" in name or len(name) > 200
                or name.casefold() in seen_names):
            raise ValueError("TARGET_METADATA_MEMBER_DUPLICATE_OR_INVALID")
        for key, limit in (("shortDescription", 500),
                           ("detailedDescription", 10_000)):
            value = member[key]
            if not isinstance(value, str) or "\x00" in value or len(value) > limit:
                raise ValueError("TARGET_METADATA_DESCRIPTION_INVALID")
        seen_ids.add(member_id); seen_names.add(name.casefold())
        normalized.append({"memberId": member_id, "name": name,
                           "shortDescription": member["shortDescription"],
                           "detailedDescription": member["detailedDescription"]})
    referenced = {item["targetMembers"][dimension_id]
                  for item in coordinate_mappings}
    if referenced != seen_ids:
        raise ValueError("TARGET_METADATA_MEMBERS_NOT_EXACTLY_MAPPED")
    normalized.sort(key=lambda item: item["memberId"])
    return {"dimension": {"dimensionId": dimension_id,
                           "name": dimension["name"], "modelRole": "Custom",
                           "shortDescription": dimension["shortDescription"],
                           "detailedDescription": dimension["detailedDescription"],
                           "members": normalized}}


@dataclass(frozen=True, slots=True)
class LayoutPins:
    metadata_revision: int
    data_revision: int
    policy_revision: int
    schema_epoch: int
    source_commit_revision: int

    def __post_init__(self) -> None:
        for label, value in (
            ("METADATA_REVISION", self.metadata_revision),
            ("DATA_REVISION", self.data_revision),
            ("POLICY_REVISION", self.policy_revision),
            ("SCHEMA_EPOCH", self.schema_epoch),
            ("SOURCE_COMMIT_REVISION", self.source_commit_revision),
        ):
            _integer(value, label)

    def to_wire(self) -> dict[str, int]:
        return {
            "metadataRevision": self.metadata_revision,
            "dataRevision": self.data_revision,
            "policyRevision": self.policy_revision,
            "schemaEpoch": self.schema_epoch,
            "sourceCommitRevision": self.source_commit_revision,
        }


@dataclass(frozen=True, slots=True)
class SourceCoordinate:
    coordinate_id: int
    members: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class PopulatedLayoutPlan:
    document: Mapping[str, object]

    @property
    def canonical_bytes(self) -> bytes:
        return json.dumps(self.document, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")

    @property
    def digest(self) -> str:
        return sha256(self.canonical_bytes).hexdigest()

    def to_wire(self) -> dict:
        return json.loads(self.canonical_bytes)


def compile_populated_layout_plan(*, pins: LayoutPins,
                                  source_axes: object,
                                  target_axes: object,
                                  axis_mapping: object,
                                  source_coordinates: Iterable[SourceCoordinate],
                                  coordinate_mappings: object,
                                  target_metadata: object = None
                                  ) -> PopulatedLayoutPlan:
    """Compile one complete, collision-free replacement mapping.

    ``axis_mapping`` must explicitly name the target axis for every source axis,
    or ``None`` when that source axis is removed. Added target axes are allowed,
    but every target member still has to be supplied for every source coordinate.
    """
    if not isinstance(pins, LayoutPins):
        raise ValueError("LAYOUT_PINS_INVALID")
    sources = _axes(source_axes, "SOURCE_AXES")
    targets = _axes(target_axes, "TARGET_AXES")
    source_dimensions = tuple(item["dimensionId"] for item in sources)
    target_dimensions = tuple(item["dimensionId"] for item in targets)
    source_kinds = {item["dimensionId"]: item["valueKind"] for item in sources}
    target_kinds = {item["dimensionId"]: item["valueKind"] for item in targets}
    if not isinstance(axis_mapping, Mapping) or set(axis_mapping) != set(source_dimensions):
        raise ValueError("AXIS_MAPPING_INCOMPLETE")
    normalized_axes: dict[str, str | None] = {}
    mapped_targets = set()
    for source in source_dimensions:
        target = axis_mapping[source]
        if target is None:
            normalized_axes[source] = None
            continue
        target = _identifier(target, "AXIS_MAPPING_TARGET")
        if target not in target_kinds:
            raise ValueError("AXIS_MAPPING_TARGET_UNKNOWN")
        if target in mapped_targets:
            raise ValueError("AXIS_MAPPING_AMBIGUOUS")
        if source_kinds[source] != target_kinds[target]:
            raise ValueError("AXIS_MAPPING_TYPE_INCOMPATIBLE")
        mapped_targets.add(target)
        normalized_axes[source] = target
    source_rows: dict[int, dict[str, str]] = {}
    for coordinate in source_coordinates:
        if not isinstance(coordinate, SourceCoordinate):
            raise ValueError("SOURCE_COORDINATE_INVALID")
        coordinate_id = _integer(coordinate.coordinate_id, "SOURCE_COORDINATE_ID")
        if coordinate_id < 1 or coordinate_id in source_rows:
            raise ValueError("SOURCE_COORDINATE_DUPLICATE")
        source_rows[coordinate_id] = _members(
            coordinate.members, source_dimensions, "SOURCE_COORDINATE")
        if len(source_rows) > MAX_COORDINATES:
            raise ValueError("POPULATED_LAYOUT_COORDINATE_LIMIT")
    if not source_rows:
        raise ValueError("POPULATED_LAYOUT_SOURCE_EMPTY")
    if not isinstance(coordinate_mappings, list) or len(coordinate_mappings) != len(source_rows):
        raise ValueError("COORDINATE_MAPPING_INCOMPLETE")
    mappings = []
    seen_source = set()
    seen_target = set()
    for item in coordinate_mappings:
        if (not isinstance(item, Mapping) or set(item) !=
                {"sourceCoordinateId", "sourceMembers", "targetMembers"}):
            raise ValueError("COORDINATE_MAPPING_INVALID")
        coordinate_id = _integer(item["sourceCoordinateId"], "SOURCE_COORDINATE_ID")
        if coordinate_id not in source_rows:
            raise ValueError("COORDINATE_MAPPING_SOURCE_UNKNOWN")
        if coordinate_id in seen_source:
            raise ValueError("COORDINATE_MAPPING_SOURCE_DUPLICATE")
        source_members = _members(item["sourceMembers"], source_dimensions,
                                  "SOURCE_COORDINATE")
        if source_members != source_rows[coordinate_id]:
            raise ValueError("COORDINATE_MAPPING_SOURCE_CHANGED")
        target_members = _members(item["targetMembers"], target_dimensions,
                                  "TARGET_COORDINATE")
        target_key = tuple(target_members[dimension] for dimension in target_dimensions)
        if target_key in seen_target:
            raise ValueError("COORDINATE_MAPPING_AMBIGUOUS_MERGE")
        seen_source.add(coordinate_id)
        seen_target.add(target_key)
        mappings.append({"sourceCoordinateId": coordinate_id,
                         "sourceMembers": source_members,
                         "targetMembers": target_members})
    if seen_source != set(source_rows):
        raise ValueError("COORDINATE_MAPPING_INCOMPLETE")
    mappings.sort(key=lambda item: item["sourceCoordinateId"])
    metadata = _target_metadata(target_metadata,
        source_dimensions=source_dimensions, target_dimensions=target_dimensions,
        coordinate_mappings=mappings)
    if metadata is not None:
        new_axis = metadata["dimension"]["dimensionId"]
        if (set(target_dimensions) != set(source_dimensions) | {new_axis}
                or any(normalized_axes[source] != source
                       for source in source_dimensions)
                or any(any(mapping["targetMembers"][source] !=
                               mapping["sourceMembers"][source]
                           for source in source_dimensions)
                       for mapping in mappings)):
            raise ValueError("TARGET_METADATA_ADDITIVE_AXIS_ONLY")
    document = {
        "format": ("openepm-populated-layout-plan-v2" if metadata is not None
                   else "openepm-populated-layout-plan-v1"),
        "pins": pins.to_wire(),
        "sourceAxes": list(sources),
        "targetAxes": list(targets),
        "axisMapping": normalized_axes,
        "coordinateMappings": mappings,
        "sourceCoordinateCount": len(mappings),
        "targetCoordinateCount": len(seen_target),
    }
    if metadata is not None:
        document["targetMetadata"] = metadata
    return PopulatedLayoutPlan(document)

