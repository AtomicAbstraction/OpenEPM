"""Resolve canonical cube selections against one pinned metadata snapshot."""

from __future__ import annotations

from hashlib import sha256
import json
from typing import Mapping, Sequence

from .member_list_contract import FORMAT as MEMBER_LIST_FORMAT, member_list_digest
from .member_list_evaluator import (
    evaluate_member_list, evaluate_member_list_placements)
from .selection_contract import canonical_selection


MAX_RESOLVED_MEMBERS = 100_000


def _digest(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def resolve_selection(
    selection: object,
    *,
    metadata_revision: int,
    active_dimensions: Sequence[str],
    members: Mapping[str, Mapping[str, str]],
    relationships: Mapping[str, Sequence[tuple[str, str]]],
    placement_relationships: Mapping[str, Sequence[Mapping[str, str]]],
    attributes: Mapping[str, Mapping[str, Mapping[str, object]]],
    attribute_types: Mapping[str, Mapping[str, str]],
    member_lists: Mapping[tuple[str, int], object],
) -> dict:
    """Return unique stable member IDs and exact reusable-list pins.

    The caller must obtain every supplied mapping inside one authorized,
    revision-pinned metadata read.  This pure boundary neither queries nor
    mutates storage, so PostgreSQL and MCP adapters can share it exactly.
    """

    if type(metadata_revision) is not int or metadata_revision < 1:
        raise ValueError("CUBE_SELECTION_METADATA_REVISION_INVALID")
    canonical = canonical_selection(selection, active_dimensions=active_dimensions)
    if canonical["metadataRevision"] != metadata_revision:
        raise ValueError("CUBE_SELECTION_METADATA_STALE")
    dimensions = set(active_dimensions)
    if (set(members) != dimensions or set(relationships) != dimensions
            or set(placement_relationships) != dimensions
            or set(attributes) != dimensions or set(attribute_types) != dimensions):
        raise ValueError("CUBE_SELECTION_METADATA_SNAPSHOT_INCOMPLETE")

    pins: list[dict] = []

    def resolve(dimension: str, selector: Mapping[str, object]) -> tuple[list[str],list[dict]]:
        kind = selector["kind"]
        if kind == "member":
            result = [selector["memberId"]]
            placements = [{"memberId": selector["memberId"],
                           "pathRelationshipIds": []}]
        elif kind == "members":
            result = list(selector["memberIds"])
            placements = [{"memberId": member,"pathRelationshipIds": []}
                          for member in result]
        else:
            if kind == "hierarchy":
                expression = {"kind": selector["operator"],
                    "hierarchyId": selector["hierarchyId"],
                    "memberId": selector["memberId"],
                    "includeSelf": selector["includeSelf"]}
                definition = {"format": MEMBER_LIST_FORMAT,
                    "listId": "selection.inline", "version": 1,
                    "dimensionId": dimension, "name": "Inline selection",
                    "parameters": [], "expression": expression}
                parameters = {}
            elif kind == "attribute":
                definition = {"format": MEMBER_LIST_FORMAT,
                    "listId": "selection.inline", "version": 1,
                    "dimensionId": dimension, "name": "Inline selection",
                    "parameters": [], "expression": dict(selector)}
                parameters = {}
            elif kind == "member_list":
                key = (selector["listId"], selector["version"])
                definition = member_lists.get(key)
                if definition is None:
                    raise ValueError("CUBE_SELECTION_MEMBER_LIST_UNAVAILABLE")
                parameters = selector["parameters"]
                try:
                    digest = member_list_digest(definition)
                except (TypeError, ValueError) as error:
                    raise ValueError("CUBE_SELECTION_MEMBER_LIST_CORRUPT") from error
                pins.append({"listId": key[0], "version": key[1],
                             "canonicalDigest": digest,
                             "parameters": parameters})
            else:
                raise ValueError("CUBE_SELECTION_SELECTOR_KIND_UNSUPPORTED")
            if definition.get("dimensionId") != dimension:
                raise ValueError("CUBE_SELECTION_MEMBER_LIST_DIMENSION_MISMATCH")
            result = evaluate_member_list(
                definition, members=members[dimension],
                relationships=relationships[dimension],
                attributes=attributes[dimension],
                attribute_types=attribute_types[dimension],
                parameters=parameters)
            placements = evaluate_member_list_placements(
                definition, members=members[dimension],
                relationships=placement_relationships[dimension],
                attributes=attributes[dimension],
                attribute_types=attribute_types[dimension],
                parameters=parameters)
        unavailable = set(result) - set(members[dimension])
        if unavailable:
            raise ValueError("CUBE_SELECTION_MEMBER_UNAVAILABLE")
        if [item["memberId"] for item in placements
                if item["memberId"] not in set(result)]:
            raise ValueError("CUBE_SELECTION_PLACEMENT_RESOLUTION_INVALID")
        return result, placements

    resolved: dict[str, list[str]] = {}
    resolved_placements: dict[str, list[dict]] = {}
    total = 0
    for dimension in canonical["dimensions"]:
        dimension_id = dimension["dimensionId"]
        included, included_placements = resolve(
            dimension_id, dimension["include"])
        if dimension["exclude"] is None:
            excluded = set()
        else:
            excluded, _ = resolve(dimension_id, dimension["exclude"])
            excluded = set(excluded)
        selected = [member for member in included if member not in excluded]
        selected_placements = [item for item in included_placements
                               if item["memberId"] not in excluded]
        total += len(selected)
        if total > MAX_RESOLVED_MEMBERS:
            raise ValueError("CUBE_SELECTION_RESOLUTION_LIMIT_EXCEEDED")
        resolved[dimension_id] = selected
        resolved_placements[dimension_id] = selected_placements
    pins.sort(key=lambda item: (item["listId"], item["version"],
                                _digest(item["parameters"])))
    sealed = {"format": "openepm-resolved-selection-v1",
              "metadataRevision": metadata_revision,
              "members": resolved, "placements": resolved_placements,
              "memberListPins": pins}
    return {**sealed, "resolutionDigest": _digest(sealed)}
