"""Pure semantic validation for a private populated-layout generation.

This contract produces an activation *eligibility* certificate, not an
activation.  Callers must still pin and recheck the same request, plan,
application revisions and private generation in the durable workflow.
"""
from __future__ import annotations

from decimal import Decimal
from hashlib import sha256
import json
import re
from typing import Mapping

from .populated_layout_mapping import LayoutPins


_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_COORDINATES = 100_000
MAX_DIAGNOSTICS = 100
MAX_AMOUNT = Decimal("99999999999999999999.99999999")


def _decimal(value: object, label: str) -> Decimal:
    if not isinstance(value, Decimal) or isinstance(value, bool):
        raise ValueError(f"{label}_DECIMAL_REQUIRED")
    if not value.is_finite() or value.as_tuple().exponent < -8 or abs(value) > MAX_AMOUNT:
        raise ValueError(f"{label}_OVERFLOW")
    return value


def _wire_decimal(value: Decimal | None) -> str | None:
    if value is None:
        return None
    return format(value, "f")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _target_key(members: Mapping[str, str], dimensions: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(members, Mapping) or set(members) != set(dimensions):
        raise ValueError("TARGET_GRAIN_INCOMPLETE")
    values = []
    for dimension in dimensions:
        member = members[dimension]
        if not isinstance(member, str) or not member:
            raise ValueError("TARGET_MEMBER_INVALID")
        values.append(member)
    return tuple(values)


def _numeric(value: object) -> dict:
    if not isinstance(value, Mapping) or set(value) != {"present", "amount"}:
        raise ValueError("NUMERIC_SHAPE_INVALID")
    if type(value["present"]) is not bool:
        raise ValueError("NUMERIC_PRESENCE_INVALID")
    amount = value["amount"]
    if value["present"]:
        amount = _decimal(amount, "NUMERIC")
    elif amount is not None:
        raise ValueError("NUMERIC_ABSENCE_INVALID")
    return {"present": value["present"], "amount": amount}


def _text(value: object) -> dict:
    if not isinstance(value, Mapping) or set(value) != {"present", "value"}:
        raise ValueError("TEXT_SHAPE_INVALID")
    if type(value["present"]) is not bool:
        raise ValueError("TEXT_PRESENCE_INVALID")
    text = value["value"]
    if value["present"]:
        if not isinstance(text, str) or "\x00" in text:
            raise ValueError("TEXT_VALUE_INVALID")
    elif text is not None:
        raise ValueError("TEXT_ABSENCE_INVALID")
    return {"present": value["present"], "value": text}


def _detail(value: object) -> dict:
    if (not isinstance(value, Mapping)
            or set(value) != {"present", "total", "items"}
            or type(value["present"]) is not bool
            or not isinstance(value["items"], list)):
        raise ValueError("DETAIL_SHAPE_INVALID")
    items = []
    for item in value["items"]:
        if (not isinstance(item, Mapping)
                or set(item) != {"description", "amount"}
                or not isinstance(item["description"], str)
                or not item["description"] or "\x00" in item["description"]):
            raise ValueError("DETAIL_ITEM_INVALID")
        items.append({"description": item["description"],
                      "amount": _decimal(item["amount"], "DETAIL_ITEM")})
    if value["present"]:
        total = _decimal(value["total"], "DETAIL_TOTAL")
        if sum((item["amount"] for item in items), Decimal(0)) != total:
            raise ValueError("DETAIL_TOTAL_DRIFT")
    else:
        if value["total"] is not None or items:
            raise ValueError("DETAIL_ABSENCE_INVALID")
        total = None
    return {"present": value["present"], "total": total, "items": items}


def _cell(row: object, *, staged: bool) -> dict:
    required = ({"targetMembers", "sourceCoordinateIds", "numeric", "text", "detail"}
                if staged else {"sourceCoordinateId", "numeric", "text", "detail"})
    if not isinstance(row, Mapping) or set(row) != required:
        raise ValueError("STAGED_CELL_INVALID" if staged else "SOURCE_CELL_INVALID")
    result = {"numeric": _numeric(row["numeric"]), "text": _text(row["text"]),
              "detail": _detail(row["detail"])}
    if staged:
        ids = row["sourceCoordinateIds"]
        if (not isinstance(ids, list) or not ids
                or any(type(item) is not int or item < 1 for item in ids)
                or len(ids) != len(set(ids))):
            raise ValueError("LINEAGE_SOURCE_IDS_INVALID")
        result.update(targetMembers=row["targetMembers"],
                      sourceCoordinateIds=tuple(sorted(ids)))
    else:
        coordinate = row["sourceCoordinateId"]
        if type(coordinate) is not int or coordinate < 1:
            raise ValueError("SOURCE_COORDINATE_ID_INVALID")
        result["sourceCoordinateId"] = coordinate
    return result


def _expected(group: list[dict], policy: str) -> dict:
    if len(group) > 1 and policy != "aggregate_exact":
        raise ValueError("MANY_TO_ONE_POLICY_REQUIRED")
    if len(group) == 1:
        source = group[0]
        return {"numeric": source["numeric"], "text": source["text"],
                "detail": source["detail"]}
    present_numeric = [item["numeric"]["amount"] for item in group
                       if item["numeric"]["present"]]
    numeric = ({"present": True, "amount": sum(present_numeric, Decimal(0))}
               if present_numeric else {"present": False, "amount": None})
    if numeric["present"]:
        _decimal(numeric["amount"], "NUMERIC_AGGREGATE")
    present_text = [item["text"]["value"] for item in group
                    if item["text"]["present"]]
    if len(set(present_text)) > 1:
        raise ValueError("TEXT_MERGE_INCOMPATIBLE")
    text = ({"present": True, "value": present_text[0]}
            if present_text else {"present": False, "value": None})
    details = [item["detail"] for item in group if item["detail"]["present"]]
    detail_items = [entry for detail in details for entry in detail["items"]]
    detail = ({"present": True,
               "total": sum((item["total"] for item in details), Decimal(0)),
               "items": detail_items} if details else
              {"present": False, "total": None, "items": []})
    if detail["present"]:
        _decimal(detail["total"], "DETAIL_AGGREGATE")
    return {"numeric": numeric, "text": text, "detail": detail}


def validate_populated_layout_generation(*, request_id: str, plan_digest: str,
        pins: LayoutPins, generation_id: str, target_dimensions: object,
        coordinate_mappings: object, merge_policy: str, source_cells: object,
        staged_cells: object, valid_target_members: object,
        affected_dependencies: object, compatibility_decisions: object) -> dict:
    """Return a deterministic bounded certificate; never raise for mismatches.

    Structural/type errors raise because no trustworthy certificate can be
    produced. Semantic mismatches are accumulated and make eligibility false.
    """
    if (not isinstance(request_id, str) or not _HEX32.fullmatch(request_id)
            or not isinstance(generation_id, str) or not _HEX32.fullmatch(generation_id)
            or not isinstance(plan_digest, str) or not _HEX64.fullmatch(plan_digest)
            or not isinstance(pins, LayoutPins)
            or merge_policy not in ("one_to_one", "aggregate_exact")):
        raise ValueError("GENERATION_VALIDATION_IDENTITY_INVALID")
    if (not isinstance(target_dimensions, list) or not target_dimensions
            or len(target_dimensions) != len(set(target_dimensions))
            or any(not isinstance(item, str) or not item for item in target_dimensions)):
        raise ValueError("TARGET_DIMENSIONS_INVALID")
    dimensions = tuple(target_dimensions)
    if (not isinstance(coordinate_mappings, list)
            or not isinstance(source_cells, list)
            or not isinstance(staged_cells, list)
            or not 1 <= len(source_cells) <= MAX_COORDINATES
            or len(coordinate_mappings) > MAX_COORDINATES
            or len(staged_cells) > MAX_COORDINATES):
        raise ValueError("GENERATION_VALIDATION_BOUND_INVALID")
    sources = [_cell(row, staged=False) for row in source_cells]
    source_by_id = {row["sourceCoordinateId"]: row for row in sources}
    if len(source_by_id) != len(sources):
        raise ValueError("SOURCE_COORDINATE_DUPLICATE")
    if (not isinstance(valid_target_members, Mapping)
            or set(valid_target_members) != set(dimensions)
            or any(not isinstance(values, list) or len(values) != len(set(values))
                   or any(not isinstance(value, str) or not value for value in values)
                   for values in valid_target_members.values())):
        raise ValueError("TARGET_REFERENCES_INVALID")

    errors: list[dict] = []
    error_count = 0
    def reject(code: str, key: object = None) -> None:
        nonlocal error_count
        error_count += 1
        if len(errors) < MAX_DIAGNOSTICS:
            errors.append({"code": code, "key": key})

    groups: dict[tuple[str, ...], list[dict]] = {}
    mapped_sources = set()
    for mapping in coordinate_mappings:
        if (not isinstance(mapping, Mapping)
                or set(mapping) != {"sourceCoordinateId", "targetMembers"}):
            raise ValueError("COORDINATE_MAPPING_INVALID")
        source_id = mapping["sourceCoordinateId"]
        if type(source_id) is not int or source_id < 1 or source_id in mapped_sources:
            reject("SOURCE_MAPPING_DUPLICATE", source_id)
            continue
        mapped_sources.add(source_id)
        if source_id not in source_by_id:
            reject("SOURCE_MAPPING_UNPINNED", source_id)
            continue
        try:
            key = _target_key(mapping["targetMembers"], dimensions)
        except ValueError as error:
            reject(str(error), source_id); continue
        for dimension, member in zip(dimensions, key):
            if member not in valid_target_members[dimension]:
                reject("TARGET_REFERENCE_MISSING", [dimension, member])
        groups.setdefault(key, []).append(source_by_id[source_id])
    for source_id in sorted(set(source_by_id) - mapped_sources):
        reject("SOURCE_MAPPING_MISSING", source_id)

    staged_by_key = {}
    for raw in staged_cells:
        row = _cell(raw, staged=True)
        try:
            key = _target_key(row["targetMembers"], dimensions)
        except ValueError as error:
            reject(str(error)); continue
        if key in staged_by_key:
            reject("TARGET_COORDINATE_DUPLICATE", list(key)); continue
        staged_by_key[key] = row
    for key in sorted(set(groups) - set(staged_by_key)):
        reject("TARGET_COORDINATE_MISSING", list(key))
    for key in sorted(set(staged_by_key) - set(groups)):
        reject("TARGET_COORDINATE_EXTRA", list(key))
    for key in sorted(set(groups) & set(staged_by_key)):
        try:
            expected = _expected(groups[key], merge_policy)
        except ValueError as error:
            reject(str(error), list(key)); continue
        actual = staged_by_key[key]
        expected_ids = tuple(sorted(item["sourceCoordinateId"] for item in groups[key]))
        if actual["sourceCoordinateIds"] != expected_ids:
            reject("LINEAGE_SOURCE_IDS_MISMATCH", list(key))
        if actual["numeric"] != expected["numeric"]:
            reject("NUMERIC_VALUE_OR_PRESENCE_MISMATCH", list(key))
        if actual["text"] != expected["text"]:
            reject("TEXT_VALUE_OR_PRESENCE_MISMATCH", list(key))
        if actual["detail"] != expected["detail"]:
            reject("DETAIL_VALUE_OR_ITEMS_MISMATCH", list(key))

    if not isinstance(affected_dependencies, list) or not isinstance(
            compatibility_decisions, list):
        raise ValueError("DEPENDENCY_DECISIONS_INVALID")
    affected = set()
    for item in affected_dependencies:
        if (not isinstance(item, Mapping) or set(item) != {"kind", "id"}
                or item["kind"] not in ("rule", "publication")
                or not isinstance(item["id"], str) or not item["id"]):
            raise ValueError("AFFECTED_DEPENDENCY_INVALID")
        affected.add((item["kind"], item["id"]))
    decisions = {}
    for item in compatibility_decisions:
        if (not isinstance(item, Mapping) or set(item) != {"kind", "id", "decision"}
                or item["decision"] not in ("Compatible", "Invalidate", "Rebuild", "Incompatible")):
            raise ValueError("COMPATIBILITY_DECISION_INVALID")
        key = (item["kind"], item["id"])
        if key in decisions:
            raise ValueError("COMPATIBILITY_DECISION_DUPLICATE")
        decisions[key] = item["decision"]
    for dependency in sorted(affected - set(decisions)):
        reject("COMPATIBILITY_DECISION_MISSING", list(dependency))
    for dependency in sorted(set(decisions) - affected):
        reject("COMPATIBILITY_DECISION_EXTRA", list(dependency))
    for dependency, decision in sorted(decisions.items()):
        if decision == "Incompatible":
            reject("DEPENDENCY_INCOMPATIBLE", list(dependency))

    errors.sort(key=lambda item: _canonical(item))
    summary = {"requestId": request_id, "planDigest": plan_digest,
               "pins": pins.to_wire(), "privateGenerationId": generation_id,
               "mergePolicy": merge_policy, "sourceCoordinateCount": len(sources),
               "mappedSourceCount": len(mapped_sources),
               "expectedTargetCount": len(groups),
               "stagedTargetCount": len(staged_by_key),
               "errorCount": error_count,
               "diagnostics": errors,
               "diagnosticsTruncated": error_count > len(errors),
               "activationEligible": error_count == 0}
    # Convert exact decimals only in the internal comparison path; the
    # certificate deliberately contains counts/identities, not cell values.
    summary["validationDigest"] = sha256(_canonical(summary)).hexdigest()
    return summary
