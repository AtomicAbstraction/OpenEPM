"""Authoritative typed member-attribute snapshot for metadata evaluation."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, cast

from .persistence_contract import ApplicationScope


@dataclass(frozen=True)
class MemberAttributeSnapshot:
    """Typed values and current descriptors from one metadata snapshot."""

    values: dict[str, dict[str, dict[str, object]]]
    types: dict[str, dict[str, str]]
    definitions: dict[str, dict[str, dict[str, object]]]


def load_member_attribute_snapshot(
        db,
        scope: ApplicationScope,
        dimensions: Iterable[str],
        member_rows: Iterable[Mapping[str, object]],
) -> MemberAttributeSnapshot:
    """Load one interpretation of legacy and native member attributes.

    Member values already share ``member.custom_values``.  This adapter adds
    the legacy display-name aliases and, critically, loads the native
    ``attribute_definition`` types used by the member-list evaluator.  Every
    caller therefore sees the same identifiers, values, types and ambiguity
    rejection.
    """
    dimension_ids = tuple(dict.fromkeys(dimensions))
    dimension_set = set(dimension_ids)
    columns = db.execute("""SELECT dimension_id,slot,display_name,
        properties FROM epm.semantic_column WHERE workspace_id=%s
        AND application_id=%s AND scope='Member' AND dimension_id=ANY(%s::text[])
        ORDER BY dimension_id,slot""", (scope.workspace_id,
        scope.application_id, list(dimension_ids))).fetchall()
    definitions = db.execute("""SELECT dimension_id,attribute_id,value_type,
        state_token
        FROM epm.attribute_definition WHERE workspace_id=%s
        AND application_id=%s AND scope='Member' AND status='Active'
        AND dimension_id=ANY(%s::text[]) ORDER BY dimension_id,attribute_id""", (scope.workspace_id,
        scope.application_id, list(dimension_ids))).fetchall()

    columns_by_dimension: dict[str, list[Mapping[str, Any]]] = {
        dimension: [] for dimension in dimension_ids}
    attribute_types: dict[str, dict[str, str]] = {
        dimension: {} for dimension in dimension_ids}
    alias_sources: dict[str, dict[str, tuple[str, str]]] = {
        dimension: {} for dimension in dimension_ids}
    descriptors: dict[str, dict[str, dict[str, object]]] = {
        dimension: {} for dimension in dimension_ids}
    for column in columns:
        dimension = column["dimension_id"]
        if dimension not in dimension_set:
            continue
        columns_by_dimension[dimension].append(column)
        slot = f"Custom{column['slot']:02d}"
        value_type = cast(str, column["properties"]["valueType"])
        for alias in (slot, column["display_name"]):
            source = ("legacy", slot)
            previous = alias_sources[dimension].get(alias)
            if previous is not None and previous != source:
                raise ValueError("MEMBER_LIST_ATTRIBUTE_AMBIGUOUS")
            alias_sources[dimension][alias] = source
            attribute_types[dimension][alias] = value_type
            descriptors[dimension][alias] = {
                "attributeId": slot,
                "valueType": value_type,
                "stateToken": None,
                "origin": "LegacySemanticColumn",
            }
    for definition in definitions:
        dimension = definition["dimension_id"]
        if dimension not in dimension_set:
            continue
        attribute_id = definition["attribute_id"]
        previous = alias_sources[dimension].get(attribute_id)
        if previous is not None and previous != ("legacy", attribute_id):
            raise ValueError("MEMBER_LIST_ATTRIBUTE_AMBIGUOUS")
        if (previous is not None
                and attribute_types[dimension][attribute_id]
                != definition["value_type"]):
            raise ValueError("MEMBER_LIST_ATTRIBUTE_AMBIGUOUS")
        alias_sources[dimension][attribute_id] = ("native", attribute_id)
        attribute_types[dimension][attribute_id] = cast(
            str, definition["value_type"])
        descriptors[dimension][attribute_id] = {
            "attributeId": attribute_id,
            "valueType": definition["value_type"],
            "stateToken": definition["state_token"],
            "origin": "AttributeDefinition",
        }

    attributes: dict[str, dict[str, dict[str, object]]] = {
        dimension: {} for dimension in dimension_ids}
    for member in member_rows:
        dimension = member["dimension_id"]
        if dimension not in dimension_set:
            continue
        custom_values = member["custom_values"]
        if custom_values is None:
            custom_values = {}
        if not isinstance(custom_values, Mapping):
            raise ValueError("MEMBER_ATTRIBUTE_VALUES_CORRUPT")
        values: dict[str, object] = dict(custom_values)
        for column in columns_by_dimension[dimension]:
            slot = f"Custom{column['slot']:02d}"
            values[column["display_name"]] = values.get(slot)
        attributes[dimension][cast(str, member["member_id"])] = values
    return MemberAttributeSnapshot(attributes, attribute_types, descriptors)
