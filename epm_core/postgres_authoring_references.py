"""Bind scoped authoring references before canonical operation validation.

Only the untrusted Python proposal boundary admits these nodes. Persisted
business definitions, public V2 inputs and sealed plans use existing IDs/IR.
"""
from __future__ import annotations

import json
from collections.abc import Mapping

from openepm.metadata_references import MARKER, MetadataReference
from .postgres_authoring_context import metadata_row_allowed
from .postgres_dimensional_scope import resolve_effective_dimensional_scope

MAX_REFERENCES = 10_000
MAX_DEPTH = 64
MAX_NODES = 200_000
MAX_BYTES = 4 * 1024 * 1024
_HIERARCHY_KINDS = frozenset(("children", "parents", "descendants", "ancestors", "siblings", "leaves", "base", "hierarchy"))
_TRANSFORM_KINDS = frozenset(("Children", "Descendants", "Leaves"))
_DOMAIN_FORMATS = frozenset(("openepm-applicability-domain-v1", "openepm-apportionment-domain-v1"))


def _reference_slots(value, *, parameter_requests=None):
    """Collect only slots defined by the existing typed expression contracts.

    The unchanged canonical compilers subsequently validate complete shapes.
    A coincidental key in text, a literal, or an unknown object is not a slot.
    """
    references = {}
    parameter_requests = [] if parameter_requests is None else parameter_requests
    nodes = 0

    def walk(item, *, depth=0, dimension=None, slot=None, container=None):
        nonlocal nodes
        nodes += 1
        if depth > MAX_DEPTH or nodes > MAX_NODES:
            raise ValueError("AUTHORING_REFERENCE_STRUCTURE_BUDGET")
        if type(item) is dict and MARKER in item:
            reference = MetadataReference.from_wire(item)
            if slot != (reference.kind, reference.field):
                raise ValueError("AUTHORING_REFERENCE_POSITION_INVALID")
            if reference.dimension_id != dimension:
                raise ValueError("AUTHORING_REFERENCE_DIMENSION_MISMATCH")
            references[reference.structural_key] = reference
            if len(references) > MAX_REFERENCES:
                raise ValueError("AUTHORING_REFERENCE_COUNT_BUDGET")
            return
        if type(item) is list:
            for child in item:
                walk(child, depth=depth + 1, dimension=dimension, slot=slot,
                     container=container)
            return
        if type(item) is not dict:
            return
        selected_dimension = item.get("dimensionId", dimension)
        if not isinstance(selected_dimension, (str, type(None))):
            selected_dimension = None
        kind = item.get("kind")
        if type(kind) is not str:
            kind = None
        if kind == "member_list":
            parameter_requests.append((selected_dimension, item.get("listId"), item.get("parameters", {})))
        for key, child in item.items():
            child_dimension = selected_dimension
            admitted = None
            if container in ("coordinate", "memberOverrides", "fixedMembers", "sourceMembers", "targetMembers"):
                child_dimension, admitted = key, ("member", "id")
            elif container == "member_list.parameters" and type(child) is dict and MARKER in child:
                admitted = ("member", "id")
            elif container == "selectors":
                child_dimension = key
            elif key == "memberIds" and (kind in ("explicit", "members", "Members")
                    or container in ("targetMemberSet", "targetMemberSets", "sourceDomain")):
                admitted = ("member", "id")
            elif key in ("sourceMemberIds", "targetMemberId") and container in (
                    "reduceMemberSet", "reduceMemberSets.selections", "reduceSelection", "reduceSelections"):
                admitted = ("member", "id")
            elif key == "sample" and item.get("type") in ("Member", "MemberList"):
                admitted = ("member", "id")
            elif key == "memberId" and (kind in _HIERARCHY_KINDS | {"member"}
                    or container == "target"):
                admitted = ("member", "id")
            elif key == "rootMemberId" and kind in _TRANSFORM_KINDS:
                admitted = ("member", "id")
            elif key == "hierarchyId" and kind in _HIERARCHY_KINDS | _TRANSFORM_KINDS:
                admitted = ("hierarchy", "id")
            elif key == "attributeId" and (kind == "attribute"
                    or (kind == "order" and item.get("by") == "attribute")):
                admitted = ("attribute", "id")
            elif key == "listId" and kind == "member_list":
                admitted = ("member_list", "id")
            elif (type(item.get("format")) is str
                  and item.get("format") in _DOMAIN_FORMATS):
                field = {"relationId": "id", "relationStateToken": "stateToken",
                         "relationDigest": "definitionDigest"}.get(key)
                if field is not None:
                    child_dimension, admitted = None, ("applicability_relation", field)
            child_container = ("member_list.parameters" if key == "parameters" and kind == "member_list"
                else "reduceMemberSets.selections"
                if key == "selections" and container == "reduceMemberSets" else key)
            walk(child, depth=depth + 1, dimension=child_dimension,
                 slot=admitted, container=child_container)

    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError) as error:
        raise ValueError("AUTHORING_REFERENCE_INPUT_INVALID") from error
    if len(encoded) > MAX_BYTES:
        raise ValueError("AUTHORING_REFERENCE_BYTE_BUDGET")
    walk(value)
    return tuple(sorted(references.values(), key=lambda reference: json.dumps(
        reference.to_wire(), sort_keys=True, separators=(",", ":"))))


def _select(rows, lookup, id_key):
    exact = [row for row in rows if row[id_key] == lookup]
    candidates = exact or rows
    if not candidates:
        raise ValueError("METADATA_NAME_UNAVAILABLE")
    if len(candidates) != 1:
        raise ValueError("METADATA_NAME_AMBIGUOUS")
    return candidates[0]


def bind_authoring_references(db, scope, identity, arguments, *, metadata_revision, function):
    """Resolve bounded references under the caller's transaction/security fence."""
    parameter_requests = []
    references = _reference_slots(arguments, parameter_requests=parameter_requests)
    if not references:
        return arguments
    expected = (scope.workspace_id, scope.application_id, metadata_revision)
    if any(reference.application != expected for reference in references):
        raise ValueError("AUTHORING_REFERENCE_SCOPE_MISMATCH")
    state = db.execute("""SELECT metadata_revision,policy_revision,schema_epoch,security_revision
        FROM epm.application_state WHERE workspace_id=%s AND application_id=%s""",
        (scope.workspace_id, scope.application_id)).fetchone()
    if state is None or state["metadata_revision"] != metadata_revision:
        raise ValueError("PYTHON_BUILD_STALE_CONTEXT")
    authority = resolve_effective_dimensional_scope(db, identity, scope)
    dimensions = {}
    resolved_objects = {}

    def resolve(reference):
        object_key = (reference.kind, reference.dimension_id, reference.lookup)
        if object_key in resolved_objects:
            return resolved_objects[object_key][reference.field]
        dimension = reference.dimension_id
        if dimension is not None and dimension not in dimensions:
            row = db.execute("""SELECT dimension_id,read_security_tags,write_security_tags FROM epm.dimension
                WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s
                  AND status='Active' AND model_role IS DISTINCT FROM 'Currency'""",
                (*expected[:2], dimension)).fetchone()
            if row is None or not metadata_row_allowed(authority, dimension, row):
                raise ValueError("METADATA_NAME_UNAVAILABLE")
            dimensions[dimension] = row
        lookup = reference.lookup
        if reference.kind == "member":
            rows = db.execute("""SELECT member_id,name,read_security_tags,write_security_tags
                FROM epm.member WHERE workspace_id=%s AND application_id=%s
                  AND dimension_id=%s AND status='Active' AND (member_id=%s OR name=%s)
                ORDER BY (member_id=%s) DESC,member_id LIMIT 2""",
                (*expected[:2], dimension, lookup, lookup, lookup)).fetchall()
            # Exact ID precedence is evaluated before filtering visibility, so
            # a denied ID cannot silently rebind to somebody else's name.
            exact = [row for row in rows if row["member_id"] == lookup]
            candidates = exact or rows
            if any(not metadata_row_allowed(authority, dimension, row) for row in candidates):
                raise ValueError("METADATA_NAME_UNAVAILABLE")
            row = _select(candidates, lookup, "member_id")
            result = {"id": row["member_id"]}
        elif reference.kind == "hierarchy":
            rows = db.execute("""SELECT d.hierarchy_id,d.name,s.state_token,s.metadata_revision
                FROM epm.hierarchy_definition d LEFT JOIN epm.hierarchy_state s
                  USING(workspace_id,application_id,dimension_id,hierarchy_id)
                WHERE d.workspace_id=%s AND d.application_id=%s AND d.dimension_id=%s
                  AND d.status='Active' AND
                  ((%s::text IS NULL AND d.is_default) OR d.hierarchy_id=%s OR d.name=%s)
                ORDER BY (d.hierarchy_id=%s) DESC,d.hierarchy_id LIMIT 2""",
                (*expected[:2], dimension, lookup, lookup, lookup, lookup)).fetchall()
            row = _select(rows, lookup, "hierarchy_id")
            if row["metadata_revision"] != metadata_revision or row["state_token"] is None:
                raise ValueError("METADATA_HIERARCHY_UNAVAILABLE")
            result = {"id": row["hierarchy_id"], "stateToken": row["state_token"]}
        elif reference.kind == "attribute":
            rows = db.execute("""SELECT attribute_id,display_name FROM epm.attribute_definition
                WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s
                  AND scope='Member' AND status='Active' AND (attribute_id=%s OR display_name=%s)
                ORDER BY (attribute_id=%s) DESC,attribute_id LIMIT 2""",
                (*expected[:2], dimension, lookup, lookup, lookup)).fetchall()
            row = _select(rows, lookup, "attribute_id")
            result = {"id": row["attribute_id"]}
        elif reference.kind == "member_list":
            rows = db.execute("""SELECT * FROM epm.member_list_definition
                WHERE workspace_id=%s AND application_id=%s AND dimension_id=%s
                  AND status='Published' AND metadata_revision=%s AND (list_id=%s OR name=%s)
                ORDER BY (list_id=%s) DESC,list_id LIMIT 2""",
                (*expected[:2], dimension, metadata_revision, lookup, lookup, lookup)).fetchall()
            row = _select(rows, lookup, "list_id")
            from .postgres_definition_lifecycle import assert_current_executable
            from .member_list_contract import canonical_member_list_definition
            assert_current_executable(db, scope, row)
            definition = canonical_member_list_definition(row["definition"])
            if definition["dimensionId"] != dimension:
                raise ValueError("AUTHORING_REFERENCE_DIMENSION_MISMATCH")
            result = {"id": row["list_id"], "definition": definition}
        else:
            rows = db.execute("""SELECT relation_id,name,state_token,definition_digest
                FROM epm.applicability_relation_definition
                WHERE workspace_id=%s AND application_id=%s AND status='Active'
                  AND metadata_revision=%s AND (relation_id=%s OR name=%s)
                ORDER BY (relation_id=%s) DESC,relation_id LIMIT 2""",
                (*expected[:2], metadata_revision, lookup, lookup, lookup)).fetchall()
            row = _select(rows, lookup, "relation_id")
            result = {"id": row["relation_id"], "stateToken": row["state_token"],
                      "definitionDigest": row["definition_digest"]}
        resolved_objects[object_key] = result
        return result[reference.field]

    # Parameter maps are admitted only through the requested current list's
    # declaration; a Member lookup may never become a generic string literal.
    parameter_definitions = []
    for dimension, list_value, supplied in parameter_requests:
        list_reference = (MetadataReference.from_wire(list_value) if type(list_value) is dict
            else MetadataReference(expected, "member_list", dimension, list_value))
        resolved_id = resolve(list_reference)
        if isinstance(list_value, str) and resolved_id != list_value:
            raise ValueError("METADATA_NAME_UNAVAILABLE")
        definition = resolved_objects[("member_list", dimension, list_reference.lookup)]["definition"]
        declarations = {item["name"]: item for item in definition["parameters"]}
        if type(supplied) is not dict:
            raise ValueError("MEMBER_LIST_PARAMETER_VALUES_INVALID")
        for name, value in supplied.items():
            if type(value) is dict and MARKER in value:
                if declarations.get(name, {}).get("type") != "Member":
                    raise ValueError("AUTHORING_REFERENCE_PARAMETER_TYPE_INVALID")
        parameter_definitions.append((definition, supplied))
    values = {reference.structural_key: resolve(reference) for reference in references}
    final = db.execute("""SELECT metadata_revision,policy_revision,schema_epoch,security_revision
        FROM epm.application_state WHERE workspace_id=%s AND application_id=%s""",
        (scope.workspace_id, scope.application_id)).fetchone()
    current_authority = resolve_effective_dimensional_scope(db, identity, scope)
    if state != final or authority.scope_digest != current_authority.scope_digest:
        raise ValueError("PYTHON_BUILD_STALE_CONTEXT")

    def lower(item):
        if type(item) is dict:
            if MARKER in item:
                return values[MetadataReference.from_wire(item).structural_key]
            result = {key: lower(child) for key, child in item.items()}
            # This selector is an unordered set in the existing transform IR;
            # SDK sorting must happen on bound stable IDs, never lookup names.
            if result.get("kind") == "Members" and type(result.get("memberIds")) is list:
                result["memberIds"] = sorted(result["memberIds"])
            if set(result) == {"dimensionId", "memberIds"} and type(result["memberIds"]) is list:
                result["memberIds"] = sorted(result["memberIds"])
            if (set(result) >= {"dimensionId", "sourceMemberIds", "targetMemberId"}
                    and type(result["sourceMemberIds"]) is list):
                result["sourceMemberIds"] = sorted(result["sourceMemberIds"])
            if (result.get("languageVersion") == 2
                    and result.get("function") == "facts.expression.calculate"
                    and type(result.get("arguments")) is dict
                    and "apportionment" in result["arguments"]):
                from .expression_apportionment import normalize_request
                result["arguments"] = normalize_request(result["arguments"])
            return result
        if type(item) is list:
            return [lower(child) for child in item]
        return item
    from .member_list_evaluator import resolve_member_list_parameters
    for definition, supplied in parameter_definitions:
        resolve_member_list_parameters(definition, lower(supplied))
    result = lower(arguments)
    if function == "facts.expression.calculate" and "apportionment" in result:
        from .expression_apportionment import normalize_request
        result = normalize_request(result)
    return result
