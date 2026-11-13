"""Compile admitted calculated-member operators into W05 dependencies."""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Iterable

from .calculated_member_contract import (
    calculated_member_digest,
    canonical_calculated_member,
)
from .calculation_dependency_contract import (
    DependencyTemplate,
    compile_dependency_template,
)
from .hierarchy_node_contract import HierarchyNodePlan
from .postgres_expression import (
    expression_references,
    source_lookups,
    source_text_lookups,
    temporal_window,
)


def _digest(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()


def _scope(mapping: dict[str, Iterable[str]]) -> list[dict[str, object]]:
    return [{"dimensionId": axis, "memberIds": sorted(set(members))}
            for axis, members in sorted(mapping.items()) if members]


def _dependency(kind: str, object_type: str, object_id: str, *,
        scope: list[dict[str, object]] | None = None,
        absence: bool = False, fanout: str = "same_partition") -> dict:
    return {"kind": kind, "objectType": object_type,
        "objectId": object_id, "scope": scope or [],
        "absenceWatch": absence, "fanout": fanout}


def _selection_dependencies(selection: dict, selector_references=None) -> tuple[list[dict], list[dict]]:
    from .selection_resolver import selection_semantic_references
    explicit = {}
    dimensions = {item['dimensionId'] for item in selection['dimensions']}
    for dimension in selection['dimensions']:
        include = dimension['include']
        if include['kind'] == 'member':
            explicit[dimension['dimensionId']] = [include['memberId']]
        elif include['kind'] == 'members' and len(include['memberIds']) <= 500:
            explicit[dimension['dimensionId']] = list(include['memberIds'])
    references = (selection_semantic_references(selection) if selector_references is None
                  else selector_references)
    dependencies, members = [], {}
    mapping = {'attribute': ('selector', 'member-attribute'),
        'hierarchy': ('hierarchy', 'named-hierarchy'),
        'hierarchy-default': ('hierarchy', 'default-hierarchy'),
        'member-domain': ('selector', 'dimension-members'),
        'member-name': ('selector', 'member-name'),
        'member-list': ('selector', 'member-list')}
    for dimension, kind, identity in sorted(set(references)):
        if dimension not in dimensions or kind not in {*mapping, 'member'}:
            raise ValueError('CALCULATION_SELECTION_REFERENCE_INVALID')
        if kind == 'member':
            members.setdefault(dimension, set()).add(identity)
            continue
        dependency_kind, object_type = mapping[kind]
        object_id = f'{dimension}:{identity}' if kind in {'attribute','hierarchy'} else identity
        dependencies.append(_dependency(dependency_kind, object_type, object_id, fanout='full_instance'))
    for dimension, identities in sorted(members.items()):
        ordered = sorted(identities)
        for offset in range(0, len(ordered), 500):
            dependencies.append(_dependency('selector', 'dimension-member', dimension,
                scope=_scope({dimension: ordered[offset:offset + 500]}), fanout='full_instance'))
    return _scope(explicit), dependencies


def compile_calculated_member_dependency_template(definition: object, *,
        active_dimensions: Iterable[str], compiler_version: str,
        selector_references=None) -> DependencyTemplate:
    dimensions = tuple(active_dimensions)
    calculated = canonical_calculated_member(
        definition, active_dimensions=dimensions)
    selection_scope, dependencies = _selection_dependencies(
        calculated["sourceSelection"], selector_references)
    dependencies.append(_dependency("raw", "numeric-fact", "raw-numeric",
        scope=selection_scope))

    # Relative lookups are absence-sensitive even when the primary selected
    # domain is anchored by present rows: a later insertion can satisfy a
    # previously missing required operand.
    for lookup in source_lookups(calculated["expression"]):
        mapping = {axis: [member] for axis, member in lookup}
        dependencies.append(_dependency("absence_range", "numeric-fact",
            "relative:" + _digest(lookup), scope=_scope(mapping),
            absence=True))
    for lookup in source_text_lookups(calculated["expression"]):
        mapping = {axis: [member] for axis, member in lookup}
        dependencies.append(_dependency("absence_range", "text-fact",
            "relative-text:" + _digest(lookup), scope=_scope(mapping),
            absence=True))

    # The owning formula and explicit definition edges are not published
    # result keys. Keeping their types distinct also avoids false graph cycles
    # when a result key happens to equal a definition ID.
    dependencies.append(_dependency("formula", "calculated-member",
        calculated["definitionId"], fanout="full_instance"))
    for item in calculated["dependencies"]:
        dependencies.append(_dependency("upstream", "calculated-member",
            item["definitionId"], fanout="downstream"))
    for identity in sorted(expression_references(calculated["expression"])):
        dependencies.append(_dependency("upstream", "calculation-result",
            identity, fanout="downstream"))

    window = temporal_window(calculated["expression"])
    if window is not None:
        temporal = window["definition"]
        dependencies.append(_dependency("calendar", "application-calendar",
            temporal["calendarId"],
            fanout="future_periods"))
    dependencies.append(_dependency("unit_policy", "result-unit",
        calculated["resultUnit"], fanout="full_instance"))

    target = calculated["target"]
    partition_key = (calculated["resultKey"] or
        f"dynamic:{calculated['definitionId']}")
    return compile_dependency_template({
        "format": "openepm-calculation-dependency-template-v1",
        "definitionId": calculated["definitionId"],
        "definitionDigest": calculated_member_digest(
            calculated, active_dimensions=dimensions),
        "compilerVersion": compiler_version,
        "dependencies": dependencies,
        "targets": [{"partitionKey": partition_key,
            "scope": _scope({target["dimensionId"]: [target["memberId"]]}),
            "createsFromEmpty": False}],
        "coverage": "complete",
    })


def compile_hierarchy_node_dependency_template(plan: HierarchyNodePlan, *,
        root_member_id: str, compiler_version: str) -> DependencyTemplate:
    """Compile a node definition while leaving its fixed POV to the binding."""
    if not isinstance(plan, HierarchyNodePlan):
        raise ValueError("HIERARCHY_NODE_DEPENDENCY_PLAN_INVALID")
    if (not isinstance(root_member_id, str) or not root_member_id
            or root_member_id != root_member_id.strip()
            or len(root_member_id) > 200
            or any(ord(character) < 32 for character in root_member_id)):
        raise ValueError("HIERARCHY_NODE_DEPENDENCY_ROOT_INVALID")
    value = plan.normalized
    definition_digest = _digest({
        "plan": value,
        "rootMemberId": root_member_id,
    })
    definition_id = f"hierarchy-node:{definition_digest[:32]}"
    partition_key = f"hierarchy-node:{definition_digest}"
    dimension = str(value["dimensionId"])
    hierarchy_identity = (
        f"{dimension}:{value['hierarchyId']}"
    )
    dependencies = [
        _dependency("raw", "numeric-fact", "raw-numeric",
                    fanout="full_instance"),
        _dependency("hierarchy", "named-hierarchy",
                    hierarchy_identity,
                    fanout="full_instance"),
        _dependency("hierarchy", "dimension-members", dimension, fanout="full_instance"),
        _dependency("unit_policy", "result-unit",
                    str(value["resultUnit"]), fanout="full_instance"),
    ]
    return compile_dependency_template({
        "format": "openepm-calculation-dependency-template-v1",
        "definitionId": definition_id,
        "definitionDigest": definition_digest,
        "compilerVersion": compiler_version,
        "dependencies": dependencies,
        "targets": [{
            "partitionKey": partition_key,
            "scope": _scope({dimension: [root_member_id]}),
            "createsFromEmpty": False,
        }],
        "coverage": "complete",
    })


def compile_applicability_expression_dependency_template(plan: object, *,
        compiler_version: str) -> DependencyTemplate:
    """Compile one relation-driven expression into exact W05 dependencies.

    The applicability relation is the selector.  Its current state token is
    deliberately resolved in the execution manifest rather than embedded in
    the symbolic identity, so a replacement of the same stable relation ID
    reaches the existing reverse index.
    """
    applicability = getattr(plan, "applicability_domain", None)
    result_key = getattr(plan, "result_key", None)
    expression = getattr(plan, "expression", None)
    if (not isinstance(applicability, dict)
            or not isinstance(result_key, str) or not result_key
            or not isinstance(expression, dict)):
        raise ValueError("APPLICABILITY_DEPENDENCY_PLAN_INVALID")
    dependencies = [
        _dependency("raw", "numeric-fact", "raw-numeric",
                    fanout="full_instance"),
        _dependency("selector", "applicability-relation",
                    applicability["relationId"], fanout="full_instance"),
    ]
    for lookup in source_lookups(expression):
        dependencies.append(_dependency("absence_range", "numeric-fact",
            "relative:" + _digest(lookup),
            scope=_scope({axis: [member] for axis, member in lookup}),
            absence=True, fanout="full_instance"))
    for lookup in source_text_lookups(expression):
        dependencies.append(_dependency("absence_range", "text-fact",
            "relative-text:" + _digest(lookup),
            scope=_scope({axis: [member] for axis, member in lookup}),
            absence=True, fanout="full_instance"))
    for identity in sorted(expression_references(expression)):
        dependencies.append(_dependency("upstream", "calculation-result",
            identity, fanout="downstream"))
    result_unit = getattr(plan, "result_unit", None)
    if result_unit is not None:
        dependencies.append(_dependency("unit_policy", "result-unit",
            f"{result_unit[0]}:{result_unit[1]}", fanout="full_instance"))
    normalized = dict(plan.normalized_program)
    normalized.pop("expectedTargetStateToken", None)
    definition_digest = _digest(normalized)
    return compile_dependency_template({
        "format": "openepm-calculation-dependency-template-v1",
        "definitionId": f"expression-result:{result_key}",
        "definitionDigest": definition_digest,
        "compilerVersion": compiler_version,
        "dependencies": dependencies,
        "targets": [{"partitionKey": result_key, "scope": [],
                     "createsFromEmpty": False}],
        "coverage": "complete",
    })


def compile_relation_apportionment_dependency_template(request: object, *,
        compiler_version: str) -> DependencyTemplate:
    """Compile one grouped business allocation as one dependency instance."""
    from .expression_apportionment import normalize_relation_request
    normalized = normalize_relation_request(request)
    domain = normalized["apportionmentDomain"]
    result_key = normalized["resultKey"]
    definition = dict(normalized)
    definition["apportionmentDomain"] = {
        key: value for key, value in domain.items()
        if key != "relationStateToken"}
    definition_digest = _digest(definition)
    return compile_dependency_template({
        "format": "openepm-calculation-dependency-template-v1",
        "definitionId": f"expression-result:{result_key}",
        "definitionDigest": definition_digest,
        "compilerVersion": compiler_version,
        "dependencies": [
            _dependency("raw", "numeric-fact", "raw-numeric",
                        fanout="full_instance"),
            _dependency("selector", "applicability-relation",
                        domain["relationId"], fanout="full_instance"),
        ],
        "targets": [{"partitionKey": result_key, "scope": [],
                     "createsFromEmpty": False}],
        "coverage": "complete",
    })
