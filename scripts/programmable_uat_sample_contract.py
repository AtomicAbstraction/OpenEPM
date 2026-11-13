"""Deterministic contract for two disposable programmable qualification fixtures.

This module is deliberately transport-neutral.  It validates the owner-approved
fixture catalogue and lowers its metadata into ordinary public V2 programs. It
does not connect to PostgreSQL, bypass MCP, or reproduce calculation logic.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any


FORMAT = "openepm-programmable-uat-samples-v1"
CANONICAL_ROLES = ("Account", "Entity", "Year", "Period", "View", "Value",
                   "Scenario", "DataType")
APPLICATIONS = ("operating-cube", "simulation-cube")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_FORBIDDEN = re.compile(
    r"(?:consolidat|intercompany|cta|goodwill|rolling.forecast|planning.mode)",
    re.IGNORECASE,
)


class SampleContractError(ValueError):
    """The final programmable sample contract is incomplete or unsafe."""


def _exact(value: object, fields: set[str], code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise SampleContractError(code)
    return value


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise SampleContractError(code)
    return value


def _text(value: object, code: str, maximum: int = 200) -> str:
    if (not isinstance(value, str) or value != value.strip()
            or not 1 <= len(value) <= maximum or _FORBIDDEN.search(value)):
        raise SampleContractError(code)
    return value


def _unique(items: list[dict[str, Any]], field: str, code: str) -> None:
    values = [item[field] for item in items]
    if len(values) != len(set(values)):
        raise SampleContractError(code)


def validate_sample_manifest(value: object) -> dict[str, Any]:
    from epm_core.member_list_contract import canonical_member_list_definition
    from epm_core.postgres_saved_grids import PostgresSavedGrids

    root = _exact(value, {"format", "applications"}, "SAMPLE_MANIFEST_INVALID")
    if root["format"] != FORMAT:
        raise SampleContractError("SAMPLE_FORMAT_UNSUPPORTED")
    applications = root["applications"]
    if not isinstance(applications, list) or len(applications) != 2:
        raise SampleContractError("SAMPLE_APPLICATION_COUNT_INVALID")
    normalized: list[dict[str, Any]] = []
    for raw in applications:
        app = _exact(raw, {
            "applicationId", "name", "purpose", "customDimension",
            "members", "relationships", "attributeDefinitions", "attributeValues",
            "memberLists", "facts", "grid", "calculatedMembers",
        }, "SAMPLE_APPLICATION_INVALID")
        application_id = _identifier(app["applicationId"], "SAMPLE_APPLICATION_ID_INVALID")
        members = app["members"]
        if not isinstance(members, list) or len(members) < 14:
            raise SampleContractError("SAMPLE_MEMBERS_INCOMPLETE")
        normalized_members = []
        coordinates: set[tuple[str, str]] = set()
        custom = _exact(app["customDimension"], {"dimensionId", "name"},
                        "SAMPLE_CUSTOM_DIMENSION_INVALID")
        custom_id = _identifier(custom["dimensionId"], "SAMPLE_CUSTOM_DIMENSION_INVALID")
        if custom_id in CANONICAL_ROLES:
            raise SampleContractError("SAMPLE_CUSTOM_DIMENSION_INVALID")
        dimensions = set(CANONICAL_ROLES) | {custom_id}
        for raw_member in members:
            member = _exact(raw_member, {"dimensionId", "memberId", "name"},
                            "SAMPLE_MEMBER_INVALID")
            dimension = _identifier(member["dimensionId"], "SAMPLE_MEMBER_INVALID")
            member_id = _identifier(member["memberId"], "SAMPLE_MEMBER_INVALID")
            if dimension not in dimensions or (dimension, member_id) in coordinates:
                raise SampleContractError("SAMPLE_MEMBER_INVALID")
            coordinates.add((dimension, member_id))
            normalized_members.append({"dimensionId": dimension,
                                       "memberId": member_id,
                                       "name": _text(member["name"], "SAMPLE_MEMBER_INVALID")})
        if not all(any(member["dimensionId"] == role for member in normalized_members)
                   for role in dimensions):
            raise SampleContractError("SAMPLE_DIMENSION_MEMBERS_INCOMPLETE")
        relationships = app["relationships"]
        if not isinstance(relationships, list) or not relationships:
            raise SampleContractError("SAMPLE_RELATIONSHIPS_INCOMPLETE")
        normalized_relationships = []
        for raw_relationship in relationships:
            relationship = _exact(raw_relationship, {
                "dimensionId", "relationshipId", "parentMemberId", "childMemberId",
                "aggregationOperatorOverride",
            }, "SAMPLE_RELATIONSHIP_INVALID")
            dimension = _identifier(relationship["dimensionId"], "SAMPLE_RELATIONSHIP_INVALID")
            parent = _identifier(relationship["parentMemberId"], "SAMPLE_RELATIONSHIP_INVALID")
            child = _identifier(relationship["childMemberId"], "SAMPLE_RELATIONSHIP_INVALID")
            if ((dimension, parent) not in coordinates or (dimension, child) not in coordinates
                    or parent == child or relationship["aggregationOperatorOverride"] not in
                    {None, "Add", "Subtract", "Ignore", "NeverAggregate"}):
                raise SampleContractError("SAMPLE_RELATIONSHIP_INVALID")
            normalized_relationships.append({**relationship,
                "relationshipId": _identifier(relationship["relationshipId"],
                                               "SAMPLE_RELATIONSHIP_INVALID")})
        _unique(normalized_relationships, "relationshipId", "SAMPLE_RELATIONSHIP_DUPLICATE")
        definitions = app["attributeDefinitions"]
        attributes = app["attributeValues"]
        if (not isinstance(definitions, list) or not definitions
                or not isinstance(attributes, list) or not attributes):
            raise SampleContractError("SAMPLE_SEMANTICS_INCOMPLETE")
        normalized_definitions = []
        for raw_definition in definitions:
            definition = _exact(raw_definition, {
                "scope", "dimensionId", "attributeId", "defaultName",
                "displayName", "shortDescription", "semanticDescription",
                "valueType", "validationConstraints",
            }, "SAMPLE_ATTRIBUTE_DEFINITION_INVALID")
            choices = definition["validationConstraints"].get("allowedValues") \
                if isinstance(definition["validationConstraints"], dict) else None
            if (definition["scope"] != "Member"
                    or definition["dimensionId"] not in dimensions
                    or definition["valueType"] != "Text"
                    or not isinstance(choices, list) or not choices):
                raise SampleContractError("SAMPLE_ATTRIBUTE_DEFINITION_INVALID")
            normalized_definitions.append({**definition,
                "attributeId": _identifier(definition["attributeId"],
                    "SAMPLE_ATTRIBUTE_DEFINITION_INVALID"),
                "defaultName": _text(definition["defaultName"],
                    "SAMPLE_ATTRIBUTE_DEFINITION_INVALID"),
                "displayName": _text(definition["displayName"],
                    "SAMPLE_ATTRIBUTE_DEFINITION_INVALID"),
                "shortDescription": _text(definition["shortDescription"],
                    "SAMPLE_ATTRIBUTE_DEFINITION_INVALID", 500),
                "semanticDescription": _text(definition["semanticDescription"],
                    "SAMPLE_ATTRIBUTE_DEFINITION_INVALID", 2000)})
        normalized_attributes = []
        definition_keys = {(item["dimensionId"], item["attributeId"]): item
                           for item in normalized_definitions}
        for raw_attribute in attributes:
            attribute = _exact(raw_attribute, {
                "scope", "dimensionId", "attributeId", "objectId", "value"},
                               "SAMPLE_MEMBER_ATTRIBUTE_INVALID")
            definition = definition_keys.get(
                (attribute["dimensionId"], attribute["attributeId"]))
            choices = (definition or {}).get("validationConstraints", {}).get(
                "allowedValues", [])
            if (attribute["scope"] != "Member"
                    or (attribute["dimensionId"], attribute["objectId"])
                        not in coordinates
                    or definition is None or attribute["value"] not in choices):
                raise SampleContractError("SAMPLE_MEMBER_ATTRIBUTE_INVALID")
            normalized_attributes.append(attribute)
        member_lists = app["memberLists"]
        if not isinstance(member_lists, list) or len(member_lists) < 2:
            raise SampleContractError("SAMPLE_MEMBER_LISTS_INCOMPLETE")
        for definition in member_lists:
            if not isinstance(definition, dict) or definition.get("format") != "openepm-member-list-v1":
                raise SampleContractError("SAMPLE_MEMBER_LIST_INVALID")
            try:
                canonical_member_list_definition(definition)
            except ValueError as error:
                raise SampleContractError("SAMPLE_MEMBER_LIST_INVALID") from error
        facts = app["facts"]
        if (not isinstance(facts, dict) or set(facts) != {"numeric", "text"}
                or not isinstance(facts["numeric"], list) or not facts["numeric"]
                or not isinstance(facts["text"], list) or not facts["text"]):
            raise SampleContractError("SAMPLE_FACTS_INCOMPLETE")
        for family, value_field in (("numeric", "decimal"), ("text", "text")):
            for fact in facts[family]:
                if (not isinstance(fact, dict)
                        or set(fact) != {"coordinate", value_field}
                        or not isinstance(fact["coordinate"], dict)
                        or set(fact["coordinate"]) != dimensions
                        or any((dimension, member) not in coordinates
                               for dimension, member in fact["coordinate"].items())
                        or not isinstance(fact[value_field], str)):
                    raise SampleContractError("SAMPLE_FACT_INVALID")
        grid = app["grid"]
        _exact(grid, {"gridId", "name", "definition"}, "SAMPLE_GRID_INVALID")
        try:
            PostgresSavedGrids._definition(grid["definition"])
        except ValueError as error:
            raise SampleContractError("SAMPLE_GRID_INVALID") from error
        calculated = app["calculatedMembers"]
        if (not isinstance(calculated, list) or len(calculated) < 2
                or {item.get("evaluation") for item in calculated} != {"dynamic", "materialized"}):
            raise SampleContractError("SAMPLE_CALCULATED_MEMBERS_INCOMPLETE")
        normalized.append({**app, "applicationId": application_id,
            "name": _text(app["name"], "SAMPLE_APPLICATION_NAME_INVALID"),
            "purpose": _text(app["purpose"], "SAMPLE_APPLICATION_PURPOSE_INVALID", 500),
            "customDimension": {"dimensionId": custom_id,
                                "name": _text(custom["name"], "SAMPLE_CUSTOM_DIMENSION_INVALID")},
            "members": normalized_members, "relationships": normalized_relationships,
            "attributeDefinitions": normalized_definitions,
            "attributeValues": normalized_attributes})
    if tuple(item["applicationId"] for item in normalized) != APPLICATIONS:
        raise SampleContractError("SAMPLE_APPLICATION_IDENTITIES_INVALID")
    return {"format": FORMAT, "applications": normalized}


@dataclass(frozen=True)
class MetadataPlan:
    application_id: str
    initial_revision: int
    final_revision: int
    operations: tuple[dict[str, Any], ...]


@dataclass(frozen=True)
class FactPlan:
    application_id: str
    operations: tuple[dict[str, Any], ...]


def build_metadata_plan(application: dict[str, Any], *, initial_revision: int = 1) -> MetadataPlan:
    """Lower one validated empty application into ordered public metadata programs."""
    if type(initial_revision) is not int or initial_revision < 1:
        raise SampleContractError("SAMPLE_INITIAL_REVISION_INVALID")
    revision = initial_revision
    operations: list[dict[str, Any]] = []

    def add(function: str, arguments: dict[str, Any], key: str, *,
            increments_metadata: bool = True) -> None:
        nonlocal revision
        operations.append({"program": {"languageVersion": 2, "function": function,
                                       "arguments": {**arguments,
                                           "expectedMetadataRevision": revision}},
                           "idempotencyKey": key})
        if increments_metadata:
            revision += 1

    prefix = "programmable-uat-v1-" + application["applicationId"]
    custom = application["customDimension"]
    add("metadata.dimension.create", {**custom, "modelRole": "Custom"}, prefix + "-dimension")
    for member in application["members"]:
        add("metadata.member.create", member,
            prefix + "-member-" + member["dimensionId"] + "-" + member["memberId"])
    for relationship in application["relationships"]:
        operator = relationship["aggregationOperatorOverride"]
        base = {key: relationship[key] for key in (
            "dimensionId", "relationshipId", "parentMemberId", "childMemberId")}
        add("metadata.relationship.create", base,
            prefix + "-relationship-" + relationship["relationshipId"])
        if operator is not None:
            add("metadata.relationship.aggregation-operator.set", {
                "relationshipId": relationship["relationshipId"],
                "aggregationOperatorOverride": operator,
            }, prefix + "-relationship-operator-" + relationship["relationshipId"])
    for dimension in sorted({item["dimensionId"] for item in application["relationships"]}):
        add("metadata.hierarchy.build", {"dimensionId": dimension,
            "membershipSemantics": "unique_member"}, prefix + "-hierarchy-" + dimension,
            increments_metadata=False)
    for definition in application["attributeDefinitions"]:
        add("metadata.attribute-definition.create", definition,
            prefix + "-attribute-definition-" + definition["dimensionId"] + "-"
            + definition["attributeId"])
    for attribute in application["attributeValues"]:
        add("metadata.attribute-value.set", attribute,
            prefix + "-attribute-value-" + attribute["dimensionId"] + "-"
            + attribute["objectId"] + "-" + attribute["attributeId"])
    return MetadataPlan(application["applicationId"], initial_revision, revision,
                        tuple(operations))


def build_calculated_member_definitions(application: dict[str, Any], *,
                                        metadata_revision: int) -> tuple[dict[str, Any], ...]:
    """Construct canonical complete-grain definitions from sample descriptors."""
    from epm_core.calculated_member_contract import canonical_calculated_member

    dimensions = sorted(set(CANONICAL_ROLES) | {
        application["customDimension"]["dimensionId"]})
    source_coordinate = application["facts"]["numeric"][0]["coordinate"]
    definitions = []
    for descriptor in application["calculatedMembers"]:
        selection = {"format": "openepm-cube-selection-v1",
            "metadataRevision": metadata_revision,
            "dimensions": [{"dimensionId": dimension,
                "include": {"kind": "member", "memberId":
                    (descriptor["sourceMemberId"] if dimension == "Account"
                     else source_coordinate[dimension])},
                "exclude": None} for dimension in dimensions]}
        definition = {"format": "openepm-calculated-member-v1",
            "definitionId": descriptor["definitionId"],
            "name": descriptor["name"],
            "target": {"dimensionId": "Account",
                       "memberId": descriptor["targetMemberId"]},
            "evaluation": descriptor["evaluation"],
            "sourceSelection": selection, "expression": descriptor["expression"],
            "dependencies": [], "resultUnit": "amount",
            "resultKey": descriptor["resultKey"],
            "maxSourceCells": 100, "maxOutputCells": 10}
        definitions.append(canonical_calculated_member(
            definition, active_dimensions=dimensions))
    return tuple(definitions)


def build_fact_plan(application: dict[str, Any]) -> FactPlan:
    """Lower mixed sample facts into ordinary preview/submit job programs."""
    prefix = "programmable-uat-v1-" + application["applicationId"]
    operations = []
    for family, literal, field in (
            ("numeric", "AmountLiteral", "decimal"),
            ("text", "TextLiteral", "text")):
        mutations = [{"coordinate": item["coordinate"], "op": "set",
            "expectedChangeId": "", "value": {"type": literal,
                field: item[field]}} for item in application["facts"][family]]
        operations.append({"family": "durable_job", "execution": "preview_submit_wait",
            "program": {"languageVersion": 2,
                "function": "facts." + family + ".batch",
                "arguments": {"mutations": mutations}},
            "idempotencyKey": prefix + "-facts-" + family})
    return FactPlan(application["applicationId"], tuple(operations))


def build_substantial_application_rule(application: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build a 14-primitive client rule from generic operations only.

    The returned binding references the current active member list.  The rule
    definition itself contains no EPM domain policy and no server-side custom
    function: clients can replace it with any other composition of primitives.
    """
    from openepm import (Amount, ApplicationRule, ApplicationRuleParameter,
                         NumericSequence, NumericSequenceExpression, Ratio,
                         StatementValue)

    custom = application["customDimension"]["dimensionId"]
    members_by_dimension: dict[str, list[str]] = {}
    parents: dict[str, set[str]] = {}
    for member in application["members"]:
        members_by_dimension.setdefault(member["dimensionId"], []).append(member["memberId"])
    for relationship in application["relationships"]:
        parents.setdefault(relationship["dimensionId"], set()).add(
            relationship["parentMemberId"])
    leaves = {dimension: [member for member in values
                          if member not in parents.get(dimension, set())]
              for dimension, values in members_by_dimension.items()}
    source = application["facts"]["numeric"][0]["coordinate"]
    outputs = {dimension: next((member for member in values
                                if member != source.get(dimension)), values[0])
               for dimension, values in leaves.items()}
    # Use the non-source View/Value and every leaf combination to guarantee
    # fresh raw coordinates without inventing scratch dimensions or members.
    candidates = []
    for account in leaves["Account"]:
        if account in {item["targetMemberId"] for item in application["calculatedMembers"]}:
            continue
        for entity in leaves["Entity"]:
            for period in leaves["Period"]:
                for custom_member in leaves[custom]:
                    candidates.append({"Account": account, "Entity": entity,
                        "Year": source["Year"], "Period": period,
                        "View": outputs["View"], "Value": outputs["Value"],
                        "Scenario": source["Scenario"], "DataType": source["DataType"],
                        custom: custom_member})
    if len(candidates) < 11:
        raise SampleContractError("SAMPLE_RULE_COORDINATES_INCOMPLETE")
    parameter = ApplicationRuleParameter(
        "SelectedMembers", "MemberList", leaves[custom], dimension_id=custom)
    rule = ApplicationRule(application["applicationId"] + ".full-rule").with_parameter(parameter)
    fact_plan = build_fact_plan(application)
    rule = rule.then(fact_plan.operations[0]["program"]["function"],
                     fact_plan.operations[0]["program"]["arguments"],
                     checkpoint_name="seed-numeric")
    rule = rule.then(fact_plan.operations[1]["program"]["function"],
                     fact_plan.operations[1]["program"]["arguments"],
                     checkpoint_name="seed-text")
    for index, coordinate in enumerate(candidates[:10], 1):
        rule = rule.then("facts.numeric.batch", {"mutations": [{
            "coordinate": coordinate, "op": "set", "expectedChangeId": "",
            "value": {"type": "AmountLiteral", "decimal": str(index)}}]},
            checkpoint_name="write-" + str(index).zfill(2))
    sequence_coordinate = candidates[10]
    sequence = (NumericSequence()
        .set(sequence_coordinate, Amount("10"), expected_change_id="")
        .add(sequence_coordinate, StatementValue(0))
        .set(sequence_coordinate,
             NumericSequenceExpression.statement_amount(1) * Ratio("0.5")))
    rule = rule.then_numeric_sequence(sequence, checkpoint_name="ordered-sequence")
    target = application["calculatedMembers"][0]["targetMemberId"]
    rule = rule.then("facts.expression.calculate", {
        "sourceMembers": {dimension: member for dimension, member in source.items()
                          if dimension != custom},
        "sourceMemberSets": [{"dimensionId": custom,
            "memberIds": parameter.reference().to_wire()}],
        "targetMembers": {"Account": target},
        "expression": {"op": "Add", "left": {"op": "SourceAmount"},
                       "right": {"op": "AmountLiteral", "decimal": "1"}},
        "resultKey": application["applicationId"] + ".full-rule.result",
    }, checkpoint_name="selection-calculation")
    definition = rule.to_definition(name=application["name"] + " full primitive rule")
    binding_list = application["memberLists"][1]
    bindings = {"SelectedMembers": {"listId": binding_list["listId"],
        "parameters": {}}}
    return definition, bindings


def contract_digest(value: dict[str, Any]) -> str:
    from hashlib import sha256
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()
