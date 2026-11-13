"""Reconstruct current AIcompanies applicability data and authored rules via MCP.

This module consumes the pinned offline rule packets.  Business mapping rows are
saved as current application metadata before the readable Python source is
validated and activated.  It never creates calculation batches or worker work.
"""
from __future__ import annotations

from hashlib import sha256
import json

from epm_core.applicability_relation_contract import (
    applicability_relation_digest, canonical_applicability_relation)
from scripts.programmable_source_authoring import (
    _program, author_and_activate, author_and_validate, state_pins)
from scripts.provision_programmable_uat_sample_contents import _exact_replay
from scripts.aicompanies_rule_definitions import (
    reconcile_numeric_kind_requirements)


SUPPORTED_FORMATS = frozenset((
    "openepm-aicompanies-native-rules-v1",
    "openepm-aicompanies-scalar-supplement-v1",
    "openepm-aicompanies-apportionment-v1",
))


class ReconstructionReadinessError(ValueError):
    def __init__(self, readiness):
        super().__init__("AICOMPANIES_NUMERIC_KIND_REQUIREMENTS_UNSATISFIED")
        self.readiness = readiness


def _operation_prefix(prefix: str, kind: str, identity: str) -> str:
    """Keep public idempotency identities bounded and content-independent."""
    return prefix + "-" + kind + "-" + sha256(identity.encode()).hexdigest()[:24]


def validate_packet(packet: object) -> dict:
    if (type(packet) is not dict or packet.get("format") not in SUPPORTED_FORMATS
            or type(packet.get("definitions")) is not list
            or type(packet.get("inactiveDefinitions", [])) is not list):
        raise ValueError("AICOMPANIES_RULE_PACKET_INVALID")
    active_definitions = packet["definitions"]
    inactive_definitions = packet.get("inactiveDefinitions", [])
    definitions = active_definitions + inactive_definitions
    identifiers = [item.get("definitionId") for item in definitions]
    if (any(type(item) is not dict or item.get("kind") != "ApplicationRule"
            or type(item.get("definitionId")) is not str
            or type(item.get("source")) is not str
            or item.get("sourceDigest") != sha256(item["source"].encode()).hexdigest()
            or type(item.get("applicabilityRelations", [])) is not list
            for item in definitions)
            or len(identifiers) != len(set(identifiers))):
        raise ValueError("AICOMPANIES_RULE_DEFINITION_INVALID")
    # Packet placement is an execution decision, not presentation metadata.
    # Bind it to the generator's explicit eligibility bit so a copied,
    # rearranged or partially rebuilt packet cannot silently activate a source
    # conflict or demote a reviewed calculation without detection.
    if (any(item.get("activationEligible") is not True
            or item.get("activationPerformed") is not False
            for item in active_definitions)
            or any(item.get("activationEligible") is not False
                   or item.get("activationPerformed") is not False
                   for item in inactive_definitions)):
        raise ValueError("AICOMPANIES_ACTIVATION_DISPOSITION_INVALID")
    relations = {}
    for item in definitions:
        for raw in item.get("applicabilityRelations", []):
            relation = canonical_applicability_relation(raw)
            identity = relation["relationId"]
            if identity in relations and relations[identity] != relation:
                raise ValueError("AICOMPANIES_RELATION_IDENTITY_COLLISION")
            relations[identity] = relation
    declared = packet.get("applicabilityRelations", [])
    if declared:
        canonical_declared = {
            item["relationId"]: item
            for item in map(canonical_applicability_relation, declared)}
        if canonical_declared != relations:
            raise ValueError("AICOMPANIES_RELATION_INVENTORY_MISMATCH")
    return {"definitions": active_definitions,
            "inactiveDefinitions": inactive_definitions,
            "relations": relations}


def semantic_manifest(packets):
    """Seal calculated, excluded and unresolved source coverage before writes."""
    mappings, exclusions, unresolved = [], [], []
    seen_results = set()
    for packet in packets:
        packet_format = packet.get("format")
        for active, definitions in ((True, packet.get("definitions", [])),
                                    (False, packet.get("inactiveDefinitions", []))):
            for definition in definitions:
                rule_id = definition.get("definitionId")
                for case in definition.get("cases", []):
                    source_id = case.get("sourceObservationId",
                                         case.get("sourceFamilyId"))
                    result_key = case.get("resultKey")
                    if (not isinstance(rule_id, str)
                            or not isinstance(source_id, str)
                            or not isinstance(result_key, str)):
                        raise ValueError("AICOMPANIES_SEMANTIC_CASE_INVALID")
                    if "expectedRows" in case:
                        rows = case["expectedRows"]
                        if not isinstance(rows, list) or not rows:
                            raise ValueError(
                                "AICOMPANIES_SEMANTIC_OUTPUTS_INVALID")
                        outputs = [{"members": row.get("members"),
                                    "value": row.get("amount"),
                                    "unit": "amount"} for row in rows]
                        if active and outputs != [{"members": row.get("members"),
                                "value": row.get("amount"), "unit": "amount"}
                                for row in case.get("sourceControlRows", [])]:
                            raise ValueError(
                                "AICOMPANIES_ACTIVE_CONTROL_MISMATCH")
                    else:
                        outputs = [{"members": case.get("targetMembers"),
                                    "value": case.get(
                                        "expectedCalculatedValue"),
                                    "unit": case.get("resultUnit")}]
                        if active and case.get(
                                "matchesSourceControlAtEightDecimals") is not True:
                            raise ValueError(
                                "AICOMPANIES_ACTIVE_CONTROL_MISMATCH")
                    target = mappings if active else exclusions
                    for ordinal, output in enumerate(outputs, 1):
                        identity = [result_key, output["members"]]
                        encoded = json.dumps(identity, sort_keys=True,
                            separators=(",", ":"), ensure_ascii=True)
                        output_id = sha256(encoded.encode()).hexdigest()
                        if output_id in seen_results:
                            raise ValueError(
                                "AICOMPANIES_SEMANTIC_OUTPUT_COLLISION")
                        seen_results.add(output_id)
                        target.append({
                            "packetFormat": packet_format,
                            "sourceCaseId": source_id,
                            "ruleId": rule_id,
                            "resultKey": result_key,
                            "outputOrdinal": ordinal,
                            "outputIdentity": output_id,
                            **output,
                            "disposition": ("calculated" if active else
                                "excluded_conflict")})
        for item in packet.get("coverage", []):
            if item.get("status") == "unresolved":
                unresolved.append({
                    "packetFormat": packet_format,
                    "sourceCaseId": item.get("sourceObservationId"),
                    "reason": item.get("reason"),
                    "disposition": "retain_source_observation_only"})
            elif item.get("status") in (
                    "requires-source-coverage", "requires-source-binding"):
                unresolved.append({
                    "packetFormat": packet_format,
                    "sourceCaseId": item.get("sourceId"),
                    "reason": item.get("reason"),
                    "disposition": "retain_unresolved_definition_only"})
            elif item.get("status") == "partially-prepared":
                unresolved.append({
                    "packetFormat": packet_format,
                    "sourceCaseId": item.get("sourceId"),
                    "reason": "PARTIAL_SOURCE_COVERAGE",
                    "disposition": "retain_partial_definition_context"})
            for gap in item.get("uncovered", []):
                unresolved.append({
                    "packetFormat": packet_format,
                    "sourceCaseId": gap.get("sourceObservationId"),
                    "reason": gap.get("reason"),
                    "disposition": "retain_source_observation_only"})
        for gap in packet.get("movementCoverage", {}).get("uncovered", []):
            unresolved.append({
                "packetFormat": packet_format,
                "sourceCaseId": gap.get("sourceObservationId"),
                "reason": gap.get("reason"),
                "disposition": "retain_source_observation_only"})
    if any(not isinstance(item["sourceCaseId"], str)
           or not isinstance(item["reason"], str) for item in unresolved):
        raise ValueError("AICOMPANIES_UNRESOLVED_COVERAGE_INVALID")
    ordering = lambda value: json.dumps(value, sort_keys=True,
        separators=(",", ":"), ensure_ascii=True)
    mappings.sort(key=ordering)
    exclusions.sort(key=ordering)
    unresolved.sort(key=ordering)
    def digest(values):
        return sha256(json.dumps(values, sort_keys=True,
            separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()
    source_gaps_by_packet = {}
    for item in unresolved:
        if item["disposition"] == "retain_source_observation_only":
            packet_format = item["packetFormat"]
            source_gaps_by_packet[packet_format] = (
                source_gaps_by_packet.get(packet_format, 0) + 1)
    return {
        "format": "openepm-aicompanies-semantic-manifest-v1",
        "calculatedOutputCount": len(mappings),
        "excludedConflictOutputCount": len(exclusions),
        "coverageDispositionCount": len(unresolved),
        "partialDefinitionCount": sum(item["disposition"] ==
            "retain_partial_definition_context" for item in unresolved),
        "unresolvedDefinitionCount": sum(item["disposition"] ==
            "retain_unresolved_definition_only" for item in unresolved),
        "unresolvedSourceObservationCount": sum(item["disposition"] ==
            "retain_source_observation_only" for item in unresolved),
        "unresolvedSourceObservationsByPacketFormat":
            source_gaps_by_packet,
        "calculatedOutputsSha256": digest(mappings),
        "excludedConflictsSha256": digest(exclusions),
        "unresolvedCoverageSha256": digest(unresolved),
    }


async def _relation_catalog(call, scope):
    values, after, token = {}, None, None
    for _ in range(10_001):
        arguments = {"limit": 100}
        if after is not None:
            arguments.update(afterRelationId=after,
                             expectedCollectionToken=token)
        page = (await call("read_v2_program", {**scope,
            "program": _program("metadata.applicability_relation.list",
                                arguments)}))["result"]
        if token is not None and page["collectionToken"] != token:
            raise RuntimeError("AICOMPANIES_RELATION_CATALOG_CHANGED")
        token = page["collectionToken"]
        for item in page["applicabilityRelations"]:
            if item["relationId"] in values:
                raise RuntimeError("AICOMPANIES_RELATION_CATALOG_DUPLICATE")
            values[item["relationId"]] = item
        after = page["nextAfterRelationId"]
        if after is None:
            return values
    raise RuntimeError("AICOMPANIES_RELATION_CATALOG_PAGE_LIMIT")


async def _member_catalog(call, scope, dimensions):
    values = []
    for dimension in sorted(dimensions):
        after, revision = None, None
        for _ in range(10_001):
            arguments = {"dimension": dimension, "limit": 500}
            if after is not None:
                arguments.update(afterMemberId=after,
                                 expectedMetadataRevision=revision)
            page = (await call("read_v2_program", {**scope,
                "program": _program("metadata.member.list",
                                    arguments)}))["result"]
            if revision is not None and page["metadataRevision"] != revision:
                raise RuntimeError("AICOMPANIES_MEMBER_CATALOG_CHANGED")
            revision = page["metadataRevision"]
            values.extend(page["rows"])
            after = page["nextAfterMemberId"]
            if after is None:
                break
        else:
            raise RuntimeError("AICOMPANIES_MEMBER_CATALOG_PAGE_LIMIT")
    return values


async def _save_relation(call, scope, definition, prior, *, active, key_prefix):
    if prior is not None:
        if (prior["definitionDigest"] == applicability_relation_digest(definition)
                and prior["status"] == ("Active" if active else "Saved")):
            return prior
    pins = await state_pins(call, scope)
    arguments = {"definition": definition,
                 "expectedMetadataRevision": pins["expectedMetadataRevision"],
                 "expectedPolicyRevision": pins["expectedPolicyRevision"]}
    if prior is not None:
        arguments["expectedStateToken"] = prior["stateToken"]
    saved = (await _exact_replay(call, "execute_v2_metadata_program", {
        **scope, "program": _program(
            "metadata.applicability_relation.save", arguments),
        "idempotency_key": key_prefix + "-save"}, key_prefix + "-save"))["result"]
    if not active:
        return saved
    pins = await state_pins(call, scope)
    activated = (await _exact_replay(call, "execute_v2_metadata_program", {
        **scope, "program": _program("metadata.applicability_relation.activate", {
            "relationId": definition["relationId"],
            "expectedStateToken": saved["stateToken"],
            "expectedMetadataRevision": pins["expectedMetadataRevision"],
            "expectedPolicyRevision": pins["expectedPolicyRevision"]}),
        "idempotency_key": key_prefix + "-activate"},
        key_prefix + "-activate"))["result"]
    return activated


async def reconstruct_rule_packets(call, scope, packets, *, key_prefix="aic-current"):
    """Install current mapping relations, then current active authored rules."""
    prepared = [validate_packet(packet) for packet in packets]
    semantics = semantic_manifest(packets)
    dimensions = {item.get("dimensionId") for packet in packets
        for item in packet.get("numericKindRequirements", [])
        if isinstance(item, dict) and isinstance(item.get("dimensionId"), str)}
    current_members = await _member_catalog(call, scope, dimensions)
    readiness = reconcile_numeric_kind_requirements(packets, current_members)
    if not readiness["ready"]:
        raise ReconstructionReadinessError(readiness)
    definitions = [item for packet in prepared for item in packet["definitions"]]
    inactive = [item for packet in prepared
                for item in packet["inactiveDefinitions"]]
    all_ids = [item["definitionId"] for item in definitions + inactive]
    if len(all_ids) != len(set(all_ids)):
        raise ValueError("AICOMPANIES_RULE_IDENTITY_COLLISION")
    active_relations = {relation["relationId"]: relation
        for item in definitions for relation in item.get("applicabilityRelations", [])}
    inactive_relations = {relation["relationId"]: relation
        for item in inactive for relation in item.get("applicabilityRelations", [])
        if relation["relationId"] not in active_relations}
    if set(active_relations) & set(inactive_relations):
        raise ValueError("AICOMPANIES_RELATION_STATUS_CONFLICT")
    catalog = await _relation_catalog(call, scope)
    installed_relations = []
    # A relation is inert business metadata.  It must be Active for the source
    # builder to resolve it even when the resulting rule remains inactive.
    for active, relations in ((True, active_relations),
                              (True, inactive_relations)):
        for relation_id in sorted(relations):
            installed_relations.append(await _save_relation(
                call, scope, relations[relation_id], catalog.get(relation_id),
                active=active,
                key_prefix=_operation_prefix(
                    key_prefix, "relation", relation_id)))
    installed_rules = []
    for item in sorted(definitions, key=lambda value: value["definitionId"]):
        result = await author_and_activate(call, scope,
            program_id="source-rule-" + item["definitionId"],
            source=item["source"],
            declared_output={"kind":"ApplicationRule","definitionId":item["definitionId"]},
            key_prefix=_operation_prefix(
                key_prefix, "rule", item["definitionId"]),
            environment=None)
        installed_rules.append(result)
    inactive_rules = []
    for item in sorted(inactive, key=lambda value: value["definitionId"]):
        inactive_rules.append(await author_and_validate(call, scope,
            program_id="source-rule-" + item["definitionId"],
            source=item["source"],
            declared_output={"kind":"ApplicationRule","definitionId":item["definitionId"]},
            key_prefix=_operation_prefix(
                key_prefix, "rule", item["definitionId"])))
    return {"relations": installed_relations, "rules": installed_rules,
            "inactiveRules": inactive_rules,
            "numericKindReadiness": readiness,
            "semanticManifest": semantics,
            "inactiveRuleCount": len(inactive),
            "relationCount": len(installed_relations),
            "ruleCount": len(installed_rules)}
