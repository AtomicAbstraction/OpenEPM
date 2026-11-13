"""Qualify complete AIcompanies Python packets as fixed-core rule plans.

This is an offline qualification boundary for source packets generated from the
pinned owner export.  It executes only those hash-checked generated sources and
does not connect to or mutate an application.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from epm_core.postgres_application_rules import validate_definition
from openepm import Application, BuildContext
from scripts.aicompanies_rule_reconstruction import validate_packet
from scripts.reconstruct_aicompanies_via_saved_mcp import (
    load_packet, validate_complete_packet_set)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()


def qualify_packets(packets: list[dict]) -> dict:
    validate_complete_packet_set(packets)
    for packet in packets:
        validate_packet(packet)
    definitions = [item for packet in packets for item in
                   packet["definitions"] + packet.get("inactiveDefinitions", [])]
    identities = [item["definitionId"] for item in definitions]
    if len(identities) != len(set(identities)):
        raise ValueError("AICOMPANIES_RULE_IDENTITY_COLLISION")

    relations = {}
    for item in definitions:
        for relation in item.get("applicabilityRelations", []):
            relation_id = relation["relationId"]
            if relation_id in relations and relations[relation_id] != relation:
                raise ValueError("AICOMPANIES_RELATION_IDENTITY_COLLISION")
            relations[relation_id] = relation
    descriptors = [{
        "relationId": item["relationId"], "name": item["name"],
        "stateToken": "1" * 64, "definitionDigest": "2" * 64,
        "status": "Active", "columns": item["columns"],
    } for item in relations.values()]
    context = BuildContext(Application("qualification", "aicompanies"),
        1, 1, 375, {"metadata": {
            "workspaceId": "qualification", "applicationId": "aicompanies",
            "metadataRevision": 1, "dimensions": [],
            "applicabilityRelations": descriptors}})

    plans = []
    active = inactive = operation_count = case_count = relation_row_count = 0
    for packet in packets:
        for is_active, values in ((True, packet["definitions"]),
                                  (False, packet.get("inactiveDefinitions", []))):
            for item in values:
                source = item["source"]
                if sha256(source.encode()).hexdigest() != item["sourceDigest"]:
                    raise ValueError("AICOMPANIES_RULE_SOURCE_DIGEST_MISMATCH")
                namespace: dict[str, object] = {}
                exec(compile(source, "<" + item["definitionId"] + ">", "exec"),
                     namespace)
                try:
                    rule = namespace["build"](context, {})
                except Exception as error:
                    raise ValueError("AICOMPANIES_RULE_SOURCE_BUILD_FAILED:" +
                                     item["definitionId"]) from error
                definition = rule.to_definition()
                if definition.get("name") != item["definitionId"]:
                    raise ValueError("AICOMPANIES_RULE_SOURCE_IDENTITY_MISMATCH")
                validate_definition(definition)
                operations = [operation for unit in definition["units"]
                              for operation in unit["operations"]]
                if any(operation.get("function") != "facts.expression.calculate"
                       for operation in operations):
                    raise ValueError("AICOMPANIES_RULE_OPERATION_UNSUPPORTED")
                declared_relations = {
                    relation["relationId"]
                    for relation in item.get("applicabilityRelations", [])}
                emitted_relations = set()
                for operation in operations:
                    arguments = operation["arguments"]
                    domain = arguments.get("applicabilityDomain",
                                           arguments.get("apportionmentDomain"))
                    if not isinstance(domain, dict):
                        raise ValueError(
                            "AICOMPANIES_RULE_RELATION_DOMAIN_MISSING")
                    emitted_relations.add(domain["relationId"])
                if emitted_relations != declared_relations:
                    raise ValueError("AICOMPANIES_RULE_RELATION_BINDING_MISMATCH")
                plans.append({"definitionId": item["definitionId"],
                    "active": is_active,
                    "sourceDigest": item["sourceDigest"],
                    "definition": definition})
                active += is_active
                inactive += not is_active
                operation_count += len(operations)
                case_count += len(item.get("cases", []))
                relation_row_count += sum(len(relation["rows"])
                    for relation in item.get("applicabilityRelations", []))
    plans.sort(key=lambda item: item["definitionId"])
    return {
        "format": "openepm-aicompanies-rule-plan-qualification-v1",
        "activeDefinitionCount": active,
        "inactiveDefinitionCount": inactive,
        "definitionCount": len(plans),
        "operationCount": operation_count,
        "sourceCaseCount": case_count,
        "relationCount": len(relations),
        "relationRowCount": relation_row_count,
        "definitionIdsSha256": sha256(_canonical(sorted(identities))).hexdigest(),
        "fixedCorePlansSha256": sha256(_canonical(plans)).hexdigest(),
        "targetMutationPerformed": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, action="append", required=True)
    args = parser.parse_args()
    packets = [load_packet(path) for path in args.packet]
    print(json.dumps(qualify_packets(packets), sort_keys=True))


if __name__ == "__main__":
    main()
