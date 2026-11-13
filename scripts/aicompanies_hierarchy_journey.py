"""Prepare exact named-hierarchy MCP intents from a verified source packet.

Offline only: no authentication, network, dispatch, automatic retry or source
mutation. All metadata edits precede the builds, which share one final metadata
revision. Root declarations are explicit node memberships, never invented edges.
"""
from __future__ import annotations

import argparse
from collections import Counter
from decimal import Decimal
import gzip
from hashlib import sha256
import json
from pathlib import Path

try:
    from scripts.aicompanies_mcp_journey import (
        AXES, canonical, contained, digest, exact_json, iter_source_rows,
        load_packet, source_text, summary_text, verify_file,
    )
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from aicompanies_mcp_journey import (
        AXES, canonical, contained, digest, exact_json, iter_source_rows,
        load_packet, source_text, summary_text, verify_file,
    )

FORMAT = "openepm-aicompanies-hierarchy-journey-v1"
OPERATORS = {"ADD": "Add", "SUBTRACT": "Subtract", "EXCLUDE": "Ignore",
             "NON_ADDITIVE": "NeverAggregate", "NONADDITIVE": "NeverAggregate"}
CONTRACTS = {
    "metadata.hierarchy.create": ({"dimensionId", "hierarchyId", "name", "membershipMode", "isDefault", "expectedMetadataRevision"}, set()),
    "metadata.hierarchy.members.set": ({"dimensionId", "hierarchyId", "members", "expectedMetadataRevision"}, set()),
    "metadata.relationship.create": ({"dimensionId", "relationshipId", "parentMemberId", "childMemberId", "expectedMetadataRevision"}, {"hierarchyId", "status", "name", "shortDescription", "detailedDescription"}),
    "metadata.relationship.aggregation-operator.set": ({"relationshipId", "aggregationOperatorOverride", "expectedMetadataRevision"}, set()),
    "metadata.hierarchy.build": ({"dimensionId", "expectedMetadataRevision"}, {"hierarchyId", "membershipSemantics"}),
}


def verify_catalog(catalog):
    if catalog.get("languageVersion") != 2:
        raise ValueError("FUNCTION_CATALOG_INVALID")
    selected = {}
    for function, (required, optional) in CONTRACTS.items():
        contract = catalog.get("functions", {}).get(function, {})
        if (set(contract.get("arguments", {})) != required
                or set(contract.get("optionalArguments", {})) != optional
                or contract.get("mode") != "atomic_write"
                or contract.get("permission") != "admin"
                or contract.get("previewRequired") is not False
                or contract.get("idempotencyRequired") is not True
                or contract.get("requiredCapabilities") != []):
            raise ValueError("FUNCTION_CONTRACT_MISMATCH:" + function)
        selected[function] = digest(contract)
    return selected


def identifier(value):
    value = source_text(value, 200)
    if not value or value != value.strip() or any(ord(char) < 32 for char in value):
        raise ValueError("SOURCE_ID_INVALID")
    return value


def flag(row, field):
    if row["cellTypes"][field] != "b" or row["fields"][field] not in ("0", "1"):
        raise ValueError("SOURCE_BOOLEAN_INVALID:" + field)
    return row["fields"][field] == "1"


def graph_summary(members, edges):
    """Validate a DAG and independently pin its root/descendant semantics."""
    children = {member: set() for member in members}
    child_ids = set()
    for parent, child in edges:
        if parent not in children or child not in children or parent == child:
            raise ValueError("SOURCE_GRAPH_ENDPOINT_INVALID")
        if child in children[parent]:
            raise ValueError("SOURCE_DUPLICATE_GRAPH_EDGE")
        children[parent].add(child)
        child_ids.add(child)
    pending, descendants = set(members), {}
    while pending:
        ready = sorted(member for member in pending if not children[member] & pending)
        if not ready:
            raise ValueError("SOURCE_HIERARCHY_CYCLE")
        for member in ready:
            descendants[member] = set(children[member])
            for child in children[member]:
                descendants[member].update(descendants[child])
            pending.remove(member)
    return {"rootMemberIds": sorted(set(members) - child_ids),
            "descendantSetsSha256": digest({member: sorted(descendants[member]) for member in sorted(members)})}


def source_graphs(manifest_path, manifest, tables):
    relative = "source/hierarchies.json.gz"
    path = contained(manifest_path.parent, relative)
    verify_file(path, manifest["files"][relative])
    exported = exact_json(gzip.decompress(path.read_bytes()))
    dimensions = exported["dimensions"]
    if (type(dimensions) is not list or len(dimensions) != len(AXES)
            or {d["dimensionKey"] for d in dimensions} != {key for key, _, _ in AXES}):
        raise ValueError("SOURCE_HIERARCHY_DIMENSIONS_INVALID")
    by_key = {d["dimensionKey"]: d for d in dimensions}
    graphs, all_relationships = [], set()
    for key, table, target in AXES:
        dimension = by_key[key]
        master_rows = {row["fields"][key]: row for row in tables[table]}
        canonical_members = {member: flag(row, "IsActive") for member, row in master_rows.items()}
        if len(canonical_members) != len(tables[table]):
            raise ValueError("SOURCE_DUPLICATE_MASTER_ID")
        trees = dimension["hierarchies"]
        if (not trees or len({tree["hierarchyId"] for tree in trees}) != len(trees)
                or any(type(tree["isDefault"]) is not bool for tree in trees)
                or sum(tree["isDefault"] for tree in trees) != 1):
            raise ValueError("SOURCE_HIERARCHY_DEFAULT_INVALID")
        relationship_tables = {tree["relationshipTable"] for tree in trees}
        if len(relationship_tables) != 1:
            raise ValueError("SOURCE_RELATIONSHIP_TABLE_AMBIGUOUS")
        relationship_table = next(iter(relationship_tables))
        raw_rows = list(iter_source_rows(manifest_path, manifest, relationship_table))
        if len(raw_rows) != manifest["tables"][relationship_table]["recordCount"]:
            raise ValueError("SOURCE_RELATIONSHIP_COUNT_MISMATCH")
        known_trees = {tree["hierarchyId"] for tree in trees}
        if any(row["fields"]["HierarchyID"] not in known_trees for row in raw_rows):
            raise ValueError("SOURCE_UNKNOWN_HIERARCHY")
        for tree in sorted(trees, key=lambda item: (not item["isDefault"], item["hierarchyId"])):
            hierarchy_id = identifier(tree["hierarchyId"])
            name = identifier(tree["name"])
            members = tree["memberIds"]
            if (type(members) is not list or len(set(members)) != len(members)
                    or any(member not in canonical_members for member in members)):
                raise ValueError("SOURCE_GRAPH_MEMBERS_INVALID")
            exported_edges = {row["relationshipId"]: row for row in tree["edges"]}
            if len(exported_edges) != len(tree["edges"]):
                raise ValueError("SOURCE_DUPLICATE_EXPORTED_EDGE")
            active_ids, nodes, placements, roots, active_edges = set(), set(), [], [], []
            for row in raw_rows:
                fields = row["fields"]
                if fields["HierarchyID"] != hierarchy_id:
                    continue
                relationship_id = identifier(fields["RelationshipID"])
                if relationship_id in all_relationships:
                    raise ValueError("SOURCE_DUPLICATE_RELATIONSHIP_ID")
                all_relationships.add(relationship_id)
                active, root = flag(row, "IsActive"), flag(row, "IsRoot")
                child = identifier(fields["ChildMemberID"])
                parent = fields["ParentMemberID"]
                if root != (parent is None or parent == ""):
                    raise ValueError("SOURCE_ROOT_DECLARATION_INVALID")
                parent = None if root else identifier(parent)
                if child not in canonical_members or (parent is not None and parent not in canonical_members):
                    raise ValueError("SOURCE_GRAPH_UNKNOWN_MEMBER")
                nodes.add(child)
                if parent is not None:
                    nodes.add(parent)
                operator = OPERATORS.get(fields["RollupOperator"])
                if operator is None:
                    raise ValueError("SOURCE_OPERATOR_UNSUPPORTED")
                weight = Decimal(fields["Weight"])
                if not weight.is_finite() or weight != 1:
                    raise ValueError("SOURCE_WEIGHT_UNSUPPORTED")
                if active:
                    active_ids.add(relationship_id)
                    exported_row = exported_edges.get(relationship_id, {})
                    if (exported_row.get("hierarchyId") != hierarchy_id
                            or exported_row.get("parentMemberId") != parent
                            or exported_row.get("childMemberId") != child
                            or exported_row.get("rollupOperator") != fields["RollupOperator"]
                            or exported_row.get("isActive") is not True
                            or exported_row.get("isRoot") is not root
                            or Decimal(str(exported_row.get("weight"))) != weight):
                        raise ValueError("SOURCE_ACTIVE_EXPORT_MISMATCH")
                    if child not in members or (parent is not None and parent not in members):
                        raise ValueError("SOURCE_ACTIVE_MEMBERSHIP_MISMATCH")
                    if root:
                        roots.append(child)
                    else:
                        active_edges.append((parent, child))
                placements.append({"relationshipId": relationship_id, "parentMemberId": parent,
                    "childMemberId": child, "status": "Active" if active else "Inactive",
                    "aggregationOperatorOverride": operator, "root": root,
                    "sourceRecordId": row["recordId"], "fields": fields})
            if active_ids != set(exported_edges) or not set(members) <= nodes:
                raise ValueError("SOURCE_EXPORTED_EDGE_COVERAGE_MISMATCH")
            graph = graph_summary(members, active_edges)
            retired = sorted(member for member in members if not canonical_members[member])
            reconciled = []
            for member in retired:
                fields = master_rows[member]["fields"]
                if (fields.get("MemberType") != "Retired" or member not in roots
                        or any(member in edge for edge in active_edges)):
                    raise ValueError("SOURCE_ACTIVE_EDGE_OR_NODE_USES_INACTIVE_MEMBER")
                notes = source_text(fields.get("Notes"))
                if not notes:
                    raise ValueError("SOURCE_RETIRED_ROOT_POLICY_MISSING")
                reconciled.append({"memberId": member, "sourceMasterStatus": "Inactive",
                    "sourceMemberType": fields["MemberType"], "sourceRootPlacementStatus": "Active",
                    "targetMembershipStatus": "Inactive", "sourceNotes": notes,
                    "sourceMetadataStatus": fields.get("MetadataStatus"),
                    "sourceRootRecordIds": [row["sourceRecordId"] for row in placements if row["root"] and row["childMemberId"] == member and row["status"] == "Active"]})
            effective_members = [member for member in members if canonical_members[member]]
            effective = graph_summary(effective_members, active_edges)
            if graph["rootMemberIds"] != sorted(roots) or graph["rootMemberIds"] != sorted(tree["rootMemberIds"]):
                raise ValueError("SOURCE_GRAPH_ROOT_MISMATCH")
            graphs.append({"dimensionId": target, "sourceDimensionKey": key,
                "hierarchyId": hierarchy_id, "name": name, "isDefault": tree["isDefault"],
                "members": [{"memberId": member, "status": "Active" if member in effective_members else "Inactive"} for member in sorted(nodes)],
                "placements": sorted(placements, key=lambda item: item["relationshipId"]),
                "sourceDefinitionSha256": digest(tree),
                "sourceRootMemberIds": graph["rootMemberIds"],
                "sourceDescendantSetsSha256": graph["descendantSetsSha256"],
                "retiredRootReconciliations": reconciled, **effective})
    return graphs, exported


def build_requests(graphs, packet_sha256, workspace_id, application_id, start_revision):
    if type(start_revision) is not int or start_revision < 1:
        raise ValueError("START_METADATA_REVISION_INVALID")
    revision = start_revision
    stages = {"metadata": [], "builds": []}
    def add(stage, function, args):
        nonlocal revision
        arguments = {**args, "expectedMetadataRevision": revision}
        required, optional = CONTRACTS[function]
        if not required <= set(arguments) or set(arguments) - required - optional:
            raise ValueError("GENERATED_ARGUMENT_CONTRACT_MISMATCH")
        program = {"languageVersion": 2, "function": function, "arguments": arguments}
        identity = digest({"domain": FORMAT, "packet": packet_sha256,
            "workspaceId": workspace_id, "applicationId": application_id, "program": program})
        stages[stage].append({"id": "aic.hierarchy." + identity[:24], "route": "application",
            "tool": "execute_v2_metadata_program", "arguments": {"workspace_id": workspace_id,
                "application_id": application_id, "program": program, "idempotency_key": "aic-" + identity}})
        if stage == "metadata":
            revision += 1
    graph_summaries = []
    for graph in graphs:
        scope = {"dimensionId": graph["dimensionId"], "hierarchyId": graph["hierarchyId"]}
        add("metadata", "metadata.hierarchy.create", {**scope, "name": graph["name"],
            "membershipMode": "explicit", "isDefault": graph["isDefault"]})
        for offset in range(0, len(graph["members"]), 500):
            add("metadata", "metadata.hierarchy.members.set", {**scope, "members": graph["members"][offset:offset + 500]})
        for placement in graph["placements"]:
            if placement["root"]:
                continue
            fields = placement["fields"]
            description = [f'{graph["name"]}: {placement["parentMemberId"]} → {placement["childMemberId"]}.']
            for field in ("AggregationPolicy", "Notes", "SourceBasis", "SourceLocator"):
                if fields.get(field) not in (None, ""):
                    description.append(f"{field}: {source_text(fields[field])}")
            detail = source_text("\n".join(description))
            add("metadata", "metadata.relationship.create", {**scope,
                "relationshipId": placement["relationshipId"], "name": placement["relationshipId"],
                "parentMemberId": placement["parentMemberId"], "childMemberId": placement["childMemberId"],
                "status": placement["status"], "shortDescription": summary_text(description[0]),
                "detailedDescription": detail})
            add("metadata", "metadata.relationship.aggregation-operator.set", {
                "relationshipId": placement["relationshipId"],
                "aggregationOperatorOverride": placement["aggregationOperatorOverride"]})
        graph_summaries.append({key: graph[key] for key in ("dimensionId", "sourceDimensionKey", "hierarchyId", "name", "isDefault", "rootMemberIds", "sourceDefinitionSha256", "descendantSetsSha256", "sourceRootMemberIds", "sourceDescendantSetsSha256", "retiredRootReconciliations")} | {
            "membershipCounts": dict(Counter(row["status"] for row in graph["members"])),
            "placementCounts": dict(Counter(("root" if row["root"] else "edge") + row["status"] for row in graph["placements"])),
            "membershipSha256": digest(graph["members"]),
            "relationshipIdentityAndPolicySha256": digest([{key: row[key] for key in ("relationshipId", "parentMemberId", "childMemberId", "status", "aggregationOperatorOverride", "root", "sourceRecordId")} for row in graph["placements"]])})
    # Build only after EVERY metadata change: builds do not advance metadata_revision.
    for graph in graphs:
        add("builds", "metadata.hierarchy.build", {"dimensionId": graph["dimensionId"],
            "hierarchyId": graph["hierarchyId"], "membershipSemantics": "unique_member"})
    counts = Counter(("root" if row["root"] else "edge") + row["status"] for graph in graphs for row in graph["placements"])
    return stages, {"initialMetadataRevision": start_revision, "finalMetadataRevision": revision,
        "graphCount": len(graphs), "sourcePlacementCount": sum(counts.values()),
        "placementCounts": dict(counts), "graphs": graph_summaries,
        "retiredRootReconciliationCount": sum(len(graph["retiredRootReconciliations"]) for graph in graphs),
        "retiredRootPolicy": "Canonical master retirement overrides stale active isolated-root declarations only when explicitly Retired with source notes. Preserve raw placement unchanged in generic context; do not claim raw root-status parity. Active edges touching inactive members are rejected.",
        "rootRepresentation": "Explicit node membership; root source IDs/notes retained in generic source records. No invented parent relationships.",
        "buildPolicy": "All metadata mutations precede all builds; builds share the final metadata revision and do not increment it. Any later metadata change requires rebuilding before hierarchy queries.",
        "inactivePolicy": "Inactive source placements remain inactive; their operator overrides are preserved without activating members or relationships.",
        "sourceOrderingPolicy": "Original sort order, weights, definition text and root-record IDs remain in generic source context; non-unit weights are rejected rather than approximated.",
        "dispatchPrerequisites": ["Verify the live function contracts against the recorded hashes after named-hierarchy deployment.", "Verify exact target application metadata revision equals initialMetadataRevision and these named hierarchies/relationship IDs are absent.", "Use original request bytes and keys for exact replay; stop and reconcile any failed or unconfirmed outcome."]}


def generate(manifest_path, expected_sha256, catalog_path, output, *, start_revision,
             catalog_origin, workspace_id="ws-pilot", application_id="AIcompanies"):
    if catalog_origin not in ("candidate", "live"):
        raise ValueError("CATALOG_ORIGIN_INVALID")
    manifest, _, tables = load_packet(manifest_path, expected_sha256)
    catalog_raw = catalog_path.read_bytes()
    contracts = verify_catalog(exact_json(catalog_raw))
    graphs, exported = source_graphs(manifest_path, manifest, tables)
    stages, summary = build_requests(graphs, expected_sha256, workspace_id, application_id, start_revision)
    summary.update({"format": FORMAT, "workspaceId": workspace_id, "applicationId": application_id,
        "sourcePacketManifestSha256": expected_sha256, "sourceRevision": manifest["sourceRevision"],
        "sourceHierarchyRevision": exported["revisionId"],
        "sourceHierarchyArchive": manifest["files"]["source/hierarchies.json.gz"],
        "catalogOrigin": catalog_origin, "catalogSha256": sha256(catalog_raw).hexdigest(),
        "functionContractSha256": contracts, "generatorSourceSha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "targetMutationPerformed": False, "files": {}})
    files = {}
    for stage, requests in stages.items():
        raw = ("\n".join(canonical(request) for request in requests) + "\n").encode()
        files[stage + ".jsonl"] = raw
        summary["files"][stage] = {"path": stage + ".jsonl", "requestCount": len(requests),
            "bytes": len(raw), "sha256": sha256(raw).hexdigest()}
    files["summary.json"] = (json.dumps(summary, indent=2, ensure_ascii=False) + "\n").encode()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    if any((output / name).exists() for name in files):
        raise ValueError("OUTPUT_EXISTS_PRESERVE_ORIGINAL_INTENTS")
    for name, raw in files.items():
        with (output / name).open("xb") as stream:
            stream.write(raw)
        (output / name).chmod(0o600)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("manifest", "catalog", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--start-metadata-revision", required=True, type=int)
    parser.add_argument("--catalog-origin", choices=("candidate", "live"), required=True)
    parser.add_argument("--workspace-id", default="ws-pilot")
    parser.add_argument("--application-id", default="AIcompanies")
    args = parser.parse_args()
    result = generate(args.manifest, args.manifest_sha256, args.catalog, args.output,
        start_revision=args.start_metadata_revision, catalog_origin=args.catalog_origin,
        workspace_id=args.workspace_id, application_id=args.application_id)
    print(json.dumps({key: result[key] for key in ("graphCount", "sourcePlacementCount", "placementCounts", "initialMetadataRevision", "finalMetadataRevision", "files", "targetMutationPerformed")}, sort_keys=True))


if __name__ == "__main__":
    main()
