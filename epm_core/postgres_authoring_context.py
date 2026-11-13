"""Bounded authorized names for application-aware isolated Python builders."""
from __future__ import annotations

import hashlib
import json

from openepm.metadata_references import BOOTSTRAP_CONTRACT, BOOTSTRAP_CONTRACT_DIGEST

from .dimensional_security_policy import AccessKind, ResolvedMemberSecurity, evaluate_coordinate
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_processing_limits import configure_statement_timeout

READ = "metadata.authoring.context"
CONTRACT = BOOTSTRAP_CONTRACT
CONTRACT_DIGEST = hashlib.sha256(CONTRACT.encode("ascii")).hexdigest()


def authoring_contract() -> dict[str, object]:
    """Return the static, machine-readable authoring surface.

    The descriptor names only delivered SDK primitives.  Application names and
    versions remain fixed-core-resolved symbolic references.
    """
    value = {
        "format": "openepm-authoring-contract-v1",
        "version": 3,
        "objects": {
            "member": "scoped identity; explicit singleton selection",
            "relationship": "scoped immediate edge reference",
            "placement": "current hierarchy and full ordered root-to-member edge path",
            "attribute": "typed symbolic predicate; no implicit scalar read",
        },
        "selectors": {
            "dimension": ["member", "member_list", "hierarchy", "attribute"],
            "member": ["selection", "attribute", "children", "parents",
                       "descendants", "ancestors", "siblings", "leaves", "base"],
            "hierarchy": ["children", "parents", "descendants", "ancestors", "siblings", "leaves", "base"],
            "set": ["union", "intersection", "difference"],
            "attribute": ["eq", "ne", "in", "exists"],
        },
        "expression": {
            "numeric": ["current_amount", "constant", "add", "subtract",
                        "multiply", "divide"],
            "effects": ["set"],
        },
        "policies": {
            "missing": "preserve_missing_unless_explicitly_handled",
            "parentInput": ["own_only", "children_only", "own_plus_children"],
            "placement": "explicit_hierarchy_and_placement_identity",
            "units": ["amount", "ratio"],
            "evaluation": ["dynamic", "materialized"],
            "construction": "symbolic scoped references; fixed-core binding before sealing",
            "metadataValues": "explicit authorized descriptor reads only",
            "builderContract": BOOTSTRAP_CONTRACT,
            "builderContractDigest": BOOTSTRAP_CONTRACT_DIGEST,
        },
        "limits": {"dimensions": 128, "referencesPerBuild": 10_000,
                   "referenceInputBytes": 4 * 1024 * 1024,
                   "dynamicOutputRows": 100_000},
        "lifecycle": ["save", "automatic_validation", "test", "activate", "run"],
        "inspection": ["calculation.status.read",
                       "calculation.impact.explain",
                       "facts.cube.resolved.read"],
        "references": {
            "applicabilityRelation":
                "context.app.applicability_relation(name).domain(...)",
            "pythonAuthoring": "/documentation/architecture/python-authoring/",
            "functionReference": "/documentation/mcp/tools/",
        },
    }
    value["digest"] = _digest(value)
    return value


def _digest(value):
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def catalog():
    return {READ: {"mode": "read", "permission": "read", "arguments": {},
        "result": "authorized symbolic application grain and current build revisions; emitted references resolve under fixed-core authority",
        "previewRequired": False, "idempotencyRequired": False, "workClass": "bounded_read"}}


def read_context(dsn, scope, identity, raw):
    from psycopg.rows import dict_row
    from .postgres_connection import connect_postgres
    from .postgres_numeric_store import PostgresNumericFactStore
    if (type(raw) is not dict or set(raw) != {"languageVersion", "function", "arguments"}
            or type(raw["languageVersion"]) is not int or raw["languageVersion"] != 2
            or raw["function"] != READ or raw["arguments"] != {}):
        raise ValueError("AUTHORING_CONTEXT_PROGRAM_INVALID")
    with connect_postgres(dsn, row_factory=dict_row) as db:
        with db.transaction():
            db.execute("SET TRANSACTION READ ONLY")
            PostgresNumericFactStore._set_scope(db, scope)
            from .postgres_access import PostgresAccessChecker
            PostgresAccessChecker.check_in_transaction(db, identity, scope, "read", function=READ)
            state = db.execute("""SELECT metadata_revision,policy_revision,schema_epoch,security_revision
                FROM epm.application_state WHERE workspace_id=%s AND application_id=%s""",
                (scope.workspace_id, scope.application_id)).fetchone()
            if state is None:
                raise ValueError("APPLICATION_UNAVAILABLE")
            metadata = bootstrap_context(db, scope, identity,
                expected_metadata_revision=state["metadata_revision"])
            PostgresAccessChecker.check_in_transaction(db, identity, scope, "read", function=READ)
            final = db.execute("""SELECT metadata_revision,policy_revision,schema_epoch,security_revision
                FROM epm.application_state WHERE workspace_id=%s AND application_id=%s""",
                (scope.workspace_id, scope.application_id)).fetchone()
            if state != final:
                raise ValueError("PYTHON_BUILD_STALE_CONTEXT")
    return {"workspaceId": scope.workspace_id, "applicationId": scope.application_id,
        "metadataRevision": state["metadata_revision"], "policyRevision": state["policy_revision"],
        "schemaEpoch": state["schema_epoch"], "securityRevision": state["security_revision"],
        "authority": {"issuer": identity.issuer, "subjectId": identity.subject_id},
        "references": {"metadata": metadata,
                       "authoringContract": authoring_contract()}}


def metadata_context(db, scope, identity, *, expected_metadata_revision):
    """Compatibility name for the current symbolic bootstrap contract.

    This function deliberately performs no member, hierarchy, attribute, list,
    or applicability-relation catalog read.  Fixed-core binding resolves only
    the references emitted by the builder.
    """
    return bootstrap_context(db, scope, identity,
        expected_metadata_revision=expected_metadata_revision)


def _dimension_rows(db, scope, after):
    """The bounded coordinate grain catalog, without dimension contents."""
    dimensions = db.execute("""SELECT d.dimension_id,d.name,d.read_security_tags,d.write_security_tags,
        h.state_token,h.hierarchy_id,
        h.metadata_revision AS hierarchy_revision FROM epm.dimension d
        LEFT JOIN epm.hierarchy_state h ON h.workspace_id=d.workspace_id
          AND h.application_id=d.application_id AND h.dimension_id=d.dimension_id
          AND h.hierarchy_id=epm.default_hierarchy_id(d.workspace_id,d.application_id,d.dimension_id)
        WHERE d.workspace_id=%s AND d.application_id=%s AND d.status='Active'
          AND d.model_role IS DISTINCT FROM 'Currency'
          AND (%s::text IS NULL OR d.dimension_id>%s)
        ORDER BY d.dimension_id LIMIT 256""",
        (scope.workspace_id, scope.application_id, after, after)).fetchall()
    return dimensions


def bootstrap_context(db, scope, identity, *, expected_metadata_revision):
    """Only the coordinate grain is materialized before symbolic construction.

    Members, graph contents, attributes, lists and relations are resolved from
    the references actually emitted by the builder, under fixed-core authority.
    This deliberately never falls back to the legacy descriptor catalog.
    """
    configure_statement_timeout(db, 5000)
    authority = resolve_effective_dimensional_scope(db, identity, scope)
    dimensions, complete_grain = _dimension_catalog(db, scope, authority)
    current = db.execute("""SELECT metadata_revision FROM epm.application_state
        WHERE workspace_id=%s AND application_id=%s""",
        (scope.workspace_id, scope.application_id)).fetchone()
    if current is None or current["metadata_revision"] != expected_metadata_revision:
        raise ValueError("PYTHON_BUILD_STALE_CONTEXT")
    result = {"contract": BOOTSTRAP_CONTRACT, "contractDigest": BOOTSTRAP_CONTRACT_DIGEST,
        "workspaceId": scope.workspace_id, "applicationId": scope.application_id,
        "metadataRevision": expected_metadata_revision,
        "authorizationScopeDigest": authority.scope_digest,
        "referenceMode": "symbolic", "cubeGrainAvailable": complete_grain,
        "dimensions": [{
            "dimensionId": row["dimension_id"], "name": row["name"],
            "nameLookupAllowed": row["nameLookupAllowed"], "referenceMode": "symbolic"} for row in dimensions]}
    result["contextDigest"] = _digest(result)
    return result


def metadata_row_allowed(authority, dimension, row):
    """Use current dimensional policy for dimension and member descriptors."""
    if authority.policy is None:
        return True
    return evaluate_coordinate((ResolvedMemberSecurity(dimension,
        row.get("member_id", dimension), tuple(row["read_security_tags"]),
        tuple(row["write_security_tags"])),), kind=AccessKind.READ,
        expected_dimensions=(dimension,), policy=authority.policy,
        read_assignments=authority.read_assignments, write_assignments=authority.write_assignments,
        application_administrator=authority.access.role == "Administrator",
        workspace_administrator=authority.access.workspace_administrator).allowed


def _dimension_catalog(db, scope, authority):
    """Count admitted grain descriptors, never denied rows, against its limit.

    The fixed scan budget limits private inspection work; exhausting it yields
    no partial catalog and discloses neither a hidden name nor a hidden count.
    """
    visible, after, scanned, complete = [], None, 0, True
    reserved_ids = set()
    while True:
        page = _dimension_rows(db, scope, after)
        scanned += len(page)
        if scanned > 4096:
            raise ValueError("AUTHORING_METADATA_SCOPE_UNAVAILABLE")
        for row in page:
            if metadata_row_allowed(authority, row["dimension_id"], row):
                visible.append(row)
                if len(visible) > 128:
                    raise ValueError("AUTHORING_METADATA_DIMENSION_BUDGET")
            else:
                complete = False
                reserved_ids.add(row["dimension_id"])
        if len(page) < 256:
            return [{**row, "nameLookupAllowed": row["name"] not in reserved_ids}
                    for row in visible], complete
        after = page[-1]["dimension_id"]
