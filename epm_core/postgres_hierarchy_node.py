"""Authorized hierarchy-node resolution over one pinned metadata snapshot."""

from __future__ import annotations

from dataclasses import dataclass

from psycopg.rows import dict_row

from .cube_aggregate_ir import CubeAggregateIR
from .calculation_dependency_compiler import (
    compile_hierarchy_node_dependency_template,
)
from .calculation_dependency_contract import DependencyTemplate
from .hierarchy_node_contract import (
    HierarchyNodePlan,
    effective_edge_operator,
    resolve_hierarchy_contributions,
)
from .hierarchy_node_lowering import lower_hierarchy_node
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout


@dataclass(frozen=True, slots=True)
class ResolvedHierarchyNode:
    aggregate_plan: CubeAggregateIR
    technical_lineage: dict[str, object] | None
    dependency_template: DependencyTemplate


class PostgresHierarchyNodeResolver:
    """Resolve metadata only; the native aggregate stage reads numeric facts."""

    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("A verified identity is required")
        self.dsn = dsn
        self.identity = identity

    def resolve(
        self,
        scope: ApplicationScope,
        plan: HierarchyNodePlan,
        *,
        root_member_id: str,
        fixed_members: dict[str, str],
    ):
        if not isinstance(scope, ApplicationScope):
            raise ValueError("HIERARCHY_NODE_SCOPE_INVALID")
        if not isinstance(plan, HierarchyNodePlan):
            raise ValueError("HIERARCHY_NODE_PLAN_INVALID")
        dimension = plan.normalized["dimensionId"]
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION READ ONLY")
                configure_statement_timeout(db, 5000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "read"
                )
                state = db.execute(
                    """SELECT metadata_revision,policy_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s""",
                    (scope.workspace_id, scope.application_id),
                ).fetchone()
                hierarchy = db.execute(
                    """SELECT metadata_revision,membership_semantics
                    FROM epm.hierarchy_state WHERE workspace_id=%s
                    AND application_id=%s AND dimension_id=%s
                    AND hierarchy_id=%s AND state_token=%s""",
                    (
                        scope.workspace_id,
                        scope.application_id,
                        dimension,
                        plan.normalized["hierarchyId"],
                        plan.normalized["hierarchyStateToken"],
                    ),
                ).fetchone()
                if (
                    state is None
                    or hierarchy is None
                    or hierarchy["metadata_revision"] != state["metadata_revision"]
                    or hierarchy["membership_semantics"]
                    != plan.normalized["membershipSemantics"]
                ):
                    raise ValueError("HIERARCHY_NODE_BINDING_STALE")
                root = db.execute(
                    """SELECT 1 FROM epm.member WHERE workspace_id=%s
                    AND application_id=%s AND dimension_id=%s
                    AND member_id=%s AND status='Active'""",
                    (
                        scope.workspace_id,
                        scope.application_id,
                        dimension,
                        root_member_id,
                    ),
                ).fetchone()
                if root is None:
                    raise ValueError("HIERARCHY_NODE_ROOT_UNAVAILABLE")
                rows = db.execute(
                    """SELECT r.parent_member_id,r.child_member_id,
                    r.relationship_id,r.aggregation_operator_override,
                    m.aggregation_operator AS member_operator
                    FROM epm.relationship r JOIN epm.member m
                      ON m.workspace_id=r.workspace_id
                     AND m.application_id=r.application_id
                     AND m.dimension_id=r.dimension_id
                     AND m.member_id=r.child_member_id
                    WHERE r.workspace_id=%s AND r.application_id=%s
                      AND r.dimension_id=%s AND r.hierarchy_id=%s
                      AND r.status='Active' AND m.status='Active'
                    ORDER BY r.parent_member_id,r.relationship_id""",
                    (
                        scope.workspace_id,
                        scope.application_id,
                        dimension,
                        plan.normalized["hierarchyId"],
                    ),
                ).fetchall()
        children: dict[str, list[tuple[str, str, str, str]]] = {}
        placement = plan.normalized["membershipSemantics"] == "placement"
        for row in rows:
            operator, source = effective_edge_operator(
                plan, relationship_id=row["relationship_id"],
                member_operator=row["member_operator"],
                relationship_override=row["aggregation_operator_override"],
                placement=placement)
            if operator in {"NeverAggregate", "Formula"}:
                raise ValueError("HIERARCHY_NODE_OPERATOR_NOT_ADDITIVE")
            children.setdefault(row["parent_member_id"], []).append(
                (row["child_member_id"], row["relationship_id"], operator, source)
            )
        authored_overrides = set(plan.normalized.get("ruleOperatorOverrides", {}))
        resolved_relationships = {row["relationship_id"] for row in rows}
        if not authored_overrides <= resolved_relationships:
            raise ValueError("HIERARCHY_NODE_RULE_OVERRIDE_TARGET_UNAVAILABLE")
        contributions = resolve_hierarchy_contributions(
            plan, root_member_id=root_member_id, children=children
        )
        aggregate_plan = lower_hierarchy_node(
            plan,
            contributions=contributions,
            fixed_members=fixed_members,
            metadata_revision=state["metadata_revision"],
            policy_revision=state["policy_revision"],
        )
        return ResolvedHierarchyNode(
            aggregate_plan,
            contributions.lineage if placement else None,
            compile_hierarchy_node_dependency_template(
                plan,
                root_member_id=root_member_id,
                compiler_version=aggregate_plan.normalized_program["compiler"],
            ),
        )
