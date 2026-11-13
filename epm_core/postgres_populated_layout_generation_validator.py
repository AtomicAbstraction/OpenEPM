"""Read-only PostgreSQL binding for private layout-generation validation.

Migration 0107 represents a private generation as an exact staged coordinate
mapping. Until a later materializer adds separate private fact tables, its
target fact view is the deterministic relational projection of pinned current
facts through that mapping. This service validates that complete private view;
it never persists a certificate or activates a layout.
"""
from __future__ import annotations

from decimal import Decimal
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .populated_layout_generation_validation import (
    MAX_COORDINATES, validate_populated_layout_generation,
)
from .populated_layout_mapping import LayoutPins
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_numeric_store import PostgresNumericFactStore


_HEX32 = re.compile(r"^[0-9a-f]{32}$")


class PostgresPopulatedLayoutGenerationValidator:
    """Validate one Staged request as a current scoped Administrator."""

    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError("A PostgreSQL connection string is required")
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("A verified identity is required")
        self.dsn, self.identity = dsn, identity

    def validate(self, scope: ApplicationScope, request_id: str, *,
                 merge_policy: str, affected_dependencies: list,
                 compatibility_decisions: list) -> dict:
        if (not isinstance(scope, ApplicationScope)
                or not isinstance(request_id, str)
                or not _HEX32.fullmatch(request_id)):
            raise ValueError("LAYOUT_GENERATION_VALIDATION_REQUEST_INVALID")
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            db.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY")
            PostgresNumericFactStore._set_scope(db, scope)
            access = PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, "admin")
            authorization_scope_digest = resolve_effective_dimensional_scope(
                db, self.identity, scope, access=access,
                function="metadata.layout.populated.replace.request").scope_digest
            request = self._request(db, scope, request_id)
            if request is None:
                raise ValueError("LAYOUT_REPLACEMENT_NOT_FOUND")
            self._require_authority(request, authorization_scope_digest)
            if request["status"] != "Staged":
                raise ValueError("LAYOUT_REPLACEMENT_NOT_STAGED")
            pins = LayoutPins(request["metadata_revision"], request["data_revision"],
                              request["policy_revision"], request["schema_epoch"],
                              request["source_commit_revision"])
            self._require_pins(self._state(db, scope), pins)
            plan = request["plan"]
            mappings = plan.get("coordinateMappings") if isinstance(plan, dict) else None
            target_axes = plan.get("targetAxes") if isinstance(plan, dict) else None
            if (not isinstance(mappings, list) or not 1 <= len(mappings) <= MAX_COORDINATES
                    or not isinstance(target_axes, list)):
                raise ValueError("LAYOUT_REPLACEMENT_PLAN_INVALID")
            target_dimensions = [axis.get("dimensionId") for axis in target_axes
                                 if isinstance(axis, dict)]
            if len(target_dimensions) != len(target_axes):
                raise ValueError("LAYOUT_REPLACEMENT_PLAN_INVALID")
            plan_mapping = {item.get("sourceCoordinateId"): item.get("targetMembers")
                            for item in mappings if isinstance(item, dict)}
            if len(plan_mapping) != len(mappings):
                raise ValueError("LAYOUT_REPLACEMENT_PLAN_INVALID")

            source_ids = sorted(plan_mapping)
            source_rows = db.execute("""SELECT source.coordinate_id AS source_coordinate_id,
                n.present AS numeric_present,n.amount,
                t.present AS text_present,t.text_value,
                d.items AS detail_items,d.total AS detail_total
                FROM epm.coordinate source
                LEFT JOIN epm.numeric_cell_current n ON
                  n.workspace_id=source.workspace_id AND n.application_id=source.application_id
                  AND n.coordinate_id=source.coordinate_id
                LEFT JOIN epm.text_cell_current t ON
                  t.workspace_id=source.workspace_id AND t.application_id=source.application_id
                  AND t.coordinate_id=source.coordinate_id
                LEFT JOIN epm.line_detail_current d ON
                  d.workspace_id=source.workspace_id AND d.application_id=source.application_id
                  AND d.coordinate_id=source.coordinate_id
                WHERE source.workspace_id=%s AND source.application_id=%s
                  AND source.coordinate_id=ANY(%s::bigint[])
                ORDER BY source.coordinate_id LIMIT %s""",
                (scope.workspace_id, scope.application_id, source_ids,
                 MAX_COORDINATES + 1)).fetchall()
            staged_rows = db.execute("""SELECT source_coordinate_id,target_members
                FROM epm.layout_replacement_staged_mapping(%s,%s,%s)""",
                (scope.workspace_id, scope.application_id, request_id)).fetchall()
            if len(source_rows) > MAX_COORDINATES or len(staged_rows) > MAX_COORDINATES:
                raise ValueError("LAYOUT_GENERATION_COORDINATE_LIMIT")
            source_cells = []
            for row in source_rows:
                source_id = row["source_coordinate_id"]
                detail_items = row["detail_items"] or []
                source_cells.append({
                    "sourceCoordinateId": source_id,
                    "numeric": {"present": bool(row["numeric_present"]),
                                "amount": row["amount"] if row["numeric_present"] else None},
                    "text": {"present": bool(row["text_present"]),
                             "value": row["text_value"] if row["text_present"] else None},
                    "detail": {"present": row["detail_total"] is not None,
                               "total": row["detail_total"],
                               "items": [{"description": item["description"],
                                          "amount": Decimal(item["amount"])}
                                         for item in detail_items]}})
            relational_mappings = []
            for row in staged_rows:
                source_id = row["source_coordinate_id"]
                if plan_mapping.get(source_id) != row["target_members"]:
                    raise ValueError("LAYOUT_GENERATION_MAPPING_TAMPERED")
                relational_mappings.append({"sourceCoordinateId": source_id,
                                            "targetMembers": row["target_members"]})

            referenced = {dimension: set() for dimension in target_dimensions}
            for mapping in mappings:
                members = mapping.get("targetMembers", {})
                for dimension in target_dimensions:
                    if dimension in members:
                        referenced[dimension].add(members[dimension])
            member_ids = sorted({member for values in referenced.values() for member in values})
            member_rows = db.execute("""SELECT dimension_id,member_id FROM epm.member
                WHERE workspace_id=%s AND application_id=%s AND status='Active'
                AND dimension_id=ANY(%s::text[]) AND member_id=ANY(%s::text[])""",
                (scope.workspace_id, scope.application_id,
                 target_dimensions, member_ids)).fetchall()
            valid_members = {dimension: [] for dimension in target_dimensions}
            for row in member_rows:
                if row["member_id"] in referenced.get(row["dimension_id"], set()):
                    valid_members[row["dimension_id"]].append(row["member_id"])
            for values in valid_members.values():
                values.sort()
            proposed = plan.get("targetMetadata")
            if proposed is not None:
                try:
                    proposed_dimension = proposed["dimension"]
                    proposed_id = proposed_dimension["dimensionId"]
                    proposed_members = sorted(member["memberId"]
                                              for member in proposed_dimension["members"])
                except (KeyError, TypeError):
                    raise ValueError("LAYOUT_REPLACEMENT_PLAN_INVALID")
                if (proposed_id not in valid_members
                        or valid_members[proposed_id]
                        or set(proposed_members) != referenced[proposed_id]):
                    raise ValueError("LAYOUT_PROPOSED_METADATA_INVALID")
                valid_members[proposed_id] = proposed_members

            materialization = db.execute("""SELECT status,target_count,content_digest
                FROM epm.layout_replacement_materialization WHERE workspace_id=%s
                AND application_id=%s AND request_id=%s""",
                (scope.workspace_id, scope.application_id, request_id)).fetchone()
            if materialization is None or materialization["status"] != "Complete":
                raise ValueError("LAYOUT_MATERIALIZATION_NOT_COMPLETE")
            private_rows = db.execute("""SELECT c.target_members,c.source_coordinate_ids,
                n.present AS numeric_present,n.amount,t.present AS text_present,t.text_value,
                d.present AS detail_present,d.items AS detail_items,d.total AS detail_total
                FROM epm.layout_replacement_private_coordinate c
                LEFT JOIN epm.layout_replacement_private_numeric n USING
                 (workspace_id,application_id,generation_id,target_digest)
                LEFT JOIN epm.layout_replacement_private_text t USING
                 (workspace_id,application_id,generation_id,target_digest)
                LEFT JOIN epm.layout_replacement_private_detail d USING
                 (workspace_id,application_id,generation_id,target_digest)
                WHERE c.workspace_id=%s AND c.application_id=%s AND c.generation_id=%s
                ORDER BY c.target_key LIMIT %s""",
                (scope.workspace_id, scope.application_id,
                 request["target_generation_id"], MAX_COORDINATES + 1)).fetchall()
            if len(private_rows) > MAX_COORDINATES:
                raise ValueError("LAYOUT_GENERATION_COORDINATE_LIMIT")
            staged_cells = []
            for row in private_rows:
                if row["numeric_present"] is None or row["text_present"] is None or row["detail_present"] is None:
                    raise ValueError("LAYOUT_PRIVATE_FACT_PARTIAL")
                staged_cells.append({"targetMembers": row["target_members"],
                    "sourceCoordinateIds": list(row["source_coordinate_ids"]),
                    "numeric": {"present": row["numeric_present"],
                                "amount": row["amount"] if row["numeric_present"] else None},
                    "text": {"present": row["text_present"],
                             "value": row["text_value"] if row["text_present"] else None},
                    "detail": {"present": row["detail_present"],
                        "total": row["detail_total"] if row["detail_present"] else None,
                        "items": [{"description": item["description"],
                                   "amount": Decimal(item["amount"])}
                                  for item in (row["detail_items"] or [])]}})

            certificate = validate_populated_layout_generation(
                request_id=request_id, plan_digest=request["plan_digest"], pins=pins,
                generation_id=request["target_generation_id"],
                target_dimensions=target_dimensions,
                coordinate_mappings=relational_mappings, merge_policy=merge_policy,
                source_cells=source_cells, staged_cells=staged_cells,
                valid_target_members=valid_members,
                affected_dependencies=affected_dependencies,
                compatibility_decisions=compatibility_decisions)
            final_request = self._request(db, scope, request_id)
            if (final_request is None or final_request["status"] != "Staged"
                    or final_request["claim_generation"] != request["claim_generation"]
                    or final_request["plan_digest"] != request["plan_digest"]
                    or final_request["target_generation_id"] != request["target_generation_id"]):
                raise ValueError("LAYOUT_GENERATION_STATE_CHANGED")
            self._require_authority(final_request, authorization_scope_digest)
            self._require_pins(self._state(db, scope), pins)
            return certificate

    def persist(self, scope: ApplicationScope, request_id: str,
                certificate: dict) -> dict:
        """Persist one immutable certificate and fenced terminal state."""
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "admin")
                authorization_scope_digest = resolve_effective_dimensional_scope(
                    db, self.identity, scope, access=access,
                    function="metadata.layout.populated.replace.request").scope_digest
                request = self._request(db, scope, request_id)
                if request is None or request["status"] != "Staged":
                    raise ValueError("LAYOUT_REPLACEMENT_NOT_STAGED")
                self._require_authority(request, authorization_scope_digest)
                pins = LayoutPins(request["metadata_revision"],request["data_revision"],
                    request["policy_revision"],request["schema_epoch"],request["source_commit_revision"])
                self._require_pins(self._state(db, scope), pins)
                material = db.execute("""SELECT status,target_count,content_digest FROM
                    epm.layout_replacement_materialization WHERE workspace_id=%s
                    AND application_id=%s AND request_id=%s""",
                    (scope.workspace_id,scope.application_id,request_id)).fetchone()
                if material is None or material["status"]!="Complete":
                    raise ValueError("LAYOUT_MATERIALIZATION_NOT_COMPLETE")
                status=db.execute("""SELECT epm.layout_replacement_validation_publish
                    (%s,%s,%s,%s,%s,%s) AS status""",
                    (scope.workspace_id,scope.application_id,request_id,
                     material["content_digest"],material["target_count"],
                     Jsonb(certificate))).fetchone()["status"]
                return {"requestId":request_id,"status":status,
                        "validationDigest":certificate["validationDigest"]}

    @staticmethod
    def _request(db, scope: ApplicationScope, request_id: str):
        return db.execute("""SELECT status,claim_generation,plan,plan_digest,
            metadata_revision,data_revision,policy_revision,schema_epoch,
            source_commit_revision,target_generation_id,expected_coordinate_count,
            issuer,subject_id,verified_groups,authorization_scope_digest
            FROM epm.layout_replacement_request WHERE workspace_id=%s
            AND application_id=%s AND request_id=%s""",
            (scope.workspace_id, scope.application_id, request_id)).fetchone()

    def _require_authority(self, request, authorization_scope_digest):
        if (request["issuer"] != self.identity.issuer
                or request["subject_id"] != self.identity.subject_id
                or tuple(request["verified_groups"]) != self.identity.groups
                or request["authorization_scope_digest"] is None
                or request["authorization_scope_digest"] !=
                authorization_scope_digest):
            raise ValueError("LAYOUT_REPLACEMENT_AUTHORIZATION_SCOPE_CHANGED")

    @staticmethod
    def _state(db, scope: ApplicationScope):
        return db.execute("""SELECT metadata_revision,data_revision,policy_revision,
            schema_epoch,commit_revision,commit_open FROM epm.application_state
            WHERE workspace_id=%s AND application_id=%s""",
            (scope.workspace_id, scope.application_id)).fetchone()

    @staticmethod
    def _require_pins(state, pins: LayoutPins) -> None:
        if state is None or state["commit_open"] or LayoutPins(
                state["metadata_revision"], state["data_revision"],
                state["policy_revision"], state["schema_epoch"],
                state["commit_revision"]) != pins:
            raise ValueError("LAYOUT_GENERATION_SOURCE_PINS_STALE")
