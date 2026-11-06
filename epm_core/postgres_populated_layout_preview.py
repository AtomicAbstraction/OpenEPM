"""Authorized, read-only impact preview for populated layout replacement.

The service deliberately stops before staging or activation.  It binds the
pure mapping contract to the current PostgreSQL application snapshot, checks
every referenced dimension/member, and reports conservative invalidation
counts.  Publication must recheck these pins in a later durable workflow.
"""
from __future__ import annotations

from hashlib import sha256
import json
from typing import Mapping

from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .populated_layout_mapping import (
    LayoutPins, MAX_COORDINATES, SourceCoordinate,
    compile_populated_layout_plan,
)
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore


FUNCTION = "metadata.layout.populated.preview"
MAX_PUBLIC_ARGUMENT_BYTES = 32 * 1024 * 1024
MAX_LAYOUT_AXES = 200


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    return sha256(encoded).hexdigest()


class PostgresPopulatedLayoutPreview:
    """Compile a mapping and its impact against one authorized DB snapshot."""

    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError("A PostgreSQL connection string is required")
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("A verified identity is required")
        self.dsn = dsn
        self.identity = identity

    def read(self, scope: ApplicationScope, program: object) -> dict:
        """Validate the public V2 envelope before entering the DB boundary."""
        if (not isinstance(program, dict)
                or set(program) != {"languageVersion", "function", "arguments"}
                or type(program.get("languageVersion")) is not int
                or program["languageVersion"] != 2
                or program.get("function") != FUNCTION
                or not isinstance(program.get("arguments"), dict)):
            raise ValueError("V2_POPULATED_LAYOUT_PREVIEW_INVALID")
        arguments = program["arguments"]
        if (set(arguments) not in ({"expectedPins", "targetAxes", "axisMapping",
                                   "coordinateMappings"},
                                  {"expectedPins", "targetAxes", "axisMapping",
                                   "coordinateMappings", "targetMetadata"})):
            raise ValueError("V2_POPULATED_LAYOUT_PREVIEW_INVALID")
        pins = arguments["expectedPins"]
        if (not isinstance(pins, dict) or set(pins) != {
                "metadataRevision", "dataRevision", "policyRevision",
                "schemaEpoch", "sourceCommitRevision"}):
            raise ValueError("V2_POPULATED_LAYOUT_PREVIEW_INVALID")
        axes = arguments["targetAxes"]
        mappings = arguments["coordinateMappings"]
        if (not isinstance(axes, list) or not 1 <= len(axes) <= MAX_LAYOUT_AXES
                or not isinstance(mappings, list)
                or not 1 <= len(mappings) <= MAX_COORDINATES
                or not isinstance(arguments["axisMapping"], dict)):
            raise ValueError("V2_POPULATED_LAYOUT_PREVIEW_INVALID")
        try:
            size = len(json.dumps(arguments, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=True, allow_nan=False).encode("ascii"))
            expected = LayoutPins(
                pins["metadataRevision"], pins["dataRevision"],
                pins["policyRevision"], pins["schemaEpoch"],
                pins["sourceCommitRevision"])
        except (TypeError, ValueError) as error:
            raise ValueError("V2_POPULATED_LAYOUT_PREVIEW_INVALID") from error
        if size > MAX_PUBLIC_ARGUMENT_BYTES:
            raise ValueError("V2_POPULATED_LAYOUT_PREVIEW_ARGUMENT_LIMIT")
        return self.preview(
            scope, expected_pins=expected, target_axes=axes,
            axis_mapping=arguments["axisMapping"],
            coordinate_mappings=mappings,
            target_metadata=arguments.get("targetMetadata"))

    def preview(self, scope: ApplicationScope, *, expected_pins: LayoutPins,
                target_axes: object, axis_mapping: object,
                coordinate_mappings: object, target_metadata: object = None) -> dict:
        if not isinstance(scope, ApplicationScope):
            raise ValueError("Application scope is required")
        if not isinstance(expected_pins, LayoutPins):
            raise ValueError("LAYOUT_PINS_INVALID")
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            db.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY")
            PostgresNumericFactStore._set_scope(db, scope)
            decision = PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, "admin")
            if decision.role != "Administrator":
                raise ValueError("LAYOUT_PREVIEW_ADMINISTRATOR_REQUIRED")

            actual_pins = self._read_pins(db, scope)
            if actual_pins != expected_pins:
                raise ValueError("STALE_LAYOUT_PINS")
            layout = db.execute("""SELECT dimensions FROM epm.coordinate_layout
                WHERE workspace_id=%s AND application_id=%s
                AND schema_epoch=%s""",
                (scope.workspace_id, scope.application_id,
                 actual_pins.schema_epoch)).fetchone()
            if layout is None:
                raise ValueError("ACTIVE_COORDINATE_LAYOUT_MISSING")
            source_dimensions = list(layout["dimensions"])
            if not source_dimensions or len(source_dimensions) != len(set(source_dimensions)):
                raise ValueError("ACTIVE_COORDINATE_LAYOUT_INVALID")
            source_axes = [{"dimensionId": dimension, "valueKind": "member"}
                           for dimension in source_dimensions]

            target_dimensions = self._target_dimensions(target_axes)
            rows = db.execute("""SELECT coordinate_id,members
                FROM epm.coordinate WHERE workspace_id=%s AND application_id=%s
                ORDER BY coordinate_id LIMIT %s""",
                (scope.workspace_id, scope.application_id,
                 MAX_COORDINATES + 1)).fetchall()
            if len(rows) > MAX_COORDINATES:
                raise ValueError("POPULATED_LAYOUT_COORDINATE_LIMIT")
            coordinates = [SourceCoordinate(row["coordinate_id"], row["members"])
                           for row in rows]
            plan = compile_populated_layout_plan(
                pins=actual_pins, source_axes=source_axes,
                target_axes=target_axes, axis_mapping=axis_mapping,
                source_coordinates=coordinates,
                coordinate_mappings=coordinate_mappings,
                target_metadata=target_metadata)
            proposed = plan.to_wire().get("targetMetadata")
            proposed_dimension = (proposed["dimension"]["dimensionId"]
                                  if proposed is not None else None)
            self._require_dimensions(db, scope, target_dimensions,
                                     proposed_dimension=proposed_dimension)
            self._require_members(db, scope, plan.to_wire(),
                                  source_dimensions, target_dimensions,
                                  proposed_metadata=proposed)

            affected_dimensions = sorted(set(source_dimensions) |
                                         set(target_dimensions))
            impact = self._read_impact(db, scope, affected_dimensions)
            final_pins = self._read_pins(db, scope)
            if final_pins != actual_pins:
                raise ValueError("LAYOUT_CHANGED_DURING_PREVIEW")
            result = {
                "format": ("openepm-populated-layout-preview-v2"
                           if proposed is not None else
                           "openepm-populated-layout-preview-v1"),
                "pins": actual_pins.to_wire(),
                "planDigest": plan.digest,
                "sourceAxes": source_axes,
                "targetAxes": plan.to_wire()["targetAxes"],
                "affectedDimensions": affected_dimensions,
                "impact": impact,
            }
            if proposed is not None:
                result["targetMetadata"] = proposed
            result["previewDigest"] = _canonical_digest(result)
            return result

    @staticmethod
    def _read_pins(db, scope: ApplicationScope) -> LayoutPins:
        row = db.execute("""SELECT metadata_revision,data_revision,
            policy_revision,schema_epoch,commit_revision,commit_open
            FROM epm.application_state
            WHERE workspace_id=%s AND application_id=%s""",
            (scope.workspace_id, scope.application_id)).fetchone()
        if row is None:
            raise ValueError("APPLICATION_UNAVAILABLE")
        if row["commit_open"]:
            raise ValueError("APPLICATION_COMMIT_IN_PROGRESS")
        return LayoutPins(row["metadata_revision"], row["data_revision"],
                          row["policy_revision"], row["schema_epoch"],
                          row["commit_revision"])

    @staticmethod
    def _target_dimensions(target_axes: object) -> list[str]:
        if not isinstance(target_axes, list) or not target_axes:
            raise ValueError("TARGET_AXES_INVALID")
        result = []
        for axis in target_axes:
            if (not isinstance(axis, Mapping)
                    or set(axis) != {"dimensionId", "valueKind"}):
                raise ValueError("TARGET_AXES_INVALID")
            if axis["valueKind"] != "member":
                raise ValueError("TARGET_AXIS_TYPE_UNSUPPORTED")
            if (not isinstance(axis["dimensionId"], str)
                    or not axis["dimensionId"]):
                raise ValueError("TARGET_AXES_INVALID")
            result.append(axis["dimensionId"])
        if len(result) != len(set(result)):
            raise ValueError("TARGET_AXES_DUPLICATE")
        return result

    @staticmethod
    def _require_dimensions(db, scope: ApplicationScope,
                            dimensions: list[str], *,
                            proposed_dimension: str | None = None) -> None:
        rows = db.execute("""SELECT dimension_id FROM epm.dimension
            WHERE workspace_id=%s AND application_id=%s
            AND dimension_id=ANY(%s::text[])""",
            (scope.workspace_id, scope.application_id, dimensions)).fetchall()
        found = {row["dimension_id"] for row in rows}
        expected = set(dimensions)
        if proposed_dimension is not None:
            if proposed_dimension in found:
                raise ValueError("TARGET_METADATA_DIMENSION_ALREADY_EXISTS")
            expected.remove(proposed_dimension)
        if found != expected:
            raise ValueError("TARGET_DIMENSION_REFERENCE_MISSING")

    @staticmethod
    def _require_members(db, scope: ApplicationScope, plan: dict,
                         source_dimensions: list[str],
                         target_dimensions: list[str], *,
                         proposed_metadata: dict | None = None) -> None:
        source_required = {
            (dimension, mapping["sourceMembers"][dimension])
            for mapping in plan["coordinateMappings"]
            for dimension in source_dimensions
        }
        target_required = {
            (dimension, mapping["targetMembers"][dimension])
            for mapping in plan["coordinateMappings"]
            for dimension in target_dimensions
        }
        required = source_required | target_required
        dimensions = sorted(set(source_dimensions) | set(target_dimensions))
        member_ids = sorted({member for _, member in required})
        rows = db.execute("""SELECT dimension_id,member_id FROM epm.member
            WHERE workspace_id=%s AND application_id=%s
            AND dimension_id=ANY(%s::text[])
            AND member_id=ANY(%s::text[])""",
            (scope.workspace_id, scope.application_id,
             dimensions, member_ids)).fetchall()
        found = {(row["dimension_id"], row["member_id"]) for row in rows}
        if proposed_metadata is not None:
            proposed = proposed_metadata["dimension"]
            proposed_ids = [member["memberId"] for member in proposed["members"]]
            conflicts = db.execute("""SELECT member_id FROM epm.member
                WHERE workspace_id=%s AND application_id=%s
                AND member_id=ANY(%s::text[])""",
                (scope.workspace_id, scope.application_id,
                 proposed_ids)).fetchall()
            if conflicts:
                raise ValueError("TARGET_METADATA_MEMBER_ALREADY_EXISTS")
            found.update((proposed["dimensionId"], member["memberId"])
                         for member in proposed["members"])
        if not source_required <= found:
            raise ValueError("SOURCE_MEMBER_REFERENCE_MISSING")
        if not target_required <= found:
            raise ValueError("TARGET_MEMBER_REFERENCE_MISSING")

    @staticmethod
    def _read_impact(db, scope: ApplicationScope,
                     dimensions: list[str]) -> dict:
        facts = db.execute("""SELECT
            (SELECT count(*) FROM epm.coordinate
             WHERE workspace_id=%s AND application_id=%s) AS coordinates,
            (SELECT count(*) FROM epm.numeric_cell_current
             WHERE workspace_id=%s AND application_id=%s) AS numeric_cells,
            (SELECT count(*) FROM epm.text_cell_current
             WHERE workspace_id=%s AND application_id=%s) AS text_cells,
            (SELECT count(*) FROM epm.line_detail_current
             WHERE workspace_id=%s AND application_id=%s) AS detail_lines""",
            (scope.workspace_id, scope.application_id,
             scope.workspace_id, scope.application_id,
             scope.workspace_id, scope.application_id,
             scope.workspace_id, scope.application_id)).fetchone()
        counts = db.execute("""SELECT
            (SELECT count(*) FROM epm.hierarchy_active
             WHERE workspace_id=%s AND application_id=%s
             AND dimension_id=ANY(%s::text[])) AS hierarchies,
            (SELECT count(*) FROM epm.expression_rule_publication
             WHERE workspace_id=%s AND application_id=%s) AS rules,
            (SELECT count(*) FROM epm.calculation_publication
             WHERE workspace_id=%s AND application_id=%s) AS calculations,
            (SELECT count(*) FROM epm.ic_elimination_publication
             WHERE workspace_id=%s AND application_id=%s) AS eliminations,
            (SELECT count(*) FROM epm.python_program_publication
             WHERE workspace_id=%s AND application_id=%s) AS python_programs""",
            (scope.workspace_id, scope.application_id, dimensions,
             scope.workspace_id, scope.application_id,
             scope.workspace_id, scope.application_id,
             scope.workspace_id, scope.application_id,
             scope.workspace_id, scope.application_id)).fetchone()
        return {
            "coordinates": facts["coordinates"],
            "facts": {"numericCells": facts["numeric_cells"],
                      "textCells": facts["text_cells"],
                      "detailLines": facts["detail_lines"]},
            "hierarchies": counts["hierarchies"],
            "rules": counts["rules"],
            "publications": {"calculations": counts["calculations"],
                             "eliminations": counts["eliminations"],
                             "pythonPrograms": counts["python_programs"]},
        }
