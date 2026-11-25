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
from psycopg.errors import RaiseException

from .persistence_contract import ApplicationScope, Coordinate
from .populated_layout_mapping import (
    LayoutPins, MAX_COORDINATES, SourceCoordinate,
    compile_populated_layout_plan, _members,
)
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .multidimensional_roles import REQUIRED_PROGRAMMABLE_ROLES
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_processing_limits import configure_lock_wait, configure_statement_timeout
from .postgres_execution_policy import MAX_RESPONSE_BYTES
from .postgres_execution_scope import remaining_milliseconds


FUNCTION = "metadata.layout.populated.preview"
SOURCE_READ = "metadata.layout.populated.source.read"
REVIEW = "metadata.layout.populated.review"
DEPENDENCY_REFUSALS = frozenset({
    "STALE_LAYOUT_DEPENDENCIES",
    "LAYOUT_DEPENDENCY_LIMIT",
    "LAYOUT_DEPENDENCY_CERTIFICATE_LIMIT",
    "LAYOUT_DEPENDENCY_INVENTORY_MISMATCH",
    "LAYOUT_DEPENDENCY_COMPATIBILITY_UNPROVEN",
})
MAX_PUBLIC_ARGUMENT_BYTES = 32 * 1024 * 1024
MAX_LAYOUT_AXES = 200
# Bound the entire public envelope below the existing transport ceiling, with
# at least 4 KiB for the adapter frame. The current 64 MB transport ceiling
# leaves the existing 32 MiB whole-plan limit unchanged.
MAX_SOURCE_RESPONSE_BYTES = min(MAX_PUBLIC_ARGUMENT_BYTES, MAX_RESPONSE_BYTES - 4096)
_SOURCE_FETCH_SIZE = 500


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    return sha256(encoded).hexdigest()


def authorize_layout_plan_read(db, identity, scope, access, plan):
    """Check the complete source members of a stored replacement plan."""
    mappings = plan.get("coordinateMappings") if isinstance(plan, dict) else None
    if not isinstance(mappings, list) or not 1 <= len(mappings) <= MAX_COORDINATES:
        raise ValueError("LAYOUT_REPLACEMENT_PLAN_INVALID")
    authorize_coordinates(
        db, identity, scope,
        (Coordinate.from_mapping(mapping["sourceMembers"]) for mapping in mappings),
        kind=AccessKind.READ, expected_access=access)


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
        if isinstance(program, dict) and program.get("function") == SOURCE_READ:
            if (set(program) != {"languageVersion", "function", "arguments"}
                    or type(program.get("languageVersion")) is not int
                    or program["languageVersion"] != 2
                    or type(program.get("arguments")) is not dict
                    or program["arguments"]):
                raise ValueError("V2_POPULATED_LAYOUT_SOURCE_INVALID")
            return self.source(scope)
        if (not isinstance(program, dict)
                or set(program) != {"languageVersion", "function", "arguments"}
                or type(program.get("languageVersion")) is not int
                or program["languageVersion"] != 2
                or program.get("function") not in (FUNCTION, REVIEW)
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
            target_metadata=arguments.get("targetMetadata"),
            include_dependencies=program["function"] == REVIEW)

    def _read_authority(self, db, scope: ApplicationScope, function: str):
        access = PostgresAccessChecker.check_in_transaction(
            db, self.identity, scope, "admin", function=function)
        if access.role != "Administrator":
            if function == SOURCE_READ:
                raise ValueError("LAYOUT_SOURCE_ADMINISTRATOR_REQUIRED")
            raise ValueError("LAYOUT_PREVIEW_ADMINISTRATOR_REQUIRED")
        authority = resolve_effective_dimensional_scope(
            db, self.identity, scope, access=access, function=function)
        return access, authority.scope_digest

    def source(self, scope: ApplicationScope) -> dict:
        """Return the complete bounded source set, or no inventory at all.

        A single server cursor owns one coordinate SELECT snapshot. Application
        revision pins alone do not version registration-only coordinates, so no
        client continuation or filtered-complete result is offered here.
        """
        if not isinstance(scope, ApplicationScope):
            raise ValueError("Application scope is required")
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            db.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY")
            configure_lock_wait(db)
            configure_statement_timeout(db, 5000)
            PostgresNumericFactStore._set_scope(db, scope)
            access, scope_digest = self._read_authority(db, scope, SOURCE_READ)
            pins = self._read_pins(db, scope)
            layout = db.execute("""SELECT dimensions FROM epm.coordinate_layout
                WHERE workspace_id=%s AND application_id=%s AND schema_epoch=%s""",
                (scope.workspace_id, scope.application_id, pins.schema_epoch)).fetchone()
            dimensions = layout["dimensions"] if layout else None
            if (type(dimensions) is not list or not 1 <= len(dimensions) <= MAX_LAYOUT_AXES
                    or any(type(axis) is not str or not axis for axis in dimensions)
                    or len(set(dimensions)) != len(dimensions)):
                raise ValueError("ACTIVE_COORDINATE_LAYOUT_INVALID")
            result = {"format": "openepm-populated-layout-source-v1", "pins": pins.to_wire(),
                "sourceAxes": [{"dimensionId": axis, "valueKind": "member"} for axis in dimensions],
                "sourceCoordinates": [], "coordinateCount": 0, "complete": True}
            envelope = {"languageVersion": 2, "function": SOURCE_READ, "result": result}
            base_bytes = len(json.dumps(envelope, sort_keys=True, separators=(",", ":"),
                ensure_ascii=True, allow_nan=False).encode("ascii"))
            row_bytes = 0
            prior_id = 0
            # The cursor is private to this transaction and closes on every
            # success/refusal. LIMIT also bounds a too-large sparse inventory.
            with db.cursor(name="epm_layout_source", row_factory=dict_row) as cursor:
                configure_statement_timeout(db, 5000)
                cursor.execute("""SELECT c.coordinate_id,c.members FROM epm.coordinate c
                    JOIN epm.coordinate_projection_state p
                      USING(workspace_id,application_id,coordinate_id)
                    JOIN epm.application_state s USING(workspace_id,application_id)
                    WHERE c.workspace_id=%s AND c.application_id=%s
                      AND p.projection_generation=s.active_projection_generation
                      AND p.schema_epoch=s.schema_epoch
                    ORDER BY c.coordinate_id LIMIT %s""",
                    (scope.workspace_id, scope.application_id, MAX_COORDINATES + 1))
                while True:
                    configure_statement_timeout(db, 5000)
                    rows = cursor.fetchmany(_SOURCE_FETCH_SIZE)
                    if not rows:
                        break
                    points = []
                    for row in rows:
                        source_id = row["coordinate_id"]
                        if type(source_id) is not int or source_id <= prior_id:
                            raise ValueError("LAYOUT_SOURCE_COORDINATE_INVALID")
                        prior_id = source_id
                        members = _members(row["members"], tuple(dimensions), "SOURCE_COORDINATE")
                        coordinate = {"sourceCoordinateId": source_id, "sourceMembers": members}
                        count = len(result["sourceCoordinates"]) + 1
                        if count > MAX_COORDINATES:
                            raise ValueError("POPULATED_LAYOUT_COORDINATE_LIMIT")
                        row_bytes += len(json.dumps(coordinate, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True, allow_nan=False).encode("ascii"))
                        # Replace [] and count0 in the base envelope exactly.
                        encoded_size = base_bytes + row_bytes + count - 1 + len(str(count)) - 1
                        if encoded_size > MAX_SOURCE_RESPONSE_BYTES:
                            raise ValueError("LAYOUT_SOURCE_RESPONSE_LIMIT")
                        result["sourceCoordinates"].append(coordinate)
                        points.append(Coordinate.from_mapping(members))
                    configure_statement_timeout(db, 5000)
                    authorize_coordinates(db, self.identity, scope, points,
                                          kind=AccessKind.READ, expected_access=access)
            result["coordinateCount"] = len(result["sourceCoordinates"])
            # Empty inventory still has a bounded envelope; no source value is
            # returned before both current authority and pin checks complete.
            if len(json.dumps(envelope, sort_keys=True, separators=(",", ":"),
                    ensure_ascii=True, allow_nan=False).encode("ascii")) > MAX_SOURCE_RESPONSE_BYTES:
                raise ValueError("LAYOUT_SOURCE_RESPONSE_LIMIT")
            if self._read_authority(db, scope, SOURCE_READ) != (access, scope_digest):
                raise ValueError("LAYOUT_SOURCE_AUTHORIZATION_CHANGED")
            if self._read_pins(db, scope) != pins:
                raise ValueError("LAYOUT_CHANGED_DURING_SOURCE_READ")
            remaining_milliseconds()
            return result

    def preview(self, scope: ApplicationScope, *, expected_pins: LayoutPins,
                target_axes: object, axis_mapping: object,
                coordinate_mappings: object, target_metadata: object = None,
                include_dependencies: bool = False) -> dict:
        if not isinstance(scope, ApplicationScope):
            raise ValueError("Application scope is required")
        if not isinstance(expected_pins, LayoutPins):
            raise ValueError("LAYOUT_PINS_INVALID")
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            db.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY")
            configure_lock_wait(db)
            configure_statement_timeout(db, 5000)
            PostgresNumericFactStore._set_scope(db, scope)
            function = REVIEW if include_dependencies else FUNCTION
            access, scope_digest = self._read_authority(db, scope, function)

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
            rows = db.execute("""SELECT c.coordinate_id,c.members
                FROM epm.coordinate c JOIN epm.coordinate_projection_state p
                  USING(workspace_id,application_id,coordinate_id)
                JOIN epm.application_state s USING(workspace_id,application_id)
                WHERE c.workspace_id=%s AND c.application_id=%s
                  AND p.projection_generation=s.active_projection_generation
                  AND p.schema_epoch=s.schema_epoch
                ORDER BY c.coordinate_id LIMIT %s""",
                (scope.workspace_id, scope.application_id,
                 MAX_COORDINATES + 1)).fetchall()
            if len(rows) > MAX_COORDINATES:
                raise ValueError("POPULATED_LAYOUT_COORDINATE_LIMIT")
            authorize_coordinates(
                db, self.identity, scope,
                (Coordinate.from_mapping(row["members"]) for row in rows),
                kind=AccessKind.READ, expected_access=access)
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
            if include_dependencies:
                try:
                    inventory = db.execute(
                        "SELECT * FROM epm.layout_replacement_dependency_inventory(%s,%s)",
                        (scope.workspace_id, scope.application_id)).fetchone()
                except RaiseException as error:
                    code = error.diag.message_primary
                    if code in DEPENDENCY_REFUSALS:
                        raise ValueError(code) from error
                    raise
                dependencies = inventory["dependencies"]
                rules = sum(item["kind"] == "rule" for item in dependencies)
                if (rules != impact["rules"] or
                        len(dependencies) - rules != impact["publications"]["calculations"]):
                    raise ValueError("LAYOUT_DEPENDENCIES_CHANGED_DURING_REVIEW")
            if self._read_authority(db, scope, function) != (access, scope_digest):
                raise ValueError("LAYOUT_PREVIEW_AUTHORIZATION_CHANGED")
            final_pins = self._read_pins(db, scope)
            # Registration alone can add a current coordinate without moving a pin.
            if final_pins != actual_pins or impact["coordinates"] != len(coordinates):
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
            remaining_milliseconds()
            if include_dependencies:
                return {"preview": result, "dependencies": dependencies,
                        "dependencyDigest": inventory["dependency_digest"]}
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
        omitted = db.execute("""SELECT d.dimension_id FROM epm.dimension d
            JOIN epm.application a USING(workspace_id,application_id)
            WHERE d.workspace_id=%s AND d.application_id=%s
            AND a.kind='multidimensional' AND d.model_role=ANY(%s::text[])
            AND NOT (d.dimension_id=ANY(%s::text[])) LIMIT 1""",
            (scope.workspace_id, scope.application_id,
             sorted(REQUIRED_PROGRAMMABLE_ROLES), dimensions)).fetchone()
        if omitted is not None:
            raise ValueError("PROGRAMMABLE_REQUIRED_DIMENSION")

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
                AND dimension_id=%s AND member_id=ANY(%s::text[])""",
                (scope.workspace_id, scope.application_id,
                 proposed["dimensionId"], proposed_ids)).fetchall()
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
            (SELECT count(*) FROM epm.coordinate_projection_state p
             JOIN epm.application_state s USING(workspace_id,application_id)
             WHERE p.workspace_id=%s AND p.application_id=%s
               AND p.projection_generation=s.active_projection_generation
               AND p.schema_epoch=s.schema_epoch) AS coordinates,
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
            (SELECT count(*) FROM epm.hierarchy_state
             WHERE workspace_id=%s AND application_id=%s
             AND dimension_id=ANY(%s::text[])) AS hierarchies,
            (SELECT count(*) FROM epm.expression_rule_definition
             WHERE workspace_id=%s AND application_id=%s
               AND status='Active') AS rules,
            (SELECT count(*) FROM epm.calculation_result_state
             WHERE workspace_id=%s AND application_id=%s) AS calculations,
            (SELECT count(*) FROM epm.ic_elimination_state
             WHERE workspace_id=%s AND application_id=%s) AS eliminations,
            (SELECT count(*) FROM epm.python_program_definition
             WHERE workspace_id=%s AND application_id=%s
               AND status='Active') AS python_programs""",
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


def read_program_contract(function):
    if function not in (FUNCTION, SOURCE_READ, REVIEW):
        return None
    from .metadata_read_contract import read_contract, read_example, obj
    from .populated_layout_mapping import MAX_TARGET_MEMBERS
    identifier = {'type': 'string', 'pattern': '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'}
    count = {'type': 'integer', 'minimum': 0}
    digest = {'type': 'string', 'pattern': '^[0-9a-f]{64}$'}
    pins = obj({key: count for key in LayoutPins(0, 0, 0, 0, 0).to_wire()})
    if function == SOURCE_READ:
        axes = {'type': 'array', 'minItems': 1, 'maxItems': MAX_LAYOUT_AXES,
            'items': obj({'dimensionId': identifier, 'valueKind': {'const': 'member'}})}
        members = {'type': 'object', 'propertyNames': identifier, 'additionalProperties': identifier}
        result = obj({'format': {'const': 'openepm-populated-layout-source-v1'}, 'pins': pins,
            'sourceAxes': axes, 'sourceCoordinates': {'type': 'array', 'maxItems': MAX_COORDINATES,
                'items': obj({'sourceCoordinateId': {'type': 'integer', 'minimum': 1},
                             'sourceMembers': members})},
            'coordinateCount': {'type': 'integer', 'minimum': 0, 'maximum': MAX_COORDINATES},
            'complete': {'const': True}})
        return read_contract(function, obj({}), result,
            owner='PostgresPopulatedLayoutPreview.source',
            examples=[read_example(function, {}, name='Read the complete current layout source inventory',
                binding='Use a current Administrator application grant. Every source coordinate must pass current READ; no filtered partial inventory is returned.')],
            semantic_rules=['Includes current registration-only, numeric, text, detail and cleared coordinates from the active logical projection without fact values; historical storage coordinates are not current inventory.',
                'Complete means one coordinate SELECT snapshot, not a historical snapshot or paged collection. Later registration-only coordinates can invalidate preview despite unchanged five pins; preview revalidates the complete source set.',
                'At most 100,000 stored coordinates and a 32 MiB encoded public envelope; limit/deadline/authority refusal yields no inventory.',
                'Empty inventory is complete but cannot be used as a populated-layout preview. The existing preview whole-plan byte limit is checked separately after target mappings are supplied. Current native ID, grain and authority validation remains authoritative.'])
    axis = obj({'dimensionId': identifier, 'valueKind': {'const': 'member'}})
    target_axes = {'type': 'array', 'minItems': 1, 'maxItems': MAX_LAYOUT_AXES, 'items': axis}
    members = {'type': 'object', 'propertyNames': identifier, 'additionalProperties': identifier}
    descriptions = {'name': {'type': 'string', 'minLength': 1, 'maxLength': 200},
        'shortDescription': {'type': 'string', 'maxLength': 500},
        'detailedDescription': {'type': 'string', 'maxLength': 10000}}
    metadata = obj({'dimension': obj({'dimensionId': identifier, **descriptions,
        'modelRole': {'const': 'Custom'}, 'members': {'type': 'array',
            'minItems': 1, 'maxItems': MAX_TARGET_MEMBERS,
            'items': obj({'memberId': identifier, **descriptions})}})})
    arguments = obj({'expectedPins': pins, 'targetAxes': target_axes,
        'axisMapping': {'type': 'object', 'propertyNames': identifier,
            'additionalProperties': {'anyOf': [identifier, {'type': 'null'}]}},
        'coordinateMappings': {'type': 'array', 'minItems': 1, 'maxItems': MAX_COORDINATES,
            'items': obj({'sourceCoordinateId': {'type': 'integer', 'minimum': 1},
                'sourceMembers': members, 'targetMembers': members})},
        'targetMetadata': {'anyOf': [metadata, {'type': 'null'}]}},
        ['expectedPins', 'targetAxes', 'axisMapping', 'coordinateMappings'])
    base = {'pins': pins, 'planDigest': digest,
        'sourceAxes': {'type': 'array', 'minItems': 1, 'items': axis},
        'targetAxes': target_axes, 'affectedDimensions': {'type': 'array',
            'minItems': 1, 'uniqueItems': True, 'items': identifier},
        'impact': obj({'coordinates': count,
            'facts': obj({'numericCells': count, 'textCells': count, 'detailLines': count}),
            'hierarchies': count, 'rules': count,
            'publications': obj({'calculations': count, 'eliminations': count, 'pythonPrograms': count})}),
        'previewDigest': digest}
    result = {'oneOf': [
        obj({**base, 'format': {'const': 'openepm-populated-layout-preview-v1'}}),
        obj({**base, 'format': {'const': 'openepm-populated-layout-preview-v2'}, 'targetMetadata': metadata})]}
    example = {'expectedPins': {'metadataRevision': 1, 'dataRevision': 2,
        'policyRevision': 3, 'schemaEpoch': 4, 'sourceCommitRevision': 5},
        'targetAxes': [{'dimensionId': 'Entity', 'valueKind': 'member'}],
        'axisMapping': {'Entity': 'Entity'}, 'coordinateMappings': [
            {'sourceCoordinateId': 1, 'sourceMembers': {'Entity': 'E1'},
             'targetMembers': {'Entity': 'E1'}}]}
    if function == REVIEW:
        review_result = obj({'preview': result, 'dependencyDigest': digest,
            'dependencies': {'type': 'array', 'maxItems': 10000,
                'items': obj({'kind': {'enum': ['rule', 'publication']},
                    'id': {'type': 'string', 'minLength': 1, 'maxLength': 256},
                    'stateToken': digest, 'contentDigest': digest})}})
        return read_contract(function, arguments, review_result,
            owner='PostgresPopulatedLayoutPreview.read',
            examples=[read_example(function, example,
                name='Review an exact layout and its current dependencies',
                binding='Bind all five pins, axes and coordinates from the complete source read. Review each listed kind and ID and include dependencyDigest as expectedDependencyDigest in the replacement request.')],
            semantic_rules=['Reads the complete current dependency inventory used by replacement admission and validation. A denied source coordinate refuses the entire review.',
                'The nested preview retains its original schema and digest. The dependency digest binds the ordered inventory including current rule and publication tokens.',
                'Adding a Custom axis requires an explicit Invalidate or Rebuild decision for each listed dependency. Review starts no replacement or activation.'])
    return read_contract(function, arguments, result, owner='PostgresPopulatedLayoutPreview.read',
        examples=[read_example(function, example,
            name='Preview an exact already-known populated layout mapping',
            binding='Read metadata.layout.populated.source.read first. This minimal example assumes its complete inventory has one axis and one coordinate. Bind every returned sourceCoordinateId/sourceMembers and all five pins; include the complete source set and every required application axis. Never infer IDs from row order or a series digest.')],
        semantic_rules=['This administrator-only read reports an exact plan/impact and does not stage or activate a replacement. It checks current dimensional READ on every stored source coordinate and refuses the whole preview if any coordinate is denied.',
            'Native complete source/target grain, required programmable roles, collision/no-merge rules, exact coordinate coverage, current authority and pin fences remain authoritative.',
            'The optional v2 targetMetadata creates no metadata during preview. Its one new Custom axis, exact mapped member inventory, descriptions and byte limits remain native.',
            'The argument JSON size limit is enforced after canonical encoding; structural schemas do not replace native byte, coordinate or reference budgets.'])
