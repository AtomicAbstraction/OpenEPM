"""One authorized revision cut for canonical raw/calculated/combined views."""
from __future__ import annotations

from .cube_view_read_contract import (
    FORMAT, assemble_cube_view_rows, compile_cube_view_read, view_read_identity)
from psycopg import sql
from .cube_view_contract import cube_view_digest
from .postgres_access import AccessDenied, PostgresAccessChecker
from .postgres_calculation_scan import PostgresCalculationScan
from .postgres_cube_query import PostgresCubeQuery
from .postgres_dimensional_scope import reject_mixed_metadata_reads, resolve_effective_dimensional_scope
from .postgres_dimensional_security import CUBE_READ_AUTHORIZATION_STALE
from .postgres_dimensional_security_enforcement import filter_read_rows
from .postgres_processing_limits import configure_statement_timeout
from .postgres_selection_preview import resolve_selection_in_transaction

FUNCTION = "facts.cube.resolved.read"


def read_cube_view_in_transaction(db, scope, *, identity, dsn, cursor_secret,
                                  arguments, dimensions, snapshot):
    # The existing resolved-read owner establishes READ ONLY and scope. Recheck
    # the exact function here and at completion; a view reference grants nothing.
    from .postgres_resolved_cube_read import load_resolved_read_snapshot
    plan = compile_cube_view_read(arguments, active_dimensions=dimensions,
                                  expected_metadata_revision=snapshot["metadataRevision"])
    configure_statement_timeout(db, plan["limits"]["timeoutMs"])
    access = PostgresAccessChecker.check_in_transaction(
        db, identity, scope, "read", function=FUNCTION)
    authority = resolve_effective_dimensional_scope(db, identity, scope, access=access)
    stored = None
    if access.authorization_model == 'group_assignments':
        from .postgres_saved_grids import _object_visible_sql, _view_visible_sql
        current_view = sql.SQL("""SELECT g.state_token FROM epm.saved_grid_definition g
            WHERE g.workspace_id=%s AND g.application_id=%s AND g.grid_id=%s AND g.canonical_digest=%s
              AND {} AND {}""").format(_object_visible_sql(authority,'views.run'), _view_visible_sql(authority))
        view_params = (scope.workspace_id,scope.application_id,plan['view']['viewId'],cube_view_digest(plan['view']))
        stored = db.execute(current_view,view_params).fetchone()
        if stored is None:
            raise ValueError('SAVED_GRID_NOT_FOUND')
        if plan['view']['dataSource']['kind'] != 'raw' or plan['readPolicy']['semantics'] != 'stored':
            raise AccessDenied('CUBE_VIEW_RAW_STORED_SOURCE_REQUIRED')
        if reject_mixed_metadata_reads(authority):
            raise AccessDenied('DIMENSIONAL_SELECTION_REJECT_ALL_REQUIRES_EXPLICIT_COORDINATES')
    resolved = resolve_selection_in_transaction(db, scope,
        plan["view"]["selection"], snapshot["metadataRevision"], authority=authority,
        require_current_layout=True)
    maximum = plan["limits"]["maxRows"]
    kind = plan["view"]["dataSource"]["kind"]
    raw = []
    raw_source_count = 0
    calculation = None
    if kind in {"raw", "combined"}:
        raw = PostgresCubeQuery._page(db, scope, {}, "",
            snapshot["commitRevision"], snapshot["commitRevision"], True,
            maximum + 1, member_sets=resolved["members"], include_zero=True,
            **({'assignment_scope':authority} if stored is not None else {}))
        if len(raw) > maximum:
            raise ValueError("RESOURCE_LIMIT")
        raw_source_count = len(raw)
        if raw_source_count > plan["limits"]["maxSourceRows"]:
            raise ValueError("RESOURCE_LIMIT")
        raw = filter_read_rows(db, identity, scope, raw, expected_access=access)
        if plan["readPolicy"]["semantics"] == "own":
            # Own semantics retain the existing resolver's unit, presence and
            # parent-input behavior. They are not a relabelled stored scan.
            from .resolved_cube_read_contract import compile_resolved_cube_read
            from .postgres_resolved_cube_read import (
                compile_current_resolved_read, _execute_direct_in_transaction)
            own = compile_resolved_cube_read({
                "format": "openepm-resolved-cube-read-v1",
                "selection": plan["view"]["selection"],
                "source": {"semantics": "own"}, "outputGrain": dimensions,
                "freshness": "current", "dynamicFallback": False,
                "delivery": "direct", "limits": plan["limits"],
                "presentation": {"pageSize": plan["view"]["pageSize"],
                    "suppression": plan["view"]["suppression"]}},
                active_dimensions=dimensions)
            execution = compile_current_resolved_read(db, scope, plan=own,
                snapshot=snapshot, resolved_members=resolved["members"])
            raw = _execute_direct_in_transaction(db, scope, identity,
                plan=own, execution=execution, snapshot=snapshot,
                resolved=resolved, dimensions=dimensions, authorized=raw,
                raw_source_count=raw_source_count, binding=None)["rows"]
    if kind in {"calculated", "combined"}:
        calculation = PostgresCalculationScan(dsn, identity=identity,
            cursor_secret=cursor_secret).scan_in_transaction(db, scope,
                result_key=plan["view"]["dataSource"]["resultKey"],
                limit=maximum, member_sets=resolved["members"], include_zero=True,
                max_source_rows=plan["limits"]["maxSourceRows"] - raw_source_count,
                expected_access=access)
        if calculation["hasMore"]:
            raise ValueError("RESOURCE_LIMIT")
        if (not calculation["resultCurrentness"]["matchesAtRead"]
                or not calculation["inputRevisionStatus"]["matchesAtRead"]):
            raise ValueError("CALCULATION_REQUIRED")
    calculated = calculation["rows"] if calculation else []
    if raw_source_count + (calculation["sourceRows"] if calculation else 0) > plan["limits"]["maxSourceRows"]:
        raise ValueError("RESOURCE_LIMIT")
    rows = assemble_cube_view_rows(plan, raw_rows=raw,
        calculated_rows=calculated,
        result_token=calculation["resultStateToken"] if calculation else None)
    after = load_resolved_read_snapshot(db, scope)
    final_authority = resolve_effective_dimensional_scope(db, identity, scope,
                                                         function=FUNCTION)
    if final_authority.access != access:
        raise ValueError(CUBE_READ_AUTHORIZATION_STALE)
    if after != snapshot or final_authority.scope_digest != authority.scope_digest:
        raise ValueError("RESOLVED_READ_SNAPSHOT_CHANGED")
    if stored is not None and db.execute(current_view,view_params).fetchone()!=stored:
        raise ValueError('RESOLVED_READ_SNAPSHOT_CHANGED')
    result = {"format": FORMAT, **view_read_identity(plan),
        "snapshot": snapshot, "resolutionDigest": resolved["resolutionDigest"],
        "rows": rows, "complete": True,
        "presentation": {"pageSize": plan["view"]["pageSize"],
            "suppression": plan["view"]["suppression"], "rowCount": len(rows)}}
    if calculation:
        result["calculation"] = {"resultKey": calculation["resultKey"],
            "resultStateToken": calculation["resultStateToken"],
            "resultCurrentness": calculation["resultCurrentness"],
            "inputRevisionStatus": calculation["inputRevisionStatus"]}
    return result
