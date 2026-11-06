"""Shared fixed-core enforcement for active dimensional-security policy."""
from __future__ import annotations

from collections.abc import Iterable

from .dimensional_security_policy import AccessKind, MixedSelection
from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import AccessDenied, PostgresAccessChecker, VerifiedIdentity
from .postgres_dimensional_security import PostgresDimensionalSecurityResolver


def authorize_coordinate(db, identity: VerifiedIdentity,
                         scope: ApplicationScope, coordinate: Coordinate, *,
                         kind: AccessKind) -> None:
    """Authorize one full coordinate using current server-owned policy state."""
    resolved = PostgresDimensionalSecurityResolver.resolve_active_in_transaction(
        db, identity, scope, kind=kind, coordinate=dict(coordinate.members))
    if resolved is not None and not resolved.decision.allowed:
        raise AccessDenied(resolved.decision.reason)


def authorize_coordinates(db, identity: VerifiedIdentity,
                          scope: ApplicationScope,
                          coordinates: Iterable[Coordinate], *,
                          kind: AccessKind) -> None:
    """Authorize a bounded collection of coordinates without caller policy input."""
    points=tuple(coordinates)
    if any(not isinstance(point,Coordinate) for point in points):
        raise ValueError("Trusted dimensional-security inputs are required")
    # The overwhelmingly common unrestricted case must remain a set-bounded
    # admission check.  Calling the exact-coordinate resolver for every point
    # would reload the same policy pointer, grants and layout N times and makes
    # the public 500-cell batch contract scale in SQL round trips.  Take the
    # same workspace fence used by policy activation, inspect the authoritative
    # pointer once, and only resolve individual coordinates when a policy is
    # actually active.
    PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
    active=db.execute('''SELECT active_dimensional_security_policy_version
        FROM epm.application_state WHERE workspace_id=%s
        AND application_id=%s''',
        (scope.workspace_id,scope.application_id)).fetchone()
    if active is None:
        raise ValueError("APPLICATION_UNAVAILABLE")
    if active['active_dimensional_security_policy_version'] is None:
        return
    for coordinate in points:
        authorize_coordinate(db, identity, scope, coordinate, kind=kind)


def coordinate_read_allowed(db, identity: VerifiedIdentity,
                            scope: ApplicationScope,
                            coordinate: Coordinate) -> bool:
    """Return the current exact-coordinate READ decision without broad-scan rules."""
    resolved = PostgresDimensionalSecurityResolver.resolve_active_in_transaction(
        db, identity, scope, kind=AccessKind.READ,
        coordinate=dict(coordinate.members))
    return resolved is None or resolved.decision.allowed


def filter_read_rows(db, identity: VerifiedIdentity,
                     scope: ApplicationScope,
                     rows: Iterable[dict]) -> list[dict]:
    """Filter one bounded raw cube page through the active read policy.

    A reject-all policy cannot be proved over an unbounded scan page-by-page,
    so broad reads fail closed whenever that policy is active.  Filtering
    profiles return only allowed full coordinates.  Callers must advance their
    continuation over the raw page, not over this filtered result.
    """
    permitted: list[dict] = []
    for row in rows:
        members = row.get("members")
        if type(members) is not dict:
            raise ValueError("DIMENSIONAL_SELECTION_COORDINATE_INVALID")
        resolved = PostgresDimensionalSecurityResolver.resolve_active_in_transaction(
            db, identity, scope, kind=AccessKind.READ, coordinate=members)
        if resolved is None:
            permitted.append(row)
            continue
        if resolved.mixed_selection is MixedSelection.REJECT_ALL:
            raise AccessDenied("DIMENSIONAL_SELECTION_REJECT_ALL_REQUIRES_EXPLICIT_COORDINATES")
        if resolved.decision.allowed:
            permitted.append(row)
    return permitted
