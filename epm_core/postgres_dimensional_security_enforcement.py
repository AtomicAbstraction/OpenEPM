"""Shared fixed-core enforcement for active dimensional-security policy."""
from __future__ import annotations

from collections.abc import Callable, Iterable

from .dimensional_security_policy import AccessKind, MixedSelection
from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import AccessDecision, AccessDenied, VerifiedIdentity
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
                          kind: AccessKind,
                          expected_access: AccessDecision | None = None) -> None:
    """Authorize a bounded collection of coordinates without caller policy input."""
    points=tuple(coordinates)
    if any(not isinstance(point,Coordinate) for point in points):
        raise ValueError("Trusted dimensional-security inputs are required")
    # The resolver deliberately caps one policy evaluation at 1,000 points.
    # Public source batches and set-oriented calculations are larger, so the
    # fixed core owns deterministic chunking.  Every chunk runs in the same
    # transaction; the first resolution takes the workspace fence and retains
    # it until the caller commits, preventing a policy change between chunks.
    coordinates=tuple(dict(point.members) for point in points)
    for offset in range(0,len(coordinates),1000):
        resolved=(PostgresDimensionalSecurityResolver.
            resolve_many_active_in_transaction(
                db,identity,scope,kind=kind,
                coordinates=coordinates[offset:offset+1000],
                expected_access=expected_access))
        if resolved is None:
            continue
        for item in resolved:
            if not item.decision.allowed:
                raise AccessDenied(item.decision.reason)


def coordinate_read_allowed(db, identity: VerifiedIdentity,
                            scope: ApplicationScope,
                            coordinate: Coordinate, *,
                            expected_access: AccessDecision | None = None) -> bool:
    """Return the current exact-coordinate READ decision without broad-scan rules."""
    resolved = PostgresDimensionalSecurityResolver.resolve_active_in_transaction(
        db, identity, scope, kind=AccessKind.READ,
        coordinate=dict(coordinate.members), expected_access=expected_access)
    return resolved is None or resolved.decision.allowed


def filter_read_rows(db, identity: VerifiedIdentity,
                     scope: ApplicationScope,
                     rows: Iterable[dict], *,
                     expected_access: AccessDecision | None = None,
                     allow_unbound: bool = False) -> list[dict]:
    """Filter one bounded raw cube page through the active read policy.

    A reject-all policy cannot be proved over an unbounded scan page-by-page,
    so broad reads fail closed whenever that policy is active.  Filtering
    profiles return only allowed full coordinates. Source evidence may also
    contain application records without a cube coordinate. Only that owner
    opts in to retaining those rows after checking application access.
    """
    source = tuple(rows)
    coordinates: list[dict[str, str]] = []
    for row in source:
        members = row.get("members")
        if type(members) is not dict:
            raise ValueError("DIMENSIONAL_SELECTION_COORDINATE_INVALID")
        if members or not allow_unbound:
            coordinates.append(members)
    resolved = PostgresDimensionalSecurityResolver.resolve_many_active_in_transaction(
        db, identity, scope, kind=AccessKind.READ,
        coordinates=tuple(coordinates), expected_access=expected_access)
    if resolved is None:
        return list(source)
    if len(resolved) != len(coordinates):
        raise ValueError("DIMENSIONAL_AUTHORIZATION_PAGE_INVALID")
    if any(item.mixed_selection is MixedSelection.REJECT_ALL
           for item in resolved):
        raise AccessDenied(
            "DIMENSIONAL_SELECTION_REJECT_ALL_REQUIRES_EXPLICIT_COORDINATES")
    decisions = iter(resolved)
    return [row for row in source
            if (allow_unbound and not row['members']) or next(decisions).decision.allowed]


def authorized_read_page(
        db, identity: VerifiedIdentity, scope: ApplicationScope, *,
        after: object, limit: int,
        fetch: Callable[[object, int], list[dict]],
        cursor_key: Callable[[dict], object],
        order_key: Callable[[object], object] = lambda value: value,
        candidate_limit: int = 10_000,
        expected_access: AccessDecision | None = None,
        allow_unbound: bool = False) -> tuple[list[dict], bool, object | None]:
    """Build a stable visible page without exposing denied-row positions."""
    if (type(limit) is not int or not 1 <= limit <= 500
            or type(candidate_limit) is not int
            or candidate_limit < limit + 1):
        raise ValueError("DIMENSIONAL_AUTHORIZATION_PAGE_INVALID")
    permitted: list[dict] = []
    scanned = 0
    raw_after = after
    exhausted = False
    while len(permitted) <= limit and not exhausted:
        fetch_limit = min(500, candidate_limit - scanned)
        # Read just the rest of the page and its lookahead while every
        # candidate has been visible. If filtering drops rows, scan larger
        # bounded batches to prove completeness without one query per row.
        if len(permitted) == scanned:
            fetch_limit = min(fetch_limit, limit + 1 - len(permitted))
        if fetch_limit <= 0:
            raise AccessDenied("DIMENSIONAL_AUTHORIZATION_COMPLETENESS_LIMIT")
        raw = fetch(raw_after, fetch_limit)
        if not isinstance(raw, list) or len(raw) > fetch_limit:
            raise ValueError("DIMENSIONAL_AUTHORIZATION_PAGE_INVALID")
        if not raw:
            exhausted = True
            break
        keys = [cursor_key(row) for row in raw]
        ordered = [order_key(key) for key in keys]
        prior = order_key(raw_after)
        if (any(key <= prior for key in ordered)
                or any(right <= left
                       for left, right in zip(ordered, ordered[1:]))):
            raise ValueError("DIMENSIONAL_AUTHORIZATION_PAGE_ORDER_INVALID")
        permitted.extend(filter_read_rows(db, identity, scope, raw,
            expected_access=expected_access, allow_unbound=allow_unbound))
        scanned += len(raw)
        raw_after = keys[-1]
        exhausted = len(raw) < fetch_limit
        if (scanned >= candidate_limit and len(permitted) <= limit
                and not exhausted):
            raise AccessDenied("DIMENSIONAL_AUTHORIZATION_COMPLETENESS_LIMIT")
    has_more = len(permitted) > limit
    page = permitted[:limit]
    next_after = cursor_key(page[-1]) if has_more and page else None
    return page, has_more, next_after
