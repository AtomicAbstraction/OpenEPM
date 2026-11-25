"""Group-assigned numeric import authorization at the existing source transaction."""

from hashlib import sha256

from .dimensional_security_policy import AccessKind
from .persistence_contract import Coordinate
from .postgres_access import AccessDenied, PostgresAccessChecker
from .postgres_dimensional_security_enforcement import authorize_coordinates
from .postgres_planning_duty_availability import group_workflow_role_unbound
from .postgres_planning_write_guard import WORKFLOW_ROLE_UNBOUND

UNSUPPORTED = "GROUP_SOURCE_NUMERIC_MERGE_REQUIRED"


def require_supported_policy(db, scope, identity, access):
    if access.authorization_model == "group_assignments" and group_workflow_role_unbound(db, scope, identity, access):
        raise ValueError(WORKFLOW_ROLE_UNBOUND)


def source_access(db, identity, scope, function, *, expected_groups=None):
    # The directory must stay current through the receipt or staged response.
    # Lock order matches assignment management and external revocations.
    PostgresAccessChecker.lock_directory_membership_for_assignment(db)
    return PostgresAccessChecker.check_in_transaction(
        db, identity, scope, "write", function=function, expected_groups=expected_groups
    )


def check_model(access, batch):
    if bool(batch["group_numeric_import"]) != (access.authorization_model == "group_assignments"):
        raise AccessDenied("SOURCE_BATCH_UNAVAILABLE")


def authorize_rows(db, identity, scope, access, rows):
    if any(row["value_kind"] != "numeric" for row in rows):
        raise ValueError(UNSUPPORTED)
    try:
        authorize_coordinates(
            db,
            identity,
            scope,
            (Coordinate.from_mapping(row["members"]) for row in rows),
            kind=AccessKind.WRITE,
            expected_access=access,
        )
    except (ValueError, AccessDenied) as exc:
        if isinstance(exc, AccessDenied) or str(exc) in {
            "DIMENSIONAL_COORDINATE_LAYOUT_MISMATCH",
            "DIMENSIONAL_COORDINATE_MEMBER_UNAVAILABLE",
            "MEMBER_SECURITY_TAG_CARDINALITY_VIOLATION",
        }:
            raise AccessDenied("SOURCE_IMPORT_TARGET_UNAVAILABLE") from None
        raise


def require_plannable_rows(db, identity, scope, access, rows):
    from .postgres_planning_write_guard import enforce_active_planning_policy
    # Imports can stage repeated rows while diagnostics are being prepared.
    # Evaluate each target once here; the import owner validates duplicates.
    points = tuple(dict.fromkeys(Coordinate.from_mapping(row['members']) for row in rows))
    for offset in range(0, len(points), 1000):
        enforce_active_planning_policy(db, scope, identity=identity, workflow_role=access.role,
            writes=tuple((point, 'Set') for point in points[offset:offset + 1000]))


def authorize_existing(db, identity, scope, access, batch, *, check_planning=False):
    check_model(access, batch)
    if not batch["group_numeric_import"]:
        return
    # A replay that can no longer prove its original targets cannot release
    # a receipt. The source owner retains at most 100,000 staged rows.
    seen = 0
    with db.cursor(name="group_numeric_import_targets") as cursor:
        cursor.execute(
            """SELECT members,value_kind FROM epm.source_batch_row
            WHERE workspace_id=%s AND application_id=%s AND batch_id=%s
            ORDER BY row_ordinal LIMIT 100001""",
            (scope.workspace_id, scope.application_id, batch["batch_id"]),
        )
        while chunk := cursor.fetchmany(1000):
            seen += len(chunk)
            if seen > 100000:
                raise ValueError("SOURCE_BATCH_ROW_LIMIT")
            authorize_rows(db, identity, scope, access, chunk)
            if check_planning:
                require_plannable_rows(db, identity, scope, access, chunk)
    if seen != batch["row_count"]:
        raise AccessDenied("SOURCE_IMPORT_TARGET_UNAVAILABLE")


def preview_digest(token):
    if not isinstance(token, str) or not token.isascii() or not 1 <= len(token) <= 4096:
        raise ValueError("SOURCE_PREVIEW_INVALID")
    return sha256(token.encode("ascii")).hexdigest()
