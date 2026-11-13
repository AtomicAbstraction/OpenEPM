"""Resolve the application calendar for one temporal expression definition."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Mapping, Sequence

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .temporal_expression_contract import TemporalExpressionPlan


@dataclass(frozen=True, slots=True)
class ResolvedTemporalCalendar:
    rows: tuple[dict[str, object], ...]
    metadata_revision: int
    policy_revision: int
    digest: str


def _identifier(value: object) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 200
        or value != value.strip()
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError("TEMPORAL_EXPRESSION_MEMBER_INVALID")
    return value


class PostgresTemporalExpressionResolver:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError("A verified identity is required")
        self.dsn = dsn
        self.identity = identity

    def resolve(
        self,
        scope: ApplicationScope,
        plan: TemporalExpressionPlan,
        *,
        periods_by_reset_group: Mapping[str, Sequence[str]],
    ) -> ResolvedTemporalCalendar:
        if not isinstance(scope, ApplicationScope):
            raise ValueError("TEMPORAL_EXPRESSION_SCOPE_INVALID")
        if not isinstance(plan, TemporalExpressionPlan):
            raise ValueError("TEMPORAL_EXPRESSION_PLAN_INVALID")
        if (
            not isinstance(periods_by_reset_group, Mapping)
            or not 1 <= len(periods_by_reset_group) <= 100
        ):
            raise ValueError("TEMPORAL_EXPRESSION_DOMAIN_INVALID")
        requested: list[dict[str, str]] = []
        for group, periods in periods_by_reset_group.items():
            year = _identifier(group)
            if (
                not isinstance(periods, Sequence)
                or isinstance(periods, (str, bytes))
                or not 1 <= len(periods) <= 366
                or len(set(periods)) != len(periods)
            ):
                raise ValueError("TEMPORAL_EXPRESSION_DOMAIN_INVALID")
            requested.extend(
                {"year_member_id": year, "period_member_id": _identifier(period)}
                for period in periods
            )
        if len(requested) > 500:
            raise ValueError("TEMPORAL_EXPRESSION_DOMAIN_BUDGET")
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
                roles = db.execute(
                    """SELECT model_role,dimension_id FROM epm.dimension
                    WHERE workspace_id=%s AND application_id=%s
                    AND model_role IN ('Year','Period') AND status='Active'
                    ORDER BY model_role,dimension_id""",
                    (scope.workspace_id, scope.application_id),
                ).fetchall()
                by_role: dict[str, list[str]] = {}
                for row in roles:
                    by_role.setdefault(row["model_role"], []).append(row["dimension_id"])
                if (
                    state is None
                    or set(by_role) != {"Year", "Period"}
                    or len(by_role["Year"]) != 1
                    or by_role["Period"] != [plan.normalized["periodDimensionId"]]
                    or plan.normalized["calendarVersion"] != state["metadata_revision"]
                ):
                    raise ValueError("TEMPORAL_EXPRESSION_CALENDAR_STALE")
                rows = db.execute(
                    """SELECT requested.year_member_id,
                    requested.period_member_id,c.ordinal,c.starts_on,
                    c.ends_before,c.change_id
                    FROM jsonb_to_recordset(%s::jsonb)
                      requested(year_member_id text,period_member_id text)
                    LEFT JOIN epm.calendar_period_current c
                      ON c.workspace_id=%s AND c.application_id=%s
                     AND c.year_member_id=requested.year_member_id
                     AND c.period_member_id=requested.period_member_id
                    ORDER BY requested.year_member_id COLLATE "C",
                             c.ordinal,requested.period_member_id COLLATE "C"
                    """,
                    (Jsonb(requested), scope.workspace_id, scope.application_id),
                ).fetchall()
        if len(rows) != len(requested) or any(row["change_id"] is None for row in rows):
            raise ValueError("TEMPORAL_EXPRESSION_CALENDAR_INCOMPLETE")
        normalized = tuple(
            {
                "resetGroupId": row["year_member_id"],
                "periodId": row["period_member_id"],
                "ordinal": row["ordinal"],
                "startsOn": row["starts_on"].isoformat(),
                "endsBefore": row["ends_before"].isoformat(),
                "changeId": row["change_id"],
            }
            for row in rows
        )
        for group in periods_by_reset_group:
            ordinals = [
                row["ordinal"] for row in normalized if row["resetGroupId"] == group
            ]
            if len(ordinals) != len(set(ordinals)):
                raise ValueError("TEMPORAL_EXPRESSION_CALENDAR_ORDER_INVALID")
        payload = {
            "definitionDigest": plan.digest,
            "metadataRevision": state["metadata_revision"],
            "policyRevision": state["policy_revision"],
            "rows": normalized,
        }
        digest = sha256(
            json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
        ).hexdigest()
        return ResolvedTemporalCalendar(
            normalized, state["metadata_revision"], state["policy_revision"], digest
        )
