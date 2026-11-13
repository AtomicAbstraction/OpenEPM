"""Fixed PostgreSQL lowering for ordered temporal expression relations.

The caller supplies two private, transaction-local relations:

``epm_temporal_source(period_id, reset_group_id, ordinal, amount, present, emit)``
and, for predecessor deltas with an opening boundary,
``epm_temporal_opening(reset_group_id, amount, present)``.

This module never interpolates client identifiers or expressions into SQL.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from .temporal_expression_contract import TemporalExpressionPlan


COMPILER = "temporal-expression-postgres-v1"


@dataclass(frozen=True, slots=True)
class TemporalSqlPlan:
    sql: str
    compiler: str
    definition_digest: str
    preflight_sql: str | None = None

    @property
    def digest(self) -> str:
        return sha256(
            f"{self.compiler}\0{self.definition_digest}\0{self.sql}\0"
            f"{self.preflight_sql or ''}".encode("ascii")
        ).hexdigest()


_PREFIX_SUM = """WITH evaluated AS (
 SELECT period_id,reset_group_id,ordinal,emit,
   sum(amount) FILTER (WHERE present) OVER (
     PARTITION BY reset_group_id ORDER BY ordinal
     ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) AS amount,
   count(*) FILTER (WHERE present) OVER (
     PARTITION BY reset_group_id ORDER BY ordinal
     ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)>0 AS present,
   min(ordinal) OVER (PARTITION BY reset_group_id) AS dependency_start_ordinal
 FROM epm_temporal_source)
SELECT period_id,reset_group_id,ordinal,amount,present,dependency_start_ordinal
FROM evaluated
WHERE emit
ORDER BY reset_group_id COLLATE "C",ordinal,period_id COLLATE "C"
""";

_PERIOD_END = """SELECT period_id,reset_group_id,ordinal,
 CASE WHEN present THEN amount END AS amount,present,
 ordinal AS dependency_start_ordinal
FROM epm_temporal_source
WHERE emit
ORDER BY reset_group_id COLLATE "C",ordinal,period_id COLLATE "C"
""";

_PREDECESSOR_OPENING = """WITH ordered AS (
 SELECT s.*,
   row_number() OVER (PARTITION BY reset_group_id ORDER BY ordinal) AS position,
   lag(amount) OVER (PARTITION BY reset_group_id ORDER BY ordinal) AS prior_amount,
   lag(present) OVER (PARTITION BY reset_group_id ORDER BY ordinal) AS prior_present,
   lag(ordinal) OVER (PARTITION BY reset_group_id ORDER BY ordinal) AS prior_ordinal
 FROM epm_temporal_source s), evaluated AS (
 SELECT o.period_id,o.reset_group_id,o.ordinal,o.emit,
   CASE WHEN o.present AND CASE WHEN o.position=1 THEN p.present
                               ELSE o.prior_present END
     THEN o.amount-CASE WHEN o.position=1 THEN p.amount
                        ELSE o.prior_amount END END AS amount,
   o.present AND CASE WHEN o.position=1 THEN coalesce(p.present,false)
                      ELSE coalesce(o.prior_present,false) END AS present,
   CASE WHEN o.position=1 THEN o.ordinal ELSE o.prior_ordinal END
     AS dependency_start_ordinal
 FROM ordered o LEFT JOIN epm_temporal_opening p
   ON p.reset_group_id=o.reset_group_id)
SELECT period_id,reset_group_id,ordinal,amount,present,dependency_start_ordinal
FROM evaluated
WHERE emit AND present
ORDER BY reset_group_id COLLATE "C",ordinal,period_id COLLATE "C"
""";

_PREDECESSOR_ERROR = """WITH ordered AS (
 SELECT s.*,
   row_number() OVER (PARTITION BY reset_group_id ORDER BY ordinal) AS position,
   lag(amount) OVER (PARTITION BY reset_group_id ORDER BY ordinal) AS prior_amount,
   lag(present) OVER (PARTITION BY reset_group_id ORDER BY ordinal) AS prior_present,
   lag(ordinal) OVER (PARTITION BY reset_group_id ORDER BY ordinal) AS prior_ordinal
 FROM epm_temporal_source s)
SELECT period_id,reset_group_id,ordinal,
 CASE WHEN present AND prior_present THEN amount-prior_amount END AS amount,
 present AND coalesce(prior_present,false) AS present,
 prior_ordinal AS dependency_start_ordinal
FROM ordered
WHERE emit AND position>1 AND present AND prior_present
ORDER BY reset_group_id COLLATE "C",ordinal,period_id COLLATE "C"
""";

_PREDECESSOR_OPENING_PREFLIGHT = """WITH ordered AS (
 SELECT s.*,
   row_number() OVER (PARTITION BY reset_group_id ORDER BY ordinal) AS position,
   lag(present) OVER (PARTITION BY reset_group_id ORDER BY ordinal) AS prior_present
 FROM epm_temporal_source s)
SELECT coalesce(bool_or(o.emit AND (NOT o.present OR
  CASE WHEN o.position=1 THEN NOT coalesce(p.present,false)
       ELSE NOT coalesce(o.prior_present,false) END)),false) AS invalid
FROM ordered o LEFT JOIN epm_temporal_opening p
  ON p.reset_group_id=o.reset_group_id""";

_PREDECESSOR_ERROR_PREFLIGHT = """WITH ordered AS (
 SELECT s.*,
   row_number() OVER (PARTITION BY reset_group_id ORDER BY ordinal) AS position,
   lag(present) OVER (PARTITION BY reset_group_id ORDER BY ordinal) AS prior_present
 FROM epm_temporal_source s)
SELECT coalesce(bool_or(emit AND
  (NOT present OR position=1 OR NOT coalesce(prior_present,false))),false) AS invalid
FROM ordered""";


def compile_temporal_sql(plan: TemporalExpressionPlan) -> TemporalSqlPlan:
    operator = plan.normalized["operator"]
    if operator == "prefix_sum":
        sql = _PREFIX_SUM
        preflight = None
    elif operator == "period_end":
        sql = _PERIOD_END
        preflight = None
    elif plan.normalized["boundaryPolicy"] == "use_opening_value":
        sql = _PREDECESSOR_OPENING
        preflight = _PREDECESSOR_OPENING_PREFLIGHT
    else:
        sql = _PREDECESSOR_ERROR
        preflight = _PREDECESSOR_ERROR_PREFLIGHT
    return TemporalSqlPlan(sql, COMPILER, plan.digest, preflight)
