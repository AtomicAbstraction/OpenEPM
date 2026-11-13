"""Generic ordered temporal expressions with exact missing semantics."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from hashlib import sha256
import json
from typing import Mapping, Sequence


FORMAT = "openepm-temporal-expression-v1"
OPERATORS = frozenset({"prefix_sum", "predecessor_delta", "period_end"})


def _identifier(value: object, code: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 200
        or value != value.strip()
        or any(ord(character) < 32 for character in value)
    ):
        raise ValueError(code)
    return value


@dataclass(frozen=True, slots=True)
class TemporalExpressionPlan:
    normalized: dict[str, object]

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            self.normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
        return sha256(encoded).hexdigest()


def compile_temporal_expression(value: object) -> TemporalExpressionPlan:
    required = {
        "format",
        "operator",
        "periodDimensionId",
        "calendarId",
        "calendarVersion",
        "orderPolicy",
        "resetPolicy",
        "boundaryPolicy",
        "missingPolicy",
        "sourceUnit",
        "resultUnit",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("TEMPORAL_EXPRESSION_INVALID")
    if value["format"] != FORMAT:
        raise ValueError("TEMPORAL_EXPRESSION_FORMAT_UNSUPPORTED")
    operator = value["operator"]
    if operator not in OPERATORS:
        raise ValueError("TEMPORAL_EXPRESSION_OPERATOR_UNSUPPORTED")
    dimension = _identifier(
        value["periodDimensionId"], "TEMPORAL_EXPRESSION_PERIOD_INVALID"
    )
    calendar = _identifier(value["calendarId"], "TEMPORAL_EXPRESSION_CALENDAR_INVALID")
    if calendar != "application-calendar":
        raise ValueError("TEMPORAL_EXPRESSION_CALENDAR_UNSUPPORTED")
    version = value["calendarVersion"]
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ValueError("TEMPORAL_EXPRESSION_CALENDAR_INVALID")
    if value["orderPolicy"] != "calendar":
        raise ValueError("TEMPORAL_EXPRESSION_ORDER_UNSUPPORTED")
    if value["resetPolicy"] != "calendar_group":
        raise ValueError("TEMPORAL_EXPRESSION_RESET_UNSUPPORTED")
    boundary = value["boundaryPolicy"]
    allowed_boundary = (
        {"not_applicable"}
        if operator in {"prefix_sum", "period_end"}
        else {"error", "use_opening_value"}
    )
    if boundary not in allowed_boundary:
        raise ValueError("TEMPORAL_EXPRESSION_BOUNDARY_UNSUPPORTED")
    missing = value["missingPolicy"]
    allowed_missing = (
        {"exclude_absent"}
        if operator == "prefix_sum"
        else {"error"}
        if operator == "predecessor_delta"
        else {"preserve_absent"}
    )
    if missing not in allowed_missing:
        raise ValueError("TEMPORAL_EXPRESSION_MISSING_UNSUPPORTED")
    source_unit = _identifier(value["sourceUnit"], "TEMPORAL_EXPRESSION_UNIT_INVALID")
    result_unit = _identifier(value["resultUnit"], "TEMPORAL_EXPRESSION_UNIT_INVALID")
    if source_unit != result_unit:
        raise ValueError("TEMPORAL_EXPRESSION_UNIT_MISMATCH")
    return TemporalExpressionPlan(
        {
            "format": FORMAT,
            "operator": operator,
            "periodDimensionId": dimension,
            "calendarId": calendar,
            "calendarVersion": version,
            "orderPolicy": "calendar",
            "resetPolicy": "calendar_group",
            "boundaryPolicy": boundary,
            "missingPolicy": missing,
            "sourceUnit": source_unit,
            "resultUnit": result_unit,
        }
    )


def evaluate_temporal_expression(
    plan: TemporalExpressionPlan,
    *,
    ordered_periods: Sequence[str],
    reset_groups: Mapping[str, str],
    values: Mapping[str, Decimal | None],
    opening_values: Mapping[str, Decimal] | None = None,
) -> dict[str, Decimal | None]:
    """Independent exact oracle used by dynamic and materialized tests."""

    periods = list(ordered_periods)
    if (
        not periods
        or len(periods) != len(set(periods))
        or set(reset_groups) != set(periods)
        or any(not isinstance(group, str) or not group for group in reset_groups.values())
    ):
        raise ValueError("TEMPORAL_EXPRESSION_ORDER_INVALID")
    for period in periods:
        _identifier(period, "TEMPORAL_EXPRESSION_PERIOD_INVALID")
        value = values.get(period)
        if value is not None and not isinstance(value, Decimal):
            raise ValueError("TEMPORAL_EXPRESSION_VALUE_INVALID")
    operator = plan.normalized["operator"]
    result: dict[str, Decimal | None] = {}
    running: dict[str, Decimal] = {}
    running_present: set[str] = set()
    previous_period: dict[str, str] = {}
    for period in periods:
        group = reset_groups[period]
        value = values.get(period)
        if operator == "prefix_sum":
            if value is not None:
                running[group] = running.get(group, Decimal(0)) + value
                running_present.add(group)
            result[period] = running.get(group) if group in running_present else None
        elif operator == "period_end":
            result[period] = value
        else:
            predecessor = previous_period.get(group)
            if predecessor is None:
                if plan.normalized["boundaryPolicy"] == "error":
                    raise ValueError("TEMPORAL_EXPRESSION_PREDECESSOR_MISSING")
                opening = (opening_values or {}).get(group)
                if opening is None or value is None:
                    raise ValueError("TEMPORAL_EXPRESSION_PREDECESSOR_MISSING")
                result[period] = value - opening
            else:
                prior = values.get(predecessor)
                if prior is None or value is None:
                    raise ValueError("TEMPORAL_EXPRESSION_PREDECESSOR_MISSING")
                result[period] = value - prior
            previous_period[group] = period
        if operator != "predecessor_delta":
            previous_period[group] = period
    return result
