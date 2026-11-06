"""Immutable public plan-building types.

The SDK represents exact values and symbolic expressions only.  Evaluation,
authorization, dimensional resolution and publication stay in the fixed core.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal, InvalidOperation
from hashlib import sha256
import json
import re
from types import MappingProxyType
from typing import Any, Mapping


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_RESULT_KEY = re.compile(r"^[A-Za-z0-9._-]{8,128}$")
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_OPERATIONS = 10_000
MAX_PLAN_BYTES = 4 * 1024 * 1024
MAX_APPLICATION_RULE_OPERATIONS = 500
MAX_NUMERIC_SEQUENCE_STATEMENTS = 500
MAX_NUMERIC_ITERATIONS = 128
MAX_NUMERIC_ITERATION_EFFECTS = 8192


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"{label} must be a nonempty stable identifier")
    return value


def _result_key(value: object) -> str:
    if not isinstance(value, str) or not _RESULT_KEY.fullmatch(value):
        raise ValueError("result_key must be an 8-128 character stable result key")
    return value


def _exact(value: object, *, integer_digits: int, scale: int, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{label} must cross the boundary as a decimal string")
    try:
        number = Decimal(value)
    except (InvalidOperation, ValueError) as error:
        raise ValueError(f"{label} is not a decimal string") from error
    if not number.is_finite():
        raise ValueError(f"{label} must be finite")
    sign, digits, exponent = number.as_tuple()
    del sign
    if max(0, len(digits) + exponent) > integer_digits or -exponent > scale:
        raise ValueError(f"{label} exceeds its supported precision")
    # Avoid exponent notation on the wire and preserve meaningful authored scale.
    return format(number, "f")


@dataclass(frozen=True, slots=True)
class Amount:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _exact(
            self.value, integer_digits=20, scale=8, label="Amount"))

    def to_wire(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class Ratio:
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", _exact(
            self.value, integer_digits=8, scale=12, label="Ratio"))

    def to_wire(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class StatementValue:
    """Reference the present exact value produced by an earlier statement."""

    statement_index: int

    def __post_init__(self) -> None:
        if type(self.statement_index) is not int or self.statement_index < 0:
            raise ValueError("statement_index must be a nonnegative integer")

    def to_wire(self) -> dict[str, Any]:
        return {"type": "StatementValue", "statementIndex": self.statement_index}


@dataclass(frozen=True, slots=True)
class ApplicationRuleParameter:
    """One typed immutable runtime input declared by an application rule."""

    name: str
    value_type: str
    sample: object
    dimension_id: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.name, "parameter name")
        if self.value_type not in {
                "Amount", "Ratio", "Member", "MemberList", "String",
                "Boolean", "Date"}:
            raise ValueError("unsupported application-rule parameter type")
        if ((self.value_type in {"Member", "MemberList"}) !=
                (self.dimension_id is not None)):
            raise ValueError(
                "Member and MemberList parameters require only a dimension_id")
        if self.dimension_id is not None:
            _identifier(self.dimension_id, "dimension_id")
        if self.value_type == "Amount":
            _exact(self.sample, integer_digits=20, scale=8, label="Amount sample")
        elif self.value_type == "Ratio":
            _exact(self.sample, integer_digits=8, scale=12, label="Ratio sample")
        elif self.value_type == "Boolean":
            if type(self.sample) is not bool:
                raise ValueError("Boolean sample must be boolean")
        elif self.value_type == "MemberList":
            if (type(self.sample) not in (list, tuple) or not self.sample
                    or len(self.sample) > 100_000
                    or any(type(member) is not str or not member
                           or member != member.strip() or len(member) > 200
                           for member in self.sample)
                    or len(set(self.sample)) != len(self.sample)):
                raise ValueError(
                    "MemberList sample must contain unique stable member IDs")
            object.__setattr__(self, "sample", tuple(self.sample))
        elif (type(self.sample) is not str or not self.sample
              or self.sample != self.sample.strip() or "\x00" in self.sample):
            raise ValueError("parameter sample must be a nonempty string")
        elif self.value_type == "Date":
            try:
                if date.fromisoformat(self.sample).isoformat() != self.sample:
                    raise ValueError
            except ValueError as error:
                raise ValueError("Date sample must use ISO YYYY-MM-DD") from error

    def reference(self) -> ApplicationRuleParameterRef:
        return ApplicationRuleParameterRef(self.name, self.value_type,
                                           self.dimension_id)

    def to_wire(self) -> dict[str, Any]:
        return {"name": self.name, "type": self.value_type,
                "sample": (list(self.sample)
                           if self.value_type == "MemberList" else self.sample),
                **({"dimensionId": self.dimension_id}
                   if self.dimension_id is not None else {})}


@dataclass(frozen=True, slots=True)
class ApplicationRuleParameterRef:
    """Symbolic placeholder replaced by fixed core before plan sealing."""

    name: str
    value_type: str
    dimension_id: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.name, "parameter name")
        if self.value_type not in {
                "Amount", "Ratio", "Member", "MemberList", "String",
                "Boolean", "Date"}:
            raise ValueError("unsupported application-rule parameter type")
        if ((self.value_type in {"Member", "MemberList"}) !=
                (self.dimension_id is not None)):
            raise ValueError(
                "Member and MemberList parameter references require a dimension_id")
        if self.dimension_id is not None:
            _identifier(self.dimension_id, "dimension_id")

    def to_wire(self) -> dict[str, Any]:
        return {"type": "ApplicationRuleParameter", "name": self.name,
                "valueType": self.value_type,
                **({"dimensionId": self.dimension_id}
                   if self.dimension_id is not None else {})}


@dataclass(frozen=True, slots=True)
class NumericSequenceExpression:
    """Exact typed expression evaluated by the ordered relational primitive.

    This is authoring IR only. The fixed core validates types, references,
    presence, work bounds, rounding and overflow before a rule can be sealed.
    """

    node: Mapping[str, Any]

    @classmethod
    def amount(cls, value: Amount) -> NumericSequenceExpression:
        if not isinstance(value, Amount):
            raise TypeError("value must be Amount")
        return cls({"op": "AmountLiteral", "decimal": value.value})

    @classmethod
    def ratio(cls, value: Ratio) -> NumericSequenceExpression:
        if not isinstance(value, Ratio):
            raise TypeError("value must be Ratio")
        return cls({"op": "RatioLiteral", "decimal": value.value})

    @classmethod
    def parameter(cls, value: ApplicationRuleParameterRef
                  ) -> NumericSequenceExpression:
        if (not isinstance(value,ApplicationRuleParameterRef)
                or value.value_type not in ("Amount","Ratio")):
            raise TypeError("expression parameter must be Amount or Ratio")
        return cls({"op":f"{value.value_type}Literal",
                    "decimal":value.to_wire()})

    @classmethod
    def current_amount(cls) -> NumericSequenceExpression:
        return cls({"op": "CurrentAmount"})

    @classmethod
    def current_present(cls) -> NumericSequenceExpression:
        return cls({"op": "CurrentPresent"})

    @classmethod
    def statement_amount(cls, index: int) -> NumericSequenceExpression:
        return cls({"op": "StatementAmount", "statementIndex": index})

    @classmethod
    def statement_present(cls, index: int) -> NumericSequenceExpression:
        return cls({"op": "StatementPresent", "statementIndex": index})

    def __post_init__(self) -> None:
        node = _canonical_copy(self.node, label="numeric sequence expression")
        if not isinstance(node, dict) or not isinstance(node.get("op"), str):
            raise ValueError("numeric sequence expression requires a typed node")
        object.__setattr__(self, "node", _freeze(node))

    def __bool__(self) -> bool:
        raise TypeError("NumericSequenceExpression is symbolic")

    @staticmethod
    def _node(value: NumericSequenceExpression | Amount | Ratio) -> Mapping[str, Any]:
        if isinstance(value, NumericSequenceExpression):
            return value.node
        if isinstance(value, Amount):
            return {"op": "AmountLiteral", "decimal": value.value}
        if isinstance(value, Ratio):
            return {"op": "RatioLiteral", "decimal": value.value}
        raise TypeError("operand must be NumericSequenceExpression, Amount or Ratio")

    def _binary(self, operator: str,
                other: NumericSequenceExpression | Amount | Ratio
                ) -> NumericSequenceExpression:
        return NumericSequenceExpression({"op": operator, "left": self.node,
            "right": self._node(other)})

    def __add__(self, other: NumericSequenceExpression | Amount | Ratio
                ) -> NumericSequenceExpression:
        return self._binary("Add", other)

    def __sub__(self, other: NumericSequenceExpression | Amount | Ratio
                ) -> NumericSequenceExpression:
        return self._binary("Subtract", other)

    def __mul__(self, other: NumericSequenceExpression | Amount | Ratio
                ) -> NumericSequenceExpression:
        return self._binary("Multiply", other)

    def __truediv__(self, other: NumericSequenceExpression | Amount | Ratio
                    ) -> NumericSequenceExpression:
        return self._binary("Divide", other)

    def compare(self, operator: str,
                other: NumericSequenceExpression | Amount | Ratio
                ) -> NumericSequenceExpression:
        normalized = {"eq": "eq", "ne": "ne", "lt": "lt", "lte": "le",
                      "gt": "gt", "gte": "ge"}.get(operator)
        if normalized is None:
            raise ValueError("unsupported comparison operator")
        return NumericSequenceExpression({"op": "Compare",
            "operator": normalized, "left": self.node,
            "right": self._node(other)})

    def if_else(self, when_true: NumericSequenceExpression | Amount | Ratio,
                when_false: NumericSequenceExpression | Amount | Ratio
                ) -> NumericSequenceExpression:
        return NumericSequenceExpression({"op": "If", "test": self.node,
            "then": self._node(when_true), "else": self._node(when_false)})

    def to_wire(self) -> dict[str, Any]:
        return _thaw(self.node)


@dataclass(frozen=True, slots=True)
class NumericSequence:
    """Immutable exact Set/Add/Clear statement sequence for one atomic unit."""

    statements: tuple[Mapping[str, Any], ...] = ()

    def __post_init__(self) -> None:
        if (not isinstance(self.statements, tuple)
                or len(self.statements) > MAX_NUMERIC_SEQUENCE_STATEMENTS):
            raise ValueError("numeric sequence supports at most 500 statements")
        normalized = tuple(_freeze(_canonical_copy(item,
            label="numeric sequence statement")) for item in self.statements)
        object.__setattr__(self, "statements", normalized)

    @staticmethod
    def _series_key(coordinate: Mapping[str, str]) -> str:
        return json.dumps(coordinate, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True)

    @staticmethod
    def _references(node: object):
        if isinstance(node, Mapping):
            if node.get("op") in ("StatementAmount", "StatementPresent"):
                yield node.get("statementIndex")
            for child in node.values():
                yield from NumericSequence._references(child)
        elif isinstance(node, (list, tuple)):
            for child in node:
                yield from NumericSequence._references(child)

    def _append(self, coordinate: Mapping[str, str], operation: str,
                value: Amount | StatementValue | NumericSequenceExpression |
                       ApplicationRuleParameterRef | None,
                *, expected_change_id: str | None) -> NumericSequence:
        if len(self.statements) >= MAX_NUMERIC_SEQUENCE_STATEMENTS:
            raise ValueError("numeric sequence supports at most 500 statements")
        raw_members = _canonical_copy({axis:(member.to_wire()
            if isinstance(member,ApplicationRuleParameterRef) else member)
            for axis,member in coordinate.items()}, label="coordinate")
        if (not isinstance(raw_members, dict) or not 1 <= len(raw_members) <= 128
                or any(not isinstance(axis, str) or not 1 <= len(axis) <= 200
                       for axis in raw_members)):
            raise ValueError("coordinate must contain bounded dimension/member IDs")
        members = {}
        for axis, member in sorted(raw_members.items()):
            if isinstance(member, dict) and member.get("type") == "ApplicationRuleParameter":
                members[axis] = member
            elif isinstance(member, str) and 1 <= len(member) <= 200:
                members[axis] = member
            else:
                raise ValueError("coordinate members must be stable IDs or parameters")
        touched = {self._series_key(_thaw(item["coordinate"]))
                   for item in self.statements}
        first = self._series_key(members) not in touched
        if (first and (type(expected_change_id) is not str
                       or len(expected_change_id) > 200)
                or not first and expected_change_id is not None):
            raise ValueError("expected_change_id is required only on first coordinate touch")
        statement: dict[str, Any] = {"coordinate": members, "op": operation}
        if first:
            statement["expectedChangeId"] = expected_change_id
        if operation != "clear":
            if isinstance(value, Amount):
                wire = {"type": "AmountLiteral", "decimal": value.value}
            elif isinstance(value, StatementValue):
                if value.statement_index >= len(self.statements):
                    raise ValueError("statement reference must identify an earlier statement")
                wire = value.to_wire()
            elif isinstance(value, NumericSequenceExpression):
                references = tuple(self._references(value.node))
                if any(type(index) is not int or index < 0
                       or index >= len(self.statements) for index in references):
                    raise ValueError("expression references must identify earlier statements")
                wire = {"type": "NumericExpression",
                        "expression": value.to_wire()}
            elif (isinstance(value, ApplicationRuleParameterRef)
                  and value.value_type == "Amount"):
                wire = {"type": "AmountLiteral", "decimal": value.to_wire()}
            else:
                raise TypeError("numeric sequence value is invalid")
            statement["value"] = wire
        elif value is not None:
            raise ValueError("clear does not accept a value")
        return NumericSequence(self.statements + (statement,))

    def set(self, coordinate: Mapping[str, str],
            value: Amount | StatementValue | NumericSequenceExpression |
                   ApplicationRuleParameterRef, *,
            expected_change_id: str | None = None) -> NumericSequence:
        return self._append(coordinate, "set", value,
                            expected_change_id=expected_change_id)

    def add(self, coordinate: Mapping[str, str],
            value: Amount | StatementValue | NumericSequenceExpression |
                   ApplicationRuleParameterRef, *,
            expected_change_id: str | None = None) -> NumericSequence:
        return self._append(coordinate, "add", value,
                            expected_change_id=expected_change_id)

    def clear(self, coordinate: Mapping[str, str], *,
              expected_change_id: str | None = None) -> NumericSequence:
        return self._append(coordinate, "clear", None,
                            expected_change_id=expected_change_id)

    def to_arguments(self) -> dict[str, Any]:
        if not self.statements:
            raise ValueError("numeric sequence requires at least one statement")
        statements = [_thaw(item) for item in self.statements]
        result: dict[str, Any] = {"statements": statements}
        if any(item.get("value", {}).get("type") == "NumericExpression"
               for item in statements):
            result["rounding"] = "half_even_8"
        return result


@dataclass(frozen=True, slots=True)
class NumericIteration:
    """Bounded fixed-point execution of one exact numeric sequence.

    This object only constructs the public application-language request.  The
    fixed core remains responsible for expression validation, work budgets,
    authorization, convergence evaluation, fencing and atomic publication.
    """

    sequence: NumericSequence
    tolerance: Amount | ApplicationRuleParameterRef
    max_iterations: int

    def __post_init__(self) -> None:
        if not isinstance(self.sequence, NumericSequence):
            raise TypeError("sequence must be NumericSequence")
        if not self.sequence.statements:
            raise ValueError("numeric iteration requires at least one statement")
        if (not isinstance(self.tolerance, Amount)
                and not (isinstance(self.tolerance,
                                    ApplicationRuleParameterRef)
                         and self.tolerance.value_type == "Amount")):
            raise TypeError("tolerance must be Amount or an Amount parameter")
        if (isinstance(self.tolerance, Amount)
                and Decimal(self.tolerance.value) < 0):
            raise ValueError("tolerance must be nonnegative")
        if (type(self.max_iterations) is not int
                or not 1 <= self.max_iterations <= MAX_NUMERIC_ITERATIONS):
            raise ValueError("max_iterations must be between 1 and 128")
        if (len(self.sequence.statements) * self.max_iterations
                > MAX_NUMERIC_ITERATION_EFFECTS):
            raise ValueError("numeric iteration exceeds the 8192-effect limit")

    def to_arguments(self) -> dict[str, Any]:
        arguments = self.sequence.to_arguments()
        # The iterative compiler requires its rounding contract explicitly,
        # including sequences containing literals only.
        arguments["rounding"] = "half_even_8"
        decimal = (self.tolerance.value
                   if isinstance(self.tolerance, Amount)
                   else self.tolerance.to_wire())
        arguments["convergence"] = {
            "mode": "absolute_delta",
            "tolerance": {"type": "AmountLiteral", "decimal": decimal},
            "maxIterations": self.max_iterations,
            "onNonConvergence": "fail",
        }
        return arguments


@dataclass(frozen=True, slots=True)
class OwnershipValueDependency:
    source_id: str
    relationship_id: str
    scenario_id: str
    year_id: str
    period_id: str
    account: str
    expected_present: bool
    expected_amount: Amount | None
    expected_change_id: str

    def __post_init__(self) -> None:
        for value, label in ((self.source_id, "source_id"),
                             (self.relationship_id, "relationship_id"),
                             (self.scenario_id, "scenario_id"),
                             (self.year_id, "year_id"),
                             (self.period_id, "period_id")):
            _identifier(value, label)
        if (self.account not in {'POWN', 'PCON', 'PCTRL', 'DOWN', 'Active',
                                 'Method', 'Consol1', 'Consol2', 'Consol3'}
                or type(self.expected_present) is not bool
                or self.expected_present != isinstance(self.expected_amount, Amount)
                or not isinstance(self.expected_change_id, str)
                or _HEX32.fullmatch(self.expected_change_id) is None):
            raise ValueError("ownership dependency is invalid")

    def to_wire(self) -> dict[str, Any]:
        return {"kind": "OwnershipValue", "sourceId": self.source_id,
            "relationshipId": self.relationship_id,
            "scenarioId": self.scenario_id, "yearId": self.year_id,
            "periodId": self.period_id, "account": self.account,
            "expectedPresent": self.expected_present,
            "expectedAmount": (self.expected_amount.value
                               if self.expected_amount else None),
            "expectedChangeId": self.expected_change_id}


@dataclass(frozen=True, slots=True)
class CalendarPeriodDependency:
    source_id: str
    year_id: str
    period_id: str
    effective_on: str
    expected_change_id: str

    def __post_init__(self) -> None:
        for value, label in ((self.source_id, "source_id"),
                             (self.year_id, "year_id"),
                             (self.period_id, "period_id")):
            _identifier(value, label)
        try:
            parsed = date.fromisoformat(self.effective_on)
        except (TypeError, ValueError) as error:
            raise ValueError("effective_on must be an ISO date") from error
        if (parsed.isoformat() != self.effective_on
                or not isinstance(self.expected_change_id, str)
                or _HEX32.fullmatch(self.expected_change_id) is None):
            raise ValueError("calendar dependency is invalid")

    def to_wire(self) -> dict[str, Any]:
        return {"kind": "CalendarPeriod", "sourceId": self.source_id,
            "yearId": self.year_id, "periodId": self.period_id,
            "effectiveOn": self.effective_on,
            "expectedChangeId": self.expected_change_id}


@dataclass(frozen=True, slots=True)
class ContextAssertion:
    assertion_id: str
    name: str
    value: bool

    def __post_init__(self) -> None:
        _identifier(self.assertion_id, "assertion_id")
        _identifier(self.name, "name")
        if type(self.value) is not bool:
            raise ValueError("assertion value must be boolean")

    def to_wire(self) -> dict[str, Any]:
        return {"assertionId": self.assertion_id, "name": self.name,
                "value": self.value,
                "assurance": "CallerDeclaredUnverified"}


@dataclass(frozen=True, slots=True)
class Application:
    workspace_id: str
    application_id: str

    def __post_init__(self) -> None:
        _identifier(self.workspace_id, "workspace_id")
        _identifier(self.application_id, "application_id")

    def to_wire(self) -> dict[str, str]:
        return {"workspace_id": self.workspace_id, "application_id": self.application_id}


@dataclass(frozen=True, slots=True)
class PythonBuildArtifactSection:
    """One fully verified immutable section of a sealed Python build."""

    build_id: str
    section: str
    plan_digest: str
    source_digest: str
    section_digest: str
    compiler_version: str
    unit_count: int
    total_bytes: int
    content: Mapping[str, Any] | str

    def __post_init__(self) -> None:
        if (type(self.build_id) is not str
                or _HEX32.fullmatch(self.build_id) is None
                or self.section not in {'Plan', 'SourceMap', 'BuildLog'}
                or any(type(value) is not str or _HEX64.fullmatch(value) is None
                       for value in (self.plan_digest, self.source_digest,
                                     self.section_digest))
                or type(self.compiler_version) is not str
                or _ID.fullmatch(self.compiler_version) is None
                or type(self.unit_count) is not int
                or not 1 <= self.unit_count <= MAX_OPERATIONS
                or type(self.total_bytes) is not int or self.total_bytes < 0):
            raise ValueError('Python build artifact metadata is invalid')
        if self.section == 'BuildLog':
            if type(self.content) is not str or '\x00' in self.content:
                raise ValueError('Python build artifact content is invalid')
        elif not isinstance(self.content, Mapping):
            raise ValueError('Python build artifact content is invalid')
        else:
            object.__setattr__(self, 'content', _freeze(_canonical_copy(
                self.content, label='Python build artifact content')))


@dataclass(frozen=True, slots=True)
class MemberSet:
    dimension_id: str
    selector: Mapping[str, Any]

    @classmethod
    def members(cls, dimension_id: str, *member_ids: str) -> MemberSet:
        if not member_ids or len(member_ids) > 10_000:
            raise ValueError("MemberSet requires 1-10000 members")
        checked = tuple(_identifier(value, "member_id") for value in member_ids)
        if len(set(checked)) != len(checked):
            raise ValueError("MemberSet member IDs must be unique")
        return cls(dimension_id, {"kind": "Members", "memberIds": sorted(checked)})

    @classmethod
    def descendants(cls, dimension_id: str, root_member_id: str, *,
                    hierarchy_version: int | str = "active",
                    include_self: bool = False) -> MemberSet:
        return cls._hierarchy("Descendants", dimension_id, root_member_id,
                              hierarchy_version=hierarchy_version,
                              include_self=include_self)

    @classmethod
    def children(cls, dimension_id: str, root_member_id: str, *,
                 hierarchy_version: int | str = "active") -> MemberSet:
        return cls._hierarchy("Children", dimension_id, root_member_id,
                              hierarchy_version=hierarchy_version)

    @classmethod
    def leaves(cls, dimension_id: str, root_member_id: str, *,
               hierarchy_version: int | str = "active") -> MemberSet:
        return cls._hierarchy("Leaves", dimension_id, root_member_id,
                              hierarchy_version=hierarchy_version)

    @classmethod
    def _hierarchy(cls, kind: str, dimension_id: str, root_member_id: str, *,
                   hierarchy_version: int | str,
                   include_self: bool = False) -> MemberSet:
        _identifier(root_member_id, "root_member_id")
        if not (hierarchy_version == "active" or
                type(hierarchy_version) is int and 0 < hierarchy_version < 2**63):
            raise ValueError("hierarchy_version must be active or a positive integer")
        if not isinstance(include_self, bool):
            raise ValueError("include_self must be boolean")
        return cls(dimension_id, {"kind": kind, "rootMemberId": root_member_id,
            "hierarchyVersion": hierarchy_version, "includeSelf": include_self})

    def __post_init__(self) -> None:
        _identifier(self.dimension_id, "dimension_id")
        frozen = _canonical_copy(self.selector, label="selector")
        if not isinstance(frozen, dict) or frozen.get("kind") not in (
                "Members", "Children", "Descendants", "Leaves"):
            raise ValueError("MemberSet selector is invalid")
        object.__setattr__(self, "selector", _freeze(frozen))

    def to_wire(self) -> dict[str, Any]:
        return _thaw(self.selector)


def _literal(value: object) -> dict[str, str]:
    if isinstance(value, Amount):
        return {"op": "AmountLiteral", "decimal": value.value}
    if isinstance(value, Ratio):
        return {"op": "RatioLiteral", "decimal": value.value}
    raise TypeError("Expression operands must be CubeExpression, Amount or Ratio")


def _member_mapping(value: Mapping[str, str], *, label: str,
                    allow_empty: bool = False) -> dict[str, str]:
    normalized = _canonical_copy(value, label=label)
    if (not isinstance(normalized, dict)
            or not (0 if allow_empty else 1) <= len(normalized) <= 128
            or any(not isinstance(axis, str) or not 1 <= len(axis) <= 200
                   or not isinstance(member, str) or not 1 <= len(member) <= 200
                   for axis, member in normalized.items())):
        raise ValueError(f"{label} must contain bounded dimension/member IDs")
    return dict(sorted(normalized.items()))


def _explicit_member_set(value: MemberSet, *, label: str) -> tuple[str, list[str]]:
    if not isinstance(value, MemberSet) or value.selector.get("kind") != "Members":
        raise ValueError(f"{label} requires an explicit MemberSet.members selector")
    members = list(value.selector["memberIds"])
    if not 1 <= len(members) <= 100:
        raise ValueError(f"{label} supports 1-100 explicit members")
    return value.dimension_id, members


@dataclass(frozen=True, slots=True)
class CubeExpression:
    node: Mapping[str, Any]

    @classmethod
    def source_amount(cls) -> CubeExpression:
        return cls({"op": "SourceAmount"})

    @classmethod
    def source_value(cls, member_overrides: Mapping[str, str], *,
                     value_type: str = "amount",
                     measure_dimension_id: str | None = None) -> CubeExpression:
        if value_type not in ("amount", "ratio"):
            raise ValueError("value_type must be amount or ratio")
        overrides = _member_mapping(member_overrides,
                                    label="member_overrides")
        node: dict[str, Any] = {"op": "SourceValue",
            "memberOverrides": overrides, "valueType": value_type}
        if measure_dimension_id is not None:
            if (not isinstance(measure_dimension_id, str)
                    or measure_dimension_id not in overrides):
                raise ValueError(
                    "measure_dimension_id must identify an overridden dimension")
            node["measureDimensionId"] = measure_dimension_id
        return cls(node)

    @classmethod
    def source_text_predicate(cls, member_overrides: Mapping[str, str], *,
                              operator: str, text: str) -> CubeExpression:
        if operator not in ("eq", "ne"):
            raise ValueError("text operator must be eq or ne")
        if not isinstance(text, str) or len(text) > 32_768:
            raise ValueError("text must be a string of at most 32768 characters")
        return cls({"op": "SourceTextPredicate",
            "memberOverrides": _member_mapping(
                member_overrides, label="member_overrides"),
            "operator": operator, "text": text, "missingPolicy": "error"})

    @classmethod
    def published_amount(cls, result_key: str,
                         member_overrides: Mapping[str, str] | None = None
                         ) -> CubeExpression:
        node: dict[str, Any] = {"op": "PublishedAmount",
                                "resultKey": _result_key(result_key)}
        if member_overrides is not None:
            node["memberOverrides"] = _member_mapping(
                member_overrides, label="member_overrides")
        return cls(node)

    @classmethod
    def published_ratio(cls, result_key: str,
                        member_overrides: Mapping[str, str] | None = None
                        ) -> CubeExpression:
        node: dict[str, Any] = {"op": "PublishedRatio",
                                "resultKey": _result_key(result_key)}
        if member_overrides is not None:
            node["memberOverrides"] = _member_mapping(
                member_overrides, label="member_overrides")
        return cls(node)

    @classmethod
    def published_unit_amount(cls, result_key: str, *,
                              output_unit_currency_member_id: str,
                              member_overrides: Mapping[str, str] | None = None
                              ) -> CubeExpression:
        if (not isinstance(output_unit_currency_member_id, str)
                or not 1 <= len(output_unit_currency_member_id) <= 200):
            raise ValueError("output unit must be a stable Currency member ID")
        return cls({"op": "PublishedUnitAmount",
            "resultKey": _result_key(result_key),
            "memberOverrides": _member_mapping(member_overrides or {},
                label="member_overrides", allow_empty=True),
            "outputUnitCurrencyMemberId": output_unit_currency_member_id})

    def __post_init__(self) -> None:
        node = _canonical_copy(self.node, label="expression")
        if not isinstance(node, dict) or not isinstance(node.get("op"), str):
            raise ValueError("CubeExpression requires a typed node")
        object.__setattr__(self, "node", _freeze(node))

    def __bool__(self) -> bool:
        raise TypeError("CubeExpression is symbolic; use typed expression conditions")

    def _binary(self, operator: str, other: object) -> CubeExpression:
        right = other.node if isinstance(other, CubeExpression) else _literal(other)
        return CubeExpression({"op": operator, "left": self.node, "right": right})

    def __add__(self, other: object) -> CubeExpression:
        return self._binary("Add", other)

    def __sub__(self, other: object) -> CubeExpression:
        return self._binary("Subtract", other)

    def __mul__(self, other: object) -> CubeExpression:
        return self._binary("Multiply", other)

    def __truediv__(self, other: object) -> CubeExpression:
        return self._binary("Divide", other)

    def compare(self, operator: str, other: object) -> CubeExpression:
        if operator not in ("eq", "ne", "lt", "lte", "gt", "gte"):
            raise ValueError("Unsupported comparison operator")
        core_operator = {"lte": "le", "gte": "ge"}.get(operator, operator)
        return self._binary("Compare", other)._with(operator=core_operator)

    def if_else(self, when_true: CubeExpression | Amount | Ratio,
                when_false: CubeExpression | Amount | Ratio) -> CubeExpression:
        def node(value: CubeExpression | Amount | Ratio) -> Mapping[str, Any]:
            return value.node if isinstance(value, CubeExpression) else _literal(value)
        return CubeExpression({"op": "If", "test": self.node,
            "then": node(when_true), "else": node(when_false)})

    def _with(self, **values: Any) -> CubeExpression:
        return CubeExpression({**self.node, **values})

    def to_wire(self) -> dict[str, Any]:
        return _thaw(self.node)


def _canonical_copy(value: object, *, label: str) -> Any:
    def reject(candidate: object) -> None:
        if isinstance(candidate, float):
            raise ValueError(f"{label} cannot contain binary floating-point values")
        if isinstance(candidate, Mapping):
            if any(not isinstance(key, str) for key in candidate):
                raise ValueError(f"{label} object keys must be strings")
            for item in candidate.values(): reject(item)
        elif isinstance(candidate, (list, tuple)):
            for item in candidate: reject(item)
        elif candidate is not None and not isinstance(candidate, (str, int, bool)):
            raise ValueError(f"{label} contains a non-JSON value")
    reject(value)
    try:
        return json.loads(json.dumps(_thaw(value), ensure_ascii=True, sort_keys=True,
                                     separators=(",", ":"), allow_nan=False))
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} must be canonical JSON") from error


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class AtomicUnit:
    operations: tuple[Mapping[str, Any], ...]
    name: str = "unit"

    def __post_init__(self) -> None:
        _identifier(self.name, "unit name")
        if not isinstance(self.operations, tuple) or not self.operations:
            raise ValueError("AtomicUnit requires at least one operation")
        normalized = []
        for operation in self.operations:
            item = _canonical_copy(operation, label="operation")
            if (not isinstance(item, dict) or item.get("languageVersion") != 2 or
                    not isinstance(item.get("function"), str) or
                    not isinstance(item.get("arguments"), dict)):
                raise ValueError("Each operation must be a V2 structured program")
            normalized.append(_freeze(item))
        object.__setattr__(self, "operations", tuple(normalized))


@dataclass(frozen=True, slots=True)
class Program:
    units: tuple[AtomicUnit, ...] = field(default_factory=tuple)

    @classmethod
    def one(cls, function: str, arguments: Mapping[str, Any], *,
            name: str = "unit") -> Program:
        return cls((AtomicUnit(({"languageVersion": 2,
            "function": _identifier(function, "function"),
            "arguments": _canonical_copy(arguments, label="arguments")},), name),))

    @classmethod
    def expression_calculation(cls, source_members: Mapping[str, str],
                               expression: CubeExpression, result_key: str, *,
                               target_members: Mapping[str, str] | None = None,
                               target_member_sets: tuple[MemberSet, ...] | None = None,
                               result_unit: str | None = None,
                               amount_unit: tuple[str, str] | None = None,
                               required_source_count: int | None = None,
                               context_dependencies: tuple[
                                   OwnershipValueDependency |
                                   CalendarPeriodDependency, ...] | None = None,
                               context_assertions: tuple[ContextAssertion, ...] | None = None,
                               name: str = "unit") -> Program:
        """Build one executable fixed-core expression operation.

        This is a plan constructor only.  The server still validates the full
        dimensional grain, types, authorization, revisions and publication
        fences before the operation can have any business effect.
        """
        if not isinstance(expression, CubeExpression):
            raise TypeError("expression must be CubeExpression")
        members = _canonical_copy(source_members, label="source_members")
        if (not isinstance(members, dict) or len(members) > 32
                or any(not isinstance(axis, str) or not isinstance(member, str)
                       or not 1 <= len(axis) <= 200 or not 1 <= len(member) <= 200
                       for axis, member in members.items())):
            raise ValueError("source_members must contain stable dimension/member IDs")
        arguments: dict[str, Any] = {
            "sourceMembers": members,
            "expression": expression.to_wire(),
            "resultKey": _result_key(result_key),
        }
        if target_members is not None:
            targets = _member_mapping(target_members, label="target_members")
            if (len(targets) > 4 or any(axis not in members
                    or members[axis] == member
                    for axis, member in targets.items())):
                raise ValueError(
                    "target_members must change 1-4 source dimensions")
            arguments["targetMembers"] = targets
        if target_member_sets is not None:
            if target_members is not None or not isinstance(target_member_sets, tuple):
                raise ValueError(
                    "target_member_sets must be a tuple used without target_members")
            normalized_sets = []
            for item in target_member_sets:
                axis, member_ids = _explicit_member_set(
                    item, label="target_member_sets")
                if axis not in members or members[axis] in member_ids:
                    raise ValueError(
                        "target member sets must replace fixed source dimensions")
                normalized_sets.append({"dimensionId": axis,
                                        "memberIds": member_ids})
            if (not 1 <= len(normalized_sets) <= 4
                    or len({item["dimensionId"] for item in normalized_sets})
                       != len(normalized_sets)):
                raise ValueError("target_member_sets requires 1-4 distinct dimensions")
            product = 1
            for item in normalized_sets:
                product *= len(item["memberIds"])
            if product > 500:
                raise ValueError("target_member_sets exceeds 500 output coordinates")
            if len(normalized_sets) == 1:
                arguments["targetMemberSet"] = normalized_sets[0]
            else:
                arguments["targetMemberSets"] = normalized_sets
        if result_unit is not None:
            if result_unit != "ratio":
                raise ValueError("result_unit must be ratio when specified")
            arguments["resultUnit"] = {"type": "Ratio", "scale": 12}
        if amount_unit is not None:
            if (not isinstance(amount_unit, tuple) or len(amount_unit) != 2
                    or any(not isinstance(value, str) or not 1 <= len(value) <= 200
                           for value in amount_unit)):
                raise ValueError("amount_unit requires dimension and member IDs")
            arguments["amountUnit"] = {"dimensionId": amount_unit[0],
                "memberId": amount_unit[1],
                "binding": "EntityDefaultCurrency"}
        if required_source_count is not None:
            if (type(required_source_count) is not int
                    or not 1 <= required_source_count <= 500):
                raise ValueError("required_source_count must be 1-500")
            arguments["requiredSourceCount"] = required_source_count
        if (context_dependencies is None) != (context_assertions is None):
            raise ValueError("context dependencies and assertions are paired")
        if context_dependencies is not None:
            if (not isinstance(context_dependencies, tuple)
                    or not 1 <= len(context_dependencies) <= 8
                    or not isinstance(context_assertions, tuple)
                    or not 1 <= len(context_assertions) <= 8
                    or any(not isinstance(item, (
                        OwnershipValueDependency, CalendarPeriodDependency))
                           for item in context_dependencies)
                    or any(not isinstance(item, ContextAssertion)
                           for item in context_assertions)):
                raise ValueError("context dependencies/assertions are invalid")
            arguments["contextDependencies"] = [item.to_wire()
                                                  for item in context_dependencies]
            arguments["contextAssertions"] = [item.to_wire()
                                                for item in context_assertions]
        return cls.one("facts.expression.calculate", arguments, name=name)

    @classmethod
    def member_set_reduction(cls, source_members: Mapping[str, str],
                             source_member_sets: MemberSet | tuple[MemberSet, ...],
                             target_member_ids: Mapping[str, str],
                             expression: CubeExpression, result_key: str, *,
                             measure: str = "sum",
                             weight_expression: CubeExpression | None = None,
                             name: str = "unit") -> Program:
        """Build a bounded explicit one-to-four-axis relational reduction."""
        if not isinstance(expression, CubeExpression):
            raise TypeError("expression must be CubeExpression")
        fixed = _member_mapping(source_members, label="source_members",
                                allow_empty=True)
        sets = ((source_member_sets,) if isinstance(source_member_sets, MemberSet)
                else source_member_sets)
        if not isinstance(sets, tuple) or not 1 <= len(sets) <= 4:
            raise ValueError("source_member_sets requires 1-4 explicit member sets")
        targets = _member_mapping(target_member_ids, label="target_member_ids")
        selections = []
        product = 1
        for item in sets:
            axis, member_ids = _explicit_member_set(
                item, label="source_member_sets")
            target = targets.get(axis)
            if (axis in fixed or target is None or target in member_ids):
                raise ValueError(
                    "each reduced dimension needs a distinct target and no fixed source")
            product *= len(member_ids)
            selections.append({"dimensionId": axis,
                "sourceMemberIds": member_ids, "targetMemberId": target})
        if (set(targets) != {item["dimensionId"] for item in selections}
                or len(selections) > 1 and
                   [item["dimensionId"] for item in selections] != sorted(
                       item["dimensionId"] for item in selections)
                or product > 500):
            raise ValueError("reduction dimensions must be distinct, sorted and <=500 cells")
        measure_map = {
            "sum": ["SumAmount", "CountPresent"],
            "average": ["AverageAmount", "CountPresent"],
            "weighted_average": ["WeightedAverageAmount", "SumWeight",
                                 "CountPresent"],
        }
        measures = measure_map.get(measure)
        if measures is None or len(selections) > 1 and measure == "weighted_average":
            raise ValueError("unsupported reduction measure/profile")
        arguments: dict[str, Any] = {"sourceMembers": fixed,
            "expression": expression.to_wire(),
            "resultKey": _result_key(result_key)}
        if len(selections) == 1:
            reduction: dict[str, Any] = {**selections[0], "measures": measures}
            if measure == "weighted_average":
                if not isinstance(weight_expression, CubeExpression):
                    raise ValueError("weighted_average requires weight_expression")
                reduction.update({"weightExpression": weight_expression.to_wire(),
                                  "zeroWeightPolicy": "error"})
            elif weight_expression is not None:
                raise ValueError("weight_expression requires weighted_average")
            arguments["reduceMemberSet"] = reduction
        else:
            if weight_expression is not None:
                raise ValueError("multi-axis reduction does not accept weights")
            arguments["reduceMemberSets"] = {
                "selections": selections, "measures": measures}
        return cls.one("facts.expression.calculate", arguments, name=name)

    @classmethod
    def domain_expression_calculation(cls,
                                      source_domain: tuple[MemberSet, ...],
                                      missing_default: Amount,
                                      expression: CubeExpression,
                                      result_key: str, *,
                                      name: str = "unit") -> Program:
        """Build a complete bounded source domain with an explicit missing value."""
        if (not isinstance(source_domain, tuple) or not source_domain
                or len(source_domain) > 32
                or not isinstance(missing_default, Amount)
                or not isinstance(expression, CubeExpression)):
            raise ValueError("source_domain, Amount default and expression are required")
        items = []
        product = 1
        for member_set in source_domain:
            axis, member_ids = _explicit_member_set(
                member_set, label="source_domain")
            product *= len(member_ids)
            items.append({"dimensionId": axis, "memberIds": member_ids})
        if (len({item["dimensionId"] for item in items}) != len(items)
                or product > 500):
            raise ValueError("source_domain dimensions must be unique and <=500 cells")
        return cls.one("facts.expression.calculate", {
            "sourceDomain": items,
            "missingDefault": {"type": "AmountLiteral",
                               "decimal": missing_default.value},
            "expression": expression.to_wire(),
            "resultKey": _result_key(result_key),
        }, name=name)

    @classmethod
    def hierarchy_reduction(cls, source_members: Mapping[str, str],
                            selections: MemberSet | tuple[MemberSet, ...],
                            target_member_ids: Mapping[str, str],
                            expression: CubeExpression, result_key: str, *,
                            measure: str = "sum",
                            name: str = "unit") -> Program:
        """Request a server-resolved and sealed one- or two-axis reduction."""
        if not isinstance(expression, CubeExpression):
            raise TypeError("expression must be CubeExpression")
        fixed = _member_mapping(source_members, label="source_members",
                                allow_empty=True)
        values = ((selections,) if isinstance(selections, MemberSet)
                  else selections)
        if not isinstance(values, tuple) or not 1 <= len(values) <= 2:
            raise ValueError("hierarchy reduction requires one or two selections")
        targets = _member_mapping(target_member_ids,
                                  label="target_member_ids")
        normalized = []
        for item in values:
            if (not isinstance(item, MemberSet)
                    or item.selector.get("kind") not in (
                        "Children", "Descendants", "Leaves")
                    or item.selector.get("includeSelf") is not False
                    or type(item.selector.get("hierarchyVersion")) is not int):
                raise ValueError(
                    "hierarchy selections require a pinned version and exclude self")
            axis = item.dimension_id
            target = targets.get(axis)
            if axis in fixed or not isinstance(target, str):
                raise ValueError(
                    "each hierarchy dimension needs a target and no fixed source")
            normalized.append({"dimensionId": axis,
                "kind": item.selector["kind"],
                "rootMemberId": item.selector["rootMemberId"],
                "hierarchyVersion": item.selector["hierarchyVersion"],
                "membershipSemantics": "UniqueMember",
                "targetMemberId": target})
        normalized.sort(key=lambda item: item["dimensionId"])
        axes = [item["dimensionId"] for item in normalized]
        if len(set(axes)) != len(axes) or set(targets) != set(axes):
            raise ValueError("hierarchy dimensions and targets must match exactly")
        measure_map = {"sum": ["SumAmount", "CountPresent"],
                       "average": ["AverageAmount", "CountPresent"]}
        measures = measure_map.get(measure)
        if measures is None:
            raise ValueError("hierarchy measure must be sum or average")
        arguments: dict[str, Any] = {"sourceMembers": fixed,
            "expression": expression.to_wire(),
            "resultKey": _result_key(result_key)}
        if len(normalized) == 1:
            arguments["reduceSelection"] = {**normalized[0],
                                              "measures": measures}
        else:
            arguments["reduceSelections"] = normalized
            arguments["measures"] = measures
        return cls.one("facts.expression.calculate", arguments, name=name)

    @classmethod
    def currency_member_set_conversion(cls, grain_dimensions: tuple[str, ...],
                                       fixed_members: Mapping[str, str],
                                       selection: MemberSet, *,
                                       to_currency_member_id: str,
                                       rate_kind: str,
                                       result_key: str,
                                       name: str = "unit") -> Program:
        """Request server-resolved exact-rate conversion over one member set."""
        if (not isinstance(grain_dimensions, tuple)
                or not 1 <= len(grain_dimensions) <= 128
                or any(not isinstance(axis, str) or not 1 <= len(axis) <= 200
                       for axis in grain_dimensions)
                or len(set(grain_dimensions)) != len(grain_dimensions)):
            raise ValueError("grain_dimensions requires 1-128 distinct IDs")
        dimensions = tuple(sorted(grain_dimensions))
        fixed = _member_mapping(fixed_members, label="fixed_members",
                                allow_empty=True)
        if (len(fixed) != len(dimensions) - 1
                or any(axis not in dimensions for axis in fixed)):
            raise ValueError("fixed_members must bind every non-selected dimension")
        if (not isinstance(selection, MemberSet)
                or selection.selector.get("kind") not in (
                    "Children", "Descendants", "Leaves")
                or type(selection.selector.get("hierarchyVersion")) is not int
                or selection.dimension_id not in dimensions
                or selection.dimension_id in fixed):
            raise ValueError("selection requires one pinned hierarchy axis")
        if (not isinstance(to_currency_member_id, str)
                or not 1 <= len(to_currency_member_id) <= 200):
            raise ValueError("to_currency_member_id must be a stable ID")
        if rate_kind not in ("balance", "flow"):
            raise ValueError("rate_kind must be balance or flow")
        return cls.one("facts.expression.calculate", {
            "grain": {"mode": "full_coordinate",
                      "dimensions": list(dimensions)},
            "fixedMembers": fixed,
            "selection": {"dimensionId": selection.dimension_id,
                "kind": selection.selector["kind"],
                "rootMemberId": selection.selector["rootMemberId"],
                "hierarchyVersion": selection.selector["hierarchyVersion"],
                "includeSelf": selection.selector["includeSelf"]},
            "sourceUnitBinding": "EntityDefaultCurrency",
            "toCurrencyMemberId": to_currency_member_id,
            "outputUnitCurrencyMemberId": to_currency_member_id,
            "rateKind": rate_kind,
            "resultKey": _result_key(result_key),
        }, name=name)

    def then(self, function: str, arguments: Mapping[str, Any], *,
             atomic: bool = False, name: str | None = None) -> Program:
        operation = {"languageVersion": 2, "function": _identifier(function, "function"),
                     "arguments": _canonical_copy(arguments, label="arguments")}
        if atomic and self.units:
            last = self.units[-1]
            units = self.units[:-1] + (AtomicUnit(last.operations + (operation,), last.name),)
        else:
            units = self.units + (AtomicUnit((operation,), name or f"unit-{len(self.units)+1}"),)
        return Program(units)

    def __post_init__(self) -> None:
        if not isinstance(self.units, tuple) or any(not isinstance(unit, AtomicUnit)
                                                    for unit in self.units):
            raise ValueError("Program units must be AtomicUnit values")
        operation_count = sum(len(unit.operations) for unit in self.units)
        if operation_count > MAX_OPERATIONS:
            raise ValueError("Program exceeds the operation limit")
        if len(self.canonical_bytes()) > MAX_PLAN_BYTES:
            raise ValueError("Program exceeds the serialized plan limit")

    def to_wire(self) -> dict[str, Any]:
        return {"format": "openepm-python-plan-v1", "units": [
            {"name": unit.name, "operations": [_thaw(operation)
                                                for operation in unit.operations]}
            for unit in self.units]}

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.to_wire(), ensure_ascii=True, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode()

    @property
    def digest(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class ApplicationRule:
    """Immutable authoring contract for a full ordered application rule.

    A member formula defines one calculated member.  An ``ApplicationRule``
    instead names and versions a complete calculation assembled from ordinary
    V2 primitives.  It deliberately reuses :class:`Program`: the fixed core
    still validates, seals and executes the plan, and the client gains no
    database or execution authority.

    Each call to :meth:`then` creates a durable checkpoint by default.  Setting
    ``atomic_with_previous`` only requests that the operation join the prior
    atomic unit; the server remains authoritative and rejects combinations for
    which it has no qualified transactional publisher.
    """

    rule_id: str
    version: int
    program: Program = field(default_factory=Program)
    parameters: tuple[ApplicationRuleParameter, ...] = ()

    def __post_init__(self) -> None:
        _identifier(self.rule_id, "rule_id")
        if type(self.version) is not int or self.version < 1:
            raise ValueError("version must be a positive integer")
        if not isinstance(self.program, Program):
            raise ValueError("program must be a Program")
        if (not isinstance(self.parameters, tuple)
                or len(self.parameters) > 100
                or any(not isinstance(item, ApplicationRuleParameter)
                       for item in self.parameters)
                or len({item.name for item in self.parameters}) !=
                   len(self.parameters)):
            raise ValueError("parameters must be up to 100 unique typed parameters")
        if self.statement_count > MAX_APPLICATION_RULE_OPERATIONS:
            raise ValueError("Application rule exceeds the 500-operation limit")

    @property
    def statement_count(self) -> int:
        return sum(len(unit.operations) for unit in self.program.units)

    @property
    def checkpoint_count(self) -> int:
        return len(self.program.units)

    def then(self, function: str, arguments: Mapping[str, Any], *,
             atomic_with_previous: bool = False,
             checkpoint_name: str | None = None) -> ApplicationRule:
        """Return a new rule with one ordered primitive appended."""
        updated = self.program.then(function, arguments,
                                    atomic=atomic_with_previous,
                                    name=checkpoint_name)
        if sum(len(unit.operations) for unit in updated.units) > \
                MAX_APPLICATION_RULE_OPERATIONS:
            raise ValueError("Application rule exceeds the 500-operation limit")
        return ApplicationRule(self.rule_id, self.version, updated,
                               self.parameters)

    def with_parameter(self, parameter: ApplicationRuleParameter
                       ) -> ApplicationRule:
        if not isinstance(parameter, ApplicationRuleParameter):
            raise TypeError("parameter must be ApplicationRuleParameter")
        if any(item.name == parameter.name for item in self.parameters):
            raise ValueError("parameter names must be unique")
        return ApplicationRule(self.rule_id, self.version, self.program,
                               self.parameters + (parameter,))

    def then_numeric_sequence(self, sequence: NumericSequence, *,
                              checkpoint_name: str | None = None
                              ) -> ApplicationRule:
        """Append one atomic ordered exact-calculation primitive."""
        if not isinstance(sequence, NumericSequence):
            raise TypeError("sequence must be NumericSequence")
        return self.then("facts.numeric.sequence", sequence.to_arguments(),
                         checkpoint_name=checkpoint_name)

    def then_numeric_iteration(self, iteration: NumericIteration, *,
                               checkpoint_name: str | None = None
                               ) -> ApplicationRule:
        """Append one bounded, atomic fixed-point calculation primitive."""
        if not isinstance(iteration, NumericIteration):
            raise TypeError("iteration must be NumericIteration")
        return self.then("facts.numeric.iterate", iteration.to_arguments(),
                         checkpoint_name=checkpoint_name)

    def to_plan(self) -> dict[str, Any]:
        """Return the existing plan envelope consumed by fixed-core sealing."""
        if self.statement_count == 0:
            raise ValueError("Application rule requires at least one operation")
        return self.program.to_wire()

    def to_definition(self, *, name: str | None = None) -> dict[str, Any]:
        """Return the immutable definition accepted by application.rule.save."""
        plan = self.to_plan()
        label = self.rule_id if name is None else name
        if (not isinstance(label, str) or not 1 <= len(label) <= 200
                or label != label.strip()):
            raise ValueError("name must be 1-200 non-whitespace characters")
        return {"format": "openepm-application-rule-v1", "name": label,
                "units": plan["units"],
                **({"parameters": [item.to_wire() for item in self.parameters]}
                   if self.parameters else {})}

    @property
    def plan_digest(self) -> str:
        if self.statement_count == 0:
            raise ValueError("Application rule requires at least one operation")
        return self.program.digest


@dataclass(frozen=True, slots=True)
class BuildContext:
    application: Application
    metadata_revision: int
    policy_revision: int
    schema_epoch: int
    references: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if any(type(value) is not int or value < 0 for value in
               (self.metadata_revision, self.policy_revision, self.schema_epoch)):
            raise ValueError("BuildContext revisions must be nonnegative integers")
        object.__setattr__(self, "references",
                           _freeze(_canonical_copy(self.references, label="references")))


@dataclass(frozen=True, slots=True)
class JobHandle:
    application: Application
    job_id: str
    request_key: str

    def __post_init__(self) -> None:
        _identifier(self.job_id, "job_id")
        _identifier(self.request_key, "request_key")
