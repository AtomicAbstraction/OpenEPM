"""Public client-side composition helpers for generic member-list IR.

These helpers contain no evaluation logic.  They construct an inspectable
document which the fixed core validates again and eventually persists/evaluates
against an authorized metadata revision.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from .metadata_references import reference_identity_key

from .model import _canonical_copy, _freeze, _identifier, _thaw


FORMAT = "openepm-member-list-v1"


@dataclass(frozen=True, slots=True)
class MemberListExpression:
    node: Mapping[str, Any]

    def __post_init__(self) -> None:
        value = _canonical_copy(self.node, label="member-list expression")
        if not isinstance(value, dict) or not isinstance(value.get("kind"), str):
            raise ValueError("member-list expression requires a typed node")
        object.__setattr__(self, "node", _freeze(value))

    @classmethod
    def explicit(cls, *member_ids: str) -> "MemberListExpression":
        if not 1 <= len(member_ids) <= 10_000:
            raise ValueError("explicit member list requires 1-10000 members")
        members = [_identifier(item, "member_id") for item in member_ids]
        if len(members) != len({reference_identity_key(value) for value in members}):
            raise ValueError("explicit member IDs must be unique")
        return cls({"kind": "explicit", "memberIds": members})

    @classmethod
    def hierarchy(
        cls,
        kind: str,
        hierarchy_id: str,
        member_id: str,
        *,
        include_self: bool = False,
    ) -> "MemberListExpression":
        if kind not in {"children", "parents", "descendants", "ancestors", "siblings", "leaves", "base"}:
            raise ValueError("unsupported hierarchy selector")
        if not isinstance(include_self, bool):
            raise ValueError("include_self must be boolean")
        if kind == "base" and include_self:
            raise ValueError("base does not accept include_self")
        return cls(
            {
                "kind": kind,
                "hierarchyId": _identifier(hierarchy_id, "hierarchy_id"),
                "memberId": _identifier(member_id, "member_id"),
                "includeSelf": include_self,
            }
        )

    @classmethod
    def attribute(
        cls, attribute_id: str, operator: str, value: object
    ) -> "MemberListExpression":
        if operator not in {
            "eq", "ne", "lt", "lte", "gt", "gte", "contains", "starts_with", "in", "exists"
        }:
            raise ValueError("unsupported attribute operator")
        return cls(
            {
                "kind": "attribute",
                "attributeId": _identifier(attribute_id, "attribute_id"),
                "operator": operator,
                "value": value,
            }
        )

    @classmethod
    def parameter(cls, name: str) -> "MemberListExpression":
        return cls({"kind": "parameter", "name": _identifier(name, "parameter name")})

    @classmethod
    def union(cls, *items: "MemberListExpression") -> "MemberListExpression":
        return cls._set_operation("union", items)

    @classmethod
    def intersection(cls, *items: "MemberListExpression") -> "MemberListExpression":
        return cls._set_operation("intersection", items)

    @classmethod
    def _set_operation(
        cls, kind: str, items: tuple["MemberListExpression", ...]
    ) -> "MemberListExpression":
        if not 2 <= len(items) <= 64 or any(
            not isinstance(item, MemberListExpression) for item in items
        ):
            raise ValueError(f"{kind} requires 2-64 member-list expressions")
        return cls({"kind": kind, "items": [item.to_wire() for item in items]})

    def difference(self, subtract: "MemberListExpression") -> "MemberListExpression":
        if not isinstance(subtract, MemberListExpression):
            raise TypeError("subtract must be a MemberListExpression")
        return MemberListExpression(
            {"kind": "difference", "source": self.to_wire(), "subtract": subtract.to_wire()}
        )

    def ordered(
        self,
        *,
        by: str = "member_id",
        direction: str = "ascending",
        attribute_id: str | None = None,
    ) -> "MemberListExpression":
        if by not in {"member_id", "name", "attribute"}:
            raise ValueError("unsupported member-list order")
        if direction not in {"ascending", "descending"}:
            raise ValueError("unsupported member-list direction")
        if (by == "attribute") != (attribute_id is not None):
            raise ValueError("attribute order requires only an attribute_id")
        return MemberListExpression(
            {
                "kind": "order",
                "source": self.to_wire(),
                "by": by,
                "direction": direction,
                "attributeId": _identifier(attribute_id, "attribute_id")
                if attribute_id is not None
                else None,
            }
        )

    def to_wire(self) -> dict[str, Any]:
        return _thaw(self.node)


@dataclass(frozen=True, slots=True)
class MemberListParameter:
    name: str
    value_type: str
    required: bool = True

    def __post_init__(self) -> None:
        _identifier(self.name, "parameter name")
        if self.value_type not in {"Member", "String", "Decimal", "Boolean", "Date"}:
            raise ValueError("unsupported member-list parameter type")
        if not isinstance(self.required, bool):
            raise ValueError("required must be boolean")

    def to_wire(self) -> dict[str, object]:
        return {"name": self.name, "type": self.value_type, "required": self.required}


@dataclass(frozen=True, slots=True)
class MemberListDefinition:
    list_id: str
    dimension_id: str
    name: str
    expression: MemberListExpression
    parameters: tuple[MemberListParameter, ...] = ()
    _source_span: tuple | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        from .source_mapping import current_span
        object.__setattr__(self, '_source_span', current_span())
        _identifier(self.list_id, "list_id")
        _identifier(self.dimension_id, "dimension_id")
        if not isinstance(self.name, str) or not 1 <= len(self.name.strip()) <= 200:
            raise ValueError("name must contain 1-200 characters")
        if not isinstance(self.expression, MemberListExpression):
            raise TypeError("expression must be a MemberListExpression")
        if not isinstance(self.parameters, tuple) or len(self.parameters) > 100:
            raise ValueError("parameters must be a tuple of at most 100 entries")
        if any(not isinstance(item, MemberListParameter) for item in self.parameters):
            raise TypeError("parameters must contain MemberListParameter values")
        names = [item.name for item in self.parameters]
        if len(names) != len(set(names)):
            raise ValueError("parameter names must be unique")

    def to_wire(self) -> dict[str, Any]:
        return {
            "format": FORMAT,
            "listId": self.list_id,
            "dimensionId": self.dimension_id,
            "name": self.name.strip(),
            "parameters": [item.to_wire() for item in self.parameters],
            "expression": self.expression.to_wire(),
        }
