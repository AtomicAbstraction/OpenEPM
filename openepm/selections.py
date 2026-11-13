"""Client composition helpers for complete-grain cube selections."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:
    from .member_lists import MemberListExpression

from .metadata_references import reference_identity_key

from .model import _canonical_copy, _freeze, _identifier, _thaw


FORMAT = "openepm-cube-selection-v1"
INLINE_EXPRESSION_FORMAT = "openepm-member-list-expression-v1"


@dataclass(frozen=True, slots=True)
class DimensionSelection:
    dimension_id: str
    include: Mapping[str, Any]
    exclude: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        _identifier(self.dimension_id, "dimension_id")
        include = _canonical_copy(self.include, label="selection include")
        exclude = None if self.exclude is None else _canonical_copy(
            self.exclude, label="selection exclude"
        )
        if not isinstance(include, dict) or not isinstance(include.get("kind"), str):
            raise ValueError("selection include requires a typed selector")
        if exclude is not None and (
            not isinstance(exclude, dict) or not isinstance(exclude.get("kind"), str)
        ):
            raise ValueError("selection exclude requires a typed selector")
        object.__setattr__(self, "include", _freeze(include))
        object.__setattr__(self, "exclude", None if exclude is None else _freeze(exclude))

    @classmethod
    def member(cls, dimension_id: str, member_id: str) -> "DimensionSelection":
        return cls(dimension_id, {"kind": "member", "memberId": _identifier(member_id, "member_id")})

    @classmethod
    def members(cls, dimension_id: str, *member_ids: str) -> "DimensionSelection":
        if not 1 <= len(member_ids) <= 10_000:
            raise ValueError("members requires 1-10000 member IDs")
        values = [_identifier(item, "member_id") for item in member_ids]
        if len(values) != len({reference_identity_key(value) for value in values}):
            raise ValueError("member IDs must be unique")
        return cls(dimension_id, {"kind": "members", "memberIds": values})

    @classmethod
    def member_list(
        cls,
        dimension_id: str,
        list_id: str,
        *,
        parameters: Mapping[str, object] | None = None,
    ) -> "DimensionSelection":
        return cls(
            dimension_id,
            {
                "kind": "member_list",
                "listId": _identifier(list_id, "list_id"),
                "parameters": dict(parameters or {}),
            },
        )

    @classmethod
    def expression(
        cls, dimension_id: str, expression: "MemberListExpression"
    ) -> "DimensionSelection":
        from .member_lists import MemberListExpression
        if not isinstance(expression, MemberListExpression):
            raise TypeError("expression must be a MemberListExpression")
        return cls(dimension_id, {
            "kind": "inline_expression",
            "expressionFormat": INLINE_EXPRESSION_FORMAT,
            "expression": expression.to_wire()})

    @classmethod
    def hierarchy(cls, dimension_id: str, hierarchy_id: str, member_id: str, *,
                  operator: str = "descendants", include_self: bool = False) -> "DimensionSelection":
        if operator not in {"children", "parents", "descendants", "ancestors", "siblings", "leaves", "base"}:
            raise ValueError("unsupported hierarchy selector")
        if type(include_self) is not bool:
            raise ValueError("include_self must be boolean")
        if operator == "base" and include_self:
            raise ValueError("base does not accept include_self")
        return cls(dimension_id, {"kind": "hierarchy", "operator": operator,
            "hierarchyId": _identifier(hierarchy_id, "hierarchy_id"),
            "memberId": _identifier(member_id, "member_id"), "includeSelf": include_self})

    def excluding(self, selector: Mapping[str, Any]) -> "DimensionSelection":
        return DimensionSelection(self.dimension_id, self.include, selector)

    @classmethod
    def from_wire(cls, value: object) -> "DimensionSelection":
        if not isinstance(value, dict) or set(value) != {
            "dimensionId", "include", "exclude"
        }:
            raise ValueError("dimension selection wire value is invalid")
        return cls(value["dimensionId"], value["include"], value["exclude"])

    def to_wire(self) -> dict[str, Any]:
        return {
            "dimensionId": self.dimension_id,
            "include": _thaw(self.include),
            "exclude": None if self.exclude is None else _thaw(self.exclude),
        }


@dataclass(frozen=True, slots=True)
class CubeSelection:
    metadata_revision: int
    dimensions: tuple[DimensionSelection, ...]

    def __post_init__(self) -> None:
        if type(self.metadata_revision) is not int or self.metadata_revision < 1:
            raise ValueError("metadata_revision must be positive")
        if not isinstance(self.dimensions, tuple) or not 1 <= len(self.dimensions) <= 128:
            raise ValueError("dimensions must contain 1-128 selections")
        if any(not isinstance(item, DimensionSelection) for item in self.dimensions):
            raise TypeError("dimensions must contain DimensionSelection values")
        names = [item.dimension_id for item in self.dimensions]
        if len(names) != len(set(names)):
            raise ValueError("dimension selections must be unique")

    def to_wire(self) -> dict[str, Any]:
        return {
            "format": FORMAT,
            "metadataRevision": self.metadata_revision,
            "dimensions": [item.to_wire() for item in self.dimensions],
        }

    @classmethod
    def from_wire(cls, value: object) -> "CubeSelection":
        if (
            not isinstance(value, dict)
            or set(value) != {"format", "metadataRevision", "dimensions"}
            or value["format"] != FORMAT
            or not isinstance(value["dimensions"], list)
        ):
            raise ValueError("cube selection wire value is invalid")
        return cls(
            value["metadataRevision"],
            tuple(DimensionSelection.from_wire(item)
                  for item in value["dimensions"]),
        )
