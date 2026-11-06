"""Client composition helpers for complete-grain cube selections."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .model import _canonical_copy, _freeze, _identifier, _thaw


FORMAT = "openepm-cube-selection-v1"


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
        if len(values) != len(set(values)):
            raise ValueError("member IDs must be unique")
        return cls(dimension_id, {"kind": "members", "memberIds": values})

    @classmethod
    def member_list(
        cls,
        dimension_id: str,
        list_id: str,
        version: int,
        *,
        parameters: Mapping[str, object] | None = None,
    ) -> "DimensionSelection":
        if type(version) is not int or version < 1:
            raise ValueError("member-list version must be positive")
        return cls(
            dimension_id,
            {
                "kind": "member_list",
                "listId": _identifier(list_id, "list_id"),
                "version": version,
                "parameters": dict(parameters or {}),
            },
        )

    def excluding(self, selector: Mapping[str, Any]) -> "DimensionSelection":
        return DimensionSelection(self.dimension_id, self.include, selector)

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
