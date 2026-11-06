"""Client-side construction of role-neutral aggregate intents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .selections import CubeSelection


FORMAT = "openepm-cube-aggregate-v1"


@dataclass(frozen=True, slots=True)
class CubeAggregate:
    selection: CubeSelection
    group_by: tuple[str, ...]
    reduce_dimensions: tuple[str, ...]
    measures: tuple[str, ...] = ("sum", "count_present")
    membership_semantics: str = "unique_member"

    def to_wire(self) -> dict[str, Any]:
        return {
            "format": FORMAT,
            "selection": self.selection.to_wire(),
            "groupBy": list(self.group_by),
            "reduceDimensions": list(self.reduce_dimensions),
            "measures": list(self.measures),
            "membershipSemantics": self.membership_semantics,
            "memberOperatorPolicy": "configured",
            "missing": "exclude",
        }
