"""Client composition for generic dynamic or materialized members."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .model import CubeExpression, _thaw
from .selections import CubeSelection


FORMAT = "openepm-calculated-member-v1"


@dataclass(frozen=True, slots=True)
class CalculatedMemberDependency:
    definition_id: str

    def to_wire(self) -> dict[str, Any]:
        return {"definitionId": self.definition_id}


@dataclass(frozen=True, slots=True)
class CalculatedMember:
    definition_id: str
    name: str
    target_dimension_id: str
    target_member_id: str
    evaluation: str
    source_selection: CubeSelection
    expression: CubeExpression
    result_unit: str
    result_key: str | None = None
    dependencies: tuple[CalculatedMemberDependency, ...] = ()
    max_source_cells: int = 100_000
    max_output_cells: int = 10_000
    _source_span: tuple | None = field(default=None, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        from .source_mapping import current_span
        object.__setattr__(self, '_source_span', current_span())

    def to_wire(self) -> dict[str, Any]:
        return _thaw({
            "format": FORMAT,
            "definitionId": self.definition_id,
            "name": self.name,
            "target": {
                "dimensionId": self.target_dimension_id,
                "memberId": self.target_member_id,
            },
            "evaluation": self.evaluation,
            "sourceSelection": self.source_selection.to_wire(),
            "expression": self.expression.to_wire(),
            "dependencies": [item.to_wire() for item in self.dependencies],
            "resultUnit": self.result_unit,
            "resultKey": self.result_key,
            "maxSourceCells": self.max_source_cells,
            "maxOutputCells": self.max_output_cells,
        })
