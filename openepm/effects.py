"""Client composition helpers for generic multidimensional write effects."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Mapping


FORMAT = "openepm-cube-effect-batch-v1"


@dataclass(frozen=True, slots=True)
class CubeEffect:
    coordinate: Mapping[str, str]
    fact_kind: str
    action: str
    value: str | Decimal | None
    expected_change_id: str

    def to_wire(self) -> dict[str, Any]:
        value = format(self.value, "f") if isinstance(self.value, Decimal) else self.value
        return {
            "coordinate": dict(self.coordinate),
            "factKind": self.fact_kind,
            "action": self.action,
            "value": value,
            "expectedChangeId": self.expected_change_id,
        }


@dataclass(frozen=True, slots=True)
class CubeEffectBatch:
    view_digest: str
    expected_metadata_revision: int
    expected_data_revision: int
    effects: tuple[CubeEffect, ...]

    def to_wire(self) -> dict[str, Any]:
        return {
            "format": FORMAT,
            "viewDigest": self.view_digest,
            "expectedMetadataRevision": self.expected_metadata_revision,
            "expectedDataRevision": self.expected_data_revision,
            "effects": [effect.to_wire() for effect in self.effects],
        }
