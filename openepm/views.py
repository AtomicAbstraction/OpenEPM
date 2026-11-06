"""Client-side construction of generic multidimensional views."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .model import _identifier
from .selections import CubeSelection


FORMAT = "openepm-cube-view-v1"


@dataclass(frozen=True, slots=True)
class CubeView:
    view_id: str
    version: int
    name: str
    selection: CubeSelection
    rows: tuple[str, ...]
    columns: tuple[str, ...]
    pages: tuple[str, ...] = ()
    filters: tuple[str, ...] = ()
    data_source: str = "raw"
    result_key: str | None = None
    suppress_missing: bool = False
    suppress_zero: bool = False
    page_size: int = 100

    def __post_init__(self) -> None:
        _identifier(self.view_id, "view_id")
        if type(self.version) is not int or self.version < 1:
            raise ValueError("version must be positive")
        if not isinstance(self.name, str) or not 1 <= len(self.name.strip()) <= 200:
            raise ValueError("name must contain 1-200 characters")
        if not isinstance(self.selection, CubeSelection):
            raise TypeError("selection must be a CubeSelection")
        for axis_name in ("rows", "columns", "pages", "filters"):
            axis = getattr(self, axis_name)
            if not isinstance(axis, tuple) or any(not isinstance(item, str) for item in axis):
                raise TypeError(f"{axis_name} must be a tuple of dimension IDs")
        if not self.rows or not self.columns:
            raise ValueError("rows and columns are required")
        placed = self.pages + self.rows + self.columns + self.filters
        selected = tuple(item.dimension_id for item in self.selection.dimensions)
        if len(placed) != len(set(placed)) or set(placed) != set(selected):
            raise ValueError("each selected dimension must appear on exactly one layout axis")
        if self.data_source not in {"raw", "calculated", "combined"}:
            raise ValueError("unsupported data_source")
        if (self.data_source == "raw") != (self.result_key is None):
            raise ValueError("calculated and combined views require a result_key; raw views forbid it")
        if not isinstance(self.suppress_missing, bool) or not isinstance(self.suppress_zero, bool):
            raise ValueError("suppression options must be boolean")
        if type(self.page_size) is not int or not 1 <= self.page_size <= 500:
            raise ValueError("page_size must be 1-500")

    def to_wire(self) -> dict[str, Any]:
        return {
            "format": FORMAT,
            "viewId": self.view_id,
            "version": self.version,
            "name": self.name.strip(),
            "selection": self.selection.to_wire(),
            "layout": {
                "pages": list(self.pages),
                "rows": list(self.rows),
                "columns": list(self.columns),
                "filters": list(self.filters),
            },
            "dataSource": {"kind": self.data_source, "resultKey": self.result_key},
            "suppression": {"missing": self.suppress_missing, "zero": self.suppress_zero},
            "pageSize": self.page_size,
        }
