"""Fixed-core orchestration for a compiled W08 mixed read.

Physical stage adapters receive one immutable read cut.  They may read raw,
stored, dynamic or hierarchy sources, but cannot publish business state.
"""
from __future__ import annotations

from typing import Callable

from .resolved_cube_read_contract import (
    ResolvedCubeReadPlan, apply_resolved_presentation,
    validate_resolved_rows)
from .resolved_cube_read_planner import ResolvedCubeReadExecution


StageReader = Callable[[dict[str, object], dict[str, int], int], dict]


def execute_resolved_read(plan: ResolvedCubeReadPlan,
        execution: ResolvedCubeReadExecution, *,
        stage_reader: StageReader,
        technical: bool = False) -> dict[str, object]:
    """Execute every coalesced stage at the exact compiled snapshot."""
    if (not isinstance(plan, ResolvedCubeReadPlan)
            or not isinstance(execution, ResolvedCubeReadExecution)
            or execution.normalized["requestDigest"] != plan.digest
            or not callable(stage_reader)):
        raise ValueError("RESOLVED_READ_EXECUTION_INVALID")
    if (plan.normalized["delivery"] != "direct" and not technical):
        raise ValueError("RESOLVED_READ_TECHNICAL_QUERY_REQUIRED")
    snapshot = execution.normalized["snapshot"]
    max_source = plan.normalized["limits"]["maxSourceRows"]
    source_rows = 0
    combined = []
    stage_evidence = []
    for stage in execution.normalized["stages"]:
        result = stage_reader(stage, snapshot, max_source - source_rows)
        if (not isinstance(result, dict)
                or set(result) != {"snapshot", "sourceRows", "rows",
                                   "evidence"}
                or result["snapshot"] != snapshot
                or type(result["sourceRows"]) is not int
                or result["sourceRows"] < 0
                or not isinstance(result["rows"], list)
                or not isinstance(result["evidence"], dict)):
            raise ValueError("RESOLVED_READ_STAGE_RESULT_INVALID")
        source_rows += result["sourceRows"]
        if source_rows > max_source:
            raise ValueError("RESOURCE_LIMIT")
        combined.extend(result["rows"])
        stage_evidence.append({"stage": stage["stage"],
            "sourceDigest": stage["sourceDigest"], **result["evidence"]})
    rows = apply_resolved_presentation(validate_resolved_rows(
        combined, plan=plan, snapshot=snapshot), plan=plan)
    return {"format": "openepm-resolved-cube-read-result-v1",
        "requestDigest": plan.digest, "executionDigest": execution.digest,
        "snapshot": snapshot, "sourceRows": source_rows, "rows": rows,
        "stages": stage_evidence, "persisted": False,
        "presentation": {**plan.normalized["presentation"],
            "rowCount": len(rows)}}
