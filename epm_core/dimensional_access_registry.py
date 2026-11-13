"""Generated audit view of dimensional-policy enforcement on public operations.

This is an inventory and fail-closed source contract.  Runtime authorization
continues to live in the fixed handlers named here; this module does not make
an authorization decision or introduce a second policy implementation.
"""
from __future__ import annotations

from pathlib import Path

from .postgres_language_v2 import PostgresLanguageV2
from .processing_operation_registry import build_registry


FORMAT = "openepm-dimensional-access-enforcement-matrix-v1"


_FAMILIES = {
    "direct_reads": {
        "matches": lambda entry: entry["function"] == "facts.cube.select",
        "mechanism": "bounded raw pages are filtered by current exact-coordinate READ policy",
        "sources": {"epm_core/postgres_cube_select.py": ("filter_read_rows(",)},
    },
    "source_evidence_records": {
        "matches": lambda entry: (entry["function"].startswith(
            "source.evidence.record.") or entry["function"] ==
            "source.evidence.generic.cutover.apply"),
        "mechanism": "record reads and raw list pages are filtered by current exact-coordinate READ policy; create, replacement, deletion and legacy cutover authorize every affected coordinate with WRITE policy",
        "sources": {
            "epm_core/postgres_source_evidence.py": (
                "filter_read_rows(", "authorize_coordinate("),
            "epm_core/postgres_source_evidence_cutover.py": (
                "authorize_coordinates(",),
        },
    },
    "aggregates": {
        "matches": lambda entry: entry["function"].startswith((
            "facts.cube.aggregate.", "cube.aggregate.")),
        "mechanism": "effective scope is bound at admission and rechecked before result storage, sealing and disclosure; active policy requires the exact filtering backend",
        "sources": {
            "epm_core/postgres_cube_aggregate_repository.py": (
                "resolve_effective_dimensional_scope(",
                "CUBE_AGGREGATE_DIMENSIONAL_SECURITY_FILTER_REQUIRED",
                "_require_current_authorization_scope("),
            "epm_core/cube_aggregate_native.py": (
                "DIMENSIONAL_SELECTION_REJECTED", "_security_sql("),
        },
    },
    "exports": {
        "matches": lambda entry: entry["function"].startswith((
            "facts.export.", "facts.transfer.export.")),
        "mechanism": "export request, producer checkpoints, manifests and payload pages are bound to and recheck the effective dimensional scope",
        "sources": {
            "epm_core/postgres_export_producer_checkpoint.py": (
                "resolve_effective_dimensional_scope(",
                "_require_current_authorization_scope("),
            "epm_core/postgres_export_payload.py": (
                "_require_current_artifact_scope(",),
            "epm_core/postgres_transfer_artifacts.py": (
                "resolve_effective_dimensional_scope(",),
        },
    },
    "sealed_selections": {
        "matches": lambda entry: entry["function"].startswith("cube.selection."),
        "mechanism": "sealed selection identity stores the effective dimensional-scope digest and refuses reuse after scope drift",
        "sources": {"epm_core/postgres_sealed_selections.py": (
            "resolve_effective_dimensional_scope(",
            "SEALED_SELECTION_AUTHORIZATION_SCOPE_CHANGED")},
    },
    "jobs": {
        "matches": lambda entry: entry["mode"] in {
            "durable_atomic_adjustment", "durable_calculation", "durable_job",
            "durable_sequence", "durable_source_publication", "durable_write"},
        "mechanism": "durable job admission persists the effective scope, replay rechecks it, and the fixed publisher receives that scope for its coordinate READ/WRITE publication fence",
        "sources": {"epm_core/postgres_jobs.py": (
            "resolve_effective_dimensional_scope(",
            "_verify_job_replay_authorization(",
            "authorization_scope_digest")},
    },
    "application_rules": {
        "matches": lambda entry: entry["function"].startswith("application.rule.run"),
        "mechanism": "rule runs bind the effective scope and recheck it at dispatch, child execution, settlement, reconciliation and result inspection",
        "sources": {"epm_core/postgres_application_rule_workflow.py": (
            "resolve_effective_dimensional_scope(",
            "_assert_authorization_scope(")},
    },
    "schedules": {
        "matches": lambda entry: (entry["function"].startswith("schedule.")
            or ".schedule." in entry["function"]),
        "mechanism": "schedule authority stores the effective scope and due dispatch, occurrence inspection and child execution recheck it",
        "sources": {
            "epm_core/postgres_application_schedules.py": (
                "resolve_effective_dimensional_scope(",
                "_assert_authorization_scope("),
            "epm_core/postgres_python_schedules.py": (
                "resolve_effective_dimensional_scope(",
                "_assert_authorization_scope("),
        },
    },
    "python_build_run": {
        "matches": lambda entry: entry["function"] in {
            "python.program.build", "python.program.run"},
        "mechanism": "build and run admission, broker context, workflow publication and public status/artifact/log disclosure bind and recheck the effective scope",
        "sources": {
            "epm_core/postgres_python_program_repository.py": (
                "resolve_effective_dimensional_scope(",
                "_assert_current_authorization_scope("),
            "epm_core/postgres_python_workflow.py": (
                "resolve_effective_dimensional_scope(",
                "_assert_workflow_authorization_scope("),
        },
    },
}


def _families(entry: dict) -> list[str]:
    return sorted(name for name, contract in _FAMILIES.items()
                  if contract["matches"](entry))


def build_dimensional_access_matrix(repo: Path | None = None) -> dict:
    repo = repo or Path(__file__).resolve().parents[1]
    registry = build_registry(PostgresLanguageV2.catalog()["functions"])
    missing_markers = []
    for family, contract in _FAMILIES.items():
        for relative, markers in contract["sources"].items():
            path = repo / relative
            source = path.read_text(encoding="utf-8") if path.is_file() else ""
            for marker in markers:
                if marker not in source:
                    missing_markers.append(
                        {"family": family, "path": relative, "marker": marker})
    if missing_markers:
        raise ValueError("DIMENSIONAL_ACCESS_HANDLER_MARKER_MISSING:"+
            repr(missing_markers))

    operations = []
    counts = {family: 0 for family in _FAMILIES}
    for entry in registry["applicationFunctions"]:
        families = _families(entry)
        if not families:
            continue
        for family in families:
            counts[family] += 1
        operations.append({
            "function": entry["function"],
            "registryFamily": entry["family"],
            "mode": entry["mode"],
            "requiredFamilies": families,
            "enforcement": [{
                "family": family,
                "mechanism": _FAMILIES[family]["mechanism"],
                "handlerSources": sorted(_FAMILIES[family]["sources"]),
            } for family in families],
            "status": "source_enforced_not_final_artifact_qualified",
        })
    if any(count == 0 for count in counts.values()):
        raise ValueError("DIMENSIONAL_ACCESS_REQUIRED_FAMILY_EMPTY:"+
                         repr(counts))
    return {
        "format": FORMAT,
        "registryFormat": registry["format"],
        "registryApplicationFunctionCount":
            registry["applicationFunctionCount"],
        "auditedOperationCount": len(operations),
        "familyCounts": counts,
        "operations": operations,
        "restoredWork": {
            "status": "qualification_required",
            "reason": "Recovery preserves the authoritative schema and application rows, but the current recovery harness does not activate a dimensional policy and prove denied plus allowed work after restore.",
            "source": "tests/qualify_release_backup_restore.py",
            "releaseGate": "Repeat post-restore reads and publication with distinct allowed and denied dimensional identities on the exact candidate.",
        },
        "qualificationBoundary": (
            "Generated source audit only; live PostgreSQL, restored-candidate, "
            "browser, Keycloak and final-artifact authorization remain separate."),
    }


def classify_public_operation(entry: dict) -> tuple[str, ...]:
    """Expose the fail-closed selector for focused registry regression tests."""
    return tuple(_families(entry))
