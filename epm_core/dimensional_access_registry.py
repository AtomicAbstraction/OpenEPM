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
    "populated_layout_source": {
        "matches": lambda entry: entry["function"] in {
            "metadata.layout.populated.source.read", "metadata.layout.populated.preview",
            "metadata.layout.populated.review"},
        "mechanism": "bounded current layout reads require Administrator and READ for every stored source coordinate, including registration-only rows; any denial refuses the complete inventory, impact preview or dependency review, and current scope is checked before return",
        "sources": {"epm_core/postgres_populated_layout_preview.py": (
            'def source(', 'kind=AccessKind.READ',
            'resolve_effective_dimensional_scope(', 'LAYOUT_SOURCE_AUTHORIZATION_CHANGED',
            'LAYOUT_PREVIEW_AUTHORIZATION_CHANGED', 'layout_replacement_dependency_inventory(')},
    },
    "slice_copy": {
        "matches": lambda entry: (entry["function"].startswith("facts.slice.copy.")
            or entry["function"] in {"facts.source.preview", "facts.source.publish"}),
        "mechanism": (
            "Copy preparation and effect replay require READ of the source and WRITE of the destination, "
            "including replace omissions. The status read requires the original actor and current READ "
            "of retained source and target coordinates. Preview and pending publication of copied batches "
            "recheck original source READ alongside destination WRITE and fence current directory groups."),
        "sources": {
            "epm_core/postgres_planning_copy.py": (
                "def _authorize_sources(", "def read_status(",
                "authorize_staged_copy_sources(", "enforce_source_batch_dimensional_security(",
                "enforce_source_batch_policy("),
            "epm_core/postgres_source_batch.py": (
                "def authorize_staged_copy_sources(", "def _authorize_copied_sources(",
                "require_current_copy_groups(db, self.identity, copy_groups)"),
        },
    },
    "direct_reads": {
        "matches": lambda entry: entry["function"] == "facts.cube.select",
        "mechanism": "bounded raw pages are filtered by current exact-coordinate READ policy",
        "sources": {"epm_core/postgres_cube_select.py": ("filter_read_rows(",)},
    },
    "metadata_directory": {
        "matches": lambda entry: entry["function"] in {
            "metadata.dimension.list", "metadata.dimension.resolve",
            "metadata.member.list", "metadata.member.resolve"},
        "mechanism": "dimensional READ precedes lookup and paging; mixed rejection withholds the selection; projected MemberReference fields require target authority; protected continuation binds current scope and actor",
        "sources": {
            "epm_core/postgres_metadata.py": (
                "resolve_effective_dimensional_scope(", "metadata_reference_read_sql(",
                "METADATA_DIRECTORY_SCOPE_UNAVAILABLE", "require_metadata_page_token(",
                "metadata_visible_attributes_sql(", "METADATA_DIRECTORY_READ_AUTHORIZATION_STALE"),
            "epm_core/postgres_dimensional_scope.py": ("def metadata_reference_read_sql(",),
        },
    },
    "metadata_hierarchy": {
        "matches": lambda entry: entry["function"] in {
            "metadata.hierarchy.list", "metadata.hierarchy.read",
            "metadata.hierarchy.members.list", "metadata.relationship.list",
            "metadata.security-tag.list"},
        "mechanism": "dimension access gates discovery, members are checked before paging, and an edge requires READ on the edge and both endpoints. Protected continuations are bound to effective scope",
        "sources": {
            "epm_core/postgres_hierarchies.py": ("metadata_dimension_visible(", "metadata_reference_read_sql(",
                "require_metadata_page_token(", "METADATA_DIRECTORY_SCOPE_UNAVAILABLE"),
            "epm_core/postgres_metadata.py": ("metadata_relationship_read_sql(", "scopeDigest", "metadata_visible_attributes_sql("),
        },
    },
    "metadata_attributes": {
        "matches": lambda entry: entry["function"] in {
            "metadata.attribute-definition.list", "metadata.attribute-definition.usage.read",
            "metadata.attribute-value.read"},
        "mechanism": "attribute reads check dimension, object and typed reference targets before revealing values, counts or samples. Write-time dependency checks retain the full inventory",
        "sources": {"epm_core/postgres_attribute_catalog.py": (
            "metadata_dimension_visible(", "metadata_relationship_read_sql(", "metadata_linked_member_read_sql(",
            "_visible_usage(", "ATTRIBUTE_USAGE_SCOPE_UNAVAILABLE", "METADATA_ATTRIBUTE_READ_AUTHORIZATION_STALE")},
    },
    "applicability_definition": {
        "matches": lambda entry: entry["function"] == "metadata.applicability_relation.read",
        "mechanism": "complete definitions require active dimensional READ for every typed Member reference and its dimension; changed metadata or authorization withholds the definition",
        "sources": {
            "epm_core/postgres_applicability_relations.py": (
                "_authorize_member_references(", "APPLICABILITY_RELATION_SCOPE_UNAVAILABLE",
                "APPLICABILITY_RELATION_READ_STALE", "APPLICABILITY_RELATION_AUTHORIZATION_STALE"),
            "epm_core/postgres_dimensional_scope.py": ("metadata_reference_read_allowed(",),
        },
    },
    "member_list_definition": {
        "matches": lambda entry: entry["function"] in {
            "metadata.member_list.list", "metadata.member_list.read", "metadata.member_list.evaluate"},
        "mechanism": "complete definitions require dimensional READ for typed references before lookup, evaluation or paging. Mixed rejection withholds the catalogue. Protected continuations bind current scope and actor",
        "sources": {"epm_core/postgres_member_lists.py": (
            "member_list_definition_visible_sql(", "MEMBER_LIST_SCOPE_UNAVAILABLE",
            "_recheck_read_authority(", "resolve_effective_dimensional_scope(",
            "metadata_expression_visible_sql("),
            "epm_core/postgres_dimensional_scope.py": (
                "def metadata_expression_visible_sql(", "metadata_linked_member_read_sql(",
                "metadata_relationship_read_sql(")},
    },
    "saved_view_definition": {
        "matches": lambda entry: entry["function"] in {
            "grid.definition.list", "grid.definition.read", "grid.definition.save", "grid.definition.delete"},
        "mechanism": "complete stored selectors, named references and typed bindings require current dimensional READ before discovery and definition effects. The visible catalogue is paged under the current actor's scope",
        "sources": {"epm_core/postgres_saved_grids.py": (
            "_view_visible_sql(", "SAVED_GRID_SCOPE_UNAVAILABLE", "_require_visible_definition(",
            "_recheck_authority(", "metadata_selection_visible_sql("),
            "epm_core/postgres_dimensional_scope.py": ("member_list_definition_visible_sql(", "metadata_expression_visible_sql(")},
    },
    "governance_definition": {
        "matches": lambda entry: entry["function"] in {
            "application.assignment.list", "application.assignment.read",
            "application.workflow.list", "application.workflow.read"},
        "mechanism": "current dimensional READ covers assignment member selectors and workflow selections, linked assignment sets and saved-view destinations before returning complete definitions or paginating them",
        "sources": {"epm_core/postgres_definition_lifecycle.py": (
            "_assignment_visible_sql(", "_governance_visible_sql(", "_require_current_governance_read(",
            "metadata_selection_visible_sql(", "_view_visible_sql(", "reject_mixed_metadata_reads(")},
    },
    "selection_attribute_projection": {
        "matches": lambda entry: entry["function"] in {"metadata.member.select", "cube.selection.preview"},
        "mechanism": "the shared selection adapter projects unreadable typed reference values as absent before comparison, ordering and disclosure. Named preview selectors check complete definitions before returning pins",
        "sources": {
            "epm_core/postgres_member_selection.py": ("metadata_visible_attributes_sql(", "resolve_effective_dimensional_scope("),
            "epm_core/postgres_dimensional_scope.py": ("def metadata_visible_attributes_sql(", "metadata_linked_member_read_sql("),
            "epm_core/postgres_selection_preview.py": ("member_list_definition_visible_sql(", "load_selection_context("),
        },
    },
    "scenario_comparison": {
        "matches": lambda entry: entry["function"] == "facts.cube.scenario.compare.read",
        "mechanism": "both exact coordinates of every pair require READ before using the current stored cube snapshot, including missing coordinates; the fixed core rechecks snapshot and effective application access before returning a result",
        "sources": {"epm_core/postgres_scenario_comparison.py": (
            "authorize_coordinates(", "kind=AccessKind.READ", "load_resolved_read_snapshot(",
            "CUBE_READ_AUTHORIZATION_STALE", "SCENARIO_COMPARISON_SNAPSHOT_STALE")},
    },
    "workflow_numeric_evidence": {
        "matches": lambda entry: entry["function"] in {
            "application.workflow.activity.evidence.list",
            "application.workflow.activity.evidence.read",
            "application.workflow.activity.complete",
        },
        "mechanism": "numeric receipt choices, completion and currentness require current READ for every exact coordinate before reading fact events or current effects; continuations use only visible receipt boundaries",
        "sources": {
            "epm_core/postgres_application_workflow_evidence.py": (
                "def validate_workflow_evidence(", "def assess_completed_basis(",
                "authorize_coordinates(", "kind=AccessKind.READ"),
            "epm_core/postgres_application_workflow_occurrences.py": (
                "def evidence_options(", "def assess_evidence(",
                "def complete(", "last_visible_revision"),
        },
    },
    "source_evidence_records": {
        "matches": lambda entry: (entry["function"].startswith(
            "source.evidence.record.") or entry["function"] ==
            "source.evidence.generic.cutover.apply"),
        "mechanism": "record reads and list continuations disclose only currently readable coordinates. Create, replacement, retirement and legacy cutover authorize every affected coordinate with WRITE policy. The native record write owner rechecks effective authority before commit",
        "sources": {
            "epm_core/postgres_source_evidence.py": (
                "filter_read_rows(", "authorized_read_page(", "authorize_coordinates(", "recheck_authority()"),
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
            "python.program.build", "python.program.run", "python.program.validate"},
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
    assignment_admission = {}
    for entry in registry["applicationFunctions"]:
        status = entry["groupAssignmentAdmission"]["status"]
        assignment_admission.setdefault(entry["family"], {}).setdefault(status, []).append(entry["function"])
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
        "groupAssignmentAdmissionByFamily": assignment_admission,
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
