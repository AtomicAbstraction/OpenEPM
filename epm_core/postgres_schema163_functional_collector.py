"""Approved public/fixed-core adapter for schema-163 functional certificates.

The adapter coordinates existing qualification fixtures.  It performs only
read-only database identity/schema inspection; every business effect belongs
to an approved fixture running through application-language/MCP or fixed-core
interfaces in an explicitly owned disposable context.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any, Callable, Mapping

from .postgres_connection import connect_postgres
from .postgres_fresh_baseline import database_profile, schema_fingerprint
from .postgres_schema163_functional_parity import (
    DOMAINS, FORMAT, validate_certificate)


APPROVED_PROVENANCE = {
    "aggregateTechnicalJob": (
        "epm_core.cube_aggregate_public_qualification",
        "tests.qualify_cube_aggregate_final_fence"),
    "sourceImportExport": ("tests.transfer_orchestration_signed_mcp_fixture",),
    "ctaTypedEffects": ("tests.real_keycloak_mixed_method_close_fixture",),
    "forecastSchedule": ("tests.real_keycloak_p20_scheduled_forecast_fixture",),
    "pythonArtifactPaging": ("tests.real_keycloak_python_run_fixture",),
    "inventoryUnrealized": ("tests.real_keycloak_inventory_unrealized_fixture",),
    "recursiveRollup": ("tests.recursive_placement_signed_mcp_fixture",),
}
_SOURCE_COMMIT = re.compile(r"[0-9a-f]{40,64}\Z")


def _fail(code: str) -> None:
    raise ValueError(code)


@dataclass(frozen=True, slots=True)
class DisposableCollectorContext:
    dsn: str
    source_commit: str
    expected_schema_fingerprint: str
    workspace_id: str
    resource_owner_token: str
    service_context: Mapping[str, Any]
    disposable: bool = False
    shared_data: bool = True

    def validate(self) -> None:
        if (not isinstance(self.dsn, str) or not self.dsn
                or not _SOURCE_COMMIT.fullmatch(self.source_commit)
                or not re.fullmatch(r"[0-9a-f]{64}",
                                    self.expected_schema_fingerprint)
                or not isinstance(self.workspace_id, str)
                or not self.workspace_id.startswith("epm-disposable-")
                or not isinstance(self.resource_owner_token, str)
                or len(self.resource_owner_token) < 16
                or self.disposable is not True or self.shared_data is not False
                or not isinstance(self.service_context, Mapping)):
            _fail("SCHEMA163_COLLECTOR_CONTEXT_INVALID")
        required = {"mcpClient", "call", "program", "compose", "restart",
                    "workerControl", "identities", "applicationFactory"}
        if set(self.service_context) != required:
            _fail("SCHEMA163_COLLECTOR_SERVICE_CONTEXT_UNAVAILABLE")
        identities = self.service_context["identities"]
        if (not isinstance(identities, Mapping)
                or not {"operator", "author", "reader", "outsider"}
                    <= set(identities)):
            _fail("SCHEMA163_COLLECTOR_IDENTITIES_UNAVAILABLE")
        for name in required - {"identities"}:
            if not callable(self.service_context[name]):
                _fail("SCHEMA163_COLLECTOR_SERVICE_CONTEXT_UNAVAILABLE")


@dataclass(frozen=True, slots=True)
class ApprovedDomainAdapter:
    domain: str
    provenance: tuple[str, ...]
    collect: Callable[[DisposableCollectorContext], Mapping[str, Any]]

    def validate(self) -> None:
        if (self.domain not in APPROVED_PROVENANCE
                or self.provenance != APPROVED_PROVENANCE[self.domain]
                or not callable(self.collect)):
            _fail("SCHEMA163_COLLECTOR_ADAPTER_NOT_APPROVED")


def _read_binding(dsn: str) -> dict[str, str]:
    """Read exact database/environment identity without business effects."""
    with connect_postgres(dsn) as db:
        system_identifier = db.execute(
            "SELECT system_identifier::text FROM pg_control_system()"
        ).fetchone()[0]
        database = db.execute(
            "SELECT current_database(),oid::text FROM pg_database "
            "WHERE datname=current_database()"
        ).fetchone()
        profile, extensions = database_profile(db)
        fingerprint = schema_fingerprint(db)
    identity = hashlib.sha256(json.dumps({
        "systemIdentifier": system_identifier,
        "databaseName": database[0], "databaseOid": database[1],
    }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {"databaseIdentity": identity, "databaseName": database[0],
            "postgresProfile": profile, "extensionProfile": extensions,
            "schemaFingerprint": fingerprint}


def collect_certificate(context: DisposableCollectorContext,
                        adapters: tuple[ApprovedDomainAdapter, ...]) -> dict[str, Any]:
    """Run every approved fixture once and return the exact normalized certificate."""
    context.validate()
    if (not isinstance(adapters, tuple) or len(adapters) != len(DOMAINS)
            or tuple(adapter.domain for adapter in adapters) != DOMAINS):
        _fail("SCHEMA163_COLLECTOR_ADAPTER_SET_INVALID")
    for adapter in adapters:
        adapter.validate()
    binding = _read_binding(context.dsn)
    if not binding["databaseName"].startswith("epm_disposable_"):
        _fail("SCHEMA163_COLLECTOR_DATABASE_NOT_DISPOSABLE")
    if binding["schemaFingerprint"] != context.expected_schema_fingerprint:
        _fail("SCHEMA163_COLLECTOR_SCHEMA_FINGERPRINT_MISMATCH")
    domains: dict[str, Any] = {}
    for adapter in adapters:
        result = adapter.collect(context)
        if not isinstance(result, Mapping):
            _fail("SCHEMA163_COLLECTOR_DOMAIN_RESULT_INVALID")
        domains[adapter.domain] = dict(result)
    certificate = {"format": FORMAT, "activationAuthorized": False,
        "databaseIdentity": binding["databaseIdentity"],
        "sourceCommit": context.source_commit,
        "schemaFingerprint": binding["schemaFingerprint"],
        "postgresProfile": binding["postgresProfile"],
        "extensionProfile": binding["extensionProfile"],
        "domains": domains}
    return validate_certificate(certificate)
