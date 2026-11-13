"""Strict raw-result adapters for public schema-163 parity qualification."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Callable, Mapping

from .postgres_schema163_functional_collector import (
    APPROVED_PROVENANCE, ApprovedDomainAdapter, DisposableCollectorContext,
)


def _fail(code: str) -> None:
    raise ValueError(code)


def python_artifact_adapter(executor: Callable[
        [DisposableCollectorContext], Mapping[str, Any]]) -> ApprovedDomainAdapter:
    """Bind the real signed-MCP Python fixture result to its certificate."""
    if not callable(executor):
        _fail("SCHEMA163_PYTHON_PUBLIC_EXECUTOR_INVALID")

    def collect(context: DisposableCollectorContext) -> Mapping[str, Any]:
        raw = executor(context)
        if not isinstance(raw, Mapping):
            _fail("SCHEMA163_PYTHON_PUBLIC_RESULT_INVALID")
        required = {"artifactSectionsReadPublicly", "artifactPageReplayStable",
            "sourceDigestBound", "artifactIdenticalAfterRestart",
            "outsiderDeniedBuildArtifactCancelAndRun",
            "acceptedBuildCancellationNoEffect", "planSectionDigest",
            "sourceMapDigest", "buildLogDigest", "functionalCertificateDomain"}
        if not required <= set(raw):
            _fail("SCHEMA163_PYTHON_PUBLIC_RESULT_INCOMPLETE")
        section_digests = {"Plan": raw["planSectionDigest"],
            "SourceMap": raw["sourceMapDigest"],
            "BuildLog": raw["buildLogDigest"]}
        digest = hashlib.sha256(json.dumps(section_digests, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        derived = {"sections": raw["artifactSectionsReadPublicly"],
            "pageReplayStable": raw["artifactPageReplayStable"],
            "sourceDigestBound": raw["sourceDigestBound"],
            "restartIdentical": raw["artifactIdenticalAfterRestart"],
            "outsiderDenied": (
                sorted(raw["outsiderDeniedBuildArtifactCancelAndRun"]) == sorted([
                    "read_v2_python_program_build",
                    "read_v2_python_program_build_artifact",
                    "cancel_v2_python_program_build",
                    "execute_v2_python_program_run"])),
            "cancelledBuildNoArtifact": raw["acceptedBuildCancellationNoEffect"],
            "artifactDigest": digest}
        if dict(raw["functionalCertificateDomain"]) != derived:
            _fail("SCHEMA163_PYTHON_PUBLIC_CERTIFICATE_DERIVATION_MISMATCH")
        return derived

    return ApprovedDomainAdapter("pythonArtifactPaging",
        APPROVED_PROVENANCE["pythonArtifactPaging"], collect)


def transfer_adapter(executor: Callable[
        [DisposableCollectorContext], Mapping[str, Any]]) -> ApprovedDomainAdapter:
    """Bind exact public transfer observations without inventing values."""
    if not callable(executor):
        _fail("SCHEMA163_TRANSFER_PUBLIC_EXECUTOR_INVALID")

    def collect(context: DisposableCollectorContext) -> Mapping[str, Any]:
        raw = executor(context)
        if (not isinstance(raw, Mapping)
                or not {"applicationId", "exportManifestDigest", "exportManifest",
                        "exportedRows", "checks",
                        "functionalCertificateDomain"} <= set(raw)):
            _fail("SCHEMA163_TRANSFER_PUBLIC_RESULT_INCOMPLETE")
        domain = dict(raw["functionalCertificateDomain"])
        checks = raw["checks"]
        bindings = {
            "zeroPresent": checks.get("zeroEmptyTextAndDetailPreserved"),
            "missingAbsent": checks.get("exactScopeReplacement"),
            "replaySameReceipt": checks.get("workerReplayAfterLostAck"),
            "snapshotStable": checks.get("laterWriteExcludedFromAcceptedSnapshot"),
            "resumeNoDuplicate": (checks.get("publicMultiChunkSourceRestartResume")
                                  and checks.get("sourcePublishReplayNoDuplicate")),
            "finalFenceRejectsStale": checks.get("staleExportWorkerFenced"),
        }
        from .export_artifact_manifest import export_artifact_manifest_matches
        from .persistence_contract import ApplicationScope
        manifest = raw["exportManifest"]
        rows = raw["exportedRows"]
        expected_scope = (ApplicationScope(context.workspace_id,
            raw["applicationId"])
            if isinstance(context, DisposableCollectorContext) else None)
        if (not export_artifact_manifest_matches(manifest, scope=expected_scope)
                or manifest.get("manifestDigest") != raw["exportManifestDigest"]
                or not isinstance(rows, list)):
            _fail("SCHEMA163_TRANSFER_PUBLIC_RESULT_INCOMPLETE")
        # The product manifest intentionally binds workspace and expiry, so its
        # raw cryptographic digest must differ across independent deployments.
        # Derive parity from the publicly read rows plus stable manifest shape,
        # while still validating the exact raw digest above inside each run.
        stable_pages = [{key: page[key] for key in (
            "pageIndex", "rowCount", "rowBytes", "typeCounts", "firstKey",
            "lastKey", "hasMore")} for page in manifest["pages"]]
        semantic_manifest = {key: manifest[key] for key in (
            "contractVersion", "status", "schema", "snapshotRevision",
            "metadataRevision", "limits", "pageCount", "totalRowCount",
            "totalRowBytes", "typeCounts")}
        semantic_manifest["pages"] = stable_pages
        semantic_manifest["rows"] = rows
        semantic_digest = hashlib.sha256(json.dumps(semantic_manifest,
            sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if (any(domain.get(key) is not value for key, value in bindings.items())
                or domain.get("manifestDigest") != raw["exportManifestDigest"]):
            _fail("SCHEMA163_TRANSFER_PUBLIC_CERTIFICATE_DERIVATION_MISMATCH")
        return {**domain, "manifestDigest": semantic_digest}

    return ApprovedDomainAdapter("sourceImportExport",
        APPROVED_PROVENANCE["sourceImportExport"], collect)


def recursive_rollup_adapter(executor: Callable[
        [DisposableCollectorContext], Mapping[str, Any]]) -> ApprovedDomainAdapter:
    if not callable(executor):
        _fail("SCHEMA163_ROLLUP_PUBLIC_EXECUTOR_INVALID")

    def collect(context: DisposableCollectorContext) -> Mapping[str, Any]:
        raw = executor(context)
        if (not isinstance(raw, Mapping) or not {
                "repeatedPlacementAmount", "relationshipDeactivationStaledAcceptedJob",
                "functionalCertificateLineage", "functionalCertificateDomain"} <= set(raw)):
            _fail("SCHEMA163_ROLLUP_PUBLIC_RESULT_INCOMPLETE")
        lineage = raw["functionalCertificateLineage"]
        digest = hashlib.sha256(json.dumps(lineage, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        domain = dict(raw["functionalCertificateDomain"] or {})
        derived = {"sharedLeafContributionCount": len(lineage),
            "pathCount": len({row.get("pathId") for row in lineage}),
            "sum": raw["repeatedPlacementAmount"],
            "zeroCounted": domain.get("zeroCounted"),
            "missingExcluded": domain.get("missingExcluded"),
            "lineagePathDistinct": len({row.get("pathId") for row in lineage}) == len(lineage),
            "stalePathRejected": raw["relationshipDeactivationStaledAcceptedJob"],
            "lineageDigest": digest}
        if (domain != derived or derived["zeroCounted"] is not True
                or derived["missingExcluded"] is not True):
            _fail("SCHEMA163_ROLLUP_PUBLIC_CERTIFICATE_DERIVATION_MISMATCH")
        return derived

    return ApprovedDomainAdapter("recursiveRollup",
        APPROVED_PROVENANCE["recursiveRollup"], collect)


def aggregate_adapter(executor: Callable[
        [DisposableCollectorContext], Mapping[str, Any]]) -> ApprovedDomainAdapter:
    if not callable(executor):
        _fail("SCHEMA163_AGGREGATE_PUBLIC_EXECUTOR_INVALID")

    def collect(context: DisposableCollectorContext) -> Mapping[str, Any]:
        raw = executor(context)
        if not isinstance(raw, Mapping):
            _fail("SCHEMA163_AGGREGATE_PUBLIC_RESULT_INCOMPLETE")
        evidence = raw.get("aggregateFunctionalCertificateEvidence")
        domain = raw.get("aggregateFunctionalCertificateDomain")
        if not isinstance(evidence, Mapping) or not isinstance(domain, Mapping):
            _fail("SCHEMA163_AGGREGATE_PUBLIC_RESULT_INCOMPLETE")
        rows = evidence.get("rows")
        if not isinstance(rows, list) or len(rows) != 1:
            _fail("SCHEMA163_AGGREGATE_PUBLIC_RESULT_INCOMPLETE")
        row = rows[0]
        derived = {"sum": row.get("sumAmount"),
            "countPresent": row.get("countPresent"),
            "zeroCounted": domain.get("zeroCounted"),
            "missingExcluded": domain.get("missingExcluded"),
            "businessRevisionDelta": evidence.get("dataRevisionAfter")-
                evidence.get("dataRevisionBefore"),
            "stablePageDigest": hashlib.sha256(json.dumps(rows,
                sort_keys=True,separators=(",", ":")).encode()).hexdigest(),
            "cancelledResultAbsent": evidence.get("cancelStatus") == "cancelled"
                and evidence.get("cancelReadStatus") == "cancelled"
                and not evidence.get("cancelReadRows"),
            "outsiderDenied": evidence.get("outsiderDenied") is True}
        if dict(domain) != derived or derived["zeroCounted"] is not True \
                or derived["missingExcluded"] is not True:
            _fail("SCHEMA163_AGGREGATE_PUBLIC_CERTIFICATE_DERIVATION_MISMATCH")
        return derived

    return ApprovedDomainAdapter("aggregateTechnicalJob",
        APPROVED_PROVENANCE["aggregateTechnicalJob"], collect)


def cta_adapter(executor: Callable[
        [DisposableCollectorContext], Mapping[str, Any]]) -> ApprovedDomainAdapter:
    if not callable(executor):
        _fail("SCHEMA163_CTA_PUBLIC_EXECUTOR_INVALID")
    def collect(context: DisposableCollectorContext) -> Mapping[str, Any]:
        raw=executor(context);evidence=raw.get("ctaFunctionalCertificateEvidence")
        domain=raw.get("ctaFunctionalCertificateDomain")
        if not isinstance(evidence,Mapping) or not isinstance(domain,Mapping):
            _fail("SCHEMA163_CTA_PUBLIC_RESULT_INCOMPLETE")
        effects=evidence.get("effects")
        if not isinstance(effects,list):_fail("SCHEMA163_CTA_PUBLIC_RESULT_INCOMPLETE")
        from decimal import Decimal
        derived={"compilerVersion":"cta-bridge-v"+
          str(evidence.get("bridgeVersion"))+"-typed-unit",
          "typedEffectCount":len(effects),
          "balance":format(sum(Decimal(str(row.get("amount"))) for row in effects),'.8f'),
          "untypedJournalAbsent":evidence.get("untypedJournalAbsent"),
          "lineageComplete":all(row.get("sourceRef") for row in effects),
          "staleSourceRejected":raw.get("negativeCases",{}).get("staleSourceDenied"),
          "readerDenied":raw.get("negativeCases",{}).get("revokedGrantDenied")}
        if dict(domain)!=derived:_fail("SCHEMA163_CTA_PUBLIC_CERTIFICATE_DERIVATION_MISMATCH")
        return derived
    return ApprovedDomainAdapter("ctaTypedEffects",
      APPROVED_PROVENANCE["ctaTypedEffects"],collect)


def inventory_adapter(executor: Callable[
        [DisposableCollectorContext], Mapping[str, Any]]) -> ApprovedDomainAdapter:
    if not callable(executor):_fail("SCHEMA163_INVENTORY_PUBLIC_EXECUTOR_INVALID")
    def collect(context: DisposableCollectorContext) -> Mapping[str, Any]:
        raw=executor(context);evidence=raw.get("inventoryFunctionalCertificateEvidence")
        domain=raw.get("inventoryFunctionalCertificateDomain")
        if not isinstance(evidence,Mapping) or not isinstance(domain,Mapping):
            _fail("SCHEMA163_INVENTORY_PUBLIC_RESULT_INCOMPLETE")
        rows=evidence.get("rows")
        if not isinstance(rows,list):_fail("SCHEMA163_INVENTORY_PUBLIC_RESULT_INCOMPLETE")
        from decimal import Decimal
        amounts={row.get("role"):Decimal(str(row.get("amount"))) for row in rows}
        balance=(amounts.get("Opening",Decimal(0))+
          amounts.get("Creation",Decimal(0))+amounts.get("Release",Decimal(0))-
          amounts.get("Closing",Decimal(0)))
        derived={"roles":[row.get("role") for row in rows],"rowCount":len(rows),
          "balance":format(balance,'.8f'),
          "legacyLineForbidden":evidence.get("effects")=="CalculatedGenerationOnly",
          "sourceLineageComplete":bool(evidence.get("sourceLookupLineage")),
          "scheduleVersionPinned":evidence.get("scheduleVersion")==1,
          "stalePointerRejected":domain.get("stalePointerRejected")}
        if dict(domain)!=derived or derived["stalePointerRejected"] is not True:
            _fail("SCHEMA163_INVENTORY_PUBLIC_CERTIFICATE_DERIVATION_MISMATCH")
        return derived
    return ApprovedDomainAdapter("inventoryUnrealized",
      APPROVED_PROVENANCE["inventoryUnrealized"],collect)
