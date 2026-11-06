#!/usr/bin/env python3
"""Build the Open EPM ASVS 5.0.0 control catalogue and disposition matrix."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path


ASVS_VERSION = "5.0.0"
ASVS_RELEASE = "v5.0.0_release"
ASVS_SOURCE_URL = (
    "https://github.com/OWASP/ASVS/releases/download/v5.0.0_release/"
    "OWASP_Application_Security_Verification_Standard_5.0.0_en.csv"
)
ASVS_SOURCE_SHA256 = "6124dba176dc563f66363a11ae0c47f9b86b8a4a84c66a793670bd196ed86cd5"


VERIFIED = {
    "V3.5.1": (
        "Browser effects enforce the exact configured origin before dispatch.",
        "tests/test_web_execution.py",
        "WebExecutionTests.test_every_post_route_has_outer_and_child_same_origin_protection",
    ),
    "V7.4.1": (
        "Logout deletes the server-side reference session and cross-tab reuse is rejected.",
        "tests/test_active_browser_session_lifecycle.py",
        "ActiveBrowserSessionLifecycleTests.test_qualifier_proves_rotation_logout_and_cross_tab_expiry",
    ),
    "V7.4.2": (
        "Reset or disable epoch changes invalidate previously issued browser identity.",
        "tests/test_web_execution.py",
        "WebExecutionTests.test_session_identity_fails_closed_after_reset_or_disable_epoch",
    ),
    "V8.2.1": (
        "Every public MCP catalogue operation resolves a current explicit permission.",
        "tests/test_mcp_universal_authorization_boundary.py",
        "McpUniversalAuthorizationBoundaryTests.test_every_catalog_contract_resolves_one_current_permission",
    ),
    "V8.3.1": (
        "The browser child delegates authorization to verified server identity methods.",
        "tests/test_platform_browser_execution.py",
        "PlatformBrowserExecutionTests.test_child_uses_identity_methods_for_catalog_read_and_write",
    ),
    "V8.3.2": (
        "Durable publishers retain the admission epoch and fail closed on stale human authority.",
        "tests/test_durable_publisher_session_authority.py",
        "DurablePublisherSessionAuthorityTests.test_every_non_job_publisher_has_epoch_kind_and_legacy_quarantine",
    ),
    "V9.1.1": (
        "Access tokens are accepted only after a valid asymmetric signature check.",
        "tests/test_postgres_oidc_auth.py",
        "OIDCAccessTests.test_signed_access_token_and_bearer_header",
    ),
    "V9.1.2": (
        "Unexpected token algorithms, including none, fail closed.",
        "tests/test_postgres_oidc_auth.py",
        "OIDCAccessTests.test_fail_closed_on_substitution_or_missing_login_identity",
    ),
    "V9.1.3": (
        "Caller-selected signing-key sources and token key URLs are rejected.",
        "tests/test_postgres_oidc_auth.py",
        "OIDCAccessTests.test_caller_supplied_jwks_never_triggers_network_rotation_fallback",
    ),
    "V9.2.1": (
        "Expired signed tokens fail closed.",
        "tests/test_postgres_oidc_auth.py",
        "OIDCAccessTests.test_fail_closed_on_substitution_or_missing_login_identity",
    ),
    "V9.2.2": (
        "Only access-token type assertions are accepted at the resource boundary.",
        "tests/test_postgres_oidc_auth.py",
        "OIDCAccessTests.test_fail_closed_on_substitution_or_missing_login_identity",
    ),
    "V9.2.3": (
        "Web and MCP audiences are distinct and cross-audience use is rejected.",
        "tests/test_postgres_oidc_auth.py",
        "OIDCAccessTests.test_web_gate_requires_distinct_web_audience",
    ),
    "V13.2.1": (
        "Portable service credentials are bounded to the identity bootstrap and platform adapters.",
        "tests/test_identity_release_contract.py",
        "IdentityReleaseContractTests.test_directory_credential_is_limited_to_bootstrap_and_platform",
    ),
    "V16.2.5": (
        "Security denial audit stores a program digest rather than the submitted program payload.",
        "tests/test_security_audit_inspection.py",
        "SecurityAuditInspectionContractTests.test_denial_recorder_hashes_the_program_before_storage",
    ),
    "V16.3.2": (
        "Denied privileged browser actions are audited without retaining program payloads.",
        "tests/test_web_execution.py",
        "WebExecutionTests.test_browser_privileged_denial_is_audited_without_program_payload",
    ),
    "V16.5.1": (
        "The public error envelope is stable, correlated, and excludes private exception detail.",
        "tests/test_web_execution.py",
        "WebExecutionTests.test_error_envelope_is_stable_safe_and_matches_response_correlation",
    ),
}

NO_MFA_FEATURE_CONTROLS = {
    "V6.4.4",
    "V6.5.1",
    "V6.5.2",
    "V6.5.3",
    "V6.5.4",
    "V6.5.5",
    "V6.5.6",
    "V6.5.7",
    "V6.6.1",
    "V6.6.2",
    "V6.6.3",
    "V6.6.4",
}


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def build(source: Path, catalogue_path: Path, matrix_path: Path) -> None:
    source_bytes = source.read_bytes()
    if hashlib.sha256(source_bytes).hexdigest() != ASVS_SOURCE_SHA256:
        raise SystemExit("official ASVS CSV digest does not match the pinned 5.0.0 release")
    rows = list(csv.DictReader(source_bytes.decode("utf-8-sig").splitlines()))
    required = {"chapter_id", "chapter_name", "section_id", "section_name", "req_id", "req_description", "L"}
    if not rows or not required.issubset(rows[0]):
        raise SystemExit("official ASVS CSV schema is not recognized")

    controls = []
    dispositions = []
    for row in rows:
        control_id = row["req_id"]
        controls.append(
            {
                "id": control_id,
                "chapterId": row["chapter_id"],
                "chapterName": row["chapter_name"],
                "sectionId": row["section_id"],
                "sectionName": row["section_name"],
                "level": int(row["L"]),
                "requirementSha256": _digest(row["req_description"]),
            }
        )
        base = {"id": control_id, "applicable": True}
        if control_id in VERIFIED:
            rationale, path, selector = VERIFIED[control_id]
            base.update(
                {
                    "disposition": "verified",
                    "rationale": rationale,
                    "evidence": [
                        {
                            "kind": "executable_test",
                            "path": path,
                            "selector": selector,
                        }
                    ],
                }
            )
        elif row["chapter_id"] == "V17":
            base.update(
                {
                    "applicable": False,
                    "disposition": "not_applicable",
                    "rationale": "Open EPM does not provide WebRTC signaling, media, peer connections, or data channels.",
                    "featureBoundary": "No WebRTC runtime, route, dependency, listener, or supported product journey is shipped.",
                }
            )
        elif control_id in NO_MFA_FEATURE_CONTROLS:
            base.update(
                {
                    "applicable": False,
                    "disposition": "not_applicable",
                    "rationale": "The settled release contract does not ship MFA, OTP, out-of-band, biometric, or lookup-secret factors.",
                    "featureBoundary": "Native username/password is the only supported interactive authentication factor for this release.",
                }
            )
        elif control_id == "V6.3.3":
            base.update(
                {
                    "disposition": "owner_policy_difference",
                    "rationale": "ASVS Level 2 calls for multiple factors or combined mechanisms; mandatory MFA is explicitly retired in the settled product contract.",
                    "ownerDecision": "Ship native Keycloak username/password, administrator-issued temporary passwords, and mandatory first-password change without mandatory MFA.",
                    "riskTreatment": "Record as an explicit release risk; retain rate limiting, password policy, session revocation, audit, least privilege, and trusted-administrator controls. Reconsider before an owner raises the assurance target.",
                }
            )
        else:
            base.update(
                {
                    "disposition": "deferred",
                    "rationale": "No complete executable final-artifact evidence is registered for this control yet.",
                    "releaseGate": "W4-ASVS evidence closure before enterprise UAT invitation",
                }
            )
        dispositions.append(base)

    if len(controls) != 345 or len({control["id"] for control in controls}) != 345:
        raise SystemExit("expected exactly 345 unique ASVS 5.0.0 controls")
    catalogue = {
        "schemaVersion": 1,
        "authority": {
            "name": "OWASP Application Security Verification Standard",
            "version": ASVS_VERSION,
            "release": ASVS_RELEASE,
            "sourceUrl": ASVS_SOURCE_URL,
            "sourceSha256": ASVS_SOURCE_SHA256,
            "license": "CC BY-SA 4.0",
        },
        "controlCount": len(controls),
        "controls": controls,
    }
    counts = {name: 0 for name in ("verified", "deferred", "not_applicable", "owner_policy_difference")}
    for disposition in dispositions:
        counts[disposition["disposition"]] += 1
    matrix = {
        "schemaVersion": 1,
        "title": "Open EPM OWASP ASVS 5.0.0 security verification matrix",
        "assuranceTarget": "ASVS Level 2 applicable-control review; this is not an ASVS compliance claim",
        "blanketComplianceClaimed": False,
        "cataloguePath": "docs/security/owasp-asvs-5.0.0-control-catalogue.json",
        "catalogueSha256": "GENERATED_AFTER_CATALOGUE_WRITE",
        "scope": {
            "included": ["browser gateway", "MCP and SDK APIs", "fixed Python core", "PostgreSQL authority", "Keycloak configuration", "workers", "portable deployment and operations"],
            "excludedFeatures": ["WebRTC", "mandatory MFA and OTP mechanisms"],
            "qualificationBoundary": "Source-level and local executable evidence only; final release artifacts, live networks, capacity, and owner UAT remain separate gates.",
        },
        "summary": {"total": len(dispositions), **counts},
        "controls": dispositions,
    }
    _write(catalogue_path, catalogue)
    matrix["catalogueSha256"] = hashlib.sha256(catalogue_path.read_bytes()).hexdigest()
    _write(matrix_path, matrix)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source_csv", type=Path)
    parser.add_argument("--catalogue", type=Path, default=Path("docs/security/owasp-asvs-5.0.0-control-catalogue.json"))
    parser.add_argument("--matrix", type=Path, default=Path("docs/security/owasp-asvs-5.0.0-openepm-matrix.json"))
    args = parser.parse_args()
    build(args.source_csv, args.catalogue, args.matrix)


if __name__ == "__main__":
    main()
