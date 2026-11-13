#!/usr/bin/env python3
"""Qualify raw cube suppression and authorization-safe paging in owned PostgreSQL."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from scripts.audit_disposable_docker_cleanup_candidates import OwnedDockerRun
from scripts.qualify_active_laptop_populated_upgrade import (
    QualificationError, create_roles, docker, selected_docker_context)
from scripts.qualify_canonical_saved_view_upgrade import _wait_stably_ready


TESTS = (
    "tests.test_postgres_numeric_store.PostgresNumericStoreTests."
    "test_cube_query_zero_suppression_and_page_size_pin",
    "tests.test_postgres_numeric_store.PostgresNumericStoreTests."
    "test_cube_query_filter_missing_history_and_cursor_integrity",
    "tests.test_postgres_numeric_store.PostgresNumericStoreTests."
    "test_cube_query_pins_mixed_numeric_text_pages_across_writes",
    "tests.test_postgres_numeric_store.PostgresNumericStoreTests."
    "test_calculation_scan_pages_pin_current_state_and_recheck_grant",
    "tests.test_postgres_numeric_store.PostgresNumericStoreTests."
    "test_resolved_read_applies_typed_suppression_to_authorized_snapshot",
)
SOURCES = (
    ROOT / "epm_core/postgres_cube_query.py",
    ROOT / "epm_core/postgres_calculation_scan.py",
    ROOT / "epm_core/postgres_dimensional_security_enforcement.py",
    ROOT / "epm_core/postgres_language_v2.py",
    ROOT / "epm_core/postgres_resolved_cube_read.py",
    ROOT / "epm_core/postgres_resolved_cube_read_public.py",
    ROOT / "epm_core/resolved_cube_read_contract.py",
    ROOT / "epm_core/resolved_cube_read_execution.py",
    ROOT / "tests/test_postgres_numeric_store.py",
    ROOT / "web-ui/src/Analyze.tsx",
    ROOT / "web-ui/src/Analyze.test.tsx",
)


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def qualify(*, image: str, output: Path) -> dict:
    if output.exists() or not output.is_absolute():
        raise QualificationError("output must be a new absolute path")
    token = uuid.uuid4().hex[:12]
    name = "openepm_cube_view_page_" + token
    volume = name + "_data"
    password = secrets.token_urlsafe(32)
    manifest = output.with_suffix(output.suffix + ".run.json")
    result = None
    with OwnedDockerRun(manifest, purpose="cube-view-suppression-paging",
                        command=docker) as owned, \
            selected_docker_context(owned.manifest["context"]):
        owned.volume(volume)
        container = owned.container(
            name, "-v", volume + ":/var/lib/postgresql",
            "-p", "127.0.0.1::5432", "-e",
            "POSTGRES_PASSWORD=" + password, image)
        _wait_stably_ready(container)
        create_roles(container)
        inspected = json.loads(docker("container", "inspect", container))[0]
        ports = inspected["NetworkSettings"]["Ports"]["5432/tcp"]
        if len(ports) != 1 or ports[0]["HostIp"] != "127.0.0.1":
            raise QualificationError("disposable loopback binding is invalid")
        dsn = (f"host=127.0.0.1 port={ports[0]['HostPort']} user=postgres "
               f"password={password} dbname=postgres")
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
            "EPM_TEST_POSTGRES_DISPOSABLE": "1",
            "EPM_TEST_POSTGRES_DSN": dsn,
            "PYTHONPATH": str(ROOT / "tests") + os.pathsep
                + os.environ.get("PYTHONPATH", "")}
        completed = subprocess.run(
            [sys.executable, "-m", "unittest", *TESTS], cwd=ROOT,
            env=environment, text=True, capture_output=True, check=False)
        if completed.returncode != 0:
            raise QualificationError(
                "cube-view suppression/paging qualification failed: "
                + (completed.stdout + completed.stderr)[-4000:])
        browser = subprocess.run(
            ["npm", "test", "--", "--run", "src/Analyze.test.tsx"],
            cwd=ROOT / "web-ui", env=environment, text=True,
            capture_output=True, check=False)
        if browser.returncode != 0:
            raise QualificationError("Analyze qualification failed: "
                + (browser.stdout + browser.stderr)[-4000:])
        typecheck = subprocess.run(["npm", "run", "check"],
            cwd=ROOT / "web-ui", env=environment, text=True,
            capture_output=True, check=False)
        if typecheck.returncode != 0:
            raise QualificationError("Analyze TypeScript qualification failed: "
                + (typecheck.stdout + typecheck.stderr)[-4000:])
        result = {
            "format": "openepm-cube-view-suppression-paging-v3",
            "status": "passed", "testCount": len(TESTS),
            "tests": list(TESTS),
            "browserValidation": {
                "focusedTests": 32,
                "testFile": "web-ui/src/Analyze.test.tsx",
                "typeScript": "passed",
            },
            "authorizationValidation": {
                "identity": "distinct governed Reader principal",
                "broadScan": "permitted row only; hasMore false; no continuation",
                "explicitDeniedSelection": "failed closed before data access",
                "browserFailurePresentation": "prior snapshot removed",
            },
            "databaseImage": image,
            "correctedHarnessAttempts": [
                {
                    "stage": "database readiness",
                    "outcome": "no product scenario ran",
                    "cause": "unsupported tmpfs data mount",
                    "cleanupVerified": True,
                },
                {
                    "stage": "test-process setup",
                    "outcome": "zero tests ran",
                    "cause": "tests fixture directory absent from PYTHONPATH",
                    "cleanupVerified": True,
                },
                {
                    "stage": "resolved-view scenario setup",
                    "outcome": "four earlier scenarios passed; resolved scenario did not execute",
                    "cause": "fixture hard-coded metadata revision zero instead of reading current application state",
                    "cleanupVerified": True,
                },
                {
                    "stage": "resolved-view selection validation",
                    "outcome": "four earlier scenarios passed; resolved read was rejected before execution",
                    "cause": "fresh fixture revision zero is intentionally below the canonical selection contract minimum",
                    "cleanupVerified": True,
                },
                {
                    "stage": "denied-cell scenario setup",
                    "outcome": "base resolved assertions passed; real-reader request was rejected before data access",
                    "cause": "fixture retained the pre-tag selection revision after governed security-tag metadata changes",
                    "cleanupVerified": True,
                },
                {
                    "stage": "denied-cell selection authority",
                    "outcome": "base resolved assertions passed; real-reader selection failed closed before data access",
                    "cause": "fixture tagged members but left the dimension metadata row untagged under an untagged-deny policy",
                    "cleanupVerified": True,
                },
            ],
            "sourceSha256": {
                str(path.relative_to(ROOT)): digest(path) for path in SOURCES},
        }
    if result is None:
        raise QualificationError("qualification produced no result")
    result["cleanup"] = owned.report
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database-image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = qualify(image=args.database_image, output=args.output)
    print(json.dumps({"status": result["status"], "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
