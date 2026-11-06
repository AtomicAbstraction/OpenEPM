#!/usr/bin/env python3
"""Bind the disposable generic-FP&A journey to the exact Mac pilot images.

This wrapper never connects to the live pilot or accepts a database DSN.  It
delegates to the established real-OIDC qualifier, which owns and removes its
own Compose project, Keycloak provider, credentials, database, and applications.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVIDENCE = (ROOT / "docs" / "qualifications" /
                    "local-mac-pilot-bootstrap-2026-10-30.json")
QUALIFIER = ROOT / "tests" / "qualify_postgres_real_oidc.py"
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")


class CandidateError(ValueError):
    pass


def load_candidate(path: Path) -> dict:
    try:
        evidence = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CandidateError(f"invalid pilot evidence: {error}") from error
    if not isinstance(evidence, dict) \
            or evidence.get("format") != "openepm-local-mac-pilot-bootstrap-v1" \
            or evidence.get("status") != "verified-for-bootstrap-scope":
        raise CandidateError("pilot evidence is not a verified bootstrap record")
    images = evidence.get("images")
    if not isinstance(images, dict):
        raise CandidateError("pilot evidence has no image identities")
    application = images.get("application")
    database = images.get("database")
    if not isinstance(application, str) or IMAGE_ID.fullmatch(application) is None \
            or not isinstance(database, str) or IMAGE_ID.fullmatch(database) is None:
        raise CandidateError("pilot evidence image identities are not exact digests")
    if images.get("applicationSourceLabelsMatch") is not True \
            or images.get("runtimeRetirementChecksPassed") is not True \
            or images.get("applicationInterpreterCacheFiles") != 0:
        raise CandidateError("pilot images have not passed source/runtime gates")
    return {"application": application, "database": database,
            "architecture": images.get("architecture"),
            "runtimeCommit": evidence.get("source", {}).get("runtimeCommit")}


def command(candidate: dict, output: Path) -> list[str]:
    if not output.is_absolute():
        raise CandidateError("qualification output must be an absolute path")
    return [sys.executable, str(QUALIFIER), "--output", str(output)]


def environment(candidate: dict) -> dict[str, str]:
    values = os.environ.copy()
    values.update({
        "EPM_TEST_REAL_OIDC_DISPOSABLE": "1",
        "EPM_TEST_REAL_OIDC_P20_GENERIC": "1",
        "EPM_TEST_REAL_OIDC_APPLICATION_IMAGE": candidate["application"],
        "EPM_TEST_REAL_OIDC_DATABASE_IMAGE": candidate["database"],
    })
    return values


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--execute", action="store_true",
                        help="run the isolated Docker/Keycloak qualification")
    arguments = parser.parse_args()
    try:
        candidate = load_candidate(arguments.evidence.resolve())
        invocation = command(candidate, arguments.output)
    except CandidateError as error:
        parser.error(str(error))
    plan = {"format": "openepm-macos-pilot-candidate-plan-v1",
            "livePilotMutation": False, "disposable": True,
            "journey": "generic-fpna-real-oidc",
            "applicationImage": candidate["application"],
            "databaseImage": candidate["database"],
            "architecture": candidate["architecture"],
            "runtimeCommit": candidate["runtimeCommit"],
            "output": str(arguments.output)}
    if not arguments.execute:
        print(json.dumps(plan, sort_keys=True))
        return 0
    completed = subprocess.run(invocation, cwd=ROOT,
                               env=environment(candidate), check=False)
    if completed.returncode:
        raise SystemExit(completed.returncode)
    print(json.dumps({**plan, "executed": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
