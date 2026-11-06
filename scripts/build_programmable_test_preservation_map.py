#!/usr/bin/env python3
"""Build the V00 test/fixture preservation inventory."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
OUTPUT = ROOT / "docs" / "qualifications" / "programmable-test-preservation-map-2026-11-02.json"
DOMAIN = ("planning", "forecast", "consolidation", "currency", "ownership", "nci", "cta", "intercompany", "goodwill", "acquisition", "disposal", "journal", "close")
INVARIANTS = {
    "authorization": ("authorization", "permission", "grant", "rls", "security"),
    "exactness": ("exact", "decimal", "round", "zero", "absence", "missing"),
    "idempotency": ("idempot", "replay", "duplicate"),
    "concurrency": ("concurr", "stale", "lock", "lease", "fence"),
    "recovery": ("recover", "restart", "restore", "rollback", "interrupt"),
    "lineage": ("lineage", "receipt", "provenance", "history"),
    "isolation": ("isolation", "cross_application", "cross-application", "scope"),
    "performance": ("capacity", "benchmark", "performance", "latency", "scale"),
}
CORE = re.compile(r"(?:from|import)\s+epm_core(?:\.([a-zA-Z0-9_]+))?")


def build() -> dict:
    files = sorted(path for path in TESTS.glob("*.py") if path.is_file())
    rows = []
    for path in files:
        text = path.read_text(encoding="utf-8")
        lowered = text.lower()
        terms = [term for term in DOMAIN if term in lowered or term in path.name.lower()]
        invariants = [
            name for name, needles in INVARIANTS.items()
            if any(needle in lowered for needle in needles)
        ]
        modules = sorted({match.group(1) or "__init__" for match in CORE.finditer(text)})
        kind = (
            "qualification_fixture" if path.name.startswith("qualify_")
            else "shared_fixture" if "fixture" in path.name
            else "unit_or_integration_test"
        )
        rows.append({
            "path": path.relative_to(ROOT).as_posix(),
            "kind": kind,
            "domainTerms": terms,
            "protectedInvariants": invariants,
            "directCoreImports": modules,
            "preservation": "retain_until_replacement_gate",
        })
    digest = sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "format": "openepm-programmable-test-preservation-map-v1",
        "fileCount": len(rows),
        "domainNamedFileCount": sum(bool(row["domainTerms"]) for row in rows),
        "fixtureCount": sum(row["kind"] != "unit_or_integration_test" for row in rows),
        "preservationMapDigest": digest,
        "files": rows,
        "policy": {
            "default": "preserve",
            "retirementGate": "generic replacement proves equivalent invariant coverage and historical fixtures remain readable",
            "classificationIsDeletionAuthority": False,
        },
    }


def main() -> None:
    OUTPUT.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
