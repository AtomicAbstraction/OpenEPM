#!/usr/bin/env python3
"""Fail closed when a public snapshot contains excluded private/site material."""
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = (
    "PROJECT_INPUTS.md",
    "public-landing",
    "scripts/serve_landing_5186.sh",
    "scripts/implementation_graph",
    "docs/implementation-graph",
    "docs/ledger-maintenance",
    ".entire",
    ".codex",
    ".agents",
    ".aws",
    "deploy/macos-pilot/openepm-pilot.env",
)
FORBIDDEN_SUFFIXES = (".pem", ".key", ".credentials", ".secret")


def main() -> None:
    violations: list[str] = []
    for relative in FORBIDDEN:
        if (ROOT / relative).exists():
            violations.append(relative)
    for path in ROOT.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        relative = path.relative_to(ROOT).as_posix()
        name = path.name.lower()
        if name == ".env" or name in {"id_rsa", "id_ed25519"} \
                or name.endswith(FORBIDDEN_SUFFIXES):
            violations.append(relative)
    if violations:
        raise SystemExit("forbidden public-source paths: " + ", ".join(sorted(set(violations))))
    print("public source boundary verified")


if __name__ == "__main__":
    main()
