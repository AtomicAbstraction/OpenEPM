#!/usr/bin/env python3
"""Fail a shipped runtime that depends on Codex or author-side paths."""
from __future__ import annotations

import argparse
import ast
from pathlib import Path
import re


class RuntimeIndependenceError(ValueError):
    pass


FORBIDDEN_IMPORTS = ("codex",)
FORBIDDEN_PATHS = (".codex", "AICOmpanies")
AUTHOR_PATH = re.compile(r"/(?:Users|home)/[^/]+/(?:\.codex|.*AICOmpanies)")
RUNTIME_SCRIPTS = (
    "operator_import_path.py", "apply_postgres_migrations.py",
    "initialize_postgres_release.py", "initialize_schema163_public_parity.py",
    "bootstrap_postgres_operator.py", "bootstrap_postgres_service_roles.py",
    "bootstrap_postgres_python_coordinator.py", "check_postgres_mcp_health.py",
    "check_postgres_worker_health.py", "serve_openepm_postgres_worker.py",
    "serve_openepm_python_build_broker.py", "serve_openepm_sandbox_launcher.py",
)


def _runtime_python(root: Path) -> list[Path]:
    files = list((root / "epm_core").glob("*.py"))
    files.extend((root / "openepm").glob("*.py"))
    files.extend(root.glob("platform_postgres*.py"))
    files.extend(root / "scripts" / name for name in RUNTIME_SCRIPTS)
    return sorted(path for path in files if path.is_file())


def check(root: Path) -> dict:
    required = [
        root / "epm_core",
        root / "platform_postgres_router_mcp_server.py",
        root / "docs" / "skills" / "multidimensional-cube-harness" / "SKILL.md",
    ]
    missing = [str(path.relative_to(root)) for path in required if not path.exists()]
    if missing:
        raise RuntimeIndependenceError("missing shipped runtime paths: " + ", ".join(missing))
    checked = []
    violations = []
    for path in _runtime_python(root):
        relative = str(path.relative_to(root))
        try:
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=relative)
        except (OSError, UnicodeError, SyntaxError) as error:
            raise RuntimeIndependenceError(f"cannot inspect {relative}: {error}") from error
        checked.append(relative)
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [item.name for item in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if name.split(".", 1)[0].lower() in FORBIDDEN_IMPORTS:
                    violations.append(relative + ": imports " + name)
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                if AUTHOR_PATH.search(value) or any(
                        token in Path(value).parts for token in FORBIDDEN_PATHS):
                    violations.append(relative + ": author/runtime path dependency")
    if violations:
        raise RuntimeIndependenceError("; ".join(sorted(set(violations))))
    return {"format": "openepm-runtime-independence-v1", "status": "pass",
            "pythonFilesChecked": len(checked), "requiredPaths": [
                str(path.relative_to(root)) for path in required]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    arguments = parser.parse_args()
    print(check(arguments.root.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
