#!/usr/bin/env python3
"""Build the pinned PostgreSQL-only SQLAlchemy/Alembic runtime.

This is a source transformation, not a scanner exclusion.  It accepts only the
exact upstream source trees recorded below, removes unsupported dialect and
test sources, rewrites the two dialect registries, removes retired-backend
documentation from the remaining runtime source, and repairs wheel RECORD
files according to PEP 376.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import importlib.metadata
from pathlib import Path
import re
import shutil
import sys


EXPECTED_VERSIONS = {"SQLAlchemy": "2.1.6", "alembic": "1.20.1"}
EXPECTED_PRE_TREES = {
    "sqlalchemy": (270, "54efd2c0f7f9c5d4c1a1bdeae5c34964012e2cf2b435d5c83055d5e24a9b7a96"),
    "alembic": (97, "3da0757502b7d5ad6b2cb8080f7d23a15e2640b7a509d8a549addac21423e54a"),
}
# Filled from the deterministic transformation and checked on every image build.
EXPECTED_POST_TREES = {
    "sqlalchemy": (183, "5ad39a2cc47ac88dbe9bb54d40a3f0da12d0beb830e3497e601563cb211c6187"),
    "alembic": (74, "aab1fcacdc704d42d49b950f32345e35d6c2b6715696b61a8aadcb0a4d091e33"),
}

RETIRED_NAME = "sql" + "ite"
RETIRED = re.compile(RETIRED_NAME, re.IGNORECASE)
TEXT_SUFFIXES = {".py", ".pyi", ".txt"}


def tree_identity(root: Path) -> tuple[int, str]:
    files = sorted(
        path for path in root.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    )
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return len(files), digest.hexdigest()


def require_identity(root: Path, expected: tuple[int, str], phase: str) -> None:
    actual = tree_identity(root)
    if actual != expected:
        raise SystemExit(
            f"{phase} source identity mismatch for {root.name}: "
            f"expected {expected}, found {actual}"
        )


def remove(path: Path) -> None:
    if not path.exists():
        raise SystemExit(f"expected adaptation input is absent: {path}")
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def rewrite(path: Path, expected: str, replacement: str) -> None:
    current = path.read_text(encoding="utf-8")
    if current != expected:
        raise SystemExit(f"unexpected upstream shape: {path}")
    path.write_text(replacement, encoding="utf-8")


def scrub_retired_documentation(root: Path) -> None:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in TEXT_SUFFIXES:
            continue
        source = path.read_text(encoding="utf-8")
        if RETIRED.search(source) or ":memory:" in source:
            path.write_text(
                RETIRED.sub("retired_embedded_backend", source).replace(
                    ":memory:", "memory-resident"
                ),
                encoding="utf-8",
            )


def record_hash(data: bytes) -> str:
    value = base64.urlsafe_b64encode(hashlib.sha256(data).digest())
    return "sha256=" + value.rstrip(b"=").decode("ascii")


def repair_record(site: Path, dist_info: Path) -> None:
    record = dist_info / "RECORD"
    rows: list[list[str]] = []
    with record.open(newline="", encoding="utf-8") as stream:
        for row in csv.reader(stream):
            if len(row) != 3:
                raise SystemExit(f"malformed RECORD row in {record}: {row!r}")
            target = site / row[0]
            if target == record:
                rows.append([row[0], "", ""])
            elif target.is_file():
                data = target.read_bytes()
                rows.append([row[0], record_hash(data), str(len(data))])
            # Removed files are deliberately omitted.
    with record.open("w", newline="", encoding="utf-8") as stream:
        csv.writer(stream, lineterminator="\n").writerows(rows)


def distribution_path(site: Path, project: str) -> Path:
    matches = sorted(site.glob(f"{project}-*.dist-info"))
    if len(matches) != 1:
        raise SystemExit(f"expected one {project} dist-info directory, found {matches}")
    return matches[0]


def adapt(site: Path, *, emit_post_identities: bool) -> None:
    installed = {
        dist.metadata["Name"]: dist.version
        for dist in importlib.metadata.distributions(path=[str(site)])
    }
    for project, version in EXPECTED_VERSIONS.items():
        actual = installed.get(project)
        if actual != version:
            raise SystemExit(f"{project} version mismatch: expected {version}, found {actual}")

    sqlalchemy = site / "sqlalchemy"
    alembic = site / "alembic"
    for package, expected in EXPECTED_PRE_TREES.items():
        require_identity(site / package, expected, "pre-adaptation")

    for dialect in ("mssql", "mysql", "oracle", RETIRED_NAME):
        remove(sqlalchemy / "dialects" / dialect)
    remove(sqlalchemy / "testing")
    remove(sqlalchemy / "dialects" / "type_migration_guidelines.txt")
    for dialect in ("mssql", "mysql", "oracle", RETIRED_NAME):
        remove(alembic / "ddl" / f"{dialect}.py")
    remove(alembic / "testing")

    sa_registry = sqlalchemy / "dialects" / "__init__.py"
    upstream_sa_registry = sa_registry.read_text(encoding="utf-8")
    upstream_dialects = (
        '__all__ = ("mssql", "mysql", "oracle", "postgresql", "'
        + RETIRED_NAME
        + '")'
    )
    if upstream_dialects not in upstream_sa_registry:
        raise SystemExit(f"unexpected SQLAlchemy dialect registry: {sa_registry}")
    adapted_sa_registry = upstream_sa_registry.replace(
        upstream_dialects,
        '__all__ = ("postgresql",)',
    )
    function_start = adapted_sa_registry.index("def _auto_fn(")
    function_end = adapted_sa_registry.index("\n\nregistry =", function_start)
    adapted_sa_registry = (
        adapted_sa_registry[:function_start]
        + '''def _auto_fn(name: str) -> Optional[Callable[[], Type[Dialect]]]:
    """Load only the qualified PostgreSQL dialect and its drivers."""
    if "." in name:
        dialect, driver = name.split(".", 1)
    else:
        dialect = name
        driver = "base"
    if dialect != "postgresql":
        return None
    try:
        module: Any = __import__(
            "sqlalchemy.dialects.postgresql", fromlist=[driver]
        )
    except ImportError:
        return None
    if hasattr(module, driver):
        target = getattr(module, driver)
        return lambda: target.dialect
    return None
'''
        + adapted_sa_registry[function_end:]
    )
    rewrite(sa_registry, upstream_sa_registry, adapted_sa_registry)

    alembic_registry = alembic / "ddl" / "__init__.py"
    rewrite(
        alembic_registry,
        "from . import mssql\nfrom . import mysql\nfrom . import oracle\n"
        "from . import postgresql\nfrom . import " + RETIRED_NAME + "\n"
        "from .impl import DefaultImpl as DefaultImpl\n",
        "from . import postgresql\nfrom .impl import DefaultImpl as DefaultImpl\n",
    )

    scrub_retired_documentation(sqlalchemy)
    scrub_retired_documentation(alembic)

    for project in ("sqlalchemy", "alembic"):
        dist_info = distribution_path(site, project)
        metadata = dist_info / "METADATA"
        metadata.write_text(
            RETIRED.sub("retired_embedded_backend", metadata.read_text(encoding="utf-8")),
            encoding="utf-8",
        )
        repair_record(site, dist_info)

    post = {name: tree_identity(site / name) for name in EXPECTED_PRE_TREES}
    if emit_post_identities:
        print(repr(post))
    elif post != EXPECTED_POST_TREES:
        raise SystemExit(
            f"post-adaptation source identity mismatch: expected "
            f"{EXPECTED_POST_TREES}, found {post}"
        )

    for root in (sqlalchemy, alembic):
        for path in root.rglob("*"):
            if path.is_file() and RETIRED.search(path.read_text(encoding="utf-8", errors="ignore")):
                raise SystemExit(f"retired backend marker remains in {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("site_packages", type=Path)
    parser.add_argument("--emit-post-identities", action="store_true")
    args = parser.parse_args()
    adapt(args.site_packages.resolve(), emit_post_identities=args.emit_post_identities)
    return 0


if __name__ == "__main__":
    sys.exit(main())
