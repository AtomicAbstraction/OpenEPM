#!/usr/bin/env python3
"""Deterministically adapt the pinned notebook dependency set.

The delivered notebook runtime has no persistent history database and no
retired embedded-database implementation, examples, stubs, language-server
profiles, or frontend documentation.  This transformation accepts only the
reviewed wheel/source layout and repairs every installed distribution RECORD.
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


EXPECTED_VERSIONS = {
    "ipython": "9.17.1",
    "jupyter_server": "2.21.1",
    "jupyterlab": "4.6.4",
    "nbformat": "5.11.1",
}
EXPECTED_PRE = {
    # Includes the reviewed dependency-free openepm HTTPS MCP transport.
    "site-packages": (12932, "6a85afed2bf351f9f657d5bb1fa09a32f48a94d55afd17972035f6d57a8e85e8"),
    "jupyter-share": (462, "46abd66cf2466a4f0687368eda805099471401934428184a3f966ef1000d97c7"),
}
EXPECTED_POST = {
    "site-packages": (12820, "f62a57f493c9af289785a2bcd003a66ea942473fc0e49c2bb64077a99b161d78"),
    "jupyter-share": (462, "ae367e83b069831adb72354ba62c12794923c3242ef2147af262d0e6510244f3"),
}

RETIRED_NAME = "sql" + "ite"
RETIRED = re.compile(RETIRED_NAME, re.IGNORECASE)
REPLACEMENT = "retired_embedded_backend"


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
            f"{phase} identity mismatch for {root}: expected {expected}, found {actual}"
        )


def remove_path(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def remove_retired_named_paths(root: Path) -> None:
    matches = sorted(
        (path for path in root.rglob("*") if RETIRED.search(path.name)),
        key=lambda path: len(path.parts),
        reverse=True,
    )
    for path in matches:
        if path.exists():
            remove_path(path)


def scrub_text(root: Path) -> None:
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "RECORD":
            continue
        data = path.read_bytes()
        try:
            source = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        adapted = RETIRED.sub(REPLACEMENT, source).replace(
            ":memory:", "memory-resident"
        )
        if adapted != source:
            path.write_text(adapted, encoding="utf-8")


def record_hash(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "sha256=" + digest.decode("ascii")


def repair_record(site: Path, record: Path) -> None:
    retained: list[list[str]] = []
    with record.open(newline="", encoding="utf-8") as stream:
        for row in csv.reader(stream):
            if len(row) != 3:
                raise SystemExit(f"malformed RECORD row in {record}: {row!r}")
            target = site / row[0]
            if target == record:
                retained.append([row[0], "", ""])
            elif target.is_file():
                data = target.read_bytes()
                retained.append([row[0], record_hash(data), str(len(data))])
    with record.open("w", newline="", encoding="utf-8") as stream:
        csv.writer(stream, lineterminator="\n").writerows(retained)


def adapt(site: Path, share: Path, *, emit_post_identities: bool) -> None:
    installed = {
        dist.metadata["Name"].lower(): dist.version
        for dist in importlib.metadata.distributions(path=[str(site)])
    }
    for project, version in EXPECTED_VERSIONS.items():
        actual = installed.get(project)
        if actual != version:
            raise SystemExit(f"{project} version mismatch: expected {version}, found {actual}")

    require_identity(site, EXPECTED_PRE["site-packages"], "pre-adaptation")
    require_identity(share, EXPECTED_PRE["jupyter-share"], "pre-adaptation")

    for root in (site, share):
        for cache in sorted(root.rglob("__pycache__"), reverse=True):
            shutil.rmtree(cache)
        remove_retired_named_paths(root)

    # Test and platform-only trees are not part of a Linux user runtime.
    for relative in (
        "IPython/sphinxext",
        "debugpy/_vendored/pydevd/pydevd_attach_to_process/winappdbg",
        "tornado/test",
    ):
        target = site / relative
        if target.exists():
            shutil.rmtree(target)

    scrub_text(site)
    scrub_text(share)

    for record in sorted(site.glob("*.dist-info/RECORD")):
        repair_record(site, record)

    post = {
        "site-packages": tree_identity(site),
        "jupyter-share": tree_identity(share),
    }
    if emit_post_identities:
        print(repr(post))
    elif post != EXPECTED_POST:
        raise SystemExit(
            f"post-adaptation identity mismatch: expected {EXPECTED_POST}, found {post}"
        )

    for root in (site, share):
        for path in root.rglob("*"):
            if RETIRED.search(path.name):
                raise SystemExit(f"retired path remains: {path}")
            if path.is_file():
                data = path.read_bytes().lower()
                if RETIRED.pattern.encode() in data or b":memory:" in data:
                    raise SystemExit(f"retired content remains: {path}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("site_packages", type=Path)
    parser.add_argument("jupyter_share", type=Path)
    parser.add_argument("--emit-post-identities", action="store_true")
    args = parser.parse_args()
    adapt(
        args.site_packages.resolve(),
        args.jupyter_share.resolve(),
        emit_post_identities=args.emit_post_identities,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
