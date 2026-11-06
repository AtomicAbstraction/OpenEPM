"""Build the public Open EPM SDK wheel without importing project code.

The release build uses this deterministic, dependency-free packager so the SDK
artifact can be audited before it is copied into builder/notebook images.  It
intentionally admits only the public ``openepm`` package and rejects bytecode,
native libraries, links and unexpected file types.
"""
from __future__ import annotations

import argparse
import base64
from hashlib import sha256
from pathlib import Path
import re
import zipfile


NAME = "openepm_sdk"
VERSION = "0.1.0"
WHEEL = f"{NAME}-{VERSION}-py3-none-any.whl"
DIST_INFO = f"{NAME}-{VERSION}.dist-info"
ALLOWED = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\.py$")
STAMP = (2026, 10, 28, 0, 0, 0)


def _entry(name: str, content: bytes) -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(name, STAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    info.create_system = 3
    return info, content


def _digest(content: bytes) -> str:
    value = base64.urlsafe_b64encode(sha256(content).digest()).rstrip(b"=")
    return "sha256=" + value.decode("ascii")


def build(source_root: Path, destination: Path) -> Path:
    package = source_root.resolve() / "openepm"
    if not package.is_dir() or package.is_symlink():
        raise ValueError("OPEN_EPM_SDK_SOURCE_INVALID")
    files: dict[str, bytes] = {}
    for path in sorted(package.iterdir(), key=lambda item: item.name):
        if path.name == "__pycache__" and path.is_dir() and not path.is_symlink():
            continue
        if path.is_symlink() or not path.is_file() or not ALLOWED.fullmatch(path.name):
            raise ValueError("OPEN_EPM_SDK_SOURCE_INVALID")
        files[f"openepm/{path.name}"] = path.read_bytes()
    if "openepm/__init__.py" not in files:
        raise ValueError("OPEN_EPM_SDK_SOURCE_INVALID")
    metadata = (
        "Metadata-Version: 2.4\n"
        "Name: openepm-sdk\n"
        f"Version: {VERSION}\n"
        "Summary: Database-neutral Python application-expression SDK for Open EPM\n"
        "Requires-Python: >=3.11\n"
        "\n"
    ).encode("utf-8")
    wheel_metadata = (
        "Wheel-Version: 1.0\n"
        "Generator: openepm-sdk-builder\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n\n"
    ).encode("ascii")
    files[f"{DIST_INFO}/METADATA"] = metadata
    files[f"{DIST_INFO}/WHEEL"] = wheel_metadata
    record_name = f"{DIST_INFO}/RECORD"
    records = [f"{name},{_digest(content)},{len(content)}"
               for name, content in sorted(files.items())]
    records.append(f"{record_name},,")
    files[record_name] = ("\n".join(records) + "\n").encode("utf-8")
    destination.mkdir(mode=0o755, parents=True, exist_ok=True)
    target = destination / WHEEL
    temporary = destination / ("." + WHEEL + ".partial")
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    try:
        with zipfile.ZipFile(temporary, "x") as archive:
            for name, content in sorted(files.items()):
                archive.writestr(*_entry(name, content))
        temporary.replace(target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return target


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--destination", type=Path, required=True)
    arguments = parser.parse_args()
    print(build(arguments.source_root, arguments.destination))


if __name__ == "__main__":
    main()

