#!/usr/bin/env python3
"""Build the trusted launcher as a deterministic standard-library zipapp."""
from __future__ import annotations

import argparse
from pathlib import Path
import zipfile


FILES = (
    "epm_core/__init__.py",
    "epm_core/persistence_contract.py",
    "epm_core/python_program_execution.py",
    "epm_core/python_sandbox_control.py",
    "epm_core/python_sandbox_launcher.py",
    "scripts/operator_import_path.py",
    "scripts/serve_openepm_sandbox_launcher.py",
)
ENTRY = "from scripts.serve_openepm_sandbox_launcher import main\nmain()\n"


def build(root: Path, output: Path) -> None:
    root, output = root.resolve(), output.resolve()
    missing = [name for name in FILES if not (root / name).is_file()]
    if missing:
        raise SystemExit("missing launcher inputs: " + ", ".join(missing))
    output.parent.mkdir(parents=True, exist_ok=True)
    timestamp = (1980, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9) as archive:
        for name in FILES:
            info = zipfile.ZipInfo(name, timestamp)
            info.external_attr = 0o100644 << 16
            archive.writestr(info, (root / name).read_bytes(),
                             compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        for package in ("scripts",):
            info = zipfile.ZipInfo(package + "/__init__.py", timestamp)
            info.external_attr = 0o100644 << 16
            archive.writestr(info, b"")
        info = zipfile.ZipInfo("__main__.py", timestamp)
        info.external_attr = 0o100644 << 16
        archive.writestr(info, ENTRY.encode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build(args.root, args.output)


if __name__ == "__main__":
    main()
