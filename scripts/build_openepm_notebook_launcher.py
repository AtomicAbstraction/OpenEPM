#!/usr/bin/env python3
"""Build the trusted notebook launcher as a deterministic zipapp."""
from __future__ import annotations
import argparse
from pathlib import Path
import zipfile

FILES = ("deploy/notebook/notebook_launcher.py",
         "scripts/serve_openepm_notebook_launcher.py")
ENTRY = "from scripts.serve_openepm_notebook_launcher import main\nmain()\n"


def build(root: Path, output: Path):
    root, output = root.resolve(), output.resolve()
    missing = [name for name in FILES if not (root / name).is_file()]
    if missing: raise SystemExit("missing launcher inputs: " + ", ".join(missing))
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9) as archive:
        for name in FILES:
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0)); info.external_attr = 0o100644 << 16
            archive.writestr(info, (root / name).read_bytes(),
                             compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
        for package in ("deploy", "deploy/notebook", "scripts"):
            info = zipfile.ZipInfo(package + "/__init__.py", (1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16; archive.writestr(info, b"")
        info = zipfile.ZipInfo("__main__.py", (1980, 1, 1, 0, 0, 0)); info.external_attr = 0o100644 << 16
        archive.writestr(info, ENTRY.encode())


def main():
    parser = argparse.ArgumentParser(); parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True); args = parser.parse_args()
    build(args.root, args.output)


if __name__ == "__main__": main()
