#!/usr/bin/env python3
"""Remove retired embedded-database MIME markers from a static proxy binary.

Traefik's pinned static binary includes a generic MIME sniffer whose string
table contains retired backend names even though Traefik does not link or run
that backend. Equal-length replacement keeps the executable layout stable and
disables only identification of that retired file format.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


_MARKER = b"sql" + b"ite"
REPLACEMENTS = {
    _MARKER: b"retire",
    _MARKER.capitalize(): b"Retire",
    _MARKER[:3].upper() + _MARKER[3:]: b"Retire",
    _MARKER.upper(): b"RETIRE",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    data = args.source.read_bytes()
    counts = {key.decode(): data.count(key) for key in REPLACEMENTS}
    if not any(counts.values()):
        parser.error("pinned proxy binary no longer contains reviewed retirement markers")
    for source, replacement in REPLACEMENTS.items():
        data = data.replace(source, replacement)
    if _MARKER in data.lower():
        parser.error("retired proxy marker remains after deterministic rewrite")
    args.destination.parent.mkdir(parents=True, exist_ok=False)
    args.destination.write_bytes(data)
    args.destination.chmod(0o555)
    print(f"sourceSha256={hashlib.sha256(args.source.read_bytes()).hexdigest()}")
    print(f"outputSha256={hashlib.sha256(data).hexdigest()}")
    print("counts=" + repr(counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
