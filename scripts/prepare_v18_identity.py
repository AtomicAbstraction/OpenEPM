#!/usr/bin/env python3
"""Start one marker-owned disposable real-OIDC provider for V18."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.v18_local_sustained_identity import (  # noqa: E402
    DisposableOidcController)


def write_manifest(path: Path, value: dict) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--marker", required=True)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--https-port", type=int, default=5443)
    values = parser.parse_args()
    directory = values.directory.resolve(strict=True)
    manifest = directory / "identity-manifest.json"
    controller = DisposableOidcController(marker=values.marker,
        directory=directory, https_port=values.https_port)
    result = controller.start()
    try:
        write_manifest(manifest, {"format": "openepm-v18-identity-v1",
            **result})
    except BaseException:
        controller.stop()
        raise
    print(json.dumps({"status": "ready", "container": result["container"],
        "issuer": result["issuer"], "subject": result["subject"],
        "manifest": str(manifest), "secretsPrinted": False},
        sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
