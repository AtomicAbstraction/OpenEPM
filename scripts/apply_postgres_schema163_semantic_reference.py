"""Apply a reviewed semantic artifact to canonical schema 143; never activate it."""
from __future__ import annotations

import argparse
import gzip
import io
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_schema163_semantic_reference import apply_artifact


def write_json(path: Path, value: object) -> None:
    data=(json.dumps(value,indent=2,sort_keys=True)+"\n").encode()
    if path.suffix=='.gz':
        with path.open('wb') as raw, gzip.GzipFile(
                filename='',mode='wb',fileobj=raw,compresslevel=9,mtime=0) as out:
            out.write(data)
    else:path.write_bytes(data)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn", default=os.environ.get("EPM_POSTGRES_ADMIN_DSN"))
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--migrations-dir", type=Path,
                        default=ROOT / "schema/postgres")
    parser.add_argument("--source-commit",
                        default=os.environ.get("EPM_SOURCE_COMMIT"))
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if not arguments.dsn:
        parser.error("Set EPM_POSTGRES_ADMIN_DSN or pass --dsn")
    if not re.fullmatch(r"[0-9a-f]{40,64}", arguments.source_commit or ""):
        raise ValueError("SEMANTIC_REFERENCE_SOURCE_COMMIT_REQUIRED")
    artifact = json.loads(arguments.artifact.read_text(encoding="utf-8"))
    with connect_postgres(arguments.dsn, autocommit=False) as db:
        evidence = apply_artifact(db, artifact, arguments.migrations_dir)
    evidence["sourceCommit"] = arguments.source_commit
    evidence["artifactPath"] = str(arguments.artifact.resolve())
    evidence["limitations"] = [
        "independent semantic reference only",
        "historical migration ledger remains at canonical schema 143",
        "no baseline artifact or activation manifest emitted",
        "independent parity review remains required",
    ]
    write_json(arguments.output,evidence)
    print(json.dumps({"output": str(arguments.output.resolve()),
                      "schemaFingerprint": evidence["schemaFingerprint"],
                      "activationAuthorized": False}))


if __name__ == "__main__":
    main()
