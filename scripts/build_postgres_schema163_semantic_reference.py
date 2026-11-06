"""Build a review artifact for schema-163 semantics; never authorizes activation."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from epm_core.postgres_schema163_semantic_reference import build_artifact


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--migrations-dir", type=Path,
                        default=ROOT / "schema/postgres")
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    artifact = build_artifact(arguments.migrations_dir)
    arguments.output.write_text(json.dumps(
        artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(arguments.output.resolve()),
                      "artifactDigest": artifact["artifactDigest"],
                      "activationAuthorized": False}))


if __name__ == "__main__":
    main()
