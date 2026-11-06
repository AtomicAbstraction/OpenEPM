#!/usr/bin/env python3
"""Generate the reviewed dimensional-access matrix from current public code."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from epm_core.dimensional_access_registry import build_dimensional_access_matrix


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=Path(
        "docs/security/dimensional-access-enforcement-matrix.json"))
    args = parser.parse_args()
    repo = ROOT
    value = build_dimensional_access_matrix(repo)
    output = args.output if args.output.is_absolute() else repo / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n",
                      encoding="utf-8")


if __name__ == "__main__":
    main()
