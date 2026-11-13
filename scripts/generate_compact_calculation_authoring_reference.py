"""Generate the compact authoring reference from its executable example."""
from __future__ import annotations

import argparse
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "examples" / "user_authored_compact_calculated_member.py"
TARGET = ROOT / "docs" / "compact-calculation-authoring.md"
HEADER = """# Compact calculation authoring

This example is executable application-language source. Names resolve only
through the caller's bounded, authorized metadata context. The partial POV and
explicit axes must cover the complete application grain exactly once. The
builder performs no business-data or database reads; the fixed core validates,
tests and executes the resulting calculated-member definition.

```python
"""


def rendered() -> str:
    return HEADER + SOURCE.read_text(encoding="utf-8").rstrip() + "\n```\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = rendered()
    if args.check:
        if not TARGET.exists() or TARGET.read_text(encoding="utf-8") != expected:
            raise SystemExit("compact calculation authoring reference is stale")
        return
    TARGET.write_text(expected, encoding="utf-8")


if __name__ == "__main__":
    main()
