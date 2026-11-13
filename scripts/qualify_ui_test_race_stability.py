#!/usr/bin/env python3
"""Reproduce the UI race regressions and two complete-suite passes."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]
UI = ROOT / "web-ui"
FOCUSED = (
    "src/DataExport.test.tsx",
    "src/PythonRuleEditor.test.tsx",
    "src/SemanticAttributes.test.tsx",
)
SOURCES = (
    UI / "src/DataExport.tsx",
    UI / "src/DataExport.test.tsx",
    UI / "src/PythonRuleEditor.tsx",
    UI / "src/PythonRuleEditor.test.tsx",
    UI / "src/SemanticAttributes.tsx",
    UI / "src/SemanticAttributes.test.tsx",
)


def digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def run(arguments: list[str], *, expected: str) -> str:
    completed = subprocess.run(arguments, cwd=UI, env=os.environ.copy(),
        text=True, capture_output=True, check=False)
    output = completed.stdout + completed.stderr
    if completed.returncode != 0 or expected not in output:
        raise RuntimeError("UI stability qualification failed: " + output[-4000:])
    return output


def qualify(output: Path) -> dict:
    if not output.is_absolute() or output.exists():
        raise ValueError("output must be a new absolute path")
    vite_temp = UI / "node_modules/.vite-temp"
    result = None
    try:
        run(["npm", "test", "--", "--run", *FOCUSED],
            expected="Tests  22 passed (22)")
        run(["npm", "run", "check"], expected="tsc -b --pretty false")
        complete_runs = []
        for ordinal in (1, 2):
            text = run(["npm", "test"], expected="Tests  538 passed (538)")
            complete_runs.append({"ordinal": ordinal,
                "testFiles": 56, "tests": 538,
                "passed": "Test Files  56 passed (56)" in text})
        result = {
            "format": "openepm-ui-test-race-stability-v1",
            "status": "passed",
            "focused": {"files": list(FOCUSED), "tests": 22},
            "typeScript": "passed",
            "completeRuns": complete_runs,
            "regressions": [
                "export retry pins one exact expiry and admission intent across wall-clock seconds",
                "Python editor synchronization reads the latest prop instead of a stale effect closure",
                "independent member and relationship semantic-definition reads execute concurrently",
            ],
            "sourceSha256": {
                str(path.relative_to(ROOT)): digest(path) for path in SOURCES},
        }
    finally:
        shutil.rmtree(vite_temp, ignore_errors=True)
    if result is None:
        raise RuntimeError("qualification produced no result")
    result["cleanup"] = {"viteTemporaryCacheAbsent": not vite_temp.exists()}
    if not result["cleanup"]["viteTemporaryCacheAbsent"]:
        raise RuntimeError("Vite temporary cache cleanup failed")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = qualify(args.output)
    print(json.dumps({"status": result["status"], "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
