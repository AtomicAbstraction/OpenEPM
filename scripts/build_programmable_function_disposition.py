#!/usr/bin/env python3
"""Build the V00 function-level programmable-platform disposition register.

This does not change the public catalogue.  It classifies the exact current
catalogue so replacement and retirement work cannot silently omit a function.
"""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError:  # Direct ``python3 scripts/name.py`` execution.
    from operator_import_path import ensure_project_root

ensure_project_root()

from epm_core.postgres_capability_contract import (
    CONSOLIDATION_FUNCTIONS,
    CORE_FUNCTIONS,
    PREPUBLIC_CORE_FUNCTIONS,
    is_retired_public_function,
)


FORMAT = "openepm-programmable-function-disposition-v1"

DOMAIN_PREFIXES = (
    "consolidation.",
    "currency.",
    "financial.",
)
DOMAIN_EXACT = frozenset(
    {
        "application.capabilities.read",
        "application.capabilities.history.read",
        "application.capabilities.configure",
    }
)
FORECAST_PREFIX = "facts.planning.forecast."
GENERIC_MISNAMED_PREFIXES = (
    "planning.",
    "facts.planning.",
)
OPERATIONAL_PREFIXES = (
    "application.taskflow.",
    "execution.delegation.",
    "facts.projections.",
    "facts.source.",
    "facts.transfer.",
    "python.environment.",
    "python.program.",
    "python.schedule.",
    "security.",
)


def _classification(name: str) -> dict[str, object]:
    if name in DOMAIN_EXACT:
        return {
            "class": "domain_specific",
            "replacement": "single application lifecycle and generic discovery",
            "reviewRequired": False,
        }
    if name.startswith(FORECAST_PREFIX):
        return {
            "class": "domain_specific",
            "replacement": "generic time selection, rule sequence, parameters and schedule",
            "reviewRequired": False,
        }
    if name.startswith(DOMAIN_PREFIXES):
        return {
            "class": "domain_specific",
            "replacement": "user-authored typed rules over generic cube primitives",
            "reviewRequired": name.startswith("currency."),
        }
    if name.startswith(GENERIC_MISNAMED_PREFIXES):
        return {
            "class": "generic_but_misnamed",
            "replacement": "domain-neutral selection, calculation, comparison, task or workflow primitive",
            "reviewRequired": True,
        }
    if name.startswith(OPERATIONAL_PREFIXES):
        return {
            "class": "operational",
            "replacement": None,
            "reviewRequired": False,
        }
    return {
        "class": "primitive",
        "replacement": None,
        "reviewRequired": False,
    }


def build() -> dict[str, object]:
    core = set(CORE_FUNCTIONS)
    consolidation = set(CONSOLIDATION_FUNCTIONS)
    prepublic = set(PREPUBLIC_CORE_FUNCTIONS)
    if core & consolidation or core & prepublic or consolidation & prepublic:
        raise RuntimeError("FUNCTION_DISPOSITION_SOURCE_SETS_OVERLAP")
    functions = []
    for name in sorted(core | consolidation | prepublic):
        item = _classification(name)
        source = (
            "consolidation"
            if name in consolidation
            else "prepublic_core"
            if name in prepublic
            else "core"
        )
        functions.append({
            "name": name,
            "sourceSet": source,
            "retirementState": (
                "public_discovery_retired"
                if is_retired_public_function(name)
                else "active"
            ),
            **item,
        })
    names = [item["name"] for item in functions]
    if len(names) != len(set(names)):
        raise RuntimeError("FUNCTION_DISPOSITION_DUPLICATE")
    counts = Counter(str(item["class"]) for item in functions)
    payload: dict[str, object] = {
        "format": FORMAT,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
        "source": "epm_core.postgres_capability_contract",
        "sourceCounts": {
            "core": len(core),
            "consolidation": len(consolidation),
            "prepublicCore": len(prepublic),
            "total": len(functions),
        },
        "classificationCounts": dict(sorted(counts.items())),
        "functions": functions,
    }
    canonical = json.dumps(
        payload["functions"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    payload["functionDispositionDigest"] = hashlib.sha256(canonical).hexdigest()
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    rendered = json.dumps(build(), indent=2, sort_keys=True) + "\n"
    if arguments.output is None:
        print(rendered, end="")
    else:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
