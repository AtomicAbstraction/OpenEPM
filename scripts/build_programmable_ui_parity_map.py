#!/usr/bin/env python3
"""Build the V00 browser route/control/network-call preservation map."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "web-ui" / "src"
OUTPUT = ROOT / "docs" / "qualifications" / "programmable-ui-parity-map-2026-11-02.json"

ROUTE_MODULES = {
    "home": ("App.tsx", "GlobalPanels.tsx"),
    "applications": ("App.tsx", "Applications.tsx"),
    "work": ("App.tsx", "MyWork.tsx"),
    "overview": ("App.tsx",),
    "grid": ("App.tsx", "Analyze.tsx"),
    "data": ("App.tsx", "CapabilityArea.tsx", "DataLoad.tsx", "DataExport.tsx", "SupportingDetail.tsx"),
    "metadata": (
        "App.tsx", "CapabilityArea.tsx", "MetadataCreate.tsx",
        "MetadataMaintenance.tsx", "MetadataRelationships.tsx",
        "SecurityTagCatalog.tsx", "SemanticAttributes.tsx",
    ),
    "lists": ("App.tsx", "CapabilityArea.tsx", "MemberLists.tsx"),
    "rules": (
        "App.tsx", "CapabilityArea.tsx", "BuildRules.tsx",
        "BuildSequences.tsx", "BuildSchedules.tsx",
    ),
    "flows": ("App.tsx", "GenericWorkflow.tsx"),
    "tasks": ("App.tsx", "MyWork.tsx"),
    "monitor": ("App.tsx", "Monitor.tsx"),
    "administration": ("App.tsx", "CapabilityArea.tsx", "AdministrationSecurity.tsx"),
}

ENDPOINT = re.compile(r"[\"'](/api/[a-z0-9/-]+)[\"']")
FUNCTION = re.compile(
    r"[\"']((?:application|facts|metadata|planning|rules|security|python|workflow|workspace|financial|consolidation|calendar|taskflow)\.[a-z0-9_.-]+)[\"']",
    re.IGNORECASE,
)
ARIA = re.compile(r"aria-label=[\"']([^\"']{1,120})[\"']")
BUTTON = re.compile(r"<button\b[^>]*>\s*([^<{][^<]{0,100}?)\s*</button>", re.DOTALL)


def _module(name: str) -> dict:
    path = SRC / name
    text = path.read_text(encoding="utf-8")
    controls = set(ARIA.findall(text))
    controls.update(" ".join(item.split()) for item in BUTTON.findall(text))
    test = path.with_name(path.stem + ".test.tsx")
    return {
        "source": path.relative_to(ROOT).as_posix(),
        "endpoints": sorted(set(ENDPOINT.findall(text))),
        "functionLiterals": sorted(set(FUNCTION.findall(text))),
        "literalControls": sorted(item for item in controls if "{" not in item),
        "test": test.relative_to(ROOT).as_posix() if test.exists() else None,
    }


def build() -> dict:
    routes = []
    all_modules = {}
    for route, names in ROUTE_MODULES.items():
        modules = []
        # Every route uses the shared API adapter through App or a child.
        for name in ("api.ts", *names):
            all_modules.setdefault(name, _module(name))
            modules.append(all_modules[name])
        routes.append({
            "route": f"#/{route}/:applicationIndex",
            "page": route,
            "modules": modules,
            "endpoints": sorted({value for module in modules for value in module["endpoints"]}),
            "functionLiterals": sorted({value for module in modules for value in module["functionLiterals"]}),
            "literalControls": sorted({value for module in modules for value in module["literalControls"]}),
        })
    digest = sha256(json.dumps(routes, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return {
        "format": "openepm-programmable-ui-parity-map-v1",
        "routeCount": len(routes),
        "moduleCount": len(all_modules),
        "routeMapDigest": digest,
        "routes": routes,
        "interpretation": {
            "purpose": "preserve current route, control and network-call reachability during generic UI replacement",
            "literalOnly": True,
            "dynamicServerCatalog": "functionLiterals are not a complete runtime function catalogue",
            "retirementAuthority": False,
        },
    }


def main() -> None:
    OUTPUT.write_text(json.dumps(build(), indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
