#!/usr/bin/env python3
"""Refresh local MCP discovery facts, preserving reviewed documentation grouping.

This imports fixed server registrations only. It does not invoke tools or connect
to a deployment. New tool names require an explicit functionality classification.
Run generate_public_mcp_reference.py and the documentation checks afterwards.
"""
from __future__ import annotations

import ast
import asyncio
from collections import Counter
from datetime import date
import hashlib
import importlib
import json
from pathlib import Path
import sys
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
INVENTORY = ROOT / "docs/public-documentation-mcp-inventory.json"
NEW_MODULES = {
    "execute_v2_application_purge": "workspace-application-lifecycle",
    "execute_v2_application_decision": "workspace-application-lifecycle",
    "issue_v2_operation_admission": "data-grids",
}


async def refresh():
    from epm_core.postgres_capability_contract import filter_catalog
    from epm_core.postgres_language_v2 import PostgresLanguageV2

    inventory = json.loads(INVENTORY.read_text())
    modules = {tool["name"]: tool["functionalityModule"] for tool in inventory["tools"]}
    modules.update(NEW_MODULES)
    tools = {}
    for endpoint in inventory["endpoints"]:
        source = ROOT / endpoint["source"]
        locations = {node.name: node.lineno for node in ast.walk(ast.parse(source.read_text()))
                     if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
        server = importlib.import_module(endpoint["source"].removesuffix(".py")).server
        registered = await server.list_tools()
        resources = await server.list_resources()
        endpoint.update(
            registeredToolCount=len(registered),
            registeredPromptCount=len(await server.list_prompts()),
            registeredResourceCount=len(resources),
            registeredResourceTemplateCount=len(await server.list_resource_templates()),
            registeredResourceUris=sorted(str(resource.uri) for resource in resources),
        )
        for tool in registered:
            if tool.name not in modules:
                raise ValueError(f"Classify new tool before refreshing: {tool.name}")
            record = tools.setdefault(tool.name, {"name": tool.name,
                "functionalityModule": modules[tool.name], "variants": []})
            record["variants"].append({"endpoint": endpoint["id"], "source": endpoint["source"],
                "sourceLine": locations[tool.name], "description": tool.description,
                "inputSchema": tool.input_schema})
    inventory["tools"] = sorted(tools.values(), key=lambda tool: tool["name"])
    for module in inventory["functionalityModules"]:
        names = sorted(name for name, tool in tools.items() if tool["functionalityModule"] == module["id"])
        module.update(primaryTools=names, primaryToolCount=len(names))
    functions = filter_catalog(PostgresLanguageV2.catalog(), [])["functions"]
    inventory["applicationLanguageFunctions"].update(
        count=len(functions), families=dict(sorted(Counter(name.split(".")[0] for name in functions).items())))
    inventory["counts"].update(
        endpointVariants=sum(len(tool["variants"]) for tool in tools.values()),
        distinctTools=len(tools), functionalityModules=len(inventory["functionalityModules"]),
        nativePrompts=sum(endpoint["registeredPromptCount"] for endpoint in inventory["endpoints"]),
        nativeResourceTemplates=sum(endpoint["registeredResourceTemplateCount"] for endpoint in inventory["endpoints"]),
        genericApplicationLanguageFunctionsAtReview=len(functions))
    counts = {endpoint["registeredResourceCount"] for endpoint in inventory["endpoints"]}
    if len(counts) != 1:
        raise ValueError("Update per-endpoint resource presentation for differing counts")
    inventory["counts"]["nativeResourcesPerEndpoint"] = counts.pop()
    for entry in inventory["sourceState"]["files"]:
        entry["sha256"] = hashlib.sha256((ROOT / entry["path"]).read_bytes()).hexdigest()
    inventory["sourceState"]["headCommit"] = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    inventory["sourceState"]["workingTreeDirty"] = bool(subprocess.check_output(
        ["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
    inventory["reviewDate"] = date.today().isoformat()
    INVENTORY.write_text(json.dumps(inventory, ensure_ascii=False, indent=2) + "\n")
    print(f"Refreshed local discovery: {len(tools)} tools, {len(functions)} generic functions")


if __name__ == "__main__":
    asyncio.run(refresh())
