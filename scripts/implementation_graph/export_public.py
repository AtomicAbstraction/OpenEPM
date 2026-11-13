#!/usr/bin/env python3
"""Project the validated implementation graph onto a static public viewer."""

from __future__ import annotations

import argparse
import ast
from collections import Counter
import json
from pathlib import Path
import re
import shutil
import tarfile

from build import GROUPS, INFRA, REGISTRY, VENDOR_SHA, digest


PUBLIC_SOURCE = "e2d19f164a2923b67ef99868b88981967867ec62"
PUBLIC_ARCHIVE_SHA = "89e251e874ecf9c25ac1f8c902d641b8c6a16b2825b566d5734f70f6a142bfed"
PUBLIC_PREFIX = "OpenEPM-" + PUBLIC_SOURCE + "/"
FILES = {"module", "file"}
SYMBOLS = {"function", "method", "class"}
SOURCE_LINKS = {"CALLS", "CONSTRUCTS", "DEFINES", "EXTENDS", "IMPORTS", "INHERITS",
                "MODULE_IMPORT", "OPERATION_LITERAL", "REGISTRY_KEY",
                "DISPATCH_CHECK", "UI_OPERATION_REFERENCE", "DECLARES_OPERATION"}
ASSOCIATIONS = {"GROUPS_OPERATION", "ASSOCIATED_IMPLEMENTATION", "IMPLEMENTATION_REFERENCES",
                "MAPS_MECHANISM", "RELATED_CALCULATION_PLATFORM", "IMPLEMENTED_IN_MODULE",
                "EXPLAINED_BY_FUNCTION", "CONNECTS_DATABASE", "GATED_ACCELERATOR_REFERENCE"}
PATH = re.compile(r"(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.(?:py|js|ts|tsx)")
IDENTIFIER = re.compile(r"[A-Za-z_$][A-Za-z0-9_$.]{0,249}")
OPERATION = re.compile(r"[a-z][a-z0-9_.-]{0,119}")
SECRET = re.compile(
    r"(?i)(?:/Users/|/home/|/private/|/run/secrets/|[a-z]:\\Users\\|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9_]{24,}|"
    r"github_pat_[A-Za-z0-9_]{24,}|AIza[A-Za-z0-9_-]{35}|AKIA[A-Z0-9]{16}|"
    r"[a-z0-9_.+-]+@[a-z0-9.-]+\.[a-z]{2,})"
)
LIMIT = 3_000_000
TEMPLATE = Path(__file__).with_name("viewer.html")


def public_reference(archive):
    if digest(archive.read_bytes()) != PUBLIC_ARCHIVE_SHA:
        raise ValueError("Public source archive does not match the reviewed digest")
    hashes = {}
    operations = set()
    with tarfile.open(archive, "r:gz") as source:
        for entry in source:
            if not entry.isfile() or not entry.name.startswith(PUBLIC_PREFIX):
                continue
            path = entry.name.removeprefix(PUBLIC_PREFIX)
            if not PATH.fullmatch(path):
                continue
            contents = source.extractfile(entry).read()
            hashes[path] = digest(contents)
            if path == REGISTRY:
                for statement in ast.parse(contents).body:
                    if (isinstance(statement, ast.Assign)
                            and ast.unparse(statement.targets[0]) in {"CORE_FUNCTIONS", "CONSOLIDATION_FUNCTIONS"}):
                        operations.update(ast.literal_eval(statement.value.args[0]))
    if not operations:
        raise ValueError("Reviewed public source registry is missing")
    return hashes, operations


def public_graph(graph, public_hashes, public_operations):
    """Keep only reviewed identities and minimal structural fields."""
    titles = {"functionality:" + row[0]: row[1] for row in (*GROUPS, *INFRA)}
    titles["functionality:calculation-optimization"] = "Plan calculation scope, dependencies and bounded execution"
    same_public_bytes = {path for path, h in graph["sourceHashes"].items()
                         if public_hashes.get(path) == h}
    nodes = {}
    for row in graph["nodes"]:
        id, kind, path, name = (row[field] for field in ("id", "kind", "path", "name"))
        node = {"id": id, "name": name, "kind": kind, "layer": row["layer"], "path": ""}
        if id in titles and kind == "functionality" and name == titles[id]:
            node["perspective"] = row["perspective"]
        elif kind == "operation" and name in public_operations and OPERATION.fullmatch(name):
            node["status"] = "Declared operation in the source registry"
        elif kind in FILES and path in public_hashes and name == path and row["layer"] != "Evidence":
            node.update(path=path, line=row["line"] if path in same_public_bytes else None)
        elif (kind in SYMBOLS and path in same_public_bytes and row["layer"] != "Evidence"
              and IDENTIFIER.fullmatch(name)):
            node.update(path=path, line=row["line"])
        elif id in {"database:postgresql", "database:duckdb"} and kind == "database terminal":
            node["status"] = {"database:postgresql": "Authoritative transactional store",
                              "database:duckdb": "Gated analytical accelerator"}[id]
        else:
            continue
        nodes[id] = node

    links = {}
    positions = {id: index for index, id in enumerate(nodes)}
    for row in graph["links"]:
        start, end, kind, certainty = (row[key] for key in ("source", "target", "kind", "certainty"))
        if start not in nodes or end not in nodes:
            continue
        association = certainty == "association" and kind in ASSOCIATIONS
        public_witness = certainty == "syntax" and kind in SOURCE_LINKS and row["path"] in same_public_bytes
        if not (association or public_witness):
            continue
        links[(start, end, kind)] = (positions[start], positions[end], kind, certainty)
    meta = {"commit": graph["meta"]["commit"], "publicSource": PUBLIC_SOURCE,
            "snapshotKind": graph["meta"].get("snapshotKind", "committed"),
            "sourceSchemaVersion": graph["meta"].get("sourceSchemaVersion")}
    if not re.fullmatch(r"[0-9a-f]{40}", meta["commit"]):
        raise ValueError("Invalid source snapshot identity")
    result = {"meta": meta, "nodes": list(nodes.values()), "links": list(links.values())}
    summary = Counter(row["kind"] for row in nodes.values())
    if not all(summary[kind] for kind in ("functionality", "operation", "module", "function")) or not links:
        raise ValueError("Public graph is missing expected structural coverage")
    return result


PUBLIC_UI = """
function welcome(){
  $('inspector').innerHTML = `<div class="eyebrow">PUBLIC KNOWLEDGE GRAPH</div>
    <div id="selection-name">Explore Open EPM’s implementation</div>
    <p>Choose a functionality to see its operations and shared components. Search for a node or click it to explore its connections.</p>
    <p class="hint">This view shows reviewed structural information. A connection does not establish runtime behavior or release qualification.</p>`;
}
$('coverage-button').onclick = () => {
  $('coverage-content').innerHTML = `<p>${DATA.meta.snapshotKind === 'working-tree' ? 'Frozen development snapshot' : 'Committed source snapshot'} <code>${esc(DATA.meta.commit.slice(0, 12))}</code> · schema ${esc(DATA.meta.sourceSchemaVersion || 'unlisted')}</p>
    <p>${DATA.nodes.length.toLocaleString()} nodes · ${DATA.links.length.toLocaleString()} relationships</p>
    <p>This public view includes functionality groups, declared operations and reviewed implementation identities. Detailed static links require a source witness matching the published code.</p>
    <p>Structural source evidence and functionality associations have separate labels. Runtime qualification is tracked in the documentation.</p>`;
  $('coverage-dialog').showModal();
};
""".strip()


def public_viewer(data):
    template = TEMPLATE.read_text()
    for opening, closing in (("<!-- local-only -->", "<!-- /local-only -->"),
                             ("/* local-only */", "/* /local-only */")):
        if template.count(opening) != template.count(closing):
            raise ValueError("Unbalanced local-only graph viewer sections")
        template = re.sub(re.escape(opening) + ".*?" + re.escape(closing), "", template, flags=re.S)
    page, script = template.split("<script>\n'use strict';", 1)
    script, footer = script.split("</script>", 1)
    if not footer.strip() == "</body></html>":
        raise ValueError("Unrecognized graph viewer template")
    page = (page.replace("<title>Open EPM · Implementation explorer</title>", "<title>Knowledge Graph · Open EPM</title>")
            .replace("OPEN EPM / REPOSITORY ATLAS", "OPEN EPM / PUBLIC VIEW")
            .replace("Implementation explorer <span", "Knowledge Graph <span")
            .replace("Evidence & coverage", "Snapshot & scope")
            .replace('<div class="header-tools">', '<div class="header-tools"><a href="/">Open EPM</a>')
            .replace('<script>/*__VENDOR__*/</script>', '<script defer src="/knowledge-graph/renderer.js"></script>'))
    raw = json.dumps(data, ensure_ascii=True, separators=(",", ":"))
    if SECRET.search(raw):
        raise ValueError("Sensitive identifier or local path detected in graph projection")
    page = page.replace("/*__DATA__*/", raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026"))
    script = ("'use strict';" + script)
    script = script.replace("const DATA=JSON.parse(document.getElementById('graph-data').textContent);", """
const DATA=JSON.parse(document.getElementById('graph-data').textContent);
DATA.links = DATA.links.map(([source, target, kind, certainty]) => ({
  source: DATA.nodes[source].id, target: DATA.nodes[target].id, kind, certainty,
  detail: certainty === 'syntax'
    ? 'Static relationship with a source witness matching the published bytes.'
    : 'Functionality or architecture grouping from the implementation graph.'
}));""")
    script = script.replace(" · source and acceptance evidence · refreshed on request", " · public view")
    script = script.replace("inspect frozen source", "inspect relationships")
    script = script.replace("n.path?n.path+':'+n.line:n.layer", "n.path?(n.line?n.path+':'+n.line:n.path):n.layer")
    script = script.replace("e.path?e.path+':'+e.line:''", "e.path?(e.line?e.path+':'+e.line:e.path):''")
    if re.search(r"\b(?:fetch|XMLHttpRequest|WebSocket|localStorage|sessionStorage|indexedDB|"
                 r"loadEdits|saveEdits|openCard|showSource|downloadJSON)\b", script):
        raise ValueError("Local graph capabilities reached the public script")
    return (page + '<script defer src="/knowledge-graph/viewer.js"></script>' + footer,
            script.replace("welcome();catalog();updateView();", PUBLIC_UI + "\nwelcome();catalog();updateView();"))


def export(artifact, archive, output):
    source = artifact / "graph.json"
    receipt = json.loads((artifact / "receipt.json").read_text())
    validation = json.loads((artifact / "validation.json").read_text())
    graph = json.loads(source.read_bytes())
    if (not validation["passed"] or validation["snapshot"] != graph["meta"]["commit"]
            or receipt["commit"] != validation["snapshot"]
            or receipt["graphSha256"] != digest(source.read_bytes())
            or validation["nodes"] != len(graph["nodes"]) or validation["edges"] != len(graph["links"])):
        raise ValueError("Current graph must pass artifact validation before public export")
    public = public_graph(graph, *public_reference(archive))
    page, script = public_viewer(public)
    renderer = artifact / "assets/3d-force-graph.min.js"
    if digest(renderer.read_bytes()) != VENDOR_SHA:
        raise ValueError("Unexpected 3D renderer bytes")
    if any(len(value.encode()) > LIMIT for value in (page, script)):
        raise ValueError("Public graph exceeded the landing response size bound")
    output.mkdir(parents=True, exist_ok=True)
    (output / "index.html").write_text(page)
    (output / "viewer.js").write_text(script)
    shutil.copyfile(renderer, output / "renderer.js")
    shutil.copyfile(artifact / "assets/LICENSE-3d-force-graph", output / "LICENSE.txt")
    print(json.dumps({"snapshot": public["meta"]["commit"], "publicSource": PUBLIC_SOURCE,
                      "nodes": len(public["nodes"]), "links": len(public["links"]),
                      "kinds": Counter(n["kind"] for n in public["nodes"])}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("public_source_archive", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    export(args.artifact, args.public_source_archive, args.output)
