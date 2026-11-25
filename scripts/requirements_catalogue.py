#!/usr/bin/env python3
"""Validate and render the documentary Open EPM blueprint; no product imports."""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sys
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]

# These are documentary relations, not execution or permission edges.
LINK_TYPES = {
    "enabled_by": {("BR", "DR")},
    "constrained_by": {("BR", "GR"), ("DR", "GR")},
    "enforced_by": {("BR", "GR"), ("DR", "GR")},
    "illustrated_by": {("DR", "BR"), ("GR", "BR")},
    "depends_on": {(a, b) for a in ("BR", "DR", "GR") for b in ("BR", "DR", "GR")},
    "related_to": {(a, b) for a in ("BR", "DR", "GR") for b in ("BR", "DR", "GR")},
    "conflicts_with": {(a, b) for a in ("BR", "DR", "GR") for b in ("BR", "DR", "GR")},
}


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"Non-finite JSON number: {value}")


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"),
                      object_pairs_hook=reject_duplicate_keys,
                      parse_constant=reject_constant)


def digest(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
                             separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def file_digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def repo_path(root: Path, name: str) -> Path:
    if not isinstance(name, str) or not name or Path(name).is_absolute():
        raise ValueError(f"Expected repository-relative path: {name!r}")
    path = (root / name).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError(f"Path escapes repository: {name}")
    return path


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def schema_registry(root: Path):
    schemas = {}
    for path in (root / "docs/product-blueprint/schemas").glob("*.schema.json"):
        value = load_json(path)
        Draft202012Validator.check_schema(value)
        schemas[value["$id"]] = value
    registry = Registry().with_resources(
        (key, Resource.from_contents(value)) for key, value in schemas.items())
    return registry


def schema_errors(value, schema, registry, label):
    errors = []
    validator = Draft202012Validator(schema, registry=registry,
                                     format_checker=FormatChecker())
    for issue in validator.iter_errors(value):
        location = "/".join(map(str, issue.absolute_path))
        errors.append(f"{label}/{location}: {issue.message}")
    return errors


def load_package(index_path: Path, root: Path = ROOT):
    index = load_json(index_path)
    catalogues = []
    for declaration in index["catalogues"]:
        path = repo_path(root, declaration["path"])
        catalogues.append((declaration, load_json(path)))
    return index, catalogues


def record_map(catalogues):
    records = {}
    locations = {}
    for declaration, catalogue in catalogues:
        for record in catalogue["records"]:
            key = record["id"]
            if key in records:
                raise ValueError(f"Duplicate primary record identity: {key}")
            records[key] = record
            locations[key] = f"{declaration['generatedDirectory']}/{key}.md"
    return records, locations


def validate_semantics(index, catalogues, root: Path):
    errors = []
    records, locations = record_map(catalogues)
    registries = {}
    for name in ("modules", "capabilities", "personas", "sources"):
        items = index[name]
        keys = [entry["id"] for entry in items]
        if len(set(keys)) != len(keys):
            errors.append(f"Duplicate {name} registry IDs")
        registries[name] = set(keys)
    nested_ids = set()
    decision_owners = {}
    for record in records.values():
        for item in walk(record):
            if "id" in item:
                key = item["id"]
                if key in nested_ids:
                    errors.append(f"Duplicate global/nested identity: {key}")
                nested_ids.add(key)
                if item is not record and not key.startswith(record["id"] + "-"):
                    errors.append(f"Nested identity outside owner: {key}")
        for decision in record["openDecisions"]:
            decision_owners[decision["id"]] = record["id"]
    dependency_edges = {}
    for record in records.values():
        key = record["id"]
        if record["githubObjects"]:
            errors.append(f"{key}: external GitHub objects prohibited")
        for field, registry_name in (("moduleRefs", "modules"), ("capabilityRefs", "capabilities")):
            values = record[field]
            if len(set(values)) != len(values):
                errors.append(f"{key}: duplicate {field}")
            for ref in values:
                if ref not in registries[registry_name]:
                    errors.append(f"{key}: unresolved {field} {ref}")
        if record.get("personaRef") and record["personaRef"] not in registries["personas"]:
            errors.append(f"{key}: unresolved persona")
        for ref in record["openDecisionRefs"]:
            if ref not in decision_owners:
                errors.append(f"{key}: unresolved decision {ref}")
        for link in record["links"]:
            target = link["targetId"]
            if (key[:2], target[:2]) not in LINK_TYPES.get(link["relation"], set()):
                errors.append(f"{key}: invalid relation direction {link['relation']} to {target}")
            if target not in records:
                errors.append(f"{key}: dangling record link {target}")
            elif target == key:
                errors.append(f"{key}: self-link")
            for ref in link.get("targetRequirementIds", []):
                if ref not in nested_ids or not ref.startswith(target + "-"):
                    errors.append(f"{key}: invalid target requirement {ref}")
            if link["relation"] == "depends_on":
                dependency_edges.setdefault(key, []).append(target)
        for item in walk(record):
            if "sourceRef" in item:
                ref = item["sourceRef"]
                if ref not in registries["sources"]:
                    errors.append(f"{key}: source not registered: {ref}")
                if not ref.startswith("https://") and not repo_path(root, ref).is_file():
                    errors.append(f"{key}: missing local source {ref}")
            for field in ("ownerModuleRef", "moduleRef"):
                if field in item and item[field] not in registries["modules"]:
                    errors.append(f"{key}: unknown {field} {item[field]}")
        if record["recordType"] == "guardrail_interaction":
            participants = {p["moduleRef"] for p in record["participants"]}
            if len(participants) < 2:
                errors.append(f"{key}: must cover at least two logical participants")
            if not participants <= set(record["moduleRefs"]):
                errors.append(f"{key}: participant omitted from moduleRefs")
            contract = record.get("interactionContract", {})
            for role in ("caller", "callee"):
                if role in contract and contract[role] not in participants:
                    errors.append(f"{key}: {role} is not an interaction participant")
            for control in record.get("enforcement", []):
                if control["ownerModuleRef"] not in participants:
                    errors.append(f"{key}: enforcement owner is not a participant")
        if record.get("recommendation", {}).get("action") == "recommend_retirement":
            if record.get("retirementProposal", {}).get("executionState") != "recommendation_only":
                errors.append(f"{key}: retirement must remain a recommendation")
    visiting, visited = set(), set()

    def visit(key):
        if key in visiting:
            errors.append(f"Dependency cycle at {key}")
            return
        if key in visited:
            return
        visiting.add(key)
        for child in dependency_edges.get(key, []):
            visit(child)
        visiting.remove(key)
        visited.add(key)

    for key in records:
        visit(key)
    for declaration, catalogue in catalogues:
        expected = {f"{declaration['idPrefix']}-{i:03d}" for i in range(1, 101)}
        actual = {r["id"] for r in catalogue["records"]}
        if actual != expected or len(catalogue["records"]) != 100:
            errors.append(f"{declaration['path']}: expected exactly IDs 001 through 100")
        if any(r["recordType"] != declaration["recordType"] for r in catalogue["records"]):
            errors.append(f"{declaration['path']}: wrong record type")
        declared_hash = declaration.get("sha256")
        if declared_hash and declared_hash != file_digest(repo_path(root, declaration["path"])):
            errors.append(f"{declaration['path']}: canonical hash differs from index")
    baseline = load_json(repo_path(root, index["baselineRef"]))
    for original in baseline["seedPreservation"]["records"]:
        current = records.get(original["id"])
        if not current:
            errors.append(f"Missing seed {original['id']}")
            continue
        for field in ("title", "businessObjective", "useCase", "userStory"):
            if current.get(field) != original[field]:
                errors.append(f"{original['id']}: seed field changed: {field}")
        for field in ("requirements", "acceptanceExamples", "openDecisions"):
            now = {item["id"]: item for item in current[field]}
            for item in original[field]:
                if item["id"] not in now:
                    errors.append(f"Missing seed nested record {item['id']}")
                elif any(now[item["id"]].get(k) != v for k, v in item.items()):
                    errors.append(f"Seed content changed: {item['id']}")
    pointer_ids = set()
    for pointer in index["decisions"]:
        if pointer["id"] in pointer_ids:
            errors.append(f"Duplicate decision pointer: {pointer['id']}")
        pointer_ids.add(pointer["id"])
        if decision_owners.get(pointer["id"]) != pointer["ownerRecordId"]:
            errors.append(f"Decision pointer ownership mismatch: {pointer['id']}")
        try:
            value = load_json(repo_path(root, pointer["path"]))
            if not pointer["jsonPointer"].startswith("/"):
                raise ValueError("Expected absolute JSON pointer")
            for part in pointer["jsonPointer"].split("/")[1:]:
                part = part.replace("~1", "/").replace("~0", "~")
                value = value[int(part)] if isinstance(value, list) else value[part]
            if value.get("id") != pointer["id"]:
                raise ValueError("Pointer resolves to a different identity")
        except (ValueError, KeyError, IndexError, TypeError, AttributeError, OSError):
            errors.append(f"Decision pointer does not resolve: {pointer['id']}")
    if pointer_ids != set(decision_owners):
        errors.append("Decision registry must contain exactly one pointer per owned decision")
    for source in index["sources"]:
        if source.get("path"):
            if source["id"] != source["path"]:
                errors.append(f"Source identity differs from local path: {source['id']}")
            if not re.fullmatch(r"[0-9a-f]{64}", source.get("sha256") or ""):
                errors.append(f"Local source requires an exact SHA-256: {source['id']}")
            path = repo_path(root, source["path"])
            if not path.is_file():
                errors.append(f"Source missing: {source['path']}")
            elif source.get("sha256") and source["sha256"] != file_digest(path):
                errors.append(f"Source changed after review capture: {source['path']}")
        elif source.get("url") != source["id"]:
            errors.append(f"External source identity differs from URL: {source['id']}")
    for module in index["modules"]:
        for ref in module.get("currentSourcePaths", []):
            if ref not in registries["sources"] or not repo_path(root, ref).is_file():
                errors.append(f"Module {module['id']}: invalid current source {ref}")
    for interaction in index["interactions"]:
        for field in ("fromModule", "toModule"):
            if interaction[field] not in registries["modules"]:
                errors.append(f"Interaction {interaction['id']}: unknown {field}")
        for ref in interaction["guardrailRefs"]:
            if ref not in records or not ref.startswith("GR-"):
                errors.append(f"Interaction {interaction['id']}: invalid guardrail {ref}")
        if interaction["classification"] == "allowed" and not interaction["guardrailRefs"]:
            errors.append(f"Interaction {interaction['id']}: unowned allowed edge")
        for ref in interaction["sourceRefs"]:
            if ref not in registries["sources"]:
                errors.append(f"Interaction {interaction['id']}: source not registered: {ref}")
    for capability in index["capabilities"]:
        for ref in capability.get("moduleRefs", []):
            if ref not in registries["modules"]:
                errors.append(f"Capability {capability['id']}: unknown module {ref}")
    for journey in index["criticalJourneys"]:
        for field, prefix in (("storyRefs", "BR-"), ("designRefs", "DR-"), ("guardrailRefs", "GR-")):
            if not journey[field]:
                errors.append(f"Journey {journey['id']}: no {field}")
            for ref in journey[field]:
                if ref not in records or not ref.startswith(prefix):
                    errors.append(f"Journey {journey['id']}: invalid {field} {ref}")
        for ref in journey.get("sourceRefs", []):
            if ref not in registries["sources"]:
                errors.append(f"Journey {journey['id']}: source not registered: {ref}")
    return errors


def validate_package(index_path: Path, root: Path = ROOT):
    index, catalogues = load_package(index_path, root)
    registry = schema_registry(root)
    errors = []
    index_schema = root / "docs/product-blueprint/schemas/index.schema.json"
    if not index_schema.is_file():
        errors.append("Missing index schema")
    else:
        errors += schema_errors(index, load_json(index_schema), registry, "index")
    for declaration, catalogue in catalogues:
        errors += schema_errors(catalogue, load_json(repo_path(root, declaration["schemaRef"])),
                                registry, declaration["path"])
    if not errors:
        errors += validate_semantics(index, catalogues, root)
    return index, catalogues, errors


def humanize(key):
    if key in {"mcp", "sdk", "id", "ids"}:
        return key.upper()
    return re.sub(r"(?<!^)(?=[A-Z])", " ", key).replace("_", " ").capitalize()


def scalar_text(value):
    if value is None:
        return "Absent / not supplied."
    if value == "":
        return '`""` (present empty text)'
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def relative_link(source_doc: str, target: str):
    if target.startswith("https://"):
        return target
    return os.path.relpath(target, Path(source_doc).parent).replace(os.sep, "/")


def render_value(value, level=3):
    if value is None:
        return "Absent / not supplied.\n"
    if isinstance(value, (str, int, float, bool)):
        return scalar_text(value) + "\n"
    if isinstance(value, list):
        if not value:
            return "None recorded.\n"
        if all(not isinstance(item, (dict, list)) for item in value):
            return "\n".join(f"- {item}" for item in value) + "\n"
        return "\n".join(render_value(item, level) for item in value)
    title = value.get("title") or value.get("question") or value.get("id")
    lines = []
    if title:
        prefix = f"{value['id']} — " if value.get("id") and title != value["id"] else ""
        lines.append(f"{'#' * min(level, 6)} {prefix}{title}\n")
    for key, child in value.items():
        if key == "id" or (key == "title" and title == child) or (key == "question" and title == child):
            continue
        if isinstance(child, (str, int, float, bool)) or child is None:
            lines.append(f"**{humanize(key)}:** {scalar_text(child)}\n")
        else:
            lines.append(f"**{humanize(key)}**\n\n{render_value(child, level + 1)}")
    return "\n".join(lines)


def context_digest(index):
    return digest({key: index[key] for key in ("productIntent", "personas", "capabilities", "modules", "sources")})


def render_record(record, declaration, index, records, locations):
    name = locations[record["id"]]
    label = {"business_story": "User story", "design_record": "Design decision", "guardrail_interaction": "Guardrail and interaction"}[record["recordType"]]
    source_link = relative_link(name, declaration["path"])
    guide_link = relative_link(name, "docs/product-blueprint/README.md")
    lines = [f"# {record['id']} — {record['title']}\n", record["summary"] + "\n",
             f"**{label}; draft for review.** Normative origin: {humanize(record['normativeStatus']).lower()}. "
             f"Scope: {humanize(record['scopeDisposition']).lower()}. Horizon: {humanize(record['deliveryHorizon']).lower()}.\n",
             f"Generated from [{declaration['path']}]({source_link}); edit the canonical record, then regenerate. "
             f"[Blueprint reader's guide]({guide_link}).\n",
             "## Product context\n", index["productIntent"]["statement"] + "\n"]
    caps = {item["id"]: item for item in index["capabilities"]}
    mods = {item["id"]: item for item in index["modules"]}
    lines += ["**Capabilities:** " + "; ".join(f"{ref}: {caps[ref]['title']}" for ref in record["capabilityRefs"]) + ".\n",
              "**Logical responsibilities:** " + "; ".join(f"{ref}: {mods[ref]['title']}" for ref in record["moduleRefs"]) + ".\n"]
    excluded = {"id", "title", "summary", "recordType", "status", "normativeStatus", "scopeDisposition", "deliveryHorizon", "capabilityRefs", "moduleRefs", "provenance", "links", "githubObjects"}
    for key, value in record.items():
        if key in excluded:
            continue
        if key == "openDecisionRefs" and value:
            lines.append("## Referenced owner decisions\n")
            pointers = {entry["id"]: entry for entry in index["decisions"]}
            for ref in value:
                owner = pointers[ref]["ownerRecordId"]
                decision = next(d for d in records[owner]["openDecisions"] if d["id"] == ref)
                lines.append(f"- [{ref}]({relative_link(name, locations[owner])}): "
                             f"{decision['question']} Status: {decision['status']}.\n")
            continue
        lines += [f"## {humanize(key)}\n", render_value(value)]
    lines += ["## Sources and interpretation\n"]
    for item in record["provenance"]:
        source = item["sourceRef"]
        lines.append(f"- [{source}]({relative_link(name, source)}) — {item['locator']}. "
                     f"{humanize(item['kind'])}: {item['claim']}\n")
    lines += ["## Related records\n"]
    if not record["links"]:
        lines.append("No record links recorded.\n")
    for link in record["links"]:
        target = link["targetId"]
        lines.append(f"- {humanize(link['relation'])}: [{target} — {records[target]['title']}]"
                     f"({relative_link(name, locations[target])}). {link['rationale']}\n")
    lines += ["## Document binding\n", f"Canonical record SHA-256: `{digest(record)}`.\n",
              f"Shared context SHA-256: `{context_digest(index)}`.\n",
              "This document specifies intended behavior. Source observations and recorded qualification retain their stated scope; document validation is not software acceptance. No GitHub object was created.\n"]
    return "\n".join(lines)


def generated_documents(index, catalogues):
    records, locations = record_map(catalogues)
    outputs = {}
    for declaration, catalogue in catalogues:
        for record in catalogue["records"]:
            outputs[locations[record["id"]]] = (record["id"], render_record(
                record, declaration, index, records, locations), digest(record))
    return outputs


def validate_render_ownership(index, catalogues, root: Path):
    """Validate the complete write set before creating or replacing any file."""
    directories = {"BR": "stories", "DR": "design", "GR": "guardrails"}
    owned = {entry["path"]: entry for entry in index["documentManifest"]}
    for declaration, _ in catalogues:
        expected = "docs/product-blueprint/" + directories[declaration["idPrefix"]]
        if declaration["generatedDirectory"] != expected:
            raise ValueError(f"Refusing unowned output directory: {declaration['generatedDirectory']}")
    for name, (key, _, _) in generated_documents(index, catalogues).items():
        if not re.fullmatch(r"(?:BR|DR|GR)-\d{3}\.md", Path(name).name):
            raise ValueError(f"Refusing unowned output path: {name}")
        path = repo_path(root, name)
        if path.exists():
            entry = owned.get(name, {})
            if entry.get("recordId") != key or entry.get("sha256") != file_digest(path):
                raise ValueError(f"Refusing to replace unowned or hand-edited output: {name}")


def check_generated(index, catalogues, root: Path):
    expected = generated_documents(index, catalogues)
    errors = []
    manifest = {item["path"]: item for item in index["documentManifest"]}
    if set(manifest) != set(expected) or len(index["documentManifest"]) != 300:
        errors.append("Generated manifest must list exactly the 300 expected documents")
    for name, (key, content, record_hash) in expected.items():
        path = repo_path(root, name)
        if not path.is_file() or path.read_text(encoding="utf-8") != content:
            errors.append(f"Generated content missing or changed: {name}")
        entry = manifest.get(name, {})
        if entry.get("sha256") != sha256(content.encode()).hexdigest() or entry.get("recordSha256") != record_hash:
            errors.append(f"Generated manifest binding mismatch: {key}")
    actual = set()
    for declaration, _ in catalogues:
        folder = repo_path(root, declaration["generatedDirectory"])
        actual.update(str(path.relative_to(root.resolve())) for path in folder.glob("*.md"))
    if actual != set(expected):
        errors.append("Unexpected/missing Markdown files in generated record directories")
    return errors


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "render", "check-generated"))
    parser.add_argument("--index", default="docs/product-blueprint/index.json")
    args = parser.parse_args(argv)
    try:
        index_path = repo_path(ROOT, args.index)
        index, catalogues, errors = validate_package(index_path)
        if errors:
            print(json.dumps({"status": "failed", "errors": errors}, indent=2))
            return 1
        if args.command == "render":
            validate_render_ownership(index, catalogues, ROOT)
            manifest = []
            for name, (key, content, record_hash) in generated_documents(index, catalogues).items():
                path = repo_path(ROOT, name)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                manifest.append({"recordId": key, "path": name,
                                 "sha256": sha256(content.encode()).hexdigest(),
                                 "recordSha256": record_hash})
            index["documentManifest"] = sorted(manifest, key=lambda item: item["recordId"])
            index_path.write_text(json.dumps(index, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        elif args.command == "check-generated":
            errors += check_generated(index, catalogues, ROOT)
        counts = Counter(record["recordType"] for _, cat in catalogues for record in cat["records"])
        print(json.dumps({"status": "failed" if errors else "passed", "scope": "Document validation only; no product acceptance", "command": args.command, "counts": dict(counts), "errors": errors}, indent=2))
        return 1 if errors else 0
    except (ValueError, KeyError, OSError, TypeError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
