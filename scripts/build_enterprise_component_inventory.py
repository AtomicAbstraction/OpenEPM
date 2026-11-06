"""Build the exhaustive, reviewable enterprise component-disposition index."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import sys
import tomllib

ROOT = Path(__file__).parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from epm_core.postgres_mcp_application import PostgresLanguageV2  # noqa: E402
from epm_core.processing_operation_registry import build_registry  # noqa: E402


BASE = ROOT / "docs/component-inventory-2026-10-28.json"
OUTPUT = ROOT / "docs/enterprise-component-disposition.json"
PRODUCTION_ROOTS = (
    "epm_core", "openepm", "schema/postgres", "scripts", "web", "web-ui/src",
    "deploy/notebook", "deploy/identity", "deploy/operations", "deploy/proxy",
    "deploy/release", "deploy/postgres",
)
EXECUTABLE_SUFFIXES = {".py", ".sh", ".ts", ".tsx", ".js", ".mjs", ".sql"}
CONFIG_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".lock"}
RETIRED_EXECUTABLES = (
    "deploy/proxy/openepm-external.yaml.template",
    "epm_core/postgres_identity_migration.py",
    "tests/identity_principal_migration_fixture.py",
    "tests/test_postgres_identity_migration.py",
    "web-ui/src/ApplicationMode.tsx",
    "web-ui/src/ConsolidationWorkspace.tsx",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def files_under(relative: str):
    path = ROOT / relative
    if path.is_file():
        return [path]
    return [item for item in path.rglob("*") if item.is_file()
            and "__pycache__" not in item.parts and ".mypy_cache" not in item.parts]


def owners(path: str, components: list[dict]) -> list[str]:
    matches = []
    for component in components:
        if component["status"] == "retired":
            continue
        if any(path == prefix or path.startswith(prefix.rstrip("/") + "/")
               for prefix in component["paths"]):
            matches.append(component["id"])
    return sorted(matches)


def literal_assignment(path: Path, name: str):
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                value = node.value
                if (isinstance(value, ast.Call) and isinstance(value.func, ast.Name)
                        and value.func.id == "frozenset" and len(value.args) == 1
                        and not value.keywords):
                    return frozenset(ast.literal_eval(value.args[0]))
                return ast.literal_eval(value)
    raise ValueError(f"COMPONENT_INVENTORY_ASSIGNMENT_MISSING:{name}")


def dependency_inventory() -> list[dict]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    dependencies = [{"ecosystem": "python", "declaration": value,
                     "source": "pyproject.toml"}
                    for value in project["project"].get("dependencies", [])]
    for line in (ROOT / "requirements-postgres.lock").read_text().splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            dependencies.append({"ecosystem": "python-runtime-lock",
                                 "declaration": value,
                                 "source": "requirements-postgres.lock"})
    package = json.loads((ROOT / "web-ui/package.json").read_text())
    for section in ("dependencies", "devDependencies"):
        for name, version in sorted(package.get(section, {}).items()):
            dependencies.append({"ecosystem": "node-" + section,
                                 "declaration": name + "@" + version,
                                 "source": "web-ui/package.json"})
    return sorted(dependencies, key=lambda item: (
        item["ecosystem"], item["declaration"], item["source"]))


def classify_test(path: Path) -> dict:
    relative = path.relative_to(ROOT).as_posix()
    if relative.startswith("web-ui/src/"):
        category = "browser_integration"
        gate = "web"
    else:
        source = path.read_text(errors="replace")
        if (path.name.startswith("qualify_") or "qualification" in path.name
                or "@pytest.mark.qualification" in source):
            category = "final_artifact_qualification"
            gate = "qualify"
        elif ("EPM_TEST_POSTGRES_DISPOSABLE" in source
              or re.search(r"EPM_[A-Z0-9_]*(?:OWNER|ADMIN)_DSN", source)
              or path.name == "test_postgres_numeric_store.py"):
            category = "disposable_integration"
            gate = "integration"
        else:
            category = "unit"
            gate = "unit"
    return {"path": relative, "category": category, "requiredGate": gate}


def build() -> dict:
    base = json.loads(BASE.read_text())
    components = base["components"]
    source_files = []
    for root in PRODUCTION_ROOTS:
        for path in files_under(root):
            relative = path.relative_to(ROOT).as_posix()
            if (path.suffix in EXECUTABLE_SUFFIXES or path.name.startswith("Dockerfile")
                    or path.name in ("epmctl", "notebook-mode-contract",
                                     "install-sandbox-launcher",
                                     "install-notebook-launcher")):
                assigned = owners(relative, components)
                if not assigned:
                    raise ValueError("UNOWNED_PRODUCTION_FILE:" + relative)
                source_files.append({"path": relative, "owners": assigned})

    migrations = []
    for path in sorted((ROOT / "schema/postgres").glob("[0-9][0-9][0-9][0-9]_*.sql")):
        source = path.read_text()
        migrations.append({
            "version": int(path.name[:4]),
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": digest(path),
            "declaredTables": sorted(set(re.findall(
                r"(?im)^CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z0-9_.]+)", source))),
            "declaredFunctions": sorted(set(re.findall(
                r"(?im)^CREATE(?:\s+OR\s+REPLACE)?\s+FUNCTION\s+([a-z0-9_.]+)", source))),
        })
    if [item["version"] for item in migrations] != list(range(1, len(migrations) + 1)):
        raise ValueError("MIGRATION_SEQUENCE_INVALID")

    web_source = ROOT / "platform_postgres_web_http.py"
    observable = sorted(literal_assignment(web_source, "_OBSERVABLE_ROUTES"))
    posts = sorted(literal_assignment(web_source, "_BROWSER_POST_ROUTES"))
    test_paths = sorted(
        path
        for root in (ROOT / "tests", ROOT / "web-ui/src")
        for path in root.rglob("*")
        if (path.is_file() and "__pycache__" not in path.parts
            and path.suffix in (".py", ".ts", ".tsx")
            and (path.name.startswith("test_") or
                 ".test." in path.name or
                 path.name.startswith("qualify_"))))
    tests = [classify_test(path) for path in test_paths]
    test_categories = {}
    for item in tests:
        test_categories[item["category"]] = test_categories.get(item["category"], 0) + 1
    configs = sorted({
        path.relative_to(ROOT).as_posix()
        for root in (ROOT / "deploy", ROOT / ".github")
        for path in root.rglob("*")
        if path.is_file() and (path.suffix in CONFIG_SUFFIXES
                               or path.name.startswith("Dockerfile")
                               or ".env." in path.name)
    } | {"pyproject.toml", "requirements-postgres.lock",
         "requirements-dev.txt", "web-ui/package.json"})
    documents = sorted({
        path.relative_to(ROOT).as_posix()
        for path in ROOT.glob("*.md") if path.is_file()
    } | {
        path.relative_to(ROOT).as_posix()
        for root in (ROOT / "docs", ROOT / "deploy")
        for path in root.rglob("*.md") if path.is_file()
    })
    schema = json.loads((ROOT / "deploy/release/release-manifest.schema.json").read_text())
    image_names = sorted(schema["properties"]["images"]["properties"])
    dockerfiles = sorted(path.relative_to(ROOT).as_posix()
                         for path in (ROOT / "deploy").rglob("Dockerfile*"))
    operations = build_registry(PostgresLanguageV2.catalog()["functions"])

    return {
        "format": "openepm-enterprise-component-disposition-v1",
        "asOf": "2026-11-05",
        "authority": "PROJECT_INPUTS.md input 702 and docs/enterprise-readiness-acceptance-register.json",
        "baseInventory": BASE.relative_to(ROOT).as_posix(),
        "summary": {
            "components": len(components),
            "productionExecutableFiles": len(source_files),
            "migrations": len(migrations),
            "declaredTables": sum(len(item["declaredTables"]) for item in migrations),
            "declaredFunctions": sum(len(item["declaredFunctions"]) for item in migrations),
            "publicApplicationFunctions": operations["applicationFunctionCount"],
            "externalPublicFunctions": len(operations["externalFunctions"]),
            "browserRoutes": len(observable),
            "browserPostRoutes": len(posts),
            "testsAndQualificationFiles": len(tests),
            "testCategoryCounts": dict(sorted(test_categories.items())),
            "configurationFiles": len(configs),
            "dependencyDeclarations": len(dependency_inventory()),
            "releaseImages": len(image_names),
            "documentationFiles": len(documents),
        },
        "components": components,
        "productionExecutableFiles": source_files,
        "databaseMigrations": migrations,
        "publicOperations": operations,
        "browserRoutes": {"observable": observable, "post": posts},
        "testsAndQualificationFiles": tests,
        "configurationFiles": configs,
        "dependencies": dependency_inventory(),
        "releaseImages": {"requiredNames": image_names,
                          "dockerfiles": dockerfiles},
        "documentationFiles": documents,
        "retiredExecutableAssertions": [
            {"path": relative, "absent": not (ROOT / relative).exists()}
            for relative in RETIRED_EXECUTABLES
        ],
    }


def main() -> None:
    OUTPUT.write_text(json.dumps(build(), indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
