#!/usr/bin/env python3
"""Prepare a hash-bound, read-only AIcompanies migration source packet.

This is evidence/extraction tooling, not an application template or importer.
Numeric cell values remain lexical strings. No target mapping, calculation,
rounding, authentication, network operation or source write occurs here.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from decimal import Decimal, InvalidOperation
from fractions import Fraction
import gzip
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import tempfile
import xml.etree.ElementTree as ET
import zipfile


WORKBOOK = "AICOmpanies_Financial_Planning_Cube.xlsx"
MODEL = "AICOmpanies_Financial_Planning_Cube.model.json"
REGISTRY = ".workbook-build/accepted-facts.json"
EXPORT = "data/workbook_readonly_export"
FORMAT = "openepm-aicompanies-source-packet-v1"
NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
MAIN = "{" + NS["m"] + "}"
REL = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"
NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z")


class SourceError(ValueError):
    """The supplied source cannot establish a complete, exact packet."""


def require(condition, message):
    if not condition:
        raise SourceError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_file(root, relative):
    path = root / relative
    require(not Path(relative).is_absolute() and ".." not in Path(relative).parts,
            "Source path escapes the source root")
    require(path.is_file() and path.resolve() == path,
            f"Source file is missing or noncanonical: {relative}")
    return path


def load(path):
    # Decimal preserves JSON fractional values without a binary-float round trip.
    return json.loads(path.read_text(encoding="utf-8"), parse_float=Decimal)


def decimal(value):
    text = str(value)
    require(NUMBER.fullmatch(text) is not None, "Invalid numeric source value")
    try:
        result = Decimal(text)
    except InvalidOperation as error:
        raise SourceError("Invalid numeric source value") from error
    require(result.is_finite(), "Non-finite numeric source value")
    return result


def column(address):
    match = re.fullmatch(r"([A-Z]+)([1-9][0-9]*)", address)
    require(match is not None, "Invalid worksheet cell address")
    number = 0
    for char in match[1]:
        number = number * 26 + ord(char) - 64
    return number, int(match[2])


def zip_target(base, value):
    path = value.lstrip("/") if value.startswith("/") else posixpath.normpath(
        posixpath.join(base, value))
    require(path.startswith("xl/") and ".." not in path.split("/"),
            "Invalid workbook relationship target")
    return path


def table_bindings(model, registry):
    bindings = {item["name"]: {**item, "kind": "dimension" if
        item["name"].startswith("Dim") else "fact"} for item in model["tables"]}
    bindings["Cube"] = {"sheet": "Cube", "kind": "queue", "primaryKey": "QueueID"}
    bindings["PersonnelEvidence"] = {"sheet": "Personnel Evidence",
        "kind": "evidence", "primaryKey": "EvidenceID"}
    for item in registry.get("evidenceCollections", []):
        bindings[item["table"]] = {**item, "kind": "evidence", "primaryKey": "EvidenceID"}
    for item in registry.get("comparisonCollections", []):
        bindings[item["table"]] = {**item, "kind": "comparison", "primaryKey": "EvidenceID"}
    for item in model.get("backendTables", []):
        bindings[item["name"]] = {**item, "kind": "backend"}
    return bindings


def workbook_rows(path, bindings):
    """Read named tables and supporting cells, never the 652MB owner export."""
    tables, records, support, sheets, table_parts = {}, {}, [], [], {}
    counts = Counter()
    with zipfile.ZipFile(path) as archive:
        shared = []
        if "xl/sharedStrings.xml" in archive.namelist():
            with archive.open("xl/sharedStrings.xml") as stream:
                for _, element in ET.iterparse(stream, events=("end",)):
                    if element.tag == MAIN + "si":
                        shared.append("".join(item.text or "" for item in element.iter(MAIN + "t")))
                        element.clear()
        for name in archive.namelist():
            if not name.startswith("xl/tables/") or not name.endswith(".xml"):
                continue
            raw = archive.read(name)
            node = ET.fromstring(raw)
            table = node.get("name")
            require(table in bindings and table not in tables, "Unexpected or duplicate named table")
            require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", table), "Unsafe table name")
            first, last = node.get("ref").split(":")
            left, header = column(first)
            right, end = column(last)
            headers = [item.get("name") for item in node.findall("m:tableColumns/m:tableColumn", NS)]
            require(len(headers) == len(set(headers)) == right - left + 1,
                    f"Invalid named-table columns: {table}")
            declared = bindings[table].get("columns")
            if declared:
                require(headers == [item["name"] for item in declared],
                        f"Model/table columns differ: {table}")
            tables[table] = {"sheet": bindings[table]["sheet"], "range": node.get("ref"),
                "columns": headers, "left": left, "header": header, "end": end,
                "sourceTableXml": raw.decode("utf-8")}
            table_parts[name] = table
        require(set(tables) == set(bindings), "Named-table/model inventory differs")
        by_sheet = {value["sheet"]: key for key, value in tables.items()}
        require(len(by_sheet) == len(tables), "Multiple named tables per source sheet are unsupported")
        book = ET.fromstring(archive.read("xl/workbook.xml"))
        relations = {item.get("Id"): item.get("Target") for item in ET.fromstring(
            archive.read("xl/_rels/workbook.xml.rels"))}
        for sheet in book.findall("m:sheets/m:sheet", NS):
            name = sheet.get("name")
            target = zip_target("xl", relations[sheet.get(REL)])
            table_name = by_sheet.get(name)
            table = tables.get(table_name)
            rows, sheet_counts = [], Counter()
            declared_parts = []
            with archive.open(target) as stream:
                for _, element in ET.iterparse(stream, events=("end",)):
                    if element.tag == MAIN + "tablePart":
                        declared_parts.append(element.get(REL))
                    if element.tag != MAIN + "row":
                        continue
                    row_number = int(element.get("r"))
                    cells = {}
                    for cell in element.findall("m:c", NS):
                        address = cell.get("r")
                        index, cell_row = column(address)
                        require(cell_row == row_number and index not in cells, "Duplicate or misplaced cell")
                        kind = cell.get("t", "n")
                        value = cell.findtext("m:v", None, NS)
                        if kind == "s":
                            value = shared[int(value)]
                        elif kind == "inlineStr":
                            value = "".join(item.text or "" for item in cell.iter(MAIN + "t"))
                        require(kind != "e", f"Cached Excel error: {name}!{address}")
                        payload = {"value": value, "type": kind}
                        if cell.get("s") is not None:
                            payload["styleIndex"] = cell.get("s")
                        formula = cell.find("m:f", NS)
                        if formula is not None:
                            payload["formula"] = {"expression": formula.text or "", "attributes": formula.attrib}
                            sheet_counts["formulas"] += 1
                            sheet_counts["formulasWithoutCachedValue"] += value is None
                        cells[index] = payload
                        sheet_counts["storedCells"] += 1
                        sheet_counts["nonemptyCells"] += value not in (None, "")
                    if table and table["header"] < row_number <= table["end"]:
                        fields, types, styles, formulas = {}, {}, {}, {}
                        for index, field in enumerate(table["columns"], table["left"]):
                            cell = cells.pop(index, None)
                            fields[field] = cell["value"] if cell else None
                            if cell:
                                types[field] = cell["type"]
                                if "styleIndex" in cell:
                                    styles[field] = cell["styleIndex"]
                                if "formula" in cell:
                                    formulas[field] = cell["formula"]
                        rows.append({"sourceRow": row_number, "fields": fields,
                            "cellTypes": types, "styleIndices": styles, "formulas": formulas})
                    if cells:
                        support.append({"sheet": name, "row": row_number,
                                        "cellsByColumn": {str(k): v for k, v in cells.items()}})
                    element.clear()
            if declared_parts:
                relation_path = posixpath.join(posixpath.dirname(target), "_rels",
                                               posixpath.basename(target) + ".rels")
                sheet_relations = {item.get("Id"): item.get("Target") for item in
                                   ET.fromstring(archive.read(relation_path))}
                declared_tables = [table_parts.get(zip_target(posixpath.dirname(target),
                    sheet_relations[part])) for part in declared_parts]
            else:
                declared_tables = []
            require(declared_tables == ([table_name] if table_name else []),
                    f"Worksheet/table relationship differs: {name}")
            if table_name:
                require(len(rows) == table["end"] - table["header"],
                        f"Named-table rows are missing: {table_name}")
                records[table_name] = rows
            sheets.append({"name": name, "state": sheet.get("state", "visible"),
                           "table": table_name, "rows": len(rows), **sheet_counts})
            counts.update(sheet_counts)
        require(set(records) == set(tables), "A declared worksheet is missing")
        metadata = {"workbookXml": archive.read("xl/workbook.xml").decode("utf-8"),
            "stylesXml": archive.read("xl/styles.xml").decode("utf-8")
                if "xl/styles.xml" in archive.namelist() else None,
            "embeddedDataModel": any(name.startswith("xl/model/") for name in archive.namelist())}
        require(not metadata["embeddedDataModel"], "Embedded Excel data model is unsupported")
    return tables, records, support, sheets, dict(counts), metadata


def validate_records(model, registry, identities, bindings, records):
    grain = model["grain"]
    require(len(grain) == len(set(grain)), "Duplicate grain dimension")
    masters, global_members, inactive_members = {}, defaultdict(list), set()
    for table, binding in bindings.items():
        if binding["kind"] != "dimension":
            continue
        key = binding["primaryKey"]
        members = [row["fields"][key] for row in records[table]]
        require(all(members) and len(members) == len(set(members)), "Duplicate or empty member key")
        masters[key] = set(members)
        for row in records[table]:
            fields = row["fields"]
            global_members[fields[key]].append(key)
            if str(fields.get("IsActive", "")).lower() in ("false", "0", "no"):
                inactive_members.add((key, fields[key]))
    require(set(grain) == set(masters), "Grain and dimension masters differ")
    source_facts = {}
    for index, row in enumerate(registry["facts"]):
        key = tuple(row.get(axis) for axis in grain)
        require(all(isinstance(value, str) and value for value in key), "Missing registry dimension key")
        require(key not in source_facts, "Duplicate registry fact grain")
        source_facts[key] = (index, row)
    active = {key: value for key, value in identities["records"].items() if value.get("status") == "active"}
    by_grain = {}
    for rid, row in active.items():
        if row.get("table") == "FactFinancial":
            require(row.get("canonicalKey") not in by_grain, "Duplicate active identity grain")
            by_grain[row["canonicalKey"]] = rid
    seen, fact_rows, counts = set(), {}, Counter()
    scenarios, roles, units, precisions, storage = (Counter() for _ in range(5))
    fact_keys, inactive_fact_rows = set(), 0
    for table, rows in records.items():
        binding = bindings[table]
        for row in rows:
            fields = row["fields"]
            kind = binding["kind"]
            if kind == "fact":
                key = tuple(fields.get(axis) for axis in grain)
                require(all(isinstance(value, str) and value for value in key), "Missing workbook dimension key")
                require(key not in fact_keys, "Duplicate workbook fact grain")
                fact_keys.add(key)
                require(all(value in masters[axis] for axis, value in zip(grain, key)), "Unknown dimension member")
                inactive_fact_rows += any((axis, value) in inactive_members for axis, value in zip(grain, key))
                require(key in source_facts, "Workbook fact is absent from accepted registry")
                source_index, accepted = source_facts[key]
                value = decimal(fields.get("Value"))
                require(value == decimal(accepted.get("Value")), "Workbook/registry numeric value differs")
                canonical = "|".join(key)
                require(canonical in by_grain, "Stable fact identity is missing")
                rid = by_grain[canonical]
                row.update(canonicalKey=canonical, registryIndex=source_index,
                           numericLexicalValue=fields["Value"])
                for field in ("RecordRole", "SourceObservationID", "ValueQualifier", "ValueUnit",
                              "ReferenceYearKey", "ReferencePeriodKey", "CalculationContext"):
                    if accepted.get(field) is not None:
                        require(str(accepted[field]) == str(fields.get(field)),
                                f"Workbook/registry provenance differs: {field}")
                fact_rows[rid] = fields
                scenarios[fields.get("ScenarioKey")] += 1
                roles[fields.get("RecordRole")] += 1
                units[fields.get("ValueUnit")] += 1
                precisions[max(0, -value.as_tuple().exponent)] += 1
                storage[row["cellTypes"].get("Value", "absent")] += 1
            else:
                key = fields.get(binding["primaryKey"])
                require(isinstance(key, str) and bool(key), "Missing stable table key")
                prefix = {"dimension": f"member:{table}:", "backend": f"backend:{table}:",
                          "queue": "queue:", "comparison": "comparison:", "evidence": "evidence:"}[kind]
                rid = prefix + key
            require(rid not in seen and rid in active and active[rid].get("table") == table,
                    "Stable record identity is duplicate, missing or bound to another table")
            seen.add(rid)
            row.update(recordId=rid, role=active[rid].get("role"), table=table)
            counts[table] += 1
    require(len(fact_rows) == len(source_facts) == len(by_grain), "Fact inventories differ")
    require(seen == set(active), "Active source identities are not completely represented")
    seeds = marginal_checks = 0
    policy = model.get("simulationPolicy", {})
    for link in policy.get("seedLinks", []):
        require(link["actualRecordId"] in fact_rows and link["simulationRecordId"] in fact_rows,
                "Simulation seed source identity is missing")
        original, seed = fact_rows[link["actualRecordId"]], fact_rows[link["simulationRecordId"]]
        require(decimal(original["Value"]) == decimal(seed["Value"]) == decimal(link["actualValue"]),
                "Simulation copy differs from its source")
        require(original["ScenarioKey"] == "SC_ACTUALS" and seed["ScenarioKey"] == "SC_SIMULATION"
                and all(original[key] == seed[key] for key in grain if key != "ScenarioKey"),
                "Simulation copy coordinates differ")
        seeds += 1
    for family in policy.get("families", []):
        ids = family["leafRecordIds"]
        require(len(ids) == len(set(ids)) and all(rid in fact_rows for rid in ids)
                and family["anchorRecordId"] in fact_rows, "Allocation family membership differs")
        leaves = [fact_rows[rid] for rid in ids]
        # Fractions avoid Decimal's ambient precision rounding for wide totals.
        total = sum((Fraction(decimal(row["Value"])) for row in leaves), Fraction(0))
        require(total == decimal(family["anchorDecimalValue"]) == decimal(family["leafDecimalTotal"])
                == decimal(fact_rows[family["anchorRecordId"]]["Value"]), "Allocation total does not reconcile")
        for axis, expected in family["marginals"].items():
            actual = defaultdict(Fraction)
            for row in leaves:
                actual[row[axis]] += Fraction(decimal(row["Value"]))
            require(dict(actual) == {key: decimal(value) for key, value in expected.items()},
                    "Allocation marginal does not reconcile")
            marginal_checks += len(actual)
    return {"tableRows": dict(counts), "factRows": len(fact_rows), "duplicateFactCoordinates": 0,
        "missingDimensionReferences": 0, "allValuesEqualRegistry": True,
        "globallyUniqueMasterKeys": len(global_members),
        "globalMasterKeyCollisions": {key: axes for key, axes in global_members.items() if len(axes) > 1},
        "inactiveMasterCount": len(inactive_members), "factRowsReferencingInactiveMasters": inactive_fact_rows,
        "stableIdentitiesComplete": True, "scenarios": dict(scenarios), "roles": dict(roles),
        "valueUnits": dict(units), "numericDecimalPlaces": dict(precisions),
        "numericCellStorageTypes": dict(storage), "exactSimulationCopies": seeds,
        "allocationFamilies": len(policy.get("families", [])), "exactMarginalChecks": marginal_checks}


def gzip_bytes(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as stream:
        stream.write(data)


def gzip_rows(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as stream:
        for row in rows:
            stream.write((json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode())


def prepare(source_root, output_dir):
    root, output = Path(source_root).resolve(), Path(output_dir).resolve()
    require(root.is_dir() and root not in output.parents and output != root,
            "Output must be outside the source project")
    require(not output.exists(), "Output already exists; use a new empty destination")
    originals = [WORKBOOK, MODEL, "dimension-schema.json", REGISTRY, EXPORT + "/manifest.json",
                 EXPORT + "/identities.json", EXPORT + "/hierarchies.json"]
    pins = {name: {"sha256": digest(source_file(root, name)), "bytes": (root / name).stat().st_size}
            for name in originals}
    model, registry = load(root / MODEL), load(root / REGISTRY)
    schema, owner_manifest = load(root / "dimension-schema.json"), load(root / EXPORT / "manifest.json")
    require(schema["canonical_fact_grain"] == model["grain"], "Schema/model grain differs")
    require(owner_manifest.get("ready") is True and owner_manifest.get("readOnly") is True,
            "Owner export is not ready/read-only")
    require(owner_manifest["sourceWorkbook"]["sha256"] == pins[WORKBOOK]["sha256"]
            and owner_manifest["sourceModel"]["sha256"] == pins[MODEL]["sha256"],
            "Owner export does not match current workbook/model")
    exported = {}
    for entry in owner_manifest["files"]:
        name = EXPORT + "/" + entry["path"]
        require(name not in exported, "Duplicate export file")
        path = source_file(root, name)
        require(path.stat().st_size == entry["bytes"] and digest(path) == entry["sha256"],
                f"Owner export hash mismatch: {entry['path']}")
        exported[name] = {"sha256": entry["sha256"], "bytes": entry["bytes"]}
    require(all(EXPORT + "/" + name in exported for name in
                ("workbook.json", "facts.json", "model.json", "identities.json", "hierarchies.json", "comparisons.json")),
            "Owner export inventory is incomplete")
    require(exported[EXPORT + "/model.json"] == pins[MODEL],
            "Exported model differs from the current source model")
    identities = load(root / EXPORT / "identities.json")
    bindings = table_bindings(model, registry)
    tables, records, support, sheets, counts, metadata = workbook_rows(root / WORKBOOK, bindings)
    checks = validate_records(model, registry, identities, bindings, records)
    require(checks["factRows"] == owner_manifest["counts"]["acceptedObservations"],
            "Owner export observation count differs")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".aicompanies-packet-", dir=output.parent) as scratch:
        staging = Path(scratch) / "packet"
        staging.mkdir(mode=0o700)
        table_catalog = {}
        for name, rows in records.items():
            relative = f"tables/{name}.ndjson.gz"
            gzip_rows(staging / relative, rows)
            table_catalog[name] = {**tables[name], "file": relative,
                "recordCount": len(rows), "kind": bindings[name]["kind"]}
        gzip_rows(staging / "worksheet-support.ndjson.gz", support)
        gzip_bytes(staging / "workbook-metadata.json.gz", json.dumps(metadata, sort_keys=True).encode())
        gzip_bytes(staging / "table-schemas.json.gz", json.dumps(table_catalog, sort_keys=True).encode())
        # Preserve original JSON bytes, including every policy/evidence/registry extra.
        raw_sources = {MODEL: "model.json", "dimension-schema.json": "dimension-schema.json",
            REGISTRY: "accepted-facts.json", EXPORT + "/identities.json": "identities.json",
            EXPORT + "/hierarchies.json": "hierarchies.json", EXPORT + "/comparisons.json": "comparisons.json",
            EXPORT + "/manifest.json": "owner-manifest.json"}
        for name, destination in raw_sources.items():
            gzip_bytes(staging / "source" / (destination + ".gz"), (root / name).read_bytes())
        for name, expected in pins.items():
            require(digest(source_file(root, name)) == expected["sha256"], "Source changed during preparation")
        for name, expected in exported.items():
            require(digest(source_file(root, name)) == expected["sha256"], "Owner export changed during preparation")
        files = {str(path.relative_to(staging)): {"sha256": digest(path), "bytes": path.stat().st_size}
                 for path in sorted(staging.rglob("*")) if path.is_file()}
        manifest = {"format": FORMAT, "applicationName": "AIcompanies", "readOnly": True,
            "sourceRoot": str(root), "sourcePins": pins, "verifiedOwnerExportFiles": exported,
            "sourceRevision": owner_manifest["revisionId"], "grain": model["grain"],
            "tables": {name: {key: value for key, value in item.items() if key != "sourceTableXml"}
                       for name, item in table_catalog.items()}, "sheets": sheets,
            "workbookCounts": counts, "checks": checks, "files": files,
            "numericContract": "Original numeric XML lexical strings; cellTypes preserves storage type. No float conversion, scaling, rounding or ratio/amount substitution.",
            "scope": "Source extraction and exact reconciliation only. No target operations or semantic remapping. Queue/evidence/comparison rows retain separate typed identities. Original JSON bytes and all named-table fields/formulas are preserved. Workbook drawing/media assets are outside this packet; original workbook hash remains pinned."}
        (staging / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        for path in staging.rglob("*"):
            path.chmod(0o700 if path.is_dir() else 0o600)
        os.rename(staging, output)
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = prepare(args.source_root, args.output_dir)
    except (SourceError, OSError, ValueError, KeyError, zipfile.BadZipFile, ET.ParseError) as error:
        parser.exit(2, f"Source preparation failed: {error}\n")
    print(json.dumps({"manifest": str(args.output_dir.resolve() / "manifest.json"),
        "sourceRevision": result["sourceRevision"], "factRows": result["checks"]["factRows"],
        "tables": len(result["tables"]), "readOnly": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
