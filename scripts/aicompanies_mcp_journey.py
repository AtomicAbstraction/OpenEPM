"""Generate reviewable AIcompanies MCP intents from a pinned offline source packet.

No network, authentication, dispatch or automatic retry. Metadata revisions form
one sequential CAS chain; replay the original bytes rather than rebasing failures.
"""
from __future__ import annotations

import argparse
from collections import Counter
from decimal import Decimal, InvalidOperation
import gzip
from hashlib import sha256
import json
from pathlib import Path
import re

FORMAT = "openepm-aicompanies-metadata-journey-v1"
AXES = (
    ("CompanyKey", "DimCompany", "Entity"),
    ("AccountKey", "DimAccount", "Account"),
    ("MovementKey", "DimMovement", "Movement"),
    ("YearKey", "DimYear", "Year"),
    ("PeriodKey", "DimPeriod", "Period"),
    ("ViewKey", "DimView", "View"),
    ("ProductKey", "DimProduct", "Product"),
    ("SegmentKey", "DimSegment", "Segment"),
    ("CostCenterKey", "DimCostCenter", "CostCenter"),
    ("DataOriginKey", "DimDataOrigin", "DataType"),
    ("CounterpartyKey", "DimCounterparty", "Counterparty"),
    ("GeographyKey", "DimGeography", "Geography"),
    ("ScenarioKey", "DimScenario", "Scenario"),
    ("CurrencyKey", "DimCurrency", "SourceCurrency"),
)
CORE = frozenset(("Account", "Entity", "Year", "Period", "View", "Value", "Scenario", "DataType"))
CONTRACTS = {
    "metadata.dimension.create": ({"dimensionId", "name", "modelRole", "expectedMetadataRevision"}, {"shortDescription", "detailedDescription"}),
    "metadata.dimension.rename": ({"dimensionId", "name", "expectedMetadataRevision"}, set()),
    "metadata.dimension.describe": ({"dimensionId", "shortDescription", "detailedDescription", "expectedMetadataRevision"}, set()),
    "metadata.member.create": ({"dimensionId", "memberId", "name", "expectedMetadataRevision"}, {"shortDescription", "detailedDescription"}),
    "metadata.member.status.set": ({"dimensionId", "memberId", "status", "expectedMetadataRevision"}, set()),
    "metadata.attribute-definition.create": ({"scope", "attributeId", "defaultName", "displayName", "shortDescription", "semanticDescription", "valueType", "validationConstraints", "expectedMetadataRevision"}, {"dimensionId"}),
    "metadata.attribute-value.set": ({"scope", "attributeId", "objectId", "value", "expectedMetadataRevision"}, {"dimensionId"}),
    "metadata.attribute-values.replace": ({"scope", "dimensionId", "attributeIds", "rows", "expectedMetadataRevision"}, set()),
}
IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,199}\Z")
SEMANTIC_FIELDS = ("Definition", "Description", "Meaning", "MeasurementBasis", "ScopeRequirement", "MissingnessMeaning", "RollupRule", "TimeAggregation", "CalculationRule", "Notes", "MetadataStatus")


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return sha256(canonical(value).encode()).hexdigest()


def exact_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("DUPLICATE_JSON_KEY")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("NONFINITE_JSON")))


def contained(root, relative):
    if not isinstance(relative, str) or Path(relative).is_absolute():
        raise ValueError("SOURCE_PATH_INVALID")
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("SOURCE_PATH_ESCAPES_ROOT")
    return path


def verify_file(path, pin):
    if not isinstance(pin, dict) or set(pin) != {"bytes", "sha256"}:
        raise ValueError("SOURCE_PIN_INVALID")
    hashed = sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            hashed.update(block)
    if size != pin["bytes"] or hashed.hexdigest() != pin["sha256"]:
        raise ValueError("SOURCE_FILE_PIN_MISMATCH:" + path.name)


def load_packet(path, expected_sha256):
    raw = path.read_bytes()
    if sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("PACKET_MANIFEST_PIN_MISMATCH")
    manifest = exact_json(raw)
    if (manifest.get("format") != "openepm-aicompanies-source-packet-v1"
            or manifest.get("readOnly") is not True
            or manifest.get("grain") != [a[0] for a in AXES]):
        raise ValueError("PACKET_CONTRACT_MISMATCH")
    root = path.parent
    for relative, pin in manifest["files"].items():
        verify_file(contained(root, relative), pin)
    source_root = Path(manifest["sourceRoot"])
    if not source_root.is_absolute():
        raise ValueError("SOURCE_ROOT_INVALID")
    for relative, pin in manifest["sourcePins"].items():
        verify_file(contained(source_root, relative), pin)
    schema = exact_json(gzip.decompress((root / "source/dimension-schema.json.gz").read_bytes()))
    schemas = {row["key"]: row for row in schema["dimensions"]}
    if set(schemas) != {a[0] for a in AXES}:
        raise ValueError("SOURCE_DIMENSION_SCHEMA_MISMATCH")
    tables = {}
    for key, table, _ in AXES:
        spec = manifest["tables"][table]
        relative = spec["file"]
        if relative not in manifest["files"] or spec["kind"] != "dimension":
            raise ValueError("SOURCE_TABLE_UNPINNED")
        rows = [exact_json(line) for line in gzip.decompress(contained(root, relative).read_bytes()).splitlines()]
        if len(rows) != spec["recordCount"] or spec["columns"][0] != key:
            raise ValueError("SOURCE_TABLE_COUNT_OR_KEY_MISMATCH")
        for row in rows:
            if (row["table"] != table or row["role"] != "dimension_member"
                    or set(row["fields"]) != set(spec["columns"])
                    or set(row["cellTypes"]) != set(spec["columns"])
                    or row["formulas"]):
                raise ValueError("SOURCE_MASTER_ROW_CONTRACT_MISMATCH")
        tables[table] = rows
    return manifest, schemas, tables


def load_live(catalog_path, responses_path, workspace_id, application_id):
    catalog_raw = catalog_path.read_bytes()
    catalog = exact_json(catalog_raw)
    responses = {}
    for line in responses_path.read_bytes().splitlines():
        response = exact_json(line)
        if "id" in response:
            if response["id"] in responses and responses[response["id"]] != response:
                raise ValueError("AMBIGUOUS_CAPTURED_RESPONSE")
            responses[response["id"]] = response
    def result(identifier):
        response = responses[identifier]
        if response.get("ok") is not True:
            raise ValueError("CAPTURED_READ_NOT_SUCCESSFUL:" + identifier)
        return response["result"]
    creation = result("create." + application_id)
    captured = result("discovery." + application_id + ".functions")
    state = result("read." + application_id + ".initial-state")["result"]
    dimensions = result("read." + application_id + ".dimensions")["result"]
    if (creation.get("workspaceId") != workspace_id or creation.get("applicationId") != application_id
            or creation.get("kind") != "multidimensional" or creation.get("blueprintVersion") != 2
            or set(creation.get("dimensions", ())) != CORE
            or catalog != captured or catalog.get("languageVersion") != 2
            or state.get("status") != "Active" or state.get("metadataRevision") != 1
            or state.get("dataRevision") != 0 or dimensions.get("metadataRevision") != 1
            or dimensions.get("hasMore") is not False
            or dimensions.get("nextAfterDimensionId") is not None
            or {r["dimension_id"] for r in dimensions["rows"]} != CORE
            or any(r["model_role"] != r["dimension_id"] or r["status"] != "Active" for r in dimensions["rows"])):
        raise ValueError("TARGET_BASELINE_OR_CATALOG_MISMATCH")
    functions = catalog["functions"]
    for function, (required, optional) in CONTRACTS.items():
        contract = functions.get(function, {})
        if (set(contract.get("arguments", {})) != required
                or set(contract.get("optionalArguments", {})) != optional
                or contract.get("mode") != "atomic_write" or contract.get("permission") != "admin"
                or contract.get("previewRequired") is not False
                or contract.get("idempotencyRequired") is not True
                or contract.get("requiredCapabilities") != []):
            raise ValueError("LIVE_FUNCTION_CONTRACT_MISMATCH:" + function)
    return {"catalogSha256": sha256(catalog_raw).hexdigest(),
            "catalogRegistryDigest": catalog["registryDigest"],
            "initialState": state, "creationResponseDigest": digest(creation),
            "dimensionResponseDigest": digest(dimensions),
            "initialStateResponseDigest": digest(state)}


def nonempty(value):
    return value is not None and value != ""


def source_text(value, maximum=10000):
    if not isinstance(value, str) or "\x00" in value or len(value) > maximum:
        raise ValueError("SOURCE_TEXT_BOUND_OR_TYPE_INVALID")
    return value


def summary_text(text, maximum=500):
    return text if len(text) <= maximum else text[:maximum - 1].rsplit(" ", 1)[0] + "…"


def member_descriptions(fields, key, name):
    pieces = []
    for field in SEMANTIC_FIELDS:
        value = fields.get(field)
        if nonempty(value):
            text = source_text(value)
            if not text.lstrip().startswith(("{", "[")):
                pieces.append(f"{field}: {text}")
    detail = "\n".join(pieces) or f"{name}; original {key} {fields[key]}."
    source_text(detail)
    short = summary_text(pieces[0] if pieces else detail)
    return short, detail


def attribute_id(field):
    return field if IDENTIFIER.fullmatch(field) else "source." + sha256(field.encode()).hexdigest()[:32]


def iter_source_rows(manifest_path, manifest, table):
    """Read a named table only after load_packet has verified its manifest."""
    relative = manifest["tables"][table]["file"]
    if relative not in manifest["files"]:
        raise ValueError("SOURCE_TABLE_UNPINNED")
    path = contained(manifest_path.parent, relative)
    verify_file(path, manifest["files"][relative])
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        for line in stream:
            yield exact_json(line)


def field_kind(rows, field):
    kinds = {r["cellTypes"][field] for r in rows if nonempty(r["fields"][field])}
    if not kinds:
        return None
    if kinds == {"b"}:
        return "Boolean"
    if kinds == {"n"}:
        return "Decimal"
    if kinds <= {"str", "s", "inlineStr", "n"}:
        return "Text"
    raise ValueError("SOURCE_ATTRIBUTE_MIXED_OR_UNSUPPORTED_TYPE:" + field)


def attribute_value(row, field, kind):
    value = source_text(row["fields"][field])
    if kind == "Boolean":
        if value not in ("0", "1"):
            raise ValueError("SOURCE_BOOLEAN_INVALID")
        return value == "1"
    if kind == "Decimal":
        try:
            number = Decimal(value)
            if (not number.is_finite() or abs(number) >= Decimal("1e20")
                    or number != number.quantize(Decimal("0.00000001"))):
                raise ValueError("SOURCE_DECIMAL_OUT_OF_RANGE")
        except InvalidOperation as error:
            raise ValueError("SOURCE_DECIMAL_INVALID") from error
    return value


def build_stages(manifest, schemas, tables, packet_sha256, workspace_id, application_id):
    stages = {"base": [], "attributes": [], "status": []}
    revision = 1
    def add(stage, function, args):
        nonlocal revision
        args = {**args, "expectedMetadataRevision": revision}
        required, optional = CONTRACTS[function]
        if not required <= set(args) or set(args) - required - optional:
            raise ValueError("GENERATED_ARGUMENT_CONTRACT_MISMATCH")
        program = {"languageVersion": 2, "function": function, "arguments": args}
        identity = digest({"domain": FORMAT, "packet": packet_sha256,
            "workspaceId": workspace_id, "applicationId": application_id, "program": program})
        stages[stage].append({"id": f"aic.{stage}.{revision:06d}", "route": "application",
            "tool": "execute_v2_metadata_program", "arguments": {
                "workspace_id": workspace_id, "application_id": application_id,
                "program": program, "idempotency_key": "aic-" + identity}})
        revision += 1
    names = {}; member_ids = set(); renames = []; per_dimension = []
    for key, table, target in AXES:
        schema = schemas[key]; meaning = source_text(schema["meaning"])
        label = source_text(schema["label"], 200)
        if target in CORE:
            if target == "Entity" or target == "DataType":
                add("base", "metadata.dimension.rename", {"dimensionId": target, "name": label})
            add("base", "metadata.dimension.describe", {"dimensionId": target,
                "shortDescription": summary_text(meaning), "detailedDescription": meaning})
        else:
            add("base", "metadata.dimension.create", {"dimensionId": target, "name": label,
                "modelRole": "Custom", "shortDescription": summary_text(meaning), "detailedDescription": meaning})
        rows = tables[table]; name_field = manifest["tables"][table]["columns"][1]
        groups = Counter(source_text(r["fields"][name_field], 200).strip().lower() for r in rows)
        final_names = set()
        for row in rows:
            fields = row["fields"]; member = source_text(fields[key], 200)
            if not member or member != member.strip() or member in member_ids or member == "SourceObservation":
                raise ValueError("SOURCE_MEMBER_ID_COLLISION_OR_INVALID")
            member_ids.add(member)
            original = source_text(fields[name_field], 200)
            name = original.strip()
            if not name:
                raise ValueError("SOURCE_MEMBER_NAME_EMPTY")
            if groups[name.lower()] > 1:
                name += f" [{member}]"
            if name != original:
                renames.append({"dimensionId": target, "memberId": member, "sourceName": original, "targetName": name})
            source_text(name, 200)
            if name.lower() in final_names:
                raise ValueError("TARGET_MEMBER_NAME_COLLISION")
            final_names.add(name.lower()); names[member] = name
        per_dimension.append({"sourceKey": key, "sourceTable": table, "dimensionId": target,
            "modelRole": target if target in CORE else "Custom", "sourceMemberCount": len(rows)})
    add("base", "metadata.dimension.describe", {"dimensionId": "Value",
        "shortDescription": "Original source observations.",
        "detailedDescription": "SourceObservation identifies the original numeric or text observation at the complete source grain. It adds no currency conversion, aggregation or accounting semantics."})
    for key, table, target in AXES:
        name_field = manifest["tables"][table]["columns"][1]
        for row in tables[table]:
            member = row["fields"][key]
            short, detail = member_descriptions(row["fields"], key, row["fields"][name_field])
            add("base", "metadata.member.create", {"dimensionId": target, "memberId": member,
                "name": names[member], "shortDescription": short, "detailedDescription": detail})
    add("base", "metadata.member.create", {"dimensionId": "Value", "memberId": "SourceObservation",
        "name": "Source observation", "shortDescription": "Original source observation at its complete grain.",
        "detailedDescription": "Preserves the source observation's value, currency, scenario, origin and other dimensions. No transformation is implied."})
    attribute_counts = {}
    for key, table, target in AXES:
        rows = tables[table]; columns = manifest["tables"][table]["columns"]
        if "SourceName" in columns:
            raise ValueError("SOURCE_NAME_ATTRIBUTE_RESERVED")
        kinds = {field: kind for field in columns if (kind := field_kind(rows, field))}
        kinds["SourceName"] = "Text"
        if len(kinds) > 200:
            raise ValueError("ATTRIBUTE_CONTEXT_LIMIT")
        attribute_counts[target] = dict(Counter(kinds.values()))
        for field, kind in kinds.items():
            semantic = (f"Exact original {columns[1]} display label from {table}, retained independently of target name disambiguation."
                if field == "SourceName" else f"Original {field} field from {table}. " +
                ("Source Boolean cells map 0 to false and 1 to true." if kind == "Boolean" else
                 "Source numeric cells retain exact decimal value without rounding." if kind == "Decimal" else
                 "Original lexical text is preserved; numeric-looking text and mixed text/numeric storage are not coerced."))
            add("attributes", "metadata.attribute-definition.create", {"scope": "Member", "dimensionId": target,
                "attributeId": attribute_id(field), "defaultName": field, "displayName": field,
                "shortDescription": f"Source {table}.{field}.", "semanticDescription": semantic,
                "valueType": kind, "validationConstraints": {"maximumLength": 10000} if kind == "Text" else {}})
        replacement_rows = []
        for row in rows:
            values = {}
            for field, kind in kinds.items():
                source_field = columns[1] if field == "SourceName" else field
                if nonempty(row["fields"][source_field]):
                    values[attribute_id(field)] = attribute_value(
                        row, source_field, kind)
            if values:
                replacement_rows.append({"objectId": row["fields"][key],
                                         "values": values})
        add("attributes", "metadata.attribute-values.replace", {
            "scope": "Member", "dimensionId": target,
            "attributeIds": [attribute_id(field) for field in kinds],
            "rows": replacement_rows})
    inactive = 0
    for key, table, target in AXES:
        for row in tables[table]:
            if row["cellTypes"]["IsActive"] != "b":
                raise ValueError("SOURCE_ACTIVE_FLAG_TYPE_INVALID")
            active = attribute_value(row, "IsActive", "Boolean")
            if not active:
                inactive += 1
                add("status", "metadata.member.status.set", {"dimensionId": target,
                    "memberId": row["fields"][key], "status": "Inactive"})
    return stages, {"axisMapping": per_dimension, "sourceMemberUniqueCount": len(member_ids),
        "targetMemberCount": len(member_ids) + 1, "inactiveSourceMembers": inactive,
        "disambiguatedNames": renames, "attributeDefinitions": attribute_counts,
        "attributeIdMappings": [{"sourceField": field, "attributeId": attribute_id(field)} for field in sorted({field for _, table, _ in AXES for field in manifest["tables"][table]["columns"] if attribute_id(field) != field})],
        "finalMetadataRevision": revision, "relationshipsGenerated": 0,
        "stageOrder": list(stages), "revisionPolicy": "Sequential CAS from captured metadata revision1; stop and reconcile any failure. Never rebase an original retry.",
        "statusPolicy": "All members are initially active; status stage restores source inactive flags only after attributes. Base alone is not completed migration."}


def generate(manifest_path, expected_sha256, catalog_path, responses_path, output, *, workspace_id="ws-pilot", application_id="AIcompanies", selected_stage="all"):
    manifest, schemas, tables = load_packet(manifest_path, expected_sha256)
    live = load_live(catalog_path, responses_path, workspace_id, application_id)
    stages, summary = build_stages(manifest, schemas, tables, expected_sha256, workspace_id, application_id)
    summary.update({"format": FORMAT, "packetManifestSha256": expected_sha256,
        "sourceRevision": manifest["sourceRevision"], "workspaceId": workspace_id,
        "applicationId": application_id, "liveContract": live,
        "generatorSourceSha256": sha256(Path(__file__).read_bytes()).hexdigest(), "files": {}})
    files = {}
    for stage, requests in stages.items():
        if selected_stage not in ("all", stage):
            continue
        raw = ("\n".join(canonical(r) for r in requests) + "\n").encode() if requests else b""
        files[stage + ".jsonl"] = raw
        summary["files"][stage] = {"path": stage + ".jsonl", "requestCount": len(requests),
            "bytes": len(raw), "sha256": sha256(raw).hexdigest(),
            "firstExpectedMetadataRevision": requests[0]["arguments"]["program"]["arguments"]["expectedMetadataRevision"] if requests else None,
            "resultingMetadataRevision": requests[-1]["arguments"]["program"]["arguments"]["expectedMetadataRevision"] + 1 if requests else None}
    files["summary.json"] = (json.dumps(summary, indent=2, ensure_ascii=False) + "\n").encode()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Complete preparation precedes all writes; refuse overwrite so original intents survive.
    if any((output / name).exists() for name in files):
        raise ValueError("OUTPUT_EXISTS_PRESERVE_ORIGINAL_INTENTS")
    for name, raw in files.items():
        with (output / name).open("xb") as stream:
            stream.write(raw)
        (output / name).chmod(0o600)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--responses", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workspace-id", default="ws-pilot")
    parser.add_argument("--application-id", default="AIcompanies")
    parser.add_argument("--stage", choices=("base", "attributes", "status", "all"), default="all")
    args = parser.parse_args(argv)
    summary = generate(args.manifest, args.manifest_sha256, args.catalog, args.responses, args.output,
        workspace_id=args.workspace_id, application_id=args.application_id, selected_stage=args.stage)
    print(json.dumps({"output": str(args.output), "files": summary["files"],
                      "sourceMemberUniqueCount": summary["sourceMemberUniqueCount"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
