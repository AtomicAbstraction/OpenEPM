"""Prepare useful, fully scoped AIcompanies saved-grid requests offline.

Every fact axis is either a fixed POV or an explicit row/column dimension. These
are raw observation views, not aggregations or derived accounting statements.
"""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from epm_core.postgres_saved_grids import PostgresSavedGrids
from scripts.aicompanies_mcp_journey import (
    AXES, canonical, digest, exact_json, iter_source_rows, load_packet,
)

FORMAT = "openepm-aicompanies-saved-views-v1"
DIMENSIONS = tuple(target for _, _, target in AXES) + ("Value",)
FINANCIAL = {"SourceCurrency": "CUR_USD", "DataType": "O_WEB_REP",
             "View": "V_YTD", "Movement": "M_NA", "Value": "SourceObservation"}
HEADCOUNT = {"Account": "STAT_HC_CLOSE", "SourceCurrency": "CUR_NONE",
            "View": "V_PER", "Movement": "M_CLOSE", "Value": "SourceObservation"}
VIEW_SPECS = (
    ("aic.actual.revenue.usd", "Actual reported revenue — USD, YTD",
     {**FINANCIAL, "Account": "IS_REV", "Scenario": "SC_ACTUALS"}, ["Year", "Period"], "USD"),
    ("aic.actual.net-income.usd", "Actual reported net income — USD, YTD",
     {**FINANCIAL, "Account": "IS_NET", "Scenario": "SC_ACTUALS"}, ["Year", "Period"], "USD"),
    ("aic.actual.headcount.estimates", "Actual headcount — source estimates, people",
     {**HEADCOUNT, "Scenario": "SC_ACTUALS", "DataType": "O_WEB_EST"}, ["Year", "Period"], "People"),
    ("aic.revenue.scenario-comparison.usd", "Reported revenue — Actual and Simulation, USD",
     {**FINANCIAL, "Account": "IS_REV"}, ["Scenario", "Year", "Period"], "USD"),
    ("aic.simulation.headcount.allocations", "Simulation allocated headcount — people",
     {**HEADCOUNT, "Scenario": "SC_SIMULATION", "DataType": "O_ALLOC"}, ["Year", "Period"], "People"),
    ("aic.actual.operating-income.usd", "Actual reported operating income — USD, YTD",
     {**FINANCIAL, "Account": "IS_OP", "Scenario": "SC_ACTUALS"}, ["Year", "Period"], "USD"),
    ("aic.actual.assets.usd", "Actual reported total assets — USD, period-end stock",
     {**FINANCIAL, "Account": "BS_ASSETS", "Scenario": "SC_ACTUALS", "View": "V_PER",
      "Movement": "M_UNDEFINED"}, ["Year", "Period"], "USD"),
    ("aic.actual.operating-cash-control.usd", "Source calculated operating cash before working capital — USD",
     {**FINANCIAL, "Account": "CF_OPER_BEFORE_WC", "Scenario": "SC_ACTUALS",
      "DataType": "O_CALC_DERIVED"}, ["Year", "Period"], "USD"),
)


def view_definition(grid_id,name,pov,columns,metadata_revision,selected):
    rows = [dimension for dimension in DIMENSIONS if dimension not in pov and dimension not in columns]
    member_ids={dimension:sorted({members[dimension] for _,members in selected})
                for dimension in DIMENSIONS}
    definition={"format":"openepm-cube-view-v1","viewId":grid_id,
        "name":name,"selection":{"format":"openepm-cube-selection-v1",
          "metadataRevision":metadata_revision,"dimensions":[
            {"dimensionId":dimension,
             "include":({"kind":"member","memberId":pov[dimension]}
               if dimension in pov else
               {"kind":"members","memberIds":member_ids[dimension]}),
             "exclude":None} for dimension in DIMENSIONS]},
        "layout":{"pages":[],"rows":rows,"columns":list(columns),
          "filters":sorted(pov)},
        "dataSource":{"kind":"raw","resultKey":None},
        "suppression":{"missing":False,"zero":False},"pageSize":100}
    definition=PostgresSavedGrids._definition(
        definition,active_dimensions=DIMENSIONS)
    if set(rows) | set(columns) | set(pov) != set(DIMENSIONS):
        raise ValueError("SAVED_VIEW_INCOMPLETE_GRAIN")
    return definition


def prepare_views(records, metadata_revision, packet_sha256, *, workspace_id="ws-pilot", application_id="AIcompanies"):
    if type(metadata_revision) is not int or metadata_revision < 1:
        raise ValueError("SAVED_VIEW_METADATA_REVISION_INVALID")
    source = []; seen_ids = set(); seen_coordinates = set()
    for record in records:
        fields = record["fields"]
        members = {target: fields[key] for key, _, target in AXES} | {"Value": "SourceObservation"}
        identity = record["recordId"]
        if identity in seen_ids or canonical(members) in seen_coordinates:
            raise ValueError("SAVED_VIEW_SOURCE_IDENTITY_OR_GRAIN_DUPLICATE")
        seen_ids.add(identity); seen_coordinates.add(canonical(members))
        source.append((record, members))
    requests, summaries = [], []
    for grid_id, name, pov, columns, unit in VIEW_SPECS:
        selected = [(record, members) for record, members in source if all(members[axis] == member for axis, member in pov.items())]
        if not selected:
            raise ValueError("SAVED_VIEW_EMPTY_SOURCE_SLICE:" + grid_id)
        definition=view_definition(grid_id,name,pov,columns,
            metadata_revision,selected)
        units = Counter(record["fields"]["ValueUnit"] for record, _ in selected)
        if set(units) != {unit}:
            raise ValueError("SAVED_VIEW_SOURCE_UNIT_MISMATCH:" + grid_id)
        scenarios = Counter(members["Scenario"] for _, members in selected)
        if "Scenario" in columns and set(scenarios) != {"SC_ACTUALS", "SC_SIMULATION"}:
            raise ValueError("SAVED_VIEW_COMPARISON_SCENARIOS_CHANGED")
        arguments = {"gridId": grid_id,
                     "definition": definition, "expectedMetadataRevision": metadata_revision}
        program = {"languageVersion": 2, "function": "grid.definition.save", "arguments": arguments}
        identity = digest({"format": FORMAT, "sourcePacket": packet_sha256,
            "workspaceId": workspace_id, "applicationId": application_id, "program": program})
        requests.append({"id": "aic.grid." + identity[:24], "route": "application",
            "tool": "execute_v2_metadata_program", "arguments": {"workspace_id": workspace_id,
                "application_id": application_id, "program": program,
                "idempotency_key": "aic-" + identity}})
        summaries.append({"gridId": grid_id, "name": name, "definition": definition,
            "expectedSourceRows": len(selected), "units": dict(units), "scenarioCounts": dict(scenarios),
            "qualifierCounts": dict(Counter(record["fields"]["ValueQualifier"] for record, _ in selected)),
            "sourceRecordIdsSha256": digest(sorted(record["recordId"] for record, _ in selected)),
            "sourceCoordinatesAndValuesSha256": digest(sorted([[canonical(members), record["numericLexicalValue"]] for record, members in selected])),
            "savedDefinitionCanonicalDigest": digest(definition)})
    return requests, summaries


def generate(manifest_path, pin, output, metadata_revision, *, workspace_id="ws-pilot", application_id="AIcompanies"):
    manifest, _, _ = load_packet(manifest_path, pin)
    records = list(iter_source_rows(manifest_path, manifest, "FactFinancial"))
    if len(records) != manifest["tables"]["FactFinancial"]["recordCount"]:
        raise ValueError("SAVED_VIEW_SOURCE_COUNT_MISMATCH")
    requests, summaries = prepare_views(records, metadata_revision, pin,
        workspace_id=workspace_id, application_id=application_id)
    raw = ("\n".join(canonical(row) for row in requests) + "\n").encode()
    summary = {"format": FORMAT, "workspaceId": workspace_id, "applicationId": application_id,
        "sourcePacketManifestSha256": pin, "sourceRevision": manifest["sourceRevision"],
        "expectedMetadataRevision": metadata_revision, "targetMutationPerformed": False,
        "generatorSourceSha256": sha256(Path(__file__).read_bytes()).hexdigest(),
        "requestFile": {"path": "saved-grids.jsonl", "requests": len(requests), "bytes": len(raw), "sha256": sha256(raw).hexdigest()},
        "views": summaries,
        "dispatchPrerequisites": ["Confirm final target metadata revision and absence of these grid IDs/version1 before initial save.", "Capture exact source-complete cube readback before declaring expected row counts qualified in the target."],
        "semantics": ["Raw complete-coordinate observations only; no cross-scenario, origin, unit or dimensional totals.", "YTD periods overlap and must not be summed across time. Simulation contains seeds/control copies and allocation observations; do not sum across Scenario or related breakdown/control scopes.", "Numeric cells do not themselves encode source ValueQualifier; '~' headcount values remain estimates. Consult the related source record for qualifier, evidence and aggregation policy."]}
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    for name, contents in (("saved-grids.jsonl", raw), ("summary.json", (json.dumps(summary, indent=2, ensure_ascii=False) + "\n").encode())):
        with (output / name).open("xb") as stream:
            stream.write(contents)
        (output / name).chmod(0o600)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--metadata-revision", type=int, required=True)
    parser.add_argument("--workspace-id", default="ws-pilot")
    parser.add_argument("--application-id", default="AIcompanies")
    args = parser.parse_args()
    result = generate(args.manifest, args.manifest_sha256, args.output, args.metadata_revision,
        workspace_id=args.workspace_id, application_id=args.application_id)
    print(canonical({"requestFile": result["requestFile"], "views": [{"gridId": view["gridId"], "expectedSourceRows": view["expectedSourceRows"], "qualifierCounts": view["qualifierCounts"]} for view in result["views"]]}))


if __name__ == "__main__":
    main()
