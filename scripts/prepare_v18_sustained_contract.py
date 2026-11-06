#!/usr/bin/env python3
"""Seal one executable V18 sustained-run contract from runtime manifests."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.v18_local_sustained_contract import (  # noqa: E402
    FAMILY_ACTION_PROFILES, FAMILY_IDENTITIES, FAMILY_MODES, FAMILIES,
    FORMAT, LocalSustainedContract, TERMINAL_PROFILES)


class V18ContractPreparationError(ValueError):
    """The runtime manifests cannot produce an exact runnable contract."""


def _fail(code: str) -> None:
    raise V18ContractPreparationError(code)


def _read(path: Path, expected_format: str) -> dict:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        _fail("V18_CONTRACT_MANIFEST_INVALID")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise V18ContractPreparationError(
            "V18_CONTRACT_MANIFEST_INVALID") from error
    if type(value) is not dict or value.get("format") != expected_format:
        _fail("V18_CONTRACT_MANIFEST_INVALID")
    return value


def _action(tool: str, function: str | None, arguments: dict, *,
            capture: str | None = None,
            capture_path: list[str] | None = None,
            extra: dict | None = None,
            expect_path: list[str] | None = None,
            expect: str = "completed") -> dict:
    payload = dict(arguments) if function is None else {"program": {
        "languageVersion": 2, "function": function,
        "arguments": arguments}}
    payload.setdefault("workspace_id", "{workspaceId}")
    payload.setdefault("application_id", "{applicationId}")
    payload.update(extra or {})
    return {"tool": tool, "arguments": payload,
        "expectPath": expect_path or ["status"],
        "expectTemplate": expect,
        "capturePath": (capture_path or [capture] if capture else None),
        "captureAs": capture}


def _workload() -> dict:
    roles = ("Account", "Entity", "Year", "Period", "View", "Value")
    dimensions = roles + ("V18Custom",)
    coordinate = {role: "V18." + role +
                  (".Target" if role == "Account" else ".Base")
                  for role in dimensions}
    aggregate_query = {"source": "raw_numeric", "grain": {
        "inputDimensions": sorted(coordinate), "groupBy": sorted(roles),
        "reduceDimensions": ["V18Custom"]},
        "selectors": {}, "measures": [
            {"kind": "SumAmount"}, {"kind": "CountPresent"}],
        "missing": "exclude", "aggregation": "unique_coordinate_sum"}
    actions = {
        "read": _action("read_v2_program", "facts.generic.value.read",
            {"tableId": "provisioned-at-runtime",
             "seriesKey": "{readerSeriesKey}"},
            expect_path=["result", "value"], expect="{readerExpectation}"),
        "write": _action("execute_v2_generic_fact_program",
            "facts.generic.value.set", {"tableId": "provisioned-at-runtime",
            "seriesKey": "{writerSeriesKey}", "value": "{writerExpectation}",
            "expectedChangeId": "provisioned-at-runtime",
            "expectedDataRevision": 1},
            extra={"idempotency_key": "v18-generic-sentinel-replay"},
            expect_path=["result", "dataRevision"], expect="2"),
        "query": _action("read_v2_program", "facts.cube.aggregate.request",
            {"query": aggregate_query, "limits": {"pageSize": 100,
            "ttlSeconds": 900}}, capture="queryId",
            capture_path=["result", "queryId"], expect_path=["function"],
            expect="facts.cube.aggregate.request"),
        "queryCancel": _action("read_v2_program",
            "facts.cube.aggregate.cancel", {"queryId": "{queryId}"},
            expect_path=["result", "status"],
            expect="$oneof:cancel_requested,cancelled"),
        "queryCancelledRead": _action("read_v2_program",
            "facts.cube.aggregate.read", {"queryId": "{queryId}"},
            expect_path=["result", "status"], expect="cancelled"),
        "invariantAudit": _action("read_v2_program",
            "facts.generic.value.read", {"tableId": "provisioned-at-runtime",
            "seriesKey": "{writerSeriesKey}"},
            expect_path=["result", "value"], expect="{writerExpectation}"),
    }
    families = {}
    for name, profiles in FAMILY_ACTION_PROFILES.items():
        family_actions = []
        for index, (tool, function) in enumerate(profiles):
            arguments = {"definitionId": name}
            kwargs = {}
            if name == "numeric":
                arguments = {"mutations": [{"coordinate": coordinate,
                    "op": "set", "value": {"type": "AmountLiteral",
                    "decimal": "1"}, "expectedChangeId":
                    "{numericExpectedChangeId}"}]}
                if index == 0:
                    kwargs = {"capture": "previewToken",
                        "capture_path": ["previewToken"],
                        "expect_path": ["function"],
                        "expect": "facts.numeric.batch"}
                else:
                    kwargs = {"capture": "numericJobId",
                        "capture_path": ["jobId"],
                        "extra": {"preview_token": "{previewToken}",
                                  "idempotency_key": "{requestId}"},
                        # A dependency-free numeric job is admitted directly
                        # to the authoritative ready queue.  "accepted" is
                        # reserved for jobs still waiting on dependencies.
                        "expect": "ready"}
            elif name == "aggregate":
                arguments = {"query": aggregate_query,
                    "limits": {"pageSize": 100, "ttlSeconds": 900}}
                kwargs = {"capture": "aggregateQueryId",
                    "capture_path": ["result", "queryId"],
                    "expect_path": ["function"],
                    "expect": "facts.cube.aggregate.request"}
            elif name == "application_rule":
                arguments = {"ruleId": "v18.generic.rule", "bindings": {}}
                kwargs = {"capture": "ruleWorkflowId",
                    "capture_path": ["result", "workflowId"],
                    "extra": {"idempotency_key": "{requestId}"},
                    "expect_path": ["function"],
                    "expect": "application.rule.run"}
            elif name == "python_build":
                arguments = {"programId": "v18.python.program",
                    "programVersion": 1, "parameters": {
                        "coordinate": coordinate},
                    "delegationId": "v18.python.authority",
                    "delegationVersion": 1, "scheduleId": None,
                    "scheduleVersion": None, "expectedMetadataRevision": 1,
                    "expectedPolicyRevision": 1, "expectedSchemaEpoch": 1}
                kwargs = {"capture": "pythonBuildId",
                    "capture_path": ["result", "buildId"],
                    "extra": {"idempotency_key": "{requestId}"},
                    "expect_path": ["function"],
                    "expect": "python.program.build"}
            elif name == "python_workflow":
                arguments = {"buildId": "{pythonBuildId}"}
                kwargs = {"capture": "pythonWorkflowId",
                    "capture_path": ["result", "workflowId"],
                    "extra": {"idempotency_key": "{requestId}"},
                    "expect_path": ["function"],
                    "expect": "python.program.run"}
            elif name in {"application_schedule", "application_workflow"}:
                arguments = ({"limit": 100} if name == "application_schedule"
                             else {})
                kwargs = {"expect_path": ["function"],
                    "expect": ("schedule.version.list" if
                               name == "application_schedule" else
                               "application.workflow.worklist")}
            elif name == "python_schedule":
                arguments = {"workspace_id": "{workspaceId}",
                    "application_id": "{applicationId}",
                    "after_sequence": "{pythonScheduleAfterSequence}",
                    "limit": 500}
                kwargs = {"expect_path": ["tasks"],
                    "expect": "worker-created-published-occurrence"}
            family_actions.append(_action(tool, function, arguments, **kwargs))
        families[name] = {"mode": FAMILY_MODES[name],
                          "actions": family_actions}
        if name == "numeric":
            families[name]["postAction"] = _action(
                "read_v2_program", "facts.cube.scan",
                {"members": coordinate, "limit": 1},
                capture="numericExpectedChangeId",
                capture_path=["result", "rows", 0, "numericChangeId"],
                expect_path=["function"], expect="facts.cube.scan")
    terminals = {}
    for name, (tool, function) in TERMINAL_PROFILES.items():
        capture, argument = FAMILY_IDENTITIES[name]
        arguments = {argument: "{" + capture + "}"}
        kwargs = {}
        if name == "aggregate":
            arguments["pageSize"] = 100
            kwargs = {"expect_path": ["result", "status"],
                      "expect": "sealed"}
        elif name == "application_rule":
            kwargs = {"expect_path": ["result", "status"],
                      "expect": "published"}
        elif name == "numeric":
            kwargs = {"expect": "published"}
        elif name == "python_build":
            kwargs = {"expect": "sealed"}
        elif name == "python_workflow":
            kwargs = {"expect": "published"}
        terminals[name] = {"settleSeconds": 60,
            "action": _action(tool, function, arguments, **kwargs)}
    return {**actions, "families": families, "familyTerminal": terminals}


def prepare(runtime_path: Path, identity_path: Path, output: Path) -> dict:
    runtime = _read(runtime_path, "openepm-v18-compose-runtime-v1")
    identity = _read(identity_path, "openepm-v18-identity-v1")
    if (runtime.get("identityManifest") != str(identity_path)
            or runtime.get("marker") != identity.get("ownershipMarker")
            or runtime.get("ownerRuntimeChanged") is not False
            or not identity.get("refreshable")):
        _fail("V18_CONTRACT_MANIFEST_MISMATCH")
    if (not output.is_absolute() or output.exists() or output.is_symlink()
            or not output.parent.is_dir() or output.parent.is_symlink()):
        _fail("V18_CONTRACT_OUTPUT_INVALID")
    marker = runtime["marker"]
    result = output.parent / "sustained-result.json"
    cleanup = output.parent / "sustained-cleanup.json"
    if any(path.exists() or path.is_symlink() for path in (result, cleanup)):
        _fail("V18_CONTRACT_EVIDENCE_ALREADY_EXISTS")
    contract = {"format": FORMAT, "claim": "bounded-local-non-final",
        "artifacts": {"sourceCommit": runtime["sourceCommit"],
            "sourceTree": runtime["sourceTree"],
            "schemaMigration": runtime["schemaMigration"],
            "applicationImageDigest": runtime["applicationImage"]["digest"],
            "databaseImageDigest": runtime["databaseImage"]["digest"]},
        "target": {"mcpUrl": runtime["endpoints"]["application"],
            "oidcIssuer": identity["issuer"],
            "oidcAudience": identity["audience"],
            "oidcCaFile": identity["caFile"],
            "composeProject": runtime["project"],
            "composeExecutable": runtime["composeExecutable"],
            "composeFiles": runtime["composeFiles"],
            "composeEnvFile": runtime["composeEnvFile"],
            "platformMcpUrl": runtime["endpoints"]["platform"],
            "workspaceMcpUrl": runtime["endpoints"]["workspace"],
            "resetMcpUrl": runtime["endpoints"]["reset"],
            "webUrl": runtime["endpoints"]["web"],
            "hostSampler": "docker-compose-cgroup-v1",
            "sampleServices": ["db", "platform", "workspace", "router",
                "web", "worker", "python-build-broker"],
            "sandboxHostDirectory": runtime["sandboxHostDirectory"],
            "sandboxControlSocket": runtime["sandboxControlSocket"],
            "sandboxNetwork": runtime["sandboxNetwork"]},
        "load": {"durationSeconds": 1800, "warmupSeconds": 120,
            "sessionCount": 1, "operationsPerMinute": 6,
            "families": sorted(FAMILIES)},
        "identity": {"subject": identity["subject"],
            "tokenFile": identity["tokenFile"]},
        "application": {"workspaceId": runtime["workspaceId"],
            "applicationId": runtime["applicationId"],
            "ownedDisposable": True, "ownershipMarker": marker,
            "readerExpectation": "reader-sentinel",
            "writerExpectation": "writer-sentinel",
            "readerSeriesKey": "reader", "writerSeriesKey": "writer",
            "numericExpectedChangeId": "",
            "pythonScheduleId": "v18.python.schedule",
            "pythonScheduleOccurrenceSource":
                "worker-created-durable-occurrences",
            "families": sorted(FAMILIES)},
        "controls": {"cancelEverySeconds": 60, "cancelSettleSeconds": 60,
            "scheduleOccurrenceSettleSeconds": 180,
            "workerRestartAtSeconds": 900, "workerService": "worker"},
        "budgets": {"maximumConnections": 50, "maximumMemoryGiB": 12,
            "maximumTemporaryDiskGiB": 4, "maximumCpuPercent": 600,
            "maximumP99Seconds": 5, "maximumQueueP99Seconds": 5},
        "workload": _workload(),
        "cleanup": {"ownershipMarker": marker,
            "composeProject": runtime["project"],
            "requireApplicationAbsent": True,
            "requireContainersAbsent": True, "requireVolumesAbsent": True,
            "evidenceOutput": str(cleanup)},
        "evidence": {"output": str(result), "sampleEverySeconds": 5},
        "exclusions": {"finalReleaseQualification": False,
            "threeHundredSessionQualification": False,
            "runscQualification": False, "notebookQualification": False,
            "cleanHostQualification": False}}
    LocalSustainedContract(contract).validate()
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(contract, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return {"status": "prepared", "config": str(output),
        "marker": marker, "secretsPrinted": False}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-manifest", type=Path, required=True)
    parser.add_argument("--identity-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        result = prepare(arguments.runtime_manifest.resolve(),
                         arguments.identity_manifest.resolve(),
                         arguments.output.resolve())
    except (OSError, KeyError, TypeError, V18ContractPreparationError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
