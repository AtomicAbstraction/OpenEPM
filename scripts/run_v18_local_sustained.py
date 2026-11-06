#!/usr/bin/env python3
"""Run the bounded, non-final V18 local sustained contract.

This runner deliberately uses only the public MCP gateway plus the trusted
local control-plane adapter.  It cannot issue a final P21 qualification.
"""
from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.v18_local_sustained_contract import (  # noqa: E402
    LocalSustainedContract, LocalSustainedContractError)
from tests.v18_local_sustained_engine import LocalSustainedEngine  # noqa: E402
from tests.v18_local_sustained_compose import (  # noqa: E402
    IsolatedComposeEndpointController)
from tests.v18_local_sustained_control import (  # noqa: E402
    GovernedLocalControlPlane)
from tests.v18_local_sustained_lifecycle import (  # noqa: E402
    GovernedDisposableWorkspaceCleanup)
from tests.v18_local_sustained_provision import (  # noqa: E402
    GovernedApplicationPrerequisites, GovernedDisposableProvisioner,
    GovernedPythonPrerequisites)
from tests.v18_local_sustained_public import (  # noqa: E402
    LocalEndpointMcpTransport, LocalPublicMcpGateway,
    LocalTrustedControlPlane)


class ClosingEndpointRetirement:
    """Close client streams before retiring their exact upstream services."""

    def __init__(self, controller, transport, endpoints):
        self.controller = controller
        self.transport = transport
        self.endpoints = endpoints

    async def retire(self, workspace_id: str, endpoints: list[dict]) -> dict:
        for endpoint in self.endpoints:
            await self.transport.close_endpoint(endpoint)
        return await self.controller.retire(workspace_id, endpoints)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _output_path(value: str, label: str) -> Path:
    path = Path(value)
    if (not path.is_absolute() or path.exists() or path.is_symlink()
            or not path.parent.is_dir() or path.parent.is_symlink()):
        raise LocalSustainedContractError(
            f"{label} must be a new absolute file in a real directory")
    return path


def write_once(path: Path, value: dict) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink(missing_ok=True)
        finally:
            raise


def bind_provisioned_workload(raw: dict, provisioned: dict) -> dict:
    """Bind authoritative provisioned identities into a validated contract.

    Contract files describe the workload shape. Resource identities and CAS
    pins are established only through governed public provisioning and must
    never be guessed by the contract author.
    """
    try:
        table_id = provisioned["tableId"]
        seed_receipts = provisioned["seedReceipts"]
        writer = next(item for item in seed_receipts
                      if item.get("seriesKey") ==
                      raw["application"]["writerSeriesKey"])
        writer_replay = provisioned["writerReplay"]
        application_endpoint = provisioned["applicationEndpoint"]
    except (KeyError, StopIteration, TypeError) as error:
        raise LocalSustainedContractError(
            "V18_LOCAL_PROVISION_BINDINGS_INCOMPLETE") from error
    if (not isinstance(table_id, str) or not table_id
            or not isinstance(writer.get("changeId"), str)
            or not writer["changeId"]
            or type(writer.get("dataRevision")) is not int
            or writer["dataRevision"] < 1
            or application_endpoint != raw["target"]["mcpUrl"]
            or type(writer_replay) is not dict
            or writer_replay.get("tool") !=
                "execute_v2_generic_fact_program"):
        raise LocalSustainedContractError(
            "V18_LOCAL_PROVISION_BINDINGS_INVALID")
    bound = copy.deepcopy(raw)
    for name in ("read", "invariantAudit"):
        bound["workload"][name]["arguments"]["program"]["arguments"][
            "tableId"] = table_id
    # Use the exact idempotent writer request already accepted during
    # provisioning. Repetition therefore returns its original receipt instead
    # of creating new business revisions or relying on a stale fabricated CAS.
    bound["workload"]["write"]["tool"] = writer_replay["tool"]
    bound["workload"]["write"]["arguments"] = copy.deepcopy(
        writer_replay["arguments"])
    bound["workload"]["write"]["arguments"].update({
        "workspace_id": "{workspaceId}",
        "application_id": "{applicationId}",
    })
    replay_program = bound["workload"]["write"]["arguments"]["program"][
        "arguments"]
    replay_program["seriesKey"] = "{writerSeriesKey}"
    replay_program["value"] = "{writerExpectation}"
    bound["workload"]["write"]["expectPath"] = ["result", "dataRevision"]
    bound["workload"]["write"]["expectTemplate"] = str(
        writer["dataRevision"])
    return bound


def bind_python_prerequisites(raw: dict, prerequisites: dict) -> dict:
    try:
        state = prerequisites["state"]
        program_id = prerequisites["programId"]
        delegation_id = prerequisites["delegationId"]
        schedule_id = prerequisites["pythonScheduleId"]
    except (KeyError, TypeError) as error:
        raise LocalSustainedContractError(
            "V18_LOCAL_PYTHON_BINDINGS_INCOMPLETE") from error
    if (not all(isinstance(value, str) and value for value in (
            program_id, delegation_id, schedule_id))
            or schedule_id != raw["application"]["pythonScheduleId"]
            or type(state) is not dict
            or any(type(state.get(name)) is not int for name in (
                "metadataRevision", "policyRevision", "schemaEpoch"))):
        raise LocalSustainedContractError(
            "V18_LOCAL_PYTHON_BINDINGS_INVALID")
    bound = copy.deepcopy(raw)
    action = bound["workload"]["families"]["python_build"]["actions"][0]
    arguments = action["arguments"]["program"]["arguments"]
    arguments.update({"programId": program_id,
        "delegationId": delegation_id,
        "expectedMetadataRevision": state["metadataRevision"],
        "expectedPolicyRevision": state["policyRevision"],
        "expectedSchemaEpoch": state["schemaEpoch"]})
    return bound


async def execute(contract: LocalSustainedContract) -> dict:
    raw = contract.raw
    target = raw["target"]
    application = raw["application"]
    required_session_seconds = (raw["load"]["warmupSeconds"]
                                + raw["load"]["durationSeconds"] + 300)
    transport = LocalEndpointMcpTransport(target, raw["identity"],
        required_session_seconds=required_session_seconds)
    gateway = LocalPublicMcpGateway(transport)
    host = LocalTrustedControlPlane(raw, transport)
    controller = IsolatedComposeEndpointController(raw)
    # MCP streamable-HTTP clients install nested AnyIO cancel scopes in the
    # task that opens them.  Retire in strict LIFO order: the application
    # session is opened after the workspace session and therefore must close
    # first.  Closing the workspace first masks the real qualification error
    # with AnyIO's "cancel scope isn't current" failure.
    retirement = ClosingEndpointRetirement(controller, transport, (
        target["mcpUrl"], target["workspaceMcpUrl"]))
    lifecycle = GovernedDisposableWorkspaceCleanup({
        "workspaceId": application["workspaceId"],
        "applicationId": application["applicationId"],
        "ownershipMarker": application["ownershipMarker"],
        "workspaceEndpoint": target["workspaceMcpUrl"],
        "resetEndpoint": target["resetMcpUrl"],
        "idempotencyPrefix": application["ownershipMarker"],
    }, transport, retirement)
    control = GovernedLocalControlPlane(host, lifecycle,
        workspace_id=application["workspaceId"],
        application_id=application["applicationId"],
        ownership_marker=application["ownershipMarker"])
    try:
        provisioned = await GovernedDisposableProvisioner({
            "platformEndpoint": target["platformMcpUrl"],
            "workspaceId": application["workspaceId"],
            "workspaceName": "V18 sustained qualification workspace",
            "applicationId": application["applicationId"],
            "applicationName": "V18 sustained qualification application",
            "ownershipMarker": application["ownershipMarker"],
            "idempotencyPrefix": application["ownershipMarker"],
            "readerExpectation": application["readerExpectation"],
            "writerExpectation": application["writerExpectation"],
        }, transport, controller).run()
        prerequisites = await GovernedApplicationPrerequisites({
            "workspaceId": application["workspaceId"],
            "applicationId": application["applicationId"],
            "ownershipMarker": application["ownershipMarker"],
            "idempotencyPrefix": application["ownershipMarker"],
            "applicationEndpoint": target["mcpUrl"],
        }, transport).run()
        if (prerequisites.get("applicationRuleId") != "v18.generic.rule"
                or prerequisites.get("applicationScheduleId") !=
                    "v18.application.schedule"
                or prerequisites.get("applicationWorkflowId") !=
                    "v18.application.workflow"
                or prerequisites.get("databaseAccessUsed") is not False):
            raise LocalSustainedContractError(
                "V18_LOCAL_PREREQUISITES_INVALID")
        python_prerequisites = await GovernedPythonPrerequisites({
            "workspaceId": application["workspaceId"],
            "applicationId": application["applicationId"],
            "ownershipMarker": application["ownershipMarker"],
            "idempotencyPrefix": application["ownershipMarker"],
            "applicationEndpoint": target["mcpUrl"],
        }, transport).run()
        bound_raw = bind_provisioned_workload(raw, provisioned)
        bound_raw = bind_python_prerequisites(
            bound_raw, python_prerequisites)
        bound = LocalSustainedContract(bound_raw)
        bound.validate()
        return await LocalSustainedEngine(bound, gateway, control).run()
    except BaseException:
        # Once provisioning has been attempted, a runner failure must not
        # strand a marker-owned workspace. The engine owns cleanup only after
        # it has started; earlier failures are handled here.
        try:
            await control.cleanup(application["ownershipMarker"])
        except BaseException:
            pass
        raise
    finally:
        await transport.aclose()
        await controller.aclose()


async def cleanup_existing(contract: LocalSustainedContract) -> dict:
    """Finish governed cleanup for an interrupted marker-owned V18 run.

    This recovery path deliberately does not provision, execute workload, or
    touch the database directly.  It re-enters the same public reset protocol
    with the exact marker and endpoint inventory sealed in the contract.
    """
    raw = contract.raw
    target = raw["target"]
    application = raw["application"]
    transport = LocalEndpointMcpTransport(target, raw["identity"],
        required_session_seconds=300)
    controller = IsolatedComposeEndpointController(raw)
    retirement = ClosingEndpointRetirement(controller, transport, (
        target["mcpUrl"], target["workspaceMcpUrl"]))
    lifecycle = GovernedDisposableWorkspaceCleanup({
        "workspaceId": application["workspaceId"],
        "applicationId": application["applicationId"],
        "ownershipMarker": application["ownershipMarker"],
        "workspaceEndpoint": target["workspaceMcpUrl"],
        "resetEndpoint": target["resetMcpUrl"],
        "idempotencyPrefix": application["ownershipMarker"],
    }, transport, retirement)
    try:
        return await lifecycle.run()
    finally:
        await transport.aclose()
        await controller.aclose()


def persist(contract: LocalSustainedContract, result: dict) -> tuple[Path, Path]:
    if (type(result) is not dict
            or result.get("format") !=
                "openepm-programmable-v18-local-sustained-evidence-v1"
            or result.get("qualificationClaimed") is not False
            or result.get("claim") != "bounded-local-non-final"):
        raise LocalSustainedContractError("V18_LOCAL_EVIDENCE_SHAPE_INVALID")
    evidence = _output_path(contract.raw["evidence"]["output"],
                            "evidence output")
    cleanup = _output_path(contract.raw["cleanup"]["evidenceOutput"],
                           "cleanup output")
    if evidence == cleanup:
        raise LocalSustainedContractError("V18_LOCAL_OUTPUTS_MUST_BE_DISTINCT")
    cleanup_value = {"format": "openepm-v18-local-cleanup-evidence-v1",
        "status": "passed" if result.get("checks", {}).get("exactCleanup")
            is True else "failed",
        "ownershipMarker": contract.raw["application"]["ownershipMarker"],
        "cleanup": result.get("cleanup", {}),
        "qualificationClaimed": False}
    # Cleanup is written first so a successful main record can never exist
    # without its independently inspectable cleanup result.
    write_once(cleanup, cleanup_value)
    try:
        write_once(evidence, result)
    except BaseException:
        cleanup.unlink(missing_ok=True)
        raise
    return evidence, cleanup


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--cleanup-only", action="store_true",
        help="finish governed cleanup for an interrupted owned run")
    arguments = parser.parse_args()
    try:
        contract = LocalSustainedContract.load(arguments.config.resolve())
        if arguments.cleanup_only:
            cleanup = asyncio.run(cleanup_existing(contract))
            print(json.dumps({"status": cleanup["status"],
                "ownershipMarker": cleanup["ownershipMarker"],
                "databaseAccessUsed": cleanup["databaseAccessUsed"]},
                sort_keys=True))
            return 0
        result = asyncio.run(execute(contract))
        evidence, cleanup = persist(contract, result)
    except (LocalSustainedContractError, OSError) as error:
        parser.error(str(error))
    print(json.dumps({"status": result["status"],
        "claim": result["claim"], "qualificationClaimed": False,
        "evidence": str(evidence), "cleanupEvidence": str(cleanup)},
        sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
