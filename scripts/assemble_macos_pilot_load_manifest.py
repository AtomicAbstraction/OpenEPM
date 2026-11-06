#!/usr/bin/env python3
"""Assemble the real Mac-pilot load contract from qualified protected inputs."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from epm_core.macos_pilot_load import (MacPilotLoadContract, PilotLoadError,
                                       build_standard_workload)
from scripts.provision_macos_pilot_application_access import (
    AccessManifestError, _read_protected_json, _read_roster,
    validate_manifest as validate_access_manifest,
)
from scripts.qualify_macos_pilot_load import _write_evidence


FORMAT = "openepm-macos-pilot-load-assembly-v1"
SENTINEL_FORMAT = "openepm-macos-pilot-load-sentinels-result-v1"


class PilotLoadAssemblyError(ValueError):
    pass


def _path(value: object, label: str) -> Path:
    if not isinstance(value, str):
        raise PilotLoadAssemblyError(f"PILOT_LOAD_ASSEMBLY_{label}_INVALID")
    path = Path(value)
    if not path.is_absolute():
        raise PilotLoadAssemblyError(f"PILOT_LOAD_ASSEMBLY_{label}_INVALID")
    return path


def _access_plan(path: Path, output: Path) -> tuple[dict, dict]:
    raw = _read_protected_json(path, "ASSEMBLY_ACCESS_MANIFEST")
    # Validation requires a fresh evidence destination.  This path is only a
    # validation sentinel; assembling the load contract performs no grant.
    probe = output.parent / (output.name + ".access-validation")
    if probe.exists() or probe.is_symlink():
        raise PilotLoadAssemblyError(
            "PILOT_LOAD_ASSEMBLY_ACCESS_VALIDATION_PATH_INVALID")
    return raw, validate_access_manifest(raw, path, probe)


def _sentinels(path: Path, applications: list[str]) -> dict[str, dict]:
    raw = _read_protected_json(path, "ASSEMBLY_SENTINELS")
    if (raw.get("format") != SENTINEL_FORMAT or raw.get("status") != "passed"
            or raw.get("businessMutationPerformed") is not True
            or raw.get("mutationBoundary") !=
                "authorized fixed-core public application MCP"
            or not isinstance(raw.get("applications"), list)):
        raise PilotLoadAssemblyError("PILOT_LOAD_ASSEMBLY_SENTINELS_INVALID")
    by_application: dict[str, dict] = {}
    required = {"workspaceId", "applicationId", "genericTableId",
                "readerSeriesKey", "readerExpectation", "writerExpectation",
                "tableReplayIdentical", "sentinelReplayIdentical",
                "sentinelReadVerified"}
    for item in raw["applications"]:
        if (type(item) is not dict or set(item) != required
                or item["applicationId"] in by_application
                or item["tableReplayIdentical"] is not True
                or item["sentinelReplayIdentical"] is not True
                or item["sentinelReadVerified"] is not True):
            raise PilotLoadAssemblyError(
                "PILOT_LOAD_ASSEMBLY_SENTINELS_INVALID")
        by_application[item["applicationId"]] = item
    if set(by_application) != set(applications):
        raise PilotLoadAssemblyError(
            "PILOT_LOAD_ASSEMBLY_SENTINEL_SCOPE_MISMATCH")
    return by_application


def assemble(value: object, manifest_path: Path, output: Path) -> dict:
    if type(value) is not dict or set(value) != {
            "format", "accessManifest", "sentinelResult", "target",
            "browser", "load", "controlTiming", "budgets", "model",
            "applicationBindings", "evidence"}:
        raise PilotLoadAssemblyError("PILOT_LOAD_ASSEMBLY_MANIFEST_INVALID")
    if value["format"] != FORMAT:
        raise PilotLoadAssemblyError("PILOT_LOAD_ASSEMBLY_MANIFEST_INVALID")
    if (not manifest_path.is_absolute() or not output.is_absolute()
            or output.suffix != ".json" or output.exists()
            or output.is_symlink() or not output.parent.is_dir()
            or output.parent.is_symlink()):
        raise PilotLoadAssemblyError("PILOT_LOAD_ASSEMBLY_OUTPUT_INVALID")

    access_raw, access = _access_plan(
        _path(value["accessManifest"], "ACCESS_MANIFEST"), output)
    sentinel_map = _sentinels(
        _path(value["sentinelResult"], "SENTINEL_RESULT"),
        access["applications"])

    target = value["target"]
    if (type(target) is not dict
            or target.get("oidcIssuer") != access["issuer"]
            or target.get("oidcAudience") != access["audience"]):
        raise PilotLoadAssemblyError("PILOT_LOAD_ASSEMBLY_TARGET_MISMATCH")

    identities = []
    labels = {}
    for item in access_raw["identities"]:
        roster_path = _path(item["rosterFile"], "ROSTER")
        roster = _read_roster(roster_path, access["issuer"], access["audience"])
        identity = {"subject": roster["subject"],
                    "tokenFile": roster["credentialFile"],
                    "kind": item["kind"]}
        identities.append(identity)
        labels[item["label"]] = identity

    browser_source = value["browser"]
    if type(browser_source) is not dict or "identityLabel" not in browser_source:
        raise PilotLoadAssemblyError("PILOT_LOAD_ASSEMBLY_BROWSER_INVALID")
    browser_label = browser_source["identityLabel"]
    browser_identity = labels.get(browser_label)
    if browser_identity is None or browser_identity["kind"] != "human":
        raise PilotLoadAssemblyError("PILOT_LOAD_ASSEMBLY_BROWSER_INVALID")
    browser = {key: item for key, item in browser_source.items()
               if key != "identityLabel"}
    if "sampleFeed" in browser:
        browser["identitySubjectSha256"] = hashlib.sha256(
            browser_identity["subject"].encode()).hexdigest()
    else:
        browser["identitySubject"] = browser_identity["subject"]

    bindings = value["applicationBindings"]
    if (not isinstance(bindings, list)
            or len(bindings) != len(access["applications"])):
        raise PilotLoadAssemblyError(
            "PILOT_LOAD_ASSEMBLY_APPLICATION_BINDINGS_INVALID")
    by_application = {}
    for binding in bindings:
        if (type(binding) is not dict or "applicationId" not in binding
                or binding["applicationId"] in by_application):
            raise PilotLoadAssemblyError(
                "PILOT_LOAD_ASSEMBLY_APPLICATION_BINDINGS_INVALID")
        by_application[binding["applicationId"]] = binding
    if set(by_application) != set(access["applications"]):
        raise PilotLoadAssemblyError(
            "PILOT_LOAD_ASSEMBLY_APPLICATION_BINDINGS_INVALID")

    applications = []
    for application_id in access["applications"]:
        sentinel = sentinel_map[application_id]
        binding = by_application[application_id]
        app = {"workspaceId": access["workspaceId"],
               "applicationId": application_id,
               "genericTableId": sentinel["genericTableId"],
               "readerSeriesKey": sentinel["readerSeriesKey"],
               "readerExpectation": sentinel["readerExpectation"],
               "writerExpectation": sentinel["writerExpectation"]}
        for optional in ("workloadRoles", "importRow", "forecastProfile"):
            if optional in binding:
                app[optional] = binding[optional]
        if set(binding) - {"applicationId", "workloadRoles", "importRow",
                           "forecastProfile"}:
            raise PilotLoadAssemblyError(
                "PILOT_LOAD_ASSEMBLY_APPLICATION_BINDINGS_INVALID")
        applications.append(app)

    timing = value["controlTiming"]
    if type(timing) is not dict or set(timing) != {
            "revocationAtSeconds", "isolationAtSeconds"}:
        raise PilotLoadAssemblyError("PILOT_LOAD_ASSEMBLY_TIMING_INVALID")
    denied_application = access["isolation"]["deniedApplicationId"]
    controls = {
        "controlSubject": labels[access["controlLabel"]]["subject"],
        "revocationSubject": labels[access["revocationLabel"]]["subject"],
        "revocationAtSeconds": timing["revocationAtSeconds"],
        "isolationSubject": labels[access["isolation"]["label"]]["subject"],
        "isolationDeniedApplicationIndex": access["applications"].index(
            denied_application),
        "isolationAtSeconds": timing["isolationAtSeconds"],
    }
    model = value["model"]
    if type(model) is not dict or set(model) != {
            "calculationSource", "targetDimension", "targetMembers",
            "aggregateDimensions"}:
        raise PilotLoadAssemblyError("PILOT_LOAD_ASSEMBLY_MODEL_INVALID")
    workload = build_standard_workload(
        model["calculationSource"], model["targetDimension"],
        model["targetMembers"], model["aggregateDimensions"])
    load = dict(value["load"])
    load["identityCount"] = len(identities)
    load["applicationCount"] = len(applications)
    load["aggressiveIdentityCount"] = sum(
        item["kind"] == "agent" for item in identities)
    result = {"format": "openepm-macos-pilot-load-v2",
              "target": target, "browser": browser, "load": load,
              "identities": identities, "applications": applications,
              "controls": controls, "budgets": value["budgets"],
              "workload": workload, "evidence": value["evidence"]}
    MacPilotLoadContract(result).validate()
    return result


def redacted(result: dict) -> dict:
    plan = MacPilotLoadContract(result).redacted_plan()
    return {**plan, "assembled": True, "rawSubjectsIncluded": False,
            "credentialPathsIncluded": False,
            "applicationBindingsIncluded": False,
            "businessMutationPerformed": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        value = _read_protected_json(arguments.manifest, "ASSEMBLY_MANIFEST")
        result = assemble(value, arguments.manifest, arguments.output)
        _write_evidence(arguments.output, result)
    except (AccessManifestError, PilotLoadAssemblyError, PilotLoadError,
            OSError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print(json.dumps(redacted(result), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
