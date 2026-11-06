#!/usr/bin/env python3
"""Build a non-executing, exact-image Mac-pilot upgrade readiness plan.

This module deliberately cannot mutate the shared pilot.  It binds a qualified
candidate, a fresh distinct-restore result, the observed running deployment and
a separately tested rollback path before emitting the exact environment
overrides and post-upgrade assertions an operator-controlled upgrader must use.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import re


IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
MD5 = re.compile(r"^[0-9a-f]{32}$")
GIT_ID = re.compile(r"^[0-9a-f]{40}$")
UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
APP_SERVICES = ("platform", "workspace", "router", "web", "worker")
OPTIONAL_SERVICE = "python-build-broker"
PORTS = (5192, 5193, 5194, 5195)
DENIALS = ("web", "platformMcp", "workspaceMcp", "applicationMcp")


class ReadinessError(ValueError):
    pass


def _read(path: Path, label: str) -> dict:
    if not path.is_absolute():
        raise ReadinessError(f"{label} path must be absolute")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReadinessError(f"invalid {label}: {error}") from error
    if not isinstance(value, dict):
        raise ReadinessError(f"{label} must be one JSON object")
    return value


def _image(value: object, label: str) -> str:
    if not isinstance(value, str) or IMAGE.fullmatch(value) is None:
        raise ReadinessError(f"{label} must be an exact sha256 image identity")
    return value


def _schema(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise ReadinessError(f"{label} schema is missing")
    rows, minimum, maximum = value.get("rows"), value.get("minimum"), value.get("maximum")
    if "orderedDigestSha256" in value:
        key, ordered, pattern = "orderedDigestSha256", value.get("orderedDigestSha256"), DIGEST
    else:
        key, ordered, pattern = "orderedDigestMd5", value.get("orderedDigestMd5"), MD5
    if (not isinstance(rows, int) or isinstance(rows, bool) or rows < 1
            or minimum != 1 or maximum != rows
            or not isinstance(ordered, str) or pattern.fullmatch(ordered) is None):
        raise ReadinessError(f"{label} schema identity is invalid")
    return {"rows": rows, "minimum": minimum, "maximum": maximum,
            key: ordered}


def artifact(record: dict, application: str, database: str) -> dict:
    if record.get("format") != "openepm-macos-pilot-artifact-attestation-v1" \
            or record.get("passed") is not True:
        raise ReadinessError("exact candidate artifact attestation is required")
    if _image(record.get("applicationImage"), "attested application image") != application \
            or _image(record.get("databaseImage"), "attested database image") != database:
        raise ReadinessError("artifact attestation is bound to different images")
    if record.get("architecture") != "linux/arm64" \
            or record.get("applicationSourceLabelsMatch") is not True \
            or record.get("runtimeRetirementChecksPassed") is not True:
        raise ReadinessError(
            "candidate architecture, source labels, and runtime retirement must be attested")
    commit, tree = record.get("sourceCommit"), record.get("sourceTree")
    if not isinstance(commit, str) or GIT_ID.fullmatch(commit) is None \
            or not isinstance(tree, str) or GIT_ID.fullmatch(tree) is None:
        raise ReadinessError("candidate source-label identities are invalid")
    return {"architecture": "linux/arm64", "sourceCommit": commit,
            "sourceTree": tree}


def candidate(record: dict, attestation: dict) -> dict:
    if record.get("format") != "openepm-real-oidc-provider-v1" \
            or record.get("passed") is not True:
        raise ReadinessError("candidate evidence is not a passing real-OIDC record")
    application = _image(record.get("applicationImage"), "candidate application image")
    frozen = _image(record.get("frozenApplicationImageId"), "frozen application image")
    database = _image(record.get("databaseImage"), "candidate database image")
    if frozen != application:
        raise ReadinessError("candidate application image changed during qualification")
    if record.get("sourcesUnchangedDuringRun") is not True \
            or record.get("cleanupErrors") != [] \
            or record.get("remainingOwnedContainers") not in ([], "") \
            or record.get("providerRemoved") is not True:
        raise ReadinessError("candidate qualification did not finish cleanly")
    return {"applicationImage": application, "databaseImage": database,
            **artifact(attestation, application, database)}


def running(record: dict) -> dict:
    if record.get("format") != "openepm-macos-pilot-running-state-v1" \
            or record.get("project") != "openepm-macos-pilot":
        raise ReadinessError("running-state evidence has the wrong format or project")
    captured = record.get("capturedAtUtc")
    if not isinstance(captured, str) or UTC.fullmatch(captured) is None:
        raise ReadinessError("running-state capture time is invalid")
    # Reject impossible dates as well as weak text shapes.
    try:
        datetime.strptime(captured, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ReadinessError("running-state capture time is invalid") from error
    application = _image(record.get("applicationImage"), "running application image")
    database = _image(record.get("databaseImage"), "running database image")
    schema = _schema(record.get("schema"), "running")
    count = record.get("applicationCount")
    if not isinstance(count, int) or isinstance(count, bool) or count not in (5, 6):
        raise ReadinessError("running pilot must contain exactly five or six applications")
    labels = record.get("applicationLabels")
    commit = labels.get("org.openepm.source.commit") if isinstance(labels, dict) else None
    tree = labels.get("org.openepm.source.tree") if isinstance(labels, dict) else None
    labels_complete = (
        isinstance(commit, str) and GIT_ID.fullmatch(commit) is not None
        and isinstance(tree, str) and GIT_ID.fullmatch(tree) is not None)
    labels_legacy_empty = commit == "" and tree == ""
    if not isinstance(labels, dict) \
            or labels.get("org.openepm.qualification") != "schema163-public-parity" \
            or not (labels_complete or labels_legacy_empty) \
            or record.get("applicationSourceLabelsComplete") is not labels_complete:
        raise ReadinessError("running application source labels are invalid")
    services = record.get("services")
    broker_enabled = record.get("pythonBuildBrokerEnabled")
    if not isinstance(broker_enabled, bool):
        raise ReadinessError("running-state Python-build broker flag is missing")
    expected = ("db", *APP_SERVICES,
                *((OPTIONAL_SERVICE,) if broker_enabled else ()))
    if not isinstance(services, dict) or set(services) != set(expected):
        raise ReadinessError("running-state service inventory is incomplete")
    for name in expected:
        item = services[name]
        image = database if name == "db" else application
        common_valid = (isinstance(item, dict) and item.get("running") is True
                        and _image(item.get("imageId"), f"{name} image") == image)
        if name == OPTIONAL_SERVICE:
            health_valid = (item.get("healthConfigured") is False
                            and item.get("healthStatus") == "not-configured")
        else:
            health_valid = (item.get("healthConfigured") is True
                            and item.get("healthStatus") == "healthy")
        if not common_valid or not health_valid:
            raise ReadinessError(f"running service is not exact and healthy: {name}")
    ports = record.get("ports")
    if not isinstance(ports, dict) or set(ports) != {str(port) for port in PORTS} \
            or any(ports[str(port)] != "listening" for port in PORTS):
        raise ReadinessError("running pilot loopback-port evidence is incomplete")
    denials = record.get("unsignedDenials")
    if not isinstance(denials, dict) or set(denials) != set(DENIALS) \
            or any(denials[name] != 401 for name in DENIALS):
        raise ReadinessError("unsigned boundary denial evidence is incomplete")
    return {"capturedAtUtc": captured, "applicationImage": application,
            "databaseImage": database, "schema": schema,
            "applicationCount": count, "applicationLabels": labels,
            "applicationSourceLabelsComplete": labels_complete,
            "pythonBuildBrokerEnabled": broker_enabled}


def restored(record: dict, expected: dict, source: dict) -> dict:
    if record.get("format") != "openepm-macos-pilot-backup-restore-v1" \
            or record.get("status") != "verified-for-distinct-restore-scope" \
            or record.get("disposable") is not True:
        raise ReadinessError("restore evidence is not a passing disposable cross-version result")
    if _image(record.get("applicationImage"), "restore application image") \
            != expected["applicationImage"] \
            or _image(record.get("databaseImage"), "restore database image") \
            != expected["databaseImage"]:
        raise ReadinessError("restore evidence is bound to different candidate images")
    details = record.get("restore")
    if not isinstance(details, dict):
        raise ReadinessError("restore details are missing")
    source_schema = _schema(details.get("sourceMigrations"), "restore source")
    target_schema = _schema(details.get("currentReleaseMigrations"), "restore target")
    if source_schema != source["schema"]:
        raise ReadinessError("restore source schema differs from running pilot")
    if target_schema["maximum"] <= source_schema["maximum"]:
        raise ReadinessError("restore evidence did not exercise a forward migration")
    row_counts = details.get("rowCounts")
    if not isinstance(row_counts, dict) \
            or row_counts.get("applications") != source["applicationCount"]:
        raise ReadinessError("restore did not preserve the exact application count")
    backup = record.get("backup")
    cleanup = record.get("cleanup")
    if not isinstance(backup, dict) or backup.get("catalogReadable") is not True \
            or not isinstance(backup.get("aclEntries"), int) \
            or isinstance(backup.get("aclEntries"), bool) \
            or backup.get("aclEntries") <= 0 \
            or details.get("archiveRestoredLogicalDataIdentical") is not True \
            or details.get("businessDataIdenticalAfterMigration") is not True \
            or details.get("targetOnlyNewTablesEmpty") is not True \
            or details.get("databasePrivilegeAclReplayEnabled") is not True \
            or details.get("businessDataDigestExcludes") != ["epm.schema_migration"] \
            or not isinstance(cleanup, dict) or cleanup.get("cleanupErrors") != [] \
            or cleanup.get("disposableContainerRemoved") is not True \
            or cleanup.get("disposableVolumeRemoved") is not True \
            or cleanup.get("temporaryBackupCopyRemoved") is not True:
        raise ReadinessError("restore evidence did not pass preservation and cleanup gates")
    name = record.get("backupName")
    if not isinstance(name, str) or not name \
            or not isinstance(backup.get("sha256"), str) \
            or DIGEST.fullmatch(backup["sha256"]) is None:
        raise ReadinessError("restore evidence has no exact backup identity")
    return {"backup": {"name": name, "sha256": backup["sha256"],
                       "aclEntries": backup["aclEntries"]},
            "sourceSchema": source_schema, "targetSchema": target_schema}


def _switch_phase(record: object, *, label: str, application_image: str,
                  database_image: str, schema: dict, application_count: int,
                  broker_enabled: bool) -> dict:
    if not isinstance(record, dict) \
            or _image(record.get("applicationImage"), label + " application image") \
                != application_image \
            or _image(record.get("databaseImage"), label + " database image") \
                != database_image \
            or _schema(record.get("schema"), label) != schema \
            or _schema(record.get("archiveSchema"), label + " archive") is None \
            or record.get("applicationCount") != application_count \
            or record.get("healthPassed") is not True \
            or record.get("unsignedDenialsPassed") is not True:
        raise ReadinessError(label + " service-switch phase is incomplete")
    services = record.get("services")
    if not isinstance(services, dict) or set(services) != set(APP_SERVICES):
        raise ReadinessError(label + " service inventory is incomplete")
    for name, item in services.items():
        if not isinstance(item, dict) or item.get("running") is not True \
                or item.get("health") != "healthy" \
                or _image(item.get("image"), label + " " + name + " image") \
                    != application_image:
            raise ReadinessError(label + " service is not exact and healthy: " + name)
    denials = record.get("unsignedDenials")
    if not isinstance(denials, dict) \
            or set(denials) != {"platform", "workspace", "router", "web"} \
            or any(status != 401 for status in denials.values()):
        raise ReadinessError(label + " unsigned boundary evidence is incomplete")
    broker = record.get("pythonBuildBroker")
    if not isinstance(broker, dict) or broker.get("enabled") is not broker_enabled:
        raise ReadinessError(label + " broker evidence differs from the source")
    if broker_enabled and (broker.get("running") is not True
            or broker.get("health") != "not-configured"
            or _image(broker.get("image"), label + " broker image")
                != application_image
            or broker.get("invalidCapabilityStatus") != 403):
        raise ReadinessError(label + " broker evidence is incomplete")
    if not isinstance(record.get("archiveAclEntries"), int) \
            or isinstance(record.get("archiveAclEntries"), bool) \
            or record.get("archiveAclEntries") <= 0 \
            or not isinstance(record.get("archiveLogicalDataSha256"), str) \
            or DIGEST.fullmatch(record["archiveLogicalDataSha256"]) is None:
        raise ReadinessError(label + " archive preservation evidence is incomplete")
    return record


def rollback(record: dict, source: dict, selected: dict, recovery: dict) -> dict:
    if record.get("format") != "openepm-macos-pilot-disposable-service-switch-v1" \
            or record.get("passed") is not True \
            or record.get("sharedPilotMutation") is not False \
            or record.get("liveSharedPilotMutationTested") is not False \
            or record.get("ownedDisposableServiceSwitchTested") is not True \
            or record.get("sourceStateRestored") is not True \
            or record.get("sharedPilotUnchanged") is not True:
        raise ReadinessError("owned disposable service-switch evidence is required")
    backup = record.get("backup")
    if not isinstance(backup, dict) or backup.get("name") != recovery["backup"]["name"] \
            or backup.get("sha256") != recovery["backup"]["sha256"]:
        raise ReadinessError("service-switch evidence uses a different protected backup")
    before, after = record.get("sourceBefore"), record.get("sourceAfter")
    if not isinstance(before, dict) or before != after \
            or before.get("applicationImage") != source["applicationImage"] \
            or before.get("databaseImage") != source["databaseImage"] \
            or _schema(before.get("schema"), "service-switch source") != source["schema"] \
            or before.get("applicationCount") != source["applicationCount"] \
            or before.get("pythonBuildBrokerEnabled") \
                is not source["pythonBuildBrokerEnabled"]:
        raise ReadinessError("service-switch evidence does not bind the exact shared source")
    candidate_phase = _switch_phase(
        record.get("candidate"), label="candidate",
        application_image=selected["applicationImage"],
        database_image=selected["databaseImage"],
        schema=recovery["targetSchema"],
        application_count=source["applicationCount"],
        broker_enabled=source["pythonBuildBrokerEnabled"])
    rollback_phase = _switch_phase(
        record.get("rollback"), label="rollback",
        application_image=source["applicationImage"],
        database_image=source["databaseImage"], schema=source["schema"],
        application_count=source["applicationCount"],
        broker_enabled=source["pythonBuildBrokerEnabled"])
    if _schema(candidate_phase["archiveSchema"], "candidate archive") \
                != source["schema"] \
            or _schema(rollback_phase["archiveSchema"], "rollback archive") \
                != source["schema"] \
            or candidate_phase["archiveLogicalDataSha256"] \
                != rollback_phase["archiveLogicalDataSha256"] \
            or record.get("candidateVolumePreservedUntilRollbackPassed") is not True:
        raise ReadinessError("service-switch source preservation is incomplete")
    cleanup = record.get("cleanup")
    if not isinstance(cleanup, dict) or cleanup.get("cleanupErrors") != [] \
            or cleanup.get("candidateProjectRemoved") is not True \
            or cleanup.get("rollbackProjectRemoved") is not True \
            or cleanup.get("ownedVolumesRemoved") is not True \
            or cleanup.get("temporaryArchiveCopyRemoved") is not True:
        raise ReadinessError("service-switch cleanup is incomplete")
    return {"applicationImage": source["applicationImage"],
            "databaseImage": source["databaseImage"],
            "schema": source["schema"], "applicationCount": source["applicationCount"],
            "pythonBuildBrokerEnabled": source["pythonBuildBrokerEnabled"],
            "protectedBackup": recovery["backup"],
            "ownedDisposableServiceSwitchTested": True,
            "sharedPilotMutationTested": False}


def plan(candidate_record: dict, artifact_record: dict, restore_record: dict,
         running_record: dict, rollback_record: dict) -> dict:
    selected = candidate(candidate_record, artifact_record)
    current = running(running_record)
    if selected["applicationImage"] == current["applicationImage"]:
        raise ReadinessError("candidate application image is already running")
    recovery = restored(restore_record, selected, current)
    prior = rollback(rollback_record, current, selected, recovery)
    intended = [*APP_SERVICES,
                *((OPTIONAL_SERVICE,) if current["pythonBuildBrokerEnabled"] else ())]
    process_running = ["db", *intended]
    return {
        "format": "openepm-macos-pilot-upgrade-readiness-v1",
        "readyForOperatorControlledUpgradePreparation": True,
        "readyForSharedActivation": False,
        "liveMutationSupportedByThisArtifact": False,
        "reason": "candidate/recovery compatibility passes, but shared activation "
                  "still requires quiescence, a final backup/current-state capture, "
                  "sandbox-network activation, authenticated readback and explicit "
                  "write-admission control",
        "composeEnvironment": {
            "EPM_APPLICATION_IMAGE": selected["applicationImage"],
            "EPM_DATABASE_IMAGE": selected["databaseImage"],
        },
        "current": current,
        "candidate": {**selected, "targetSchema": recovery["targetSchema"]},
        "protectedBackup": recovery["backup"],
        "rollback": prior,
        "pythonBuildBrokerEnabled": current["pythonBuildBrokerEnabled"],
        "intendedServices": intended,
        "inPlaceDatabaseRecreationAllowed": False,
        "replacementProjectAndVolumeRequired": True,
        "remainingLivePreconditions": [
            "quiesce accepted writes and all active jobs/builds",
            "capture a final ACL-preserving backup after quiescence",
            "recapture the exact current shared source state",
            "prepare and verify the replacement project/volumes without public ports",
            "switch the trusted launcher/broker sandbox network exactly once",
            "prove health, unsigned denials and authenticated read-only public readback",
            "open writes only after the explicit rollback point-of-no-return decision",
        ],
        "requiredPostAssertions": {
            "applicationImage": selected["applicationImage"],
            "databaseImage": selected["databaseImage"],
            "schema": recovery["targetSchema"],
            "applicationCount": current["applicationCount"],
            "processRunningServices": process_running,
            "healthyServices": ["db", *APP_SERVICES],
            "servicesWithoutDockerHealthcheck": (
                [OPTIONAL_SERVICE] if current["pythonBuildBrokerEnabled"] else []),
            "loopbackPorts": list(PORTS),
            "unsignedHttpStatuses": {name: 401 for name in DENIALS},
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-evidence", type=Path, required=True)
    parser.add_argument("--artifact-attestation", type=Path, required=True)
    parser.add_argument("--restore-evidence", type=Path, required=True)
    parser.add_argument("--running-state", type=Path, required=True)
    parser.add_argument("--rollback-evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    if not arguments.output.is_absolute():
        parser.error("output path must be absolute")
    try:
        result = plan(
            _read(arguments.candidate_evidence, "candidate evidence"),
            _read(arguments.artifact_attestation, "artifact attestation"),
            _read(arguments.restore_evidence, "restore evidence"),
            _read(arguments.running_state, "running state"),
            _read(arguments.rollback_evidence, "rollback evidence"),
        )
    except ReadinessError as error:
        parser.error(str(error))
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"passed": True, "output": str(arguments.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
