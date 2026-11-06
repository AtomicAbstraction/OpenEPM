#!/usr/bin/env python3
"""Seal an executable Mac-pilot activation contract from trusted evidence.

This module performs no runtime action.  The existing activation-plan-v1 stays
dry and non-executable; only this stricter, post-quiescence contract may be
consumed by a future authenticated executor.
"""
from __future__ import annotations

from datetime import datetime
import base64
import hashlib
import json
import re
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


SHA = re.compile(r"^[0-9a-f]{64}$")
IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,127}$")
KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}$")
UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
INFRA_DIGESTS = (
    "composeSha256", "pythonComposeSha256", "controllerSha256",
    "boundedStarterSha256", "slotResolverSha256", "slotForwarderSha256",
    "launcherSha256",
    "builderProfileSha256", "builderManifestSha256", "cloudflareConfigSha256",
    "pilotLaunchAgentSha256", "tunnelLaunchAgentSha256")
ACTIVE_WORK = ("jobs", "builds", "workflows", "queries", "schedules", "imports",
               "exports", "metadataMigrations", "lifecycleOperations")


class ExecutionContractError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA.fullmatch(value) is None:
        raise ExecutionContractError(f"{label} must be an SHA-256 digest")
    return value


def _utc(value: object, label: str) -> str:
    if not isinstance(value, str) or UTC.fullmatch(value) is None:
        raise ExecutionContractError(f"{label} must be an exact UTC second")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise ExecutionContractError(f"{label} is invalid") from error
    return value


def _sealed(value: dict, field: str, label: str) -> str:
    claimed = _sha(value.get(field), label)
    body = {key: item for key, item in value.items() if key != field}
    if digest(body) != claimed:
        raise ExecutionContractError(f"{label} digest does not match content")
    return claimed


def _signed(value: dict, expected_format: str, label: str, *, key_id: str,
            public_key: Ed25519PublicKey) -> str:
    if not isinstance(public_key, Ed25519PublicKey):
        raise ExecutionContractError(f"{label} verifier key is invalid")
    claimed = _sha(value.get("evidenceSha256"), label)
    signature = value.get("signature")
    body = {key: item for key, item in value.items()
            if key not in ("evidenceSha256", "signature")}
    if value.get("format") != expected_format \
            or not isinstance(signature, dict) \
            or set(signature) != {"algorithm", "keyId", "valueBase64"} \
            or signature.get("algorithm") != "Ed25519" \
            or signature.get("keyId") != key_id \
            or digest(body) != claimed:
        raise ExecutionContractError(f"{label} signed envelope is invalid")
    try:
        raw = base64.b64decode(signature.get("valueBase64", ""), validate=True)
        public_key.verify(raw, canonical({**body, "evidenceSha256": claimed}))
    except (InvalidSignature, ValueError, TypeError) as error:
        raise ExecutionContractError(f"{label} signature is invalid") from error
    return claimed


def _schema(value: object, label: str) -> dict:
    if not isinstance(value, dict) or value.get("minimum") != 1 \
            or value.get("maximum") != value.get("rows") \
            or not isinstance(value.get("rows"), int) \
            or isinstance(value.get("rows"), bool) or value["rows"] < 1 \
            or not isinstance(value.get("orderedDigestMd5"), str) \
            or re.fullmatch(r"[0-9a-f]{32}", value["orderedDigestMd5"]) is None:
        raise ExecutionContractError(f"{label} schema identity is invalid")
    return {key: value[key] for key in ("rows", "minimum", "maximum",
                                         "orderedDigestMd5")}


def _verifier(value: object, label: str, *, public_key_sha256: str | None = None) -> dict:
    expected = {"algorithm", "keyId", "version"}
    if public_key_sha256 is not None:
        expected.add("publicKeySha256")
    if not isinstance(value, dict) or set(value) != expected \
            or value.get("algorithm") != "Ed25519" \
            or not isinstance(value.get("keyId"), str) \
            or KEY_ID.fullmatch(value["keyId"]) is None \
            or not isinstance(value.get("version"), int) \
            or isinstance(value.get("version"), bool) or value["version"] < 1 \
            or (public_key_sha256 is not None
                and value.get("publicKeySha256") != public_key_sha256):
        raise ExecutionContractError(f"{label} verifier identity is invalid")
    return dict(value)


def _services(value: object, label: str, *, stopped_app: bool = False) -> dict:
    expected = {"db", "platform", "workspace", "router", "web", "worker",
                "python-build-broker"}
    if not isinstance(value, dict) or set(value) != expected:
        raise ExecutionContractError(f"{label} service inventory is incomplete")
    result = {}
    for name, item in sorted(value.items()):
        running_expected = not stopped_app or name == "db"
        health_expected = ((False, "not-configured")
            if running_expected and name == "python-build-broker"
            else ((True, "healthy") if running_expected
                  else (name != "python-build-broker", "stopped")))
        if not isinstance(item, dict) or item.get("running") is not running_expected \
                or not isinstance(item.get("imageId"), str) \
                or IMAGE.fullmatch(item["imageId"]) is None \
                or not isinstance(item.get("networks"), dict) \
                or not item["networks"] \
                or any(not isinstance(network_name, str)
                       or NAME.fullmatch(network_name) is None
                       or not isinstance(network_id, str)
                       or SHA.fullmatch(network_id) is None
                       for network_name, network_id in item["networks"].items()) \
                or (item.get("healthConfigured"), item.get("healthStatus")) \
                    != health_expected:
            raise ExecutionContractError(f"{label} service is not exact: {name}")
        result[name] = {
            "imageId": item["imageId"], "healthConfigured": item.get("healthConfigured"),
            "healthStatus": item.get("healthStatus"),
            "networks": dict(sorted(item["networks"].items()))}
    return result


def _networks(value: object, services: dict, label: str) -> dict:
    if not isinstance(value, dict) or not value or len(value) > 4:
        raise ExecutionContractError(f"{label} network inventory is invalid")
    result = {}
    for name, item in sorted(value.items()):
        if not isinstance(name, str) or NAME.fullmatch(name) is None \
                or not isinstance(item, dict) \
                or _sha(item.get("networkId"), label + " network") is None \
                or item.get("driver") != "bridge" or item.get("scope") != "local" \
                or not isinstance(item.get("internal"), bool) \
                or not isinstance(item.get("attachable"), bool):
            raise ExecutionContractError(f"{label} network properties are invalid")
        result[name] = dict(item)
    for service in services.values():
        for name, network_id in service["networks"].items():
            if name not in result or result[name].get("networkId") != network_id:
                raise ExecutionContractError(f"{label} service/network attachment differs")
    return result


def _network_topology(networks: dict, services: dict, *, project: str,
                      sandbox_name: str | None = None) -> tuple[str, str]:
    defaults = [name for name, item in networks.items()
                if item.get("composeNetwork") == "default"]
    sandboxes = [name for name, item in networks.items()
                 if item.get("composeNetwork") == "sandbox"
                 or (sandbox_name is not None and name == sandbox_name)]
    if len(defaults) != 1 or len(sandboxes) != 1 or defaults[0] == sandboxes[0]:
        raise ExecutionContractError("default/sandbox network topology is ambiguous")
    default, sandbox = defaults[0], sandboxes[0]
    if networks[default].get("composeProject") != project \
            or networks[default].get("internal") is not False \
            or networks[sandbox].get("internal") is not True:
        raise ExecutionContractError("network topology properties differ")
    for name, service in services.items():
        expected = {default, sandbox} if name == "python-build-broker" else {default}
        if set(service["networks"]) != expected:
            raise ExecutionContractError("service network attachment topology differs")
    return default, sandbox


def seal(dry_plan: dict, source: dict, quiescence: dict, backup: dict,
         candidate: dict, infrastructure: dict, *, activation_id: str,
         prepared_at_utc: str, executor_verifier: dict,
         owner_verifier: dict, authority_verifier: dict, evidence_verifier: dict,
         evidence_public_key: Ed25519PublicKey,
         expected_dry_plan_sha256: str) -> dict:
    dry_sha = _sealed(dry_plan, "planSha256", "dry plan")
    if dry_sha != _sha(expected_dry_plan_sha256, "expected dry plan"):
        raise ExecutionContractError("dry plan differs from protected expectation")
    constraints = dry_plan.get("constraints")
    if dry_plan.get("format") != "openepm-macos-pilot-activation-plan-v1" \
            or constraints != {"publicIngressStoppedUntilCommit": True,
                "writesDeniedUntilCommit": True, "bluePreservedUntilCommit": True,
                "rollbackPermittedAfterCommit": False,
                "commitIsPointOfNoReturn": True, "dockerExecutionIncluded": False,
                "sharedPilotMutationIncluded": False} \
            or dry_plan.get("blue", {}).get("project") == dry_plan.get("green", {}).get("project") \
            or dry_plan.get("blue", {}).get("databaseVolume") \
                == dry_plan.get("green", {}).get("databaseVolume"):
        raise ExecutionContractError("qualified dry activation plan is required")
    if not isinstance(activation_id, str) or NAME.fullmatch(activation_id) is None:
        raise ExecutionContractError("activation identity is invalid")
    prepared = _utc(prepared_at_utc, "prepared time")
    if not isinstance(evidence_public_key, Ed25519PublicKey):
        raise ExecutionContractError("evidence verifier key is invalid")
    evidence_public_key_sha256 = hashlib.sha256(evidence_public_key.public_bytes(
        Encoding.Raw, PublicFormat.Raw)).hexdigest()
    evidence_verifier_value = _verifier(
        evidence_verifier, "evidence",
        public_key_sha256=evidence_public_key_sha256)
    evidence_key_id = evidence_verifier_value["keyId"]

    stopped_source = source.get("format")=="openepm-macos-pilot-stopped-source-v1"
    if stopped_source:
        _signed(source,"openepm-macos-pilot-stopped-source-v1","source capture",
                key_id=evidence_key_id,public_key=evidence_public_key)
    source_sha = digest(source)
    source_binding_sha = digest({key: value for key, value in source.items()
        if key not in ("quiescenceEvidenceSha256","evidenceSha256","signature")})
    if (not stopped_source and source.get("format") !=
            "openepm-macos-pilot-running-state-v1") \
            or source.get("captureConsistency") not in (
                "quiescence-bound-v1","single-repeatable-read-stopped-app-v1") \
            or source.get("readOnlyCapture") is not True \
            or source.get("project") != dry_plan["blue"]["project"] \
            or source.get("databaseVolume") != dry_plan["blue"]["databaseVolume"] \
            or source.get("applicationImage") != dry_plan["blue"]["applicationImage"] \
            or source.get("databaseImage") != dry_plan["blue"]["databaseImage"]:
        raise ExecutionContractError("source is not an exact quiescence-bound capture")
    source_schema = _schema(source.get("schema"), "source")
    if source_schema != _schema(dry_plan["blue"].get("schema"), "dry source"):
        raise ExecutionContractError("source schema differs from dry plan")
    source_data = _sha(source.get("dataDumpFingerprintSha256"), "source data fingerprint")
    source_business = _sha(source.get("businessDataDumpFingerprintSha256"),
                           "source business-data fingerprint")
    app_count = source.get("applicationCount")
    if not isinstance(app_count, int) or isinstance(app_count, bool) or app_count not in (5, 6):
        raise ExecutionContractError("source application count is invalid")
    source_services = _services(source.get("services"), "source",
                                stopped_app=stopped_source)
    source_networks = _networks(source.get("networks"), source_services, "source")
    _network_topology(source_networks, source_services,
                      project=dry_plan["blue"]["project"])
    for name, item in source_services.items():
        expected_image = dry_plan["blue"]["databaseImage"] if name == "db" \
            else dry_plan["blue"]["applicationImage"]
        if item["imageId"] != expected_image:
            raise ExecutionContractError("source service image differs from dry plan")
    ports = source.get("ports")
    denials = source.get("unsignedDenials")
    sealed_ports=dry_plan.get("privatePorts")
    if not isinstance(sealed_ports,dict) \
            or set(sealed_ports)!={"web","platform","workspace","application"} \
            or any(not isinstance(port,int) or isinstance(port,bool)
                   or port<1024 or port>65535 for port in sealed_ports.values()) \
            or len(set(sealed_ports.values()))!=4:
        raise ExecutionContractError("sealed private port binding is invalid")
    port_values=tuple(sealed_ports[name] for name in (
        "web","platform","workspace","application"))
    expected_ports={str(port):("closed" if stopped_source else "listening")
                    for port in port_values}
    expected_denials={} if stopped_source else {name: 401 for name in
        ("web", "platformMcp", "workspaceMcp", "applicationMcp")}
    if ports != expected_ports or denials != expected_denials:
        raise ExecutionContractError("source ports or unsigned denials are incomplete")
    source_profile = source.get("dataDumpFingerprintProfile")
    business_profile = source.get("businessDataDumpFingerprintProfile")
    if not isinstance(source_profile, dict) or not isinstance(business_profile, dict) \
            or source_profile.get("kind") != "pg_dump-data-only-column-inserts-v1" \
            or source_profile.get("excludedTables") != [] \
            or business_profile.get("kind") != "pg_dump-data-only-column-inserts-v1" \
            or business_profile.get("excludedTables") != ["epm.schema_migration"] \
            or source_profile.get("pgDumpVersion") != business_profile.get("pgDumpVersion"):
        raise ExecutionContractError("source data fingerprint profiles are invalid")

    quiescence_sha = _signed(quiescence, "openepm-macos-pilot-quiescence-v1",
        "quiescence evidence", key_id=evidence_key_id, public_key=evidence_public_key)
    active_work = quiescence.get("activeWork")
    if quiescence.get("passed") is not True \
            or quiescence.get("sourceCaptureSha256") != source_binding_sha \
            or source.get("quiescenceEvidenceSha256") != quiescence_sha \
            or quiescence.get("acceptedWritesClosed") is not True \
            or _sha(quiescence.get("writeClosureEvidenceSha256"),
                    "write closure") is None \
            or not isinstance(active_work, dict) or set(active_work) != set(ACTIVE_WORK) \
            or any(not isinstance(active_work[name], int)
                   or isinstance(active_work[name], bool)
                   or active_work[name] != 0 for name in ACTIVE_WORK) \
            or _sha(quiescence.get("activeWorkEvidenceSha256"),
                    "active work") is None \
            or quiescence.get("captureAfterBoundary") is not True:
        raise ExecutionContractError("quiescence/drain evidence is incomplete")
    boundary = _utc(quiescence.get("boundaryAtUtc"), "quiescence boundary")
    source_captured = _utc(source.get("capturedAtUtc"), "source capture time")
    if source_captured < boundary:
        raise ExecutionContractError("source capture predates quiescence")
    source_volume_id = _sha(source.get("databaseVolumeId"), "source volume")
    if quiescence.get("sourceVolumeName") != dry_plan["blue"]["databaseVolume"] \
            or quiescence.get("sourceVolumeId") != source_volume_id:
        raise ExecutionContractError("source volume identity differs from dry plan")

    backup_sha = _signed(backup, "openepm-macos-pilot-protected-backup-v1",
        "backup evidence", key_id=evidence_key_id, public_key=evidence_public_key)
    if backup.get("status") != "protected-backup-created" \
            or backup.get("sourceComposeProject") != dry_plan["blue"]["project"] \
            or backup.get("databaseContainerImage") != dry_plan["blue"]["databaseImage"] \
            or backup.get("sourceCaptureSha256") != source_sha \
            or backup.get("quiescenceEvidenceSha256") != quiescence_sha \
            or backup.get("sourceDataDumpFingerprintSha256") != source_data:
        raise ExecutionContractError("final backup is not bound to quiesced source")
    captured = _utc(backup.get("capturedAtUtc"), "backup capture time")
    if captured < source_captured:
        raise ExecutionContractError("final backup predates quiescence")
    if not isinstance(backup.get("backupName"), str) \
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{2,127}\.dump",
                            backup["backupName"]) is None:
        raise ExecutionContractError("final backup name is unsafe")
    backup_item = backup.get("backup")
    if not isinstance(backup_item, dict) or backup_item.get("catalogReadable") is not True \
            or backup_item.get("mode") != "0600" \
            or not all(isinstance(backup_item.get(key), int)
                       and not isinstance(backup_item.get(key), bool)
                       and backup_item[key] > 0
                       for key in ("bytes", "catalogEntries", "aclEntries")):
        raise ExecutionContractError("final backup identity is incomplete")
    archive_digest = _sha(backup_item.get("sha256"), "final backup")

    candidate_sha = _signed(candidate, "openepm-macos-pilot-prepared-candidate-v1",
        "candidate evidence", key_id=evidence_key_id, public_key=evidence_public_key)
    if candidate.get("passed") is not True \
            or candidate.get("project") != dry_plan["green"]["project"] \
            or candidate.get("applicationImage") != dry_plan["green"]["applicationImage"] \
            or candidate.get("operationsImage") != dry_plan["green"]["applicationImage"] \
            or candidate.get("databaseImage") != dry_plan["green"]["databaseImage"] \
            or candidate.get("databaseVolume") != dry_plan["green"]["databaseVolume"] \
            or candidate.get("restoredBackupSha256") != archive_digest \
            or candidate.get("applicationCount") != app_count \
            or candidate.get("publicPortsExposed") is not False \
            or _sha(candidate.get("publicPortAbsenceEvidenceSha256"),
                    "candidate port absence") is None \
            or candidate.get("writesDenied") is not True \
            or _sha(candidate.get("writeDenialEvidenceSha256"),
                    "candidate write denial") is None \
            or candidate.get("businessDataDumpFingerprintSha256") != source_business:
        raise ExecutionContractError("candidate is not an exact private restored target")
    candidate_schema = _schema(candidate.get("schema"), "candidate")
    if candidate_schema != _schema(dry_plan["green"].get("schema"), "dry candidate"):
        raise ExecutionContractError("candidate schema differs from dry plan")
    candidate_services = _services(candidate.get("services"), "candidate")
    candidate_networks = _networks(candidate.get("networks"), candidate_services,
                                   "candidate")
    candidate_default, candidate_sandbox_name = _network_topology(
        candidate_networks, candidate_services, project=dry_plan["green"]["project"],
        sandbox_name=dry_plan["sandboxNetwork"])
    if candidate_sandbox_name != dry_plan["sandboxNetwork"]:
        raise ExecutionContractError("candidate sandbox name differs from dry plan")
    for name, item in candidate_services.items():
        expected_image = dry_plan["green"]["databaseImage"] if name == "db" \
            else dry_plan["green"]["applicationImage"]
        if item["imageId"] != expected_image:
            raise ExecutionContractError("candidate service image differs from dry plan")
    candidate_prepared = _utc(candidate.get("preparedAtUtc"), "candidate preparation time")
    if candidate_prepared < captured or prepared < candidate_prepared:
        raise ExecutionContractError("activation preparation time chain is invalid")

    infrastructure_sha = _signed(infrastructure,
        "openepm-macos-pilot-activation-infrastructure-v1",
        "infrastructure evidence", key_id=evidence_key_id,
        public_key=evidence_public_key)
    digests = infrastructure.get("artifactDigests")
    network = infrastructure.get("sandboxNetwork")
    route_authority_sha = infrastructure.get("routeAuthoritySha256")
    if infrastructure.get("passed") is not True \
            or not isinstance(digests, dict) or set(digests) != set(INFRA_DIGESTS) \
            or any(SHA.fullmatch(str(digests[key])) is None for key in INFRA_DIGESTS) \
            or SHA.fullmatch(str(route_authority_sha)) is None \
            or not isinstance(network, dict) \
            or network.get("name") != dry_plan.get("sandboxNetwork") \
            or SHA.fullmatch(str(network.get("networkId"))) is None \
            or network.get("driver") != "bridge" or network.get("scope") != "local" \
            or network.get("internal") is not True \
            or network.get("attachable") is not False \
            or network.get("externallyManaged") is not True:
        raise ExecutionContractError("activation infrastructure is incomplete")
    network_id = network["networkId"]
    if candidate.get("sandboxNetworkId") != network_id:
        raise ExecutionContractError("candidate does not use the sealed sandbox network")
    if network_id not in candidate_services["python-build-broker"]["networks"].values():
        raise ExecutionContractError("candidate broker is not attached to sealed sandbox network")
    candidate_sandbox = candidate_networks.get(network["name"])
    if not isinstance(candidate_sandbox, dict) \
            or candidate_sandbox.get("networkId") != network_id \
            or candidate_sandbox.get("internal") is not True \
            or candidate_sandbox.get("externallyManaged") is not True:
        raise ExecutionContractError("candidate sandbox network properties differ")
    candidate_volume_id = _sha(candidate.get("databaseVolumeId"), "candidate volume")
    if source_volume_id == candidate_volume_id:
        raise ExecutionContractError("source and candidate database volumes are not distinct")
    if candidate_networks[candidate_default]["networkId"] in {
            item["networkId"] for item in source_networks.values()}:
        raise ExecutionContractError("source and candidate default networks are not distinct")
    executor = _verifier(executor_verifier, "executor")
    owner = _verifier(owner_verifier, "owner")
    authority = _verifier(authority_verifier, "authority")
    if len({executor["keyId"],owner["keyId"],authority["keyId"],evidence_key_id})!=4:
        raise ExecutionContractError("activation verifier identities must be distinct")

    body = {
        "format": "openepm-macos-pilot-activation-execution-contract-v3",
        "activationId": activation_id, "dryPlanSha256": dry_sha,
        "preparedAtUtc": prepared,
        "source": {"project": source["project"], "applicationImage": source["applicationImage"],
            "databaseImage": source["databaseImage"],
            "databaseVolume": dry_plan["blue"]["databaseVolume"],
            "databaseVolumeId": source_volume_id,
            "schema": source_schema, "applicationCount": app_count,
            "services": source_services, "networks": source_networks, "ports": ports,
            "dataDumpFingerprintSha256": source_data,
            "businessDataDumpFingerprintSha256": source_business,
            "runningStateEvidenceSha256": source_sha,
            "quiescenceEvidenceSha256": quiescence_sha},
        "candidate": {"project": candidate["project"],
            "applicationImage": candidate["applicationImage"],
            "operationsImage": candidate["operationsImage"],
            "databaseImage": candidate["databaseImage"],
            "databaseVolume": candidate["databaseVolume"],
            "databaseVolumeId": candidate_volume_id,
            "schema": candidate_schema, "applicationCount": app_count,
            "services": candidate_services, "networks": candidate_networks,
            "publicPortsExposed": False,
            "businessDataDumpFingerprintSha256": source_business,
            "candidateEvidenceSha256": candidate_sha},
        "finalBackup": {"name": backup["backupName"], "sha256": archive_digest,
            "bytes": backup_item["bytes"], "catalogEntries": backup_item["catalogEntries"],
            "aclEntries": backup_item["aclEntries"], "backupEvidenceSha256": backup_sha,
            "quiescenceEvidenceSha256": quiescence_sha,
            "sourceDataDumpFingerprintSha256": source_data},
        "infrastructure": {"sandboxNetwork": dict(network),
            "artifactDigests": dict(digests),
            "routeAuthoritySha256": route_authority_sha,
            "infrastructureEvidenceSha256": infrastructure_sha},
        "expectedAssertions": {"runningServices": sorted(candidate_services),
            "healthyServices": sorted(name for name, item in candidate_services.items()
                                      if item["healthConfigured"] is True),
            "unsignedHttpStatuses": denials,
            "schema": candidate_schema, "applicationCount": app_count,
            "businessDataDumpFingerprintSha256": source_business,
            "authenticatedReadResultSha256": _sha(
                candidate.get("authenticatedReadResultSha256"), "authenticated read"),
            "writesDeniedBeforeCommit": True},
        "executorVerifier": executor, "ownerAuthorizationVerifier": owner,
        "authorityVerifier":authority,
        "evidenceVerifier": evidence_verifier_value,
        "constraints": {"sourceAndCandidateDistinct": True,
            "publicIngressStoppedUntilCommit": True,
            "writesDeniedUntilCommit": True, "rollbackForbiddenAfterCommit": True,
            "dryPlanAloneIsNotExecutable": True},
    }
    return {**body, "executionContractSha256": digest(body)}
