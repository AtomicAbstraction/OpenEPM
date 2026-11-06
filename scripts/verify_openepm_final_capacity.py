#!/usr/bin/env python3
"""Verify external P21 evidence against exact final release identities."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import statistics

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.p21_final_capacity_contract import (  # noqa: E402
    CapacityContractError, FinalCapacityContract, TECHNICAL_QUEUE_FAMILIES)


class CapacityEvidenceError(ValueError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def percentile(values: list[float], fraction: float) -> float:
    ordered=sorted(values)
    return ordered[min(len(ordered)-1,max(0,int(len(ordered)*fraction)))]


def load(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CapacityEvidenceError(f"invalid {label}: {error}") from error
    if not isinstance(value, dict):
        raise CapacityEvidenceError(f"{label} must be an object")
    return value


def verify_notebook_attestations(values: object, subjects: list[str],
                                 expected_digest: str) -> None:
    required = {"subject", "container", "containerId", "runtime", "image",
        "imageDigest", "running", "rootReadOnly", "capabilitiesDropped",
        "noNewPrivileges", "pidsLimit", "cpuLimit", "memoryMiB", "user",
        "managedLabel", "userLabel", "network"}
    if not isinstance(values, list) or len(values) != 10:
        raise CapacityEvidenceError("ten trusted notebook runtime attestations are required")
    expected_subjects, containers, identities = set(subjects), set(), set()
    for value in values:
        if (not isinstance(value, dict) or set(value) != required
                or value.get("subject") not in expected_subjects
                or value.get("runtime") != "runsc"
                or value.get("imageDigest") != expected_digest
                or not str(value.get("image", "")).endswith("@" + expected_digest)
                or any(value.get(field) is not True for field in
                       ("running", "rootReadOnly", "capabilitiesDropped",
                        "noNewPrivileges", "managedLabel"))
                or value.get("pidsLimit") != 256
                or value.get("cpuLimit") != 1
                or value.get("memoryMiB") != 1024
                or value.get("user") != "10001:10001"
                or value.get("userLabel") != value["subject"].removeprefix("u-")
                or not isinstance(value.get("network"), str) or not value["network"]
                or not isinstance(value.get("containerId"), str)
                or not re.fullmatch(r"[a-f0-9]{12,64}", value["containerId"])):
            raise CapacityEvidenceError("notebook runtime attestation is invalid")
        containers.add(value["container"]); identities.add(value["containerId"])
    if (set(value["subject"] for value in values) != expected_subjects
            or len(containers) != 10 or len(identities) != 10):
        raise CapacityEvidenceError("notebook runtime attestations are not distinct and complete")


def verify(contract: FinalCapacityContract, *, host: dict,
           engine: dict) -> dict:
    raw = contract.raw
    hardware = raw["hardware"]
    if (host.get("architecture") != hardware["requiredArchitecture"]
            or host.get("runsc") is not True
            or host.get("cpuCount", 0) < 16
            or host.get("memoryGiB", 0) < 64
            or host.get("freeDiskGiB", 0) < 200):
        raise CapacityEvidenceError("qualifying hardware/native runsc proof is insufficient")
    manifest_path = Path(raw["releaseManifest"])
    manifest = load(manifest_path, "final manifest")
    architecture = hardware["requiredArchitecture"]
    expected_release = {"release": manifest["release"],
        "sourceCommit": manifest["sourceCommit"],
        "schemaMigration": manifest["schemaMigration"],
        "resolvedReleasePolicy": manifest["resolvedReleasePolicy"],
        "architecture": architecture,
        "images": {name: value["digests"][architecture]
                   for name, value in manifest["images"].items()}}
    if (not isinstance(expected_release["release"],str)
            or not expected_release["release"]
            or not re.fullmatch(r"[0-9]{4}_[A-Za-z0-9_]+\.sql",
                                str(expected_release["schemaMigration"]))
            or any(not re.fullmatch(r"sha256:[a-f0-9]{64}",str(value))
                   for value in expected_release["images"].values())):
        raise CapacityEvidenceError("final release/schema/image identity is invalid")
    if engine.get("releaseIdentity") != expected_release:
        raise CapacityEvidenceError("engine evidence differs from final release/image identity")
    verify_notebook_attestations(engine.get("notebookRuntimeAttestations"),
        raw["notebooks"]["subjects"], expected_release["images"]["notebook"])
    if (engine.get("status") != "passed"
            or engine.get("qualificationClaimed") is not False
            or engine.get("errors") != []
            or engine.get("configurationDigest") != hashlib.sha256(
                json.dumps(raw, sort_keys=True).encode()).hexdigest()):
        raise CapacityEvidenceError("engine evidence/configuration identity is invalid")
    measurement = engine.get("measurement", {})
    if (measurement.get("configuredWarmupSeconds", 0) < 120
            or measurement.get("configuredPostWarmupSeconds", 0) < 1800
            or measurement.get("observedTotalSeconds", 0) <
                measurement.get("configuredWarmupSeconds", 0) +
                measurement.get("configuredPostWarmupSeconds", 0)
            or measurement.get("observedPostWarmupSeconds", 0) <
                measurement.get("configuredPostWarmupSeconds", 0)
            or measurement.get("authenticatedSessionCount") != 300
            or measurement.get("notebookCount") != 10
            or measurement.get("applicationCount", 0) < 3):
        raise CapacityEvidenceError("30-minute/300-session measurement is incomplete")
    notebook_observation=engine.get("notebookConcurrentObservation")
    if (not isinstance(notebook_observation,dict)
            or notebook_observation.get("count")!=10
            or notebook_observation.get("subjects")!=sorted(
                raw["notebooks"]["subjects"])):
        raise CapacityEvidenceError("ten notebooks were not concurrently observed")
    required_checks = {"allSubjectsMadeProgress", "allApplicationsMadeProgress",
        "measurementBoundaryCaptured", "postWarmupAllSubjectsMadeProgress",
        "postWarmupAllApplicationsMadeProgress", "postWarmupAllFamiliesCompleted",
        "allFamiliesHaveQueueTiming", "queueWaitBudgetHeld",
        "allFamiliesMadeProgress", "allFamiliesReachedTerminalState",
        "tenNotebooksStarted", "grantChangeExecuted",
        "grantRevocationDeniedAccess", "grantRestorationRestoredAccess",
        "workerRestartExecuted", "allFamiliesProgressedAfterRestart",
        "cancellationExecuted", "cancellationReachedTerminalState",
        "noLostDuplicateOrCrossApplicationEffects", "noErrors", "exactCleanup",
        "latencyBudgetHeld"}
    checks = engine.get("checks")
    if not isinstance(checks, dict) or any(checks.get(key) is not True
                                           for key in required_checks):
        raise CapacityEvidenceError("mixed-load control/invariant checks are incomplete")
    counts=engine.get("counts")
    controls=engine.get("controlCounts")
    expected_control={"revocations":1,"revocationDenials":1,
        "revocationRestores":1,"restarts":1,
        "postRestartFamilies":len(raw["applications"])*len(raw["load"]["families"])}
    if (not isinstance(counts,dict)
            or counts.get("invariantAudit")!=len(raw["applications"])
            or not isinstance(controls,dict)
            or any(controls.get(key)!=value for key,value in expected_control.items())
            or type(controls.get("cancellations")) is not int
            or controls["cancellations"]<=0
            or controls.get("terminalCancellations")!=controls["cancellations"]):
        raise CapacityEvidenceError("raw control/invariant counters are incomplete")
    post_counts = engine.get("postWarmupCounts")
    subject_counts=engine.get("postWarmupSubjectCounts")
    application_counts=engine.get("postWarmupApplicationCounts")
    post_terminals = engine.get("postWarmupFamilyTerminalCounts")
    throughput = engine.get("postWarmupThroughputPerSecond")
    duration = measurement["configuredPostWarmupSeconds"]
    if (not isinstance(post_counts, dict) or not isinstance(post_terminals, dict)
            or not isinstance(subject_counts,dict)
            or set(subject_counts)!={row["subject"] for row in raw["identities"]}
            or any(type(value) is not int or value<=0
                   for value in subject_counts.values())
            or not isinstance(application_counts,dict)
            or set(application_counts)!={row["applicationId"]
                                         for row in raw["applications"]}
            or any(type(value) is not int or value<=0
                   for value in application_counts.values())
            or sum(subject_counts.values())!=sum(post_counts.values())
            or sum(application_counts.values())!=sum(post_counts.values())
            or set(post_terminals) != set(raw["load"]["families"])
            or any(post_counts.get("family:" + family, 0) <= 0
                   or post_terminals.get(family) != post_counts["family:" + family]
                   for family in raw["load"]["families"])
            or not isinstance(throughput, dict) or set(throughput) != set(post_counts)
            or any(not isinstance(value, (int, float)) or value <= 0
                   or abs(value - post_counts[name] / duration) > 1e-12
                   for name, value in throughput.items())):
        raise CapacityEvidenceError("post-warm-up throughput/family evidence is incomplete")
    latency = engine.get("latency")
    latency_samples=engine.get("latencySamples")
    required_latency = {"read", "write", "query"} | {
        "family:" + family for family in raw["load"]["families"]} | {
        "familyTerminal:" + family
        for family in raw["workload"]["familyTerminal"]}
    if (not isinstance(latency, dict) or set(latency)!=required_latency
            or not isinstance(latency_samples,dict)
            or set(latency_samples)!=required_latency
            or any(not isinstance(latency[name], dict)
                or latency[name].get("count", 0) <= 0
                or any(not isinstance(latency[name].get(field), (int, float))
                       or latency[name][field] < 0 for field in
                       ("p50Seconds","p95Seconds","p99Seconds"))
                or not latency[name]["p50Seconds"] <= latency[name]["p95Seconds"]
                    <= latency[name]["p99Seconds"]
                for name in required_latency)):
        raise CapacityEvidenceError("post-warm-up latency evidence is incomplete")
    for name in required_latency:
        values=latency_samples[name]
        if (not isinstance(values,list) or len(values)!=latency[name]["count"]
                or len(values)>2_000_000
                or any(type(value) not in (int,float) or value<0
                       for value in values)
                or latency[name]!={"count":len(values),
                    "p50Seconds":statistics.median(values),
                    "p95Seconds":percentile(values,.95),
                    "p99Seconds":percentile(values,.99)}):
            raise CapacityEvidenceError("latency summary lacks exact bounded raw samples")
    queue_wait = engine.get("queueWait")
    queue_samples=engine.get("queueWaitSamples")
    if (not isinstance(queue_wait, dict)
            or set(queue_wait) != TECHNICAL_QUEUE_FAMILIES
            or not isinstance(queue_samples,dict)
            or set(queue_samples)!=TECHNICAL_QUEUE_FAMILIES
            or any(not isinstance(queue_wait[family], dict)
                or queue_wait[family].get("count", 0) <= 0
                or any(not isinstance(queue_wait[family].get(field), (int, float))
                       or queue_wait[family][field] < 0 for field in
                       ("p50Seconds", "p95Seconds", "p99Seconds"))
                or not queue_wait[family]["p50Seconds"] \
                    <= queue_wait[family]["p95Seconds"] \
                    <= queue_wait[family]["p99Seconds"] \
                    <= raw["budgets"]["maximumP99Seconds"]
                for family in TECHNICAL_QUEUE_FAMILIES)):
        raise CapacityEvidenceError("authoritative queue-wait evidence is incomplete")
    for family in TECHNICAL_QUEUE_FAMILIES:
        micros=queue_samples[family]
        values=[] if not isinstance(micros,list) else [value/1_000_000
                                                       for value in micros]
        if (not isinstance(micros,list) or len(micros)>3000
                or any(type(value) is not int or value<0 for value in micros)
                or queue_wait[family]!={"count":len(values),
                    "p50Seconds":statistics.median(values),
                    "p95Seconds":percentile(values,.95),
                    "p99Seconds":percentile(values,.99)}):
            raise CapacityEvidenceError("queue-wait summary lacks exact bounded raw samples")
    samples = engine.get("resourceSamples")
    cadence=raw["evidence"]["sampleEverySeconds"]
    measured=[item for item in samples if isinstance(item,dict)
              and item.get("inMeasurementWindow") is True]
    minimum_samples=max(1,int(duration/cadence)-1)
    if (not isinstance(samples, list) or len(measured)<minimum_samples
            or any(not isinstance(item,dict)
                   or item.get("resourceScope") != "trusted_host_release_plus_sandboxes"
                   or item.get("managedNotebookServices") != 10
                   or not isinstance(item.get("activeBuilderServices"), int)
                   or item["activeBuilderServices"] < 0
                   or item.get("hostServices") != len(raw["target"]["sampleServices"])
                        + 10 + item["activeBuilderServices"]
                   or type(item.get("observedAtSeconds")) not in (int,float)
                   or type(item.get("inMeasurementWindow")) is not bool
                   or any(type(item.get(field)) not in (int,float)
                          or item[field]<0 or item[field]>hardware_limit
                          for field,hardware_limit in (("connections",raw["budgets"]["maximumConnections"]),("memoryGiB",raw["budgets"]["maximumMemoryGiB"]),("temporaryDiskGiB",raw["budgets"]["maximumTemporaryDiskGiB"]),("cpuPercent",raw["budgets"]["maximumCpuPercent"])))
                   for item in samples)
            or measured[-1]["observedAtSeconds"]-
               measured[0]["observedAtSeconds"]<duration-cadence*2):
        raise CapacityEvidenceError(
            "trusted host release/sandbox resource samples are required; public metrics are insufficient")
    marker = "p21-" + hashlib.sha256(json.dumps(
        raw, sort_keys=True).encode()).hexdigest()[:24]
    expected_cleanup={"format":"openepm-capacity-cleanup-v1",
        "ownershipMarker":marker,"cleanupAttempted":True,
        "cleanupVerified":True,"ownedRemaining":0,"containers":[],
        "networks":[],"volumes":[],"temporaryCredentials":[],
        "scratchPaths":[],"managedNotebookRemaining":0,
        "attemptedContainers":[],"attemptedNetworks":[],
        "attemptedVolumes":[],
        "sharedResourcesTouched":False,"activeResourcesTouched":False}
    if engine.get("cleanup")!=expected_cleanup:
        raise CapacityEvidenceError("capacity run cleanup is incomplete")
    clean_certificate = load(Path(raw["cleanLinuxCertificate"]),
                             "clean Linux certificate")
    return {"format": "openepm-final-capacity-certificate-v1", "status": "passed",
        "releaseManifestSha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "resolvedReleasePolicySha256":
            clean_certificate["resolvedReleasePolicySha256"],
        "cleanLinuxCertificateSha256": hashlib.sha256(
            Path(raw["cleanLinuxCertificate"]).read_bytes()).hexdigest(),
        "configurationSha256": engine["configurationDigest"],
        "engineEvidenceSha256": hashlib.sha256(canonical(engine)).hexdigest(),
        "architecture": architecture, "authenticatedSessions": 300,
        "postWarmupSeconds": measurement["configuredPostWarmupSeconds"],
        "notebooks": 10,
        "notebookRuntimeAttestationsSha256": hashlib.sha256(canonical(
            engine["notebookRuntimeAttestations"])).hexdigest(),
        "externalCapacityExecutionVerified": True}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--host-evidence", type=Path, required=True)
    parser.add_argument("--engine-evidence", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    try:
        contract = FinalCapacityContract.load(args.config.resolve())
        result = verify(contract, host=load(args.host_evidence.resolve(), "host evidence"),
                        engine=load(args.engine_evidence.resolve(), "engine evidence"))
    except (CapacityContractError, CapacityEvidenceError) as error:
        parser.error(str(error))
    args.output.write_bytes(canonical(result) + b"\n")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
