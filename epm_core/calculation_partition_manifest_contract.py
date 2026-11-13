"""Current logical result manifests for server-owned partitions."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping, Sequence


FORMAT = "openepm-calculation-partition-manifest-v2"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _partition(value: object) -> dict[str, object]:
    required = {"partitionKey", "certificateDigest", "presence", "rowCount"}
    if (not isinstance(value, dict) or set(value) != required
            or not isinstance(value.get("partitionKey"), str)
            or _ID.fullmatch(value["partitionKey"]) is None
            or not isinstance(value.get("certificateDigest"), str)
            or _DIGEST.fullmatch(value["certificateDigest"]) is None
            or type(value.get("rowCount")) is not int
            or value["rowCount"] < 0):
        raise ValueError("CALCULATION_PARTITION_INVALID")
    presence = value["presence"]
    if ((presence == "empty" and value["rowCount"] != 0)
            or (presence == "present" and value["rowCount"] < 1)):
        raise ValueError("CALCULATION_PARTITION_INVALID")
    if presence not in {"empty", "present"}:
        raise ValueError("CALCULATION_PARTITION_INVALID")
    return {key: value[key] for key in (
        "partitionKey", "certificateDigest", "presence", "rowCount")}


@dataclass(frozen=True, slots=True)
class PartitionManifest:
    normalized: dict[str, object]

    @property
    def digest(self) -> str:
        return _digest(self.normalized)

    @property
    def partitions(self) -> dict[str, dict[str, object]]:
        return {str(item["partitionKey"]): item
                for item in self.normalized["partitions"]}


def compile_partition_manifest(value: object) -> PartitionManifest:
    required = {"format", "bindingDigest", "executionManifestDigest",
                "partitionPolicyVersion", "coverage", "partitions"}
    if (not isinstance(value, dict) or set(value) != required
            or value["format"] != FORMAT
            or not isinstance(value["bindingDigest"], str)
            or _DIGEST.fullmatch(value["bindingDigest"]) is None
            or not isinstance(value["executionManifestDigest"], str)
            or _DIGEST.fullmatch(value["executionManifestDigest"]) is None
            or type(value["partitionPolicyVersion"]) is not int
            or value["partitionPolicyVersion"] < 1
            or value["coverage"] not in {"complete", "partial"}
            or not isinstance(value["partitions"], list)
            or not 1 <= len(value["partitions"]) <= 10_000):
        raise ValueError("CALCULATION_PARTITION_MANIFEST_INVALID")
    partitions = [_partition(item) for item in value["partitions"]]
    if len({item["partitionKey"] for item in partitions}) != len(partitions):
        raise ValueError("CALCULATION_PARTITION_DUPLICATE")
    return PartitionManifest({
        "format": FORMAT,
        "bindingDigest": value["bindingDigest"],
        "executionManifestDigest": value["executionManifestDigest"],
        "partitionPolicyVersion": value["partitionPolicyVersion"],
        "coverage": value["coverage"],
        "partitions": sorted(partitions,
                             key=lambda item: item["partitionKey"]),
    })


def replace_partitions(current: PartitionManifest, *,
        expected_certificates: Mapping[str, str],
        replacements: Sequence[dict[str, object]],
        execution_manifest_digest: str) -> PartitionManifest:
    """Return a new map only when every replaced partition still matches.

    Disjoint replacements may merge into a newer logical manifest because the
    caller names the exact fragment identities it observed.  Missing and
    certified-empty remain distinct (`None` is valid only for an existing
    certified-empty partition).
    """
    if (not isinstance(expected_certificates, Mapping)
            or not isinstance(execution_manifest_digest, str)
            or _DIGEST.fullmatch(execution_manifest_digest) is None):
        raise ValueError("CALCULATION_PARTITION_REPLACEMENT_INVALID")
    updated = dict(current.partitions)
    incoming = [_partition(item) for item in replacements]
    if (not incoming or len({item["partitionKey"] for item in incoming})
            != len(incoming) or set(expected_certificates) !=
            {item["partitionKey"] for item in incoming}):
        raise ValueError("CALCULATION_PARTITION_REPLACEMENT_INVALID")
    for item in incoming:
        key = str(item["partitionKey"])
        observed = updated.get(key)
        if observed is None:
            raise ValueError("CALCULATION_PARTITION_EXPECTATION_STALE")
        if observed["certificateDigest"] != expected_certificates[key]:
            raise ValueError("CALCULATION_PARTITION_EXPECTATION_STALE")
        updated[key] = item
    return compile_partition_manifest({
        **current.normalized,
        "executionManifestDigest": execution_manifest_digest,
        "partitions": list(updated.values()),
    })


def merge_coordinate_partitions(current: PartitionManifest | None, *,
        binding_digest: str, partition_policy_version: int,
        declared_partitions: Sequence[str],
        expected_certificates: Mapping[str, str | None],
        replacements: Sequence[dict[str, object]],
        execution_manifest_digest: str) -> PartitionManifest:
    """Add or replace exact fragments within one qualified coordinate map.

    A missing fragment can be added only when the admitted task expected no
    certificate. An existing fragment can be replaced only from its exact
    certificate. Whole-head equality is intentionally unnecessary: a task
    admitted before a disjoint fragment advanced may still merge when its own
    fragment is unchanged.
    """
    declared = list(declared_partitions)
    incoming = [_partition(item) for item in replacements]
    if (not isinstance(binding_digest, str)
            or _DIGEST.fullmatch(binding_digest) is None
            or type(partition_policy_version) is not int
            or partition_policy_version < 1
            or not isinstance(execution_manifest_digest, str)
            or _DIGEST.fullmatch(execution_manifest_digest) is None
            or not declared or len(declared) != len(set(declared))
            or any(not isinstance(item, str) or _ID.fullmatch(item) is None
                   for item in declared)
            or not incoming
            or len({item["partitionKey"] for item in incoming}) != len(incoming)
            or set(expected_certificates) !=
                {item["partitionKey"] for item in incoming}
            or any(item["partitionKey"] not in declared for item in incoming)):
        raise ValueError("CALCULATION_PARTITION_REPLACEMENT_INVALID")
    if current is None:
        updated: dict[str, dict[str, object]] = {}
    else:
        value = current.normalized
        if (value["bindingDigest"] != binding_digest
                or value["partitionPolicyVersion"] !=
                    partition_policy_version
                or any(key not in declared for key in current.partitions)):
            raise ValueError("CALCULATION_PARTITION_EXPECTATION_STALE")
        updated = dict(current.partitions)
    for item in incoming:
        key = str(item["partitionKey"])
        observed = updated.get(key)
        expected = expected_certificates[key]
        if ((observed is None and expected is not None)
                or (observed is not None
                    and observed["certificateDigest"] != expected)):
            raise ValueError("CALCULATION_PARTITION_EXPECTATION_STALE")
        updated[key] = item
    coverage = "complete" if set(updated) == set(declared) else "partial"
    return compile_partition_manifest({
        "format": FORMAT,
        "bindingDigest": binding_digest,
        "executionManifestDigest": execution_manifest_digest,
        "partitionPolicyVersion": partition_policy_version,
        "coverage": coverage,
        "partitions": list(updated.values()),
    })
