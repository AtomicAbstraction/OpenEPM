"""Deterministic W07 affected-work planning contracts.

This module is deliberately storage independent.  It turns the durable W05/W06
scope state and exact predecessor pins into a bounded, canonical request.  The
PostgreSQL adapter persists this result and maps it to the existing job queue;
clients cannot supply executable SQL or bypass the normal job fences.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Iterable, Mapping, Sequence

from .current_object_contract import is_state_token


FORMAT = "openepm-calculation-work-plan-v1"
MODES = frozenset({"affected", "force_populated", "force_domain"})
REASON_CODES = frozenset({
    "STALE_DEPENDENCY", "IMPACT_COVERAGE_PENDING", "CALCULATION_REQUIRED",
    "DEFINITION_REVALIDATION_REQUIRED", "DEPENDENCY_CYCLE",
    "TARGET_COLLISION", "SCOPE_EMPTY_REQUIRED", "RESOURCE_LIMIT",
    "INTERRUPTED", "FORCE_POPULATED", "FORCE_DOMAIN",
})
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError(code)
    return value


def _scope_key(value: Mapping[str, object]) -> tuple[str, str, str]:
    return (str(value["bindingDigest"]), str(value["stage"]),
            str(value["partitionKey"]))


def _normalize_state(value: object) -> dict[str, object]:
    required = {"bindingDigest", "stage", "partitionKey", "requiredEpoch",
        "publishedEpoch", "coverage", "presence", "definitionDigest",
        "currentResultStateToken", "reasons"}
    optional = {"currentPartitionCertificateDigest", "currentManifestDigest",
                "partitionPolicyVersion"}
    if (not isinstance(value, Mapping) or not required <= set(value)
            or set(value) - required - optional):
        raise ValueError("CALCULATION_WORK_SCOPE_INVALID")
    binding = value["bindingDigest"]
    definition = value["definitionDigest"]
    current_result_state_token = value.get("currentResultStateToken")
    required_epoch = value["requiredEpoch"]
    published_epoch = value["publishedEpoch"]
    reasons = value["reasons"]
    partition_certificate = value.get("currentPartitionCertificateDigest")
    manifest = value.get("currentManifestDigest")
    policy = value.get("partitionPolicyVersion")
    if (not isinstance(binding, str) or _DIGEST.fullmatch(binding) is None
            or not isinstance(definition, str)
            or _DIGEST.fullmatch(definition) is None
            or (current_result_state_token is not None
                and not is_state_token(current_result_state_token))
            or (partition_certificate is not None
                and (not isinstance(partition_certificate,str)
                     or _DIGEST.fullmatch(partition_certificate) is None))
            or (manifest is not None and (not isinstance(manifest, str)
                or _DIGEST.fullmatch(manifest) is None))
            or (policy is not None and (type(policy) is not int or policy < 1))
            or type(required_epoch) is not int or required_epoch < 0
            or type(published_epoch) is not int
            or not 0 <= published_epoch <= required_epoch
            or value["coverage"] not in {"complete", "conservative_superset",
                                         "unknown"}
            or value["presence"] not in {"unknown", "empty", "present"}
            or not isinstance(reasons, Sequence)
            or isinstance(reasons, (str, bytes))
            or any(not isinstance(item, str) or not item for item in reasons)):
        raise ValueError("CALCULATION_WORK_SCOPE_INVALID")
    return {
        "bindingDigest": binding,
        "stage": _identifier(value["stage"], "CALCULATION_WORK_SCOPE_INVALID"),
        "partitionKey": _identifier(value["partitionKey"],
                                    "CALCULATION_WORK_SCOPE_INVALID"),
        "requiredEpoch": required_epoch,
        "publishedEpoch": published_epoch,
        "coverage": value["coverage"],
        "presence": value["presence"],
        "definitionDigest": definition,
        "currentResultStateToken": current_result_state_token,
        "currentPartitionCertificateDigest": partition_certificate,
        "currentManifestDigest": manifest,
        "partitionPolicyVersion": policy,
        "reasons": sorted(set(reasons)),
    }


def _normalize_edge(value: object) -> tuple[tuple[str, str, str],
                                             tuple[str, str, str], dict]:
    required = {"predecessor", "successor", "predecessorReceiptId",
                "predecessorResultStateToken", "predecessorManifestDigest"}
    if not isinstance(value, Mapping) or set(value) != required:
        raise ValueError("CALCULATION_WORK_DEPENDENCY_INVALID")
    endpoints = []
    for name in ("predecessor", "successor"):
        endpoint = value[name]
        if (not isinstance(endpoint, Mapping)
                or set(endpoint) != {"bindingDigest", "stage", "partitionKey"}):
            raise ValueError("CALCULATION_WORK_DEPENDENCY_INVALID")
        binding = endpoint["bindingDigest"]
        if not isinstance(binding, str) or _DIGEST.fullmatch(binding) is None:
            raise ValueError("CALCULATION_WORK_DEPENDENCY_INVALID")
        endpoints.append((binding,
            _identifier(endpoint["stage"], "CALCULATION_WORK_DEPENDENCY_INVALID"),
            _identifier(endpoint["partitionKey"],
                        "CALCULATION_WORK_DEPENDENCY_INVALID")))
    receipt = value["predecessorReceiptId"]
    result_state_token = value["predecessorResultStateToken"]
    manifest = value["predecessorManifestDigest"]
    if ((receipt is None) != (result_state_token is None)
            or (receipt is not None and (not isinstance(receipt, str)
                or _ID.fullmatch(receipt) is None))
            or (result_state_token is not None
                and not is_state_token(result_state_token))
            or (manifest is not None and (not isinstance(manifest, str)
                or _DIGEST.fullmatch(manifest) is None))):
        raise ValueError("CALCULATION_WORK_DEPENDENCY_INVALID")
    pin = {"receiptId": receipt, "resultStateToken": result_state_token,
           "manifestDigest": manifest}
    return endpoints[0], endpoints[1], pin


@dataclass(frozen=True, slots=True)
class CalculationWorkPlan:
    normalized: dict[str, object]

    @property
    def digest(self) -> str:
        return _digest(self.normalized)

    @property
    def task_count(self) -> int:
        return len(self.normalized["tasks"])


def compile_calculation_work_plan(*, mode: str, states: Iterable[object],
        dependencies: Iterable[object] = (), impact_barrier_pending: bool = False,
        max_tasks: int = 10_000) -> CalculationWorkPlan:
    """Build the exact bounded closure to enqueue.

    ``affected`` starts at stale partitions only. ``force_populated`` starts at
    partitions with an existing present result as well as stale partitions.
    ``force_domain`` starts at every supplied partition. Successors are then
    included deterministically so a downstream stage cannot retain an older
    predecessor pin.
    """
    if (mode not in MODES or not isinstance(impact_barrier_pending, bool)
            or type(max_tasks) is not int or not 1 <= max_tasks <= 100_000):
        raise ValueError("CALCULATION_WORK_REQUEST_INVALID")
    normalized_states = [_normalize_state(item) for item in states]
    by_key = {_scope_key(item): item for item in normalized_states}
    if len(by_key) != len(normalized_states):
        raise ValueError("CALCULATION_WORK_SCOPE_DUPLICATE")
    edge_rows = [_normalize_edge(item) for item in dependencies]
    successors: dict[tuple[str, str, str], set[tuple[str, str, str]]] = {}
    predecessor_pins: dict[tuple[str, str, str], list[dict[str, object]]] = {}
    indegree = {key: 0 for key in by_key}
    for predecessor, successor, pin in edge_rows:
        if predecessor not in by_key or successor not in by_key:
            raise ValueError("CALCULATION_WORK_DEPENDENCY_SCOPE_UNKNOWN")
        bucket = successors.setdefault(predecessor, set())
        if successor not in bucket:
            bucket.add(successor)
            indegree[successor] += 1
        predecessor_pins.setdefault(successor, []).append({
            "bindingDigest": predecessor[0], "stage": predecessor[1],
            "partitionKey": predecessor[2], **pin})
    ready = sorted(key for key, degree in indegree.items() if degree == 0)
    order: list[tuple[str, str, str]] = []
    while ready:
        key = ready.pop(0)
        order.append(key)
        for successor in sorted(successors.get(key, ())):
            indegree[successor] -= 1
            if indegree[successor] == 0:
                ready.append(successor)
                ready.sort()
    if len(order) != len(by_key):
        raise ValueError("DEPENDENCY_CYCLE")

    selected: set[tuple[str, str, str]] = set()
    reasons: dict[tuple[str, str, str], set[str]] = {}
    if impact_barrier_pending:
        # Fail safe: callers may inspect this plan, but no work can be admitted
        # against an incomplete impact prefix.
        return CalculationWorkPlan({"format": FORMAT, "mode": mode,
            "status": "blocked", "reasonCodes": ["IMPACT_COVERAGE_PENDING"],
            "tasks": []})
    for key, state in by_key.items():
        stale = state["requiredEpoch"] != state["publishedEpoch"]
        choose = stale or mode == "force_domain" or (
            mode == "force_populated" and state["presence"] == "present")
        if not choose:
            continue
        selected.add(key)
        reason = ("CALCULATION_REQUIRED" if stale else
                  "FORCE_DOMAIN" if mode == "force_domain" else
                  "FORCE_POPULATED")
        reasons.setdefault(key, set()).add(reason)
        if state["coverage"] != "complete":
            reasons[key].add("STALE_DEPENDENCY")
        if "definition_changed" in state["reasons"]:
            reasons[key].add("DEFINITION_REVALIDATION_REQUIRED")
    frontier = sorted(selected)
    while frontier:
        predecessor = frontier.pop(0)
        for successor in sorted(successors.get(predecessor, ())):
            if successor not in selected:
                selected.add(successor)
                frontier.append(successor)
            reasons.setdefault(successor, set()).add("STALE_DEPENDENCY")
    if len(selected) > max_tasks:
        raise ValueError("RESOURCE_LIMIT")
    tasks = []
    for ordinal, key in enumerate(item for item in order if item in selected):
        state = by_key[key]
        pins = sorted(predecessor_pins.get(key, []), key=lambda item: (
            item["bindingDigest"], item["stage"], item["partitionKey"]))
        tasks.append({
            "ordinal": ordinal, "bindingDigest": key[0], "stage": key[1],
            "partitionKey": key[2],
            "expectedRequiredEpoch": state["requiredEpoch"],
            "definitionDigest": state["definitionDigest"],
            "expectedResultStateToken": state["currentResultStateToken"],
            "expectedPartitionCertificateDigest":
                state["currentPartitionCertificateDigest"],
            "expectedManifestDigest": state["currentManifestDigest"],
            "partitionPolicyVersion": state["partitionPolicyVersion"],
            "reasonCodes": sorted(reasons[key]), "predecessorPins": pins,
        })
    status = "no_change" if not tasks else "planned"
    return CalculationWorkPlan({"format": FORMAT, "mode": mode,
        "status": status, "reasonCodes": [], "tasks": tasks})
