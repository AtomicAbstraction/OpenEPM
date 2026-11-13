"""Immutable W05 dependency templates, execution manifests and freshness.

The contract separates symbolic definition dependencies from the exact tokens
resolved for one execution.  It is domain-neutral and contains no client SQL.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping, Sequence

from .current_object_contract import is_state_token


TEMPLATE_FORMAT = "openepm-calculation-dependency-template-v1"
MANIFEST_FORMAT = "openepm-calculation-execution-manifest-v1"
BINDING_FORMAT = "openepm-calculation-instance-binding-v1"
DEPENDENCY_KINDS = frozenset({
    "raw", "absence_range", "selector", "hierarchy", "formula",
    "calendar", "unit_policy", "upstream",
})
FANOUTS = frozenset({
    "same_partition", "future_periods", "downstream", "full_instance",
})
COVERAGE = frozenset({"complete", "conservative_superset", "unknown"})
REASONS = frozenset({
    "data_changed", "upstream_changed", "membership_changed",
    "hierarchy_changed", "definition_changed", "calendar_changed",
    "unit_policy_changed", "coverage_unknown",
})
ACTIVITIES = frozenset({
    "idle", "queued", "running", "failed", "interrupted", "blocked",
})
PRESENCE = frozenset({"unknown", "empty", "present"})
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_COMPILER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


def _identifier(value: object, code: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError(code)
    return value


def _digest(value: object, code: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(code)
    return value


def _scope(value: object, *, allow_empty: bool) -> list[dict[str, object]]:
    if (not isinstance(value, list) or len(value) > 32
            or (not allow_empty and not value)):
        raise ValueError("CALCULATION_DEPENDENCY_SCOPE_INVALID")
    normalized = []
    seen = set()
    for item in value:
        if (not isinstance(item, dict)
                or set(item) != {"dimensionId", "memberIds"}
                or not isinstance(item.get("memberIds"), list)
                or not 1 <= len(item["memberIds"]) <= 500):
            raise ValueError("CALCULATION_DEPENDENCY_SCOPE_INVALID")
        axis = _identifier(item.get("dimensionId"),
                           "CALCULATION_DEPENDENCY_SCOPE_INVALID")
        members = [_identifier(member,
            "CALCULATION_DEPENDENCY_SCOPE_INVALID")
            for member in item["memberIds"]]
        if axis in seen or len(members) != len(set(members)):
            raise ValueError("CALCULATION_DEPENDENCY_SCOPE_INVALID")
        seen.add(axis)
        normalized.append({"dimensionId": axis,
                           "memberIds": sorted(members)})
    return sorted(normalized, key=lambda item: item["dimensionId"])


def _bounded_json(value: object, *, depth: int = 0,
                  budget: list[int] | None = None) -> object:
    if budget is None:
        budget = [0]
    budget[0] += 1
    if depth > 8 or budget[0] > 1000:
        raise ValueError("CALCULATION_DEPENDENCY_PAYLOAD_LIMIT")
    if value is None or isinstance(value, (bool, int, str)):
        if isinstance(value, str) and len(value) > 1000:
            raise ValueError("CALCULATION_DEPENDENCY_PAYLOAD_LIMIT")
        return value
    if isinstance(value, list):
        if len(value) > 500:
            raise ValueError("CALCULATION_DEPENDENCY_PAYLOAD_LIMIT")
        return [_bounded_json(item, depth=depth + 1, budget=budget)
                for item in value]
    if isinstance(value, dict):
        if len(value) > 100:
            raise ValueError("CALCULATION_DEPENDENCY_PAYLOAD_LIMIT")
        normalized = {}
        for key in sorted(value):
            if not isinstance(key, str) or not 1 <= len(key) <= 200:
                raise ValueError("CALCULATION_DEPENDENCY_PAYLOAD_LIMIT")
            normalized[key] = _bounded_json(value[key], depth=depth + 1,
                                             budget=budget)
        return normalized
    raise ValueError("CALCULATION_DEPENDENCY_PAYLOAD_INVALID")


def semantic_dependency_identity_matches(effect: Mapping[str, object],
        dependency: Mapping[str, object]) -> bool:
    """Match admitted semantic identities without parsing IDs or prefixes.

    Writers address the semantic object that changed; a member value effect
    addresses its attribute and carries the member in ``scope``. Definition
    identities and published result keys occupy different namespaces even
    when their text is equal. Tokens/revisions belong to execution evidence,
    never to these stable reverse-index identities.
    """
    domain = effect["domain"]
    effect_type = effect["objectType"]
    dependency_type = dependency["object_type"]
    kind = dependency["dependency_kind"]
    if domain == "definition":
        kinds = {
            "member-list": {"selector"},
            "calculated-member": {"formula", "upstream"},
            "application-rule": {"formula", "upstream"},
            "expression-rule": {"formula", "upstream"},
            "resolved-read-binding": {"selector", "formula"},
            "applicability-relation": {"selector"},
        }.get(effect_type, set())
        admitted = dependency_type == effect_type and kind in kinds
    elif domain == "attribute":
        admitted = (effect_type in {"member-attribute-definition", "member-attribute-value",
                                   "member-attribute-value-set"}
            and dependency_type == "member-attribute" and kind == "selector")
    elif domain == "calendar":
        admitted = (effect_type == dependency_type == "application-calendar"
                    and kind == "calendar")
    elif domain == "hierarchy":
        admitted = (kind == 'hierarchy' and (
            effect_type in {'named_hierarchy', 'named-hierarchy'} and dependency_type == 'named-hierarchy'
            or effect_type == dependency_type == 'default-hierarchy'))
    elif domain == "calculation_result":
        admitted = (effect_type == dependency_type == "calculation-result"
                    and kind == "upstream")
    else:
        return False
    return admitted and effect["objectId"] == dependency["object_id"]


def _dependency(value: object) -> dict[str, object]:
    required = {"kind", "objectType", "objectId", "scope",
                "absenceWatch", "fanout"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("CALCULATION_DEPENDENCY_INVALID")
    kind = value["kind"]
    if kind not in DEPENDENCY_KINDS or value["fanout"] not in FANOUTS:
        raise ValueError("CALCULATION_DEPENDENCY_INVALID")
    absence = value["absenceWatch"]
    if not isinstance(absence, bool) or (kind == "absence_range") != absence:
        raise ValueError("CALCULATION_DEPENDENCY_INVALID")
    return {
        "kind": kind,
        "objectType": _identifier(value["objectType"],
                                  "CALCULATION_DEPENDENCY_INVALID"),
        "objectId": _identifier(value["objectId"],
                                "CALCULATION_DEPENDENCY_INVALID"),
        "scope": _scope(value["scope"], allow_empty=True),
        "absenceWatch": absence,
        "fanout": value["fanout"],
    }


def _target(value: object) -> dict[str, object]:
    if (not isinstance(value, dict)
            or set(value) != {"partitionKey", "scope", "createsFromEmpty"}
            or not isinstance(value["createsFromEmpty"], bool)):
        raise ValueError("CALCULATION_TARGET_DESCRIPTOR_INVALID")
    return {
        "partitionKey": _identifier(
            value["partitionKey"], "CALCULATION_TARGET_DESCRIPTOR_INVALID"),
        # A relation-driven expression discovers its affected coordinates
        # from the current sparse relation at execution time.  Its symbolic
        # target therefore has no statically enumerable member scope; the
        # partition key remains exact and the execution manifest resolves the
        # current relation token.  Empty here means "the whole named output
        # partition", not an unbounded client query.
        "scope": _scope(value["scope"], allow_empty=True),
        "createsFromEmpty": value["createsFromEmpty"],
    }


@dataclass(frozen=True, slots=True)
class DependencyTemplate:
    normalized: dict[str, object]

    @property
    def digest(self) -> str:
        return digest(self.normalized)


def compile_dependency_template(value: object) -> DependencyTemplate:
    required = {"format", "definitionId", "definitionDigest",
                "compilerVersion", "dependencies",
                "targets", "coverage"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("CALCULATION_DEPENDENCY_TEMPLATE_INVALID")
    if (value["format"] != TEMPLATE_FORMAT
            or not isinstance(value["compilerVersion"], str)
            or _COMPILER.fullmatch(value["compilerVersion"]) is None
            or value["coverage"] not in COVERAGE
            or not isinstance(value["dependencies"], list)
            or not 1 <= len(value["dependencies"]) <= 500
            or not isinstance(value["targets"], list)
            or not 1 <= len(value["targets"]) <= 500):
        raise ValueError("CALCULATION_DEPENDENCY_TEMPLATE_INVALID")
    dependencies = [_dependency(item) for item in value["dependencies"]]
    targets = [_target(item) for item in value["targets"]]
    dependency_keys = [(item["kind"], item["objectType"], item["objectId"],
                        digest(item)) for item in dependencies]
    if len(dependency_keys) != len(set(dependency_keys)):
        raise ValueError("CALCULATION_DEPENDENCY_TEMPLATE_DUPLICATE")
    if len({item["partitionKey"] for item in targets}) != len(targets):
        raise ValueError("CALCULATION_TARGET_DESCRIPTOR_DUPLICATE")
    normalized = {
        "format": TEMPLATE_FORMAT,
        "definitionId": _identifier(
            value["definitionId"], "CALCULATION_DEPENDENCY_TEMPLATE_INVALID"),
        "definitionDigest": _digest(
            value["definitionDigest"],
            "CALCULATION_DEPENDENCY_TEMPLATE_INVALID"),
        "compilerVersion": value["compilerVersion"],
        "dependencies": sorted(dependencies, key=lambda item: (
            item["kind"], item["objectType"], item["objectId"], digest(item))),
        "targets": sorted(targets, key=lambda item: item["partitionKey"]),
        "coverage": value["coverage"],
    }
    return DependencyTemplate(normalized)


def calculation_instance_binding(*, template_digest: str,
        definition_id: str, definition_state_token: str, stage: str,
        parameters: Mapping[str, object], partition_policy_version: int) -> dict:
    if (not isinstance(definition_state_token, str)
            or _DIGEST.fullmatch(definition_state_token) is None
            or not isinstance(partition_policy_version, int)
            or isinstance(partition_policy_version, bool)
            or partition_policy_version < 1 or not isinstance(parameters, Mapping)):
        raise ValueError("CALCULATION_INSTANCE_BINDING_INVALID")
    normalized = {
        "format": BINDING_FORMAT,
        "templateDigest": _digest(
            template_digest, "CALCULATION_INSTANCE_BINDING_INVALID"),
        "definitionId": _identifier(
            definition_id, "CALCULATION_INSTANCE_BINDING_INVALID"),
        "definitionStateToken": definition_state_token,
        "stage": _identifier(stage, "CALCULATION_INSTANCE_BINDING_INVALID"),
        "parameters": _bounded_json(dict(parameters)),
        "partitionPolicyVersion": partition_policy_version,
    }
    return {**normalized, "bindingDigest": digest(normalized)}


@dataclass(frozen=True, slots=True)
class ExecutionManifest:
    normalized: dict[str, object]

    @property
    def digest(self) -> str:
        return digest(self.normalized)


def compile_execution_manifest(value: object) -> ExecutionManifest:
    required = {"format", "templateDigest", "bindingDigest", "schemaEpoch",
                "readCut", "resolvedDependencies", "targetPartitions",
                "coverage"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("CALCULATION_EXECUTION_MANIFEST_INVALID")
    read_cut = value["readCut"]
    if (not isinstance(read_cut, dict)
            or set(read_cut) != {"commit", "metadata", "data", "policy"}
            or any(not isinstance(item, int) or isinstance(item, bool) or item < 0
                   for item in read_cut.values())
            or not isinstance(value["schemaEpoch"], int)
            or value["schemaEpoch"] < 1
            or value["coverage"] not in COVERAGE
            or not isinstance(value["resolvedDependencies"], list)
            or not 1 <= len(value["resolvedDependencies"]) <= 1000
            or not isinstance(value["targetPartitions"], list)
            or not 1 <= len(value["targetPartitions"]) <= 500):
        raise ValueError("CALCULATION_EXECUTION_MANIFEST_INVALID")
    dependencies = []
    seen = set()
    for item in value["resolvedDependencies"]:
        if (not isinstance(item, dict)
                or set(item) != {"templateOrdinal", "tokenDigest", "token",
                                 "outputPartitions"}
                or not isinstance(item["templateOrdinal"], int)
                or not 0 <= item["templateOrdinal"] < 500
                or not isinstance(item["outputPartitions"], list)
                or not 1 <= len(item["outputPartitions"]) <= 500):
            raise ValueError("CALCULATION_RESOLVED_DEPENDENCY_INVALID")
        partitions = sorted(_identifier(partition,
            "CALCULATION_RESOLVED_DEPENDENCY_INVALID")
            for partition in item["outputPartitions"])
        if len(partitions) != len(set(partitions)):
            raise ValueError("CALCULATION_RESOLVED_DEPENDENCY_INVALID")
        token = _bounded_json(item["token"])
        token_digest = _digest(item["tokenDigest"],
                               "CALCULATION_RESOLVED_DEPENDENCY_INVALID")
        if token_digest != digest(token) or item["templateOrdinal"] in seen:
            raise ValueError("CALCULATION_RESOLVED_DEPENDENCY_INVALID")
        seen.add(item["templateOrdinal"])
        dependencies.append({"templateOrdinal": item["templateOrdinal"],
            "tokenDigest": token_digest, "token": token,
            "outputPartitions": partitions})
    partitions = sorted(_identifier(item,
        "CALCULATION_EXECUTION_MANIFEST_INVALID")
        for item in value["targetPartitions"])
    if len(partitions) != len(set(partitions)):
        raise ValueError("CALCULATION_EXECUTION_MANIFEST_INVALID")
    normalized = {
        "format": MANIFEST_FORMAT,
        "templateDigest": _digest(
            value["templateDigest"], "CALCULATION_EXECUTION_MANIFEST_INVALID"),
        "bindingDigest": _digest(
            value["bindingDigest"], "CALCULATION_EXECUTION_MANIFEST_INVALID"),
        "schemaEpoch": value["schemaEpoch"],
        "readCut": {key: read_cut[key]
                    for key in ("commit", "metadata", "data", "policy")},
        "resolvedDependencies": sorted(
            dependencies, key=lambda item: item["templateOrdinal"]),
        "targetPartitions": partitions,
        "coverage": value["coverage"],
    }
    return ExecutionManifest(normalized)


def validate_manifest_against_template(
        template: DependencyTemplate, manifest: ExecutionManifest) -> None:
    """Prove that a resolved manifest covers one immutable template.

    Compilation validates each artifact in isolation.  This relation check is
    deliberately separate so stored artifacts can be authenticated by digest
    before they are compared.
    """
    value = manifest.normalized
    expected_dependencies = len(template.normalized["dependencies"])
    target_partitions = {
        item["partitionKey"] for item in template.normalized["targets"]
    }
    manifest_partitions = set(value["targetPartitions"])
    resolved_ordinals = {
        item["templateOrdinal"] for item in value["resolvedDependencies"]
    }
    resolved_partitions = {
        partition
        for item in value["resolvedDependencies"]
        for partition in item["outputPartitions"]
    }
    if (value["templateDigest"] != template.digest
            or not manifest_partitions
            or not manifest_partitions.issubset(target_partitions)
            or not resolved_partitions.issubset(manifest_partitions)
            or any(ordinal >= expected_dependencies
                   for ordinal in resolved_ordinals)):
        raise ValueError("CALCULATION_EXECUTION_MANIFEST_RELATION_INVALID")
    # Execution coverage is complete for the exact target subset named by
    # this manifest. The immutable template owns the full output domain;
    # independently scheduled partitions must not claim they computed every
    # other target merely to receive a complete certificate.
    if value["coverage"] == "complete" and (
            resolved_ordinals != set(range(expected_dependencies))
            or resolved_partitions != manifest_partitions):
        raise ValueError("CALCULATION_EXECUTION_MANIFEST_COVERAGE_INCOMPLETE")


def validate_dependency_template_graph(
        templates: Sequence[DependencyTemplate]) -> None:
    """Reject implicit cycles among the supplied immutable definitions."""
    by_definition: dict[str, DependencyTemplate] = {}
    for template in templates:
        definition_id = str(template.normalized["definitionId"])
        if definition_id in by_definition:
            raise ValueError("CALCULATION_DEPENDENCY_GRAPH_DUPLICATE")
        by_definition[definition_id] = template
    edges = {
        definition_id: {
            str(dependency["objectId"])
            for dependency in template.normalized["dependencies"]
            if dependency["kind"] == "upstream"
            and dependency["objectType"] == "calculated-member"
            and dependency["objectId"] in by_definition
        }
        for definition_id, template in by_definition.items()
    }
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(definition_id: str) -> None:
        if definition_id in visiting:
            raise ValueError("CALCULATION_DEPENDENCY_GRAPH_CYCLE")
        if definition_id in visited:
            return
        visiting.add(definition_id)
        for upstream in sorted(edges[definition_id]):
            visit(upstream)
        visiting.remove(definition_id)
        visited.add(definition_id)

    for definition_id in sorted(edges):
        visit(definition_id)


def freshness_status(*, current_result_state_token: str | None,
        required_epoch: int, published_epoch: int,
        definition_valid: bool, coverage_complete: bool,
        reasons: Sequence[str], presence: str, activity: str) -> dict:
    if (not isinstance(required_epoch, int)
            or isinstance(required_epoch, bool) or required_epoch < 0
            or not isinstance(published_epoch, int)
            or isinstance(published_epoch, bool) or published_epoch < 0
            or published_epoch > required_epoch
            or (current_result_state_token is not None
                and not is_state_token(current_result_state_token))
            or not isinstance(definition_valid, bool)
            or not isinstance(coverage_complete, bool)
            or presence not in PRESENCE or activity not in ACTIVITIES
            or not isinstance(reasons, Sequence)
            or isinstance(reasons, (str, bytes))
            or any(reason not in REASONS for reason in reasons)):
        raise ValueError("CALCULATION_FRESHNESS_STATUS_INVALID")
    normalized_reasons = sorted(set(reasons))
    if ((not coverage_complete
         and "coverage_unknown" not in normalized_reasons)
            or (coverage_complete
                and "coverage_unknown" in normalized_reasons)):
        raise ValueError("CALCULATION_FRESHNESS_STATUS_INVALID")
    if not definition_valid:
        freshness = "invalid_definition"
        action = "rebuild_definition"
    elif current_result_state_token is None:
        freshness = "never_calculated"
        action = ("resolve_dependency" if not coverage_complete
                  else "calculate")
    elif (not coverage_complete or published_epoch != required_epoch
          or normalized_reasons):
        freshness = "impacted"
        action = ("resolve_dependency" if not coverage_complete
                  else "calculate")
    else:
        freshness = "current"
        action = "none"
    return {"freshness": freshness, "reasons": normalized_reasons,
            "presence": presence, "activity": activity,
            "requiredAction": action, "requiredEpoch": required_epoch,
            "publishedEpoch": published_epoch,
            "currentResultStateToken": current_result_state_token,
            "coverageComplete": coverage_complete}
