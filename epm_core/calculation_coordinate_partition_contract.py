"""Qualified coordinate ownership for partial calculation publication.

Partial carry-forward is safe only when fixed core can prove which one declared
partition owns every payload coordinate.  A target scope is a conjunction of
dimension/member sets.  Two targets are provably disjoint when they share at
least one dimension whose member sets do not overlap.  Opaque, empty, partial,
or merely *apparently* disjoint target descriptions are not admitted.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .calculation_dependency_contract import DependencyTemplate


@dataclass(frozen=True, slots=True)
class CoordinatePartitionProfile:
    binding_digest: str
    stage: str
    partition_policy_version: int
    scopes: dict[str, dict[str, frozenset[str]]]

    @property
    def partition_keys(self) -> tuple[str, ...]:
        return tuple(sorted(self.scopes))

    def serialized_scopes(self) -> list[dict[str, object]]:
        return [{"partitionKey": key, "dimensions": [
            {"dimensionId": dimension, "memberIds": sorted(members)}
            for dimension, members in sorted(self.scopes[key].items())]}
            for key in self.partition_keys]


def compile_coordinate_partition_profile(template: DependencyTemplate, *,
        binding_digest: str, stage: str,
        partition_policy_version: int) -> CoordinatePartitionProfile:
    """Compile the only partition shape eligible for partial carry-forward."""
    if (template.normalized["coverage"] != "complete"
            or not isinstance(binding_digest, str)
            or len(binding_digest) != 64
            or any(character not in "0123456789abcdef"
                   for character in binding_digest)
            or not isinstance(stage, str) or not stage
            or type(partition_policy_version) is not int
            or partition_policy_version < 1):
        raise ValueError("CALCULATION_COORDINATE_PARTITION_UNQUALIFIED")
    targets = template.normalized["targets"]
    scopes: dict[str, dict[str, frozenset[str]]] = {}
    for target in targets:
        if not target["scope"]:
            raise ValueError("CALCULATION_COORDINATE_PARTITION_UNQUALIFIED")
        scopes[str(target["partitionKey"])] = {
            str(axis["dimensionId"]): frozenset(map(str, axis["memberIds"]))
            for axis in target["scope"]}
    keys = sorted(scopes)
    for ordinal, left_key in enumerate(keys):
        left = scopes[left_key]
        for right_key in keys[ordinal + 1:]:
            right = scopes[right_key]
            shared = set(left) & set(right)
            if not any(left[axis].isdisjoint(right[axis]) for axis in shared):
                raise ValueError("CALCULATION_COORDINATE_PARTITION_OVERLAP")
    return CoordinatePartitionProfile(binding_digest=binding_digest,
        stage=stage, partition_policy_version=partition_policy_version,
        scopes=scopes)


def classify_coordinate(profile: CoordinatePartitionProfile,
        members: Mapping[str, str]) -> str:
    """Return the one proven owner, rejecting uncovered or ambiguous input."""
    if (not isinstance(members, Mapping)
            or any(not isinstance(axis, str) or not isinstance(member, str)
                   for axis, member in members.items())):
        raise ValueError("CALCULATION_COORDINATE_PARTITION_INVALID")
    matches = [key for key, scope in profile.scopes.items()
        if all(members.get(axis) in allowed
               for axis, allowed in scope.items())]
    if len(matches) != 1:
        raise ValueError("CALCULATION_COORDINATE_PARTITION_UNOWNED")
    return matches[0]
