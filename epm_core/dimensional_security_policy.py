"""Pure fixed-core contract for dimensional member authorization.

This module deliberately does not select Open EPM's active policy.  The owner
has not yet settled the Boolean, untagged-member, hierarchy, administrator,
write/read, or mixed-selection semantics.  Callers must therefore provide a
complete :class:`DimensionalSecurityPolicy`; there are no permissive defaults.

The evaluator consumes server-resolved member tags and server-resolved grant
assignments.  Caller-supplied tags must never be passed to this boundary as
authority.  Database integration and final-publication rechecks are separate
work and must not claim enforcement merely because this pure contract exists.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
import json
from typing import Mapping, Sequence


class AccessKind(StrEnum):
    READ = "read"
    WRITE = "write"


class AcrossDimensions(StrEnum):
    EVERY_PROTECTED = "every_protected"
    ANY_PROTECTED = "any_protected"


class WithinDimension(StrEnum):
    ANY_TAG = "any_tag"
    ALL_TAGS = "all_tags"


class UntaggedMember(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class UntaggedDenyPrecedence(StrEnum):
    ABSOLUTE = "absolute"
    DIMENSION_RESULT = "dimension_result"


class MemberTagCardinality(StrEnum):
    MULTIPLE = "multiple"
    EXACTLY_ONE_WHEN_PROTECTED = "exactly_one_when_protected"


class HierarchyTags(StrEnum):
    SELECTED_MEMBER_ONLY = "selected_member_only"
    EFFECTIVE_TAGS_RESOLVED_BY_SERVER = "effective_tags_resolved_by_server"


class WriteReadRelationship(StrEnum):
    INDEPENDENT = "independent"
    REQUIRE_READ = "require_read"


class MixedSelection(StrEnum):
    FILTER_READS_REJECT_WRITES = "filter_reads_reject_writes"
    FILTER_READS_AND_WRITES = "filter_reads_and_writes"
    REJECT_ALL = "reject_all"


class AdministratorTreatment(StrEnum):
    REQUIRE_ASSIGNMENT = "require_assignment"
    BYPASS = "bypass"


class FactSideAuthority(StrEnum):
    """Fact-side fields can never replace current metadata authorization."""

    DERIVED_QUERY_AID_ONLY = "derived_query_aid_only"


@dataclass(frozen=True, slots=True)
class DimensionalSecurityPolicy:
    """Every supported policy alternative must be stated explicitly.

    A separately selected default tag and placement-specific inheritance are
    intentionally unsupported by this first contract. Choosing either still
    requires an expanded, versioned model before runtime activation.
    """

    across_dimensions: AcrossDimensions
    within_dimension: WithinDimension
    untagged_member: UntaggedMember
    untagged_deny_precedence: UntaggedDenyPrecedence
    member_tag_cardinality: MemberTagCardinality
    hierarchy_tags: HierarchyTags
    write_read_relationship: WriteReadRelationship
    mixed_selection: MixedSelection
    administrator_treatment: AdministratorTreatment
    fact_side_authority: FactSideAuthority

    def __post_init__(self) -> None:
        expected = (
            (self.across_dimensions, AcrossDimensions),
            (self.within_dimension, WithinDimension),
            (self.untagged_member, UntaggedMember),
            (self.untagged_deny_precedence, UntaggedDenyPrecedence),
            (self.member_tag_cardinality, MemberTagCardinality),
            (self.hierarchy_tags, HierarchyTags),
            (self.write_read_relationship, WriteReadRelationship),
            (self.mixed_selection, MixedSelection),
            (self.administrator_treatment, AdministratorTreatment),
            (self.fact_side_authority, FactSideAuthority),
        )
        if any(not isinstance(value, enum_type)
               for value, enum_type in expected):
            raise TypeError("A complete typed dimensional-security policy is required")


def dimensional_security_policy_digest(
        workspace_id: str, application_id: str,
        policy: DimensionalSecurityPolicy) -> str:
    """Bind the current scoped policy to every semantic choice."""
    if (not isinstance(workspace_id, str) or not workspace_id
            or not isinstance(application_id, str) or not application_id
            or not isinstance(policy, DimensionalSecurityPolicy)):
        raise ValueError("A scoped typed policy is required")
    payload = {
        "applicationId": application_id,
        "policy": {
            "acrossDimensions": policy.across_dimensions.value,
            "administratorTreatment": policy.administrator_treatment.value,
            "factSideAuthority": policy.fact_side_authority.value,
            "hierarchyTags": policy.hierarchy_tags.value,
            "memberTagCardinality": policy.member_tag_cardinality.value,
            "mixedSelection": policy.mixed_selection.value,
            "untaggedDenyPrecedence":
                policy.untagged_deny_precedence.value,
            "untaggedMember": policy.untagged_member.value,
            "withinDimension": policy.within_dimension.value,
            "writeReadRelationship": policy.write_read_relationship.value,
        },
        "workspaceId": workspace_id,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return sha256(encoded).hexdigest()


def _canonical_tags(value: tuple[str, ...], label: str) -> tuple[str, ...]:
    if (not isinstance(value, tuple)
            or len(value) > 100
            or any(not isinstance(tag, str) or not tag
                   or tag != tag.strip() or len(tag) > 20
                   or ";" in tag for tag in value)
            or tuple(sorted(set(value))) != value):
        raise ValueError(f"{label} must be sorted unique canonical tags")
    return value


@dataclass(frozen=True, slots=True)
class ResolvedMemberSecurity:
    """Tags read by trusted core code for one selected member.

    ``effective_*`` may include hierarchy-derived tags only when the active
    policy says the server resolved them.  They are never accepted from an MCP
    client or Python program.
    """

    dimension_id: str
    member_id: str
    read_tags: tuple[str, ...]
    write_tags: tuple[str, ...]
    effective_read_tags: tuple[str, ...] | None = None
    effective_write_tags: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if (not isinstance(self.dimension_id, str) or not self.dimension_id
                or not isinstance(self.member_id, str) or not self.member_id):
            raise ValueError("Stable dimension and member IDs are required")
        _canonical_tags(self.read_tags, "Read tags")
        _canonical_tags(self.write_tags, "Write tags")
        if self.effective_read_tags is not None:
            _canonical_tags(self.effective_read_tags, "Effective read tags")
        if self.effective_write_tags is not None:
            _canonical_tags(self.effective_write_tags, "Effective write tags")


@dataclass(frozen=True, slots=True)
class CoordinateSecurityDecision:
    allowed: bool
    reason: str
    protected_dimensions: tuple[str, ...]
    matched_dimensions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class SelectionSecurityDecision:
    permitted_indexes: tuple[int, ...]
    denied_indexes: tuple[int, ...]
    rejected: bool
    reason: str


def _assignment_for(assignments: Mapping[str, Sequence[str]],
                    dimension_id: str) -> frozenset[str]:
    assigned = assignments.get(dimension_id, ())
    if (isinstance(assigned, (str, bytes)) or not isinstance(assigned, Sequence)
            or len(assigned) > 100
            or any(not isinstance(tag, str) or not tag
                   or tag != tag.strip() or len(tag) > 20
                   or ";" in tag for tag in assigned)
            or list(assigned) != sorted(set(assigned))):
        raise ValueError("Server-resolved assignments are invalid")
    return frozenset(assigned)


def _member_tags(member: ResolvedMemberSecurity, kind: AccessKind,
                 policy: DimensionalSecurityPolicy) -> tuple[str, ...]:
    if policy.hierarchy_tags is HierarchyTags.SELECTED_MEMBER_ONLY:
        return member.read_tags if kind is AccessKind.READ else member.write_tags
    effective = (member.effective_read_tags if kind is AccessKind.READ
                 else member.effective_write_tags)
    if effective is None:
        raise ValueError("SERVER_EFFECTIVE_SECURITY_TAGS_REQUIRED")
    return effective


def _kind_allowed(members: tuple[ResolvedMemberSecurity, ...],
                  assignments: Mapping[str, Sequence[str]], kind: AccessKind,
                  policy: DimensionalSecurityPolicy
                  ) -> CoordinateSecurityDecision:
    protected: list[str] = []
    matched: list[str] = []
    untagged_denied = False
    for member in members:
        direct_tags = (member.read_tags if kind is AccessKind.READ
                       else member.write_tags)
        if (policy.member_tag_cardinality
                is MemberTagCardinality.EXACTLY_ONE_WHEN_PROTECTED
                and len(direct_tags) > 1):
            raise ValueError("MEMBER_SECURITY_TAG_CARDINALITY_VIOLATION")
        tags = _member_tags(member, kind, policy)
        if not tags:
            if policy.untagged_member is UntaggedMember.DENY:
                protected.append(member.dimension_id)
                untagged_denied = True
            else:
                continue
        else:
            protected.append(member.dimension_id)
            assigned = _assignment_for(assignments, member.dimension_id)
            tag_set = frozenset(tags)
            if ((policy.within_dimension is WithinDimension.ANY_TAG
                    and bool(tag_set & assigned))
                    or (policy.within_dimension is WithinDimension.ALL_TAGS
                        and tag_set <= assigned)):
                matched.append(member.dimension_id)
    protected_tuple = tuple(protected)
    matched_tuple = tuple(matched)
    if not protected:
        return CoordinateSecurityDecision(
            True, "NO_PROTECTED_DIMENSIONS", protected_tuple, matched_tuple)
    allowed = (len(matched) == len(protected)
               if policy.across_dimensions is AcrossDimensions.EVERY_PROTECTED
               else bool(matched))
    if (untagged_denied and policy.untagged_deny_precedence
            is UntaggedDenyPrecedence.ABSOLUTE):
        allowed = False
    return CoordinateSecurityDecision(
        allowed,
        "DIMENSIONAL_SCOPE_ALLOWED" if allowed else "DIMENSIONAL_SCOPE_DENIED",
        protected_tuple, matched_tuple)


def _validate_common(kind: AccessKind, expected_dimensions: tuple[str, ...],
                     policy: DimensionalSecurityPolicy,
                     application_administrator: bool,
                     workspace_administrator: bool) -> None:
    if (not isinstance(kind, AccessKind)
            or not isinstance(policy, DimensionalSecurityPolicy)
            or not isinstance(application_administrator, bool)
            or not isinstance(workspace_administrator, bool)):
        raise TypeError("Typed dimensional-security inputs are required")
    if (not isinstance(expected_dimensions, tuple)
            or not expected_dimensions
            or any(not isinstance(value, str) or not value
                   for value in expected_dimensions)
            or len(expected_dimensions) != len(set(expected_dimensions))):
        raise ValueError("A canonical application layout is required")


def evaluate_coordinate(
        members: Sequence[ResolvedMemberSecurity], *, kind: AccessKind,
        expected_dimensions: tuple[str, ...],
        read_assignments: Mapping[str, Sequence[str]],
        write_assignments: Mapping[str, Sequence[str]],
        policy: DimensionalSecurityPolicy,
        application_administrator: bool = False,
        workspace_administrator: bool = False) -> CoordinateSecurityDecision:
    """Evaluate one explicit coordinate independently of fact presence."""
    _validate_common(kind, expected_dimensions, policy,
                     application_administrator, workspace_administrator)
    members_tuple = tuple(members)
    if not members_tuple:
        raise ValueError("A complete coordinate is required")
    dimensions = tuple(member.dimension_id for member in members_tuple)
    if dimensions != expected_dimensions:
        raise ValueError(
            "A coordinate must exactly match canonical application layout")
    if ((application_administrator or workspace_administrator)
            and policy.administrator_treatment
            is AdministratorTreatment.BYPASS):
        return CoordinateSecurityDecision(
            True, "ADMINISTRATOR_BYPASS", (), ())
    read_decision = _kind_allowed(
        members_tuple, read_assignments, AccessKind.READ, policy)
    if kind is AccessKind.READ:
        return read_decision
    write_decision = _kind_allowed(
        members_tuple, write_assignments, AccessKind.WRITE, policy)
    if (policy.write_read_relationship is WriteReadRelationship.REQUIRE_READ
            and not read_decision.allowed):
        return CoordinateSecurityDecision(
            False, "WRITE_REQUIRES_READ", read_decision.protected_dimensions,
            read_decision.matched_dimensions)
    return write_decision


def evaluate_selection(
        coordinates: Sequence[Sequence[ResolvedMemberSecurity]], *,
        kind: AccessKind,
        expected_dimensions: tuple[str, ...],
        read_assignments: Mapping[str, Sequence[str]],
        write_assignments: Mapping[str, Sequence[str]],
        policy: DimensionalSecurityPolicy,
        application_administrator: bool = False,
        workspace_administrator: bool = False) -> SelectionSecurityDecision:
    """Evaluate an already bounded coordinate selection without data access."""
    _validate_common(kind, expected_dimensions, policy,
                     application_administrator, workspace_administrator)
    if not isinstance(coordinates, Sequence) or isinstance(coordinates, (str, bytes)):
        raise TypeError("A bounded coordinate selection is required")
    decisions = tuple(evaluate_coordinate(
        coordinate, kind=kind, expected_dimensions=expected_dimensions,
        read_assignments=read_assignments,
        write_assignments=write_assignments, policy=policy,
        application_administrator=application_administrator,
        workspace_administrator=workspace_administrator)
        for coordinate in coordinates)
    permitted = tuple(index for index, decision in enumerate(decisions)
                      if decision.allowed)
    denied = tuple(index for index, decision in enumerate(decisions)
                   if not decision.allowed)
    if not decisions:
        return SelectionSecurityDecision((), (), False,
                                         "AUTHORIZED_EMPTY_SELECTION")
    if denied and not permitted:
        return SelectionSecurityDecision((), denied, True,
                                         "DIMENSIONAL_SCOPE_DENIED")
    mixed = bool(permitted and denied)
    rejected = mixed and (
        policy.mixed_selection is MixedSelection.REJECT_ALL
        or (kind is AccessKind.WRITE and policy.mixed_selection
            is MixedSelection.FILTER_READS_REJECT_WRITES))
    if rejected:
        return SelectionSecurityDecision((), denied, True,
                                         "DIMENSIONAL_SELECTION_REJECTED")
    return SelectionSecurityDecision(
        permitted, denied, False,
        "DIMENSIONAL_SELECTION_FILTERED" if mixed else
        ("DIMENSIONAL_SELECTION_ALLOWED" if permitted else
         "DIMENSIONAL_SELECTION_DENIED"))
