"""Application-bound metadata handles that construct ordinary typed plans.

Names become scoped references in symbolic contexts; fixed core resolves them.
Materialized descriptors remain explicit read values, never a fallback.
No handle performs I/O or evaluates business data in the Python builder.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping

from .model import (ApplicabilityDomain, ApportionmentDomain, CubeExpression,
                    NumericSequenceExpression, Program, RelationOperand,
                    RelationValue, _canonical_copy, _freeze, _identifier, _thaw)
from .metadata_references import (MetadataReference, token_reference,
                                  BOOTSTRAP_CONTRACT, BOOTSTRAP_CONTRACT_DIGEST,
                                  reference_identity_key)
from .member_lists import MemberListExpression
from .selections import (
    INLINE_EXPRESSION_FORMAT,
    CubeSelection,
    DimensionSelection,
)


class MetadataAuthoringError(ValueError):
    """Fixed metadata failure classification; never carries caller names/values."""

    def __init__(self, code: str, kind: str):
        self.code = code
        self.kind = kind
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ApplicabilityRelation:
    """Current application-owned sparse business mapping handle."""
    application: tuple[str, str, int]
    descriptor: Mapping

    @property
    def id(self) -> str | MetadataReference:
        return self.descriptor["relationId"]

    @property
    def columns(self) -> tuple[Mapping, ...]:
        if self.descriptor.get("referenceMode") == "symbolic":
            raise MetadataAuthoringError("METADATA_DESCRIPTOR_READ_REQUIRED", "applicability_relation")
        return tuple(self.descriptor["columns"])

    def domain(self, *, anchor_columns: Mapping[str, str],
               target_columns: Mapping[str, str] | None = None,
               operands: tuple[RelationOperand, ...] = (),
               values: tuple[RelationValue, ...] = (),
               max_rows: int = 500) -> ApplicabilityDomain:
        """Bind authored column roles to this exact current relation state."""
        return ApplicabilityDomain(
            relation_id=self.id,
            relation_state_token=self.descriptor["stateToken"],
            relation_digest=self.descriptor["definitionDigest"],
            anchor_columns=anchor_columns,
            target_columns={} if target_columns is None else target_columns,
            operands=operands, values=values, max_rows=max_rows)

    def apportionment_domain(self, *, anchor_columns: Mapping[str, str],
            target_columns: Mapping[str, str],
            operands: tuple[RelationOperand, ...], group_column_id: str,
            component_column_id: str, formula_column_id: str,
            weight_column_id: str, quantum_column_id: str,
            rounding_column_id: str, tie_dimensions: tuple[str, ...],
            max_rows: int = 100_000,
            max_groups: int = 10_000) -> ApportionmentDomain:
        """Bind grouped allocation roles to this exact current relation."""
        return ApportionmentDomain(self.id,
            self.descriptor["stateToken"],
            self.descriptor["definitionDigest"], anchor_columns,
            target_columns, operands, group_column_id, component_column_id,
            formula_column_id, weight_column_id, quantum_column_id,
            rounding_column_id, tie_dimensions, max_rows, max_groups)


def _lookup(rows, name, key):
    kind = {
        "dimensionId": "dimension",
        "hierarchyId": "hierarchy",
        "attributeId": "attribute",
        "listId": "member_list",
        "relationId": "applicability_relation",
    }.get(key, "member")
    if not isinstance(name, str) or not name:
        raise MetadataAuthoringError("METADATA_NAME_REQUIRED", kind)
    # Stable IDs are authoritative even when another object's display name
    # happens to equal the ID. Names remain ambiguity checked within scope.
    matches = [row for row in rows if row.get(key) == name]
    if not matches:
        matches = [row for row in rows
                   if row.get("nameLookupAllowed", True)
                   and name in (row.get("name"), row.get("displayName"))]
    if not matches:
        raise MetadataAuthoringError("METADATA_NAME_UNAVAILABLE", kind)
    if len(matches) != 1:
        raise MetadataAuthoringError("METADATA_NAME_AMBIGUOUS", kind)
    return matches[0]


@dataclass(frozen=True, slots=True)
class AxisSelection:
    application: tuple[str, str, int]
    dimension_id: str
    selector: Mapping | None
    cube_selector: Mapping | None = None
    expression: MemberListExpression | None = None

    def __bool__(self) -> bool:
        raise TypeError("AxisSelection is symbolic; compose it with set operators")

    def _combine(self, other: "Member | AxisSelection", operator: str) -> "AxisSelection":
        other = _axis_selection(other)
        if (other.application != self.application
                or other.dimension_id != self.dimension_id):
            raise ValueError("CROSS_APPLICATION_OR_DIMENSION_SELECTION")
        if self.expression is None or other.expression is None:
            raise ValueError("VERSIONED_MEMBER_LIST_COMPOSITION_UNSUPPORTED")
        expression = (MemberListExpression.intersection(
            self.expression, other.expression) if operator == "intersection"
            else MemberListExpression.union(self.expression, other.expression))
        return AxisSelection(self.application, self.dimension_id, None,
            {"kind": "inline_expression",
             "expressionFormat": INLINE_EXPRESSION_FORMAT,
             "expression": expression.to_wire()},
            expression)

    def __and__(self, other: "Member | AxisSelection") -> "AxisSelection":
        return self._combine(other, "intersection")

    def __or__(self, other: "Member | AxisSelection") -> "AxisSelection":
        return self._combine(other, "union")

    def __sub__(self, other: "Member | AxisSelection") -> "AxisSelection":
        other = _axis_selection(other)
        if (other.application != self.application
                or other.dimension_id != self.dimension_id):
            raise ValueError("CROSS_APPLICATION_OR_DIMENSION_SELECTION")
        if self.expression is None or other.expression is None:
            raise ValueError("VERSIONED_MEMBER_LIST_COMPOSITION_UNSUPPORTED")
        expression = self.expression.difference(other.expression)
        return AxisSelection(self.application, self.dimension_id, None,
            {"kind": "inline_expression",
             "expressionFormat": INLINE_EXPRESSION_FORMAT,
             "expression": expression.to_wire()},
            expression)

    def to_dimension_selection(self) -> DimensionSelection:
        if self.cube_selector is None:
            raise MetadataAuthoringError(
                "METADATA_CUBE_SELECTOR_UNAVAILABLE", "selection"
            )
        return DimensionSelection(self.dimension_id, self.cube_selector)


@dataclass(frozen=True, slots=True)
class Attribute:
    dimension: "Dimension"
    descriptor: Mapping
    member: "Member | None" = None

    @property
    def id(self):
        return self.descriptor["attributeId"]

    @property
    def value_type(self):
        if self.descriptor.get("referenceMode") == "symbolic":
            raise MetadataAuthoringError("METADATA_DESCRIPTOR_READ_REQUIRED", "attribute")
        return self.descriptor.get("valueType")

    def __bool__(self) -> bool:
        raise TypeError("Attribute is symbolic; use an explicit predicate")

    def _selection(self, operator: str, value: object) -> AxisSelection:
        expression = MemberListExpression.attribute(self.id, operator, value)
        selected = AxisSelection(self.dimension.application, self.dimension.id,
            None, {"kind": "attribute", "attributeId": self.id,
                   "operator": operator, "value": value}, expression)
        return (selected if self.member is None
                else self.member.selection() & selected)

    def eq(self, value: object) -> AxisSelection:
        return self._selection("eq", value)

    def ne(self, value: object) -> AxisSelection:
        return self._selection("ne", value)

    def isin(self, *values: object) -> AxisSelection:
        if not values:
            raise ValueError("attribute in requires at least one value")
        return self._selection("in", list(values))

    def exists(self, value: bool = True) -> AxisSelection:
        if type(value) is not bool:
            raise TypeError("exists requires a boolean")
        return self._selection("exists", value)


@dataclass(frozen=True, slots=True)
class Dimension:
    application: tuple[str, str, int]
    descriptor: Mapping

    @property
    def id(self):
        return self.descriptor["dimensionId"]

    def _reference(self, kind, name, field="id"):
        return MetadataReference(self.application, kind, self.id, name, field)

    def member(self, name: str) -> Member:
        if self.descriptor.get("referenceMode") == "symbolic":
            return Member(self, {"referenceMode": "symbolic",
                                 "memberId": self._reference("member", name)})
        return Member(self, _lookup(self.descriptor["members"], name, "memberId"))

    def attribute(self, name: str) -> Attribute:
        if self.descriptor.get("referenceMode") == "symbolic":
            return Attribute(self, {"referenceMode": "symbolic",
                "attributeId": self._reference("attribute", name)})
        return Attribute(self, _lookup(
            self.descriptor.get("attributes", ()), name, "attributeId"))

    def member_list(self, name: str, *,
                    parameters: Mapping[str, object] | None = None
                    ) -> AxisSelection:
        descriptor = ({"listId": self._reference("member_list", name), "status": "Published"}
            if self.descriptor.get("referenceMode") == "symbolic" else
            _lookup(self.descriptor.get("memberLists", ()), name, "listId"))
        if descriptor.get("status") != "Published":
            raise MetadataAuthoringError("METADATA_MEMBER_LIST_UNAVAILABLE","member_list")
        selector = {
            "kind": "member_list",
            "listId": descriptor["listId"],
            "parameters": dict(parameters or {}),
        }
        return AxisSelection(self.application, self.id, None, selector, None)

    def hierarchy(self, name: str) -> Hierarchy:
        if self.descriptor.get("referenceMode") == "symbolic":
            return Hierarchy(self, {"referenceMode": "symbolic",
                "hierarchyId": self._reference("hierarchy", name),
                "stateToken": self._reference("hierarchy", name, "stateToken")})
        rows = self.descriptor.get("hierarchies", ())
        return Hierarchy(self, _lookup(rows, name, "hierarchyId"))

    def _default_hierarchy(self) -> Hierarchy:
        if self.descriptor.get("referenceMode") == "symbolic":
            return self.hierarchy(None)
        identity = self.descriptor.get("defaultHierarchyId")
        if identity is not None:
            return self.hierarchy(identity)
        return Hierarchy(self, {"stateToken": self.descriptor.get("hierarchyStateToken")})

    def descendants(self, name: str | Member, *, include_self: bool = False) -> AxisSelection:
        return self._default_hierarchy().descendants(name, include_self=include_self)

    def children(self, name: str | Member) -> AxisSelection:
        return self._default_hierarchy().children(name)

    def leaves(self, name: str | Member) -> AxisSelection:
        return self._default_hierarchy().leaves(name)

    def ancestors(self, name: str | Member, *, include_self: bool = False
                  ) -> AxisSelection:
        return self._default_hierarchy().ancestors(
            name, include_self=include_self)

    def siblings(self, name: str | Member) -> AxisSelection:
        return self._default_hierarchy().siblings(name)

    def parents(self, name: str | Member) -> AxisSelection:
        return self._default_hierarchy().parents(name)

    def base(self, name: str | Member) -> AxisSelection:
        return self._default_hierarchy().base(name)


@dataclass(frozen=True, slots=True, eq=False)
class Member:
    """Scoped member identity; navigation constructs fixed-core expressions.

    A member is neither a set nor a placement. Converting it to a singleton
    selection is explicit here and normalized at cube/set binding boundaries.
    Attribute predicates do not fetch scalar values from the authoring process.
    """
    dimension: Dimension
    descriptor: Mapping

    def __post_init__(self) -> None:
        if not isinstance(self.dimension, Dimension):
            raise TypeError("Member requires a Dimension")
        if not isinstance(self.descriptor, Mapping):
            raise TypeError("Member requires a member descriptor")
        descriptor = _freeze(_canonical_copy(self.descriptor, label="member descriptor"))
        _identifier(descriptor.get("memberId"), "member_id")
        object.__setattr__(self, "descriptor", descriptor)

    @property
    def id(self) -> str | MetadataReference:
        return self.descriptor["memberId"]

    @property
    def name(self) -> str | None:
        if self.descriptor.get("referenceMode") == "symbolic":
            raise MetadataAuthoringError("METADATA_DESCRIPTOR_READ_REQUIRED", "member")
        return self.descriptor.get("name")

    @property
    def application(self) -> tuple[str, str, int]:
        return self.dimension.application

    @property
    def dimension_id(self) -> str:
        return self.dimension.id

    def __eq__(self, other):
        if isinstance(self.id, MetadataReference) or (isinstance(other, Member)
                and isinstance(other.id, MetadataReference)):
            raise TypeError("Member identity is unresolved; comparison requires an explicit metadata read")
        if not isinstance(other, Member):
            return NotImplemented
        return (self.application, self.dimension_id, self.id) == (other.application, other.dimension_id, other.id)

    def __hash__(self):
        if isinstance(self.id, MetadataReference):
            raise TypeError("Member identity is unresolved; hashing requires an explicit metadata read")
        return hash((self.application, self.dimension_id, self.id))

    def __bool__(self) -> bool:
        raise TypeError("Member is symbolic; query metadata explicitly")

    def selection(self) -> AxisSelection:
        return AxisSelection(self.application, self.dimension_id,
            {"kind": "Members", "memberIds": [self.id]},
            {"kind": "member", "memberId": self.id},
            MemberListExpression.explicit(self.id))

    def to_dimension_selection(self) -> DimensionSelection:
        return self.selection().to_dimension_selection()

    def __and__(self, other: Member | AxisSelection) -> AxisSelection:
        return self.selection() & other

    def __or__(self, other: Member | AxisSelection) -> AxisSelection:
        return self.selection() | other

    def __sub__(self, other: Member | AxisSelection) -> AxisSelection:
        return self.selection() - other

    def attribute(self, name: str) -> Attribute:
        attribute = self.dimension.attribute(name)
        return Attribute(self.dimension, attribute.descriptor, self)

    def _hierarchy(self, hierarchy: str | Hierarchy | None) -> Hierarchy:
        selected = (self.dimension._default_hierarchy() if hierarchy is None
                    else self.dimension.hierarchy(hierarchy)
                    if isinstance(hierarchy, str) else hierarchy)
        if not isinstance(selected, Hierarchy):
            raise TypeError("hierarchy must be a name or Hierarchy")
        if (selected.dimension.application != self.application
                or selected.dimension.id != self.dimension_id):
            raise ValueError("CROSS_APPLICATION_OR_DIMENSION_SELECTION")
        return selected

    def children(self, *, hierarchy: str | Hierarchy | None = None) -> AxisSelection:
        return self._hierarchy(hierarchy).children(self)

    def parents(self, *, hierarchy: str | Hierarchy | None = None) -> AxisSelection:
        return self._hierarchy(hierarchy).parents(self)

    def descendants(self, *, hierarchy: str | Hierarchy | None = None,
                    include_self: bool = False) -> AxisSelection:
        return self._hierarchy(hierarchy).descendants(self, include_self=include_self)

    def ancestors(self, *, hierarchy: str | Hierarchy | None = None,
                  include_self: bool = False) -> AxisSelection:
        return self._hierarchy(hierarchy).ancestors(self, include_self=include_self)

    def siblings(self, *, hierarchy: str | Hierarchy | None = None) -> AxisSelection:
        return self._hierarchy(hierarchy).siblings(self)

    def leaves(self, *, hierarchy: str | Hierarchy | None = None) -> AxisSelection:
        return self._hierarchy(hierarchy).leaves(self)

    def base(self, *, hierarchy: str | Hierarchy | None = None) -> AxisSelection:
        """Select this member only if it is included and leaf in the hierarchy."""
        return self._hierarchy(hierarchy).base(self)


def _axis_selection(value: Member | AxisSelection) -> AxisSelection:
    """One normalization boundary; member identity never becomes another AST."""
    if isinstance(value, Member):
        return value.selection()
    if not isinstance(value, AxisSelection):
        raise TypeError("member-set operands require Member or AxisSelection")
    return value


@dataclass(frozen=True, slots=True)
class Hierarchy:
    dimension: Dimension
    descriptor: Mapping

    @property
    def id(self):
        return self.descriptor.get("hierarchyId")

    @property
    def state_token(self) -> str | MetadataReference:
        token = self.descriptor.get("stateToken")
        if (not token_reference(token, "hierarchy", "stateToken") and
                (not isinstance(token, str) or re.fullmatch(r"[0-9a-f]{64}", token) is None)):
            raise MetadataAuthoringError("METADATA_HIERARCHY_UNAVAILABLE", "hierarchy")
        return token

    def _member(self, value: str | Member) -> Member:
        member = self.dimension.member(value) if isinstance(value, str) else value
        if not isinstance(member, Member):
            raise TypeError("hierarchy navigation requires a member name or Member")
        if (member.application != self.dimension.application
                or member.dimension_id != self.dimension.id):
            raise ValueError("CROSS_APPLICATION_OR_DIMENSION_SELECTION")
        return member

    def relationship(self, relationship_id: str, *, parent: str | Member,
                     child: str | Member) -> Relationship:
        """Construct a scoped reference; the core still verifies graph membership."""
        return Relationship(self, relationship_id, self._member(parent),
                            self._member(child))

    def placement(self, root: str | Member,
                  *path: Relationship) -> Placement:
        """Retain every ordered edge from the declared root to this occurrence."""
        return Placement(self, self._member(root), tuple(path))

    def _selection(self, kind, name, include_self=False):
        if type(include_self) is not bool:
            raise ValueError("include_self must be boolean")
        member = self._member(name)
        self.state_token  # Reject unavailable graph pins before constructing IR.
        member_id = member.id
        lower_kind = kind.lower()
        expression = (
            MemberListExpression.hierarchy(
                lower_kind, self.id, member_id, include_self=include_self
            )
            if self.id is not None
            else None
        )
        transform = ({"kind": kind, "rootMemberId": member_id,
             "includeSelf": include_self,
             **({"hierarchyId": self.id} if self.id is not None else {})}
             if kind in {"Children","Descendants","Leaves"} else None)
        cube_selector = (
            {
                "kind": "hierarchy",
                "operator": lower_kind,
                "hierarchyId": self.id,
                "memberId": member_id,
                "includeSelf": include_self,
            }
            if self.id is not None
            else None
        )
        return AxisSelection(self.dimension.application, self.dimension.id,
            transform, cube_selector, expression)

    def descendants(self, name: str | Member, *, include_self: bool = False) -> AxisSelection:
        return self._selection("Descendants", name, include_self)

    def children(self, name: str | Member) -> AxisSelection:
        return self._selection("Children", name)

    def leaves(self, name: str | Member) -> AxisSelection:
        return self._selection("Leaves", name)

    def ancestors(self, name: str | Member, *, include_self: bool = False
                  ) -> AxisSelection:
        return self._selection("Ancestors", name, include_self)

    def siblings(self, name: str | Member) -> AxisSelection:
        return self._selection("Siblings", name)

    def parents(self, name: str | Member) -> AxisSelection:
        return self._selection("Parents", name)

    def base(self, name: str | Member) -> AxisSelection:
        return self._selection("Base", name)


@dataclass(frozen=True, slots=True)
class Relationship:
    """A scoped immediate edge, never a substitute for a full placement path.

    Endpoints and token are proposed references, not evidence of authorization
    or graph membership. Only the fixed core validates them against current state.
    """
    hierarchy: Hierarchy
    id: str
    parent: Member
    child: Member

    def __post_init__(self) -> None:
        if not isinstance(self.hierarchy, Hierarchy) or self.hierarchy.id is None:
            raise ValueError("RELATIONSHIP_REQUIRES_NAMED_HIERARCHY")
        self.hierarchy.state_token
        _identifier(self.id, "relationship_id")
        if not isinstance(self.parent, Member) or not isinstance(self.child, Member):
            raise TypeError("relationship endpoints require Member references")
        self.hierarchy._member(self.parent)
        self.hierarchy._member(self.child)
        if reference_identity_key(self.parent.id) == reference_identity_key(self.child.id):
            raise ValueError("RELATIONSHIP_SELF_EDGE")

    def to_reference(self) -> dict:
        application = self.hierarchy.dimension.application
        return _thaw({"workspaceId": application[0], "applicationId": application[1],
                "metadataRevision": application[2],
                "dimensionId": self.hierarchy.dimension.id,
                "hierarchyId": self.hierarchy.id,
                "hierarchyStateToken": self.hierarchy.state_token,
                "relationshipId": self.id, "parentMemberId": self.parent.id,
                "childMemberId": self.child.id})


@dataclass(frozen=True, slots=True)
class Placement:
    """One full ordered path occurrence, bound to a current named hierarchy.

    Local checks reject disconnected/cyclic paths. They do not prove that the
    declared root is a graph root or that an edge exists; core resolution does.
    This object is not implicitly coerced to a member set or aggregate input.
    """
    hierarchy: Hierarchy
    root: Member
    path: tuple[Relationship, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.hierarchy, Hierarchy) or self.hierarchy.id is None:
            raise ValueError("PLACEMENT_REQUIRES_NAMED_HIERARCHY")
        self.hierarchy.state_token
        if not isinstance(self.root, Member):
            raise TypeError("placement root requires a Member reference")
        self.hierarchy._member(self.root)
        if not isinstance(self.path, tuple) or len(self.path) > 32:
            raise ValueError("PLACEMENT_PATH_INVALID")
        prior = self.root.id
        seen = {reference_identity_key(prior)}
        edges = set()
        for edge in self.path:
            if not isinstance(edge, Relationship):
                raise TypeError("placement path requires Relationship references")
            if (edge.hierarchy.dimension.application != self.hierarchy.dimension.application
                    or edge.hierarchy.dimension.id != self.hierarchy.dimension.id
                    or reference_identity_key(edge.hierarchy.id) != reference_identity_key(self.hierarchy.id)
                    or reference_identity_key(edge.hierarchy.state_token) != reference_identity_key(self.hierarchy.state_token)):
                raise ValueError("PLACEMENT_HIERARCHY_MISMATCH")
            if reference_identity_key(edge.parent.id) != reference_identity_key(prior):
                raise ValueError("PLACEMENT_PATH_DISCONNECTED")
            if edge.id in edges or reference_identity_key(edge.child.id) in seen:
                raise ValueError("PLACEMENT_PATH_CYCLE")
            edges.add(edge.id)
            seen.add(reference_identity_key(edge.child.id))
            prior = edge.child.id

    @property
    def member(self) -> Member:
        return self.root if not self.path else self.path[-1].child

    @property
    def parent(self) -> Placement | None:
        return None if not self.path else Placement(self.hierarchy, self.root, self.path[:-1])

    @property
    def path_relationship_ids(self) -> tuple[str, ...]:
        return tuple(edge.id for edge in self.path)

    def to_reference(self) -> dict:
        application = self.hierarchy.dimension.application
        return _thaw({"workspaceId": application[0], "applicationId": application[1],
                "metadataRevision": application[2],
                "dimensionId": self.hierarchy.dimension.id,
                "hierarchyId": self.hierarchy.id,
                "hierarchyStateToken": self.hierarchy.state_token,
                "rootMemberId": self.root.id, "memberId": self.member.id,
                "pathRelationshipIds": list(self.path_relationship_ids)})


@dataclass(frozen=True, slots=True)
class SelectedFacts:
    application: tuple[str, str, int]
    grain: tuple[str, ...]
    axes: tuple[AxisSelection, ...]

    @property
    def value(self) -> NumericSequenceExpression:
        return NumericSequenceExpression.current_amount()

    def set(self, expression: NumericSequenceExpression, *, name="transform") -> Program:
        """Return one server-resolved effect over existing selected numeric facts."""
        if not isinstance(expression, NumericSequenceExpression):
            raise TypeError("set requires an exact numeric expression")
        if any(axis.selector is None for axis in self.axes):
            raise ValueError("NUMERIC_TRANSFORM_SELECTOR_UNSUPPORTED")
        return Program.one("facts.numeric.transform", {
            "selection": {"grain": {"mode": "full_coordinate",
                "dimensions": list(self.grain)},
                "selectors": {axis.dimension_id: _thaw(axis.selector)
                              for axis in self.axes}},
            "expression": _thaw(expression.node),
            "expectedMetadataRevision": self.application[2],
            "rounding": "half_even_8"}, name=name)


@dataclass(frozen=True, slots=True)
class PartialPointOfView:
    application: tuple[str, str, int]
    axes: tuple[AxisSelection, ...]

    def __post_init__(self) -> None:
        ids = [axis.dimension_id for axis in self.axes]
        if (any(axis.application != self.application for axis in self.axes)
                or len(ids) != len(set(ids))):
            raise ValueError("POV_AXES_INVALID")
        if any(axis.expression is None
               or axis.expression.node.get("kind") != "explicit"
               or len(axis.expression.node.get("memberIds", ())) != 1
               for axis in self.axes):
            raise ValueError("POV_REQUIRES_FIXED_MEMBERS")


@dataclass(frozen=True, slots=True)
class RelativeSource:
    scope: "CalculationScope"
    overrides: tuple[AxisSelection, ...]

    @property
    def value(self) -> CubeExpression:
        values = {
            axis.dimension_id: axis.expression.node["memberIds"][0]
            for axis in self.overrides
        }
        return CubeExpression.source_value(values)


@dataclass(frozen=True, slots=True)
class CalculationScope:
    application: tuple[str, str, int]
    cube: "Cube"
    axes: tuple[AxisSelection, ...]

    @property
    def value(self) -> CubeExpression:
        return CubeExpression.source_amount()

    def at(self, **bindings: Member | AxisSelection) -> RelativeSource:
        axes = self.cube._axes(bindings)
        return RelativeSource(self, axes)

    def calculate(
        self,
        *,
        definition_id: str,
        name: str,
        target: Mapping[str, Member | AxisSelection],
        expression: CubeExpression,
        evaluation: str,
        result_key: str | None,
        result_unit: str,
        missing: str = "error",
    ):
        from .calculated_members import CalculatedMember
        if missing != "error":
            raise ValueError("only explicit missing='error' is currently supported")
        if not isinstance(expression, CubeExpression):
            raise TypeError("expression must be CubeExpression")
        target_axes = self.cube._axes(target)
        if len(target_axes) != 1:
            raise ValueError("CALCULATION_TARGET_REQUIRES_ONE_MEMBER")
        target_axis = target_axes[0]
        if (target_axis.expression is None
                or target_axis.expression.node.get("kind") != "explicit"
                or len(target_axis.expression.node.get("memberIds", ())) != 1):
            raise ValueError("CALCULATION_TARGET_REQUIRES_ONE_MEMBER")
        selection = CubeSelection(self.application[2], tuple(
            axis.to_dimension_selection() for axis in self.axes))
        return CalculatedMember(
            definition_id, name, target_axis.dimension_id,
            target_axis.expression.node["memberIds"][0], evaluation,
            selection, expression, result_unit, result_key=result_key,
        )


@dataclass(frozen=True, slots=True)
class Cube:
    application: tuple[str, str, int]
    dimensions: tuple[str, ...]
    descriptors: tuple[Mapping, ...] = ()

    def _dimension(self, name: str) -> Dimension:
        return Dimension(self.application, _lookup(self.descriptors, name, "dimensionId"))

    def _axes(self, bindings: Mapping[str, Member | AxisSelection]) -> tuple[AxisSelection, ...]:
        if not isinstance(bindings, Mapping):
            raise TypeError("axis bindings must be a mapping")
        axes = []
        for dimension_name, selected in bindings.items():
            dimension = self._dimension(dimension_name)
            selected = _axis_selection(selected)
            if (selected.application != self.application
                    or selected.dimension_id != dimension.id):
                raise ValueError("AXIS_BINDING_DIMENSION_INVALID")
            axes.append(selected)
        ids = [axis.dimension_id for axis in axes]
        if len(ids) != len(set(ids)):
            raise ValueError("AXIS_BINDING_DUPLICATE")
        return tuple(sorted(axes, key=lambda axis: axis.dimension_id))

    def pov(self, bindings: Mapping[str, str | Member | AxisSelection]) -> PartialPointOfView:
        if not isinstance(bindings, Mapping):
            raise TypeError("pov requires a mapping")
        resolved = {}
        for dimension_name, value in bindings.items():
            dimension = self._dimension(dimension_name)
            selected = dimension.member(value) if isinstance(value, str) else _axis_selection(value)
            resolved[dimension_name] = selected
        return PartialPointOfView(self.application, self._axes(resolved))

    def scope(self, *, pov: PartialPointOfView | None = None,
              **bindings: Member | AxisSelection) -> CalculationScope:
        explicit = self._axes(bindings)
        if pov is not None and (not isinstance(pov, PartialPointOfView)
                                or pov.application != self.application):
            raise ValueError("POV_APPLICATION_INVALID")
        combined = explicit + (() if pov is None else pov.axes)
        ids = [axis.dimension_id for axis in combined]
        if len(ids) != len(set(ids)):
            raise ValueError("SCOPE_AXIS_DUPLICATE")
        if set(ids) != set(self.dimensions):
            raise ValueError("SCOPE_GRAIN_INCOMPLETE")
        return CalculationScope(self.application, self,
            tuple(sorted(combined, key=lambda axis: axis.dimension_id)))

    def select(self, *axes: Member | AxisSelection) -> SelectedFacts:
        if not axes:
            raise TypeError("select requires dimension selections")
        axes = tuple(_axis_selection(axis) for axis in axes)
        if any(axis.application != self.application for axis in axes):
            raise ValueError("CROSS_APPLICATION_SELECTION")
        ids = [axis.dimension_id for axis in axes]
        if len(ids) != len(set(ids)) or not set(ids) <= set(self.dimensions):
            raise ValueError("SELECTION_DIMENSIONS_INVALID")
        return SelectedFacts(self.application, self.dimensions, tuple(axes))


@dataclass(frozen=True, slots=True)
class AuthoringApplication:
    context: object

    @property
    def _snapshot(self):
        snapshot = self.context.references.get("metadata")
        if (not isinstance(snapshot, Mapping)
                or snapshot.get("workspaceId") != self.context.application.workspace_id
                or snapshot.get("applicationId") != self.context.application.application_id
                or snapshot.get("metadataRevision") != self.context.metadata_revision):
            raise MetadataAuthoringError("AUTHORING_METADATA_CONTEXT_UNAVAILABLE", "context")
        if (snapshot.get("referenceMode") == "symbolic" and
                (snapshot.get("contract") != BOOTSTRAP_CONTRACT
                 or snapshot.get("contractDigest") != BOOTSTRAP_CONTRACT_DIGEST)):
            raise MetadataAuthoringError("AUTHORING_CONTEXT_CONTRACT_UNSUPPORTED", "context")
        return snapshot

    @property
    def _identity(self):
        return (self.context.application.workspace_id,
                self.context.application.application_id, self.context.metadata_revision)

    def dimension(self, name: str) -> Dimension:
        return Dimension(self._identity,
            _lookup(self._snapshot["dimensions"], name, "dimensionId"))

    def applicability_relation(self, name: str) -> ApplicabilityRelation:
        if self._snapshot.get("referenceMode") == "symbolic":
            return ApplicabilityRelation(self._identity, {
                "referenceMode": "symbolic", **{key: MetadataReference(
                    self._identity, "applicability_relation", None, name, field)
                    for key, field in (("relationId", "id"), ("stateToken", "stateToken"),
                                       ("definitionDigest", "definitionDigest"))}})
        descriptor = _lookup(self._snapshot.get("applicabilityRelations", ()),
                             name, "relationId")
        if descriptor.get("status") != "Active":
            raise MetadataAuthoringError(
                "METADATA_APPLICABILITY_RELATION_UNAVAILABLE",
                "applicability_relation")
        return ApplicabilityRelation(self._identity, descriptor)

    @property
    def cube(self) -> Cube:
        if self._snapshot.get("cubeGrainAvailable") is False:
            raise MetadataAuthoringError("METADATA_CUBE_GRAIN_UNAVAILABLE", "cube")
        descriptors = tuple(self._snapshot["dimensions"])
        return Cube(self._identity, tuple(sorted(
            row["dimensionId"] for row in descriptors)), descriptors)
