"""Private symbolic lookup nodes in untrusted proposed plans, never saved IR.

A reference carries a scope and a lookup; it is not a guessed stable ID or a
materialized metadata value. The fixed core resolves only admitted positions.
"""
from dataclasses import dataclass
from hashlib import sha256
from typing import Mapping

MARKER = "$openepmMetadataReference"
FORMAT = "openepm-authoring-reference-v1"
BOOTSTRAP_CONTRACT = "openepm-authoring-bootstrap-v1"
BOOTSTRAP_CONTRACT_DIGEST = sha256(BOOTSTRAP_CONTRACT.encode("ascii")).hexdigest()
FIELDS = {
    "member": frozenset(("id",)),
    "hierarchy": frozenset(("id", "stateToken")),
    "attribute": frozenset(("id",)),
    "member_list": frozenset(("id",)),
    "applicability_relation": frozenset(("id", "stateToken", "definitionDigest")),
}

@dataclass(frozen=True, slots=True, eq=False)
class MetadataReference:
    application: tuple[str, str, int]
    kind: str
    dimension_id: str | None
    lookup: str | None
    field: str = "id"

    def __post_init__(self):
        if (not isinstance(self.application, tuple) or len(self.application) != 3
                or any(type(value) is not str or not value for value in self.application[:2])
                or type(self.application[2]) is not int or self.application[2] < 1
                or type(self.kind) is not str or self.kind not in FIELDS
                or type(self.field) is not str or self.field not in FIELDS[self.kind]
                or (self.kind == "applicability_relation") != (self.dimension_id is None)
                or (self.dimension_id is not None and (type(self.dimension_id) is not str
                    or not 1 <= len(self.dimension_id) <= 200))
                or (self.lookup is None and self.kind != "hierarchy")
                or (self.lookup is not None and (type(self.lookup) is not str
                    or not 1 <= len(self.lookup) <= 200))):
            raise ValueError("AUTHORING_REFERENCE_INVALID")

    @property
    def structural_key(self):
        return (*self.application, self.kind, self.dimension_id, self.lookup, self.field)

    def _comparison_unavailable(self, other):
        raise TypeError("Metadata reference is unresolved; scalar comparison requires an explicit metadata read")

    __eq__ = __ne__ = __lt__ = __le__ = __gt__ = __ge__ = _comparison_unavailable
    __hash__ = None

    def __bool__(self):
        raise TypeError("Metadata reference is symbolic; query metadata explicitly")

    def __str__(self):
        raise TypeError("Metadata reference is symbolic; query metadata explicitly")

    def to_wire(self):
        return {MARKER: {"format": FORMAT,
            "workspaceId": self.application[0], "applicationId": self.application[1],
            "metadataRevision": self.application[2], "kind": self.kind,
            "dimensionId": self.dimension_id, "lookup": self.lookup, "field": self.field}}

    @classmethod
    def from_wire(cls, value):
        if not isinstance(value, Mapping) or set(value) != {MARKER}:
            raise ValueError("AUTHORING_REFERENCE_INVALID")
        node = value[MARKER]
        if (not isinstance(node, Mapping) or set(node) != {
                "format", "workspaceId", "applicationId", "metadataRevision",
                "kind", "dimensionId", "lookup", "field"}
                or node["format"] != FORMAT):
            raise ValueError("AUTHORING_REFERENCE_INVALID")
        return cls((node["workspaceId"], node["applicationId"], node["metadataRevision"]),
                   node["kind"], node["dimensionId"], node["lookup"], node["field"])


def identifier_reference(value, label):
    kinds = {"member_id": "member", "root_member_id": "member",
        "hierarchy_id": "hierarchy", "attribute_id": "attribute",
        "list_id": "member_list", "relation_id": "applicability_relation"}
    return (isinstance(value, MetadataReference) and value.field == "id"
            and kinds.get(label) == value.kind)


def token_reference(value, kind, field):
    return (isinstance(value, MetadataReference)
            and value.kind == kind and value.field == field)


def reference_identity_key(value):
    """Private construction dedup key, never semantic name-to-ID equality."""
    if isinstance(value, MetadataReference):
        return ("unresolved", value.structural_key)
    return ("resolved", value)
