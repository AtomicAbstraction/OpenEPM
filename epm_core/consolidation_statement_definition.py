"""Strict, policy-neutral current statement-definition and coverage contract.

An application owner declares the complete structural source slots and exact
equations for one current definition. Runtime source identities remain pinned
separately.  This contract proves coverage of the declared definition only; it
does not infer accounting policy or professional whole-statement certification.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Mapping

from .consolidation_statement_pack import KINDS, MAX_EQUATIONS, compile_pack
from .persistence_contract import Coordinate


_ID = re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
_NAME = re.compile(r"[A-Za-z0-9._:-]{1,200}\Z")
_MAX_SLOTS = 64
_MAX_EQUATIONS = MAX_EQUATIONS
_MAX_TERMS = 128
PACK_FUNCTION = "consolidation.statement.pack.preview"


def _identifier(value: object, *, short: bool = False) -> str:
    pattern = _NAME if short else _ID
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError("STATEMENT_DEFINITION_IDENTIFIER_INVALID")
    return value


@dataclass(frozen=True)
class StatementSourceSlot:
    slot_id: str
    source_kind: str
    role: str
    required_member_dimensions: tuple[str, ...]

    @classmethod
    def parse(cls, value: object) -> "StatementSourceSlot":
        if (not isinstance(value, dict) or set(value) != {
                "slotId", "sourceKind", "role",
                "requiredMemberDimensions"}
                or value.get("sourceKind") not in KINDS
                or not isinstance(value.get("requiredMemberDimensions"), list)
                or not 1 <= len(value["requiredMemberDimensions"]) <= 64):
            raise ValueError("STATEMENT_DEFINITION_SLOT_INVALID")
        try:
            dimensions = tuple(sorted(_identifier(item, short=True)
                                      for item in
                                      value["requiredMemberDimensions"]))
            slot = cls(_identifier(value["slotId"]), value["sourceKind"],
                       _identifier(value["role"], short=True), dimensions)
        except ValueError as error:
            raise ValueError("STATEMENT_DEFINITION_SLOT_INVALID") from error
        if len(set(dimensions)) != len(dimensions):
            raise ValueError("STATEMENT_DEFINITION_SLOT_INVALID")
        return slot

    def normalized(self) -> dict:
        return {"slotId": self.slot_id, "sourceKind": self.source_kind,
                "role": self.role,
                "requiredMemberDimensions":
                    list(self.required_member_dimensions)}


@dataclass(frozen=True)
class StatementDefinitionTerm:
    slot_id: str
    section_id: str
    sign: int

    @classmethod
    def parse(cls, value: object) -> "StatementDefinitionTerm":
        if (not isinstance(value, dict)
                or set(value) != {"slotId", "sectionId", "sign"}
                or type(value.get("sign")) is not int
                or value["sign"] not in (-1, 1)):
            raise ValueError("STATEMENT_DEFINITION_TERM_INVALID")
        try:
            return cls(_identifier(value["slotId"]),
                       _identifier(value["sectionId"]), value["sign"])
        except ValueError as error:
            raise ValueError("STATEMENT_DEFINITION_TERM_INVALID") from error

    def normalized(self) -> dict:
        return {"slotId": self.slot_id, "sectionId": self.section_id,
                "sign": self.sign}


@dataclass(frozen=True)
class StatementDefinitionEquation:
    equation_id: str
    terms: tuple[StatementDefinitionTerm, ...]

    @classmethod
    def parse(cls, value: object) -> "StatementDefinitionEquation":
        if (not isinstance(value, dict)
                or set(value) != {"equationId", "terms"}
                or not isinstance(value.get("terms"), list)
                or not 2 <= len(value["terms"]) <= _MAX_TERMS):
            raise ValueError("STATEMENT_DEFINITION_EQUATION_INVALID")
        try:
            equation_id = _identifier(value["equationId"])
            terms = tuple(sorted((StatementDefinitionTerm.parse(term)
                                  for term in value["terms"]),
                                 key=lambda term: term.slot_id))
        except ValueError as error:
            raise ValueError("STATEMENT_DEFINITION_EQUATION_INVALID") from error
        if len({term.slot_id for term in terms}) != len(terms):
            raise ValueError("STATEMENT_DEFINITION_EQUATION_INVALID")
        return cls(equation_id, terms)

    def normalized(self) -> dict:
        return {"equationId": self.equation_id,
                "terms": [term.normalized() for term in self.terms]}


@dataclass(frozen=True)
class StatementDefinition:
    definition_id: str
    source_slots: tuple[StatementSourceSlot, ...]
    equations: tuple[StatementDefinitionEquation, ...]

    @classmethod
    def parse(cls, value: object) -> "StatementDefinition":
        if (not isinstance(value, dict) or set(value) != {
                "definitionId", "sourceSlots", "equations"}
                or not isinstance(value.get("sourceSlots"), list)
                or not 2 <= len(value["sourceSlots"]) <= _MAX_SLOTS
                or not isinstance(value.get("equations"), list)
                or not 2 <= len(value["equations"]) <= _MAX_EQUATIONS):
            raise ValueError("STATEMENT_DEFINITION_INVALID")
        try:
            definition_id = _identifier(value["definitionId"])
            slots = tuple(sorted((StatementSourceSlot.parse(slot)
                                  for slot in value["sourceSlots"]),
                                 key=lambda slot: slot.slot_id))
            equations = tuple(sorted((StatementDefinitionEquation.parse(item)
                                      for item in value["equations"]),
                                     key=lambda item: item.equation_id))
        except ValueError as error:
            raise ValueError("STATEMENT_DEFINITION_INVALID") from error
        slot_ids = {slot.slot_id for slot in slots}
        used = {term.slot_id for equation in equations
                for term in equation.terms}
        if (len(slot_ids) != len(slots)
                or len({slot.role for slot in slots}) != len(slots)
                or len({item.equation_id for item in equations}) !=
                    len(equations)
                or used != slot_ids):
            raise ValueError("STATEMENT_DEFINITION_COVERAGE_INVALID")
        return cls(definition_id, slots, equations)

    def normalized(self) -> dict:
        return {"definitionId": self.definition_id,
                "sourceSlots": [slot.normalized()
                                for slot in self.source_slots],
                "equations": [item.normalized()
                              for item in self.equations]}

    @property
    def digest(self) -> str:
        raw = json.dumps(self.normalized(), sort_keys=True,
                         separators=(",", ":"), ensure_ascii=True,
                         allow_nan=False).encode("ascii")
        return sha256(raw).hexdigest()


def materialize_declared_coverage(definition: StatementDefinition,
                                  bindings: object, *, pack_id: object,
                                  fixed_members: object,
                                  currency_dimension_id: object,
                                  currency_member_id: object,
                                  pins: Mapping[str, object]) -> dict:
    """Bind every declared slot and build a strict ordinary pack program."""
    if (not isinstance(definition, StatementDefinition)
            or not isinstance(bindings, list)
            or not isinstance(pins, Mapping)
            or set(pins) != {"expectedMetadataRevision",
                             "expectedDataRevision",
                             "expectedPolicyRevision",
                             "expectedCommitRevision"}
            or any(type(value) is not int or value < 0
                   for value in pins.values())):
        raise ValueError("STATEMENT_DEFINITION_BINDING_INVALID")
    try:
        pack_identity = _identifier(pack_id)
        unit_dimension = _identifier(currency_dimension_id, short=True)
        unit_member = _identifier(currency_member_id, short=True)
        fixed = dict(Coordinate.from_mapping(fixed_members).members)
    except (TypeError, ValueError) as error:
        raise ValueError("STATEMENT_DEFINITION_BINDING_INVALID") from error
    slots = {slot.slot_id: slot for slot in definition.source_slots}
    by_slot = {}
    for binding in bindings:
        if (not isinstance(binding, dict)
                or set(binding) != {"slotId", "source"}
                or binding.get("slotId") not in slots
                or binding["slotId"] in by_slot
                or not isinstance(binding.get("source"), dict)):
            raise ValueError("STATEMENT_DEFINITION_BINDING_INVALID")
        slot = slots[binding["slotId"]]
        source = binding["source"]
        if (source.get("sourceKind") != slot.source_kind
                or "sourceId" in source
                or not isinstance(source.get("members"), dict)
                or set(source["members"]) !=
                    set(slot.required_member_dimensions)):
            raise ValueError("STATEMENT_DEFINITION_BINDING_INVALID")
        by_slot[slot.slot_id] = {**source, "sourceId": slot.slot_id}
    if set(by_slot) != set(slots):
        raise ValueError("STATEMENT_DEFINITION_COVERAGE_INCOMPLETE")
    equations = [{"equationId": equation.equation_id,
      "fixedMembers": fixed, "currencyDimensionId": unit_dimension,
      "currencyMemberId": unit_member,
      "terms": [{"sourceId": term.slot_id,
                 "sectionId": term.section_id, "sign": term.sign}
                for term in equation.terms]}
      for equation in definition.equations]
    raw = {"languageVersion": 2, "function": PACK_FUNCTION,
           "arguments": {"packId": pack_identity,
             "sources": [by_slot[slot.slot_id]
                         for slot in definition.source_slots],
             "equations": equations, **dict(pins)}}
    compiled = compile_pack(raw, PACK_FUNCTION)
    return {"definitionId": definition.definition_id,
            "definitionDigest": definition.digest,
            "declaredCoverageComplete": True,
            "slotRoles": {slot.slot_id: slot.role
                          for slot in definition.source_slots},
            "packProgram": raw, "compiledPack": compiled}
