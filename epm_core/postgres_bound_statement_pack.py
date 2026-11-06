"""Definition-bound structural statement-pack preview.

The active immutable definition owns source slots, equations, section names and
signs.  A caller supplies only concrete pinned sources and runtime grain/unit
values.  This proves completeness against that declared definition; it does
not establish accounting correctness or professional whole-statement review.
"""
from __future__ import annotations

import re

from .consolidation_statement_definition import (
    StatementDefinition, materialize_declared_coverage)
from .persistence_contract import Coordinate
from .postgres_jobs import _canonical_digest
from .postgres_statement_definitions import PostgresStatementDefinitions
from .postgres_statement_pack import PostgresStatementPack


FUNCTION = "consolidation.statement.pack.bound.preview"
_ID = re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_PINS = ("expectedMetadataRevision", "expectedDataRevision",
         "expectedPolicyRevision", "expectedCommitRevision")


def compile_request(raw: object) -> dict:
    required = {"packId", "definitionId", "definitionVersion",
                "definitionDigest", "bindings", "fixedMembers",
                "currencyDimensionId", "currencyMemberId", *_PINS}
    if (not isinstance(raw, dict)
            or set(raw) != {"languageVersion", "function", "arguments"}
            or raw.get("languageVersion") != 2
            or raw.get("function") != FUNCTION
            or not isinstance(raw.get("arguments"), dict)
            or set(raw["arguments"]) != required):
        raise ValueError("BOUND_STATEMENT_PACK_PROGRAM_INVALID")
    arguments = raw["arguments"]
    if (not isinstance(arguments["packId"], str)
            or not _ID.fullmatch(arguments["packId"])
            or not isinstance(arguments["definitionId"], str)
            or not _ID.fullmatch(arguments["definitionId"])
            or type(arguments["definitionVersion"]) is not int
            or arguments["definitionVersion"] < 1
            or not isinstance(arguments["definitionDigest"], str)
            or not _DIGEST.fullmatch(arguments["definitionDigest"])
            or not isinstance(arguments["bindings"], list)
            or not 2 <= len(arguments["bindings"]) <= 64
            or any(type(arguments[name]) is not int or arguments[name] < 0
                   for name in _PINS)
            or not isinstance(arguments["currencyDimensionId"], str)
            or not 1 <= len(arguments["currencyDimensionId"]) <= 200
            or not isinstance(arguments["currencyMemberId"], str)
            or not 1 <= len(arguments["currencyMemberId"]) <= 200):
        raise ValueError("BOUND_STATEMENT_PACK_ARGUMENTS_INVALID")
    try:
        fixed = dict(Coordinate.from_mapping(arguments["fixedMembers"]).members)
    except (TypeError, ValueError) as error:
        raise ValueError("BOUND_STATEMENT_PACK_ARGUMENTS_INVALID") from error
    bindings = []
    slots = set()
    for binding in arguments["bindings"]:
        if (not isinstance(binding, dict)
                or set(binding) != {"slotId", "source"}
                or not isinstance(binding.get("slotId"), str)
                or not _ID.fullmatch(binding["slotId"])
                or binding.get("slotId") in slots
                or not isinstance(binding.get("source"), dict)
                or not isinstance(binding["source"].get("members"),dict)):
            raise ValueError("BOUND_STATEMENT_PACK_BINDING_INVALID")
        try:
            Coordinate.from_mapping(binding["source"]["members"])
        except (TypeError,ValueError) as error:
            raise ValueError("BOUND_STATEMENT_PACK_BINDING_INVALID") from error
        slots.add(binding["slotId"])
        bindings.append({"slotId": binding["slotId"],
                         "source": dict(binding["source"])})
    return {"packId": arguments["packId"],
            "definitionId": arguments["definitionId"],
            "definitionVersion": arguments["definitionVersion"],
            "definitionDigest": arguments["definitionDigest"],
            "bindings": bindings, "fixedMembers": fixed,
            "currencyDimensionId": arguments["currencyDimensionId"],
            "currencyMemberId": arguments["currencyMemberId"],
            "pins": {name: arguments[name] for name in _PINS}}


def catalog() -> dict:
    return {FUNCTION: {
      "mode": "read_only", "permission": "read",
      "requiredCapabilities": ["financial_consolidation"],
      "previewRequired": False, "idempotencyRequired": False,
      "workClass": "short", "arguments": {
        "packId": "bounded structural pack identity",
        "definitionId": "exact active immutable definition identity",
        "definitionVersion": "exact active immutable version",
        "definitionDigest": "exact active canonical digest",
        "bindings": "one concrete pinned source for every declared slot",
        "fixedMembers": "runtime fixed statement grain",
        "currencyDimensionId": "configured Currency dimension",
        "currencyMemberId": "explicit same-unit member",
        "expectedMetadataRevision": "current", "expectedDataRevision": "current",
        "expectedPolicyRevision": "current", "expectedCommitRevision": "current"},
      "result": "definition-bound exact structural coverage proof; Unreviewed, no effects and no accounting certification",
      "workflowRoute": {
        "stages": ["consolidation.period.close.request",
                   "consolidation.period.close.read",
                   "consolidation.period.close.reopen"],
        "boundary": "the separate preview-bound close request revalidates this exact active definition, concrete bindings, statement-pack lineage digest and current revision pins, creates the scoped period lock and immutable Unreviewed receipt, and only an explicit reviewed reopen releases that lock"}}}


class PostgresBoundStatementPack:
    def __init__(self, dsn, *, identity):
        self.dsn, self.identity = dsn, identity

    def read(self, scope, raw: object) -> dict:
        request = compile_request(raw)
        active = PostgresStatementDefinitions(
            self.dsn, identity=self.identity).read_active_exact(
                scope, request["definitionId"],
                request["definitionVersion"], request["definitionDigest"],
                function=FUNCTION)
        definition = StatementDefinition.parse(active["definition"])
        coverage = materialize_declared_coverage(
            definition, request["bindings"], pack_id=request["packId"],
            fixed_members=request["fixedMembers"],
            currency_dimension_id=request["currencyDimensionId"],
            currency_member_id=request["currencyMemberId"],
            pins=request["pins"])
        pack = PostgresStatementPack(
            self.dsn, identity=self.identity).read(
                scope, coverage["packProgram"])
        binding = {"definitionId": definition.definition_id,
                   "definitionVersion": definition.version,
                   "definitionDigest": definition.digest,
                   "pointerVersion": active["pointerVersion"],
                   "stateRevision": active["stateRevision"]}
        pack_digest = pack["lineageDigest"]
        return {**pack, "declaredCoverageComplete": True,
                "definitionBinding": binding,
                "slotRoles": coverage["slotRoles"],
                "packLineageDigest": pack_digest,
                "lineageDigest": _canonical_digest({
                    "definitionBinding": binding,
                    "packLineageDigest": pack_digest}),
                "structuralOnly": True,
                "accountingPolicyStatus": "Unreviewed",
                "wholeStatementCertified": False,
                "effects": None}
