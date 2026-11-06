"""Current-policy redaction for calculated-result provenance."""
from __future__ import annotations

from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import VerifiedIdentity
from .postgres_dimensional_security_enforcement import coordinate_read_allowed


_ROW_LINEAGE_KEYS = (
    "sourceAmount", "sourceChangeId", "sourcePresent", "sourceMembers",
    "sourceLookupLineage", "source_amount", "source_change_id",
    "source_present", "basis", "rollupSources", "groupSources",
)


def _lineage_coordinates(value: object) -> set[Coordinate]:
    found: set[Coordinate] = set()
    if isinstance(value, dict):
        for key in ("sourceMembers", "weightMembers", "members"):
            members=value.get(key)
            if type(members) is dict and members:
                found.add(Coordinate.from_mapping(members))
        for item in value.values():
            found.update(_lineage_coordinates(item))
    elif isinstance(value, list):
        for item in value:
            found.update(_lineage_coordinates(item))
    return found


def redact_expression_lineage(db, identity: VerifiedIdentity,
                              scope: ApplicationScope, program: dict,
                              rows: list[dict]) -> bool:
    """Remove expression provenance when any contributing source is denied.

    The calculated output amount remains governed by its output coordinate.
    Source amounts, change IDs, member mappings and nested lookup lineage are
    disclosed only when every source coordinate contributing to that row is
    currently readable.
    """
    any_restricted=False
    reduction=bool(program.get("reduceMemberSet") or
                   program.get("reduceMemberSets"))
    source_domain=bool(program.get("sourceDomain"))
    source_members=program.get("sourceMembers",{})
    for row in rows:
        coordinates=_lineage_coordinates(row.get("sourceLookupLineage",[]))
        if source_domain:
            coordinates.add(Coordinate.from_mapping(row["members"]))
        elif not reduction:
            coordinates.add(Coordinate.from_mapping(
                {**row["members"],**source_members}))
        elif not coordinates:
            # A grouped result without complete source lineage cannot safely
            # disclose aggregate provenance under an active policy.
            restricted=True
        else:
            restricted=False
        if not (reduction and not coordinates):
            restricted=any(not coordinate_read_allowed(
                db,identity,scope,coordinate) for coordinate in coordinates)
        if not restricted:
            continue
        any_restricted=True
        for key in _ROW_LINEAGE_KEYS:
            row.pop(key,None)
        row["sourceLineageRestricted"]=True
    return any_restricted


def redact_calculation_lineage(db, identity: VerifiedIdentity,
                               scope: ApplicationScope,
                               rows: list[dict]) -> bool:
    """Redact non-expression provenance using its explicit source grain.

    Specialized publishers persist bounded source lineage with full ``members``
    dictionaries.  The authorized calculated output remains visible, but its
    IC, acquisition, journal and contribution provenance is removed whenever
    any explicitly identified source coordinate is currently unreadable.
    Lineage without a coordinate is not treated as authority evidence; its
    surrounding coordinate-bearing record governs it.
    """
    any_restricted=False
    for row in rows:
        lineage=row.get("sourceLookupLineage",[])
        coordinates=_lineage_coordinates(lineage)
        if not coordinates or not any(not coordinate_read_allowed(
                db,identity,scope,coordinate) for coordinate in coordinates):
            continue
        any_restricted=True
        for key in _ROW_LINEAGE_KEYS:
            row.pop(key,None)
        row["sourceLineageRestricted"]=True
    return any_restricted


def redact_expression_result_metadata(result: dict) -> None:
    """Remove source-oriented top-level metadata after any row restriction."""
    if not any(row.get("sourceLineageRestricted")
               for row in result.get("rows",())):
        return
    for key in ("sourceLookups", "sourceTextLookups", "outputMapping",
                "rawDriverStatus", "publishedInputStatus",
                "contributionContext", "aggregateContext",
                "periodNciContext", "periodNciSourceStatus",
                "equitySourceStatus", "proportionalSourceStatus",
                "methodTotalSourceStatus",
                "inventoryUnrealizedSourceStatus"):
        result.pop(key,None)
    result["sourceLineageRestricted"]=True
