"""Current-policy redaction for calculated-result provenance."""
from __future__ import annotations

from .persistence_contract import ApplicationScope, Coordinate
from .postgres_access import AccessDecision, VerifiedIdentity
from .dimensional_security_policy import AccessKind
from .postgres_dimensional_security import PostgresDimensionalSecurityResolver


_ROW_LINEAGE_KEYS = (
    "sourceAmount", "sourceChangeId", "sourcePresent", "sourceMembers",
    "sourceLookupLineage", "source_amount", "source_change_id",
    "source_present", "basis", "rollupSources", "groupSources",
    "countPresent", "sourceEvidenceDigest", "rateLineage",
)


def _lineage_coordinates(value: object) -> set[Coordinate]:
    found: set[Coordinate] = set()
    if isinstance(value, dict):
        for key in ("sourceMembers", "weightMembers", "members",
                    "sourceCoordinate", "coordinate"):
            members=value.get(key)
            if type(members) is dict and members:
                found.add(Coordinate.from_mapping(members))
        for item in value.values():
            found.update(_lineage_coordinates(item))
    elif isinstance(value, list):
        for item in value:
            found.update(_lineage_coordinates(item))
    return found


def _producer_source_coordinates(db, scope, producer):
    """Recover retained single-output input grain, never a partial selector.

    These native publishers store their source proof in the immutable receipt
    instead of row lookup lineage. Entity/Period IDs have exactly the same
    meaning as in their native publication security owners; current model-role
    ambiguity withholds explanation without changing the authorized output.
    None means that a recognized producer's source proof is incomplete.
    """
    if producer is None:
        return set()
    function=producer.get("function_name")
    if function not in (
            "consolidation.full.contribute", "consolidation.full.typed.contribute",
            "currency.translation.publish", "currency.calculation.translation.publish",
            "consolidation.full.aggregate", "consolidation.full.translated.aggregate"):
        return set()
    program=producer.get("normalized_program")
    receipt=producer.get("job_result")
    if type(program) is not dict or type(receipt) is not dict:
        return None
    aggregate=function in ("consolidation.full.aggregate",
                           "consolidation.full.translated.aggregate")
    key="parentMembers" if aggregate else "sourceMembers"
    base=receipt.get(key)
    if type(base) is not dict or not base or program.get(key) != base:
        return None
    coordinates={Coordinate.from_mapping(base)}
    if function in ("consolidation.full.contribute", "consolidation.full.typed.contribute"):
        return coordinates
    axis=None
    if function!="currency.translation.publish":
        # Receipts below retain IDs, not their historical role-axis mapping.
        # Current roles prove that mapping only at the same metadata revision.
        if (type(producer.get("source_metadata_revision")) is not int or
                producer["source_metadata_revision"] != producer.get("current_metadata_revision")):
            return None
        role="Entity" if aggregate else "Period"
        axes=db.execute('''SELECT dimension_id FROM epm.dimension
            WHERE workspace_id=%s AND application_id=%s AND status='Active'
            AND model_role=%s ORDER BY dimension_id''',
            (scope.workspace_id,scope.application_id,role)).fetchall()
        if len(axes)!=1 or axes[0]["dimension_id"] not in base:
            return None
        axis=axes[0]["dimension_id"]
    entries=receipt.get("sources" if aggregate else "periods")
    if type(entries) is not list or not entries or any(type(item) is not dict for item in entries):
        return None
    if aggregate:
        decisions=program.get("decisions")
        if (type(decisions) is not list or any(type(item) is not dict for item in decisions)
                or sorted(item.get("relationshipId","") for item in decisions) !=
                sorted(item.get("relationshipId","") for item in entries
                       if item.get("relationshipId") is not None)):
            return None
    elif function=="currency.calculation.translation.publish":
        pins=program.get("periodPins")
        if (type(pins) is not list or any(type(item) is not dict for item in pins)
                or sorted(item.get("periodId","") for item in pins) !=
                sorted(item.get("periodMemberId","") for item in entries)):
            return None
    else:
        if entries[-1].get("sourceCoordinate") != base:
            return None
        # Raw PVA is the complete fiscal prefix, not only its final period.
        if program.get("method")=="PVA":
            ordinals=[item.get("ordinal") for item in entries]
            if (any(type(value) is not int for value in ordinals) or
                    ordinals!=list(range(1,len(entries)+1))):
                return None
        elif program.get("method")!="VAL" or len(entries)!=1:
            return None
    for entry in entries:
        if aggregate:
            child=entry.get("childEntityId")
            parent_source=(entry.get("parentSource") is True if function==
                "consolidation.full.translated.aggregate" else
                entry.get("relationshipId") is None and child is None)
            if parent_source:
                declared=(program.get("parentTranslation") is not None if function==
                    "consolidation.full.translated.aggregate" else
                    program.get("includeParentSource") is True)
                if not declared:
                    return None
                members=base
            elif type(child) is str and child:
                members={**base,axis:child}
            else:
                return None
        else:
            period=entry.get("periodMemberId")
            if type(period) is not str or not period:
                return None
            if function=="currency.translation.publish":
                members=entry.get("sourceCoordinate")
                if type(members) is not dict or not members or set(members)!=set(base):
                    return None
            else:
                members={**base,axis:period}
            rate=entry.get("rate")
            rate_sources=rate.get("sources") if type(rate) is dict else None
            if type(rate_sources) is not list or any(
                    type(item) is not dict or type(item.get("coordinate")) is not dict
                    or not item["coordinate"] for item in rate_sources):
                return None
        coordinates.add(Coordinate.from_mapping(members))
        # Native period/rate/own-source evidence contains full coordinates.
        # No child ID, period ID, or partial selector is authorized by itself.
        coordinates.update(_lineage_coordinates(entry))
    return coordinates


def _coordinates_read_allowed(db, identity, scope, coordinates, *, expected_access):
    points=tuple(dict(point.members) for point in sorted(
        coordinates,key=lambda point:point.members))
    for offset in range(0,len(points),1000):
        decisions=PostgresDimensionalSecurityResolver.resolve_many_active_in_transaction(
            db,identity,scope,kind=AccessKind.READ,
            coordinates=points[offset:offset+1000], expected_access=expected_access)
        if decisions is not None and any(not item.decision.allowed for item in decisions):
            return False
    return True


def _expression_base_coordinate(program, row):
    """Invert only an unambiguous normalized output overlay.

    A SourceAmount-only publication can have empty operand lineage. Singleton
    selected members and fixed source members recover its driver coordinate;
    a multi-member axis overwritten by a target does not identify which input
    produced that row. Never authorize the visible target as that input.
    """
    source=dict(program.get("sourceMembers",{}))
    selected={item["dimensionId"]:item["memberIds"]
              for item in program.get("sourceMemberSets",())}
    for axis in program.get("targetMembers",{}):
        if axis in source:
            continue
        members=selected.get(axis,())
        if len(members)!=1:
            # Existing explicit RawAmount/Raw base operand evidence also
            # identifies the driver even when the output overlay is many-to-one.
            bases=set()
            for item in row.get("sourceLookupLineage",()):
                if (type(item) is dict and item.get("inputKind") in ("RawAmount","Raw")
                        and item.get("memberOverrides")=={} and type(item.get("sourceMembers")) is dict):
                    base=item["sourceMembers"]
                    if ({**base,**program.get("targetMembers",{})}==row["members"]
                            and all(base.get(key)==value for key,value in source.items())
                            and all(base.get(key) in values for key,values in selected.items())):
                        bases.add(Coordinate.from_mapping(base))
            return next(iter(bases)) if len(bases)==1 else None
        source[axis]=members[0]
    return Coordinate.from_mapping({**row["members"],**source})


def redact_expression_lineage(db, identity: VerifiedIdentity,
                              scope: ApplicationScope, program: dict,
                              rows: list[dict], *,
                              expected_access: AccessDecision | None = None) -> bool:
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
    for row in rows:
        coordinates=_lineage_coordinates(row.get("sourceLookupLineage",[]))
        restricted=False
        if source_domain:
            coordinates.add(Coordinate.from_mapping(row["members"]))
        elif not reduction:
            source=_expression_base_coordinate(program,row)
            if source is None:
                restricted=(PostgresDimensionalSecurityResolver.active_policy_in_transaction(
                    db,identity,scope) is not None)
            else:
                coordinates.add(source)
        elif not coordinates:
            # A grouped result without complete source lineage cannot safely
            # disclose aggregate provenance under an active policy.
            restricted=(PostgresDimensionalSecurityResolver.active_policy_in_transaction(
                db,identity,scope) is not None)
        restricted |= not _coordinates_read_allowed(
            db, identity, scope, coordinates, expected_access=expected_access)
        if not restricted:
            continue
        any_restricted=True
        for key in _ROW_LINEAGE_KEYS:
            row.pop(key,None)
        row["sourceLineageRestricted"]=True
    return any_restricted


def redact_calculation_lineage(db, identity: VerifiedIdentity,
                               scope: ApplicationScope,
                               rows: list[dict], *,
                               producer: dict | None = None,
                               expected_access: AccessDecision | None = None) -> bool:
    """Redact non-expression provenance using its explicit source grain.

    Specialized publishers persist bounded source lineage with full ``members``
    dictionaries.  The authorized calculated output remains visible, but its
    IC, acquisition, journal and contribution provenance is removed whenever
    any explicitly identified source coordinate is currently unreadable.
    Lineage without a coordinate is not treated as authority evidence; its
    surrounding coordinate-bearing record governs it.
    """
    coordinates=_producer_source_coordinates(db,scope,producer)
    source_restricted=(
        PostgresDimensionalSecurityResolver.active_policy_in_transaction(db,identity,scope) is not None
        if coordinates is None else not _coordinates_read_allowed(
            db, identity, scope, coordinates, expected_access=expected_access))
    any_restricted=source_restricted
    for row in rows:
        coordinates=set()
        for key in ("sourceLookupLineage", "basis", "rollupSources", "groupSources",
                    "rateLineage"):
            coordinates.update(_lineage_coordinates(row.get(key,[])))
        if not source_restricted and _coordinates_read_allowed(
                db, identity, scope, coordinates, expected_access=expected_access):
            continue
        any_restricted=True
        for key in _ROW_LINEAGE_KEYS:
            row.pop(key,None)
        row["sourceLineageRestricted"]=True
    return any_restricted


def redact_expression_result_metadata(
        result: dict, *, source_restricted: bool = False,
        db=None, identity: VerifiedIdentity | None = None,
        scope: ApplicationScope | None = None,
        producer: dict | None = None,
        expected_access: AccessDecision | None = None) -> None:
    """Withhold source details independently from authorized output values.

    Specialized contexts can cover sources outside the visible page. Their
    existing coordinate-bearing native records must pass current READ as well;
    row visibility alone is never authority for those result-wide details.
    Partial expression selectors are not treated as full coordinates here.
    """
    source_restricted |= any(row.get("sourceLineageRestricted")
                             for row in result.get("rows",()))
    if db is not None and not source_restricted:
        coordinates=set()
        for key in ("contributionContext", "placementLineage",
                    "translationContext", "calculationTranslationContext",
                    "aggregateContext", "translatedAggregateContext"):
            coordinates.update(_lineage_coordinates(result.get(key,{})))
        # Metadata covers off-page sources independently of row visibility.
        source_restricted=not _coordinates_read_allowed(
            db, identity, scope, coordinates, expected_access=expected_access)
    if (not source_restricted and producer is not None and producer.get("function_name") ==
            "facts.expression.calculate"):
        # An expression's result-wide selectors can name absent sources or
        # sources outside this page. Reuse its owner decoder, and disclose the
        # selector only when its named source members occur in currently
        # authorized full-grain evidence; never authorize a partial selector
        # as though it were a coordinate. Unknown evidence is withheld, not
        # reported as an empty/zero business result.
        from .postgres_expression import decode_expression_program
        try:
            plan=decode_expression_program(producer["normalized_program"])
        except (KeyError,TypeError,ValueError):
            source_restricted=(PostgresDimensionalSecurityResolver.active_policy_in_transaction(
                db,identity,scope) is not None)
        else:
            wanted=set(plan.source_members)
            selections=tuple(plan.source_member_sets or ()) + tuple(plan.source_domain or ())
            if plan.reduce_member_set:
                selections+=((plan.reduce_member_set[0],plan.reduce_member_set[1]),)
            if plan.reduce_member_sets:
                selections+=tuple((axis,members) for axis,members,_target in
                                  plan.reduce_member_sets[0])
            wanted.update((axis,member) for axis,members in selections for member in members)
            permitted=set()
            for row in result.get("rows",()):
                if row.get("sourceLineageRestricted"):
                    continue
                sources=_lineage_coordinates(row.get("sourceLookupLineage",[]))
                if row.get("sourceMembers"):
                    sources.add(Coordinate.from_mapping(row["sourceMembers"]))
                if plan.source_domain:
                    sources.add(Coordinate.from_mapping(row["members"]))
                elif not (plan.reduce_member_set or plan.reduce_member_sets):
                    base=_expression_base_coordinate(producer["normalized_program"],row)
                    if base is not None:
                        sources.add(base)
                permitted.update(pair for source in sources for pair in source.members)
            if not result.get("rows") or not wanted <= permitted:
                source_restricted=(PostgresDimensionalSecurityResolver.active_policy_in_transaction(
                    db,identity,scope) is not None)
    if not source_restricted and not any(row.get("sourceLineageRestricted")
               for row in result.get("rows",())):
        return
    for key in ("sourceLookups", "sourceTextLookups", "outputMapping",
                "rawDriverStatus", "publishedInputStatus",
                "contributionContext", "aggregateContext",
                "periodNciContext", "periodNciSourceStatus",
                "equitySourceStatus", "proportionalSourceStatus",
                "methodTotalSourceStatus",
                "inventoryUnrealizedSourceStatus", "sourceMemberSets",
                "placementContext", "placementPathContext", "placementLineage",
                "rollupSliceContext", "translationContext",
                "calculationTranslationContext", "translatedAggregateContext",
                "typedFullContextStatus", "publishedChildStatus",
                "publishedTranslationStatus", "publishedCalculationTranslationStatus",
                "publishedRatioBasisStatus", "equityContextStatus",
                "proportionalContextStatus", "contextDependencyStatus",
                "contextAssertions", "publishedInputs"):
        result.pop(key,None)
    result["sourceLineageRestricted"]=True
