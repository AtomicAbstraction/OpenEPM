"""Generic sealed-selection adapter over the qualified durable aggregate engine."""

from __future__ import annotations

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .cube_aggregate_lifecycle import AggregateQueryBudgets
from .cube_aggregate_service import CubeAggregateService
from .generic_aggregate_contract import FORMAT, compile_generic_aggregate
from .generic_aggregate_lowering import lower_generic_aggregate
from .generic_placement import (
    combine_placement_lineage, resolve_placement_contributions,
    resolve_sealed_placement_contributions)
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout
from .postgres_sealed_selections import PostgresSealedSelections, READ as SELECTION_READ


REQUEST="cube.aggregate.request"
READ="cube.aggregate.read"
CANCEL="cube.aggregate.cancel"
LINEAGE="cube.aggregate.lineage.read"


def catalog() -> dict:
    common={"permission":"read","previewRequired":False}
    return {
        REQUEST:{**common,"mode":"durable_technical_query",
            "workClass":"medium","idempotencyRequired":False,
            "arguments":{"selectionId":"current sealed selection identity",
                "groupBy":"output dimensions","reduceDimensions":"reduced dimensions",
                "measures":"sum and/or count_present",
                "membershipSemantics":"unique_member or placement",
                "memberOperatorPolicy":"configured","missing":"exclude"},
            "optionalArguments":{"limits":"lower aggregate execution budgets"},
            "result":"durable generic aggregate query identity"},
        READ:{**common,"mode":"read","workClass":"short",
            "idempotencyRequired":False,
            "arguments":{"queryId":"accepted generic aggregate query"},
            "optionalArguments":{"cursor":"signed continuation cursor",
                                 "pageSize":"1-500"},
            "result":"durable status or bounded exact result page"},
        LINEAGE:{**common,"mode":"read","workClass":"short",
            "idempotencyRequired":False,
            "arguments":{"queryId":"accepted placement aggregate query"},
            "result":"immutable exact placement paths and effective operators"},
        CANCEL:{**common,"mode":"technical_control","workClass":"short",
            "idempotencyRequired":False,
            "arguments":{"queryId":"accepted generic aggregate query"},
            "result":"durable cancellation state"},
    }


def _program(raw: object) -> tuple[str,dict]:
    if (not isinstance(raw,dict)
            or set(raw)!={"languageVersion","function","arguments"}
            or raw.get("languageVersion")!=2
            or raw.get("function") not in {REQUEST,READ,CANCEL,LINEAGE}
            or not isinstance(raw.get("arguments"),dict)):
        raise ValueError("GENERIC_AGGREGATE_PROGRAM_INVALID")
    function,args=raw["function"],raw["arguments"]
    if function==REQUEST:
        required={"selectionId","groupBy","reduceDimensions","measures",
                  "membershipSemantics","memberOperatorPolicy","missing"}
        if set(args) not in (required,required|{"limits"}):
            raise ValueError("GENERIC_AGGREGATE_ARGUMENTS_INVALID")
    elif function in {CANCEL,LINEAGE}:
        if set(args)!={"queryId"} or not isinstance(args["queryId"],str):
            raise ValueError("GENERIC_AGGREGATE_ARGUMENTS_INVALID")
    elif (set(args)-{"queryId","cursor","pageSize"} or "queryId" not in args
            or not isinstance(args["queryId"],str)
            or ("cursor" in args and not isinstance(args["cursor"],str))
            or ("pageSize" in args and type(args["pageSize"]) is not int)):
        raise ValueError("GENERIC_AGGREGATE_ARGUMENTS_INVALID")
    return function,args


def _budgets(value: object) -> AggregateQueryBudgets:
    if value is None:
        return AggregateQueryBudgets()
    if not isinstance(value,dict) or set(value)-{
            "maxGroups","maxResultBytes","pageSize","ttlSeconds"}:
        raise ValueError("GENERIC_AGGREGATE_LIMITS_INVALID")
    try:
        return AggregateQueryBudgets(value.get("maxGroups",100000),
            value.get("maxResultBytes",33554432),value.get("pageSize",500),
            value.get("ttlSeconds",900))
    except (TypeError,ValueError) as error:
        raise ValueError("GENERIC_AGGREGATE_LIMITS_INVALID") from error


class PostgresGenericAggregate:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 aggregate_service: CubeAggregateService):
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError("A verified identity is required")
        if not isinstance(aggregate_service,CubeAggregateService):
            raise ValueError("GENERIC_AGGREGATE_SERVICE_INVALID")
        self.dsn,self.identity,self.aggregate_service=(
            dsn,identity,aggregate_service)

    def execute(self,scope:ApplicationScope,raw:dict)->dict:
        function,args=_program(raw)
        if function==LINEAGE:
            return self._read_lineage(scope,args["queryId"])
        if function==READ:
            return self.aggregate_service.read(scope,args["queryId"],
                cursor=args.get("cursor"),page_size=args.get("pageSize"))
        if function==CANCEL:
            return self.aggregate_service.cancel(scope,args["queryId"])
        sealed=PostgresSealedSelections(
            self.dsn,identity=self.identity).execute(scope,{"languageVersion":2,
                "function":SELECTION_READ,
                "arguments":{"selectionId":args["selectionId"]}})
        resolved=sealed["resolvedSelection"]["members"]
        sealed_placements=sealed["resolvedSelection"].get("placements")
        if sum(len(values) for values in resolved.values())>500:
            raise ValueError("GENERIC_AGGREGATE_RESOLUTION_BUDGET")
        intent={"format":FORMAT,"selection":sealed["selection"],
            "groupBy":args["groupBy"],
            "reduceDimensions":args["reduceDimensions"],
            "measures":args["measures"],
            "membershipSemantics":args["membershipSemantics"],
            "memberOperatorPolicy":args["memberOperatorPolicy"],
            "missing":args["missing"]}
        dimensions=sorted(resolved)
        plan=compile_generic_aggregate(intent,active_dimensions=dimensions)
        requested=[{"dimension_id":dimension,"member_id":member}
            for dimension in dimensions for member in resolved[dimension]]
        all_placement_members={}
        placement_relationships={}
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION READ ONLY")
                configure_statement_timeout(db,5000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,"read",function=REQUEST)
                state=db.execute("""SELECT metadata_revision,policy_revision
                    FROM epm.application_state WHERE workspace_id=%s
                    AND application_id=%s""",(scope.workspace_id,
                    scope.application_id)).fetchone()
                if (state is None
                        or state["metadata_revision"]!=sealed["metadataRevision"]
                        or state["policy_revision"]!=sealed["policyRevision"]):
                    raise ValueError("GENERIC_AGGREGATE_SELECTION_STALE")
                rows=db.execute("""SELECT i.dimension_id,i.member_id,
                    m.aggregation_operator FROM jsonb_to_recordset(%s::jsonb)
                    i(dimension_id text,member_id text) LEFT JOIN epm.member m
                    ON m.workspace_id=%s AND m.application_id=%s
                    AND m.dimension_id=i.dimension_id AND m.member_id=i.member_id
                    AND m.status='Active' ORDER BY i.dimension_id,i.member_id""",
                    (Jsonb(requested),scope.workspace_id,
                     scope.application_id)).fetchall()
                if plan.normalized["membershipSemantics"]=="placement":
                    reduced=plan.normalized["reduceDimensions"]
                    member_rows=db.execute("""SELECT dimension_id,member_id,
                        aggregation_operator FROM epm.member
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=ANY(%s::text[]) AND status='Active'
                        ORDER BY dimension_id,member_id""",(scope.workspace_id,
                        scope.application_id,reduced)).fetchall()
                    # Sealed paths contain globally unique relationship IDs. Fetch
                    # only those identities; a named graph must never contribute
                    # an edge merely because its endpoints share dimension members.
                    path_ids=(sorted({edge for dimension in reduced
                        for placement in sealed_placements[dimension]
                        for edge in placement["pathRelationshipIds"]})
                        if sealed_placements is not None else None)
                    relationship_rows=db.execute("""SELECT dimension_id,
                        relationship_id,parent_member_id,child_member_id,
                        aggregation_operator_override FROM epm.relationship
                        WHERE workspace_id=%s AND application_id=%s
                        AND dimension_id=ANY(%s::text[]) AND status='Active'
                        AND ((%s::text[] IS NOT NULL AND relationship_id=ANY(%s::text[]))
                          OR (%s::text[] IS NULL AND hierarchy_id=epm.default_hierarchy_id(
                            workspace_id,application_id,dimension_id)))
                        ORDER BY dimension_id,relationship_id""",(
                        scope.workspace_id,scope.application_id,reduced,path_ids,path_ids,path_ids)).fetchall()
                    all_placement_members={dimension:{} for dimension in reduced}
                    placement_relationships={dimension:[] for dimension in reduced}
                    for row in member_rows:
                        all_placement_members[row["dimension_id"]][row["member_id"]]=(
                            row["aggregation_operator"])
                    for row in relationship_rows:
                        placement_relationships[row["dimension_id"]].append({
                            "relationshipId":row["relationship_id"],
                            "parentMemberId":row["parent_member_id"],
                            "childMemberId":row["child_member_id"],
                            "aggregationOperatorOverride":
                                row["aggregation_operator_override"]})
        if len(rows)!=len(requested) or any(
                row["aggregation_operator"] is None for row in rows):
            raise ValueError("GENERIC_AGGREGATE_MEMBER_UNAVAILABLE")
        operators={dimension:{} for dimension in dimensions}
        for row in rows:
            operators[row["dimension_id"]][row["member_id"]]=(
                row["aggregation_operator"])
        placement_contributions={}
        placement_artifacts={}
        pins={
                "selectionId":sealed["selectionId"],
                "resolutionDigest":sealed["resolutionDigest"],
                "metadataRevision":sealed["metadataRevision"],
                "policyRevision":sealed["policyRevision"]}
        if plan.normalized["membershipSemantics"]=="placement":
            by_dimension={item["dimensionId"]:item
                          for item in sealed["selection"]["dimensions"]}
            for dimension in plan.normalized["reduceDimensions"]:
                if sealed_placements is not None:
                    artifact=resolve_sealed_placement_contributions(
                        sealed_placements[dimension],
                        member_operators=all_placement_members[dimension],
                        relationships=placement_relationships[dimension])
                else:
                    artifact=resolve_placement_contributions(
                        by_dimension[dimension]["include"],
                        selected_members=resolved[dimension],
                        member_operators=all_placement_members[dimension],
                        relationships=placement_relationships[dimension])
                placement_artifacts[dimension]=artifact
                placement_contributions[dimension]={
                    "weights":artifact["weights"],
                    "lineageDigest":artifact["lineageDigest"]}
            combined=combine_placement_lineage(placement_artifacts)
            pins["placementLineageDigest"]=combined["lineageDigest"]
        lowered=lower_generic_aggregate(plan,resolved_members=resolved,
            configured_operators=operators,selection_pins=pins,
            placement_contributions=placement_contributions)
        return self.aggregate_service.request(scope,lowered.normalized_arguments,
            input_dimensions=dimensions,
            dimension_roles={dimension:None for dimension in dimensions},
            budgets=_budgets(args.get("limits")),
            technical_lineage=(combined if placement_artifacts else None))

    def _read_lineage(self,scope:ApplicationScope,query_id:str)->dict:
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION READ ONLY")
                configure_statement_timeout(db,5000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,"read",function=LINEAGE)
                row=db.execute("""SELECT status,placement_lineage,
                    placement_lineage_digest FROM epm.cube_aggregate_query
                    WHERE workspace_id=%s AND application_id=%s
                    AND query_id=%s AND issuer=%s AND subject_id=%s""",(
                    scope.workspace_id,scope.application_id,query_id,
                    self.identity.issuer,self.identity.subject_id)).fetchone()
        if row is None or row["placement_lineage"] is None:
            raise ValueError("CUBE_AGGREGATE_PLACEMENT_LINEAGE_UNAVAILABLE")
        return {"queryId":query_id,"status":row["status"],
                "lineageDigest":row["placement_lineage_digest"],
                "lineage":row["placement_lineage"]}
