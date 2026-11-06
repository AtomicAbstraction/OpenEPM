"""Immutable generic calculated-member definitions over the shared registry."""

from __future__ import annotations

from .calculated_member_contract import (
    canonical_calculated_member, validate_calculated_member_graph)
from .postgres_expression_rules import PostgresExpressionRules, _ID
from .postgres_jobs import _canonical_digest
from .postgres_selection_preview import PostgresSelectionPreview,PREVIEW
from .selection_contract import selection_digest


SAVE="calculated.member.version.save"
PUBLISH="calculated.member.version.publish"
READ="calculated.member.version.read"
LIST="calculated.member.version.list"
MATERIALIZE="calculated.member.materialize"
EVALUATE="calculated.member.evaluate"
STORED_FUNCTION="calculated.member.definition"


def catalog() -> dict:
    common={"previewRequired":False,"workClass":"short"}
    return {
        SAVE:{**common,"mode":"immutable_definition_write",
            "permission":"rule_design","idempotencyRequired":True,
            "arguments":{"definition":"canonical calculated-member v1",
                "expectedMetadataRevision":"current metadata revision",
                "expectedPolicyRevision":"current policy revision"},
            "result":"immutable definition version, digest and receipt"},
        PUBLISH:{**common,"mode":"atomic_publication",
            "permission":"rule_publish","idempotencyRequired":True,
            "arguments":{"definitionId":"saved definition identity",
                "version":"saved immutable version",
                "expectedMetadataRevision":"current metadata revision",
                "expectedPolicyRevision":"current policy revision"},
            "result":"published exact version, dependency graph and receipt"},
        READ:{**common,"mode":"read","permission":"read",
            "idempotencyRequired":False,
            "arguments":{"definitionId":"definition identity"},
            "optionalArguments":{"version":"positive immutable version"},
            "result":"definition and publication state"},
        LIST:{**common,"mode":"read","permission":"read",
            "idempotencyRequired":False,"arguments":{},
            "optionalArguments":{"limit":"1-100",
                "afterDefinitionId":"stable keyset cursor",
                "expectedMetadataRevision":"cursor metadata revision",
                "expectedPolicyRevision":"cursor policy revision"},
            "result":"bounded current calculated-member publications"},
        EVALUATE:{**common,"mode":"read","permission":"read",
            "idempotencyRequired":False,
            "arguments":{"definitionId":
                "current published dynamic definition"},
            "result":"bounded typed rows evaluated in one read snapshot"},
        MATERIALIZE:{"mode":"durable_calculation","permission":"write",
            "previewRequired":True,"idempotencyRequired":True,
            "workClass":"short",
            "arguments":{"definitionId":"current published materialized definition"},
            "result":"immutable exact generation and atomic result publication"},
    }


def _dimensions(definition: object) -> list[str]:
    try:
        values=definition["sourceSelection"]["dimensions"]
        result=[item["dimensionId"] for item in values]
    except (KeyError,TypeError) as error:
        raise ValueError("CALCULATED_MEMBER_INVALID") from error
    return result


def _program(raw: object, function: str) -> dict:
    if (not isinstance(raw,dict)
            or set(raw)!={"languageVersion","function","arguments"}
            or raw.get("languageVersion")!=2 or raw.get("function")!=function
            or not isinstance(raw.get("arguments"),dict)):
        raise ValueError("CALCULATED_MEMBER_PROGRAM_INVALID")
    args=raw["arguments"]
    for field in ("expectedMetadataRevision","expectedPolicyRevision"):
        if field in args and (type(args[field]) is not int or args[field]<0):
            raise ValueError("CALCULATED_MEMBER_ARGUMENTS_INVALID")
    if function==SAVE:
        if set(args)!={"definition","expectedMetadataRevision",
                      "expectedPolicyRevision"}:
            raise ValueError("CALCULATED_MEMBER_ARGUMENTS_INVALID")
        definition=canonical_calculated_member(args["definition"],
            active_dimensions=_dimensions(args["definition"]))
        rule_id=definition["definitionId"];version=definition["version"]
        calculation={"languageVersion":2,"function":STORED_FUNCTION,
                     "arguments":definition}
        return {**args,"ruleId":rule_id,"version":version,
                "calculation":calculation,"plan":definition}
    if function==PUBLISH:
        required={"definitionId","version","expectedMetadataRevision",
                  "expectedPolicyRevision"}
        if set(args)!=required:
            raise ValueError("CALCULATED_MEMBER_ARGUMENTS_INVALID")
        rule_id=args["definitionId"]
        if (not isinstance(rule_id,str) or not _ID.fullmatch(rule_id)
                or type(args["version"]) is not int or args["version"]<1):
            raise ValueError("CALCULATED_MEMBER_ARGUMENTS_INVALID")
        return {**args,"ruleId":rule_id}
    if function==READ:
        if set(args) not in ({"definitionId"},{"definitionId","version"}):
            raise ValueError("CALCULATED_MEMBER_ARGUMENTS_INVALID")
        rule_id=args["definitionId"]
        if (not isinstance(rule_id,str) or not _ID.fullmatch(rule_id)
                or ("version" in args and (type(args["version"]) is not int
                                            or args["version"]<1))):
            raise ValueError("CALCULATED_MEMBER_ARGUMENTS_INVALID")
        return {**args,"ruleId":rule_id}
    if function==LIST:
        mapped=dict(args)
        if "afterDefinitionId" in mapped:
            mapped["afterRuleId"]=mapped.pop("afterDefinitionId")
        allowed={"limit","afterRuleId","expectedMetadataRevision",
                 "expectedPolicyRevision"}
        if set(mapped)-allowed:
            raise ValueError("CALCULATED_MEMBER_ARGUMENTS_INVALID")
        limit=mapped.get("limit",100);after=mapped.get("afterRuleId")
        if (type(limit) is not int or not 1<=limit<=100
                or (after is not None and (not isinstance(after,str)
                                           or not _ID.fullmatch(after)))
                or any(type(mapped[key]) is not int or mapped[key]<0
                       for key in ("expectedMetadataRevision",
                                   "expectedPolicyRevision") if key in mapped)
                or (after is not None and not {"expectedMetadataRevision",
                    "expectedPolicyRevision"}<=set(mapped))):
            raise ValueError("CALCULATED_MEMBER_ARGUMENTS_INVALID")
        return mapped
    raise ValueError("CALCULATED_MEMBER_FUNCTION_INVALID")


class PostgresCalculatedMembers(PostgresExpressionRules):
    SAVE,PUBLISH,READ,LIST,EVALUATE,MATERIALIZE=(
        SAVE,PUBLISH,READ,LIST,EVALUATE,MATERIALIZE)
    STORED_FUNCTION=STORED_FUNCTION
    _parse=staticmethod(_program)

    @staticmethod
    def _validate_definition(db,scope,definition):
        dimensions=[row["dimension_id"] for row in db.execute('''SELECT
            dimension_id FROM epm.dimension WHERE workspace_id=%s
            AND application_id=%s AND status='Active' ORDER BY dimension_id''',
            (scope.workspace_id,scope.application_id)).fetchall()]
        canonical=canonical_calculated_member(
            definition,active_dimensions=dimensions)
        if canonical!=definition:
            raise ValueError("CALCULATED_MEMBER_DEFINITION_NONCANONICAL")
        target=canonical["target"]
        row=db.execute('''SELECT 1 FROM epm.member WHERE workspace_id=%s
            AND application_id=%s AND dimension_id=%s AND member_id=%s
            AND status='Active' ''',(scope.workspace_id,scope.application_id,
            target["dimensionId"],target["memberId"])).fetchone()
        if row is None:
            raise ValueError("CALCULATED_MEMBER_TARGET_UNAVAILABLE")

    @staticmethod
    def _validate_publication(db,scope,args,definition):
        root=definition["program"]["arguments"]
        current_metadata=db.execute('''SELECT metadata_revision FROM
            epm.application_state WHERE workspace_id=%s AND application_id=%s''',
            (scope.workspace_id,scope.application_id)).fetchone()[
                "metadata_revision"]
        pending=[(root["definitionId"],root["version"],root)]
        definitions=[];seen=set()
        while pending:
            definition_id,version,item=pending.pop()
            key=(definition_id,version)
            if key in seen:
                continue
            seen.add(key);definitions.append(item)
            for dependency in item["dependencies"]:
                row=db.execute('''SELECT v.program,v.program_digest,
                    v.metadata_revision,p.version published_version
                    FROM epm.expression_rule_version v
                    LEFT JOIN epm.expression_rule_publication p
                      USING(workspace_id,application_id,rule_id)
                    WHERE v.workspace_id=%s AND v.application_id=%s
                    AND v.rule_id=%s AND v.version=%s''',(
                    scope.workspace_id,scope.application_id,
                    dependency["definitionId"],dependency["version"])).fetchone()
                if (row is None or row["published_version"]!=dependency["version"]
                        or row["program"].get("function")!=STORED_FUNCTION
                        or row["metadata_revision"]!=current_metadata
                        or _canonical_digest(row["program"])!=
                           row["program_digest"]):
                    raise ValueError("CALCULATED_MEMBER_DEPENDENCY_UNAVAILABLE")
                pending.append((dependency["definitionId"],
                                dependency["version"],
                                row["program"]["arguments"]))
        validate_calculated_member_graph(definitions)
        target=root["target"]
        conflict=db.execute('''SELECT p.rule_id FROM
            epm.expression_rule_publication p JOIN epm.expression_rule_version v
            USING(workspace_id,application_id,rule_id,version)
            WHERE p.workspace_id=%s AND p.application_id=%s
            AND p.rule_id<>%s AND v.program->>'function'=%s
            AND v.program->'arguments'->'target'->>'dimensionId'=%s
            AND v.program->'arguments'->'target'->>'memberId'=%s LIMIT 1''',(
            scope.workspace_id,scope.application_id,args["ruleId"],
            STORED_FUNCTION,target["dimensionId"],target["memberId"])).fetchone()
        if conflict is not None:
            raise ValueError("CALCULATED_MEMBER_TARGET_ALREADY_PUBLISHED")

    @staticmethod
    def _summary(definition):
        return {"target":definition["target"],
                "evaluation":definition["evaluation"],
                "resultUnit":definition["resultUnit"],
                "dependencies":definition["dependencies"]}

    @staticmethod
    def _external(result: dict) -> dict:
        value=dict(result)
        if "ruleId" in value:
            value["definitionId"]=value.pop("ruleId")
        if "rows" in value:
            value["rows"]=[{"definitionId":row["ruleId"],
                            **{key:item for key,item in row.items()
                               if key!="ruleId"}} for row in value["rows"]]
            if "nextAfterRuleId" in value:
                value["nextAfterDefinitionId"]=value.pop("nextAfterRuleId")
        return value

    def execute(self,scope,raw,*,idempotency_key):
        return self._external(super().execute(
            scope,raw,idempotency_key=idempotency_key))

    def read(self,scope,raw):
        return self._external(super().read(scope,raw))

    def list_published(self,scope,raw):
        return self._external(super().list_published(scope,raw))

    def _prepare(self,scope,raw,*,function,evaluation):
        if (not isinstance(raw,dict)
                or set(raw)!={"languageVersion","function","arguments"}
                or raw.get("languageVersion")!=2
                or raw.get("function")!=function
                or not isinstance(raw.get("arguments"),dict)
                or set(raw["arguments"])!={"definitionId"}
                or not isinstance(raw["arguments"]["definitionId"],str)
                or not _ID.fullmatch(raw["arguments"]["definitionId"])):
            raise ValueError("CALCULATED_MEMBER_EVALUATION_REQUEST_INVALID")
        definition_id=raw["arguments"]["definitionId"]
        current=self.read(scope,{"languageVersion":2,"function":READ,
            "arguments":{"definitionId":definition_id}})
        if (not current["defined"] or current["status"]!="Published"
                or current["definitionMetadataRevision"]!=
                   current["currentMetadataRevision"]):
            raise ValueError("CALCULATED_MEMBER_PUBLICATION_UNAVAILABLE")
        definition=current["program"]["arguments"]
        if definition["evaluation"]!=evaluation:
            raise ValueError("CALCULATED_MEMBER_EVALUATION_MODE_MISMATCH")
        resolved=PostgresSelectionPreview(
            self.dsn,identity=self.identity).read(scope,{
                "languageVersion":2,"function":PREVIEW,"arguments":{
                    "selection":definition["sourceSelection"],
                    "expectedPolicyRevision":current["policyRevision"]}})
        selected_cells=1
        for members in resolved["members"].values():
            selected_cells*=len(members)
        if (selected_cells<1
                or selected_cells>definition["maxSourceCells"]
                or selected_cells>definition["maxOutputCells"]):
            raise ValueError("CALCULATED_MEMBER_BUDGET_EXCEEDED")
        source_members={};source_sets=[]
        for dimension_id,members in sorted(resolved["members"].items()):
            if len(members)==1:
                source_members[dimension_id]=members[0]
            elif 1<len(members)<=100:
                source_sets.append({"dimensionId":dimension_id,
                                    "memberIds":sorted(members)})
            else:
                raise ValueError("CALCULATED_MEMBER_SOURCE_SET_LIMIT")
        target=definition["target"]
        arguments={"sourceMembers":source_members,
            "expression":definition["expression"],
            "resultKey":(definition["resultKey"] if evaluation=="materialized"
                else "dynamic."+current["programDigest"][:32]),
            "targetMembers":{target["dimensionId"]:target["memberId"]}}
        if source_sets:
            arguments["sourceMemberSets"]=source_sets
        if definition["resultUnit"]=="ratio":
            arguments["resultUnit"]={"type":"Ratio","scale":12}
        pin={"definitionId":definition_id,"version":current["version"],
            "programDigest":current["programDigest"],
            "publishedRevision":current["publishedRevision"],
            "policyRevision":current["policyRevision"],
            "sourceSelectionDigest":selection_digest(
                definition["sourceSelection"]),
            "resolvedSelection":{key:resolved[key] for key in (
                "format","metadataRevision","members","placements",
                "memberListPins","resolutionDigest")}}
        program={"languageVersion":2,"function":"facts.expression.calculate",
                 "arguments":arguments}
        return program,pin

    def prepare_materialization(self,scope,raw):
        return self._prepare(scope,raw,function=MATERIALIZE,
                             evaluation="materialized")

    def prepare_dynamic(self,scope,raw):
        return self._prepare(scope,raw,function=EVALUATE,
                             evaluation="dynamic")

    def evaluate(self,scope,raw):
        from psycopg.rows import dict_row
        from .postgres_access import PostgresAccessChecker
        from .postgres_connection import connect_postgres
        from .postgres_expression import (compile_expression_program,
            compiler_for,evaluate_dynamic_expression,resolve_published_inputs)
        from .postgres_numeric_store import PostgresNumericFactStore
        from .postgres_processing_limits import configure_statement_timeout

        program,pin=self.prepare_dynamic(scope,raw)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db,5000)
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state=db.execute('''SELECT metadata_revision,data_revision,
                    policy_revision,commit_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s FOR SHARE''',(
                    scope.workspace_id,scope.application_id)).fetchone()
                if state is None:
                    raise ValueError("APPLICATION_UNAVAILABLE")
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,"read",function=EVALUATE)
                inputs=resolve_published_inputs(db,scope,
                    program["arguments"]["expression"])
                plan=compile_expression_program(program,
                    expected_publication_revision=0,
                    published_inputs=inputs,calculated_member=pin)
                verify_calculated_member_pin(
                    db,scope,pin,plan,evaluation="dynamic")
                rows=evaluate_dynamic_expression(
                    db,scope,self.identity,plan)
                compiler,plan_digest=compiler_for(plan)
        return {"definitionId":pin["definitionId"],
            "version":pin["version"],"programDigest":pin["programDigest"],
            "publishedRevision":pin["publishedRevision"],
            "sourceSelectionDigest":pin["sourceSelectionDigest"],
            "resolvedSelection":pin["resolvedSelection"],
            "metadataRevision":state["metadata_revision"],
            "dataRevision":state["data_revision"],
            "policyRevision":state["policy_revision"],
            "commitRevision":state["commit_revision"],
            "compilerVersion":compiler,"planDigest":plan_digest,
            "dynamic":True,"persisted":False,"rows":rows}


def verify_calculated_member_pin(db,scope,pin,plan,*,evaluation):
    required={"definitionId","version","programDigest","publishedRevision",
              "policyRevision","sourceSelectionDigest","resolvedSelection"}
    if not isinstance(pin,dict) or set(pin)!=required:
        raise ValueError("CALCULATED_MEMBER_PIN_INVALID")
    row=db.execute('''SELECT p.version,p.published_revision,v.program,
        v.program_digest,v.metadata_revision definition_metadata_revision,
        s.metadata_revision current_metadata_revision,
        s.policy_revision current_policy_revision
        FROM epm.expression_rule_publication p
        JOIN epm.expression_rule_version v
          USING(workspace_id,application_id,rule_id,version)
        JOIN epm.application_state s USING(workspace_id,application_id)
        WHERE p.workspace_id=%s AND p.application_id=%s AND p.rule_id=%s''',(
        scope.workspace_id,scope.application_id,pin["definitionId"])).fetchone()
    if (row is None or row["version"]!=pin["version"]
            or row["published_revision"]!=pin["publishedRevision"]
            or row["program_digest"]!=pin["programDigest"]
            or _canonical_digest(row["program"])!=pin["programDigest"]
            or row["definition_metadata_revision"]!=
               row["current_metadata_revision"]
            or row["current_policy_revision"]!=pin["policyRevision"]
            or row["program"].get("function")!=STORED_FUNCTION):
        raise ValueError("STALE_CALCULATED_MEMBER_PUBLICATION")
    definition=row["program"]["arguments"]
    resolved=pin["resolvedSelection"]
    sealed={key:resolved.get(key) for key in (
        "format","metadataRevision","members","placements","memberListPins")}
    if (selection_digest(definition["sourceSelection"])!=
            pin["sourceSelectionDigest"]
            or resolved.get("resolutionDigest")!=_canonical_digest(sealed)
            or resolved.get("metadataRevision")!=
               row["definition_metadata_revision"]
            or definition["evaluation"]!=evaluation
            or (definition["resultKey"] if evaluation=="materialized"
                else "dynamic."+pin["programDigest"][:32])!=plan.result_key
            or definition["expression"]!=plan.expression
            or dict(plan.target_members)!={definition["target"]["dimensionId"]:
                                           definition["target"]["memberId"]}):
        raise ValueError("CALCULATED_MEMBER_PLAN_MISMATCH")


def verify_materialization_pin(db,scope,pin,plan):
    return verify_calculated_member_pin(
        db,scope,pin,plan,evaluation="materialized")
