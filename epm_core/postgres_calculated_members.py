"""Current generic calculated-member definitions over the shared registry."""

from __future__ import annotations

from .calculated_member_contract import (
    calculated_member_digest, canonical_calculated_member,
    validate_calculated_member_graph)
from .postgres_expression_rules import PostgresExpressionRules, _ID
from .postgres_jobs import _canonical_digest
from .postgres_selection_preview import PostgresSelectionPreview,PREVIEW
from .selection_contract import selection_digest


SAVE="calculated.member.save"
PUBLISH="calculated.member.activate"
READ="calculated.member.read"
LIST="calculated.member.list"
MATERIALIZE="calculated.member.materialize"
EVALUATE="calculated.member.evaluate"
STORED_FUNCTION="calculated.member.definition"


def catalog() -> dict:
    common={"previewRequired":False,"workClass":"short"}
    return {
        SAVE:{**common,"mode":"current_definition_write",
            "permission":"rule_design","idempotencyRequired":True,
            "arguments":{"definition":"canonical calculated-member v1",
                "expectedMetadataRevision":"current metadata revision",
                "expectedPolicyRevision":"current policy revision"},
            "optionalArguments":{"expectedStateToken":"required to replace the current definition"},
            "result":"current inactive definition, state token and digest"},
        PUBLISH:{**common,"mode":"atomic_activation",
            "permission":"rule_publish","idempotencyRequired":True,
            "arguments":{"definitionId":"saved definition identity",
                "expectedStateToken":"current definition state token",
                "expectedMetadataRevision":"current metadata revision",
                "expectedPolicyRevision":"current policy revision"},
            "result":"current Active definition, dependency graph and receipt"},
        READ:{**common,"mode":"read","permission":"read",
            "idempotencyRequired":False,
            "arguments":{"definitionId":"definition identity"},
            "result":"current definition and activation state"},
        LIST:{**common,"mode":"read","permission":"read",
            "idempotencyRequired":False,"arguments":{},
            "optionalArguments":{"limit":"1-100",
                "afterDefinitionId":"stable keyset cursor",
                "expectedMetadataRevision":"cursor metadata revision",
                "expectedPolicyRevision":"cursor policy revision"},
            "result":"bounded current calculated-member definitions"},
        EVALUATE:{**common,"mode":"read","permission":"read",
            "idempotencyRequired":False,
            "arguments":{"definitionId":
                "current published dynamic definition"},
            "optionalArguments":{"expectedStateToken":"exact inspected Active definition state",
                "expectedProgramDigest":"exact inspected compiled digest"},
            "result":"bounded typed rows evaluated in one read snapshot"},
        MATERIALIZE:{"mode":"durable_calculation","permission":"write",
            "previewRequired":True,"idempotencyRequired":True,
            "workClass":"short",
            "arguments":{"definitionId":"current published materialized definition"},
            "optionalArguments":{"expectedStateToken":"exact inspected Active definition state",
                "expectedProgramDigest":"exact inspected compiled digest"},
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
        required={"definition","expectedMetadataRevision",
                  "expectedPolicyRevision"}
        if set(args) not in (required, required|{"expectedStateToken"}):
            raise ValueError("CALCULATED_MEMBER_ARGUMENTS_INVALID")
        if ("expectedStateToken" in args and (
                type(args["expectedStateToken"]) is not str
                or len(args["expectedStateToken"])!=64
                or any(character not in "0123456789abcdef"
                       for character in args["expectedStateToken"]))):
            raise ValueError("CALCULATED_MEMBER_ARGUMENTS_INVALID")
        definition=canonical_calculated_member(args["definition"],
            active_dimensions=_dimensions(args["definition"]))
        rule_id=definition["definitionId"]
        calculation={"languageVersion":2,"function":STORED_FUNCTION,
                     "arguments":definition}
        return {**args,"ruleId":rule_id,
                "calculation":calculation,"plan":definition}
    if function==PUBLISH:
        required={"definitionId","expectedStateToken","expectedMetadataRevision",
                  "expectedPolicyRevision"}
        if set(args)!=required:
            raise ValueError("CALCULATED_MEMBER_ARGUMENTS_INVALID")
        rule_id=args["definitionId"]
        if (not isinstance(rule_id,str) or not _ID.fullmatch(rule_id)
                or type(args["expectedStateToken"]) is not str
                or len(args["expectedStateToken"])!=64
                or any(character not in "0123456789abcdef"
                       for character in args["expectedStateToken"])):
            raise ValueError("CALCULATED_MEMBER_ARGUMENTS_INVALID")
        return {**args,"ruleId":rule_id}
    if function==READ:
        if set(args)!={"definitionId"}:
            raise ValueError("CALCULATED_MEMBER_ARGUMENTS_INVALID")
        rule_id=args["definitionId"]
        if not isinstance(rule_id,str) or not _ID.fullmatch(rule_id):
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


def expression_program_for_definition(definition, *, result_key):
    """Lower a definition without expanding its server-owned selection."""
    from .selected_domain_contract import from_calculated_member
    dimensions=tuple(item["dimensionId"]
                     for item in definition["sourceSelection"]["dimensions"])
    arguments={"selectedDomain":from_calculated_member(
            definition,active_dimensions=dimensions),
        "expression":definition["expression"],
        "resultKey":result_key}
    if definition["resultUnit"]=="ratio":
        arguments["resultUnit"]={"type":"Ratio","scale":12}
    return {"languageVersion":2,"function":"facts.expression.calculate","arguments":arguments}


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
    def _validate_publication(db,scope,args,definition,*,register_template=True):
        root=definition["program"]["arguments"]
        current_metadata=db.execute('''SELECT metadata_revision FROM
            epm.application_state WHERE workspace_id=%s AND application_id=%s''',
            (scope.workspace_id,scope.application_id)).fetchone()[
                "metadata_revision"]
        pending=[(root["definitionId"],root)]
        definitions=[];seen=set()
        while pending:
            definition_id,item=pending.pop()
            if definition_id in seen:
                continue
            seen.add(definition_id);definitions.append(item)
            for dependency in item["dependencies"]:
                row=db.execute('''SELECT *
                    FROM epm.expression_rule_definition
                    WHERE workspace_id=%s AND application_id=%s
                    AND rule_id=%s''',(
                    scope.workspace_id,scope.application_id,
                    dependency["definitionId"])).fetchone()
                if (row is None or row["status"]!='Active'
                        or row["program"].get("function")!=STORED_FUNCTION
                        or row["metadata_revision"]!=current_metadata
                        or _canonical_digest(row["program"])!=
                           row["program_digest"]):
                    raise ValueError("CALCULATED_MEMBER_DEPENDENCY_UNAVAILABLE")
                from .postgres_python_definitions import assert_source_active
                assert_source_active(db,scope,row)
                pending.append((dependency["definitionId"],
                                row["program"]["arguments"]))
        validate_calculated_member_graph(definitions)
        target=root["target"]
        conflict=db.execute('''SELECT rule_id FROM
            epm.expression_rule_definition
            WHERE workspace_id=%s AND application_id=%s AND status='Active'
            AND rule_id<>%s AND program->>'function'=%s
            AND program->'arguments'->'target'->>'dimensionId'=%s
            AND program->'arguments'->'target'->>'memberId'=%s LIMIT 1''',(
            scope.workspace_id,scope.application_id,args["ruleId"],
            STORED_FUNCTION,target["dimensionId"],target["memberId"])).fetchone()
        if conflict is not None:
            raise ValueError("CALCULATED_MEMBER_TARGET_ALREADY_PUBLISHED")
        # Publication atomically installs the immutable symbolic dependency
        # template.  Resolved member/change tokens remain execution-manifest
        # state and are deliberately not guessed during authoring.
        template = compile_current_dependency_template(db, scope, root)
        if register_template:
            from .postgres_calculation_dependencies import register_dependency_template
            state = db.execute('''SELECT schema_epoch FROM epm.application_state
                WHERE workspace_id=%s AND application_id=%s''',
                (scope.workspace_id, scope.application_id)).fetchone()
            register_dependency_template(db, scope, template,
                schema_epoch=state["schema_epoch"])

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

    def execute(self,scope,raw,*,idempotency_key,_connection=None,_source_build_id=None):
        return self._external(super().execute(
            scope,raw,idempotency_key=idempotency_key,
            _connection=_connection,_source_build_id=_source_build_id))

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
                or set(raw["arguments"]) not in ({"definitionId"},
                    {"definitionId","expectedStateToken","expectedProgramDigest"})
                or not isinstance(raw["arguments"]["definitionId"],str)
                or not _ID.fullmatch(raw["arguments"]["definitionId"])):
            raise ValueError("CALCULATED_MEMBER_EVALUATION_REQUEST_INVALID")
        definition_id=raw["arguments"]["definitionId"]
        args=raw['arguments']
        if 'expectedStateToken' in args and (
                type(args['expectedStateToken']) is not str
                or len(args['expectedStateToken'])!=64
                or type(args['expectedProgramDigest']) is not str
                or len(args['expectedProgramDigest'])!=64):
            raise ValueError('CALCULATED_MEMBER_EVALUATION_REQUEST_INVALID')
        current=self.read(scope,{"languageVersion":2,"function":READ,
            "arguments":{"definitionId":definition_id}})
        if not current.get("executable",False):
            raise ValueError("CALCULATED_MEMBER_PUBLICATION_UNAVAILABLE")
        if current.get('source') is not None and 'expectedStateToken' not in args:
            raise ValueError('CALCULATED_MEMBER_EXPECTED_STATE_TOKEN_REQUIRED')
        if 'expectedStateToken' in args and (
                current['stateToken']!=args['expectedStateToken']
                or current['programDigest']!=args['expectedProgramDigest']):
            raise ValueError('CALCULATED_MEMBER_EXPECTED_STATE_MISMATCH')
        definition=current["program"]["arguments"]
        if definition["evaluation"]!=evaluation:
            raise ValueError("CALCULATED_MEMBER_EVALUATION_MODE_MISMATCH")
        resolved=PostgresSelectionPreview(
            self.dsn,identity=self.identity).read(scope,{
                "languageVersion":2,"function":PREVIEW,"arguments":{
                    "selection":definition["sourceSelection"],
                    "expectedPolicyRevision":current["policyRevision"]}})
        program=expression_program_for_definition(definition,result_key=(definition["resultKey"]
            if evaluation=="materialized" else "dynamic."+current["programDigest"][:32]))
        from .selected_domain_contract import selected_domain_digest
        selected_domain=program["arguments"]["selectedDomain"]
        pin={"definitionId":definition_id,
            "stateToken":current["stateToken"],
            "programDigest":current["programDigest"],
            "definitionDigest":calculated_member_digest(definition,
                active_dimensions=tuple(resolved["members"])),
            "policyRevision":current["policyRevision"],
            "sourceSelectionDigest":selection_digest(
                definition["sourceSelection"]),
            "selectedDomainDigest":selected_domain_digest(
                selected_domain,active_dimensions=tuple(resolved["members"])),
            "resolutionDigest":resolved["resolutionDigest"]}
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
                    expected_target_state_token=None,
                    published_inputs=inputs,calculated_member=pin)
                verify_calculated_member_pin(
                    db,scope,pin,plan,evaluation="dynamic")
                rows=evaluate_dynamic_expression(
                    db,scope,self.identity,plan)
                compiler,plan_digest=compiler_for(plan)
        return {"definitionId":pin["definitionId"],
            "stateToken":pin["stateToken"],"programDigest":pin["programDigest"],
            "definitionDigest":pin["definitionDigest"],
            "sourceSelectionDigest":pin["sourceSelectionDigest"],
            "resolutionDigest":pin["resolutionDigest"],
            "metadataRevision":state["metadata_revision"],
            "dataRevision":state["data_revision"],
            "policyRevision":state["policy_revision"],
            "commitRevision":state["commit_revision"],
            "compilerVersion":compiler,"planDigest":plan_digest,
            "dynamic":True,"persisted":False,"rows":rows}


def verify_calculated_member_pin(db,scope,pin,plan,*,evaluation):
    compact={"definitionId","stateToken","programDigest",
             "definitionDigest",
             "policyRevision","sourceSelectionDigest","selectedDomainDigest",
             "resolutionDigest"}
    if not isinstance(pin,dict) or set(pin)!=compact:
        raise ValueError("CALCULATED_MEMBER_PIN_INVALID")
    row=db.execute('''SELECT v.*,v.metadata_revision definition_metadata_revision,
        s.metadata_revision current_metadata_revision,
        s.policy_revision current_policy_revision
        FROM epm.expression_rule_definition v
        JOIN epm.application_state s USING(workspace_id,application_id)
        WHERE v.workspace_id=%s AND v.application_id=%s AND v.rule_id=%s''',(
        scope.workspace_id,scope.application_id,pin["definitionId"])).fetchone()
    if (row is None or row["status"]!='Active'
            or row["state_token"]!=pin["stateToken"]
            or row["program_digest"]!=pin["programDigest"]
            or _canonical_digest(row["program"])!=pin["programDigest"]
            or row["definition_metadata_revision"]!=
               row["current_metadata_revision"]
            or row["current_policy_revision"]!=pin["policyRevision"]
            or row["program"].get("function")!=STORED_FUNCTION):
        raise ValueError("STALE_CALCULATED_MEMBER_PUBLICATION")
    from .postgres_python_definitions import assert_source_active
    assert_source_active(db,scope,row)
    definition=row["program"]["arguments"]
    from .postgres_selection_preview import resolve_selection_in_transaction
    from .selected_domain_contract import selected_domain_digest
    resolved=resolve_selection_in_transaction(db,scope,
        definition["sourceSelection"],row["definition_metadata_revision"])
    dimensions=tuple(resolved["members"])
    resolution_invalid=(resolved["resolutionDigest"]!=pin["resolutionDigest"]
        or calculated_member_digest(definition,
            active_dimensions=dimensions)!=pin["definitionDigest"]
        or plan.selected_domain is None
        or selected_domain_digest(plan.selected_domain,
            active_dimensions=dimensions)!=pin["selectedDomainDigest"])
    _install_selected_domain_members(db,resolved,plan.selected_domain)
    if (selection_digest(definition["sourceSelection"])!=
            pin["sourceSelectionDigest"]
            or resolution_invalid
            or definition["evaluation"]!=evaluation
            or (definition["resultKey"] if evaluation=="materialized"
                else "dynamic."+pin["programDigest"][:32])!=plan.result_key
            or definition["expression"]!=plan.expression
            or dict(plan.target_members)!={definition["target"]["dimensionId"]:
                                           definition["target"]["memberId"]}):
        raise ValueError("CALCULATED_MEMBER_PLAN_MISMATCH")


def _install_selected_domain_members(db,resolved,profile=None):
    """Install one transaction-local relational membership relation."""
    rows=[{"dimension_id":axis,"member_id":member}
          for axis,members in sorted(resolved["members"].items())
          for member in members]
    if not resolved["members"]:
        raise ValueError("CALCULATED_MEMBER_PLAN_MISMATCH")
    if profile is not None:
        expected_axes = {item["dimensionId"]
            for item in profile["sourceSelection"]["dimensions"]}
        if set(resolved["members"]) != expected_axes:
            raise ValueError("CALCULATED_MEMBER_PLAN_MISMATCH")
        target=profile["targetMapping"]
        selected_target_members=resolved["members"].get(target["dimensionId"])
        if (selected_target_members is None or len(selected_target_members)>1
                or selected_target_members == [target["memberId"]]):
            raise ValueError("CALCULATED_MEMBER_TARGET_MAPPING_AMBIGUOUS")
    from psycopg.types.json import Jsonb
    existing=db.execute("""SELECT to_regclass(
        'pg_temp.epm_selected_domain_member') AS relation""").fetchone()
    relation=(existing.get('relation') if isinstance(existing,dict)
              else existing[0])
    if relation is None:
        db.execute('''CREATE TEMP TABLE epm_selected_domain_member(
            dimension_id text NOT NULL,member_id text NOT NULL,
            PRIMARY KEY(dimension_id,member_id)) ON COMMIT DROP''')
    # DELETE remains legal for a session-local temporary relation inside a
    # READ ONLY business-data transaction; TRUNCATE does not.
    db.execute('''DELETE FROM pg_temp.epm_selected_domain_member''')
    db.execute('''INSERT INTO pg_temp.epm_selected_domain_member(
        dimension_id,member_id) SELECT dimension_id,member_id
        FROM jsonb_to_recordset(%s::jsonb)
        AS item(dimension_id text,member_id text)''',(Jsonb(rows),))


def verify_materialization_pin(db,scope,pin,plan):
    return verify_calculated_member_pin(
        db,scope,pin,plan,evaluation="materialized")


def dependency_template_compiler(definition):
    """The maintained calculation compiler for this definition's expression."""
    from .postgres_expression import (SELECTED_DOMAIN_COMPILER,
        TEMPORAL_SELECTED_DOMAIN_COMPILER, temporal_window)
    return (TEMPORAL_SELECTED_DOMAIN_COMPILER
        if temporal_window(definition["expression"]) is not None
        else SELECTED_DOMAIN_COMPILER)


def compile_current_dependency_template(db, scope, definition):
    """Compile current semantic dependencies; callers own acceptance checks.

    Validation uses this for an inactive draft. Execution and readers must
    first verify the current owner/pins and require the exact registered result.
    """
    from .calculation_dependency_compiler import compile_calculated_member_dependency_template
    from .postgres_selection_preview import selection_semantic_references_in_transaction
    dimensions = [row["dimension_id"] for row in db.execute('''SELECT
        dimension_id FROM epm.dimension WHERE workspace_id=%s
        AND application_id=%s AND status='Active' ORDER BY dimension_id''',
        (scope.workspace_id, scope.application_id)).fetchall()]
    compiler = dependency_template_compiler(definition)
    references = selection_semantic_references_in_transaction(
        db, scope, definition["sourceSelection"])
    return compile_calculated_member_dependency_template(definition,
        active_dimensions=dimensions, compiler_version=compiler,
        selector_references=references)


def load_current_dependency_template(db, scope, definition, *,
        expected_definition_digest=None, expected_compiler_version=None):
    """Require the validated template for these exact current semantics.

    A named selection can change without changing the calculation source. Its
    old immutable template remains execution evidence, never a candidate for
    the new current definition. This path performs no registration or writes.
    """
    from .calculation_dependency_contract import compile_dependency_template
    template = compile_current_dependency_template(db, scope, definition)
    if ((expected_definition_digest is not None and
            template.normalized["definitionDigest"] != expected_definition_digest)
            or (expected_compiler_version is not None and
                template.normalized["compilerVersion"] != expected_compiler_version)):
        raise ValueError("CALCULATION_DEPENDENCY_TEMPLATE_PIN_MISMATCH")
    row = db.execute('''SELECT t.template_digest,t.template FROM
        epm.calculation_dependency_template t JOIN epm.application_state s
        USING(workspace_id,application_id,schema_epoch)
        WHERE t.workspace_id=%s AND t.application_id=%s
        AND t.template_digest=%s''', (scope.workspace_id,
        scope.application_id, template.digest)).fetchone()
    if row is None:
        raise ValueError("CALCULATION_DEPENDENCY_TEMPLATE_UNAVAILABLE")
    stored = compile_dependency_template(row["template"])
    if stored.digest != row["template_digest"] or stored.digest != template.digest:
        raise ValueError("CALCULATION_DEPENDENCY_TEMPLATE_INVALID")
    return stored


def prepare_materialization_dependency_state(db, scope, pin, plan, *,
        job_id: str, state: dict) -> dict:
    """Seal the exact W05 binding/manifest before result computation."""
    from .calculation_dependency_contract import (
        calculation_instance_binding, compile_execution_manifest, digest)
    from .postgres_calculation_dependencies import (
        initialize_scope_state, register_instance_binding,
        seal_execution_manifest)
    required_state = {"schema_epoch", "commit_revision", "metadata_revision",
                      "data_revision", "policy_revision"}
    if not required_state <= set(state):
        raise ValueError("CALCULATION_DEPENDENCY_READ_CUT_INVALID")
    from .postgres_expression import compiler_for
    compiler_version = compiler_for(plan)[0]
    owner = db.execute('''SELECT * FROM epm.expression_rule_definition
        WHERE workspace_id=%s AND application_id=%s AND rule_id=%s''',
        (scope.workspace_id, scope.application_id, pin["definitionId"])).fetchone()
    if (owner is None or owner["status"] != "Active"
            or owner["state_token"] != pin["stateToken"]
            or owner["program_digest"] != pin["programDigest"]
            or _canonical_digest(owner["program"]) != pin["programDigest"]
            or owner["program"].get("function") != STORED_FUNCTION):
        raise ValueError("STALE_CALCULATED_MEMBER_PUBLICATION")
    from .postgres_python_definitions import assert_source_active
    assert_source_active(db, scope, owner)
    template = load_current_dependency_template(db, scope,
        owner["program"]["arguments"],
        expected_definition_digest=pin["definitionDigest"],
        expected_compiler_version=compiler_version)
    binding = calculation_instance_binding(
        template_digest=template.digest,
        definition_id=pin["definitionId"],
        definition_state_token=pin["stateToken"], stage="materialize",
        parameters={
            "resolutionDigest": pin["resolutionDigest"],
            "selectedDomainDigest": pin["selectedDomainDigest"],
            "resultKey": plan.result_key,
        }, partition_policy_version=1)
    register_instance_binding(db, scope, binding)
    partitions = [item["partitionKey"]
                  for item in template.normalized["targets"]]
    read_cut = {"commit": state["commit_revision"],
                "metadata": state["metadata_revision"],
                "data": state["data_revision"],
                "policy": state["policy_revision"]}
    resolved = []
    for ordinal, dependency in enumerate(
            template.normalized["dependencies"]):
        kind = dependency["kind"]
        token = {"kind": kind,
                 "objectType": dependency["objectType"],
                 "objectId": dependency["objectId"],
                 "scope": dependency["scope"],
                 "readCut": ({"data": state["data_revision"]}
                     if kind in {"raw", "absence_range"}
                     else {"metadata": state["metadata_revision"]}
                     if kind in {"selector", "hierarchy", "calendar",
                                 "unit_policy"}
                     else {"commit": state["commit_revision"],
                           "data": state["data_revision"]})}
        if dependency['objectType'] == 'calculation-result':
            from .postgres_calculation_status import published_result_status
            pins = {item['resultKey']: item['resultStateToken'] for item in plan.published_inputs or ()}
            result_key = dependency['objectId']
            if result_key not in pins:
                raise ValueError('CALCULATION_PRODUCER_PIN_UNRESOLVED')
            status = published_result_status(db, scope, result_key, pins[result_key])
            if not status['matchesAtRead'] or status['truncated']:
                raise ValueError('CALCULATION_PRODUCER_PIN_STALE')
            from .postgres_job_origin import published_dependency_evidence
            token['publishedDependencyEvidence'] = published_dependency_evidence(status)
        resolved.append({"templateOrdinal": ordinal,
                         "tokenDigest": digest(token), "token": token,
                         "outputPartitions": partitions})
    manifest = compile_execution_manifest({
        "format": "openepm-calculation-execution-manifest-v1",
        "templateDigest": template.digest,
        "bindingDigest": binding["bindingDigest"],
        "schemaEpoch": state["schema_epoch"], "readCut": read_cut,
        "resolvedDependencies": resolved,
        "targetPartitions": partitions,
        "coverage": template.normalized["coverage"],
    })
    seal_execution_manifest(db, scope, template=template, binding=binding,
                            manifest=manifest, job_id=job_id)
    initialize_scope_state(db, scope, template=template, binding=binding)
    epochs = db.execute('''SELECT partition_key,required_epoch FROM
        epm.calculation_scope_state WHERE workspace_id=%s
        AND application_id=%s AND binding_digest=%s AND stage=%s
        ORDER BY partition_key''', (scope.workspace_id, scope.application_id,
        binding["bindingDigest"], binding["stage"])).fetchall()
    if [row["partition_key"] for row in epochs] != partitions:
        raise ValueError("CALCULATION_SCOPE_STATE_INCOMPLETE")
    return {"template": template, "binding": binding,
            "manifest": manifest,
            "requiredEpochs": {row["partition_key"]: row["required_epoch"]
                               for row in epochs}}


def stage_dependency_partition_manifest(db, scope, artifact: dict, *,
        generation_id: str, row_count: int):
    """Stage the W05 partition certificate before current-result replacement."""
    from .calculation_partition_manifest_contract import (
        compile_partition_manifest)
    from .postgres_calculation_dependencies import store_partition_manifest
    template = artifact["template"]
    binding = artifact["binding"]
    manifest = artifact["manifest"]
    partitions = list(artifact["requiredEpochs"])
    presence = "present" if row_count else "empty"
    partition_manifest = compile_partition_manifest({
        "format": "openepm-calculation-partition-manifest-v2",
        "bindingDigest": binding["bindingDigest"],
        "executionManifestDigest": manifest.digest,
        "partitionPolicyVersion": binding["partitionPolicyVersion"],
        "coverage": template.normalized["coverage"],
        "partitions": [{"partitionKey": partition,
            "certificateDigest": manifest.digest,
            "presence": presence, "rowCount": row_count}
            for partition in partitions],
    })
    store_partition_manifest(db, scope, generation_id=generation_id,
                             manifest=partition_manifest)
    return partition_manifest


def publish_materialization_dependency_state(db, scope, artifact: dict, *,
        result_state_token: str, partition_manifest) -> dict:
    """CAS every target scope after its staged certificate is current."""
    from .postgres_calculation_dependencies import publish_scope_current
    template = artifact["template"]
    binding = artifact["binding"]
    manifest = artifact["manifest"]
    partitions = list(artifact["requiredEpochs"])
    presence_by_partition = {item["partitionKey"]: item["presence"]
                             for item in partition_manifest.normalized["partitions"]}
    if set(presence_by_partition) != set(partitions):
        raise ValueError("CALCULATION_PARTITION_INDEX_CONFLICT")
    for partition in partitions:
        publish_scope_current(db, scope,
            binding_digest=binding["bindingDigest"],
            stage=binding["stage"], partition_key=partition,
            expected_required_epoch=artifact["requiredEpochs"][partition],
            result_state_token=result_state_token,
            dependency_token_digest=manifest.digest,
            presence=presence_by_partition[partition],
            definition_digest=template.normalized["definitionDigest"])
    return {"bindingDigest": binding["bindingDigest"],
            "executionManifestDigest": manifest.digest,
            "partitionManifestDigest": partition_manifest.digest,
            "definitionDigest": template.normalized["definitionDigest"]}
