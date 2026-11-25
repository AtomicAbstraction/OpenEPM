"""Current generic calculated-member definitions over the shared registry."""

from __future__ import annotations

import re

from .calculated_member_contract import (
    FORMAT as DEFINITION_FORMAT, calculated_member_digest, canonical_calculated_member,
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
READ_FUNCTIONS = frozenset((LIST, READ, EVALUATE))
EVALUATION_AUTHORIZATION_STALE = 'CALCULATED_MEMBER_READ_AUTHORIZATION_STALE'
EVALUATION_SNAPSHOT_STALE = 'CALCULATED_MEMBER_READ_CUT_STALE'
REVIEW_AUTHORIZATION_STALE = 'CALCULATED_MEMBER_REVIEW_AUTHORIZATION_STALE'
PREVIEW_SNAPSHOT_STALE = 'CALCULATED_MEMBER_PREVIEW_CUT_STALE'
_LOOKUP_ID = re.compile(r'[A-Za-z0-9._:-]{1,200}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_LIST_LIMIT = 100
_LIST_REVISIONS = ('expectedMetadataRevision', 'expectedPolicyRevision')


def _identifier_schema():
    return {'type': 'string', 'pattern': '^' + _LOOKUP_ID.pattern.removesuffix(r'\Z') + r'(?![\s\S])'}


def _digest_schema():
    return {'type': 'string', 'pattern': '^' + _DIGEST.pattern.removesuffix(r'\Z') + r'(?![\s\S])'}


def _execution_request_schema():
    from .metadata_read_contract import obj

    arguments = obj({'definitionId': _identifier_schema(), 'expectedStateToken': _digest_schema(),
                     'expectedProgramDigest': _digest_schema()}, ['definitionId'])
    arguments['dependentRequired'] = {'expectedStateToken': ['expectedProgramDigest'],
                                      'expectedProgramDigest': ['expectedStateToken']}
    return arguments


def materialization_program_contract() -> dict:
    from .metadata_read_contract import DIALECT, obj, read_example
    from .postgres_jobs import job_submission_schema
    from .postgres_numeric_catalog import program_schema
    from .postgres_planning_write_guard import planning_write_evidence_schema

    digest = _digest_schema()
    revision = {'type': 'integer', 'minimum': 0}
    result_key = {'type': 'string', 'pattern': r'^[A-Za-z0-9._-]{8,128}(?![\s\S])'}
    engine = {'const': 'postgres_exact_sql'}
    member_pin = obj({'definitionId': _identifier_schema(), 'policyRevision': revision,
        **dict.fromkeys(('stateToken', 'programDigest', 'definitionDigest', 'sourceSelectionDigest',
                         'selectedDomainDigest', 'resolutionDigest'), digest)})
    input_pins = {'type': 'array', 'items': obj({'resultKey': result_key, 'resultStateToken': digest})}
    amount = obj({'type': {'const': 'Amount'}, 'scale': {'const': 8}})
    ratio = obj({'type': {'const': 'Ratio'}, 'scale': {'const': 12}})
    preview = {'$schema': DIALECT, **obj({
        'languageVersion': {'type': 'integer', 'const': 2}, 'function': {'const': MATERIALIZE},
        'programDigest': digest, 'planDigest': digest, 'compilerVersion': {'type': 'string'},
        'revisionVector': obj(dict.fromkeys(('metadata_revision', 'data_revision', 'policy_revision'), revision)),
        'expectedTargetStateToken': {'anyOf': [digest, {'type': 'null'}]},
        'estimatedRows': revision, 'engine': engine, 'resourceClass': {'const': 'short'},
        'rounding': {'enum': ['half-even-final-8', 'half-even-final-12']},
        'previewToken': {'type': 'string', 'minLength': 1}, 'publishedInputs': input_pins,
        'calculatedMember': member_pin, 'resultKey': result_key, 'resultUnit': {'oneOf': [amount, ratio]},
    })}
    preview.update({'if': {'properties': {'resultUnit': ratio}},
                    'then': {'properties': {'rounding': {'const': 'half-even-final-12'}}},
                    'else': {'properties': {'rounding': {'const': 'half-even-final-8'}}}})
    member_map = {'type': 'object', 'additionalProperties': {'type': 'string'}}
    publication = {
        'resultKey': result_key, 'resultStateToken': digest, 'resultContentDigest': digest,
        'rowCount': revision, 'sourceCommitRevision': revision, 'engine': engine,
        'impactDigest': digest, 'targetMembers': member_map, 'calculatedMember': member_pin,
    }
    published = {'$schema': DIALECT, **obj({**publication,
        'resultUnit': ratio, 'publishedInputs': input_pins,
        'sourceLookups': {'type': 'array', 'items': member_map},
        'sourceTextLookups': {'type': 'array', 'items': member_map},
        'planningPolicy': planning_write_evidence_schema(),
        'dependencyState': obj(dict.fromkeys(('bindingDigest', 'executionManifestDigest',
                                               'partitionManifestDigest', 'definitionDigest'), digest)),
        'outputUnit': {'type': 'object'}, 'rateLineage': {'type': 'object'},
        'consolidationTranslation': {'const': False},
    }, list(publication))}
    submission = job_submission_schema()
    return {'schemaCoverage': 'program-and-result', 'schemaDialect': DIALECT,
        'programSchema': program_schema(MATERIALIZE, _execution_request_schema()),
        'resultSchema': submission, 'resultSchemaScope': 'envelope',
        'programContract': {
            'owner': 'PostgresCalculatedMembers and the expression job owner',
            'examples': [read_example(MATERIALIZE, {'definitionId': 'example-calculated-member',
                'expectedStateToken': '1' * 64, 'expectedProgramDigest': '2' * 64},
                name='Preview the inspected materialized definition',
                binding='Read an executable materialized definition in the authorized application. Copy its definitionId, stateToken and programDigest.')],
            'outputSchemas': {
                'preview': {'schema': preview, 'scope': 'envelope',
                            'surface': 'preview_v2_program or Browser /api/preview'},
                'submission': {'schema': submission, 'scope': 'envelope',
                               'surface': 'submit_v2_program or Browser /api/submit'},
                'publishedResult': {'schema': published, 'scope': 'result',
                                    'surface': 'result from read_v2_job or Browser /api/job after publication'},
            },
            'semanticRules': [
                'Review the result key, unit, rounding, estimated row count, current definition pins and target state in Preview.',
                'Submission binds the unchanged program and original preview to an operation admission. Only the worker publishes the resulting generation.',
                'Use current write and run permissions. Source and target checks are enforced by the fixed core. Historical publication evidence identifies the committed result at its original revision.',
            ],
            'recovery': ('Read the original job with its operation ID if the acknowledgement was lost. '
                'Exact replay uses the same program, preview token, operation ID and ordered job dependencies, including for an accepted expired request. '
                'After a definitive stale refusal, inspect the current owner and review a new preview before requesting a new admission.'),
        },
    }


def _dynamic_result_schema(identifier, digest, revision):
    from .metadata_read_contract import obj
    from .postgres_expression import MAX_DYNAMIC_MEMBER_ROWS

    string = {'type': 'string'}
    nullable_string = {'type': ['string', 'null']}
    members = {'type': 'object', 'minProperties': 1, 'additionalProperties': string}
    source = {'sourceMembers': members, 'sourceSeriesKey': string,
              'sourceChangeId': string}
    lookup = {field: {'anyOf': [shape, {'type': 'null'}]} for field, shape in source.items()}
    lookup['memberOverrides'] = {'type': 'object', 'additionalProperties': string}
    lineage = {'oneOf': [
        obj({**lookup, 'inputKind': {'const': 'RawAmount'}, 'sourceAmount': nullable_string}),
        obj({**lookup, 'inputKind': {'const': 'RawText'}, 'sourceText': nullable_string}),
        obj({**source, 'inputKind': {'const': 'RawAmount'}, 'sourceAmount': string,
             'sourceCoordinateId': {'type': 'integer', 'minimum': 1}, 'calendarChangeId': string,
             'calendarOrdinal': {'type': 'integer'}}),
        obj({'inputKind': {'const': 'OpeningAmount'}, 'amount': string,
             'resetGroupId': nullable_string}),
        {'type': 'null'},
    ]}
    amount = {'type': 'string', 'pattern': r'^-?[0-9]+\.[0-9]{8}(?![\s\S])'}
    ratio = {'type': 'string', 'pattern': r'^-?[0-9]+\.[0-9]{12}(?![\s\S])'}
    row = obj({'members': members, 'sourceMembers': members, 'sourceAmount': amount,
        'sourceChangeId': string, 'sourceLineage': {'type': 'array', 'items': lineage},
        'value': {'oneOf': [obj({'type': {'const': 'AmountLiteral'}, 'decimal': amount}),
                            obj({'type': {'const': 'RatioLiteral'}, 'decimal': ratio})]}})
    return obj({'definitionId': identifier, **dict.fromkeys(
            ('stateToken', 'programDigest', 'definitionDigest', 'sourceSelectionDigest',
             'resolutionDigest', 'planDigest'), digest),
        **dict.fromkeys(('metadataRevision', 'dataRevision', 'policyRevision',
                         'commitRevision'), revision),
        'compilerVersion': string, 'dynamic': {'const': True}, 'persisted': {'const': False},
        'rows': {'type': 'array', 'items': row, 'maxItems': MAX_DYNAMIC_MEMBER_ROWS}})


def read_program_contract(function: str) -> dict:
    from .metadata_read_contract import obj, read_contract, read_example
    from .selection_contract import structural_schema_definitions

    identifier = _identifier_schema()
    digest = _digest_schema()
    nullable_digest = {'anyOf': [digest, {'type': 'null'}]}
    revision = {'type': 'integer', 'minimum': 0}
    text = {'type': ['string', 'null']}
    boolean = {'type': 'boolean'}
    sample = 'example-calculated-member'
    definitions = None
    if function == EVALUATE:
        arguments = _execution_request_schema()
        result = _dynamic_result_schema(identifier, digest, revision)
        examples = [read_example(EVALUATE, {'definitionId': sample, 'expectedStateToken': '1' * 64,
            'expectedProgramDigest': '2' * 64}, name='Evaluate the inspected dynamic definition',
            binding='Read an executable dynamic definition in the current application. Copy its definitionId, stateToken and programDigest.')]
        rules = ['The core evaluates dynamic definitions under current source and target READ authority.',
                 'Every returned row contains the original source and the exact AmountLiteral or RatioLiteral result. Evaluation produces no stored result or business receipt.']
    else:
        state = {**dict.fromkeys(('defined', 'valid', 'active', 'sourceCurrent', 'executable'), boolean),
                 'resultCurrent': {'type': 'null'}, 'reason': text}
        status = {'enum': ['Active', 'Inactive', 'Unavailable']}
        pins = {'definitionId': identifier, 'stateToken': nullable_digest,
                'programDigest': nullable_digest}
        target = obj({'dimensionId': identifier, 'memberId': identifier})
        summary = {'target': target, 'evaluation': {'enum': ['dynamic', 'materialized']},
                   'resultUnit': {'enum': ['amount', 'ratio']},
                   'dependencies': {'type': 'array', 'maxItems': 100, 'uniqueItems': True,
                                    'items': obj({'definitionId': identifier})}}
        if function == LIST:
            anchor = {'anyOf': [identifier, {'type': 'null'}]}
            arguments = obj({'limit': {**revision, 'minimum': 1, 'maximum': _LIST_LIMIT,
                                       'default': _LIST_LIMIT}, 'afterDefinitionId': anchor,
                             **dict.fromkeys(_LIST_REVISIONS, revision)}, [])
            arguments.update({'if': {'required': ['afterDefinitionId'],
                                     'properties': {'afterDefinitionId': identifier}},
                              'then': {'required': list(_LIST_REVISIONS)}})
            required = {**pins, **state, 'status': status, 'definitionMetadataRevision': revision,
                        'metadataCurrent': boolean, 'sourceBuildId': text}
            row = obj({**required, 'stateToken': digest, **summary}, list(required))
            row.update({'if': {'properties': {'programDigest': {'type': 'string'}}},
                        'then': {'required': list(summary)}})
            result = obj({'rows': {'type': 'array', 'maxItems': _LIST_LIMIT, 'items': row},
                          'metadataRevision': revision, 'policyRevision': revision,
                          'hasMore': boolean, 'nextAfterDefinitionId': anchor})
            result.update({'if': {'properties': {'hasMore': {'const': True}}},
                           'then': {'properties': {'rows': {'minItems': 1},
                                                   'nextAfterDefinitionId': identifier}},
                           'else': {'properties': {'nextAfterDefinitionId': {'type': 'null'}}}})
            examples = [read_example(LIST, {'limit': 1}, name='List the first current definition page',
                                     binding='Select the authorized application.'),
                        read_example(LIST, {'limit': 1, 'afterDefinitionId': sample,
                            'expectedMetadataRevision': 1, 'expectedPolicyRevision': 1},
                            name='Continue the calculated-member inventory',
                            binding='Use the previous nextAfterDefinitionId, metadataRevision and policyRevision in the same application.')]
            rules = ['A successful empty page has no nextAfterDefinitionId. A continued page uses the same metadata and policy revisions.',
                     'Inventory rows can describe inactive or unresolved definitions. Compiled definitions carry their target, evaluation mode, unit and dependencies.']
        elif function == READ:
            arguments = obj({'definitionId': identifier})
            definitions = structural_schema_definitions()
            body = obj({'format': {'const': DEFINITION_FORMAT}, 'definitionId': identifier,
                        'name': {'type': 'string', 'minLength': 1, 'maxLength': 200}, **summary,
                        'sourceSelection': {'$ref': '#/$defs/cubeSelection'}, 'expression': {'type': 'object'},
                        'resultKey': text, 'maxSourceCells': {**revision, 'minimum': 1, 'maximum': 1_000_000},
                        'maxOutputCells': {**revision, 'minimum': 1, 'maximum': 100_000}})
            body.update({'if': {'properties': {'evaluation': {'const': 'dynamic'}}},
                         'then': {'properties': {'resultKey': {'type': 'null'}}},
                         'else': {'properties': {'resultKey': {'type': 'string',
                             'pattern': r'^[A-Za-z0-9._-]{8,128}(?![\s\S])'}}}})
            stored = obj({'languageVersion': {'const': 2}, 'function': {'const': STORED_FUNCTION},
                          'arguments': body})
            source = obj({'programId': {'type': 'string'}, 'programSourceToken': text,
                          'sourceDigest': text, 'buildId': text, 'active': boolean})
            required = {**pins, **state, 'program': {'anyOf': [stored, {'type': 'null'}]},
                        'source': {'anyOf': [source, {'type': 'null'}]},
                        'currentMetadataRevision': revision, 'policyRevision': revision,
                        'definitionMetadataRevision': {'anyOf': [revision, {'type': 'null'}]},
                        'updatedOperationId': text, 'updatedAt': text}
            result = obj({**required, 'status': status}, list(required))
            result.update({'if': {'properties': {'defined': {'const': True}}},
                           'then': {'required': ['status'], 'properties': {'stateToken': digest}},
                           'else': {'properties': {name: {'type': 'null'} for name in
                               ('stateToken', 'programDigest', 'program', 'source', 'definitionMetadataRevision',
                                'updatedOperationId', 'updatedAt')}}})
            examples = [read_example(READ, {'definitionId': sample}, name='Inspect one current definition',
                                     binding='Copy definitionId from the current calculated-member inventory.')]
            rules = ['An unknown definition returns defined=false with null owner pins. Read executable, evaluation and the owner pins before requesting work.',
                     'The fixed expression compiler owns the stored expression grammar. The response preserves the current compiled program and its source binding.']
        else:
            raise ValueError('CALCULATED_MEMBER_FUNCTION_INVALID')
    contract = read_contract(function, arguments, result, owner='PostgresCalculatedMembers',
                             examples=examples, semantic_rules=rules, definitions=definitions)
    contract['programContract']['recovery'] = (
        'Refresh current access after an access change. Restart the inventory after a stale page. '
        'Inspect the current definition before retrying an evaluation with new pins.')
    return contract


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
            "result":"current definition and activation state",
            **read_program_contract(READ)},
        LIST:{**common,"mode":"read","permission":"read",
            "idempotencyRequired":False,"arguments":{},
            "optionalArguments":{"limit":"1-100",
                "afterDefinitionId":"stable keyset cursor",
                "expectedMetadataRevision":"cursor metadata revision",
                "expectedPolicyRevision":"cursor policy revision"},
            "result":"bounded current calculated-member definitions",
            **read_program_contract(LIST)},
        EVALUATE:{**common,"mode":"read","permission":"read",
            "idempotencyRequired":False,
            "arguments":{"definitionId":
                "current published dynamic definition"},
            "optionalArguments":{"expectedStateToken":"exact inspected Active definition state",
                "expectedProgramDigest":"exact inspected compiled digest"},
            "result":"bounded typed rows evaluated in one read snapshot",
            **read_program_contract(EVALUATE)},
        MATERIALIZE:{"mode":"durable_calculation","permission":"write",
            "previewRequired":True,"idempotencyRequired":True,
            "workClass":"short",
            "arguments":{"definitionId":"current published materialized definition"},
            "optionalArguments":{"expectedStateToken":"exact inspected Active definition state",
                "expectedProgramDigest":"exact inspected compiled digest"},
            "result":"immutable exact generation and atomic result publication",
            **materialization_program_contract()},
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
        if not isinstance(rule_id,str) or not _LOOKUP_ID.fullmatch(rule_id):
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
        limit=mapped.get("limit",_LIST_LIMIT);after=mapped.get("afterRuleId")
        if (type(limit) is not int or not 1<=limit<=_LIST_LIMIT
                or (after is not None and (not isinstance(after,str)
                                           or not _LOOKUP_ID.fullmatch(after)))
                or any(type(mapped[key]) is not int or mapped[key]<0
                       for key in _LIST_REVISIONS if key in mapped)
                or (after is not None and not set(_LIST_REVISIONS)<=set(mapped))):
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
    LIST_COLLECTION_FORMAT = None
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
        args=parse_evaluation_request(raw,function=function)
        definition_id=args['definitionId']
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
        from .postgres_dimensional_security import CUBE_READ_AUTHORIZATION_STALE
        from .postgres_expression import (compile_expression_program,
            compiler_for,evaluate_dynamic_expression,resolve_published_inputs)
        from .postgres_numeric_store import PostgresNumericFactStore
        from .postgres_processing_limits import configure_statement_timeout

        program,pin=self.prepare_dynamic(scope,raw)
        state_sql = '''SELECT metadata_revision, data_revision, policy_revision,
            commit_revision, schema_epoch, security_revision FROM epm.application_state
            WHERE workspace_id=%s AND application_id=%s'''
        keys = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                create_selected_domain_read_relation(db)
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db,5000)
                PostgresNumericFactStore._set_scope(db,scope)
                authorize = PostgresAccessChecker.check_in_transaction
                opening_access = authorize(db,self.identity,scope,'read',function=EVALUATE)
                state = db.execute(state_sql, keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                inputs=resolve_published_inputs(db,scope,
                    program["arguments"]["expression"])
                plan=compile_expression_program(program,
                    expected_target_state_token=None,
                    published_inputs=inputs,calculated_member=pin)
                verify_calculated_member_pin(
                    db,scope,pin,plan,evaluation="dynamic")
                try:
                    rows=evaluate_dynamic_expression(
                        db,scope,self.identity,plan,expected_access=opening_access)
                except ValueError as reason:
                    if str(reason) == CUBE_READ_AUTHORIZATION_STALE:
                        raise ValueError(EVALUATION_AUTHORIZATION_STALE) from None
                    raise
                compiler,plan_digest=compiler_for(plan)
                if authorize(db,self.identity,scope,'read',function=EVALUATE) != opening_access:
                    raise ValueError(EVALUATION_AUTHORIZATION_STALE)
                if db.execute(state_sql, keys).fetchone() != state:
                    raise ValueError(EVALUATION_SNAPSHOT_STALE)
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


def parse_evaluation_request(raw,*,function):
    """One public evaluation grammar, shared by preparation and prior lookup."""
    if (not isinstance(raw,dict)
            or set(raw)!={"languageVersion","function","arguments"}
            or raw.get("languageVersion")!=2
            or raw.get("function")!=function
            or not isinstance(raw.get("arguments"),dict)
            or set(raw["arguments"]) not in ({"definitionId"},
                {"definitionId","expectedStateToken","expectedProgramDigest"})
            or not isinstance(raw["arguments"]["definitionId"],str)
            or not _LOOKUP_ID.fullmatch(raw["arguments"]["definitionId"])):
        raise ValueError("CALCULATED_MEMBER_EVALUATION_REQUEST_INVALID")
    args=raw['arguments']
    if 'expectedStateToken' in args and any(
            not isinstance(args[key], str) or not _DIGEST.fullmatch(args[key])
            for key in ('expectedStateToken', 'expectedProgramDigest')):
        raise ValueError('CALCULATED_MEMBER_EVALUATION_REQUEST_INVALID')
    return args


def recheck_materialization_run_access(db, identity, scope, opening_access):
    """Require run permission under the same authority used for review or admission."""
    from .postgres_access import PostgresAccessChecker

    if PostgresAccessChecker.check_in_transaction(
            db, identity, scope, 'rule_run', function=MATERIALIZE) != opening_access:
        raise ValueError(REVIEW_AUTHORIZATION_STALE)


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


def create_selected_domain_read_relation(db):
    """Create private membership scratch before the read-only data transaction."""
    db.execute('''CREATE TEMP TABLE IF NOT EXISTS epm_selected_domain_member(
        dimension_id text NOT NULL,member_id text NOT NULL,
        PRIMARY KEY(dimension_id,member_id)) ON COMMIT PRESERVE ROWS''')


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
