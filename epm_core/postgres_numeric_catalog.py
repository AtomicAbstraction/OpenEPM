"""Self-contained discovery contracts for existing ordered numeric operations.

Schemas describe wire structure. Cross-statement, type, metadata, authority and
work-budget rules stay enforced by the unchanged fixed compilers and core.
"""
from copy import deepcopy

SEQUENCE='facts.numeric.sequence'
ITERATE='facts.numeric.iterate'
SAVE='rules.numeric_sequence.save'
PUBLISH='rules.numeric_sequence.activate'
READ='rules.numeric_sequence.read'
LIST='rules.numeric_sequence.list'
RUN='rules.numeric_sequence.run'
RULE_ID={'type':'string','pattern':'^[A-Za-z0-9._-]{1,100}$'}
PARAM_NAME={'type':'string','pattern':'^[A-Za-z][A-Za-z0-9_]{0,63}$'}
ID={'type':'string','minLength':1}
COUNT={'type':'integer','minimum':1}
REVISION={'type':'integer','minimum':0}
DECIMAL={'type':'string','description':'Finite exact decimal string; no JSON number. Amount: at most20 integer digits/8 fractional places. Ratio:8/12. Fixed compiler validates Decimal exponent/range; canonical plain decimal recommended.'}


def obj(properties,required=None):
    return {'type':'object','properties':properties,'required':list(properties) if required is None else required,'additionalProperties':False}


def node(op,properties=None):
    return obj({'op':{'const':op},**(properties or {})})


def definitions(template=False):
    expression={'$ref':'#/$defs/expression'}
    nodes=[node(op) for op in ('CurrentAmount','CurrentPresent')]
    nodes += [node(op,{'statementIndex':{'type':'integer','minimum':0}}) for op in ('StatementAmount','StatementPresent')]
    nodes += [node(op,{'decimal':DECIMAL}) for op in ('AmountLiteral','RatioLiteral')]
    nodes += [node(op,{'left':expression,'right':expression}) for op in ('Add','Subtract','Multiply','Divide')]
    nodes += [node('Compare',{'operator':{'enum':['eq','ne','lt','le','gt','ge']},'left':expression,'right':expression}),
              node('If',{'test':expression,'then':expression,'else':expression})]
    values=[obj({'type':{'const':'AmountLiteral'},'decimal':DECIMAL}),
            obj({'type':{'const':'StatementValue'},'statementIndex':{'type':'integer','minimum':0}}),
            obj({'type':{'const':'NumericExpression'},'expression':expression})]
    member=deepcopy(ID)
    if template:
        nodes.append(node('Parameter',{'name':PARAM_NAME}))
        values.append(obj({'type':{'const':'AmountParameter'},'name':PARAM_NAME}))
        member={'oneOf':[ID,obj({'type':{'const':'MemberParameter'},'name':PARAM_NAME})]}
    coordinate={'type':'object','minProperties':1,'propertyNames':ID,'additionalProperties':member}
    common={'coordinate':coordinate}
    if not template:common['expectedChangeId']={'type':'string','maxLength':200}
    variants=[]
    for op in ('set','add','clear'):
        fields={**common,'op':{'const':op}}
        if op!='clear':fields['value']={'$ref':'#/$defs/value'}
        variants.append(obj(fields,['coordinate','op']+(['value'] if op!='clear' else [])))
    return {'expression':{'oneOf':nodes},'value':{'oneOf':values},
        'statement':{'oneOf':variants},'statements':{'type':'array','minItems':1,'maxItems':500,'items':{'$ref':'#/$defs/statement'}}}


def program_schema(function,arguments,defs=None):
    return {'$schema':'https://json-schema.org/draft/2020-12/schema',
        **obj({'languageVersion':{'type':'integer','const':2},'function':{'const':function},'arguments':arguments}),
        **({'$defs':defs} if defs is not None else {})}


def argument_schema(function):
    if function in (SEQUENCE,ITERATE):
        fields={'statements':{'$ref':'#/$defs/statements'},'rounding':{'const':'half_even_8'}}
        required=['statements']
        if function==ITERATE:
            fields['convergence']=obj({'mode':{'const':'absolute_delta'},
                'tolerance':obj({'type':{'const':'AmountLiteral'},'decimal':DECIMAL}),
                'maxIterations':{'type':'integer','minimum':1,'maximum':128},'onNonConvergence':{'const':'fail'}})
            required=list(fields)
        return program_schema(function,obj(fields,required),definitions())
    state_token={'type':'string','pattern':'^[0-9a-f]{64}$'}
    fields={'ruleId':RULE_ID,'expectedMetadataRevision':REVISION,
        'expectedPolicyRevision':REVISION}
    if function==SAVE:
        parameter={'oneOf':[{'enum':['amount','ratio']},obj({'type':{'const':'member'},
            'dimensionId':{'type':'string','minLength':1,'maxLength':200},
            'sampleMemberId':{'type':'string','minLength':1,'maxLength':200}})]}
        fields['definition']=obj({'statements':{'$ref':'#/$defs/statements'},'rounding':{'const':'half_even_8'},
            'parameters':{'type':'object','maxProperties':8,'propertyNames':PARAM_NAME,'additionalProperties':parameter}},['statements'])
        fields['expectedStateToken']=state_token
        return program_schema(function,obj(fields,[key for key in fields
            if key!='expectedStateToken']),definitions(True))
    if function==PUBLISH:
        fields['expectedStateToken']=state_token
        return program_schema(function,obj(fields))
    if function==READ:return program_schema(function,obj({'ruleId':RULE_ID}))
    if function==LIST:
        fields={'limit':{'type':'integer','minimum':1,'maximum':100},'afterRuleId':RULE_ID,
                'expectedMetadataRevision':REVISION,'expectedPolicyRevision':REVISION}
        args=obj(fields,[]);args['dependentRequired']={'afterRuleId':['expectedMetadataRevision','expectedPolicyRevision']}
        return program_schema(function,args)
    if function==RUN:
        return program_schema(function,obj({'ruleId':RULE_ID,'bindings':{'type':'object','maxProperties':8,
            'propertyNames':PARAM_NAME,'additionalProperties':{'type':'string','minLength':1,'maxLength':200}}},['ruleId']))
    raise ValueError('UNKNOWN_NUMERIC_CATALOG_FUNCTION')


WIRE_RULES=[
 'Unknown object fields are rejected. Counts/revisions/statement indices/languageVersion are strict JSON integers, never booleans or decimal-number tokens such as1.0. Schemas validate structure; the fixed compiler/core remains authoritative.',
 'A coordinate maps every active fact dimension except modelRole Currency to one active stable member ID. No omitted axes, wildcards, display names, implicit member sets or invented financial axes. Discover metadata in the target application.',
 'On each distinct full coordinate the first statement requires current numeric expectedChangeId, even for Clear; subsequent touches must omit it. Empty string means no numeric event has ever existed, not a previously cleared tombstone. Refresh current IDs and preview for a new intent.',
 'Statement indices are zero-based and strictly earlier than the referring statement; the whole ordered array shares history across coordinates. StatementValue/StatementAmount require a present earlier output; StatementPresent safely tests presence. Clear yields missing; Set zero remains present. Add on missing starts at zero.',
 'NumericExpression requires explicit rounding half_even_8. Omitting rounding supports only outer AmountLiteral and StatementValue under the original compiler. Clear has no value; Set/Add require an amount-valued result.',
 'AmountLiteral/CurrentAmount/StatementAmount are amount; RatioLiteral is ratio; CurrentPresent/StatementPresent are boolean. Current nodes read that coordinate at this statement, including earlier touches. Missing amount reads fail unless guarded by a selected If branch.',
 'Add/Subtract require equal numeric types. Multiply permits amount×ratio, ratio×amount or ratio×ratio; amount×amount is rejected. Divide permits amount/ratio→amount, ratio/ratio→ratio, amount/amount→ratio; ratio/amount is rejected. Zero or missing evaluated denominators fail. Compare requires equal numeric types and permits exact dynamic division in either operand.',
 'If requires a boolean test and same numeric type for then/else. Both branches must be structurally/type valid; only the selected branch propagates runtime missing/division errors. No standalone boolean literals or logical operators exist in this profile.',
 'Each NumericExpression has at most64 nodes and depth12 (root depth0); a typed program has at most2048 expression/value nodes excluding per-statement Publish instructions and500 statements. Every statement result must fit NUMERIC(28,8), even if subsequently cleared.',
 'Typed arithmetic uses exact rational PostgreSQL stages; half-even rounding is once at each statement boundary including existing target for Add. Later statements see that rounded amount. SourceAmount, SourceValue, PublishedAmount, SQL, Python, callbacks and arbitrary executable code are unsupported here.',
]
SAVED_RULES=[
 'Saved definitions contain statements plus optional parameters/rounding; authored expectedChangeId and convergence are forbidden. Server obtains current first-touch CAS IDs set-wise at run preview. Saved versions never become iterative implicitly.',
 'Declare at most8 parameters; names start with an ASCII letter and continue ASCII letters/digits/underscore up to64 characters. Every declaration must be used; no undeclared reference. amount/ratio declarations bind exact decimal strings; member declarations require type:member, dimensionId, active sampleMemberId.',
 'MemberParameter {type:MemberParameter,name} is allowed only as a coordinate value and its declared dimensionId must equal that axis. Runtime member binding is an active ID in that same dimension, trimmed/non-NUL,1–200 characters; sampleMemberId validates authoring, not a runtime default.',
 'AmountParameter {type:AmountParameter,name} is an outer statement value only for an amount declaration. Parameter {op:Parameter,name} is an expression leaf of its declared amount/ratio type. No member-expression parameter, code substitution or partial coordinate substitution.',
 'Run bindings must match all and only declared parameter names; no defaults. Values cross the wire as strings. Numeric bindings satisfy amount20/8 or ratio8/12 ranges; member bindings satisfy their dimension. Fetch the current definition with rules.numeric_sequence.read to learn its declarations.',
 'Save creates one current definition or replaces it with the exact inspected state token and current metadata/policy revisions; sample numeric parameters compile as1 and member samples must be active. Activate requires the current state token, advances policy revision, and requires a separate publish grant. Run needs current write+rule_run and the current Active definition; authoring needs write+rule_design.',
 'Rule IDs are1–100 ASCII letters/digits/dot/underscore/hyphen. Definition kind cannot change; expression and ordered current read/list are separate. A LIST continuation requires both pinned metadata/policy revisions and afterRuleId; limit defaults100.',
]
ITERATION_RULES=[
 'Require explicit half_even_8 and convergence:{mode:absolute_delta,tolerance:{type:AmountLiteral,decimal:nonnegative amount string},maxIterations:strict integer1–128,onNonConvergence:fail}. No best-effort final publication.',
 'Each previous-final target vector seeds next initial state. Earlier statement indices reset per iteration; Current nodes still see preceding same-iteration writes. No implicit prior-iteration StatementAmount or external source node.',
 'Every final target presence must equal its iteration-initial presence and every present amount absolute delta must be<=tolerance in exact PostgreSQL arithmetic. Missing and present zero differ; final rather than intermediate statement values determine convergence.',
 'At declared maxIterations reject more than8192 executed statement effects,32768 instructions including Publish, or16MB expanded normalized program.20s computation/staged-publication budget inherits shorter tool/lease time; SQL stages at most5s. This does not certify outer commit acknowledgement or all background DNS/process limits.',
 'Nonconvergent preview returns admissionAllowed:false, diagnostics, errorCode NUMERIC_ITERATION_NOT_CONVERGED and no previewToken. It cannot admit work. Success returns signed token, finalValues and per-iteration presenceChanges/maxAbsoluteDelta; worker result retains convergence report and all executed events atomically.',
]
EXECUTION={
 'previewTool':'preview_v2_program','submitTool':'submit_v2_program','jobTool':'read_v2_job','cancelTool':'cancel_v2_job',
 'scope':'application listener is bound; router tools additionally require workspace_id/application_id',
 'submission':'Send unchanged program + preview_token from current preview + unique idempotency_key; optional depends_on_job_ids. Use durable jobId to poll. Do not execute statement/iteration loops in the client.',
 'snapshot':'Preview writes no data. New admission and publication recheck grants, revisions, CAS, active metadata, planning locks and claim. Re-preview on stale input; never silently rewrite an accepted intent.',
 'replay':'Same verified identity/application/key/program/dependency order returns original job without rebasing, even after preview expiry; current write/run authority still required. Changed intent under an existing key conflicts. Cancellation cannot undo committed publication.',
 'publication':'All statement events/final cells/receipt/revision/published-job result commit atomically. A failed/cancelled/stale worker cannot publish partial effects.',
}

SOURCE_OWNED_REPLACEMENT={
 'ownerKind':'ApplicationRule',
 'authoring':'Author reviewed Python source returning ApplicationRule with a NumericSequence checkpoint; discover the current Python program contract and permitted source lifecycle in this application.',
 'bindingDiscovery':[
     {'view':'functions','function':'application.state.read'},
     {'view':'functions','function':'python.environment.list'},
     {'view':'functions','function':'python.environment.read'},
     {'view':'functions','function':'facts.cube.scan'}],
 'revisionPins':{'expectedMetadataRevision':'metadataRevision',
     'expectedPolicyRevision':'policyRevision','expectedSchemaEpoch':'schemaEpoch'},
 'environmentPins':{'environmentId':'environment_id','environmentStateToken':'state_token'},
 'environmentBinding':'Use one reviewed Active row from the current registered environment reads. If those reads are unavailable under your grant, obtain the binding from an application administrator.',
 'rawCoordinateArguments':{'includeMissing':True,'limit':1},
 'coordinateBinding':'Pass the full exact coordinate as members to facts.cube.scan. Take numericChangeId from a matching authorized row, including a cleared row. An empty page alone does not prove a coordinate has no prior numeric event.',
 'authoringDiscovery':[
     {'view':'functions','function':'python.program.save'},
     {'view':'functions','function':'python.program.activate'}],
 'validationReview':{'statusTool':'read_v2_python_program_build',
     'buildIdFromSave':'$.result.validation.buildId','buildIdArgument':'build_id',
     'requiredStatus':'sealed','artifactTool':'read_v2_python_program_build_artifact',
     'artifactSection':'PlanSummary'},
 'lifecycle':'Save queues Validation. Read and review the exact build before activation. Refresh the application revision pins and use the reviewed validationBuildId and current source state token. Inspect the activated rule and use separate run admission.',
 'inspection':'Use the permitted application.rule list/read/run contracts for the source-owned rule. Find ordered rules with the inspection filter, then inspect each rule before requesting an authorized run.',
 'inspectionFilter':{'containsOperation':'facts.numeric.sequence'},
 'inspectionDiscovery':[
     {'view':'functions','function':'application.rule.list'},
     {'view':'functions','function':'application.rule.read'}],
 'runDiscovery':{'view':'functions','function':'application.rule.run'},
 'runOutcome':{
     'discovery':{'view':'functions','function':'application.rule.run.read'},
     'workflowIdFromRun':'$.result.workflowId',
     'guidance':('Keep the exact admitted run program and signed operation ID. Read the outcome by workflow ID, or use the original request if the acknowledgement is lost. '
                 'Check the recorded status and committed checkpoints before reporting publication. An unavailable outcome remains unresolved.'),
 },
 'semantics':'Review the full coordinate, typed parameter declarations, ordered statements and checkpoint boundaries. NumericSequence requires explicit first-touch expected_change_id; empty means no prior numeric event, not a previously cleared value.',
 'automaticMigration':False,
 'identity':'A legacy sequence ID, bindings or state token does not identify an ApplicationRule. Do not translate or copy them implicitly. Reauthoring requires deliberate review; legacy automatic runtime CAS is not reproduced by source authoring.',
 'history':'Existing routes, stored references and historical execution records remain. This guidance does not retire them, claim migration complete or authorize replay as new work.',
}


def examples():
    def wire(fn,args):return {'languageVersion':2,'function':fn,'arguments':args}
    point={'Metric':'A'}
    ordered=wire(SEQUENCE,{'statements':[
        {'coordinate':point,'op':'set','expectedChangeId':'','value':{'type':'AmountLiteral','decimal':'100'}},
        {'coordinate':point,'op':'add','value':{'type':'AmountLiteral','decimal':'5'}},
        {'coordinate':{'Metric':'B'},'op':'set','expectedChangeId':'','value':{'type':'StatementValue','statementIndex':1}},
        {'coordinate':point,'op':'clear'}]})
    expression={'op':'Add','left':{'op':'AmountLiteral','decimal':'100'},'right':{'op':'Multiply',
        'left':{'op':'If','test':{'op':'CurrentPresent'},'then':{'op':'CurrentAmount'},'else':{'op':'AmountLiteral','decimal':'0'}},
        'right':{'op':'RatioLiteral','decimal':'0.1'}}}
    iterative=wire(ITERATE,{'statements':[{'coordinate':point,'op':'set','expectedChangeId':'',
        'value':{'type':'NumericExpression','expression':expression}}],'rounding':'half_even_8',
        'convergence':{'mode':'absolute_delta','tolerance':{'type':'AmountLiteral','decimal':'0.00000001'},
            'maxIterations':16,'onNonConvergence':'fail'}})
    template={'parameters':{'Target':{'type':'member','dimensionId':'Metric','sampleMemberId':'A'},'Seed':'amount','Rate':'ratio'},
        'rounding':'half_even_8','statements':[
            {'coordinate':{'Metric':{'type':'MemberParameter','name':'Target'}},'op':'set','value':{'type':'AmountParameter','name':'Seed'}},
            {'coordinate':{'Metric':{'type':'MemberParameter','name':'Target'}},'op':'add',
             'value':{'type':'NumericExpression','expression':{'op':'Multiply','left':{'op':'CurrentAmount'},'right':{'op':'Parameter','name':'Rate'}}}}]}
    typed_ordered=deepcopy(iterative);typed_ordered['function']=SEQUENCE;typed_ordered['arguments'].pop('convergence')
    nonconvergent=deepcopy(iterative)
    nonconvergent['arguments']['convergence']['maxIterations']=1
    prerequisite=('A separate disposable application for this example: exactly one active fact axis Metric '
        '(Custom), active members A and B, and no numeric events or supporting detail at either coordinate. '
        'Current write authority includes these full coordinates, current read authority permits inspection, and planning scope is open. '
        'These are explicit fixture conditions, not default product metadata or an application mode. The operation is a generic primitive. Empty expectedChangeId means no prior event; '
        'a cleared tombstone does not satisfy it. Discover the actual full fact grain and current change IDs before rebinding another application.')
    return {SEQUENCE:[{'id':'ordered-literal-reference-clear','program':ordered,
                'prerequisites':prerequisite,
                'expectedFinal':{'A':None,'B':'105.00000000'},
                'expectedPreview':{'statementCount':4,'targetCount':2},
                'expectedPublished':{'statementCount':4,'changedCount':2}},
            {'id':'ordered-typed-guard','program':typed_ordered,'prerequisites':prerequisite,
                'expectedFinal':{'A':'100.00000000'},
                'expectedPreview':{'statementCount':1,'targetCount':1},
                'expectedPublished':{'statementCount':1,'changedCount':1}}],
        ITERATE:[{'id':'bounded-recurrence','program':iterative,'prerequisites':prerequisite,
                'expectedFinal':{'A':'111.11111111'},'expectedIterations':11,
                'expectedPreview':{'converged':True,'admissionAllowed':True,'executedStatementCount':11},
                'expectedPublished':{'statementCount':11,'iterationStatementCount':1,'changedCount':1}},
            {'id':'bounded-recurrence-does-not-converge','program':nonconvergent,'prerequisites':prerequisite,
                'expectedPreview':{'converged':False,'admissionAllowed':False,'iterations':1,
                    'executedStatementCount':1,'errorCode':'NUMERIC_ITERATION_NOT_CONVERGED',
                    'diagnostics':[{'iteration':1,'presenceChanges':1,'maxAbsoluteDelta':'0.00000000'}]},
                'expectedEvaluatedFinal':{'A':'100.00000000'},
                'expectedPublication':'None; no signed preview or job is created by preview, and nonconvergence cannot admit publication.'}],
        SAVE:[{'id':'saved-typed-template','program':wire(SAVE,{'ruleId':'plan.example','definition':template,
            'expectedMetadataRevision':3,'expectedPolicyRevision':0})}],
        PUBLISH:[{'id':'activate-template','program':wire(PUBLISH,{'ruleId':'plan.example','expectedStateToken':'a'*64,'expectedMetadataRevision':3,'expectedPolicyRevision':0})}],
        READ:[{'id':'read-template','program':wire(READ,{'ruleId':'plan.example'})}],
        LIST:[{'id':'list-templates','program':wire(LIST,{'limit':10})}],
        RUN:[{'id':'run-typed-template','program':wire(RUN,{'ruleId':'plan.example','bindings':{'Target':'A','Seed':'100','Rate':'0.25'}}),
            'expectedFinal':{'A':'125.00000000'}}]}


def _program_contract(function, rules, samples):
    return {'version':1,'validationScope':'JSON Schema wire structure plus required semanticRules; fixed compiler/core is authoritative',
            'programSchema':argument_schema(function),'semanticRules':rules,'examples':samples[function],
            'examplePrerequisites':{'warning':'Synthetic examples; never run blindly in an existing business application.',
                'application':'Separate fresh blank application for each data example; saved lifecycle examples share one fresh application. Consolidation disabled.',
                'metadata':[{'function':'metadata.dimension.create','arguments':{'dimensionId':'Metric','name':'Metric','modelRole':'Custom','expectedMetadataRevision':0}},
                            {'function':'metadata.member.create','arguments':{'dimensionId':'Metric','memberId':'A','name':'A','expectedMetadataRevision':1}},
                            {'function':'metadata.member.create','arguments':{'dimensionId':'Metric','memberId':'B','name':'B','expectedMetadataRevision':2}}],
                'snapshot':'Metadata revision3/policy0; no prior numeric events. Saved examples run save→publish→read/list→run; save/publish revisions are examples, use actual current revisions.',
                'authority':'Current write; saved lifecycle also needs separate design/publish/run grants. Reader can inspect saved read/list, not execute writes.'}}


def direct_program_contract(function, samples):
    """Return the owner descriptor for direct ordered or iterative execution."""
    from . import postgres_numeric_iteration, postgres_numeric_sequence

    if function == SEQUENCE:
        owner = postgres_numeric_sequence
        rules = WIRE_RULES
    elif function == ITERATE:
        owner = postgres_numeric_iteration
        rules = WIRE_RULES + ITERATION_RULES
    else:
        raise ValueError('DIRECT_NUMERIC_PROGRAM_FUNCTION_INVALID')
    contract = _program_contract(function, rules, samples)
    contract['execution'] = deepcopy(EXECUTION)
    contract.update(owner.output_contract())
    contract['examplePrerequisites'] = {
        'warning':'Each example declares a complete isolated fixture; do not run blindly in an existing business application.',
        'binding':'Discover the target application, active full fact grain, members, current numeric change IDs and current authority. Replace every illustrative coordinate and first-touch change ID together; never omit an active fact axis.',
        'state':'Run each example independently from its declared empty numeric history. Metadata and policy revision numbers are server-pinned by preview, not universal constants.',
        'workflow':'Inspect the preview and its exact amounts/diagnostics; only a convergent iteration returns a token. Obtain current operation admission and submit the unchanged program, preview and original operation identity. Poll the returned jobId; verify publication before treating preview amounts as stored facts.'}
    contract['execution']['admission']='Transport operation admission remains required. Native matching-job replay after signed preview expiry does not promise acceptance of an expired outer admission token.'
    contract['execution']['recovery']='Preserve the original program, ordered dependencies, verified identity, operation key and known jobId. Read that job and its receipt under current authority before retrying an unknown outcome; never create a new operation to guess whether the first committed.'
    contract['execution']['history']='Current stage schemas describe current direct execution only. Authorized historical reads preserve stored result/provenance, without re-enabling unsupported saved owners or asserting cross-version resubmission compatibility.'
    return contract


def enrich(catalog):
    """Add guidance only; never change dispatch, grants, compilers or definitions."""
    samples=examples()
    for function in (SEQUENCE, ITERATE):
        catalog['functions'][function]['programContract'] = direct_program_contract(function, samples)
    for function in (SAVE,PUBLISH,READ,LIST,RUN):
        rules=SAVED_RULES+WIRE_RULES if function==SAVE else SAVED_RULES
        contract=_program_contract(function, rules, samples)
        if function==RUN:contract['execution']=deepcopy(EXECUTION)
        else:contract['execution']={'tool':'execute_v2_expression_rule_program' if function in (SAVE,PUBLISH) else 'read_v2_program',
            'scope':'Router additionally needs workspace_id/application_id; bound application listener does not.',
            'submission':'Authoring/publication needs program + unique idempotency_key, no preview; reads need only program.',
            'effects':'Save replaces the current inactive definition; activate permits it to run and advances policy revision, but never runs data calculations.'}
        if function in (SAVE,PUBLISH,READ,LIST,RUN):
            from .postgres_saved_numeric_sequence import current_owner_availability
            availability=current_owner_availability()
            catalog['functions'][function]['availability']=availability
            contract['replacement']=deepcopy(SOURCE_OWNED_REPLACEMENT)
            if availability['status']=='unsupported':
                code=('APPLICATION_FUNCTION_RETIRED' if function in (SAVE,PUBLISH)
                      else availability['code'])
                contract['semanticRules']=[
                    'The saved-template current owner is unsupported. Function registration and a valid wire shape do not make this lifecycle available.',
                    'Schemas and example programs preserve legacy request interpretation only. They are not a working save/activate/read/list/run tutorial. Current public save and activate are retired.',
                    'No ApplicationRule alias, synthetic empty list, automatic parameter conversion or new legacy owner is provided. Follow the source-owned replacement guidance deliberately.',
                    'Current authorization still applies. Historical operation/job evidence uses its existing authorized read/replay contract; this availability marker does not grant access or authorize new work.',
                ]
                contract['examples']=[{**{key:value for key,value in sample.items()
                    if key not in ('expectedFinal','expectedIterations')},
                    'expectedError':code,'purpose':'legacy wire shape; unavailable current lifecycle'}
                    for sample in samples[function]]
                contract['examplePrerequisites']={
                    'warning':'Diagnostic wire examples only; no metadata setup can create the unsupported current owner.',
                    'authority':'The application catalogue filters current grants before exposing function contracts.'}
                contract['execution']={
                    'scope':EXECUTION['scope'], 'newExecutionAvailable':False,
                    'diagnostic':code,
                    'history':'Existing authorized historical job and receipt inspection is unchanged; do not reinterpret a legacy request as a new source-owned rule.'}
                catalog['functions'][function]['result']=(
                    'Current lifecycle unavailable: '+code+'. Legacy wire contract retained; '
                    'see programContract.replacement for deliberate source-owned ApplicationRule authoring.')
        catalog['functions'][function]['programContract']=deepcopy(contract)
    return catalog
