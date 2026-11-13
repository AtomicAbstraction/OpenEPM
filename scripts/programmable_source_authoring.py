"""Readable SDK source and public Save → Validation → Activate for sample clients."""
from __future__ import annotations

import asyncio
from base64 import b64decode
from hashlib import sha256
import json
import os


def _expression(node, *, sequence=False):
    kind=node['op']; owner='NumericSequenceExpression' if sequence else 'CubeExpression'
    if kind in ('AmountLiteral','RatioLiteral'):
        if isinstance(node['decimal'],dict) and node['decimal'].get('type')=='ApplicationRuleParameter':
            if not sequence:raise ValueError('SAMPLE_SOURCE_CUBE_PARAMETER_UNSUPPORTED')
            return 'NumericSequenceExpression.parameter('+node['decimal']['name']+'.reference())'
        return ('Amount' if kind=='AmountLiteral' else 'Ratio')+'('+repr(node['decimal'])+')'
    if kind=='SourceAmount':return 'CubeExpression.source_amount()'
    if kind=='TemporalWindow':
        definition=node['definition']
        arguments=[
            'operator='+repr(definition['operator']),
            'period_dimension_id='+repr(definition['periodDimensionId']),
            'reset_group_dimension_id='+repr(node['resetGroupDimensionId']),
            'calendar_version='+repr(definition['calendarVersion']),
            'boundary_policy='+repr(definition['boundaryPolicy']),
            'missing_policy='+repr(definition['missingPolicy']),
        ]
        if 'openingAmount' in node:
            arguments.append('opening_amount='+repr(node['openingAmount']))
        return (_expression(node['source'],sequence=sequence)+
                '.temporal_window('+', '.join(arguments)+')')
    if kind=='SourceValue':
        arguments=[repr(node['memberOverrides'])]
        if node.get('valueType','amount')!='amount':
            arguments.append('value_type='+repr(node['valueType']))
        if node.get('measureDimensionId') is not None:
            arguments.append('measure_dimension_id='+repr(
                node['measureDimensionId']))
        return 'CubeExpression.source_value('+', '.join(arguments)+')'
    if kind=='StatementAmount':return f"NumericSequenceExpression.statement_amount({node['statementIndex']})"
    if kind=='Parameter':return f"{owner}.parameter({node['name']}.reference())"
    operators={'Add':'+','Subtract':'-','Multiply':'*','Divide':'/'}
    if kind in operators:
        return '('+_expression(node['left'],sequence=sequence)+' '+operators[kind]+' '+_expression(node['right'],sequence=sequence)+')'
    raise ValueError('SAMPLE_SOURCE_EXPRESSION_UNSUPPORTED:'+kind)


def _literal(value):
    if isinstance(value,dict):
        if value.get('type')=='ApplicationRuleParameter':
            return value['name']+'.reference().to_wire()'
        return '{'+', '.join(repr(k)+': '+_literal(v) for k,v in value.items())+'}'
    if isinstance(value,list):return '['+', '.join(_literal(v) for v in value)+']'
    return repr(value)


def _dimension_selection(item):
    include=item['include'];kind=include['kind'];dimension=repr(item['dimensionId'])
    if kind=='member':
        node=f"DimensionSelection.member({dimension}, {include['memberId']!r})"
    elif kind=='members':
        node='DimensionSelection.members('+dimension+', '+', '.join(
            map(repr,include['memberIds']))+')'
    elif kind=='member_list':
        node=(f"DimensionSelection.member_list({dimension}, {include['listId']!r}, "
              f"parameters={_literal(include.get('parameters',{}))})")
    elif kind=='hierarchy':
        node=(f"DimensionSelection.hierarchy({dimension}, {include['hierarchyId']!r}, "
              f"{include['memberId']!r}, operator={include['operator']!r}, "
              f"include_self={include.get('includeSelf',False)!r})")
    elif kind=='inline_expression':
        if include.get('expressionFormat')!='openepm-member-list-expression-v1':
            raise ValueError('SAMPLE_SOURCE_SELECTION_FORMAT_UNSUPPORTED')
        node=(f"DimensionSelection.expression({dimension}, "
              f"MemberListExpression({_literal(include['expression'])}))")
    else:
        raise ValueError('SAMPLE_SOURCE_SELECTION_UNSUPPORTED:'+kind)
    if item.get('exclude') is not None:
        node+='.excluding('+_literal(item['exclude'])+')'
    return node


def calculated_member_source(definition):
    selections=[]
    for item in definition['sourceSelection']['dimensions']:
        selections.append('        '+_dimension_selection(item)+',')
    dependencies='('+''.join(f"CalculatedMemberDependency({item['definitionId']!r}), "
                            for item in definition.get('dependencies',[]))+')'
    return ('from openepm import Amount, Ratio, CalculatedMember, CalculatedMemberDependency, CubeExpression, CubeSelection, DimensionSelection, MemberListExpression\n\n'
        'def build(context, parameters):\n'
        '    selected = CubeSelection(context.metadata_revision, (\n'+'\n'.join(selections)+'\n    ))\n'
        f"    return CalculatedMember({definition['definitionId']!r}, {definition['name']!r},\n"
        f"        {definition['target']['dimensionId']!r}, {definition['target']['memberId']!r}, {definition['evaluation']!r},\n"
        f"        selected, {_expression(definition['expression'])}, {definition['resultUnit']!r},\n"
        f"        result_key={definition['resultKey']!r}, dependencies={dependencies}, max_source_cells={definition['maxSourceCells']},\n"
        f"        max_output_cells={definition['maxOutputCells']})\n")


def application_rule_source(rule_id,definition):
    lines=['from openepm import (Amount, Ratio, ApplicationRule, ApplicationRuleParameter,',
           '    NumericSequence, NumericSequenceExpression, StatementValue, CubeExpression)',
           '', 'def build(context, parameters):',f'    rule = ApplicationRule({rule_id!r})']
    for parameter in definition.get('parameters',[]):
        name=parameter['name']
        if not name.isidentifier():raise ValueError('SAMPLE_SOURCE_PARAMETER_IDENTIFIER_INVALID')
        suffix=(', dimension_id='+repr(parameter['dimensionId'])) if 'dimensionId' in parameter else ''
        lines.extend([f"    {name} = ApplicationRuleParameter({name!r}, {parameter['type']!r}, {parameter['sample']!r}{suffix})",
                      f'    rule = rule.with_parameter({name})'])
    for unit in definition['units']:
        if len(unit['operations'])!=1:raise ValueError('SAMPLE_SOURCE_ATOMIC_UNIT_UNSUPPORTED')
        operation=unit['operations'][0];function=operation['function'];args=operation['arguments']
        if function in ('facts.numeric.batch','facts.numeric.sequence'):
            lines.append('    sequence = NumericSequence()')
            for row in args.get('mutations',args.get('statements',[])):
                value=row.get('value');argument=''
                if value is not None:
                    if value['type']=='AmountLiteral':
                        literal=value['decimal']
                        argument=(', '+literal['name']+'.reference()' if isinstance(literal,dict)
                            and literal.get('type')=='ApplicationRuleParameter' else ', Amount('+repr(literal)+')')
                    elif value['type']=='ApplicationRuleParameter':argument=', '+value['name']+'.reference()'
                    elif value['type']=='StatementValue':argument=f", StatementValue({value['statementIndex']})"
                    elif value['type']=='NumericExpression':argument=', '+_expression(value['expression'],sequence=True)
                    else:raise ValueError('SAMPLE_SOURCE_NUMERIC_VALUE_UNSUPPORTED')
                if 'expectedChangeId' in row:argument+=', expected_change_id='+repr(row['expectedChangeId'])
                lines.append(f"    sequence = sequence.{row['op']}({_literal(row['coordinate'])}{argument})")
            lines.append(f"    rule = rule.then_numeric_sequence(sequence, checkpoint_name={unit['name']!r})")
        else:
            # The SDK has no typed text writer or parameterized source-member-set
            # expression helper. Use its generic primitive constructor only here.
            lines.append('    # This primitive has no equivalent typed SDK helper.')
            arguments=dict(args)
            expression=arguments.pop('expression',None)
            literal=_literal(arguments)
            if expression is not None:literal=literal[:-1]+", 'expression': "+_expression(expression)+'.to_wire()}'
            lines.append(f"    rule = rule.then({function!r}, {literal}, checkpoint_name={unit['name']!r})")
    return '\n'.join([*lines,'    return rule',''])


def _program(function,arguments):
    return {'languageVersion':2,'function':function,'arguments':arguments}


async def state_pins(call,scope):
    state=(await call('read_v2_program',{**scope,'program':_program('application.state.read',{})}))['result']
    return {'expectedMetadataRevision':state['metadataRevision'],
            'expectedPolicyRevision':state['policyRevision'],'expectedSchemaEpoch':state['schemaEpoch']}


async def stable_state_pins(call,scope):
    """Fence activation after asynchronous validation publication settles."""
    previous=await state_pins(call,scope)
    unchanged=0
    for _ in range(120):
        await asyncio.sleep(.25)
        current=await state_pins(call,scope)
        if current==previous:
            unchanged+=1
            if unchanged==2:return current
        else:
            unchanged=0
        previous=current
    raise RuntimeError('SAMPLE_APPLICATION_STATE_DID_NOT_SETTLE')


async def active_environment(call,scope,*,key_prefix):
    """Select only an administrator-approved deployment profile; never invent one."""
    profiles=(await call('read_v2_program',{**scope,'program':_program('python.environment.profile.list',{})}))['result']['profiles']
    requested=os.environ.get('EPM_SAMPLE_PYTHON_PROFILE_ID')
    matches=[p for p in profiles if requested is None or p['profileId']==requested]
    if len(matches)!=1:raise RuntimeError('SAMPLE_APPROVED_PYTHON_PROFILE_REQUIRED')
    profile=matches[0];key={'environmentId':profile['environmentId']}
    found=(await call('read_v2_program',{**scope,'program':_program('python.environment.read',{'environmentId':key['environmentId']})}))['result']
    if not found.get('defined'):
        args={'environmentId':key['environmentId'],'profileId':profile['profileId'],
              **await state_pins(call,scope)}
        registered=(await call('execute_v2_python_program_registry',{**scope,'program':_program('python.environment.register',args),
            'idempotency_key':key_prefix+'-environment'})
        )['result']
        key['environmentStateToken']=registered['stateToken']
    elif found['environment']['status']!='Active':
        raise RuntimeError('SAMPLE_PYTHON_ENVIRONMENT_MISMATCH')
    else:
        environment=found['environment']
        token=environment.get('stateToken',environment.get('state_token'))
        if not isinstance(token,str):
            raise RuntimeError('SAMPLE_PYTHON_ENVIRONMENT_TOKEN_MISSING')
        key['environmentStateToken']=token
    return key


async def wait_build(call,scope,build_id):
    for _ in range(480):
        result=await call('read_v2_python_program_build',{**scope,'build_id':build_id})
        if result['status']=='sealed':return result
        if result['status'] in ('failed','cancelled','expired'):
            raise RuntimeError('SAMPLE_SOURCE_VALIDATION_FAILED:'+json.dumps({key:result.get(key) for key in ('status','errorCode','diagnostics')},sort_keys=True))
        await asyncio.sleep(.25)
    else:raise RuntimeError('SAMPLE_SOURCE_VALIDATION_TIMEOUT')


async def read_artifact(call,scope,build_id,section):
    chunks=[];cursor=None;digest=None;size=0
    for _ in range(256):
        page=await call('read_v2_python_program_build_artifact',{
            **scope,'build_id':build_id,'section':section,'cursor':cursor})
        if digest is not None and page['sectionDigest']!=digest:
            raise RuntimeError('SAMPLE_ARTIFACT_IDENTITY_CHANGED')
        digest=page['sectionDigest'];chunk=b64decode(page['chunkBase64'],validate=True)
        size+=len(chunk)
        if size>16*1024*1024:raise RuntimeError('SAMPLE_ARTIFACT_LIMIT')
        chunks.append(chunk);cursor=page['nextCursor']
        if cursor is None:break
    else:raise RuntimeError('SAMPLE_ARTIFACT_PAGE_LIMIT')
    raw=b''.join(chunks)
    if sha256(raw).hexdigest()!=digest:raise RuntimeError('SAMPLE_ARTIFACT_DIGEST_MISMATCH')
    return json.loads(raw)


async def save_named_selection(call,scope,*,definition,key_prefix):
    """Save and activate inert selection metadata through ordinary public commands."""
    from scripts.provision_programmable_uat_sample_contents import _exact_replay
    pins=await state_pins(call,scope)
    saved=(await _exact_replay(call,'execute_v2_metadata_program',{
        **scope,'program':_program('metadata.member_list.save',{
            'definition':definition,'expectedMetadataRevision':pins['expectedMetadataRevision'],
            'expectedPolicyRevision':pins['expectedPolicyRevision']}),
        'idempotency_key':key_prefix+'-save'},key_prefix+'-save'))['result']
    pins=await state_pins(call,scope)
    active=(await _exact_replay(call,'execute_v2_metadata_program',{
        **scope,'program':_program('metadata.member_list.activate',{
            'listId':definition['listId'],'expectedStateToken':saved['stateToken'],
            'expectedMetadataRevision':pins['expectedMetadataRevision'],
            'expectedPolicyRevision':pins['expectedPolicyRevision']}),
        'idempotency_key':key_prefix+'-activate'},key_prefix+'-activate'))['result']
    return {'saved':saved,'activated':active}


async def author_and_validate(call,scope,*,program_id,source,key_prefix,declared_output,environment=None,
                              parameter_schema=None,definition_parameters=None,
                              for_activation=False):
    """Save current readable source and complete Validation/Test without activation."""
    from scripts.provision_programmable_uat_sample_contents import _exact_replay
    environment=environment or await active_environment(call,scope,key_prefix=key_prefix)
    definition={'format':'openepm-current-python-source-v1',
          'programId':program_id,'sourceText':source,'entryPoint':'build',
          'parameterSchema':parameter_schema or {},'declaredOutput':declared_output,
          **environment}
    current=(await call('read_v2_program',{**scope,
        'program':_program('python.program.read',{'programId':program_id})}))['result']
    exact=(current.get('defined') is True
        and current.get('sourceText')==source
        and current.get('sourceDigest')==sha256(source.encode()).hexdigest()
        and current.get('entryPoint')=='build'
        and current.get('parameterSchema')==(parameter_schema or {})
        and current.get('declaredOutput')==declared_output
        and current.get('environmentId')==environment['environmentId']
        and current.get('environmentStateToken')==environment['environmentStateToken'])
    reusable_validation=(current.get('validation') if exact else None)
    reusable=(definition_parameters is None
        and isinstance(reusable_validation,dict)
        and reusable_validation.get('status')=='sealed'
        and reusable_validation.get('current') is True
        and isinstance(reusable_validation.get('buildId'),str)
        # Activation admission is deliberately time bounded.  The public
        # source read reports revision/source currentness, but an otherwise
        # current sealed build can still be older than the activation window.
        # Re-save an inactive exact source to request a fresh Validation build;
        # active executable sources remain resumable without source churn.
        and (not for_activation or (current.get('status')=='Active'
            and current.get('active') is True
            and current.get('executable') is True)))
    if reusable:
        saved=current
    else:
        args={'definition':definition,**await stable_state_pins(call,scope)}
        if current.get('defined') is True:
            token=current.get('stateToken')
            if not isinstance(token,str):
                raise RuntimeError('SAMPLE_CURRENT_SOURCE_STATE_INVALID')
            args['expectedStateToken']=token
        saved=(await _exact_replay(call,'execute_v2_python_program_registry',{
            **scope,'program':_program('python.program.save',args),'idempotency_key':key_prefix+'-save'},key_prefix+'-save'))['result']
    build_id=saved['validation']['buildId']
    if not reusable:
        await wait_build(call,scope,build_id)
    impact=None
    if definition_parameters is not None:
        tested=(await _exact_replay(call,'execute_v2_python_program_build',{
            **scope,'program':_program('python.program.test',{'programId':program_id,
                'programSourceToken':saved['sourceToken'],
                'parameters':{},'definitionParameters':definition_parameters,**await state_pins(call,scope)}),
            'idempotency_key':key_prefix+'-test'},key_prefix+'-test'))['result']
        build_id=tested['buildId']
        await wait_build(call,scope,build_id)
        impact=await read_artifact(call,scope,build_id,'Impact')
        if (impact.get('status')!='complete' or impact.get('businessDataChanged') is not False
                or impact.get('sourceDigest')!=sha256(source.encode()).hexdigest()
                or impact.get('definitionParameters')!=definition_parameters):
            raise RuntimeError('SAMPLE_IMPACT_IDENTITY_MISMATCH')
    current=(await call('read_v2_program',{**scope,'program':_program('python.program.read',{'programId':program_id})}))['result']
    if current['sourceText']!=source or current['sourceDigest']!=sha256(source.encode()).hexdigest():
        raise RuntimeError('SAMPLE_SOURCE_READBACK_MISMATCH')
    return {'saved':saved,'validationBuildId':build_id,
            'sourceDigest':current['sourceDigest'],'current':current,
            **({'impact':impact} if impact is not None else {})}


async def author_and_activate(call,scope,*,program_id,source,key_prefix,declared_output,environment=None,
                              parameter_schema=None,definition_parameters=None):
    from scripts.provision_programmable_uat_sample_contents import _exact_replay
    for attempt in range(6):
        attempt_key=(key_prefix if attempt==0 else
                     key_prefix+'.context-'+str(attempt))
        try:
            prepared=await author_and_validate(call,scope,program_id=program_id,
                source=source,key_prefix=attempt_key,
                declared_output=declared_output,environment=environment,
                parameter_schema=parameter_schema,
                definition_parameters=definition_parameters,for_activation=True)
            current=prepared['current'];build_id=prepared['validationBuildId']
            if (current.get('status')=='Active' and current.get('active') is True
                    and current.get('executable') is True):
                result={key:value for key,value in prepared.items() if key!='current'}
                return {**result,'activated':current}
            activate={'programId':program_id,'expectedStateToken':current['stateToken'],
                      'validationBuildId':build_id,**await stable_state_pins(call,scope)}
            published=(await _exact_replay(call,'execute_v2_python_program_registry',{
                **scope,'program':_program('python.program.activate',activate),
                'idempotency_key':attempt_key+'-activate'},
                attempt_key+'-activate'))['result']
            result={key:value for key,value in prepared.items() if key!='current'}
            return {**result,'activated':published}
        except RuntimeError as error:
            if ('PYTHON_PROGRAM_STALE_CONTEXT' not in str(error)
                    or attempt==5):
                raise
    raise RuntimeError('SAMPLE_SOURCE_ACTIVATION_RETRY_EXHAUSTED')
