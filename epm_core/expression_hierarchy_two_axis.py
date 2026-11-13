"""Sealed two-axis hierarchy selection for generic exact reductions."""
from __future__ import annotations

import json,re
from hashlib import sha256
from psycopg.types.json import Jsonb
from .postgres_hierarchies import identifier as hierarchy_identifier
from .expression_hierarchy_member_set import _current_hierarchy

from .postgres_expression import (FUNCTION,
    TWO_AXIS_HIERARCHY_REDUCTION_COMPILER as COMPILER,
    TWO_AXIS_HIERARCHY_REDUCTION_PLAN_DIGEST as PLAN_DIGEST,
    compile_expression_program,decode_expression_program)

MAX_MEMBERS=100; MAX_PRESENT_SOURCES=500; MAX_OUTPUT_GROUPS=1
_ID=re.compile(r'[^\x00]{1,200}\Z'); _KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z')

def _id(value):
    if not isinstance(value,str) or not _ID.fullmatch(value) or value!=value.strip():
        raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_ID_INVALID')
    return value

def _digest(value):
    return sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
        ensure_ascii=False).encode()).hexdigest()

def normalize_request(program):
    if (not isinstance(program,dict) or set(program)!={'languageVersion','function','arguments'}
            or program.get('languageVersion')!=2 or program.get('function')!=FUNCTION
            or not isinstance(program.get('arguments'),dict)):
        raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_PROGRAM_INVALID')
    args=program['arguments']
    if set(args)!={'sourceMembers','expression','reduceSelections','measures','resultKey'}:
        raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_ARGUMENTS_INVALID')
    source=args['sourceMembers']; selections=args['reduceSelections']
    if (not isinstance(source,dict) or len(source)>127
            or not isinstance(selections,list) or len(selections)!=2
            or args.get('measures') not in (['SumAmount','CountPresent'],
                ['AverageAmount','CountPresent'])
            or not isinstance(args.get('resultKey'),str)
            or not _KEY.fullmatch(args['resultKey'])):
        raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_ARGUMENTS_INVALID')
    normalized=[]
    for item in selections:
        if (not isinstance(item,dict) or set(item)-{'hierarchyId'}!={'dimensionId','kind',
                'rootMemberId','membershipSemantics','targetMemberId'}
                or item.get('kind') not in ('Children','Descendants','Leaves')
                or item.get('membershipSemantics')!='UniqueMember'):
            raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_SELECTION_INVALID')
        normalized.append({'dimensionId':_id(item['dimensionId']),'kind':item['kind'],
            'rootMemberId':_id(item['rootMemberId']),
            **({'hierarchyId':hierarchy_identifier(item['hierarchyId'])}
               if 'hierarchyId' in item else {}),
            'membershipSemantics':'UniqueMember','targetMemberId':_id(item['targetMemberId'])})
    normalized.sort(key=lambda item:item['dimensionId'])
    if normalized[0]['dimensionId']==normalized[1]['dimensionId'] or any(
            item['dimensionId'] in source for item in normalized):
        raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_GRAIN_INVALID')
    return {'sourceMembers':dict(sorted((_id(k),_id(v)) for k,v in source.items())),
        'expression':args['expression'],'reduceSelections':normalized,
        'measures':list(args['measures']),'resultKey':args['resultKey']}

def _members(db,scope,item,state):
    current=_current_hierarchy(db,scope,item['dimensionId'],item.get('hierarchyId'))
    if (current is None or current['membership_semantics']!='unique_member'
            or current['metadata_revision']!=state['metadata_revision']
            or ('hierarchyStateToken' in item
                and current['state_token']!=item['hierarchyStateToken'])):
        raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_HIERARCHY_STALE')
    rows=db.execute('''SELECT DISTINCT h.descendant_member_id member_id
        FROM epm.hierarchy_closure h JOIN epm.member m ON
        m.workspace_id=h.workspace_id AND m.application_id=h.application_id
        AND m.dimension_id=h.dimension_id AND m.member_id=h.descendant_member_id
        AND m.status='Active' WHERE h.workspace_id=%s AND h.application_id=%s
        AND h.dimension_id=%s AND h.hierarchy_id=%s AND h.state_token=%s
        AND h.ancestor_member_id=%s
        AND h.min_depth>0 AND (%s<>'Children' OR h.min_depth=1)
        AND (%s<>'Leaves' OR NOT EXISTS (SELECT 1 FROM epm.hierarchy_closure c
          WHERE c.workspace_id=h.workspace_id AND c.application_id=h.application_id
          AND c.dimension_id=h.dimension_id AND c.hierarchy_id=h.hierarchy_id
          AND c.state_token=h.state_token
          AND c.ancestor_member_id=h.descendant_member_id AND c.min_depth>0))
        ORDER BY h.descendant_member_id LIMIT %s''',(scope.workspace_id,
        scope.application_id,item['dimensionId'],current['hierarchy_id'],current['state_token'],item['rootMemberId'],
        item['kind'],item['kind'],MAX_MEMBERS+1)).fetchall()
    values=sorted(row['member_id'] for row in rows)
    if not 1<=len(values)<=MAX_MEMBERS:
        raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_EXPANSION_LIMIT')
    if item['targetMemberId'] in values:
        raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_TARGET_OVERLAP')
    return values,current

def resolve(db,scope,program,state,*,expected_target_state_token):
    request=normalize_request(program)
    axes=db.execute('''SELECT dimension_id,model_role FROM epm.dimension WHERE
        workspace_id=%s AND application_id=%s AND status='Active'
        ORDER BY dimension_id''',(scope.workspace_id,scope.application_id)).fetchall()
    fact=[row['dimension_id'] for row in axes if row['model_role']!='Currency']
    selected={item['dimensionId'] for item in request['reduceSelections']}
    if any(row['dimension_id'] in selected and row['model_role']=='Currency' for row in axes) \
            or set(request['sourceMembers'])!=set(fact)-selected:
        raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_GRAIN_INVALID')
    lookups=[{'dimension_id':axis,'member_id':member}
             for axis,member in request['sourceMembers'].items()]
    lookups.extend({'dimension_id':item['dimensionId'],'member_id':member}
        for item in request['reduceSelections']
        for member in (item['rootMemberId'],item['targetMemberId']))
    unavailable=db.execute('''SELECT 1 FROM jsonb_to_recordset(%s::jsonb)
        i(dimension_id text,member_id text) LEFT JOIN epm.member m ON
        m.workspace_id=%s AND m.application_id=%s
        AND m.dimension_id=i.dimension_id AND m.member_id=i.member_id
        AND m.status='Active' WHERE m.member_id IS NULL LIMIT 1''',(
        Jsonb(lookups),scope.workspace_id,scope.application_id)).fetchone()
    if unavailable:
        raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_MEMBER_UNAVAILABLE')
    sealed=[]; contexts=[]
    for item in request['reduceSelections']:
        values,current=_members(db,scope,item,state)
        sealed.append({'dimensionId':item['dimensionId'],'sourceMemberIds':values,
            'targetMemberId':item['targetMemberId']})
        contexts.append({key:item[key] for key in ('dimensionId','kind','rootMemberId',
            'membershipSemantics','targetMemberId') if key in item} | {
            'hierarchyId':current['hierarchy_id'],
            'hierarchyStateToken':current['state_token'],
            'resolvedMemberIds':values,'membershipDigest':_digest(values)})
    if len(sealed[0]['sourceMemberIds'])*len(sealed[1]['sourceMemberIds'])>MAX_PRESENT_SOURCES:
        raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_EXPANSION_LIMIT')
    context={'format':'hierarchy-two-axis-reduction-v1','selections':contexts,
        'layoutDigest':_digest({'factAxes':fact}),'metadataRevision':state['metadata_revision']}
    explicit={'languageVersion':2,'function':FUNCTION,'arguments':{
        'sourceMembers':request['sourceMembers'],'expression':request['expression'],
        'resultKey':request['resultKey'],'reduceMemberSets':{
            'selections':sealed,'measures':request['measures']}}}
    return compile_expression_program(explicit,
        expected_target_state_token=expected_target_state_token,
        published_inputs=(),two_axis_reduction_context=context)

def validate_admission(program,digest):
    if _digest(program)!=digest:
        raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_DIGEST_MISMATCH')
    plan=decode_expression_program(program)
    if plan.two_axis_reduction_context is None:
        raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_PROGRAM_INVALID')
    return plan

def validate_publication(db,scope,plan):
    context=plan.two_axis_reduction_context
    if context is None:return
    state={'metadata_revision':context['metadataRevision']}
    for item in context['selections']:
        values,_=_members(db,scope,item,state)
        if values!=item['resolvedMemberIds']:
            raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_CONTEXT_STALE')
    axes=db.execute('''SELECT dimension_id FROM epm.dimension WHERE workspace_id=%s
        AND application_id=%s AND status='Active' AND model_role IS DISTINCT FROM
        'Currency' ORDER BY dimension_id''',(scope.workspace_id,scope.application_id)).fetchall()
    if _digest({'factAxes':[row['dimension_id'] for row in axes]})!=context['layoutDigest']:
        raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_CONTEXT_STALE')

def cardinality(db,scope,plan):
    if plan.reduce_member_sets is None: raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_CONTEXT_INVALID')
    selections,_=plan.reduce_member_sets; (a,am,_),(b,bm,_)=selections
    row=db.execute('''SELECT count(*)::bigint present_source_count,
        count(DISTINCT ((c.members-%s::text)-%s::text))::bigint grouped_output_count
        FROM epm.coordinate c JOIN epm.numeric_cell_current n
        USING(workspace_id,application_id,coordinate_id) WHERE c.workspace_id=%s
        AND c.application_id=%s AND n.present AND c.members @> %s::jsonb
        AND c.members->>%s=ANY(%s::text[]) AND c.members->>%s=ANY(%s::text[])''',
        (a,b,scope.workspace_id,scope.application_id,Jsonb(dict(plan.source_members)),
         a,list(am),b,list(bm))).fetchone()
    sources=row['present_source_count']; outputs=row['grouped_output_count']
    if (type(sources) is not int or type(outputs) is not int or not 0<=sources<=500
            or not 0<=outputs<=1 or (sources==0)!=(outputs==0)):
        raise ValueError('EXPRESSION_HIERARCHY_TWO_AXIS_CARDINALITY_LIMIT')
    return {'presentSourceCount':sources,'groupedOutputCount':outputs}
