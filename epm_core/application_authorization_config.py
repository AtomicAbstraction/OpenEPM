"""Wire contracts and pure edits for the application authorization catalogue."""
from copy import deepcopy
import re
from functools import lru_cache

from jsonschema import Draft202012Validator

from .application_authorization_actions import ACTION_SCOPE_KINDS
from . import application_role_templates as templates
from .metadata_read_contract import read_contract, read_example
from .postgres_numeric_catalog import obj, program_schema
from .planning_workflow_policy import policy_identifier_schema


READ = 'security.application.authorization.read'
PREVIEW = 'security.application.authorization.preview'
APPLY = 'security.application.authorization.apply'
INVALID = 'APPLICATION_AUTHORIZATION_CHANGE_INVALID'
REVISION = 'APPLICATION_AUTHORIZATION_REVISION_STALE'
REVIEW = 'APPLICATION_AUTHORIZATION_REVIEW_STALE'
COLLECTIONS = ('roles', 'scopes', 'assignments', 'eligibleGroups')
ID = {'type': 'string', 'pattern':r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}(?![\s\S])'}
REFERENCE = {'type':'string','minLength':1,'maxLength':300,'pattern':r'^[^\x00-\x1f*]+(?![\s\S])'}
NAME = {'type': 'string', 'minLength': 1, 'maxLength': 160, 'pattern':r'^[^\x00-\x1f]+(?![\s\S])'}
REV = {'type': 'integer', 'minimum': 0, 'maximum': 2**63 - 1}
TOKEN = {'type':'string','pattern':r'^[a-f0-9]{64}(?![\s\S])'}
ACTIONS = {'enum': sorted(ACTION_SCOPE_KINDS)}
PRIVILEGE = obj({'action': ACTIONS, 'scopeId': ID})
WORKFLOW_DUTIES = {'type':'array','maxItems':100,'uniqueItems':True,'items':policy_identifier_schema()}
WORKFLOW_DUTY_CHANGES={'type':'array','maxItems':100,'items':obj({'roleId':ID,
                      'addedDuties':WORKFLOW_DUTIES,'removedDuties':WORKFLOW_DUTIES})}
KINDS = {'enum':['entire_application','dimension_tags','exact_object']}
SAVED_VIEW_ID = {'type':'string','pattern':r'^[A-Za-z0-9][A-Za-z0-9._-]{2,127}(?![\s\S])'}
EXACT_SAVED_VIEW = obj({'objectType':{'const':'saved_view'},'objectId':SAVED_VIEW_ID})
SELECTOR = {'oneOf':[obj({}), EXACT_SAVED_VIEW,
    {'type':'object','minProperties':1,'maxProperties':64,'additionalProperties':{
        'type':'array','minItems':1,'maxItems':100,'uniqueItems':True,'items':{'type':'string'}}}]}
FIELDS = {
    'roles': {'roleId':ID,'name':NAME,'actions':{'type':'array','minItems':1,'maxItems':256,
                                                  'uniqueItems':True,'items':ACTIONS}},
    'scopes': {'scopeId':ID,'name':NAME,'scopeKind':KINDS,'selector':SELECTOR},
    'assignments': {'assignmentId':ID,'groupId':REFERENCE,'roleId':ID,
                    'privileges':{'type':'array','minItems':1,'maxItems':256,
                                  'uniqueItems':True,'items':PRIVILEGE}}}
OPERATIONS = {prefix+name:(collection,prefix=='remove')
              for name,collection in (('Role','roles'),('Scope','scopes'),('Assignment','assignments'))
              for prefix in ('put','remove')}
KEY = {'roles':'roleId','scopes':'scopeId','assignments':'assignmentId','eligibleGroups':'groupId'}
CHANGE = {'oneOf': [obj({'op':{'const':op}, **({KEY[kind]:ID} if remove else FIELDS[kind])})
                    for op,(kind,remove) in OPERATIONS.items()]}
for shape in CHANGE['oneOf']:
    if shape['properties']['op']['const']=='putRole':
        shape['properties']['workflowDuties']=WORKFLOW_DUTIES
ADOPT_TEMPLATE = 'adoptRoleTemplate'
OPERATIONS[ADOPT_TEMPLATE]=('roles',False)
TEMPLATE_ID={'type':'string','pattern':r'^[a-z][a-z0-9-]{0,62}(?![\s\S])'}
TEMPLATE_VERSION={'type':'integer','minimum':1,'maximum':999999999}
CHANGE['oneOf'].append(obj({'op':{'const':ADOPT_TEMPLATE},'roleId':ID,'templateId':TEMPLATE_ID,'templateVersion':TEMPLATE_VERSION}))
TEMPLATE_ACTIONS={'type':'array','items':ACTIONS,'maxItems':256,'uniqueItems':True}
TEMPLATE_ORIGIN=obj({'templateId':TEMPLATE_ID,'version':TEMPLATE_VERSION,'upstreamName':NAME,
                     'upstreamActions':TEMPLATE_ACTIONS,'nameOverridden':{'type':'boolean'},
                     'addedActions':TEMPLATE_ACTIONS,'removedActions':TEMPLATE_ACTIONS})
TEMPLATE_DEF=obj({'templateId':TEMPLATE_ID,'version':TEMPLATE_VERSION,'name':NAME,'actions':TEMPLATE_ACTIONS})
CHANGES = {'type':'array','minItems':1,'maxItems':100,'items':CHANGE}
SELECT_ARGS = obj({'collection':{'enum':list(COLLECTIONS)},'limit':{'type':'integer','minimum':1,'maximum':100},
                   'after':REFERENCE,'expectedSnapshot':TOKEN}, [])
SELECT_ARGS['dependentRequired']={'after':['collection','expectedSnapshot'],'expectedSnapshot':['collection']}
WRITE_ARGS = obj({'expectedRevision':REV,'changes':CHANGES})
APPLY_ARGS = obj({'expectedRevision':REV,'changes':CHANGES,'reviewDigest':TOKEN})


@lru_cache(maxsize=3)
def _validator(function):
    return Draft202012Validator(program_schema(function,{READ:SELECT_ARGS,PREVIEW:WRITE_ARGS,APPLY:APPLY_ARGS}[function]))


def compile_config(program):
    if not isinstance(program,dict) or program.get('function') not in (READ,PREVIEW,APPLY):
        raise ValueError(INVALID)
    function=program['function']
    if type(program.get('languageVersion')) is not int or not _validator(function).is_valid(program):
        raise ValueError(INVALID)
    args=program['arguments']
    if any(type(args[key]) is not int for key in ('limit','expectedRevision') if key in args):
        raise ValueError(INVALID)
    seen=set()
    for item in args.get('changes',[]):
        kind,remove=OPERATIONS[item['op']]
        identity=(kind,item[KEY[kind]])
        if identity in seen or any(item[k]!=item[k].strip() for k in ('name','groupId') if k in item):
            raise ValueError(INVALID)
        seen.add(identity)
        if item['op']==ADOPT_TEMPLATE and type(item['templateVersion']) is not int:
            raise ValueError(INVALID)
        if kind=='scopes' and not remove:
            _check_selector(item['scopeKind'],item['selector'])
    return args


def _check_selector(kind, selector):
    if kind=='entire_application':
        if selector: raise ValueError(INVALID)
    elif kind=='dimension_tags':
        if (not selector or any(not dimension or dimension != dimension.strip() or len(dimension)>200
                or any(ord(c)<32 for c in dimension) or not isinstance(tags,list)
                or not 1<=len(tags)<=100 or any(not isinstance(tag,str)
                or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,19}',tag) is None for tag in tags)
                or len(set(tags))!=len(tags) for dimension,tags in selector.items())):
            raise ValueError(INVALID)
    elif (set(selector)!={'objectType','objectId'} or selector['objectType'] != 'saved_view'
          or not isinstance(selector['objectId'],str)
          or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{2,127}',selector['objectId']) is None):
        raise ValueError(INVALID)


def covers(ceiling, requested):
    if ceiling['scopeKind']=='entire_application':
        return True
    if ceiling['scopeKind']!=requested['scopeKind']:
        return False
    if requested['scopeKind']=='dimension_tags':
        # Selecting another axis grants visibility on that axis. For facts it
        # can also exchange an untagged axis for a protected population.
        return ceiling['selector'].keys() == requested['selector'].keys() and all(
                   set(requested['selector'][axis]) <= set(tags)
                   for axis,tags in ceiling['selector'].items())
    return ceiling['selector']==requested['selector']


def desired_state(before, changes):
    after=deepcopy(before)
    changed={kind:[] for kind in FIELDS}
    for item in changes:
        kind,remove=OPERATIONS[item['op']]
        key=item[KEY[kind]]
        prior=before[kind].get(key)
        if remove:
            if prior is None: raise ValueError('APPLICATION_AUTHORIZATION_REFERENCE_UNAVAILABLE')
            del after[kind][key]
        else:
            proposed=(templates.adopt(item,prior) if item['op']==ADOPT_TEMPLATE else
                      {name:deepcopy(item[name]) for name in FIELDS[kind]})
            if kind=='roles':
                proposed['actions'].sort()
                proposed['workflowDuties']=sorted(item.get('workflowDuties',(prior or {}).get('workflowDuties',())))
                if proposed['workflowDuties'] and not {'facts.read','facts.write'}.issubset(proposed['actions']):
                    raise ValueError('APPLICATION_AUTHORIZATION_WORKFLOW_WRITE_ROLE_REQUIRED')
                if item['op']!=ADOPT_TEMPLATE:
                    proposed['templateOrigin']=templates.retain_customizations(prior,proposed)
            if kind=='assignments': proposed['privileges'].sort(key=lambda x:(x['action'],x['scopeId']))
            if kind=='scopes' and proposed['scopeKind']=='dimension_tags':
                proposed['selector']={axis:sorted(tags) for axis,tags in proposed['selector'].items()}
            if prior is not None and all(proposed[k]==prior.get(k,[] if k=='workflowDuties' else None) for k in proposed):
                continue
            proposed['revision']=(prior['revision'] if prior else 0)+1
            after[kind][key]=proposed
        changed[kind].append(key)
    for assignment in after['assignments'].values():
        role=after['roles'].get(assignment['roleId'])
        if role is None: raise ValueError('APPLICATION_AUTHORIZATION_ROLE_IN_USE_OR_MISSING')
        for p in assignment['privileges']:
            scope=after['scopes'].get(p['scopeId'])
            if (scope is None or p['action'] not in role['actions']
                    or scope['scopeKind'] not in ACTION_SCOPE_KINDS.get(p['action'],())):
                raise ValueError('APPLICATION_AUTHORIZATION_PRIVILEGE_INVALID')
    return after,changed


def catalog():
    nullable={'type':['string','null']}
    array=lambda item:{'type':'array','items':item,'maxItems':100}
    mode={'enum':['legacy','group_assignments']}
    overview={kind:array(obj({**fields,'revision':REV})) for kind,fields in FIELDS.items()}
    overview['roles']=array(obj({**FIELDS['roles'],'revision':REV,'workflowDuties':WORKFLOW_DUTIES,
                                 'templateOrigin':{'anyOf':[TEMPLATE_ORIGIN,{'type':'null'}]}}))
    overview['roleTemplates']=array(TEMPLATE_DEF)
    overview.update({'eligibleGroups':array(obj({'groupId':REFERENCE,'groupName':nullable,'displayName':nullable})),
                     'canManageRoles':{'type':'boolean'}, 'canManageScopes':{'type':'boolean'},
                     'canManageAssignments':{'type':'boolean'},'canManageWorkflowDuties':{'type':'boolean'},
                     'availableWorkflowDuties':WORKFLOW_DUTIES,'workflowDutiesComplete':{'type':'boolean'},
                     'actions':{'type':'array','items':obj({'action':ACTIONS,'canDelegate':{'type':'boolean'},
                                 'scopeKinds':{'type':'array','items':KINDS}})},
                     'nextAfter':obj({key:nullable for key in COLLECTIONS}),
                     'snapshotToken':TOKEN,'complete':{'type':'boolean'}})
    scope_fields={'workspaceId':{'type':'string'},'applicationId':{'type':'string'}}
    common={**scope_fields,'revision':REV,'authorizationMode':mode}
    impact=obj({'requesterBenefit':requester_benefit_schema(), 'affectedAssignments':{'type':'array','items':ID},
                'changed':obj({key:{'type':'array','items':ID} for key in FIELDS}),
                'reviewedWorkflowDuties':WORKFLOW_DUTY_CHANGES,
                'reviewedRoleTemplates':{'type':'array','items':obj({'roleId':ID,'name':NAME,'priorVersion':{'anyOf':[TEMPLATE_VERSION,{'type':'null'}]},
                    'origin':TEMPLATE_ORIGIN,'actions':TEMPLATE_ACTIONS,'addedActions':TEMPLATE_ACTIONS,'removedActions':TEMPLATE_ACTIONS})}},['affectedAssignments','changed'])
    entries={}
    for function,arguments,result,example in (
        (READ,SELECT_ARGS,obj({**common,**overview}),{'limit':25}),
        (PREVIEW,WRITE_ARGS,obj({**scope_fields,'expectedRevision':REV,'reviewDigest':TOKEN,'impact':impact,
                                'authorizationMode':mode,'changes':CHANGES}),
            {'expectedRevision':0,'changes':[{'op':'putRole','roleId':'reader','name':'Reader','actions':['facts.read']}]}),
        (APPLY,APPLY_ARGS,obj({**common,'reviewDigest':TOKEN,'impact':impact,'changed':{'type':'boolean'}}),
            {'expectedRevision':0,'changes':[{'op':'putRole','roleId':'reader','name':'Reader','actions':['facts.read']}],
             'reviewDigest':'0'*64})):
        effect=function==APPLY
        structural=read_contract(function,arguments,result,owner='PostgresAuthorizationConfiguration',
            examples=[read_example(function,example,name=function.rsplit('.',1)[1].title()+' scoped configuration',
                        binding='Read the selected application. Supply its current revision and the exact reviewed change batch.')],
            semantic_rules=['Projection and review use the current authorized scope. A preview has no effects.',
                            'Apply rechecks the caller, delegated scope, group status, references and expected revision.',
                            'A role with facts.read and facts.write can link stable workflow duty IDs declared in the active application planning policy. '
                            'Omit workflowDuties to preserve existing links or supply an empty list to clear them. '
                            'Changing links in the group-assignment model requires access.manage and roles.manage plus existing delegation ceilings. '
                            'A legacy workspace administrator can clear retained links. New links require the group-assignment model. '
                            'A duty applies on a target only through an assignment granting read and write there.'])
        entries[function]={'mode':'atomic_security_write' if effect else 'read','permission':'admin',
                           'previewRequired':False,'idempotencyRequired':effect,'workClass':'short',
                           'arguments':list(arguments['properties']),'result':'application authorization configuration',
                           **structural}
        if effect:
            entries[function]['idempotencyScope']='workspace security-operation namespace with exact application and actor'
    return entries


def requester_benefit_schema():
    reasons = ['new_application_entry','new_grant_path','potential_scope_expansion','additional_grant_path']
    # Receipts may outlive the period in which an action is assignable.
    grant = obj({'assignmentId':ID,'groupId':REFERENCE,'roleId':ID,'action':ID,
                 'scopeId':ID,'scopeRevision':REV,'scopeKind':KINDS,'selector':SELECTOR,
                 'reason':{'enum':reasons}})
    grant['properties']['expandedPrerequisite']=ID
    grant['properties'].update(previousWorkflowDuties=WORKFLOW_DUTIES,reviewedWorkflowDuties=WORKFLOW_DUTIES,
                               previousDutyScope=obj({'scopeKind':KINDS,'scopeRevision':REV,'selector':SELECTOR}))
    return obj({'classification':{'enum':['none',*reasons]}, 'applicationEntry':{'enum':['admitted','requires_entry']},
                'grantsComplete':{'type':'boolean'},'grants':{'type':'array','items':grant}})
