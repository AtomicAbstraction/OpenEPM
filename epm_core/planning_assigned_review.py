"""Pure public contract for assignment-bound sequential review."""
import re

SUBMIT='planning.slice.submit.assigned';REVIEW='planning.slice.review'
REOPEN='planning.slice.assigned.reopen';READ='planning.slice.assigned.read'
FUNCTIONS=(SUBMIT,REVIEW,REOPEN,READ)
PUBLIC_SUBMIT='cube.write.scope.submit.assigned'
PUBLIC_REVIEW='cube.write.scope.review'
PUBLIC_REOPEN='cube.write.scope.assigned.reopen'
PUBLIC_READ='cube.write.scope.assigned.read'
PUBLIC_FUNCTIONS=(PUBLIC_SUBMIT,PUBLIC_REVIEW,PUBLIC_REOPEN,PUBLIC_READ)
PUBLIC_TO_LEGACY=dict(zip(PUBLIC_FUNCTIONS,FUNCTIONS))
LEGACY_TO_PUBLIC={value:key for key,value in PUBLIC_TO_LEGACY.items()}
ALL_FUNCTIONS=FUNCTIONS+PUBLIC_FUNCTIONS
_ID=re.compile(r'[A-Za-z0-9][A-Za-z0-9._:@/-]{0,299}\Z')
_KEY=re.compile(r'[A-Za-z0-9._-]{8,128}\Z');_LOCK=re.compile(r'[0-9a-f]{32}\Z');_DIGEST=re.compile(r'[0-9a-f]{64}\Z')

def scope_overlaps_selectors(scope_members,selectors):
 """Omitted scope axes are wildcards; explicit conflicts are disjoint."""
 return all(axis not in scope_members or scope_members[axis] in allowed
            for axis,allowed in selectors)

def issuer_bound_principal_matches(expected_issuer,identity_issuer,subject_id,
                                   groups,subjects,assigned_groups):
 return (identity_issuer==expected_issuer and
         (subject_id in subjects or bool(set(groups)&set(assigned_groups))))

def catalog():
 legacy={
  SUBMIT:{'mode':'assigned_workflow_write','permission':'write','requiredCapabilities':[],'previewRequired':True,'idempotencyRequired':True,'workClass':'short','arguments':{'scopeMembers':'exact assignment-covered scope','scopeAll':'must be false','assignmentSetId':'active immutable set','assignmentVersion':'active version','assignmentDigest':'canonical digest','assignmentId':'effective assigned item','expectedControlVersion':'CAS','reason':'audit reason','idempotencyKey':'request key'},'result':'locked assigned submission and first reviewer'},
  REVIEW:{'mode':'assigned_workflow_write','permission':'read','requiredCapabilities':[],'previewRequired':True,'idempotencyRequired':True,'workClass':'short','arguments':{'lockId':'assigned submission','expectedWorkflowVersion':'CAS','action':'Approve or Return','reason':'audit reason','idempotencyKey':'request key'},'result':'advanced, approved or returned workflow'},
  REOPEN:{'mode':'assigned_workflow_write','permission':'admin','requiredCapabilities':[],'previewRequired':True,'idempotencyRequired':True,'workClass':'short','arguments':{'lockId':'approved assigned submission','expectedWorkflowVersion':'CAS','reason':'audit reason','idempotencyKey':'request key'},'result':'authorized reopen and unlocked slice'},
     READ:{'mode':'read','permission':'read','requiredCapabilities':[],'previewRequired':False,'idempotencyRequired':False,'workClass':'short','arguments':{'lockId':'assigned submission'},'result':'assignment snapshot, chain, progress and events'}}
 return {**legacy,**{public:{**legacy[old],
  'privateCompatibilitySource':old} for public,old in PUBLIC_TO_LEGACY.items()}}

def compile_program(raw):
 if not isinstance(raw,dict) or set(raw)!={'languageVersion','function','arguments'} or raw.get('languageVersion')!=2 or raw.get('function') not in ALL_FUNCTIONS or not isinstance(raw.get('arguments'),dict):raise ValueError('V2_ASSIGNED_REVIEW_FUNCTION_INVALID')
 f=PUBLIC_TO_LEGACY.get(raw['function'],raw['function']);a=raw['arguments']
 expected=({'scopeMembers','scopeAll','assignmentSetId','assignmentVersion','assignmentDigest','assignmentId','expectedControlVersion','reason','idempotencyKey'} if f==SUBMIT else {'lockId'} if f==READ else {'lockId','expectedWorkflowVersion','action','reason','idempotencyKey'} if f==REVIEW else {'lockId','expectedWorkflowVersion','reason','idempotencyKey'})
 if f==READ:
  if set(a)!=expected or not isinstance(a['lockId'],str) or not _LOCK.fullmatch(a['lockId']):raise ValueError('ASSIGNED_REVIEW_READ_INVALID')
  return {'function':f,'lockId':a['lockId']}
 if set(a)!=expected or not isinstance(a['reason'],str) or not 1<=len(a['reason'])<=500 or '\0' in a['reason'] or not isinstance(a['idempotencyKey'],str) or not _KEY.fullmatch(a['idempotencyKey']):raise ValueError('V2_ASSIGNED_REVIEW_ARGUMENTS_INVALID')
 n={'function':f,'reason':a['reason'],'idempotencyKey':a['idempotencyKey']}
 if f==SUBMIT:
  if a['scopeAll'] is not False or not isinstance(a['scopeMembers'],dict) or not a['scopeMembers'] or len(a['scopeMembers'])>32 or any(not _ID.fullmatch(k) or not _ID.fullmatch(v) for k,v in a['scopeMembers'].items()):raise ValueError('ASSIGNED_REVIEW_SCOPE_INVALID')
  if any(not isinstance(a[x],str) or not (_DIGEST if x=='assignmentDigest' else _ID).fullmatch(a[x]) for x in ('assignmentSetId','assignmentDigest','assignmentId')) or type(a['assignmentVersion']) is not int or a['assignmentVersion']<1 or type(a['expectedControlVersion']) is not int or a['expectedControlVersion']<0:raise ValueError('ASSIGNED_REVIEW_ASSIGNMENT_INVALID')
  n.update({k:a[k] for k in ('assignmentSetId','assignmentVersion','assignmentDigest','assignmentId','expectedControlVersion')});n['scopeMembers']=dict(sorted(a['scopeMembers'].items()));n['scopeAll']=False
 elif f==REVIEW:
  if not isinstance(a['lockId'],str) or not _LOCK.fullmatch(a['lockId']) or type(a['expectedWorkflowVersion']) is not int or a['expectedWorkflowVersion']<1 or a['action'] not in ('Approve','Return'):raise ValueError('ASSIGNED_REVIEW_TRANSITION_INVALID')
  n.update({k:a[k] for k in ('lockId','expectedWorkflowVersion','action')})
 else:
  if not isinstance(a['lockId'],str) or not _LOCK.fullmatch(a['lockId']) or type(a['expectedWorkflowVersion']) is not int or a['expectedWorkflowVersion']<1:raise ValueError('ASSIGNED_REVIEW_TRANSITION_INVALID')
  n.update({k:a[k] for k in ('lockId','expectedWorkflowVersion')})
 return n
