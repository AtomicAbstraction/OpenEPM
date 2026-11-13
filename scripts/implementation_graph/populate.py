#!/usr/bin/env python3
"""Explicitly populate missing review content through the graph app's own API.

Never overwrites an existing node overlay and never runs executable tests. This
is not invoked automatically by refresh, so owner edits/deletions stay intact.
"""
import argparse
import ast
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import urllib.request
from functools import lru_cache
from scenarios import SCENARIOS

p=argparse.ArgumentParser(description=__doc__);p.add_argument('--artifact',required=True,type=Path);p.add_argument('--url',required=True);a=p.parse_args()
assert re.fullmatch(r'http://(?:127\.0\.0\.1|localhost):\d+',a.url), 'Local graph URL required'
d=json.loads((a.artifact/'graph.json').read_text());nodes={n['id']:n for n in d['nodes']};adj=defaultdict(list)
for e in d['links']:adj[e['source']].append(e)
current=json.load(urllib.request.urlopen(a.url+'/api/annotations'));state=current['state'];added=0;specs=0;linked=0

def tokens(text):return set(re.findall(r'[a-z]{3,}',text.lower()))-{'test','postgres','core','epm','functionality','planning','consolidation','facts'}
@lru_cache(maxsize=None)
def cases(path):
    text=d['sources'].get(path,'')
    if not path.endswith('.py'):return []
    try:tree=ast.parse(text)
    except SyntaxError:return []
    found=[]
    def visit(parent,prefix=''):
        for n in ast.iter_child_nodes(parent):
            if isinstance(n,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)):
                q=prefix+'.'+n.name if prefix else n.name
                if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name.startswith('test_'):found.append((q,n.lineno,ast.get_docstring(n) or ''))
                visit(n,q)
            else:visit(n,prefix)
    visit(tree);return found

for fid,n in sorted(nodes.items()):
    if n['kind'] not in {'functionality','calculation mechanism'} or fid in state['nodes']:continue
    module_ids=[e['target'] for e in adj[fid] if e['kind'] in {'IMPLEMENTATION_REFERENCES','ASSOCIATED_IMPLEMENTATION','IMPLEMENTED_IN_MODULE'}]
    if n['kind']=='calculation mechanism':
        module_ids+=['file:'+n['path']]
    module_ids=list(dict.fromkeys(module_ids));module_ids.sort(key=lambda id:('postgres_language_v2.py' in nodes[id]['path'],nodes[id]['path'].startswith('web/'),nodes[id]['path']))
    anchors=module_ids[:4];refs=[r['id'] for id in anchors for r in nodes[id].get('entireReferences',[])][:2]
    operations=[nodes[e['target']]['name'] for e in adj[fid] if e['kind']=='GROUPS_OPERATION']
    if n['kind']=='functionality':
        key=fid.split(':',1)[1];title,precondition,action,expected=SCENARIOS[key]
    else:
        key=fid;title='Review '+n['name'].lower();precondition='A disposable fixture exercises the supported contract in '+n['path']+' with current revision/authority pins.';action='Exercise the exact named mechanism and its invalid/stale/bounded variants through the supported application workflow. Source anchor: '+n['path']+':'+str(n['line']);expected=n['notes']+' No unmeasured benefit, production readiness or missing automatic selective engine is asserted.'
    notes='PRECONDITIONS\n'+precondition+'\n\nINPUTS / CONTRACT ANCHORS\n'+('Declared operation names: '+', '.join(operations)+'. ' if operations else '')+'Use explicit typed fixture IDs and current source/policy/layout pins; never shared business instances. Source modules: '+', '.join(nodes[id]['path'] for id in anchors)+'.\n\nACTION\n'+action+'\n\nEXPECTED OUTCOME\n'+expected+'\n\nEVIDENCE STATUS\nAuthored repository-grounded specification. Not implemented by this record, not executed, and not a verified passing run. Related package: '+n.get('package','P10')+'.'
    tests=[dict(id='spec:'+key+':journey:v1',name=title,kind='draft specification',status='Active',path='',notes=notes,entireRefs=refs,
        semanticNodes=[fid]+anchors,comments=[dict(id='comment:scope-v1',text='Draft for owner review. Fixed-core exactness, authorization, application isolation and publication semantics remain acceptance requirements. No test execution is claimed.')],
        author='Codex repository-grounded draft',sourceCommit=d['meta']['commit'])];specs+=1
    candidates=[];query=tokens(n['name']+' '+key)
    for mid in module_ids:
        for association in nodes[mid].get('tests',[]):
            target=nodes.get(association['test'])
            if not target:continue
            for symbol,line,doc in cases(target['path']):
                score=len(query&tokens(target['path']+' '+symbol+' '+doc))+(5 if association['kind']=='RECORDED_TEST_ASSOCIATION' else 0)
                if score:candidates.append((score,target['path'],symbol,line,association))
    seen=set()
    for _,path,symbol,line,association in sorted(candidates,key=lambda c:(-c[0],c[1],c[2])):
        identity='existing:'+hashlib.sha256((path+'::'+symbol).encode()).hexdigest()[:24]
        if identity in seen:continue
        seen.add(identity)
        tests.append(dict(id=identity,name=symbol,kind='existing executable association',status='Active',path=path,entireRefs=refs,
            semanticNodes=[fid]+anchors,notes='EXISTING EXECUTABLE\n'+path+':'+str(line)+' · '+symbol+'\n\nASSOCIATION BASIS\n'+association['confidence']+'; source '+association['path']+':'+str(association['line'])+'.\n\nPRECONDITIONS / INPUTS / ACTION / EXPECTATIONS\nThe named executable case defines its own fixture, actions and assertions in frozen source. Use its qualified disposable harness; do not substitute a direct shared-application operation. This association has not been independently behaviorally reviewed or run by the graph task.',
            comments=[dict(id='comment:association-v1',text='Linked existing case, not a newly implemented or newly passing test. Import/name associations can be wrong; inspect the named source case before relying on blast-radius selection.')],
            author='Codex evidence-linked association',sourceCommit=d['meta']['commit']));linked+=1
        if len(seen)>=2:break
    state['nodes'][fid]=dict(description=n['summary'],tests=tests,hiddenGeneratedTests=[],author='Codex populated review content',sourceCommit=d['meta']['commit']);added+=1
state['snapshotCommit']=d['meta']['commit']
request=urllib.request.Request(a.url+'/api/annotations',method='PUT',headers={'Content-Type':'application/json','Origin':a.url,'If-Match':str(current['revision'])},data=json.dumps(state).encode())
result=json.load(urllib.request.urlopen(request));report=dict(addedSemanticNodes=added,authoredSpecifications=specs,linkedExistingCaseAssociations=linked,revision=result['revision'],snapshot=d['meta']['commit'],noneExecuted=True)
(a.artifact/'population.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
