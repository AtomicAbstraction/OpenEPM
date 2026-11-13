#!/usr/bin/env python3
"""Validate actual artifact integrity and abstraction/provenance boundaries."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('artifact',type=Path);a=p.parse_args();root=a.artifact
d=json.loads((root/'graph.json').read_text());receipt=json.loads((root/'receipt.json').read_text())
assert hashlib.sha256((root/'index.html').read_bytes()).hexdigest()==receipt['htmlSha256']
assert hashlib.sha256((root/'graph.json').read_bytes()).hexdigest()==receipt['graphSha256']
assert hashlib.sha256((root/'entire.snapshot.ndjson.gz').read_bytes()).hexdigest()==receipt['snapshotSha256']
nodes={n['id']:n for n in d['nodes']};assert len(nodes)==len(d['nodes'])
assert all(n['kind'] not in {'variable','statement','expression','table','index','trigger','policy','database table'} for n in nodes.values())
assert all(not id.startswith('local/') for id in nodes), 'Raw Entire IDs cannot define main semantic nodes'
assert all('entireReferences' in n for n in nodes.values())
assert any(n['entireReferences'] for n in nodes.values())
for path,text in d['sources'].items():
    assert hashlib.sha256(text.encode()).hexdigest()==d['sourceHashes'][path],path
for n in nodes.values():
    if n['path']:
        assert n['path'] in d['sources'],n['id']
        assert 1<=n['line']<=len(d['sources'][n['path']].splitlines())+1,(n['id'],n['line'])
    if n['kind']=='operation':assert 'interfaces' in n
for e in d['links']:
    assert e['source'] in nodes and e['target'] in nodes
    assert e['certainty'] in {'syntax','heuristic','association','recorded'}
    if e['path']:
        assert e['path'] in d['sources'],e
        assert e['line']>=1
    assert nodes[e['source']]['kind'] not in {'database terminal','external package','standard library'},e
    if e['kind'].startswith('TEST_'):assert e['certainty']=='heuristic'
    if e['kind'] in {'GROUPS_OPERATION','ASSOCIATED_IMPLEMENTATION','IMPLEMENTATION_REFERENCES'}:assert e['certainty']=='association'
    if e.get('provenance') in {'INFERRED','AMBIGUOUS'}:assert e['certainty']=='heuristic'
assert nodes['database:duckdb']['status']=='gated analytical accelerator; production disabled'
assert nodes['database:postgresql']['status']=='authoritative transactional store'
assert any(e['kind']=='GATED_ACCELERATOR_REFERENCE' for e in d['links'])
assert d['meta']['wholeRebuildComplete'] is False
assert not d['meta']['fallbackFunctionalityLabels'],d['meta']['fallbackFunctionalityLabels']
result={'passed':True,'snapshot':d['meta']['commit'],'nodes':len(nodes),'edges':len(d['links']),'functionsAndMethods':sum(n['kind'] in {'function','method'} for n in nodes.values()),'checks':['hash receipts','source bytes and locations','no dangling edges','terminal external boundaries','function-level floor','inference/association distinctions','UI/MCP per-operation fields','disabled acceleration','honest completion status']}
(root/'validation.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
