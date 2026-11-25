#!/usr/bin/env python3
"""Validate actual artifact integrity and abstraction/provenance boundaries."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from build import evidence_source_bindings

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
register_path = 'docs/enterprise-readiness-acceptance-register.json'
register = json.loads(d['sources'].get(register_path, '{}'))
improvement = d['meta'].get('recordedAcceptance', {}).get('improvementPlan')
assert (improvement is not None) == ('productImprovementAcceptance' in register)
if improvement is not None:
    group = register['productImprovementAcceptance']
    authority = group['authority']
    assert improvement['authority'] == authority
    assert improvement['authoritySha256'] == group['authoritySha256'] == d['sourceHashes'][authority]
    expected_criteria, expected_evidence, expected_retained = set(), set(), set()
    statuses, evidence_ids = Counter(), set()
    documents = {n['path']: json.loads(d['sources'][n['path']])
                 for n in nodes.values() if n['kind']=='qualification evidence'}
    bound_files = {path: evidence_source_bindings(value) for path, value in documents.items()}
    assert improvement['workPackages'] == len(group['workPackages'])
    for package in group['workPackages']:
        pid = 'package:' + package['id']
        assert nodes[pid]['status'] == package['status']
        for criterion in package['acceptanceCriteria']:
            cid = 'criterion:' + criterion['id']
            expected_criteria.add((pid, cid))
            statuses[criterion['status']] += 1
            assert nodes[cid]['status'] == criterion['status'] and nodes[cid]['notes'] == criterion['requirement']
            assert nodes[cid]['path'] == register_path
            for reference in criterion['evidence']:
                path = reference['artifactPath']
                eid = 'qualification:' + path
                assert nodes[eid]['evidenceSha256'] == reference['artifactSha256'] == d['sourceHashes'][path]
                expected_evidence.add((cid, eid))
                evidence_ids.add(eid)
                component = documents[path]
                if component['format'] == 'openepm-improvement-acceptance-evidence-v1':
                    for retained in component['independentReview'].get('reviewedPackets', []):
                        reviewed_id = 'qualification:' + retained['artifactPath']
                        assert nodes[reviewed_id]['evidenceSha256'] == retained['artifactSha256']
                        evidence_ids.add(reviewed_id)
                        expected_retained.add((eid, reviewed_id))
    assert improvement['criterionStatuses'] == dict(statuses)
    assert improvement['evidenceDocuments'] == len(evidence_ids)
    assert {(e['source'], e['target']) for e in d['links'] if e['kind']=='HAS_ACCEPTANCE_CRITERION'} == expected_criteria
    assert {(e['source'], e['target']) for e in d['links'] if e['kind']=='HAS_RECORDED_EVIDENCE'} == expected_evidence
    assert {(e['source'], e['target']) for e in d['links'] if e['kind']=='REVIEWED_PACKET'} == expected_retained
    for e in d['links']:
        if e['kind'] == 'EVIDENCE_BINDS_SOURCE':
            assert e['certainty'] == 'recorded'
            path = nodes[e['target']]['path']
            expected = bound_files[e['path']][path]
            assert e['expectedSourceSha256'] == expected
            assert e['sourceBindingState'] == ('matches' if expected == d['sourceHashes'][path] else 'changed')
result={'passed':True,'snapshot':d['meta']['commit'],'nodes':len(nodes),'edges':len(d['links']),'functionsAndMethods':sum(n['kind'] in {'function','method'} for n in nodes.values()),'checks':['hash receipts','source bytes and locations','no dangling edges','terminal external boundaries','function-level floor','inference/association distinctions','UI/MCP per-operation fields','disabled acceleration','honest completion status']}
if improvement is not None:
    result['checks'].append('registered improvement criterion, evidence and explicit source bindings')
(root/'validation.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
