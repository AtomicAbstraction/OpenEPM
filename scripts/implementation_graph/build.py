#!/usr/bin/env python3
"""Read-only, offline graph assembly. Never imports or executes application code.

Input is a frozen git archive plus an Entire Graph full NDJSON export of the
same commit. Output is an offline viewer, machine-readable graph and receipt.
"""
from __future__ import annotations

import argparse
import ast
from collections import Counter, defaultdict
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
from scenarios import SCENARIOS

REGISTER = 'docs/enterprise-obligation-disposition.json'
REGISTRY = 'epm_core/postgres_capability_contract.py'
VENDOR_SHA = '13088340aad408156064fd120c3bc3a47c93a3cc45b8f132d6284b20e2223be9'
ROOTS = {'epm_core', 'openepm', 'schema', 'scripts', 'web', 'web-ui', 'deploy'}
# Longest matching prefix wins. These are authored navigation associations,
# never asserted business correctness or runtime reachability.
GROUPS = [
 ('facts.planning.driver', 'Build driver-based plans', 'P13'),
 ('facts.planning.seed', 'Seed plans from scenarios', 'P13'),
 ('facts.planning.scenario', 'Copy planning scenarios', 'P13'),
 ('facts.planning.rollup', 'Roll up bottom-up plans', 'P13'),
 ('facts.planning.group', 'Aggregate planning groups', 'P13'),
 ('facts.planning.spread', 'Spread top-down targets', 'P13'),
 ('facts.planning.allocat', 'Allocate planning amounts', 'P13'),
 ('planning.workflow', 'Submit, review and reopen plans', 'P14'),
 ('application.assignment.', 'Assign application work and reviewers', 'P14'),
 ('application.workflow.', 'Coordinate application workflows', 'P14'),
 ('planning.slice', 'Submit, review and reopen planning slices', 'P14'),
 ('planning.', 'Govern planning policies and locks', 'P14'),
 ('facts.source', 'Import and validate source data', 'P12'),
 ('facts.transfer', 'Manage durable data transfers', 'P12'),
 ('facts.export', 'Export fact pages', 'P12'),
 ('facts.cube.aggregate', 'Run durable analytical queries', 'P11'),
 ('facts.cube', 'Explore multidimensional cube data', 'P11'),
 ('facts.projection', 'Reconstruct and clean fact projections', 'P07'),
 ('facts.numeric', 'Write and transform exact numeric facts', 'P07'),
 ('facts.text', 'Write text facts', 'P07'),
 ('facts.line-detail', 'Maintain supporting detail', 'P07'),
 ('facts.generic', 'Maintain generic tables and values', 'P07'),
 ('facts.calculation', 'Read calculated facts and lineage', 'P10'),
 ('facts.expression', 'Calculate typed expressions', 'P10'),
 ('rules.', 'Author and execute current business rules', 'P09'),
 ('metadata.layout', 'Replace populated cube layouts', 'P06'),
 ('metadata.', 'Define dimensions, members and hierarchies', 'P06'),
 ('financial.', 'Configure financial semantics', 'P06'),
 ('calendar.', 'Maintain fiscal calendars', 'P13'),
 ('currency.', 'Manage rates and translate currency', 'P10'),
 ('consolidation.journal', 'Post and reverse manual journals', 'P16'),
 ('consolidation.full', 'Calculate Full-method consolidation', 'P16'),
 ('consolidation.equity.contribution', 'Preview Equity-method contribution', 'P16'),
 ('consolidation.equity', 'Inspect equity rollforwards', 'P17'),
 ('consolidation.proportional', 'Preview Proportional contribution', 'P16'),
 ('consolidation.ownership', 'Manage ownership and consolidation methods', 'P16'),
 ('consolidation.nci', 'Measure and govern non-controlling interests', 'P16'),
 ('consolidation.ic', 'Match and eliminate intercompany balances', 'P17'),
 ('consolidation.acquisition', 'Measure and record acquisitions', 'P17'),
 ('consolidation.disposal', 'Measure disposals', 'P17'),
 ('consolidation.cash_flow', 'Inspect and reconcile cash flow', 'P17'),
 ('consolidation.inventory', 'Inspect inventory unrealized profit', 'P17'),
 ('consolidation.fixed_asset', 'Inspect fixed-asset unrealized profit', 'P17'),
 ('consolidation.cta', 'Bridge currency translation adjustments', 'P16'),
 ('consolidation.period', 'Close and reopen financial periods', 'P16'),
 ('consolidation.statement', 'Reconcile financial statement structure', 'P16'),
 ('consolidation.policy', 'Govern current accounting policies', 'P15'),
 ('consolidation.scope', 'Assess consolidation scope', 'P16'),
 ('python.schedule', 'Schedule published Python programs', 'P25'),
 ('python.program', 'Author, publish, build and run Python programs', 'P25'),
 ('python.environment.', 'Manage Python environment profiles', 'P25'),
 ('schedule.', 'Manage current schedules', 'P08'),
 ('calculation.', 'Inspect and request calculation work', 'P10'),
 ('security.identity.', 'Read the verified current identity', 'P05'),
 ('security.application.', 'Manage application access and dimensional security', 'P05'),
 ('security.workspace.', 'Manage workspace access', 'P05'),
 ('security.rule.', 'Manage access to business rules', 'P05'),
 ('grid.definition.', 'Manage saved grid definitions', 'P06'),
 ('calculated.member.', 'Define and evaluate calculated members', 'P10'),
 ('cube.selection.', 'Preview and seal cube selections', 'P11'),
 ('cube.write.policy.', 'Manage cube write policies', 'P14'),
 ('cube.write.scope.', 'Submit, review and lock cube write scopes', 'P14'),
 ('consolidation.layout.', 'Configure consolidation layouts', 'P16'),
 ('consolidation.method.', 'Inspect and publish consolidation method totals', 'P16'),
 ('execution.', 'Delegate scheduled execution', 'P05'),
 ('application.', 'Manage application state and shared decisions', 'P05'),
]
GROUP_PREFIX_ALIASES = {
 'application.rule.': 'rules.',
 'cube.aggregate.': 'facts.cube.aggregate.',
}
INFRA = [
 ('client', 'Discover and operate through MCP and SDK', 'P18',
  ['openepm', 'epm_core/postgres_mcp', 'epm_core/postgres_http', 'web-ui/src/', 'platform_postgres_']),
 ('auth', 'Authenticate and authorize scoped work', 'P05',
  ['epm_core/postgres_access', 'epm_core/postgres_auth', 'epm_core/postgres_security', 'epm_core/postgres_oidc', 'epm_core/postgres_execution_delegations']),
 ('language', 'Validate and dispatch application-language programs', 'P09',
  ['epm_core/postgres_language_v2.py', 'epm_core/postgres_capability_contract.py', 'epm_core/postgres_composite']),
 ('concurrency', 'Coordinate jobs, leases, fairness and cancellation', 'P08',
  ['epm_core/postgres_job', 'epm_core/postgres_worker', 'epm_core/postgres_sequence_dispatch', 'epm_core/postgres_processing', 'epm_core/postgres_capacity', 'scripts/serve_openepm_postgres_worker.py']),
 ('continuity', 'Back up, restore and recover durable state', 'P27',
  ['scripts/backup_', 'scripts/restore_', 'scripts/export_postgres_recovery', 'scripts/import_postgres_recovery', 'epm_core/postgres_reconstruct', 'epm_core/postgres_recovery', 'epm_core/release_recovery']),
 ('lifecycle', 'Create, reset and retire scoped applications', 'P19',
  ['epm_core/postgres_lifecycle', 'epm_core/postgres_reset', 'epm_core/postgres_provision']),
 ('sandbox', 'Isolate untrusted Python plan builds', 'P25',
  ['epm_core/python_', 'epm_core/postgres_python_', 'openepm/builder_runtime.py']),
 ('release', 'Package and operate a portable Linux release', 'P23',
  ['deploy/', 'epm_core/release_', 'scripts/openepm_', 'scripts/check_postgres_']),
 ('acceleration', 'Gate analytical acceleration by exactness', 'P03',
  ['epm_core/cube_aggregate_', 'epm_core/postgres_cube_aggregate']),
]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def operation_entries(tree):
    """Read registry declarations without reviving private retired operations."""
    declarations = {}
    for statement in tree.body:
        if (isinstance(statement, ast.Assign)
                and isinstance(statement.targets[0], ast.Name)
                and isinstance(statement.value, ast.Call)
                and statement.value.args
                and isinstance(statement.value.args[0], (ast.Tuple, ast.List))):
            declarations[statement.targets[0].id] = statement.value.args[0].elts
    retired = {ast.literal_eval(item)
               for name in ('RETIRED_PUBLIC_FUNCTIONS',
                            'SOURCE_AUTHORING_RETIRED_FUNCTIONS',
                            'CONSOLIDATION_FUNCTIONS')
               for item in declarations.get(name, [])}
    for name, status in (
            ('CORE_FUNCTIONS', 'declared public registry'),
            ('PREPUBLIC_CORE_FUNCTIONS', 'internal lowering only'),
            ('CONTROL_PLANE_FUNCTIONS', 'declared control-plane registry')):
        for literal in declarations.get(name, []):
            operation = ast.literal_eval(literal)
            if operation not in retired:
                yield operation, literal.lineno, status


def render_local_viewer(data_bytes, vendor):
    if digest(vendor) != VENDOR_SHA:
        raise ValueError('Unexpected renderer bytes')
    template = Path(__file__).with_name('viewer.html').read_text()
    safe = data_bytes.decode().replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')
    return template.replace('/*__VENDOR__*/', vendor.decode().replace('</script', '<\\/script')).replace('/*__DATA__*/', safe)


def implementation_path(path):
    return (path.split('/')[0] in ROOTS
            or re.fullmatch(r'platform_postgres_[a-z_]+\.py', path) is not None)


def layer(path):
    if path.startswith(('tests/', 'docs/')) or re.search(r'\.test\.[jt]sx?$', path):
        return 'Evidence'
    if path.startswith('schema/'):
        return 'Database'
    if re.search(r'backup|restore|recovery|reconstruct|projection_rebuild', path):
        return 'Continuity / recovery'
    if re.search(r'worker|dispatch|lease|capacity|processing|job_queue|sequence_dispatch', path):
        return 'Concurrency coordination'
    if path.startswith(('openepm/', 'web/', 'web-ui/')) or re.search(r'mcp|http|oidc', path):
        return 'MCP / client boundary'
    if path.startswith('deploy/'):
        return 'Deployment'
    return 'Core application'


def validate_annotations(data):
    assert isinstance(data,dict) and data.get('format')=='openepm-graph-annotations-v1', 'Invalid annotation format'
    assert isinstance(data.get('nodes'),dict) and len(data['nodes'])<=20000, 'Invalid annotation nodes'
    for id, row in data['nodes'].items():
        assert isinstance(id,str) and 0<len(id)<=2000 and isinstance(row,dict), 'Invalid annotation identity'
        assert isinstance(row.get('description',''),str) and len(row.get('description',''))<=12000
        assert isinstance(row.get('tests',[]),list) and len(row.get('tests',[]))<=200
        assert isinstance(row.get('hiddenGeneratedTests',[]),list) and all(isinstance(x,str) for x in row.get('hiddenGeneratedTests',[]))
        for test in row.get('tests',[]):
            assert isinstance(test,dict) and all(isinstance(test.get(k,''),str) for k in ['id','name','notes','path','kind'])
            assert test.get('kind') in {'draft specification','existing executable association'}
            assert 0<len(test.get('id',''))<=200 and 0<len(test.get('name',''))<=300 and len(test.get('notes',''))<=12000
            assert test.get('status') in {'Active','Inactive'}
            assert isinstance(test.get('entireRefs',[]),list) and len(test.get('entireRefs',[]))<=20 and all(isinstance(v,str) and len(v)<=4000 for v in test.get('entireRefs',[]))
            assert isinstance(test.get('comments',[]),list)
            for comment in test.get('comments',[]):
                assert isinstance(comment,dict) and isinstance(comment.get('id'),str) and isinstance(comment.get('text'),str) and len(comment['text'])<=12000
    return data


def build(snapshot, raw_path, out, assets, annotations=None, base_commit=None):
    out.mkdir(parents=True, exist_ok=True)
    records = [json.loads(line) for line in (gzip.open(raw_path, 'rt') if raw_path.suffix == '.gz' else raw_path.open())]
    header, summary = records[0], records[-1]
    assert summary['record_type'] == 'summary', 'Incomplete Entire export'
    nodes, edges, sources, used_paths = {}, {}, {}, set()
    source_hashes = {}
    for path in sorted(snapshot.rglob('*')):
        if path.is_file() and '.git' not in path.relative_to(snapshot).parts:
            source_hashes[path.relative_to(snapshot).as_posix()] = digest(path.read_bytes())
    for r in records:
        if r.get('record_type') == 'file':
            assert source_hashes.get(r['path']) == r['blob'], 'Snapshot/export mismatch: ' + r['path']

    def source(path):
        if path not in sources and (snapshot / path).is_file():
            sources[path] = (snapshot / path).read_text(errors='replace')
        return sources.get(path, '')

    def node(id, name, kind, path='', line=1, end=None, **kw):
        if id in nodes:
            return id
        if path:
            assert path in source_hashes, path
            used_paths.add(path)
        node_layer = kw.pop('layer', layer(path) if path else 'Functionality')
        nodes[id] = dict(id=id, name=name, kind=kind, layer=node_layer,
                         path=path, line=line, end=end or line, **kw)
        return id

    def edge(a, b, kind, path='', line=1, certainty='syntax', detail='', **kw):
        if a not in nodes or b not in nodes or a == b:
            return
        key = (a, b, kind, path, line)
        edges[key] = dict(source=a, target=b, kind=kind, path=path, line=line,
                          certainty=certainty, detail=detail, **kw)
        if path:
            used_paths.add(path)

    def file_node(path):
        id = 'file:' + path
        if id not in nodes:
            node(id, path, 'module' if path.endswith(('.py', '.js', '.ts', '.tsx')) else 'file', path)
            parts = Path(path).parts[:-1]
            parent = None
            for depth in range(1, len(parts) + 1):
                directory = '/'.join(parts[:depth])
                did = node('folder:' + directory, directory + '/', 'folder', layer=layer(path))
                if parent:
                    edge(parent, did, 'CONTAINS_FOLDER', path)
                parent = did
            if parent:
                edge(parent, id, 'CONTAINS_FILE', path)
        return id

    # Entire code symbols, not its document heading/JSON-key inventory. Do not
    # include heuristic detected routes, channels, similarity or cochange edges.
    entire_ids = {}
    symbols_by_path = defaultdict(list)
    for r in records:
        if r.get('record_type') == 'file':
            path = r['path']
            if implementation_path(path):
                entire_ids[r['id']] = file_node(path)
        elif r.get('record_type') == 'symbol':
            path = r['file_path']
            if not implementation_path(path) or r['kind'] not in {
                    'function', 'method', 'class', 'resource', 'stage'}:
                continue
            id = r['id']
            node(id, r.get('qualified_name') or r['name'], r['kind'], path,
                 r['start_line'], r['end_line'], signature=r.get('signature', ''),
                 extractor='Entire Graph v0.6.0')
            entire_ids[id] = id
            symbols_by_path[path].append(nodes[id])
    rejected = Counter()
    for r in records:
        if r.get('record_type') != 'relation':
            continue
        kind = r['type']
        if kind not in {'CONTAINS', 'DEFINES', 'IMPORTS', 'CALLS', 'CONSTRUCTS', 'EXTENDS', 'INHERITS', 'RESOURCE_DEPENDS_ON'}:
            rejected[kind] += 1
            continue
        if r['from_id'] not in entire_ids or r['to_id'] not in entire_ids:
            continue
        a, b = entire_ids[r['from_id']], entire_ids[r['to_id']]
        ev = r.get('evidence') or [{}]
        path = ev[0].get('file_path') or nodes[a]['path']
        ln = ev[0].get('start_line') or nodes[a]['line']
        exact = r.get('provenance') == 'EXTRACTED' and r.get('resolution') in {'exact', 'import_resolved'}
        edge(a, b, kind, path, ln, 'syntax' if exact else 'heuristic', r.get('reason', ''),
             confidence=r.get('confidence'), resolution=r.get('resolution'),
             provenance=r.get('provenance'), evidence=ev, warnings=r.get('warning_codes', []),
             locationMeaning='reference location reported by Entire' if ev[0].get('start_line') else 'source scope declaration; exact reference line not reported by Entire')

    def owner(path, lineno):
        choices = [s for s in symbols_by_path[path] if s['line'] <= lineno <= s['end']]
        return min(choices, key=lambda s: s['end'] - s['line'])['id'] if choices else file_node(path)

    # Static parsing of literal public registry sets, never runtime import.
    trees, constants, imports = {}, {}, {}
    for path in sorted(source_hashes):
        if implementation_path(path) and path.endswith('.py'):
            tree = ast.parse(source(path), filename=path)
            trees[path] = tree
            c, im = {}, {}
            for n in tree.body:
                if isinstance(n, (ast.Assign, ast.AnnAssign)):
                    try:
                        value = ast.literal_eval(n.value)
                    except (ValueError, TypeError, SyntaxError):
                        continue
                    targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                    for target in targets:
                        if isinstance(target, ast.Name):
                            c[target.id] = value
                elif isinstance(n, ast.ImportFrom):
                    base = path.split('/')[:-1]
                    if n.level:
                        module = '.'.join(base[:len(base) - n.level + 1] + ([n.module] if n.module else []))
                    else:
                        module = n.module or ''
                    for a in n.names:
                        im[a.asname or a.name] = (module.replace('.', '/') + '.py', a.name)
            constants[path], imports[path] = c, im
            module_doc=ast.get_docstring(tree)
            if module_doc:nodes[file_node(path)]['summary']=module_doc.split('\n\n')[0][:1200]
            lexical={}
            def collect_scope(parent,prefix=''):
                for child in ast.iter_child_nodes(parent):
                    if isinstance(child,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                        qualified=prefix+'.'+child.name if prefix else child.name
                        lexical[child.lineno]=qualified;collect_scope(child,qualified)
                    else:collect_scope(child,prefix)
            collect_scope(tree)
            for s in symbols_by_path[path]:
                if s['line'] in lexical:s['sourceQualifiedName']=lexical[s['line']]
            for n in ast.walk(tree):
                if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):
                    doc=ast.get_docstring(n)
                    if doc:
                        for s in symbols_by_path[path]:
                            if s['line']==n.lineno:
                                s['summary']=doc.split('\n\n')[0][:900]

    def value(path, n):
        if isinstance(n, ast.Constant):
            return n.value
        if isinstance(n, ast.Name):
            if n.id in constants[path]:
                return constants[path][n.id]
            if n.id in imports[path]:
                target, name = imports[path][n.id]
                return constants.get(target, {}).get(name)
        return None

    # Actual import declarations establish local modules or external dependency
    # boundaries. They do not prove a dependency is installed or running.
    for path, tree in trees.items():
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                modules = [a.name for a in n.names]
            elif isinstance(n, ast.ImportFrom):
                base = path.split('/')[:-1]
                modules = ['.'.join(base[:len(base)-n.level+1] + ([n.module] if n.module else [])) if n.level else n.module or '']
            else:
                continue
            for module in modules:
                target = module.replace('.', '/') + '.py'
                if target in source_hashes:
                    edge(file_node(path), file_node(target), 'MODULE_IMPORT', path, n.lineno,
                         detail='Exact Python import declaration resolved to this snapshot file.')
                elif module and module.split('.')[0] not in {'epm_core', 'openepm', '__future__'}:
                    package = module.split('.')[0]
                    dep = node('dependency:' + package, package, 'standard library' if package in sys.stdlib_module_names else 'external package',
                               layer='External dependency',
                               qualification='Imported dependency boundary; installation, version and running state not established.')
                    edge(file_node(path), dep, 'IMPORTS_DEPENDENCY', path, n.lineno,
                         detail='Python import syntax: ' + module + '; external implementation is not represented.')

    operations = {}
    for op, line, status in operation_entries(trees[REGISTRY]):
        id = node('operation:' + op, op, 'operation', REGISTRY, line,
                  status=status,
                  qualification='Registry presence does not establish per-application discovery, execution or qualification.',
                  requiredCapability='core / argument-dependent')
        operations[op] = id
        edge(file_node(REGISTRY), id, 'DECLARES_OPERATION', REGISTRY, line)

    # UI literals are wiring evidence, not proof of complete controls/parity.
    for op, oid in operations.items():
        nodes[oid]['interfaces'] = {
            'MCP': {'availability': nodes[oid]['status'], 'verification': 'Individual execution not established by registry presence.'},
            'UI': {'availability': 'No dedicated literal reference found; absence is not a defect.', 'verification': 'Not individually audited.'}}
    browser_sources = [path for path in sorted(source_hashes)
                       if path.startswith('web-ui/src/') and path.endswith(('.ts', '.tsx'))
                       and layer(path) != 'Evidence']
    for path in browser_sources + ['web/postgres-inspector.js', 'web/postgres-inspector.html']:
        text = source(path)
        for op, oid in operations.items():
            hits = list(re.finditer(r'(?<=[\'\"])' + re.escape(op) + r'(?=[\'\"])', text))
            for m in hits:
                line = text.count('\n', 0, m.start()) + 1
                key = 'UI_TEMPLATE_REFERENCE' if path.endswith('.html') else 'UI_OPERATION_REFERENCE'
                edge(oid, owner(path, line), key, path, line,
                     detail='Exact registered-name literal in browser source. A literal reference does not establish a user action or successful UI behavior.')
                ui = nodes[oid]['interfaces']['UI']
                ui['availability'] = 'Browser source literal reference'
                ui.setdefault('references', []).append(dict(path=path,line=line,kind=key))

    # Scoped historical interface evidence: retain the exact artifact and
    # assertions, and explicitly compare its source pins with this snapshot.
    browser_path = 'tests/evidence/p18-lean-browser-real-keycloak-passed-final-v3.json'
    browser_record = json.loads(source(browser_path))
    visual = browser_record.get('planningAssignments', {}).get('visualBrowser', {})
    hashpins = browser_record.get('sourcesSHA256', {})
    changed_pins = [p for p, h in hashpins.items() if source_hashes.get(p) != h]
    harness = 'tests/qualify_planning_browser_real_keycloak.js'
    browser_node = node('verification:rendered-browser', 'Recorded rendered UI / real Keycloak journey',
                        'interface verification', browser_path,
                        status='passed in recorded historical artifact' if browser_record.get('passed') else 'not passed',
                        record=dict(assertions=visual, applicationImage=browser_record.get('applicationImage'),
                                    sourcesChangedSinceEvidence=len(changed_pins), changedPaths=changed_pins,
                                    historicalHarness=harness, harnessPresentInSnapshot=harness in source_hashes,
                                    limitations=browser_record.get('limitations')))
    if harness in source_hashes:
        edge(browser_node,file_node(harness),'EVIDENCE_HARNESS',browser_path,certainty='recorded',detail='Historical harness retained in this snapshot. The recorded assertions were not rerun.')
    browser_assertions = {
        'facts.numeric.batch': ['typedJobSubmitted', 'typedJobReceiptRendered'],
        'cube.write.scope.submit': ['submitStatus', 'readerMutationDenied'],
        'cube.write.scope.approve': ['approveStatus'],
        'cube.write.scope.reopen': ['reopenStatus'],
        'facts.calculation.scan': ['certifiedFullResultAndLineageRendered'],
        'consolidation.full.contribute.certified': ['financialCatalogExposesCertifiedFull', 'genericCatalogHidesCertifiedFull', 'certifiedFullJobStatusRendered'],
    }
    for op, fields in browser_assertions.items():
        if op not in operations:
            continue
        oid = operations[op]
        evidence = {key:visual.get(key) for key in fields}
        nodes[oid]['interfaces']['UI']['verification'] = 'Recorded historical rendered journey; see exact assertions/artifact. Not rerun on this snapshot.'
        nodes[oid]['interfaces']['UI']['recordedAssertions'] = evidence
        edge(oid,browser_node,'RECORDED_UI_JOURNEY',browser_path,certainty='recorded',
             detail='Scoped historical assertion mapping: ' + json.dumps(evidence))

    # Literal declarations, catalog dictionary keys and dispatch equality tests
    # connect dynamic application-language names to actual code owners.
    dispatch_counts = Counter()
    for path, tree in trees.items():
        if path == REGISTRY:
            continue
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign):
                val = value(path, n.value)
                if isinstance(val, str) and val in operations:
                    edge(operations[val], owner(path, n.lineno), 'OPERATION_LITERAL', path, n.lineno,
                         detail='Literal operation-name assignment in this code scope; not a call edge.')
            elif isinstance(n, ast.Dict):
                for key in n.keys:
                    val = value(path, key)
                    if isinstance(val, str) and val in operations:
                        edge(operations[val], owner(path, n.lineno), 'REGISTRY_KEY', path, key.lineno,
                             detail='Resolved operation-name dictionary key. Inspect source for catalog/handler meaning.')
            elif isinstance(n, ast.Compare):
                for operand in [n.left] + n.comparators:
                    val = value(path, operand)
                    if isinstance(val, str) and val in operations:
                        edge(operations[val], owner(path, n.lineno), 'DISPATCH_CHECK', path, n.lineno,
                             detail='Resolved operation name occurs in this comparison. This identifies the containing dispatch/validation scope, not a proven runtime branch target.')
                        dispatch_counts[val] += 1

    # SQL entities merge repeat migrations under one identity. Extract only
    # explicit schema-qualified CREATE/REFERENCES tokens outside SQL comments.
    postgres = node('database:postgresql', 'PostgreSQL', 'database terminal', layer='Database',
                    status='authoritative transactional store',
                    qualification='EPM-owned connection and SQL integration ends here; database internals are opaque.')
    duckdb = node('database:duckdb', 'DuckDB / pg_duckdb', 'database terminal', layer='Database',
                  status='gated analytical accelerator; production disabled',
                  qualification='Qualification/integration code exists. No active production routing or runtime state is asserted.')
    for s in symbols_by_path.get('epm_core/postgres_connection.py', []):
        if s['name'] == 'connect_postgres':
            edge(s['id'], postgres, 'CONNECTS_DATABASE', s['path'], s['line'], detail='Fixed EPM-owned psycopg connection integration; PostgreSQL is authoritative.')
    entity_ids, ddl_blocks, database_entities = {}, [], []
    for path in sorted(source_hashes):
        if not path.startswith('schema/postgres/') or not path.endswith('.sql'):
            continue
        text = source(path)
        clean = re.sub(r'/\*.*?\*/|--[^\n]*', lambda m: '\n' * m[0].count('\n'), text, flags=re.S)
        for m in re.finditer(r'\bCREATE\s+(?:OR\s+REPLACE\s+)?(TABLE|VIEW|FUNCTION)\s+(?:IF\s+NOT\s+EXISTS\s+)?(epm\.[a-zA-Z_][\w]*)', clean, re.I):
            name, kind = m[2], m[1].lower()
            line = clean.count('\n', 0, m.start()) + 1
            id = postgres
            entity_ids[name] = postgres
            database_entities.append(dict(name=name, kind=kind, path=path, line=line))
            edge(file_node(path), postgres, 'DDL_DECLARATION', path, line, detail=kind + ' ' + name + '; entity evidence only, no database internals expansion.')
            end = clean.find(';', m.end())
            ddl_blocks.append((id, path, clean[m.end():end if end >= 0 else len(clean)], line))
    unresolved_sql = Counter()
    for path, tree in trees.items():
        for n in ast.walk(tree):
            if not isinstance(n, ast.Constant) or not isinstance(n.value, str):
                continue
            # SQL-looking literal only; docs/error messages are not SQL edges.
            if not re.search(r'\b(SELECT|INSERT|UPDATE|DELETE|FROM|JOIN|CALL)\b', n.value, re.I):
                continue
            for name in sorted(set(re.findall(r'\bepm\.[a-zA-Z_]\w*', n.value))):
                if name in entity_ids:
                    edge(owner(path, n.lineno), entity_ids[name], 'SQL_LITERAL_REFERENCE', path, n.lineno,
                         detail=name + ': schema-qualified name in a SQL-like Python string literal; no claim that it executes on every path.')
                    nodes[owner(path, n.lineno)].setdefault('databaseEntities', []).append(dict(name=name,path=path,line=n.lineno))
                else:
                    unresolved_sql[name] += 1
            if re.search(r'\bduckdb\.', n.value):
                edge(owner(path, n.lineno), duckdb, 'GATED_ACCELERATOR_REFERENCE', path, n.lineno,
                     detail='DuckDB setting in EPM SQL literal. Qualification/gated integration only; production acceleration is disabled.')
    nodes[postgres]['databaseEntities'] = database_entities

    packages = json.loads(source(REGISTER))
    package_ids = {}
    former_packages = [row for row in packages['obligations']
                       if row['source'] == 'P']
    for index, p in enumerate(former_packages):
        package_id = p['obligationId']
        status = p['disposition']
        pid = node('package:' + package_id,
                   package_id + ' · ' + status, 'acceptance package', REGISTER,
                   status=status, notes=p['rationale'],
                   pointer='/obligations/' + str(index), layer='Evidence')
        package_ids[package_id] = pid

    functionalities, unknown_operations = {}, []
    def functionality(id, title, package, basis):
        fid = node('functionality:' + id, title, 'functionality',
                   status='implemented source; qualification is scoped in linked evidence',
                   package=package, basis=basis, perspective='user')
        functionalities[fid] = []
        edge(fid, package_ids[package], 'ASSOCIATED_ACCEPTANCE_PACKAGE', REGISTER,
             certainty='association', detail='Authored navigation association. Package status is not inherited by individual operations.')
        return fid

    group_ids = {}
    for op, oid in operations.items():
        if nodes[oid]['status'] == 'internal lowering only':
            continue
        group_name=next((new+op[len(old):] for old,new in GROUP_PREFIX_ALIASES.items()
                         if op.startswith(old)),op)
        matches = [g for g in GROUPS if group_name.startswith(g[0])]
        if matches:
            prefix, title, package = max(matches, key=lambda g: len(g[0]))
        else:
            prefix, title, package = op.rsplit('.', 1)[0], op.rsplit('.', 1)[0], 'P09'
            unknown_operations.append(op)
        fid = group_ids.get(prefix)
        if not fid:
            fid = group_ids[prefix] = functionality(prefix, title, package,
                 'Authored grouping of registered operation names by prefix: ' + prefix)
        functionalities[fid].append(oid)
        edge(fid, oid, 'GROUPS_OPERATION', REGISTRY, nodes[oid]['line'], certainty='association',
             detail='Business navigation grouping by longest registered-name prefix; not proof of full business coverage.')

    for key, title, package, prefixes in INFRA:
        fid = functionality(key, title, package, 'Authored infrastructure association to explicit current source-path prefixes.')
        nodes[fid]['perspective'] = 'platform'
        for path in sorted(source_hashes):
            if (implementation_path(path) and layer(path)!='Evidence'
                    and any(path.startswith(prefix) for prefix in prefixes)):
                mid = file_node(path)
                functionalities[fid].append(mid)
                edge(fid, mid, 'ASSOCIATED_IMPLEMENTATION', path, certainty='association',
                     detail='Authored source-path association: ' + ', '.join(prefixes))

    optimization = functionality('calculation-optimization', 'Plan calculation scope, dependencies and bounded execution', 'P10',
        'Authored platform branch mapping actual planning/currentness/relational mechanisms. No new benchmark or speedup claim.')
    nodes[optimization]['perspective'] = 'platform'
    nodes[optimization]['notes'] = ('Changed-record example: stored raw changes/revision state and published dependency pins exist, but a complete durable affected-record flag set driving automatic incremental consolidation is not established. '
        'Revision/currentness checks can invalidate a wider application/result scope. Correct recalculation must include transitive dependencies, metadata/policy changes and output/publication semantics; directly changed records alone are insufficient.')
    mechanisms = [
        ('Retain revision state and test input currentness', 'epm_core/postgres_calculation_status.py', 'input_revision_status',
         'Compares expected/observed metadata, data and policy revisions at read time; not a per-record dirty-flag scheduler.'),
        ('Follow nested published dependencies', 'epm_core/postgres_calculation_status.py', 'published_child_status',
         'Traverses pinned Full child generations, including grandchildren, with depth/count bounds; read-time observation is not an accounting certificate.'),
        ('Validate expression dependency closure', 'epm_core/postgres_calculation_status.py', 'published_input_status',
         'Checks immutable published input pins recursively with a shared budget; no automatic incremental rerun is asserted.'),
        ('Plan bounded bottom-up Full trees', 'epm_core/postgres_full_tree_plan.py', 'PostgresFullTreePlanner.plan',
         'Plans an explicit bounded Full tree from active relationships and decisions; rejects unsupported shared/cyclic shapes. Not an automatically selected changed-data tree.'),
        ('Resolve source grain and bound candidate work', 'epm_core/postgres_expression.py', 'source_count',
         'Validates scoped domains, measure types, present facts and bounded result counts. This is source/grain planning, not proof of selective dirty-record recomputation.'),
        ('Materialize exact relational calculation targets', 'epm_core/postgres_expression.py', 'materialize_targets',
         'EPM-owned relational lowering/materialization for explicit typed plans; mechanism presence does not establish a measured speedup.'),
        ('Compile query selectors and grouping', 'epm_core/cube_aggregate_ir.py', 'compile_cube_aggregate',
         'Compiles a bounded aggregate intermediate representation from declared selectors/grain; correctness and performance qualification are separate.'),
        ('Execute native PostgreSQL aggregate stages', 'epm_core/cube_aggregate_native.py', 'NativeCubeAggregateStage.compute',
         'Native exact SQL computes bounded query outputs; fresh authorization, fencing and publication remain separate.'),
        ('Keep accelerator candidates gated', 'epm_core/cube_aggregate_native.py', 'CandidatePgDuckDbCubeAggregateStage._configure_backend',
         'Candidate pg_duckdb configuration exists for qualification. Production stays native; no reactivation or benefit claim.'),
    ]
    for i,(title,path,symbol,note) in enumerate(mechanisms):
        candidates = [s for s in symbols_by_path[path] if s['name'] == symbol]
        assert len(candidates) == 1, (path,symbol)
        target = candidates[0]
        mid = node('mechanism:' + str(i), title, 'calculation mechanism', path, target['line'],
                   status='implemented source mechanism; benefit not measured here', notes=note)
        edge(optimization,mid,'MAPS_MECHANISM',path,target['line'],certainty='association',detail=note)
        edge(mid,target['id'],'EXPLAINED_BY_FUNCTION',path,target['line'],detail='Exact named EPM-owned function/method definition.')
        edge(mid,file_node(path),'IMPLEMENTED_IN_MODULE',path,target['line'])
        functionalities[optimization].append(mid)
    for f in list(functionalities):
        if f != optimization and nodes[f]['package'] in {'P09','P10','P11','P16'}:
            edge(f,optimization,'RELATED_CALCULATION_PLATFORM',certainty='association',
                 detail='Authored related-platform navigation. Follow individual source paths to determine which mechanisms this operation actually uses.')
    nodes['functionality:concurrency']['scaleEvidence'] = {
        'target': '300 concurrent users; 500 GB per application is owner-deferred and not qualified.',
        'recordedScope': packages['packages'][8]['next'],
        'remainingGate': next(p['next'] for p in packages['packages'] if p['id']=='P21'),
        'evidencePath': REGISTER,
        'qualification': 'Historical register statements, not new measurements. Concurrent correctness does not certify sustained capacity.'}

    # The retained workflow matrix is a record, not a fresh rerun. Superseded
    # metadata and transfer matrices were removed with their historical tests.
    for path in ['docs/p14-workflow-acceptance-matrix.json']:
        d = json.loads(source(path))
        rows = d.get('journeys', d.get('criteria', d.get('requirements', [])))
        for index, row in enumerate(rows):
            rid = node('outcome:' + row['id'], row.get('outcome', row.get('requirement', row['id'])),
                       'recorded outcome', path, status=row.get('status', 'unknown'), record=row,
                       pointer='/' + ('journeys' if 'journeys' in d else 'criteria' if 'criteria' in d else 'requirements') + '/' + str(index))
            package = row['id'].split('-')[0]
            if package in package_ids:
                edge(package_ids[package], rid, 'RECORDS_OUTCOME', path, certainty='recorded',
                     detail='Acceptance matrix statement preserved verbatim; not requalified by graph generation.')
            for field in ['sourceEvidence', 'testEvidence', 'sourceTests', 'liveEvidence']:
                for ref in row.get(field, []):
                    if isinstance(ref, str) and ref in source_hashes:
                        edge(rid, file_node(ref), field, path, certainty='recorded', detail='Explicit path recorded in ' + field)
            source_refs = row.get('sourceEvidence', [])
            test_refs = row.get('testEvidence', row.get('sourceTests', []))
            for src in source_refs:
                for test in test_refs:
                    if isinstance(src,str) and isinstance(test,str) and src in source_hashes and test in source_hashes:
                        edge(file_node(src),file_node(test),'RECORDED_TEST_ASSOCIATION',path,certainty='recorded',
                             detail='Source and test paths co-listed in acceptance criterion ' + row['id'] + '. This is scoped recorded association, not function-level proof.')

    test_imports = 0
    for path in sorted(source_hashes):
        if not path.startswith('tests/') or not path.endswith('.py'):
            continue
        for n in ast.walk(ast.parse(source(path),filename=path)):
            if not isinstance(n,ast.ImportFrom) or not n.module or not n.module.startswith(('epm_core.','openepm.')):
                continue
            target_path = n.module.replace('.','/') + '.py'
            if target_path not in source_hashes:
                continue
            tid=file_node(path)
            nodes[tid]['kind']='test file'
            edge(tid,file_node(target_path),'TEST_IMPORT_CANDIDATE',path,n.lineno,certainty='heuristic',
                 detail='Exact test import declaration; possible coverage association only. Importing does not prove any behavior is tested.')
            test_imports+=1
            for alias in n.names:
                for s in symbols_by_path[target_path]:
                    if s['name']==alias.name:
                        edge(tid,s['id'],'TEST_SYMBOL_IMPORT_CANDIDATE',path,n.lineno,certainty='heuristic',
                             detail='Imported EPM symbol in test source. No execution/behavioral coverage claim.')
    # Component retention/disposition inventory: useful for implemented vs
    # retired/deferred boundaries, not a functionality-completion label.
    invpath = 'docs/component-inventory-2026-10-28.json'
    for component in json.loads(source(invpath))['components']:
        cid = node('component:' + component['id'], component['id'], 'inventory disposition', invpath,
                   status=component['status'], record=component)
        for ref in component.get('paths', []):
            if ref in source_hashes:
                edge(cid, file_node(ref), 'INVENTORIES_PATH', invpath, certainty='recorded')
            elif 'folder:' + ref in nodes:
                edge(cid, 'folder:' + ref, 'INVENTORIES_PATH', invpath, certainty='recorded')

    # Summarize a functionality->module connection using actual paths through
    # operations; retain the operation evidence in every summary edge.
    adjacent = defaultdict(list)
    for e in list(edges.values()):
        adjacent[e['source']].append(e)
    for fid, seeds in list(functionalities.items()):
        modules = defaultdict(list)
        for seed in seeds:
            if nodes[seed]['kind'] == 'operation':
                for e in adjacent[seed]:
                    target = nodes[e['target']]
                    if target['path'] and target['path'] != REGISTRY:
                        modules[target['path']].append(dict(operation=nodes[seed]['name'], kind=e['kind'], line=e['line']))
        for path, witnesses in modules.items():
            mid = file_node(path)
            edge(fid, mid, 'IMPLEMENTATION_REFERENCES', path, witnesses[0]['line'], certainty='association',
                 detail='Summarized operation-reference path; declarations/checks do not prove execution.', witnesses=witnesses)

    # Module imports show sharing without conflating containment and calls.
    for e in list(edges.values()):
        if e['kind'] == 'IMPORTS':
            a, b = nodes[e['source']], nodes[e['target']]
            if a['path'] and b['path'] and a['path'] != b['path']:
                edge(file_node(a['path']), file_node(b['path']), 'MODULE_IMPORT', e['path'], e['line'],
                     e['certainty'], e['detail'])

    test_links=defaultdict(list)
    for e in edges.values():
        if e['kind']=='RECORDED_TEST_ASSOCIATION':
            test_links[e['source']].append(dict(test=e['target'],kind=e['kind'],path=e['path'],line=e['line'],confidence='recorded criterion association'))
        elif e['kind'] in {'TEST_IMPORT_CANDIDATE','TEST_SYMBOL_IMPORT_CANDIDATE'}:
            test_links[e['target']].append(dict(test=e['source'],kind=e['kind'],path=e['path'],line=e['line'],confidence='candidate only; not behavioral coverage'))
    for id,n in nodes.items():
        if n['kind']!='test file':
            n['tests']=test_links.get(id,[])
            n['testCoverage']='Scoped recorded association exists; exact behavior/function coverage requires review.' if any(t['kind']=='RECORDED_TEST_ASSOCIATION' for t in n['tests']) else 'Behavioral test mapping not established.'

    # The main model owns semantic identities. Entire definitions are read-only
    # technical attachments, not main-node IDs or an expansion floor in the UI.
    # No fuzzy identity migration is performed for earlier authored records.
    semantic_ids={id: 'code:'+n['path']+'::'+n['kind']+':'+n.get('sourceQualifiedName',n['name'])
                  for id,n in nodes.items() if id.startswith('local/')}
    identity_counts=Counter(semantic_ids.values())
    for id,n in nodes.items():
        if id in semantic_ids:
            base=semantic_ids[id]
            if identity_counts[base]>1:
                # Conditional definitions share a qualified name. Retire the
                # ambiguous base identity so existing reviews never attach to
                # an arbitrarily selected declaration.
                declaration='\n'.join(source(n['path']).splitlines()[n['line']-1:n['end']])
                semantic_ids[id]=base+'@'+digest(declaration.encode())[:20]
            n['entireReferences']=[dict(id=id,name=n['name'],path=n['path'],line=n['line'],end=n['end'],
                kind=n['kind'],commit=header['commit'],match='same declaration path, kind and location; lexical scope checked in source',provider='Entire Graph '+header['provider_version'])]
            n['name']=n.get('sourceQualifiedName',n['name'])
    for r in records:
        if r.get('record_type')=='file' and 'file:'+r['path'] in nodes:
            nodes['file:'+r['path']].setdefault('entireReferences',[]).append(dict(id=r['id'],name=r['path'],path=r['path'],line=1,
                kind='file',commit=header['commit'],match='exact source path and content SHA-256',provider='Entire Graph '+header['provider_version']))
    rekeyed={}
    for id,n in nodes.items():
        new=semantic_ids.get(id,id)
        assert new not in rekeyed, 'Ambiguous semantic identity: '+new
        n['id']=new
        n.setdefault('entireReferences',[])
        for t in n.get('tests',[]):
            t['test']=semantic_ids.get(t['test'],t['test'])
        rekeyed[new]=n
    nodes=rekeyed
    for e in edges.values():
        e['source']=semantic_ids.get(e['source'],e['source'])
        e['target']=semantic_ids.get(e['target'],e['target'])

    # Optional technical footprint of attached references. This is bounded
    # reverse dependency traversal, never a business-severity/affected-set claim.
    dependency_kinds={'CALLS','CONSTRUCTS','ASYNC_CALLS','IMPORTS','EXTENDS','INHERITS','USES_TYPE','PARAM_TYPE','RETURNS_TYPE'}
    reverse=defaultdict(set);neighbors=defaultdict(set);all_counts=defaultdict(Counter);dependency_edges=defaultdict(set)
    raw_ids={}
    def ordinal(id):
        if id not in raw_ids:raw_ids[id]=len(raw_ids)
        return raw_ids[id]
    for i,r in enumerate(records):
        if r.get('record_type')!='relation':continue
        a,b=r['from_id'],r['to_id'];all_counts[a][r['type']]+=1
        if a!=b:all_counts[b][r['type']]+=1
        if r['type'] in dependency_kinds:
            reverse[b].add(a);neighbors[a].add(b);neighbors[b].add(a)
            dependency_edges[a].add(i);dependency_edges[b].add(i);ordinal(a);ordinal(b)
    connectivity={}
    for n in nodes.values():
        for ref in n['entireReferences']:
            id=ref['id'];visited=set();front={id};truncated=False
            for depth in range(2):
                nxt=set()
                for target in sorted(front):
                    nxt.update(reverse[target])
                nxt-=visited|{id}
                if len(visited)+len(nxt)>2000:
                    nxt=set(sorted(nxt)[:max(0,2000-len(visited))]);truncated=True
                visited.update(nxt);front=nxt
                if truncated:break
            footprint=dict(directRelationCounts=dict(all_counts[id]),directRelationCount=sum(all_counts[id].values()),
                directDependencyNeighborIds=sorted(ordinal(v) for v in neighbors[id]),
                directDependencyEdgeIds=sorted(dependency_edges[id]),
                incomingDependencyIds=sorted(ordinal(v) for v in reverse[id]),
                reachableDependentIdsDepth2=sorted(ordinal(v) for v in visited),truncated=truncated)
            connectivity[id]=footprint
    for n in nodes.values():
        if n['kind']=='functionality':
            scenario=SCENARIOS.get(n['id'].split(':',1)[1])
            if scenario:
                n['summary']=scenario[0]+'. '+scenario[2]+' Scope/qualification: '+n.get('notes','see the linked package record; source presence does not establish a passing journey.')
            else:
                n['summary']='Registered operations grouped under '+n['name']+'. No authored review scenario is attached.'
        elif not n.get('summary'):
            if n['kind'] in {'function','method','class'}:
                n['summary']='EPM-owned '+n['kind']+' '+n['name']+' in '+n['path']+'. '+n.get('signature','')+' Inspect its source and named connections; behavior-level test mapping may remain unestablished.'
            elif n['kind']=='operation':
                n['summary']='Deterministic application-language operation '+n['name']+'. Registry classification: '+n['requiredCapability']+'. UI wiring, MCP exposure, code references and verification are reported separately.'
            else:n['summary']=n.get('notes') or n.get('qualification') or (n['kind']+' '+n['name']+'. Follow the explicit source and relationship evidence; this structural identity is not a completion claim.')

    # A source evidence link always opens the frozen bytes, never the moving
    # checkout. Include all referenced sources so file:// remains fully offline.
    for path in sorted(used_paths):
        source(path)
    rows = sorted(nodes.values(), key=lambda x: x['id'])
    links = sorted(edges.values(), key=lambda x: (x['source'], x['target'], x['kind'], x['path'], x['line']))
    schema_versions = [int(match[1]) for path in source_hashes
                       if (match := re.fullmatch(r'schema/postgres/([0-9]{4})_[^/]+\.sql', path))]
    coverage = dict(
        commit=header['commit'], tree=header['tree'], provider=header['provider'], providerVersion=header['provider_version'],model='openepm-semantic-graph-v1',
        profile=header['profile'], nodes=len(rows), edges=len(links),
        snapshotKind='working-tree' if base_commit else 'committed', baseCommit=base_commit or header['commit'],
        sourceSchemaVersion=max(schema_versions, default=None),
        kinds=dict(Counter(n['kind'] for n in rows)), relations=dict(Counter(e['kind'] for e in links)),
        certainty=dict(Counter(e['certainty'] for e in links)),
        declaredPublicOperations=sum(nodes[v]['status'] == 'declared public registry' for v in operations.values()),
        declaredControlPlaneOperations=sum(nodes[v]['status'] == 'declared control-plane registry' for v in operations.values()),
        operationsWithoutDispatchComparison=[op for op in operations if not dispatch_counts[op]],
        fallbackFunctionalityLabels=unknown_operations,
        wholeRebuildComplete=packages['baseline']['wholeRebuildComplete'],
        packageCompletion=packages['completion'], integratedSchemaMigrations=packages['currentIntegratedSchemaMigrations'],
        unresolvedSqlNames=dict(unresolved_sql), entireSummary=summary,
        deliberatelyExcludedRelationFamilies=dict(rejected),
        sourceFiles=len(sources), sourceHashManifest=digest(json.dumps(source_hashes, sort_keys=True).encode()),
        testImportCandidates=test_imports, refresh='ad hoc, on user request only',
        entireFootprintScope=dict(direction='incoming / reverse dependency users',maxDepth=2,maxDependentsPerReference=2000,
            relationKinds=sorted(dependency_kinds),excludes='containment, definitions, co-change, similarity, routes and channels',
            confidence='Includes static heuristic/ambiguous relations. Not a certified blast radius, complete transitive closure or business criticality.'),
        limitations=[
            ('Frozen development source from the checkout, based on the stated committed revision. '
             'Only the named source scopes were overlaid; release state and later edits are excluded.'
             if base_commit else 'Frozen committed snapshot; uncommitted changes and later commits are excluded.'),
            'Graph nodes prove source presence, not correctness, usage, feature completeness or production release.',
            'Business groupings, infrastructure paths and package associations are authored, inferred navigation.',
            'Entire Graph call resolution is static: heuristic edges may be wrong; dynamic factories, reflection and runtime wiring may be absent.',
            'Literal registry/dispatch and SQL references identify syntax, not guaranteed execution paths or live database state.',
            'DDL identities are declarations across migrations; ALTER/DROP and generated physical relations are not a live schema reconstruction.',
            'External MCP clients and identity providers have no invented implementation nodes. Runtime processes are not observed.',
            'Acceptance records are preserved claims for their stated artifacts/scopes, not tests rerun during graph generation.',
            'No selective-test runner, automatic blast-radius certification, shared-service access or source upload.',
        ])
    annotation_data=validate_annotations(json.loads(annotations.read_text())) if annotations else {'format':'openepm-graph-annotations-v1','snapshotCommit':header['commit'],'nodes':{}}
    coverage['annotationOrphans']=[id for id in annotation_data['nodes'] if id not in nodes]
    data = dict(meta=coverage, nodes=rows, links=links, sources=sources, sourceHashes={p:source_hashes[p] for p in sources},annotations=annotation_data,entireConnectivity=connectivity)
    data_bytes = json.dumps(data, separators=(',', ':'), ensure_ascii=True).encode()
    (out / 'graph.json').write_bytes(data_bytes)
    (out / 'source-manifest.json').write_text(json.dumps(source_hashes, indent=2) + '\n')
    (out / 'coverage.json').write_text(json.dumps(coverage, indent=2) + '\n')
    (out / 'annotations.seed.json').write_text(json.dumps(annotation_data,indent=2)+'\n')
    vendor = (assets / '3d-force-graph.min.js').read_bytes()
    (out / 'index.html').write_text(render_local_viewer(data_bytes, vendor))
    shutil.copy(assets / 'LICENSE-3d-force-graph', out / 'LICENSE-3d-force-graph.txt')
    (out/'assets').mkdir(exist_ok=True)
    for name in ['3d-force-graph.min.js','LICENSE-3d-force-graph']:
        if (assets/name).resolve()!=(out/'assets'/name).resolve():
            shutil.copy(assets/name,out/'assets'/name)
    if raw_path.suffix != '.gz':
        with gzip.GzipFile(out / 'entire.snapshot.ndjson.gz', 'wb', mtime=0) as f:
            f.write(raw_path.read_bytes())
    else:
        if raw_path.resolve() != (out / 'entire.snapshot.ndjson.gz').resolve():
            shutil.copy(raw_path, out / 'entire.snapshot.ndjson.gz')
    receipt = dict(commit=header['commit'], tree=header['tree'], graphSha256=digest(data_bytes),
                   htmlSha256=digest((out / 'index.html').read_bytes()), rendererSha256=VENDOR_SHA,
                   snapshotSha256=digest((out / 'entire.snapshot.ndjson.gz').read_bytes()),
                   sourceManifestSha256=digest((out / 'source-manifest.json').read_bytes()),
                   nodes=len(rows), edges=len(links), selfContained=True)
    receipt['generatorSourcesSha256']={p.name:digest(p.read_bytes()) for p in Path(__file__).parent.iterdir() if p.is_file() and p.suffix in {'.py','.html','.mjs','.cjs'}}
    (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--snapshot', required=True, type=Path)
    p.add_argument('--entire', required=True, type=Path)
    p.add_argument('--assets', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    p.add_argument('--annotations', type=Path, help='Explicit exported user metadata to preserve through refresh; orphan identities are retained and flagged.')
    a = p.parse_args()
    build(a.snapshot, a.entire, a.out, a.assets,a.annotations)
