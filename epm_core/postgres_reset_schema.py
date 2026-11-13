"""Read-only schema coverage audit for exact PostgreSQL workspace reset.

The FK graph pins the owner-only deletion primitive. It does not authorize
reset apply or prove external endpoint inventory is complete.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re


# Updated only after a migration's workspace deletion implications are
# reviewed. An unreviewed table or FK leaves reset apply blocked.
EXPECTED_SCHEMA_FINGERPRINT = (
    '090c87c423ce39f0233ea03dc9db290f2305fae43668f413ad657929c4b94fa1')

_PROJECTION_VIEWS = frozenset((
    'numeric_cell_current', 'text_cell_current', 'line_detail_current',
    'generic_fact_current', 'coordinate_member', 'coordinate_projection'))


def _normalize_view_definition(definition: str) -> str:
    # Deparsing can omit epm qualifications when epm is on search_path.
    # Preserve quoted identifiers/string contents; collapsing whitespace inside
    # a SQL literal could otherwise conceal a semantic definition change.
    pieces = re.split(r'''('(?:''|[^'])*'|"(?:""|[^"])*")''', definition)
    for index in range(0, len(pieces), 2):
        pieces[index] = re.sub(r'\s+', ' ', re.sub(r'\bepm\.', '', pieces[index]))
    return ''.join(pieces).strip()


def _canonical(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(',',':'),
                      ensure_ascii=False).encode('utf-8')


def inspect_reset_schema(db) -> dict:
    relations=[]
    for row in db.execute('''SELECT c.relname AS relation_name,
                c.relkind AS relation_kind,
                c.reloptions AS relation_options,
                CASE WHEN c.relkind='v' THEN pg_get_viewdef(c.oid,false)
                    ELSE NULL END AS view_definition,
                EXISTS (SELECT 1 FROM pg_attribute a
                    WHERE a.attrelid=c.oid AND a.attname='workspace_id'
                    AND a.attnum>0 AND NOT a.attisdropped)
                    AS workspace_scoped
                FROM pg_class c JOIN pg_namespace n
                  ON n.oid=c.relnamespace
                WHERE n.nspname='epm'
                AND c.relkind IN ('r','p','m','f','v')
                ORDER BY c.relname''').fetchall():
        relation={'name':row['relation_name'], 'kind':row['relation_kind'],
                  'workspaceScoped':row['workspace_scoped']}
        if relation['kind']=='v':
            relation['definition']=_normalize_view_definition(row['view_definition'])
            relation['options']=sorted(row['relation_options'] or [])
        relations.append(relation)
    foreign_keys=[{'child':row['child_table'],
                   'parent':row['parent_table'],
                   'name':row['constraint_name'],
                   'childColumns':row['child_columns'],
                   'parentColumns':row['parent_columns'],
                   'deleteAction':row['delete_action']}
                  for row in db.execute('''SELECT child.relname AS child_table,
                      parent.relname AS parent_table,
                      con.conname AS constraint_name,
                      ARRAY(SELECT a.attname FROM unnest(con.conkey)
                          WITH ORDINALITY AS k(attnum,ordinal)
                          JOIN pg_attribute a ON a.attrelid=child.oid
                          AND a.attnum=k.attnum ORDER BY k.ordinal)
                          AS child_columns,
                      ARRAY(SELECT a.attname FROM unnest(con.confkey)
                          WITH ORDINALITY AS k(attnum,ordinal)
                          JOIN pg_attribute a ON a.attrelid=parent.oid
                          AND a.attnum=k.attnum ORDER BY k.ordinal)
                          AS parent_columns,
                      con.confdeltype AS delete_action
                      FROM pg_constraint con
                      JOIN pg_class child ON child.oid=con.conrelid
                      JOIN pg_namespace nc ON nc.oid=child.relnamespace
                      JOIN pg_class parent ON parent.oid=con.confrelid
                      JOIN pg_namespace np ON np.oid=parent.relnamespace
                      WHERE con.contype='f' AND nc.nspname='epm'
                      AND np.nspname='epm'
                      ORDER BY child.relname,parent.relname,con.conname'''
                      ).fetchall()]
    external_incoming=[{'childSchema':row['child_schema'],
                        'child':row['child_table'],
                        'parent':row['parent_table'],
                        'name':row['constraint_name']}
                       for row in db.execute('''SELECT
                           nc.nspname AS child_schema,
                           child.relname AS child_table,
                           parent.relname AS parent_table,
                           con.conname AS constraint_name
                           FROM pg_constraint con
                           JOIN pg_class child ON child.oid=con.conrelid
                           JOIN pg_namespace nc ON nc.oid=child.relnamespace
                           JOIN pg_class parent ON parent.oid=con.confrelid
                           JOIN pg_namespace np ON np.oid=parent.relnamespace
                           WHERE con.contype='f' AND np.nspname='epm'
                           AND nc.nspname<>'epm'
                           ORDER BY nc.nspname,child.relname,
                                    parent.relname,con.conname''').fetchall()]
    structural={'relations':relations,'foreignKeys':foreign_keys,
                'externalIncomingReferences':external_incoming}
    fingerprint=sha256(_canonical(structural)).hexdigest()
    tables=[row for row in relations if row['kind'] in ('r','p')]
    scoped={row['name'] for row in tables if row['workspaceScoped']}
    global_tables={row['name'] for row in tables if not row['workspaceScoped']}
    projection_views=[row for row in relations if row['kind']=='v'
        and row['name'] in _PROJECTION_VIEWS
        and {'security_invoker=true','security_barrier=true'} <= set(row['options'])]
    other_relations=[row for row in relations if row['kind'] not in ('r','p')
        and row not in projection_views]
    global_references=[edge for edge in foreign_keys
                       if edge['child'] in global_tables
                       and edge['parent'] in scoped]
    self_references=[edge for edge in foreign_keys
                     if edge['child']==edge['parent']
                     and edge['child'] in scoped]
    graph={name:set() for name in scoped}
    for edge in foreign_keys:
        child,parent=edge['child'],edge['parent']
        if child in graph and parent in graph and child!=parent:
            graph[child].add(parent)
    parent_first=[]
    while graph:
        ready=sorted(name for name,deps in graph.items()
                     if not (set(graph)-{name})&deps)
        if not ready:
            break
        for name in ready:
            parent_first.append(name)
            del graph[name]
    return {'fingerprint':fingerprint,
            'expectedFingerprint':EXPECTED_SCHEMA_FINGERPRINT,
            'matchesExpected':fingerprint==EXPECTED_SCHEMA_FINGERPRINT,
            'workspaceTables':sorted(scoped),
            'globalTables':sorted(global_tables),
            'projectionViews':projection_views,
            'otherRelations':other_relations,
            'foreignKeyCount':len(foreign_keys),
            'foreignKeys':foreign_keys,
            'externalIncomingReferences':external_incoming,
            'selfReferences':self_references,
            'globalToWorkspaceReferences':global_references,
            'cycleTables':sorted(graph),
            'fkChildFirstOrder':list(reversed(parent_first))}
