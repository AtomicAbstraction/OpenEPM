"""Select potentially runnable ApplicationRules before applying the public page limit."""
from psycopg import sql
from psycopg.types.json import Jsonb

from .dimensional_privileges import coordinate_write_assignment_sql
from .postgres_group_rule_source import runnable_rules


def _candidate_query(policy, *, filtered):
    operation = sql.SQL(' AND v.program @> %(operation)s') if filtered else sql.SQL('')
    return sql.SQL("""
        WITH write_scopes AS MATERIALIZED (
            SELECT * FROM jsonb_to_recordset(%(grants)s) AS b(assignment text,action text,kind text,selector jsonb)
        )
        SELECT v.* FROM epm.expression_rule_definition v
        JOIN epm.python_program_definition d ON (d.workspace_id,d.application_id,d.program_id,d.source_token,d.source_digest)
             =(v.workspace_id,v.application_id,v.source_program_id,v.source_token,v.source_digest)
        JOIN epm.python_environment_definition e ON (e.workspace_id,e.application_id,e.environment_id,e.state_token)
             =(d.workspace_id,d.application_id,d.environment_id,d.environment_state_token)
        JOIN epm.coordinate_layout layout ON (layout.workspace_id,layout.application_id,layout.schema_epoch)
             =(v.workspace_id,v.application_id,%(epoch)s)
        WHERE v.workspace_id=%(workspace)s AND v.application_id=%(app)s AND v.rule_id>%(after)s
          AND v.definition_kind='ApplicationRule' AND v.status='Active' AND v.ownership_state='Source'
          AND d.status='Active' AND d.declared_output->>'kind'='ApplicationRule'
          AND d.declared_output->>'definitionId'=v.rule_id AND e.status='Active'
          AND v.metadata_revision=%(metadata)s AND v.current_certificate->'schemaEpoch'=to_jsonb(%(epoch)s::bigint)
          AND v.current_certificate->>'environmentId'=e.environment_id
          AND v.current_certificate->>'environmentStateToken'=e.state_token
          AND coalesce(e.manifest->'compilerVersions',jsonb_build_array(e.manifest->'compilerVersion'))
              ? (v.current_certificate->>'compilerVersion')
          AND NOT jsonb_path_exists(v.program,
                '$.arguments.parameters[*] ? (@.type != "Amount" && @.type != "Ratio")')
          AND NOT jsonb_path_exists(v.program,
                '$.arguments.units[*].operations[*] ? (@.function != "facts.numeric.sequence" && @.function != "facts.numeric.batch")')
          {operation}
          AND NOT EXISTS (
            SELECT 1 FROM (
                SELECT jsonb_path_query(v.program,'$.arguments.units[*].operations[*].arguments.mutations[*].coordinate') AS members
                UNION
                SELECT jsonb_path_query(v.program,'$.arguments.units[*].operations[*].arguments.statements[*].coordinate')
            ) target
            WHERE NOT (
                WITH axes AS MATERIALIZED (
                    SELECT p.dimension_id,m.member_id,m.read_security_tags AS read_tags,m.write_security_tags AS write_tags,
                           p.value->>'type'='ApplicationRuleParameter' AND bound.sample IS NULL AS needs_binding
                    FROM jsonb_each(CASE WHEN jsonb_typeof(target.members)='object' THEN target.members
                                         ELSE '{{}}'::jsonb END) p(dimension_id,value)
                    LEFT JOIN LATERAL (
                        -- The canonical compiler handles alternate decimal spellings in member-ID positions.
                        SELECT param->>'sample' AS sample FROM jsonb_array_elements(
                            CASE WHEN jsonb_typeof(v.program->'arguments'->'parameters')='array'
                                 THEN v.program->'arguments'->'parameters' ELSE '[]'::jsonb END) param
                        WHERE p.value->>'type'='ApplicationRuleParameter' AND param->>'name'=p.value->>'name'
                          AND param->>'type' IN ('Amount','Ratio')
                          AND param->>'sample' ~ '^-?(0|[1-9][0-9]*)([.][0-9]+)?$'
                    ) bound ON true
                    LEFT JOIN epm.member m ON (m.workspace_id,m.application_id,m.dimension_id,m.member_id)
                        =(v.workspace_id,v.application_id,p.dimension_id,coalesce(bound.sample,p.value#>>'{{}}'))
                        AND m.status='Active'
                ) SELECT {allowed}
            )
          )
          AND v.current_certificate->>'dependencyDigest'=epm.definition_dependency_digest(
              v.workspace_id,v.application_id,v.definition_kind,v.program)
        ORDER BY v.rule_id LIMIT %(count)s
    """).format(operation=operation, allowed=coordinate_write_assignment_sql(policy))


def runnable_page(db, identity, scope, authority, state, *, after, limit, operation, stored_function):
    # Narrow to complete read/write assignments before crossing the SQL/Python boundary.
    grants = [{'assignment': row.assignment_id, 'action': row.action, 'kind': row.scope_kind,
               'selector': row.selector} for row in authority.privileges.rows
              if row.action in ('facts.read','facts.write') and row.scope_kind in ('entire_application','dimension_tags')]
    readers = {g['assignment'] for g in grants if g['action']=='facts.read'}
    writers = {g['assignment'] for g in grants if g['action']=='facts.write'}
    complete = readers & writers
    if not complete:
        return []
    query = _candidate_query(authority.policy, filtered=operation is not None)
    args = {'workspace': scope.workspace_id, 'app': scope.application_id, 'epoch': state['schema_epoch'],
            'metadata': state['metadata_revision'], 'after': after or '',
            'grants': Jsonb([g for g in grants if g['assignment'] in complete])}
    if operation is not None:
        args['operation'] = Jsonb({'function':stored_function,
                                   'arguments':{'units':[{'operations':[{'function':operation}]}]}})
    page = []
    wanted = limit + 1
    args['count'] = wanted
    while True:
        candidates = db.execute(query,args).fetchall()
        # SQL supplies candidates. The shared verifier decides each rule
        # separately, resolving its SDK ownership, certificate and targets in batches.
        page.extend(runnable_rules(db,identity,scope,candidates))
        if len(page)>=wanted:
            return page[:wanted]
        if len(candidates)<args['count']:
            return page
        args['after'] = candidates[-1]['rule_id']
        # Only exact-check rejections need a refill. Use a bounded internal
        # batch even for one-row public pages and keep its anchor private.
        args['count'] = max(32,wanted-len(page))
