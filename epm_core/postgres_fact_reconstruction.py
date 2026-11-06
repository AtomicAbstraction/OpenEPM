"""Fixed, scoped preflight for rebuilding raw materialized fact state.

This module never changes a fact, event, receipt or revision. It validates the
whole retained source chain before comparing current projections. Values stay
in PostgreSQL (including opaque JSON numbers); only counts leave the database.
Publication/recovery privilege is deliberately not granted by this preflight.
"""
from psycopg.rows import dict_row

from .postgres_access import PostgresAccessChecker, VerifiedIdentity, assert_nonowner_role
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout, lock_busy_boundary


# Fixed identifiers, never supplied by a caller. The same canonical CTEs are
# usable by the eventual narrowly authorized reconstruction publisher.
_SOURCES = {
    'numeric': ('numeric_fact_event', 'numeric_cell_current', 'coordinate_id',
                'committed_revision DESC,line_ordinal DESC',
                'present,resulting_amount AS amount,change_id,committed_revision AS last_revision',
                'present,amount,change_id,last_revision', 'true'),
    'text': ('text_fact_event', 'text_cell_current', 'coordinate_id',
             'committed_revision DESC,line_ordinal DESC',
             'present,resulting_value AS text_value,change_id,committed_revision AS last_revision',
             'present,text_value,change_id,last_revision', 'true'),
    'detail': ('line_detail_event', 'line_detail_current', 'coordinate_id',
               'committed_revision DESC',
               'present,items,total,change_id,committed_revision AS last_revision',
               'items,total,change_id,last_revision', 'present'),
    'generic': ('generic_fact_event', 'generic_fact_current', 'table_id,series_key',
                'committed_revision DESC',
                'action,after_value AS value,resulting_change_id AS change_id,committed_revision AS last_revision',
                'value,change_id,last_revision', "action<>'Delete'"),
}


def _latest(family):
    event, _, keys, order, columns, _, _ = _SOURCES[family]
    return f'''SELECT DISTINCT ON ({keys}) {keys},{columns}
        FROM epm.{event} WHERE workspace_id=%s AND application_id=%s
        ORDER BY {keys},{order}'''


def _inspect_sources(db, scope, head, *, maximum_ms=5000):
    """Internal transaction primitive; caller holds scoped app publication fence."""
    if type(maximum_ms) is not int or not 1 <= maximum_ms <= 20000:
        raise ValueError('RECONSTRUCTION_STATEMENT_BUDGET_INVALID')
    keys = (scope.workspace_id, scope.application_id)

    def reject(query, code, args=keys):
        configure_statement_timeout(db, maximum_ms)
        if db.execute(query, args).fetchone():
            raise ValueError(code)

    # A corrupt historical event must fail even when the latest state happens
    # to look correct. Never infer canonical validity from current projections.
    for family, (event, *_rest) in _SOURCES.items():
        actor = ' OR e.actor_id<>r.actor_id' if family == 'generic' else ''
        reject(f'''SELECT 1 FROM epm.{event} e LEFT JOIN epm.operation_receipt r
            USING(workspace_id,application_id,operation_id)
            WHERE e.workspace_id=%s AND e.application_id=%s AND
              (r.operation_id IS NULL OR NOT r.sealed OR
               e.committed_revision<>r.committed_revision OR
               e.committed_revision>%s {actor}) LIMIT 1''',
            'RECONSTRUCTION_RECEIPT_INVALID', (*keys, head))

    reject('''WITH h AS (SELECT *,lag(resulting_amount) OVER chain AS prior_amount
        FROM epm.numeric_fact_event WHERE workspace_id=%s AND application_id=%s
        WINDOW chain AS (PARTITION BY coordinate_id ORDER BY committed_revision,line_ordinal))
        SELECT 1 FROM h WHERE present IS DISTINCT FROM (kind<>'clear')
          OR delta IS DISTINCT FROM coalesce(resulting_amount,0)-coalesce(prior_amount,0)
          LIMIT 1''', 'RECONSTRUCTION_NUMERIC_LINEAGE_INVALID')
    reject('''WITH h AS (SELECT *,lag(present) OVER chain AS previous_present,
          lag(resulting_value) OVER chain AS previous_value
        FROM epm.text_fact_event WHERE workspace_id=%s AND application_id=%s
        WINDOW chain AS (PARTITION BY coordinate_id ORDER BY committed_revision,line_ordinal))
        SELECT 1 FROM h WHERE present IS DISTINCT FROM (kind<>'clear')
          OR prior_present IS DISTINCT FROM coalesce(previous_present,false)
          OR prior_value IS DISTINCT FROM previous_value LIMIT 1''',
        'RECONSTRUCTION_TEXT_LINEAGE_INVALID')
    reject('''WITH h AS (SELECT *,lag(present) OVER chain AS previous_present,
          lag(items) OVER chain AS previous_items,lag(total) OVER chain AS previous_total
        FROM epm.line_detail_event WHERE workspace_id=%s AND application_id=%s
        WINDOW chain AS (PARTITION BY coordinate_id ORDER BY committed_revision))
        SELECT 1 FROM h WHERE prior_items IS DISTINCT FROM
            CASE WHEN previous_present THEN previous_items ELSE NULL END
          OR prior_total IS DISTINCT FROM CASE WHEN previous_present THEN previous_total ELSE NULL END
          OR total IS DISTINCT FROM (SELECT coalesce(sum((x->>'amount')::numeric),0)
              FROM jsonb_array_elements(items)x) LIMIT 1''',
        'RECONSTRUCTION_DETAIL_LINEAGE_INVALID')
    reject('''WITH h AS (SELECT *,lag(action) OVER chain AS previous_action,
          lag(after_value) OVER chain AS previous_value,lag(resulting_change_id) OVER chain AS previous_id
        FROM epm.generic_fact_event WHERE workspace_id=%s AND application_id=%s
        WINDOW chain AS (PARTITION BY table_id,series_key ORDER BY committed_revision))
        SELECT 1 FROM h WHERE
          before_value IS DISTINCT FROM CASE WHEN previous_action<>'Delete' THEN previous_value ELSE NULL END
          OR before_change_id IS DISTINCT FROM CASE WHEN previous_action<>'Delete' THEN previous_id ELSE '' END
          OR (action='Create') IS DISTINCT FROM (previous_action IS NULL OR previous_action='Delete')
          OR resulting_change_id!~'^[0-9a-f]{32}$'
          OR (action='Delete' AND after_value IS NOT NULL)
          OR (action<>'Delete' AND (after_value IS NULL OR after_value='null'::jsonb))
          LIMIT 1''', 'RECONSTRUCTION_GENERIC_LINEAGE_INVALID')

    reject(f'''WITH n AS ({_latest('numeric')}),t AS ({_latest('text')})
        SELECT 1 FROM n JOIN t USING(coordinate_id) WHERE n.present AND t.present LIMIT 1''',
        'RECONSTRUCTION_VALUE_TYPE_CONFLICT', (*keys, *keys))
    reject(f'''WITH n AS ({_latest('numeric')}),d AS ({_latest('detail')})
        SELECT 1 FROM d LEFT JOIN n USING(coordinate_id) WHERE d.present AND
          (NOT coalesce(n.present,false) OR n.amount IS DISTINCT FROM d.total) LIMIT 1''',
        'RECONSTRUCTION_DETAIL_TOTAL_CONFLICT', (*keys, *keys))
    reject('''SELECT 1 FROM epm.line_detail_event d LEFT JOIN LATERAL (
          SELECT present,resulting_amount FROM epm.numeric_fact_event n
          WHERE n.workspace_id=d.workspace_id AND n.application_id=d.application_id
            AND n.coordinate_id=d.coordinate_id AND n.committed_revision<=d.committed_revision
          ORDER BY n.committed_revision DESC,n.line_ordinal DESC LIMIT 1)n ON true
        WHERE d.workspace_id=%s AND d.application_id=%s AND d.present AND
          (NOT coalesce(n.present,false) OR n.resulting_amount IS DISTINCT FROM d.total) LIMIT 1''',
        'RECONSTRUCTION_DETAIL_HISTORY_TOTAL_CONFLICT')

    result = {}
    for family, (_, current, key_columns, _, _, columns, present) in _SOURCES.items():
        compare = ','.join('e.'+c for c in columns.split(','))
        actual = ','.join('c.'+c for c in columns.split(','))
        key = key_columns.split(',')[0]
        configure_statement_timeout(db, maximum_ms)
        result[family] = dict(db.execute(f'''WITH latest AS ({_latest(family)}),
            expected AS (SELECT * FROM latest WHERE {present}),
            current AS (SELECT * FROM epm.{current} WHERE workspace_id=%s AND application_id=%s)
            SELECT (SELECT count(*) FROM latest) AS "sourceKeys",
              count(e.{key}) AS "expectedRows",count(c.{key}) AS "currentRows",
              count(*) FILTER (WHERE e.{key} IS NOT NULL AND c.{key} IS NULL) AS "missingRows",
              count(*) FILTER (WHERE e.{key} IS NULL AND c.{key} IS NOT NULL) AS "extraRows",
              count(*) FILTER (WHERE e.{key} IS NOT NULL AND c.{key} IS NOT NULL
                AND ROW({compare}) IS DISTINCT FROM ROW({actual})) AS "differentRows"
            FROM expected e FULL JOIN current c USING({key_columns})''', (*keys, *keys)).fetchone())
    configure_statement_timeout(db, maximum_ms)
    result['coordinateMembers'] = dict(db.execute('''WITH expected AS (
        SELECT c.coordinate_id,pair.key AS dimension_id,pair.value AS member_id
        FROM epm.coordinate c CROSS JOIN LATERAL jsonb_each_text(c.members) pair
        WHERE c.workspace_id=%s AND c.application_id=%s), current AS (
        SELECT * FROM epm.coordinate_member WHERE workspace_id=%s AND application_id=%s)
        SELECT count(e.coordinate_id) AS "sourceKeys",count(e.coordinate_id) AS "expectedRows",
          count(c.coordinate_id) AS "currentRows",
          count(*) FILTER(WHERE e.coordinate_id IS NOT NULL AND c.coordinate_id IS NULL) AS "missingRows",
          count(*) FILTER(WHERE e.coordinate_id IS NULL AND c.coordinate_id IS NOT NULL) AS "extraRows",
          count(*) FILTER(WHERE e.coordinate_id IS NOT NULL AND c.coordinate_id IS NOT NULL
            AND e.member_id IS DISTINCT FROM c.member_id) AS "differentRows"
        FROM expected e FULL JOIN current c USING(coordinate_id,dimension_id)''', (*keys, *keys)).fetchone())
    return result


class PostgresFactReconstruction:
    """Administrator preflight, internal core API; no public repair endpoint yet."""
    def __init__(self, dsn, *, identity):
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        assert_nonowner_role(dsn, 'epm_runtime', ('application_state', 'numeric_fact_event',
            'text_fact_event', 'line_detail_event', 'generic_fact_event'))
        self.dsn, self.identity = dsn, identity

    @lock_busy_boundary
    def inspect(self, scope, *, expected_commit_revision):
        if type(expected_commit_revision) is not int or expected_commit_revision < 0:
            raise ValueError('EXPECTED_COMMIT_REVISION_REQUIRED')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db, scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(db, self.identity, scope, 'admin')
                configure_statement_timeout(db, 5000)
                state = db.execute('''SELECT commit_revision,commit_open,schema_epoch,
                    metadata_revision,data_revision,policy_revision FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s FOR UPDATE''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                if state['commit_revision'] != expected_commit_revision or state['commit_open']:
                    raise ValueError('STALE_RECONSTRUCTION_SOURCE')
                families = _inspect_sources(db, scope, state['commit_revision'])
                return {'source': dict(state), 'families': families,
                        'requiresReconstruction': any(r[k] for r in families.values()
                            for k in ('missingRows','extraRows','differentRows'))}
