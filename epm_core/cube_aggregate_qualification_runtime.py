"""Disposable runtime support for aggregate-route qualification.

This module is deliberately absent from production listeners.  Its cleanup
primitive is narrower than application reset: it can remove only the exact
technical query created by the verified qualification identity, and only from
a database explicitly marked disposable at both the database-name and server
setting boundaries.
"""
from __future__ import annotations

import os

from psycopg.rows import dict_row

from .cube_aggregate_public_qualification import OPT_IN
from .persistence_contract import ApplicationScope
from .postgres_access import VerifiedIdentity
from .postgres_connection import connect_postgres


DISPOSABLE_DATABASE_PREFIX = 'openepm_qualification_'
DISPOSABLE_SETTING = 'epm.qualification_disposable'


class DisposableAggregateResultCleaner:
    """Delete one identity-owned technical result from a disposable database."""

    def __init__(self, dsn: str, *, scope: ApplicationScope,
                 identity: VerifiedIdentity):
        if (os.environ.get(OPT_IN) != '1' or type(dsn) is not str or not dsn
                or not isinstance(scope, ApplicationScope)
                or not isinstance(identity, VerifiedIdentity)):
            raise ValueError('PGDUCKDB_PUBLIC_DISPOSABLE_CLEANUP_DISABLED')
        self.dsn, self.scope, self.identity = dsn, scope, identity

    def __call__(self, query_id: str, terminal_status: str) -> None:
        if (type(query_id) is not str or not query_id
                or type(terminal_status) is not str or not terminal_status):
            raise ValueError('PGDUCKDB_PUBLIC_CLEANUP_TARGET_INVALID')
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                self._assert_guard(db)
                db.execute("SELECT set_config('epm.workspace_id',%s,true),"
                           "set_config('epm.application_id',%s,true)",
                           (self.scope.workspace_id,
                            self.scope.application_id))
                deleted = db.execute('''DELETE FROM epm.cube_aggregate_query
                    WHERE workspace_id=%s AND application_id=%s AND query_id=%s
                      AND issuer=%s AND subject_id=%s
                    RETURNING query_id''',
                    (self.scope.workspace_id, self.scope.application_id,
                     query_id, self.identity.issuer,
                     self.identity.subject_id)).fetchone()
                if not deleted:
                    raise ValueError('PGDUCKDB_PUBLIC_CLEANUP_TARGET_NOT_OWNED')
                remains = db.execute('''SELECT EXISTS(
                    SELECT 1 FROM epm.cube_aggregate_result
                    WHERE workspace_id=%s AND application_id=%s
                      AND query_id=%s) AS remains''',
                    (self.scope.workspace_id, self.scope.application_id,
                     query_id)).fetchone()
                if not remains or remains['remains']:
                    raise ValueError('PGDUCKDB_PUBLIC_CLEANUP_INCOMPLETE')

    def assert_disposable(self) -> None:
        """Fail before the lifecycle is allowed to create a technical row."""
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                self._assert_guard(db)

    @staticmethod
    def _assert_guard(db) -> None:
        guard = db.execute(
            "SELECT current_database() AS database_name, "
            "current_setting(%s,true) AS disposable",
            (DISPOSABLE_SETTING,)).fetchone()
        if (not guard
                or not guard['database_name'].startswith(
                    DISPOSABLE_DATABASE_PREFIX)
                or guard['disposable'] != 'on'):
            raise ValueError('PGDUCKDB_PUBLIC_DATABASE_NOT_DISPOSABLE')

