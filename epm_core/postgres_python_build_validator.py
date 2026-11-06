"""Identity-aware, no-effect validation for Python-generated V2 operations."""
from __future__ import annotations

import json
from typing import Mapping

from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_capability_contract import filter_catalog
from .postgres_connection import connect_postgres
from .postgres_language_v2 import PostgresLanguageV2
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import configure_statement_timeout


class PostgresPythonBuildOperationValidator:
    """Validate by the public preview compiler without admitting any effect.

    The initial Python frontend intentionally supports only functions whose
    public contract requires preview.  A function without an authoritative
    no-effect compiler is rejected rather than approximated with an allow-list.
    """

    def __init__(self, dsn: str, *, identity: VerifiedIdentity,
                 preview_secret: bytes, metadata_revision: int,
                 policy_revision: int, schema_epoch: int,
                 language=None):
        if (type(dsn) is not str or not dsn
                or not isinstance(identity, VerifiedIdentity)
                or type(preview_secret) is not bytes or len(preview_secret) < 32
                or any(type(value) is not int or value < 0 for value in
                       (metadata_revision, policy_revision, schema_epoch))):
            raise ValueError('PYTHON_BUILD_VALIDATOR_CONFIGURATION_INVALID')
        self.dsn, self.identity = dsn, identity
        self.preview_secret = preview_secret
        self.expected = (metadata_revision, policy_revision, schema_epoch)
        self.language = language or PostgresLanguageV2(
            dsn, identity=identity, preview_secret=preview_secret)

    def _read_state(self, scope: ApplicationScope) -> dict:
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 15000)
                PostgresNumericFactStore._set_scope(db, scope)
                state = db.execute('''SELECT metadata_revision,policy_revision,
                    schema_epoch,enabled_capabilities FROM epm.application_state
                    WHERE workspace_id=%s AND application_id=%s''',
                    (scope.workspace_id, scope.application_id)).fetchone()
                if state is None or tuple(state[key] for key in
                        ('metadata_revision','policy_revision','schema_epoch')) != self.expected:
                    raise ValueError('PYTHON_BUILD_STALE_CONTEXT')
                return dict(state)

    def validate_operation(self, scope: ApplicationScope, function: str,
                           arguments: Mapping[str, object]) -> dict:
        if (not isinstance(scope, ApplicationScope) or type(function) is not str
                or type(arguments) is not dict):
            raise ValueError('PYTHON_BUILD_OPERATION_INVALID')
        state = self._read_state(scope)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                configure_statement_timeout(db, 15000)
                PostgresNumericFactStore._set_scope(db, scope)
                catalog = filter_catalog(PostgresLanguageV2.catalog(),
                                         state['enabled_capabilities'])
                specification = catalog['functions'].get(function)
                if specification is None:
                    raise ValueError('PYTHON_BUILD_FUNCTION_UNAVAILABLE')
                if not specification.get('previewRequired', False):
                    raise ValueError('PYTHON_BUILD_FUNCTION_NO_EFFECT_VALIDATOR')
                permission = specification.get('permission')
                if permission not in ('write', 'admin', 'rule_design',
                                      'rule_publish', 'rule_run'):
                    raise ValueError('PYTHON_BUILD_FUNCTION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(db, self.identity,
                    scope, permission, function=function,
                    arguments=dict(arguments))
        program = {'languageVersion': 2, 'function': function,
                   'arguments': dict(arguments)}
        # This path compiles, resolves metadata, enforces work bounds and signs
        # a disposable preview.  It never calls submit/apply/publish.
        result = self.language.preview(scope, program)
        if (type(result) is not dict or result.get('function') != function
                or 'previewToken' not in result):
            raise ValueError('PYTHON_BUILD_PREVIEW_VALIDATION_FAILED')
        vector = result.get('revisionVector')
        if vector is not None:
            if type(vector) is not dict:
                raise ValueError('PYTHON_BUILD_PREVIEW_VALIDATION_FAILED')
            aliases = (('metadata_revision', 'metadataRevision', self.expected[0]),
                       ('policy_revision', 'policyRevision', self.expected[1]),
                       ('schema_epoch', 'schemaEpoch', self.expected[2]))
            for snake, camel, expected in aliases:
                present = [vector[name] for name in (snake, camel)
                           if name in vector]
                if present and any(value != expected for value in present):
                    raise ValueError('PYTHON_BUILD_STALE_CONTEXT')
        # Preview uses its own transaction.  Its result is provisional until a
        # second read proves that all build pins still match after compilation.
        self._read_state(scope)
        try:
            return json.loads(json.dumps(arguments, sort_keys=True,
                separators=(',', ':'), ensure_ascii=True, allow_nan=False))
        except (TypeError, ValueError) as error:
            raise ValueError('PYTHON_BUILD_OPERATION_NOT_CANONICAL') from error
