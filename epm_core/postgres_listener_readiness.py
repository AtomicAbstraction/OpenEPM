"""Bounded database and schema readiness for public PostgreSQL listeners."""
from __future__ import annotations

import os
import re
from pathlib import Path

from .deployment_secrets import configured_text
from .postgres_connection import connect_postgres


_DSNS = (
    ('EPM_PG_ACCESS_DSN', 'EPM_PG_ACCESS_DSN_FILE'),
    ('EPM_PG_RUNTIME_DSN', 'EPM_PG_RUNTIME_DSN_FILE'),
    ('EPM_PG_LIFECYCLE_DSN', 'EPM_PG_LIFECYCLE_DSN_FILE'),
    ('EPM_PG_SECURITY_DSN', 'EPM_PG_SECURITY_DSN_FILE'),
    ('EPM_PG_PROVISION_DSN', 'EPM_PG_PROVISION_DSN_FILE'),
)


def expected_schema_version(root: Path | None = None) -> int:
    directory = (Path(__file__).resolve().parents[1] / 'schema' / 'postgres'
                 if root is None else Path(root))
    versions = []
    for path in directory.glob('[0-9][0-9][0-9][0-9]_*.sql'):
        match = re.match(r'^(\d{4})_', path.name)
        if match:
            versions.append(int(match.group(1)))
    if not versions or len(versions) != len(set(versions)):
        raise ValueError('LISTENER_SCHEMA_INVENTORY_INVALID')
    maximum = max(versions)
    if set(versions) != set(range(1, maximum + 1)):
        raise ValueError('LISTENER_SCHEMA_INVENTORY_INVALID')
    return maximum


def configured_dsns(environment=None) -> tuple[str, ...]:
    environment = os.environ if environment is None else environment
    values = []
    for direct, file_name in _DSNS:
        if environment.get(direct) or environment.get(file_name):
            values.append(configured_text(environment, direct, file_name))
    if not values:
        raise ValueError('LISTENER_DATABASE_NOT_CONFIGURED')
    # A listener may expose the same role through multiple internal adapters.
    # Probe each credential only once without putting it in a set that could be
    # accidentally serialized by diagnostic code.
    return tuple(dict.fromkeys(values))


def assert_listener_database_readiness(environment=None) -> None:
    expected = expected_schema_version()
    for dsn in configured_dsns(environment):
        with connect_postgres(dsn, autocommit=True) as db:
            db.execute("SET statement_timeout='2000ms'")
            row = db.execute('''SELECT current_user,
                to_regprocedure('epm.current_schema_version()') IS NOT NULL,
                epm.current_schema_version()''').fetchone()
            if (not row or not isinstance(row[0], str) or not row[0]
                    or row[1] is not True or row[2] != expected):
                raise ValueError('LISTENER_DATABASE_SCHEMA_NOT_READY')
