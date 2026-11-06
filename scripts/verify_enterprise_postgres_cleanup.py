#!/usr/bin/env python3
"""Verify that the disposable enterprise PostgreSQL run left no owned state."""
from __future__ import annotations

import json
import os
import sys

import psycopg


ALLOWED_DATABASES = frozenset(("postgres",))
ALLOWED_SCHEMAS = frozenset(("public",))


def evaluate(databases: list[str], schemas: list[str]) -> dict:
    remaining_databases = sorted(set(databases) - ALLOWED_DATABASES)
    remaining_schemas = sorted(set(schemas) - ALLOWED_SCHEMAS)
    return {
        "format": "openepm-enterprise-postgres-cleanup-v1",
        "cleanupVerified": not remaining_databases and not remaining_schemas,
        "remainingDatabases": remaining_databases,
        "remainingSchemas": remaining_schemas,
        "serviceContainerLifecycle": "ci-or-caller-owned-disposable",
    }


def verify(dsn: str) -> dict:
    if os.environ.get("EPM_TEST_POSTGRES_DISPOSABLE") != "1":
        raise RuntimeError("EPM_TEST_POSTGRES_DISPOSABLE=1 is required")
    if not dsn:
        raise RuntimeError("EPM_TEST_POSTGRES_DSN is required")
    with psycopg.connect(dsn, autocommit=True) as connection:
        databases = [row[0] for row in connection.execute(
            "SELECT datname FROM pg_database "
            "WHERE datallowconn AND NOT datistemplate ORDER BY datname")]
        schemas = [row[0] for row in connection.execute(
            "SELECT nspname FROM pg_namespace "
            "WHERE nspname NOT LIKE 'pg_%' AND nspname <> 'information_schema' "
            "ORDER BY nspname")]
    return evaluate(databases, schemas)


def main() -> int:
    result = verify(os.environ.get("EPM_TEST_POSTGRES_DSN", ""))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["cleanupVerified"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, psycopg.Error) as error:
        print(json.dumps({
            "format": "openepm-enterprise-postgres-cleanup-v1",
            "cleanupVerified": False,
            "error": str(error)[:512],
        }, sort_keys=True, separators=(",", ":")), file=sys.stderr)
        raise SystemExit(2) from error
