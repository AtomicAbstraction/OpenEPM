"""Apply ordered Open EPM PostgreSQL migrations with checksum protection.

This is a deployment-owner tool. Development tests use only disposable
databases. Business metadata and facts still flow through the application core.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re

import sys

# Support both the packaged module command and direct deployment-owner CLI.
if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_fresh_baseline import (
    assert_pristine_database,database_profile,load_baseline_manifest,schema_fingerprint)
from epm_core.postgres_schema163_semantic_reference import (
    derive_historical_execution_statement)


LOCK_KEY = 0x45504D4D494752
DEFAULT_DIR = Path(__file__).resolve().parents[1] / 'schema' / 'postgres'
MIGRATION_LOCK_TIMEOUT_MS = 5_000
MIGRATION_STATEMENT_TIMEOUT_MS = 600_000


def configure_migration_budgets(db) -> None:
    """Bound each migration statement and lock wait without weakening limits."""
    db.execute('''SELECT set_config(s.name,
        least(coalesce(nullif(s.setting::bigint,0),b.ms),b.ms)::text,false)
        FROM pg_settings s JOIN (VALUES
          ('lock_timeout',%s),('statement_timeout',%s)) AS b(name,ms)
        ON s.name=b.name''',
        (MIGRATION_LOCK_TIMEOUT_MS, MIGRATION_STATEMENT_TIMEOUT_MS))


def apply_migrations(dsn: str, directory: Path = DEFAULT_DIR, *,
                     fresh_baseline_manifest: Path|None = None,
                     _baseline_failure_point: str|None = None) -> list[str]:
    files = sorted(directory.glob('*.sql'))
    parsed = []
    for file in files:
        match = re.fullmatch(r'(\d{4})_([a-z0-9_]+)\.sql', file.name)
        if not match:
            raise ValueError(f'Unexpected migration filename: {file.name}')
        parsed.append((int(match.group(1)), match.group(2), file))
    if not parsed or [version for version, _, _ in parsed] != list(
            range(1, len(parsed) + 1)):
        raise ValueError('PostgreSQL migrations must start at 0001 with no gaps')

    outcome = []
    baseline_applied=set()
    baseline=(load_baseline_manifest(fresh_baseline_manifest,parsed)
              if fresh_baseline_manifest is not None else None)
    with connect_postgres(dsn, autocommit=True) as db:
        locked = db.execute('SELECT pg_try_advisory_lock(%s)',
                            (LOCK_KEY,)).fetchone()[0]
        if not locked:
            raise ValueError('Another PostgreSQL migration runner is active')
        try:
            configure_migration_budgets(db)
            table = db.execute("SELECT to_regclass('epm.schema_migration')").fetchone()[0]
            existing = (dict(db.execute('SELECT version, checksum '
                                        'FROM epm.schema_migration').fetchall())
                        if table else {})
            if baseline is not None:
                assert_pristine_database(db)
                if database_profile(db)!=(baseline['postgresProfile'],baseline['extensionProfile']):
                    raise ValueError('FRESH_BASELINE_DATABASE_PROFILE_MISMATCH')
                with db.transaction():
                    for statement in baseline['statements']:
                        # Extended-query preparation rejects multiple top-level
                        # commands even when an item contains semicolons.
                        try:
                            db.execute(statement,prepare=True)
                        except psycopg.errors.SyntaxError as exc:
                            if 'multiple commands' not in str(exc).lower():
                                raise
                            raise ValueError(
                                'FRESH_BASELINE_ARTIFACT_STATEMENT_FORBIDDEN') from exc
                    if _baseline_failure_point=='after-artifact':
                        raise RuntimeError('INJECTED_BASELINE_FAILURE_AFTER_ARTIFACT')
                    table=db.execute("SELECT to_regclass('epm.schema_migration')").fetchone()[0]
                    if not table:
                        raise ValueError('FRESH_BASELINE_MIGRATION_RECORD_MISSING')
                    existing=dict(db.execute('SELECT version,checksum FROM epm.schema_migration').fetchall())
                    expected={x['version']:x['sha256'] for x in baseline['canonicalMigrations']}
                    if existing != expected:
                        raise ValueError('FRESH_BASELINE_MIGRATION_RECORD_MISMATCH')
                    actual_fingerprint=schema_fingerprint(db)
                    if actual_fingerprint != baseline['schemaFingerprint']:
                        raise ValueError('FRESH_BASELINE_SCHEMA_FINGERPRINT_MISMATCH')
                    if _baseline_failure_point=='after-fingerprint':
                        raise RuntimeError('INJECTED_BASELINE_FAILURE_AFTER_FINGERPRINT')
                    audit_version,audit_description,audit_file=parsed[163]
                    if audit_version!=164:
                        raise ValueError('FRESH_BASELINE_AUDIT_MIGRATION_MISSING')
                    audit_source=audit_file.read_bytes()
                    audit_checksum=hashlib.sha256(audit_source).hexdigest()
                    db.execute(audit_source.decode('utf-8'))
                    db.execute('''INSERT INTO epm.schema_migration
                      (version,description,checksum) VALUES (%s,%s,%s)''',(
                      audit_version,audit_description.replace('_',' '),audit_checksum))
                    db.execute('''INSERT INTO epm.schema_baseline_materialization(
                      baseline_id,target_version,canonical_chain_digest,
                      execution_artifact_digest,equivalence_evidence_digest,
                      schema_fingerprint,reviewer_identity,source_commit,build_id,
                      postgres_profile,extension_profile,artifact_format,
                      materialization_method)
                      VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',(
                      baseline['baselineId'],baseline['targetVersion'],
                      baseline['canonicalChainDigest'],baseline['artifactSha256'],
                      baseline['equivalenceEvidenceSha256'],baseline['schemaFingerprint'],
                      baseline['reviewerIdentity'],baseline['sourceCommit'],baseline['buildId'],
                      baseline['postgresProfile'],baseline['extensionProfile'],
                      baseline['artifactFormat'],
                      baseline['method']))
                    if _baseline_failure_point=='after-audit':
                        raise RuntimeError('INJECTED_BASELINE_FAILURE_AFTER_AUDIT')
                    existing[164]=audit_checksum
                    baseline_applied.add(164)
                outcome.append(f"baseline {baseline['baselineId']} materialized")
            if set(existing) - {version for version, _, _ in parsed}:
                raise ValueError('Database has a migration absent from this release')
            for version, description, file in parsed:
                source = file.read_bytes()
                checksum = hashlib.sha256(source).hexdigest()
                if version in existing:
                    if existing[version] != checksum:
                        raise ValueError(f'Migration {version:04d} checksum changed')
                    outcome.append(f'{version:04d} ' +
                                   ('applied' if version in baseline_applied else 'verified'))
                    continue
                if any(old_version not in existing for old_version in range(1, version)):
                    raise ValueError(f'Migration {version:04d} has an unapplied predecessor')
                with db.transaction():
                    text=source.decode('utf-8')
                    if 144 <= version <= 163:
                        statement,_ = derive_historical_execution_statement(
                            version,source)
                        db.execute(statement)
                    else:
                        db.execute(text)
                    db.execute('''INSERT INTO epm.schema_migration
                        (version, description, checksum) VALUES (%s,%s,%s)''',
                        (version, description.replace('_', ' '), checksum))
                existing[version] = checksum
                outcome.append(f'{version:04d} applied')
        finally:
            db.execute('SELECT pg_advisory_unlock(%s)', (LOCK_KEY,))
    return outcome


def main() -> None:
    from epm_core.postgres_admin_execution import add_budget_argument,run_admin_cli
    parser = argparse.ArgumentParser(description=__doc__)
    add_budget_argument(parser)
    parser.add_argument('--dsn', default=os.environ.get('EPM_POSTGRES_ADMIN_DSN'),
                        help='Migration-owner DSN; prefer EPM_POSTGRES_ADMIN_DSN')
    parser.add_argument('--migrations-dir', type=Path, default=DEFAULT_DIR)
    parser.add_argument('--fresh-baseline-manifest',type=Path,
        help='Qualified pristine-install snapshot manifest; never valid for upgrades')
    args = parser.parse_args()
    if not args.dsn:
        parser.error('Set EPM_POSTGRES_ADMIN_DSN or pass --dsn')
    results=run_admin_cli(parser,'migrate',{'dsn':args.dsn,
        'directory':str(args.migrations_dir.resolve()),
        'freshBaselineManifest':(None if args.fresh_baseline_manifest is None else
            str(args.fresh_baseline_manifest.resolve()))},args.timeout_seconds)
    for result in results:
        print(result)


if __name__ == '__main__':
    main()
