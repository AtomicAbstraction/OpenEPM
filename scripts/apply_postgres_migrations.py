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
    assert_pristine_database,canonical_chain_digest,database_profile,
    load_baseline_manifest,schema_fingerprint)
from epm_core.postgres_schema163_semantic_reference import (
    derive_historical_execution_statement)


LOCK_KEY = 0x45504D4D494752
DEFAULT_DIR = Path(__file__).resolve().parents[1] / 'schema' / 'postgres'
MIGRATION_LOCK_TIMEOUT_MS = 5_000
MIGRATION_STATEMENT_TIMEOUT_MS = 600_000
DATABASE_IDENTITY_SQL = """SELECT system_identifier::text || ' ' || oid::text
    FROM pg_catalog.pg_control_system(), pg_catalog.pg_database
    WHERE datname = pg_catalog.current_database()"""


def migration_database_digest(identity: str) -> str:
    """Bind a PostgreSQL cluster and database without recording its DSN."""
    if not isinstance(identity, str) or re.fullmatch(
            r'[1-9][0-9]{0,19} [1-9][0-9]{0,9}', identity) is None:
        raise ValueError('MIGRATION_DATABASE_IDENTITY_INVALID')
    return hashlib.sha256(b'openepm-migration-database-v1\0' + identity.encode('ascii')).hexdigest()


def configure_migration_budgets(db) -> None:
    """Bound each migration statement and lock wait without weakening limits."""
    db.execute('''SELECT set_config(s.name,
        least(coalesce(nullif(s.setting::bigint,0),b.ms),b.ms)::text,false)
        FROM pg_settings s JOIN (VALUES
          ('lock_timeout',%s),('statement_timeout',%s)) AS b(name,ms)
        ON s.name=b.name''',
        (MIGRATION_LOCK_TIMEOUT_MS, MIGRATION_STATEMENT_TIMEOUT_MS))


def migration_files(directory: Path = DEFAULT_DIR, *,
                    expected_final_migration: str | None = None) -> list[tuple[int, str, Path]]:
    files = sorted(directory.glob('*.sql'))
    parsed = []
    for file in files:
        match = re.fullmatch(r'([0-9]{4})_([a-z0-9_]+)\.sql', file.name)
        if not match or file.is_symlink() or not file.is_file():
            raise ValueError(f'Unexpected migration filename: {file.name}')
        parsed.append((int(match.group(1)), match.group(2), file))
    if not parsed or [version for version, _, _ in parsed] != list(
            range(1, len(parsed) + 1)):
        raise ValueError('PostgreSQL migrations must start at 0001 with no gaps')
    if expected_final_migration is not None and parsed[-1][2].name != expected_final_migration:
        raise ValueError('MIGRATION_TARGET_DIFFERS_FROM_RELEASE')
    return parsed


def verify_applied_migrations(files: list[tuple[int, str, Path]],
                              applied: dict[int, str]) -> None:
    """Verify the entire installed prefix before running any pending migration."""
    if set(applied) - {version for version, _, _ in files}:
        raise ValueError('Database has a migration absent from this release')
    if set(applied) != set(range(1, len(applied) + 1)):
        raise ValueError('Installed PostgreSQL migration history has a gap')
    for version, _, file in files[:len(applied)]:
        if applied[version] != hashlib.sha256(file.read_bytes()).hexdigest():
            raise ValueError(f'Migration {version:04d} checksum changed')


def apply_migrations(dsn: str, directory: Path = DEFAULT_DIR, *,
                     fresh_baseline_manifest: Path|None = None,
                     expected_final_migration: str | None = None,
                     expected_source_ledger: str | None = None,
                     expected_source_database: str | None = None,
                     _baseline_failure_point: str|None = None) -> list[str]:
    if fresh_baseline_manifest is not None and expected_final_migration is not None:
        raise ValueError('MIGRATION_TARGET_INCOMPATIBLE_WITH_FRESH_BASELINE')
    if (expected_source_ledger is not None and
            (expected_final_migration is None
             or not isinstance(expected_source_ledger, str)
             or re.fullmatch(r'[0-9]{4} [a-f0-9]{64}', expected_source_ledger) is None)):
        raise ValueError('MIGRATION_SOURCE_LEDGER_INVALID')
    if (expected_source_database is not None and
            (expected_source_ledger is None or not isinstance(expected_source_database, str)
             or re.fullmatch(r'[a-f0-9]{64}', expected_source_database) is None)):
        raise ValueError('MIGRATION_SOURCE_DATABASE_INVALID')
    parsed = migration_files(directory, expected_final_migration=expected_final_migration)

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
            if expected_source_database is not None:
                identity = db.execute(DATABASE_IDENTITY_SQL).fetchone()
                if (identity is None or
                        migration_database_digest(identity[0]) != expected_source_database):
                    raise ValueError('MIGRATION_SOURCE_DATABASE_CHANGED')
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
            verify_applied_migrations(parsed, existing)
            if expected_source_ledger is not None:
                digest = canonical_chain_digest([
                    {'version': version, 'sha256': checksum}
                    for version, checksum in sorted(existing.items())
                ])
                if expected_source_ledger != f'{len(existing):04d} {digest}':
                    raise ValueError('MIGRATION_SOURCE_LEDGER_CHANGED')
            for version, description, file in parsed:
                if version in existing:
                    outcome.append(f'{version:04d} ' +
                                   ('applied' if version in baseline_applied else 'verified'))
                    continue
                source = file.read_bytes()
                checksum = hashlib.sha256(source).hexdigest()
                try:
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
                except psycopg.errors.RaiseException as error:
                    if (version != 366 or error.diag.message_primary
                            != 'DEFINITION_OWNER_0366_UNKNOWN_RULE_KIND'):
                        raise
                    raise ValueError(
                        'DEFINITION_OWNER_0366_UNKNOWN_RULE_KIND. Migration 0366 refused stored rules '
                        'without a supported owner. Preserve the source application and review the affected '
                        'rule definitions for re-authoring before retrying.'
                    ) from None
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
    variants = parser.add_mutually_exclusive_group()
    variants.add_argument('--fresh-baseline-manifest',type=Path,
        help='Qualified pristine-install snapshot manifest; never valid for upgrades')
    variants.add_argument('--expected-final-migration',
        help='Exact final filename declared by the verified release manifest during upgrade')
    parser.add_argument('--expected-source-ledger',
        help='Source version and chain digest observed before upgrade backup, checked under the migration lock')
    parser.add_argument('--expected-source-database',
        help='Digest of the source PostgreSQL cluster and database checked under the migration lock')
    args = parser.parse_args()
    if not args.dsn:
        parser.error('Set EPM_POSTGRES_ADMIN_DSN or pass --dsn')
    arguments = {'dsn': args.dsn, 'directory': str(args.migrations_dir.resolve())}
    if args.fresh_baseline_manifest is not None:
        arguments['freshBaselineManifest'] = str(args.fresh_baseline_manifest.resolve())
    if args.expected_final_migration is not None:
        arguments['expectedFinalMigration'] = args.expected_final_migration
    if args.expected_source_ledger is not None:
        arguments['expectedSourceLedger'] = args.expected_source_ledger
    if args.expected_source_database is not None:
        arguments['expectedSourceDatabase'] = args.expected_source_database
    results = run_admin_cli(parser, 'migrate', arguments, args.timeout_seconds)
    for result in results:
        print(result)


if __name__ == '__main__':
    main()
