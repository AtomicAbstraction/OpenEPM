"""Qualify public numeric-sequence retirement with preserved historical reads.

The fixture owns a disposable database upgraded to the current migration head and an owned host. It never modifies a
shared application. The retained producer job and receipt are read through the
real Browser and MCP adapters after public admission has been closed.
"""
from argparse import ArgumentParser
from hashlib import sha256
import json
from pathlib import Path
from runpy import run_path
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import uuid4


QUALIFICATIONS = Path('docs/qualifications')
HOST = QUALIFICATIONS / 'improvement-independent-restore-transfer-evidence-2026-11-23/run.py.txt'
DATABASE = 'sha256:07055f3aa4251aa21f73995daeb6769498b73c8cfac7bc320a7b592db2c06d26'
METHOD = 'test_populated_367_producer_upgrade_preserves_rows_and_rejects_unproven_adoption'


def check_history_authority(case, legacy, router, browser, ids, history, request, job, receipt, snapshot, migrated, dsn):
    from epm_core.postgres_access import AccessDenied, VerifiedIdentity
    from epm_core.postgres_mcp_application import PostgresMCPApplication
    from epm_core.postgres_security_language import PostgresSecurityLanguage
    from psycopg.rows import dict_row

    owner = VerifiedIdentity(legacy.test_identity.issuer, 'fixture-owner', issued_at=1)
    other = VerifiedIdentity(legacy.test_identity.issuer, 'reader', issued_at=1)
    security = PostgresSecurityLanguage(legacy.security_dsn, identity=owner)
    scope = dict(workspaceId=ids[0], applicationId=ids[1])

    def grant(actor, action, key):
        arguments = {'subjectId': actor.subject_id, 'action': action,
                     'role': 'Reader' if action == 'grant' else None}
        security.execute(legacy.scope, {'languageVersion': 2, 'function': 'security.application.access.set',
                                       'arguments': arguments}, idempotency_key=key)

    def job_reads(actor):
        return (
            lambda: router.job('fixture', *ids, history['job_id']),
            lambda: router.job('fixture', *ids, operation_id=history['idempotency_key']),
            lambda: browser._dispatch('/api/job', b'', {**scope, 'jobId': history['job_id']}, actor),
            lambda: browser._dispatch('/api/job', b'', {**scope, 'operationId': history['idempotency_key']}, actor),
        )

    def receipt_reads(actor):
        return (
            lambda: router.read('fixture', *ids, request),
            lambda: browser._dispatch('/api/read', b'', {**scope, 'program': request}, actor),
        )

    def read_rows():
        with case.case.psycopg.connect(dsn, row_factory=dict_row) as connection:
            return snapshot(connection)

    grant(legacy.test_identity, 'revoke', 'history-revoke-original-reader')
    revoked = read_rows()
    with patch.object(PostgresMCPApplication, '_identity', return_value=legacy.test_identity):
        for entry in (*job_reads(legacy.test_identity), *receipt_reads(legacy.test_identity)):
            with case.assertRaisesRegex(AccessDenied, '^APPLICATION_GRANT_REQUIRED$'):
                entry()
    case.assertEqual(read_rows(), revoked)

    grant(legacy.test_identity, 'grant', 'history-restore-original-reader')
    restored = read_rows()
    with patch.object(PostgresMCPApplication, '_identity', return_value=legacy.test_identity):
        for entry in job_reads(legacy.test_identity):
            case.assertEqual(entry(), job)
        for entry in receipt_reads(legacy.test_identity):
            case.assertEqual(entry(), receipt)
    case.assertEqual(read_rows(), restored)

    grant(other, 'grant', 'history-grant-other-reader')
    other_grant = read_rows()
    with patch.object(PostgresMCPApplication, '_identity', return_value=other):
        for entry in job_reads(other):
            with case.assertRaisesRegex(ValueError, '^JOB_UNAVAILABLE$'):
                entry()
        for entry in receipt_reads(other):
            case.assertEqual(entry(), receipt)
    case.assertEqual(read_rows(), other_grant)

    protected = ('job', 'operation_receipt', 'numeric_fact_event', 'numeric_cell_projection',
                 'application_rule_workflow_child', 'expression_rule_definition')
    for table in protected:
        case.assertEqual(other_grant[table], migrated[table], table)
    return {
        'currentRevocationRefusedReads': 6, 'currentReaderRegrantRecoveredExactReads': 6,
        'otherReaderCouldNotReadOwnerJob': 4, 'otherReaderCouldReadBoundedReceipt': 2,
        'readAttemptsPreservedScopedRows': True, 'preservedTablesAcrossGrantLifecycle': list(protected),
    }


def check_public_retirement(case, legacy, router, browser, ids, snapshot, dsn):
    from epm_core.postgres_mcp_application import PostgresMCPApplication
    from epm_core.postgres_language_v2 import PostgresLanguageV2
    from psycopg.rows import dict_row

    identity = legacy.test_identity
    scope = {'workspaceId': ids[0], 'applicationId': ids[1]}
    retired = ('rules.numeric_sequence.list', 'rules.numeric_sequence.read',
               'rules.numeric_sequence.run')
    replacement = ('application.rule.list', 'application.rule.read',
                   'application.rule.run')
    case.assertTrue(all(name in PostgresLanguageV2.catalog()['functions']
                        for name in replacement))

    def rows():
        with case.case.psycopg.connect(dsn, row_factory=dict_row) as db:
            return snapshot(db)

    before = rows()
    with patch.object(PostgresMCPApplication, '_identity', return_value=identity):
        catalogs = (
            router.catalog('fixture', *ids),
            browser._dispatch('/api/catalog', b'', scope, identity),
        )
        for catalog in catalogs:
            functions = catalog['functions']
            case.assertTrue(all(name not in functions for name in retired))

        for function, arguments in (
                (retired[0], {}), (retired[1], {'ruleId': 'legacy-rule'})):
            request = {'languageVersion': 2, 'function': function,
                       'arguments': arguments}
            with case.assertRaisesRegex(ValueError, '^APPLICATION_FUNCTION_RETIRED$'):
                router.read('fixture', *ids, request)
            with case.assertRaisesRegex(ValueError, '^APPLICATION_FUNCTION_RETIRED$'):
                browser._dispatch('/api/read', b'', {**scope, 'program': request}, identity)

        request = {'languageVersion': 2, 'function': retired[2],
                   'arguments': {'ruleId': 'legacy-rule', 'bindings': {}}}
        with case.assertRaisesRegex(ValueError, '^APPLICATION_FUNCTION_RETIRED$'):
            router.issue_operation_admission('fixture', *ids, request)
        with case.assertRaisesRegex(ValueError, '^APPLICATION_FUNCTION_RETIRED$'):
            browser._dispatch('/api/operation-admission', b'',
                              {**scope, 'program': request}, identity)
        with case.assertRaisesRegex(ValueError, '^APPLICATION_FUNCTION_RETIRED$'):
            router.submit('fixture', *ids, request, preview_token='stale',
                          idempotency_key='stale')
        with case.assertRaisesRegex(ValueError, '^APPLICATION_FUNCTION_RETIRED$'):
            browser._dispatch('/api/submit', b'', {**scope, 'program': request,
                'idempotencyKey': 'stale', 'previewToken': 'stale',
                'dependsOnJobIds': [], 'confirmed': True}, identity)
    case.assertEqual(rows(), before)
    return {'facades': ['mcp', 'browser'], 'retiredNamesAbsent': list(retired),
            'replacementInFixedCatalog': list(replacement),
            'staleReadRefusals': 4, 'staleRunRefusals': 4,
            'refusalCode': 'APPLICATION_FUNCTION_RETIRED',
            'scopedRowsUnchanged': True}


def run_owned_cases(output):
    from scripts import qualify_native_member_selection as qualification

    def bind(proof):
        observed = proof['populatedProducerUpgrade']
        if (observed.get('targetSchema') != proof['freshMigrationCount']
                or not observed.get('publicRetirement') or not observed.get('historyAuthority')):
            raise ValueError('RETIREMENT_HISTORY_OBSERVATIONS_MISSING')
        script = Path(__file__).resolve()
        proof['fixtureExtension'] = {
            'sha256': sha256(script.read_bytes()).hexdigest(), 'file': script.name,
            'baseMethod': METHOD,
        }

    qualification.qualify(output=output, database_image=DATABASE,
                          test_suite='legacy-sequence-upgrade', finalize_proof=bind)


def run_replay(output):
    if not output.is_dir() or any(output.iterdir()):
        raise ValueError('Use an empty output directory')
    host = run_path(str(HOST))
    base = host['base']
    docker, invoke = host['docker'], base['invoke']
    profile = 'epm-legacy-authority-' + uuid4().hex[:8]
    with TemporaryDirectory(prefix='epm-legacy-authority-image-') as directory:
        archive = Path(directory) / 'postgres.tar'
        with host['fresh_host'](profile) as context:
            docker(base['SOURCE_CONTEXT'], 'image', 'save', '--output', str(archive), DATABASE, timeout=180)
            docker(context, 'image', 'load', '--input', str(archive), timeout=180)
            archive.unlink()
            assert host['image_id'](context, DATABASE) == DATABASE
            environment = {**base['ENV'], 'DOCKER_CONTEXT': context,
                           'PYTHONPATH': str(Path.cwd()), 'PYTHONDONTWRITEBYTECODE': '1'}
            result = invoke(sys.executable, '-B', str(Path(__file__).resolve()), str(output / 'native.json'),
                            '--owned-cases', env=environment, timeout=600, check=False)
            (output / 'native.log.txt').write_bytes(result.stdout + result.stderr)
            host['assert_empty'](context)
    (output / 'cleanup.json').write_text(json.dumps({'profile': profile, 'databaseImage': DATABASE,
        'ownedVmContextAndDataDiskRemoved': True, 'exitCode': result.returncode}, indent=2) + '\n')
    return result.returncode


if __name__ == '__main__':
    parser = ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--owned-cases', action='store_true')
    args = parser.parse_args()
    if args.owned_cases:
        run_owned_cases(args.output.resolve())
    else:
        raise SystemExit(run_replay(args.output.resolve(strict=True)))
