"""Immutable, content-checked acquisition policy source captures.

The server verifies the bytes received from the authorized client. The claimed
source URI/version and external origin are not independently authenticated.
"""
from __future__ import annotations

import base64
import binascii
from hashlib import sha256
import re

import psycopg
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_processing_limits import configure_statement_timeout
from psycopg.rows import dict_row

from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_jobs import _canonical_digest
from .postgres_numeric_store import PostgresNumericFactStore
from psycopg.types.json import Jsonb
from .postgres_policy_client_pdf import (
    SCHEMA_VERSION as CLIENT_PDF_SCHEMA,
    TRUST as CLIENT_PDF_TRUST, validate_manifest)


CAPTURE_FUNCTION = 'consolidation.policy.source.artifact.capture'
READ_FUNCTION = 'consolidation.policy.source.artifact.read'
CONTENT_FUNCTION = 'consolidation.policy.source.artifact.content.read'
CLIENT_PDF_PAGE_FUNCTION = (
    'consolidation.policy.source.artifact.client_pdf.page.read')
_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_HASH = re.compile(r'[0-9a-f]{64}\Z')
_MAX_BYTES = 4 * 1024 * 1024
_MEDIA_TYPES = frozenset(('application/pdf', 'text/plain',
                          'application/json', 'image/png', 'image/jpeg'))


def _program(raw: object, function: str) -> dict:
    if (not isinstance(raw, dict)
            or set(raw) != {'languageVersion', 'function', 'arguments'}
            or type(raw['languageVersion']) is not int
            or raw['languageVersion'] != 2 or raw['function'] != function
            or not isinstance(raw['arguments'], dict)):
        raise ValueError('POLICY_SOURCE_ARTIFACT_PROGRAM_INVALID')
    args = raw['arguments']
    if function in (READ_FUNCTION, CONTENT_FUNCTION,
                    CLIENT_PDF_PAGE_FUNCTION):
        expected = ({'artifactId','extractionArtifactId','page'}
                    if function == CLIENT_PDF_PAGE_FUNCTION
                    else {'artifactId'})
        if (set(args) != expected
                or not isinstance(args['artifactId'], str)
                or not _KEY.fullmatch(args['artifactId'])
                or function == CLIENT_PDF_PAGE_FUNCTION and (
                    not isinstance(args['extractionArtifactId'], str)
                    or not _KEY.fullmatch(args['extractionArtifactId'])
                    or args['extractionArtifactId'] == args['artifactId']
                    or
                    type(args['page']) is not int
                    or not 1 <= args['page'] <= 100)):
            raise ValueError('POLICY_SOURCE_ARTIFACT_ARGUMENTS_INVALID')
        return args
    base = {'sourceRef', 'sourceVersion', 'mediaType', 'contentBase64',
            'expectedSha256', 'expectedPolicyRevision',
            'expectedCommitRevision'}
    if (function != CAPTURE_FUNCTION
            or set(args) not in (base, base | {'clientPdfExtraction'})
            or not isinstance(args['sourceRef'], str)
            or not 1 <= len(args['sourceRef'].strip()) <= 500
            or args['sourceRef'] != args['sourceRef'].strip()
            or not isinstance(args['sourceVersion'], str)
            or not 1 <= len(args['sourceVersion'].strip()) <= 128
            or args['sourceVersion'] != args['sourceVersion'].strip()
            or not isinstance(args['mediaType'], str)
            or args['mediaType'] not in _MEDIA_TYPES
            or not isinstance(args['contentBase64'], str)
            or not 4 <= len(args['contentBase64']) <=
                4 * ((_MAX_BYTES + 2) // 3)
            or not isinstance(args['expectedSha256'], str)
            or not _HASH.fullmatch(args['expectedSha256'])
            or any(type(args[key]) is not int or args[key] < 0
                   for key in ('expectedPolicyRevision',
                               'expectedCommitRevision'))):
        raise ValueError('POLICY_SOURCE_ARTIFACT_ARGUMENTS_INVALID')
    if 'clientPdfExtraction' in args:
        extraction = args['clientPdfExtraction']
        if (args['mediaType'] != 'application/pdf'
                or not isinstance(extraction, dict)
                or set(extraction) != {'artifactId', 'contentBase64',
                                       'expectedSha256'}
                or not isinstance(extraction['artifactId'], str)
                or not _KEY.fullmatch(extraction['artifactId'])
                or not isinstance(extraction['contentBase64'], str)
                or not 4 <= len(extraction['contentBase64']) <=
                    4 * ((2 * 1024 * 1024 + 2) // 3)
                or not isinstance(extraction['expectedSha256'], str)
                or not _HASH.fullmatch(extraction['expectedSha256'])):
            raise ValueError('POLICY_SOURCE_ARTIFACT_ARGUMENTS_INVALID')
    return args


class PostgresPolicySourceArtifacts:
    def __init__(self, dsn: str, *, identity: VerifiedIdentity):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError('A PostgreSQL runtime DSN is required')
        if not isinstance(identity, VerifiedIdentity):
            raise ValueError('A verified identity is required')
        self.dsn, self.identity = dsn, identity

    def capture(self, scope: ApplicationScope, program: object, *,
                idempotency_key: str) -> dict:
        if not isinstance(scope, ApplicationScope):
            raise ValueError('Application scope is required')
        args = _program(program, CAPTURE_FUNCTION)
        if (not isinstance(idempotency_key, str)
                or not _KEY.fullmatch(idempotency_key)):
            raise ValueError('POLICY_SOURCE_ARTIFACT_IDEMPOTENCY_KEY_INVALID')
        try:
            content = base64.b64decode(args['contentBase64'], validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError('POLICY_SOURCE_ARTIFACT_BASE64_INVALID') from error
        if not 1 <= len(content) <= _MAX_BYTES:
            raise ValueError('POLICY_SOURCE_ARTIFACT_SIZE_INVALID')
        digest = sha256(content).hexdigest()
        if digest != args['expectedSha256']:
            raise ValueError('POLICY_SOURCE_ARTIFACT_HASH_MISMATCH')
        extraction = None
        if 'clientPdfExtraction' in args:
            raw = args['clientPdfExtraction']
            if raw['artifactId'] == idempotency_key:
                raise ValueError('POLICY_SOURCE_CLIENT_EXTRACTION_ID_CONFLICT')
            try:
                extraction_content = base64.b64decode(
                    raw['contentBase64'], validate=True)
            except (binascii.Error, ValueError) as error:
                raise ValueError(
                    'POLICY_SOURCE_CLIENT_EXTRACTION_BASE64_INVALID') from error
            extraction_digest = sha256(extraction_content).hexdigest()
            if extraction_digest != raw['expectedSha256']:
                raise ValueError('POLICY_SOURCE_CLIENT_EXTRACTION_HASH_MISMATCH')
            manifest = validate_manifest(extraction_content,
                document_artifact_id=idempotency_key,
                document_sha256=digest)
            extraction = {'artifactId': raw['artifactId'],
                'content': extraction_content,
                'contentSha256': extraction_digest,
                'contentBytes': len(extraction_content),
                'schemaVersion': manifest['schemaVersion'],
                'extractor': manifest['extractor']}
        keys = (scope.workspace_id, scope.application_id)
        command_digest = _canonical_digest({
            'scope': list(keys),
            'identity': [self.identity.issuer, self.identity.subject_id],
            'function': CAPTURE_FUNCTION,
            'sourceRef': args['sourceRef'],
            'sourceVersion': args['sourceVersion'],
            'mediaType': args['mediaType'],
            'contentSha256': digest,
            'expectedPolicyRevision': args['expectedPolicyRevision'],
            'expectedCommitRevision': args['expectedCommitRevision'],
            'clientPdfExtraction': (None if extraction is None else {
                key: extraction[key] for key in ('artifactId','contentSha256',
                                                  'schemaVersion','extractor')})})
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                state = db.execute('''SELECT s.policy_revision,
                    s.commit_revision,s.processing_mode,
                    a.status AS application_status
                    FROM epm.application_state s JOIN epm.application a
                    USING (workspace_id,application_id)
                    WHERE s.workspace_id=%s AND s.application_id=%s
                    FOR UPDATE OF s''', keys).fetchone()
                if state is None:
                    raise ValueError('APPLICATION_UNAVAILABLE')
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin', function=CAPTURE_FUNCTION)
                prior = db.execute('''SELECT command_digest,actor_id,result
                    FROM epm.operation_receipt WHERE workspace_id=%s
                    AND application_id=%s AND operation_id=%s''',
                    (*keys, idempotency_key)).fetchone()
                if prior:
                    if (prior['command_digest'] != command_digest
                            or prior['actor_id'] != self.identity.subject_id):
                        raise ValueError(
                            'POLICY_SOURCE_ARTIFACT_IDEMPOTENCY_CONFLICT')
                    return prior['result']
                if (state['application_status'] != 'Active'
                        or state['processing_mode'] != 'Active'):
                    raise ValueError('APPLICATION_NOT_WRITABLE')
                if (state['policy_revision'] != args['expectedPolicyRevision']
                        or state['commit_revision'] !=
                        args['expectedCommitRevision']):
                    raise ValueError('STALE_POLICY_SOURCE_ARTIFACT_REVISION')
                if db.execute('''SELECT 1 FROM
                    epm.policy_source_artifact WHERE workspace_id=%s
                    AND application_id=%s AND client_extraction_id=%s''',
                    (*keys,idempotency_key)).fetchone():
                    raise ValueError(
                        'POLICY_SOURCE_ARTIFACT_IDEMPOTENCY_CONFLICT')
                if extraction is not None and db.execute('''SELECT 1 FROM
                    epm.policy_source_artifact WHERE workspace_id=%s
                    AND application_id=%s AND (artifact_id=%s OR
                    client_extraction_id=%s)''',
                    (*keys, extraction['artifactId'],
                     extraction['artifactId'])).fetchone():
                    raise ValueError(
                        'POLICY_SOURCE_CLIENT_EXTRACTION_ID_CONFLICT')
                policy_revision = state['policy_revision'] + 1
                commit_revision = state['commit_revision'] + 1
                result = {'artifactId': idempotency_key,
                    'sourceRef': args['sourceRef'],
                    'sourceVersion': args['sourceVersion'],
                    'mediaType': args['mediaType'],
                    'contentSha256': digest,
                    'contentBytes': len(content),
                    'captureIntegrityVerified': True,
                    'sourceOriginVerified': False,
                    'policyRevision': policy_revision,
                    'committedRevision': commit_revision,
                    'accountingExecutionSupported': False}
                if extraction is not None:
                    result['clientPdfExtraction'] = {
                        'artifactId': extraction['artifactId'],
                        'contentSha256': extraction['contentSha256'],
                        'contentBytes': extraction['contentBytes'],
                        'schemaVersion': extraction['schemaVersion'],
                        'extractor': extraction['extractor'],
                        'extractionTrust': CLIENT_PDF_TRUST}
                db.execute('''UPDATE epm.application_state SET
                    policy_revision=%s,commit_revision=%s
                    WHERE workspace_id=%s AND application_id=%s''',
                    (policy_revision, commit_revision, *keys))
                db.execute('''INSERT INTO epm.operation_receipt
                    (workspace_id,application_id,operation_id,
                    command_digest,actor_id,committed_revision,result)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)''',
                    (*keys, idempotency_key, command_digest,
                     self.identity.subject_id, commit_revision,
                     Jsonb(result)))
                db.execute('''INSERT INTO epm.policy_source_artifact
                    (workspace_id,application_id,artifact_id,source_ref,
                    source_version,media_type,content_sha256,
                    content_bytes,content,actor_issuer,actor_subject,
                    policy_revision,committed_revision,
                    client_extraction_id,client_extraction_sha256,
                    client_extraction_bytes,client_extraction)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                            %s,%s,%s,%s)''',
                    (*keys, idempotency_key,args['sourceRef'],
                     args['sourceVersion'],args['mediaType'],digest,
                     len(content),content,self.identity.issuer,
                     self.identity.subject_id,policy_revision,
                     commit_revision,
                     extraction['artifactId'] if extraction else None,
                     extraction['contentSha256'] if extraction else None,
                     extraction['contentBytes'] if extraction else None,
                     extraction['content'] if extraction else None))
                return result

    def read(self, scope: ApplicationScope, program: object, *,
             content: bool = False) -> dict:
        if not isinstance(scope, ApplicationScope):
            raise ValueError('Application scope is required')
        args = _program(program, CONTENT_FUNCTION if content else READ_FUNCTION)
        keys = (scope.workspace_id, scope.application_id)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, 'admin' if content else 'read', function=CONTENT_FUNCTION if content else READ_FUNCTION)
                content_column = ',content' if content else ''
                row = db.execute(f'''SELECT artifact_id,source_ref,
                    source_version,media_type,content_sha256,
                    content_bytes,actor_issuer,actor_subject,
                    policy_revision,committed_revision,captured_at,
                    client_extraction_id,client_extraction_sha256,
                    client_extraction_bytes
                    {content_column}
                    FROM epm.policy_source_artifact WHERE workspace_id=%s
                    AND application_id=%s AND artifact_id=%s''',
                    (*keys,args['artifactId'])).fetchone()
                if row is None:
                    raise ValueError('POLICY_SOURCE_ARTIFACT_UNAVAILABLE')
                result = {'artifactId': row['artifact_id'],
                    'sourceRef': row['source_ref'],
                    'sourceVersion': row['source_version'],
                    'mediaType': row['media_type'],
                    'contentSha256': row['content_sha256'],
                    'contentBytes': row['content_bytes'],
                    'captureActor': {'issuer': row['actor_issuer'],
                                     'subjectId': row['actor_subject']},
                    'policyRevision': row['policy_revision'],
                    'committedRevision': row['committed_revision'],
                    'capturedAt': row['captured_at'].isoformat(),
                    'captureIntegrityVerified': True,
                    'sourceOriginVerified': False,
                    'accountingExecutionSupported': False}
                if content:
                    raw = bytes(row['content'])
                    if sha256(raw).hexdigest() != row['content_sha256']:
                        raise ValueError('POLICY_SOURCE_ARTIFACT_CORRUPT')
                    result['contentBase64'] = base64.b64encode(raw).decode()
                if row['client_extraction_id'] is not None:
                    result['clientPdfExtraction'] = {
                        'artifactId':row['client_extraction_id'],
                        'contentSha256':row['client_extraction_sha256'],
                        'contentBytes':row['client_extraction_bytes'],
                        'schemaVersion':CLIENT_PDF_SCHEMA,
                        'extractionTrust':CLIENT_PDF_TRUST}
                return result

    def read_client_pdf_page(self, scope: ApplicationScope,
                             program: object) -> dict:
        if not isinstance(scope, ApplicationScope):
            raise ValueError('Application scope is required')
        args = _program(program, CLIENT_PDF_PAGE_FUNCTION)
        with connect_postgres(self.dsn, row_factory=dict_row) as db:
            with db.transaction():
                configure_statement_timeout(db, 10000)
                PostgresNumericFactStore._set_scope(db, scope)
                PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,'admin',
                    function=CLIENT_PDF_PAGE_FUNCTION)
                row = db.execute('''SELECT artifact_id,content_sha256,
                    media_type,client_extraction_id,
                    client_extraction_sha256,client_extraction_bytes,
                    client_extraction
                    FROM epm.policy_source_artifact
                    WHERE workspace_id=%s AND application_id=%s
                    AND artifact_id=%s''',
                    (scope.workspace_id,scope.application_id,
                     args['artifactId'])).fetchone()
                if row is None:
                    raise ValueError('POLICY_SOURCE_ARTIFACT_UNAVAILABLE')
                if (row['media_type'] != 'application/pdf'
                        or row['client_extraction_id'] !=
                            args['extractionArtifactId']):
                    raise ValueError('POLICY_SOURCE_VALUE_MEDIA_TYPE_UNSUPPORTED')
                extraction_content = bytes(row['client_extraction'])
                if (len(extraction_content) != row['client_extraction_bytes']
                        or sha256(extraction_content).hexdigest() !=
                            row['client_extraction_sha256']):
                    raise ValueError('POLICY_SOURCE_ARTIFACT_CORRUPT')
                manifest = validate_manifest(extraction_content,
                    document_artifact_id=args['artifactId'],
                    document_sha256=row['content_sha256'])
                page = manifest['pages'].get(args['page'])
                if page is None:
                    raise ValueError('POLICY_SOURCE_CLIENT_PDF_PAGE_UNAVAILABLE')
                return {'artifactId':args['artifactId'],
                    'extractionArtifactId':args['extractionArtifactId'],
                    'contentSha256':row['content_sha256'], **page,
                    'schemaVersion':CLIENT_PDF_SCHEMA,
                    'extractor':manifest['extractor'],
                    'extractionTrust':CLIENT_PDF_TRUST,
                    'sourceOriginVerified':False,
                    'accountingExecutionSupported':False}
