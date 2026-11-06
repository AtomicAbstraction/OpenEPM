"""Enroll the first verified platform operator after PostgreSQL migrations.

This deployment-owner command establishes the identity trust root only; all
workspace and application creation must then use authenticated V2 MCP programs.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import os

import sys
from pathlib import Path

# Support both the packaged module command and direct deployment-owner CLI.
if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


def bootstrap_operator(dsn: str,issuer: str,subject_id: str) -> str:
    if not isinstance(dsn,str) or not dsn:
        raise ValueError('Migration-owner PostgreSQL DSN is required')
    if (not isinstance(issuer,str) or not issuer.startswith('https://')
            or not 1 <= len(issuer) <= 300
            or not isinstance(subject_id,str)
            or not 1 <= len(subject_id) <= 300):
        raise ValueError('Verified provider issuer and subject are required')
    with connect_postgres(dsn,row_factory=dict_row) as db:
        with db.transaction():
            owner=db.execute('''SELECT pg_get_userbyid(relowner)=current_user
                AS owns_table FROM pg_class WHERE oid=
                'epm.platform_operator_grant'::regclass''').fetchone()
            if not owner or not owner['owns_table']:
                raise ValueError('OPERATOR_BOOTSTRAP_REQUIRES_MIGRATION_OWNER')
            db.execute('''SELECT pg_advisory_xact_lock(
                hashtextextended('epm.platform.operator.bootstrap',0))''')
            existing=db.execute('''SELECT issuer,subject_id
                FROM epm.platform_operator_grant''').fetchall()
            if existing:
                if any(row['issuer']==issuer and row['subject_id']==subject_id
                       for row in existing):
                    current=db.execute('''SELECT status
                        FROM epm.identity_user_directory_state
                        WHERE issuer=%s AND subject_id=%s''',
                        (issuer,subject_id)).fetchone()
                    if not current or current['status']!='Active':
                        raise ValueError(
                            'PLATFORM_OPERATOR_DIRECTORY_STATE_NOT_ACTIVE')
                    return 'verified'
                raise ValueError('PLATFORM_OPERATOR_ALREADY_INITIALIZED')
            db.execute('''INSERT INTO epm.platform_operator_grant
                (issuer,subject_id) VALUES (%s,%s)''',(issuer,subject_id))
            revision=db.execute('''UPDATE epm.identity_directory_state
                SET revision=revision+1,updated_at=transaction_timestamp()
                WHERE singleton RETURNING revision''').fetchone()
            if not revision:
                raise ValueError('IDENTITY_DIRECTORY_STATE_MISSING')
            db.execute('''INSERT INTO epm.identity_user_directory_state
                (issuer,subject_id,status,directory_revision)
                VALUES (%s,%s,'Active',%s)''',
                (issuer,subject_id,revision['revision']))
            actor_digest=sha256((issuer+'\0'+subject_id).encode()).hexdigest()
            db.execute('''INSERT INTO epm.security_audit
                (actor_id,action,target_digest,outcome,detail)
                VALUES (%s,'platform.operator.bootstrap',%s,'Accepted',%s)''',
                (actor_digest,actor_digest,Jsonb({})))
            return 'enrolled'


def main() -> None:
    from epm_core.postgres_admin_execution import add_budget_argument,run_admin_cli
    parser=argparse.ArgumentParser(description=__doc__)
    add_budget_argument(parser)
    parser.add_argument('--dsn',default=os.environ.get('EPM_POSTGRES_ADMIN_DSN'))
    parser.add_argument('--issuer',required=True,
                        help='Verified provider issuer URL')
    parser.add_argument('--subject-id',required=True,
                        help='Stable verified provider subject ID')
    args=parser.parse_args()
    print(run_admin_cli(parser,'operator',{'dsn':args.dsn,'issuer':args.issuer,
        'subjectId':args.subject_id},args.timeout_seconds))


if __name__=='__main__':
    main()
