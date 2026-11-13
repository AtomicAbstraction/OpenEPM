"""Create the six non-owner PostgreSQL service logins after migrations.

Supply EPM_POSTGRES_ADMIN_DSN and one distinct 24+-character password in each
EPM_PG_*_PASSWORD variable. Existing logins are checked, never silently
regranted or rotated. Password values are not printed or written to files.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os

import sys
from pathlib import Path

# Support both the packaged module command and direct deployment-owner CLI.
if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import psycopg
from epm_core.postgres_connection import connect_postgres
from psycopg import sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb


ROLES = (
    ('epm_runtime_login','epm_runtime','EPM_PG_RUNTIME_PASSWORD'),
    ('epm_access_login','epm_access','EPM_PG_ACCESS_PASSWORD'),
    ('epm_worker_login','epm_worker','EPM_PG_WORKER_PASSWORD'),
    ('epm_lifecycle_login','epm_lifecycle','EPM_PG_LIFECYCLE_PASSWORD'),
    ('epm_provision_login','epm_provision','EPM_PG_PROVISION_PASSWORD'),
    ('epm_security_login','epm_security','EPM_PG_SECURITY_PASSWORD'),
)


def bootstrap_service_roles(dsn: str,passwords: dict[str,str]) -> dict[str,str]:
    if not isinstance(dsn,str) or not dsn:
        raise ValueError('Migration-owner PostgreSQL DSN is required')
    secrets=[]
    for _,_,key in ROLES:
        value=passwords.get(key)
        if not isinstance(value,str) or len(value)<24 or '\x00' in value:
            raise ValueError(f'{key} must be a distinct 24+ character secret')
        secrets.append(value)
    if len(set(secrets))!=len(secrets):
        raise ValueError('Service login passwords must be distinct')
    results={}
    with connect_postgres(dsn,row_factory=dict_row) as db:
        with db.transaction():
            owner=db.execute('''SELECT pg_get_userbyid(relowner)=current_user
                AS owns_table FROM pg_class WHERE oid=
                'epm.schema_migration'::regclass''').fetchone()
            if not owner or not owner['owns_table']:
                raise ValueError('SERVICE_BOOTSTRAP_REQUIRES_MIGRATION_OWNER')
            db.execute('''SELECT pg_advisory_xact_lock(
                hashtextextended('epm.platform.service_roles.bootstrap',0))''')
            for login,member_role,password_key in ROLES:
                existing=db.execute('''SELECT rolcanlogin,rolsuper,rolbypassrls,
                    rolcreaterole,rolcreatedb,rolreplication
                    FROM pg_roles WHERE rolname=%s''',(login,)).fetchone()
                if existing:
                    memberships={row['rolname'] for row in db.execute('''SELECT
                        parent.rolname FROM pg_auth_members m
                        JOIN pg_roles child ON child.oid=m.member
                        JOIN pg_roles parent ON parent.oid=m.roleid
                        WHERE child.rolname=%s''',(login,)).fetchall()}
                    if (not existing['rolcanlogin']
                            or any(existing[key] for key in (
                                'rolsuper','rolbypassrls','rolcreaterole',
                                'rolcreatedb','rolreplication'))
                            or memberships!={member_role}):
                        raise ValueError('SERVICE_LOGIN_CONFIGURATION_CONFLICT')
                    results[login]='verified'
                    continue
                db.execute(sql.SQL('''CREATE ROLE {} LOGIN INHERIT PASSWORD {}
                    NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
                    NOREPLICATION''').format(
                        sql.Identifier(login),sql.Literal(passwords[password_key])))
                db.execute(sql.SQL('GRANT {} TO {}').format(
                    sql.Identifier(member_role),sql.Identifier(login)))
                results[login]='created'
            if 'created' in results.values():
                actor_digest=sha256(('deployment:'+db.execute(
                    'SELECT current_user').fetchone()['current_user']).encode()
                    ).hexdigest()
                db.execute('''INSERT INTO epm.security_audit
                    (actor_id,action,target_digest,outcome,detail)
                    VALUES (%s,'platform.service_roles.bootstrap',%s,
                    'Accepted',%s)''',
                    (actor_digest,sha256(','.join(results).encode()).hexdigest(),
                     Jsonb({'created':[role for role,status in results.items()
                                       if status=='created']})))
    return results


def main() -> None:
    from epm_core.postgres_admin_execution import add_budget_argument,run_admin_cli
    parser=argparse.ArgumentParser(description=__doc__)
    add_budget_argument(parser)
    parser.add_argument('--dsn',default=os.environ.get('EPM_POSTGRES_ADMIN_DSN'))
    args=parser.parse_args()
    result=run_admin_cli(parser,'service-roles',{'dsn':args.dsn,
        'passwords':{key:os.environ.get(key,'') for _,_,key in ROLES}},args.timeout_seconds)
    print(json.dumps(result,
                     sort_keys=True))


if __name__=='__main__':
    main()
