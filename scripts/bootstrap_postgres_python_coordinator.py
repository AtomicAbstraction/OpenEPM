"""Create the fixed least-privilege Python-build coordinator login.

This is deployment bootstrap, not an application/business-data interface.  The
password is read from a protected file and is never printed or persisted by
the script.  Existing roles are verified exactly and are never broadened.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from psycopg import sql
from psycopg.rows import dict_row

from epm_core.postgres_connection import connect_postgres


LOGIN = "epm_python_coordinator_login"
GROUP = "epm_python_coordinator"


def _password(path: str) -> str:
    target = Path(path)
    try:
        if not target.is_file() or target.is_symlink():
            raise OSError
        value = target.read_text("utf-8").strip()
    except (OSError, UnicodeError) as error:
        raise ValueError("PYTHON_COORDINATOR_PASSWORD_UNAVAILABLE") from error
    if not 24 <= len(value) <= 4096 or "\x00" in value:
        raise ValueError("PYTHON_COORDINATOR_PASSWORD_INVALID")
    return value


def bootstrap(dsn: str, password: str) -> str:
    if type(dsn) is not str or not dsn or type(password) is not str \
            or not 24 <= len(password) <= 4096 or "\x00" in password:
        raise ValueError("PYTHON_COORDINATOR_BOOTSTRAP_INVALID")
    with connect_postgres(dsn, row_factory=dict_row) as db:
        with db.transaction():
            owner = db.execute("""SELECT pg_get_userbyid(relowner)=current_user
                AS owns_table FROM pg_class WHERE oid=
                'epm.schema_migration'::regclass""").fetchone()
            if not owner or not owner["owns_table"]:
                raise ValueError("PYTHON_COORDINATOR_BOOTSTRAP_REQUIRES_OWNER")
            db.execute("""SELECT pg_advisory_xact_lock(
                hashtextextended('epm.platform.python-coordinator.bootstrap',0))""")
            existing = db.execute("""SELECT rolcanlogin,rolsuper,rolbypassrls,
                rolcreaterole,rolcreatedb,rolreplication FROM pg_roles
                WHERE rolname=%s""", (LOGIN,)).fetchone()
            if existing is None:
                db.execute(sql.SQL("""CREATE ROLE {} LOGIN INHERIT PASSWORD {}
                    NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE
                    NOREPLICATION""").format(sql.Identifier(LOGIN),
                                              sql.Literal(password)))
                db.execute(sql.SQL("GRANT {} TO {}").format(
                    sql.Identifier(GROUP), sql.Identifier(LOGIN)))
                return "created"
            memberships = {row["rolname"] for row in db.execute("""SELECT
                parent.rolname FROM pg_auth_members m
                JOIN pg_roles child ON child.oid=m.member
                JOIN pg_roles parent ON parent.oid=m.roleid
                WHERE child.rolname=%s""", (LOGIN,)).fetchall()}
            if (not existing["rolcanlogin"]
                    or any(existing[key] for key in (
                        "rolsuper", "rolbypassrls", "rolcreaterole",
                        "rolcreatedb", "rolreplication"))
                    or memberships != {GROUP}):
                raise ValueError("PYTHON_COORDINATOR_LOGIN_CONFLICT")
            # The protected runtime secret may be regenerated while the
            # durable PostgreSQL role survives. Shape verification alone does
            # not prove that the configured DSN can authenticate. Reapply the
            # exact protected password after verifying least privilege so
            # recovery converges the credential instead of leaving the broker
            # in a restart loop.
            db.execute(sql.SQL("ALTER ROLE {} PASSWORD {}").format(
                sql.Identifier(LOGIN), sql.Literal(password)))
            return "synchronized"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dsn", default=os.environ.get("EPM_POSTGRES_ADMIN_DSN"))
    parser.add_argument("--password-file", default=os.environ.get(
        "EPM_PG_PYTHON_COORDINATOR_PASSWORD_FILE"))
    arguments = parser.parse_args()
    result = bootstrap(arguments.dsn or "", _password(arguments.password_file or ""))
    print(json.dumps({"login": LOGIN, "status": result}, sort_keys=True))


if __name__ == "__main__":
    main()
