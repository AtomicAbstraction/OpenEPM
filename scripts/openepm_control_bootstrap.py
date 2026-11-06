"""Fixed bootstrap for the isolated JupyterHub and Keycloak databases."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
from urllib.parse import parse_qs, unquote, urlsplit

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from scripts.openepm_release_operations import connection


ADMIN_DSN = Path("/run/secrets/control_admin_dsn")
HUB_URL = Path("/run/secrets/hub_database_url")
KEYCLOAK_URL = Path("/run/secrets/keycloak_database_url")
KEYCLOAK_USERNAME = Path("/run/secrets/keycloak_database_username")
KEYCLOAK_PASSWORD = Path("/run/secrets/keycloak_database_password")
ROLE = re.compile(r"[a-z][a-z0-9_]{0,62}$")


class Runner:
    def run(self, arguments: list[str], *, stdin_data: bytes, env: dict[str, str]) -> None:
        subprocess.run(arguments, input=stdin_data,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                       check=True, timeout=120, env=env)


def read_secret(path: Path, *, maximum: int = 4096) -> str:
    if not path.is_file() or path.is_symlink():
        raise ValueError("CONTROL_BOOTSTRAP_SECRET_INVALID")
    raw = path.read_bytes()
    if not raw or len(raw) > maximum or b"\0" in raw:
        raise ValueError("CONTROL_BOOTSTRAP_SECRET_INVALID")
    try:
        return raw.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise ValueError("CONTROL_BOOTSTRAP_SECRET_INVALID") from error


def parse_postgres_url(value: str, *, jdbc: bool = False) -> tuple[str, int, str, str, str | None]:
    if jdbc:
        if not value.startswith("jdbc:postgresql://"):
            raise ValueError("CONTROL_BOOTSTRAP_DATABASE_URL_INVALID")
        value = value.removeprefix("jdbc:")
    parsed = urlsplit(value)
    query = parse_qs(parsed.query, strict_parsing=True)
    if (parsed.scheme not in ("postgres", "postgresql") or not parsed.hostname
            or parsed.path in ("", "/") or parsed.fragment
            or set(query) - {"sslmode"} or any(len(items) != 1 for items in query.values())):
        raise ValueError("CONTROL_BOOTSTRAP_DATABASE_URL_INVALID")
    username = unquote(parsed.username or "")
    password = unquote(parsed.password) if parsed.password is not None else None
    return parsed.hostname, parsed.port or 5432, unquote(parsed.path[1:]), username, password


def sql_literal(value: str) -> str:
    if not 16 <= len(value.encode("utf-8")) <= 4096 or any(ord(c) < 32 for c in value):
        raise ValueError("CONTROL_BOOTSTRAP_PASSWORD_INVALID")
    return "'" + value.replace("'", "''") + "'"


def configuration(identity_mode: str, notebook_mode: str, *, admin_dsn: Path = ADMIN_DSN,
                  hub_url: Path = HUB_URL,
                  keycloak_url: Path = KEYCLOAK_URL,
                  keycloak_username: Path = KEYCLOAK_USERNAME,
                  keycloak_password: Path = KEYCLOAK_PASSWORD):
    if identity_mode != "bundled":
        raise ValueError("CONTROL_BOOTSTRAP_IDENTITY_MODE_INVALID")
    if notebook_mode not in ("disabled", "managed"):
        raise ValueError("CONTROL_BOOTSTRAP_NOTEBOOK_MODE_INVALID")
    admin = parse_postgres_url(read_secret(admin_dsn))
    expected = []
    services = []
    if notebook_mode == "managed":
        hub = parse_postgres_url(read_secret(hub_url))
        expected.append((hub, "openepm_hub", "openepm_hub"))
        if hub[4] is None:
            raise ValueError("CONTROL_BOOTSTRAP_DATABASE_URL_INVALID")
        services.append(("openepm_hub", "openepm_hub", hub[4]))
    keycloak = parse_postgres_url(read_secret(keycloak_url), jdbc=True)
    keycloak_user = read_secret(keycloak_username)
    keycloak_secret = read_secret(keycloak_password)
    expected.append((keycloak, "openepm_keycloak", ""))
    if keycloak[4] is not None or keycloak_user != "openepm_keycloak":
        raise ValueError("CONTROL_BOOTSTRAP_DATABASE_URL_INVALID")
    for value, database, username in expected:
        if (value[0:2] != admin[0:2] or value[2] != database
                or value[3] != username or (username and not ROLE.fullmatch(username))):
            raise ValueError("CONTROL_BOOTSTRAP_DATABASE_URL_INVALID")
    if not admin[3] or admin[2] != "postgres":
        raise ValueError("CONTROL_BOOTSTRAP_ADMIN_DSN_INVALID")
    services.append(("openepm_keycloak", "openepm_keycloak", keycloak_secret))
    return tuple(services)


def bootstrap(identity_mode: str, notebook_mode: str, *, runner: Runner = Runner(), **paths) -> None:
    services = configuration(identity_mode, notebook_mode, **paths)
    if not services: return
    statements = ["\\set ON_ERROR_STOP on", "SET standard_conforming_strings = on;",
                  "SELECT pg_advisory_lock(718206143);" ]
    for database, role, password in services:
        statements.extend((
            "SELECT 'CREATE ROLE " + role + " LOGIN' WHERE NOT EXISTS "
            "(SELECT 1 FROM pg_roles WHERE rolname = '" + role + "') \\gexec",
            "ALTER ROLE " + role + " LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOREPLICATION NOBYPASSRLS PASSWORD " + sql_literal(password) + ";",
            "SELECT 'CREATE DATABASE " + database + " OWNER " + role + "' "
            "WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = '" +
            database + "') \\gexec",
            "ALTER DATABASE " + database + " OWNER TO " + role + ";",
            "REVOKE ALL ON DATABASE " + database + " FROM PUBLIC;",
            "GRANT CONNECT, TEMPORARY ON DATABASE " + database + " TO " + role + ";"))
    statements.extend(("SELECT pg_advisory_unlock(718206143);", ""))
    flags, environment = connection(paths.get("admin_dsn", ADMIN_DSN))
    runner.run(["psql", *flags, "-X", "--quiet", "--file=-"],
               stdin_data="\n".join(statements).encode("utf-8"), env=environment)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--identity-mode", required=True, choices=("bundled",))
    parser.add_argument("--notebook-mode", required=True,
                        choices=("disabled", "managed"))
    arguments = parser.parse_args()
    bootstrap(arguments.identity_mode, arguments.notebook_mode)


if __name__ == "__main__":
    main()
