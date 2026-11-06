#!/usr/bin/env python3
"""Prepare a clean programmable Mac-pilot replacement generation privately.

The active owner-UAT generation is observed and bound to an exact protected
backup, but never stopped or modified.  The replacement starts from an empty
PostgreSQL volume, applies the exact release schema, enrolls the already
configured verified platform operator, and verifies zero applications on
private loopback ports.  Application creation and public activation are
separate governed phases.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from urllib import error as urlerror, request as urlrequest
from urllib.parse import parse_qs, quote, urlencode, urlsplit

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

from scripts.capture_macos_pilot_running_state import compose_frontend
from scripts import macos_pilot_owner_uat_controller as owner
from scripts.qualify_macos_pilot_service_switch import (
    application_count, compose, docker, inspect_exact, parse_env, schema_state,
    wait_broker_ready, wait_health, write_phase_environment,
    write_python_secrets,
)


PROJECT = "openepm-programmable-next"
FORMAT = "openepm-programmable-replacement-state-v1"
IMAGE = re.compile(r"^sha256:[0-9a-f]{64}$")
SAFE_PROJECT = re.compile(r"^openepm-[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?-next$")
PRIVATE_PORTS = {"workspace": 5392, "platform": 5393,
                 "router": 5394, "web": 5395}
PREPARED_STATES = {
    "prepared-empty", "prepared-populated", "rolled-back-populated",
    "suspended", "provisioning-failed",
}


class ReplacementError(RuntimeError):
    pass


def load_state(root: Path) -> dict:
    try:
        value = json.loads(owner.state_path(root).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReplacementError("replacement state is unavailable") from exc
    if (not isinstance(value, dict) or value.get("format") != FORMAT
            or SAFE_PROJECT.fullmatch(str(value.get("project", ""))) is None):
        raise ReplacementError("replacement state differs")
    return value


def exact_inputs(args) -> None:
    if (IMAGE.fullmatch(str(args.application_image)) is None
            or IMAGE.fullmatch(str(args.database_image)) is None
            or not isinstance(args.expected_schema, int)
            or isinstance(args.expected_schema, bool)
            or args.expected_schema < 1
            or SAFE_PROJECT.fullmatch(str(args.project)) is None):
        raise ReplacementError("exact replacement inputs are required")


def read_deployment_seed(path: Path) -> dict[str, str]:
    """Read only non-identity settings needed to create a fresh generation.

    The currently public rollback generation can legitimately contain a
    retired authentication configuration.  Copying that environment into a
    new Keycloak generation would preserve obsolete Google/Cloudflare keys
    and can also make preparation depend on an old provider's required
    fields.  Treat the public environment as a source for deployment
    coordinates only; ``configure_keycloak`` supplies the complete new
    identity contract.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ReplacementError("deployment seed environment is unreadable") from exc
    source: dict[str, str] = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ReplacementError("deployment seed environment is invalid")
        key, value = line.split("=", 1)
        if (not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in source):
            raise ReplacementError("deployment seed environment is invalid")
        source[key] = value
    required = {
        "EPM_PUBLIC_WEB_ORIGIN", "EPM_PUBLIC_MCP_ORIGIN",
        "EPM_PG_WORKSPACE_ID",
    }
    if required - source.keys() or any(not source[key] for key in required):
        raise ReplacementError("deployment seed environment is incomplete")
    retained = {key: source[key] for key in required}
    if "EPM_PILOT_PYTHON_BUILD_ENABLED" in source:
        enabled = source["EPM_PILOT_PYTHON_BUILD_ENABLED"]
        if enabled not in ("0", "1"):
            raise ReplacementError("deployment seed Python setting is invalid")
        retained["EPM_PILOT_PYTHON_BUILD_ENABLED"] = enabled
    return retained


def _read_protected(path: Path, maximum: int) -> str:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) & 0o077):
                raise ReplacementError("Keycloak source secret is not protected")
            raw = os.read(descriptor, maximum + 1)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise ReplacementError("Keycloak source secret is unavailable") from exc
    if len(raw) > maximum:
        raise ReplacementError("Keycloak source secret is oversized")
    try:
        value = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ReplacementError("Keycloak source secret is invalid") from exc
    if not value:
        raise ReplacementError("Keycloak source secret is empty")
    return value


def _write_protected(directory: Path, name: str, value: str) -> None:
    path = directory / name
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW, 0o400)
    try:
        os.write(descriptor, value.encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _openssl(*arguments: str, timeout: int = 30) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["openssl", *arguments], check=True, capture_output=True,
            text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReplacementError("Keycloak internal TLS operation failed") from exc


def generate_internal_identity_tls(directory: Path) -> None:
    """Create one pilot-owned CA and an identity-host certificate."""
    with tempfile.TemporaryDirectory(dir=directory.parent) as temporary:
        scratch = Path(temporary)
        ca_key = scratch / "ca.key"
        ca_certificate = scratch / "ca.crt"
        identity_key = scratch / "identity.key"
        request = scratch / "identity.csr"
        identity_certificate = scratch / "identity.crt"
        extensions = scratch / "identity.ext"
        extensions.write_text(
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid,issuer\n"
            "subjectAltName=DNS:identity,DNS:localhost,IP:127.0.0.1,IP:::1\n",
            encoding="ascii")
        _openssl("req", "-x509", "-newkey", "rsa:3072", "-nodes",
                 "-sha256", "-days", "397", "-subj",
                 "/CN=Open EPM Mac Pilot Internal CA",
                 "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                 "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                 "-addext", "subjectKeyIdentifier=hash",
                 "-addext", "authorityKeyIdentifier=keyid:always,issuer",
                 "-keyout", str(ca_key), "-out", str(ca_certificate))
        _openssl("req", "-new", "-newkey", "rsa:3072", "-nodes",
                 "-sha256", "-subj", "/CN=identity",
                 "-keyout", str(identity_key), "-out", str(request))
        _openssl("x509", "-req", "-sha256", "-days", "397",
                 "-in", str(request), "-CA", str(ca_certificate),
                 "-CAkey", str(ca_key), "-CAcreateserial",
                 "-extfile", str(extensions), "-out",
                 str(identity_certificate))
        _write_protected(directory, "keycloak_internal_tls_certificate",
                         identity_certificate.read_text(encoding="ascii"))
        _write_protected(directory, "keycloak_internal_tls_private_key",
                         identity_key.read_text(encoding="ascii"))
        _write_protected(directory, "keycloak_internal_ca_certificate",
                         ca_certificate.read_text(encoding="ascii"))
    validate_internal_identity_tls(directory)


def validate_internal_identity_tls(directory: Path) -> None:
    certificate = directory / "keycloak_internal_tls_certificate"
    private_key = directory / "keycloak_internal_tls_private_key"
    ca_certificate = directory / "keycloak_internal_ca_certificate"
    for path in (certificate, private_key, ca_certificate):
        _read_protected(path, 1024 * 1024)
    _openssl("verify", "-x509_strict", "-CAfile", str(ca_certificate),
             str(certificate))
    _openssl("x509", "-checkend", "604800", "-noout", "-in",
             str(certificate))
    _openssl("x509", "-checkhost", "identity", "-noout", "-in",
             str(certificate))
    _openssl("x509", "-checkhost", "localhost", "-noout", "-in",
             str(certificate))
    _openssl("x509", "-checkip", "127.0.0.1", "-noout", "-in",
             str(certificate))
    certificate_key = _openssl(
        "x509", "-pubkey", "-noout", "-in", str(certificate)).stdout
    private_public_key = _openssl(
        "pkey", "-pubout", "-in", str(private_key)).stdout
    if (not certificate_key or certificate_key != private_public_key):
        raise ReplacementError(
            "Keycloak internal certificate and private key differ")


def browser_api_401_config(current: str) -> tuple[str, bool]:
    """Return the exact gateway policy that keeps API expiry machine-readable.

    OAuth2 Proxy redirects ordinary unauthenticated browser navigation to the
    identity provider.  Browser ``fetch`` follows that redirect, however, so
    an expired ``/api`` request can otherwise arrive at the client as a 200
    HTML login page.  The application-wide lifecycle needs the proxy's
    supported API-route fence to receive a real 401 and deactivate every
    rendered page.
    """
    marker = 'cookie_refresh = "5m"'
    policy = 'api_routes = ["^/api/"]'
    if not isinstance(current, str) or current.count(marker) != 1:
        raise ReplacementError("browser gateway refresh policy differs")
    api_lines = [line for line in current.splitlines()
                 if line.strip().startswith("api_routes")]
    if api_lines:
        if api_lines != [policy]:
            raise ReplacementError("browser gateway API policy differs")
        return current, False
    return current.replace(marker, marker + "\n" + policy), True


def _replace_protected(path: Path, value: str) -> None:
    descriptor, name = tempfile.mkstemp(prefix="." + path.name + ".",
                                        suffix=".partial", dir=path.parent)
    temporary = Path(name)
    try:
        os.fchmod(descriptor, 0o400)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def rotate_internal_identity_tls(directory: Path) -> None:
    """Replace the private CA and leaf as one validated, rollback-safe set."""
    names = (
        "keycloak_internal_tls_certificate",
        "keycloak_internal_tls_private_key",
        "keycloak_internal_ca_certificate",
    )
    original = {name: _read_protected(directory / name, 1024 * 1024)
                for name in names}
    with tempfile.TemporaryDirectory(dir=directory.parent) as temporary:
        candidate = Path(temporary) / "candidate"
        candidate.mkdir(mode=0o700)
        generate_internal_identity_tls(candidate)
        replacement = {name: _read_protected(candidate / name, 1024 * 1024)
                       for name in names}
    try:
        for name in names:
            _replace_protected(directory / name, replacement[name] + "\n")
        validate_internal_identity_tls(directory)
    except BaseException:
        for name in names:
            _replace_protected(directory / name, original[name] + "\n")
        validate_internal_identity_tls(directory)
        raise


def oidc_origin(issuer: str) -> str:
    parsed = urlsplit(issuer)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or parsed.path != "/realms/openepm"):
        raise ReplacementError("exact Keycloak issuer is required")
    return parsed.scheme + "://" + parsed.netloc


def browser_backend_logout_url(issuer: str, web_origin: str) -> str:
    return (
        issuer
        + "/protocol/openid-connect/logout?id_token_hint={id_token}"
        + "&client_id=openepm-web&post_logout_redirect_uri="
        + quote(web_origin + "/", safe="")
    )


def configure_keycloak(root: Path, values: dict[str, str], args) -> None:
    if args.identity_mode != "keycloak":
        return
    for image in (args.identity_image, args.operations_image):
        if IMAGE.fullmatch(str(image)) is None:
            raise ReplacementError("exact Keycloak images are required")
    identity_origin = oidc_origin(str(args.oidc_issuer))
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._@+-]{2,199}",
                        str(args.initial_admin_username)):
        raise ReplacementError("initial native administrator user ID is required")
    directory = root / "keycloak-secrets"
    directory.mkdir(mode=0o700)
    generate_internal_identity_tls(directory)
    control_password = secrets.token_urlsafe(48)
    database_password = secrets.token_urlsafe(48)
    admin_password = secrets.token_urlsafe(48)
    directory_secret = secrets.token_urlsafe(48)
    web_secret = secrets.token_urlsafe(48)
    cookie_secret = secrets.token_urlsafe(32)
    session_password = secrets.token_urlsafe(48)
    gateway_config = "\n".join((
        'redirect_url = ' + json.dumps(values["EPM_PUBLIC_WEB_ORIGIN"]
                                       + "/oidc/callback"),
        'proxy_prefix = "/oidc"',
        'email_domains = ["*"]',
        'cookie_name = "__Host-openepm_session"',
        'cookie_secure = true',
        'cookie_httponly = true',
        'cookie_samesite = "lax"',
        'cookie_expire = "8h"',
        'cookie_refresh = "5m"',
        # Browser fetch follows redirects.  Without an API route fence, an
        # expired server-side session can turn an /api request into a 200
        # Keycloak HTML response instead of the 401 consumed by the shared
        # application lifecycle.  Keep interactive page navigation on the
        # normal OIDC redirect while every browser API fails closed as 401.
        'api_routes = ["^/api/"]',
        'cookie_secret = ' + json.dumps(cookie_secret),
        'session_store_type = "redis"',
        'redis_connection_url = "redis://browser-session-store:6379/0"',
        'redis_password = ' + json.dumps(session_password),
        'reverse_proxy = true',
        'skip_provider_button = true',
        'silence_ping_logging = true',
        '',
    ))
    backend_logout_url = browser_backend_logout_url(
        str(args.oidc_issuer), values["EPM_PUBLIC_WEB_ORIGIN"]
    )
    gateway_alpha = """server:
  bindAddress: 0.0.0.0:4180
metricsServer:
  bindAddress: 0.0.0.0:44180
providers:
  - id: openepm-keycloak
    provider: keycloak-oidc
    clientID: openepm-web
    clientSecretFile: /run/secrets/keycloak_web_client_secret
    backendLogoutURL: {backend_logout_url}
    code_challenge_method: S256
    scope: openid profile
    oidcConfig:
      issuerURL: {issuer}
      emailClaim: preferred_username
      userIDClaim: preferred_username
      insecureAllowUnverifiedEmail: true
      insecureSkipNonce: false
upstreamConfig:
  upstreams:
    - id: openepm-platform-browser
      path: ^/api/platform/browser/(.*)$
      rewriteTarget: /browser/$1
      uri: http://platform:5193
    - id: openepm-fixed-core-web
      path: /
      uri: http://web:5195
injectRequestHeaders:
  - name: Authorization
    preserveRequestValue: false
    values:
      - claimSource:
          claim: access_token
          prefix: "Bearer "
""".format(
        issuer=json.dumps(str(args.oidc_issuer)),
        backend_logout_url=json.dumps(backend_logout_url),
    )
    session_config = "\n".join((
        "bind 0.0.0.0",
        "protected-mode yes",
        "port 6379",
        'save ""',
        "appendonly no",
        "maxmemory 128mb",
        "maxmemory-policy noeviction",
        "requirepass " + session_password,
        'rename-command FLUSHALL ""',
        'rename-command FLUSHDB ""',
        '',
    ))
    material = {
        "control_postgres_password": control_password,
        "control_admin_dsn": ("postgresql://postgres:" + control_password
                              + "@control-db:5432/postgres"),
        "keycloak_database_url":
            "jdbc:postgresql://control-db:5432/openepm_keycloak",
        "keycloak_database_username": "openepm_keycloak",
        "keycloak_database_password": database_password,
        "keycloak_admin_username": "openepm-bootstrap-admin",
        "keycloak_admin_password": admin_password,
        "keycloak_directory_client_secret": directory_secret,
        "keycloak_web_client_secret": web_secret,
        "keycloak_initial_admin_password": secrets.token_urlsafe(48),
        "browser_gateway.cfg": gateway_config,
        "browser_gateway_alpha.yaml": gateway_alpha,
        "browser_session_store.conf": session_config,
        "keycloak_bootstrap_config.json": json.dumps({
            "format": "openepm-keycloak-bootstrap-v1",
            "adminUrl": "https://identity:8443",
            "webOrigin": values["EPM_PUBLIC_WEB_ORIGIN"],
            "mcpRedirectUris": ["http://127.0.0.1:8765/callback"],
            "initialAdministrator": {
                "username": args.initial_admin_username,
                "displayName": "Open EPM Owner",
            },
        }, sort_keys=True, separators=(",", ":")),
    }
    for name, value in material.items():
        _write_protected(directory, name, value)
    values.update({
        "EPM_AUTH_MODE": "oidc",
        "EPM_IDENTITY_IMAGE": args.identity_image,
        "EPM_OPERATIONS_IMAGE": args.operations_image,
        "EPM_PILOT_KEYCLOAK_SECRET_DIR": str(directory),
        "EPM_IDENTITY_PUBLIC_ORIGIN": identity_origin,
        "EPM_OIDC_ISSUER": args.oidc_issuer,
        "EPM_OIDC_JWKS_URL":
            "https://identity:8443" + urlsplit(args.oidc_issuer).path.rstrip("/")
            + "/protocol/openid-connect/certs",
        "EPM_OIDC_AUD_MCP": "openepm-mcp",
        "EPM_OIDC_AUD_WEB": "openepm-web",
        "EPM_PLATFORM_OPERATOR_ISSUER": args.oidc_issuer,
        "EPM_PLATFORM_OPERATOR_SUBJECT": "pending-keycloak-bootstrap",
        "EPM_IDENTITY_LOOPBACK_PORT": "5390",
        "EPM_BROWSER_GATEWAY_LOOPBACK_PORT": "5196",
        "EPM_BROWSER_GATEWAY_IMAGE":
            "quay.io/oauth2-proxy/oauth2-proxy:v7.15.5@sha256:8498b0d0ef0a7b29686414000a08aee467f02d0299c9ed1e006a8f33fc017916",
        "EPM_BROWSER_SESSION_STORE_IMAGE":
            "valkey/valkey:8.1.11-alpine@sha256:2602ace2be6569bc2bbb06f873776516ab9089821525be34f4305c67eb9db02a",
    })
    target = root / "compose.env"
    target.write_text("".join(key + "=" + value + "\n"
                              for key, value in sorted(values.items())),
                      encoding="utf-8")
    target.chmod(0o600)


def override(application_image: str, database_image: str) -> str:
    value = owner.override(application_image, database_image, public=False)
    for service, old_port in owner.PRIVATE_PORTS.items():
        old = f"127.0.0.1:{old_port}:{owner.PUBLIC_PORTS[service]}"
        new = f"127.0.0.1:{PRIVATE_PORTS[service]}:{owner.PUBLIC_PORTS[service]}"
        if value.count(old) != 1:
            raise ReplacementError("replacement Compose port shape differs")
        value = value.replace(old, new)
    return value


def base(root: Path) -> tuple[list[str], dict]:
    compose_file = (ROOT / "deploy/postgres/compose.yaml").resolve()
    python_file = (ROOT / "deploy/macos-pilot/python-build.compose.yaml").resolve()
    keycloak_file = (ROOT / "deploy/macos-pilot/keycloak.compose.yaml").resolve()
    durable = load_state(root)
    identity_mode = durable.get("identityMode", "cloudflare")
    if identity_mode == "cloudflare":
        # Retain only the already-sealed rollback generation until guarded
        # Keycloak activation passes. New preparation defaults to Keycloak and
        # the application runtime itself no longer accepts this identity mode.
        try:
            lines = (root / "compose.env").read_text(
                encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise ReplacementError("rollback environment is unreadable") from exc
        values = {}
        for line in lines:
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ReplacementError("rollback environment is invalid")
            key, value = line.split("=", 1)
            if (not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in values):
                raise ReplacementError("rollback environment is invalid")
            values[key] = value
        required = {"EPM_AUTH_MODE", "EPM_ACCESS_TEAM_DOMAIN",
                    "EPM_ACCESS_AUD_MCP", "EPM_ACCESS_AUD_WEB",
                    "EPM_PUBLIC_WEB_ORIGIN", "EPM_PUBLIC_MCP_ORIGIN",
                    "EPM_PLATFORM_OPERATOR_ISSUER",
                    "EPM_PLATFORM_OPERATOR_SUBJECT", "EPM_PG_WORKSPACE_ID"}
        if (required - values.keys() or any(not values[key] for key in required)
                or values["EPM_AUTH_MODE"] != "cloudflare"):
            raise ReplacementError("rollback environment is incomplete")
    elif identity_mode == "keycloak":
        try:
            lines = (root / "compose.env").read_text(
                encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as exc:
            raise ReplacementError("Keycloak environment is unreadable") from exc
        values = {}
        for line in lines:
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ReplacementError("Keycloak environment is invalid")
            key, value = line.split("=", 1)
            if (not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in values):
                raise ReplacementError("Keycloak environment is invalid")
            values[key] = value
        expected_origin = oidc_origin(values.get("EPM_OIDC_ISSUER", ""))
        configured_origin = values.get("EPM_IDENTITY_PUBLIC_ORIGIN")
        if configured_origin not in (None, expected_origin):
            raise ReplacementError("Keycloak public origin differs")
        # Existing prepared state predates this split. Supplying the derived
        # value to Compose is a compatible controller correction; the durable
        # issuer and realm data are unchanged.
        values["EPM_IDENTITY_PUBLIC_ORIGIN"] = expected_origin
        # The bundled Keycloak service is the authoritative signing-key
        # back-channel. Keep the token issuer public HTTPS while using the
        # explicitly trusted private CA for sibling-container traffic.
        values["EPM_OIDC_JWKS_URL"] = (
            "https://identity:8443" +
            urlsplit(values["EPM_OIDC_ISSUER"]).path.rstrip("/") +
            "/protocol/openid-connect/certs")
        values.pop("EPM_OIDC_ALLOW_INTERNAL_HTTP_JWKS", None)
        required = {"EPM_AUTH_MODE", "EPM_OIDC_ISSUER", "EPM_OIDC_JWKS_URL",
                    "EPM_OIDC_AUD_MCP", "EPM_OIDC_AUD_WEB",
                    "EPM_PLATFORM_OPERATOR_ISSUER",
                    "EPM_PLATFORM_OPERATOR_SUBJECT", "EPM_PUBLIC_WEB_ORIGIN",
                    "EPM_PUBLIC_MCP_ORIGIN", "EPM_PG_WORKSPACE_ID",
                    "EPM_PILOT_KEYCLOAK_SECRET_DIR", "EPM_IDENTITY_IMAGE",
                    "EPM_OPERATIONS_IMAGE"}
        if (required - values.keys() or any(not values[key] for key in required)
                or values["EPM_AUTH_MODE"] != "oidc"):
            raise ReplacementError("Keycloak environment is incomplete")
        validate_internal_identity_tls(
            Path(values["EPM_PILOT_KEYCLOAK_SECRET_DIR"]))
    else:
        raise ReplacementError("replacement identity mode differs")
    project = durable["project"]
    command = [*compose_frontend(), "--project-name", project,
               "--env-file", str(root / "compose.env"),
               "-f", str(compose_file), "-f", str(python_file)]
    if identity_mode == "keycloak":
        if not keycloak_file.is_file():
            raise ReplacementError("Keycloak Compose overlay is unavailable")
        command.extend(("-f", str(keycloak_file)))
    command.extend(("-f", str(root / "override.yaml")))
    if identity_mode == "keycloak":
        # Keep the complete private service graph addressable for lifecycle
        # commands such as stop/rm. Explicit ``up`` calls still start only
        # their named services and dependencies.
        for profile in ("keycloak", "v2", "workspace", "python-build",
                        "browser-session"):
            command.extend(("--profile", profile))
    return command, {**os.environ, **values}


def synchronize_python_coordinator(command: list[str], environment: dict) -> None:
    """Converge the protected secret volume and its durable login password."""
    compose(command, "--profile", "setup", "up", "--no-build", "-d", "db",
            environment=environment)
    database = compose(command, "ps", "-q", "db", environment=environment)
    if not database:
        raise ReplacementError("replacement database is unavailable")
    wait_health(database, "replacement:db")
    compose(command, "--profile", "python-build-setup", "run", "--rm",
            "python-build-secret-init", environment=environment)
    compose(command, "--profile", "python-build-setup", "run", "--rm",
            "bootstrap-python-coordinator", environment=environment)


def start_keycloak(command: list[str], environment: dict,
                   identity_image: str, database_image: str) -> dict:
    compose(command, "--profile", "keycloak", "up", "--no-build", "-d",
            "control-db", environment=environment)
    control_db = compose(command, "ps", "-q", "control-db",
                         environment=environment)
    if not control_db:
        raise ReplacementError("Keycloak control database is unavailable")
    wait_health(control_db, "replacement:control-db")
    control_evidence = inspect_exact(control_db, database_image, health=True)
    compose(command, "--profile", "keycloak", "--profile", "keycloak-setup",
            "run", "--rm",
            "control-bootstrap-keycloak", environment=environment)
    compose(command, "--profile", "keycloak", "up", "--no-build", "-d",
            "identity", environment=environment)
    identity = compose(command, "ps", "-q", "identity",
                       environment=environment)
    if not identity:
        raise ReplacementError("Keycloak identity service is unavailable")
    wait_health(identity, "replacement:identity")
    identity_evidence = inspect_exact(identity, identity_image, health=True)
    output = compose(command, "--profile", "keycloak", "--profile",
                     "keycloak-setup", "run", "--rm",
                     "keycloak-bootstrap", environment=environment)
    try:
        result = json.loads(output.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as exc:
        raise ReplacementError("Keycloak bootstrap result is invalid") from exc
    subject = result.get("initialAdministratorSubject")
    if (result.get("format") != "openepm-keycloak-bootstrap-result-v1"
            or not re.fullmatch(r"[A-Za-z0-9._:-]{1,255}", str(subject))):
        raise ReplacementError("Keycloak bootstrap result is invalid")
    return {"controlDatabase": control_evidence,
            "identity": identity_evidence,
            "realmBootstrapped": True,
            "initialAdministratorSubject": subject}


def wait_browser_gateway(port: int, timeout: float = 60.0) -> dict:
    """Wait for the live gateway process, not a second config-test process."""
    if (not isinstance(port, int) or isinstance(port, bool)
            or not 1024 <= port <= 65535):
        raise ReplacementError("browser gateway port is invalid")
    deadline = time.monotonic() + timeout
    opener = urlrequest.build_opener(urlrequest.ProxyHandler({}))
    last_error = "unavailable"
    while time.monotonic() < deadline:
        try:
            query = urlrequest.Request(
                f"http://127.0.0.1:{port}/ping",
                headers={"User-Agent": "openepm-gateway-readiness/1"},
            )
            with opener.open(query, timeout=2) as response:
                body = response.read(1025)
                if response.status == 200 and len(body) <= 1024:
                    return {"status": 200, "path": "/ping",
                            "loopbackPort": port}
                last_error = f"status-{response.status}"
        except (urlerror.URLError, TimeoutError, OSError) as exc:
            last_error = type(exc).__name__
        time.sleep(0.25)
    raise ReplacementError(
        "browser gateway readiness failed: " + last_error)


class _NoRedirect(urlrequest.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _browser_response(url: str) -> tuple[int, object, bytes]:
    opener = urlrequest.build_opener(urlrequest.ProxyHandler({}), _NoRedirect())
    query = urlrequest.Request(
        url, headers={"User-Agent": "openepm-private-browser-probe/1"})
    try:
        response = opener.open(query, timeout=10)
    except urlerror.HTTPError as failure:
        response = failure
    try:
        body = response.read(262145)
        status = response.status
        headers = response.headers
    finally:
        response.close()
    if len(body) > 262144:
        raise ReplacementError("browser gateway response is oversized")
    return status, headers, body


def probe_browser_authorization(port: int, issuer: str,
                                public_origin: str) -> dict:
    """Qualify the unauthenticated browser code-flow boundary without secrets."""
    if port < 1024 or port > 65535:
        raise ReplacementError("browser gateway port is invalid")
    public = urlsplit(public_origin)
    if (public.scheme != "https" or not public.hostname or public.username
            or public.password or public.path not in ("", "/")
            or public.query or public.fragment):
        raise ReplacementError("public browser origin is invalid")
    public_origin = public.scheme + "://" + public.netloc
    origin = "http://127.0.0.1:" + str(port)
    status, headers, _ = _browser_response(origin + "/")
    location = headers.get("Location", "")
    parsed = urlsplit(location)
    expected = urlsplit(issuer)
    parameters = parse_qs(parsed.query, keep_blank_values=True)
    required = {
        "client_id": ["openepm-web"],
        "response_type": ["code"],
        "code_challenge_method": ["S256"],
        "redirect_uri": [public_origin + "/oidc/callback"],
    }
    if (status != 302 or parsed.scheme != expected.scheme
            or parsed.netloc != expected.netloc
            or parsed.path != expected.path
            + "/protocol/openid-connect/auth"
            or any(parameters.get(key) != value
                   for key, value in required.items())
            or len(parameters.get("state", [])) != 1
            or len(parameters.get("nonce", [])) != 1
            or len(parameters.get("code_challenge", [])) != 1):
        raise ReplacementError("browser authorization redirect differs")
    cookie_headers = headers.get_all("Set-Cookie") or []
    cookies = SimpleCookie()
    for header in cookie_headers:
        cookies.load(header)
    csrf_name = "__Host-openepm_session_csrf"
    if list(cookies.keys()) != [csrf_name]:
        raise ReplacementError("browser pre-authentication cookie differs")
    raw_cookie = cookie_headers[0].lower()
    if ("; secure" not in raw_cookie or "; httponly" not in raw_cookie
            or "samesite=lax" not in raw_cookie or "path=/" not in raw_cookie
            or "domain=" in raw_cookie):
        raise ReplacementError("browser CSRF cookie policy differs")

    # Use the valid, opaque state while deliberately omitting the CSRF cookie.
    # This represents an expired/restarted login window without exposing the
    # state or cookie in evidence.
    callback = origin + "/oidc/callback?" + urlencode({
        "code": "invalid-not-redeemed",
        "state": parameters["state"][0],
    })
    callback_status, callback_headers, callback_body = _browser_response(
        callback)
    callback_text = callback_body.decode("utf-8", errors="replace")
    callback_cookies = callback_headers.get_all("Set-Cookie") or []
    if (callback_status != 403
            or "Login Failed" not in callback_text
            or any(header.startswith("__Host-openepm_session=")
                   for header in callback_cookies)):
        raise ReplacementError("missing-cookie callback handling differs")

    auth_status, auth_headers, _ = _browser_response(origin + "/oidc/auth")
    if (auth_status != 401 or auth_headers.get("Location")):
        raise ReplacementError("browser auth-check boundary differs")
    return {
        "format": "openepm-private-browser-entry-v1",
        "authorizationStatus": status,
        "authorizationEndpoint": parsed.scheme + "://" + parsed.netloc
        + parsed.path,
        "authorizationCodeFlow": True,
        "pkceMethod": "S256",
        "noncePresent": True,
        "statePresent": True,
        "csrfCookieName": csrf_name,
        "csrfCookieSecure": True,
        "csrfCookieHttpOnly": True,
        "csrfCookieSameSite": "Lax",
        "sessionCookieBeforeCallback": False,
        "missingCookieCallbackStatus": callback_status,
        "missingCookieHasRecoveryMessage": True,
        "missingCookieCreatesSession": False,
        "unauthenticatedAuthCheckStatus": auth_status,
    }


def start_browser_gateway(command: list[str], environment: dict) -> dict:
    """Start and verify the server-side browser session boundary."""
    gateway_image = environment.get("EPM_BROWSER_GATEWAY_IMAGE", "")
    store_image = environment.get("EPM_BROWSER_SESSION_STORE_IMAGE", "")
    try:
        port = int(environment.get("EPM_BROWSER_GATEWAY_LOOPBACK_PORT", ""))
    except ValueError as exc:
        raise ReplacementError("browser gateway port is invalid") from exc
    if (IMAGE.fullmatch(gateway_image) is None
            and "@sha256:" not in gateway_image):
        raise ReplacementError("exact browser gateway image is required")
    if (IMAGE.fullmatch(store_image) is None
            and "@sha256:" not in store_image):
        raise ReplacementError("exact browser session-store image is required")
    compose(command, "--profile", "v2", "--profile", "browser-session",
            "up", "--no-build", "-d",
            "browser-session-store", "browser-gateway",
            environment=environment)
    store = compose(command, "ps", "-q", "browser-session-store",
                    environment=environment)
    gateway = compose(command, "ps", "-q", "browser-gateway",
                      environment=environment)
    if not store or not gateway:
        raise ReplacementError("browser session runtime is unavailable")
    wait_health(store, "replacement:browser-session-store")
    store_id = docker("image", "inspect", "--format", "{{.Id}}", store_image)
    gateway_id = docker("image", "inspect", "--format", "{{.Id}}",
                        gateway_image)
    store_evidence = inspect_exact(store, store_id, health=True)
    gateway_evidence = inspect_exact(gateway, gateway_id, health=False)
    store_evidence["reference"] = store_image
    gateway_evidence["reference"] = gateway_image
    gateway_evidence["readiness"] = wait_browser_gateway(port)
    return {"gateway": gateway_evidence, "sessionStore": store_evidence,
            "tokensInBrowser": False}


def stop_keycloak_runtime(command: list[str], environment: dict,
                          *, identity: bool) -> None:
    services = ["browser-gateway", "browser-session-store"]
    if identity:
        services.extend(("identity", "control-db"))
    compose(command, "stop", *services, environment=environment)


def bind_rollback(owner_root: Path) -> dict:
    """Bind rollback to the exact preserved generation, never to a dump.

    During product redesign there is no stable data contract to which a
    retained database snapshot can honestly be restored.  The guarded switch
    therefore preserves and suspends the complete old generation.  Rollback
    restarts that exact volume and exact images; it does not manufacture or
    retain a per-deployment backup artifact.
    """
    try:
        state = owner.status(argparse.Namespace(state_root=owner_root))
        owner_format = True
        application_image = state.get("candidateImage")
        public_writable = state.get("publicWritable") is True
    except owner.OwnerUatError:
        state = status(argparse.Namespace(state_root=owner_root))
        owner_format = False
        application_image = state.get("applicationImage")
        public_writable = (state.get("publicPortsChanged") is True
                           and state.get("activationVerification", {}).get(
                               "databaseWritable") is True)
    if (state.get("state") != "active" or state.get("verified") is not True
            or not public_writable or IMAGE.fullmatch(str(application_image)) is None
            or IMAGE.fullmatch(str(state.get("databaseImage"))) is None):
        raise ReplacementError("verified active owner-UAT generation is required")
    if owner_format:
        command, _, environment, _ = owner.bases(owner_root, public=True)
    else:
        command, environment = base(owner_root)
    active_work = owner.verify_no_active_work(command, environment)
    return {
        "mechanism": "preserved-suspended-generation",
        "generation": state["project"],
        "schema": state["expectedSchema"],
        "applications": state["expectedApplications"],
        "applicationImage": application_image,
        "databaseImage": state["databaseImage"],
        "activeWork": active_work,
    }


def preserved_generation(root: Path) -> tuple[str, dict, str]:
    """Read the exact preserved generation through its owning controller.

    The first programmable cutover was itself produced by this replacement
    controller, while older owner-UAT generations use the original owner
    controller.  Activation and rollback must preserve either qualified
    format; guessing that every predecessor is an owner-UAT state makes the
    rollback fence unusable precisely when generations are chained.
    """
    try:
        state = owner.status(argparse.Namespace(state_root=root))
        image = state.get("candidateImage")
        kind = "owner-uat"
    except owner.OwnerUatError:
        state = status(argparse.Namespace(state_root=root))
        image = state.get("applicationImage")
        kind = "programmable-replacement"
    if (state.get("state") != "active" or state.get("verified") is not True
            or IMAGE.fullmatch(str(image)) is None):
        raise ReplacementError("preserved generation is not verified active")
    return kind, state, str(image)


def suspend_preserved(root: Path, kind: str) -> dict:
    if kind == "owner-uat":
        return owner.suspend(argparse.Namespace(state_root=root))
    if kind == "programmable-replacement":
        return suspend(argparse.Namespace(state_root=root))
    raise ReplacementError("preserved generation controller differs")


def recover_preserved(root: Path, kind: str) -> dict:
    if kind == "owner-uat":
        return owner.recover(argparse.Namespace(state_root=root))
    if kind == "programmable-replacement":
        return recover(argparse.Namespace(state_root=root))
    raise ReplacementError("preserved generation controller differs")


def verify_private(root: Path, application_image: str, database_image: str,
                   expected_schema: int, expected_applications: int = 0) -> dict:
    command, environment = base(root)
    project = load_state(root)["project"]
    database = compose(command, "ps", "-q", "db", environment=environment)
    if not database:
        raise ReplacementError("replacement database is unavailable")
    wait_health(database, project + ":db")
    database_evidence = inspect_exact(database, database_image, health=True)
    identity = schema_state(database)
    if (not isinstance(expected_applications, int)
            or isinstance(expected_applications, bool)
            or expected_applications < 0
            or identity.get("maximum") != expected_schema
            or application_count(database) != expected_applications):
        raise ReplacementError("clean replacement database identity differs")
    services = {}
    for service in owner.HEALTH_SERVICES:
        profiles = ("--profile", "workspace") if service == "workspace" \
            else ("--profile", "v2")
        compose(command, *profiles, "up", "--no-build", "-d", service,
                environment=environment)
        container = compose(command, "ps", "-q", service,
                            environment=environment)
        wait_health(container, project + ":" + service)
        services[service] = inspect_exact(
            container, application_image, health=True)
        compose(command, "stop", service, environment=environment)
        compose(command, "rm", "-f", service, environment=environment)
    compose(command, "--profile", "python-build", "up", "--no-build", "-d",
            "python-build-broker", environment=environment)
    broker = compose(command, "ps", "-q", "python-build-broker",
                     environment=environment)
    denied = wait_broker_ready(broker)
    services["python-build-broker"] = inspect_exact(
        broker, application_image, health=False)
    services["python-build-broker"]["invalidCapabilityStatus"] = denied
    compose(command, "stop", "python-build-broker", environment=environment)
    compose(command, "rm", "-f", "python-build-broker",
            environment=environment)
    browser = None
    if load_state(root).get("identityMode") == "keycloak":
        compose(command, "--profile", "v2", "up", "--no-build", "-d",
                "web", environment=environment)
        web = compose(command, "ps", "-q", "web", environment=environment)
        wait_health(web, project + ":web-for-browser-gateway")
        browser = start_browser_gateway(command, environment)
        compose(command, "stop", "browser-gateway", "browser-session-store",
                "web", environment=environment)
        compose(command, "rm", "-f", "browser-gateway",
                "browser-session-store", "web", environment=environment)
    return {
        "database": database_evidence,
        "schema": identity,
        "applications": expected_applications,
        "services": services,
        "browserSession": browser,
        "privatePorts": PRIVATE_PORTS,
        "publicPortsChanged": False,
    }


def quiesce_prepared(command: list[str], environment: dict,
                     identity_mode: str) -> None:
    """Leave a privately verified generation dormant but recoverable.

    Prepared volumes and protected configuration remain available for the
    authenticated provisioning/activation phases.  No service needs to keep
    running between those phases, and completed setup containers are not
    evidence or recovery state.
    """
    owner.all_stop(command, environment)
    compose(command, "stop", "db", environment=environment)
    if identity_mode == "keycloak":
        stop_keycloak_runtime(command, environment, identity=True)
    compose(command, "rm", "-f", "backup-volume-init",
            "python-build-secret-init", environment=environment)


def prepared_runtime(command: list[str], environment: dict,
                     identity_mode: str) -> dict:
    """Prove that a prepared generation is dormant, not merely labelled so."""
    services = ["db", *owner.APP_SERVICES, "python-build-broker"]
    if identity_mode == "keycloak":
        services.extend(("identity", "control-db", "browser-gateway",
                         "browser-session-store"))
    running = [service for service in services if compose(
        command, "ps", "-q", service, environment=environment)]
    return {"quiesced": not running, "runningServices": running}


def prepare(args) -> dict:
    exact_inputs(args)
    root = args.state_root.resolve()
    owner_root = args.owner_state_root.resolve()
    with owner.locked(root):
        if owner.state_path(root).exists():
            raise ReplacementError("replacement already has durable state")
        rollback = bind_rollback(owner_root)
        source_values = read_deployment_seed(
            ROOT / "deploy/macos-pilot/openepm-pilot.env")
        values = write_phase_environment(
            source_values, root / "compose.env", root / "secrets")
        values.update(EPM_APPLICATION_IMAGE=args.application_image,
                      EPM_DATABASE_IMAGE=args.database_image)
        configure_keycloak(root, values, args)
        write_python_secrets(root / "secrets", values,
                             args.application_image, args.project)
        (root / "override.yaml").write_text(
            override(args.application_image, args.database_image),
            encoding="utf-8")
        (root / "override.yaml").chmod(0o600)
        state = {
            "format": FORMAT,
            "project": args.project,
            "identityMode": args.identity_mode,
            "identityImage": args.identity_image,
            "operationsImage": args.operations_image,
            "state": "preparing",
            "applicationImage": args.application_image,
            "databaseImage": args.database_image,
            "expectedSchema": args.expected_schema,
            "expectedApplications": 0,
            "ownerStateRoot": str(owner_root),
            "rollback": rollback,
            "activeGenerationMutation": False,
            "publicPortsChanged": False,
        }
        owner.write_json(owner.state_path(root), state)
        command = None
        environment = None
        try:
            command, environment = base(root)
            identity_evidence = None
            if args.identity_mode == "keycloak":
                identity_evidence = start_keycloak(
                    command, environment, args.identity_image,
                    args.database_image)
                values["EPM_PLATFORM_OPERATOR_SUBJECT"] = \
                    identity_evidence["initialAdministratorSubject"]
                (root / "compose.env").write_text(
                    "".join(key + "=" + value + "\n"
                            for key, value in sorted(values.items())),
                    encoding="utf-8")
                (root / "compose.env").chmod(0o600)
                environment["EPM_PLATFORM_OPERATOR_SUBJECT"] = \
                    values["EPM_PLATFORM_OPERATOR_SUBJECT"]
            compose(command, "--profile", "setup", "up", "--no-build", "-d",
                    "db", environment=environment)
            database = compose(command, "ps", "-q", "db",
                               environment=environment)
            wait_health(database, args.project + ":db")
            inspect_exact(database, args.database_image, health=True)
            compose(command, "--profile", "setup", "run", "--rm", "migrate",
                    environment=environment)
            compose(command, "--profile", "setup", "run", "--rm",
                    "bootstrap-roles", environment=environment)
            compose(command, "--profile", "setup", "run", "--rm",
                    "bootstrap-operator", environment=environment)
            synchronize_python_coordinator(command, environment)
            evidence = verify_private(
                root, args.application_image, args.database_image,
                args.expected_schema)
            quiesce_prepared(
                command, environment, args.identity_mode)
            state.update(
                state="prepared-empty",
                preparedAt=datetime.now(timezone.utc).isoformat(),
                identityVerification=identity_evidence,
                privateVerification=evidence)
            owner.write_json(owner.state_path(root), state)
            return state
        except BaseException:
            cleanup = {"attempted": False, "quiesced": False}
            if command is not None and environment is not None:
                cleanup["attempted"] = True
                try:
                    quiesce_prepared(command, environment,
                                     args.identity_mode)
                    cleanup["quiesced"] = prepared_runtime(
                        command, environment, args.identity_mode)["quiesced"]
                except BaseException as cleanup_error:
                    cleanup["errorType"] = type(cleanup_error).__name__
            state.update(state="prepare-failed",
                         failedPreparationCleanup=cleanup)
            owner.write_json(owner.state_path(root), state)
            raise


def activate(args) -> dict:
    """Atomically select the already-populated replacement generation."""
    root = args.state_root.resolve()
    with owner.locked(root):
        state = load_state(root)
        if (state.get("format") != FORMAT
                or state.get("state") not in
                   ("prepared-populated", "rolled-back-populated")
                or state.get("expectedApplications") != 2):
            raise ReplacementError("populated replacement is not activatable")
        owner_root = Path(state["ownerStateRoot"])
        preserved_kind, active, preserved_image = preserved_generation(
            owner_root)
        rollback = state["rollback"]
        if (active.get("state") != "active"
                or active.get("expectedSchema") != rollback["schema"]
                or active.get("expectedApplications") != rollback["applications"]
                or preserved_image != rollback["applicationImage"]
                or active.get("databaseImage") != rollback["databaseImage"]):
            raise ReplacementError("rollback generation differs before activation")
        command, environment = base(root)
        suspended = False
        try:
            # Recheck the private generation before touching the active one.
            identity = start_keycloak(
                command, environment, state["identityImage"],
                state["databaseImage"])
            synchronize_python_coordinator(command, environment)
            owner.all_up(command, environment)
            private = verify_private(
                root, state["applicationImage"], state["databaseImage"],
                state["expectedSchema"], expected_applications=2)
            compose(command, "stop", "db", environment=environment)
            suspend_preserved(owner_root, preserved_kind)
            suspended = True
            (root / "override.yaml").write_text(
                owner.override(state["applicationImage"],
                               state["databaseImage"], public=True),
                encoding="utf-8")
            (root / "override.yaml").chmod(0o600)
            command, environment = base(root)
            owner.all_up(command, environment)
            browser = start_browser_gateway(command, environment)
            public = owner.verify_generation(
                command, environment, state["applicationImage"],
                state["databaseImage"], state["expectedSchema"], 2,
                public=True)
            public["identity"] = identity
            public["browserSession"] = browser
        except BaseException:
            try:
                owner.all_stop(command, environment)
                stop_keycloak_runtime(command, environment, identity=True)
                compose(command, "stop", "db", environment=environment)
                (root / "override.yaml").write_text(
                    override(state["applicationImage"], state["databaseImage"]),
                    encoding="utf-8")
                (root / "override.yaml").chmod(0o600)
                if suspended:
                    recover_preserved(owner_root, preserved_kind)
            finally:
                state.update(state="rolled-back-populated",
                             publicPortsChanged=False,
                             activeGenerationMutation=False,
                             lastActivationResult="failed-and-old-recovered",
                             lastActivationFailedAt=
                             datetime.now(timezone.utc).isoformat())
                owner.write_json(owner.state_path(root), state)
            raise
        state.update(
            state="active", expectedApplications=2,
            activatedAt=datetime.now(timezone.utc).isoformat(),
            publicPortsChanged=True, activeGenerationMutation=True,
            privatePreActivationVerification=private,
            activationVerification=public)
        owner.write_json(owner.state_path(root), state)
        return state


def rollback(args) -> dict:
    """Restore the exact suspended owner generation and preserve replacement."""
    root = args.state_root.resolve()
    with owner.locked(root):
        state = load_state(root)
        if (state.get("format") != FORMAT
                or state.get("state") != "active"):
            raise ReplacementError("programmable replacement is not active")
        command, environment = base(root)
        active_work = owner.verify_no_active_work(command, environment)
        owner.all_stop(command, environment)
        stop_keycloak_runtime(command, environment, identity=True)
        compose(command, "stop", "db", environment=environment)
        (root / "override.yaml").write_text(
            override(state["applicationImage"], state["databaseImage"]),
            encoding="utf-8")
        (root / "override.yaml").chmod(0o600)
        owner_root = Path(state["ownerStateRoot"])
        # The preserved generation is expected to be suspended while this
        # replacement is active, so resolve its controller from the protected
        # durable format rather than requiring active-status verification.
        try:
            raw = json.loads(owner.state_path(owner_root).read_text(
                encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ReplacementError("preserved rollback state is invalid") from exc
        preserved_kind = ("owner-uat" if raw.get("format") == owner.FORMAT
                          else "programmable-replacement"
                          if raw.get("format") == FORMAT else "")
        restored = recover_preserved(owner_root, preserved_kind)
        state.update(
            state="rolled-back-populated", publicPortsChanged=False,
            activeGenerationMutation=False, replacementDataPreserved=True,
            rolledBackAt=datetime.now(timezone.utc).isoformat(),
            rollbackActiveWork=active_work,
            restoredGeneration={
                "project": restored["project"],
                "schema": restored["expectedSchema"],
                "applications": restored["expectedApplications"],
                "verified": (restored.get("publicWritable") is True
                             or (restored.get("publicPortsChanged") is True
                                 and restored.get(
                                     "activationVerification", {}).get(
                                         "databaseWritable") is True)),
            })
        owner.write_json(owner.state_path(root), state)
        return state


def recover(args) -> dict:
    """Converge and verify the exact active or suspended replacement."""
    root = args.state_root.resolve()
    with owner.locked(root):
        state = load_state(root)
        if (state.get("format") != FORMAT
                or state.get("state") not in ("active", "suspended")):
            raise ReplacementError("programmable replacement is not recoverable")
        command, environment = base(root)
        identity_mode = state.get("identityMode", "cloudflare")
        identity = (start_keycloak(
            command, environment, state["identityImage"],
            state["databaseImage"])
            if identity_mode == "keycloak" else None)
        synchronize_python_coordinator(command, environment)
        owner.all_up(command, environment)
        browser = (start_browser_gateway(command, environment)
                   if identity_mode == "keycloak" else None)
        evidence = owner.verify_generation(
            command, environment, state["applicationImage"],
            state["databaseImage"], state["expectedSchema"],
            state["expectedApplications"], public=True)
        if identity_mode == "keycloak":
            evidence["identity"] = identity
            evidence["browserSession"] = browser
        history = list(state.get("recoveryHistory", []))
        history.append({
            "recoveredAt": datetime.now(timezone.utc).isoformat(),
            "applicationImage": state["applicationImage"],
            "databaseImage": state["databaseImage"],
            "schema": state["expectedSchema"],
            "applications": state["expectedApplications"],
            "verified": True,
        })
        state.update(state="active", publicPortsChanged=True,
                     activeGenerationMutation=True,
                     activationVerification=evidence,
                     recoveryHistory=history)
        owner.write_json(owner.state_path(root), state)
        return state


def suspend(args) -> dict:
    """Quiesce the active replacement while preserving both generations."""
    root = args.state_root.resolve()
    with owner.locked(root):
        state = load_state(root)
        if state.get("state") == "suspended":
            return state
        if (state.get("format") != FORMAT
                or state.get("state") != "active"):
            raise ReplacementError("programmable replacement is not active")
        command, environment = base(root)
        identity_mode = state.get("identityMode", "cloudflare")
        active_work = owner.verify_no_active_work(command, environment)
        headroom = owner.verify_suspend_storage_headroom(command, environment)
        owner.all_stop(command, environment)
        if identity_mode == "keycloak":
            stop_keycloak_runtime(command, environment, identity=True)
        compose(command, "stop", "db", environment=environment)
        state.update(state="suspended", publicPortsChanged=True,
                     activeGenerationMutation=True,
                     suspendedAt=datetime.now(timezone.utc).isoformat(),
                     suspendedActiveWork=active_work,
                     suspendedStorageHeadroom=headroom)
        owner.write_json(owner.state_path(root), state)
        return state


def upgrade_image(args) -> dict:
    """Guardedly replace only the application image of the active generation."""
    root = args.state_root.resolve()
    new_image = str(args.application_image)
    if IMAGE.fullmatch(new_image) is None:
        raise ReplacementError("upgrade-image requires an exact application image")
    with owner.locked(root):
        state = load_state(root)
        if state.get("state") != "active":
            raise ReplacementError("programmable replacement is not active")
        old_image = state["applicationImage"]
        if new_image == old_image:
            raise ReplacementError("programmable replacement already uses that image")
        command, environment = base(root)
        active_work = owner.verify_no_active_work(command, environment)
        database = compose(command, "ps", "-q", "db", environment=environment)
        if not database:
            raise ReplacementError("programmable replacement database is unavailable")
        wait_health(database, state["project"] + ":db")
        identity = schema_state(database)
        if identity.get("maximum") != state["expectedSchema"]:
            raise ReplacementError("programmable replacement schema identity differs")
        # Activation is bound to exactly two sample applications. After UAT
        # begins, governed application creation/deletion is legitimate. Freeze
        # the live count at this upgrade boundary and require both candidate
        # and rollback verification to preserve it.
        live_applications = application_count(database)
        override_path = root / "override.yaml"
        old_override = override_path.read_text(encoding="utf-8")
        builder_changed = False
        try:
            stop_keycloak_runtime(command, environment, identity=False)
            owner.all_stop(command, environment)
            owner.replace_builder_image(root, old_image, new_image)
            builder_changed = True
            override_path.write_text(
                owner.override(new_image, state["databaseImage"], public=True),
                encoding="utf-8",
            )
            override_path.chmod(0o600)
            command, environment = base(root)
            owner.all_up(command, environment)
            browser = start_browser_gateway(command, environment)
            evidence = owner.verify_generation(
                command,
                environment,
                new_image,
                state["databaseImage"],
                state["expectedSchema"],
                live_applications,
                public=True,
            )
            evidence["browserSession"] = browser
        except BaseException:
            stop_keycloak_runtime(command, environment, identity=False)
            owner.all_stop(command, environment)
            override_path.write_text(old_override, encoding="utf-8")
            override_path.chmod(0o600)
            if builder_changed:
                owner.replace_builder_image(root, new_image, old_image)
            old_command, old_environment = base(root)
            owner.all_up(old_command, old_environment)
            old_browser = start_browser_gateway(old_command, old_environment)
            old_evidence = owner.verify_generation(
                old_command,
                old_environment,
                old_image,
                state["databaseImage"],
                state["expectedSchema"],
                live_applications,
                public=True,
            )
            old_evidence["browserSession"] = old_browser
            raise
        history = list(state.get("imageUpgradeHistory", []))
        history.append(
            {
                "from": old_image,
                "to": new_image,
                "activeWork": active_work,
                "upgradedAt": datetime.now(timezone.utc).isoformat(),
            }
        )
        state.update(
            applicationImage=new_image,
            expectedApplications=live_applications,
            activationVerification=evidence,
            imageUpgradeHistory=history,
        )
        owner.write_json(owner.state_path(root), state)
        return state


def upgrade_active_release(args) -> dict:
    """Advance an active populated generation to one exact image and schema.

    Unlike ``upgrade-image``, this operation owns the forward migration.  Its
    durable marker makes interruption visible and permits an exact retry; a
    migrated database is never relabelled as the old release or silently
    paired with the old application image.
    """
    root = args.state_root.resolve()
    new_image = str(args.application_image)
    new_schema = args.expected_schema
    if (IMAGE.fullmatch(new_image) is None or not isinstance(new_schema, int)
            or isinstance(new_schema, bool) or new_schema < 1):
        raise ReplacementError(
            "upgrade-active-release requires an exact image and schema")
    with owner.locked(root):
        state = load_state(root)
        if (state.get("state") not in {
                "active", "active-upgrading", "active-upgrade-failed"}
                or state.get("identityMode") != "keycloak"):
            raise ReplacementError(
                "active Keycloak replacement generation is required")
        old_image = state["applicationImage"]
        old_schema = state["expectedSchema"]
        marker = state.get("activeUpgrade")
        previous_target = None
        previous_schema_target = None
        if state["state"] == "active":
            if new_image == old_image or new_schema <= old_schema:
                raise ReplacementError(
                    "active release upgrade must advance image and schema")
            marker = {
                "applicationFrom": old_image, "applicationTo": new_image,
                "schemaFrom": old_schema, "schemaTo": new_schema,
                "startedAt": datetime.now(timezone.utc).isoformat(),
            }
        elif (not isinstance(marker, dict)
              or marker.get("applicationFrom") != old_image
              or marker.get("schemaFrom") != old_schema):
            raise ReplacementError("active release upgrade identity differs")
        else:
            if marker.get("schemaTo") != new_schema:
                previous_schema_target = marker.get("schemaTo")
                if (state["state"] != "active-upgrade-failed"
                        or not isinstance(previous_schema_target, int)
                        or isinstance(previous_schema_target, bool)
                        or new_schema <= previous_schema_target):
                    raise ReplacementError(
                        "active release upgrade identity differs")
                schema_retargets = list(marker.get(
                    "schemaRetargetHistory", []))
                schema_retargets.append({
                    "from": previous_schema_target, "to": new_schema,
                    "retargetedAt": datetime.now(timezone.utc).isoformat(),
                })
                marker = {**marker, "schemaTo": new_schema,
                          "schemaRetargetHistory": schema_retargets}
            if marker.get("applicationTo") == new_image:
                pass
            elif state["state"] != "active-upgrade-failed":
                raise ReplacementError("active release upgrade identity differs")
            else:
                previous_target = marker.get("applicationTo")
                if IMAGE.fullmatch(str(previous_target)) is None:
                    raise ReplacementError(
                        "active release upgrade identity differs")
                retargets = list(marker.get("applicationRetargetHistory", []))
                retargets.append({
                    "from": previous_target, "to": new_image,
                    "retargetedAt": datetime.now(timezone.utc).isoformat(),
                })
                marker = {**marker, "applicationTo": new_image,
                          "applicationRetargetHistory": retargets}

        command, environment = base(root)
        active_work = owner.verify_no_active_work(command, environment)
        database = compose(command, "ps", "-q", "db", environment=environment)
        if not database:
            raise ReplacementError("programmable replacement database is unavailable")
        wait_health(database, state["project"] + ":db")
        observed = schema_state(database).get("maximum")
        if (not isinstance(observed, int) or isinstance(observed, bool)
                or observed < old_schema or observed > new_schema):
            raise ReplacementError("active release schema identity differs")
        if (previous_schema_target is not None
                and observed != previous_schema_target):
            raise ReplacementError(
                "active release retarget source schema differs")
        # Governed application creation and deletion are legitimate after the
        # generation becomes active, so the durable activation count is an
        # observation of that earlier boundary rather than a permanent
        # admission constraint. Freeze the current count here, then require
        # candidate verification to preserve it across this exact upgrade.
        live_applications = application_count(database)

        state.update(state="active-upgrading", activeUpgrade={
            **marker, "lastAttemptAt": datetime.now(timezone.utc).isoformat(),
            "activeWork": active_work, "observedSchemaAtStart": observed,
            "expectedApplications": live_applications,
        })
        owner.write_json(owner.state_path(root), state)
        override_path = root / "override.yaml"
        try:
            stop_keycloak_runtime(command, environment, identity=True)
            owner.all_stop(command, environment)
            profile_path = root / "secrets/epm_python_builder_profiles.json"
            profile = json.loads(profile_path.read_text(encoding="utf-8"))
            profile_image = profile["profiles"][0]["image"]
            if profile_image == old_image:
                owner.replace_builder_image(root, old_image, new_image)
            elif previous_target is not None and profile_image == previous_target:
                owner.replace_builder_image(root, previous_target, new_image)
            elif profile_image != new_image:
                raise ReplacementError("active release builder image differs")
            expected_override = owner.override(
                new_image, state["databaseImage"], public=True)
            if override_path.read_text(encoding="utf-8") != expected_override:
                override_path.write_text(expected_override, encoding="utf-8")
                override_path.chmod(0o600)
            command, environment = base(root)
            compose(command, "--profile", "setup", "up", "--no-build", "-d",
                    "db", environment=environment)
            compose(command, "--profile", "setup", "run", "--rm", "migrate",
                    environment=environment)
            compose(command, "--profile", "setup", "run", "--rm",
                    "bootstrap-roles", environment=environment)
            compose(command, "--profile", "setup", "run", "--rm",
                    "bootstrap-operator", environment=environment)
            synchronize_python_coordinator(command, environment)
            migrated = schema_state(database).get("maximum")
            if migrated != new_schema:
                raise ReplacementError("active release migration target differs")
            identity = start_keycloak(
                command, environment, state["identityImage"],
                state["databaseImage"])
            owner.all_up(command, environment)
            browser = start_browser_gateway(command, environment)
            evidence = owner.verify_generation(
                command, environment, new_image, state["databaseImage"],
                new_schema, live_applications, public=True)
            evidence["browserSession"] = browser
        except BaseException as upgrade_error:
            failure_schema = None
            try:
                current_database = compose(
                    command, "ps", "-q", "db", environment=environment)
                if current_database:
                    failure_schema = schema_state(current_database).get("maximum")
            except BaseException:
                pass
            state.update(state="active-upgrade-failed", activeUpgrade={
                **state["activeUpgrade"],
                "failedAt": datetime.now(timezone.utc).isoformat(),
                "failureType": type(upgrade_error).__name__,
                "observedSchemaAfterFailure": failure_schema,
            })
            owner.write_json(owner.state_path(root), state)
            raise

        history = list(state.get("activeReleaseUpgradeHistory", []))
        history.append({
            "applicationFrom": old_image, "applicationTo": new_image,
            "schemaFrom": old_schema, "schemaTo": new_schema,
            "applications": live_applications, "activeWork": active_work,
            "upgradedAt": datetime.now(timezone.utc).isoformat(),
        })
        state.update(
            state="active", applicationImage=new_image,
            expectedSchema=new_schema, expectedApplications=live_applications,
            activationVerification=evidence, identityVerification=identity,
            verified=True, activeReleaseUpgradeHistory=history)
        state.pop("activeUpgrade", None)
        owner.write_json(owner.state_path(root), state)
        return state


def upgrade_prepared_image(args) -> dict:
    """Privately qualify and bind new release artifacts without public ports."""
    root = args.state_root.resolve()
    with owner.locked(root):
        state = load_state(root)
        if (state.get("state") not in PREPARED_STATES
                or state.get("identityMode") != "keycloak"):
            raise ReplacementError(
                "prepared Keycloak replacement generation is required")
        old_image = state["applicationImage"]
        old_operations = state["operationsImage"]
        old_schema = state["expectedSchema"]
        requested_schema = getattr(args, "expected_schema", None)
        new_schema = old_schema if requested_schema is None else requested_schema
        if (not isinstance(new_schema, int) or isinstance(new_schema, bool)
                or new_schema < old_schema):
            raise ReplacementError(
                "prepared schema upgrade must be forward-only")
        requested_image = getattr(args, "application_image", None)
        requested_operations = getattr(args, "operations_image", None)
        new_image = str(requested_image or old_image)
        new_operations = str(requested_operations or old_operations)
        if (IMAGE.fullmatch(new_image) is None
                or IMAGE.fullmatch(new_operations) is None):
            raise ReplacementError(
                "upgrade-prepared-image requires exact release images")
        application_changed = new_image != old_image
        operations_changed = new_operations != old_operations
        schema_changed = new_schema != old_schema
        if schema_changed and (state.get("state") != "prepared-empty"
                or state.get("expectedApplications") != 0
                or not application_changed):
            raise ReplacementError(
                "schema advance requires a new image and empty prepared generation")
        if not application_changed and not operations_changed and not schema_changed:
            raise ReplacementError(
                "prepared replacement already uses those images")
        command, environment = base(root)
        runtime = prepared_runtime(command, environment, "keycloak")
        if not runtime["quiesced"]:
            raise ReplacementError("prepared replacement is not quiesced")
        override_path = root / "override.yaml"
        old_override = override_path.read_text(encoding="utf-8")
        environment_path = root / "compose.env"
        old_environment = environment_path.read_text(encoding="utf-8")
        builder_changed = False
        try:
            if application_changed:
                owner.replace_builder_image(root, old_image, new_image)
                builder_changed = True
            # Regenerate the entire exact-image override even for an
            # operations-only upgrade. This prevents a newly added one-shot
            # service from falling through to an old env-file image binding.
            override_path.write_text(
                override(new_image, state["databaseImage"]),
                encoding="utf-8")
            override_path.chmod(0o600)
            new_environment = old_environment
            for key, expected in (("EPM_APPLICATION_IMAGE", new_image),
                                  ("EPM_OPERATIONS_IMAGE", new_operations)):
                matches = re.findall(r"^" + re.escape(key) + r"=.*$",
                                     new_environment, flags=re.MULTILINE)
                if len(matches) != 1:
                    raise ReplacementError(
                        "prepared release-image binding differs")
                new_environment = new_environment.replace(
                    matches[0], key + "=" + expected)
            environment_path.write_text(new_environment, encoding="utf-8")
            environment_path.chmod(0o600)
            if schema_changed:
                state.update(
                    state="preparing-upgrade",
                    applicationImage=new_image,
                    operationsImage=new_operations,
                    expectedSchema=new_schema,
                    preparedUpgrade={
                        "schemaFrom": old_schema,
                        "schemaTo": new_schema,
                        "applicationFrom": old_image,
                        "applicationTo": new_image,
                        "startedAt": datetime.now(timezone.utc).isoformat(),
                    })
                owner.write_json(owner.state_path(root), state)
            command, environment = base(root)
            if schema_changed:
                compose(command, "--profile", "setup", "up", "--no-build",
                        "-d", "db", environment=environment)
                database = compose(command, "ps", "-q", "db",
                                   environment=environment)
                if not database:
                    raise ReplacementError(
                        "replacement database is unavailable")
                wait_health(database, state["project"] + ":db")
                compose(command, "--profile", "setup", "run", "--rm",
                        "migrate", environment=environment)
                compose(command, "--profile", "setup", "run", "--rm",
                        "bootstrap-roles", environment=environment)
                compose(command, "--profile", "setup", "run", "--rm",
                        "bootstrap-operator", environment=environment)
            identity = start_keycloak(
                command, environment, state["identityImage"],
                state["databaseImage"])
            synchronize_python_coordinator(command, environment)
            expected_applications = state["expectedApplications"]
            if state.get("lastProvisionFailedAt"):
                database = compose(command, "ps", "-q", "db",
                                   environment=environment)
                observed_applications = application_count(database)
                if (state.get("state") == "prepared-empty"
                        and expected_applications == 0
                        and observed_applications in (1, 2)):
                    # A governed provision attempt can commit application
                    # units before a later sample operation fails. Recover
                    # that exact durable count; never call it empty.
                    expected_applications = observed_applications
                elif observed_applications != expected_applications:
                    raise ReplacementError(
                        "prepared application count differs")
            evidence = verify_private(
                root, new_image, state["databaseImage"],
                new_schema, expected_applications)
            quiesce_prepared(command, environment, "keycloak")
            runtime = prepared_runtime(command, environment, "keycloak")
            if not runtime["quiesced"]:
                raise ReplacementError(
                    "upgraded prepared replacement did not quiesce")
        except BaseException as upgrade_error:
            cleanup_error = None
            try:
                quiesce_prepared(command, environment, "keycloak")
            except BaseException as caught_cleanup_error:
                cleanup_error = caught_cleanup_error
            if schema_changed:
                try:
                    runtime = prepared_runtime(
                        command, environment, "keycloak")
                except BaseException as runtime_error:
                    runtime = {
                        "quiesced": False,
                        "runningServices": [],
                        "inspectionErrorType": type(runtime_error).__name__,
                    }
                state.update(
                    state="prepared-upgrade-failed",
                    applicationImage=new_image,
                    operationsImage=new_operations,
                    expectedSchema=new_schema,
                    preparedRuntime=runtime,
                    preparedUpgrade={
                        **state["preparedUpgrade"],
                        "failedAt": datetime.now(timezone.utc).isoformat(),
                        "failureType": type(upgrade_error).__name__,
                        "cleanupErrorType": (None if cleanup_error is None
                                             else type(cleanup_error).__name__),
                    })
                owner.write_json(owner.state_path(root), state)
            else:
                override_path.write_text(old_override, encoding="utf-8")
                override_path.chmod(0o600)
                environment_path.write_text(
                    old_environment, encoding="utf-8")
                environment_path.chmod(0o600)
                if builder_changed:
                    owner.replace_builder_image(
                        root, new_image, old_image)
            if cleanup_error is not None:
                raise ReplacementError(
                    "prepared upgrade failed and did not quiesce") \
                    from upgrade_error
            raise
        history = list(state.get("preparedImageUpgradeHistory", []))
        history.append({
            "applicationFrom": old_image, "applicationTo": new_image,
            "operationsFrom": old_operations,
            "operationsTo": new_operations,
            "schemaFrom": old_schema,
            "schemaTo": new_schema,
            "upgradedAt": datetime.now(timezone.utc).isoformat(),
            "publicPortsChanged": False,
        })
        state.update(
            state=("prepared-empty" if schema_changed else
                   "provisioning-failed" if (
                       state.get("lastProvisionFailedAt") and
                       expected_applications in (1, 2)) else state["state"]),
            applicationImage=new_image,
            operationsImage=new_operations,
            expectedSchema=new_schema,
            identityVerification=identity,
            privateVerification=evidence,
            preparedRuntime=runtime,
            expectedApplications=expected_applications,
            preparedImageUpgradeHistory=history,
        )
        state.pop("preparedUpgrade", None)
        owner.write_json(owner.state_path(root), state)
        return state


def quiesce(args) -> dict:
    """Reconcile a prepared replacement back to its dormant runtime state."""
    root = args.state_root.resolve()
    with owner.locked(root):
        state = load_state(root)
        if state.get("state") not in PREPARED_STATES | {
                "prepare-failed", "preparing-upgrade",
                "prepared-upgrade-failed"}:
            raise ReplacementError("prepared replacement generation is required")
        command, environment = base(root)
        identity_mode = state.get("identityMode", "cloudflare")
        quiesce_prepared(command, environment, identity_mode)
        runtime = prepared_runtime(command, environment, identity_mode)
        if not runtime["quiesced"]:
            raise ReplacementError("prepared replacement did not quiesce")
        state.update(preparedRuntime=runtime)
        owner.write_json(owner.state_path(root), state)
        return state


def backup(args) -> dict:
    """Capture the active programmable generation into owner-only storage."""
    root = args.state_root.resolve()
    with owner.locked(root):
        state = load_state(root)
        if state.get("state") != "active":
            raise ReplacementError("programmable replacement is not active")
        if state.get("stableContractAccepted") is not True:
            raise ReplacementError(
                "backups are disabled until stable-contract owner UAT passes")
        history = list(state.get("backupHistory", []))
        if len(history) >= owner.MAX_RETAINED_OWNER_UAT_BACKUPS:
            raise ReplacementError("programmable backup retention limit reached")
        command, environment = base(root)
        evidence = owner.verify_generation(
            command, environment, state["applicationImage"],
            state["databaseImage"], state["expectedSchema"],
            state["expectedApplications"], public=True)
        active_work = owner.verify_no_active_work(command, environment)
        database = compose(command, "ps", "-q", "db", environment=environment)
        if not database:
            raise ReplacementError("programmable database is unavailable")
        wait_health(database, state["project"] + ":db")
        directory = root / "backups"
        if directory.exists() and (directory.is_symlink() or not directory.is_dir()):
            raise ReplacementError("programmable backup directory is unsafe")
        directory.mkdir(mode=0o700, exist_ok=True)
        metadata = directory.stat()
        if (stat.S_IMODE(metadata.st_mode) != 0o700
                or metadata.st_uid != os.geteuid()):
            raise ReplacementError("programmable backup directory is unsafe")
        created = datetime.now(timezone.utc)
        name = "programmable-" + created.strftime("%Y%m%dT%H%M%SZ") + ".dump"
        destination = directory / name
        manifest = directory / (name + ".json")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix="." + name + ".", suffix=".partial", dir=directory)
        os.close(descriptor); temporary = Path(temporary_name)
        container_path = "/tmp/" + name
        try:
            owner.docker("exec", database, "pg_dump", "-U", "postgres", "-d",
                         "postgres", "--format=custom",
                         "--file=" + container_path)
            listing = owner.docker("exec", database, "pg_restore", "--list",
                                   container_path)
            entries = sum(1 for line in listing.splitlines()
                          if line and not line.startswith(";"))
            if entries < 1:
                raise ReplacementError("programmable backup catalogue is empty")
            owner.docker("cp", database + ":" + container_path, str(temporary))
            temporary.chmod(0o600)
            size = temporary.stat().st_size
            if size < 1:
                raise ReplacementError("programmable backup is empty")
            digest = owner.file_digest(temporary)
            os.replace(temporary, destination)
            record = {
                "createdAt": created.isoformat(), "name": name,
                "sha256": digest, "bytes": size,
                "catalogEntries": entries,
                "schema": state["expectedSchema"],
                "applications": state["expectedApplications"],
                "applicationImage": state["applicationImage"],
                "databaseImage": state["databaseImage"],
                "activeWork": active_work,
                "generationVerified": evidence.get("databaseWritable") is True,
            }
            owner.write_json(manifest, record)
            history.append(record)
            state.update(backupHistory=history, lastBackup=record)
            owner.write_json(owner.state_path(root), state)
            return record
        finally:
            temporary.unlink(missing_ok=True)
            owner.docker("exec", database, "rm", "-f", container_path)


def backups(args) -> dict:
    """Verify and list retained programmable-generation backups."""
    root = args.state_root.resolve()
    with owner.locked(root):
        state = load_state(root)
        history = state.get("backupHistory", [])
        if (not isinstance(history, list)
                or len(history) > owner.MAX_RETAINED_OWNER_UAT_BACKUPS):
            raise ReplacementError("programmable backup history is invalid")
        directory = root / "backups"
        if history and (not directory.is_dir() or directory.is_symlink()):
            raise ReplacementError("programmable backup directory is unsafe")
        verified = []
        for record in history:
            if not isinstance(record, dict):
                raise ReplacementError("programmable backup record is invalid")
            name = record.get("name")
            if (not isinstance(name, str)
                    or re.fullmatch(
                        r"programmable-[0-9]{8}T[0-9]{6}Z[.]dump", name) is None):
                raise ReplacementError("programmable backup name is invalid")
            archive = directory / name
            manifest = directory / (name + ".json")
            for path in (archive, manifest):
                metadata = path.stat(follow_symlinks=False)
                if (path.is_symlink() or not stat.S_ISREG(metadata.st_mode)
                        or stat.S_IMODE(metadata.st_mode) != 0o600
                        or metadata.st_uid != os.geteuid()):
                    raise ReplacementError("programmable backup artifact is unsafe")
            try:
                value = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError) as exc:
                raise ReplacementError("programmable backup manifest is invalid") from exc
            if (value != record or archive.stat().st_size != record.get("bytes")
                    or owner.file_digest(archive) != record.get("sha256")):
                raise ReplacementError("programmable backup artifact differs")
            verified.append(record)
        return {"format": "openepm-programmable-backup-list-v1",
                "count": len(verified),
                "maximum": owner.MAX_RETAINED_OWNER_UAT_BACKUPS,
                "items": verified}


def reconcile_build_recovery_state(args) -> dict:
    """Remove stale snapshot references during the no-backup build phase.

    This intentionally changes only controller bookkeeping.  It neither
    touches the active database volume nor deletes an artifact.  If a backup
    artifact exists, cleanup must be performed through an explicitly reviewed
    exact-target deletion before this command can reconcile the state.
    """
    root = args.state_root.resolve()
    with owner.locked(root):
        state = load_state(root)
        if state.get("stableContractAccepted") is True:
            raise ReplacementError(
                "stable-contract recovery state cannot be build-reconciled")
        directory = root / "backups"
        if directory.exists():
            if directory.is_symlink() or not directory.is_dir():
                raise ReplacementError("programmable backup directory is unsafe")
            if any(directory.iterdir()):
                raise ReplacementError(
                    "backup artifacts remain; exact-target cleanup is required")
        state.pop("backupHistory", None)
        state.pop("lastBackup", None)
        rollback = state.get("rollback")
        if isinstance(rollback, dict):
            rollback = dict(rollback)
            rollback.pop("backupName", None)
            rollback.pop("backupSha256", None)
            rollback["mechanism"] = "preserved-suspended-generation"
            state["rollback"] = rollback
        state.update(
            recoveryPolicy="build-phase-no-snapshots",
            buildRecoveryStateReconciledAt=
            datetime.now(timezone.utc).isoformat(),
        )
        owner.write_json(owner.state_path(root), state)
        return state


def _project_resources(kind: str, project: str) -> list[str]:
    """Return exact Compose-owned resources after rechecking their label."""
    if kind not in ("container", "volume", "network"):
        raise ReplacementError("unsupported prepared resource kind")
    arguments = (["ps", "-a"] if kind == "container"
                 else [kind, "ls"])
    arguments.extend(("--filter", "label=com.docker.compose.project=" + project,
                      "--format", "{{.ID}}" if kind == "container"
                      else "{{.Name}}"))
    names = [line.strip() for line in docker(*arguments).splitlines()
             if line.strip()]
    labels = ('.Config.Labels' if kind == "container" else '.Labels')
    for name in names:
        label = docker("inspect", "--type", kind, "--format",
                       '{{ index ' + labels
                       + ' "com.docker.compose.project" }}',
                       name)
        if label != project:
            raise ReplacementError("prepared resource ownership differs")
    return names


def discard_prepared(args) -> dict:
    """Permanently discard one empty, dormant, private build generation.

    This operation intentionally exists only for the pre-UAT build phase.  It
    cannot target an active/populated/public generation and never removes a
    release image.  Docker resources are selected and rechecked by their exact
    Compose project label before removal; the protected state tree is removed
    only after those resources are gone.
    """
    root = args.state_root.resolve()
    runtime_parent = (ROOT / "deploy/macos-pilot/.runtime").resolve()
    if (root.parent != runtime_parent or root == runtime_parent
            or not root.name or root.name.startswith(".")):
        raise ReplacementError("prepared discard state root is unsafe")
    tombstone = runtime_parent / (
        "." + root.name + ".discard-" + secrets.token_hex(8))
    result: dict[str, object]
    with owner.locked(root):
        state = load_state(root)
        prior_state = state.get("state")
        if (prior_state not in ("prepared-empty", "prepare-failed",
                                "preparing-upgrade",
                                "prepared-upgrade-failed")
                or state.get("expectedApplications") != 0
                or state.get("activeGenerationMutation") is not False
                or state.get("publicPortsChanged") is not False
                or state.get("stableContractAccepted") is True):
            raise ReplacementError(
                "only an empty private build generation can be discarded")
        if state.get("backupHistory") or state.get("lastBackup"):
            raise ReplacementError("prepared generation has recovery evidence")
        backup_directory = root / "backups"
        if backup_directory.exists() and (
                backup_directory.is_symlink()
                or not backup_directory.is_dir()
                or any(backup_directory.iterdir())):
            raise ReplacementError("prepared generation has backup artifacts")
        project = str(state["project"])
        containers = _project_resources("container", project)
        volumes = _project_resources("volume", project)
        networks = _project_resources("network", project)
        if prior_state in ("prepare-failed", "preparing-upgrade",
                           "prepared-upgrade-failed") and (
                containers or volumes or networks):
            runtime = state.get("preparedRuntime")
            if (not isinstance(runtime, dict)
                    or runtime.get("quiesced") is not True
                    or runtime.get("runningServices") != []):
                raise ReplacementError(
                    "failed preparation is not durably quiesced")
        for container in containers:
            status = docker("inspect", "--type", "container", "--format",
                            "{{.State.Status}}", container)
            if status not in ("created", "exited", "dead"):
                raise ReplacementError(
                    "prepared generation is not dormant")
        for container in containers:
            docker("rm", container)
        for volume in volumes:
            docker("volume", "rm", volume)
        for network in networks:
            docker("network", "rm", network)
        if tombstone.exists():
            raise ReplacementError("prepared discard tombstone already exists")
        root.rename(tombstone)
        result = {
            "format": "openepm-prepared-discard-v1",
            "project": project,
            "priorState": prior_state,
            "applications": 0,
            "containersRemoved": len(containers),
            "volumesRemoved": len(volumes),
            "networksRemoved": len(networks),
            "releaseImagesRemoved": 0,
            "activeGenerationMutation": False,
            "publicPortsChanged": False,
            "discardedAt": datetime.now(timezone.utc).isoformat(),
        }
    shutil.rmtree(tombstone)
    return result


def verify_prepared_browser(args) -> dict:
    """Start, qualify and re-quiesce the exact private browser boundary."""
    root = args.state_root.resolve()
    with owner.locked(root):
        state = load_state(root)
        if (state.get("state") not in PREPARED_STATES
                or state.get("identityMode") != "keycloak"):
            raise ReplacementError(
                "prepared Keycloak replacement generation is required")
        command, environment = base(root)
        runtime = prepared_runtime(command, environment, "keycloak")
        if not runtime["quiesced"]:
            raise ReplacementError("prepared replacement is not quiesced")
        try:
            identity = start_keycloak(
                command, environment, state["identityImage"],
                state["databaseImage"])
            synchronize_python_coordinator(command, environment)
            owner.all_up(command, environment)
            browser = start_browser_gateway(command, environment)
            entry = probe_browser_authorization(
                int(environment["EPM_BROWSER_GATEWAY_LOOPBACK_PORT"]),
                environment["EPM_OIDC_ISSUER"],
                environment["EPM_PUBLIC_WEB_ORIGIN"])
        finally:
            quiesce_prepared(command, environment, "keycloak")
        runtime = prepared_runtime(command, environment, "keycloak")
        if not runtime["quiesced"]:
            raise ReplacementError(
                "browser-qualified replacement did not quiesce")
        evidence = {
            "verifiedAt": datetime.now(timezone.utc).isoformat(),
            "identity": identity,
            "browserSession": browser,
            "entry": entry,
            "preparedRuntime": runtime,
            "publicPortsChanged": False,
            "activeGenerationMutation": False,
        }
        state.update(browserEntryVerification=evidence,
                     preparedRuntime=runtime)
        owner.write_json(owner.state_path(root), state)
        return evidence


def upgrade_browser_session_policy(args) -> dict:
    """Guardedly make API session expiry return 401 on the active generation."""
    root = args.state_root.resolve()
    with owner.locked(root):
        state = load_state(root)
        if (state.get("state") != "active"
                or state.get("identityMode") != "keycloak"):
            raise ReplacementError(
                "active Keycloak replacement generation is required")
        command, environment = base(root)
        active_work = owner.verify_no_active_work(command, environment)
        path = root / "keycloak-secrets/browser_gateway.cfg"
        current = _read_protected(path, 65536)
        candidate, changed = browser_api_401_config(current)
        port = int(environment["EPM_BROWSER_GATEWAY_LOOPBACK_PORT"])
        if changed:
            try:
                _replace_protected(path, candidate + "\n")
                compose(command, "stop", "browser-gateway",
                        environment=environment)
                readiness = start_browser_gateway(command, environment)
                status, _headers, _body = _browser_response(
                    f"http://127.0.0.1:{port}/api/session-identity")
                if status != 401:
                    raise ReplacementError(
                        "browser gateway API expiry fence did not return 401")
            except BaseException:
                _replace_protected(path, current + "\n")
                compose(command, "stop", "browser-gateway",
                        environment=environment)
                start_browser_gateway(command, environment)
                raise
        else:
            readiness = start_browser_gateway(command, environment)
            status, _headers, _body = _browser_response(
                f"http://127.0.0.1:{port}/api/session-identity")
            if status != 401:
                raise ReplacementError(
                    "browser gateway API expiry fence did not return 401")
        evidence = {
            "format": "openepm-browser-api-401-policy-v1",
            "configuredAt": datetime.now(timezone.utc).isoformat(),
            "changed": changed,
            "unauthenticatedApiStatus": status,
            "interactiveNavigationRedirectPreserved": True,
            "activeWork": active_work,
            "readiness": readiness,
        }
        history = list(state.get("browserSessionPolicyHistory", []))
        history.append(evidence)
        state.update(browserSessionPolicy=evidence,
                     browserSessionPolicyHistory=history)
        owner.write_json(owner.state_path(root), state)
        return evidence


def status(args) -> dict:
    root = args.state_root.resolve()
    with owner.locked(root):
        value = load_state(root)
        if value.get("state") == "active":
            command, environment = base(root)
            evidence = owner.verify_generation(
                command, environment, value["applicationImage"],
                value["databaseImage"], value["expectedSchema"],
                value["expectedApplications"], public=True)
            return {**value, "verified": True,
                    "activationVerification": evidence}
        prepared = value.get("state") in PREPARED_STATES
        runtime = None
        if prepared:
            command, environment = base(root)
            runtime = prepared_runtime(
                command, environment, value.get("identityMode", "cloudflare"))
        value = {**value,
                 "verified": prepared and runtime["quiesced"],
                 "preparedRuntime": runtime}
        return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=(
        "prepare", "activate", "rollback", "recover", "suspend", "backup",
        "backups", "reconcile-build-recovery-state", "status",
        "upgrade-image", "upgrade-active-release", "upgrade-prepared-image", "quiesce-prepared",
        "discard-prepared", "verify-prepared-browser",
        "upgrade-browser-session-policy"))
    parser.add_argument("--state-root", type=Path, default=
                        ROOT / "deploy/macos-pilot/.runtime/programmable-next")
    parser.add_argument("--owner-state-root", type=Path, default=
                        ROOT / "deploy/macos-pilot/.runtime/owner-uat")
    parser.add_argument("--application-image")
    parser.add_argument("--database-image")
    parser.add_argument("--expected-schema", type=int)
    parser.add_argument("--project", default=PROJECT)
    parser.add_argument("--identity-mode", choices=("cloudflare", "keycloak"),
                        default="cloudflare")
    parser.add_argument("--identity-image")
    parser.add_argument("--operations-image")
    parser.add_argument("--oidc-issuer")
    parser.add_argument("--initial-admin-username")
    arguments = parser.parse_args()
    try:
        if arguments.command == "prepare":
            result = prepare(arguments)
        elif arguments.command == "activate":
            result = activate(arguments)
        elif arguments.command == "rollback":
            result = rollback(arguments)
        elif arguments.command == "recover":
            result = recover(arguments)
        elif arguments.command == "suspend":
            result = suspend(arguments)
        elif arguments.command == "backup":
            result = backup(arguments)
        elif arguments.command == "backups":
            result = backups(arguments)
        elif arguments.command == "reconcile-build-recovery-state":
            result = reconcile_build_recovery_state(arguments)
        elif arguments.command == "upgrade-image":
            result = upgrade_image(arguments)
        elif arguments.command == "upgrade-active-release":
            result = upgrade_active_release(arguments)
        elif arguments.command == "upgrade-browser-session-policy":
            result = upgrade_browser_session_policy(arguments)
        elif arguments.command == "upgrade-prepared-image":
            result = upgrade_prepared_image(arguments)
        elif arguments.command == "quiesce-prepared":
            result = quiesce(arguments)
        elif arguments.command == "discard-prepared":
            result = discard_prepared(arguments)
        elif arguments.command == "verify-prepared-browser":
            result = verify_prepared_browser(arguments)
        else:
            result = status(arguments)
    except (ReplacementError, owner.OwnerUatError, RuntimeError,
            ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
