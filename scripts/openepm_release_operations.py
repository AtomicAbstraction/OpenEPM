"""Fixed release backup, restore verification and upgrade preflight utilities.

The operations container receives reviewed database DSNs and an independent
export mount.  Payloads are authenticated-encrypted before their final bundle
directory becomes visible.  Restore accepts only a completed v5 manifest and
only databases that the caller has already prepared as an isolated target.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tarfile
import tempfile
from urllib.parse import parse_qs, unquote, urlsplit

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

if __package__ in (None, ''):
    from operator_import_path import ensure_project_root
    ensure_project_root()

from scripts.apply_postgres_migrations import (
    DATABASE_IDENTITY_SQL, migration_database_digest, migration_files,
    verify_applied_migrations,
)
from epm_core.postgres_fresh_baseline import canonical_chain_digest


FORMAT = "openepm-release-backup-v5"
MAGIC = b"OEPMENC1"
BUNDLE = re.compile(r"^openepm-base-[0-9]{8}T[0-9]{6}Z-[0-9]+$")
EXPORT_ROOT = Path("/var/lib/openepm/export")
KEY_FILE = Path("/run/secrets/backup_encryption_key")
DATABASES = (
    ("epm", Path("/run/secrets/epm_admin_dsn"), "custom"),
    ("control", Path("/run/secrets/control_admin_dsn"), "plain"),
    ("identity", Path("/run/secrets/identity_admin_dsn"), "custom"),
)
AUXILIARY = (
    ("protected-config", Path("/var/lib/openepm/protected-config/source")),
)
AUXILIARY_RESTORE = (
    ("protected-config", Path("/var/lib/openepm/protected-config/restore")),
)
RESTORE_GROUP_ROLES = (
    "epm_access", "epm_analyst", "epm_lifecycle", "epm_provision",
    "epm_python_coordinator", "epm_runtime", "epm_security", "epm_worker",
)
CHUNK = 1024 * 1024
MAX_TREE_FILES = 100_000
MAX_TREE_BYTES = 100 * 1024 * 1024 * 1024
STAGING_HEADROOM_BYTES = 64 * 1024 * 1024
MIGRATIONS = Path(__file__).resolve().parents[1] / "schema" / "postgres"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def digest(path: Path) -> str:
    value = sha256()
    with path.open("rb") as stream:
        while block := stream.read(CHUNK): value.update(block)
    return value.hexdigest()


def key_from_file(path: Path = KEY_FILE) -> bytes:
    raw = path.read_bytes()
    if len(raw) < 32 or len(raw) > 4096:
        raise ValueError("BACKUP_ENCRYPTION_KEY_INVALID")
    return sha256(b"openepm-release-backup-v2\0" + raw).digest()


def manifest_key(key: bytes) -> bytes:
    return hmac.new(key, b"openepm-release-manifest-v3", sha256).digest()


def tree_entries(root: Path) -> list[tuple[str, Path, bool]]:
    if not root.is_dir() or root.is_symlink():
        raise ValueError("BACKUP_AUXILIARY_SOURCE_INVALID")
    entries: list[tuple[str, Path, bool]] = []
    total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative == "secrets/backup_encryption_key":
            continue
        if (not relative or relative.startswith("/") or ".." in relative.split("/")
                or path.is_symlink() or path.name == "backup_encryption_key"):
            raise ValueError("BACKUP_AUXILIARY_ENTRY_INVALID")
        if path.is_dir():
            entries.append((relative, path, True))
        elif path.is_file():
            size = path.stat().st_size
            total += size
            entries.append((relative, path, False))
        else:
            raise ValueError("BACKUP_AUXILIARY_ENTRY_INVALID")
        if len(entries) > MAX_TREE_FILES or total > MAX_TREE_BYTES:
            raise ValueError("BACKUP_AUXILIARY_LIMIT_EXCEEDED")
    return entries


def tree_digest(root: Path) -> str:
    value = sha256()
    for relative, path, directory in tree_entries(root):
        value.update(("d\0" if directory else "f\0").encode())
        value.update(relative.encode("utf-8")); value.update(b"\0")
        if not directory:
            value.update(str(path.stat().st_size).encode()); value.update(b"\0")
            with path.open("rb") as stream:
                while block := stream.read(CHUNK): value.update(block)
    return value.hexdigest()


def archive_tree(root: Path, target: Path) -> str:
    entries = tree_entries(root)
    value = sha256()

    class DigestingReader:
        def __init__(self, stream): self.stream = stream
        def read(self, size=-1):
            block = self.stream.read(size)
            value.update(block)
            return block

    with tarfile.open(target, "x:") as archive:
        for relative, path, directory in entries:
            value.update(("d\0" if directory else "f\0").encode())
            value.update(relative.encode("utf-8")); value.update(b"\0")
            info = tarfile.TarInfo(relative + ("/" if directory else ""))
            info.uid = info.gid = 0; info.uname = info.gname = ""
            info.mtime = 0; info.mode = 0o700 if directory else 0o600
            if directory:
                info.type = tarfile.DIRTYPE; archive.addfile(info)
            else:
                info.size = path.stat().st_size
                value.update(str(info.size).encode()); value.update(b"\0")
                with path.open("rb") as stream:
                    archive.addfile(info, DigestingReader(stream))
    return value.hexdigest()


def extract_tree(source: Path, target: Path) -> None:
    if target.exists() or target.is_symlink():
        raise ValueError("RESTORE_AUXILIARY_TARGET_NOT_EMPTY")
    target.mkdir(mode=0o700, parents=False)
    count = total = 0
    try:
        with tarfile.open(source, "r:") as archive:
            for member in archive:
                count += 1; total += member.size
                parts = Path(member.name).parts
                if (not parts or member.name.startswith("/") or ".." in parts
                        or count > MAX_TREE_FILES or total > MAX_TREE_BYTES
                        or not (member.isdir() or member.isfile())):
                    raise ValueError("BACKUP_AUXILIARY_ARCHIVE_INVALID")
                destination = target.joinpath(*parts)
                if member.isdir(): destination.mkdir(mode=0o700, parents=True, exist_ok=True)
                else:
                    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    incoming = archive.extractfile(member)
                    if incoming is None: raise ValueError("BACKUP_AUXILIARY_ARCHIVE_INVALID")
                    with destination.open("xb") as outgoing:
                        shutil.copyfileobj(incoming, outgoing, CHUNK)
                    os.chmod(destination, 0o600)
    except Exception:
        shutil.rmtree(target, ignore_errors=True)
        raise


def archive_expanded_bytes(source: Path) -> int:
    """Validate the tar index and return its bounded extracted byte count."""
    count = total = 0
    try:
        with tarfile.open(source, "r:") as archive:
            for member in archive:
                count += 1
                total += member.size
                parts = Path(member.name).parts
                if (not parts or member.name.startswith("/") or ".." in parts
                        or count > MAX_TREE_FILES or total > MAX_TREE_BYTES
                        or not (member.isdir() or member.isfile())):
                    raise ValueError("BACKUP_AUXILIARY_ARCHIVE_INVALID")
    except (OSError, tarfile.TarError) as error:
        raise ValueError("BACKUP_AUXILIARY_ARCHIVE_INVALID") from error
    return total


def require_capacity(path: Path, required: int, code: str) -> None:
    if required < 0 or shutil.disk_usage(path).free < required:
        raise ValueError(code)


def encrypt(source: Path, target: Path, key: bytes) -> None:
    nonce = secrets.token_bytes(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(MAGIC + nonce)
    with source.open("rb") as incoming, target.open("xb") as outgoing:
        outgoing.write(MAGIC + nonce)
        while block := incoming.read(CHUNK): outgoing.write(encryptor.update(block))
        outgoing.write(encryptor.finalize())
        outgoing.write(encryptor.tag)


def decrypt(source: Path, target: Path, key: bytes, *, expected_cipher_sha256: str | None = None) -> None:
    with source.open("rb") as incoming:
        size = os.fstat(incoming.fileno()).st_size
        if size < len(MAGIC) + 12 + 16:
            raise ValueError("BACKUP_PAYLOAD_INVALID")
        header = incoming.read(len(MAGIC) + 12)
        if not header.startswith(MAGIC): raise ValueError("BACKUP_PAYLOAD_INVALID")
        nonce = header[len(MAGIC):]
        incoming.seek(-16, os.SEEK_END); tag = incoming.read(16)
        incoming.seek(len(header)); remaining = size - len(header) - 16
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(header)
        ciphertext_digest = sha256(header)
        with target.open("xb") as outgoing:
            while remaining:
                block = incoming.read(min(CHUNK, remaining))
                if not block: raise ValueError("BACKUP_PAYLOAD_TRUNCATED")
                ciphertext_digest.update(block)
                remaining -= len(block); outgoing.write(decryptor.update(block))
            ciphertext_digest.update(tag)
            if (expected_cipher_sha256 is not None
                    and ciphertext_digest.hexdigest() != expected_cipher_sha256):
                raise ValueError("BACKUP_PAYLOAD_DIGEST_MISMATCH")
            outgoing.write(decryptor.finalize())


class Runner:
    def run(self, arguments: list[str], *, stdout=None, env=None) -> None:
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=stdout,
            stderr=subprocess.PIPE, timeout=7200, env=env)
        if result.returncode:
            detail = result.stderr.decode("utf-8", "replace").strip()[:4096]
            raise RuntimeError("RELEASE_COMMAND_FAILED: " + detail)

    def output(self, arguments: list[str], *, env=None) -> str:
        return subprocess.run(arguments, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
            timeout=60, text=True, env=env).stdout.strip()


def dsn(path: Path) -> str:
    value = path.read_text().strip()
    if (not value.startswith(("postgresql://", "postgres://"))
            or "\x00" in value or len(value) > 4096):
        raise ValueError("BACKUP_DATABASE_DSN_INVALID")
    return value


def connection(path: Path) -> tuple[list[str], dict[str,str]]:
    parsed=urlsplit(dsn(path)); query=parse_qs(parsed.query,strict_parsing=True)
    if (not parsed.hostname or not parsed.username or parsed.path in ('','/')
            or parsed.fragment or set(query)-{'sslmode'}
            or any(len(values)!=1 for values in query.values())):
        raise ValueError("BACKUP_DATABASE_DSN_INVALID")
    flags=['--host',parsed.hostname,'--port',str(parsed.port or 5432),
           '--username',unquote(parsed.username),'--dbname',unquote(parsed.path[1:])]
    environment={**os.environ}
    if parsed.password is not None:environment['PGPASSWORD']=unquote(parsed.password)
    if 'sslmode' in query:
        mode=query['sslmode'][0]
        if mode not in ('disable','allow','prefer','require','verify-ca','verify-full'):
            raise ValueError("BACKUP_DATABASE_DSN_OPTIONS_UNSUPPORTED")
        environment['PGSSLMODE']=mode
    return flags,environment


def pg(runner: Runner, executable: str, secret_path: Path, arguments: list[str], *,
       output=False, connection_parameters=None):
    flags,environment=connection_parameters or connection(secret_path)
    command=[executable,*flags,*arguments]
    return (runner.output(command,env=environment) if output
            else runner.run(command,env=environment))


def ensure_restore_group_roles(runner: Runner, secret_path: Path) -> None:
    """Create only the fixed, unprivileged group roles referenced by policies."""
    roles=','.join("'%s'" % role for role in RESTORE_GROUP_ROLES)
    sql_text=f'''DO $restore_roles$
DECLARE role_name text; role_state record;
BEGIN
  FOREACH role_name IN ARRAY ARRAY[{roles}] LOOP
    SELECT rolcanlogin,rolsuper,rolinherit,rolcreaterole,rolcreatedb,
           rolreplication,rolbypassrls INTO role_state
      FROM pg_roles WHERE rolname=role_name;
    IF NOT FOUND THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN INHERIT NOSUPERUSER '
                     'NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',
                     role_name);
    ELSIF role_state.rolcanlogin OR role_state.rolsuper
          OR NOT role_state.rolinherit OR role_state.rolcreaterole
          OR role_state.rolcreatedb OR role_state.rolreplication
          OR role_state.rolbypassrls THEN
      RAISE EXCEPTION 'RESTORE_ROLE_CONFIGURATION_CONFLICT: %',role_name;
    END IF;
  END LOOP;
END $restore_roles$;'''
    pg(runner,'psql',secret_path,['-X','--set','ON_ERROR_STOP=1','-c',sql_text])


SERVICE_PASSWORD_FILES = {
    'EPM_PG_RUNTIME_PASSWORD': 'epm_runtime_password',
    'EPM_PG_ACCESS_PASSWORD': 'epm_access_password',
    'EPM_PG_WORKER_PASSWORD': 'epm_worker_password',
    'EPM_PG_LIFECYCLE_PASSWORD': 'epm_lifecycle_password',
    'EPM_PG_PROVISION_PASSWORD': 'epm_provision_password',
    'EPM_PG_SECURITY_PASSWORD': 'epm_security_password',
}


def ensure_restore_service_logins(admin_secret: Path) -> None:
    """Create the fixed service logins and memberships on the restore target.

    The dump deliberately excludes cluster roles.  Restoring GRANTs is not
    enough: the five delivery services authenticate as their own login roles,
    so those roles must exist before activation.  Reuse the install-time
    bootstrap so creation, membership checks and audit semantics stay identical.
    """
    from scripts.bootstrap_postgres_service_roles import bootstrap_service_roles
    passwords = {}
    for key, name in SERVICE_PASSWORD_FILES.items():
        path = Path('/run/secrets') / name
        try:
            value = path.read_text('utf-8').strip()
        except (OSError, UnicodeError) as error:
            raise ValueError('RESTORE_SERVICE_PASSWORD_UNAVAILABLE') from error
        if len(value) < 24 or '\0' in value:
            raise ValueError('RESTORE_SERVICE_PASSWORD_INVALID')
        passwords[key] = value
    bootstrap_service_roles(dsn(admin_secret), passwords)
    from scripts.bootstrap_postgres_python_coordinator import bootstrap
    coordinator = Path('/run/secrets/epm_python_coordinator_password')
    try:
        coordinator_password = coordinator.read_text('utf-8').strip()
    except (OSError, UnicodeError) as error:
        raise ValueError('RESTORE_PYTHON_COORDINATOR_PASSWORD_UNAVAILABLE') from error
    if not 24 <= len(coordinator_password) <= 4096 or '\0' in coordinator_password:
        raise ValueError('RESTORE_PYTHON_COORDINATOR_PASSWORD_INVALID')
    bootstrap(dsn(admin_secret), coordinator_password)


def manifest(bundle: Path, key: bytes, *, expected_sha256: str | None = None) -> dict:
    path = bundle / "manifest.json"
    if not path.is_file() or path.is_symlink(): raise ValueError("BACKUP_MANIFEST_INVALID")
    with path.open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536: raise ValueError("BACKUP_MANIFEST_INVALID")
    if expected_sha256 is not None and sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("BACKUP_MANIFEST_DIGEST_MISMATCH")
    value = json.loads(raw)
    if type(value) is not dict or value.get("format") != FORMAT:
        raise ValueError("BACKUP_MANIFEST_INVALID")
    expected_fields = {"format", "bundle", "createdAt", "payloads", "source",
                       "deployment", "manifestHmac"}
    if (set(value) != expected_fields
            or value["bundle"] != bundle.name or not BUNDLE.fullmatch(bundle.name)
            or type(value["payloads"]) is not list
            or value["deployment"] != {"identityMode": "bundled"}):
        raise ValueError("BACKUP_MANIFEST_INVALID")
    expected_payloads = ["control.dump.enc", "epm.dump.enc",
                         "identity.dump.enc", "protected-config.tar.enc"]
    if [item.get("name") for item in value["payloads"]] != sorted(expected_payloads):
        raise ValueError("BACKUP_MANIFEST_INVALID")
    if canonical(value) + b"\n" != raw: raise ValueError("BACKUP_MANIFEST_NONCANONICAL")
    signature=value["manifestHmac"]
    unsigned={name:item for name,item in value.items() if name!='manifestHmac'}
    expected=hmac.new(manifest_key(key),canonical(unsigned),sha256).hexdigest()
    if (type(signature) is not str or not hmac.compare_digest(signature,expected)):
        raise ValueError("BACKUP_MANIFEST_AUTHENTICATION_FAILED")
    if (type(value["createdAt"]) is not str or not re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            value["createdAt"]) or type(value["source"]) is not dict
            or set(value["source"]) != {"epmServerVersion","controlServerVersion",
                                        "schemaMigration"}
            or not all(type(item) is str and re.fullmatch(r"[0-9]+",item)
                       for item in value["source"].values())):
        raise ValueError("BACKUP_MANIFEST_INVALID")
    for item in value["payloads"]:
        if (type(item) is not dict or set(item) != {"name", "cipherSha256",
                "plainSha256", "plainBytes", "kind", "treeSha256"}
                or not re.fullmatch(r"[0-9a-f]{64}", item["cipherSha256"])
                or not re.fullmatch(r"[0-9a-f]{64}", item["plainSha256"])
                or type(item["plainBytes"]) is not int or item["plainBytes"] < 1
                or item["kind"] not in ("custom", "plain", "tree")
                or (item["kind"] == "tree") != isinstance(item["treeSha256"], str)
                or (item["treeSha256"] is not None and not re.fullmatch(
                    r"[0-9a-f]{64}", item["treeSha256"]))):
            raise ValueError("BACKUP_MANIFEST_INVALID")
        payload = bundle / item["name"]
        if not payload.is_file() or payload.is_symlink() or digest(payload) != item["cipherSha256"]:
            raise ValueError("BACKUP_PAYLOAD_DIGEST_MISMATCH")
    return value


def selected_databases(identity_mode: str):
    if identity_mode != "bundled":
        raise ValueError("BACKUP_IDENTITY_MODE_INVALID")
    return DATABASES


def manifest_databases(value: dict):
    # manifest() has already authenticated the exact current payload inventory.
    return selected_databases(value["deployment"]["identityMode"])


def backup_cleanup_evidence(root: Path, name: str, *, outcome: str,
                            stage: Path, final: Path) -> dict:
    """Publish exact evidence only for this run-owned backup staging path."""
    expected_stage = root / ("." + name + ".partial")
    expected_final = root / name
    if stage != expected_stage or final != expected_final or not BUNDLE.fullmatch(name):
        raise ValueError("BACKUP_CLEANUP_OWNERSHIP_INVALID")
    scratch = []
    for directory in (stage, final):
        if directory.is_dir() and not directory.is_symlink():
            scratch.extend(path.name for pattern in ("*.dump", "*.tar")
                           for path in directory.glob(pattern) if path.is_file())
    value = {"format": "openepm-backup-cleanup-v1", "operationId": name,
        "outcome": outcome, "ownedStage": stage.name,
        "ownedStageRemaining": stage.exists() or stage.is_symlink(),
        "publishedBundleExists": final.is_dir() and not final.is_symlink(),
        "plaintextScratchRemaining": sorted(scratch)}
    value["cleanupVerified"] = (
        value["ownedStageRemaining"] is False
        and value["plaintextScratchRemaining"] == []
        and value["publishedBundleExists"] is (outcome == "succeeded"))
    evidence = root / ("." + name + ".cleanup.json")
    if evidence.exists() or evidence.is_symlink():
        raise ValueError("BACKUP_CLEANUP_EVIDENCE_CONFLICT")
    evidence.write_bytes(canonical(value) + b"\n")
    os.chmod(evidence, 0o400)
    if not value["cleanupVerified"]:
        raise ValueError("BACKUP_CLEANUP_INCOMPLETE")
    return value


def _publish_backup(*, runner: Runner = Runner(), root: Path = EXPORT_ROOT,
                    key_file: Path = KEY_FILE, clock=None, pid: int | None = None,
                    auxiliary=None, identity_mode: str = "bundled",
                    expected_source_database: str | None = None) -> tuple[str, str]:
    if identity_mode != "bundled":
        raise ValueError("BACKUP_IDENTITY_MODE_INVALID")
    auxiliary = AUXILIARY if auxiliary is None else auxiliary
    if len(auxiliary) != 1 or auxiliary[0][0] != "protected-config":
        raise ValueError("BACKUP_AUXILIARY_SOURCE_INVALID")
    root.resolve().mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink(): raise ValueError("BACKUP_EXPORT_ROOT_INVALID")
    now = (clock or (lambda: datetime.now(timezone.utc)))()
    name = f"openepm-base-{now:%Y%m%dT%H%M%SZ}-{pid or os.getpid()}"
    if not BUNDLE.fullmatch(name): raise ValueError("BACKUP_ID_INVALID")
    stage, final = root / ("." + name + ".partial"), root / name
    cleanup = root / ("." + name + ".cleanup.json")
    if (stage.exists() or stage.is_symlink() or final.exists()
            or final.is_symlink() or cleanup.exists() or cleanup.is_symlink()):
        raise ValueError("BACKUP_ID_CONFLICT")
    key = key_from_file(key_file)
    stage.mkdir(mode=0o700)
    payloads = []
    try:
        app_secret = DATABASES[0][1]
        app_connection = connection(app_secret) if expected_source_database is not None else None

        def check_application_database():
            identity = pg(runner, 'psql', app_secret, ['-AtX', '-c', DATABASE_IDENTITY_SQL],
                          output=True, connection_parameters=app_connection)
            if migration_database_digest(identity) != expected_source_database:
                raise ValueError("BACKUP_SOURCE_DATABASE_CHANGED")

        databases=selected_databases(identity_mode)
        for label, secret_path, kind in databases:
            plain = stage / (label + ".dump")
            if kind == "custom":
                arguments = ["--format=custom", "--no-owner",
                             "--file", str(plain)]
                # The EPM database must retain its GRANTs: the restore target
                # creates the fixed NOLOGIN policy roles and the service login
                # memberships, and the runtime role needs those ACLs to serve
                # business traffic.  Control-plane databases are restored into
                # independently bootstrapped roles, so their ACLs stay out.
                if label != "epm":
                    arguments.append("--no-acl")
            else:
                arguments = ["--format=plain", "--no-owner", "--no-acl",
                             "--file",str(plain)]
            # Control state is scoped to the configured database.  A cluster-wide
            # pg_dumpall would include service roles and the active restore
            # principal, making a restore into an independently bootstrapped
            # deployment both over-broad and impossible (the current role cannot
            # drop itself).  Restore already requires an empty target, so emitting
            # destructive cleanup statements would add failure modes without
            # providing any supported behavior.
            if label == 'epm' and app_connection:
                check_application_database()
            pg(runner, 'pg_dump', secret_path, arguments,
               connection_parameters=app_connection if label == 'epm' else None)
            if label == 'epm' and app_connection:
                check_application_database()
            if not plain.is_file() or plain.stat().st_size < 1:
                raise ValueError("BACKUP_DATABASE_DUMP_EMPTY")
            encrypted = stage / (label + ".dump.enc")
            plain_hash, plain_size = digest(plain), plain.stat().st_size
            encrypt(plain, encrypted, key); plain.unlink()
            payloads.append({"name": encrypted.name, "cipherSha256": digest(encrypted),
                "plainSha256": plain_hash, "plainBytes": plain_size, "kind": kind,
                "treeSha256": None})
        for label, source in auxiliary:
            if label != "protected-config":
                raise ValueError("BACKUP_AUXILIARY_SOURCE_INVALID")
            plain = stage / (label + ".tar")
            tree_hash = archive_tree(source, plain)
            encrypted = stage / (label + ".tar.enc")
            plain_hash, plain_size = digest(plain), plain.stat().st_size
            encrypt(plain, encrypted, key); plain.unlink()
            payloads.append({"name": encrypted.name, "cipherSha256": digest(encrypted),
                "plainSha256": plain_hash, "plainBytes": plain_size, "kind": "tree",
                "treeSha256": tree_hash})
        payloads.sort(key=lambda item: item["name"])
        source = {"epmServerVersion": pg(runner,'psql',app_secret,
            ["-AtX","-c","SHOW server_version_num"],output=True, connection_parameters=app_connection),
            "controlServerVersion": pg(runner,'psql',DATABASES[1][1],
            ["-AtX","-c","SHOW server_version_num"],output=True),
            "schemaMigration": pg(runner,'psql',app_secret,
            ["-AtX","-c","SELECT COALESCE(max(version),0) FROM epm.schema_migration"],
            output=True, connection_parameters=app_connection)}
        if app_connection:
            check_application_database()
        value = {"format": FORMAT, "bundle": name,
                 "createdAt": now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                 "payloads": payloads, "source": source,
                 "deployment": {"identityMode": identity_mode}}
        value["manifestHmac"]=hmac.new(
            manifest_key(key),canonical(value),sha256).hexdigest()
        manifest_bytes = canonical(value) + b"\n"
        (stage / "manifest.json").write_bytes(manifest_bytes)
        os.chmod(stage / "manifest.json", 0o400)
        stage.rename(final)
        backup_cleanup_evidence(root, name, outcome="succeeded",
                                stage=stage, final=final)
        return name, sha256(manifest_bytes).hexdigest()
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        backup_cleanup_evidence(root, name, outcome="failed",
                                stage=stage, final=final)
        raise


def backup(*, runner: Runner = Runner(), root: Path = EXPORT_ROOT,
           key_file: Path = KEY_FILE, clock=None, pid: int | None = None,
           auxiliary=None, identity_mode: str = "bundled") -> str:
    name, _ = _publish_backup(runner=runner, root=root, key_file=key_file, clock=clock,
                              pid=pid, auxiliary=auxiliary, identity_mode=identity_mode)
    return name


def validate_bundle(name: str, root: Path = EXPORT_ROOT,
                    key_file: Path = KEY_FILE, *,
                    expected_manifest_sha256: str | None = None) -> tuple[Path, dict]:
    if type(name) is not str or not BUNDLE.fullmatch(name):
        raise ValueError("BACKUP_ID_INVALID")
    bundle = root / name
    if not bundle.is_dir() or bundle.is_symlink(): raise ValueError("BACKUP_UNAVAILABLE")
    return bundle, manifest(bundle, key_from_file(key_file), expected_sha256=expected_manifest_sha256)


def _verify_migration_chain(runner: Runner, secret_path: Path, migrations: Path, *,
                            operation: str, expected_version: int | None = None,
                            expected_final_migration: str | None = None,
                            require_final: bool = False,
                            bind_database: bool = False) -> tuple[int, str] | tuple[int, str, str]:
    try:
        files = migration_files(migrations, expected_final_migration=expected_final_migration)
    except (OSError, ValueError) as error:
        raise ValueError(f"{operation}_MIGRATION_SET_INVALID") from error
    if require_final:
        expected_version = len(files)
    if expected_version is not None and not 1 <= expected_version <= len(files):
        raise ValueError(f"{operation}_MIGRATION_SET_INVALID")
    ledger_query = ("SELECT COALESCE(json_agg(json_build_array(version,checksum) "
                    "ORDER BY version)::text,'[]') FROM epm.schema_migration")
    query = (f"SELECT json_build_array(({DATABASE_IDENTITY_SQL}), ({ledger_query})::json)::text"
             if bind_database else ledger_query)
    raw = pg(runner, 'psql', secret_path, ["-AtX", "-c", query], output=True)
    try:
        actual = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError(f"{operation}_MIGRATION_LEDGER_INVALID") from error
    if bind_database:
        if type(actual) is not list or len(actual) != 2:
            raise ValueError(f"{operation}_MIGRATION_LEDGER_INVALID")
        identity, actual = actual
        database_digest = migration_database_digest(identity)
    if (type(actual) is not list or not actual or any(
            type(row) is not list or len(row) != 2
            or type(row[0]) is not int or row[0] < 1
            or not isinstance(row[1], str) or not re.fullmatch(r'[0-9a-f]{64}', row[1])
            for row in actual)):
        raise ValueError(f"{operation}_MIGRATION_LEDGER_INVALID")
    applied = dict(actual)
    version = max(applied)
    if operation == 'UPGRADE' and version > len(files):
        raise ValueError("UPGRADE_DATABASE_NEWER_THAN_RELEASE")
    if len(actual) != len(applied) or (expected_version is not None and version != expected_version):
        raise ValueError(f"{operation}_MIGRATION_CHAIN_MISMATCH")
    try:
        verify_applied_migrations(files, applied)
    except OSError as error:
        raise ValueError(f"{operation}_MIGRATION_SET_INVALID") from error
    except ValueError as error:
        raise ValueError(f"{operation}_MIGRATION_CHAIN_MISMATCH") from error
    ledger = (version, canonical_chain_digest([
        {'version': applied_version, 'sha256': checksum}
        for applied_version, checksum in sorted(applied.items())
    ]))
    return (*ledger, database_digest) if bind_database else ledger


def verify_migration_chain(runner: Runner, secret_path: Path,
                           expected_version: int, migrations: Path = MIGRATIONS) -> None:
    """Bind the restored immutable ledger to the packaged migration bytes."""
    _verify_migration_chain(runner, secret_path, migrations, operation='RESTORE',
                            expected_version=expected_version)


def restore(name: str, *, runner: Runner = Runner(), root: Path = EXPORT_ROOT,
            key_file: Path = KEY_FILE, auxiliary=None,
            identity_mode: str = "bundled", expected_manifest_sha256: str | None = None) -> None:
    auxiliary = AUXILIARY_RESTORE if auxiliary is None else auxiliary
    bundle, value = validate_bundle(name, root, key_file, expected_manifest_sha256=expected_manifest_sha256)
    key = key_from_file(key_file)
    if identity_mode != "bundled":
        raise ValueError("RESTORE_TARGET_IDENTITY_MODE_INVALID")
    databases = manifest_databases(value)
    # The controller supplies a distinct Compose project.  The utility adds a
    # second guard: both target databases must contain no non-system schemas.
    for _, secret_path, _ in databases:
        count = pg(runner,'psql',secret_path,["-AtX","-c",
            "SELECT count(*) FROM pg_namespace n WHERE n.nspname NOT LIKE 'pg_%' "
            "AND n.nspname NOT IN ('information_schema','public') AND NOT EXISTS "
            "(SELECT 1 FROM pg_depend d JOIN pg_extension e ON e.oid=d.refobjid "
            "WHERE d.classid='pg_namespace'::regclass AND d.objid=n.oid "
            "AND d.deptype='e' AND e.extname='pg_duckdb')"],output=True)
        if count != "0": raise ValueError("RESTORE_TARGET_NOT_EMPTY")
    auxiliary_targets = {label: source for label, source in auxiliary}
    expected_auxiliary = {"protected-config"}
    if len(auxiliary) != 1 or set(auxiliary_targets) != expected_auxiliary:
        raise ValueError("RESTORE_AUXILIARY_TARGET_INVALID")
    if any(path.exists() or path.is_symlink() for path in auxiliary_targets.values()):
        raise ValueError("RESTORE_AUXILIARY_TARGET_NOT_EMPTY")
    # Plaintext staging belongs to the independently mounted export filesystem,
    # not the operations container's 64 MiB /tmp. Preflight the authenticated
    # manifest before creating any plaintext and always remove the owned stage.
    staging_bytes = sum(item["plainBytes"] for item in value["payloads"])
    require_capacity(root, staging_bytes + STAGING_HEADROOM_BYTES,
                     "RESTORE_STAGING_CAPACITY_INSUFFICIENT")
    with tempfile.TemporaryDirectory(prefix=".openepm-restore-", dir=root) as temporary:
        directory = Path(temporary)
        decoded = {}
        for item in value["payloads"]:
            target = directory / item["name"].removesuffix(".enc")
            decrypt(bundle / item["name"], target, key, expected_cipher_sha256=item["cipherSha256"])
            if target.stat().st_size != item["plainBytes"] or digest(target) != item["plainSha256"]:
                raise ValueError("BACKUP_PLAINTEXT_DIGEST_MISMATCH")
            decoded[item["name"]] = target
        stages = {}
        try:
            for label in sorted(expected_auxiliary):
                target = auxiliary_targets[label]
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                stage = target.parent / ("." + target.name + ".restore-partial")
                if stage.exists() or stage.is_symlink():
                    raise ValueError("RESTORE_AUXILIARY_TARGET_NOT_EMPTY")
                expanded = archive_expanded_bytes(decoded[label + ".tar.enc"])
                require_capacity(target.parent,
                    expanded + STAGING_HEADROOM_BYTES,
                    "RESTORE_AUXILIARY_CAPACITY_INSUFFICIENT")
                extract_tree(decoded[label + ".tar.enc"], stage)
                expected = next(item["treeSha256"] for item in value["payloads"]
                                if item["name"] == label + ".tar.enc")
                if tree_digest(stage) != expected:
                    raise ValueError("BACKUP_AUXILIARY_TREE_DIGEST_MISMATCH")
                stages[label] = stage
            # Database-scoped dumps deliberately exclude cluster globals.
            # Create the fixed NOLOGIN policy roles only after every payload
            # and auxiliary target has passed validation; deployment-owned
            # service login credentials are never backed up.
            ensure_restore_group_roles(runner,DATABASES[0][1])
            for label,secret_path,kind in databases:
                if kind == "plain":
                    pg(runner,'psql',secret_path,["-X","--set","ON_ERROR_STOP=1",
                        "--file",str(decoded[label+".dump.enc"])])
                else:
                    arguments=["--exit-on-error","--no-owner"]
                    if label != "epm":
                        arguments.append("--no-acl")
                    arguments.append(str(decoded[label+".dump.enc"]))
                    pg(runner,'pg_restore',secret_path,arguments)
            # Login roles are deployment-owned and never restored from the
            # backup.  Recreate them from the target's protected password files
            # so the restored database is servable by the real runtime roles.
            ensure_restore_service_logins(DATABASES[0][1])
            for label in sorted(expected_auxiliary):
                stages[label].rename(auxiliary_targets[label])
        except Exception:
            for stage in stages.values():
                if stage.exists(): shutil.rmtree(stage, ignore_errors=True)
            raise


def verify(name: str, *, runner: Runner = Runner(), root: Path = EXPORT_ROOT,
           key_file: Path = KEY_FILE, auxiliary=None,
           identity_mode: str = "bundled", migrations: Path = MIGRATIONS,
           expected_manifest_sha256: str | None = None) -> None:
    auxiliary = AUXILIARY_RESTORE if auxiliary is None else auxiliary
    _, value = validate_bundle(name, root, key_file, expected_manifest_sha256=expected_manifest_sha256)
    if identity_mode != "bundled":
        raise ValueError("RESTORE_TARGET_IDENTITY_MODE_INVALID")
    actual = pg(runner,'psql',DATABASES[0][1],["-AtX","-c",
        "SELECT COALESCE(max(version),0) FROM epm.schema_migration"],output=True)
    if actual != str(value["source"]["schemaMigration"]):
        raise ValueError("RESTORE_SCHEMA_VERSION_MISMATCH")
    verify_migration_chain(runner, DATABASES[0][1], int(actual), migrations)
    if pg(runner,'psql',DATABASES[0][1],["-AtX","-c","SELECT 1"],output=True) != "1":
        raise ValueError("RESTORE_EPM_DATABASE_UNAVAILABLE")
    privileges = pg(runner,'psql',DATABASES[0][1],["-AtX","-c",
        "SELECT concat("
        "has_schema_privilege('epm_runtime','epm','USAGE')::int,"
        "has_table_privilege('epm_runtime','epm.application_state','SELECT')::int,"
        "has_table_privilege('epm_runtime','epm.numeric_fact_event','INSERT')::int,"
        "has_column_privilege('epm_runtime','epm.numeric_cell_current',"
        "'workspace_id','UPDATE')::int,"
        "coalesce((SELECT count(*)=7 AND bool_and(rolcanlogin) FROM pg_roles WHERE rolname IN "
        "('epm_runtime_login','epm_access_login','epm_worker_login',"
        "'epm_lifecycle_login','epm_provision_login','epm_security_login',"
        "'epm_python_coordinator_login')),false)::int)"],
        output=True)
    privilege_errors = (
        "RESTORE_RUNTIME_SCHEMA_PRIVILEGE_MISSING",
        "RESTORE_RUNTIME_APPLICATION_READ_PRIVILEGE_MISSING",
        "RESTORE_RUNTIME_EVENT_WRITE_PRIVILEGE_MISSING",
        "RESTORE_RUNTIME_CURRENT_LOCK_PRIVILEGE_MISSING",
        "RESTORE_SERVICE_LOGIN_MISSING",
    )
    if len(privileges) != len(privilege_errors) or any(
            value not in '01' for value in privileges):
        raise ValueError("RESTORE_RUNTIME_PRIVILEGE_PROBE_INVALID")
    for allowed, code in zip(privileges, privilege_errors):
        if allowed != '1':
            raise ValueError(code)
    if pg(runner,'psql',DATABASES[1][1],["-AtX","-c","SELECT 1"],output=True) != "1":
        raise ValueError("RESTORE_CONTROL_DATABASE_UNAVAILABLE")
    for label,secret_path,_ in selected_databases(identity_mode)[2:]:
        if pg(runner,'psql',secret_path,["-AtX","-c","SELECT 1"],output=True) != "1":
            raise ValueError("RESTORE_"+label.upper()+"_DATABASE_UNAVAILABLE")
    targets = dict(auxiliary)
    labels = ("protected-config",)
    for label in labels:
        expected = next(item["treeSha256"] for item in value["payloads"]
                        if item["name"] == label + ".tar.enc")
        if label not in targets or tree_digest(targets[label]) != expected:
            raise ValueError("RESTORE_AUXILIARY_VERIFICATION_FAILED")


def _check_definition_owner_upgrade(runner: Runner, current: int, migrations: Path) -> None:
    if not 43 <= current < 366:
        return
    target = next(migrations.glob('0366_*.sql'), None)
    if target is None:
        return
    # Reuse the immutable migration's exact classifier. Current runtime owner
    # types can evolve without changing what a pending historical migration accepts.
    try:
        source = target.read_text(encoding='utf-8')
        cases = re.findall(
            r"^UPDATE epm\.expression_rule_definition SET definition_kind="
            r"(CASE program->>'function'(?:\s+WHEN '[a-z][a-z._]+' THEN '[A-Za-z]+')+\s+END);$",
            source, re.MULTILINE)
    except (OSError, UnicodeError) as error:
        raise ValueError("UPGRADE_DEFINITION_OWNER_0366_PROBE_INVALID") from error
    if len(cases) != 1:
        raise ValueError("UPGRADE_DEFINITION_OWNER_0366_PROBE_INVALID")

    relation = 'epm.expression_rule_definition'
    latest = ''
    if current < 308:
        relation = 'epm.expression_rule_version'
        # Migration 0308 keeps the latest saved version, even when its older
        # publication points at a different version of that rule.
        latest = """ AND NOT EXISTS (
            SELECT 1 FROM epm.expression_rule_version newer
            WHERE (newer.workspace_id, newer.application_id, newer.rule_id)
                = (rule.workspace_id, rule.application_id, rule.rule_id)
              AND newer.version > rule.version)"""
    observed = pg(runner, 'psql', DATABASES[0][1], ['-AtX', '-c',
        f'SELECT EXISTS(SELECT 1 FROM {relation} rule WHERE ({cases[0]}) IS NULL{latest})::int'],
        output=True)
    if observed == '1':
        raise ValueError("UPGRADE_DEFINITION_OWNER_0366_REQUIRES_REVIEW")
    if observed != '0':
        raise ValueError("UPGRADE_DEFINITION_OWNER_0366_PROBE_INVALID")


def _check_producer_upgrade(runner: Runner, current: int, migrations: Path) -> None:
    if not 217 <= current < 368:
        return
    target = next(migrations.glob('0368_*.sql'), None)
    if target is None:
        return
    invalid = "UPGRADE_PRODUCER_0368_PROBE_INVALID"
    # The signed historical migration owns these predicates. Only probe
    # conditions whose relations and provenance columns exist on the source.
    try:
        block, end, _ = target.read_text(encoding='utf-8').partition('END $preflight$;')
    except (OSError, UnicodeError) as error:
        raise ValueError(invalid) from error
    checks = re.findall(
        r"^ IF (EXISTS\(SELECT [^;]+?\)) THEN\n  RAISE EXCEPTION '(PRODUCER_0368_[A-Z_]+)';\n END IF;",
        block, re.MULTILINE)
    introduced = {'PRODUCER_0368_AMBIGUOUS_CHILD': 217,
                  'PRODUCER_0368_CURRENT_HEAD_JOB_UNPROVEN': 356,
                  'PRODUCER_0368_ACTIVE_LEGACY_WORK': 217}
    if not end or tuple(code for _, code in checks) != tuple(introduced):
        raise ValueError(invalid)
    eligible = {code: predicate for predicate, code in checks if current >= introduced[code]}
    clauses = ' '.join(f"WHEN {predicate} THEN '{code}'" for code, predicate in eligible.items())
    observed = pg(runner, 'psql', DATABASES[0][1], ['-AtX', '-c',
        f"SELECT CASE {clauses} ELSE '0' END"], output=True)
    if observed in eligible:
        raise ValueError('UPGRADE_' + observed)
    if observed != '0':
        raise ValueError(invalid)


def preflight(*, runner: Runner = Runner(), migrations: Path = MIGRATIONS,
              expected_final_migration: str | None = None,
              bind_database: bool = False) -> tuple[int, str] | tuple[int, str, str]:
    ledger = _verify_migration_chain(runner, DATABASES[0][1], migrations, operation='UPGRADE',
                                     expected_final_migration=expected_final_migration,
                                     bind_database=bind_database)
    current = ledger[0]
    server = int(pg(runner,'psql',DATABASES[0][1],["-AtX","-c",
        "SHOW server_version_num"],output=True))
    if server // 10000 != 18: raise ValueError("UPGRADE_POSTGRES_VERSION_UNSUPPORTED")
    control_server = int(pg(runner,'psql',DATABASES[1][1],["-AtX","-c",
        "SHOW server_version_num"],output=True))
    if control_server // 10000 != 18:
        raise ValueError("UPGRADE_CONTROL_POSTGRES_VERSION_UNSUPPORTED")
    _check_definition_owner_upgrade(runner, current, migrations)
    if current < 12:
        return ledger
    if current >= 175:
        active = "EXISTS(SELECT 1 FROM epm.task WHERE status IN ('Accepted','Waiting','Running','InterruptRequested'))"
        inspection = "EXISTS(SELECT 1 FROM epm.task WHERE status='NeedsInspection')"
    else:
        active = "EXISTS(SELECT 1 FROM epm.job WHERE status IN ('accepted','ready','running','staged','cancel_requested'))"
        inspection = "EXISTS(SELECT 1 FROM epm.job WHERE status='needs_inspection')"
    impact_pending = impact_failed = 'false'
    if current >= 299:
        # The impact outbox is not represented by universal tasks. Use the
        # same watermark and failed head as the application queue read.
        impact_pending = """EXISTS(SELECT 1 FROM epm.application_state
            WHERE impact_epoch > processed_impact_epoch)"""
        impact_failed = """EXISTS(SELECT 1 FROM epm.calculation_impact_progress p
            JOIN epm.application_state s USING (workspace_id,application_id)
            WHERE s.impact_epoch > s.processed_impact_epoch
              AND p.impact_epoch = s.processed_impact_epoch + 1 AND p.status = 'failed')"""
    flags = ",':',".join(f'({predicate})::int' for predicate in
                         (active, inspection, impact_pending, impact_failed))
    observed = pg(runner, 'psql', DATABASES[0][1], ['-AtX', '-c', f'SELECT concat({flags})'],
                  output=True)
    if not isinstance(observed, str) or not re.fullmatch(r'[01](?::[01]){3}', observed):
        raise ValueError("UPGRADE_DURABLE_WORK_PROBE_INVALID")
    active_flag, inspection_flag, pending_flag, failed_flag = observed.split(':')
    if failed_flag == '1':
        raise ValueError("UPGRADE_CALCULATION_IMPACT_REQUIRES_REVIEW")
    if active_flag == '1':
        raise ValueError("UPGRADE_ACTIVE_DURABLE_WORK_REQUIRES_DRAIN")
    if inspection_flag == '1':
        raise ValueError("UPGRADE_UNCERTAIN_DURABLE_WORK_REQUIRES_CLASSIFICATION")
    if pending_flag == '1':
        raise ValueError("UPGRADE_CALCULATION_IMPACT_REQUIRES_DRAIN")
    _check_producer_upgrade(runner, current, migrations)
    return ledger


def main(operation: str | None = None) -> None:
    operation = operation or Path(os.environ.get("OPEN_EPM_OPERATION", "")).name
    parser = argparse.ArgumentParser()
    if operation == "backup":
        action = parser.add_mutually_exclusive_group()
        action.add_argument("--report-manifest-sha256", action="store_true")
        action.add_argument("--verify-bundle")
        parser.add_argument("--expected-manifest-sha256")
        parser.add_argument("--expected-source-schema")
        parser.add_argument("--expected-source-database")
    if operation in ("restore", "restore-verify"):
        parser.add_argument("bundle")
        parser.add_argument("--expected-manifest-sha256")
    if operation == "upgrade-preflight":
        parser.add_argument("--target-migration", required=True)
        parser.add_argument("--verify-installed", action="store_true")
        parser.add_argument("--bind-database", action="store_true")
    args = parser.parse_args()
    if operation == "backup":
        if args.verify_bundle is not None:
            if (not re.fullmatch(r"[0-9a-f]{64}", args.expected_manifest_sha256 or "")
                    or not re.fullmatch(r"[0-9]{4}", args.expected_source_schema or "")):
                parser.error("verification requires an exact manifest digest and source schema")
        elif args.expected_manifest_sha256 is not None or args.expected_source_schema is not None:
            parser.error("expected manifest and schema are only available with --verify-bundle")
        if (args.expected_source_database is not None
                and (not args.report_manifest_sha256
                     or not re.fullmatch(r"[0-9a-f]{64}", args.expected_source_database))):
            parser.error("expected source database requires a SHA-256 digest and a backup receipt")
    if operation in ("backup", "restore", "restore-verify"):
        identity_mode = os.environ.get("EPM_IDENTITY_MODE")
        if identity_mode != "bundled":
            raise SystemExit(
                "EPM_IDENTITY_MODE must be bundled; external identity profiles are retired")
    try:
        if operation == "backup":
            if args.verify_bundle is not None:
                _, value = validate_bundle(args.verify_bundle,
                    expected_manifest_sha256=args.expected_manifest_sha256)
                if int(value["source"]["schemaMigration"]) != int(args.expected_source_schema):
                    raise ValueError("BACKUP_SOURCE_SCHEMA_MISMATCH")
            else:
                name, manifest_sha256 = _publish_backup(identity_mode=identity_mode,
                    expected_source_database=args.expected_source_database)
                suffix = f" manifest_sha256={manifest_sha256}" if args.report_manifest_sha256 else ""
                print(f"bundle={name}{suffix}")
        elif operation == "restore": restore(args.bundle,
            identity_mode=identity_mode, expected_manifest_sha256=args.expected_manifest_sha256)
        elif operation == "restore-verify": verify(args.bundle,
            identity_mode=identity_mode, expected_manifest_sha256=args.expected_manifest_sha256)
        elif operation == "upgrade-preflight":
            if args.verify_installed:
                ledger = _verify_migration_chain(
                    Runner(), DATABASES[0][1], MIGRATIONS, operation='UPGRADE',
                    expected_final_migration=args.target_migration, require_final=True,
                    bind_database=args.bind_database)
            else:
                ledger = preflight(expected_final_migration=args.target_migration, bind_database=args.bind_database)
            print(f"{ledger[0]:04d}", *ledger[1:])
        else: raise SystemExit("Unsupported fixed release operation")
    except BaseException:
        if operation in ("restore", "restore-verify"):
            from epm_core.observability import record_operational_signal
            record_operational_signal("recovery_failure")
        raise


if __name__ == "__main__": main()
