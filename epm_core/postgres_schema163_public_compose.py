"""Qualification-only Compose overlay for schema-163 public parity.

The production Compose file is deliberately not modified.  This renderer
creates one disposable database lifecycle at a time and rewrites every service
DSN to the owned database before any application service starts.
"""
from __future__ import annotations

import re
import json
import os
from contextlib import contextmanager
from pathlib import Path
import subprocess
import shutil
import sys
import secrets
from tempfile import TemporaryDirectory
from typing import Any

MODES = {"fresh-baseline-164", "semantic-reference-164"}
_HOST_RUNTIME_ENV=("PATH","HOME","USER","TMPDIR","DOCKER_HOST","DOCKER_CONTEXT",
                   "DOCKER_CONFIG","COLIMA_HOME")
_SERVICES = ("platform", "workspace", "router", "web", "worker")
_DSNS = {
    "platform": ("EPM_PG_PROVISION_DSN", "epm_provision_login", "EPM_PG_PROVISION_PASSWORD"),
    "workspace": ("EPM_PG_LIFECYCLE_DSN", "epm_lifecycle_login", "EPM_PG_LIFECYCLE_PASSWORD"),
    "router": ("EPM_PG_ACCESS_DSN", "epm_access_login", "EPM_PG_ACCESS_PASSWORD"),
    "web": ("EPM_PG_ACCESS_DSN", "epm_access_login", "EPM_PG_ACCESS_PASSWORD"),
    "worker": ("EPM_PG_WORKER_DSN", "epm_worker_login", "EPM_PG_WORKER_PASSWORD"),
}


def _dsn(user: str, password_var: str, database: str) -> str:
    return (f"host=db port=5432 user={user} "
            f"password=${{{password_var}:?set {password_var}}} dbname={database}")


def render_public_parity_override(database: str, mode: str) -> dict[str, Any]:
    if not re.fullmatch(r"epm_disposable_[a-z0-9_]{1,48}", database):
        raise ValueError("SCHEMA163_PARITY_DATABASE_NOT_DISPOSABLE")
    if mode not in MODES:
        raise ValueError("SCHEMA163_PARITY_MODE_INVALID")
    services: dict[str, Any] = {
        "db": {"build": None,
               "image": "${EPM_TEST_COMPOSE_DATABASE_IMAGE:?set exact database image}",
               "environment": {"POSTGRES_DB": database},
               "healthcheck": {"test": ["CMD-SHELL",
                   f"pg_isready -U postgres -d {database}"]}},
        "parity-initialize": {
            "image": "${EPM_TEST_QUALIFICATION_IMAGE:?set exact qualification image}",
            "profiles": ["schema163-public-parity"],
            "user": "10001:10001", "restart": "no", "read_only": True,
            "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=32m"],
            "command": ["python", "-m", "scripts.initialize_schema163_public_parity",
                "--dsn", ("host=db port=5432 user=postgres "
                    "password=${EPM_POSTGRES_PASSWORD:?set EPM_POSTGRES_PASSWORD} "
                    f"dbname={database}"), "--mode", mode,
                "--artifact", "/qualification/artifact.json", "--migrations",
                "/qualification/migrations", "--source-commit",
                "${EPM_TEST_SOURCE_COMMIT:?set exact source commit}",
                "--expected-database",database],
            "environment": {"EPM_SCHEMA163_PUBLIC_PARITY_DISPOSABLE": "1"},
            "depends_on": {"db": {"condition": "service_healthy"}}},
        "parity-runner": {
            "image": "${EPM_TEST_QUALIFICATION_IMAGE:?set exact qualification image}",
            "profiles": ["schema163-public-parity"], "restart": "no",
            "read_only": True, "working_dir": "/srv/openepm",
            "tmpfs": ["/tmp:rw,noexec,nosuid,nodev,size=64m"],
            "environment": {"EPM_SCHEMA163_PUBLIC_PARITY_DISPOSABLE": "1",
                "EPM_TEST_DATABASE_NAME": database, "EPM_TEST_INITIALIZATION_MODE": mode}},
    }
    services["backup-volume-init"]={"build":None,"image":
        "${EPM_TEST_COMPOSE_DATABASE_IMAGE:?set exact database image}"}
    for service in ("migrate","bootstrap-roles","bootstrap-operator",*_SERVICES):
        services.setdefault(service,{})["build"]=None
        services[service]["image"]=(
            "${EPM_TEST_QUALIFICATION_IMAGE:?set exact qualification image}")
    for service, (key, user, password) in _DSNS.items():
        services.setdefault(service, {}).setdefault("environment", {})[key] = _dsn(user,password,database)
    admin=_dsn("postgres","EPM_POSTGRES_PASSWORD",database)
    for service in ("migrate","bootstrap-roles","bootstrap-operator"):
        services.setdefault(service,{}).setdefault("environment",{})[
            "EPM_POSTGRES_ADMIN_DSN"]=admin
    # Services with multiple credentials need all of them rewritten.
    for service in ("router", "web", "worker"):
        env=services.setdefault(service,{}).setdefault("environment",{})
        env["EPM_PG_RUNTIME_DSN"]=_dsn("epm_runtime_login","EPM_PG_RUNTIME_PASSWORD",database)
    for service in ("workspace", "router"):
        services[service]["environment"]["EPM_PG_SECURITY_DSN"]=_dsn(
            "epm_security_login","EPM_PG_SECURITY_PASSWORD",database)
    for service in ("platform","workspace","router","web"):
        services[service].setdefault("environment",{})["SSL_CERT_FILE"]="/run/parity-ca/ca.pem"
        services[service]["volumes"]=[
            "${EPM_TEST_OIDC_CA_PATH:?set disposable OIDC CA path}:/run/parity-ca/ca.pem:ro"]
    return {"services": services}


class DockerComposePublicParityFactory:
    """Own one sequential disposable Compose lifecycle and always remove it."""

    def __init__(self, *, root: Path, project_prefix: str,
                 environment: dict[str, str],
                 run=subprocess.run, compose_command: tuple[str,...]|None=None):
        self.root=Path(root).resolve()
        self.compose=self.root/'deploy/postgres/compose.yaml'
        self.project_prefix=project_prefix
        self.environment=dict(environment)
        secret_keys=("EPM_POSTGRES_PASSWORD","EPM_PG_RUNTIME_PASSWORD",
            "EPM_PG_ACCESS_PASSWORD","EPM_PG_WORKER_PASSWORD",
            "EPM_PG_LIFECYCLE_PASSWORD","EPM_PG_PROVISION_PASSWORD",
            "EPM_PG_SECURITY_PASSWORD")
        self.secret_keys=secret_keys
        if any(key in self.environment for key in secret_keys):
            raise ValueError("SCHEMA163_PARITY_CALLER_SECRET_FORBIDDEN")
        generated={key:secrets.token_urlsafe(32)+str(index)
                   for index,key in enumerate(secret_keys)}
        self.environment.update(generated)
        source=self.environment.get("EPM_TEST_SOURCE_COMMIT","")
        if not re.fullmatch(r"[0-9a-f]{40}",source):
            raise ValueError("SCHEMA163_PARITY_SOURCE_COMMIT_INVALID")
        tree=self.environment.get("EPM_TEST_SOURCE_TREE","")
        if not re.fullmatch(r"[0-9a-f]{40}",tree):
            raise ValueError("SCHEMA163_PARITY_SOURCE_TREE_INVALID")
        ca=Path(self.environment.get("EPM_TEST_OIDC_CA_PATH","")).resolve()
        if not ca.is_file():
            raise ValueError("SCHEMA163_PARITY_OIDC_CA_INVALID")
        for key in ("EPM_TEST_QUALIFICATION_IMAGE","EPM_TEST_COMPOSE_DATABASE_IMAGE"):
            if not re.fullmatch(r"sha256:[0-9a-f]{64}",self.environment.get(key,"")):
                raise ValueError("SCHEMA163_PARITY_IMAGE_NOT_DIGEST_PINNED")
        self.run=run
        self.compose_command=(compose_command or
            (("docker-compose",) if shutil.which("docker-compose") else
             ("docker","compose")))
        if not re.fullmatch(r"[a-z0-9-]{3,40}",project_prefix):
            raise ValueError("SCHEMA163_PARITY_PROJECT_PREFIX_INVALID")

    def _call(self,base:list[str],*args:str,capture:bool=False)->str:
        result=self.run(base+list(args),cwd=self.root,env=self.subprocess_environment(),
            check=True,text=True,capture_output=capture)
        return result.stdout.strip() if capture else ""

    def _cleanup(self,base:list[str],project:str)->None:
        errors=[]
        for _ in range(3):
            try:
                self._call(base,"--profile","v2","--profile","workspace",
                    "--profile","schema163-public-parity","--profile","setup",
                    "down","--volumes","--remove-orphans")
            except Exception as exc:errors.append(repr(exc))
            remaining=[]
            for command in (("ps","-aq"),("network","ls","-q"),("volume","ls","-q")):
                result=self.run(["docker",*command,"--filter",
                    f"label=com.docker.compose.project={project}"],cwd=self.root,
                    env=self.subprocess_environment(),check=True,text=True,
                    capture_output=True).stdout.strip()
                if result:remaining.append((command[0],result))
            if not remaining:return
        raise RuntimeError("SCHEMA163_PARITY_CLEANUP_FAILED:"+repr(remaining)+repr(errors))

    def _verify_images(self)->None:
        qualification=self.environment["EPM_TEST_QUALIFICATION_IMAGE"]
        result=self.run(["docker","image","inspect",qualification,"--format",
            '{{.Id}} {{index .Config.Labels "org.openepm.qualification"}} '
            '{{index .Config.Labels "org.openepm.source.commit"}} '
            '{{index .Config.Labels "org.openepm.source.tree"}}'],cwd=self.root,
            env=self.subprocess_environment(),check=True,text=True,
            capture_output=True).stdout.split()
        if result != [qualification,"schema163-public-parity",
                self.environment["EPM_TEST_SOURCE_COMMIT"],
                self.environment["EPM_TEST_SOURCE_TREE"]]:
            raise ValueError("SCHEMA163_PARITY_QUALIFICATION_IMAGE_BINDING_INVALID")
        database=self.environment["EPM_TEST_COMPOSE_DATABASE_IMAGE"]
        actual=self.run(["docker","image","inspect",database,"--format","{{.Id}}"],
            cwd=self.root,env=self.subprocess_environment(),check=True,text=True,
            capture_output=True).stdout.strip()
        if actual!=database:
            raise ValueError("SCHEMA163_PARITY_DATABASE_IMAGE_BINDING_INVALID")

    def subprocess_environment(self)->dict[str,str]:
        return {**{key:os.environ[key] for key in _HOST_RUNTIME_ENV if key in os.environ},
                **self.environment}

    @contextmanager
    def lifecycle(self,mode:str):
        self._verify_images()
        suffix="fresh" if mode=="fresh-baseline-164" else "semantic"
        database=f"epm_disposable_{self.project_prefix.replace('-','_')}_{suffix}"
        project=f"{self.project_prefix}-{suffix}"
        with TemporaryDirectory(prefix="openepm-parity-compose-") as temporary:
            override=Path(temporary)/"override.json"
            override.write_text(json.dumps(render_public_parity_override(
                database,mode),sort_keys=True,separators=(",",":")))
            ports=Path(temporary)/"ports.yaml"
            ports.write_text("""services:
  db: {ports: !override [\"127.0.0.1::5432\"]}
  platform: {ports: !override [\"127.0.0.1::5193\"]}
  workspace: {ports: !override [\"127.0.0.1::5192\"]}
  router: {ports: !override [\"127.0.0.1::5194\"]}
  web: {ports: !override [\"127.0.0.1::5195\"]}
""")
            base=[*self.compose_command,"--project-directory",str(self.root),"-p",project,
                "-f",str(self.compose),"-f",str(override),"-f",str(ports)]
            try:
                self._call(base,"config","--quiet")
                self._call(base,"--profile","setup","up","-d","db")
                self._call(base,"--profile","schema163-public-parity","run","--rm",
                    "parity-initialize")
                self._call(base,"--profile","setup","run","--rm","bootstrap-roles")
                self._call(base,"--profile","setup","run","--rm","bootstrap-operator")
                try:
                    self._call(base,"--profile","v2","--profile","workspace","up","-d",
                        "--wait","platform","workspace","router","web","worker")
                except subprocess.CalledProcessError as exc:
                    logs=self._call(base,"--profile","workspace","logs","--no-color",
                        "--tail","200","workspace",capture=True)
                    raise RuntimeError("SCHEMA163_PARITY_WORKSPACE_START_FAILED\n"+logs) from exc
                ids={name:self._call(base,"ps","-q",name,capture=True)
                     for name in ("db","platform","workspace","router","worker")}
                if any(not value for value in ids.values()):
                    raise RuntimeError("SCHEMA163_PARITY_SERVICE_IDENTITY_MISSING")
                address=self._call(base,"port","db","5432",capture=True)
                host,port=address.rsplit(":",1)
                service_ports={name:int(self._call(base,"port",name,str(internal),
                    capture=True).rsplit(":",1)[1]) for name,internal in (
                    ("platform",5193),("workspace",5192),("router",5194),("web",5195))}
                yield {"mode":mode,"database":database,"project":project,
                    "adminDsn":f"host={host} port={port} user=postgres dbname={database}",
                    "serviceIdentities":ids,"servicePorts":service_ports,
                    "baseCommand":tuple(base)}
            finally:
                primary=sys.exc_info()[1]
                try:self._cleanup(base,project)
                except Exception as cleanup:
                    raise RuntimeError("SCHEMA163_PARITY_PRIMARY_AND_CLEANUP_FAILURE:"
                        +repr(primary)+":"+repr(cleanup)) from cleanup
