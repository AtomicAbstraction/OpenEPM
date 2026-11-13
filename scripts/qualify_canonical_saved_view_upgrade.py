#!/usr/bin/env python3
"""Qualify migration 0374 on an owned clone of the populated laptop database."""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
import uuid

ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,""):
    sys.path.insert(0,str(ROOT))

from scripts.audit_disposable_docker_cleanup_candidates import OwnedDockerRun
from scripts.qualify_active_laptop_populated_upgrade import (
    QualificationError, create_roles, docker, psql, selected_docker_context,
    wait_ready,
)


MIGRATION=ROOT/"schema/postgres/0374_canonical_saved_cube_views.sql"
MIGRATION_NAME=re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")


def _file_digest(path: Path) -> str:
    digest=sha256()
    with path.open("rb") as stream:
        while block:=stream.read(1024*1024):digest.update(block)
    return digest.hexdigest()


def _wait_stably_ready(container: str) -> None:
    """Ignore the image entrypoint's temporary bootstrap server."""
    wait_ready(container)
    consecutive=0
    for _ in range(150):
        try:
            if psql(container,"postgres","SELECT 1")=="1":consecutive+=1
            else:consecutive=0
        except QualificationError:
            consecutive=0
        if consecutive>=5:return
        time.sleep(.2)
    raise QualificationError("disposable database did not become stably ready")


def qualify(*,source: str,database_image: str,output: Path) -> dict:
    if output.exists() or not output.is_absolute():
        raise QualificationError("output must be a new absolute path")
    token=uuid.uuid4().hex[:12]
    clone="openepm_saved_view_upgrade_"+token
    volume=clone+"_data"
    password=secrets.token_urlsafe(32)
    result=None
    manifest=output.with_suffix(output.suffix+".run.json")
    with OwnedDockerRun(manifest,purpose="canonical-saved-view-upgrade",
                        command=docker) as owned, \
            selected_docker_context(owned.manifest["context"]):
        owned.protect_container(source)
        with tempfile.TemporaryDirectory(prefix="openepm-saved-view-upgrade-") as temp:
            archive=Path(temp)/"source.dump"
            with archive.open("wb") as stream:
                docker("exec",source,"pg_dump","-U","postgres","-d","postgres",
                       "--format=custom","--no-owner","--no-comments",stdout=stream)
            if archive.stat().st_size<=0:raise QualificationError("source archive is empty")
            archive_digest=_file_digest(archive)
            owned.volume(volume)
            clone=owned.container(clone,"-v",volume+":/var/lib/postgresql",
                "-p","127.0.0.1::5432",
                "-e","POSTGRES_PASSWORD="+password,database_image)
            _wait_stably_ready(clone);create_roles(clone)
            inspected=json.loads(docker("container","inspect",clone))[0]
            ports=inspected["NetworkSettings"]["Ports"]["5432/tcp"]
            if len(ports)!=1 or ports[0]["HostIp"]!="127.0.0.1":
                raise QualificationError("disposable loopback binding is invalid")
            port=ports[0]["HostPort"]
            docker("cp",str(archive),clone+":/tmp/source.dump")
            docker("exec",clone,"pg_restore","-U","postgres","-d","postgres",
                   "--exit-on-error","--no-owner","/tmp/source.dump")
            before_version=psql(clone,"postgres",
                "SELECT max(version) FROM epm.schema_migration")
            before_count=psql(clone,"postgres",
                "SELECT count(*) FROM epm.saved_grid_definition")
            if (not before_version.isdecimal() or int(before_version)>=374
                    or not before_count.isdecimal()):
                raise QualificationError("source schema or saved-view count is invalid")
            psql(clone,"postgres","""CREATE TABLE public.saved_grid_0374_before AS
                SELECT workspace_id,application_id,grid_id,name,definition,
                  metadata_revision FROM epm.saved_grid_definition""")
            applied=[]
            for migration in sorted((ROOT/"schema/postgres").glob("*.sql")):
                match=MIGRATION_NAME.fullmatch(migration.name)
                if match is None:raise QualificationError("migration filename invalid")
                version=int(match.group(1))
                if not int(before_version)<version<=374:continue
                target=f"/tmp/{migration.name}"
                docker("cp",str(migration),clone+":"+target)
                docker("exec",clone,"psql","-U","postgres","-d","postgres",
                       "-v","ON_ERROR_STOP=1","-f",target)
                checksum=_file_digest(migration)
                description=match.group(2).replace("_"," ").replace("'","''")
                psql(clone,"postgres",f"""INSERT INTO epm.schema_migration
                  (version,description,checksum) VALUES
                  ({version},'{description}','{checksum}')""")
                applied.append(version)
            if applied!=list(range(int(before_version)+1,375)):
                raise QualificationError("candidate migration chain is incomplete")
            after_count=psql(clone,"postgres",
                "SELECT count(*) FROM epm.saved_grid_definition")
            mismatch=psql(clone,"postgres","""
              SELECT count(*) FROM public.saved_grid_0374_before b
              FULL JOIN epm.saved_grid_definition g
                USING(workspace_id,application_id,grid_id)
              WHERE b.grid_id IS NULL OR g.grid_id IS NULL OR g.name<>b.name
                OR g.metadata_revision<>b.metadata_revision
                OR g.definition->>'format'<>'openepm-cube-view-v1'
                OR g.definition->>'viewId'<>b.grid_id
                OR g.definition->>'name'<>b.name
                OR g.definition->'layout'->'rows'<>b.definition->'rowDimensions'
                OR g.definition->'layout'->'columns'<>b.definition->'columnDimensions'
                OR g.definition->'layout'->'pages'<>'[]'::jsonb
                OR g.definition->'layout'->'filters'<>(SELECT coalesce(
                  jsonb_agg(key ORDER BY key),'[]'::jsonb)
                  FROM jsonb_object_keys(b.definition->'pov') AS p(key))
                OR g.definition->'dataSource'->>'kind'<>b.definition->>'dataLayer'
                OR g.definition->'pageSize'<>b.definition->'pageSize'
                OR g.definition->'suppression'<>
                  '{"missing":false,"zero":false}'::jsonb
                OR EXISTS(SELECT 1 FROM jsonb_each_text(b.definition->'pov') p
                  WHERE NOT EXISTS(SELECT 1
                    FROM jsonb_array_elements(
                      g.definition->'selection'->'dimensions') selected
                    WHERE selected->>'dimensionId'=p.key
                      AND selected->'include'=jsonb_build_object(
                        'kind','member','memberId',p.value)))
                OR EXISTS(SELECT 1 FROM epm.dimension d
                  WHERE d.workspace_id=g.workspace_id
                    AND d.application_id=g.application_id AND d.status='Active'
                    AND NOT b.definition->'pov' ? d.dimension_id
                    AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(
                      g.definition->'selection'->'dimensions') selected
                      WHERE selected->>'dimensionId'=d.dimension_id
                        AND selected->'include'=jsonb_build_object(
                          'kind','members','memberIds',(SELECT jsonb_agg(
                            m.member_id ORDER BY m.member_id) FROM epm.member m
                            WHERE m.workspace_id=d.workspace_id
                              AND m.application_id=d.application_id
                              AND m.dimension_id=d.dimension_id
                              AND m.status='Active'))))""")
            if after_count!=before_count or mismatch!="0":
                raise QualificationError("saved-view semantic reconciliation failed")
            runtime_password=secrets.token_urlsafe(32)
            psql(clone,"postgres",f"ALTER ROLE epm_runtime LOGIN PASSWORD '{runtime_password}'")
            owner_dsn=(f"host=127.0.0.1 port={port} user=postgres "
                       f"password={password} dbname=postgres")
            runtime_dsn=(f"host=127.0.0.1 port={port} user=epm_runtime "
                         f"password={runtime_password} dbname=postgres")
            environment={**dict(os.environ),
                "PYTHONDONTWRITEBYTECODE":"1",
                "EPM_TEST_POSTGRES_DISPOSABLE":"1",
                "EPM_TEST_POSTGRES_DSN":owner_dsn,
                "EPM_TEST_POSTGRES_RUNTIME_DSN":runtime_dsn}
            lifecycle=subprocess.run([sys.executable,
                "tests/qualify_current_decision_grid_lifecycle.py"],cwd=ROOT,
                env=environment,text=True,capture_output=True,check=False)
            if lifecycle.returncode!=0:
                raise QualificationError("canonical saved-view runtime lifecycle failed: "+
                    lifecycle.stderr.strip()[-1000:])
            result={"format":"openepm-canonical-saved-view-upgrade-v1",
                "status":"passed","sharedDatabaseMutation":False,
                "sourceSchema":int(before_version),"targetMigration":374,
                "appliedMigrations":applied,
                "savedViews":int(after_count),"semanticMismatches":0,
                "canonicalRuntimeLifecycle":True,
                "migrationSha256":_file_digest(MIGRATION),
                "sourceSha256":{str(path.relative_to(ROOT)):_file_digest(path)
                    for path in (ROOT/"epm_core/postgres_saved_grids.py",
                        ROOT/"epm_core/cube_view_contract.py",
                        ROOT/"tests/qualify_current_decision_grid_lifecycle.py")},
                "archive":{"bytes":archive.stat().st_size,
                           "sha256":archive_digest,"retained":False}}
    if result is None:raise QualificationError("qualification produced no result")
    result["cleanup"]={**owned.report,"archiveRemoved":not archive.exists()}
    output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    return result


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-container",required=True)
    parser.add_argument("--database-image",required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    try:result=qualify(source=args.source_container,
        database_image=args.database_image,output=args.output)
    except QualificationError as error:parser.error(str(error))
    print(json.dumps({"status":result["status"],"output":str(args.output)},
                     sort_keys=True))
    return 0


if __name__=="__main__":raise SystemExit(main())
