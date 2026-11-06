"""Initialize one owned database for schema-163 public parity qualification.

Qualification-only: requires an explicit opt-in and an epm_disposable_* target.
Fresh manifests and equivalence bindings exist only in a temporary directory.
"""
from __future__ import annotations
import argparse,hashlib,json,os,re
from pathlib import Path
from tempfile import TemporaryDirectory

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_fresh_baseline import (
 ARTIFACT_FORMAT,METHOD,canonical_chain_digest,database_profile)
from scripts.apply_postgres_migrations import apply_migrations

FINGERPRINT="8e1e86e4ad38e9feee783e369f3fce1b361ee6d8f5c4c213b91bc7763afc1bab"
ARTIFACT_SHA="fda196901bd73492357296cbb105cc9257c05bde39ac05b6549b4fe924ec10ff"
POSTGRES_PROFILE="postgres-18.1 (Debian 18.1-1.pgdg12+2)"
EXTENSION_PROFILE='[["pg_duckdb","1.1.0"],["plpgsql","1.0"]]'

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def entries(directory):
 result=[]
 for version in range(1,164):
  matches=list(directory.glob(f'{version:04d}_*.sql'))
  if len(matches)!=1:raise ValueError('SCHEMA163_PARITY_MIGRATION_SET_INVALID')
  result.append({'version':version,'sha256':sha(matches[0])})
 return result
def assert_target(dsn,expected_database,allow_signed_recovery_postgres=False):
 with connect_postgres(dsn,autocommit=True) as db:
  name=db.execute('SELECT current_database()').fetchone()[0]
  ordinary_disposable=(re.fullmatch(r'epm_disposable_[a-z0-9_]{1,48}',name)
                        and name==expected_database)
  signed_recovery_disposable=(allow_signed_recovery_postgres
    and os.environ.get('EPM_SCHEMA163_SIGNED_RECOVERY_DISPOSABLE')=='1'
    and name==expected_database=='postgres')
  if not (ordinary_disposable or signed_recovery_disposable):
   raise ValueError('SCHEMA163_PARITY_DATABASE_NOT_DISPOSABLE')
  db.execute('CREATE EXTENSION IF NOT EXISTS pg_duckdb')
  profile=database_profile(db)
  if profile!=(POSTGRES_PROFILE,EXTENSION_PROFILE):
   raise ValueError('SCHEMA163_PARITY_DATABASE_PROFILE_MISMATCH')
  return name,profile
def initialize(dsn,mode,artifact,migrations,source_commit,expected_database,
               allow_signed_recovery_postgres=False):
 if os.environ.get('EPM_SCHEMA163_PUBLIC_PARITY_DISPOSABLE')!='1':
  raise ValueError('SCHEMA163_PARITY_OPT_IN_REQUIRED')
 if not re.fullmatch(r'[0-9a-f]{40}',source_commit):
  raise ValueError('SCHEMA163_PARITY_SOURCE_COMMIT_INVALID')
 if allow_signed_recovery_postgres and mode!='fresh-baseline-164':
  raise ValueError('SCHEMA163_SIGNED_RECOVERY_MODE_INVALID')
 name,profile=assert_target(dsn,expected_database,allow_signed_recovery_postgres)
 if sha(artifact)!=ARTIFACT_SHA:raise ValueError('SCHEMA163_PARITY_ARTIFACT_MISMATCH')
 canonical=entries(migrations)
 release_files=list(migrations.glob('[0-9][0-9][0-9][0-9]_*.sql'))
 release_count=len(release_files)
 if release_count < 164:
  raise ValueError('SCHEMA163_PARITY_RELEASE_MIGRATIONS_INCOMPLETE')
 if mode=='semantic-reference-164':
  payload=json.loads(artifact.read_bytes())
  with connect_postgres(dsn,autocommit=True) as db:
   with db.transaction():
    for statement in payload['statements']:db.execute(statement,prepare=True)
  apply_migrations(dsn,migrations)
 elif mode=='fresh-baseline-164':
  with TemporaryDirectory(prefix='openepm-parity-manifest-') as temporary:
   root=Path(temporary);copy=root/'artifact.json';copy.write_bytes(artifact.read_bytes())
   manifest={'baselineId':'schema163-public-parity-test-only','targetVersion':163,
    'artifact':copy.name,'artifactSha256':ARTIFACT_SHA,'artifactFormat':ARTIFACT_FORMAT,
    'canonicalMigrations':canonical,'canonicalChainDigest':canonical_chain_digest(canonical),
    'equivalenceEvidence':'evidence.json','equivalenceEvidenceSha256':'0'*64,
    'schemaFingerprint':FINGERPRINT,'method':METHOD,
    'reviewerIdentity':'disposable-public-parity-test-only','sourceCommit':source_commit,
    'buildId':'public-parity-'+source_commit[:12],
    'postgresProfile':profile[0],'extensionProfile':profile[1]}
   keys=('baselineId','canonicalChainDigest','schemaFingerprint','reviewerIdentity',
    'sourceCommit','buildId','postgresProfile','extensionProfile','artifactSha256','artifactFormat')
   evidence={'evidenceVersion':1,'binding':{key:manifest[key] for key in keys},
    'baselineSchemaFingerprint':FINGERPRINT,'upgradedSchemaFingerprint':FINGERPRINT}
   ep=root/'evidence.json';ep.write_text(json.dumps(evidence,separators=(',',':')))
   manifest['equivalenceEvidenceSha256']=sha(ep)
   mp=root/'manifest.json';mp.write_text(json.dumps(manifest,separators=(',',':')))
   apply_migrations(dsn,migrations,fresh_baseline_manifest=mp)
 else:raise ValueError('SCHEMA163_PARITY_MODE_INVALID')
 return {'databaseName':name,'mode':mode,'activationAuthorized':False,
  'activationManifestRetained':False,'migrationCount':release_count}
def main():
 p=argparse.ArgumentParser();p.add_argument('--dsn',default=os.environ.get('EPM_POSTGRES_ADMIN_DSN'));p.add_argument('--mode',required=True)
 p.add_argument('--artifact',type=Path,required=True);p.add_argument('--migrations',type=Path,required=True)
 p.add_argument('--source-commit',required=True);p.add_argument('--expected-database',required=True)
 p.add_argument('--allow-signed-recovery-postgres',action='store_true');a=p.parse_args()
 if not a.dsn:p.error('Set EPM_POSTGRES_ADMIN_DSN or pass --dsn')
 print(json.dumps(initialize(a.dsn,a.mode,a.artifact,a.migrations,a.source_commit,
  a.expected_database,a.allow_signed_recovery_postgres),sort_keys=True))
if __name__=='__main__':main()
