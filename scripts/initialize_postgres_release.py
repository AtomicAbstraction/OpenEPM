"""Initialize pristine releases from the qualified schema-163 snapshot."""
from __future__ import annotations
import argparse,hashlib,json,os
from pathlib import Path
from tempfile import TemporaryDirectory
try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()
from epm_core.postgres_admin_execution import add_budget_argument,run_admin_cli
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_fresh_baseline import ARTIFACT_FORMAT,METHOD,canonical_chain_digest,database_profile

ROOT=Path(__file__).resolve().parents[1];MIGRATIONS=ROOT/'schema'/'postgres'
ARTIFACT=Path('/qualification/artifact.json')
ARTIFACT_SHA256='fda196901bd73492357296cbb105cc9257c05bde39ac05b6549b4fe924ec10ff'
SCHEMA_FINGERPRINT='8e1e86e4ad38e9feee783e369f3fce1b361ee6d8f5c4c213b91bc7763afc1bab'
POSTGRES_PROFILE='postgres-18.1 (Debian 18.1-1.pgdg12+2)'
EXTENSION_PROFILE='[["pg_duckdb","1.1.0"],["plpgsql","1.0"]]'
SOURCE_COMMIT='d79a4914f0c48721fbf3491b705cf7f4d5ca8829'

def _sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def _entries():
 result=[]
 for version in range(1,164):
  matches=list(MIGRATIONS.glob(f'{version:04d}_*.sql'))
  if len(matches)!=1:raise ValueError('RELEASE_BASELINE_MIGRATION_SET_INVALID')
  result.append({'version':version,'sha256':_sha(matches[0])})
 return result
def _state(dsn):
 with connect_postgres(dsn,autocommit=True) as db:
  present=db.execute("SELECT 1 FROM pg_namespace WHERE nspname='epm' OR nspname LIKE 'epm\\_%' ESCAPE '\\' LIMIT 1").fetchone()
  pristine=present is None
  if pristine:
   # A newly provisioned application database inherits template1, while the
   # pinned pg_duckdb image installs pg_duckdb only in its default postgres
   # database.  Establish the exact bundled extension profile before binding
   # the qualified fresh baseline.  Existing databases remain migration-only:
   # this initializer must not change their extension inventory implicitly.
   db.execute('CREATE EXTENSION IF NOT EXISTS pg_duckdb')
  return pristine,database_profile(db)
def _manifest(root,profile):
 root.mkdir(mode=0o700,parents=True,exist_ok=True)
 if not root.is_dir():raise ValueError('RELEASE_BASELINE_TEMPORARY_PATH_INVALID')
 if profile!=(POSTGRES_PROFILE,EXTENSION_PROFILE):raise ValueError('RELEASE_BASELINE_DATABASE_PROFILE_MISMATCH')
 if not ARTIFACT.is_file() or _sha(ARTIFACT)!=ARTIFACT_SHA256:raise ValueError('RELEASE_BASELINE_ARTIFACT_MISMATCH')
 artifact=root/'artifact.json';artifact.write_bytes(ARTIFACT.read_bytes());canonical=_entries()
 manifest={'baselineId':'schema163-qualified-release-2026-10-29','targetVersion':163,
  'artifact':artifact.name,'artifactSha256':ARTIFACT_SHA256,'artifactFormat':ARTIFACT_FORMAT,
  'canonicalMigrations':canonical,'canonicalChainDigest':canonical_chain_digest(canonical),
  'equivalenceEvidence':'equivalence.json','equivalenceEvidenceSha256':'0'*64,
  'schemaFingerprint':SCHEMA_FINGERPRINT,'method':METHOD,
  'reviewerIdentity':'openepm-qualified-schema163-activation-v1','sourceCommit':SOURCE_COMMIT,
  'buildId':'schema163-qualified-artifact-fda196901bd7','postgresProfile':profile[0],
  'extensionProfile':profile[1]}
 keys=('baselineId','canonicalChainDigest','schemaFingerprint','reviewerIdentity','sourceCommit','buildId','postgresProfile','extensionProfile','artifactSha256','artifactFormat')
 evidence={'evidenceVersion':1,'binding':{key:manifest[key] for key in keys},
  'baselineSchemaFingerprint':SCHEMA_FINGERPRINT,'upgradedSchemaFingerprint':SCHEMA_FINGERPRINT}
 ep=root/'equivalence.json';ep.write_text(json.dumps(evidence,separators=(',',':')),encoding='utf-8')
 manifest['equivalenceEvidenceSha256']=_sha(ep);mp=root/'manifest.json'
 mp.write_text(json.dumps(manifest,separators=(',',':')),encoding='utf-8');return mp
def main():
 parser=argparse.ArgumentParser(description=__doc__);add_budget_argument(parser)
 parser.add_argument('--dsn',default=os.environ.get('EPM_POSTGRES_ADMIN_DSN'));args=parser.parse_args()
 if not args.dsn:parser.error('Set EPM_POSTGRES_ADMIN_DSN or pass --dsn')
 pristine,profile=_state(args.dsn)
 with TemporaryDirectory(prefix='openepm-release-baseline-') as temporary:
  manifest=_manifest(Path(temporary),profile) if pristine else None
  results=run_admin_cli(parser,'migrate',{'dsn':args.dsn,'directory':str(MIGRATIONS),
   'freshBaselineManifest':None if manifest is None else str(manifest)},args.timeout_seconds)
 for result in results:print(result)
if __name__=='__main__':main()
