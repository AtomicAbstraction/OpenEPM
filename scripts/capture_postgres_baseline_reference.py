"""Read-only capture of a candidate schema-163 reference; never creates a baseline."""
from __future__ import annotations
import argparse,hashlib,json,os,re
from pathlib import Path
try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()
from epm_core.postgres_connection import connect_postgres
from epm_core.postgres_fresh_baseline import (canonical_chain_digest,database_profile,
 schema_fingerprint,schema_fingerprint_objects)

ROOT=Path(__file__).resolve().parents[1]

def capture(dsn:str,directory:Path=ROOT/'schema/postgres')->dict:
 files=sorted(directory.glob('*.sql'));canonical=[]
 for path in files:
  version=int(path.name[:4])
  if version<=163:canonical.append({'version':version,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
 if [x['version'] for x in canonical]!=list(range(1,164)):
  raise ValueError('REFERENCE_CANONICAL_CHAIN_INCOMPLETE')
 source_commit=os.environ.get('EPM_SOURCE_COMMIT','')
 if not re.fullmatch(r'[0-9a-f]{40,64}',source_commit):
  raise ValueError('REFERENCE_SOURCE_COMMIT_REQUIRED')
 with connect_postgres(dsn,autocommit=False) as db:
  # One database-enforced snapshot prevents a concurrent migration from mixing
  # chain rows from one instant with catalog objects from another. READ ONLY is
  # the safety boundary; the absence of write statements in this script is not.
  with db.transaction():
   db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
   if db.execute("SELECT to_regclass('epm.schema_migration')").fetchone()[0] is None:
    raise ValueError('REFERENCE_MIGRATION_TABLE_MISSING')
   rows=[{'version':v,'sha256':c} for v,c in db.execute(
    'SELECT version,checksum FROM epm.schema_migration WHERE version<=163 ORDER BY version')]
   extra=db.execute('SELECT version FROM epm.schema_migration WHERE version>163 ORDER BY version').fetchall()
   if rows!=canonical or extra:raise ValueError('REFERENCE_MIGRATION_CHAIN_MISMATCH')
   pg,extensions=database_profile(db);objects=schema_fingerprint_objects(db)
   encoded=json.dumps(objects,separators=(',',':')).encode()
   return {'status':'candidate-reference-captured','activationAuthorized':False,
    'targetVersion':163,'canonicalMigrations':canonical,
    'canonicalChainDigest':canonical_chain_digest(canonical),
    'schemaFingerprint':schema_fingerprint(db),'schemaObjects':objects,
    'objectCount':len(objects),'objectListDigest':hashlib.sha256(encoded).hexdigest(),
    'postgresProfile':pg,'extensionProfile':extensions,'sourceCommit':source_commit,
    'limitations':['read-only reference evidence only','no artifact emitted',
     'independent parity review and artifact construction remain required']}

def main()->None:
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--dsn',required=True)
 p.add_argument('--migrations-dir',type=Path,default=ROOT/'schema/postgres');a=p.parse_args()
 print(json.dumps(capture(a.dsn,a.migrations_dir),indent=2,sort_keys=True))
if __name__=='__main__':main()
