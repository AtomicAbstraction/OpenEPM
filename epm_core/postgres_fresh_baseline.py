"""Fail-closed materialization of a reviewed fresh-install snapshot."""
from __future__ import annotations
import hashlib,json,re
from pathlib import Path
from typing import Any

METHOD="qualified-fresh-snapshot";ARTIFACT_FORMAT="openepm-sql-statements-v1"
def _digest(data:bytes)->str:return hashlib.sha256(data).hexdigest()
def _unquoted_sql(value:str)->str:
 out=[];i=0;single=double=False;dollar=None
 while i<len(value):
  if dollar:
   if value.startswith(dollar,i):out.extend(' '*len(dollar));i+=len(dollar);dollar=None
   else:out.append(' ');i+=1
   continue
  ch=value[i]
  if single:
   out.append(' ');i+=1
   if ch=="'":
    if i<len(value) and value[i]=="'":out.append(' ');i+=1
    else:single=False
   continue
  if double:
   out.append(' ');i+=1
   if ch=='"':
    if i<len(value) and value[i]=='"':out.append(' ');i+=1
    else:double=False
   continue
  match=re.match(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$",value[i:])
  if match:dollar=match.group();out.extend(' '*len(dollar));i+=len(dollar);continue
  out.append(ch);i+=1
  if ch=="'":single=True
  elif ch=='"':double=True
 if single or double or dollar:raise ValueError("FRESH_BASELINE_ARTIFACT_STATEMENT_FORBIDDEN")
 return ''.join(out)
def canonical_chain_digest(entries:list[dict[str,Any]])->str:
 return _digest(json.dumps(entries,separators=(",",":"),sort_keys=True).encode())

def load_artifact(path:Path)->list[str]:
 try:a=json.loads(path.read_text(encoding="utf-8"))
 except (UnicodeDecodeError,json.JSONDecodeError) as e:raise ValueError("FRESH_BASELINE_ARTIFACT_INVALID") from e
 if set(a)!={"format","statements"} or a["format"]!=ARTIFACT_FORMAT or not isinstance(a["statements"],list) or not a["statements"]:raise ValueError("FRESH_BASELINE_ARTIFACT_INVALID")
 tx=re.compile(r"(^|\s)(BEGIN|START\s+TRANSACTION|COMMIT|ROLLBACK|SAVEPOINT|RELEASE\s+SAVEPOINT|PREPARE\s+TRANSACTION)(\s|;|$)",re.I)
 for s in a["statements"]:
  unquoted=_unquoted_sql(s) if isinstance(s,str) else ''
  if not isinstance(s,str) or not s.strip() or "\x00" in s or re.search(r"(^|\n)\s*\\",unquoted) or "--" in s or "/*" in s or "*/" in s or tx.search(unquoted):raise ValueError("FRESH_BASELINE_ARTIFACT_STATEMENT_FORBIDDEN")
 return a["statements"]

def load_baseline_manifest(path:Path,migrations:list[tuple[int,str,Path]])->dict[str,Any]:
 m=json.loads(path.read_bytes());allowed={"baselineId","targetVersion","artifact","artifactSha256","artifactFormat","canonicalMigrations","canonicalChainDigest","equivalenceEvidence","equivalenceEvidenceSha256","schemaFingerprint","method","reviewerIdentity","sourceCommit","buildId","postgresProfile","extensionProfile"}
 if set(m)!=allowed or m.get("method")!=METHOD or m.get("artifactFormat")!=ARTIFACT_FORMAT:raise ValueError("FRESH_BASELINE_MANIFEST_SHAPE_INVALID")
 if m.get("targetVersion")!=163 or len(migrations)<164 or migrations[163][0:2]!=(164,"fresh_install_baseline_audit"):raise ValueError("FRESH_BASELINE_TARGET_INVALID")
 expected=[{"version":v,"sha256":_digest(f.read_bytes())} for v,_,f in migrations if v<=163];chain=canonical_chain_digest(expected)
 if m.get("canonicalMigrations")!=expected:raise ValueError("FRESH_BASELINE_CANONICAL_CHAIN_MISMATCH")
 if m.get("canonicalChainDigest")!=chain:raise ValueError("FRESH_BASELINE_CANONICAL_DIGEST_MISMATCH")
 for f in ("artifactSha256","equivalenceEvidenceSha256","schemaFingerprint"):
  if not re.fullmatch(r"[0-9a-f]{64}",str(m.get(f,""))):raise ValueError("FRESH_BASELINE_MANIFEST_DIGEST_INVALID")
 for f in ("baselineId","reviewerIdentity","sourceCommit","buildId","postgresProfile","extensionProfile"):
  if not isinstance(m.get(f),str) or not m[f].strip():raise ValueError("FRESH_BASELINE_MANIFEST_IDENTITY_INVALID")
 for name,dfield in (("artifact","artifactSha256"),("equivalenceEvidence","equivalenceEvidenceSha256")):
  p=(path.parent/m[name]).resolve()
  if path.parent.resolve() not in p.parents:raise ValueError("FRESH_BASELINE_PATH_ESCAPE")
  if not p.is_file() or _digest(p.read_bytes())!=m[dfield]:raise ValueError(f"FRESH_BASELINE_{name.upper()}_DIGEST_MISMATCH")
  m[name]=p
 m["statements"]=load_artifact(m["artifact"])
 try:e=json.loads(m["equivalenceEvidence"].read_text())
 except (UnicodeDecodeError,json.JSONDecodeError) as x:raise ValueError("FRESH_BASELINE_EQUIVALENCE_EVIDENCE_INVALID") from x
 binding={k:m[k] for k in ("baselineId","canonicalChainDigest","schemaFingerprint","reviewerIdentity","sourceCommit","buildId","postgresProfile","extensionProfile","artifactSha256","artifactFormat")}
 if e.get("evidenceVersion")!=1 or e.get("binding")!=binding or e.get("baselineSchemaFingerprint")!=m["schemaFingerprint"] or e.get("upgradedSchemaFingerprint")!=m["schemaFingerprint"]:raise ValueError("FRESH_BASELINE_EQUIVALENCE_EVIDENCE_INVALID")
 return m

def assert_pristine_database(db:Any)->None:
 if db.execute("SELECT 1 FROM pg_namespace WHERE nspname='epm' OR nspname LIKE 'epm\\_%' ESCAPE '\\' LIMIT 1").fetchone():raise ValueError("FRESH_BASELINE_REQUIRES_PRISTINE_DATABASE")

def database_profile(db:Any)->tuple[str,str]:
 pg=db.execute("SHOW server_version").fetchone()[0]
 extensions=db.execute("SELECT extname,extversion FROM pg_extension ORDER BY extname").fetchall()
 return f"postgres-{pg}",json.dumps(extensions,separators=(",",":"))

def schema_fingerprint(db:Any)->str:
 q=r'''WITH o(k,v) AS (
SELECT 'schema',jsonb_build_object('name',nspname,'owner',pg_get_userbyid(nspowner),'acl',nspacl)::text FROM pg_namespace WHERE nspname='epm'
UNION ALL SELECT 'class',jsonb_build_object('name',n.nspname||'.'||c.relname,'kind',c.relkind,'owner',pg_get_userbyid(c.relowner),'rls',c.relrowsecurity,'forceRls',c.relforcerowsecurity,'persistence',c.relpersistence,'replicaIdentity',c.relreplident,'accessMethod',coalesce(am.amname,''),'tablespace',coalesce(ts.spcname,''),'partitionBound',pg_get_expr(c.relpartbound,c.oid),'options',c.reloptions)::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_am am ON am.oid=c.relam LEFT JOIN pg_tablespace ts ON ts.oid=c.reltablespace WHERE n.nspname='epm'
UNION ALL SELECT 'inheritance',jsonb_build_object('child',cn.nspname||'.'||cc.relname,'parent',pn.nspname||'.'||pc.relname,'ordinal',i.inhseqno,'detachPending',i.inhdetachpending)::text FROM pg_inherits i JOIN pg_class cc ON cc.oid=i.inhrelid JOIN pg_namespace cn ON cn.oid=cc.relnamespace JOIN pg_class pc ON pc.oid=i.inhparent JOIN pg_namespace pn ON pn.oid=pc.relnamespace WHERE cn.nspname='epm' OR pn.nspname='epm'
UNION ALL SELECT 'view-definition',jsonb_build_object('name',n.nspname||'.'||c.relname,'definition',pg_get_viewdef(c.oid,true))::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='epm' AND c.relkind IN ('v','m')
UNION ALL SELECT 'rewrite-rule',jsonb_build_object('relation',n.nspname||'.'||c.relname,'name',r.rulename,'event',r.ev_type,'instead',r.is_instead,'definition',pg_get_ruledef(r.oid,true))::text FROM pg_rewrite r JOIN pg_class c ON c.oid=r.ev_class JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='epm'
UNION ALL SELECT 'column',jsonb_build_object('relation',n.nspname||'.'||c.relname,'name',a.attname,'type',format_type(a.atttypid,a.atttypmod),'notNull',a.attnotnull,'identity',a.attidentity,'generated',a.attgenerated,'collation',coalesce(z.collname,''),'default',pg_get_expr(d.adbin,d.adrelid))::text FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum LEFT JOIN pg_collation z ON z.oid=a.attcollation WHERE n.nspname='epm' AND a.attnum>0 AND NOT a.attisdropped
UNION ALL SELECT 'constraint',jsonb_build_object('name',x.conname,'relation',coalesce(n.nspname||'.'||c.relname,''),'type',x.contype,'deferrable',x.condeferrable,'deferred',x.condeferred,'validated',x.convalidated,'definition',pg_get_constraintdef(x.oid,true))::text FROM pg_constraint x LEFT JOIN pg_class c ON c.oid=x.conrelid LEFT JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='epm' OR x.connamespace='epm'::regnamespace
UNION ALL SELECT 'index',jsonb_build_object('name',schemaname||'.'||indexname,'definition',indexdef)::text FROM pg_indexes WHERE schemaname='epm'
UNION ALL SELECT 'trigger',jsonb_build_object('relation',n.nspname||'.'||c.relname,'name',CASE WHEN t.tgisinternal THEN '' ELSE t.tgname END,'enabled',t.tgenabled,'internal',t.tgisinternal,'constraint',coalesce(x.conname,''),'function',t.tgfoid::regprocedure::text,'type',t.tgtype,'deferrable',t.tgdeferrable,'initiallyDeferred',t.tginitdeferred,'definition',CASE WHEN t.tgisinternal THEN '' ELSE pg_get_triggerdef(t.oid,true) END)::text FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_constraint x ON x.oid=t.tgconstraint WHERE n.nspname='epm'
UNION ALL SELECT 'routine',jsonb_build_object('identity',p.oid::regprocedure::text,'owner',pg_get_userbyid(p.proowner),'acl',p.proacl,'definition',pg_get_functiondef(p.oid))::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='epm'
UNION ALL SELECT 'policy',jsonb_build_object('relation',schemaname||'.'||tablename,'name',policyname,'command',cmd,'permissive',permissive,'roles',roles,'using',qual,'check',with_check)::text FROM pg_policies WHERE schemaname='epm'
UNION ALL SELECT 'type',jsonb_build_object('name',n.nspname||'.'||t.typname,'kind',t.typtype,'category',t.typcategory,'base',format_type(t.typbasetype,t.typtypmod),'notNull',t.typnotnull,'default',t.typdefault,'enum',(SELECT jsonb_agg(e.enumlabel ORDER BY e.enumsortorder) FROM pg_enum e WHERE e.enumtypid=t.oid))::text FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace WHERE n.nspname='epm'
UNION ALL SELECT 'sequence',row_to_json(s)::text FROM pg_sequences s WHERE schemaname='epm'
UNION ALL SELECT 'class-acl',jsonb_build_object('object',n.nspname||'.'||c.relname,'grantor',pg_get_userbyid(a.grantor),'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,'privilege',a.privilege_type,'grantable',a.is_grantable)::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault(CASE WHEN c.relkind='S' THEN 'S'::"char" ELSE 'r'::"char" END,c.relowner))) a WHERE n.nspname='epm'
UNION ALL SELECT 'column-acl',jsonb_build_object('relation',n.nspname||'.'||c.relname,'column',x.attname,'grantor',pg_get_userbyid(a.grantor),'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,'privilege',a.privilege_type,'grantable',a.is_grantable)::text FROM pg_attribute x JOIN pg_class c ON c.oid=x.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN LATERAL aclexplode(x.attacl) a WHERE n.nspname='epm' AND x.attnum>0 AND NOT x.attisdropped AND x.attacl IS NOT NULL
UNION ALL SELECT 'schema-acl',jsonb_build_object('schema',n.nspname,'grantor',pg_get_userbyid(a.grantor),'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,'privilege',a.privilege_type,'grantable',a.is_grantable)::text FROM pg_namespace n CROSS JOIN LATERAL aclexplode(coalesce(n.nspacl,acldefault('n',n.nspowner))) a WHERE n.nspname='epm'
UNION ALL SELECT 'routine-acl',jsonb_build_object('routine',p.oid::regprocedure::text,'grantor',pg_get_userbyid(a.grantor),'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,'privilege',a.privilege_type,'grantable',a.is_grantable)::text FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE n.nspname='epm'
UNION ALL SELECT 'type-acl',jsonb_build_object('type',n.nspname||'.'||t.typname,'grantor',pg_get_userbyid(a.grantor),'grantee',CASE WHEN a.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END,'privilege',a.privilege_type,'grantable',a.is_grantable)::text FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace CROSS JOIN LATERAL aclexplode(coalesce(t.typacl,acldefault('T',t.typowner))) a WHERE n.nspname='epm'
UNION ALL SELECT 'default-acl',jsonb_build_object('owner',r.rolname,'schema',coalesce(n.nspname,''),'type',d.defaclobjtype,'acl',d.defaclacl)::text FROM pg_default_acl d JOIN pg_roles r ON r.oid=d.defaclrole LEFT JOIN pg_namespace n ON n.oid=d.defaclnamespace WHERE n.nspname='epm'
UNION ALL SELECT 'role',jsonb_build_object('name',rolname,'super',rolsuper,'inherit',rolinherit,'createRole',rolcreaterole,'createDb',rolcreatedb,'login',rolcanlogin,'replication',rolreplication,'bypassRls',rolbypassrls,'connLimit',rolconnlimit)::text FROM pg_roles WHERE rolname LIKE 'epm\_%' ESCAPE '\'
UNION ALL SELECT 'membership',jsonb_build_object('member',m.rolname,'role',r.rolname,'grantor',g.rolname,'admin',x.admin_option,'inherit',x.inherit_option,'set',x.set_option)::text FROM pg_auth_members x JOIN pg_roles m ON m.oid=x.member JOIN pg_roles r ON r.oid=x.roleid JOIN pg_roles g ON g.oid=x.grantor WHERE m.rolname LIKE 'epm\_%' ESCAPE '\' OR r.rolname LIKE 'epm\_%' ESCAPE '\'
UNION ALL SELECT 'role-setting',jsonb_build_object('role',r.rolname,'database',coalesce(d.datname,''),'setting',s.setting)::text FROM pg_db_role_setting x JOIN pg_roles r ON r.oid=x.setrole LEFT JOIN pg_database d ON d.oid=x.setdatabase CROSS JOIN LATERAL unnest(x.setconfig) s(setting) WHERE r.rolname LIKE 'epm\_%' ESCAPE '\'
UNION ALL SELECT 'extension',jsonb_build_object('name',e.extname,'version',e.extversion,'schema',n.nspname)::text FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace
) SELECT encode(digest(string_agg(k||':'||v,E'\n' ORDER BY k,v),'sha256'),'hex') FROM o'''
 # Hash the canonical catalog rows in trusted Python rather than relying on
 # pgcrypto.digest().  pgcrypto is intentionally absent from the qualified
 # database extension profile; requiring it here made baseline verification
 # impossible on the exact declared runtime.
 rows=db.execute(q.rsplit('SELECT encode',1)[0]+
     'SELECT k,v FROM o ORDER BY k,v').fetchall()
 if not rows:raise ValueError("FRESH_BASELINE_SCHEMA_FINGERPRINT_EMPTY")
 return hashlib.sha256('\n'.join(f'{kind}:{value}' for kind,value in rows).encode()).hexdigest()

def schema_fingerprint_objects(db:Any)->list[tuple[str,str]]:
 """Canonical ordered inputs used to review two independent fingerprints."""
 q=next(x for x in schema_fingerprint.__code__.co_consts
        if isinstance(x,str) and x.startswith('WITH o'))
 return db.execute(q.rsplit('SELECT encode',1)[0]+'SELECT k,v FROM o ORDER BY k,v').fetchall()
