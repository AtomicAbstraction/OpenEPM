"""Build deterministic non-activating schema-163 SQL artifact from pg_dump SQL."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

from epm_core.postgres_fresh_baseline import (
    ARTIFACT_FORMAT, _unquoted_sql, load_artifact)


ROLES=("epm_access","epm_analyst","epm_lifecycle","epm_provision",
       "epm_python_coordinator","epm_runtime","epm_security","epm_worker")

_DUMP_DDL = re.compile(
    r"(?:CREATE\s+(?:EXTENSION|SCHEMA|TYPE|DOMAIN|SEQUENCE|TABLE|FUNCTION|"
    r"PROCEDURE|VIEW|MATERIALIZED\s+VIEW|(?:UNIQUE\s+)?INDEX|"
    r"(?:CONSTRAINT\s+)?TRIGGER|POLICY|RULE)\b|"
    r"ALTER\s+(?:SCHEMA|TYPE|DOMAIN|SEQUENCE|TABLE|FUNCTION|PROCEDURE|VIEW|"
    r"MATERIALIZED\s+VIEW|DEFAULT\s+PRIVILEGES)\b|"
    r"(?:GRANT|REVOKE|COMMENT\s+ON|SECURITY\s+LABEL\s+ON)\b)", re.I)
_DUMP_FORBIDDEN = re.compile(
    r"\b(?:CREATE\s+(?:DATABASE|TABLESPACE|SERVER|FOREIGN\s+DATA\s+WRAPPER|"
    r"USER\s+MAPPING)|ALTER\s+(?:DATABASE|SYSTEM)|DROP|COPY|MERGE|TRUNCATE|"
    r"VACUUM|ANALYZE|LOAD|DO|CALL|BEGIN|COMMIT|ROLLBACK|"
    r"SAVEPOINT|PREPARE\s+TRANSACTION|SET\s+ROLE|SET\s+SESSION\s+AUTHORIZATION)\b",
    re.I)


def _validate_dump_statement(statement:str)->None:
    """Reject anything outside pg_dump's reviewed, schema-only DDL surface.

    Function bodies and quoted values are blanked before checking because EPM
    routines legitimately contain DML.  The resulting artifact still passes
    catalog parity; this guard prevents a dump input from smuggling a top-level
    data, database, session, or external-object command into that artifact.
    """
    structural=_unquoted_sql(statement).strip()
    if not _DUMP_DDL.match(structural) or _DUMP_FORBIDDEN.search(structural):
        raise ValueError('BASELINE_DUMP_STATEMENT_FORBIDDEN')
    raw=statement.lower()
    if any(token in raw for token in ('postgres_fdw','file_fdw','dblink',
      'pg_read_file','pg_write_file','pg_ls_dir','lo_import','lo_export')):
        raise ValueError('BASELINE_DUMP_EXTERNAL_ACCESS_FORBIDDEN')


def _strip_external_comments(text:str)->str:
    out=[];i=0;single=double=False;dollar=None
    while i<len(text):
        if dollar:
            if text.startswith(dollar,i):out.append(dollar);i+=len(dollar);dollar=None
            else:out.append(text[i]);i+=1
            continue
        ch=text[i]
        if single:
            out.append(ch);i+=1
            if ch=="'":
                if i<len(text) and text[i]=="'":out.append(text[i]);i+=1
                else:single=False
            continue
        if double:
            out.append(ch);i+=1
            if ch=='"':
                if i<len(text) and text[i]=='"':out.append(text[i]);i+=1
                else:double=False
            continue
        match=re.match(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$",text[i:])
        if match:dollar=match.group();out.append(dollar);i+=len(dollar);continue
        if text.startswith('--',i):
            end=text.find('\n',i);i=len(text) if end<0 else end+1;out.append('\n');continue
        if text.startswith('/*',i):
            end=text.find('*/',i+2)
            if end<0:raise ValueError('BASELINE_DUMP_UNTERMINATED_COMMENT')
            out.append(' ');i=end+2;continue
        out.append(ch);i+=1
        if ch=="'":single=True
        elif ch=='"':double=True
    if single or double or dollar:raise ValueError('BASELINE_DUMP_UNTERMINATED_QUOTE')
    return ''.join(out)


def _split(text:str)->list[str]:
    result=[];start=0;i=0;single=double=False;dollar=None
    while i<len(text):
        if dollar:
            if text.startswith(dollar,i):i+=len(dollar);dollar=None
            else:i+=1
            continue
        ch=text[i]
        if single:
            i+=1
            if ch=="'":
                if i<len(text) and text[i]=="'":i+=1
                else:single=False
            continue
        if double:
            i+=1
            if ch=='"':
                if i<len(text) and text[i]=='"':i+=1
                else:double=False
            continue
        match=re.match(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$",text[i:])
        if match:dollar=match.group();i+=len(dollar);continue
        if ch=="'":single=True;i+=1;continue
        if ch=='"':double=True;i+=1;continue
        if ch==';':
            value=text[start:i+1].strip()
            if value:result.append(value)
            start=i+1
        i+=1
    if text[start:].strip():raise ValueError('BASELINE_DUMP_TRAILING_SQL')
    return result


def _escape_body(body:str)->str:
    value=body.replace('\\','\\\\').replace("'","''")
    value=value.replace('--','\\x2d-').replace('/*','\\x2f*').replace('*/','*\\x2f')
    return "E'"+value+"'"


def _encode_dollar_bodies(statement:str)->str:
    pattern=re.compile(r"\$[A-Za-z_][A-Za-z0-9_]*\$|\$\$")
    out=[];position=0
    while True:
        match=pattern.search(statement,position)
        if not match:out.append(statement[position:]);break
        tag=match.group();end=statement.find(tag,match.end())
        if end<0:raise ValueError('BASELINE_DUMP_UNTERMINATED_DOLLAR_BODY')
        out.append(statement[position:match.start()]);out.append(_escape_body(statement[match.end():end]))
        position=end+len(tag)
    return ''.join(out)


def _normalize_statement(statement:str)->str:
    """Normalize pg_dump output whose order is not catalog-defined."""
    if statement.lstrip().upper().startswith('CREATE POLICY '):
        def ordered(match):
            roles=sorted(part.strip() for part in match.group(2).split(','))
            return match.group(1)+', '.join(roles)+match.group(3)
        statement=re.sub(r'(\sTO\s+)((?:"[^"]+"(?:,\s*)?)+)(\s+(?:USING|WITH CHECK))',
                         ordered,statement,count=1,flags=re.I)
    return statement


def parse_dump(path:Path)->list[str]:
    lines=[line for line in path.read_text(encoding='utf-8').splitlines()
           if not line.startswith('\\')]
    statements=[]
    for statement in _split(_strip_external_comments('\n'.join(lines)+'\n')):
        upper=statement.lstrip().upper()
        if upper.startswith('SET ') or upper.startswith("SELECT PG_CATALOG.SET_CONFIG("):
            continue
        normalized=_normalize_statement(_encode_dollar_bodies(statement))
        _validate_dump_statement(normalized)
        statements.append(normalized)
    return statements


def role_statements()->list[str]:
    result=[]
    for role in ROLES:
        result.append("DO E'BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=''"+
          role+"'') THEN CREATE ROLE \""+role+"\"; END IF; END'")
        result.append('ALTER ROLE "'+role+'" NOSUPERUSER INHERIT NOCREATEROLE '
          'NOCREATEDB NOLOGIN NOREPLICATION NOBYPASSRLS CONNECTION LIMIT -1')
    return result


def migration_insert(directory:Path)->str:
    rows=[]
    for version in range(1,164):
        matches=sorted(directory.glob(f'{version:04d}_*.sql'))
        if len(matches)!=1:raise ValueError('BASELINE_CANONICAL_MIGRATION_SET_INVALID')
        path=matches[0];description=path.stem[5:].replace("'","''")
        rows.append(f"({version},'{description}','{hashlib.sha256(path.read_bytes()).hexdigest()}')")
    return 'INSERT INTO "epm"."schema_migration"("version","description","checksum") VALUES '+','.join(rows)


def review_existing_artifact(path:Path,directory:Path,*,expected_sha256:str)->dict[str,object]:
    """Review the exact retained artifact without rewriting or authorizing it.

    The dump-statement guard cannot be proven to have reviewed an old artifact
    merely because a newer generator contains it.  This entry point binds that
    guard to the artifact bytes and separately checks the three constructor-
    owned regions (roles, local validation setting, and migration ledger).
    """
    source=path.read_bytes();actual=hashlib.sha256(source).hexdigest()
    if not re.fullmatch(r'[0-9a-f]{64}',expected_sha256) or actual!=expected_sha256:
        raise ValueError('BASELINE_RETAINED_ARTIFACT_DIGEST_MISMATCH')
    statements=load_artifact(path)
    roles=role_statements()
    if statements[:len(roles)]!=roles:
        raise ValueError('BASELINE_RETAINED_ARTIFACT_ROLE_REGION_MISMATCH')
    offset=len(roles)
    if statements[offset]!='SET LOCAL check_function_bodies = false':
        raise ValueError('BASELINE_RETAINED_ARTIFACT_LOCAL_SETTING_MISMATCH')
    if statements[-1]!=migration_insert(directory):
        raise ValueError('BASELINE_RETAINED_ARTIFACT_LEDGER_MISMATCH')
    dump_statements=statements[offset+1:-1]
    if not dump_statements:
        raise ValueError('BASELINE_RETAINED_ARTIFACT_DDL_MISSING')
    for statement in dump_statements:
        _validate_dump_statement(statement)
    return {'artifactSha256':actual,'statementCount':len(statements),
      'reviewedDumpStatementCount':len(dump_statements),
      'constructorStatementCount':len(roles)+2,
      'activationAuthorized':False}


def main()->None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dump',type=Path,required=True)
    parser.add_argument('--migrations-dir',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    statements=(role_statements()+['SET LOCAL check_function_bodies = false']+
      parse_dump(args.dump)+[migration_insert(args.migrations_dir)])
    payload={'format':ARTIFACT_FORMAT,'statements':statements}
    args.output.write_text(json.dumps(payload,sort_keys=True,separators=(',',':'))+'\n')
    load_artifact(args.output)
    print(json.dumps({'output':str(args.output.resolve()),'statementCount':len(statements),
      'sha256':hashlib.sha256(args.output.read_bytes()).hexdigest(),
      'activationAuthorized':False}))


if __name__=='__main__':main()
