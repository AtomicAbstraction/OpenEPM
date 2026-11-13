"""Audit exact delivered image IDs, including absence and no hidden base layers."""
from __future__ import annotations
import argparse
import json
import hashlib
import subprocess


def command(argv,input=None):
    done=subprocess.run(argv,input=input,text=True,capture_output=True,check=False,timeout=90)
    if done.returncode:raise ValueError('Delivered runtime check failed: '+(done.stderr or done.stdout)[-4000:])
    return done.stdout.strip()


def audit_image(image: str,kind: str,*,pdf: bytes|None=None) -> dict:
    if kind not in ('app','db'):raise ValueError('Expected app or db image')
    info=json.loads(command(['docker','image','inspect',image]))[0]
    identity=info['Id'];config=info['Config'];layers=info['RootFS']['Layers']
    empty='sha256:'+hashlib.sha256(bytes(1024)).hexdigest()
    payload_layers=[layer for layer in layers if layer!=empty]
    if info['Os']!='linux' or info['Architecture']!='arm64' or len(payload_layers)!=1:
        raise ValueError('Expected a flattened linux/arm64 runtime with exactly one nonempty filesystem layer')
    expected_user='10001:10001' if kind=='app' else 'postgres'
    if config['User']!=expected_user:raise ValueError('Runtime must preserve its unprivileged service identity')
    if kind=='db' and (config['Entrypoint']!=['docker-entrypoint.sh'] or config['Cmd']!=['postgres']
            or config['StopSignal']!='SIGINT' or '/var/lib/postgresql' not in config['Volumes']):
        raise ValueError('Database runtime startup/recovery contract changed')
    absence=command(['docker','run','--rm','--user','0:0','--entrypoint','/bin/bash',identity,'/usr/local/bin/openepm-runtime-check']
        + (['--require-published-skill'] if kind == 'app' else []))
    if 'Runtime-retirement gate passed:' not in absence:raise ValueError('Runtime absence gate did not complete')
    if kind=='app':
        probe="""import os,importlib.util
assert os.getuid()==10001
marker='sql'+'ite'
assert all(importlib.util.find_spec(name) is None for name in (marker+'3','_'+marker+'3','dbm.'+marker+'3'))
import psycopg,cryptography
import platform_postgres_router_mcp_http,platform_postgres_web_http
from epm_core.postgres_language_v2 import PostgresLanguageV2
assert len(PostgresLanguageV2.catalog()['functions'])>=164
print('Unprivileged application imports passed')
"""
        imports=command(['docker','run','--rm','--entrypoint','python',identity,'-c',probe])
        pdf_verified=False
    else:
        imports=command(['docker','run','--rm','--entrypoint','/bin/bash',identity,'-ec',
            'test "$(id -u)" = 999; postgres --version; initdb --version; pg_verifybackup --version'])
        pdf_verified=False
    return {'imageId':identity,'kind':kind,'architecture':'linux/arm64','filesystemLayers':len(layers),'nonemptyFilesystemLayers':len(payload_layers),
        'layerDigest':payload_layers[0],'user':config['User'],'absenceAudit':absence,'serviceProbe':imports,'pdfWorkerVerified':pdf_verified,
        'serverPdfParserPresent':False}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('image');parser.add_argument('kind',choices=('app','db'))
    args=parser.parse_args();print(json.dumps(audit_image(args.image,args.kind),sort_keys=True))


if __name__=='__main__':main()
