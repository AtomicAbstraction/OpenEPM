#!/usr/bin/env python3
"""Explicit, on-demand refresh; never starts a schedule or executes EPM code."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import tarfile
import os
import shutil
import stat
import sys
from build import build

project=Path(__file__).resolve().parents[2]

# Only product implementation, infrastructure and executable test source may
# overlay the archived commit. Review data and local runtime state stay apart.
SOURCE_DIRS=('epm_core', 'openepm', 'schema', 'deploy', 'scripts', 'tests', 'web', 'web-ui')
SOURCE_SUFFIXES={'.py','.sql','.sh','.js','.mjs','.cjs','.ts','.tsx','.jsx','.css',
                 '.html','.yaml','.yml','.toml','.json','.txt','.lock','.template'}


def freeze_working_source(snapshot, base):
    def paths():
        entries=subprocess.check_output(['git','ls-files','-z','--cached','--others',
                 '--exclude-standard','--',*SOURCE_DIRS,'platform_postgres_*.py'],cwd=project)
        return sorted({os.fsdecode(item) for item in entries.split(b'\0') if item})

    selected=[]
    inventory=paths()
    for name in inventory:
        path=Path(name)
        target=snapshot/path
        if name.startswith(('scripts/implementation_graph/','tests/evidence/')):
            continue
        if not target.exists() and (path.suffix not in SOURCE_SUFFIXES
                or any(part.startswith('.') for part in path.parts)):
            continue
        source=project/path
        if source.is_symlink() or source.resolve()!=source:
            raise ValueError(f'Noncanonical development source: {name}')
        if source.is_file():
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(source,target)
        elif target.is_file():
            target.unlink()
        selected.append(name)
    if (paths()!=inventory or any((snapshot/name).is_file()!=(project/name).is_file()
            or ((snapshot/name).is_file() and ((snapshot/name).read_bytes()!=(project/name).read_bytes()
                or bool((snapshot/name).stat().st_mode & stat.S_IXUSR)!=bool((project/name).stat().st_mode & stat.S_IXUSR)))
            for name in selected)):
        raise ValueError('Development source changed while freezing the graph. Retry on stable source.')

    env={key:value for key,value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_CONFIG_GLOBAL='/dev/null',GIT_CONFIG_SYSTEM='/dev/null',GIT_CONFIG_NOSYSTEM='1',
               GIT_AUTHOR_NAME='Open EPM Snapshot',GIT_AUTHOR_EMAIL='snapshot@example.invalid',
               GIT_COMMITTER_NAME='Open EPM Snapshot',GIT_COMMITTER_EMAIL='snapshot@example.invalid')
    stamp=subprocess.check_output(['git','show','-s','--format=%ct',base],cwd=project,text=True).strip()
    env.update(GIT_AUTHOR_DATE=f'@{stamp} +0000',GIT_COMMITTER_DATE=f'@{stamp} +0000')

    def git(*args):
        return subprocess.check_output(['git','-c','core.hooksPath=/dev/null','-c','core.autocrlf=false',
                                        *args],cwd=snapshot,env=env,text=True).strip()

    git('init','--quiet','--template=')
    git('add','--force','--all','--','.')
    commit=git('commit-tree',git('write-tree'),'-m',f'Frozen Open EPM development source based on {base}')
    git('update-ref','HEAD',commit)
    return commit


p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--out',type=Path,help='Artifact directory; defaults to last local artifact pointer')
p.add_argument('--assets',type=Path,help='Directory containing the pinned renderer and license; defaults to artifact/assets')
p.add_argument('--working-tree',action='store_true',help='Freeze current implementation source in a disposable local Git repository')
a=p.parse_args()
pointer=project/'docs/implementation-graph/local-artifact.json'
out=a.out or Path(json.loads(pointer.read_text())['artifact'])
assets=a.assets or out/'assets'
state=project/'docs/implementation-graph/annotations.json'
base=subprocess.check_output(['git','rev-parse','HEAD'],cwd=project,text=True).strip()
commit=base
print('Freezing source based on',base,flush=True)
with tempfile.TemporaryDirectory(prefix='openepm-graph-refresh-') as directory:
    temp=Path(directory);archive=temp/'snapshot.tar'
    with archive.open('wb') as f:
        subprocess.run(['git','archive',commit],cwd=project,stdout=f,check=True)
    snapshot=temp/'source';snapshot.mkdir()
    with tarfile.open(archive) as tar:
        tar.extractall(snapshot,filter='data')
    if a.working_tree:
        commit=freeze_working_source(snapshot,base)
        print('Frozen development snapshot',commit,flush=True)
        settings=snapshot/'.entire/settings.local.json'
        settings.parent.mkdir(parents=True,exist_ok=True)
        settings.write_text(json.dumps({'enabled':True,'telemetry':False,
            'strategy_options':{'push_sessions':False}})+'\n')
    raw=temp/'entire.ndjson'
    print('Reading local Entire Graph export (no setup, upload or business services)',flush=True)
    with raw.open('w') as f:
        subprocess.run(['entire','graph','snapshot','--repo',str(snapshot if a.working_tree else project),
                        '--format','ndjson','--profile','full'],stdout=f,check=True)
    with raw.open() as f:header=json.loads(f.readline())
    if header['commit']!=commit:
        raise SystemExit('HEAD changed during export. Previous artifact preserved; rerun refresh on a stable commit.')
    # Build completely before changing the served artifact. User metadata is
    # loaded by the server from its separate live file and is never overwritten.
    candidate=temp/'artifact'
    build(snapshot,raw,candidate,assets,state if state.exists() else None,base if a.working_tree else None)
    subprocess.run([sys.executable,str(Path(__file__).with_name('validate.py')),str(candidate)],check=True)
    out.mkdir(parents=True,exist_ok=True)
    for file in candidate.iterdir():
        if file.is_file():
            target=out/file.name;staging=out/(file.name+'.refresh-tmp')
            staging.write_bytes(file.read_bytes());os.replace(staging,target)
        elif file.is_dir():
            shutil.copytree(file,out/file.name,dirs_exist_ok=True)
    pointer.parent.mkdir(parents=True,exist_ok=True)
    pointer.write_text(json.dumps({'artifact':str(out.resolve()),'commit':commit,
                                  'snapshotKind':'working-tree' if a.working_tree else 'committed',
                                  'baseCommit':base},indent=2)+'\n')
print('Refreshed',out/'index.html')
print('Reload the local app. Exact stable IDs retain their annotations; orphan IDs are flagged for reconciliation.')
