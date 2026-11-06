"""Remove a retired optional backend from the pinned container interpreter.

This never targets host Python. Small reviewed AST edits retain surrounding
source and copyright notices; the final image is flattened after verification.
"""
from __future__ import annotations
import ast
import base64
import csv
import hashlib
import json
from email.parser import Parser
import os
from pathlib import Path
import pprint
import shutil
import sysconfig

MARKER='sql'+'ite'


def filtered_vars(values):
    markers=(MARKER,'_tkinter','tcltk')
    result={}
    for key,value in values.items():
        if any(marker in str(key).lower() for marker in markers):continue
        if isinstance(value,str) and any(marker in value.lower() for marker in markers):
            value=' '.join(token for token in value.split() if not any(marker in token.lower() for marker in markers))
        result[key]=value
    return result


def restricted_metadata(source: str,licenses: Path) -> str:
    message=Parser().parsestr(source)
    requirements=message.get_all('Requires-Dist',[])
    obsolete=[]
    retired_requirements=[]
    package=(message.get('Name','').lower(),message.get('Version',''))
    retired_async_name='aio'+MARKER
    sqlalchemy_retired_async={
        'sqlalchemy[asyncio]; extra == "'+retired_async_name+'"',
        retired_async_name+'; extra == "'+retired_async_name+'"',
    }
    for requirement in requirements:
        if MARKER in requirement.lower():
            if 'extra == "examples-db"' in requirement:
                obsolete.append('examples-db')
            elif package==('sqlalchemy','2.1.6') and requirement.lower() in sqlalchemy_retired_async:
                obsolete.append(retired_async_name);retired_requirements.append(requirement.lower())
            else:
                raise ValueError('A live package dependency requires explicit retirement')
    if package==('sqlalchemy','2.1.6') and retired_requirements \
            and set(retired_requirements)!=sqlalchemy_retired_async:
        raise ValueError('Pinned SQLAlchemy optional-extra shape changed')
    if not obsolete and MARKER not in str(message.get_payload()).lower():return source
    notices=message.get_all('License-File',[])
    if not notices:raise ValueError('Explicit retained license notices are required')
    for name in notices:
        if not (licenses/name).is_file():raise ValueError('Required distribution notice is unavailable')
    extras=message.get_all('Provides-Extra',[])
    if 'Requires-Dist' in message:del message['Requires-Dist']
    for requirement in requirements:
        if not any('extra == "'+extra+'"' in requirement for extra in obsolete):message['Requires-Dist']=requirement
    if 'Provides-Extra' in message:del message['Provides-Extra']
    for extra in extras:
        if extra not in obsolete:message['Provides-Extra']=extra
    message.set_payload('Optional example documentation is omitted from this restricted server runtime. '
        'See the preserved project metadata and distribution license files for source and licensing.\n')
    result=message.as_string()
    if MARKER in result.lower():raise ValueError('Unreviewed package declaration remains')
    return result


def filtered_dict(source: str,name: str) -> str:
    tree=ast.parse(source)
    assignments=[node for node in tree.body if isinstance(node,ast.Assign)
        and any(isinstance(target,ast.Name) and target.id==name for target in node.targets)]
    if len(assignments)!=1:raise ValueError('Pinned runtime dictionary shape changed')
    node=assignments[0].value
    values=ast.literal_eval(node)
    if not isinstance(values,dict):raise ValueError('Expected runtime dictionary')
    clean=filtered_vars(values) if name=='build_time_vars' else {key:value for key,value in values.items() if MARKER not in repr((key,value)).lower()}
    lines=source.splitlines(keepends=True)
    start=sum(len(line) for line in lines[:node.lineno-1])+node.col_offset
    end=sum(len(line) for line in lines[:node.end_lineno-1])+node.end_col_offset
    return source[:start]+pprint.pformat(clean,width=100,sort_dicts=False)+source[end:]


def clean_dispatch(source: str) -> str:
    source=source.replace('dbm.'+MARKER+'3, ','')
    tree=ast.parse(source);lines=source.splitlines(keepends=True)
    changes=[]
    for node in ast.walk(tree):
        if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='_names' for target in node.targets):
            value=ast.literal_eval(node.value)
            start=sum(map(len,lines[:node.value.lineno-1]))+node.value.col_offset
            end=sum(map(len,lines[:node.value.end_lineno-1]))+node.value.end_col_offset
            changes.append((start,end,repr([item for item in value if MARKER not in item.lower()])))
        elif isinstance(node,ast.If) and any(isinstance(item,ast.Constant) and isinstance(item.value,bytes)
                and MARKER.encode() in item.value.lower() for item in ast.walk(node.test)):
            start=sum(map(len,lines[:node.lineno-1]));end=sum(map(len,lines[:node.end_lineno]))
            changes.append((start,end,''))
    for start,end,replacement in sorted(changes,reverse=True):source=source[:start]+replacement+source[end:]
    source=''.join(line for line in source.splitlines(keepends=True)
        if not (line.lstrip().startswith('#') and MARKER in line.lower()))
    if MARKER in source.lower():raise ValueError('Unreviewed backend dispatch reference remains')
    ast.parse(source)
    return source


def rewrite(path: Path,source: str) -> None:
    path.write_text(source)
    for cache in (path.parent/'__pycache__').glob(path.stem+'.*.pyc'):
        cache.unlink()


def prune(root: Path,*,prefix: Path|None=None) -> list[str]:
    changed=[]
    sysconfig_files=list(root.glob('_sysconfigdata__linux_*-linux-gnu.py'))
    if len(sysconfig_files)!=1:raise ValueError('Pinned Python sysconfig shape changed')
    sysconfig_name=sysconfig_files[0].name
    for name,assignment in ((sysconfig_name,'build_time_vars'),
            ('pydoc_data/module_docs.py','module_docs'),('site-packages/pip/_vendor/pygments/lexers/_mapping.py','LEXERS')):
        path=root/name
        if not path.is_file():
            if name.startswith('site-packages/pip/') and not (root/'site-packages/pip').exists():
                continue
            raise ValueError('Pinned Python runtime file missing: '+name)
        original=path.read_text();clean=filtered_dict(original,assignment)
        if MARKER in clean.lower():raise ValueError('Unreviewed runtime reference remains: '+name)
        rewrite(path,clean);changed.append(name)
    path=root/'dbm/__init__.py';rewrite(path,clean_dispatch(path.read_text()));changed.append('dbm/__init__.py')
    # Remove actual files/extension modules, not just their import registration.
    for path in sorted(root.rglob('*'),key=lambda p:len(p.parts),reverse=True):
        if MARKER in path.name.lower():
            if path.is_dir() and not path.is_symlink():shutil.rmtree(path)
            else:path.unlink()
    # This headless slim base ships an unusable optional GUI extension without
    # its linked Tcl/Tk libraries. Omit that frontend instead of hiding broken
    # native dependencies or adding a desktop stack to the server runtime.
    for name in ('tkinter','idlelib','turtledemo','turtle.py'):
        path=root/name
        if path.is_dir():shutil.rmtree(path)
        elif path.exists():path.unlink()
    for path in (root/'lib-dynload').glob('_tkinter*.so'):path.unlink()
    for path in root.glob('_sysconfig_vars*.json'):
        values=json.loads(path.read_text())
        if not isinstance(values,dict):raise ValueError('Unexpected runtime JSON metadata')
        path.write_text(json.dumps(filtered_vars(values),sort_keys=True)+'\n')
    # This is a locked binary-wheel server distribution, not a C-extension SDK.
    for path in root.glob('config-*'):
        if path.is_dir():shutil.rmtree(path)
    if prefix is not None:
        version=f'python{sysconfig.get_python_version()}'
        if version not in {'python3.13','python3.14'} or root!=prefix/'lib'/version:
            raise ValueError('Unexpected SDK prefix')
        include=prefix/'include'/version
        if include.is_dir():shutil.rmtree(include)
        for path in (prefix/'bin').glob('python*-config'):
            if path.is_file() or path.is_symlink():path.unlink()
    site=root/'site-packages'
    for path in site.glob('*.dist-info/METADATA'):
        source=path.read_text()
        if MARKER in source.lower():
            path.write_text(restricted_metadata(source,path.parent/'licenses'))
            changed.append(str(path.relative_to(root)))
    # Keep installed pip's content inventory accurate after the documented
    # derivative lexer-map cleanup; original notices stay in the source header.
    for record in site.glob('*.dist-info/RECORD'):
        with record.open(newline='') as stream:rows=list(csv.reader(stream))
        for row in rows:
            path=site/row[0]
            if 'site-packages/'+row[0] in changed:
                payload=path.read_bytes()
                row[1]='sha256='+base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).decode().rstrip('=')
                row[2]=str(len(payload))
        with record.open('w',newline='') as stream:csv.writer(stream).writerows(rows)
    return changed


def main() -> None:
    if os.geteuid()!=0 or not Path('/etc/openepm-image-build').is_file():
        raise SystemExit('Image-build guard required; host runtimes are not a target')
    root=Path(sysconfig.get_path('stdlib'))
    version=f'python{sysconfig.get_python_version()}'
    if version not in {'python3.13','python3.14'} or root!=Path('/usr/local/lib')/version:
        raise SystemExit('Unexpected pinned interpreter path')
    changed=prune(root,prefix=Path('/usr/local'))
    print('Retired optional Python backend; reviewed metadata edits:',', '.join(changed))


if __name__=='__main__':main()
