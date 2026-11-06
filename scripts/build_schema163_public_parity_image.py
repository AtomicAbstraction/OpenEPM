"""Build the parity runner from an exact clean Git export, never the worktree."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
from tempfile import TemporaryDirectory

# A registry digest and a local Docker content ID are both immutable inputs.
# The latter is required for cleaned qualification images that deliberately
# have no pushed registry manifest.  Mutable repository tags remain rejected.
PIN=re.compile(r"(?:[a-z0-9./_-]+@)?sha256:[0-9a-f]{64}\Z")
COMMIT=re.compile(r"[0-9a-f]{40}\Z")


def command(*args:str,**kwargs):
    return subprocess.run(args,check=True,text=True,**kwargs)


def build(root:Path,base_image:str,tag:str)->dict[str,str]:
    root=root.resolve()
    if not PIN.fullmatch(base_image):
        raise ValueError("SCHEMA163_PARITY_BASE_IMAGE_NOT_DIGEST_PINNED")
    status=command("git","status","--porcelain","--untracked-files=all",
                   cwd=root,capture_output=True).stdout
    if status:
        raise ValueError("SCHEMA163_PARITY_SOURCE_NOT_CLEAN")
    commit=command("git","rev-parse","HEAD",cwd=root,capture_output=True).stdout.strip()
    tree=command("git","rev-parse","HEAD^{tree}",cwd=root,capture_output=True).stdout.strip()
    if not COMMIT.fullmatch(commit) or not COMMIT.fullmatch(tree):
        raise ValueError("SCHEMA163_PARITY_SOURCE_IDENTITY_INVALID")
    paths=("epm_core","scripts","examples","schema/postgres","tests",
           "platform_postgres*.py",
           "deploy/qualification/Dockerfile.schema163-public-parity")
    with TemporaryDirectory(prefix="openepm-parity-build-") as temporary:
        context=Path(temporary).resolve();archive=context/"source.tar"
        with archive.open("wb") as stream:
            subprocess.run(["git","archive","--format=tar",commit,*paths],
                cwd=root,check=True,stdout=stream)
        with tarfile.open(archive) as source:
            for member in source.getmembers():
                target=(context/member.name).resolve()
                if context not in target.parents:
                    raise ValueError("SCHEMA163_PARITY_ARCHIVE_PATH_INVALID:"+member.name)
            source.extractall(context)
        archive.unlink()
        command("docker","build","--build-arg",f"APPLICATION_IMAGE={base_image}",
            "--build-arg",f"SOURCE_COMMIT={commit}","--build-arg",f"SOURCE_TREE={tree}",
            "-f",str(context/"deploy/qualification/Dockerfile.schema163-public-parity"),
            "-t",tag,str(context),env={**os.environ,"DOCKER_BUILDKIT":"0"})
    inspected=command("docker","image","inspect",tag,"--format",
        '{{.Id}} {{index .Config.Labels "org.openepm.source.commit"}} '
        '{{index .Config.Labels "org.openepm.source.tree"}}',capture_output=True).stdout.split()
    if len(inspected)!=3 or inspected[1:]!=[commit,tree] or not re.fullmatch(
            r"sha256:[0-9a-f]{64}",inspected[0]):
        raise ValueError("SCHEMA163_PARITY_IMAGE_BINDING_INVALID")
    return {"imageId":inspected[0],"sourceCommit":commit,"sourceTree":tree}


def main()->None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,default=Path(__file__).parents[1])
    parser.add_argument("--base-image",required=True)
    parser.add_argument("--tag",required=True)
    args=parser.parse_args()
    print(json.dumps(build(args.root,args.base_image,args.tag),sort_keys=True))


if __name__=="__main__":main()
