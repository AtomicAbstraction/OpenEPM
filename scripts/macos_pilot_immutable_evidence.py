"""Atomic no-clobber publication for immutable privileged evidence."""
from __future__ import annotations
import os
from pathlib import Path
import stat
import tempfile

class ImmutableEvidenceError(RuntimeError):pass

def _existing(path:Path,payload:bytes,owner:int)->None:
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        meta=os.fstat(fd);raw=os.read(fd,len(payload)+1)
        if stat.S_ISREG(meta.st_mode) and meta.st_nlink>1 and meta.st_uid==owner \
                and stat.S_IMODE(meta.st_mode)==0o400 and raw==payload:
            removed=False
            for candidate in path.parent.glob("."+path.name+".*"):
                try:item=os.lstat(candidate)
                except FileNotFoundError:continue
                if stat.S_ISREG(item.st_mode) and item.st_dev==meta.st_dev \
                        and item.st_ino==meta.st_ino and item.st_uid==owner \
                        and stat.S_IMODE(item.st_mode)==0o400:
                    candidate.unlink();removed=True
            if removed:
                directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
                try:os.fsync(directory)
                finally:os.close(directory)
            meta=os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink!=1 or meta.st_uid!=owner \
                or stat.S_IMODE(meta.st_mode)!=0o400 or raw!=payload:
            raise ImmutableEvidenceError("immutable evidence differs")
    finally:os.close(fd)

def publish_immutable(path:Path,payload:bytes,*,owner:int=0,
                      _after_publish=None)->None:
    path=Path(path)
    if not isinstance(payload,bytes) or not payload:
        raise ImmutableEvidenceError("immutable evidence payload differs")
    try:_existing(path,payload,owner);return
    except FileNotFoundError:pass
    fd,name=tempfile.mkstemp(prefix="."+path.name+".",dir=path.parent)
    temporary=Path(name);published=False
    try:
        os.fchmod(fd,0o600);offset=0
        while offset<len(payload):
            written=os.write(fd,payload[offset:])
            if written<1:raise OSError("immutable evidence write made no progress")
            offset+=written
        os.fsync(fd);os.fchmod(fd,0o400);os.fsync(fd);os.close(fd);fd=-1
        try:
            os.link(temporary,path,follow_symlinks=False);published=True
        except FileExistsError:
            _existing(path,payload,owner);return
        temporary.unlink();published=False
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
        if _after_publish is not None:_after_publish()
    finally:
        if fd>=0:os.close(fd)
        if not published:
            try:temporary.unlink()
            except FileNotFoundError:pass
