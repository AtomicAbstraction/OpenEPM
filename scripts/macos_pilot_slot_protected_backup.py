#!/usr/bin/env python3
"""Slot-bound, crash-reconciling protected backup authority for Mac pilot."""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from typing import Protocol
import uuid


SHA = re.compile(r"^[0-9a-f]{64}$")
SAFE = re.compile(r"^[a-z0-9][a-z0-9_.-]{1,127}$")
CONFIG = "backup-slots.json"
MAX_CONFIG = 64 * 1024


class SlotBackupError(RuntimeError):
    pass


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def digest(value: object) -> str:
    return digest_bytes(canonical(value))


class BackupEvidenceProvider(Protocol):
    def quiescence(self, slot: str, operation_key: str,
                   contract: dict) -> dict: ...


class BackupCaptureBackend(Protocol):
    def capture(self, binding: dict, destination: Path) -> dict: ...


class ProcessResult:
    __slots__ = ("returncode", "stdout", "stderr")
    def __init__(self, returncode: int, stdout: bytes, stderr: bytes):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


class BackupProcessBackend(Protocol):
    def run(self, argv: tuple[str, ...], environment: dict[str, str],
            timeout_seconds: int, *, stdout_path: Path | None = None,
            stdin_path: Path | None = None) \
            -> ProcessResult: ...


class SubprocessBackupProcessBackend:
    """Streaming, no-shell process boundary with bounded diagnostic output."""

    def run(self, argv: tuple[str, ...], environment: dict[str, str],
            timeout_seconds: int, *, stdout_path: Path | None = None,
            stdin_path: Path | None = None) \
            -> ProcessResult:
        output = subprocess.PIPE
        descriptor = input_descriptor = None
        try:
            if stdout_path is not None:
                descriptor = os.open(stdout_path, os.O_WRONLY | os.O_CREAT
                                     | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                output = descriptor
            input_value = subprocess.DEVNULL
            if stdin_path is not None:
                input_descriptor = os.open(stdin_path, os.O_RDONLY | os.O_NOFOLLOW)
                input_value = input_descriptor
            completed = subprocess.run(argv, stdin=input_value,
                stdout=output, stderr=subprocess.PIPE, env=environment,
                timeout=timeout_seconds, check=False)
            stderr = completed.stderr or b""
            if len(stderr) > 1024 * 1024:
                raise SlotBackupError("backup process diagnostic output is oversized")
            stdout = b"" if stdout_path is not None else (completed.stdout or b"")
            if len(stdout) > 1024 * 1024:
                raise SlotBackupError("backup process output is oversized")
            if descriptor is not None:
                os.fchmod(descriptor, 0o600)
                os.fsync(descriptor)
            return ProcessResult(completed.returncode, stdout, stderr)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if input_descriptor is not None:
                os.close(input_descriptor)


class FixedContainerPgDumpBackend:
    """Capture one protected, configured PostgreSQL container without caller argv."""

    ENVIRONMENT = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}

    def __init__(self, process: BackupProcessBackend):
        if not hasattr(process, "run"):
            raise SlotBackupError("backup process backend is unavailable")
        self.process = process

    def _executable(self, binding: dict) -> str:
        identity = binding.get("dockerExecutable")
        legacy = {"path", "sha256", "device", "inode", "ownerUid", "mode"}
        portable = {"path", "sha256", "ownerUid", "mode"}
        if not isinstance(identity, dict) or set(identity) not in (legacy, portable):
            raise SlotBackupError("protected Docker executable identity is invalid")
        path = Path(identity["path"])
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise SlotBackupError("protected Docker executable is unavailable")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            meta = os.fstat(descriptor)
            if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 \
                    or ("device" in identity and meta.st_dev != identity["device"]) \
                    or ("inode" in identity and meta.st_ino != identity["inode"]) \
                    or meta.st_uid != identity["ownerUid"] \
                    or stat.S_IMODE(meta.st_mode) != identity["mode"] \
                    or meta.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise SlotBackupError("protected Docker executable identity differs")
            hasher = hashlib.sha256()
            for chunk in iter(lambda: os.read(descriptor, 1024 * 1024), b""):
                hasher.update(chunk)
            if hasher.hexdigest() != identity["sha256"]:
                raise SlotBackupError("protected Docker executable digest differs")
        finally:
            os.close(descriptor)
        return str(path)

    def _run(self, binding: dict, arguments: tuple[str, ...], timeout: int, *,
             stdout_path: Path | None = None,
             stdin_path: Path | None = None) -> ProcessResult:
        executable = self._executable(binding)
        argv = (executable, *arguments)
        result = self.process.run(argv, dict(self.ENVIRONMENT), timeout,
                                  stdout_path=stdout_path, stdin_path=stdin_path)
        if not isinstance(result, ProcessResult) or result.returncode != 0:
            raise SlotBackupError("fixed backup process failed")
        return result

    def _inspect(self, binding: dict) -> None:
        container = binding["sourceIdentity"]
        result = self._run(binding, ("inspect", container), 30)
        try:
            values = json.loads(result.stdout.decode("utf-8"))
            value = values[0]
            state, mounts, image = value["State"], value["Mounts"], value["Image"]
        except (UnicodeError, json.JSONDecodeError, IndexError, KeyError,
                TypeError) as error:
            raise SlotBackupError("backup container inspection is invalid") from error
        mounted = [item for item in mounts if item.get("Destination") \
                   == "/var/lib/postgresql/data"]
        if state.get("Running") is not True or len(mounted) != 1 \
                or mounted[0].get("Name") != binding["databaseVolume"] \
                or image != binding["containerImage"]:
            raise SlotBackupError("backup container or volume identity differs")

    def _database_identity(self, binding: dict) -> None:
        sql = ("SELECT current_database() || '|' || "
               "(pg_control_system()).system_identifier::text")
        result = self._run(binding, ("exec", binding["sourceIdentity"],
            "psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-U",
            "postgres", "-d", binding["database"], "-c", sql), 30)
        expected = f'{binding["database"]}|{binding["systemIdentifier"]}'
        try:
            observed = result.stdout.decode("utf-8").strip()
        except UnicodeError as error:
            raise SlotBackupError("database identity output is invalid") from error
        if observed != expected:
            raise SlotBackupError("connected database system identity differs")

    def capture(self, binding: dict, destination: Path) -> dict:
        required = {"database", "systemIdentifier", "databaseVolume",
                    "sourceIdentity", "backupDirectory", "receiptKeyFile",
                    "manifestFile", "containerImage", "dockerExecutable"}
        if not isinstance(binding, dict) or set(binding) != required \
                or any(SAFE.fullmatch(str(binding.get(key))) is None for key in
                       ("database", "databaseVolume", "sourceIdentity")) \
                or not str(binding.get("systemIdentifier", "")).isdecimal() \
                or not destination.is_absolute() or destination.exists():
            raise SlotBackupError("fixed backup capture binding is invalid")
        self._inspect(binding)
        self._database_identity(binding)
        try:
            self._run(binding, ("exec", binding["sourceIdentity"], "pg_dump",
                "-U", "postgres", "-d", binding["database"], "--format=custom",
                "--no-owner", "--file=-"), 3600, stdout_path=destination)
            meta = destination.stat()
            if not stat.S_ISREG(meta.st_mode) or stat.S_IMODE(meta.st_mode) != 0o600 \
                    or meta.st_size < 1:
                raise SlotBackupError("captured archive is unsafe")
            # pg_restore comes from the exact already-pinned database image;
            # the archive is streamed on stdin, so no host pg_restore is required.
            listing = self._run(binding, ("exec", "-i", binding["sourceIdentity"],
                "pg_restore", "--list", "-"), 120, stdin_path=destination)
            try:
                lines = [line for line in listing.stdout.decode("utf-8").splitlines()
                         if line and not line.startswith(";")]
            except UnicodeError as error:
                raise SlotBackupError("backup catalogue is invalid") from error
            acl = [line for line in lines if " ACL " in line or " DEFAULT ACL " in line]
            if not lines or not acl:
                raise SlotBackupError("backup catalogue or ACL evidence is absent")
            archive_sha = hashlib.sha256()
            with destination.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    archive_sha.update(chunk)
            return {"database": binding["database"],
                "systemIdentifier": binding["systemIdentifier"],
                "databaseVolume": binding["databaseVolume"],
                "sourceIdentity": binding["sourceIdentity"], "bytes": meta.st_size,
                "sha256": archive_sha.hexdigest(), "catalogEntries": len(lines),
                "aclEntries": len(acl),
                "catalogSha256": digest_bytes(listing.stdout)}
        except BaseException:
            try:
                destination.unlink()
            except FileNotFoundError:
                pass
            raise


class VerifiedArchive:
    """Read-only pinned archive capability; never reveals its filesystem path."""

    def __init__(self, descriptor: int, *, owner: int, size: int,
                 sha256: str, receipt: dict):
        self._fd = descriptor
        self._owner, self._size, self._sha256 = owner, size, sha256
        self.receipt_sha256 = digest(receipt)

    def _verify(self) -> None:
        if self._fd is None:
            raise SlotBackupError("verified archive is closed")
        meta = os.fstat(self._fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink < 1 \
                or meta.st_uid != self._owner or stat.S_IMODE(meta.st_mode) != 0o600 \
                or meta.st_size != self._size:
            raise SlotBackupError("verified archive identity changed")
        os.lseek(self._fd, 0, os.SEEK_SET)
        hasher = hashlib.sha256()
        while True:
            chunk = os.read(self._fd, 1024 * 1024)
            if not chunk: break
            hasher.update(chunk)
        os.lseek(self._fd, 0, os.SEEK_SET)
        if hasher.hexdigest() != self._sha256:
            raise SlotBackupError("verified archive digest changed")

    def fileno(self) -> int:
        self._verify()
        return self._fd

    def read(self, size: int = -1) -> bytes:
        self._verify()
        if not isinstance(size, int) or isinstance(size, bool):
            raise SlotBackupError("verified archive read size is invalid")
        return os.read(self._fd, self._size if size < 0 else min(size, self._size))

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd); self._fd = None

    def __enter__(self):
        self._verify(); return self

    def __exit__(self, *_): self.close()


class FixedSlotProtectedBackup:
    """Create one exact backup selected solely by protected slot configuration."""

    def __init__(self, config_root: Path, evidence: BackupEvidenceProvider,
                 backend: BackupCaptureBackend, state_root: Path | None = None, *,
                 _test_owner_uid: int | None = None,
                 _test_effective_uid: int | None = None):
        self.root = Path(config_root)
        self.state_root=Path(state_root) if state_root is not None else None
        self.owner = 0 if _test_owner_uid is None else _test_owner_uid
        effective = os.geteuid() if _test_effective_uid is None else _test_effective_uid
        if _test_effective_uid is None and effective != 0:
            raise SlotBackupError("slot backup authority requires root")
        if not hasattr(evidence, "quiescence") or not hasattr(backend, "capture"):
            raise SlotBackupError("slot backup dependency is unavailable")
        self.evidence, self.backend = evidence, backend
        self._root_fd = self._open_root()
        self._closed = False
        try:
            self.config = self._read_config()
            self._backup_fds = {slot: self._open_directory(item["backupDirectory"])
                                for slot, item in self.config["slots"].items()}
            base=self.root if self.state_root is None else self.state_root
            self._backup_paths={slot:base/item["backupDirectory"]
                for slot,item in self.config["slots"].items()}
            self._attempts_fd = self._open_directory(
                self.config["attemptsDirectory"])
            self._keys = {slot: self._protected_bytes(item["receiptKeyFile"], 4096)
                          for slot, item in self.config["slots"].items()}
            if any(len(value) < 32 for value in self._keys.values()):
                raise SlotBackupError("slot backup receipt key is too short")
        except Exception:
            os.close(self._root_fd)
            raise

    def _open_root(self) -> int:
        if not self.root.is_absolute() or self.root.is_symlink() \
                or not self.root.is_dir() or self.root.resolve(strict=True) != self.root:
            raise SlotBackupError("slot backup config root is unsafe")
        current = self.root.parent
        while True:
            meta = os.lstat(current)
            writable = meta.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            if stat.S_ISLNK(meta.st_mode) or meta.st_uid not in (0, self.owner) \
                    or writable and not meta.st_mode & stat.S_ISVTX:
                raise SlotBackupError("slot backup ancestry is unsafe")
            if current.parent == current:
                break
            current = current.parent
        meta = self.root.stat()
        if meta.st_uid != self.owner or stat.S_IMODE(meta.st_mode) != 0o700:
            raise SlotBackupError("slot backup config root is unsafe")
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                     | getattr(os, "O_CLOEXEC", 0))
        opened = os.fstat(fd)
        if not stat.S_ISDIR(opened.st_mode) or opened.st_uid != self.owner \
                or stat.S_IMODE(opened.st_mode) != 0o700:
            os.close(fd)
            raise SlotBackupError("opened slot backup root is unsafe")
        return fd

    def _protected_bytes(self, name: str, maximum: int) -> bytes:
        if SAFE.fullmatch(name or "") is None:
            raise SlotBackupError("protected backup filename is unsafe")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=self._root_fd)
        try:
            meta = os.fstat(fd)
            if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 \
                    or meta.st_uid != self.owner or stat.S_IMODE(meta.st_mode) != 0o400 \
                    or not 1 <= meta.st_size <= maximum:
                raise SlotBackupError("protected backup file is unsafe")
            raw = os.read(fd, maximum + 1)
            if len(raw) != meta.st_size:
                raise SlotBackupError("protected backup file changed while reading")
            return raw
        finally:
            os.close(fd)

    def _read_config(self) -> dict:
        raw = self._protected_bytes(CONFIG, MAX_CONFIG)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise SlotBackupError("slot backup config is invalid") from error
        required = {"format", "attemptsDirectory", "slots"}
        if not isinstance(value, dict) or set(value) != required \
                or raw != canonical(value) \
                or value.get("format") not in ("openepm-macos-pilot-slot-backup-v1",
                    "openepm-macos-pilot-slot-backup-v2") \
                or SAFE.fullmatch(str(value.get("attemptsDirectory"))) is None \
                or not isinstance(value.get("slots"), dict) \
                or set(value["slots"]) != {"blue", "green"} \
                or value.get("format").endswith("-v2") and self.state_root is None:
            raise SlotBackupError("slot backup config differs")
        distinct = {key: set() for key in ("databaseVolume", "backupDirectory",
                                            "receiptKeyFile", "sourceIdentity")}
        keys = {"database", "systemIdentifier", "databaseVolume", "sourceIdentity",
                "backupDirectory", "receiptKeyFile", "manifestFile",
                "containerImage", "dockerExecutable"}
        for item in value["slots"].values():
            if not isinstance(item, dict) or set(item) != keys \
                    or any(SAFE.fullmatch(str(item.get(key))) is None for key in
                           ("database", "databaseVolume", "sourceIdentity",
                            "backupDirectory", "receiptKeyFile", "manifestFile")) \
                    or not str(item.get("systemIdentifier", "")).isdecimal():
                raise SlotBackupError("slot backup binding is invalid")
            executable = item.get("dockerExecutable")
            executable_keys = ({"path", "sha256", "ownerUid", "mode"}
                if value.get("format").endswith("-v2") else
                {"path", "sha256", "device", "inode", "ownerUid", "mode"})
            if not isinstance(executable, dict) or set(executable) != executable_keys \
                    or not isinstance(item.get("containerImage"), str) \
                    or not item["containerImage"].startswith("sha256:"):
                raise SlotBackupError("slot backup executable binding is invalid")
            for key, seen in distinct.items():
                if item[key] in seen:
                    raise SlotBackupError("slot backup resources must be distinct")
                seen.add(item[key])
        return value

    def _open_directory(self, name: str) -> int:
        if self.state_root is None:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=self._root_fd)
        else:
            if not self.state_root.is_absolute() or self.state_root.is_symlink() \
                    or not self.state_root.is_dir():
                raise SlotBackupError("slot backup state root is unsafe")
            fd=os.open(self.state_root/name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        meta = os.fstat(fd)
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != self.owner \
                or stat.S_IMODE(meta.st_mode) != 0o700:
            os.close(fd)
            raise SlotBackupError("slot backup directory is unsafe")
        return fd

    def _verified_directory_path(self,slot:str)->Path:
        path=self._backup_paths[slot]
        if path.is_symlink() or not path.is_dir():
            raise SlotBackupError("slot backup directory path changed")
        observed=path.stat();opened=os.fstat(self._backup_fds[slot])
        if (observed.st_dev,observed.st_ino)!=(opened.st_dev,opened.st_ino) \
                or observed.st_uid!=self.owner \
                or stat.S_IMODE(observed.st_mode)!=0o700:
            raise SlotBackupError("slot backup directory path changed")
        return path

    def _contract_binding(self, slot: str, contract: dict) -> dict:
        name = "source" if slot == "blue" else "candidate"
        binding = contract.get(name)
        expected = self.config["slots"][slot]
        if not isinstance(binding, dict) \
                or binding.get("databaseVolume") != expected["databaseVolume"]:
            raise SlotBackupError("slot backup contract binding differs")
        return binding

    def _validate_evidence(self, slot: str, operation: str,
                           contract: dict) -> dict:
        value = self.evidence.quiescence(slot, operation, contract)
        required = {"format", "slot", "activationId", "executionContractSha256",
                    "intentEventSha256", "admissionClosed", "servicesStopped",
                    "fenceClosed", "quiescenceSha256", "evidenceSha256"}
        if not isinstance(value, dict) or set(value) != required \
                or value.get("format") != "openepm-macos-pilot-backup-authority-v1" \
                or value.get("slot") != slot \
                or value.get("activationId") != contract.get("activationId") \
                or value.get("executionContractSha256") \
                    != contract.get("executionContractSha256") \
                or value.get("intentEventSha256") != operation \
                or value.get("admissionClosed") is not True \
                or value.get("servicesStopped") is not True \
                or value.get("fenceClosed") is not True \
                or SHA.fullmatch(str(value.get("quiescenceSha256"))) is None \
                or value.get("evidenceSha256") != digest({key: item for key, item
                    in value.items() if key != "evidenceSha256"}):
            raise SlotBackupError("slot backup authority differs")
        return value

    def _read_json(self, directory_fd: int, name: str) -> dict | None:
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        except FileNotFoundError:
            return None
        try:
            meta = os.fstat(fd)
            if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 \
                    or meta.st_uid != self.owner or stat.S_IMODE(meta.st_mode) != 0o600 \
                    or not 1 <= meta.st_size <= MAX_CONFIG:
                raise SlotBackupError("slot backup receipt is unsafe")
            raw = os.read(fd, MAX_CONFIG + 1)
        finally:
            os.close(fd)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise SlotBackupError("slot backup receipt is invalid") from error
        if not isinstance(value, dict) or raw != canonical(value):
            raise SlotBackupError("slot backup receipt is invalid")
        return value

    def _atomic_bytes(self, directory_fd: int, name: str, payload: bytes) -> None:
        temporary = f".{name}.{uuid.uuid4().hex}.partial"
        fd = None
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
            offset = 0
            while offset < len(payload):
                written = os.write(fd, payload[offset:])
                if written < 1:
                    raise OSError("slot backup write made no progress")
                offset += written
            os.fchmod(fd, 0o600)
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.rename(temporary, name, src_dir_fd=directory_fd,
                      dst_dir_fd=directory_fd)
            os.fsync(directory_fd)
        finally:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except FileNotFoundError:
                pass

    def _verify_archive(self, directory_fd: int, name: str,
                        expected: dict) -> None:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
        try:
            meta = os.fstat(fd)
            if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 \
                    or meta.st_uid != self.owner or stat.S_IMODE(meta.st_mode) != 0o600 \
                    or meta.st_size != expected["bytes"]:
                raise SlotBackupError("protected backup archive is unsafe")
            hasher = hashlib.sha256()
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
            if hasher.hexdigest() != expected["sha256"]:
                raise SlotBackupError("protected backup archive digest differs")
        finally:
            os.close(fd)

    def create(self, slot: str, operation_key: str, contract: dict) -> dict:
        if self._closed:
            raise SlotBackupError("slot backup authority is closed")
        if slot not in ("blue", "green") or not isinstance(operation_key, str) \
                or SHA.fullmatch(operation_key) is None or not isinstance(contract, dict):
            raise SlotBackupError("slot backup request is invalid")
        claimed = contract.get("executionContractSha256")
        if not isinstance(claimed, str) or SHA.fullmatch(claimed) is None \
                or digest({key: value for key, value in contract.items()
                           if key != "executionContractSha256"}) != claimed:
            raise SlotBackupError("slot backup contract digest differs")
        self._contract_binding(slot, contract)
        authority = self._validate_evidence(slot, operation_key, contract)
        binding = self.config["slots"][slot]
        request = digest({"slot": slot, "operationKey": operation_key,
                          "contractSha256": claimed,
                          "authoritySha256": authority["evidenceSha256"],
                          "binding": binding})
        name = f"{operation_key}.json"
        lock = os.open("backup.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW,
                       0o600, dir_fd=self._attempts_fd)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX)
            prior = self._read_json(self._attempts_fd, name)
            if prior is not None:
                if prior.get("requestSha256") != request:
                    raise SlotBackupError("slot backup replay differs")
                signed = {key: item for key, item in prior.items()
                          if key != "receiptHmacSha256"}
                expected_hmac = hmac.new(self._keys[slot], canonical(signed),
                                         hashlib.sha256).hexdigest()
                if not hmac.compare_digest(str(prior.get("receiptHmacSha256")),
                                           expected_hmac):
                    raise SlotBackupError("slot backup receipt authentication differs")
                self._verify_archive(self._backup_fds[slot], prior["archiveName"],
                                     prior["backup"])
                return prior
            archive_name = f"{operation_key}.dump"
            temporary_name = f".{archive_name}.{uuid.uuid4().hex}.capture"
            destination = self._verified_directory_path(slot) / temporary_name
            try:
                result = self.backend.capture(dict(binding), destination)
            except BaseException:
                try:
                    os.unlink(temporary_name, dir_fd=self._backup_fds[slot])
                except FileNotFoundError:
                    pass
                raise
            if not isinstance(result, dict) or set(result) != {
                    "database", "systemIdentifier", "databaseVolume", "sourceIdentity", "bytes",
                    "sha256", "catalogEntries", "aclEntries", "catalogSha256"} \
                    or result.get("database") != binding["database"] \
                    or result.get("systemIdentifier") != binding["systemIdentifier"] \
                    or result.get("databaseVolume") != binding["databaseVolume"] \
                    or result.get("sourceIdentity") != binding["sourceIdentity"] \
                    or not isinstance(result.get("bytes"), int) \
                    or isinstance(result.get("bytes"), bool) or result["bytes"] < 1 \
                    or SHA.fullmatch(str(result.get("sha256"))) is None \
                    or not isinstance(result.get("catalogEntries"), int) \
                    or result["catalogEntries"] < 1 \
                    or not isinstance(result.get("aclEntries"), int) \
                    or result["aclEntries"] < 1 \
                    or SHA.fullmatch(str(result.get("catalogSha256"))) is None:
                raise SlotBackupError("backup capture evidence differs")
            # Verify backend output independently before atomic publication.
            capture_fd = os.open(temporary_name, os.O_RDONLY | os.O_NOFOLLOW,
                                 dir_fd=self._backup_fds[slot])
            try:
                meta = os.fstat(capture_fd)
                if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 \
                        or meta.st_uid != self.owner or stat.S_IMODE(meta.st_mode) != 0o600 \
                        or meta.st_size != result["bytes"]:
                    raise SlotBackupError("captured backup archive is unsafe")
                hasher = hashlib.sha256()
                while True:
                    chunk = os.read(capture_fd, 1024 * 1024)
                    if not chunk:
                        break
                    hasher.update(chunk)
                if hasher.hexdigest() != result["sha256"]:
                    raise SlotBackupError("captured backup digest differs")
                os.fsync(capture_fd)
            finally:
                os.close(capture_fd)
            os.rename(temporary_name, archive_name,
                      src_dir_fd=self._backup_fds[slot],
                      dst_dir_fd=self._backup_fds[slot])
            os.fsync(self._backup_fds[slot])
            body = {"format": "openepm-macos-pilot-slot-backup-receipt-v1",
                    "slot": slot, "operationKey": operation_key,
                    "requestSha256": request, "activationId": contract["activationId"],
                    "executionContractSha256": claimed,
                    "authoritySha256": authority["evidenceSha256"],
                    "archiveName": archive_name, "backup": result}
            signature = hmac.new(self._keys[slot], canonical(body),
                                 hashlib.sha256).hexdigest()
            receipt = {**body, "receiptHmacSha256": signature}
            self._atomic_bytes(self._attempts_fd, name, canonical(receipt))
            self._atomic_bytes(self._backup_fds[slot], binding["manifestFile"],
                               canonical(receipt))
            return receipt
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
            os.close(lock)

    def verify(self, slot: str, operation_key: str, contract: dict) -> dict:
        """Freshly verify authority, receipt authentication and archive; never create."""
        if self._closed or slot not in ("blue", "green") \
                or SHA.fullmatch(operation_key or "") is None:
            raise SlotBackupError("slot backup verification request is invalid")
        claimed = contract.get("executionContractSha256") if isinstance(contract, dict) else None
        if not isinstance(claimed, str) or digest({key: value for key, value
                in contract.items() if key != "executionContractSha256"}) != claimed:
            raise SlotBackupError("slot backup contract digest differs")
        self._contract_binding(slot, contract)
        authority = self._validate_evidence(slot, operation_key, contract)
        binding = self.config["slots"][slot]
        request = digest({"slot": slot, "operationKey": operation_key,
            "contractSha256": claimed, "authoritySha256": authority["evidenceSha256"],
            "binding": binding})
        receipt = self._read_json(self._attempts_fd, f"{operation_key}.json")
        if receipt is None or receipt.get("requestSha256") != request:
            raise SlotBackupError("protected backup receipt is unavailable")
        signed = {key: item for key, item in receipt.items()
                  if key != "receiptHmacSha256"}
        expected = hmac.new(self._keys[slot], canonical(signed), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(str(receipt.get("receiptHmacSha256")), expected):
            raise SlotBackupError("slot backup receipt authentication differs")
        self._verify_archive(self._backup_fds[slot], receipt["archiveName"],
                             receipt["backup"])
        return receipt

    def open_verified_archive(self, operation_key: str, contract: dict,
                              slot: str) -> VerifiedArchive:
        """Return an exact read-only fd after fresh authority and receipt checks."""
        receipt = self.verify(slot, operation_key, contract)
        expected = receipt["backup"]
        descriptor = os.open(receipt["archiveName"], os.O_RDONLY | os.O_NOFOLLOW
                             | getattr(os, "O_CLOEXEC", 0),
                             dir_fd=self._backup_fds[slot])
        try:
            meta = os.fstat(descriptor)
            if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1 \
                    or meta.st_uid != self.owner or stat.S_IMODE(meta.st_mode) != 0o600 \
                    or meta.st_size != expected["bytes"]:
                raise SlotBackupError("protected archive handoff is unsafe")
            capability = VerifiedArchive(descriptor, owner=self.owner,
                size=expected["bytes"], sha256=expected["sha256"], receipt=receipt)
            capability._verify()
            descriptor = None
            return capability
        finally:
            if descriptor is not None: os.close(descriptor)

    def close(self) -> None:
        if self._closed:
            return
        for fd in (*self._backup_fds.values(), self._attempts_fd, self._root_fd):
            os.close(fd)
        self._closed = True
