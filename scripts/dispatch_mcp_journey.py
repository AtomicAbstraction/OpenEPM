"""Dispatch pinned request files serially through an existing native MCP CLI.

This helper has no network, token, database or authentication implementation.
It feeds the maintained client's protected local FIFO, journals intent before
dispatch, waits for each acknowledgement, and stops on any failed/unknown result.
"""
from __future__ import annotations

import argparse
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import time


def append_record(stream, value):
    stream.write(json.dumps(value, separators=(",", ":"), allow_nan=False) + "\n")
    stream.flush()
    os.fsync(stream.fileno())


class Responses:
    def __init__(self, path):
        self.stream = path.open("r", encoding="utf-8")
        self.pending = ""
        self.values = {}

    def poll(self):
        self.pending += self.stream.read()
        lines = self.pending.split("\n")
        self.pending = lines.pop()
        for line in lines:
            if not line:
                continue
            value = json.loads(line)
            identity = value.get("id")
            if identity is None:
                if value.get("ok") is False:
                    raise RuntimeError("CLIENT_REJECTED_REQUEST_FRAME")
                continue
            if identity in self.values:
                raise RuntimeError("DUPLICATE_RESPONSE_ID")
            self.values[identity] = value

    def close(self):
        self.stream.close()


def dispatch(request_file, expected_sha256, fifo, response_file, journal_file,
             *, start=0, count=None, timeout=330, progress=None):
    raw = request_file.read_bytes()
    if sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("REQUEST_FILE_DIGEST_MISMATCH")
    lines = raw.splitlines()
    requests = [json.loads(line) for line in lines]
    if len({r["id"] for r in requests}) != len(requests):
        raise ValueError("DUPLICATE_REQUEST_ID")
    if start < 0 or start > len(requests) or (count is not None and count < 1):
        raise ValueError("REQUEST_RANGE_INVALID")
    mode = fifo.lstat()
    if (not stat.S_ISFIFO(mode.st_mode) or mode.st_uid != os.getuid()
            or stat.S_IMODE(mode.st_mode) & 0o077):
        raise ValueError("CLIENT_FIFO_MUST_BE_OWNER_ONLY")
    selected = list(zip(lines, requests))[start:None if count is None else start + count]
    journal_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_fd = os.open(str(journal_file) + ".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    responses = None
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        intents, acknowledged = {}, {}
        if journal_file.exists():
            for line in journal_file.read_text().splitlines():
                item = json.loads(line)
                if item["event"] == "intent":
                    if item["id"] in intents:
                        raise RuntimeError("DUPLICATE_JOURNAL_INTENT")
                    intents[item["id"]] = item
                elif item["event"] == "acknowledged":
                    acknowledged[item["id"]] = item
        responses = Responses(response_file)
        responses.poll()
        # Nonblocking open proves a live reader/holder before any intent is recorded.
        pipe_fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        os.set_blocking(pipe_fd, True)
        with os.fdopen(pipe_fd, "wb", buffering=0) as pipe:
            journal_fd = os.open(journal_file, os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(journal_fd, "a", encoding="utf-8") as journal:
                completed = 0
                for line, request in selected:
                    identity = request["id"]
                    request_digest = sha256(line).hexdigest()
                    prior = intents.get(identity)
                    if prior is not None:
                        if prior["requestSha256"] != request_digest:
                            raise RuntimeError("JOURNEY_INTENT_CHANGED")
                        response = responses.values.get(identity)
                        if response is None:
                            raise RuntimeError("UNKNOWN_OUTCOME_REQUIRES_EXPLICIT_RECONCILIATION:" + identity)
                        if response.get("ok") is not True:
                            raise RuntimeError("PRIOR_REQUEST_FAILED:" + identity)
                        if identity not in acknowledged:
                            append_record(journal, {"event": "acknowledged", "id": identity,
                                                   "response": response})
                    else:
                        if identity in responses.values:
                            raise RuntimeError("UNJOURNALED_RESPONSE_REQUIRES_RECONCILIATION:" + identity)
                        intent = {"event": "intent", "id": identity,
                                  "requestFileSha256": expected_sha256,
                                  "requestSha256": request_digest, "request": request}
                        append_record(journal, intent)
                        intents[identity] = intent
                        payload = memoryview(line + b"\n")
                        while payload:
                            written = pipe.write(payload)
                            if not written:
                                raise RuntimeError("CLIENT_PIPE_WRITE_FAILED:" + identity)
                            payload = payload[written:]
                        deadline = time.monotonic() + timeout
                        while identity not in responses.values:
                            responses.poll()
                            if identity in responses.values:
                                break
                            if time.monotonic() >= deadline:
                                raise RuntimeError("UNKNOWN_OUTCOME_REQUIRES_EXPLICIT_RECONCILIATION:" + identity)
                            time.sleep(0.1)
                        response = responses.values[identity]
                        append_record(journal, {"event": "acknowledged", "id": identity,
                                               "response": response})
                        if response.get("ok") is not True:
                            raise RuntimeError("REQUEST_FAILED:" + identity + ":" +
                                               response.get("error", {}).get("code", "UNKNOWN"))
                    completed += 1
                    if progress and (completed == 1 or completed % 100 == 0 or completed == len(selected)):
                        progress({"completed": completed, "selected": len(selected), "lastId": identity})
        return completed
    finally:
        if responses is not None:
            responses.close()
        os.close(lock_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("requests", "fifo", "responses", "journal"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--requests-sha256", required=True)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--count", type=int)
    args = parser.parse_args()
    dispatch(args.requests, args.requests_sha256, args.fifo, args.responses,
             args.journal, start=args.start, count=args.count,
             progress=lambda value: print(json.dumps(value), flush=True))


if __name__ == "__main__":
    main()
