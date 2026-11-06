"""Bounded external resource sampler for disposable aggregate benchmarks."""
from __future__ import annotations

import asyncio
import math
import re
import threading
import time


_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class BoundedContainerResourceSampler:
    """Poll a trusted external probe while one MCP lifecycle is in flight.

    The injected probe is the only host integration point.  It must return
    server-owned Docker/cgroup observations; this class neither accepts a
    caller command nor reads business storage.
    """
    def __init__(self, *, container_id: str, image_digest: str, probe,
                 memory_limit_bytes: int, spill_limit_bytes: int,
                 interval_seconds: float = .05, maximum_seconds: float = 120):
        if (type(container_id) is not str or _HEX64.fullmatch(container_id) is None
                or type(image_digest) is not str
                or _HEX64.fullmatch(image_digest) is None or not callable(probe)
                or type(memory_limit_bytes) is not int or memory_limit_bytes <= 0
                or type(spill_limit_bytes) is not int or spill_limit_bytes <= 0
                or isinstance(interval_seconds, bool)
                or not isinstance(interval_seconds, (int, float))
                or not .01 <= interval_seconds <= 1
                or isinstance(maximum_seconds, bool)
                or not isinstance(maximum_seconds, (int, float))
                or not 1 <= maximum_seconds <= 600):
            raise ValueError("PGDUCKDB_BENCHMARK_RESOURCE_SAMPLER_INVALID")
        self.container_id = container_id
        self.image_digest = image_digest
        self.probe = probe
        self.memory_limit_bytes = memory_limit_bytes
        self.spill_limit_bytes = spill_limit_bytes
        self.interval_seconds = float(interval_seconds)
        self.maximum_seconds = float(maximum_seconds)

    def _sample(self):
        value = self.probe(self.container_id)
        required = {"containerId", "imageDigest", "running", "memoryBytes",
                    "temporarySpillBytes"}
        if (type(value) is not dict or set(value) != required
                or value["containerId"] != self.container_id
                or value["imageDigest"] != self.image_digest
                or value["running"] is not True):
            raise ValueError("PGDUCKDB_BENCHMARK_RESOURCE_IDENTITY_MISMATCH")
        for field in ("memoryBytes", "temporarySpillBytes"):
            number = value[field]
            if (type(number) is not int or number < 0
                    or not math.isfinite(float(number))):
                raise ValueError("PGDUCKDB_BENCHMARK_RESOURCE_SAMPLE_INVALID")
        return value

    async def measure(self, operation):
        if not callable(operation):
            raise ValueError("PGDUCKDB_BENCHMARK_RESOURCE_OPERATION_INVALID")
        stop = threading.Event(); samples = []; failures = []
        deadline = time.monotonic() + self.maximum_seconds
        def poll():
            while not stop.is_set():
                if time.monotonic() > deadline:
                    failures.append(ValueError(
                        "PGDUCKDB_BENCHMARK_RESOURCE_SAMPLING_TIMEOUT")); return
                try: samples.append(self._sample())
                except Exception as error:
                    failures.append(error); return
                stop.wait(self.interval_seconds)
        thread = threading.Thread(target=poll, daemon=True); thread.start()
        try:
            response = await operation()
        finally:
            stop.set(); thread.join(timeout=2)
        if thread.is_alive() or failures:
            raise failures[0] if failures else ValueError(
                "PGDUCKDB_BENCHMARK_RESOURCE_SAMPLER_STUCK")
        # Require a distinct start and terminal observation.  Fast operations
        # are sampled once more synchronously rather than inventing a peak.
        if len(samples) < 2:
            samples.append(self._sample())
        peak_memory = max(row["memoryBytes"] for row in samples)
        peak_spill = max(row["temporarySpillBytes"] for row in samples)
        if (peak_memory > self.memory_limit_bytes
                or peak_spill > self.spill_limit_bytes):
            raise ValueError("PGDUCKDB_BENCHMARK_RESOURCE_LIMIT_EXCEEDED")
        return response, {"peakMemoryBytes": peak_memory,
            "spillBytes": peak_spill,
            "memoryLimitBytes": self.memory_limit_bytes,
            "spillLimitBytes": self.spill_limit_bytes}
