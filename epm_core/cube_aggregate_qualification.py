"""Order-balanced evidence recorder for the public aggregate route candidate."""
from __future__ import annotations

from hashlib import sha256
import json
import time
from typing import Callable, Mapping

from .cube_aggregate_acceleration import (ACCELERATED, FORMAT, MIN_PAIRS,
                                          NATIVE)


def _digest(value: object) -> str:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError('PGDUCKDB_ROUTE_RESULT_INVALID') from error
    return sha256(raw).hexdigest()


class PairedPublicAggregateQualification:
    """Measure the whole supplied request callable, not a SQL fragment.

    ``run`` is a qualification-only server adapter.  It receives the requested
    candidate profile and must return the backend actually selected plus the
    complete public result and its exact source pins.  Production callers never
    receive this requested-backend argument.
    """

    def __init__(self, *, profile: Mapping[str, object],
                 controls: Mapping[str, bool],
                 run: Callable[[str, str], Mapping[str, object]],
                 clock: Callable[[], float] | None = None):
        if (type(profile) is not dict or type(controls) is not dict
                or not callable(run) or (clock is not None and not callable(clock))):
            raise ValueError('PGDUCKDB_HARNESS_CONFIGURATION_INVALID')
        self.profile = dict(profile)
        self.controls = dict(controls)
        self.run = run
        self.clock = clock or time.perf_counter

    def record(self, *, pairs: int = MIN_PAIRS) -> dict:
        if type(pairs) is not int or not MIN_PAIRS <= pairs <= 100:
            raise ValueError('PGDUCKDB_HARNESS_PAIR_COUNT_INVALID')
        samples = []
        for index in range(pairs):
            pair_id = f'pair-{index:03d}'
            order = ((NATIVE, ACCELERATED) if index % 2 == 0
                     else (ACCELERATED, NATIVE))
            for requested in order:
                before = self.clock()
                response = self.run(requested, pair_id)
                after = self.clock()
                if (type(before) not in (int, float)
                        or type(after) not in (int, float) or after <= before
                        or type(response) is not dict
                        or set(response) != {'selectedBackend', 'result',
                                             'sourcePins'}
                        or response['selectedBackend'] not in
                           (NATIVE, ACCELERATED, 'execution_error')):
                    raise ValueError('PGDUCKDB_HARNESS_RESPONSE_INVALID')
                samples.append({'pairId': pair_id,
                    'requestedBackend': requested,
                    'selectedBackend': response['selectedBackend'],
                    'endToEndMs': (after - before) * 1000,
                    'resultDigest': _digest(response['result']),
                    'sourcePinsDigest': _digest(response['sourcePins'])})
        return {'format': FORMAT, 'profile': self.profile,
                'controls': self.controls, 'samples': samples}
