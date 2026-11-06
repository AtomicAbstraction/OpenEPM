"""Fixed-core deadline context; no dependency on an MCP SDK or client program."""
from contextlib import contextmanager
from contextvars import ContextVar
import math
import time

_deadline = ContextVar('epm_server_tool_deadline', default=None)


class ToolDeadlineExpired(TimeoutError):
    pass


def current_deadline():
    return _deadline.get()


def remaining_milliseconds():
    deadline = _deadline.get()
    if deadline is None:
        return None
    remaining = deadline-time.monotonic()
    if remaining <= 0:
        raise ToolDeadlineExpired()
    return max(1, math.ceil(remaining*1000))


@contextmanager
def tool_execution_scope(deadline):
    if type(deadline) not in (float, int) or not math.isfinite(deadline):
        raise ValueError('Invalid server tool deadline')
    token = _deadline.set(deadline)
    try:
        remaining_milliseconds()
        yield
    finally:
        _deadline.reset(token)
