"""Strict process-local deployment settings outside the public policy model."""
from __future__ import annotations

import os


TOOL_PROCESSES_ENV = 'EPM_MCP_TOOL_PROCESSES_PER_LISTENER'


def configured_tool_processes(maximum: int, environment=None) -> int:
    if type(maximum) is not int or maximum <= 0:
        raise ValueError('A positive tool-process maximum is required')
    environment = os.environ if environment is None else environment
    raw = environment.get(TOOL_PROCESSES_ENV, str(maximum))
    if (not isinstance(raw, str) or not raw.isdecimal()
            or not 1 <= int(raw) <= maximum):
        raise ValueError(TOOL_PROCESSES_ENV+f' must be 1–{maximum}')
    return int(raw)
