"""Make repository-owned operator scripts directly executable from any cwd.

Production images install packages normally. Source-tree operators are also
documented as ``python3 /path/to/scripts/name.py`` commands, where Python puts
only ``scripts/`` on ``sys.path``.  This small bootstrap adds the repository
root without depending on the caller's working directory or ``PYTHONPATH``.
"""
from __future__ import annotations

from pathlib import Path
import sys


def ensure_project_root() -> Path:
    root = Path(__file__).resolve().parents[1]
    value = str(root)
    if value not in sys.path:
        sys.path.insert(0, value)
    return root

