"""Immutable clean-host qualification program executed only in the builder."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path

from openepm import Program


def build(context, parameters):
    if parameters != {}:
        raise ValueError("QUALIFICATION_PARAMETERS_INVALID")
    workspace = Path("/workspace")
    observation = {
        "format": "openepm-builder-observation-v1",
        "sourceExecutionCount": 1,
        "databaseCredentialsPresent": any(
            name.startswith(("EPM_PG_", "PG", "DATABASE_")) for name in os.environ),
        "trustedCorePresent": importlib.util.find_spec("epm_core") is not None,
        "dockerSocketPresent": Path("/var/run/docker.sock").exists(),
        "sourceMounted": (workspace.exists()
            and any(workspace.iterdir())),
    }
    print(json.dumps(observation, sort_keys=True, separators=(",", ":")))
    return Program.one("facts.numeric.batch", {"mutations": [{
        "coordinate": {"Scenario": "Plan"}, "op": "set",
        "value": {"type": "AmountLiteral", "decimal": "17.25000000"},
        "expectedChangeId": "",
    }]})
