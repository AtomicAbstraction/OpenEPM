"""Evaluate a frozen public-route qualification record without enabling it."""
import argparse
import json
from pathlib import Path

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from epm_core.cube_aggregate_acceleration import evaluate_pgduckdb_profile


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('evidence')
    parser.add_argument('--output')
    args = parser.parse_args(argv)
    source = Path(args.evidence)
    decision = evaluate_pgduckdb_profile(json.loads(source.read_text()))
    rendered = json.dumps(decision.wire(), sort_keys=True, indent=2) + '\n'
    if args.output:
        Path(args.output).write_text(rendered)
    else:
        print(rendered, end='')
    return 0 if decision.admitted else 2


if __name__ == '__main__':
    raise SystemExit(main())
