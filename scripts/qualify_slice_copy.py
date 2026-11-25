#!/usr/bin/env python3
"""Qualify the generic public slice-copy owner on disposable PostgreSQL."""
from __future__ import annotations
import argparse
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,''):sys.path.insert(0,str(ROOT))
from scripts import qualify_native_member_selection as harness
from scripts.qualify_public_read_contract import SOURCE_FILES as READ_SOURCE_FILES

SUITE='slice-copy'
SOURCE_FILES=(*READ_SOURCE_FILES,'epm_core/slice_copy_contract.py',
    'epm_core/mcp_function_routing.py',
    'epm_core/postgres_planning_copy.py','epm_core/postgres_source_batch.py',
    'epm_core/postgres_dimensional_security_enforcement.py','tests/test_slice_copy_contract.py',
    'tests/test_generic_model_scenarios_postgres.py','scripts/qualify_slice_copy.py')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true',required=True)
    parser.add_argument('--database-image',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    # Anchor cleanup inspection to the actual maintained fixture owner; the
    # slice test class composes that owner through another wrapper level.
    harness.TEST_SUITES[SUITE]=('tests.test_expired_operation_replay_postgres','ExpiredOperationReplayPostgresTests',
        'openepm-public-slice-copy-qualification-v1')
    harness.TEST_CASES[SUITE]=('tests.test_slice_copy_contract.SliceCopyPostgresTests',
        'tests.test_expired_operation_replay_postgres.ExpiredOperationReplayPostgresTests',
        'tests.test_generic_model_scenarios_postgres.GenericModelScenariosPostgresTests')
    harness.SOURCE_FILES=SOURCE_FILES
    proof=harness.qualify(output=args.output,database_image=args.database_image,test_suite=SUITE)
    proof['invocation']['argv']=[sys.executable,'-m','scripts.qualify_slice_copy','--execute',
        '--database-image',args.database_image,'--output',str(args.output)]
    proof['scope']={'currentFix':'One discoverable generic axis-member copy prepares through the existing source-batch/provenance owner. Independent source READ and destination WRITE include implicit clears; exact replay does not rebase.',
        'transport':'Real PostgreSQL plus browser dispatcher/MCP application facade with explicit verified-identity fixture seam. No external HTTP/provider/JSON-RPC or installed image claim.',
        'fixtures':'Four sparse-kernel security/routing/replay/presence cases plus existing native replay and three public eight-role worked-domain fixtures. No shared business data.',
        'legacy':'Planning-named copy remains retired from public discovery; no public alias or policy-preset revival.'}
    harness.write_json(args.output,proof)
    print(f'Passed {proof["testsRun"]} isolated cases; cleanup verified; evidence: {args.output}')
    return 0


if __name__=='__main__':raise SystemExit(main())
