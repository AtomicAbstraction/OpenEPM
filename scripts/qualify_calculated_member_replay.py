#!/usr/bin/env python3
"""Qualify original-only materialization lookup with owned native fixtures."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,''):
    sys.path.insert(0,str(ROOT))

from scripts import qualify_native_member_selection as harness
from scripts.qualify_public_sequence_replacement import SOURCE_FILES as BASE_FILES

SUITE='calculated-member-replay'
SOURCE_FILES=tuple(dict.fromkeys((*BASE_FILES,
    'epm_core/postgres_jobs.py','epm_core/postgres_calculated_members.py',
    'epm_core/expired_operation_replay.py','epm_core/operation_admission_contract.py',
    'epm_core/postgres_mcp_application.py','epm_core/postgres_mcp_router.py',
    'epm_core/postgres_dimensional_scope.py','platform_postgres_web_http.py',
    'tests/test_calculated_member_replay.py','tests/test_calculated_member_replay_postgres.py',
    'tests/test_expired_operation_replay_discovery.py',
    'tests/test_definition_owner_lifecycle_postgres.py',
    'scripts/qualify_calculated_member_replay.py')))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true',required=True)
    parser.add_argument('--database-image',required=True)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    harness.TEST_SUITES[SUITE]=('tests.test_definition_owner_lifecycle_postgres',
        'DefinitionOwnerLifecyclePostgresTests','openepm-calculated-member-replay-qualification-v1')
    harness.TEST_CASES[SUITE]=(
        'tests.test_calculated_member_replay_postgres.CalculatedMemberReplayPostgresTests',
        'tests.test_definition_owner_lifecycle_postgres.DefinitionOwnerLifecyclePostgresTests.test_schema_inventory_covers_current_typed_reference_dependencies')
    harness.SOURCE_FILES=SOURCE_FILES
    proof=harness.qualify(output=args.output,database_image=args.database_image,test_suite=SUITE)
    proof['invocation']['argv']=[sys.executable,'-m','scripts.qualify_calculated_member_replay',
        '--execute','--database-image',args.database_image,'--output',str(args.output)]
    proof['scope']={
        'function':'calculated.member.materialize',
        'transports':'Actual browser submit dispatcher, MCP submit facade and fixed language; verified identity is a fixture seam.',
        'positive':'Original ready and published jobs remain exact after changed source Save and admission/preview expiry; materialized7 is read through native calculation.scan.',
        'authority':'Current WRITE and rule_run plus original actor/application and exact effective dimensional scope. Full original request descriptor and signed preview bind dependencies, normalization and source-owner pins.',
        'negative':'Missing original, tampered preview/program/pins/dependencies, foreign actor/application, wrong route, revoked run/write and changed dimensional scope cannot create work.',
        'effects':'Full row snapshots unchanged across lookup; preparation/compilation/submission explicitly prohibited on replay. All final worker publication fences remain unchanged.',
        'limits':'Trusted source builder and isolated database; no browser rendering, external OIDC/host, packaged sandbox or operating-system crash claim.'}
    harness.write_json(args.output,proof)
    print(f'Passed {proof["testsRun"]} native materialization/schema cases; cleanup verified; {args.output}')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
