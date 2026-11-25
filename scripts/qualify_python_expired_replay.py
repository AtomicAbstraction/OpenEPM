#!/usr/bin/env python3
"""Qualify native Python original-only replay in an owned disposable database."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,''):
    sys.path.insert(0,str(ROOT))

from scripts import qualify_native_member_selection as harness

SUITE='python-expired-replay'
SOURCE_FILES=(
    'epm_core/python_execution_contract.py',
    'epm_core/public_program_contracts.py',
    'epm_core/public_program_diagnostics.py',
    'epm_core/python_program_execution.py',
    'openepm/diagnostics.py',
    'epm_core/postgres_python_build_public.py',
    'epm_core/postgres_python_program_repository.py',
    'epm_core/postgres_python_run.py',
    'epm_core/postgres_python_workflow.py',
    'epm_core/expired_operation_replay.py',
    'epm_core/operation_admission_contract.py',
    'epm_core/postgres_language_v2.py',
    'epm_core/postgres_mcp_application.py',
    'epm_core/postgres_mcp_router.py',
    'epm_core/postgres_access.py',
    'epm_core/postgres_dimensional_scope.py',
    'epm_core/postgres_execution_delegations.py',
    'epm_core/python_plan_runner.py',
    'platform_postgres_web_http.py',
    'platform_postgres_mcp_server.py',
    'platform_postgres_router_mcp_server.py',
    'openepm/client.py',
    'tests/test_openepm_sdk.py',
    'tests/test_python_expired_replay_postgres.py',
    'tests/test_python_historical_read.py',
    'tests/test_definition_owner_lifecycle_postgres.py',
    'tests/test_python_execution_contract.py',
    'tests/test_python_build_public_api.py',
    'tests/test_python_run_public.py',
    'tests/test_expired_operation_replay_discovery.py',
    'tests/test_python_save_validation_postgres.py',
    'tests/test_python_diagnostics_postgres.py',
    'tests/test_postgres_numeric_store.py',
    'tests/disposable_storage_fixture.py',
    'scripts/qualify_python_expired_replay.py',
    'scripts/qualify_native_member_selection.py',
    'scripts/audit_disposable_docker_cleanup_candidates.py',
)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true',required=True)
    parser.add_argument('--database-image',required=True)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    harness.TEST_SUITES[SUITE]=('tests.test_definition_owner_lifecycle_postgres',
        'DefinitionOwnerLifecyclePostgresTests','openepm-python-expired-replay-qualification-v1')
    harness.TEST_CASES[SUITE]=('tests.test_python_expired_replay_postgres.PythonExpiredReplayPostgresTests',
        'tests.test_definition_owner_lifecycle_postgres.DefinitionOwnerLifecyclePostgresTests.'
        'test_schema_inventory_covers_current_typed_reference_dependencies')
    harness.SOURCE_FILES=SOURCE_FILES
    proof=harness.qualify(output=args.output,database_image=args.database_image,test_suite=SUITE)
    proof['invocation']['argv']=[sys.executable,'-m','scripts.qualify_python_expired_replay',
        '--execute','--database-image',args.database_image,'--output',str(args.output)]
    proof['scope']={
        'functions':['python.program.build','python.program.test','python.program.run'],
        'historicalReads':'Existing build/workflow read tools also accept original_request under current READ, original actor and stored dimensional scope; original signature is authenticated independently of expiry. No execution, build or new work is permitted by inspection.',
        'transports':'Actual browser dispatcher and MCP application facade plus direct fixed core; verified identity is the fixture seam, no installed host/HTTP/OIDC claim.',
        'fixture':'Fresh migrated PostgreSQL, sparse custom-axis kernel applications, current source Save/Validation/activation, native delegation and Plan worker. Trusted test launcher executes known fixture source; no OS sandbox qualification claim.',
        'authority':'Exact signed actor/scope/function/program; current native grant and dimensional scope. Build keeps original-before-fresh-source semantics; workflow additionally checks current original source and delegation.',
        'effects':'Expired replay only reads existing native records; no new build, artifact, workflow, job, receipt or inline advance. Known-ID reads remain separately authorized.',
    }
    harness.write_json(args.output,proof)
    print(f'Passed {proof["testsRun"]} native Python replay cases; cleanup verified; {args.output}')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
