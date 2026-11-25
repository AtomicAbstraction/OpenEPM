#!/usr/bin/env python3
"""Qualify saved-rule original-only replay using owned native source fixtures."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from scripts import qualify_native_member_selection as harness
from scripts.qualify_public_sequence_replacement import SOURCE_FILES as BASE_FILES

SUITE = 'application-rule-expired-replay'
SOURCE_FILES = tuple(dict.fromkeys((*BASE_FILES,
    'epm_core/expired_operation_replay.py',
    'epm_core/operation_admission_contract.py',
    'epm_core/processing_operation_registry.py',
    'epm_core/postgres_mcp_router.py',
    'epm_core/postgres_dimensional_scope.py',
    'platform_postgres_web_http.py',
    'tests/test_application_rule_workflow.py',
    'epm_core/python_plan_runner.py',
    'epm_core/postgres_job_origin.py',
    'epm_core/postgres_application_rule_dispatch.py',
    'epm_core/postgres_worker_service.py',
    'tests/test_definition_owner_lifecycle_postgres.py',
    'tests/test_expired_operation_replay_discovery.py',
    'scripts/qualify_application_rule_expired_replay.py')))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.add_argument('--database-image', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    harness.TEST_SUITES[SUITE] = ('tests.test_definition_owner_lifecycle_postgres',
        'DefinitionOwnerLifecyclePostgresTests', 'openepm-application-rule-replay-qualification-v1')
    harness.TEST_CASES[SUITE] = (
        'tests.test_public_numeric_sequence_owner.PublicSequenceReplacementPostgresTests',
        'tests.test_definition_owner_lifecycle_postgres.DefinitionOwnerLifecyclePostgresTests.'
        'test_schema_inventory_covers_current_typed_reference_dependencies',
    )
    harness.SOURCE_FILES = SOURCE_FILES
    proof = harness.qualify(output=args.output, database_image=args.database_image, test_suite=SUITE)
    proof['invocation']['argv'] = [sys.executable, '-m', 'scripts.qualify_application_rule_expired_replay',
        '--execute', '--database-image', args.database_image, '--output', str(args.output)]
    proof['scope'] = {
        'function': 'application.rule.run',
        'transports': 'Actual browser dispatcher and MCP application facade plus direct fixed core; verified identity is the fixture seam. No installed HTTP, external MCP host or OIDC claim.',
        'fixture': 'Fresh fully migrated PostgreSQL, two sparse custom-axis applications, current source Save/Validation/activation and normal worker publication. Trusted reviewed source uses the existing in-process builder fixture; no OS sandbox proof.',
        'authority': 'Signed exact actor/application/function/program; native current WRITE, rule_run and effective dimensional scope. Historical original lookup deliberately does not require the current executable source or reseal it.',
        'effects': 'Full workflow, child, build, artifact, job, receipt and application-state row snapshots remain equal across lookups. Missing original never creates or advances work. Separate known-ID reads use native READ authority.',
        'recovery': 'Real durable acceptance followed by injected eager-advance failure; exact expired replay returns the original. Two-unit cases commit the first child, accept the second and lose its reply before the parent checkpoint. A new coordinator binds the same retained child without preview/submission or source sealing. Normal recovery publishes both once; native grant revocation preserves the committed prefix and blocks the remaining effect. No operating-system crash injected.',
    }
    harness.write_json(args.output, proof)
    print(f'Passed {proof["testsRun"]} native source/rule replay cases; cleanup verified; {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
