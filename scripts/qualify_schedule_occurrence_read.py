#!/usr/bin/env python3
"""Qualify bounded schedule occurrence reads on an owned disposable PostgreSQL.

Reuse the maintained ownership, full-migration and cleanup harness. No supplied
database DSN, shared application, deployment or public-family retirement occurs.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from scripts import qualify_native_member_selection as harness


SUITE = 'schedule-occurrence-read'
SOURCE_FILES = (
    'epm_core/postgres_application_schedules.py',
    'epm_core/postgres_tasks.py',
    'epm_core/postgres_application_schedule_worker.py',
    'epm_core/postgres_application_schedule_dispatch.py',
    'epm_core/postgres_access.py',
    'epm_core/postgres_language_v2.py',
    'epm_core/postgres_mcp_application.py',
    'epm_core/postgres_mcp_router.py',
    'platform_postgres_web_http.py',
    'tests/test_schedule_occurrence_read_postgres.py',
    'tests/test_application_schedule_public_adapter.py',
    'tests/test_postgres_numeric_store.py',
    'tests/source_definition_authoring_fixture.py',
    'tests/disposable_storage_fixture.py',
    'scripts/qualify_schedule_occurrence_read.py',
    'scripts/qualify_native_member_selection.py',
    'scripts/audit_disposable_docker_cleanup_candidates.py',
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.add_argument('--database-image', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    harness.TEST_SUITES[SUITE] = (
        'tests.test_schedule_occurrence_read_postgres',
        'ScheduleOccurrenceReadPostgresTests',
        'openepm-schedule-occurrence-read-qualification-v1',
    )
    harness.TEST_CASES[SUITE] = (
        'tests.test_schedule_occurrence_read_postgres.ScheduleOccurrenceReadPostgresTests',
    )
    harness.SOURCE_FILES = SOURCE_FILES
    proof = harness.qualify(output=args.output,
        database_image=args.database_image, test_suite=SUITE)
    proof['invocation']['argv'] = [sys.executable, '-m',
        'scripts.qualify_schedule_occurrence_read', '--execute',
        '--database-image', args.database_image, '--output', str(args.output)]
    proof['scope'] = {
        'currentFix': 'Bounded schedule occurrence history reuses existing task owner/admin visibility, exact current definition pins and native task references.',
        'coveredAdapters': 'Real browser dispatcher, MCP application facade with identity fixture seam, and fixed schedule/task core.',
        'fixture': 'Fresh migrated PostgreSQL, source-authored active ApplicationRule and native schedules in disposable sparse kernel applications; not public eight-axis application creation.',
        'transport': 'No external MCP host, HTTP session verification, live browser or deployed image claim.',
        'authority': 'Every page uses current transaction read/admin authorization and native task visibility; occurrence references confer no authority or new effects.',
    }
    harness.write_json(args.output, proof)
    print(f'Passed {proof["testsRun"]} isolated cases; cleanup verified; evidence: {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
