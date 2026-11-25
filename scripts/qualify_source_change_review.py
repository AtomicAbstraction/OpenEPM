#!/usr/bin/env python3
"""Qualify exact source change review semantics on an owned disposable PostgreSQL.

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


SUITE = 'source-change-review'
SOURCE_FILES = (
    'epm_core/postgres_source_batch.py',
    'epm_core/postgres_language_v2.py',
    'epm_core/postgres_dimensional_security_enforcement.py',
    'epm_core/postgres_dimensional_security.py',
    'epm_core/postgres_access.py',
    'epm_core/persistence_contract.py',
    'epm_core/postgres_line_detail.py',
    'epm_core/postgres_numeric_store.py',
    'tests/test_source_change_review_postgres.py',
    'tests/test_postgres_numeric_store.py',
    'tests/disposable_storage_fixture.py',
    'scripts/qualify_source_change_review.py',
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
        'tests.test_source_change_review_postgres',
        'SourceChangeReviewPostgresTests',
        'openepm-source-change-review-qualification-v1',
    )
    harness.TEST_CASES[SUITE] = (
        'tests.test_source_change_review_postgres.SourceChangeReviewPostgresTests',
    )
    harness.SOURCE_FILES = SOURCE_FILES
    proof = harness.qualify(output=args.output,
        database_image=args.database_image, test_suite=SUITE)
    proof['invocation']['argv'] = [sys.executable, '-m',
        'scripts.qualify_source_change_review', '--execute',
        '--database-image', args.database_image, '--output', str(args.output)]
    proof['scope'] = {
        'currentFix': 'Bounded current source before/after samples, READ filtering, typed supporting-detail companions and final revision consistency fence.',
        'countSemantics': 'Original source set/clear counts are unchanged; companion changes describe linked effects and do not add fact counts.',
        'fixture': 'Fresh migrated PostgreSQL and disposable sparse custom-axis kernel applications; not public eight-axis application creation.',
        'transport': 'Typed V2 source functions through the fixed core; no external MCP host, browser or deployed image qualification.',
        'authority': 'Current write admission and independent coordinate READ policy; preview does not grant publication authority.',
    }
    harness.write_json(args.output, proof)
    print(f'Passed {proof["testsRun"]} isolated cases; cleanup verified; evidence: {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
