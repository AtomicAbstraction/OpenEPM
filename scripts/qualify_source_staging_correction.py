#!/usr/bin/env python3
"""Qualify CSV correction on an owned disposable PostgreSQL fixture only.

Reuses the maintained OwnedDockerRun lifetime, full canonical migrations and
proof-finalization boundary. No separate service, restored snapshot or shared
application is used; the supplied PostgreSQL image remains preexisting.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ''):
    sys.path.insert(0, str(ROOT))

from scripts import qualify_native_member_selection as harness
from scripts.qualify_public_program_contracts import SOURCE_FILES as CONTRACT_SOURCES

SUITE = 'source-staging-correction'
MODULE = 'tests.test_source_staging_correction_postgres'
CLASS = 'SourceStagingCorrectionPostgresTests'
FORMAT = 'openepm-source-staging-correction-qualification-v1'
REQUIRED_CASES = frozenset((
    'test_all_declared_input_refusals_preserve_exact_staging_and_business_rows',
    'test_corrected_row_after_500_accepted_preserves_prefix_and_publishes_once',
    'test_replayed_expired_or_authority_refusals_never_establish_correctable_input',
))
REQUIRED_OBSERVATIONS = frozenset((
    'declared-prewrite-refusals', 'corrected-525-row-publication',
    'uncertainty-expiry-authority-boundaries',
))
SOURCE_FILES = tuple(dict.fromkeys((*CONTRACT_SOURCES,
    'epm_core/postgres_source_batch.py',
    'epm_core/postgres_source_upload_manifest.py',
    'epm_core/postgres_import_execution.py',
    'epm_core/postgres_transfer_artifacts.py',
    'epm_core/postgres_fact_export.py',
    'epm_core/source_import_diagnostics.py',
    'epm_core/persistence_contract.py',
    'epm_core/postgres_numeric_store.py',
    'epm_core/expired_operation_replay.py',
    'tests/test_source_csv_input_rejections.py',
    'tests/test_source_staging_correction_postgres.py',
    'scripts/qualify_source_staging_correction.py',
)))


def validate_scenarios():
    from tests.test_source_staging_correction_postgres import SourceStagingCorrectionPostgresTests
    selected = tuple(MODULE + '.' + CLASS + '.' + name for name in sorted(REQUIRED_CASES))
    loader = unittest.TestLoader()
    if (set(loader.getTestCaseNames(SourceStagingCorrectionPostgresTests)) != REQUIRED_CASES
            or len(selected) != 3 or len(set(selected)) != 3
            or tuple(harness.scenario_ids(loader.loadTestsFromNames(selected))) != selected):
        raise harness.QualificationError('CSV_CORRECTION_SCENARIOS_CHANGED')
    return selected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true', required=True)
    parser.add_argument('--database-image', required=True)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    selected = validate_scenarios()
    from tests.test_source_staging_correction_postgres import SourceStagingCorrectionPostgresTests
    harness.TEST_SUITES[SUITE] = (MODULE, CLASS, FORMAT)
    harness.TEST_CASES[SUITE] = selected
    harness.SOURCE_FILES = SOURCE_FILES

    def finalize_proof(proof):
        if (proof.get('format') != FORMAT or proof.get('testSuite') != SUITE
                or proof.get('testScenarioIds') != list(selected)):
            raise harness.QualificationError('CSV_CORRECTION_PROOF_SCENARIOS_CHANGED')
        observations = SourceStagingCorrectionPostgresTests.observations
        if (len(observations) != len(REQUIRED_OBSERVATIONS)
                or {item.get('scenario') for item in observations} != REQUIRED_OBSERVATIONS):
            raise harness.QualificationError('CSV_CORRECTION_OBSERVATIONS_INCOMPLETE')
        proof['observations'] = observations
        proof['invocation']['argv'] = [sys.executable, '-B', '-m',
            'scripts.qualify_source_staging_correction', '--execute',
            '--database-image', args.database_image, '--output', str(args.output)]
        proof['invocation']['ambientTestSettings'] = (
            'All EPM_TEST_* settings excluded; names and values not retained.')
        proof['scope'] = {
            'functions': ['facts.source.csv.append', 'facts.source.begin', 'facts.source.seal',
                          'facts.source.manifest.attach', 'facts.source.preview',
                          'facts.transfer.import.request', 'facts.export.page'],
            'correction': 'An invalid first header can be corrected on the original empty batch. After 500 accepted rows, a rejected25-row remainder receives fresh admission for changed input; an altered payload with the original admission is refused. Accepted prefix rows/chunk remain byte-for-byte unchanged, the corrected append is exactly replayed and525 facts publish once with exact public readback.',
            'rejections': 'Every code in the current source-owner declaration and eight malformed-number families is observed as the exact native400 boundary through browser dispatch and MCP facade, preserving all scoped physical staging/business/receipt rows. Separate pure tests prove the declared refusals precede the staging database connection.',
            'recovery': 'Accepted append replay returns the same rows/digest with duplicate=true. Expired missing-original append creates no work. Current public Reader downgrade refuses both accepted and unaccepted packets. This native test does not infer browser first-dispatch/prior-uncertainty state; component tests own that distinction.',
            'schemaGraph': 'Actual before/after physical schema and canonical migration observations cover all three cases in their sole owned fixture. No equality is asserted for mutable physical fingerprints.',
            'schemaGraphScenarioIds': list(selected),
            'fixture': 'Sparse kernel application owned by the existing full-migration test fixture; inherited privileged setup and verified identity are explicit seams. Additional dimensions/members, staging, publication and grant changes use public workflows. SQL only observes exact owned rows.',
            'excludedClaims': 'No OIDC/HTTP listener or installed MCP host, rendered browser, complete import/export family, all-function contract completion, whole IP07/IP10 acceptance, deployment, performance threshold, or snapshot restoration.',
            'cleanup': 'The existing OwnedDockerRun and composed fixture verify their exact database/roles/container/volume are removed before final proof publication. The supplied preexisting PostgreSQL image is preserved; separately owned campaign images require separate cleanup evidence.',
        }

    saved = {name: value for name, value in os.environ.items() if name.startswith('EPM_TEST_')}
    for name in saved:
        os.environ.pop(name, None)
    try:
        proof = harness.qualify(output=args.output, database_image=args.database_image,
            test_suite=SUITE, finalize_proof=finalize_proof)
    finally:
        for name in tuple(os.environ):
            if name.startswith('EPM_TEST_'):
                os.environ.pop(name, None)
        os.environ.update(saved)
    print(f'Passed {proof["testsRun"]} CSV correction cases; owned cleanup verified; {args.output}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
