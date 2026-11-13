#!/usr/bin/env python3
"""Build the explicit enterprise PostgreSQL test disposition inventory.

The integration class contains current programmable-platform coverage and
required migration/recovery fixtures. Obsolete public-domain scenarios are
removed from the source; they are not retained as disabled test cases.
New tests are deliberately left unclassified until this builder and its policy
are reviewed and the checked-in inventory is regenerated.
"""
from __future__ import annotations

import ast
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from epm_core.postgres_capability_contract import (
    CONSOLIDATION_FUNCTIONS, RETIRED_PUBLIC_FUNCTIONS)


SOURCE=ROOT/'tests/test_postgres_numeric_store.py'
OUTPUT=ROOT/'docs/qualifications/enterprise-postgres-test-inventory-2026-11-05.json'
CLASS='PostgresNumericStoreTests'

# These cases qualify historical schema construction or require an external
# dump/restore topology. They remain required evidence, but not in the normal
# disposable database integration job.
HISTORICAL_SCHEMA_TESTS={
    'test_0054_to_0055_upgrade_preserves_published_ic_history',
    'test_coordinate_layout_upgrade_preserves_populated_facts_and_rejects_bad_grain',
    'test_coordinate_layout_upgrade_serializes_post_backfill_coordinate_write',
    'test_cube_selection_upgrade_seals_populated_legacy_hierarchy_without_changing_facts',
    'test_fact_publication_upgrade_rejects_corruption_and_preserves_valid_history',
    'test_generic_provenance_upgrade_preserves_legacy_and_records_new',
    'test_generic_publication_upgrade_preserves_history_and_rejects_corruption',
    'test_job_keyed_control_populated85_upgrade',
    'test_projection_generation_populated_76_upgrade_preserves_history',
    'test_raw_operation_membership_populated_83_upgrade',
}
ARTIFACT_QUALIFICATION_TESTS={
    'test_workspace_reset_delete_owner_primitive_is_scoped_atomic_and_audited',
    'test_saved_ordered_accepted_job_restores_before_publication',
}

# The owner has explicitly deferred concurrency, performance and process-death
# campaigns until the five-user laptop application's functional behavior is
# accepted.  Keep these cases named and fail-closed in the inventory; do not
# run them as part of the current functional CI gate.
DEFERRED_CONCURRENCY_CAMPAIGN_TESTS={
    'test_current_worker_cross_family_fairness_and_poison_deferral',
    'test_same_application_disjoint_calculations_compute_concurrently',
    'test_saved_ordered_concurrency_admission_pins_sources_metadata_and_rule_authority',
    'test_saved_ordered_concurrency_lease_takeover_preserves_new_owner',
    'test_saved_ordered_concurrency_process_death_rolls_back_and_recovers',
    'test_saved_ordered_concurrency_running_cancel_rolls_back_staged_effects',
    'test_saved_ordered_private_compute_does_not_block_writer_and_stale_publish_fails',
}

RETIRED_CURRENT_OBJECT_FRAGMENTS={
    'from epm.calculation_generation',
    'from epm.calculation_result ',
    'join epm.calculation_result ',
    'from epm.calculation_publication',
    'expectedstaterevision',
}



def _methods() -> list[tuple[str,int,str]]:
    text=SOURCE.read_text(encoding='utf-8')
    tree=ast.parse(text)
    klass=next(node for node in tree.body
               if isinstance(node,ast.ClassDef) and node.name==CLASS)
    lines=text.splitlines(keepends=True)
    result=[]
    for node in klass.body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node.name.startswith('test_'):
            source=''.join(lines[node.lineno-1:node.end_lineno])
            result.append((node.name,node.lineno,source))
    return sorted(result)


def build() -> dict:
    retired=RETIRED_PUBLIC_FUNCTIONS|CONSOLIDATION_FUNCTIONS
    rows=[]
    for name,line,source in _methods():
        referenced=sorted(function for function in retired if function in source)
        if name in ARTIFACT_QUALIFICATION_TESTS:
            disposition='artifact_qualification'
            rationale='requires packaged dump/restore topology'
        elif name in HISTORICAL_SCHEMA_TESTS:
            disposition='historical_compatibility'
            rationale='constructs and upgrades a superseded schema generation'
        elif name in DEFERRED_CONCURRENCY_CAMPAIGN_TESTS:
            disposition='deferred_concurrency_campaign'
            rationale='owner-deferred until five-user laptop functional acceptance'
        elif referenced:
            raise RuntimeError(
                f'OBSOLETE_PUBLIC_CONTRACT_TEST_REQUIRES_CLEANUP: {name}')
        else:
            retired_storage=sorted(fragment for fragment in
                RETIRED_CURRENT_OBJECT_FRAGMENTS
                if fragment in source.lower())
            if retired_storage:
                raise RuntimeError(
                    'RETIRED_CURRENT_OBJECT_TEST_REQUIRES_CLEANUP: '
                    f'{name}: {retired_storage}')
            disposition='active_disposable_integration'
            rationale='current programmable-platform database behavior'
        rows.append({'test':name,'line':line,'disposition':disposition,
                     'rationale':rationale,
                     'retiredFunctions':referenced})
    digest=sha256(json.dumps(rows,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    counts={}
    for row in rows:counts[row['disposition']]=counts.get(row['disposition'],0)+1
    return {'format':'openepm-enterprise-postgres-test-inventory-v1',
            'source':SOURCE.relative_to(ROOT).as_posix(),
            'class':CLASS,'testCount':len(rows),
            'dispositionCounts':dict(sorted(counts.items())),
            'inventoryDigest':digest,'tests':rows,
            'policy':{
                'unknownTestsFail':True,
                'activeSelectionMustNotSkip':True,
                'obsoletePublicContractTestsRetained':False,
                'artifactQualificationRunsSeparately':True,
                'deferredConcurrencyCampaignRunsSeparately':True}}


def main() -> None:
    OUTPUT.write_text(json.dumps(build(),indent=2)+'\n',encoding='utf-8')


if __name__=='__main__':main()
