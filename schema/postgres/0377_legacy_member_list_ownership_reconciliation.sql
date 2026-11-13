BEGIN;

DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=376) THEN
    RAISE EXCEPTION 'MIGRATION_0377_REQUIRES_0376';
  END IF;
END $migration$;

-- Migration 0366 could associate only the current unversioned
-- metadata.member_list.save plan shape.  A populated database can still contain
-- the exact source build for a member list authored by the retired
-- metadata.member_list.version.save contract, while 0307 has already projected
-- that versioned row into the one current definition (without its version
-- field).  Reconcile only that exact historical representation, or the exact
-- current representation, and leave every incomplete or ambiguous case
-- unresolved and inactive.
CREATE TEMP TABLE member_list_owner_0377_map ON COMMIT DROP AS
SELECT l.workspace_id,l.application_id,l.list_id,l.dimension_id,l.state_token,
       s.program_id,s.source_token,s.source_digest
FROM epm.member_list_definition l
JOIN epm.python_program_build b
  ON (b.workspace_id,b.application_id,b.build_id)=
     (l.workspace_id,l.application_id,l.source_build_id)
JOIN epm.python_program_definition s
  ON (s.workspace_id,s.application_id,s.program_id,s.source_token)=
     (b.workspace_id,b.application_id,b.program_id,b.program_source_token)
LEFT JOIN epm.python_plan_artifact a
  ON (a.workspace_id,a.application_id,a.build_id)=
     (b.workspace_id,b.application_id,b.build_id)
CROSS JOIN LATERAL (
  SELECT a.canonical_plan#>'{units,0,operations,0}' AS operation
) compiled
WHERE l.ownership_state='Unresolved'
  AND l.status='Inactive'
  AND l.current_certificate IS NULL
  AND l.definition IS NOT NULL
  AND l.canonical_digest IS NOT NULL
  AND s.status='Inactive'
  AND s.declared_output IS NULL
  AND (
    (a.build_id IS NOT NULL
      AND jsonb_typeof(a.canonical_plan->'units')='array'
      AND jsonb_array_length(a.canonical_plan->'units')=1
      AND jsonb_typeof(a.canonical_plan#>'{units,0,operations}')='array'
      AND jsonb_array_length(a.canonical_plan#>'{units,0,operations}')=1
      AND compiled.operation->>'function' IN (
        'metadata.member_list.version.save','metadata.member_list.save')
      AND compiled.operation#>>'{arguments,definition,listId}'=l.list_id
      AND compiled.operation#>>'{arguments,definition,dimensionId}'=l.dimension_id
      AND (
        (compiled.operation->>'function'='metadata.member_list.version.save'
          AND jsonb_typeof(compiled.operation#>'{arguments,definition,version}')='number'
          AND compiled.operation#>>'{arguments,definition,version}' ~ '^[1-9][0-9]*$'
          AND ((compiled.operation#>'{arguments,definition}')-'version')=l.definition)
        OR
        (compiled.operation->>'function'='metadata.member_list.save'
          AND compiled.operation#>'{arguments,definition}'=l.definition)))
    OR (a.build_id IS NULL AND b.purpose='ImpactTest' AND b.status='expired'
      AND b.expected_metadata_revision=l.metadata_revision)
  );

-- One retained source must own exactly one current definition, and one current
-- definition must resolve to exactly one retained source.  Drop both sides of
-- any ambiguous candidate set rather than selecting by incidental row order.
DELETE FROM member_list_owner_0377_map m USING (
  SELECT workspace_id,application_id,program_id
  FROM member_list_owner_0377_map
  GROUP BY workspace_id,application_id,program_id HAVING count(*)<>1
) bad
WHERE (m.workspace_id,m.application_id,m.program_id)=
      (bad.workspace_id,bad.application_id,bad.program_id);
DELETE FROM member_list_owner_0377_map m USING (
  SELECT workspace_id,application_id,list_id
  FROM member_list_owner_0377_map
  GROUP BY workspace_id,application_id,list_id HAVING count(*)<>1
) bad
WHERE (m.workspace_id,m.application_id,m.list_id)=
      (bad.workspace_id,bad.application_id,bad.list_id);

CREATE TEMP TABLE member_list_owner_0377_app ON COMMIT DROP AS
SELECT DISTINCT workspace_id,application_id FROM member_list_owner_0377_map;

UPDATE epm.python_program_definition s
SET declared_output=jsonb_build_object(
      'kind','MemberList','definitionId',m.list_id,'dimensionId',m.dimension_id),
    state_token=m.state_token
FROM member_list_owner_0377_map m
WHERE (s.workspace_id,s.application_id,s.program_id,s.source_token,s.source_digest)=
      (m.workspace_id,m.application_id,m.program_id,m.source_token,m.source_digest)
  AND s.status='Inactive' AND s.declared_output IS NULL;

UPDATE epm.member_list_definition l
SET ownership_state='Source',source_program_id=m.program_id,
    source_token=m.source_token,source_digest=m.source_digest,
    canonical_digest=epm.definition_payload_digest('MemberList',l.definition)
FROM member_list_owner_0377_map m
WHERE (l.workspace_id,l.application_id,l.list_id)=
      (m.workspace_id,m.application_id,m.list_id)
  AND l.ownership_state='Unresolved' AND l.status='Inactive'
  AND l.current_certificate IS NULL;

UPDATE epm.application_state s
SET policy_revision=policy_revision+1,commit_revision=commit_revision+1
WHERE EXISTS(SELECT 1 FROM member_list_owner_0377_app a
  WHERE (a.workspace_id,a.application_id)=(s.workspace_id,s.application_id));

-- Force all deferred reciprocal ownership, source identity and state-token
-- checks before the migration runner records 0377 as applied.
SET CONSTRAINTS ALL IMMEDIATE;

COMMIT;
SELECT '0377 applied' AS migration;
