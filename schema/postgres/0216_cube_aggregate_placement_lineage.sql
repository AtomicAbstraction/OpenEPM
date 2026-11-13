-- Persist the exact path contributions behind a placement aggregate.  This is
-- technical read evidence, not a business receipt, and follows the owning
-- query's existing lifecycle and reset behavior.

DO $migration$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=215) THEN
    RAISE EXCEPTION 'MIGRATION_0216_PREDECESSOR_0215_REQUIRED';
  END IF;
END $migration$;

ALTER TABLE epm.cube_aggregate_query
  ADD COLUMN placement_lineage jsonb,
  ADD COLUMN placement_lineage_digest text;

ALTER TABLE epm.cube_aggregate_query
  ADD CONSTRAINT cube_aggregate_placement_lineage_shape CHECK(
    (placement_lineage IS NULL AND placement_lineage_digest IS NULL
      AND normalized_request->>'aggregation'<>'generic_placement_weighted_sum')
    OR
    (placement_lineage IS NOT NULL
      AND jsonb_typeof(placement_lineage)='object'
      AND placement_lineage->>'format'='openepm-placement-lineage-v1'
      AND jsonb_typeof(placement_lineage->'dimensions')='array'
      AND jsonb_array_length(placement_lineage->'dimensions') BETWEEN 1 AND 128
      AND octet_length(placement_lineage::text)<=4194304
      AND placement_lineage_digest~'^[0-9a-f]{64}$'
      AND placement_lineage->>'lineageDigest'=placement_lineage_digest
      AND normalized_request->>'aggregation'='generic_placement_weighted_sum'
      AND normalized_request->'genericPins'->>'placementLineageDigest'
          =placement_lineage_digest));

COMMENT ON COLUMN epm.cube_aggregate_query.placement_lineage IS
  'Immutable fixed-core path evidence for one placement aggregate request.';
COMMENT ON COLUMN epm.cube_aggregate_query.placement_lineage_digest IS
  'Canonical SHA-256 also sealed into the normalized plan generic pins.';
