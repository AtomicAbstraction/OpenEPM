BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=296) THEN
    RAISE EXCEPTION 'MIGRATION_0297_REQUIRES_0296';
  END IF;
END $migration$;

ALTER TABLE epm.cube_aggregate_query
  DROP CONSTRAINT cube_aggregate_placement_lineage_shape;

ALTER TABLE epm.cube_aggregate_query
  ADD CONSTRAINT cube_aggregate_placement_lineage_shape CHECK(
    (placement_lineage IS NULL AND placement_lineage_digest IS NULL
      AND normalized_request->>'aggregation' NOT IN
        ('generic_placement_weighted_sum','hierarchy_placement_weighted_sum'))
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
          =placement_lineage_digest)
    OR
    (placement_lineage IS NOT NULL
      AND jsonb_typeof(placement_lineage)='object'
      AND placement_lineage->>'format'='openepm-hierarchy-node-lineage-v1'
      AND jsonb_typeof(placement_lineage->'sumWeights')='object'
      AND jsonb_typeof(placement_lineage->'countWeights')='object'
      AND jsonb_typeof(placement_lineage->'placementPaths')='array'
      AND jsonb_array_length(placement_lineage->'placementPaths') BETWEEN 1 AND 10000
      AND octet_length(placement_lineage::text)<=4194304
      AND placement_lineage_digest~'^[0-9a-f]{64}$'
      AND placement_lineage->>'lineageDigest'=placement_lineage_digest
      AND normalized_request->>'aggregation'='hierarchy_placement_weighted_sum'
      AND normalized_request->'hierarchyPins'->>'placementLineageDigest'
          =placement_lineage_digest));

COMMENT ON COLUMN epm.cube_aggregate_query.placement_lineage IS
  'Immutable fixed-core path evidence for generic placement or hierarchy-node aggregate requests.';
COMMENT ON COLUMN epm.cube_aggregate_query.placement_lineage_digest IS
  'Canonical SHA-256 sealed into the matching generic or hierarchy pins.';
COMMIT;
