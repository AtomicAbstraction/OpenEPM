BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=364) THEN
    RAISE EXCEPTION 'MIGRATION_0365_REQUIRES_0364';
  END IF;
END $migration$;

-- Member identity is (workspace, application, dimension, member). The primary
-- key and all qualified member references already use this identity. Remove
-- only the older application-wide uniqueness restriction; existing IDs, facts,
-- names, references and business definitions are not rewritten.
LOCK TABLE epm.member IN ACCESS EXCLUSIVE MODE;

DO $migration$
DECLARE scoped_key smallint[];
DECLARE unscoped_key smallint[];
DECLARE constraint_count integer;
DECLARE constraint_name name;
DECLARE constraint_index oid;
BEGIN
  SELECT array_agg(attribute.attnum ORDER BY requested.ordinality)::smallint[]
    INTO scoped_key
    FROM unnest(ARRAY['workspace_id','application_id','dimension_id','member_id'])
      WITH ORDINALITY requested(name,ordinality)
    JOIN pg_attribute attribute ON attribute.attrelid='epm.member'::regclass
      AND attribute.attname=requested.name AND NOT attribute.attisdropped;
  IF cardinality(scoped_key) IS DISTINCT FROM 4 THEN
    RAISE EXCEPTION 'MEMBER_IDENTITY_0365_COLUMNS_MISMATCH';
  END IF;
  unscoped_key:=ARRAY[scoped_key[1],scoped_key[2],scoped_key[4]];

  IF (SELECT count(*) FROM pg_constraint
      WHERE conrelid='epm.member'::regclass AND contype='p'
        AND conkey=scoped_key AND convalidated AND NOT condeferrable)<>1 THEN
    RAISE EXCEPTION 'MEMBER_IDENTITY_0365_PRIMARY_KEY_MISMATCH';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM pg_index
      WHERE indexrelid=to_regclass('epm.member_name_per_dimension')
        AND indrelid='epm.member'::regclass
        AND indisunique AND indisvalid AND indisready
        AND indnkeyatts=4 AND indnatts=4 AND indpred IS NULL
        AND indkey::text=array_to_string(
          ARRAY[scoped_key[1],scoped_key[2],scoped_key[3],0], ' ')
        AND pg_get_expr(indexprs,indrelid)='lower(name)') THEN
    RAISE EXCEPTION 'MEMBER_IDENTITY_0365_NAME_INDEX_MISMATCH';
  END IF;

  SELECT count(*) INTO constraint_count FROM pg_constraint
    WHERE conrelid='epm.member'::regclass AND contype='u'
      AND conkey=unscoped_key;
  IF constraint_count<>1 THEN
    RAISE EXCEPTION 'MEMBER_IDENTITY_0365_UNIQUE_CONSTRAINT_MISMATCH';
  END IF;
  SELECT conname,conindid INTO constraint_name,constraint_index
    FROM pg_constraint WHERE conrelid='epm.member'::regclass
      AND contype='u' AND conkey=unscoped_key
      AND convalidated AND NOT condeferrable;
  IF constraint_name IS NULL OR constraint_index IS NULL THEN
    RAISE EXCEPTION 'MEMBER_IDENTITY_0365_UNIQUE_CONSTRAINT_MISMATCH';
  END IF;

  -- Do not silently remove or reinterpret a newly introduced unscoped foreign
  -- key. Its owning contract must be migrated before this restriction retires.
  IF EXISTS(SELECT 1 FROM pg_constraint
      WHERE contype='f' AND confrelid='epm.member'::regclass
        AND (conindid=constraint_index OR confkey=unscoped_key)) THEN
    RAISE EXCEPTION 'MEMBER_IDENTITY_0365_UNSCOPED_FOREIGN_KEY';
  END IF;
  IF EXISTS(SELECT 1 FROM pg_index candidate
      WHERE candidate.indrelid='epm.member'::regclass AND candidate.indisunique
        AND candidate.indexrelid<>constraint_index AND candidate.indnkeyatts=3
        AND ARRAY(SELECT key FROM unnest(candidate.indkey::smallint[])
          WITH ORDINALITY indexed(key,position)
          WHERE position<=candidate.indnkeyatts ORDER BY key)
          =ARRAY(SELECT key FROM unnest(unscoped_key) key ORDER BY key)) THEN
    RAISE EXCEPTION 'MEMBER_IDENTITY_0365_UNEXPECTED_UNIQUE_INDEX';
  END IF;

  EXECUTE format('ALTER TABLE epm.member DROP CONSTRAINT %I RESTRICT',
                 constraint_name);
END $migration$;
COMMIT;
