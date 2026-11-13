-- Establish exact layout applicability before looking up a prior receipt.
-- A SQL JOIN may otherwise choose an application-wide receipt index scan even
-- though the new receipt is unrelated to every layout activation. Keep this
-- control-flow boundary explicit; all receipt guards and deferred seals remain.
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=294) THEN
    RAISE EXCEPTION 'MIGRATION_0295_REQUIRES_0294';
  END IF;
END $migration$;

CREATE OR REPLACE FUNCTION epm.layout_activation_receipt_replay() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE
    prior epm.operation_receipt%ROWTYPE;
    target_generation bigint;
BEGIN
    SELECT x.target_projection_generation INTO target_generation
      FROM epm.layout_replacement_activation x
     WHERE x.workspace_id=NEW.workspace_id
       AND x.application_id=NEW.application_id
       AND x.activation_id=NEW.operation_id AND x.status='Activating';
    IF NOT FOUND THEN
        RETURN NEW;
    END IF;
    IF epm.layout_replacement_activation_allowed(
        NEW.workspace_id,NEW.application_id,target_generation,'activate') IS NOT TRUE THEN
        RETURN NEW;
    END IF;
    SELECT r.* INTO prior FROM epm.operation_receipt r
     WHERE r.workspace_id=NEW.workspace_id AND r.application_id=NEW.application_id
       AND r.operation_id=NEW.operation_id;
    IF FOUND THEN
        IF (to_jsonb(prior)-'sealed'-'committed_at')
           IS DISTINCT FROM (to_jsonb(NEW)-'sealed'-'committed_at') THEN
            RAISE EXCEPTION 'LAYOUT_ACTIVATION_RECEIPT_CONFLICT';
        END IF;
        RETURN NULL;
    END IF;
    RETURN NEW;
END $$;
