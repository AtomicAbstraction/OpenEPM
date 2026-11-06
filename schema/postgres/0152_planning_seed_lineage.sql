-- Immutable, fact-version provenance for reusable scenario Seed publication.
CREATE TABLE epm.planning_seed_lineage (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    batch_id text NOT NULL,
    action_ordinal bigint NOT NULL CHECK (action_ordinal BETWEEN 1 AND 100000),
    action text NOT NULL CHECK (action IN ('Set','ReplaceClear')),
    value_family text NOT NULL CHECK (value_family IN ('Numeric','Text','Detail')),
    target_series_key text NOT NULL CHECK (target_series_key ~ '^[0-9a-f]{64}$'),
    target_coordinate_id bigint,
    target_change_id text,
    target_detail_change_id text,
    target_committed_revision bigint,
    source_series_key text,
    source_coordinate_id bigint,
    source_change_id text,
    source_detail_change_id text,
    source_committed_revision bigint,
    policy_id text NOT NULL,
    policy_version bigint NOT NULL CHECK (policy_version > 0),
    policy_digest text NOT NULL CHECK (policy_digest ~ '^[0-9a-f]{64}$'),
    content_digest text NOT NULL CHECK (content_digest ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,batch_id,action_ordinal),
    UNIQUE (workspace_id,application_id,batch_id,target_series_key,value_family),
    FOREIGN KEY (workspace_id,application_id,batch_id)
      REFERENCES epm.source_batch(workspace_id,application_id,batch_id)
      ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,target_coordinate_id)
      REFERENCES epm.coordinate(workspace_id,application_id,coordinate_id)
      ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id,application_id,source_coordinate_id)
      REFERENCES epm.coordinate(workspace_id,application_id,coordinate_id)
      ON DELETE RESTRICT,
    CHECK ((action='Set' AND source_series_key IS NOT NULL
            AND source_coordinate_id IS NOT NULL AND source_change_id IS NOT NULL
            AND source_committed_revision IS NOT NULL)
        OR (action='ReplaceClear' AND source_series_key IS NULL
            AND source_coordinate_id IS NULL AND source_change_id IS NULL
            AND source_detail_change_id IS NULL
            AND source_committed_revision IS NULL)),
    CHECK ((target_coordinate_id IS NULL AND target_change_id IS NULL
            AND target_detail_change_id IS NULL
            AND target_committed_revision IS NULL)
        OR (target_coordinate_id IS NOT NULL AND target_change_id IS NOT NULL
            AND target_committed_revision IS NOT NULL)),
    CHECK ((value_family='Detail'
            AND ((action='Set' AND source_detail_change_id IS NOT NULL)
                 OR (action='ReplaceClear'
                     AND source_detail_change_id IS NULL))
            AND (target_coordinate_id IS NULL
                 OR target_detail_change_id IS NOT NULL))
        OR (value_family<>'Detail'
            AND source_detail_change_id IS NULL
            AND target_detail_change_id IS NULL))
);
CREATE INDEX planning_seed_lineage_page ON epm.planning_seed_lineage
 (workspace_id,application_id,batch_id,action_ordinal);
GRANT SELECT,INSERT ON epm.planning_seed_lineage TO epm_runtime;
GRANT SELECT ON epm.planning_seed_lineage TO epm_lifecycle;
ALTER TABLE epm.planning_seed_lineage ENABLE ROW LEVEL SECURITY;
CREATE POLICY planning_seed_lineage_runtime ON epm.planning_seed_lineage
 TO epm_runtime USING
 (workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true))
 WITH CHECK
 (workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true));
CREATE POLICY planning_seed_lineage_lifecycle ON epm.planning_seed_lineage
 TO epm_lifecycle USING
 (workspace_id=current_setting('epm.workspace_id',true));

CREATE FUNCTION epm.validate_planning_seed_lineage()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,epm AS $$
DECLARE source_ok boolean; target_ok boolean;
BEGIN
  IF NEW.workspace_id IS DISTINCT FROM current_setting('epm.workspace_id',true)
     OR NEW.application_id IS DISTINCT FROM
        current_setting('epm.application_id',true) THEN
    RAISE EXCEPTION 'PLANNING_SEED_LINEAGE_SCOPE_INVALID';
  END IF;
  IF TG_OP='UPDATE' AND NOT (
      OLD.target_coordinate_id IS NULL
      AND NEW.target_coordinate_id IS NOT NULL
      AND (to_jsonb(OLD)-ARRAY['target_coordinate_id','target_change_id',
          'target_detail_change_id','target_committed_revision']) =
          (to_jsonb(NEW)-ARRAY['target_coordinate_id','target_change_id',
          'target_detail_change_id','target_committed_revision'])) THEN
    RAISE EXCEPTION 'PLANNING_SEED_LINEAGE_IMMUTABLE';
  END IF;
  IF NEW.source_coordinate_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM epm.coordinate c WHERE c.workspace_id=NEW.workspace_id
       AND c.application_id=NEW.application_id
       AND c.coordinate_id=NEW.source_coordinate_id
       AND c.series_key=NEW.source_series_key) THEN
    RAISE EXCEPTION 'PLANNING_SEED_LINEAGE_SOURCE_COORDINATE_INVALID';
  END IF;
  IF NEW.target_coordinate_id IS NOT NULL AND NOT EXISTS (
      SELECT 1 FROM epm.coordinate c WHERE c.workspace_id=NEW.workspace_id
       AND c.application_id=NEW.application_id
       AND c.coordinate_id=NEW.target_coordinate_id
       AND c.series_key=NEW.target_series_key) THEN
    RAISE EXCEPTION 'PLANNING_SEED_LINEAGE_TARGET_COORDINATE_INVALID';
  END IF;
  IF NEW.action='Set' THEN
    IF NEW.value_family='Text' THEN
      SELECT EXISTS(SELECT 1 FROM epm.text_fact_event e
       WHERE e.workspace_id=NEW.workspace_id AND e.application_id=NEW.application_id
        AND e.coordinate_id=NEW.source_coordinate_id AND e.change_id=NEW.source_change_id
        AND e.committed_revision=NEW.source_committed_revision AND e.present)
       INTO source_ok;
    ELSE
      SELECT EXISTS(SELECT 1 FROM epm.numeric_fact_event e
       WHERE e.workspace_id=NEW.workspace_id AND e.application_id=NEW.application_id
        AND e.coordinate_id=NEW.source_coordinate_id AND e.change_id=NEW.source_change_id
        AND e.committed_revision=NEW.source_committed_revision AND e.present)
       AND (NEW.value_family<>'Detail' OR EXISTS(
        SELECT 1 FROM epm.line_detail_event d WHERE d.workspace_id=NEW.workspace_id
         AND d.application_id=NEW.application_id
         AND d.coordinate_id=NEW.source_coordinate_id
         AND d.change_id=NEW.source_detail_change_id
         AND d.committed_revision=NEW.source_committed_revision AND d.present))
       INTO source_ok;
    END IF;
    IF NOT source_ok THEN RAISE EXCEPTION 'PLANNING_SEED_LINEAGE_SOURCE_EVENT_INVALID'; END IF;
  END IF;
  IF NEW.target_coordinate_id IS NULL THEN RETURN NEW; END IF;
  IF NEW.value_family='Text' THEN
    SELECT EXISTS(SELECT 1 FROM epm.text_fact_event e
     WHERE e.workspace_id=NEW.workspace_id AND e.application_id=NEW.application_id
      AND e.coordinate_id=NEW.target_coordinate_id AND e.operation_id=NEW.batch_id
      AND e.change_id=NEW.target_change_id
      AND e.committed_revision=NEW.target_committed_revision
      AND e.kind=CASE WHEN NEW.action='Set' THEN 'set' ELSE 'clear' END
      AND e.present=(NEW.action='Set')) INTO target_ok;
  ELSE
    SELECT EXISTS(SELECT 1 FROM epm.numeric_fact_event e
     WHERE e.workspace_id=NEW.workspace_id AND e.application_id=NEW.application_id
      AND e.coordinate_id=NEW.target_coordinate_id AND e.operation_id=NEW.batch_id
      AND e.change_id=NEW.target_change_id
      AND e.committed_revision=NEW.target_committed_revision
      AND e.kind=CASE WHEN NEW.action='Set' THEN 'set' ELSE 'clear' END
      AND e.present=(NEW.action='Set'))
     AND (NEW.value_family<>'Detail' OR EXISTS(
      SELECT 1 FROM epm.line_detail_event d WHERE d.workspace_id=NEW.workspace_id
       AND d.application_id=NEW.application_id
       AND d.coordinate_id=NEW.target_coordinate_id AND d.operation_id=NEW.batch_id
       AND d.change_id=NEW.target_detail_change_id
       AND d.committed_revision=NEW.target_committed_revision
       AND d.present=(NEW.action='Set'))) INTO target_ok;
  END IF;
  IF NOT target_ok THEN RAISE EXCEPTION 'PLANNING_SEED_LINEAGE_TARGET_EVENT_INVALID'; END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.validate_planning_seed_lineage() FROM PUBLIC;
CREATE TRIGGER planning_seed_lineage_validate
 BEFORE INSERT OR UPDATE ON epm.planning_seed_lineage
 FOR EACH ROW EXECUTE FUNCTION epm.validate_planning_seed_lineage();

CREATE FUNCTION epm.finalize_planning_seed_lineage(
 p_workspace text,p_application text,p_batch text,p_revision bigint)
RETURNS bigint LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,epm AS $$
DECLARE changed bigint;
BEGIN
  IF p_workspace IS DISTINCT FROM current_setting('epm.workspace_id',true)
     OR p_application IS DISTINCT FROM current_setting('epm.application_id',true)
     OR p_revision<1 THEN
    RAISE EXCEPTION 'PLANNING_SEED_LINEAGE_FINALIZE_SCOPE_INVALID';
  END IF;
  UPDATE epm.planning_seed_lineage l SET
    target_coordinate_id=c.coordinate_id,
    target_change_id=CASE WHEN l.value_family='Text'
                          THEN t.change_id ELSE n.change_id END,
    target_detail_change_id=CASE WHEN l.value_family='Detail'
                                 THEN d.change_id END,
    target_committed_revision=p_revision
  FROM epm.coordinate c
  LEFT JOIN epm.numeric_fact_event n ON n.workspace_id=c.workspace_id
   AND n.application_id=c.application_id AND n.coordinate_id=c.coordinate_id
   AND n.operation_id=p_batch
  LEFT JOIN epm.text_fact_event t ON t.workspace_id=c.workspace_id
   AND t.application_id=c.application_id AND t.coordinate_id=c.coordinate_id
   AND t.operation_id=p_batch
  LEFT JOIN epm.line_detail_event d ON d.workspace_id=c.workspace_id
   AND d.application_id=c.application_id AND d.coordinate_id=c.coordinate_id
   AND d.operation_id=p_batch
  WHERE l.workspace_id=p_workspace AND l.application_id=p_application
   AND l.batch_id=p_batch AND l.target_coordinate_id IS NULL
   AND c.workspace_id=l.workspace_id AND c.application_id=l.application_id
   AND c.series_key=l.target_series_key;
  GET DIAGNOSTICS changed=ROW_COUNT;
  RETURN changed;
END $$;
REVOKE ALL ON FUNCTION epm.finalize_planning_seed_lineage(text,text,text,bigint)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.finalize_planning_seed_lineage(
 text,text,text,bigint) TO epm_runtime;

-- Preserve the qualified owner-only reset implementation and only add the new
-- child immediately before source_batch rows.
DO $$
DECLARE definition text; revised text;
DECLARE old_pair text := $pattern$'text_fact_event','text_cell_current','source_import_execution','source_batch_row',$pattern$;
DECLARE new_pair text := $pattern$'text_fact_event','text_cell_current','planning_seed_lineage','source_import_execution','source_batch_row',$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_pair IN definition)=0 OR position(new_pair IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0152_DEFINITION_MISMATCH';
  END IF;
  revised := replace(definition,old_pair,new_pair);
  IF revised=definition OR position(new_pair IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0152_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END $$;
