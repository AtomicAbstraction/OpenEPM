-- Versioned application cube layout; point identity remains the existing SeriesKey.
-- Projection contains no amounts and never merges raw/journal/calculated layers.
CREATE TABLE epm.coordinate_layout (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    schema_epoch bigint NOT NULL CHECK(schema_epoch>=0),
    dimensions text[] NOT NULL,
    role_dimensions jsonb NOT NULL CHECK(jsonb_typeof(role_dimensions)='object'),
    custom_dimensions text[] NOT NULL,
    PRIMARY KEY(workspace_id,application_id,schema_epoch),
    FOREIGN KEY(workspace_id,application_id)
        REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT
);
CREATE TABLE epm.coordinate_projection (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    coordinate_id bigint NOT NULL,
    fact_table_id text NOT NULL DEFAULT 'cube' CHECK(fact_table_id='cube'),
    schema_epoch bigint NOT NULL CHECK(schema_epoch>=0),
    entity_member text, account_member text, scenario_member text,
    year_member text, period_member text, value_member text, view_member text,
    icp_member text, data_type_member text,
    custom_members text[] NOT NULL,
    PRIMARY KEY(workspace_id,application_id,coordinate_id),
    FOREIGN KEY(workspace_id,application_id,coordinate_id)
        REFERENCES epm.coordinate(workspace_id,application_id,coordinate_id) ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,schema_epoch)
        REFERENCES epm.coordinate_layout(workspace_id,application_id,schema_epoch) ON DELETE RESTRICT
);
CREATE INDEX coordinate_projection_entity ON epm.coordinate_projection(workspace_id,application_id,fact_table_id,schema_epoch,entity_member,coordinate_id);
CREATE INDEX coordinate_projection_account ON epm.coordinate_projection(workspace_id,application_id,fact_table_id,schema_epoch,account_member,coordinate_id);
CREATE INDEX coordinate_projection_scenario ON epm.coordinate_projection(workspace_id,application_id,fact_table_id,schema_epoch,scenario_member,coordinate_id);
CREATE INDEX coordinate_projection_year ON epm.coordinate_projection(workspace_id,application_id,fact_table_id,schema_epoch,year_member,coordinate_id);
CREATE INDEX coordinate_projection_period ON epm.coordinate_projection(workspace_id,application_id,fact_table_id,schema_epoch,period_member,coordinate_id);
CREATE INDEX coordinate_projection_value ON epm.coordinate_projection(workspace_id,application_id,fact_table_id,schema_epoch,value_member,coordinate_id);
CREATE INDEX coordinate_projection_view ON epm.coordinate_projection(workspace_id,application_id,fact_table_id,schema_epoch,view_member,coordinate_id);
CREATE INDEX coordinate_projection_icp ON epm.coordinate_projection(workspace_id,application_id,fact_table_id,schema_epoch,icp_member,coordinate_id);
CREATE INDEX coordinate_projection_data_type ON epm.coordinate_projection(workspace_id,application_id,fact_table_id,schema_epoch,data_type_member,coordinate_id);
CREATE INDEX coordinate_projection_custom ON epm.coordinate_projection USING gin(custom_members);

-- Reject ambiguous legacy roles rather than silently choosing one during upgrade.
DO $$ BEGIN
    IF EXISTS(SELECT 1 FROM epm.dimension WHERE status='Active'
        AND model_role IS NOT NULL AND model_role NOT IN ('Custom','Currency')
        GROUP BY workspace_id,application_id,model_role HAVING count(*)>1) THEN
        RAISE EXCEPTION 'COORDINATE_LAYOUT_ROLE_AMBIGUOUS' USING ERRCODE='23514';
    END IF;
END $$;
INSERT INTO epm.coordinate_layout(workspace_id,application_id,schema_epoch,dimensions,role_dimensions,custom_dimensions)
SELECT s.workspace_id,s.application_id,s.schema_epoch,
    coalesce(array_agg(d.dimension_id ORDER BY d.dimension_id COLLATE "C") FILTER(WHERE d.dimension_id IS NOT NULL),'{}'::text[]),
    coalesce(jsonb_object_agg(d.model_role,d.dimension_id) FILTER(WHERE d.model_role IS NOT NULL AND d.model_role<>'Custom'),'{}'::jsonb),
    coalesce(array_agg(d.dimension_id ORDER BY d.dimension_id COLLATE "C") FILTER(WHERE d.dimension_id IS NOT NULL AND (d.model_role IS NULL OR d.model_role='Custom')),'{}'::text[])
FROM epm.application_state s LEFT JOIN epm.dimension d ON d.workspace_id=s.workspace_id AND d.application_id=s.application_id
    AND d.status='Active' AND d.model_role IS DISTINCT FROM 'Currency'
GROUP BY s.workspace_id,s.application_id,s.schema_epoch;

-- One private, set-based projector is also usable by deployment-owner recovery.
-- Caller cannot supply member values or rewrite facts; projection is derived.
CREATE FUNCTION epm.coordinate_projection_build(w text,a text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
BEGIN
    PERFORM 1 FROM epm.application_state WHERE workspace_id=w AND application_id=a FOR UPDATE;
    IF EXISTS(SELECT 1 FROM epm.coordinate c JOIN epm.application_state s USING(workspace_id,application_id)
        JOIN epm.coordinate_layout l USING(workspace_id,application_id,schema_epoch)
        WHERE c.workspace_id=w AND c.application_id=a
        AND ARRAY(SELECT key FROM jsonb_object_keys(c.members) keys(key) ORDER BY key COLLATE "C")<>l.dimensions) THEN
        RAISE EXCEPTION 'COORDINATE_LAYOUT_GRAIN_MISMATCH' USING ERRCODE='23514';
    END IF;
    INSERT INTO epm.coordinate_projection(workspace_id,application_id,coordinate_id,schema_epoch,
        entity_member,account_member,scenario_member,year_member,period_member,value_member,view_member,icp_member,data_type_member,custom_members)
    SELECT c.workspace_id,c.application_id,c.coordinate_id,l.schema_epoch,
        c.members->>(l.role_dimensions->>'Entity'),c.members->>(l.role_dimensions->>'Account'),
        c.members->>(l.role_dimensions->>'Scenario'),c.members->>(l.role_dimensions->>'Year'),
        c.members->>(l.role_dimensions->>'Period'),c.members->>(l.role_dimensions->>'Value'),
        c.members->>(l.role_dimensions->>'View'),c.members->>(l.role_dimensions->>'ICP'),c.members->>(l.role_dimensions->>'DataType'),
        ARRAY(SELECT c.members->>axis FROM unnest(l.custom_dimensions) WITH ORDINALITY axes(axis,position) ORDER BY position)
    FROM epm.coordinate c JOIN epm.application_state s USING(workspace_id,application_id)
    JOIN epm.coordinate_layout l USING(workspace_id,application_id,schema_epoch)
    WHERE c.workspace_id=w AND c.application_id=a
    ON CONFLICT(workspace_id,application_id,coordinate_id) DO UPDATE SET
        schema_epoch=excluded.schema_epoch,entity_member=excluded.entity_member,account_member=excluded.account_member,
        scenario_member=excluded.scenario_member,year_member=excluded.year_member,period_member=excluded.period_member,
        value_member=excluded.value_member,view_member=excluded.view_member,icp_member=excluded.icp_member,
        data_type_member=excluded.data_type_member,custom_members=excluded.custom_members;
END $$;
-- Deployment migration backfill; transaction rolls back on inconsistent legacy grain.
DO $$ DECLARE app record; BEGIN
    FOR app IN SELECT workspace_id,application_id FROM epm.application_state ORDER BY workspace_id,application_id LOOP
        PERFORM epm.coordinate_projection_build(app.workspace_id,app.application_id);
    END LOOP;
END $$;

CREATE FUNCTION epm.coordinate_layout_refresh(w text,a text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE epoch bigint; dims text[]; roles jsonb; customs text[]; prior epm.coordinate_layout%ROWTYPE;
BEGIN
    SELECT schema_epoch INTO epoch FROM epm.application_state WHERE workspace_id=w AND application_id=a FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'APPLICATION_LAYOUT_UNAVAILABLE' USING ERRCODE='23514'; END IF;
    IF EXISTS(SELECT 1 FROM epm.dimension WHERE workspace_id=w AND application_id=a AND status='Active'
        AND model_role IS NOT NULL AND model_role NOT IN ('Custom','Currency') GROUP BY model_role HAVING count(*)>1) THEN
        RAISE EXCEPTION 'COORDINATE_LAYOUT_ROLE_AMBIGUOUS' USING ERRCODE='23514';
    END IF;
    SELECT coalesce(array_agg(dimension_id ORDER BY dimension_id COLLATE "C"),'{}'::text[]),
        coalesce(jsonb_object_agg(model_role,dimension_id) FILTER(WHERE model_role IS NOT NULL AND model_role<>'Custom'),'{}'::jsonb),
        coalesce(array_agg(dimension_id ORDER BY dimension_id COLLATE "C") FILTER(WHERE model_role IS NULL OR model_role='Custom'),'{}'::text[])
    INTO dims,roles,customs FROM epm.dimension WHERE workspace_id=w AND application_id=a AND status='Active'
        AND model_role IS DISTINCT FROM 'Currency';
    SELECT * INTO prior FROM epm.coordinate_layout WHERE workspace_id=w AND application_id=a AND schema_epoch=epoch;
    IF FOUND THEN
        IF ROW(prior.dimensions,prior.role_dimensions,prior.custom_dimensions) IS NOT DISTINCT FROM ROW(dims,roles,customs) THEN RETURN; END IF;
        IF EXISTS(SELECT 1 FROM epm.coordinate WHERE workspace_id=w AND application_id=a) THEN
            RAISE EXCEPTION 'POPULATED_AXIS_REBUILD_REQUIRED' USING ERRCODE='23514';
        END IF;
        epoch=epoch+1;
        UPDATE epm.application_state SET schema_epoch=epoch WHERE workspace_id=w AND application_id=a;
    END IF;
    INSERT INTO epm.coordinate_layout(workspace_id,application_id,schema_epoch,dimensions,role_dimensions,custom_dimensions)
        VALUES(w,a,epoch,dims,roles,customs);
END $$;
CREATE FUNCTION epm.coordinate_layout_dimension_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
BEGIN
    -- Only the existing owner-only workspace reset may remove layout history.
    -- Its reviewed table order deletes projections/layouts before dimensions.
    IF TG_OP='DELETE' AND pg_has_role(session_user,
        (SELECT relowner FROM pg_class WHERE oid='epm.coordinate_layout'::regclass),'USAGE')
        AND EXISTS(SELECT 1 FROM epm.workspace WHERE workspace_id=OLD.workspace_id AND status='Maintenance') THEN
        RETURN NULL;
    END IF;
    IF TG_OP='DELETE' THEN PERFORM epm.coordinate_layout_refresh(OLD.workspace_id,OLD.application_id);
    ELSE PERFORM epm.coordinate_layout_refresh(NEW.workspace_id,NEW.application_id); END IF;
    RETURN NULL;
END $$;
CREATE TRIGGER coordinate_layout_dimension_change AFTER INSERT OR UPDATE OR DELETE ON epm.dimension
    FOR EACH ROW EXECUTE FUNCTION epm.coordinate_layout_dimension_change();
CREATE FUNCTION epm.coordinate_layout_application_create() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
BEGIN PERFORM epm.coordinate_layout_refresh(NEW.workspace_id,NEW.application_id); RETURN NULL; END $$;
CREATE TRIGGER coordinate_layout_application_create AFTER INSERT ON epm.application_state
    FOR EACH ROW EXECUTE FUNCTION epm.coordinate_layout_application_create();

-- Hot publication touches only the INSERT transition set, never the whole cube.
CREATE FUNCTION epm.coordinate_project_inserted() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
BEGIN
    PERFORM 1 FROM epm.application_state s
        JOIN (SELECT DISTINCT workspace_id,application_id FROM coordinate_inserted) c USING(workspace_id,application_id)
        ORDER BY s.workspace_id,s.application_id FOR UPDATE OF s;
    IF EXISTS(SELECT 1 FROM coordinate_inserted c JOIN epm.application_state s USING(workspace_id,application_id)
        JOIN epm.coordinate_layout l USING(workspace_id,application_id,schema_epoch)
        WHERE ARRAY(SELECT key FROM jsonb_object_keys(c.members) keys(key) ORDER BY key COLLATE "C")<>l.dimensions) THEN
        RAISE EXCEPTION 'COORDINATE_LAYOUT_GRAIN_MISMATCH' USING ERRCODE='23514';
    END IF;
    INSERT INTO epm.coordinate_projection(workspace_id,application_id,coordinate_id,schema_epoch,
        entity_member,account_member,scenario_member,year_member,period_member,value_member,view_member,icp_member,data_type_member,custom_members)
    SELECT c.workspace_id,c.application_id,c.coordinate_id,l.schema_epoch,
        c.members->>(l.role_dimensions->>'Entity'),c.members->>(l.role_dimensions->>'Account'),
        c.members->>(l.role_dimensions->>'Scenario'),c.members->>(l.role_dimensions->>'Year'),
        c.members->>(l.role_dimensions->>'Period'),c.members->>(l.role_dimensions->>'Value'),
        c.members->>(l.role_dimensions->>'View'),c.members->>(l.role_dimensions->>'ICP'),c.members->>(l.role_dimensions->>'DataType'),
        ARRAY(SELECT c.members->>axis FROM unnest(l.custom_dimensions) WITH ORDINALITY axes(axis,position) ORDER BY position)
    FROM coordinate_inserted c JOIN epm.application_state s USING(workspace_id,application_id)
    JOIN epm.coordinate_layout l USING(workspace_id,application_id,schema_epoch);
    RETURN NULL;
END $$;
CREATE TRIGGER coordinate_project_inserted AFTER INSERT ON epm.coordinate
    REFERENCING NEW TABLE AS coordinate_inserted FOR EACH STATEMENT EXECUTE FUNCTION epm.coordinate_project_inserted();

ALTER TABLE epm.coordinate_layout ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.coordinate_projection ENABLE ROW LEVEL SECURITY;
CREATE POLICY coordinate_layout_scope ON epm.coordinate_layout TO epm_runtime,epm_analyst
    USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
CREATE POLICY coordinate_projection_scope ON epm.coordinate_projection TO epm_runtime,epm_analyst
    USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
GRANT SELECT ON epm.coordinate_layout,epm.coordinate_projection TO epm_runtime,epm_analyst;
REVOKE ALL ON FUNCTION epm.coordinate_projection_build(text,text),epm.coordinate_layout_refresh(text,text),
    epm.coordinate_layout_dimension_change(),epm.coordinate_layout_application_create(),epm.coordinate_project_inserted() FROM PUBLIC;

-- Extend the existing owner-only reset; no new reset authority or gate bypass.
CREATE OR REPLACE FUNCTION epm.delete_workspace_reset_owner_only(
    p_workspace_id text, p_operation_id text, p_manifest_digest text,
    p_schema_fingerprint text, p_actor_digest text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog AS $$
DECLARE
    v_prior epm.workspace_reset_receipt%ROWTYPE;
    v_status text;
    v_table text;
    v_deleted bigint;
    v_counts jsonb := '{}'::jsonb;
    v_apps jsonb;
    v_result jsonb;
BEGIN
    IF p_workspace_id IS NULL OR p_workspace_id = '' OR
       p_workspace_id <> current_setting('epm.workspace_id',true) OR
       p_operation_id IS NULL OR
       p_operation_id !~ '^[A-Za-z0-9._-]{8,128}$' OR
       p_manifest_digest IS NULL OR
       p_manifest_digest !~ '^[0-9a-f]{64}$' OR
       p_schema_fingerprint IS NULL OR
       p_schema_fingerprint <> '9c455649c20c16f7e580582e0b37f4a65529a1d0e483548a79ec2884e77582ea' OR
       p_actor_digest IS NULL OR
       p_actor_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'RESET_DELETE_ARGUMENTS_INVALID';
    END IF;
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'RESET_REQUIRES_READ_COMMITTED';
    END IF;
    PERFORM pg_advisory_xact_lock(
        hashtextextended('epm.security.workspace:' || p_workspace_id,0));
    SELECT * INTO v_prior FROM epm.workspace_reset_receipt
        WHERE target_workspace_id=p_workspace_id
        AND operation_id=p_operation_id;
    IF FOUND THEN
        IF v_prior.manifest_digest<>p_manifest_digest OR
           v_prior.schema_fingerprint<>p_schema_fingerprint OR
           v_prior.actor_digest<>p_actor_digest THEN
            RAISE EXCEPTION 'IDEMPOTENCY_KEY_REUSED';
        END IF;
        RETURN v_prior.result;
    END IF;
    SELECT status INTO v_status FROM epm.workspace
        WHERE workspace_id=p_workspace_id FOR UPDATE;
    IF v_status IS DISTINCT FROM 'Maintenance' THEN
        RAISE EXCEPTION 'WORKSPACE_NOT_IN_MAINTENANCE';
    END IF;
    IF EXISTS (SELECT 1 FROM epm.job WHERE workspace_id=p_workspace_id
        AND status IN ('accepted','ready','running','staged',
                       'cancel_requested','needs_inspection')) THEN
        RAISE EXCEPTION 'UNSETTLED_OR_INSPECTION_JOBS';
    END IF;
    IF EXISTS (SELECT 1 FROM epm.expression_rule_sequence
        WHERE workspace_id=p_workspace_id
          AND status IN ('accepted','running','cancel_requested')) THEN
        RAISE EXCEPTION 'UNSETTLED_RULE_SEQUENCES';
    END IF;
    IF EXISTS (SELECT 1 FROM epm.full_aggregate_sequence
        WHERE workspace_id=p_workspace_id
          AND status IN ('accepted','running','cancel_requested')) THEN
        RAISE EXCEPTION 'UNSETTLED_FULL_SEQUENCES';
    END IF;
    IF EXISTS (SELECT 1 FROM epm.source_batch
        WHERE workspace_id=p_workspace_id
        AND status IN ('staging','ready')) THEN
        RAISE EXCEPTION 'UNPUBLISHED_SOURCE_BATCHES';
    END IF;
    IF EXISTS (SELECT 1 FROM epm.job j
        JOIN epm.operation_receipt r
          ON r.workspace_id=j.workspace_id
         AND r.application_id=j.application_id
         AND r.operation_id=j.job_id
        WHERE j.workspace_id=p_workspace_id
        AND j.status<>'published') THEN
        RAISE EXCEPTION 'JOB_RECEIPT_REQUIRES_INSPECTION';
    END IF;
    IF EXISTS (SELECT 1 FROM epm.source_batch b
        JOIN epm.operation_receipt r
          ON r.workspace_id=b.workspace_id
         AND r.application_id=b.application_id
         AND r.operation_id=b.batch_id
        WHERE b.workspace_id=p_workspace_id
        AND b.status<>'published') THEN
        RAISE EXCEPTION 'SOURCE_BATCH_RECEIPT_REQUIRES_INSPECTION';
    END IF;
    SELECT COALESCE(jsonb_agg(application_id ORDER BY application_id),
                    '[]'::jsonb) INTO v_apps
        FROM epm.application WHERE workspace_id=p_workspace_id;

    -- The order is pinned to the reviewed 0074 FK graph. All names are
    -- constants; callers cannot supply a table or SQL fragment.
    -- Self-referential journal FKs are removed by table-wide DELETE statements.
    FOREACH v_table IN ARRAY ARRAY[
        'coordinate_projection','coordinate_layout',
        'generic_fact_event','generic_fact_current',
        'rollup_source_lineage','ownership_value_event',
        'ownership_value_current','allocation_basis_lineage','relationship',
        'planning_submission_event','manual_journal_line',
        'hierarchy_closure','hierarchy_active','expression_rule_publication','coordinate_member',
        'calendar_period_event','calendar_period_current',
        'ic_elimination_line','ic_elimination_publication',
        'calculation_result','calculation_publication',
        'text_fact_event','text_cell_current','source_batch_row',
        'source_batch_chunk','semantic_column','policy_pack_draft',
        'acquisition_journal_line','acquisition_journal',
        'policy_activation_current','policy_activation_event',
        'policy_acquisition_approval','policy_acquisition_case_review',
        'policy_acquisition_case_bundle','policy_source_artifact',
        'planning_submission','planning_lock_event','planning_copy_origin',
        'numeric_fact_event','numeric_cell_current','member',
        'manual_journal','line_detail_event','line_detail_current',
        'job_event','job_dependency','hierarchy_version',
        'ic_elimination_withdrawal','ic_elimination_generation',
        'calculation_generation','source_batch','planning_slice_lock',
        'expression_rule_version','operation_receipt','job_event_cursor','job','generic_fact_table','expression_rule_sequence',
        'full_aggregate_sequence','dimension',
        'coordinate','rule_access_grant','application_state',
        'application_access_grant','workspace_lifecycle_receipt',
        'workspace_access_grant','security_operation_receipt',
        'application','worker_workspace_dispatch','workspace']
    LOOP
        EXECUTE format('DELETE FROM epm.%I WHERE workspace_id=$1',v_table)
            USING p_workspace_id;
        GET DIAGNOSTICS v_deleted = ROW_COUNT;
        v_counts := v_counts || jsonb_build_object(v_table,v_deleted);
    END LOOP;

    v_result := jsonb_build_object(
        'workspaceId',p_workspace_id,
        'operationId',p_operation_id,
        'status','Deleted',
        'manifestDigest',p_manifest_digest,
        'schemaFingerprint',p_schema_fingerprint,
        'applicationIds',v_apps,
        'deletedCounts',v_counts);
    INSERT INTO epm.workspace_reset_receipt
        (target_workspace_id,operation_id,manifest_digest,
         schema_fingerprint,actor_digest,result)
        VALUES (p_workspace_id,p_operation_id,p_manifest_digest,
                p_schema_fingerprint,p_actor_digest,v_result);
    INSERT INTO epm.security_audit
        (actor_id,action,workspace_id,target_digest,outcome,detail)
        VALUES (p_actor_digest,'workspace.reset.apply',p_workspace_id,
                p_manifest_digest,'Accepted',
                jsonb_build_object('operationId',p_operation_id,
                                   'schemaFingerprint',p_schema_fingerprint,
                                   'applicationIds',v_apps,
                                   'deletedCounts',v_counts));
    RETURN v_result;
END $$;
REVOKE ALL ON FUNCTION epm.delete_workspace_reset_owner_only(
    text,text,text,text,text) FROM PUBLIC;
-- No runtime/lifecycle GRANT EXECUTE: the owner-only primitive remains
-- behind the separately validated workspace-reset application gate.
