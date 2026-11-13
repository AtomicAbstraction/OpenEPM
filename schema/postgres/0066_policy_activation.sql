-- Immutable activation history and one current pointer per functional variant.
CREATE TABLE epm.policy_activation_event (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    event_id text NOT NULL,
    variant_key text NOT NULL CHECK(variant_key ~ '^[0-9a-f]{64}$'),
    action text NOT NULL CHECK(action IN ('Activate','Withdraw')),
    approval_id text NOT NULL,
    activation_id text,
    previous_event_id text,
    manifest jsonb NOT NULL CHECK(jsonb_typeof(manifest)='object'),
    actor_issuer text NOT NULL,
    actor_subject text NOT NULL,
    policy_revision bigint NOT NULL CHECK(policy_revision>0),
    committed_revision bigint NOT NULL CHECK(committed_revision>0),
    recorded_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY(workspace_id,application_id,event_id),
    CHECK((action='Activate' AND activation_id IS NULL) OR
          (action='Withdraw' AND activation_id IS NOT NULL)),
    FOREIGN KEY(workspace_id,application_id,event_id)
        REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,approval_id)
        REFERENCES epm.policy_acquisition_approval(workspace_id,application_id,approval_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,activation_id)
        REFERENCES epm.policy_activation_event(workspace_id,application_id,event_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,previous_event_id)
        REFERENCES epm.policy_activation_event(workspace_id,application_id,event_id)
        ON DELETE RESTRICT
);
CREATE TABLE epm.policy_activation_current (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    variant_key text NOT NULL CHECK(variant_key ~ '^[0-9a-f]{64}$'),
    event_id text NOT NULL,
    activation_id text NOT NULL,
    status text NOT NULL CHECK(status IN ('Active','Withdrawn')),
    PRIMARY KEY(workspace_id,application_id,variant_key),
    FOREIGN KEY(workspace_id,application_id,event_id)
        REFERENCES epm.policy_activation_event(workspace_id,application_id,event_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,activation_id)
        REFERENCES epm.policy_activation_event(workspace_id,application_id,event_id)
        ON DELETE RESTRICT
);
GRANT SELECT,INSERT ON epm.policy_activation_event TO epm_runtime;
GRANT SELECT,INSERT,UPDATE ON epm.policy_activation_current TO epm_runtime;
GRANT SELECT ON epm.policy_activation_event,epm.policy_activation_current TO epm_lifecycle;
ALTER TABLE epm.policy_activation_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.policy_activation_current ENABLE ROW LEVEL SECURITY;
CREATE POLICY policy_activation_event_scope ON epm.policy_activation_event TO epm_runtime
    USING(workspace_id=current_setting('epm.workspace_id',true)
        AND application_id=current_setting('epm.application_id',true))
    WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
        AND application_id=current_setting('epm.application_id',true));
CREATE POLICY policy_activation_current_scope ON epm.policy_activation_current TO epm_runtime
    USING(workspace_id=current_setting('epm.workspace_id',true)
        AND application_id=current_setting('epm.application_id',true))
    WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
        AND application_id=current_setting('epm.application_id',true));
CREATE POLICY policy_activation_event_lifecycle_read ON epm.policy_activation_event
    FOR SELECT TO epm_lifecycle
    USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY policy_activation_current_lifecycle_read ON epm.policy_activation_current
    FOR SELECT TO epm_lifecycle
    USING(workspace_id=current_setting('epm.workspace_id',true));

-- Re-pin the owner-only reset primitive to the reviewed 0066 FK graph.
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
       p_schema_fingerprint <> '649bee450940bf52a89142622e5ab947e3fa1af54f41c1fea85dda794672744c' OR
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

    -- The order is pinned to the reviewed 0066 FK graph. All names are
    -- constants; callers cannot supply a table or SQL fragment. The one
    -- self-referential manual_journal FK is removed by one table-wide DELETE.
    FOREACH v_table IN ARRAY ARRAY[
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
-- No GRANT EXECUTE: migration owner only until the full MCP apply gate exists.
