-- Withdraw one current unreviewed IC offset without altering raw facts or
-- deleting its immutable generation and lines. This is not a journal reversal.
CREATE TABLE epm.ic_elimination_withdrawal (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    withdrawal_id text NOT NULL
        CHECK (withdrawal_id ~ '^[A-Za-z0-9._-]{8,128}$'),
    generation_id text NOT NULL,
    parent_entity_member_id text NOT NULL,
    pair_key text NOT NULL CHECK (pair_key ~ '^[0-9a-f]{64}$'),
    withdrawn_revision bigint NOT NULL CHECK (withdrawn_revision > 0),
    issuer text NOT NULL,
    subject_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,withdrawal_id),
    UNIQUE (workspace_id,application_id,generation_id),
    FOREIGN KEY (workspace_id,application_id,generation_id)
        REFERENCES epm.ic_elimination_generation
        (workspace_id,application_id,generation_id)
        ON DELETE RESTRICT
);
GRANT SELECT,INSERT ON epm.ic_elimination_withdrawal TO epm_runtime;
GRANT DELETE ON epm.ic_elimination_publication TO epm_runtime;
ALTER TABLE epm.ic_elimination_withdrawal ENABLE ROW LEVEL SECURITY;
CREATE POLICY ic_elimination_withdrawal_scope
    ON epm.ic_elimination_withdrawal TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));

-- Re-pin owner-only deletion to the reviewed 0055 FK graph.
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
       p_schema_fingerprint <> '5de21dd434c2135658a8401c125c05b9dcca16b40651e21702addc217113555d' OR
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

    -- The order is pinned to the reviewed 0055 FK graph. All names are
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
        'application','workspace']
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
