-- Separate governed acquisition investment-offset layer. No raw/manual overwrite.
CREATE TABLE epm.acquisition_journal (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    journal_id text NOT NULL CHECK(journal_id ~ '^[A-Za-z0-9._-]{8,128}$'),
    acquisition_key text NOT NULL CHECK(acquisition_key ~ '^[A-Za-z0-9._-]{8,128}$'),
    job_id text,
    reversal_of text,
    activation_id text NOT NULL,
    currency_dimension_id text NOT NULL,
    currency_member_id text NOT NULL,
    reason text NOT NULL CHECK(length(reason) BETWEEN 1 AND 500),
    manifest jsonb NOT NULL CHECK(jsonb_typeof(manifest)='object'),
    issuer text NOT NULL CHECK(length(issuer) BETWEEN 1 AND 300),
    subject_id text NOT NULL CHECK(length(subject_id) BETWEEN 1 AND 300),
    metadata_revision bigint NOT NULL CHECK(metadata_revision>=0),
    policy_revision bigint NOT NULL CHECK(policy_revision>=0),
    committed_revision bigint NOT NULL CHECK(committed_revision>0),
    posted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    status text NOT NULL DEFAULT 'Building' CHECK(status IN ('Building','Posted')),
    PRIMARY KEY(workspace_id,application_id,journal_id),
    CHECK((job_id IS NOT NULL AND reversal_of IS NULL) OR
          (job_id IS NULL AND reversal_of IS NOT NULL)),
    FOREIGN KEY(workspace_id,application_id,journal_id)
        REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,job_id)
        REFERENCES epm.job(workspace_id,application_id,job_id) ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,reversal_of)
        REFERENCES epm.acquisition_journal(workspace_id,application_id,journal_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,activation_id)
        REFERENCES epm.policy_activation_event(workspace_id,application_id,event_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,currency_dimension_id,currency_member_id)
        REFERENCES epm.member(workspace_id,application_id,dimension_id,member_id)
        ON DELETE RESTRICT
);
CREATE UNIQUE INDEX acquisition_journal_economic_key
    ON epm.acquisition_journal(workspace_id,application_id,acquisition_key)
    WHERE reversal_of IS NULL;
CREATE UNIQUE INDEX acquisition_journal_one_reversal
    ON epm.acquisition_journal(workspace_id,application_id,reversal_of)
    WHERE reversal_of IS NOT NULL;
CREATE UNIQUE INDEX acquisition_journal_one_job
    ON epm.acquisition_journal(workspace_id,application_id,job_id)
    WHERE job_id IS NOT NULL;
CREATE TABLE epm.acquisition_journal_line (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    journal_id text NOT NULL,
    line_ordinal integer NOT NULL CHECK(line_ordinal BETWEEN 1 AND 100),
    coordinate_id bigint NOT NULL,
    signed_amount numeric(28,8) NOT NULL CHECK(signed_amount<>0),
    line_role text NOT NULL CHECK(line_role IN ('netAssetsOffset','goodwill',
        'investmentOffset','nonControllingInterest','remeasurementGainOrLoss')),
    PRIMARY KEY(workspace_id,application_id,journal_id,line_ordinal),
    UNIQUE(workspace_id,application_id,journal_id,coordinate_id),
    UNIQUE(workspace_id,application_id,journal_id,line_role),
    FOREIGN KEY(workspace_id,application_id,journal_id)
        REFERENCES epm.acquisition_journal(workspace_id,application_id,journal_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(workspace_id,application_id,coordinate_id)
        REFERENCES epm.coordinate(workspace_id,application_id,coordinate_id)
        ON DELETE RESTRICT
);
CREATE INDEX acquisition_journal_line_coordinate ON epm.acquisition_journal_line
    (workspace_id,application_id,coordinate_id,journal_id);

-- Building headers cannot commit. Lines can be inserted only before the
-- one-way seal; runtime cannot unseal or edit a posted header. The persisted
-- seal survives logical restore without relying on source-server transaction IDs.
CREATE FUNCTION epm.reject_sealed_acquisition_line()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE v_status text;
BEGIN
    SELECT status INTO v_status FROM epm.acquisition_journal
        WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
        AND journal_id=NEW.journal_id;
    IF v_status IS DISTINCT FROM 'Building' THEN
        RAISE EXCEPTION 'ACQUISITION_JOURNAL_IMMUTABLE' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.reject_sealed_acquisition_line() FROM PUBLIC;
CREATE TRIGGER acquisition_journal_line_creation BEFORE INSERT ON epm.acquisition_journal_line
    FOR EACH ROW EXECUTE FUNCTION epm.reject_sealed_acquisition_line();
CREATE FUNCTION epm.seal_acquisition_journal()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
    IF OLD.status<>'Building' OR NEW.status<>'Posted' OR
       (to_jsonb(NEW)-'status') IS DISTINCT FROM (to_jsonb(OLD)-'status') THEN
        RAISE EXCEPTION 'ACQUISITION_JOURNAL_IMMUTABLE' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.seal_acquisition_journal() FROM PUBLIC;
CREATE TRIGGER acquisition_journal_seal BEFORE UPDATE ON epm.acquisition_journal
    FOR EACH ROW EXECUTE FUNCTION epm.seal_acquisition_journal();

-- End-of-transaction backstop: no committed empty/unbalanced header or partial
-- reversal, even if a future core bug bypasses the Python entry checks.
CREATE FUNCTION epm.validate_acquisition_journal_balance()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE v_count bigint; v_sum numeric; v_original text; v_header epm.acquisition_journal%ROWTYPE;
BEGIN
    SELECT * INTO v_header FROM epm.acquisition_journal
        WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
        AND journal_id=NEW.journal_id;
    IF v_header.status IS DISTINCT FROM 'Posted' THEN
        RAISE EXCEPTION 'ACQUISITION_JOURNAL_NOT_SEALED' USING ERRCODE='23514';
    END IF;
    SELECT count(*),sum(signed_amount) INTO v_count,v_sum
        FROM epm.acquisition_journal_line WHERE workspace_id=NEW.workspace_id
        AND application_id=NEW.application_id AND journal_id=NEW.journal_id;
    IF v_count NOT BETWEEN 2 AND 5 OR v_sum IS DISTINCT FROM 0::numeric THEN
        RAISE EXCEPTION 'ACQUISITION_JOURNAL_NOT_BALANCED' USING ERRCODE='23514';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM epm.policy_activation_event e
        WHERE e.workspace_id=NEW.workspace_id AND e.application_id=NEW.application_id
        AND e.event_id=v_header.activation_id AND e.action='Activate') THEN
        RAISE EXCEPTION 'ACQUISITION_ACTIVATION_EVENT_REQUIRED' USING ERRCODE='23514';
    END IF;
    v_original := v_header.reversal_of;
    IF v_original IS NOT NULL THEN
        IF NOT EXISTS(SELECT 1 FROM epm.acquisition_journal j
            WHERE j.workspace_id=NEW.workspace_id AND j.application_id=NEW.application_id
            AND j.journal_id=v_original AND j.reversal_of IS NULL
            AND j.acquisition_key=v_header.acquisition_key
            AND j.activation_id=v_header.activation_id
            AND j.currency_dimension_id=v_header.currency_dimension_id
            AND j.currency_member_id=v_header.currency_member_id) OR EXISTS(
                SELECT 1 FROM (SELECT coordinate_id,line_role,signed_amount
                    FROM epm.acquisition_journal_line WHERE workspace_id=NEW.workspace_id
                    AND application_id=NEW.application_id AND journal_id=v_original) original
                FULL JOIN (SELECT coordinate_id,line_role,signed_amount
                    FROM epm.acquisition_journal_line WHERE workspace_id=NEW.workspace_id
                    AND application_id=NEW.application_id AND journal_id=NEW.journal_id) reversal
                USING(coordinate_id,line_role)
                WHERE original.coordinate_id IS NULL OR reversal.coordinate_id IS NULL
                OR original.signed_amount<>-reversal.signed_amount) THEN
            RAISE EXCEPTION 'ACQUISITION_REVERSAL_MISMATCH' USING ERRCODE='23514';
        END IF;
    END IF;
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION epm.validate_acquisition_journal_balance() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER acquisition_journal_balanced_header AFTER INSERT OR UPDATE
    ON epm.acquisition_journal DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION epm.validate_acquisition_journal_balance();
CREATE CONSTRAINT TRIGGER acquisition_journal_balanced_lines AFTER INSERT
    ON epm.acquisition_journal_line DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION epm.validate_acquisition_journal_balance();
CREATE TRIGGER planning_lock_acquisition_journal_insert AFTER INSERT
    ON epm.acquisition_journal_line REFERENCING NEW TABLE AS affected_rows
    FOR EACH STATEMENT EXECUTE FUNCTION epm.reject_locked_fact_write();

GRANT SELECT,INSERT ON epm.acquisition_journal,epm.acquisition_journal_line TO epm_runtime;
GRANT UPDATE(status) ON epm.acquisition_journal TO epm_runtime;
GRANT SELECT ON epm.acquisition_journal,epm.acquisition_journal_line TO epm_lifecycle;
ALTER TABLE epm.acquisition_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.acquisition_journal_line ENABLE ROW LEVEL SECURITY;
CREATE POLICY acquisition_journal_scope ON epm.acquisition_journal TO epm_runtime
    USING(workspace_id=current_setting('epm.workspace_id',true)
        AND application_id=current_setting('epm.application_id',true))
    WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
        AND application_id=current_setting('epm.application_id',true));
CREATE POLICY acquisition_journal_line_scope ON epm.acquisition_journal_line TO epm_runtime
    USING(workspace_id=current_setting('epm.workspace_id',true)
        AND application_id=current_setting('epm.application_id',true))
    WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
        AND application_id=current_setting('epm.application_id',true));
CREATE POLICY acquisition_journal_lifecycle ON epm.acquisition_journal
    FOR SELECT TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY acquisition_journal_line_lifecycle ON epm.acquisition_journal_line
    FOR SELECT TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));

-- Re-pin the owner-only reset primitive to the reviewed 0067 FK graph.
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
       p_schema_fingerprint <> 'dee924a664401eca5e5c82259daf0133e73e2fe27fd587af07c4a2922b988c56' OR
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

    -- The order is pinned to the reviewed 0067 FK graph. All names are
    -- constants; callers cannot supply a table or SQL fragment.
    -- Self-referential journal FKs are removed by table-wide DELETE statements.
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
