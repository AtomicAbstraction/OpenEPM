-- Immutable, application-scoped policy-pack drafts. Drafts do not authorize
-- accounting execution; a later reviewed promotion must pin golden cases.
CREATE TABLE epm.policy_pack_draft (
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    policy_id text NOT NULL CHECK (policy_id ~ '^[A-Za-z0-9._-]{1,100}$'),
    version integer NOT NULL CHECK (version > 0),
    family text NOT NULL CHECK (family IN ('IFRS','US_GAAP','CUSTOM')),
    effective_from date NOT NULL,
    effective_before date NOT NULL,
    required_elections jsonb NOT NULL CHECK (jsonb_typeof(required_elections)='array'),
    source_refs jsonb NOT NULL CHECK (jsonb_typeof(source_refs)='array'),
    created_operation_id text NOT NULL,
    created_revision bigint NOT NULL CHECK (created_revision > 0),
    created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (workspace_id,application_id,policy_id,version),
    FOREIGN KEY (workspace_id,application_id,created_operation_id)
        REFERENCES epm.operation_receipt
        (workspace_id,application_id,operation_id) ON DELETE RESTRICT,
    CHECK (effective_from < effective_before)
);
CREATE INDEX policy_draft_effective ON epm.policy_pack_draft
    (workspace_id,application_id,family,effective_from,effective_before);

CREATE FUNCTION epm.reject_policy_draft_overlap() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM 1 FROM epm.application_state
      WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
      FOR UPDATE;
    IF EXISTS (SELECT 1 FROM epm.policy_pack_draft existing
      WHERE existing.workspace_id=NEW.workspace_id
        AND existing.application_id=NEW.application_id
        AND existing.policy_id=NEW.policy_id
        AND (existing.policy_id,existing.version)
            IS DISTINCT FROM (NEW.policy_id,NEW.version)
        AND daterange(existing.effective_from,existing.effective_before,'[)')
            && daterange(NEW.effective_from,NEW.effective_before,'[)')) THEN
      RAISE EXCEPTION 'POLICY_EFFECTIVE_RANGE_OVERLAP' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER reject_policy_draft_overlap
    BEFORE INSERT OR UPDATE ON epm.policy_pack_draft
    FOR EACH ROW EXECUTE FUNCTION epm.reject_policy_draft_overlap();

GRANT SELECT,INSERT ON epm.policy_pack_draft TO epm_runtime;
ALTER TABLE epm.policy_pack_draft ENABLE ROW LEVEL SECURITY;
CREATE POLICY policy_draft_scope ON epm.policy_pack_draft TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true))
    WITH CHECK (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
