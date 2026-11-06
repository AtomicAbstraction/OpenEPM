-- Revocable, application-scoped authority for unattended fixed-core execution.
CREATE FUNCTION epm.valid_execution_operation_scope(value text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT cardinality(value) BETWEEN 1 AND 32
 AND NOT EXISTS(SELECT 1 FROM unnest(value) item WHERE item !~ '^[A-Za-z][A-Za-z0-9_.-]{0,199}$')
 AND cardinality(value)=(SELECT count(DISTINCT item) FROM unnest(value) item)
$$;
REVOKE ALL ON FUNCTION epm.valid_execution_operation_scope(text[]) FROM PUBLIC;
CREATE TABLE epm.execution_delegation_version(
 workspace_id text NOT NULL, application_id text NOT NULL,
 delegation_id text NOT NULL CHECK(delegation_id ~ '^[A-Za-z0-9._-]{1,200}$'),
 version bigint NOT NULL CHECK(version>0),
 issuer text NOT NULL CHECK(length(issuer) BETWEEN 1 AND 300 AND issuer !~ '[[:cntrl:]]'),
 subject_id text NOT NULL CHECK(length(subject_id) BETWEEN 1 AND 300 AND subject_id !~ '[[:cntrl:]]'),
 operation_scope text[] NOT NULL CHECK(epm.valid_execution_operation_scope(operation_scope)),
 valid_from timestamptz NOT NULL, valid_until timestamptz NOT NULL CHECK(valid_until>valid_from),
 schedule_id text, schedule_version bigint, operation_id text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,delegation_id,version),
 CONSTRAINT execution_delegation_receipt_fkey FOREIGN KEY(workspace_id,application_id,operation_id) REFERENCES epm.operation_receipt(workspace_id,application_id,operation_id) ON DELETE CASCADE,
 CHECK((schedule_id IS NULL)=(schedule_version IS NULL)));
CREATE TABLE epm.execution_delegation_state(
 workspace_id text NOT NULL,application_id text NOT NULL,delegation_id text NOT NULL,
 latest_version bigint NOT NULL,active_version bigint,state_revision bigint NOT NULL CHECK(state_revision>0),
 revoked_at timestamptz,updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,delegation_id),
 CONSTRAINT execution_delegation_latest_fkey FOREIGN KEY(workspace_id,application_id,delegation_id,latest_version) REFERENCES epm.execution_delegation_version(workspace_id,application_id,delegation_id,version) ON DELETE CASCADE,
 CONSTRAINT execution_delegation_active_fkey FOREIGN KEY(workspace_id,application_id,delegation_id,active_version) REFERENCES epm.execution_delegation_version(workspace_id,application_id,delegation_id,version) ON DELETE CASCADE,
 CHECK(active_version=latest_version), CHECK((revoked_at IS NULL)=(active_version IS NOT NULL)));
ALTER TABLE epm.execution_delegation_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.execution_delegation_state ENABLE ROW LEVEL SECURITY;
CREATE POLICY execution_delegation_version_scope ON epm.execution_delegation_version TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true)) WITH CHECK(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
CREATE POLICY execution_delegation_state_scope ON epm.execution_delegation_state TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true)) WITH CHECK(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
CREATE POLICY execution_delegation_version_lifecycle ON epm.execution_delegation_version TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY execution_delegation_state_lifecycle ON epm.execution_delegation_state TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));
REVOKE ALL ON epm.execution_delegation_version,epm.execution_delegation_state FROM PUBLIC,epm_runtime,epm_worker;
GRANT SELECT,INSERT ON epm.execution_delegation_version TO epm_runtime;
GRANT SELECT,INSERT,UPDATE ON epm.execution_delegation_state TO epm_runtime;
GRANT SELECT(workspace_id,application_id,delegation_id,version) ON epm.execution_delegation_version TO epm_lifecycle;
GRANT SELECT(workspace_id,application_id,delegation_id,latest_version,active_version,state_revision) ON epm.execution_delegation_state TO epm_lifecycle;
CREATE FUNCTION epm.execution_delegation_is_current(p_workspace text,p_application text,p_delegation text,p_version bigint,p_issuer text,p_subject text,p_operation text,p_schedule text,p_schedule_version bigint) RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$ SELECT EXISTS(SELECT 1 FROM epm.execution_delegation_state s JOIN epm.execution_delegation_version v ON (v.workspace_id,v.application_id,v.delegation_id,v.version)=(s.workspace_id,s.application_id,s.delegation_id,s.active_version) WHERE s.workspace_id=p_workspace AND s.application_id=p_application AND s.delegation_id=p_delegation AND v.version=p_version AND v.issuer=p_issuer AND v.subject_id=p_subject AND p_operation=ANY(v.operation_scope) AND v.schedule_id IS NOT DISTINCT FROM p_schedule AND v.schedule_version IS NOT DISTINCT FROM p_schedule_version AND s.revoked_at IS NULL AND clock_timestamp()>=v.valid_from AND clock_timestamp()<v.valid_until) $$;
REVOKE ALL ON FUNCTION epm.execution_delegation_is_current(text,text,text,bigint,text,text,text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.execution_delegation_is_current(text,text,text,bigint,text,text,text,text,bigint) TO epm_runtime,epm_worker;
