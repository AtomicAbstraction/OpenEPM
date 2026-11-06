-- Server-owned consolidation layout and immutable source-bound CTA bridges.
ALTER TABLE epm.calculation_generation ADD CONSTRAINT
 calculation_generation_identity_result_unique UNIQUE
 (workspace_id,application_id,generation_id,result_key);
CREATE TABLE epm.consolidation_layout_version (
 workspace_id text NOT NULL, application_id text NOT NULL,
 layout_version bigint NOT NULL CHECK(layout_version>0), layout_digest text NOT NULL CHECK(layout_digest~'^[0-9a-f]{64}$'),
 account_dimension_id text NOT NULL,entity_dimension_id text NOT NULL,currency_dimension_id text NOT NULL,
 stage_dimension_id text NOT NULL,movement_dimension_id text NOT NULL,
 metadata_revision bigint NOT NULL CHECK(metadata_revision>=0),policy_revision bigint NOT NULL CHECK(policy_revision>=0),
 issuer text NOT NULL,subject_id text NOT NULL,created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,layout_version),
 UNIQUE(workspace_id,application_id,layout_digest),
 UNIQUE(workspace_id,application_id,layout_version,layout_digest),
 FOREIGN KEY(workspace_id,application_id) REFERENCES epm.application_state(workspace_id,application_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,account_dimension_id) REFERENCES epm.dimension(workspace_id,application_id,dimension_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,entity_dimension_id) REFERENCES epm.dimension(workspace_id,application_id,dimension_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,currency_dimension_id) REFERENCES epm.dimension(workspace_id,application_id,dimension_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,stage_dimension_id) REFERENCES epm.dimension(workspace_id,application_id,dimension_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,movement_dimension_id) REFERENCES epm.dimension(workspace_id,application_id,dimension_id) ON DELETE RESTRICT,
 CHECK(stage_dimension_id<>movement_dimension_id));
CREATE TABLE epm.consolidation_layout_state (
 workspace_id text NOT NULL,application_id text NOT NULL,active_layout_version bigint NOT NULL,active_layout_digest text NOT NULL,
 PRIMARY KEY(workspace_id,application_id),
 FOREIGN KEY(workspace_id,application_id,active_layout_version,active_layout_digest) REFERENCES epm.consolidation_layout_version(workspace_id,application_id,layout_version,layout_digest) ON DELETE RESTRICT);
CREATE TABLE epm.cta_bridge (
 workspace_id text NOT NULL,application_id text NOT NULL,bridge_id text NOT NULL CHECK(bridge_id~'^[0-9a-f]{32}$'),
 journal_id text NOT NULL,bridge_digest text NOT NULL CHECK(bridge_digest~'^[0-9a-f]{64}$'),compiler_version text NOT NULL CHECK(compiler_version='cta-bridge-v2'),
 status text NOT NULL CHECK(status='Posted'),currency_dimension_id text NOT NULL,currency_member_id text NOT NULL,effective_period jsonb NOT NULL CHECK(jsonb_typeof(effective_period)='object'),
 opening_amount numeric(28,8) NOT NULL,movement_amount numeric(28,8) NOT NULL,closing_amount numeric(28,8) NOT NULL,
 layout_version bigint NOT NULL,layout_digest text NOT NULL,metadata_revision bigint NOT NULL,data_revision bigint NOT NULL,policy_revision bigint NOT NULL,
 committed_revision bigint NOT NULL,issuer text NOT NULL,subject_id text NOT NULL,reason text NOT NULL CHECK(length(reason) BETWEEN 1 AND 500),
 result jsonb NOT NULL CHECK(jsonb_typeof(result)='object'),created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,bridge_id),UNIQUE(workspace_id,application_id,journal_id),
 FOREIGN KEY(workspace_id,application_id,journal_id) REFERENCES epm.manual_journal(workspace_id,application_id,journal_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,layout_version,layout_digest) REFERENCES epm.consolidation_layout_version(workspace_id,application_id,layout_version,layout_digest) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,currency_dimension_id,currency_member_id) REFERENCES epm.member(workspace_id,application_id,dimension_id,member_id) ON DELETE RESTRICT,
 CHECK(opening_amount+movement_amount=closing_amount));
CREATE TABLE epm.cta_bridge_source (
 workspace_id text NOT NULL,application_id text NOT NULL,bridge_id text NOT NULL,source_ordinal integer NOT NULL CHECK(source_ordinal>0),
 role text NOT NULL CHECK(role IN('Opening','Movement','Closing')),movement_id text,result_key text NOT NULL,generation_id text NOT NULL,
 published_revision bigint NOT NULL CHECK(published_revision>0),members jsonb NOT NULL CHECK(jsonb_typeof(members)='object'),amount numeric(28,8) NOT NULL,
 sign smallint NOT NULL CHECK(sign IN(-1,1)),currency_dimension_id text NOT NULL,currency_member_id text NOT NULL,source_function text NOT NULL,compiler_version text NOT NULL,
 lineage jsonb NOT NULL CHECK(jsonb_typeof(lineage)='object'),dependency_status jsonb CHECK(dependency_status IS NULL OR jsonb_typeof(dependency_status)='object'),
 PRIMARY KEY(workspace_id,application_id,bridge_id,source_ordinal),
 FOREIGN KEY(workspace_id,application_id,bridge_id) REFERENCES epm.cta_bridge(workspace_id,application_id,bridge_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,generation_id,result_key) REFERENCES epm.calculation_generation(workspace_id,application_id,generation_id,result_key) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,currency_dimension_id,currency_member_id) REFERENCES epm.member(workspace_id,application_id,dimension_id,member_id) ON DELETE RESTRICT,
 CHECK((role='Movement')=(movement_id IS NOT NULL)));

GRANT SELECT,INSERT ON epm.consolidation_layout_version,epm.consolidation_layout_state,epm.cta_bridge,epm.cta_bridge_source TO epm_runtime;
GRANT UPDATE(active_layout_version,active_layout_digest) ON epm.consolidation_layout_state TO epm_runtime;
GRANT SELECT ON epm.consolidation_layout_version,epm.consolidation_layout_state,epm.cta_bridge,epm.cta_bridge_source TO epm_lifecycle;
ALTER TABLE epm.consolidation_layout_version ENABLE ROW LEVEL SECURITY;ALTER TABLE epm.consolidation_layout_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.cta_bridge ENABLE ROW LEVEL SECURITY;ALTER TABLE epm.cta_bridge_source ENABLE ROW LEVEL SECURITY;
CREATE POLICY consolidation_layout_version_runtime ON epm.consolidation_layout_version TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true)) WITH CHECK(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
CREATE POLICY consolidation_layout_state_runtime ON epm.consolidation_layout_state TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true)) WITH CHECK(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
CREATE POLICY cta_bridge_runtime ON epm.cta_bridge TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true)) WITH CHECK(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
CREATE POLICY cta_bridge_source_runtime ON epm.cta_bridge_source TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true)) WITH CHECK(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
CREATE POLICY consolidation_layout_version_lifecycle ON epm.consolidation_layout_version FOR SELECT TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY consolidation_layout_state_lifecycle ON epm.consolidation_layout_state FOR SELECT TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY cta_bridge_lifecycle ON epm.cta_bridge FOR SELECT TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY cta_bridge_source_lifecycle ON epm.cta_bridge_source FOR SELECT TO epm_lifecycle USING(workspace_id=current_setting('epm.workspace_id',true));

DO $$ DECLARE d text; r text; old text:=$p$'calculation_ratio_result','calculation_unit_result',$p$; new text:=$p$'cta_bridge_source','cta_bridge','consolidation_layout_state','consolidation_layout_version','calculation_ratio_result','calculation_unit_result',$p$;
BEGIN SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure) INTO d;
 IF position(old IN d)=0 OR position(new IN d)>0 THEN RAISE EXCEPTION 'RESET_0145_DEFINITION_MISMATCH'; END IF;
 r:=replace(d,old,new); IF r=d THEN RAISE EXCEPTION 'RESET_0145_DEFINITION_MISMATCH'; END IF; EXECUTE r; END $$;
