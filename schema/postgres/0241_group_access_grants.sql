-- First-class Keycloak group grants. Direct user grants remain in their
-- existing immutable tables; fixed-core authorization resolves the strongest
-- currently verified user-or-group grant without treating token claims as
-- self-authorizing business roles.

DO $migration$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=240) THEN
        RAISE EXCEPTION 'MIGRATION_0241_PREDECESSOR_0240_REQUIRED';
    END IF;
END $migration$;

CREATE FUNCTION epm.valid_authorization_group_id(group_id text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
STRICT
SET search_path=pg_catalog
AS $$
    SELECT char_length(group_id) BETWEEN 1 AND 300
       AND group_id=btrim(group_id)
       AND group_id !~ '[[:cntrl:]]'
       AND position('*' IN group_id)=0
$$;

REVOKE ALL ON FUNCTION epm.valid_authorization_group_id(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.valid_authorization_group_id(text)
    TO epm_runtime,epm_access,epm_security,epm_lifecycle;

CREATE TABLE epm.workspace_group_access_grant (
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 300
        AND issuer=btrim(issuer) AND issuer !~ '[[:cntrl:]]'),
    group_id text NOT NULL CHECK (epm.valid_authorization_group_id(group_id)),
    workspace_id text NOT NULL REFERENCES epm.workspace(workspace_id)
        ON DELETE RESTRICT,
    role text NOT NULL CHECK (role='Administrator'),
    granted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (issuer,group_id,workspace_id)
);
CREATE INDEX workspace_group_access_grant_scope
    ON epm.workspace_group_access_grant(workspace_id,issuer,group_id);

CREATE TABLE epm.application_group_access_grant (
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 300
        AND issuer=btrim(issuer) AND issuer !~ '[[:cntrl:]]'),
    group_id text NOT NULL CHECK (epm.valid_authorization_group_id(group_id)),
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    role text NOT NULL CHECK (role IN ('Reader','Editor','Administrator')),
    read_security_tags jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (
        epm.valid_dimensional_security_tag_map(read_security_tags)),
    write_security_tags jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (
        epm.valid_dimensional_security_tag_map(write_security_tags)),
    granted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (issuer,group_id,workspace_id,application_id),
    FOREIGN KEY (workspace_id,application_id)
        REFERENCES epm.application(workspace_id,application_id)
        ON DELETE RESTRICT
);
CREATE INDEX application_group_access_grant_scope
    ON epm.application_group_access_grant(
        workspace_id,application_id,role,issuer,group_id);

CREATE TABLE epm.rule_group_access_grant (
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 300
        AND issuer=btrim(issuer) AND issuer !~ '[[:cntrl:]]'),
    group_id text NOT NULL CHECK (epm.valid_authorization_group_id(group_id)),
    workspace_id text NOT NULL,
    application_id text NOT NULL,
    can_design boolean NOT NULL DEFAULT false,
    can_publish boolean NOT NULL DEFAULT false,
    can_run boolean NOT NULL DEFAULT false,
    granted_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (issuer,group_id,workspace_id,application_id),
    FOREIGN KEY (workspace_id,application_id)
        REFERENCES epm.application(workspace_id,application_id)
        ON DELETE RESTRICT
);
CREATE INDEX rule_group_access_grant_scope
    ON epm.rule_group_access_grant(
        workspace_id,application_id,issuer,group_id);

ALTER TABLE epm.workspace_group_access_grant ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.application_group_access_grant ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.rule_group_access_grant ENABLE ROW LEVEL SECURITY;

CREATE POLICY workspace_group_grant_runtime_read
    ON epm.workspace_group_access_grant FOR SELECT TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY application_group_grant_runtime_read
    ON epm.application_group_access_grant FOR SELECT TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));
CREATE POLICY rule_group_grant_runtime_read
    ON epm.rule_group_access_grant FOR SELECT TO epm_runtime
    USING (workspace_id=current_setting('epm.workspace_id',true)
       AND application_id=current_setting('epm.application_id',true));

CREATE POLICY workspace_group_grant_access_read
    ON epm.workspace_group_access_grant FOR SELECT
    TO epm_access,epm_security USING (true);
CREATE POLICY application_group_grant_access_read
    ON epm.application_group_access_grant FOR SELECT
    TO epm_access,epm_security USING (true);
CREATE POLICY rule_group_grant_access_read
    ON epm.rule_group_access_grant FOR SELECT
    TO epm_access,epm_security USING (true);

CREATE POLICY workspace_group_grant_security_write
    ON epm.workspace_group_access_grant TO epm_security
    USING (true) WITH CHECK (true);
CREATE POLICY application_group_grant_security_write
    ON epm.application_group_access_grant TO epm_security
    USING (true) WITH CHECK (true);
CREATE POLICY rule_group_grant_security_write
    ON epm.rule_group_access_grant TO epm_security
    USING (true) WITH CHECK (true);

CREATE POLICY workspace_group_grant_lifecycle_read
    ON epm.workspace_group_access_grant FOR SELECT TO epm_lifecycle
    USING (workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY application_group_grant_lifecycle_read
    ON epm.application_group_access_grant FOR SELECT TO epm_lifecycle
    USING (workspace_id=current_setting('epm.workspace_id',true));
CREATE POLICY rule_group_grant_lifecycle_read
    ON epm.rule_group_access_grant FOR SELECT TO epm_lifecycle
    USING (workspace_id=current_setting('epm.workspace_id',true));

REVOKE ALL ON epm.workspace_group_access_grant,
    epm.application_group_access_grant,epm.rule_group_access_grant
    FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_access,
         epm_security,epm_lifecycle;
GRANT SELECT ON epm.workspace_group_access_grant,
    epm.application_group_access_grant,epm.rule_group_access_grant
    TO epm_runtime,epm_access,epm_security,epm_lifecycle;
GRANT INSERT,UPDATE,DELETE ON epm.workspace_group_access_grant,
    epm.application_group_access_grant,epm.rule_group_access_grant
    TO epm_security;

-- Group administration shares the existing immutable security receipt
-- namespace. Keep its vocabulary closed and explicit so an arbitrary caller
-- cannot smuggle a new security operation class into audit history.
ALTER TABLE epm.security_operation_receipt
    DROP CONSTRAINT security_operation_receipt_action_check;
ALTER TABLE epm.security_operation_receipt
    ADD CONSTRAINT security_operation_receipt_action_check CHECK (action=ANY(
        ARRAY['application.grant','application.revoke',
              'workspace.grant','workspace.revoke',
              'rule.set','rule.revoke','dimension-access.set',
              'dimension-policy.version.save','dimension-policy.activate',
              'dimension-policy.deactivate',
              'application-group.grant','application-group.revoke',
              'workspace-group.grant','workspace-group.revoke',
              'rule-group.set','rule-group.revoke',
              'group-dimension-access.set']::text[]));

-- Extend the exact owner-reset inventory in child-first order. Group rule and
-- application grants precede application; workspace group grants precede the
-- workspace parent. Every expected anchor is checked before replacement.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_rule text :=
  $pattern$'coordinate_layout','rule_access_grant','application_state',$pattern$;
DECLARE new_rule text :=
  $pattern$'coordinate_layout','rule_group_access_grant','rule_access_grant','application_state',$pattern$;
DECLARE old_application text :=
  $pattern$'dimensional_security_policy_version','application_access_grant','workspace_lifecycle_receipt',$pattern$;
DECLARE new_application text :=
  $pattern$'dimensional_security_policy_version','application_group_access_grant','application_access_grant','workspace_lifecycle_receipt',$pattern$;
DECLARE old_workspace text :=
  $pattern$'workspace_access_grant','security_operation_receipt',$pattern$;
DECLARE new_workspace text :=
  $pattern$'workspace_group_access_grant','workspace_access_grant','security_operation_receipt',$pattern$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_rule IN definition)=0
     OR position(new_rule IN definition)>0
     OR position(old_application IN definition)=0
     OR position(new_application IN definition)>0
     OR position(old_workspace IN definition)=0
     OR position(new_workspace IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0241_DEFINITION_MISMATCH';
  END IF;
  revised:=replace(replace(replace(definition,old_rule,new_rule),
                   old_application,new_application),old_workspace,new_workspace);
  IF revised=definition OR position(new_rule IN revised)=0
     OR position(new_application IN revised)=0
     OR position(new_workspace IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0241_DEFINITION_MISMATCH';
  END IF;
  EXECUTE revised;
END $migration$;

-- The replacement fingerprint is populated only after applying this migration
-- to an isolated clean schema and inspecting its canonical relation/FK graph.
DO $migration$
DECLARE definition text; revised text;
DECLARE old_fingerprint constant text :=
  'ff52ba439b4eaaf4ffaeece6fb18917581ebc35b43370befa11371440fd1c6b9';
DECLARE new_fingerprint constant text :=
  '8e68ae31e4fa93c377f3df269c40f3d57fd0acfd87c957250d78a2d549258336';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF position(old_fingerprint IN definition)=0
     OR position(new_fingerprint IN definition)>0 THEN
    RAISE EXCEPTION 'RESET_0241_FINGERPRINT_PREDECESSOR_MISMATCH';
  END IF;
  revised:=replace(definition,old_fingerprint,new_fingerprint);
  IF revised=definition OR position(new_fingerprint IN revised)=0 THEN
    RAISE EXCEPTION 'RESET_0241_FINGERPRINT_UPDATE_FAILED';
  END IF;
  EXECUTE revised;
END $migration$;
