BEGIN;
DO $migration$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=332) THEN
    RAISE EXCEPTION 'MIGRATION_0333_REQUIRES_0332';
  END IF;
END $migration$;

-- Intercompany elimination is one current pair state, not an addressable
-- generation chain.  The current row retains the exact source evidence needed
-- for freshness checks; replacement and withdrawal rotate an opaque token.
CREATE TABLE epm.ic_elimination_state(
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  parent_entity_member_id text NOT NULL,
  pair_key text NOT NULL CHECK(pair_key~'^[0-9a-f]{64}$'),
  state_token text NOT NULL CHECK(state_token~'^[0-9a-f]{64}$'),
  status text NOT NULL CHECK(status IN
    ('PublishedUnreviewed','WithdrawnUnreviewed')),
  left_relationship_id text NOT NULL,
  right_relationship_id text NOT NULL,
  left_coordinate_id bigint NOT NULL,
  right_coordinate_id bigint NOT NULL,
  left_source_change_id text NOT NULL,
  right_source_change_id text NOT NULL,
  matched_magnitude numeric(28,8) NOT NULL CHECK(matched_magnitude>0),
  signed_residual numeric(28,8) NOT NULL,
  source_metadata_revision bigint NOT NULL CHECK(source_metadata_revision>=0),
  source_data_revision bigint NOT NULL CHECK(source_data_revision>=0),
  source_policy_revision bigint NOT NULL CHECK(source_policy_revision>=0),
  committed_revision bigint NOT NULL CHECK(committed_revision>0),
  issuer text NOT NULL,
  subject_id text NOT NULL,
  rule_id text NOT NULL DEFAULT 'basic_ic_balance_v1'
    CHECK(rule_id='basic_ic_balance_v1'),
  updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  PRIMARY KEY(workspace_id,application_id,parent_entity_member_id,pair_key),
  UNIQUE(workspace_id,application_id,parent_entity_member_id,pair_key,
    state_token),
  FOREIGN KEY(workspace_id,application_id)
    REFERENCES epm.application_state(workspace_id,application_id)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,left_coordinate_id)
    REFERENCES epm.coordinate(workspace_id,application_id,coordinate_id)
    ON DELETE RESTRICT,
  FOREIGN KEY(workspace_id,application_id,right_coordinate_id)
    REFERENCES epm.coordinate(workspace_id,application_id,coordinate_id)
    ON DELETE RESTRICT
);

CREATE TABLE epm.ic_elimination_current_line(
  workspace_id text NOT NULL,
  application_id text NOT NULL,
  parent_entity_member_id text NOT NULL,
  pair_key text NOT NULL,
  line_ordinal smallint NOT NULL CHECK(line_ordinal IN (1,2)),
  coordinate_id bigint NOT NULL,
  signed_amount numeric(28,8) NOT NULL CHECK(signed_amount<>0),
  source_change_id text NOT NULL,
  PRIMARY KEY(workspace_id,application_id,parent_entity_member_id,pair_key,
    line_ordinal),
  FOREIGN KEY(workspace_id,application_id,parent_entity_member_id,pair_key)
    REFERENCES epm.ic_elimination_state(
      workspace_id,application_id,parent_entity_member_id,pair_key)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
  FOREIGN KEY(workspace_id,application_id,coordinate_id)
    REFERENCES epm.coordinate(workspace_id,application_id,coordinate_id)
    ON DELETE RESTRICT
);

INSERT INTO epm.ic_elimination_state(
  workspace_id,application_id,parent_entity_member_id,pair_key,state_token,
  status,left_relationship_id,right_relationship_id,left_coordinate_id,
  right_coordinate_id,left_source_change_id,right_source_change_id,
  matched_magnitude,signed_residual,source_metadata_revision,
  source_data_revision,source_policy_revision,committed_revision,issuer,
  subject_id,rule_id,updated_at)
SELECT p.workspace_id,p.application_id,p.parent_entity_member_id,p.pair_key,
  encode(sha256(convert_to(concat_ws(chr(31),'current-ic-elimination',
    p.workspace_id,p.application_id,p.parent_entity_member_id,p.pair_key,
    p.generation_id,p.published_revision::text),'UTF8')),'hex'),
  'PublishedUnreviewed',g.left_relationship_id,g.right_relationship_id,
  g.left_coordinate_id,g.right_coordinate_id,g.left_source_change_id,
  g.right_source_change_id,g.matched_magnitude,g.signed_residual,
  g.source_metadata_revision,g.source_data_revision,g.source_policy_revision,
  p.published_revision,g.issuer,g.subject_id,g.rule_id,p.updated_at
FROM epm.ic_elimination_publication p
JOIN epm.ic_elimination_generation g USING(
  workspace_id,application_id,generation_id);

INSERT INTO epm.ic_elimination_current_line(
  workspace_id,application_id,parent_entity_member_id,pair_key,line_ordinal,
  coordinate_id,signed_amount,source_change_id)
SELECT p.workspace_id,p.application_id,p.parent_entity_member_id,p.pair_key,
  l.line_ordinal,l.coordinate_id,l.signed_amount,l.source_change_id
FROM epm.ic_elimination_publication p
JOIN epm.ic_elimination_line l USING(
  workspace_id,application_id,generation_id);

-- Finish the deferred state/line foreign-key checks before changing table
-- security metadata. PostgreSQL correctly rejects ALTER TABLE while those
-- populated-upgrade trigger events remain pending.
SET CONSTRAINTS ALL IMMEDIATE;

CREATE FUNCTION epm.ic_elimination_state_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $guard$
BEGIN
  IF TG_OP='UPDATE' AND
     (NEW.workspace_id,NEW.application_id,NEW.parent_entity_member_id,
      NEW.pair_key) IS DISTINCT FROM
     (OLD.workspace_id,OLD.application_id,OLD.parent_entity_member_id,
      OLD.pair_key) THEN
    RAISE EXCEPTION 'IC_ELIMINATION_STATE_IDENTITY_IMMUTABLE';
  END IF;
  IF TG_OP='UPDATE' AND NEW.state_token=OLD.state_token THEN
    RAISE EXCEPTION 'IC_ELIMINATION_STATE_TOKEN_NOT_ROTATED';
  END IF;
  IF TG_OP='UPDATE' AND NEW.committed_revision<=OLD.committed_revision THEN
    RAISE EXCEPTION 'IC_ELIMINATION_STATE_REVISION_STALE';
  END IF;
  RETURN NEW;
END $guard$;
CREATE TRIGGER ic_elimination_state_guard
BEFORE UPDATE ON epm.ic_elimination_state FOR EACH ROW
EXECUTE FUNCTION epm.ic_elimination_state_guard();

CREATE FUNCTION epm.ic_elimination_state_complete() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $complete$
DECLARE line_count bigint;
BEGIN
  SELECT count(*) INTO line_count
  FROM epm.ic_elimination_current_line l
  WHERE l.workspace_id=NEW.workspace_id
    AND l.application_id=NEW.application_id
    AND l.parent_entity_member_id=NEW.parent_entity_member_id
    AND l.pair_key=NEW.pair_key;
  IF (NEW.status='PublishedUnreviewed' AND line_count<>2)
     OR (NEW.status='WithdrawnUnreviewed' AND line_count<>0) THEN
    RAISE EXCEPTION 'IC_ELIMINATION_CURRENT_STATE_INCOMPLETE';
  END IF;
  RETURN NULL;
END $complete$;
CREATE CONSTRAINT TRIGGER ic_elimination_state_complete
AFTER INSERT OR UPDATE ON epm.ic_elimination_state
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
EXECUTE FUNCTION epm.ic_elimination_state_complete();

ALTER TABLE epm.ic_elimination_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE epm.ic_elimination_current_line ENABLE ROW LEVEL SECURITY;
CREATE POLICY ic_elimination_state_scope ON epm.ic_elimination_state
  TO epm_runtime,epm_analyst
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
CREATE POLICY ic_elimination_current_line_scope
  ON epm.ic_elimination_current_line TO epm_runtime,epm_analyst
  USING(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true))
  WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
    AND application_id=current_setting('epm.application_id',true));
REVOKE ALL ON epm.ic_elimination_state,epm.ic_elimination_current_line
  FROM PUBLIC,epm_runtime,epm_analyst;
GRANT SELECT,INSERT,UPDATE ON epm.ic_elimination_state TO epm_runtime;
GRANT SELECT,INSERT,DELETE ON epm.ic_elimination_current_line TO epm_runtime;
GRANT SELECT ON epm.ic_elimination_state,epm.ic_elimination_current_line
  TO epm_analyst;

DROP TABLE epm.ic_elimination_withdrawal;
DROP TABLE epm.ic_elimination_line;
DROP TABLE epm.ic_elimination_publication;
DROP TABLE epm.ic_elimination_generation;

DO $migration$
DECLARE definition text; revised text; inventory text[]; idx integer;
DECLARE previous constant text:='c3fe1ab97eae85f70e13abcd17afaa41f0663bd43468864a7923655258c72596';
DECLARE current_graph constant text:='da326bcb0c075788a3e4810931671e2ee6fc66b14b72a1fb9796336d5ec46e67';
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
  INTO definition;
  IF position(previous IN definition)=0
     OR position('''ic_elimination_line'',''ic_elimination_publication''' IN
       definition)=0
     OR position('''ic_elimination_withdrawal'',''ic_elimination_generation''' IN
       definition)=0 THEN
    RAISE EXCEPTION 'RESET_0333_PREDECESSOR_MISMATCH';
  END IF;
  revised:=replace(definition,
    '''ic_elimination_line'',''ic_elimination_publication''',
    '''ic_elimination_current_line'',''ic_elimination_state''');
  revised:=replace(revised,
    '''ic_elimination_withdrawal'',''ic_elimination_generation'',','');
  EXECUTE replace(revised,previous,current_graph);

  inventory:=epm.application_purge_relations();
  idx:=array_position(inventory,'ic_elimination_line');
  IF idx IS NULL OR array_position(inventory,'ic_elimination_publication')
       IS DISTINCT FROM idx+1 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0333_POINTER_ORDER_MISMATCH';
  END IF;
  inventory:=inventory[1:idx-1]||ARRAY[
    'ic_elimination_current_line','ic_elimination_state']||
    inventory[idx+2:];
  inventory:=array_remove(array_remove(inventory,
    'ic_elimination_withdrawal'),'ic_elimination_generation');
  EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() '
    'RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
    'SELECT '||quote_literal(inventory::text)||'::text[]');
  SELECT pg_get_functiondef(
    'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'::regprocedure)
  INTO definition;
  IF position(previous IN definition)=0 THEN
    RAISE EXCEPTION 'APPLICATION_PURGE_0333_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);
END $migration$;

COMMIT;
