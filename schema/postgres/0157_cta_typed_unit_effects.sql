-- CTA v3 publishes authoritative typed-unit effects without raw fact writes.
DO $$DECLARE c text;BEGIN
 SELECT conname INTO c FROM pg_constraint WHERE conrelid='epm.cta_bridge'::regclass
  AND contype='c' AND pg_get_constraintdef(oid) LIKE '%compiler_version%cta-bridge-v2%';
 IF c IS NULL THEN RAISE EXCEPTION 'CTA_COMPILER_CONSTRAINT_NOT_FOUND';END IF;
 EXECUTE format('ALTER TABLE epm.cta_bridge DROP CONSTRAINT %I',c);
END$$;
ALTER TABLE epm.cta_bridge ALTER COLUMN journal_id DROP NOT NULL;
ALTER TABLE epm.cta_bridge
 ADD CONSTRAINT cta_bridge_compiler_version CHECK(
  compiler_version IN('cta-bridge-v2','cta-bridge-v3-typed-unit')),
 ADD CONSTRAINT cta_bridge_effect_shape CHECK(
  (compiler_version='cta-bridge-v2' AND journal_id IS NOT NULL) OR
  (compiler_version='cta-bridge-v3-typed-unit' AND journal_id IS NULL));

CREATE TABLE epm.cta_bridge_unit_effect(
 workspace_id text NOT NULL,application_id text NOT NULL,bridge_id text NOT NULL,
 effect_ordinal integer NOT NULL CHECK(effect_ordinal IN(1,2)),
 effect_role text NOT NULL CHECK(effect_role IN('CTA','Offset')),
 coordinate_id text NOT NULL,currency_dimension_id text NOT NULL,
 currency_member_id text NOT NULL,amount numeric(28,8) NOT NULL,
 source_ref text NOT NULL CHECK(length(source_ref) BETWEEN 1 AND 500),
 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
 PRIMARY KEY(workspace_id,application_id,bridge_id,effect_ordinal),
 UNIQUE(workspace_id,application_id,bridge_id,effect_role),
 UNIQUE(workspace_id,application_id,bridge_id,coordinate_id,
        currency_dimension_id,currency_member_id),
 FOREIGN KEY(workspace_id,application_id,bridge_id) REFERENCES
  epm.cta_bridge(workspace_id,application_id,bridge_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,coordinate_id) REFERENCES
  epm.coordinate(workspace_id,application_id,coordinate_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,currency_dimension_id,currency_member_id)
  REFERENCES epm.member(workspace_id,application_id,dimension_id,member_id)
  ON DELETE RESTRICT);
GRANT SELECT,INSERT ON epm.cta_bridge_unit_effect TO epm_runtime;
GRANT SELECT ON epm.cta_bridge_unit_effect TO epm_lifecycle;
ALTER TABLE epm.cta_bridge_unit_effect ENABLE ROW LEVEL SECURITY;
CREATE POLICY cta_bridge_unit_effect_runtime ON epm.cta_bridge_unit_effect
 TO epm_runtime USING(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true)
  AND application_id=current_setting('epm.application_id',true));
CREATE POLICY cta_bridge_unit_effect_lifecycle ON epm.cta_bridge_unit_effect
 FOR SELECT TO epm_lifecycle USING(
  workspace_id=current_setting('epm.workspace_id',true));

DO $$DECLARE d text;r text;
 old text:='''cta_bridge_source'',''cta_bridge'',''consolidation_layout_state''';
 new text:='''cta_bridge_unit_effect'',''cta_bridge_source'',''cta_bridge'',''consolidation_layout_state''';
BEGIN SELECT pg_get_functiondef(
 'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
 INTO d;IF position(old in d)=0 THEN
 RAISE EXCEPTION 'RESET_0157_DEFINITION_MISMATCH';END IF;
 r=replace(d,old,new);EXECUTE r;END$$;
