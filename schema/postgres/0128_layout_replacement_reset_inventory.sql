-- Signed reset inventory must expose the same populated-layout work that the
-- owner delete primitive already fences.  This adds read-only lifecycle
-- visibility only; worker mutation authority and terminal artifacts are
-- unchanged.
-- Fail before mutation on replay or drift from the exact owner-delete states.
DO $$
DECLARE definition text;
BEGIN
 SELECT pg_get_functiondef(
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
 INTO definition;
 IF definition NOT LIKE '%status IN (''Accepted'',''Staging'',''Staged'')%'
 OR definition NOT LIKE '%UNSETTLED_LAYOUT_REPLACEMENT%'
 OR definition NOT LIKE '%status IN (''Requested'',''Activating'')%'
 OR definition NOT LIKE '%UNSETTLED_LAYOUT_ACTIVATION%'
 OR (SELECT count(*) FROM pg_policies WHERE schemaname='epm'
      AND tablename='layout_replacement_activation'
      AND policyname='layout_replacement_activation_lifecycle_inventory')<>0
 THEN RAISE EXCEPTION 'RESET_0128_DEFINITION_MISMATCH'; END IF;
END $$;

GRANT SELECT(target_generation_id,status,claim_generation,claimant,lease_until,
 updated_at) ON epm.layout_replacement_request TO epm_lifecycle;

CREATE POLICY layout_replacement_activation_lifecycle_inventory
 ON epm.layout_replacement_activation TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));
GRANT SELECT(workspace_id,application_id,activation_id,request_id,status,
 claim_generation,claimant,lease_until,updated_at)
 ON epm.layout_replacement_activation TO epm_lifecycle;
