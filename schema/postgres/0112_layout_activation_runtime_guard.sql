-- Restore ordinary runtime projection writes after 0110.  The helper remains
-- fail closed: non-owner callers cannot satisfy its owner-role/context check.
GRANT EXECUTE ON FUNCTION epm.layout_replacement_activation_allowed(
    text,text,bigint,text) TO epm_runtime;

CREATE FUNCTION epm.layout_replacement_activation_cancel(
    w text,a text,aid text,expected_status text,expected_version bigint)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE n integer;
BEGIN
    IF w<>current_setting('epm.workspace_id',true)
       OR a<>current_setting('epm.application_id',true) THEN
        RAISE EXCEPTION 'LAYOUT_ACTIVATION_SCOPE_INVALID';
    END IF;
    IF expected_status<>'Requested' OR expected_version<0 THEN
        RAISE EXCEPTION 'LAYOUT_ACTIVATION_CANCEL_INVALID';
    END IF;
    UPDATE epm.layout_replacement_activation
       SET status='Cancelled',claim_generation=claim_generation+1,
           claimant=NULL,lease_until=NULL,updated_at=transaction_timestamp()
     WHERE workspace_id=w AND application_id=a AND activation_id=aid
       AND status=expected_status AND claim_generation=expected_version;
    GET DIAGNOSTICS n=ROW_COUNT;
    RETURN n=1;
END $$;
REVOKE ALL ON FUNCTION epm.layout_replacement_activation_cancel(
    text,text,text,text,bigint) FROM PUBLIC,epm_runtime,epm_worker;
GRANT EXECUTE ON FUNCTION epm.layout_replacement_activation_cancel(
    text,text,text,text,bigint) TO epm_runtime;

-- The active projection and immutable event stream must advance together.
-- 0110 populated the replacement projection but omitted remap events, making
-- the next ordinary write fail lineage validation and making reconstruction
-- disagree with current state.  This trigger runs inside the same activation
-- transaction, after the pointer/revision switch and before receipt sealing.
CREATE FUNCTION epm.layout_activation_record_events() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE x epm.layout_replacement_activation%ROWTYPE;
DECLARE generation text;
BEGIN
    IF NEW.active_projection_generation=OLD.active_projection_generation THEN
        RETURN NULL;
    END IF;
    SELECT * INTO x FROM epm.layout_replacement_activation
     WHERE workspace_id=NEW.workspace_id AND application_id=NEW.application_id
       AND target_projection_generation=NEW.active_projection_generation
       AND status='Activating';
    IF NOT FOUND OR NOT epm.layout_replacement_activation_allowed(
        NEW.workspace_id,NEW.application_id,
        NEW.active_projection_generation,'activate') THEN
        RETURN NULL;
    END IF;
    SELECT generation_id INTO generation
      FROM epm.layout_replacement_validation_certificate
     WHERE workspace_id=x.workspace_id AND application_id=x.application_id
       AND request_id=x.request_id;

    INSERT INTO epm.operation_receipt(workspace_id,application_id,operation_id,
        command_digest,actor_id,committed_revision,result)
    VALUES(x.workspace_id,x.application_id,x.activation_id,x.validation_digest,
        x.subject_id,NEW.commit_revision,jsonb_build_object(
        'activationId',x.activation_id,'requestId',x.request_id,
        'committedRevision',NEW.commit_revision,'schemaEpoch',x.target_schema_epoch,
        'projectionGeneration',x.target_projection_generation,
        'historyPreserved',true));

    INSERT INTO epm.numeric_fact_event(workspace_id,application_id,coordinate_id,
        operation_id,line_ordinal,kind,delta,present,resulting_amount,change_id,
        committed_revision)
    SELECT x.workspace_id,x.application_id,m.coordinate_id,x.activation_id,
        row_number() OVER(ORDER BY m.coordinate_id),
        CASE WHEN n.present THEN 'set' ELSE 'clear' END,
        coalesce(n.amount,0)-coalesce(prior.resulting_amount,0),
        n.present,n.amount,'layout:'||x.activation_id,NEW.commit_revision
      FROM epm.layout_replacement_activation_coordinate m
      JOIN epm.layout_replacement_private_numeric n
        ON n.workspace_id=m.workspace_id AND n.application_id=m.application_id
       AND n.target_digest=m.target_digest AND n.generation_id=generation
      LEFT JOIN LATERAL(SELECT e.resulting_amount
          FROM epm.numeric_fact_event e
         WHERE e.workspace_id=m.workspace_id AND e.application_id=m.application_id
           AND e.coordinate_id=m.coordinate_id
         ORDER BY e.committed_revision DESC,e.line_ordinal DESC LIMIT 1)prior ON true
     WHERE m.workspace_id=x.workspace_id AND m.application_id=x.application_id
       AND m.activation_id=x.activation_id;

    INSERT INTO epm.text_fact_event(workspace_id,application_id,coordinate_id,
        operation_id,line_ordinal,kind,prior_present,prior_value,present,
        resulting_value,change_id,committed_revision)
    SELECT x.workspace_id,x.application_id,m.coordinate_id,x.activation_id,
        row_number() OVER(ORDER BY m.coordinate_id),
        CASE WHEN t.present THEN 'set' ELSE 'clear' END,
        coalesce(prior.present,false),prior.resulting_value,t.present,t.text_value,
        'layout:'||x.activation_id,NEW.commit_revision
      FROM epm.layout_replacement_activation_coordinate m
      JOIN epm.layout_replacement_private_text t
        ON t.workspace_id=m.workspace_id AND t.application_id=m.application_id
       AND t.target_digest=m.target_digest AND t.generation_id=generation
      LEFT JOIN LATERAL(SELECT e.present,e.resulting_value
          FROM epm.text_fact_event e
         WHERE e.workspace_id=m.workspace_id AND e.application_id=m.application_id
           AND e.coordinate_id=m.coordinate_id
         ORDER BY e.committed_revision DESC,e.line_ordinal DESC LIMIT 1)prior ON true
     WHERE m.workspace_id=x.workspace_id AND m.application_id=x.application_id
       AND m.activation_id=x.activation_id;

    INSERT INTO epm.line_detail_event(workspace_id,application_id,coordinate_id,
        operation_id,prior_items,prior_total,items,total,change_id,
        committed_revision,present)
    SELECT x.workspace_id,x.application_id,m.coordinate_id,x.activation_id,
        prior.items,prior.total,
        CASE WHEN d.present THEN d.items ELSE '[]'::jsonb END,
        CASE WHEN d.present THEN d.total ELSE 0 END,
        'layout:'||x.activation_id,NEW.commit_revision,d.present
      FROM epm.layout_replacement_activation_coordinate m
      JOIN epm.layout_replacement_private_detail d
        ON d.workspace_id=m.workspace_id AND d.application_id=m.application_id
       AND d.target_digest=m.target_digest AND d.generation_id=generation
      LEFT JOIN LATERAL(SELECT e.present,e.items,e.total
          FROM epm.line_detail_event e
         WHERE e.workspace_id=m.workspace_id AND e.application_id=m.application_id
           AND e.coordinate_id=m.coordinate_id
         ORDER BY e.committed_revision DESC LIMIT 1)prior ON true
     WHERE m.workspace_id=x.workspace_id AND m.application_id=x.application_id
       AND m.activation_id=x.activation_id
       AND (d.present OR coalesce(prior.present,false));
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION epm.layout_activation_record_events() FROM PUBLIC;

CREATE FUNCTION epm.layout_activation_receipt_replay() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,epm AS $$
DECLARE prior epm.operation_receipt%ROWTYPE;
BEGIN
    SELECT r.* INTO prior FROM epm.operation_receipt r
      JOIN epm.layout_replacement_activation x
        ON x.workspace_id=r.workspace_id AND x.application_id=r.application_id
       AND x.activation_id=r.operation_id
     WHERE r.workspace_id=NEW.workspace_id AND r.application_id=NEW.application_id
       AND r.operation_id=NEW.operation_id AND x.status='Activating'
       AND epm.layout_replacement_activation_allowed(
           x.workspace_id,x.application_id,x.target_projection_generation,'activate');
    IF FOUND THEN
        IF (to_jsonb(prior)-'sealed'-'committed_at')
           IS DISTINCT FROM (to_jsonb(NEW)-'sealed'-'committed_at') THEN
            RAISE EXCEPTION 'LAYOUT_ACTIVATION_RECEIPT_CONFLICT';
        END IF;
        RETURN NULL;
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.layout_activation_receipt_replay() FROM PUBLIC;
CREATE TRIGGER aa_layout_activation_receipt_replay
BEFORE INSERT ON epm.operation_receipt FOR EACH ROW
EXECUTE FUNCTION epm.layout_activation_receipt_replay();
CREATE TRIGGER layout_activation_record_events
AFTER UPDATE OF active_projection_generation ON epm.application_state
FOR EACH ROW EXECUTE FUNCTION epm.layout_activation_record_events();

