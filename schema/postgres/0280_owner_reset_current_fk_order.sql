BEGIN;

DO $migration$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM epm.schema_migration WHERE version=279) THEN
    RAISE EXCEPTION 'MIGRATION_0280_REQUIRES_0279';
  END IF;
END $migration$;

-- Replace the complete reset inventory with the stable topological order of
-- all 162 managed tables under the schema-279 FK graph. The predecessor body
-- is exact-digest bound. The post-change audit maps documented logical
-- projection names to physical relations and rejects every missing or
-- parent-before-child non-self FK edge before this transaction can commit.
DO $migration$
DECLARE definition text; revised text; remainder text; old_body text;
DECLARE marker constant text := 'FOREACH v_table IN ARRAY ARRAY[';
DECLARE marker_position integer; body_position integer; closing_position integer;
DECLARE new_body constant text := $inventory$
        'python_program_schedule_state','python_program_workflow_child','python_program_publication','python_environment_current',
        'cube_aggregate_result','cube_aggregate_query','projection_cleanup_manifest','projection_recovery_manifest','coordinate_projection',
        'generic_fact_event','generic_fact_current','rollup_placement_path_edge','rollup_source_lineage','rollup_placement_path',
        'ownership_value_event','ownership_value_current','allocation_basis_lineage','relationship','cube_write_scope_submission_event',
        'manual_journal_calculation_source','manual_journal_line','hierarchy_closure','hierarchy_active','expression_rule_publication',
        'coordinate_member','calendar_period_event','calendar_period_current','ic_elimination_line','ic_elimination_publication',
        'cta_bridge_unit_effect','cta_bridge_source','cta_bridge','consolidation_layout_state','consolidation_layout_version',
        'inventory_unrealized_schedule_state','inventory_unrealized_schedule_version','calculation_ratio_result',
        'calculation_unit_result','calculation_result','calculation_publication','text_fact_event','text_cell_current',
        'planning_seed_lineage','source_batch_row','source_batch_chunk','semantic_column','policy_pack_draft',
        'acquisition_journal_line','acquisition_journal','policy_activation_current','policy_activation_event',
        'policy_acquisition_approval','policy_acquisition_case_review','policy_acquisition_case_bundle','policy_source_artifact',
        'financial_period_close_event','financial_period_close','cube_write_scope_lock_event','planning_copy_origin',
        'numeric_fact_event','numeric_cell_current','member','manual_journal','line_detail_event','line_detail_current',
        'job_event','job_dependency','hierarchy_version','ic_elimination_withdrawal','ic_elimination_generation',
        'calculation_generation','application_schedule_state','application_rule_workflow_child','raw_operation_membership',
        'execution_delegation_state','fact_export_producer_page','fact_export_payload_chunk','fact_export_payload',
        'fact_export_artifact','fact_export_producer_request','source_import_diagnostic_artifact',
        'layout_replacement_activation_coordinate','layout_replacement_activation','layout_replacement_validation_certificate',
        'layout_replacement_materialization_chunk','layout_replacement_private_detail','layout_replacement_private_text',
        'layout_replacement_private_numeric','layout_replacement_private_coordinate','layout_replacement_materialization',
        'layout_replacement_staged_coordinate','layout_replacement_generation','layout_replacement_request',
        'planning_operation_policy_state','planning_operation_policy_version','cube_write_scope_assigned_review_event',
        'cube_write_scope_assigned_reviewer','cube_write_scope_assigned_submission','cube_write_scope_submission',
        'cube_write_scope_lock','transfer_cleanup_certificate','transfer_cleanup_request','task_event','task',
        'python_program_occurrence','python_program_schedule_version','source_import_execution','source_batch',
        'application_schedule_occurrence','application_schedule_version','application_rule_workflow','expression_rule_version',
        'task_cursor','statement_definition_event','statement_definition_state','statement_definition_version',
        'retired_product_history','application_workflow_evidence_link','application_workflow_event',
        'application_workflow_activity','application_workflow_occurrence','application_workflow_assignment_pin',
        'application_workflow_state','application_workflow_version','application_assignment_state','application_assignment_version',
        'cube_write_policy_state','cube_write_policy_version','member_list_publication','member_list_version',
        'job_event_cursor','job','python_program_workflow','python_plan_artifact','python_program_build','python_program_version',
        'python_environment_version','execution_delegation_version','operation_receipt','generic_fact_table',
        'expression_rule_sequence','full_aggregate_sequence','coordinate','security_tag','attribute_definition','dimension',
        'coordinate_layout','rule_group_access_grant','rule_access_grant','sealed_cube_selection','saved_grid_definition',
        'dimensional_security_policy_version','application_state','application_group_access_grant','application_access_grant',
        'workspace_lifecycle_receipt','workspace_group_access_grant','workspace_access_grant','security_operation_receipt',
        'application','worker_workspace_dispatch','workspace'$inventory$;
BEGIN
  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  marker_position := position(marker IN definition);
  IF marker_position=0 THEN
    RAISE EXCEPTION 'RESET_0280_DEFINITION_MISMATCH';
  END IF;
  body_position := marker_position + length(marker);
  remainder := substring(definition FROM body_position);
  closing_position := position(']' IN remainder);
  IF closing_position=0 THEN
    RAISE EXCEPTION 'RESET_0280_DEFINITION_MISMATCH';
  END IF;
  old_body := substring(remainder FOR closing_position-1);
  IF length(old_body)<>4633 OR md5(old_body)<>'4e8d0f9a549950f9e36323bbe8124287' THEN
    RAISE EXCEPTION 'RESET_0280_PREDECESSOR_DIGEST_MISMATCH';
  END IF;
  revised := substring(definition FROM 1 FOR body_position-1)
    || new_body || substring(remainder FROM closing_position);
  IF revised=definition THEN
    RAISE EXCEPTION 'RESET_0280_UPDATE_FAILED';
  END IF;
  EXECUTE revised;

  SELECT pg_get_functiondef(
    'epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
    INTO definition;
  IF EXISTS (
    WITH edges AS (
      SELECT child.relname AS child, parent.relname AS parent,
        CASE child.relname
          WHEN 'numeric_cell_projection' THEN 'numeric_cell_current'
          WHEN 'text_cell_projection' THEN 'text_cell_current'
          WHEN 'line_detail_projection' THEN 'line_detail_current'
          WHEN 'generic_fact_projection' THEN 'generic_fact_current'
          WHEN 'coordinate_member_projection' THEN 'coordinate_member'
          WHEN 'coordinate_projection_state' THEN 'coordinate_projection'
          ELSE child.relname END AS child_key,
        CASE parent.relname
          WHEN 'numeric_cell_projection' THEN 'numeric_cell_current'
          WHEN 'text_cell_projection' THEN 'text_cell_current'
          WHEN 'line_detail_projection' THEN 'line_detail_current'
          WHEN 'generic_fact_projection' THEN 'generic_fact_current'
          WHEN 'coordinate_member_projection' THEN 'coordinate_member'
          WHEN 'coordinate_projection_state' THEN 'coordinate_projection'
          ELSE parent.relname END AS parent_key
      FROM pg_constraint AS constraint_row
      JOIN pg_class AS child ON child.oid=constraint_row.conrelid
      JOIN pg_namespace AS child_namespace
        ON child_namespace.oid=child.relnamespace
      JOIN pg_class AS parent ON parent.oid=constraint_row.confrelid
      JOIN pg_namespace AS parent_namespace
        ON parent_namespace.oid=parent.relnamespace
      WHERE constraint_row.contype='f'
        AND child_namespace.nspname='epm'
        AND parent_namespace.nspname='epm'
        AND child.oid<>parent.oid
    ), positioned AS (
      SELECT position(quote_literal(child_key) IN definition) AS child_position,
        position(quote_literal(parent_key) IN definition) AS parent_position
      FROM edges
    )
    SELECT 1 FROM positioned
    WHERE child_position=0 OR parent_position=0
       OR child_position>parent_position
  ) THEN
    RAISE EXCEPTION 'RESET_0280_FK_ORDER_AUDIT_FAILED';
  END IF;
END $migration$;

COMMIT;
