-- One reviewed generic-value batch can produce several events under one
-- operation receipt. Keep an operation unique per series, not per event.
ALTER TABLE epm.generic_fact_event
    DROP CONSTRAINT generic_fact_event_workspace_id_application_id_operation_id_key;
CREATE UNIQUE INDEX generic_fact_event_operation_series
    ON epm.generic_fact_event
    (workspace_id,application_id,operation_id,table_id,series_key);
