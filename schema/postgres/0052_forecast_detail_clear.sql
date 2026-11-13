-- Preserve history when a selected forecast replacement removes an
-- unmentioned supporting-detail cell. Current detail presence remains the
-- existence of a row; the event stream records an explicit absent state.
ALTER TABLE epm.line_detail_event
    ADD COLUMN present boolean NOT NULL DEFAULT true,
    ADD CONSTRAINT line_detail_event_clear_shape CHECK (
        present OR (prior_items IS NOT NULL
            AND items='[]'::jsonb AND total=0));

GRANT DELETE ON epm.line_detail_current TO epm_runtime;
