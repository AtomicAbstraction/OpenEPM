-- A scheduled forecast must pin the closed-Actual boundary used to resolve
-- its next fiscal window.  Existing opaque schedule rows cannot be guessed.
ALTER TABLE epm.planning_forecast_schedule_version
    ADD COLUMN actual_closed_through date;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM epm.planning_forecast_schedule_version
           WHERE actual_closed_through IS NULL)
 THEN RAISE EXCEPTION 'FORECAST_SCHEDULE_BOUNDARY_BACKFILL_UNPROVEN'; END IF;
END $$;
ALTER TABLE epm.planning_forecast_schedule_version
    ALTER COLUMN actual_closed_through SET NOT NULL;
