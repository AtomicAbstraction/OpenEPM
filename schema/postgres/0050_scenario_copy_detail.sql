-- Carry supporting-detail lines through typed source staging, including
-- scenario copy, and one numeric/detail publication transaction.
CREATE FUNCTION epm.detail_items_match_total(items jsonb, expected numeric)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE
SET search_path=pg_catalog AS $$
DECLARE item jsonb;
DECLARE part numeric;
DECLARE total numeric := 0;
BEGIN
    IF jsonb_typeof(items) IS DISTINCT FROM 'array'
       OR jsonb_array_length(items) > 500 THEN
        RETURN false;
    END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(items) LOOP
        IF jsonb_typeof(item) IS DISTINCT FROM 'object'
           OR jsonb_typeof(item->'description') IS DISTINCT FROM 'string'
           OR length(item->>'description') NOT BETWEEN 1 AND 80
           OR jsonb_typeof(item->'amount') IS DISTINCT FROM 'string'
           OR (item->>'amount') !~ '^-?[0-9]+(\.[0-9]{1,8})?$' THEN
            RETURN false;
        END IF;
        part := (item->>'amount')::numeric;
        IF part <= -100000000000000000000::numeric
           OR part >= 100000000000000000000::numeric THEN
            RETURN false;
        END IF;
        total := total + part;
    END LOOP;
    RETURN total = expected;
EXCEPTION WHEN others THEN
    RETURN false;
END $$;

ALTER TABLE epm.source_batch_row
    DROP CONSTRAINT source_batch_row_typed_value,
    ADD COLUMN detail_items jsonb,
    ADD CONSTRAINT source_batch_row_typed_value CHECK (
        (value_kind='numeric' AND amount IS NOT NULL
            AND text_value IS NULL AND detail_items IS NULL)
        OR (value_kind='text' AND amount IS NULL
            AND text_value IS NOT NULL AND length(text_value)<=32768
            AND detail_items IS NULL)
        OR (value_kind='detail' AND amount IS NOT NULL
            AND text_value IS NULL AND detail_items IS NOT NULL
            AND epm.detail_items_match_total(detail_items,amount)));

-- The original uniqueness allowed only one detail coordinate per revision.
-- Scenario copy publishes multiple coordinates with one receipt/revision.
DO $$
DECLARE old_name text;
BEGIN
    SELECT conname INTO old_name FROM pg_constraint
    WHERE conrelid='epm.line_detail_event'::regclass
      AND contype='u'
      AND pg_get_constraintdef(oid) =
        'UNIQUE (workspace_id, application_id, committed_revision)';
    IF old_name IS NULL THEN
        RAISE EXCEPTION 'LINE_DETAIL_REVISION_CONSTRAINT_MISSING';
    END IF;
    EXECUTE format('ALTER TABLE epm.line_detail_event DROP CONSTRAINT %I',
                   old_name);
END $$;
ALTER TABLE epm.line_detail_event
    ADD CONSTRAINT line_detail_event_revision_coordinate_unique
    UNIQUE (workspace_id,application_id,committed_revision,coordinate_id);
