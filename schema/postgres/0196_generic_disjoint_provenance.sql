-- Preserve both the caller's initially current revision and the later
-- publication-base revision when a disjoint generic series commits first.
CREATE OR REPLACE FUNCTION epm.generic_provenance_validate(w text,a text,op text) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,epm AS $$
DECLARE r epm.operation_receipt%ROWTYPE; p jsonb; args jsonb; changes jsonb;
    f text; n integer; expected_keys text[]; encoding text;
BEGIN
    PERFORM epm.fact_scope_check(w,a);
    SELECT * INTO r FROM epm.operation_receipt
      WHERE workspace_id=w AND application_id=a AND operation_id=op;
    IF r.operation_id IS NULL THEN
        RAISE EXCEPTION 'GENERIC_FACT_RECEIPT_REQUIRED' USING ERRCODE='23514';
    END IF;
    p := r.provenance;
    IF p IS NULL THEN RETURN; END IF;
    IF jsonb_typeof(p) IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'GENERIC_FACT_PROVENANCE_INVALID' USING ERRCODE='23514';
    END IF;
    IF NOT(p ?& ARRAY['version','encoding','languageVersion','function','issuer','subjectId','arguments'])
       OR p-ARRAY['version','encoding','languageVersion','function','issuer','subjectId','arguments']<>'{}'::jsonb
       OR p->'version' IS DISTINCT FROM '1'::jsonb
       OR p->'languageVersion' IS DISTINCT FROM '2'::jsonb
       OR coalesce(p->>'encoding','') NOT IN
          ('generic-event-references-v1','generic-event-references-v2')
       OR jsonb_typeof(p->'issuer') IS DISTINCT FROM 'string' OR coalesce(p->>'issuer','')=''
       OR jsonb_typeof(p->'subjectId') IS DISTINCT FROM 'string'
       OR p->>'subjectId' IS DISTINCT FROM r.actor_id
       OR jsonb_typeof(p->'function') IS DISTINCT FROM 'string'
       OR jsonb_typeof(p->'arguments') IS DISTINCT FROM 'object' THEN
        RAISE EXCEPTION 'GENERIC_FACT_PROVENANCE_INVALID' USING ERRCODE='23514';
    END IF;
    f := p->>'function'; args := p->'arguments'; encoding := p->>'encoding';
    IF f IN ('facts.generic.table.create','facts.generic.table.update','facts.generic.table.delete') THEN
        IF encoding<>'generic-event-references-v1' THEN
            RAISE EXCEPTION 'GENERIC_FACT_PROVENANCE_INVALID' USING ERRCODE='23514';
        END IF;
        expected_keys := CASE f
          WHEN 'facts.generic.table.create' THEN ARRAY['name','shortDescription','semanticDefinition','expectedMetadataRevision']
          WHEN 'facts.generic.table.update' THEN ARRAY['tableId','name','shortDescription','semanticDefinition','status','expectedMetadataRevision']
          ELSE ARRAY['tableId','expectedMetadataRevision'] END;
        IF NOT(args ?& expected_keys) OR args-expected_keys<>'{}'::jsonb
           OR jsonb_typeof(args->'expectedMetadataRevision') IS DISTINCT FROM 'number'
           OR coalesce(args->>'expectedMetadataRevision','')!~'^(0|[1-9][0-9]*)$' THEN
            RAISE EXCEPTION 'GENERIC_FACT_PROVENANCE_INVALID' USING ERRCODE='23514';
        END IF;
        IF r.result->'metadataRevision' IS DISTINCT FROM to_jsonb((args->>'expectedMetadataRevision')::numeric+1)
           OR EXISTS(SELECT 1 FROM epm.generic_fact_event
              WHERE workspace_id=w AND application_id=a AND operation_id=op) THEN
            RAISE EXCEPTION 'GENERIC_FACT_PROVENANCE_INVALID' USING ERRCODE='23514';
        END IF;
        IF f<>'facts.generic.table.create' AND
           (jsonb_typeof(args->'tableId') IS DISTINCT FROM 'string'
            OR args->>'tableId' IS DISTINCT FROM r.result->>'tableId') THEN
            RAISE EXCEPTION 'GENERIC_FACT_PROVENANCE_INVALID' USING ERRCODE='23514';
        END IF;
        IF f<>'facts.generic.table.delete' AND
           (jsonb_typeof(args->'name') IS DISTINCT FROM 'string'
            OR jsonb_typeof(args->'shortDescription') IS DISTINCT FROM 'string'
            OR jsonb_typeof(args->'semanticDefinition') IS DISTINCT FROM 'string'
            OR args->>'name' IS DISTINCT FROM r.result->>'name') THEN
            RAISE EXCEPTION 'GENERIC_FACT_PROVENANCE_INVALID' USING ERRCODE='23514';
        END IF;
        IF f='facts.generic.table.update' AND
           (jsonb_typeof(args->'status') IS DISTINCT FROM 'string'
            OR args->>'status' IS DISTINCT FROM r.result->>'status') THEN
            RAISE EXCEPTION 'GENERIC_FACT_PROVENANCE_INVALID' USING ERRCODE='23514';
        END IF;
        RETURN;
    END IF;
    expected_keys := CASE encoding
      WHEN 'generic-event-references-v2' THEN
        ARRAY['tableId','expectedDataRevision','publicationBaseDataRevision','changes']
      ELSE ARRAY['tableId','expectedDataRevision','changes'] END;
    IF f NOT IN ('facts.generic.value.set','facts.generic.value.delete','facts.generic.value.bulk')
       OR NOT(args ?& expected_keys) OR args-expected_keys<>'{}'::jsonb
       OR jsonb_typeof(args->'tableId') IS DISTINCT FROM 'string'
       OR args->>'tableId' IS DISTINCT FROM r.result->>'tableId'
       OR jsonb_typeof(args->'expectedDataRevision') IS DISTINCT FROM 'number'
       OR coalesce(args->>'expectedDataRevision','')!~'^(0|[1-9][0-9]*)$'
       OR (encoding='generic-event-references-v2' AND
          (jsonb_typeof(args->'publicationBaseDataRevision') IS DISTINCT FROM 'number'
           OR coalesce(args->>'publicationBaseDataRevision','')!~'^(0|[1-9][0-9]*)$'
           OR (args->>'expectedDataRevision')::numeric>
              (args->>'publicationBaseDataRevision')::numeric))
       OR jsonb_typeof(args->'changes') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'GENERIC_FACT_PROVENANCE_INVALID' USING ERRCODE='23514';
    END IF;
    changes := args->'changes'; n := jsonb_array_length(changes);
    IF n NOT BETWEEN 1 AND 100 OR (f<>'facts.generic.value.bulk' AND n<>1)
       OR r.result->'dataRevision' IS DISTINCT FROM to_jsonb(
          (CASE encoding WHEN 'generic-event-references-v2'
             THEN args->>'publicationBaseDataRevision'
             ELSE args->>'expectedDataRevision' END)::numeric+1)
       OR (SELECT count(*) FROM epm.generic_fact_event
           WHERE workspace_id=w AND application_id=a AND operation_id=op)<>n THEN
        RAISE EXCEPTION 'GENERIC_FACT_PROVENANCE_INVALID' USING ERRCODE='23514';
    END IF;
    IF f='facts.generic.value.bulk' AND
       (jsonb_typeof(r.result->'changes') IS DISTINCT FROM 'array'
        OR jsonb_array_length(r.result->'changes')<>n) THEN
        RAISE EXCEPTION 'GENERIC_FACT_PROVENANCE_INVALID' USING ERRCODE='23514';
    END IF;
    IF EXISTS(SELECT 1 FROM jsonb_array_elements(changes) c
       WHERE jsonb_typeof(c) IS DISTINCT FROM 'object') THEN
        RAISE EXCEPTION 'GENERIC_FACT_PROVENANCE_INVALID' USING ERRCODE='23514';
    END IF;
    IF EXISTS(SELECT 1 FROM jsonb_array_elements(changes) c
       WHERE jsonb_typeof(c->'action') IS DISTINCT FROM 'string'
          OR coalesce(c->>'action','') NOT IN ('Set','Delete')
          OR NOT(c ?& CASE WHEN c->>'action'='Set'
             THEN ARRAY['action','seriesKey','expectedChangeId','eventId','valueField']
             ELSE ARRAY['action','seriesKey','expectedChangeId','eventId'] END)
          OR c-(CASE WHEN c->>'action'='Set'
             THEN ARRAY['action','seriesKey','expectedChangeId','eventId','valueField']
             ELSE ARRAY['action','seriesKey','expectedChangeId','eventId'] END)<>'{}'::jsonb
          OR jsonb_typeof(c->'seriesKey') IS DISTINCT FROM 'string'
          OR jsonb_typeof(c->'expectedChangeId') IS DISTINCT FROM 'string'
          OR jsonb_typeof(c->'eventId') IS DISTINCT FROM 'string'
          OR coalesce(c->>'eventId','')!~'^[0-9a-f]{32}$'
          OR (c->>'action'='Set' AND c->'valueField' IS DISTINCT FROM '"after_value"'::jsonb)
          OR (f='facts.generic.value.set' AND c->>'action'<>'Set')
          OR (f='facts.generic.value.delete' AND c->>'action'<>'Delete'))
       OR (SELECT count(DISTINCT c->>'eventId') FROM jsonb_array_elements(changes)c)<>n THEN
        RAISE EXCEPTION 'GENERIC_FACT_PROVENANCE_INVALID' USING ERRCODE='23514';
    END IF;
    IF EXISTS(WITH refs AS(SELECT value AS c,ordinality AS ordinal,
         CASE WHEN f='facts.generic.value.bulk'
           THEN r.result->'changes'->((ordinality-1)::integer) ELSE r.result END AS output
         FROM jsonb_array_elements(changes) WITH ORDINALITY)
       SELECT 1 FROM refs i LEFT JOIN epm.generic_fact_event e
         ON e.workspace_id=w AND e.application_id=a AND e.operation_id=op AND e.event_id=i.c->>'eventId'
       WHERE e.event_id IS NULL OR e.table_id IS DISTINCT FROM args->>'tableId'
          OR e.series_key IS DISTINCT FROM i.c->>'seriesKey'
          OR e.before_change_id IS DISTINCT FROM i.c->>'expectedChangeId'
          OR (e.action='Delete') IS DISTINCT FROM (i.c->>'action'='Delete')
          OR e.actor_id IS DISTINCT FROM p->>'subjectId'
          OR e.committed_revision<>r.committed_revision
          OR i.output->>'seriesKey' IS DISTINCT FROM e.series_key
          OR i.output->'deleted' IS DISTINCT FROM to_jsonb(e.action='Delete')
          OR i.output->>'changeId' IS DISTINCT FROM CASE WHEN e.action='Delete' THEN '' ELSE e.resulting_change_id END) THEN
        RAISE EXCEPTION 'GENERIC_FACT_PROVENANCE_INVALID' USING ERRCODE='23514';
    END IF;
END $$;
