BEGIN;
DO $preflight$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM epm.schema_migration WHERE version=365) THEN
  RAISE EXCEPTION 'MIGRATION_0366_REQUIRES_0365';
 END IF;
END $preflight$;

-- These are current typed business owners, including unvalidated drafts.
-- Build IDs become optional diagnostic locators and cease to establish ownership.
ALTER TABLE epm.python_program_definition ADD COLUMN declared_output jsonb;
ALTER TABLE epm.python_program_definition ADD COLUMN owner_rule_id text
 GENERATED ALWAYS AS (CASE WHEN declared_output->>'kind' IN ('ApplicationRule','CalculatedMember')
  THEN declared_output->>'definitionId' END) STORED;
ALTER TABLE epm.python_program_definition ADD COLUMN owner_list_id text
 GENERATED ALWAYS AS (CASE WHEN declared_output->>'kind'='MemberList'
  THEN declared_output->>'definitionId' END) STORED;
ALTER TABLE epm.python_program_definition ADD CONSTRAINT python_declared_output_shape CHECK(
 declared_output IS NULL OR ((jsonb_typeof(declared_output)='object'
 AND jsonb_typeof(declared_output->'kind')='string'
 AND jsonb_typeof(declared_output->'definitionId')='string'
 AND declared_output->>'kind' IN ('ApplicationRule','CalculatedMember','MemberList')
 AND declared_output->>'definitionId' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$'
 AND ((declared_output->>'kind'='MemberList' AND declared_output ?& ARRAY['kind','definitionId','dimensionId']
       AND declared_output-ARRAY['kind','definitionId','dimensionId']='{}'::jsonb
       AND jsonb_typeof(declared_output->'dimensionId')='string'
       AND declared_output->>'dimensionId' ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$')
   OR (declared_output->>'kind'<>'MemberList' AND declared_output ?& ARRAY['kind','definitionId']
       AND declared_output->>'definitionId' ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$'
       AND declared_output-ARRAY['kind','definitionId']='{}'::jsonb))) IS TRUE));
ALTER TABLE epm.python_program_definition ADD CONSTRAINT python_current_source_pin_unique
 UNIQUE(workspace_id,application_id,program_id,source_token,source_digest);
ALTER TABLE epm.python_program_definition ADD CONSTRAINT python_owner_rule_unique
 UNIQUE(workspace_id,application_id,owner_rule_id);
ALTER TABLE epm.python_program_definition ADD CONSTRAINT python_owner_list_unique
 UNIQUE(workspace_id,application_id,owner_list_id);

ALTER TABLE epm.expression_rule_definition
 ADD COLUMN definition_kind text,
 ADD COLUMN ownership_state text NOT NULL DEFAULT 'Configuration',
 ADD COLUMN source_program_id text, ADD COLUMN source_token text, ADD COLUMN source_digest text,
 ADD COLUMN current_certificate jsonb,
 ALTER COLUMN program DROP NOT NULL, ALTER COLUMN program_digest DROP NOT NULL;
UPDATE epm.expression_rule_definition SET definition_kind=CASE program->>'function'
 WHEN 'application.rule.plan' THEN 'ApplicationRule'
 WHEN 'calculated.member.definition' THEN 'CalculatedMember'
 WHEN 'facts.expression.calculate' THEN 'ExpressionRule' END;
DO $kind$ BEGIN
 IF EXISTS(SELECT 1 FROM epm.expression_rule_definition WHERE definition_kind IS NULL) THEN
  RAISE EXCEPTION 'DEFINITION_OWNER_0366_UNKNOWN_RULE_KIND';
 END IF;
END $kind$;
ALTER TABLE epm.expression_rule_definition ALTER COLUMN definition_kind SET NOT NULL;
ALTER TABLE epm.expression_rule_definition ADD CONSTRAINT current_rule_kind CHECK(
 definition_kind IN ('ApplicationRule','CalculatedMember','ExpressionRule'));
ALTER TABLE epm.member_list_definition
 ADD COLUMN ownership_state text NOT NULL DEFAULT 'Configuration',
 ADD COLUMN source_program_id text, ADD COLUMN source_token text, ADD COLUMN source_digest text,
 ADD COLUMN current_certificate jsonb,
 ALTER COLUMN definition DROP NOT NULL, ALTER COLUMN canonical_digest DROP NOT NULL;

-- Exact source/output matches may establish ownership, never validation success.
-- Anything missing, superseded or ambiguous remains one current unresolved object.
CREATE TEMP TABLE definition_owner_0366_map ON COMMIT DROP AS
 SELECT r.workspace_id,r.application_id,'rule'::text relation_kind,r.rule_id object_id,
 r.definition_kind,b.program_id,s.source_token,s.source_digest,
 jsonb_build_object('kind',r.definition_kind,'definitionId',r.rule_id) declared_output
 FROM epm.expression_rule_definition r
 JOIN epm.python_program_build b ON (b.workspace_id,b.application_id,b.build_id)=
  (r.workspace_id,r.application_id,r.source_build_id)
 JOIN epm.python_program_definition s ON (s.workspace_id,s.application_id,s.program_id,s.source_token)=
  (b.workspace_id,b.application_id,b.program_id,b.program_source_token)
 JOIN epm.python_plan_artifact a ON (a.workspace_id,a.application_id,a.build_id)=
  (b.workspace_id,b.application_id,b.build_id)
 WHERE r.definition_kind IN ('ApplicationRule','CalculatedMember')
  AND a.canonical_plan#>'{units,0,operations,0,arguments,definition}'=r.program->'arguments'
  AND COALESCE(a.canonical_plan#>>'{units,0,operations,0,arguments,ruleId}',
   a.canonical_plan#>>'{units,0,operations,0,arguments,definition,definitionId}')=r.rule_id
  AND jsonb_array_length(a.canonical_plan->'units')=1
  AND jsonb_array_length(a.canonical_plan#>'{units,0,operations}')=1
 UNION ALL
 SELECT r.workspace_id,r.application_id,'list',r.list_id,'MemberList',b.program_id,
 s.source_token,s.source_digest,jsonb_build_object('kind','MemberList','definitionId',r.list_id,
 'dimensionId',r.dimension_id)
 FROM epm.member_list_definition r
 JOIN epm.python_program_build b ON (b.workspace_id,b.application_id,b.build_id)=
  (r.workspace_id,r.application_id,r.source_build_id)
 JOIN epm.python_program_definition s ON (s.workspace_id,s.application_id,s.program_id,s.source_token)=
  (b.workspace_id,b.application_id,b.program_id,b.program_source_token)
 JOIN epm.python_plan_artifact a ON (a.workspace_id,a.application_id,a.build_id)=
  (b.workspace_id,b.application_id,b.build_id)
 WHERE a.canonical_plan#>'{units,0,operations,0,arguments,definition}'=r.definition
  AND a.canonical_plan#>>'{units,0,operations,0,function}'='metadata.member_list.save'
  AND jsonb_array_length(a.canonical_plan->'units')=1
  AND jsonb_array_length(a.canonical_plan#>'{units,0,operations}')=1;
-- Any current source implicated in an authored representation is inactive until
-- explicit validation, including ambiguous associations that cannot be adopted.
UPDATE epm.python_program_definition s SET status='Inactive'
 WHERE EXISTS(SELECT 1 FROM epm.python_program_build b
  WHERE (b.workspace_id,b.application_id,b.program_id,b.program_source_token)=
    (s.workspace_id,s.application_id,s.program_id,s.source_token)
  AND (EXISTS(SELECT 1 FROM epm.expression_rule_definition r WHERE
    (r.workspace_id,r.application_id,r.source_build_id)=(b.workspace_id,b.application_id,b.build_id))
   OR EXISTS(SELECT 1 FROM epm.member_list_definition l WHERE
    (l.workspace_id,l.application_id,l.source_build_id)=(b.workspace_id,b.application_id,b.build_id))));
DELETE FROM definition_owner_0366_map m USING (
 SELECT workspace_id,application_id,program_id FROM definition_owner_0366_map
 GROUP BY workspace_id,application_id,program_id HAVING count(*)<>1) bad
 WHERE (m.workspace_id,m.application_id,m.program_id)=
  (bad.workspace_id,bad.application_id,bad.program_id);

UPDATE epm.expression_rule_definition SET ownership_state='Unresolved'
 WHERE source_build_id IS NOT NULL;
UPDATE epm.member_list_definition SET ownership_state='Unresolved'
 WHERE source_build_id IS NOT NULL;
UPDATE epm.expression_rule_definition r SET ownership_state='Source',source_program_id=m.program_id,
 source_token=m.source_token,source_digest=m.source_digest
 FROM definition_owner_0366_map m WHERE m.relation_kind='rule'
 AND (r.workspace_id,r.application_id,r.rule_id)=(m.workspace_id,m.application_id,m.object_id);
UPDATE epm.member_list_definition r SET ownership_state='Source',source_program_id=m.program_id,
 source_token=m.source_token,source_digest=m.source_digest
 FROM definition_owner_0366_map m WHERE m.relation_kind='list'
 AND (r.workspace_id,r.application_id,r.list_id)=(m.workspace_id,m.application_id,m.object_id);
UPDATE epm.python_program_definition s SET declared_output=m.declared_output,status='Inactive'
 FROM definition_owner_0366_map m
 WHERE (s.workspace_id,s.application_id,s.program_id)=(m.workspace_id,m.application_id,m.program_id);

-- Migration invalidates acceptance honestly. Current payloads remain inspectable;
-- only explicit fixed-core revalidation can activate them under the new contract.
UPDATE epm.expression_rule_definition SET status='Inactive',state_token=encode(sha256(
 convert_to(state_token||':definition-owner-0366','UTF8')),'hex');
UPDATE epm.member_list_definition SET status='Inactive',state_token=encode(sha256(
 convert_to(state_token||':definition-owner-0366','UTF8')),'hex');
UPDATE epm.python_program_definition s SET state_token=r.state_token
 FROM epm.expression_rule_definition r WHERE r.ownership_state='Source'
 AND (s.workspace_id,s.application_id,s.program_id)=(r.workspace_id,r.application_id,r.source_program_id);
UPDATE epm.python_program_definition s SET state_token=r.state_token
 FROM epm.member_list_definition r WHERE r.ownership_state='Source'
 AND (s.workspace_id,s.application_id,s.program_id)=(r.workspace_id,r.application_id,r.source_program_id);
UPDATE epm.application_state s SET policy_revision=policy_revision+1,commit_revision=commit_revision+1
 WHERE EXISTS(SELECT 1 FROM epm.expression_rule_definition r
 WHERE (r.workspace_id,r.application_id)=(s.workspace_id,s.application_id))
 OR EXISTS(SELECT 1 FROM epm.member_list_definition r
 WHERE (r.workspace_id,r.application_id)=(s.workspace_id,s.application_id));
UPDATE epm.calculation_scope_state s SET required_epoch=greatest(required_epoch,published_epoch+1),
 reasons=ARRAY(SELECT DISTINCT unnest(s.reasons||ARRAY['definition_changed']::text[])),
 updated_at=transaction_timestamp()
 WHERE EXISTS(SELECT 1 FROM epm.expression_rule_definition r
 WHERE (r.workspace_id,r.application_id)=(s.workspace_id,s.application_id));

DO $constraints$ DECLARE table_name text; constraint_name text; BEGIN
 FOREACH table_name IN ARRAY ARRAY['expression_rule_definition','member_list_definition'] LOOP
  FOR constraint_name IN SELECT c.conname FROM pg_constraint c
   WHERE c.conrelid=('epm.'||table_name)::regclass AND c.contype='f'
   AND c.confrelid='epm.python_program_build'::regclass LOOP
   EXECUTE format('ALTER TABLE epm.%I DROP CONSTRAINT %I',table_name,constraint_name);
  END LOOP;
  EXECUTE format('ALTER TABLE epm.%I ADD CONSTRAINT %I CHECK(
   ownership_state IN (''Configuration'',''Source'',''Unresolved'') AND
   ((ownership_state=''Source'' AND num_nonnulls(source_program_id,source_token,source_digest)=3
      AND source_token~''^[0-9a-f]{64}$'' AND source_digest~''^[0-9a-f]{64}$'')
    OR (ownership_state<>''Source'' AND source_program_id IS NULL
      AND source_token IS NULL AND source_digest IS NULL)) AND
   (ownership_state<>''Unresolved'' OR (status=''Inactive'' AND current_certificate IS NULL)) AND
   (current_certificate IS NULL OR (jsonb_typeof(current_certificate)=''object''
      AND octet_length(current_certificate::text)<=16384)))',table_name,table_name||'_owner_shape');
  EXECUTE format('ALTER TABLE epm.%I ADD CONSTRAINT %I FOREIGN KEY
   (workspace_id,application_id,source_program_id,source_token,source_digest)
   REFERENCES epm.python_program_definition(workspace_id,application_id,program_id,source_token,source_digest)
   DEFERRABLE INITIALLY DEFERRED',table_name,table_name||'_current_source_fk');
  EXECUTE format('GRANT UPDATE(ownership_state,source_program_id,source_token,source_digest,current_certificate)
   ON epm.%I TO epm_runtime',table_name);
 END LOOP;
END $constraints$;
ALTER TABLE epm.expression_rule_definition ADD CONSTRAINT rule_source_owner_unique
 UNIQUE(workspace_id,application_id,source_program_id);
ALTER TABLE epm.member_list_definition ADD CONSTRAINT list_source_owner_unique
 UNIQUE(workspace_id,application_id,source_program_id);
-- The deferred completeness guard below checks the reciprocal source->typed
-- owner association. Avoid a circular FK graph: source deletion and typed-owner
-- deletion are still one required transaction, never independent operations.
GRANT DELETE ON epm.expression_rule_definition TO epm_runtime;
GRANT UPDATE(definition_kind) ON epm.expression_rule_definition TO epm_runtime;

CREATE TABLE epm.current_definition_reference(
 workspace_id text NOT NULL,application_id text NOT NULL,
 consumer_rule_id text,consumer_list_id text,producer_rule_id text,producer_list_id text,
 consumer_kind text GENERATED ALWAYS AS(CASE WHEN consumer_rule_id IS NULL THEN 'list' ELSE 'rule' END) STORED,
 consumer_id text GENERATED ALWAYS AS(coalesce(consumer_rule_id,consumer_list_id)) STORED,
 producer_kind text GENERATED ALWAYS AS(CASE WHEN producer_rule_id IS NULL THEN 'list' ELSE 'rule' END) STORED,
 producer_id text GENERATED ALWAYS AS(coalesce(producer_rule_id,producer_list_id)) STORED,
 CHECK(num_nonnulls(consumer_rule_id,consumer_list_id)=1 AND num_nonnulls(producer_rule_id,producer_list_id)=1),
 PRIMARY KEY(workspace_id,application_id,consumer_kind,consumer_id,producer_kind,producer_id),
 FOREIGN KEY(workspace_id,application_id,consumer_rule_id)
  REFERENCES epm.expression_rule_definition(workspace_id,application_id,rule_id) ON DELETE CASCADE,
 FOREIGN KEY(workspace_id,application_id,consumer_list_id)
  REFERENCES epm.member_list_definition(workspace_id,application_id,list_id) ON DELETE CASCADE,
 FOREIGN KEY(workspace_id,application_id,producer_rule_id)
  REFERENCES epm.expression_rule_definition(workspace_id,application_id,rule_id) ON DELETE RESTRICT,
 FOREIGN KEY(workspace_id,application_id,producer_list_id)
  REFERENCES epm.member_list_definition(workspace_id,application_id,list_id) ON DELETE RESTRICT);
ALTER TABLE epm.current_definition_reference ENABLE ROW LEVEL SECURITY;
CREATE POLICY current_definition_reference_scope ON epm.current_definition_reference TO epm_runtime
 USING(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true))
 WITH CHECK(workspace_id=current_setting('epm.workspace_id',true) AND application_id=current_setting('epm.application_id',true));
CREATE POLICY current_definition_reference_lifecycle ON epm.current_definition_reference TO epm_lifecycle
 USING(workspace_id=current_setting('epm.workspace_id',true));
REVOKE ALL ON epm.current_definition_reference FROM PUBLIC,epm_runtime,epm_worker,epm_analyst,epm_lifecycle;
GRANT SELECT,INSERT,DELETE ON epm.current_definition_reference TO epm_runtime;
GRANT SELECT ON epm.current_definition_reference TO epm_lifecycle;
-- Current reference backfill is performed by the fixed compiler before acceptance;
-- unvalidated migrated definitions cannot execute while this remains incomplete.

-- Remaining integrity guards and deletion inventory integration follow below.
CREATE FUNCTION epm.definition_canonical_json(value jsonb)
RETURNS text LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT CASE jsonb_typeof(value)
  WHEN 'object' THEN '{'||coalesce((SELECT string_agg(to_jsonb(key)::text||':'||
   epm.definition_canonical_json(item),',' ORDER BY key COLLATE "C")
   FROM jsonb_each(value) AS entry(key,item)),'')||'}'
  WHEN 'array' THEN '['||coalesce((SELECT string_agg(epm.definition_canonical_json(item),',' ORDER BY ordinal)
   FROM jsonb_array_elements(value) WITH ORDINALITY AS entry(item,ordinal)),'')||']'
  ELSE value::text END
$$;
CREATE FUNCTION epm.definition_ascii_json(value text)
RETURNS text LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
DECLARE result text:=''; letter text; code integer; BEGIN
 FOREACH letter IN ARRAY string_to_array(value,NULL) LOOP
  code:=ascii(letter);
  IF code<127 THEN result:=result||letter;
  ELSIF code<=65535 THEN result:=result||chr(92)||'u'||lpad(to_hex(code),4,'0');
  ELSE code:=code-65536;result:=result||chr(92)||'u'||to_hex(55296+code/1024)
   ||chr(92)||'u'||to_hex(56320+code%1024);END IF;
 END LOOP;
 RETURN result;
END $$;
CREATE FUNCTION epm.definition_payload_digest(kind text,payload jsonb)
RETURNS text LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT encode(sha256(convert_to(CASE WHEN kind='MemberList' THEN
  epm.definition_ascii_json(epm.definition_canonical_json(payload-'limits'))
  ELSE epm.definition_canonical_json(payload) END,'UTF8')),'hex')
$$;
REVOKE ALL ON FUNCTION epm.definition_canonical_json(jsonb),epm.definition_ascii_json(text),
 epm.definition_payload_digest(text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.definition_canonical_json(jsonb),epm.definition_ascii_json(text),
 epm.definition_payload_digest(text,jsonb) TO epm_runtime;

CREATE FUNCTION epm.definition_static_references(kind text,payload jsonb)
RETURNS TABLE(reference_kind text,reference_id text)
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT DISTINCT 'list'::text,ref#>>'{}'
 FROM jsonb_path_query(payload,'$.** ? (@.kind == "member_list").listId') ref
 WHERE kind<>'MemberList'
 UNION
 SELECT 'rule'::text,ref->>'definitionId'
 FROM jsonb_array_elements(CASE WHEN kind='CalculatedMember'
  THEN coalesce(payload#>'{arguments,dependencies}','[]'::jsonb) ELSE '[]'::jsonb END) ref
$$;
CREATE FUNCTION epm.definition_dependency_digest(w text,a text,kind text,payload jsonb)
RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog AS $$
 SELECT encode(sha256(convert_to(epm.definition_canonical_json(coalesce(jsonb_agg(
  jsonb_build_object('kind',r.reference_kind,'id',r.reference_id,
   'stateToken',coalesce(l.state_token,p.state_token),
   'digest',coalesce(l.canonical_digest,p.program_digest),
   'status',coalesce(l.status,p.status)) ORDER BY r.reference_kind COLLATE "C",r.reference_id COLLATE "C"),
  '[]'::jsonb)),'UTF8')),'hex')
 FROM epm.definition_static_references(kind,payload) r
 LEFT JOIN epm.member_list_definition l ON r.reference_kind='list'
  AND(l.workspace_id,l.application_id,l.list_id)=(w,a,r.reference_id)
 LEFT JOIN epm.expression_rule_definition p ON r.reference_kind='rule'
  AND(p.workspace_id,p.application_id,p.rule_id)=(w,a,r.reference_id)
$$;
REVOKE ALL ON FUNCTION epm.definition_static_references(text,jsonb),
 epm.definition_dependency_digest(text,text,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.definition_static_references(text,jsonb),
 epm.definition_dependency_digest(text,text,text,jsonb) TO epm_runtime;

CREATE FUNCTION epm.definition_certificate_for_build(w text,a text,bid text,k text,oid text,digest text)
RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('format','openepm-current-definition-certificate-v1',
  'semanticsVersion','openepm-current-definition-v1','sourcePurposeContract','openepm-source-purpose-v1',
  'dependencyDigest',epm.definition_dependency_digest(w,a,k,CASE WHEN k='MemberList'
   THEN p.canonical_plan#>'{units,0,operations,0,arguments,definition}'
   ELSE jsonb_build_object('arguments',p.canonical_plan#>'{units,0,operations,0,arguments,definition}') END),
  'acceptance','Validation','kind',k,'definitionId',oid,'compiledDigest',digest,
  'sourceToken',s.source_token,'sourceDigest',s.source_digest,
  'compilerVersion',p.compiler_version,'environmentId',s.environment_id,
  'environmentStateToken',s.environment_state_token,'metadataRevision',b.expected_metadata_revision,
  'policyRevision',b.expected_policy_revision,'schemaEpoch',b.expected_schema_epoch,
  'issuer',b.issuer,'subjectId',b.subject_id,'authorityScopeDigest',b.authorization_scope_digest,
  'diagnosticBuildId',bid,'impactTestAccepted',b.purpose='ImpactTest')
 FROM epm.python_program_build b JOIN epm.python_plan_artifact p USING(workspace_id,application_id,build_id)
 JOIN epm.python_program_definition s ON(s.workspace_id,s.application_id,s.program_id,s.source_token)=
  (b.workspace_id,b.application_id,b.program_id,b.program_source_token)
 WHERE b.workspace_id=w AND b.application_id=a AND b.build_id=bid AND b.status='sealed'
  AND b.purpose IN ('Validation','ImpactTest')
  AND p.sealed_at>clock_timestamp()-interval '24 hours'
  AND (b.purpose='Validation' OR p.impact->>'status'='complete')
  AND p.source_map->>'sourceDigest'=s.source_digest
  AND s.declared_output->>'kind'=k AND s.declared_output->>'definitionId'=oid
$$;
REVOKE ALL ON FUNCTION epm.definition_certificate_for_build(text,text,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.definition_certificate_for_build(text,text,text,text,text,text) TO epm_runtime;

CREATE FUNCTION epm.current_definition_owner_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE x jsonb:=to_jsonb(NEW);previous jsonb; payload jsonb; old_payload jsonb;
 kind text; object_id text; digest text; checked_build_id text; plan jsonb; expected jsonb; stored_function text;
BEGIN
 IF TG_TABLE_NAME='expression_rule_definition' THEN
  kind:=NEW.definition_kind;object_id:=NEW.rule_id;payload:=NEW.program;digest:=NEW.program_digest;
  stored_function:=CASE kind WHEN 'ApplicationRule' THEN 'application.rule.plan'
   WHEN 'CalculatedMember' THEN 'calculated.member.definition' ELSE 'facts.expression.calculate' END;
  IF payload IS NOT NULL AND payload->>'function' IS DISTINCT FROM stored_function THEN
   RAISE EXCEPTION 'DEFINITION_OWNER_KIND_MISMATCH' USING ERRCODE='23514';
  END IF;
 ELSE
  kind:='MemberList';object_id:=NEW.list_id;payload:=NEW.definition;digest:=NEW.canonical_digest;
  IF payload IS NOT NULL AND (payload->>'listId' IS DISTINCT FROM object_id
   OR payload->>'dimensionId' IS DISTINCT FROM NEW.dimension_id) THEN
   RAISE EXCEPTION 'DEFINITION_OWNER_IDENTITY_MISMATCH' USING ERRCODE='23514';
  END IF;
 END IF;
 IF payload IS NOT NULL AND digest IS DISTINCT FROM epm.definition_payload_digest(kind,payload) THEN
  RAISE EXCEPTION 'DEFINITION_PAYLOAD_DIGEST_MISMATCH' USING ERRCODE='23514';
 END IF;
 IF (payload IS NULL) IS DISTINCT FROM (digest IS NULL) THEN
  RAISE EXCEPTION 'DEFINITION_OWNER_PAYLOAD_DIGEST_REQUIRED' USING ERRCODE='23514';
 END IF;
 IF NEW.status IN('Active','Published') AND (NEW.ownership_state='Unresolved'
   OR payload IS NULL OR NEW.current_certificate IS NULL) THEN
  RAISE EXCEPTION 'DEFINITION_CURRENT_CERTIFICATE_REQUIRED' USING ERRCODE='23514';
 END IF;
 IF TG_OP='UPDATE' THEN
  previous:=to_jsonb(OLD);
  IF OLD.ownership_state='Source' AND (NEW.ownership_state<>'Source'
   OR NEW.source_program_id IS DISTINCT FROM OLD.source_program_id) THEN
   RAISE EXCEPTION 'DEFINITION_SOURCE_ASSOCIATION_IMMUTABLE' USING ERRCODE='23514';
  END IF;
  IF (x->>'workspace_id',x->>'application_id',kind,object_id) IS DISTINCT FROM
    (previous->>'workspace_id',previous->>'application_id',
     CASE WHEN TG_TABLE_NAME='member_list_definition' THEN 'MemberList' ELSE previous->>'definition_kind' END,
     coalesce(previous->>'rule_id',previous->>'list_id')) THEN
   RAISE EXCEPTION 'DEFINITION_OWNER_IDENTITY_IMMUTABLE' USING ERRCODE='23514';
  END IF;
  old_payload:=CASE WHEN TG_TABLE_NAME='member_list_definition' THEN previous->'definition' ELSE previous->'program' END;
 END IF;
 IF NEW.current_certificate IS NOT NULL THEN
  IF payload IS NULL OR NEW.current_certificate->>'format' IS DISTINCT FROM 'openepm-current-definition-certificate-v1'
   OR NEW.current_certificate->>'semanticsVersion' IS DISTINCT FROM 'openepm-current-definition-v1'
   OR NEW.current_certificate->>'sourcePurposeContract' IS DISTINCT FROM 'openepm-source-purpose-v1'
   OR NEW.current_certificate->>'compiledDigest' IS DISTINCT FROM digest
   OR NEW.current_certificate->>'kind' IS DISTINCT FROM kind
   OR NEW.current_certificate->>'definitionId' IS DISTINCT FROM object_id
   OR jsonb_typeof(NEW.current_certificate->'metadataRevision') IS DISTINCT FROM 'number'
   OR jsonb_typeof(NEW.current_certificate->'schemaEpoch') IS DISTINCT FROM 'number'
   OR jsonb_typeof(NEW.current_certificate->'impactTestAccepted') IS DISTINCT FROM 'boolean'
   OR (NEW.current_certificate->>'metadataRevision')::bigint IS DISTINCT FROM NEW.metadata_revision THEN
   RAISE EXCEPTION 'DEFINITION_CURRENT_CERTIFICATE_MISMATCH' USING ERRCODE='23514';
  END IF;
  IF TG_OP='INSERT' OR NEW.current_certificate IS DISTINCT FROM OLD.current_certificate
   OR payload IS DISTINCT FROM old_payload THEN
   IF (NEW.current_certificate->>'schemaEpoch')::bigint IS DISTINCT FROM (
     SELECT a.schema_epoch FROM epm.application_state a WHERE
      (a.workspace_id,a.application_id)=(NEW.workspace_id,NEW.application_id)) THEN
    RAISE EXCEPTION 'DEFINITION_CURRENT_SCHEMA_MISMATCH' USING ERRCODE='23514';
   END IF;
   IF NEW.current_certificate->>'dependencyDigest' IS DISTINCT FROM
     epm.definition_dependency_digest(NEW.workspace_id,NEW.application_id,kind,payload) THEN
    RAISE EXCEPTION 'DEFINITION_CURRENT_DEPENDENCY_MISMATCH' USING ERRCODE='23514';
   END IF;
  END IF;
  IF NEW.ownership_state='Source' THEN
   IF NEW.current_certificate->>'sourceToken' IS DISTINCT FROM NEW.source_token
    OR NEW.current_certificate->>'sourceDigest' IS DISTINCT FROM NEW.source_digest THEN
    RAISE EXCEPTION 'DEFINITION_CURRENT_SOURCE_MISMATCH' USING ERRCODE='23514';
   END IF;
   -- Unchanged current acceptance survives expiration/deletion of diagnostics.
   IF TG_OP='INSERT' OR NEW.current_certificate IS DISTINCT FROM OLD.current_certificate
    OR payload IS DISTINCT FROM old_payload THEN
    checked_build_id:=NEW.current_certificate->>'diagnosticBuildId';
    expected:=epm.definition_certificate_for_build(NEW.workspace_id,NEW.application_id,checked_build_id,kind,object_id,digest);
    IF expected IS NULL OR NEW.current_certificate IS DISTINCT FROM expected THEN
     RAISE EXCEPTION 'DEFINITION_VALIDATED_BUILD_REQUIRED' USING ERRCODE='23514';
    END IF;
    SELECT a.canonical_plan INTO plan FROM epm.python_plan_artifact a
     WHERE a.workspace_id=NEW.workspace_id AND a.application_id=NEW.application_id AND a.build_id=checked_build_id;
    IF jsonb_array_length(plan->'units')<>1 OR jsonb_array_length(plan#>'{units,0,operations}')<>1
     OR plan#>'{units,0,operations,0,arguments,definition}' IS DISTINCT FROM
      (CASE WHEN kind='MemberList' THEN payload ELSE payload->'arguments' END) THEN
     RAISE EXCEPTION 'DEFINITION_COMPILED_PAYLOAD_MISMATCH' USING ERRCODE='23514';
    END IF;
   END IF;
  ELSIF NEW.ownership_state='Configuration' THEN
   IF NEW.current_certificate->>'acceptance' IS DISTINCT FROM 'FixedValidation'
    OR NEW.current_certificate->>'compilerVersion' IS DISTINCT FROM 'openepm-fixed-definition-v1' THEN
    RAISE EXCEPTION 'DEFINITION_FIXED_VALIDATION_REQUIRED' USING ERRCODE='23514';
   END IF;
  ELSE
   RAISE EXCEPTION 'DEFINITION_OWNERSHIP_UNRESOLVED' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.current_definition_owner_guard() FROM PUBLIC;
CREATE TRIGGER current_expression_rule_owner_guard BEFORE INSERT OR UPDATE
 ON epm.expression_rule_definition FOR EACH ROW EXECUTE FUNCTION epm.current_definition_owner_guard();
CREATE TRIGGER current_member_list_owner_guard BEFORE INSERT OR UPDATE
 ON epm.member_list_definition FOR EACH ROW EXECUTE FUNCTION epm.current_definition_owner_guard();

CREATE FUNCTION epm.current_source_owner_identity_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
 IF OLD.declared_output IS NOT NULL AND NEW.declared_output IS DISTINCT FROM OLD.declared_output THEN
  RAISE EXCEPTION 'DEFINITION_OWNER_RETARGET_REQUIRES_REPLACEMENT' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION epm.current_source_owner_identity_guard() FROM PUBLIC;
CREATE TRIGGER current_source_owner_identity_guard BEFORE UPDATE OF declared_output
 ON epm.python_program_definition FOR EACH ROW EXECUTE FUNCTION epm.current_source_owner_identity_guard();

CREATE FUNCTION epm.current_source_owner_complete() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE x jsonb; s epm.python_program_definition%ROWTYPE; owner_row jsonb; pid text;
BEGIN
 x:=CASE WHEN TG_OP='DELETE' THEN to_jsonb(OLD) ELSE to_jsonb(NEW) END;
 pid:=CASE WHEN TG_TABLE_NAME='python_program_definition' THEN x->>'program_id' ELSE x->>'source_program_id' END;
 IF pid IS NULL THEN RETURN NULL;END IF;
 SELECT * INTO s FROM epm.python_program_definition WHERE workspace_id=x->>'workspace_id'
  AND application_id=x->>'application_id' AND program_id=pid;
 IF NOT FOUND THEN RETURN NULL;END IF; -- incoming scoped FK covers dangling owners
 IF s.declared_output IS NULL THEN
  IF EXISTS(SELECT 1 FROM epm.expression_rule_definition WHERE workspace_id=s.workspace_id
    AND application_id=s.application_id AND source_program_id=pid)
   OR EXISTS(SELECT 1 FROM epm.member_list_definition WHERE workspace_id=s.workspace_id
    AND application_id=s.application_id AND source_program_id=pid) THEN
   RAISE EXCEPTION 'DEFINITION_DECLARED_OWNER_REQUIRED' USING ERRCODE='23514';
  END IF;
  RETURN NULL;
 END IF;
 IF s.declared_output->>'kind'='MemberList' THEN
  SELECT to_jsonb(r) INTO owner_row FROM epm.member_list_definition r
   WHERE workspace_id=s.workspace_id AND application_id=s.application_id
    AND list_id=s.declared_output->>'definitionId'
    AND dimension_id=s.declared_output->>'dimensionId';
 ELSE
  SELECT to_jsonb(r) INTO owner_row FROM epm.expression_rule_definition r
   WHERE workspace_id=s.workspace_id AND application_id=s.application_id
    AND rule_id=s.declared_output->>'definitionId' AND definition_kind=s.declared_output->>'kind';
 END IF;
 IF (SELECT count(*) FROM (
   SELECT rule_id FROM epm.expression_rule_definition WHERE workspace_id=s.workspace_id
    AND application_id=s.application_id AND source_program_id=pid
   UNION ALL SELECT list_id FROM epm.member_list_definition WHERE workspace_id=s.workspace_id
    AND application_id=s.application_id AND source_program_id=pid) owned)<>1 THEN
  RAISE EXCEPTION 'DEFINITION_SOURCE_OWNER_CARDINALITY' USING ERRCODE='23514';
 END IF;
 IF owner_row IS NULL OR owner_row->>'ownership_state' IS DISTINCT FROM 'Source'
  OR owner_row->>'source_program_id' IS DISTINCT FROM pid
  OR owner_row->>'source_token' IS DISTINCT FROM s.source_token
  OR owner_row->>'source_digest' IS DISTINCT FROM s.source_digest
  OR owner_row->>'state_token' IS DISTINCT FROM s.state_token
  OR (owner_row->>'status' IN ('Active','Published')) IS DISTINCT FROM(s.status='Active') THEN
  RAISE EXCEPTION 'DEFINITION_SOURCE_OWNER_INCOMPLETE' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION epm.current_source_owner_complete() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER current_source_owner_complete AFTER INSERT OR UPDATE OR DELETE
 ON epm.python_program_definition DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW EXECUTE FUNCTION epm.current_source_owner_complete();
CREATE CONSTRAINT TRIGGER current_rule_source_complete AFTER INSERT OR UPDATE OR DELETE
 ON epm.expression_rule_definition DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW EXECUTE FUNCTION epm.current_source_owner_complete();
CREATE CONSTRAINT TRIGGER current_list_source_complete AFTER INSERT OR UPDATE OR DELETE
 ON epm.member_list_definition DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW EXECUTE FUNCTION epm.current_source_owner_complete();

DROP FUNCTION epm.source_bound_definition_guard();

-- Current static references use the existing canonical selector/dependency IDs.
-- They also cover inactive definitions that have never executed.
INSERT INTO epm.current_definition_reference(workspace_id,application_id,consumer_rule_id,producer_list_id)
 SELECT DISTINCT r.workspace_id,r.application_id,r.rule_id,p.list_id
 FROM epm.expression_rule_definition r
 CROSS JOIN LATERAL jsonb_path_query(r.program,'$.** ? (@.kind == "member_list").listId') ref
 JOIN epm.member_list_definition p ON(p.workspace_id,p.application_id,p.list_id)=
  (r.workspace_id,r.application_id,ref#>>'{}') ON CONFLICT DO NOTHING;
INSERT INTO epm.current_definition_reference(workspace_id,application_id,consumer_rule_id,producer_rule_id)
 SELECT DISTINCT r.workspace_id,r.application_id,r.rule_id,p.rule_id
 FROM epm.expression_rule_definition r
 CROSS JOIN LATERAL jsonb_array_elements(coalesce(r.program#>'{arguments,dependencies}','[]'::jsonb)) ref
 JOIN epm.expression_rule_definition p ON(p.workspace_id,p.application_id,p.rule_id)=
  (r.workspace_id,r.application_id,ref->>'definitionId')
 WHERE r.definition_kind='CalculatedMember' ON CONFLICT DO NOTHING;

-- The reference rows are a constrained projection of current typed payloads.
-- Deferred checks permit one transaction to replace payload and references.
CREATE FUNCTION epm.current_definition_reference_complete() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE snapshots jsonb[]; x jsonb; w text; a text; ck text; cid text;
 k text; payload jsonb; wanted jsonb; observed jsonb;
BEGIN
 snapshots:=CASE WHEN TG_OP='INSERT' THEN ARRAY[to_jsonb(NEW)]
  WHEN TG_OP='DELETE' THEN ARRAY[to_jsonb(OLD)] ELSE ARRAY[to_jsonb(OLD),to_jsonb(NEW)] END;
 FOREACH x IN ARRAY snapshots LOOP
  w:=x->>'workspace_id';a:=x->>'application_id';
  IF TG_TABLE_NAME='current_definition_reference' THEN
   ck:=x->>'consumer_kind';cid:=x->>'consumer_id';
  ELSE
   ck:=CASE WHEN TG_TABLE_NAME='member_list_definition' THEN 'list' ELSE 'rule' END;
   cid:=coalesce(x->>'list_id',x->>'rule_id');
  END IF;
  IF ck='list' THEN
   SELECT 'MemberList',l.definition INTO k,payload FROM epm.member_list_definition l
    WHERE (l.workspace_id,l.application_id,l.list_id)=(w,a,cid);
  ELSE
   SELECT r.definition_kind,r.program INTO k,payload FROM epm.expression_rule_definition r
    WHERE (r.workspace_id,r.application_id,r.rule_id)=(w,a,cid);
  END IF;
  IF NOT FOUND THEN CONTINUE;END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_array(r.reference_kind,r.reference_id)
    ORDER BY r.reference_kind COLLATE "C",r.reference_id COLLATE "C"),'[]'::jsonb)
   INTO wanted FROM epm.definition_static_references(k,payload) r;
  SELECT coalesce(jsonb_agg(jsonb_build_array(r.producer_kind,r.producer_id)
    ORDER BY r.producer_kind COLLATE "C",r.producer_id COLLATE "C"),'[]'::jsonb)
   INTO observed FROM epm.current_definition_reference r
   WHERE (r.workspace_id,r.application_id,r.consumer_kind,r.consumer_id)=(w,a,ck,cid);
  IF wanted IS DISTINCT FROM observed THEN
   RAISE EXCEPTION 'DEFINITION_REFERENCE_PROJECTION_MISMATCH' USING ERRCODE='23514';
  END IF;
 END LOOP;
 RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION epm.current_definition_reference_complete() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER current_rule_reference_complete AFTER INSERT OR UPDATE
 ON epm.expression_rule_definition DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW EXECUTE FUNCTION epm.current_definition_reference_complete();
CREATE CONSTRAINT TRIGGER current_list_reference_complete AFTER INSERT OR UPDATE
 ON epm.member_list_definition DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW EXECUTE FUNCTION epm.current_definition_reference_complete();
CREATE CONSTRAINT TRIGGER current_reference_projection_complete AFTER INSERT OR UPDATE OR DELETE
 ON epm.current_definition_reference DEFERRABLE INITIALLY DEFERRED
 FOR EACH ROW EXECUTE FUNCTION epm.current_definition_reference_complete();

DO $inventory$ DECLARE definition text;inventory text[];idx integer;parent text; BEGIN
 SELECT pg_get_functiondef('epm.delete_workspace_reset_owner_only(text,text,text,text,text)'::regprocedure)
  INTO definition;
 IF position('''expression_rule_definition''' IN definition)=0 THEN
  RAISE EXCEPTION 'RESET_0366_OWNER_PARENT_MISSING';
 END IF;
 parent:=CASE WHEN position('''member_list_definition''' IN definition)<
  position('''expression_rule_definition''' IN definition) THEN 'member_list_definition'
  ELSE 'expression_rule_definition' END;
 EXECUTE replace(definition,quote_literal(parent),
  '''current_definition_reference'','||quote_literal(parent));
 inventory:=epm.application_purge_relations();
 IF array_position(inventory,'expression_rule_definition') IS NULL
  OR array_position(inventory,'member_list_definition') IS NULL THEN
  RAISE EXCEPTION 'PURGE_0366_OWNER_PARENT_MISSING';END IF;
 idx:=least(array_position(inventory,'expression_rule_definition'),array_position(inventory,'member_list_definition'));
 inventory:=inventory[1:idx-1]||ARRAY['current_definition_reference']||inventory[idx:];
 EXECUTE format('CREATE OR REPLACE FUNCTION epm.application_purge_relations() '
  'RETURNS text[] LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS %L',
  'SELECT '||quote_literal(inventory::text)||'::text[]');
END $inventory$;
-- A current acceptance certificate does not keep diagnostic payloads alive.
ALTER TABLE epm.python_program_build DROP CONSTRAINT python_impact_expired_purpose;
CREATE OR REPLACE FUNCTION epm.python_definition_parameters_immutable()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
 IF NEW.definition_parameters IS DISTINCT FROM OLD.definition_parameters AND NOT(
  NEW.status IN('expired','failed','cancelled') AND NEW.definition_parameters='{}'::jsonb AND NEW.parameter_values='{}'::jsonb
  AND NOT EXISTS(SELECT 1 FROM epm.python_plan_artifact a WHERE
   (a.workspace_id,a.application_id,a.build_id)=(NEW.workspace_id,NEW.application_id,NEW.build_id))) THEN
  RAISE EXCEPTION 'PYTHON_DEFINITION_PARAMETERS_IMMUTABLE' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION epm.definition_source_payload_retire(w text,a text,pid text,token text)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE affected integer; BEGIN
 IF current_setting('epm.workspace_id',true) IS DISTINCT FROM w
  OR current_setting('epm.application_id',true) IS DISTINCT FROM a
  OR NOT EXISTS(SELECT 1 FROM epm.python_program_definition s WHERE
   (s.workspace_id,s.application_id,s.program_id,s.source_token)=(w,a,pid,token)) THEN
  RAISE EXCEPTION 'DEFINITION_PAYLOAD_RETIREMENT_SCOPE_INVALID' USING ERRCODE='42501';
 END IF;
 IF EXISTS(SELECT 1 FROM epm.python_program_build b WHERE
  (b.workspace_id,b.application_id,b.program_id,b.program_source_token)=(w,a,pid,token)
  AND b.status IN('accepted','ready','running','cancel_requested')) THEN
  RAISE EXCEPTION 'DEFINITION_PAYLOAD_ACTIVE_WORK_BLOCKER';
 END IF;
 IF EXISTS(SELECT 1 FROM epm.python_program_build b JOIN epm.python_program_workflow f
  USING(workspace_id,application_id,build_id) WHERE
  (b.workspace_id,b.application_id,b.program_id,b.program_source_token)=(w,a,pid,token)) THEN
  RAISE EXCEPTION 'DEFINITION_PAYLOAD_WORKFLOW_REFERENCE';
 END IF;
 DELETE FROM epm.python_plan_artifact p USING epm.python_program_build b WHERE
  (p.workspace_id,p.application_id,p.build_id)=(b.workspace_id,b.application_id,b.build_id)
  AND(b.workspace_id,b.application_id,b.program_id,b.program_source_token)=(w,a,pid,token);
 GET DIAGNOSTICS affected=ROW_COUNT;
 UPDATE epm.python_program_build b SET status=CASE WHEN status='sealed' THEN 'expired' ELSE status END,parameter_values='{}'::jsonb,
  definition_parameters='{}'::jsonb,diagnostics=NULL,updated_at=transaction_timestamp()
  WHERE(b.workspace_id,b.application_id,b.program_id,b.program_source_token)=(w,a,pid,token)
   AND b.status IN('sealed','failed','cancelled','expired');
 RETURN affected;
END $$;
REVOKE ALL ON FUNCTION epm.definition_source_payload_retire(text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION epm.definition_source_payload_retire(text,text,text,text) TO epm_runtime;

CREATE OR REPLACE FUNCTION epm.python_impact_expire()
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE target record;locked boolean;changed integer:=0; BEGIN
 FOR target IN SELECT p.workspace_id,p.application_id,p.build_id FROM epm.python_plan_artifact p
  JOIN epm.python_program_build b USING(workspace_id,application_id,build_id)
  WHERE p.sealed_at<clock_timestamp()-interval '24 hours'
   AND b.purpose IN('Validation','ImpactTest') AND b.status='sealed'
  ORDER BY p.sealed_at,p.workspace_id,p.application_id,p.build_id LIMIT 10 LOOP
  SELECT pg_try_advisory_xact_lock_shared(hashtextextended('epm.security.workspace:'||target.workspace_id,0)) INTO locked;
  IF NOT locked THEN CONTINUE;END IF;
  PERFORM 1 FROM epm.python_program_build b WHERE
   (b.workspace_id,b.application_id,b.build_id)=(target.workspace_id,target.application_id,target.build_id)
   AND b.status='sealed' FOR UPDATE SKIP LOCKED;
  IF NOT FOUND THEN CONTINUE;END IF;
  DELETE FROM epm.python_plan_artifact p WHERE
   (p.workspace_id,p.application_id,p.build_id)=(target.workspace_id,target.application_id,target.build_id)
   AND p.sealed_at<clock_timestamp()-interval '24 hours' AND NOT EXISTS(
    SELECT 1 FROM epm.python_program_workflow f WHERE
     (f.workspace_id,f.application_id,f.build_id)=(p.workspace_id,p.application_id,p.build_id));
  IF FOUND THEN
   UPDATE epm.python_program_build b SET status='expired',parameter_values='{}'::jsonb,
    definition_parameters='{}'::jsonb,diagnostics=NULL,error_code=NULL,updated_at=transaction_timestamp()
    WHERE(b.workspace_id,b.application_id,b.build_id)=(target.workspace_id,target.application_id,target.build_id);
   changed:=changed+1;
  END IF;
 END LOOP;
 RETURN changed;
END $$;
COMMENT ON FUNCTION epm.python_impact_expire() IS
 'Bounded current diagnostic maintenance: retire at most ten Validation/ImpactTest payloads after24h; current certificates do not depend on them.';

-- Qualified on the fresh366 schema by inspect_reset_schema; the same graph is
-- required by both destructive lifecycle primitives before any deletion.
DO $graph$ DECLARE signature text;definition text;
 previous constant text:='2e8767f44870298dacdb34265d459cea5017d699ada909c682d59fba1e0a46ac';
 current_graph constant text:='b10318fc081736be88091fb3f13bbcf31b7f545d6dda8decce0bffca23080508';
BEGIN
 FOREACH signature IN ARRAY ARRAY[
  'epm.delete_workspace_reset_owner_only(text,text,text,text,text)',
  'epm.apply_application_purge(text,text,timestamptz,text,text,text,text)'] LOOP
  SELECT pg_get_functiondef(signature::regprocedure) INTO definition;
  IF position(previous IN definition)=0 THEN
   RAISE EXCEPTION 'DEFINITION_0366_LIFECYCLE_GRAPH_PREDECESSOR_MISMATCH';
  END IF;
  EXECUTE replace(definition,previous,current_graph);
 END LOOP;
END $graph$;
COMMIT;
