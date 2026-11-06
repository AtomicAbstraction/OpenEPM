"""Versioned, application-scoped structural statement definitions.

Definitions declare complete source slots and exact equations.  They remain
policy-neutral: publishing one proves only the application's declared
structural coverage, never professional accounting review or certification.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .consolidation_statement_definition import StatementDefinition
from .persistence_contract import ApplicationScope
from .postgres_access import (PostgresAccessChecker, VerifiedIdentity,
    assert_nonowner_role)
from .postgres_connection import connect_postgres
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_processing_limits import (configure_lock_wait,
    configure_statement_timeout)


SAVE="consolidation.statement.definition.save"
READ="consolidation.statement.definition.read"
LIST="consolidation.statement.definition.list"
PUBLISH="consolidation.statement.definition.publish"
DEACTIVATE="consolidation.statement.definition.deactivate"
FUNCTIONS=frozenset((SAVE,READ,LIST,PUBLISH,DEACTIVATE))
_ID=re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
_KEY=re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
_DIGEST=re.compile(r"[0-9a-f]{64}\Z")


def catalog()->dict:
    common={"requiredCapabilities":["financial_consolidation"],
            "previewRequired":False,"workClass":"short"}
    return {
      SAVE:{**common,"mode":"immutable_policy_write","permission":"admin",
        "idempotencyRequired":True,
        "arguments":{"definition":"bounded immutable structural definition"},
        "result":"immutable definition version, exact digest and receipt"},
      READ:{**common,"mode":"read","permission":"read",
        "idempotencyRequired":False,
        "arguments":{"definitionId":"stable definition ID",
                     "version":"positive immutable version"},
        "result":"verified immutable definition and active-pointer state"},
      LIST:{**common,"mode":"read","permission":"read",
        "idempotencyRequired":False,
        "arguments":{"limit":"optional 1-100",
          "afterDefinitionId":"optional composite cursor definition ID",
          "afterVersion":"optional composite cursor version"},
        "result":"bounded verified immutable definitions"},
      PUBLISH:{**common,"mode":"atomic_policy_write","permission":"admin",
        "idempotencyRequired":True,
        "arguments":{"definitionId":"immutable definition ID",
          "version":"positive immutable version",
          "definitionDigest":"exact canonical digest",
          "expectedPointerVersion":"current nonnegative pointer version"},
        "result":"exact active definition pointer and receipt"},
      DEACTIVATE:{**common,"mode":"atomic_policy_write","permission":"admin",
        "idempotencyRequired":True,
        "arguments":{"definitionId":"active definition ID",
          "version":"active immutable version",
          "definitionDigest":"active canonical digest",
          "expectedPointerVersion":"current positive pointer version"},
        "result":"inactive pointer and immutable event/receipt"}}


class PostgresStatementDefinitions:
    def __init__(self,dsn: str,*,identity: VerifiedIdentity):
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError("A verified identity is required")
        assert_nonowner_role(dsn,"epm_runtime",(
            "statement_definition_version","statement_definition_state",
            "statement_definition_event"))
        self.dsn,self.identity=dsn,identity

    def execute_program(self,scope: ApplicationScope,program: object,*,
                        idempotency_key: str|None=None)->dict:
        function,args=_program(program)
        if function==SAVE:
            if set(args)!={"definition"} or idempotency_key is None:
                raise ValueError("STATEMENT_DEFINITION_ARGUMENTS_INVALID")
            return self.save(scope,args["definition"],
                             idempotency_key=idempotency_key)
        if function in (PUBLISH,DEACTIVATE):
            if set(args)!={"definitionId","version","definitionDigest",
                           "expectedPointerVersion"} or idempotency_key is None:
                raise ValueError("STATEMENT_DEFINITION_ARGUMENTS_INVALID")
            method=self.publish if function==PUBLISH else self.deactivate
            return method(scope,definition_id=args["definitionId"],
              version=args["version"],definition_digest=args["definitionDigest"],
              expected_pointer_version=args["expectedPointerVersion"],
              idempotency_key=idempotency_key)
        raise ValueError("STATEMENT_DEFINITION_WRITE_FUNCTION_INVALID")

    def read_program(self,scope: ApplicationScope,program: object)->dict:
        function,args=_program(program)
        if function==READ:
            if set(args)!={"definitionId","version"}:
                raise ValueError("STATEMENT_DEFINITION_ARGUMENTS_INVALID")
            return self.read(scope,args["definitionId"],args["version"])
        if function==LIST:
            if set(args)-{"limit","afterDefinitionId","afterVersion"}:
                raise ValueError("STATEMENT_DEFINITION_ARGUMENTS_INVALID")
            return self.list(scope,limit=args.get("limit",100),
              after_definition_id=args.get("afterDefinitionId"),
              after_version=args.get("afterVersion"))
        raise ValueError("STATEMENT_DEFINITION_READ_FUNCTION_INVALID")

    def save(self,scope: ApplicationScope,raw: object,*,
             idempotency_key: str)->dict:
        definition=StatementDefinition.parse(raw)
        _request_key(idempotency_key)
        command={"scope":[scope.workspace_id,scope.application_id],
          "actor":[self.identity.issuer,self.identity.subject_id],
          "function":SAVE,"definition":definition.normalized(),
          "idempotencyKey":idempotency_key}
        digest=_digest(command)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                state=self._prepare(db,scope,SAVE,"admin",lock_state=True)
                prior=self._replay(db,scope,idempotency_key,digest)
                if prior is not None:return prior
                self._require_active(state)
                existing=db.execute('''SELECT canonical_digest FROM
                  epm.statement_definition_version WHERE workspace_id=%s
                  AND application_id=%s AND definition_id=%s AND version=%s''',
                  (scope.workspace_id,scope.application_id,
                   definition.definition_id,definition.version)).fetchone()
                if existing:
                    raise ValueError("STATEMENT_DEFINITION_VERSION_CONFLICT")
                pointer=db.execute('''SELECT latest_version,active_version,
                  active_digest,pointer_version,state_revision
                  FROM epm.statement_definition_state WHERE workspace_id=%s
                  AND application_id=%s AND definition_id=%s FOR UPDATE''',
                  (scope.workspace_id,scope.application_id,
                   definition.definition_id)).fetchone()
                expected=(pointer["latest_version"]+1 if pointer else 1)
                if definition.version!=expected:
                    raise ValueError("STATEMENT_DEFINITION_VERSION_NOT_NEXT")
                revision=state["commit_revision"]+1
                db.execute('''INSERT INTO epm.statement_definition_version
                  (workspace_id,application_id,definition_id,version,
                   definition,canonical_digest,operation_id,created_revision,
                   creator_issuer,creator_subject_id)
                  VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                  (scope.workspace_id,scope.application_id,
                   definition.definition_id,definition.version,
                   Jsonb(definition.normalized()),definition.digest,
                   idempotency_key,revision,self.identity.issuer,
                   self.identity.subject_id))
                if pointer:
                    db.execute('''UPDATE epm.statement_definition_state SET
                      latest_version=%s,state_revision=%s,last_operation_id=%s,
                      updated_at=transaction_timestamp() WHERE workspace_id=%s
                      AND application_id=%s AND definition_id=%s''',
                      (definition.version,revision,idempotency_key,
                       scope.workspace_id,scope.application_id,
                       definition.definition_id))
                else:
                    db.execute('''INSERT INTO epm.statement_definition_state
                      (workspace_id,application_id,definition_id,latest_version,
                       active_version,active_digest,pointer_version,
                       state_revision,last_operation_id)
                      VALUES(%s,%s,%s,%s,NULL,NULL,0,%s,%s)''',
                      (scope.workspace_id,scope.application_id,
                       definition.definition_id,definition.version,revision,
                       idempotency_key))
                db.execute('''UPDATE epm.application_state SET
                  commit_revision=%s WHERE workspace_id=%s AND application_id=%s''',
                  (revision,scope.workspace_id,scope.application_id))
                result={"operationId":idempotency_key,"status":"Saved",
                  "definitionId":definition.definition_id,
                  "version":definition.version,
                  "definitionDigest":definition.digest,
                  "declaredCoverageComplete":False,
                  "committedRevision":revision}
                self._receipt(db,scope,idempotency_key,digest,revision,result)
                return result

    def read(self,scope: ApplicationScope,definition_id: str,
             version: int)->dict:
        _target(definition_id,version)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION READ ONLY")
                self._prepare(db,scope,READ,"read")
                row=self._row(db,scope,definition_id,version)
                definition=self._verify_row(definition_id,version,row)
                pointer=db.execute('''SELECT active_version,active_digest,
                  pointer_version,state_revision FROM
                  epm.statement_definition_state WHERE workspace_id=%s
                  AND application_id=%s AND definition_id=%s''',
                  (scope.workspace_id,scope.application_id,
                   definition_id)).fetchone()
                return {**self._stored_result(definition,row),
                  "definition":row["definition"],
                  "active":bool(pointer and pointer["active_version"]==version
                    and pointer["active_digest"]==definition.digest),
                  "pointerVersion":pointer["pointer_version"] if pointer else 0,
                  "stateRevision":pointer["state_revision"] if pointer else None}

    def list(self,scope: ApplicationScope,*,limit: int=100,
             after_definition_id: str|None=None,
             after_version: int|None=None)->dict:
        if type(limit) is not int or not 1<=limit<=100:
            raise ValueError("STATEMENT_DEFINITION_LIST_LIMIT_INVALID")
        if (after_definition_id is None)!=(after_version is None):
            raise ValueError("STATEMENT_DEFINITION_LIST_CURSOR_INVALID")
        if after_definition_id is not None:
            _target(after_definition_id,after_version)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION READ ONLY")
                self._prepare(db,scope,LIST,"read")
                rows=db.execute('''SELECT v.definition_id,v.version,
                  v.definition,v.canonical_digest,v.creator_issuer,
                  v.creator_subject_id,v.created_revision,v.created_at,
                  s.active_version,s.active_digest,s.pointer_version
                  FROM epm.statement_definition_version v JOIN
                  epm.statement_definition_state s USING
                    (workspace_id,application_id,definition_id)
                  WHERE v.workspace_id=%s AND v.application_id=%s
                  AND (%s::text IS NULL OR (v.definition_id,v.version)>(%s,%s))
                  ORDER BY v.definition_id,v.version LIMIT %s''',
                  (scope.workspace_id,scope.application_id,
                   after_definition_id,after_definition_id,after_version,
                   limit+1)).fetchall()
                values=[]
                for row in rows[:limit]:
                    definition=self._verify_row(row["definition_id"],
                                                row["version"],row)
                    values.append({**self._stored_result(definition,row),
                      "definition":row["definition"],
                      "active":row["active_version"]==definition.version and
                        row["active_digest"]==definition.digest,
                      "pointerVersion":row["pointer_version"]})
                cursor=({"afterDefinitionId":values[-1]["definitionId"],
                         "afterVersion":values[-1]["version"]}
                        if len(rows)>limit else None)
                return {"definitions":values,"nextCursor":cursor}

    def read_active_exact(self,scope: ApplicationScope,definition_id: str,
                          version: int,definition_digest: str,*,
                          function: str=READ)->dict:
        _target(definition_id,version,definition_digest)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION READ ONLY")
                self._prepare(db,scope,function,"read")
                pointer=db.execute('''SELECT active_version,active_digest,
                  pointer_version,state_revision FROM
                  epm.statement_definition_state WHERE workspace_id=%s
                  AND application_id=%s AND definition_id=%s''',
                  (scope.workspace_id,scope.application_id,
                   definition_id)).fetchone()
                if (not pointer or pointer["active_version"]!=version or
                        pointer["active_digest"]!=definition_digest):
                    raise ValueError("STATEMENT_DEFINITION_ACTIVE_STALE")
                definition=self._verify_row(definition_id,version,
                    self._row(db,scope,definition_id,version))
                if definition.digest!=definition_digest:
                    raise ValueError("STATEMENT_DEFINITION_ACTIVE_STALE")
                return {"definition":definition.normalized(),
                  "definitionDigest":definition.digest,
                  "pointerVersion":pointer["pointer_version"],
                  "stateRevision":pointer["state_revision"]}

    def publish(self,scope: ApplicationScope,*,definition_id: str,version: int,
                definition_digest: str,expected_pointer_version: int,
                idempotency_key: str)->dict:
        return self._change_pointer(scope,definition_id=definition_id,
          version=version,definition_digest=definition_digest,
          expected_pointer_version=expected_pointer_version,
          idempotency_key=idempotency_key,deactivate=False)

    def deactivate(self,scope: ApplicationScope,*,definition_id: str,
                   version: int,definition_digest: str,
                   expected_pointer_version: int,
                   idempotency_key: str)->dict:
        return self._change_pointer(scope,definition_id=definition_id,
          version=version,definition_digest=definition_digest,
          expected_pointer_version=expected_pointer_version,
          idempotency_key=idempotency_key,deactivate=True)

    def _change_pointer(self,scope,*,definition_id,version,definition_digest,
                        expected_pointer_version,idempotency_key,deactivate):
        _target(definition_id,version,definition_digest)
        if type(expected_pointer_version) is not int or expected_pointer_version<0:
            raise ValueError("STATEMENT_DEFINITION_POINTER_VERSION_INVALID")
        _request_key(idempotency_key)
        function=DEACTIVATE if deactivate else PUBLISH
        command={"scope":[scope.workspace_id,scope.application_id],
          "actor":[self.identity.issuer,self.identity.subject_id],
          "function":function,"definitionId":definition_id,"version":version,
          "definitionDigest":definition_digest,
          "expectedPointerVersion":expected_pointer_version,
          "idempotencyKey":idempotency_key}
        digest=_digest(command)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                state=self._prepare(
                    db,scope,function,"admin",lock_state=True)
                prior=self._replay(db,scope,idempotency_key,digest)
                if prior is not None:return prior
                self._require_active(state)
                pointer=db.execute('''SELECT latest_version,active_version,
                  active_digest,pointer_version,state_revision FROM
                  epm.statement_definition_state WHERE workspace_id=%s
                  AND application_id=%s AND definition_id=%s FOR UPDATE''',
                  (scope.workspace_id,scope.application_id,
                   definition_id)).fetchone()
                if not pointer:
                    raise ValueError("STATEMENT_DEFINITION_STATE_UNAVAILABLE")
                if pointer["pointer_version"]!=expected_pointer_version:
                    raise ValueError("STATEMENT_DEFINITION_POINTER_STALE")
                definition=self._verify_row(definition_id,version,
                    self._row(db,scope,definition_id,version))
                if definition.digest!=definition_digest:
                    raise ValueError("STATEMENT_DEFINITION_DIGEST_MISMATCH")
                if deactivate:
                    if (pointer["active_version"]!=version or
                            pointer["active_digest"]!=definition_digest):
                        raise ValueError("STATEMENT_DEFINITION_ACTIVE_TARGET_MISMATCH")
                else:
                    other=db.execute('''SELECT definition_id FROM
                      epm.statement_definition_state WHERE workspace_id=%s
                      AND application_id=%s AND active_version IS NOT NULL
                      AND definition_id<>%s LIMIT 1''',(scope.workspace_id,
                      scope.application_id,definition_id)).fetchone()
                    if other:
                        raise ValueError("STATEMENT_DEFINITION_OTHER_ACTIVE")
                    if (pointer["active_version"]==version and
                            pointer["active_digest"]==definition_digest):
                        raise ValueError("STATEMENT_DEFINITION_ALREADY_ACTIVE")
                next_pointer=pointer["pointer_version"]+1
                revision=state["commit_revision"]+1
                policy_revision=state["policy_revision"]+1
                db.execute('''UPDATE epm.statement_definition_state SET
                  active_version=%s,active_digest=%s,pointer_version=%s,
                  state_revision=%s,last_operation_id=%s,
                  updated_at=transaction_timestamp() WHERE workspace_id=%s
                  AND application_id=%s AND definition_id=%s''',
                  (None if deactivate else version,
                   None if deactivate else definition_digest,next_pointer,
                   revision,idempotency_key,scope.workspace_id,
                   scope.application_id,definition_id))
                event=("Deactivated" if deactivate else "Published")
                db.execute('''INSERT INTO epm.statement_definition_event
                  (workspace_id,application_id,definition_id,event_ordinal,
                   event_type,definition_version,definition_digest,
                   pointer_version,operation_id,actor_issuer,actor_subject_id,
                   command_digest,committed_revision)
                  VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                  (scope.workspace_id,scope.application_id,definition_id,
                   next_pointer,event,None if deactivate else version,
                   None if deactivate else definition_digest,next_pointer,
                   idempotency_key,self.identity.issuer,
                   self.identity.subject_id,digest,revision))
                db.execute('''UPDATE epm.application_state SET
                  policy_revision=%s,commit_revision=%s WHERE workspace_id=%s
                  AND application_id=%s''',(policy_revision,revision,
                  scope.workspace_id,scope.application_id))
                result={"operationId":idempotency_key,
                  "status":"Inactive" if deactivate else "Active",
                  "definitionId":definition_id,"version":version,
                  "definitionDigest":definition_digest,
                  "pointerVersion":next_pointer,
                  "policyRevision":policy_revision,
                  "committedRevision":revision}
                self._receipt(db,scope,idempotency_key,digest,revision,result)
                return result

    def _prepare(self,db,scope,function,permission,*,lock_state=False):
        if not isinstance(scope,ApplicationScope):
            raise ValueError("APPLICATION_SCOPE_INVALID")
        configure_statement_timeout(db,5000);configure_lock_wait(db)
        PostgresNumericFactStore._set_scope(db,scope)
        PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
        # Writable requests acquire the application-state row before the
        # capability checker takes its shared row lock.  Taking FOR SHARE and
        # then upgrading to FOR UPDATE lets two concurrent publishers deadlock
        # each other.  Workspace -> application-state remains the global order.
        state=(self._application_state(db,scope,lock=True)
               if lock_state else None)
        PostgresAccessChecker.check_in_transaction(
            db,self.identity,scope,permission,function=function)
        return state

    @staticmethod
    def _application_state(db,scope,*,lock):
        row=db.execute('''SELECT s.policy_revision,s.commit_revision,
          s.processing_mode,a.status FROM epm.application_state s JOIN
          epm.application a USING(workspace_id,application_id)
          WHERE s.workspace_id=%s AND s.application_id=%s'''+
          (" FOR UPDATE OF s" if lock else ""),
          (scope.workspace_id,scope.application_id)).fetchone()
        if row is None:raise ValueError("APPLICATION_UNAVAILABLE")
        return row

    @staticmethod
    def _require_active(state):
        if state["status"]!="Active" or state["processing_mode"]!="Active":
            raise ValueError("APPLICATION_NOT_WRITABLE")

    def _replay(self,db,scope,operation_id,digest):
        row=db.execute('''SELECT command_digest,actor_id,result FROM
          epm.operation_receipt WHERE workspace_id=%s AND application_id=%s
          AND operation_id=%s''',(scope.workspace_id,scope.application_id,
          operation_id)).fetchone()
        if not row:return None
        if (row["command_digest"]!=digest or
                row["actor_id"]!=self.identity.subject_id):
            raise ValueError("STATEMENT_DEFINITION_IDEMPOTENCY_CONFLICT")
        return row["result"]

    def _receipt(self,db,scope,operation_id,digest,revision,result):
        db.execute('''INSERT INTO epm.operation_receipt
          (workspace_id,application_id,operation_id,command_digest,actor_id,
           committed_revision,result) VALUES(%s,%s,%s,%s,%s,%s,%s)''',
          (scope.workspace_id,scope.application_id,operation_id,digest,
           self.identity.subject_id,revision,Jsonb(result)))

    @staticmethod
    def _row(db,scope,definition_id,version):
        row=db.execute('''SELECT definition,canonical_digest,created_revision,
          creator_issuer,creator_subject_id,created_at FROM
          epm.statement_definition_version WHERE workspace_id=%s
          AND application_id=%s AND definition_id=%s AND version=%s''',
          (scope.workspace_id,scope.application_id,definition_id,version)).fetchone()
        if row is None:raise ValueError("STATEMENT_DEFINITION_VERSION_UNAVAILABLE")
        return row

    @staticmethod
    def _verify_row(definition_id,version,row):
        try:definition=StatementDefinition.parse(row["definition"])
        except (TypeError,ValueError) as error:
            raise ValueError("STATEMENT_DEFINITION_PERSISTED_INVALID") from error
        if (definition.definition_id!=definition_id or
                definition.version!=version or
                definition.digest!=row["canonical_digest"]):
            raise ValueError("STATEMENT_DEFINITION_PERSISTED_DIGEST_MISMATCH")
        return definition

    @staticmethod
    def _stored_result(definition,row):
        return {"definitionId":definition.definition_id,
          "version":definition.version,"definitionDigest":definition.digest,
          "createdRevision":row["created_revision"],
          "creator":{"issuer":row["creator_issuer"],
                     "subjectId":row["creator_subject_id"]},
          "createdAt":row["created_at"]}


def _program(raw)->tuple[str,dict]:
    if (not isinstance(raw,dict) or
        set(raw)!={"languageVersion","function","arguments"} or
        raw.get("languageVersion")!=2 or raw.get("function") not in FUNCTIONS or
        not isinstance(raw.get("arguments"),dict)):
        raise ValueError("STATEMENT_DEFINITION_PROGRAM_INVALID")
    return raw["function"],raw["arguments"]


def _target(definition_id,version,definition_digest=None):
    if (not isinstance(definition_id,str) or not _ID.fullmatch(definition_id) or
            type(version) is not int or version<1 or
            (definition_digest is not None and
             (not isinstance(definition_digest,str) or
              not _DIGEST.fullmatch(definition_digest)))):
        raise ValueError("STATEMENT_DEFINITION_TARGET_INVALID")


def _request_key(value):
    if not isinstance(value,str) or not _KEY.fullmatch(value):
        raise ValueError("STATEMENT_DEFINITION_IDEMPOTENCY_KEY_INVALID")


def _digest(value)->str:
    return sha256(json.dumps(value,sort_keys=True,separators=(",",":"),
      ensure_ascii=True,allow_nan=False).encode("ascii")).hexdigest()
