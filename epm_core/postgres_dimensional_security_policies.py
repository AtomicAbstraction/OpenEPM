"""One current dimensional-security policy per application."""
from __future__ import annotations

from hashlib import sha256
import json
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .current_object_contract import new_state_token,require_state_token
from .dimensional_security_policy import (
    AdministratorTreatment,AcrossDimensions,DimensionalSecurityPolicy,
    FactSideAuthority,HierarchyTags,MemberTagCardinality,MixedSelection,
    UntaggedDenyPrecedence,UntaggedMember,WithinDimension,
    WriteReadRelationship,dimensional_security_policy_digest)
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_connection import connect_postgres

_SHA256=re.compile(r"[0-9a-f]{64}\Z")

def policy_from_values(values: dict[str,object])->DimensionalSecurityPolicy:
    try:
        return DimensionalSecurityPolicy(
            across_dimensions=AcrossDimensions(values["acrossDimensions"]),
            within_dimension=WithinDimension(values["withinDimension"]),
            untagged_member=UntaggedMember(values["untaggedMember"]),
            untagged_deny_precedence=UntaggedDenyPrecedence(values["untaggedDenyPrecedence"]),
            member_tag_cardinality=MemberTagCardinality(values["memberTagCardinality"]),
            hierarchy_tags=HierarchyTags(values["hierarchyTags"]),
            write_read_relationship=WriteReadRelationship(values["writeReadRelationship"]),
            mixed_selection=MixedSelection(values["mixedSelection"]),
            administrator_treatment=AdministratorTreatment(values["administratorTreatment"]),
            fact_side_authority=FactSideAuthority(values["factSideAuthority"]))
    except (KeyError,TypeError,ValueError) as exc:
        raise ValueError("DIMENSIONAL_SECURITY_POLICY_INVALID") from exc

def policy_values(policy: DimensionalSecurityPolicy)->dict[str,str]:
    return {"acrossDimensions":policy.across_dimensions.value,
        "withinDimension":policy.within_dimension.value,
        "untaggedMember":policy.untagged_member.value,
        "untaggedDenyPrecedence":policy.untagged_deny_precedence.value,
        "memberTagCardinality":policy.member_tag_cardinality.value,
        "hierarchyTags":policy.hierarchy_tags.value,
        "writeReadRelationship":policy.write_read_relationship.value,
        "mixedSelection":policy.mixed_selection.value,
        "administratorTreatment":policy.administrator_treatment.value,
        "factSideAuthority":policy.fact_side_authority.value}

def validate_policy_activation_supported(policy: DimensionalSecurityPolicy)->None:
    if not isinstance(policy,DimensionalSecurityPolicy):
        raise ValueError("DIMENSIONAL_SECURITY_POLICY_INVALID")
    if policy.hierarchy_tags is not HierarchyTags.SELECTED_MEMBER_ONLY:
        raise ValueError("DIMENSIONAL_SECURITY_HIERARCHY_POLICY_NOT_ACTIVATABLE")

def _row_policy(row: dict)->DimensionalSecurityPolicy:
    return policy_from_values({"acrossDimensions":row["across_dimensions"],
        "withinDimension":row["within_dimension"],
        "untaggedMember":row["untagged_member"],
        "untaggedDenyPrecedence":row["untagged_deny_precedence"],
        "memberTagCardinality":row["member_tag_cardinality"],
        "hierarchyTags":row["hierarchy_tags"],
        "writeReadRelationship":row["write_read_relationship"],
        "mixedSelection":row["mixed_selection"],
        "administratorTreatment":row["administrator_treatment"],
        "factSideAuthority":row["fact_side_authority"]})

class PostgresDimensionalSecurityPolicyStore:
    """Application-admin current-policy lifecycle."""

    _COLUMNS="""state_token,status,policy_digest,across_dimensions,
        within_dimension,untagged_member,untagged_deny_precedence,
        member_tag_cardinality,hierarchy_tags,write_read_relationship,
        mixed_selection,administrator_treatment,fact_side_authority,updated_at"""

    def __init__(self,dsn: str):
        if not isinstance(dsn,str) or not dsn:
            raise ValueError("A PostgreSQL security-writer DSN is required")
        self.dsn=dsn

    @staticmethod
    def _scope(db,scope: ApplicationScope)->None:
        db.execute("SELECT set_config('epm.workspace_id',%s,true)",(scope.workspace_id,))
        db.execute("SELECT set_config('epm.application_id',%s,true)",(scope.application_id,))

    @staticmethod
    def _verified(scope: ApplicationScope,row: dict)->dict:
        policy=_row_policy(row)
        digest=dimensional_security_policy_digest(scope.workspace_id,scope.application_id,policy)
        if row["policy_digest"]!=digest:
            raise ValueError("DIMENSIONAL_SECURITY_POLICY_CORRUPT")
        return {"stateToken":row["state_token"],"policyDigest":digest,
            "policy":policy_values(policy),"updatedAt":row["updated_at"].isoformat(),
            "authorizationEffect":row["status"]=="Active","status":row["status"]}

    @staticmethod
    def _actor_digest(actor: VerifiedIdentity)->str:
        return sha256((actor.issuer+"\0"+actor.subject_id).encode()).hexdigest()

    @staticmethod
    def _validate_common(scope,actor,operation_id,command_digest)->None:
        if (not isinstance(scope,ApplicationScope) or not isinstance(actor,VerifiedIdentity)
                or not isinstance(operation_id,str) or not 1<=len(operation_id)<=200
                or not isinstance(command_digest,str) or not _SHA256.fullmatch(command_digest)):
            raise ValueError("DIMENSIONAL_SECURITY_POLICY_OPERATION_INVALID")

    @staticmethod
    def _prior(db,scope,operation_id,command_digest,payload_digest):
        row=db.execute("""SELECT command_digest,payload_digest,result
            FROM epm.security_operation_receipt WHERE workspace_id=%s AND operation_id=%s""",
            (scope.workspace_id,operation_id)).fetchone()
        if row is None:return None
        if row["command_digest"]!=command_digest:raise ValueError("IDEMPOTENCY_KEY_REUSED")
        if row["payload_digest"]!=payload_digest:raise ValueError("IDEMPOTENCY_PAYLOAD_CHANGED")
        return row["result"]

    @staticmethod
    def _record(db,scope,actor_digest,operation_id,command_digest,payload_digest,
            action,target_digest,result)->None:
        db.execute("""INSERT INTO epm.security_operation_receipt(workspace_id,
            operation_id,command_digest,payload_digest,actor_digest,action,result)
            VALUES(%s,%s,%s,%s,%s,%s,%s)""",(scope.workspace_id,operation_id,
            command_digest,payload_digest,actor_digest,action,Jsonb(result)))
        db.execute("""INSERT INTO epm.security_audit(actor_id,action,workspace_id,
            application_id,target_digest,outcome,detail)
            VALUES(%s,%s,%s,%s,%s,'Accepted',%s)""",(actor_digest,action,
            scope.workspace_id,scope.application_id,target_digest,Jsonb({
                "operationId":operation_id,"stateToken":result["stateToken"],
                "securityRevision":result["securityRevision"],
                "authorizationEffect":result["authorizationEffect"]})))

    def save(self,scope: ApplicationScope,*,actor: VerifiedIdentity,
            policy: DimensionalSecurityPolicy,expected_state_token: str|None,
            operation_id: str,command_digest: str)->dict:
        self._validate_common(scope,actor,operation_id,command_digest)
        if not isinstance(policy,DimensionalSecurityPolicy):
            raise ValueError("DIMENSIONAL_SECURITY_POLICY_SAVE_INVALID")
        if expected_state_token is not None:
            require_state_token(expected_state_token,error="DIMENSIONAL_SECURITY_POLICY_STATE_TOKEN_INVALID")
        values=policy_values(policy)
        payload={"workspaceId":scope.workspace_id,"applicationId":scope.application_id,
            "actor":[actor.issuer,actor.subject_id],"policy":values,
            "expectedStateToken":expected_state_token}
        payload_digest=sha256(json.dumps(payload,sort_keys=True,separators=(",",":"),
            ensure_ascii=False).encode()).hexdigest()
        actor_digest=self._actor_digest(actor)
        digest=dimensional_security_policy_digest(scope.workspace_id,scope.application_id,policy)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id,exclusive=True)
            PostgresAccessChecker.check_in_transaction(db,actor,scope,"admin")
            prior=self._prior(db,scope,operation_id,command_digest,payload_digest)
            if prior is not None:return prior
            state=db.execute("""SELECT security_revision FROM epm.application_state
                WHERE workspace_id=%s AND application_id=%s FOR UPDATE""",
                (scope.workspace_id,scope.application_id)).fetchone()
            if state is None:raise ValueError("APPLICATION_UNAVAILABLE")
            current=db.execute("""SELECT * FROM epm.dimensional_security_policy_definition
                WHERE workspace_id=%s AND application_id=%s FOR UPDATE""",
                (scope.workspace_id,scope.application_id)).fetchone()
            if ((current is None)!=(expected_state_token is None)
                    or current is not None and current["state_token"]!=expected_state_token):
                raise ValueError("STALE_DIMENSIONAL_SECURITY_POLICY_STATE_TOKEN")
            next_revision=state["security_revision"]+(1 if current is not None and current["status"]=="Active" else 0)
            token=new_state_token()
            result={"workspaceId":scope.workspace_id,"applicationId":scope.application_id,
                "stateToken":token,"policyDigest":digest,"securityRevision":next_revision,
                "authorizationEffect":False,"status":"Saved"}
            db.execute("""UPDATE epm.application_state SET security_revision=%s
                WHERE workspace_id=%s AND application_id=%s""",
                (next_revision,scope.workspace_id,scope.application_id))
            db.execute("""INSERT INTO epm.dimensional_security_policy_definition(
                workspace_id,application_id,state_token,status,policy_digest,
                across_dimensions,within_dimension,untagged_member,
                untagged_deny_precedence,member_tag_cardinality,hierarchy_tags,
                write_read_relationship,mixed_selection,administrator_treatment,
                fact_side_authority,updated_operation_id,updated_by_digest)
                VALUES(%s,%s,%s,'Saved',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(workspace_id,application_id) DO UPDATE SET
                  state_token=EXCLUDED.state_token,status='Saved',policy_digest=EXCLUDED.policy_digest,
                  across_dimensions=EXCLUDED.across_dimensions,within_dimension=EXCLUDED.within_dimension,
                  untagged_member=EXCLUDED.untagged_member,
                  untagged_deny_precedence=EXCLUDED.untagged_deny_precedence,
                  member_tag_cardinality=EXCLUDED.member_tag_cardinality,
                  hierarchy_tags=EXCLUDED.hierarchy_tags,
                  write_read_relationship=EXCLUDED.write_read_relationship,
                  mixed_selection=EXCLUDED.mixed_selection,
                  administrator_treatment=EXCLUDED.administrator_treatment,
                  fact_side_authority=EXCLUDED.fact_side_authority,
                  updated_operation_id=EXCLUDED.updated_operation_id,
                  updated_by_digest=EXCLUDED.updated_by_digest,
                  updated_at=transaction_timestamp()""",(scope.workspace_id,
                scope.application_id,token,digest,values["acrossDimensions"],
                values["withinDimension"],values["untaggedMember"],
                values["untaggedDenyPrecedence"],values["memberTagCardinality"],
                values["hierarchyTags"],values["writeReadRelationship"],
                values["mixedSelection"],values["administratorTreatment"],
                values["factSideAuthority"],operation_id,actor_digest))
            self._record(db,scope,actor_digest,operation_id,command_digest,payload_digest,
                "dimension-policy.save",digest,result)
            return result

    def set_active(self,scope: ApplicationScope,*,actor: VerifiedIdentity,active: bool,
            expected_state_token: str,expected_security_revision: int,
            operation_id: str,command_digest: str)->dict:
        self._validate_common(scope,actor,operation_id,command_digest)
        require_state_token(expected_state_token,error="DIMENSIONAL_SECURITY_POLICY_STATE_TOKEN_INVALID")
        if type(active) is not bool or type(expected_security_revision) is not int or expected_security_revision<0:
            raise ValueError("DIMENSIONAL_SECURITY_POLICY_ACTIVATION_INVALID")
        action="dimension-policy.activate" if active else "dimension-policy.deactivate"
        payload={"workspaceId":scope.workspace_id,"applicationId":scope.application_id,
            "actor":[actor.issuer,actor.subject_id],"active":active,
            "expectedStateToken":expected_state_token,
            "expectedSecurityRevision":expected_security_revision}
        payload_digest=sha256(json.dumps(payload,sort_keys=True,separators=(",",":"),
            ensure_ascii=False).encode()).hexdigest();actor_digest=self._actor_digest(actor)
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id,exclusive=True)
            PostgresAccessChecker.check_in_transaction(db,actor,scope,"admin")
            prior=self._prior(db,scope,operation_id,command_digest,payload_digest)
            if prior is not None:return prior
            state=db.execute("""SELECT security_revision FROM epm.application_state
                WHERE workspace_id=%s AND application_id=%s FOR UPDATE""",
                (scope.workspace_id,scope.application_id)).fetchone()
            if state is None:raise ValueError("APPLICATION_UNAVAILABLE")
            if state["security_revision"]!=expected_security_revision:raise ValueError("SECURITY_REVISION_CHANGED")
            row=db.execute("""SELECT * FROM epm.dimensional_security_policy_definition
                WHERE workspace_id=%s AND application_id=%s FOR UPDATE""",
                (scope.workspace_id,scope.application_id)).fetchone()
            if row is None or row["state_token"]!=expected_state_token:
                raise ValueError("STALE_DIMENSIONAL_SECURITY_POLICY_STATE_TOKEN")
            wanted="Active" if active else "Saved"
            if row["status"]==wanted:raise ValueError("DIMENSIONAL_SECURITY_POLICY_ALREADY_"+wanted.upper())
            if active:validate_policy_activation_supported(_row_policy(row))
            token=new_state_token();revision=expected_security_revision+1
            result={"workspaceId":scope.workspace_id,"applicationId":scope.application_id,
                "stateToken":token,"policyDigest":row["policy_digest"],
                "securityRevision":revision,"authorizationEffect":active,"status":wanted}
            db.execute("""UPDATE epm.application_state SET security_revision=%s
                WHERE workspace_id=%s AND application_id=%s""",
                (revision,scope.workspace_id,scope.application_id))
            db.execute("""UPDATE epm.dimensional_security_policy_definition SET
                state_token=%s,status=%s,updated_operation_id=%s,updated_by_digest=%s,
                updated_at=transaction_timestamp() WHERE workspace_id=%s AND application_id=%s""",
                (token,wanted,operation_id,actor_digest,scope.workspace_id,scope.application_id))
            self._record(db,scope,actor_digest,operation_id,command_digest,payload_digest,
                action,row["policy_digest"],result)
            return result

    def read(self,scope: ApplicationScope,*,actor: VerifiedIdentity)->dict:
        if not isinstance(scope,ApplicationScope) or not isinstance(actor,VerifiedIdentity):
            raise ValueError("DIMENSIONAL_SECURITY_POLICY_READ_INVALID")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
          with db.transaction():
            self._scope(db,scope);PostgresAccessChecker.lock_workspace(db,scope.workspace_id)
            PostgresAccessChecker.check_in_transaction(db,actor,scope,"admin")
            state=db.execute("""SELECT security_revision FROM epm.application_state
                WHERE workspace_id=%s AND application_id=%s""",
                (scope.workspace_id,scope.application_id)).fetchone()
            if state is None:raise ValueError("APPLICATION_UNAVAILABLE")
            row=db.execute(f"""SELECT {self._COLUMNS} FROM epm.dimensional_security_policy_definition
                WHERE workspace_id=%s AND application_id=%s""",
                (scope.workspace_id,scope.application_id)).fetchone()
            if row is None:return {"workspaceId":scope.workspace_id,
                "applicationId":scope.application_id,"stateToken":None,"policyDigest":None,
                "policy":None,"securityRevision":state["security_revision"],
                "authorizationEffect":False,"status":"Absent"}
            return {**self._verified(scope,row),"workspaceId":scope.workspace_id,
                "applicationId":scope.application_id,"securityRevision":state["security_revision"]}
