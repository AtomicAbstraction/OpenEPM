"""One current dimensional-security policy per application."""
from __future__ import annotations

from hashlib import sha256
import json
import re

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .current_object_contract import STATE_TOKEN_PATTERN,new_state_token,require_state_token
from .dimensional_security_policy import (
    AdministratorTreatment,AcrossDimensions,DimensionalSecurityPolicy,
    FactSideAuthority,HierarchyTags,MemberTagCardinality,MixedSelection,
    UntaggedDenyPrecedence,UntaggedMember,WithinDimension,
    WriteReadRelationship,dimensional_security_policy_digest)
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker,VerifiedIdentity
from .postgres_connection import connect_postgres

_SHA256=re.compile(r"[0-9a-f]{64}\Z")
_POLICY_FIELDS = {
    'acrossDimensions': ('across_dimensions', AcrossDimensions),
    'withinDimension': ('within_dimension', WithinDimension),
    'untaggedMember': ('untagged_member', UntaggedMember),
    'untaggedDenyPrecedence': ('untagged_deny_precedence', UntaggedDenyPrecedence),
    'memberTagCardinality': ('member_tag_cardinality', MemberTagCardinality),
    'hierarchyTags': ('hierarchy_tags', HierarchyTags),
    'writeReadRelationship': ('write_read_relationship', WriteReadRelationship),
    'mixedSelection': ('mixed_selection', MixedSelection),
    'administratorTreatment': ('administrator_treatment', AdministratorTreatment),
    'factSideAuthority': ('fact_side_authority', FactSideAuthority),
}
POLICY_KEYS = frozenset(_POLICY_FIELDS)


def assignment_policy_values():
    """Fixed initial policy shared by new and migrated group-assigned applications."""
    return {
        'acrossDimensions':'every_protected','withinDimension':'any_tag',
        'untaggedMember':'deny','untaggedDenyPrecedence':'absolute',
        'memberTagCardinality':'multiple','hierarchyTags':'selected_member_only',
        'writeReadRelationship':'require_read','mixedSelection':'filter_reads_reject_writes',
        'administratorTreatment':'require_assignment','factSideAuthority':'derived_query_aid_only'}


def policy_from_values(values: dict[str,object])->DimensionalSecurityPolicy:
    try:
        return DimensionalSecurityPolicy(**{
            field: kind(values[key]) for key, (field, kind) in _POLICY_FIELDS.items()})
    except (KeyError,TypeError,ValueError) as exc:
        raise ValueError("DIMENSIONAL_SECURITY_POLICY_INVALID") from exc

def policy_values(policy: DimensionalSecurityPolicy)->dict[str,str]:
    return {key: getattr(policy, field).value for key, (field, _) in _POLICY_FIELDS.items()}


def policy_values_schema() -> dict:
    from .postgres_numeric_catalog import obj

    return obj({key: {'enum': [entry.value for entry in kind]}
                for key, (_, kind) in _POLICY_FIELDS.items()})


def policy_state_token_schema() -> dict:
    return {'type': 'string',
            'pattern': '^' + STATE_TOKEN_PATTERN.pattern.removesuffix(r'\Z') + r'(?![\s\S])'}


def _policy_scope_schema() -> dict:
    text = {'type': 'string', 'minLength': 1}
    return {'workspaceId': text, 'applicationId': text,
            'securityRevision': {'type': 'integer', 'minimum': 0}}


def _policy_current_schema() -> dict:
    digest = {'type': 'string', 'pattern': '^' + _SHA256.pattern.removesuffix(r'\Z') + r'(?![\s\S])'}
    return {**_policy_scope_schema(), 'stateToken': policy_state_token_schema(),
            'policyDigest': digest}


def policy_effect_result_schema(*, active: bool) -> dict:
    from .postgres_numeric_catalog import obj

    return obj({**_policy_current_schema(), 'status': {'const': 'Active' if active else 'Saved'},
                'authorizationEffect': {'const': active}})


def policy_read_result_schema() -> dict:
    from .postgres_numeric_catalog import obj

    present = {**_policy_current_schema(), 'policy': policy_values_schema(),
               'updatedAt': {'type': 'string', 'format': 'date-time'}}
    absent = {**_policy_scope_schema(), 'stateToken': {'type': 'null'}, 'policyDigest': {'type': 'null'},
              'policy': {'type': 'null'}}
    return {'oneOf': [obj({**absent, 'status': {'const': 'Absent'},
                           'authorizationEffect': {'const': False}}),
                      obj({**present, 'status': {'const': 'Active'},
                           'authorizationEffect': {'const': True}}),
                      obj({**present, 'status': {'const': 'Saved'},
                           'authorizationEffect': {'const': False}})]}


def validate_policy_activation_supported(policy: DimensionalSecurityPolicy)->None:
    if not isinstance(policy,DimensionalSecurityPolicy):
        raise ValueError("DIMENSIONAL_SECURITY_POLICY_INVALID")
    if policy.hierarchy_tags is not HierarchyTags.SELECTED_MEMBER_ONLY:
        raise ValueError("DIMENSIONAL_SECURITY_HIERARCHY_POLICY_NOT_ACTIVATABLE")

def _row_policy(row: dict)->DimensionalSecurityPolicy:
    return policy_from_values({key: row[field] for key, (field, _) in _POLICY_FIELDS.items()})

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
            access=PostgresAccessChecker.check_in_transaction(db,actor,scope,"admin")
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
            # The save contract replaces the active definition with a saved
            # draft. Migrated applications require uninterrupted enforcement.
            if access.authorization_model=="group_assignments" and current is not None and current["status"]=="Active":
                raise ValueError("GROUP_ASSIGNMENT_ACTIVE_POLICY_REQUIRED")
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
            access=PostgresAccessChecker.check_in_transaction(db,actor,scope,"admin")
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
            if access.authorization_model=="group_assignments":
                if not active:
                    raise ValueError("GROUP_ASSIGNMENT_ACTIVE_POLICY_REQUIRED")
                from .dimensional_privileges import require_assignment_policy
                require_assignment_policy(_row_policy(row))
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
          with PostgresAccessChecker.application_security_read(db, actor, scope):
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
