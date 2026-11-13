"""Lease-fenced chunk materializer for private populated-layout facts."""
from __future__ import annotations

from decimal import Decimal
from hashlib import sha256
import json

from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .persistence_contract import ApplicationScope
from .populated_layout_generation_validation import MAX_COORDINATES, _expected
from .populated_layout_mapping import LayoutPins
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_dimensional_scope import resolve_effective_dimensional_scope
from .postgres_numeric_store import PostgresNumericFactStore


CHUNK_SIZE = 500


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(value): return sha256(_canonical(value)).hexdigest()


class PostgresPopulatedLayoutMaterializer:
    def __init__(self, runtime_dsn: str, worker_dsn: str, *, identity: VerifiedIdentity):
        if not runtime_dsn or not worker_dsn or not isinstance(identity, VerifiedIdentity):
            raise ValueError("Materializer connections and verified identity are required")
        self.runtime_dsn, self.worker_dsn, self.identity = runtime_dsn, worker_dsn, identity

    def materialize(self, scope: ApplicationScope, request_id: str, *,
                    claimant: str, merge_policy: str, lease_seconds: int = 120) -> dict:
        claim = self._claim(scope, request_id, claimant, lease_seconds)
        if claim is None:
            return self._status(scope, request_id)
        self._assert_authority(scope, request_id, claim)
        request, source_rows = self._load_source(scope, request_id)
        mappings = request["plan"]["coordinateMappings"]
        by_source = {row["sourceCoordinateId"]: row for row in source_rows}
        dimensions = [axis["dimensionId"] for axis in request["plan"]["targetAxes"]]
        groups = {}
        for mapping in mappings:
            source_id = mapping["sourceCoordinateId"]
            if source_id not in by_source:
                raise ValueError("LAYOUT_MATERIALIZATION_SOURCE_MISSING")
            key = tuple(mapping["targetMembers"][dimension] for dimension in dimensions)
            groups.setdefault(key, []).append(by_source[source_id])
        rows = []
        for key in sorted(groups):
            values = _expected(groups[key], merge_policy)
            members = dict(zip(dimensions, key))
            rows.append({"targetDigest": _digest(members), "targetMembers": members,
                "sourceCoordinateIds": sorted(item["sourceCoordinateId"] for item in groups[key]),
                "numeric": {"present": values["numeric"]["present"],
                            "amount": (format(values["numeric"]["amount"], "f")
                                       if values["numeric"]["present"] else None)},
                "text": values["text"],
                "detail": {"present": values["detail"]["present"],
                    "total": (format(values["detail"]["total"], "f")
                              if values["detail"]["present"] else None),
                    "items": [{"description": item["description"],
                               "amount": format(item["amount"], "f")}
                              for item in values["detail"]["items"]]}})
        content_digest = _digest(rows)
        start = claim["next_chunk"]
        chunks = [rows[index:index + CHUNK_SIZE]
                  for index in range(0, len(rows), CHUNK_SIZE)]
        for index in range(start, len(chunks)):
            chunk = chunks[index]
            with connect_postgres(self.worker_dsn, row_factory=dict_row) as db:
                changed = db.execute("""SELECT epm.layout_replacement_materialization_chunk
                    (%s,%s,%s,%s,%s,%s,%s,%s) AS changed""",
                    (scope.workspace_id, scope.application_id, request_id, claimant,
                     claim["claim_generation"], index, _digest(chunk), Jsonb(chunk))).fetchone()["changed"]
            if not changed:
                raise ValueError("LAYOUT_MATERIALIZATION_STALE_WORKER")
        self._assert_authority(scope, request_id, claim)
        with connect_postgres(self.worker_dsn, row_factory=dict_row) as db:
            settled = db.execute("""SELECT epm.layout_replacement_materialization_settle
                (%s,%s,%s,%s,%s,%s,%s,NULL) AS changed""",
                (scope.workspace_id, scope.application_id, request_id, claimant,
                 claim["claim_generation"], content_digest, len(rows))).fetchone()["changed"]
        if not settled:
            raise ValueError("LAYOUT_MATERIALIZATION_STALE_WORKER")
        final = self._status(scope, request_id)
        final["contentDigest"] = content_digest
        return final

    def _claim(self, scope, request_id, claimant, seconds):
        with connect_postgres(self.worker_dsn, row_factory=dict_row) as db:
            row = db.execute("""SELECT * FROM epm.layout_replacement_materialization_authority_claim
                (%s,%s,%s,%s,%s::integer)""", (scope.workspace_id, scope.application_id,
                request_id, claimant, seconds)).fetchone()
        return dict(row) if row else None

    def _assert_authority(self, scope, request_id, claim=None):
        with connect_postgres(self.runtime_dsn, row_factory=dict_row) as db:
            with db.transaction():
                PostgresNumericFactStore._set_scope(db, scope)
                access = PostgresAccessChecker.check_in_transaction(
                    db, self.identity, scope, "admin")
                current_scope = resolve_effective_dimensional_scope(
                    db, self.identity, scope, access=access,
                    function="metadata.layout.populated.replace.request").scope_digest
                row = db.execute("""SELECT issuer,subject_id,verified_groups,
                    authorization_scope_digest FROM epm.layout_replacement_request
                    WHERE workspace_id=%s AND application_id=%s AND request_id=%s""",
                    (scope.workspace_id, scope.application_id, request_id)).fetchone()
                if row is None:
                    raise ValueError("LAYOUT_REPLACEMENT_NOT_FOUND")
                if (row["issuer"] != self.identity.issuer
                        or row["subject_id"] != self.identity.subject_id
                        or tuple(row["verified_groups"]) != self.identity.groups
                        or row["authorization_scope_digest"] is None
                        or row["authorization_scope_digest"] != current_scope
                        or (claim is not None and (
                            claim.get("issuer") != row["issuer"]
                            or claim.get("subject_id") != row["subject_id"]
                            or tuple(claim.get("verified_groups", ())) !=
                            tuple(row["verified_groups"])
                            or claim.get("authorization_scope_digest") !=
                            current_scope))):
                    raise ValueError(
                        "LAYOUT_REPLACEMENT_AUTHORIZATION_SCOPE_CHANGED")
                return row

    def _status(self, scope, request_id):
        self._assert_authority(scope, request_id)
        with connect_postgres(self.runtime_dsn, row_factory=dict_row) as db:
            PostgresNumericFactStore._set_scope(db, scope)
            PostgresAccessChecker.check_in_transaction(db, self.identity, scope, "admin")
            row = db.execute("""SELECT status,target_count,content_digest,next_chunk
                FROM epm.layout_replacement_materialization WHERE workspace_id=%s
                AND application_id=%s AND request_id=%s""",
                (scope.workspace_id, scope.application_id, request_id)).fetchone()
        if row is None: raise ValueError("LAYOUT_MATERIALIZATION_NOT_FOUND")
        return {"requestId": request_id, "status": row["status"],
                "targetCount": row["target_count"],
                "contentDigest": row["content_digest"], "nextChunk": row["next_chunk"]}

    def _load_source(self, scope, request_id):
        with connect_postgres(self.runtime_dsn, row_factory=dict_row) as db:
            db.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY")
            PostgresNumericFactStore._set_scope(db, scope)
            access = PostgresAccessChecker.check_in_transaction(
                db, self.identity, scope, "admin")
            current_scope = resolve_effective_dimensional_scope(
                db, self.identity, scope, access=access,
                function="metadata.layout.populated.replace.request").scope_digest
            request = db.execute("""SELECT plan,metadata_revision,data_revision,policy_revision,
                schema_epoch,source_commit_revision,issuer,subject_id,
                verified_groups,authorization_scope_digest
                FROM epm.layout_replacement_request
                WHERE workspace_id=%s AND application_id=%s AND request_id=%s AND status='Staged'""",
                (scope.workspace_id, scope.application_id, request_id)).fetchone()
            if request is None: raise ValueError("LAYOUT_REPLACEMENT_NOT_STAGED")
            if (request["issuer"] != self.identity.issuer
                    or request["subject_id"] != self.identity.subject_id
                    or tuple(request["verified_groups"]) != self.identity.groups
                    or request["authorization_scope_digest"] is None
                    or request["authorization_scope_digest"] != current_scope):
                raise ValueError(
                    "LAYOUT_REPLACEMENT_AUTHORIZATION_SCOPE_CHANGED")
            pins = LayoutPins(request["metadata_revision"], request["data_revision"],
                request["policy_revision"], request["schema_epoch"], request["source_commit_revision"])
            ids = sorted(item["sourceCoordinateId"] for item in request["plan"]["coordinateMappings"])
            if len(ids) > MAX_COORDINATES: raise ValueError("LAYOUT_MATERIALIZATION_BOUND")
            rows = db.execute("""SELECT c.coordinate_id,n.present AS numeric_present,n.amount,
                t.present AS text_present,t.text_value,d.items,d.total FROM epm.coordinate c
                LEFT JOIN epm.numeric_cell_current n USING(workspace_id,application_id,coordinate_id)
                LEFT JOIN epm.text_cell_current t USING(workspace_id,application_id,coordinate_id)
                LEFT JOIN epm.line_detail_current d USING(workspace_id,application_id,coordinate_id)
                WHERE c.workspace_id=%s AND c.application_id=%s AND c.coordinate_id=ANY(%s::bigint[])
                ORDER BY c.coordinate_id LIMIT %s""",
                (scope.workspace_id, scope.application_id, ids, MAX_COORDINATES + 1)).fetchall()
            state = db.execute("""SELECT metadata_revision,data_revision,policy_revision,schema_epoch,
                commit_revision,commit_open FROM epm.application_state WHERE workspace_id=%s AND application_id=%s""",
                (scope.workspace_id, scope.application_id)).fetchone()
            actual = LayoutPins(state["metadata_revision"],state["data_revision"],state["policy_revision"],
                                state["schema_epoch"],state["commit_revision"])
            if state["commit_open"] or actual != pins: raise ValueError("LAYOUT_MATERIALIZATION_SOURCE_STALE")
        result=[]
        for row in rows:
            items=row["items"] or []
            result.append({"sourceCoordinateId":row["coordinate_id"],
                "numeric":{"present":bool(row["numeric_present"]),"amount":row["amount"] if row["numeric_present"] else None},
                "text":{"present":bool(row["text_present"]),"value":row["text_value"] if row["text_present"] else None},
                "detail":{"present":row["total"] is not None,"total":row["total"],
                          "items":[{"description":i["description"],"amount":Decimal(i["amount"])} for i in items]}})
        return request,result
