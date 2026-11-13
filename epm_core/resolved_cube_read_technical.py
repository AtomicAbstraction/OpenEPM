"""Durable W08 resolved-read service on the existing technical lifecycle."""
from __future__ import annotations

import json
import time
import uuid
from hashlib import sha256

from psycopg.rows import dict_row

from .cube_aggregate_lifecycle import (
    AggregateCursor, AggregateCursorCodec, AggregateQueryBudgets,
    AggregateQueryRecord, AggregateQueryStatus, AggregateSourcePins,
    AggregateTechnicalCertificate, POSTGRES_EXACT_DIMENSIONAL_BACKEND)
from .persistence_contract import ApplicationScope
from .postgres_access import PostgresAccessChecker, VerifiedIdentity
from .postgres_connection import connect_postgres
from .postgres_cube_aggregate_repository import PostgresCubeAggregateRepository
from .postgres_numeric_store import PostgresNumericFactStore
from .postgres_resolved_cube_read import (
    FUNCTION, PostgresResolvedCubeRead, _dimensions_for_read,
    load_resolved_read_snapshot)
from .resolved_cube_read_contract import compile_resolved_cube_read


def _canonical(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(",",":"),
        ensure_ascii=True,allow_nan=False).encode("ascii")


def _digest(value: object) -> str:
    return sha256(_canonical(value)).hexdigest()


class ResolvedCubeReadTechnicalService:
    """Accept, execute and page large reads without publishing business data."""

    def __init__(self,dsn: str,*,identity: VerifiedIdentity,
                 cursor_codec: AggregateCursorCodec,
                 clock=None,query_id_factory=None):
        if not isinstance(identity,VerifiedIdentity):
            raise ValueError("Verified identity is required")
        if not isinstance(cursor_codec,AggregateCursorCodec):
            raise ValueError("RESOLVED_READ_CURSOR_CODEC_REQUIRED")
        self.dsn=dsn;self.identity=identity;self.cursor_codec=cursor_codec
        self.clock=clock or (lambda:int(time.time()))
        self.query_id_factory=query_id_factory or (lambda:uuid.uuid4().hex)
        self.repository=PostgresCubeAggregateRepository(dsn,identity=identity)

    def request(self,scope: ApplicationScope,program: object,*,
                page_size: int=500,ttl_seconds: int=900)->dict[str,object]:
        if (not isinstance(program,dict)
                or set(program)!={"languageVersion","function","arguments"}
                or program.get("languageVersion")!=2
                or program.get("function")!=FUNCTION
                or not isinstance(program.get("arguments"),dict)):
            raise ValueError("RESOLVED_READ_PROGRAM_INVALID")
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION READ ONLY")
                PostgresNumericFactStore._set_scope(db,scope)
                PostgresAccessChecker.check_in_transaction(
                    db,self.identity,scope,"read")
                dimensions=_dimensions_for_read(db,scope)
                plan=compile_resolved_cube_read(program["arguments"],
                    active_dimensions=dimensions)
                if plan.normalized["delivery"]!="technical_query":
                    raise ValueError("RESOLVED_READ_TECHNICAL_QUERY_REQUIRED")
                snapshot=load_resolved_read_snapshot(db,scope)
                if plan.normalized["selection"]["metadataRevision"]!=\
                        snapshot["metadataRevision"]:
                    raise ValueError("STALE_METADATA_REVISION")
        budget=AggregateQueryBudgets(
            max_groups=plan.normalized["limits"]["maxRows"],
            max_result_bytes=32*1024*1024,page_size=page_size,
            ttl_seconds=ttl_seconds)
        accepted=self.clock()
        record=AggregateQueryRecord(self.query_id_factory(),scope,
            self.identity.issuer,self.identity.subject_id,plan.digest,
            plan.digest,AggregateQueryStatus.ACCEPTED,budget,accepted,
            accepted+budget.ttl_seconds,request_family="resolved_read")
        ready=self.repository.insert_resolved_ready(
            record,normalized_request=plan.normalized)
        return {"queryId":ready.query_id,"status":ready.status.value,
            "requestDigest":plan.digest,"expiresAt":ready.expires_at}

    def worker_run_once(self,scope: ApplicationScope,*,claimant: str,
                        lease_seconds: int=30)->dict[str,object]|None:
        self.repository.recover_expired(
            scope,request_family='resolved_read')
        computed=self.repository.pending_computed_resolved(scope)
        if computed is not None:
            sealed=self.repository.seal(computed)
            return {"queryId":sealed.query_id,"status":sealed.status.value,
                "technicalCertificate":self._certificate(
                    sealed.certificate)}
        claim=self.repository.claim_resolved(
            scope,claimant,lease_seconds=lease_seconds)
        if claim is None:return None
        return self.worker_run_claim(claim)

    def worker_run_claim(self,claim: dict)->dict[str,object]:
        if (not isinstance(claim,dict)
                or not isinstance(claim.get('record'),AggregateQueryRecord)
                or claim['record'].request_family!='resolved_read'):
            raise ValueError('RESOLVED_READ_TECHNICAL_CLAIM_INVALID')
        record=claim["record"]
        scope=record.scope
        result=PostgresResolvedCubeRead(
            self.dsn,identity=self.identity).read_technical(scope,{
                "languageVersion":2,"function":FUNCTION,
                "arguments":claim["normalizedRequest"]})
        rows=result["rows"]
        stored=[{"format":"openepm-resolved-cube-read-row-v1",**row}
                for row in rows]
        row_bytes=sum(len(_canonical(row)) for row in stored)
        pins=result["snapshot"];technical=result["technicalPins"]
        certificate=AggregateTechnicalCertificate(record.plan_digest,
            POSTGRES_EXACT_DIMENSIONAL_BACKEND,AggregateSourcePins(
                pins["commitRevision"],pins["dataRevision"],
                pins["metadataRevision"],pins["policyRevision"],
                pins["securityRevision"],technical["schemaEpoch"],
                technical["activeProjectionGeneration"]),
            _digest(claim["normalizedRequest"]["source"].get(
                "hierarchies",[])),
            _digest(stored),len(rows),row_bytes)
        computed=self.repository.store_resolved_computed(
            record,certificate,rows,claim=claim)
        sealed=self.repository.seal(computed)
        return {"queryId":sealed.query_id,"status":sealed.status.value,
            "technicalCertificate":self._certificate(certificate)}

    @staticmethod
    def _certificate(value: AggregateTechnicalCertificate)->dict[str,object]:
        return {"kind":"technical-query-certificate",
            "planDigest":value.plan_digest,
            "backendProfile":value.backend_profile,
            "sourcePins":value.source_pins.wire(),
            "hierarchyDigest":value.hierarchy_digest,
            "resultDigest":value.result_digest,
            "groupCount":value.group_count,
            "resultBytes":value.result_bytes}

    def read(self,scope: ApplicationScope,query_id: str,*,
             cursor: str|None=None,page_size: int|None=None)->dict[str,object]:
        record=self.repository.get_resolved(scope,query_id)
        if record is None:
            raise ValueError("RESOLVED_READ_QUERY_UNAVAILABLE")
        now=self.clock()
        if now>=record.expires_at:
            if record.status==AggregateQueryStatus.SEALED:
                self.repository.compare_and_transition(
                    record,record.transition(AggregateQueryStatus.EXPIRED))
            raise ValueError("RESOLVED_READ_RESULT_EXPIRED")
        if record.status!=AggregateQueryStatus.SEALED or record.certificate is None:
            return {"queryId":query_id,"status":record.status.value}
        if cursor is None:
            size,after=page_size or record.budgets.page_size,0
        else:
            decoded=self.cursor_codec.unpack(cursor,scope=scope,
                issuer=self.identity.issuer,subject=self.identity.subject_id,
                now=now)
            if (decoded.query_id!=query_id
                    or decoded.request_digest!=record.request_digest
                    or decoded.result_digest!=record.certificate.result_digest
                    or page_size is not None and page_size!=decoded.page_size):
                raise ValueError("RESOLVED_READ_CURSOR_INVALID")
            size,after=decoded.page_size,decoded.last_ordinal
        if type(size) is not int or not 1<=size<=record.budgets.page_size:
            raise ValueError("RESOLVED_READ_PAGE_REQUEST_INVALID")
        rows,has_more=self.repository.page_resolved(
            record,after_ordinal=after,limit=size)
        next_cursor=None
        if has_more:
            next_cursor=self.cursor_codec.pack(AggregateCursor(query_id,scope,
                record.issuer,record.subject,record.request_digest,
                record.certificate.result_digest,size,rows[-1]["ordinal"],
                record.expires_at))
        return {"queryId":query_id,"status":record.status.value,
            "rows":rows,"nextCursor":next_cursor,
            "technicalCertificate":self._certificate(record.certificate)}

    def cancel(self,scope: ApplicationScope,query_id: str)->dict[str,object]:
        record=self.repository.get_resolved(scope,query_id)
        if record is None:
            raise ValueError("RESOLVED_READ_QUERY_UNAVAILABLE")
        updated=record.request_cancel()
        if updated==record:
            return {"queryId":query_id,"status":record.status.value}
        if not self.repository.compare_and_transition(record,updated):
            raise ValueError("CUBE_AGGREGATE_STALE_CONTROL_STATE")
        return {"queryId":query_id,"status":updated.status.value}
