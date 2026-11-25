#!/usr/bin/env python3
"""Canonical global active-work observation and bounded Mac-pilot drain."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import time
from typing import Callable, Protocol

try:
    from scripts.operator_import_path import ensure_project_root
except ModuleNotFoundError as error:
    if error.name != "scripts":
        raise
    from operator_import_path import ensure_project_root
ensure_project_root()

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
FAMILIES = ("jobs", "builds", "workflows", "queries", "schedules", "imports",
            "exports", "metadataMigrations", "lifecycleOperations")

# Native tables remain authoritative. Every observed status must be classified;
# a new schema status therefore fails closed instead of silently disappearing.
SOURCES = {
 "jobs": (
  ("epm.job", "status", {"accepted","ready","running","staged","cancel_requested","needs_inspection"}, {"published","failed","cancelled"}),
  ("epm.expression_rule_sequence", "status", {"accepted","running","cancel_requested"}, {"published","failed","cancelled"}),
  ("epm.full_aggregate_sequence", "status", {"accepted","running","cancel_requested"}, {"published","failed","cancelled"})),
 "builds": (("epm.python_program_build", "status", {"accepted","ready","running","cancel_requested"}, {"sealed","failed","cancelled","expired"}),),
 "workflows": (
  ("epm.python_program_workflow", "status", {"accepted","running","cancel_requested","needs_inspection"}, {"published","partially_published","failed","cancelled"}),
  ("epm.application_rule_workflow", "status", {"accepted","running","cancel_requested","needs_inspection"}, {"published","partially_published","failed","cancelled"})),
 "queries": (("epm.cube_aggregate_query", "status", {"accepted","ready","running","computed","cancel_requested"}, {"sealed","cancelled","failed","expired"}),),
 "schedules": (
  ("epm.python_program_occurrence", "status", {"ready","running","building","running_program","cancel_requested","needs_inspection"}, {"published","failed","cancelled"}),
  ("epm.python_program_schedule_state", "CASE WHEN dispatch_claimant IS NOT NULL AND dispatch_lease_until > clock_timestamp() THEN 'claimed' ELSE 'idle' END", {"claimed"}, {"idle"}),
  ("epm.python_program_schedule_definition", "CASE WHEN dispatch_claimant IS NOT NULL AND dispatch_lease_until > clock_timestamp() THEN 'claimed' ELSE 'idle' END", {"claimed"}, {"idle"}),
  ("epm.application_schedule_occurrence", "status", {"ready","running","submitted","cancel_requested","needs_inspection"}, {"published","partially_published","failed","cancelled"}),
  ("epm.application_schedule_state", "CASE WHEN dispatch_claimant IS NOT NULL AND dispatch_lease_until > clock_timestamp() THEN 'claimed' ELSE 'idle' END", {"claimed"}, {"idle"}),
  ("epm.application_schedule_definition", "CASE WHEN dispatch_claimant IS NOT NULL AND dispatch_lease_until > clock_timestamp() THEN 'claimed' ELSE 'idle' END", {"claimed"}, {"idle"})),
 "imports": (
  ("epm.source_batch", "status", {"staging","ready"},
   {"published","failed","cancelled"}),
  ("epm.source_import_execution", "status", {"Accepted","Claimed","Publishing"}, {"Completed","Failed","Cancelled"})),
 "exports": (
  ("epm.fact_export_producer_request", "status", {"Accepted","Reading","Prepared","Publishing"}, {"Completed","Failed","Cancelled"}),
  ("epm.transfer_cleanup_request", "status", {"Accepted","Running"}, {"Completed","Failed","Cancelled"})),
 "metadataMigrations": (
  ("epm.layout_replacement_request", "status", {"Accepted","Staging","Staged"}, {"Failed","Cancelled"}),
  ("epm.layout_replacement_activation", "status", {"Requested","Activating"}, {"Activated","Failed","Cancelled"})),
 "lifecycleOperations": (
  ("epm.workspace", "status", {"Deleting"}, {"Active","Maintenance"}),
  ("epm.application", "status", {"Deleting"}, {"Active","Maintenance"})),
}

# The active-work contract spans retained historical generations as well as the
# current schema. A relation is queried only while it exists, but its current
# replacement is part of the same canonical inventory from the migration that
# creates it. Unexpected absence within that bounded lifetime still fails
# closed as an ordinary SQL error.
SOURCE_INTRODUCED_SCHEMA = {
 "epm.workspace":1,"epm.application":1,"epm.job":12,"epm.source_batch":15,
 "epm.expression_rule_sequence":44,"epm.full_aggregate_sequence":54,
 "epm.cube_aggregate_query":88,"epm.python_program_build":89,
 "epm.python_program_workflow":89,"epm.layout_replacement_request":107,
 "epm.layout_replacement_activation":110,"epm.fact_export_producer_request":113,
 "epm.transfer_cleanup_request":115,"epm.python_program_occurrence":132,
 "epm.python_program_schedule_state":132,"epm.source_import_execution":151,
 "epm.application_rule_workflow":217,"epm.application_schedule_occurrence":220,
 "epm.application_schedule_state":220,
 "epm.application_schedule_definition":312,
 "epm.python_program_schedule_definition":315,
}
SOURCE_RETIRED_SCHEMA = {
 "epm.application_schedule_state":312,
 "epm.python_program_schedule_state":315,
}


class ActiveWorkError(RuntimeError): pass


def sources_for_schema(schema:int)->dict[str,tuple]:
    canonical={table for family in FAMILIES
               for table,_,_,_ in SOURCES[family]}
    if not isinstance(schema,int) or isinstance(schema,bool) or schema<1 \
            or set(SOURCE_INTRODUCED_SCHEMA)!=canonical \
            or not set(SOURCE_RETIRED_SCHEMA).issubset(canonical) \
            or any(SOURCE_RETIRED_SCHEMA[table]
                   <=SOURCE_INTRODUCED_SCHEMA[table]
                   for table in SOURCE_RETIRED_SCHEMA):
        raise ActiveWorkError("active-work schema inventory differs")
    return {family:tuple(source for source in SOURCES[family]
                         if SOURCE_INTRODUCED_SCHEMA[source[0]]<=schema
                         and schema<SOURCE_RETIRED_SCHEMA.get(
                             source[0],schema+1))
            for family in FAMILIES}


def canonical(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                      ensure_ascii=True).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


class AdmissionBoundary(Protocol):
    def close_new_public_admission(self, operation_key: str, contract: dict) -> str: ...
    def workers_running(self) -> bool: ...


class ActiveWorkObserver:
    def __init__(self, admin_dsn: str, *, statement_timeout_ms: int = 5000):
        if not isinstance(admin_dsn,str) or not admin_dsn \
                or not isinstance(statement_timeout_ms,int) \
                or isinstance(statement_timeout_ms,bool) \
                or statement_timeout_ms not in range(100,30001):
            raise ActiveWorkError("active-work observer configuration is invalid")
        self.dsn=admin_dsn;self.timeout=statement_timeout_ms

    @staticmethod
    def classify(rows: dict[str,list[dict]]) -> dict[str,int]:
        if set(rows)!=set(FAMILIES):
            raise ActiveWorkError("active-work family inventory differs")
        counts={}
        for family in FAMILIES:
            expected={table:(active|terminal,active) for table,_,active,terminal
                      in SOURCES[family]}
            seen={}
            count=0
            for row in rows[family]:
                if set(row)!={"table_name","status","count"} \
                        or row["table_name"] not in expected \
                        or not isinstance(row["status"],str) \
                        or not isinstance(row["count"],int) \
                        or isinstance(row["count"],bool) or row["count"]<0:
                    raise ActiveWorkError("active-work row is invalid")
                known,active=expected[row["table_name"]]
                if row["status"] not in known:
                    raise ActiveWorkError("unclassified active-work status")
                key=(row["table_name"],row["status"])
                if key in seen:raise ActiveWorkError("duplicate active-work status")
                seen[key]=True
                if row["status"] in active:count+=row["count"]
            counts[family]=count
        return counts

    def observe(self) -> dict[str,int]:
        # The Mac-pilot host controller imports the inventory and classifier
        # without requiring a host psycopg installation.  Database access is
        # needed only by the explicit observer path and is loaded here.
        from psycopg.rows import dict_row
        from epm_core.postgres_connection import connect_postgres

        rows={name:[] for name in FAMILIES}
        with connect_postgres(self.dsn,row_factory=dict_row) as db:
            with db.transaction():
                db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                db.execute("SELECT set_config('statement_timeout',%s,true)",
                           (str(self.timeout),))
                identity=db.execute(
                    "SELECT max(version)::bigint maximum FROM epm.schema_migration"
                ).fetchone()
                schema=identity.get("maximum") if isinstance(identity,dict) else None
                applicable=sources_for_schema(schema)
                for family in FAMILIES:
                    for table,column,_,_ in applicable[family]:
                        query=f"SELECT %s table_name,{column} status,count(*)::bigint count FROM {table} GROUP BY {column}"
                        for row in db.execute(query,(table,)).fetchall():
                            item=dict(row);item["count"]=int(item["count"])
                            rows[family].append(item)
        return self.classify(rows)


class ActiveWorkDrain:
    def __init__(self,observer: ActiveWorkObserver,boundary: AdmissionBoundary,
                 private_key: Ed25519PrivateKey,*,key_id: str,
                 timeout_seconds: float=120,poll_seconds: float=.5,
                 monotonic: Callable[[],float]=time.monotonic,
                 sleeper: Callable[[float],None]=time.sleep):
        if not hasattr(observer,"observe") or not hasattr(boundary,"close_new_public_admission") \
                or not hasattr(boundary,"workers_running") \
                or not isinstance(private_key,Ed25519PrivateKey) or not key_id \
                or timeout_seconds<=0 or poll_seconds<=0:
            raise ActiveWorkError("active-work drain configuration is invalid")
        self.observer=observer;self.boundary=boundary;self.key=private_key
        self.key_id=key_id;self.timeout=timeout_seconds;self.poll=poll_seconds
        self.monotonic=monotonic;self.sleep=sleeper

    def drain(self,*,operation_key:str,contract:dict,journal_head:str,
              journal_generation:int,observed_at_utc:str) -> dict:
        if len(operation_key)!=64 or len(journal_head)!=64 \
                or not isinstance(journal_generation,int) or journal_generation<1:
            raise ActiveWorkError("active-work drain authority is invalid")
        closure=self.boundary.close_new_public_admission(operation_key,contract)
        if not isinstance(closure,str) or len(closure)!=64:
            raise ActiveWorkError("public admission closure evidence is invalid")
        deadline=self.monotonic()+self.timeout
        while True:
            if self.boundary.workers_running() is not True:
                raise ActiveWorkError("workers stopped before active work drained")
            counts=self.observer.observe()
            if all(counts[name]==0 for name in FAMILIES):break
            if self.monotonic()>=deadline:
                raise ActiveWorkError("active-work drain timed out")
            self.sleep(self.poll)
        body={"format":"openepm-macos-pilot-active-work-drain-v1",
            "activationId":contract["activationId"],
            "executionContractSha256":contract["executionContractSha256"],
            "intentEventSha256":operation_key,"journalHeadEventSha256":journal_head,
            "journalGeneration":journal_generation,"publicAdmissionEvidenceSha256":closure,
            "workersRemainedRunning":True,"activeWork":counts,
            "observedAtUtc":observed_at_utc,"keyId":self.key_id}
        sealed={**body,"evidenceSha256":digest(body)}
        return {**sealed,"signature":{"algorithm":"Ed25519","keyId":self.key_id,
            "valueBase64":base64.b64encode(self.key.sign(canonical(sealed))).decode()}}
