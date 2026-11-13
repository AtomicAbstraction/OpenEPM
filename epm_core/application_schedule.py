"""Transport-neutral contract for generic scheduled application rules.

This module validates current schedule definitions only.  It does not read
the database, calculate a due time, acquire execution authority or run a rule.
Persistence and workers consume the same canonical definition after fixed-core
publication and delegation checks.
"""
from __future__ import annotations

from datetime import datetime,timezone
from hashlib import sha256
import json,re


FORMAT="openepm-application-schedule-v1"
MAX_BYTES=1_048_576
_ID=re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_KEY=re.compile(r"[A-Za-z0-9._-]{8,128}\Z")
_DIGEST=re.compile(r"[0-9a-f]{64}\Z")
_CATCH_UP=frozenset(("skip","latest","all"))
CANCELLATION_POLICY="PreserveCommittedStopFuture"


def _identifier(value,code="APPLICATION_SCHEDULE_DEFINITION_INVALID"):
    if type(value) is not str or _ID.fullmatch(value) is None:raise ValueError(code)
    return value


def _utc(value):
    if type(value) is not str:raise ValueError("APPLICATION_SCHEDULE_TIME_INVALID")
    try:parsed=datetime.fromisoformat(value.replace("Z","+00:00"))
    except ValueError as error:
        raise ValueError("APPLICATION_SCHEDULE_TIME_INVALID") from error
    if (parsed.tzinfo is None or parsed.utcoffset()!=timezone.utc.utcoffset(parsed)
            or parsed.second!=0 or parsed.microsecond!=0):
        raise ValueError("APPLICATION_SCHEDULE_TIME_INVALID")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00","Z")


def _json(value,code="APPLICATION_SCHEDULE_DEFINITION_INVALID"):
    try:
        raw=json.dumps(value,sort_keys=True,separators=(",",":"),
                       ensure_ascii=True,allow_nan=False)
        normalized=json.loads(raw)
    except (TypeError,ValueError,UnicodeEncodeError) as error:raise ValueError(code) from error
    def walk(item,depth=0):
        if depth>64:raise ValueError(code)
        if isinstance(item,float):raise ValueError(code)
        if isinstance(item,dict):
            if len(item)>1000:raise ValueError(code)
            for key,child in item.items():
                if type(key) is not str or not key or len(key)>200:raise ValueError(code)
                walk(child,depth+1)
        elif isinstance(item,list):
            if len(item)>100_000:raise ValueError(code)
            for child in item:walk(child,depth+1)
        elif item is not None and type(item) not in (str,int,bool):raise ValueError(code)
    walk(normalized)
    if len(raw.encode("ascii"))>MAX_BYTES:raise ValueError(code)
    return normalized


def validate_definition(value: object) -> dict:
    """Return canonical JSON-compatible schedule IR or fail closed."""
    required={"format","scheduleId","target","bindings","pov",
              "recurrence","retryPolicy","cancellationPolicy","delegation"}
    if type(value) is not dict or set(value)!=required or value.get("format")!=FORMAT:
        raise ValueError("APPLICATION_SCHEDULE_DEFINITION_INVALID")
    schedule_id=_identifier(value["scheduleId"])
    target=value["target"]
    if (type(target) is not dict or set(target)!={"kind","ruleId",
            "stateToken","programDigest"}
            or target.get("kind")!="ApplicationRule"):
        raise ValueError("APPLICATION_SCHEDULE_TARGET_INVALID")
    _identifier(target.get("ruleId"),"APPLICATION_SCHEDULE_TARGET_INVALID")
    if (type(target.get("stateToken")) is not str
            or _DIGEST.fullmatch(target["stateToken"]) is None
            or type(target.get("programDigest")) is not str
            or _DIGEST.fullmatch(target["programDigest"]) is None):
        raise ValueError("APPLICATION_SCHEDULE_TARGET_INVALID")

    bindings=_json(value["bindings"],"APPLICATION_SCHEDULE_BINDINGS_INVALID")
    if type(bindings) is not dict or len(bindings)>100:
        raise ValueError("APPLICATION_SCHEDULE_BINDINGS_INVALID")
    for name in bindings:_identifier(name,"APPLICATION_SCHEDULE_BINDINGS_INVALID")

    pov=value["pov"]
    if type(pov) is not list or len(pov)>64:
        raise ValueError("APPLICATION_SCHEDULE_POV_INVALID")
    normalized_pov=[];parameters=set();dimensions=set()
    for row in pov:
        if (type(row) is not dict
                or set(row)!={"dimensionId","parameter","memberId"}):
            raise ValueError("APPLICATION_SCHEDULE_POV_INVALID")
        dimension=_identifier(row.get("dimensionId"),"APPLICATION_SCHEDULE_POV_INVALID")
        parameter=_identifier(row.get("parameter"),"APPLICATION_SCHEDULE_POV_INVALID")
        member=_identifier(row.get("memberId"),"APPLICATION_SCHEDULE_POV_INVALID")
        if (parameter in parameters or dimension in dimensions
                or parameter in bindings):
            raise ValueError("APPLICATION_SCHEDULE_POV_INVALID")
        parameters.add(parameter);dimensions.add(dimension)
        normalized_pov.append({"dimensionId":dimension,
                               "parameter":parameter,"memberId":member})

    recurrence=value["recurrence"]
    if (type(recurrence) is not dict or set(recurrence)!={"kind",
            "intervalSeconds","firstDueAt","catchUpPolicy","maxCatchUp"}
            or recurrence.get("kind")!="FixedInterval"
            or type(recurrence.get("intervalSeconds")) is not int
            or not 60<=recurrence["intervalSeconds"]<=2_678_400
            or recurrence.get("catchUpPolicy") not in _CATCH_UP
            or type(recurrence.get("maxCatchUp")) is not int
            or not 1<=recurrence["maxCatchUp"]<=36):
        raise ValueError("APPLICATION_SCHEDULE_RECURRENCE_INVALID")
    due=_utc(recurrence.get("firstDueAt"))

    retry=value["retryPolicy"]
    if (type(retry) is not dict
            or set(retry)!={"maxAttempts","backoffSeconds",
                            "needsInspectionAfter"}
            or type(retry.get("maxAttempts")) is not int
            or not 1<=retry["maxAttempts"]<=10
            or type(retry.get("backoffSeconds")) is not int
            or not 0<=retry["backoffSeconds"]<=86_400
            or retry.get("needsInspectionAfter") is not True):
        raise ValueError("APPLICATION_SCHEDULE_RETRY_POLICY_INVALID")
    if value["cancellationPolicy"]!=CANCELLATION_POLICY:
        raise ValueError("APPLICATION_SCHEDULE_CANCELLATION_POLICY_INVALID")

    delegation=value["delegation"]
    if (type(delegation) is not dict
            or set(delegation)!={"delegationId","stateToken"}
            or type(delegation.get("delegationId")) is not str
            or _ID.fullmatch(delegation["delegationId"]) is None
            or type(delegation.get("stateToken")) is not str
            or _DIGEST.fullmatch(delegation["stateToken"]) is None):
        raise ValueError("APPLICATION_SCHEDULE_DELEGATION_INVALID")

    normalized={"format":FORMAT,"scheduleId":schedule_id,
        "target":dict(target),"bindings":bindings,"pov":normalized_pov,
        "recurrence":{"kind":"FixedInterval",
            "intervalSeconds":recurrence["intervalSeconds"],
            "firstDueAt":due,"catchUpPolicy":recurrence["catchUpPolicy"],
            "maxCatchUp":recurrence["maxCatchUp"]},
        "retryPolicy":dict(retry),"cancellationPolicy":CANCELLATION_POLICY,
        "delegation":dict(delegation)}
    _json(normalized)
    return normalized


def execution_bindings(definition: object) -> dict:
    """Merge explicit POV member bindings into the exact rule binding map."""
    value=validate_definition(definition)
    result=dict(value["bindings"])
    result.update({row["parameter"]:row["memberId"] for row in value["pov"]})
    return result


def canonical_digest(definition: object) -> str:
    value=validate_definition(definition)
    raw=json.dumps(value,sort_keys=True,separators=(",",":"),
                   ensure_ascii=True,allow_nan=False).encode("ascii")
    return sha256(raw).hexdigest()
