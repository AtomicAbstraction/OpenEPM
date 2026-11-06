"""Explicit, bounded recovery input for pre-0101 forecast schedules."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from hashlib import sha256
import json
from pathlib import Path
import re


MAX_BYTES=1_048_576
MAX_ROWS=10_000
_SCHEDULE_ID=re.compile(r'^[A-Za-z0-9._-]{1,100}$')


class _DuplicateKey(ValueError):pass


def _object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise _DuplicateKey
        result[key]=value
    return result


def validate_forecast_boundary_recovery_reachability(recovery,available,existing):
    if recovery is None:return
    if 101 not in available:
        raise ValueError('FORECAST_BOUNDARY_MAP_RELEASE_UNSUPPORTED')
    if 101 in existing:
        raise ValueError('FORECAST_BOUNDARY_MAP_NOT_APPLICABLE')
    if set(existing)!=set(range(1,101)):
        raise ValueError('FORECAST_BOUNDARY_MAP_REQUIRES_SCHEMA_0100')


@dataclass(frozen=True,slots=True)
class ForecastBoundaryRecovery:
    rows: tuple[tuple[str,str,str,int,date],...]
    digest: str


def load_forecast_boundary_recovery(path: Path|None)->ForecastBoundaryRecovery|None:
    if path is None:return None
    if not isinstance(path,Path):raise ValueError('FORECAST_BOUNDARY_MAP_PATH_INVALID')
    try:
        if not path.is_file() or path.is_symlink():
            raise ValueError('FORECAST_BOUNDARY_MAP_PATH_INVALID')
        raw=path.read_bytes()
    except OSError as error:
        raise ValueError('FORECAST_BOUNDARY_MAP_UNAVAILABLE') from error
    if not raw or len(raw)>MAX_BYTES:raise ValueError('FORECAST_BOUNDARY_MAP_SIZE_INVALID')
    try:value=json.loads(raw,object_pairs_hook=_object)
    except _DuplicateKey as error:
        raise ValueError('FORECAST_BOUNDARY_MAP_DUPLICATE_KEY') from error
    except (UnicodeError,json.JSONDecodeError) as error:
        raise ValueError('FORECAST_BOUNDARY_MAP_JSON_INVALID') from error
    if (type(value) is not dict or set(value)!={'version','schedules'}
            or type(value['version']) is not int or value['version']!=1):
        raise ValueError('FORECAST_BOUNDARY_MAP_FORMAT_INVALID')
    values=value['schedules']
    if type(values) is not list or not 1<=len(values)<=MAX_ROWS:
        raise ValueError('FORECAST_BOUNDARY_MAP_ROWS_INVALID')
    rows=[];seen=set()
    required={'workspaceId','applicationId','scheduleId','version','actualClosedThrough'}
    for item in values:
        if type(item) is not dict or set(item)!=required:
            raise ValueError('FORECAST_BOUNDARY_MAP_ROW_INVALID')
        identifiers=(item['workspaceId'],item['applicationId'],item['scheduleId'])
        if (any(type(v) is not str or not 1<=len(v)<=200 or v!=v.strip()
                or any(ord(char)<32 or ord(char)==127 for char in v)
                for v in identifiers[:2])
                or type(identifiers[2]) is not str
                or _SCHEDULE_ID.fullmatch(identifiers[2]) is None):
            raise ValueError('FORECAST_BOUNDARY_MAP_IDENTITY_INVALID')
        version=item['version']
        if type(version) is not int or version<1:
            raise ValueError('FORECAST_BOUNDARY_MAP_IDENTITY_INVALID')
        text=item['actualClosedThrough']
        try:boundary=date.fromisoformat(text) if type(text) is str else None
        except ValueError:boundary=None
        if boundary is None or boundary.isoformat()!=text:
            raise ValueError('FORECAST_BOUNDARY_MAP_DATE_INVALID')
        key=(*identifiers,version)
        if key in seen:raise ValueError('FORECAST_BOUNDARY_MAP_DUPLICATE')
        seen.add(key);rows.append((*key,boundary))
    rows.sort(key=lambda row:row[:4])
    canonical={'version':1,'schedules':[{'workspaceId':w,'applicationId':a,
        'scheduleId':s,'version':v,'actualClosedThrough':d.isoformat()}
        for w,a,s,v,d in rows]}
    encoded=json.dumps(canonical,sort_keys=True,separators=(',',':'),
                       ensure_ascii=True).encode('ascii')
    return ForecastBoundaryRecovery(tuple(rows),sha256(encoded).hexdigest())


def apply_forecast_boundary_recovery(db,recovery:ForecastBoundaryRecovery|None)->None:
    missing=db.execute('''SELECT v.workspace_id,v.application_id,v.schedule_id,v.version,
          d.definition_id IS NOT NULL AS definition_linked
        FROM epm.planning_forecast_schedule_version v
        LEFT JOIN epm.planning_forecast_definition_version d ON
          (d.workspace_id,d.application_id,d.definition_id,d.version)=
          (v.workspace_id,v.application_id,v.definition_id,v.definition_version)
        WHERE v.actual_closed_through IS NULL
        ORDER BY v.workspace_id,v.application_id,v.schedule_id,v.version''').fetchall()
    if any(not row[4] for row in missing):
        raise ValueError('FORECAST_BOUNDARY_MAP_DEFINITION_LINK_INVALID')
    expected={tuple(row[:4]) for row in missing}
    supplied=set() if recovery is None else {row[:4] for row in recovery.rows}
    if not expected and supplied:
        raise ValueError('FORECAST_BOUNDARY_MAP_TARGET_ALREADY_SET_OR_UNKNOWN')
    if expected!=supplied:
        raise ValueError('FORECAST_BOUNDARY_MAP_COVERAGE_MISMATCH')
    if not expected:return
    for workspace,application,schedule,version,boundary in recovery.rows:
        changed=db.execute('''UPDATE epm.planning_forecast_schedule_version SET
            actual_closed_through=%s WHERE workspace_id=%s AND application_id=%s
              AND schedule_id=%s AND version=%s AND actual_closed_through IS NULL''',
            (boundary,workspace,application,schedule,version)).rowcount
        if changed!=1:raise ValueError('FORECAST_BOUNDARY_MAP_TARGET_CHANGED')
    db.execute('''INSERT INTO epm.security_audit(actor_id,action,target_digest,outcome,detail)
        VALUES('migration-owner','forecast.schedule.boundary.recover',%s,'Accepted',
          jsonb_build_object('formatVersion',1,'scheduleVersionCount',%s))''',
        (recovery.digest,len(recovery.rows)))
