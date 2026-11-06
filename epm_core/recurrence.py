"""Bounded deterministic recurrence primitives for generic schedules."""
from __future__ import annotations

from datetime import datetime,timezone,timedelta
from enum import StrEnum
from typing import Sequence


MAX_CATCH_UP=36


class CatchUpPolicy(StrEnum):
    SKIP="skip"
    LATEST="latest"
    ALL="all"


def _utc(value: object) -> datetime:
    if (type(value) is not datetime or value.tzinfo is None
            or value.utcoffset()!=timezone.utc.utcoffset(value)):
        raise ValueError("SCHEDULE_DUE_TIME_INVALID")
    return value


def select_due_instants(instants: Sequence[datetime], *,
                        after: datetime|None,through: datetime,
                        policy: CatchUpPolicy,
                        maximum: int=MAX_CATCH_UP) -> tuple[datetime,...]:
    """Apply duplicate-free catch-up policy to ordered server due instants."""
    if not isinstance(policy,CatchUpPolicy):
        raise ValueError("SCHEDULE_CATCH_UP_POLICY_INVALID")
    end=_utc(through)
    start=None if after is None else _utc(after)
    if type(maximum) is not int or not 1<=maximum<=MAX_CATCH_UP:
        raise ValueError("SCHEDULE_CATCH_UP_LIMIT_INVALID")
    if not isinstance(instants,(tuple,list)) or len(instants)>4096:
        raise ValueError("SCHEDULE_DUE_INSTANTS_INVALID")
    checked=tuple(_utc(item) for item in instants)
    if any(left>=right for left,right in zip(checked,checked[1:])):
        raise ValueError("SCHEDULE_DUE_INSTANTS_NOT_ORDERED")
    due=tuple(item for item in checked
              if (start is None or item>start) and item<=end)
    if policy is CatchUpPolicy.SKIP:return ()
    if policy is CatchUpPolicy.LATEST:return due[-1:] if due else ()
    return due[:maximum]


def due_from_interval(*,first_due_at: datetime,interval_seconds: int,
                      last_due_at: datetime|None,through: datetime,
                      policy: CatchUpPolicy,
                      maximum: int=MAX_CATCH_UP) -> tuple[datetime,...]:
    """Resolve a bounded interval without iterating over dormant history."""
    first=_utc(first_due_at);end=_utc(through)
    last=None if last_due_at is None else _utc(last_due_at)
    if type(interval_seconds) is not int or not 60<=interval_seconds<=2678400:
        raise ValueError("SCHEDULE_INTERVAL_INVALID")
    if not isinstance(policy,CatchUpPolicy):
        raise ValueError("SCHEDULE_CATCH_UP_POLICY_INVALID")
    if type(maximum) is not int or not 1<=maximum<=MAX_CATCH_UP:
        raise ValueError("SCHEDULE_CATCH_UP_LIMIT_INVALID")
    if end<first:return ()
    last_ordinal=(-1 if last is None or last<first else
        int((last-first).total_seconds())//interval_seconds)
    through_ordinal=int((end-first).total_seconds())//interval_seconds
    if through_ordinal<=last_ordinal or policy is CatchUpPolicy.SKIP:return ()
    ordinals=((through_ordinal,) if policy is CatchUpPolicy.LATEST else
        range(last_ordinal+1,
              min(through_ordinal+1,last_ordinal+1+maximum)))
    return tuple(first+timedelta(seconds=ordinal*interval_seconds)
                 for ordinal in ordinals)
