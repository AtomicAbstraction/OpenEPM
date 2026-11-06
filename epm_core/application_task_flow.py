"""Pure contract for versioned, human-oriented application task flows.

The contract sequences evidence about existing Open EPM artifacts.  It does
not execute business functions, schedule work, establish identities, or create
another security/group model.  A fixed repository may later resolve each
``assignmentRef`` through the existing planning-assignment subsystem and may
validate occurrence-specific artifacts against these typed contracts.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re

from .persistence_contract import ApplicationScope


FORMAT = 'openepm-application-task-flow-v1'
MIN_ACTIVITIES = 2
MAX_ACTIVITIES = 50
MAX_SCOPE_DIMENSIONS = 32
MAX_MEMBERS_PER_SELECTOR = 1000
MAX_TOTAL_MEMBER_REFERENCES = 10_000

_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._:@/-]{0,299}\Z')
_RESULT_KEY = re.compile(r'[A-Za-z0-9._-]{8,128}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_KINDS = frozenset((
    'ManualConfirmation',
    'PlanningSliceOpen',
    'PlanningSubmission',
    'PlanningApproval',
    'CalculationPublication',
))


def _identifier(value: object, field: str) -> str:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError(f'APPLICATION_TASK_FLOW_{field}_INVALID')
    return value


def _display_name(value: object) -> str:
    if (type(value) is not str or not 1 <= len(value) <= 200
            or value != value.strip() or '\x00' in value):
        raise ValueError('APPLICATION_TASK_FLOW_NAME_INVALID')
    return value


@dataclass(frozen=True, slots=True)
class AssignmentRef:
    assignment_set_id: str
    version: int
    digest: str
    assignment_id: str

    def normalized(self) -> dict:
        return {
            'assignmentSetId': self.assignment_set_id,
            'version': self.version,
            'digest': self.digest,
            'assignmentId': self.assignment_id,
        }


@dataclass(frozen=True, slots=True)
class PeriodScope:
    year_dimension_id: str
    year_member_id: str
    period_dimension_id: str
    period_member_id: str

    def normalized(self) -> dict:
        return {
            'yearDimensionId': self.year_dimension_id,
            'yearMemberId': self.year_member_id,
            'periodDimensionId': self.period_dimension_id,
            'periodMemberId': self.period_member_id,
        }


@dataclass(frozen=True, slots=True)
class TaskFlowScope:
    period: PeriodScope
    member_selectors: tuple[tuple[str, tuple[str, ...]], ...]

    def normalized(self) -> dict:
        return {
            'period': self.period.normalized(),
            'memberSelectors': {
                dimension: list(members)
                for dimension, members in self.member_selectors
            },
        }


@dataclass(frozen=True, slots=True)
class TaskFlowActivity:
    activity_id: str
    name: str
    kind: str
    depends_on: tuple[str, ...]
    assignment_ref: AssignmentRef
    artifact_contract: tuple[tuple[str, object], ...]

    def normalized(self) -> dict:
        contract = {key: (list(value) if isinstance(value, tuple) else value)
                    for key, value in self.artifact_contract}
        return {
            'activityId': self.activity_id,
            'name': self.name,
            'kind': self.kind,
            'dependsOn': list(self.depends_on),
            'assignmentRef': self.assignment_ref.normalized(),
            'artifactContract': contract,
        }


@dataclass(frozen=True, slots=True)
class ApplicationTaskFlow:
    scope: ApplicationScope
    flow_id: str
    version: int
    name: str
    task_scope: TaskFlowScope
    activities: tuple[TaskFlowActivity, ...]
    digest: str

    @property
    def start_activity_id(self) -> str:
        return next(item.activity_id for item in self.activities
                    if not item.depends_on)

    def normalized(self) -> dict:
        return {
            'format': FORMAT,
            'workspaceId': self.scope.workspace_id,
            'applicationId': self.scope.application_id,
            'flowId': self.flow_id,
            'version': self.version,
            'name': self.name,
            'scope': self.task_scope.normalized(),
            'activities': [item.normalized() for item in self.activities],
        }


def _assignment_ref(raw: object) -> AssignmentRef:
    expected = {'assignmentSetId', 'version', 'digest', 'assignmentId'}
    if type(raw) is not dict or set(raw) != expected:
        raise ValueError('APPLICATION_TASK_FLOW_ASSIGNMENT_REF_INVALID')
    version = raw['version']
    if type(version) is not int or version < 1:
        raise ValueError('APPLICATION_TASK_FLOW_ASSIGNMENT_REF_INVALID')
    digest = raw['digest']
    if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
        raise ValueError('APPLICATION_TASK_FLOW_ASSIGNMENT_REF_INVALID')
    return AssignmentRef(
        _identifier(raw['assignmentSetId'], 'ASSIGNMENT_REF'),
        version,
        digest,
        _identifier(raw['assignmentId'], 'ASSIGNMENT_REF'),
    )


def _period_scope(raw: object) -> PeriodScope:
    expected = {'yearDimensionId', 'yearMemberId',
                'periodDimensionId', 'periodMemberId'}
    if type(raw) is not dict or set(raw) != expected:
        raise ValueError('APPLICATION_TASK_FLOW_PERIOD_SCOPE_INVALID')
    period = PeriodScope(
        _identifier(raw['yearDimensionId'], 'PERIOD_SCOPE'),
        _identifier(raw['yearMemberId'], 'PERIOD_SCOPE'),
        _identifier(raw['periodDimensionId'], 'PERIOD_SCOPE'),
        _identifier(raw['periodMemberId'], 'PERIOD_SCOPE'),
    )
    if period.year_dimension_id == period.period_dimension_id:
        raise ValueError('APPLICATION_TASK_FLOW_PERIOD_DIMENSIONS_DUPLICATE')
    return period


def _task_scope(raw: object) -> TaskFlowScope:
    if (type(raw) is not dict
            or set(raw) != {'period', 'memberSelectors'}):
        raise ValueError('APPLICATION_TASK_FLOW_SCOPE_INVALID')
    period = _period_scope(raw['period'])
    selectors = raw['memberSelectors']
    if (type(selectors) is not dict
            or not 1 <= len(selectors) <= MAX_SCOPE_DIMENSIONS):
        raise ValueError('APPLICATION_TASK_FLOW_SCOPE_SELECTORS_INVALID')
    normalized = []
    references = 0
    for dimension, members in selectors.items():
        dimension_id = _identifier(dimension, 'SCOPE_DIMENSION')
        if (type(members) is not list
                or not 1 <= len(members) <= MAX_MEMBERS_PER_SELECTOR
                or any(type(member) is not str for member in members)
                or len(members) != len(set(members))):
            raise ValueError('APPLICATION_TASK_FLOW_SCOPE_MEMBERS_INVALID')
        member_ids = tuple(sorted(
            _identifier(member, 'SCOPE_MEMBER') for member in members))
        references += len(member_ids)
        normalized.append((dimension_id, member_ids))
    if references > MAX_TOTAL_MEMBER_REFERENCES:
        raise ValueError('APPLICATION_TASK_FLOW_SCOPE_MEMBER_LIMIT')
    dimensions = {dimension for dimension, _ in normalized}
    if dimensions & {period.year_dimension_id, period.period_dimension_id}:
        raise ValueError('APPLICATION_TASK_FLOW_PERIOD_SCOPE_DUPLICATE')
    return TaskFlowScope(period, tuple(sorted(normalized)))


def _artifact_contract(kind: str, raw: object) -> tuple[tuple[str, object], ...]:
    if type(raw) is not dict:
        raise ValueError('APPLICATION_TASK_FLOW_ARTIFACT_CONTRACT_INVALID')
    if kind == 'ManualConfirmation':
        expected_raw = {'artifactType': 'ManualConfirmation'}
    elif kind == 'PlanningSliceOpen':
        expected_raw = {'artifactType': 'PlanningSlice',
                        'requiredStatuses': ['Open']}
    elif kind == 'PlanningSubmission':
        expected_raw = {'artifactType': 'PlanningSubmission',
                        'requiredStatuses': ['InReview', 'Submitted']}
    elif kind == 'PlanningApproval':
        expected_raw = {'artifactType': 'PlanningSubmission',
                        'requiredStatuses': ['Approved']}
    else:
        if set(raw) != {'artifactType', 'resultKey', 'requireCurrent'}:
            raise ValueError('APPLICATION_TASK_FLOW_ARTIFACT_CONTRACT_INVALID')
        if (raw.get('artifactType') != 'CalculationPublication'
                or raw.get('requireCurrent') is not True
                or type(raw.get('resultKey')) is not str
                or _RESULT_KEY.fullmatch(raw['resultKey']) is None):
            raise ValueError('APPLICATION_TASK_FLOW_ARTIFACT_CONTRACT_INVALID')
        expected_raw = {'artifactType': 'CalculationPublication',
                        'resultKey': raw['resultKey'], 'requireCurrent': True}
    if raw != expected_raw:
        raise ValueError('APPLICATION_TASK_FLOW_ARTIFACT_CONTRACT_INVALID')
    immutable = {key: (tuple(value) if isinstance(value, list) else value)
                 for key, value in expected_raw.items()}
    return tuple(sorted(immutable.items()))


def _activity(raw: object) -> TaskFlowActivity:
    expected = {'activityId', 'name', 'kind', 'dependsOn',
                'assignmentRef', 'artifactContract'}
    if type(raw) is not dict or set(raw) != expected:
        raise ValueError('APPLICATION_TASK_FLOW_ACTIVITY_INVALID')
    kind = raw['kind']
    if type(kind) is not str or kind not in _KINDS:
        raise ValueError('APPLICATION_TASK_FLOW_ACTIVITY_KIND_INVALID')
    dependencies = raw['dependsOn']
    if (type(dependencies) is not list or len(dependencies) > MAX_ACTIVITIES - 1
            or any(type(item) is not str for item in dependencies)
            or len(dependencies) != len(set(dependencies))):
        raise ValueError('APPLICATION_TASK_FLOW_DEPENDENCIES_INVALID')
    depends_on = tuple(sorted(
        _identifier(item, 'DEPENDENCY') for item in dependencies))
    return TaskFlowActivity(
        _identifier(raw['activityId'], 'ACTIVITY_ID'),
        _display_name(raw['name']),
        kind,
        depends_on,
        _assignment_ref(raw['assignmentRef']),
        _artifact_contract(kind, raw['artifactContract']),
    )


def _validate_graph(activities: tuple[TaskFlowActivity, ...]) -> None:
    by_id = {item.activity_id: item for item in activities}
    if len(by_id) != len(activities):
        raise ValueError('APPLICATION_TASK_FLOW_ACTIVITY_ID_DUPLICATE')
    for item in activities:
        if item.activity_id in item.depends_on:
            raise ValueError('APPLICATION_TASK_FLOW_DEPENDENCY_SELF_REFERENCE')
        if not set(item.depends_on) <= set(by_id):
            raise ValueError('APPLICATION_TASK_FLOW_DEPENDENCY_UNAVAILABLE')
    starts = [item.activity_id for item in activities if not item.depends_on]
    if len(starts) != 1:
        raise ValueError('APPLICATION_TASK_FLOW_START_NODE_INVALID')

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(activity_id: str) -> None:
        if activity_id in visited:
            return
        if activity_id in visiting:
            raise ValueError('APPLICATION_TASK_FLOW_CYCLE')
        visiting.add(activity_id)
        for dependency in by_id[activity_id].depends_on:
            visit(dependency)
        visiting.remove(activity_id)
        visited.add(activity_id)

    for activity_id in by_id:
        visit(activity_id)

    reachable = {starts[0]}
    changed = True
    while changed:
        changed = False
        for item in activities:
            if (item.activity_id not in reachable
                    and set(item.depends_on) <= reachable):
                reachable.add(item.activity_id)
                changed = True
    if reachable != set(by_id):
        raise ValueError('APPLICATION_TASK_FLOW_UNREACHABLE_ACTIVITY')


def compile_application_task_flow(definition: object) -> ApplicationTaskFlow:
    """Strictly validate and canonically digest one immutable definition."""
    expected = {'format', 'workspaceId', 'applicationId', 'flowId',
                'version', 'name', 'scope', 'activities'}
    if (type(definition) is not dict or set(definition) != expected
            or definition.get('format') != FORMAT):
        raise ValueError('APPLICATION_TASK_FLOW_DEFINITION_INVALID')
    version = definition['version']
    if type(version) is not int or version < 1:
        raise ValueError('APPLICATION_TASK_FLOW_VERSION_INVALID')
    raw_activities = definition['activities']
    if (type(raw_activities) is not list
            or not MIN_ACTIVITIES <= len(raw_activities) <= MAX_ACTIVITIES):
        raise ValueError('APPLICATION_TASK_FLOW_ACTIVITY_COUNT_INVALID')
    activities = tuple(sorted(
        (_activity(item) for item in raw_activities),
        key=lambda item: item.activity_id))
    _validate_graph(activities)
    model = ApplicationTaskFlow(
        ApplicationScope(
            _identifier(definition['workspaceId'], 'WORKSPACE_ID'),
            _identifier(definition['applicationId'], 'APPLICATION_ID')),
        _identifier(definition['flowId'], 'FLOW_ID'),
        version,
        _display_name(definition['name']),
        _task_scope(definition['scope']),
        activities,
        '',
    )
    canonical = json.dumps(model.normalized(), sort_keys=True,
                           separators=(',', ':'), ensure_ascii=False,
                           allow_nan=False).encode()
    return ApplicationTaskFlow(
        model.scope, model.flow_id, model.version, model.name,
        model.task_scope, model.activities, sha256(canonical).hexdigest())

