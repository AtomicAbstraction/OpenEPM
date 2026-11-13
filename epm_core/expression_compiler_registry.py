"""Authoritative compatibility inventory for fixed expression compilers."""

from dataclasses import dataclass
import re

from . import expression_currency_member_set as currency_member_set
from . import expression_apportionment as apportionment
from . import postgres_expression as expression


_DIGEST = re.compile(r'[0-9a-f]{64}\Z')


@dataclass(frozen=True, slots=True)
class ExpressionCompilerProfile:
    version: int
    name: str
    compiler: str
    plan_digest: str
    admission_family: str


def _profile(version: int, name: str, compiler: str, plan_digest: str,
             family: str = 'facts.expression.calculate') -> (
                 ExpressionCompilerProfile):
    return ExpressionCompilerProfile(
        version, name, compiler, plan_digest, family)


PROFILES = (
    _profile(1, 'same-grain amount expression', expression.COMPILER,
             expression.PLAN_DIGEST),
    _profile(2, 'published amount composition', expression.COMPOSED_COMPILER,
             expression.COMPOSED_PLAN_DIGEST),
    _profile(3, 'mapped published amount', expression.MAPPED_COMPILER,
             expression.MAPPED_PLAN_DIGEST),
    _profile(4, 'typed conditional', expression.CONDITIONAL_COMPILER,
             expression.CONDITIONAL_PLAN_DIGEST),
    _profile(5, 'target member transform', expression.TRANSFORM_COMPILER,
             expression.TRANSFORM_PLAN_DIGEST),
    _profile(6, 'dynamic exact division', expression.DYNAMIC_DIVISION_COMPILER,
             expression.DYNAMIC_DIVISION_PLAN_DIGEST),
    _profile(7, 'immutable saved rule', expression.SAVED_RULE_COMPILER,
             expression.SAVED_RULE_PLAN_DIGEST),
    _profile(8, 'literal-parameter saved rule',
             expression.PARAMETERIZED_RULE_COMPILER,
             expression.PARAMETERIZED_RULE_PLAN_DIGEST),
    _profile(9, 'member-parameter saved rule',
             expression.MEMBER_PARAMETER_RULE_COMPILER,
             expression.MEMBER_PARAMETER_RULE_PLAN_DIGEST),
    _profile(10, 'raw driver lookup', expression.RAW_DRIVER_COMPILER,
             expression.RAW_DRIVER_PLAN_DIGEST),
    _profile(11, 'typed raw driver lookup', expression.TYPED_DRIVER_COMPILER,
             expression.TYPED_DRIVER_PLAN_DIGEST),
    _profile(12, 'immutable driver policy', expression.POLICY_DRIVER_COMPILER,
             expression.POLICY_DRIVER_PLAN_DIGEST),
    _profile(13, 'published driver policy',
             expression.PUBLISHED_POLICY_DRIVER_COMPILER,
             expression.PUBLISHED_POLICY_DRIVER_PLAN_DIGEST),
    _profile(14, 'one-axis member-set transform',
             expression.MEMBER_SET_TRANSFORM_COMPILER,
             expression.MEMBER_SET_TRANSFORM_PLAN_DIGEST),
    _profile(15, 'one-axis sum reduction',
             expression.MEMBER_SET_REDUCTION_COMPILER,
             expression.MEMBER_SET_REDUCTION_PLAN_DIGEST),
    _profile(16, 'two-axis member-set transform',
             expression.TWO_AXIS_MEMBER_SET_COMPILER,
             expression.TWO_AXIS_MEMBER_SET_PLAN_DIGEST),
    _profile(17, 'explicit missing-default domain',
             expression.EXPLICIT_MISSING_DEFAULT_COMPILER,
             expression.EXPLICIT_MISSING_DEFAULT_PLAN_DIGEST),
    _profile(18, 'one-axis average reduction',
             expression.MEMBER_SET_AVERAGE_COMPILER,
             expression.MEMBER_SET_AVERAGE_PLAN_DIGEST),
    _profile(19, 'unit-bound reduction',
             expression.UNIT_BOUND_REDUCTION_COMPILER,
             expression.UNIT_BOUND_REDUCTION_PLAN_DIGEST),
    _profile(20, 'weighted-average reduction',
             expression.WEIGHTED_AVERAGE_COMPILER,
             expression.WEIGHTED_AVERAGE_PLAN_DIGEST),
    _profile(21, 'sealed currency conversion',
             expression.CURRENCY_CONVERSION_COMPILER,
             expression.CURRENCY_CONVERSION_PLAN_DIGEST),
    _profile(22, 'aligned published-unit expression',
             expression.UNIT_ALIGNED_COMPILER,
             expression.UNIT_ALIGNED_PLAN_DIGEST),
    _profile(23, 'server-resolved currency member set',
             currency_member_set.COMPILER, currency_member_set.PLAN_DIGEST,
             'facts.expression.currency.member_set.request'),
    _profile(24, 'ratio result', expression.RATIO_RESULT_COMPILER,
             expression.RATIO_RESULT_PLAN_DIGEST),
    _profile(25, 'published-dependency driver policy',
             expression.PUBLISHED_DEPENDENCY_DRIVER_COMPILER,
             expression.PUBLISHED_DEPENDENCY_DRIVER_PLAN_DIGEST),
    _profile(26, 'one-axis hierarchy reduction',
             expression.HIERARCHY_REDUCTION_COMPILER,
             expression.HIERARCHY_REDUCTION_PLAN_DIGEST),
    _profile(27, 'two-axis hierarchy reduction',
             expression.TWO_AXIS_HIERARCHY_REDUCTION_COMPILER,
             expression.TWO_AXIS_HIERARCHY_REDUCTION_PLAN_DIGEST),
    _profile(28, 'raw text predicate', expression.TEXT_PREDICATE_COMPILER,
             expression.TEXT_PREDICATE_PLAN_DIGEST),
    _profile(29, 'raw amount-unit expression',
             expression.RAW_UNIT_EXPRESSION_COMPILER,
             expression.RAW_UNIT_EXPRESSION_PLAN_DIGEST),
    _profile(30, 'three/four-axis member-set transform',
             expression.MULTI_AXIS_MEMBER_SET_COMPILER,
             expression.MULTI_AXIS_MEMBER_SET_PLAN_DIGEST),
    _profile(31, 'three/four-axis member-set reduction',
             expression.MULTI_AXIS_MEMBER_SET_REDUCTION_COMPILER,
             expression.MULTI_AXIS_MEMBER_SET_REDUCTION_PLAN_DIGEST),
    _profile(32, 'sealed non-fact context expression',
             expression.CONTEXT_EXPRESSION_COMPILER,
             expression.CONTEXT_EXPRESSION_PLAN_DIGEST),
    _profile(33, 'two-axis member-set reduction',
             expression.TWO_AXIS_MEMBER_SET_REDUCTION_COMPILER,
             expression.TWO_AXIS_MEMBER_SET_REDUCTION_PLAN_DIGEST),
    _profile(34, 'explicit source member-set expression',
             expression.SOURCE_MEMBER_SETS_COMPILER,
             expression.SOURCE_MEMBER_SETS_PLAN_DIGEST),
    _profile(35, 'published calculated-member expression',
             expression.CALCULATED_MEMBER_COMPILER,
             expression.CALCULATED_MEMBER_PLAN_DIGEST),
    _profile(36, 'exact signed apportionment',
             apportionment.COMPILER, apportionment.PLAN_DIGEST),
    _profile(37, 'server-resolved selected-domain expression',
             expression.SELECTED_DOMAIN_COMPILER,
             expression.SELECTED_DOMAIN_PLAN_DIGEST),
    _profile(38, 'calendar-bound selected-domain temporal expression',
             expression.TEMPORAL_SELECTED_DOMAIN_COMPILER,
             expression.TEMPORAL_SELECTED_DOMAIN_PLAN_DIGEST),
    _profile(39, 'current sparse applicability-relation expression',
             expression.APPLICABILITY_DOMAIN_COMPILER,
             expression.APPLICABILITY_DOMAIN_PLAN_DIGEST),
    _profile(40, 'grouped applicability-relation apportionment',
             apportionment.RELATION_COMPILER,
             apportionment.RELATION_PLAN_DIGEST),
)


def validate_compiler_profiles() -> tuple[ExpressionCompilerProfile, ...]:
    if tuple(item.version for item in PROFILES) != tuple(range(1, 41)):
        raise ValueError('EXPRESSION_COMPILER_VERSION_GAP')
    if len({item.compiler for item in PROFILES}) != len(PROFILES):
        raise ValueError('EXPRESSION_COMPILER_IDENTITY_COLLISION')
    if len({item.plan_digest for item in PROFILES}) != len(PROFILES):
        raise ValueError('EXPRESSION_COMPILER_PLAN_COLLISION')
    for item in PROFILES:
        if item.compiler != f'typed-numeric-expression-v{item.version}':
            raise ValueError('EXPRESSION_COMPILER_VERSION_MISMATCH')
        if not _DIGEST.fullmatch(item.plan_digest):
            raise ValueError('EXPRESSION_COMPILER_PLAN_DIGEST_INVALID')
        if not item.name or not item.admission_family:
            raise ValueError('EXPRESSION_COMPILER_PROFILE_INVALID')
    return PROFILES


def profile_for(compiler: str) -> ExpressionCompilerProfile:
    for item in validate_compiler_profiles():
        if item.compiler == compiler:
            return item
    raise ValueError('EXPRESSION_COMPILER_UNSUPPORTED')
