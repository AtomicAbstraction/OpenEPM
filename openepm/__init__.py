"""Public, database-neutral Python authoring SDK for Open EPM.

This package constructs typed application-language plans.  It intentionally has
no dependency on the trusted ``epm_core`` package or on a database driver.
"""

from ._client_identity import CLIENT_VERSION as __version__
from .aggregates import CubeAggregate
from .authoring import (Attribute, AxisSelection, Dimension, Hierarchy, Member,
                        Placement, Relationship)
from .calculated_members import CalculatedMember,CalculatedMemberDependency
from .client import EpmClient, Transport
from .decisions import ApplicationDecisions
from .lifecycle import ApplicationPurge
from .effects import CubeEffect,CubeEffectBatch
from .functions import Function,FunctionRegistry,generate_function_registry
from .member_lists import MemberListDefinition,MemberListExpression,MemberListParameter
from .selections import CubeSelection,DimensionSelection
from .views import CubeView
from .model import (
    Amount,
    ApportionmentDomain,
    ApportionmentFormula,
    ApplicabilityDomain,
    ApportionmentComponent,
    ApportionmentTarget,
    Application,
    ApplicationRule,
    ApplicationRuleParameter,
    ApplicationRuleParameterRef,
    AtomicUnit,
    BuildContext,
    CalendarPeriodDependency,
    ContextAssertion,
    CubeExpression,
    JobHandle,
    MemberSet,
    NumericIteration,
    NumericSequence,
    NumericSequenceExpression,
    OwnershipValueDependency,
    Program,
    PythonBuildArtifactSection,
    Ratio,
    RelationOperand,
    RelationValue,
    StatementValue,
)
from .transport import HttpsMcpTransport, McpTransportError
from .oidc import (DeviceAuthorizationPrompt, OidcDeviceError,
                   OidcDeviceTokenProvider)


__all__ = [
    "Attribute", "AxisSelection", "Dimension", "Hierarchy", "Member",
    "Placement", "Relationship",
    "ApportionmentComponent", "ApportionmentTarget", "ApplicabilityDomain",
    "ApportionmentDomain", "ApportionmentFormula",
    "Amount", "Application", "ApplicationDecisions", "ApplicationPurge", "ApplicationRule", "ApplicationRuleParameter",
    "ApplicationRuleParameterRef", "AtomicUnit", "BuildContext",
    "CalculatedMember", "CalculatedMemberDependency", "CalendarPeriodDependency", "ContextAssertion", "CubeExpression",
    "CubeAggregate", "CubeEffect", "CubeEffectBatch", "CubeSelection", "CubeView", "DimensionSelection",
    "EpmClient", "Function", "FunctionRegistry", "JobHandle", "MemberSet",
    "MemberListDefinition", "MemberListExpression", "MemberListParameter",
    "NumericIteration", "NumericSequence", "NumericSequenceExpression",
    "OwnershipValueDependency", "Program", "PythonBuildArtifactSection",
    "Ratio", "RelationOperand", "RelationValue", "StatementValue", "Transport", "__version__", "generate_function_registry",
    "HttpsMcpTransport", "McpTransportError",
    "DeviceAuthorizationPrompt", "OidcDeviceError", "OidcDeviceTokenProvider",
]
