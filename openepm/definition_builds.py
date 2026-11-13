"""Lower typed authored definitions into fixed, inspectable build artifacts.

This module runs in the isolated authoring runtime. It performs no persistence
or activation and has no dependency on the trusted application core.
"""
from __future__ import annotations

from .calculated_members import CalculatedMember
from .model import ApplicationRule, BuildContext, Program


def definition_program(value: object, context: BuildContext) -> Program | None:
    pins = {'expectedMetadataRevision': context.metadata_revision,
            'expectedPolicyRevision': context.policy_revision}
    if isinstance(value, ApplicationRule):
        function = 'application.rule.save'
        arguments = {'ruleId': value.rule_id,
                     'definition': value.to_definition(), **pins}
    elif isinstance(value, CalculatedMember):
        function = 'calculated.member.save'
        arguments = {'definition': value.to_wire(), **pins}
    else:
        return None
    program = Program.one(function, arguments, name='definition')
    object.__setattr__(program.units[0], '_source_spans', (value._source_span,))
    return program
