"""Explicit operation capabilities, independent of permission and SQL roles.

This registry is shared by persisted discovery and transaction-level guards.
Compiler validation and permission checks remain independent requirements.
"""
from copy import deepcopy
from hashlib import sha256
import json
from .postgres_consolidation_stages import ACQUISITION_LAYERS

FINANCIAL_CONSOLIDATION = 'financial_consolidation'
FUNCTION_REGISTRY_FORMAT = 'openepm-function-registry-v1'
KNOWN_CAPABILITIES = frozenset((FINANCIAL_CONSOLIDATION,))

# These application-mode controls remain in the private language catalogue so
# historical receipts and upgrade evidence can still be interpreted.  The
# single programmable-cube product no longer advertises them to clients or
# admits them into untrusted Python plans.
RETIRED_PUBLIC_FUNCTIONS = frozenset((
    'application.capabilities.read',
    'application.capabilities.history.read',
    'application.capabilities.configure',
    # Replaced by the generic application.assignment.* lifecycle.
    'planning.assignment.deactivate',
    'planning.assignment.list',
    'planning.assignment.publish',
    'planning.assignment.read',
    'planning.assignment.save',
    'planning.assignment.delegate',
    'planning.assignment.delegation.revoke',
    'planning.assignment.reassign',
    'planning.assignment.escalation.process',
    # Replaced by application.workflow.* and application assignment sets.
    'application.taskflow.save',
    'application.taskflow.read',
    'application.taskflow.list',
    'application.taskflow.publish',
    'application.taskflow.deactivate',
    'application.taskflow.occurrence.start',
    'application.taskflow.occurrence.read',
    'application.taskflow.worklist',
    'application.taskflow.activity.complete',
    'application.taskflow.occurrence.cancel',
    # Rolling forecast is now authored from generic time selections, rules and
    # exact application schedules in the client layer.
    'facts.planning.forecast.definition.activate',
    'facts.planning.forecast.definition.deactivate',
    'facts.planning.forecast.definition.list',
    'facts.planning.forecast.definition.read',
    'facts.planning.forecast.definition.save',
    'facts.planning.forecast.occurrence.cancel',
    'facts.planning.forecast.occurrence.read',
    'facts.planning.forecast.occurrence.request',
    'facts.planning.forecast.roll.apply',
    'facts.planning.forecast.roll.prepare',
    'facts.planning.forecast.schedule.activate',
    'facts.planning.forecast.schedule.deactivate',
    'facts.planning.forecast.schedule.list',
    'facts.planning.forecast.schedule.read',
    'facts.planning.forecast.schedule.resume',
    'facts.planning.forecast.schedule.save',
    # Financial journals, currency translation and financial member policy
    # are client-authored domain logic in the programmable-cube product.  The
    # private definitions remain only for historical receipt interpretation
    # and V17 recovery; fresh clients compose generic metadata, rules and
    # exact fact operations instead.
    'consolidation.journal.balance.read',
    'consolidation.journal.from_calculation.publish',
    'consolidation.journal.post',
    'consolidation.journal.read',
    'consolidation.journal.reverse',
    'currency.amount.translate.preview',
    'currency.amount.translate.publish',
    'currency.rate.resolve',
    'currency.settings.read',
    'currency.settings.save',
    'currency.translation.inspect',
    'currency.translation.publish',
    'financial.account.type.set',
    'financial.entity.currency.set',
    'financial.member.policy.read',
    # Built-in Seed/Driver/Rollup/Spread/Allocation products are replaced by
    # client-authored generic application rules over member lists, selections,
    # cube aggregation and exact fact operations.  Retire the policy family
    # together with every private lowering target so discovery cannot promise
    # a workflow whose generated operation is no longer admitted.
    'facts.planning.allocate.weighted',
    'facts.planning.group.sum',
    'facts.planning.group.sum.bulk',
    'facts.planning.rollup.sum',
    'facts.planning.scenario.copy.prepare',
    'facts.planning.spread.calendar.equal',
    'facts.planning.spread.equal',
    'planning.operation.policy.allocation.preview',
    'planning.operation.policy.allocation.run',
    'planning.operation.policy.deactivate',
    'planning.operation.policy.driver.preview',
    'planning.operation.policy.driver.run',
    'planning.operation.policy.list',
    'planning.operation.policy.publish',
    'planning.operation.policy.read',
    'planning.operation.policy.rollup.preview',
    'planning.operation.policy.rollup.run',
    'planning.operation.policy.save',
    'planning.operation.policy.seed.lineage.read',
    'planning.operation.policy.seed.preview',
    'planning.operation.policy.seed.run',
    'planning.operation.policy.spread.preview',
    'planning.operation.policy.spread.run',
    # Planning-version comparison is a client presentation/calculation over
    # authoritative generic cube and calculated-generation scans.  Retain the
    # private readers for historical artifacts, but do not keep ten product-
    # specific comparison contracts in the programmable-cube public surface.
    'planning.version.adjusted.compare',
    'planning.version.adjusted.scan',
    'planning.version.calculation.compare',
    'planning.version.calculation.scan',
    'planning.version.compare',
    'planning.version.cross-layer.compare',
    'planning.version.cross-layer.scan',
    'planning.version.scan',
    'planning.version.unit-calculation.compare',
    'planning.version.unit-calculation.scan',
    # Domain-neutral cube.write.policy.* contracts replace the planning-named
    # editability-policy lifecycle while preserving the fixed-core enforcement
    # boundary and private interpretation of already admitted artifacts.
    'planning.workflow.policy.deactivate',
    'planning.workflow.policy.list',
    'planning.workflow.policy.publish',
    'planning.workflow.policy.read',
    'planning.workflow.policy.save',
    # Domain-neutral cube.write.scope.* contracts replace the planning slice
    # lock/review vocabulary while retaining the same fixed-core enforcement.
    'planning.slice.approve',
    'planning.slice.assigned.read',
    'planning.slice.assigned.reopen',
    'planning.slice.lock',
    'planning.slice.read',
    'planning.slice.reopen',
    'planning.slice.review',
    'planning.slice.submit',
    'planning.slice.submit.assigned',
    'planning.slice.worklist',
    # The assignment-bound write-scope path still depends on the retired
    # planning-assignment store.  A fresh programmable application cannot
    # create that store through the public contract.  Generic assignments and
    # application workflows now compose the same human responsibility/review
    # journey around ordinary cube.write.scope.* operations.  Keep these four
    # definitions private only to interpret and recover already-admitted work.
    'cube.write.scope.submit.assigned',
    'cube.write.scope.review',
    'cube.write.scope.assigned.reopen',
    'cube.write.scope.assigned.read',
))


def is_retired_public_function(function):
    """Return whether a private historical function is closed to new clients."""
    return (function in RETIRED_PUBLIC_FUNCTIONS
            or function in CONSOLIDATION_FUNCTIONS)


def assert_public_program_admitted(program):
    """Reject retired operations at public transport boundaries.

    Private catalog definitions may remain so historical receipts can still
    be interpreted. That compatibility never makes them newly callable.
    """
    if (isinstance(program, dict)
            and is_retired_public_function(program.get('function'))):
        raise ValueError('APPLICATION_FUNCTION_RETIRED')
    return program

# Fixed-core services may need authorization before their public application-
# language/MCP catalog entry is integrated.  Keep those names explicit and
# capability-classified without advertising an unavailable public function.
# Moving an entry into CORE_FUNCTIONS is part of the later catalog/handler
# integration and is covered by describe_catalog's exact-set assertion.
PREPUBLIC_CORE_FUNCTIONS = frozenset((
    # Internal lowering target for one sealed Python atomic unit.  The public
    # registry continues to advertise its three constituent fact functions;
    # this name cannot be discovered as an independently authored operation.
    'facts.composite.batch',
))

# Narrow security/control adapters are not advertised through the ordinary
# application-language catalogue, but authorization still classifies them
# explicitly so the shared access checker does not infer effect policy from an
# HTTP/MCP route name.
CONTROL_PLANE_FUNCTIONS = frozenset((
    'security.application.access.set',
    'security.application.access.list',
    'security.application.audit.list',
    'security.application.receipt.read',
    'security.application.group-access.set',
    'security.application.group-access.list',
    'security.application.dimension-access.set',
    'security.application.dimension-access.read',
    'security.application.group-dimension-access.set',
    'security.application.group-dimension-access.read',
    'security.application.dimension-tags.read',
    'security.application.member-tags.read',
    'security.application.dimension-metadata-tags.read',
    'security.application.relationship-tags.read',
    'security.application.dimension-policy.version.save',
    'security.application.dimension-policy.version.read',
    'security.application.dimension-policy.version.list',
    'security.application.dimension-policy.activate',
    'security.application.dimension-policy.deactivate',
    'security.application.dimension-policy.active.read',
    'security.workspace.access.set',
    'security.workspace.group-access.set',
    'security.workspace.group-access.list',
    'security.rule.access.set',
    'security.rule.group-access.set',
))

# Financial planning can use balanced manual adjustments without a statutory
# policy pack. A namespace alone must never decide capability requirements.
CORE_FUNCTIONS = frozenset((
    'application.state.read',
    'application.operation.receipt.read',
    'application.workflow.occurrence.start',
    'application.workflow.occurrence.read',
    'application.workflow.worklist',
    'application.workflow.activity.complete',
    'application.workflow.activity.return',
    'application.workflow.occurrence.cancel',
    'application.workflow.save',
    'application.workflow.publish',
    'application.workflow.deactivate',
    'application.workflow.read',
    'application.workflow.list',
    'application.assignment.save',
    'application.assignment.publish',
    'application.assignment.deactivate',
    'application.assignment.read',
    'application.assignment.list',
    'schedule.version.save',
    'schedule.version.publish',
    'schedule.version.deactivate',
    'schedule.version.read',
    'schedule.version.list',
    'facts.projections.rebuild', 'facts.projections.cleanup',
    'application.capabilities.read',
    'application.capabilities.history.read',
    'application.capabilities.configure',
    'security.identity.current.read',
    'consolidation.journal.balance.read',
    'consolidation.journal.post',
    'consolidation.journal.from_calculation.publish',
    'consolidation.journal.read',
    'consolidation.journal.reverse',
    'currency.rate.resolve',
    'currency.amount.translate.preview',
    'currency.amount.translate.publish',
    'currency.settings.read',
    'currency.settings.save',
    'currency.translation.inspect',
    'currency.translation.publish',
    'execution.delegation.create',
    'execution.delegation.read',
    'execution.delegation.list',
    'execution.delegation.revoke',
    'facts.calculation.read',
    'facts.calculation.publication.list',
    'facts.calculation.scan',
    'facts.cube.scan',
    'grid.definition.save',
    'grid.definition.read',
    'grid.definition.list',
    'facts.cube.layer-report.scan',
    'facts.cube.select',
    'facts.cube.aggregate.read',
    'facts.cube.aggregate.cancel',
    'facts.cube.aggregate.request',
    'facts.export.page',
    'facts.source.manifest.attach',
    'facts.source.manifest.read',
    'facts.source.diagnostics.compile',
    'facts.transfer.export.request',
    'facts.transfer.export.read',
    'facts.transfer.export.cancel',
    'facts.transfer.import.request',
    'facts.transfer.import.read',
    'facts.transfer.import.cancel',
    'facts.transfer.import.diagnostics.read',
    'facts.transfer.import.diagnostics.list',
    'facts.transfer.export.manifest.read',
    'facts.transfer.export.manifest.list',
    'facts.transfer.export.payload.page',
    'facts.expression.calculate',
    'facts.generic.table.create',
    'facts.generic.table.delete',
    'facts.generic.table.list',
    'facts.generic.table.update',
    'facts.generic.value.bulk',
    'facts.generic.value.delete',
    'facts.generic.value.read',
    'facts.generic.value.scan',
    'facts.generic.value.set',
    'facts.generic.value.snapshot.scan',
    'facts.numeric.adjusted.read',
    'facts.numeric.adjusted.scan',
    'facts.numeric.batch',
    'facts.line-detail.replace',
    'facts.numeric.sequence',
    'facts.numeric.iterate',
    'rules.numeric_sequence.version.save',
    'rules.numeric_sequence.version.publish',
    'rules.numeric_sequence.version.read',
    'rules.numeric_sequence.version.list',
    'rules.numeric_sequence.run',
    'application.rule.version.save',
    'application.rule.version.publish',
    'application.rule.version.read',
    'application.rule.version.list',
    'application.rule.run',
    'application.rule.run.read',
    'application.rule.run.cancel',
    'application.rule.run.reconcile',
    'calculated.member.version.save',
    'calculated.member.version.publish',
    'calculated.member.version.read',
    'calculated.member.version.list',
    'calculated.member.evaluate',
    'calculated.member.materialize',
    'facts.numeric.scale',
    'facts.planning.allocate.weighted',
    'facts.planning.group.sum',
    'facts.planning.group.sum.bulk',
    'facts.planning.rollup.sum',
    'facts.planning.scenario.copy.prepare',
    'facts.planning.spread.calendar.equal',
    'facts.planning.spread.equal',
    'facts.source.append',
    'facts.source.begin',
    'facts.source.csv.append',
    'facts.source.preview',
    'facts.source.publish',
    'facts.source.seal',
    'facts.text.batch',
    'financial.account.type.set',
    'financial.entity.currency.set',
    'financial.member.policy.read',
    'metadata.calendar.period.read',
    'metadata.calendar.period.set',
    'metadata.dimension.create',
    'metadata.dimension.delete',
    'metadata.dimension.describe',
    'metadata.dimension.list',
    'metadata.dimension.rename',
    'metadata.dimension.resolve',
    'metadata.dimension.status.set',
    'metadata.hierarchy.build',
    'metadata.hierarchy.relationships.preview',
    'metadata.hierarchy.relationships.apply',
    'metadata.layout.populated.preview',
    'metadata.layout.populated.replace.request',
    'metadata.layout.populated.replace.read',
    'metadata.layout.populated.replace.cancel',
    'metadata.layout.populated.activate.request',
    'metadata.layout.populated.activate.read',
    'metadata.layout.populated.activate.cancel',
    'metadata.member.attribute.set',
    'metadata.member.attributes.read',
    'metadata.member_list.version.save',
    'metadata.member_list.version.read',
    'metadata.member_list.version.list',
    'metadata.member_list.publish',
    'metadata.member_list.deactivate',
    'metadata.member_list.evaluate',
    'cube.selection.preview',
    'cube.selection.seal',
    'cube.selection.read',
    'cube.aggregate.request',
    'cube.aggregate.read',
    'cube.aggregate.lineage.read',
    'cube.aggregate.cancel',
    'metadata.member.create',
    'metadata.member.describe',
    'metadata.member.list',
    'metadata.member.aggregation-operator.set',
    'metadata.member.numeric-kind.set',
    'metadata.member.rename',
    'metadata.member.resolve',
    'metadata.member.security-tags.set',
    'metadata.member.security-string.set',
    'metadata.dimension.security-string.set',
    'metadata.relationship.security-string.set',
    'metadata.security-tag.create',
    'metadata.security-tag.update',
    'metadata.security-tag.status.set',
    'metadata.security-tag.list',
    'metadata.member.status.set',
    'metadata.attribute-definition.create',
    'metadata.attribute-definition.update',
    'metadata.attribute-definition.status.set',
    'metadata.attribute-definition.list',
    'metadata.attribute-definition.usage.read',
    'metadata.attribute-value.set',
    'metadata.attribute-value.read',
    'metadata.relationship.attribute.set',
    'metadata.relationship.attributes.read',
    'metadata.relationship.create',
    'metadata.relationship.describe',
    'metadata.relationship.list',
    'metadata.relationship.rename',
    'metadata.relationship.aggregation-operator.set',
    'metadata.relationship.semantic_column.create',
    'metadata.relationship.semantic_column.list',
    'metadata.relationship.semantic_column.update',
    'metadata.relationship.status.set',
    'metadata.semantic_column.create',
    'metadata.semantic_column.list',
    'metadata.semantic_column.update',
    'planning.slice.approve',
    'planning.slice.lock',
    'planning.slice.read',
    'planning.slice.reopen',
    'planning.slice.submit',
    'planning.slice.submit.assigned',
    'planning.slice.review',
    'planning.slice.assigned.reopen',
    'planning.slice.assigned.read',
    'planning.slice.worklist',
    'cube.write.policy.deactivate',
    'cube.write.policy.list',
    'cube.write.policy.publish',
    'cube.write.policy.read',
    'cube.write.policy.save',
    'cube.write.scope.approve',
    'cube.write.scope.assigned.read',
    'cube.write.scope.assigned.reopen',
    'cube.write.scope.lock',
    'cube.write.scope.read',
    'cube.write.scope.reopen',
    'cube.write.scope.review',
    'cube.write.scope.submit',
    'cube.write.scope.submit.assigned',
    'cube.write.scope.worklist',
    'planning.operation.policy.deactivate',
    'planning.operation.policy.driver.preview',
    'planning.operation.policy.driver.run',
    'planning.operation.policy.seed.preview',
    'planning.operation.policy.seed.run',
    'planning.operation.policy.seed.lineage.read',
    'planning.operation.policy.rollup.preview',
    'planning.operation.policy.rollup.run',
    'planning.operation.policy.spread.preview',
    'planning.operation.policy.spread.run',
    'planning.operation.policy.allocation.preview',
    'planning.operation.policy.allocation.run',
    'planning.operation.policy.list',
    'planning.operation.policy.publish',
    'planning.operation.policy.read',
    'planning.operation.policy.save',
    'planning.workflow.policy.deactivate',
    'planning.workflow.policy.list',
    'planning.workflow.policy.publish',
    'planning.workflow.policy.read',
    'planning.workflow.policy.save',
    'planning.version.adjusted.compare',
    'planning.version.adjusted.scan',
    'planning.version.calculation.compare',
    'planning.version.calculation.scan',
    'planning.version.unit-calculation.compare',
    'planning.version.unit-calculation.scan',
    'planning.version.cross-layer.compare',
    'planning.version.cross-layer.scan',
    'planning.version.compare',
    'planning.version.scan',
    'python.program.save',
    'python.program.read',
    'python.program.list',
    'python.program.publish',
    'python.program.deactivate',
    'python.program.build',
    'python.program.run',
    'python.environment.register',
    'python.environment.read',
    'python.environment.list',
    'python.environment.profile.list',
    'python.schedule.save','python.schedule.read','python.schedule.list',
    'python.schedule.publish','python.schedule.deactivate','python.schedule.run',
    'python.schedule.occurrence.read','python.schedule.occurrence.cancel',
    'rules.expression.run',
    'rules.expression.sequence.cancel',
    'rules.expression.sequence.read',
    'rules.expression.sequence.run',
    'rules.expression.version.list',
    'rules.expression.version.publish',
    'rules.expression.version.read',
    'rules.expression.version.save',
))
CONSOLIDATION_FUNCTIONS = frozenset((
    'consolidation.cash_flow.publication.inspect',
    'consolidation.cash_flow.publication.request',
    'consolidation.cash_flow.publication.read',
    'consolidation.cash_flow.reconciliation.inspect',
    'consolidation.disposal.measure.inspect',
    'consolidation.disposal.retain_control.inspect',
    'consolidation.equity.rollforward.inspect',
    'consolidation.equity.rollforward.chain.inspect',
    'consolidation.equity.rollforward.chain.request',
    'consolidation.equity.rollforward.chain.read',
    'consolidation.fixed_asset.unrealized_profit.inspect',
    'consolidation.inventory.unrealized_profit.inspect',
    'consolidation.inventory.unrealized_profit.request',
    'consolidation.inventory.unrealized_profit.read',
    'consolidation.inventory.unrealized.schedule.save',
    'consolidation.inventory.unrealized.schedule.read',
    'consolidation.inventory.unrealized.schedule.list',
    'consolidation.inventory.unrealized.schedule.publish',
    'consolidation.inventory.unrealized.schedule.deactivate',
    'consolidation.period.close.request',
    'consolidation.period.close.read',
    'consolidation.period.close.reopen',
    'consolidation.statement.reconciliation.preview',
    'consolidation.statement.pack.preview',
    'consolidation.statement.pack.bound.preview',
    'consolidation.statement.definition.save',
    'consolidation.statement.definition.read',
    'consolidation.statement.definition.list',
    'consolidation.statement.definition.publish',
    'consolidation.statement.definition.deactivate',
    'consolidation.cta.bridge.preview',
    'consolidation.cta.bridge.post',
    'consolidation.cta.bridge.read',
    'consolidation.cta.bridge.close-handoff.read',
    'consolidation.layout.configure',
    'consolidation.layout.read',
    'consolidation.nci.period.publish',
    'consolidation.nci.period.withdraw',
    'consolidation.nci.period.result.read',
    'consolidation.nci.period.basis.define',
    'consolidation.nci.period.basis.revoke',
    'consolidation.nci.period.basis.read',
    'consolidation.nci.period.source.inspect',
    'consolidation.policy.draft.period_nci.cases.review.record',
    'consolidation.policy.draft.period_nci.cases.review.read',
    'consolidation.policy.period_nci.approval.record',
    'consolidation.policy.period_nci.approval.read',
    'consolidation.policy.period_nci.activate',
    'consolidation.policy.period_nci.withdraw',
    'consolidation.policy.period_nci.activation.read',
    'consolidation.policy.period_nci.activation.current.read',
    'consolidation.policy.period_nci.activation.resolve',

    'consolidation.policy.draft.period_nci.cases.evaluate',
    'consolidation.policy.draft.period_nci.cases.record',
    'consolidation.policy.draft.period_nci.cases.read',
    'consolidation.acquisition.journal.balance.read',
    'consolidation.acquisition.journal.publish',
    'consolidation.acquisition.journal.read',
    'consolidation.acquisition.journal.reverse',
    'consolidation.acquisition.nci.measure.inspect',
    'consolidation.acquisition.step.measure.inspect',
    'consolidation.full.aggregate',
    'consolidation.full.contribute',
    'consolidation.full.typed.contribute',
    'consolidation.full.contribute.certified',
    'consolidation.full.sequence.cancel',
    'consolidation.full.sequence.read',
    'consolidation.full.sequence.run',
    'consolidation.full.translated.aggregate',
    'consolidation.full.tree.plan',
    'consolidation.ic.adjusted.balance.read',
    'consolidation.ic.elimination.preview',
    'consolidation.ic.elimination.publish',
    'consolidation.ic.elimination.read',
    'consolidation.ic.elimination.withdraw',
    'consolidation.ic.pair.inspect',
    'consolidation.ic.residual.resolve.inspect',
    'consolidation.nci.attribution.inspect',
    'consolidation.nci.company.source.inspect',
    'consolidation.nci.period.measure.inspect',
    'consolidation.ownership.scope.read',
    'consolidation.ownership.method.preview',
    'consolidation.method.coverage.inspect',
    'consolidation.proportional.contribution.preview',
    'consolidation.proportional.contribution.publish.certified',
    'consolidation.method.total.publish',
    'consolidation.equity.contribution.preview',
    'consolidation.equity.contribution.publish.certified',
    'consolidation.ownership.value.read',
    'consolidation.ownership.value.set',
    'consolidation.policy.acquisition.activate',
    'consolidation.policy.acquisition.activation.current.read',
    'consolidation.policy.acquisition.activation.read',
    'consolidation.policy.acquisition.activation.resolve',
    'consolidation.policy.acquisition.approval.read',
    'consolidation.policy.acquisition.approval.record',
    'consolidation.policy.acquisition.withdraw',
    'consolidation.policy.draft.acquisition.cases.evaluate',
    'consolidation.policy.draft.acquisition.cases.evidence.inspect',
    'consolidation.policy.draft.acquisition.cases.read',
    'consolidation.policy.draft.acquisition.cases.record',
    'consolidation.policy.draft.acquisition.cases.review.read',
    'consolidation.policy.draft.acquisition.cases.review.record',
    'consolidation.policy.draft.create',
    'consolidation.policy.draft.effective.read',
    'consolidation.policy.draft.elections.validate',
    'consolidation.policy.source.artifact.capture',
    'consolidation.policy.source.artifact.content.read',
    'consolidation.policy.source.artifact.client_pdf.page.read',
    'consolidation.policy.source.artifact.read',
    'consolidation.scope.assess',
    'currency.calculation.translation.publish',
))



# Disable blocks new work while retaining historical reads, exact corrections,
# withdrawal and cancellation under their ordinary permission checks.
DISABLED_SAFE_FUNCTIONS = frozenset((
    'consolidation.nci.period.withdraw',
    'consolidation.nci.period.result.read',
    'consolidation.nci.period.basis.revoke',
    'consolidation.nci.period.basis.read',
    'consolidation.policy.draft.period_nci.cases.review.read',
    'consolidation.policy.period_nci.approval.read',
    'consolidation.policy.period_nci.withdraw',
    'consolidation.policy.period_nci.activation.read',
    'consolidation.policy.period_nci.activation.current.read',

    'consolidation.policy.draft.period_nci.cases.read',
    'consolidation.acquisition.journal.read',
    'consolidation.acquisition.journal.balance.read',
    'consolidation.acquisition.journal.reverse',
    'consolidation.full.sequence.read',
    'consolidation.full.sequence.cancel',
    'consolidation.ic.elimination.read',
    'consolidation.ic.elimination.withdraw',
    'consolidation.policy.draft.effective.read',
    'consolidation.policy.draft.acquisition.cases.read',
    'consolidation.policy.draft.acquisition.cases.review.read',
    'consolidation.policy.draft.acquisition.cases.evidence.inspect',
    'consolidation.policy.source.artifact.read',
    'consolidation.policy.source.artifact.content.read',
    'consolidation.policy.source.artifact.client_pdf.page.read',
    'consolidation.policy.acquisition.approval.read',
    'consolidation.policy.acquisition.activation.read',
    'consolidation.policy.acquisition.activation.current.read',
    'consolidation.policy.acquisition.withdraw',
))


def validate_enabled_capabilities(enabled):
    if (not isinstance(enabled, (list, tuple, set, frozenset))
            or any(not isinstance(item, str) for item in enabled)):
        raise ValueError('APPLICATION_CAPABILITIES_INVALID')
    result = frozenset(enabled)
    if len(result) != len(enabled) or not result <= KNOWN_CAPABILITIES:
        raise ValueError('APPLICATION_CAPABILITIES_INVALID')
    return result


def required_capabilities(function, arguments=None):
    """Classify a known operation; compiler validation remains mandatory.

    Own-currency translation is general financial planning. Explicitly adding
    acquisition/IC source layers introduces the consolidation dependency.
    Historical result reads remain available independently of enablement.
    """
    if not isinstance(function, str):
        raise ValueError('APPLICATION_FUNCTION_UNCLASSIFIED')
    if arguments is not None and not isinstance(arguments, dict):
        raise ValueError('APPLICATION_CAPABILITY_ARGUMENTS_INVALID')
    if function in ('consolidation.cta.bridge.preview','consolidation.cta.bridge.post'):
        return frozenset((FINANCIAL_CONSOLIDATION,))
    if function in CONSOLIDATION_FUNCTIONS:
        return frozenset((FINANCIAL_CONSOLIDATION,))
    if (function not in CORE_FUNCTIONS
            and function not in PREPUBLIC_CORE_FUNCTIONS
            and function not in CONTROL_PLANE_FUNCTIONS):
        raise ValueError('APPLICATION_FUNCTION_UNCLASSIFIED')
    if (function == 'currency.translation.publish' and arguments is not None
            and isinstance(arguments.get('sourceLayer'), str)
            and arguments['sourceLayer'] in ACQUISITION_LAYERS):
        return frozenset((FINANCIAL_CONSOLIDATION,))
    return frozenset()


def describe_catalog(catalog):
    """Require explicit coverage, add serializable capability metadata."""
    functions = catalog['functions']
    if set(functions) != CORE_FUNCTIONS | CONSOLIDATION_FUNCTIONS:
        raise ValueError('APPLICATION_CATALOG_CAPABILITY_COVERAGE_MISMATCH')
    result = deepcopy(catalog)
    for name, spec in result['functions'].items():
        spec['requiredCapabilities'] = sorted(required_capabilities(name))
        if is_retired_public_function(name):
            spec['retiredFromPublicDiscovery'] = True
        if name in DISABLED_SAFE_FUNCTIONS:
            spec['availableWhenDisabled'] = 'history_correction_or_cancellation'
    result['functions']['currency.translation.publish']['capabilityArgumentRules'] = [{
        'argument': 'sourceLayer', 'values': sorted(ACQUISITION_LAYERS),
        'requiredCapabilities': [FINANCIAL_CONSOLIDATION]}]
    return result


def filter_catalog(catalog, enabled):
    """Filter static requirements; conditional restrictions stay discoverable.

    This helper accepts already resolved application configuration. It neither
    reads the database nor grants execution authority. Conditional variants
    remain advertised with their requirements for deterministic client planning.
    """
    enabled = validate_enabled_capabilities(enabled)
    result = describe_catalog(catalog)
    result['functions'] = {name: spec for name, spec in result['functions'].items()
        if not is_retired_public_function(name) and
        (required_capabilities(name) <= enabled or name in DISABLED_SAFE_FUNCTIONS)}
    return result


def function_registry_digest(functions):
    """Identify the exact filtered transport contract, not execution authority."""
    if not isinstance(functions, dict) or any(
            not isinstance(name, str) or not isinstance(specification, dict)
            for name, specification in functions.items()):
        raise ValueError('APPLICATION_FUNCTION_REGISTRY_INVALID')
    envelope = {'format': FUNCTION_REGISTRY_FORMAT, 'languageVersion': 2,
                'functions': functions}
    try:
        canonical = json.dumps(envelope, sort_keys=True, separators=(',', ':'),
                               ensure_ascii=True, allow_nan=False).encode('ascii')
    except (TypeError, ValueError) as error:
        raise ValueError('APPLICATION_FUNCTION_REGISTRY_INVALID') from error
    return sha256(canonical).hexdigest()


def producer_capability_status(function,arguments,enabled,revision):
    """Availability of the recorded producer, separate from historical reads."""
    public_function={
        'consolidation.method.contribute':'consolidation.full.contribute',
        'consolidation.equity.contribution.publish':
            'consolidation.equity.contribution.publish.certified',
        'consolidation.proportional.contribution.publish':
            'consolidation.proportional.contribution.publish.certified',
    }.get(function,function)
    required=required_capabilities(public_function,arguments)
    enabled=validate_enabled_capabilities(enabled)
    return {'requiredCapabilities':sorted(required),'enabledCapabilities':sorted(enabled),
        'capabilityRevision':revision,'enabled':required <= enabled}
