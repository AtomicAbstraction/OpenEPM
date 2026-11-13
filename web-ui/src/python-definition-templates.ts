import type { PythonDefinitionKind } from "./PythonDefinitionEditor";

// These use the public typed SDK constructors qualified by
// tests/test_python_definition_sources_postgres.py. Replace metadata placeholders
// before saving; templates never choose business members on the user's behalf.
export const pythonDefinitionTemplates: Record<PythonDefinitionKind, string> = {
  ApplicationRule: `from openepm import ApplicationRule, Ratio

def build(context, parameters):
    # Replace the names and example calculation with your rule.
    app = context.app
    chosen = app.cube.select(app.dimension("dimension-name").member("member-name"))
    # Increase the definition version when changing an activated rule.
    return ApplicationRule("rule-id", 1, chosen.set(chosen.value * Ratio("2")))
`,
  MemberList: `from openepm import MemberListDefinition, MemberListExpression

def build(context, parameters):
    # Use authorized dimension and member IDs from this application.
    return MemberListDefinition(
        "list-id", "dimension-id", "Member list",
        MemberListExpression.explicit("member-id"),
    )
`,
  CalculatedMember: `from openepm import CalculatedMember, CubeExpression, CubeSelection, DimensionSelection, Ratio

def build(context, parameters):
    # Replace the IDs and example expression with your calculation.
    chosen = CubeSelection(context.metadata_revision, (
        DimensionSelection.member("dimension-id", "source-member-id"),
    ))
    # Increase the definition version when changing an activated calculation.
    return CalculatedMember(
        "calculation-id", 1, "Calculation", "dimension-id", "target-member-id",
        "dynamic", chosen, CubeExpression.source_amount() * Ratio("2"), "amount",
    )
`,
};
