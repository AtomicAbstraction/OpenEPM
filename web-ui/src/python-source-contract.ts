import { ApiError } from "./api";
import type { ApplicationCatalog, ApplicationSummary } from "./types";

export const STALE_PYTHON_SOURCE_DRAFT =
  "The saved source changed. This draft is still available to copy.";

export function pythonSourceSaveError(reason: unknown) {
  if (reason instanceof ApiError) {
    if (reason.code === "PYTHON_PROGRAM_STATE_CONFLICT")
      return STALE_PYTHON_SOURCE_DRAFT;
    if (reason.code === "PYTHON_ENVIRONMENT_NOT_ACTIVE")
      return "The build environment binding is no longer active. An application administrator can review it. Your draft is preserved.";
  }
  return reason instanceof Error
    ? reason.message
    : "Unable to save Python source.";
}

type EnvironmentBinding = {
  environmentId: string;
  environmentStateToken: string;
};
type ListedEnvironment = {
  environment_id: string;
  state_token: string;
  status: string;
};

export function pythonEnvironmentSelection(environment: ListedEnvironment) {
  return JSON.stringify([environment.environment_id, environment.state_token]);
}

export function pythonSaveEnvironment(
  selection: string,
  inventory: readonly ListedEnvironment[] | null,
  binding: EnvironmentBinding | null,
): EnvironmentBinding | undefined {
  // A designer can retain the exact environment already bound to a source.
  // Only a reviewed inventory choice can select a different environment.
  if (inventory === null)
    return binding &&
      selection ===
        JSON.stringify([binding.environmentId, binding.environmentStateToken])
      ? {
          environmentId: binding.environmentId,
          environmentStateToken: binding.environmentStateToken,
        }
      : undefined;
  const selected = inventory.find(
    (item) =>
      item.status === "Active" &&
      pythonEnvironmentSelection(item) === selection,
  );
  return selected
    ? {
        environmentId: selected.environment_id,
        environmentStateToken: selected.state_token,
      }
    : undefined;
}

export function pythonProgramActionBody(
  app: ApplicationSummary,
  catalog: ApplicationCatalog,
  program: { programId: string; stateToken: string },
  action: "activate" | "deactivate" | "delete",
  idempotencyKey: string,
  validationBuildId?: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    confirmed: true,
    idempotencyKey,
    program: {
      languageVersion: 2,
      function: `python.program.${action}`,
      arguments: {
        programId: program.programId,
        expectedStateToken: program.stateToken,
        expectedMetadataRevision: catalog.revisions.metadata,
        expectedPolicyRevision: catalog.revisions.policy,
        expectedSchemaEpoch: catalog.revisions.schemaEpoch,
        ...(action === "activate" && validationBuildId
          ? { validationBuildId }
          : {}),
      },
    },
  };
}

export function newAssignedRuleOutput(programId: string) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(programId))
    throw new Error(
      "Use 1–100 letters, digits, dots, underscores or hyphens for the rule ID.",
    );
  return { kind: "ApplicationRule", definitionId: programId };
}

export function pythonProgramSaveBody(
  app: ApplicationSummary,
  catalog: ApplicationCatalog,
  draft: {
    programId: string;
    entryPoint: string;
    environmentId: string;
    environmentStateToken: string;
    parameterSchema: Record<string, unknown>;
    sourceText: string;
    declaredOutput?: Record<string, unknown> | null;
    expectedStateToken?: string;
  },
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    confirmed: true,
    idempotencyKey,
    program: {
      languageVersion: 2,
      function: "python.program.save",
      arguments: {
        definition: {
          format: "openepm-current-python-source-v1",
          programId: draft.programId,
          entryPoint: draft.entryPoint,
          environmentId: draft.environmentId,
          environmentStateToken: draft.environmentStateToken,
          parameterSchema: draft.parameterSchema,
          sourceText: draft.sourceText,
          ...(draft.declaredOutput
            ? { declaredOutput: draft.declaredOutput }
            : {}),
        },
        ...(draft.expectedStateToken
          ? { expectedStateToken: draft.expectedStateToken }
          : {}),
        expectedMetadataRevision: catalog.revisions.metadata,
        expectedPolicyRevision: catalog.revisions.policy,
        expectedSchemaEpoch: catalog.revisions.schemaEpoch,
      },
    },
  };
}
