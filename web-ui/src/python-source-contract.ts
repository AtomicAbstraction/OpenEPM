import type { ApplicationCatalog, ApplicationSummary } from "./types";

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
