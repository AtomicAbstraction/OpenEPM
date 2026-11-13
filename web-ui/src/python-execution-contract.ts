import type { ApplicationSummary, ApplicationCatalog } from "./types";

export function pythonBuildRequestBody(
  app: ApplicationSummary,
  catalog: ApplicationCatalog,
  program: { programId: string; sourceToken: string },
  parameters: Record<string, unknown>,
  delegationId: string,
  delegationStateToken: string,
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    action: "request",
    idempotencyKey,
    confirmed: true,
    program: {
      languageVersion: 2,
      function: "python.program.build",
      arguments: {
        programId: program.programId,
        programSourceToken: program.sourceToken,
        parameters,
        expectedMetadataRevision: catalog.revisions.metadata,
        expectedPolicyRevision: catalog.revisions.policy,
        expectedSchemaEpoch: catalog.revisions.schemaEpoch,
        delegationId,
        delegationStateToken,
        scheduleId: null,
        scheduleStateToken: null,
      },
    },
  };
}

export function pythonRunRequestBody(
  app: ApplicationSummary,
  buildId: string,
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    action: "request",
    idempotencyKey,
    confirmed: true,
    program: {
      languageVersion: 2,
      function: "python.program.run",
      arguments: { buildId },
    },
  };
}
