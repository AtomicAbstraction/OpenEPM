import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  capabilityTaskListBody,
  ApplicationLifecycleSummary,
  CapabilityArea,
  dimensionListArguments,
  collectCapabilityDimensions,
  collectCapabilityMembers,
  collectPythonPrograms,
  collectPythonEnvironments,
  matchingFunctions,
  matchingJourney,
  memberSecurityMutationBody,
  memberSecurityStringMutationBody,
  memberListArguments,
  exactMemberTags,
  pythonProgramListArguments,
  pythonProgramReadArguments,
  pythonProgramActionBody,
  pythonEnvironmentListArguments,
  pythonProgramSaveBody,
  executionDelegationReadBody,
  executionDelegationListBody,
  executionDelegationMutationBody,
  pythonBuildRequestBody,
  pythonRunRequestBody,
  pythonBuildControlBody,
  pythonArtifactReadBody,
  pythonRunControlBody,
  pythonScheduleReadBody,
  pythonScheduleListBody,
  pythonScheduleMutationBody,
  pythonOccurrenceBody,
} from "./CapabilityArea";

afterEach(() => vi.unstubAllGlobals());

it("presents authoritative application lifecycle state without inventing an action", () => {
  render(
    <ApplicationLifecycleSummary
      app={{
        workspaceId: "ws-pilot",
        applicationId: "pilot-fpna",
        name: "FP&A Pilot",
        status: "Active",
        kind: "blank",
      }}
      catalog={{
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: true,
        },
        enabledCapabilities: [],
        functions: { "workspace.application.create": {} },
        revisions: {
          metadata: 46,
          data: 136,
          policy: 37,
          security: 13,
          commit: 212,
        },
      }}
      index={2}
    />,
  );
  expect(
    screen.getByRole("heading", { name: "Application lifecycle" }),
  ).toBeInTheDocument();
  expect(screen.getByText("FP&A Pilot")).toBeInTheDocument();
  expect(screen.getByText("ws-pilot / pilot-fpna")).toBeInTheDocument();
  expect(screen.getByText("Active")).toBeInTheDocument();
  expect(screen.getByText("Administrator")).toBeInTheDocument();
  expect(screen.getByText("M46 · D136")).toBeInTheDocument();
  expect(
    screen.getByRole("link", { name: "Open Applications →" }),
  ).toHaveAttribute("href", "#/applications/2");
  expect(screen.queryByRole("button")).not.toBeInTheDocument();
});

it("labels lifecycle inspection as a native overview without inventing authorization", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify({ tasks: [] }))),
  );
  render(
    <CapabilityArea
      area="administration"
      app={{
        workspaceId: "ws-pilot",
        applicationId: "pilot-fpna",
        name: "FP&A Pilot",
        status: "Active",
      }}
      catalog={{
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: true,
        },
        enabledCapabilities: [],
        functions: {},
        revisions: {
          metadata: 46,
          data: 136,
          policy: 37,
          security: 13,
          commit: 212,
        },
      }}
      index={0}
    />,
  );
  expect(
    screen.getByText(
      "Native read-only overview. Consequential actions remain in established governed workflows.",
    ),
  ).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Open application lifecycle ↓" }),
  ).toBeInTheDocument();
});

it("expands every authorized function instead of leaving an inert more count", () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify({ tasks: [] }))),
  );
  const functions = Object.fromEntries(
    Array.from({ length: 27 }, (_, index) => [
      `application.lifecycle.operation-${index + 1}`,
      {},
    ]),
  );
  render(
    <CapabilityArea
      area="administration"
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "App",
        status: "Active",
      }}
      catalog={{
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: true,
        },
        enabledCapabilities: [],
        functions,
        revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
      }}
      index={0}
    />,
  );
  const summary = screen.getByText("Show authorized functions");
  const details = summary.closest("details");
  expect(details).not.toHaveAttribute("open");
  fireEvent.click(summary);
  expect(details).toHaveAttribute("open");
  expect(screen.getAllByRole("listitem")).toHaveLength(27);
  expect(screen.queryByText("+ 7 more")).not.toBeInTheDocument();
});

it("preserves the metadata paging contracts", () => {
  expect(dimensionListArguments()).toEqual({ limit: 100 });
  expect(dimensionListArguments("Department", 12)).toEqual({
    limit: 100,
    afterDimensionId: "Department",
    expectedMetadataRevision: 12,
  });
  expect(memberListArguments("Account")).toEqual({
    dimension: "Account",
    limit: 100,
  });
  expect(memberListArguments("Account", "Revenue", 12)).toEqual({
    dimension: "Account",
    limit: 100,
    afterMemberId: "Revenue",
    expectedMetadataRevision: 12,
  });
});

it("reads complete Capability metadata catalogues beyond former caps", async () => {
  let dimensionPage = 0;
  const dimensions = await collectCapabilityDimensions(async (arguments_) => {
    const current = dimensionPage++;
    if (current > 0) expect(arguments_.expectedMetadataRevision).toBe(12);
    return {
      rows: Array.from({ length: 100 }, (_unused, row) => ({
        dimension_id: `d-${current}-${row}`,
        name: "Dimension",
        model_role: "Custom",
        status: "Active",
      })),
      nextAfterDimensionId:
        current === 10 ? null : `dimension-cursor-${current + 1}`,
      metadataRevision: 12,
    };
  });
  expect(dimensions.rows).toHaveLength(1100);

  let memberPage = 0;
  const members = await collectCapabilityMembers(
    "Account",
    async (arguments_) => {
      const current = memberPage++;
      if (current > 0) expect(arguments_.expectedMetadataRevision).toBe(12);
      return {
        rows: Array.from({ length: 100 }, (_unused, row) => ({
          member_id: `m-${current}-${row}`,
          name: "Member",
          status: "Active",
        })),
        nextAfterMemberId:
          current === 100 ? null : `member-cursor-${current + 1}`,
        metadataRevision: 12,
      };
    },
  );
  expect(members.rows).toHaveLength(10100);
});

it("reads complete Python program and environment catalogues", async () => {
  let programPage = 0;
  const programs = await collectPythonPrograms(async () => {
    const current = programPage++;
    return {
      result: {
        programs: Array.from({ length: 100 }, (_unused, row) => ({
          programId: `p-${current}-${row}`,
          version: 1,
          status: "Active",
          entryPoint: "build",
          environmentId: "python",
          environmentVersion: 1,
          sourceDigest: "a".repeat(64),
        })),
        nextAfterProgramId:
          current === 10 ? null : `program-cursor-${current + 1}`,
      },
    };
  });
  expect(programs.rows).toHaveLength(1100);

  let environmentPage = 0;
  const environments = await collectPythonEnvironments(async () => {
    const current = environmentPage++;
    return {
      result: {
        environments: Array.from({ length: 50 }, (_unused, row) => ({
          environment_id: `e-${current}-${row}`,
          version: 1,
          status: "Active",
          image_digest: "sha256:" + "b".repeat(64),
        })),
        nextAfterEnvironmentId:
          current === 20 ? null : `environment-cursor-${current + 1}`,
      },
    };
  });
  expect(environments.rows).toHaveLength(1050);
});

it("rejects malformed, repeated, and revision-drifting Capability continuations", async () => {
  await expect(
    collectPythonPrograms(async () => ({
      result: {
        programs: [],
        nextAfterProgramId: "" as never,
      },
    })),
  ).rejects.toThrow("cursor is invalid");
  let programPage = 0;
  await expect(
    collectPythonPrograms(async () => ({
      result: {
        programs: [],
        nextAfterProgramId: programPage++ < 1 ? "same" : "same",
      },
    })),
  ).rejects.toThrow("cursor repeated");
  let metadataPage = 0;
  await expect(
    collectCapabilityDimensions(async () => ({
      rows: [
        {
          dimension_id: `d-${metadataPage}`,
          name: "D",
          model_role: "Custom",
          status: "Active",
        },
      ],
      nextAfterDimensionId: metadataPage++ < 1 ? "more" : null,
      metadataRevision: metadataPage === 1 ? 12 : 13,
    })),
  ).rejects.toThrow("changed while reading");
});

it("validates and preserves exact member-security tag contracts", () => {
  expect(exactMemberTags("North; Planning", "Read")).toEqual([
    "North",
    "Planning",
  ]);
  expect(() => exactMemberTags("North; North", "Read")).toThrow(
    "Read contains a duplicate tag.",
  );
  expect(() => exactMemberTags("A-very-long-security-tag", "Write")).toThrow(
    "Write tags must be 1-20 characters.",
  );
  expect(
    memberSecurityMutationBody(
      {
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      },
      "Entity",
      "North",
      ["North"],
      ["WriteNorth"],
      12,
      "member-security-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "member-security-1",
    program: {
      languageVersion: 2,
      function: "metadata.member.security-tags.set",
      arguments: {
        dimensionId: "Entity",
        memberId: "North",
        readTags: ["North"],
        writeTags: ["WriteNorth"],
        expectedMetadataRevision: 12,
      },
    },
  });
});

it("uses the canonical Security String compiler without changing its contract", () => {
  expect(
    memberSecurityStringMutationBody(
      {
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      },
      "Entity",
      "North",
      "read=NorthRead;write=NorthWrite",
      12,
      "member-security-string-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "member-security-string-1",
    program: {
      languageVersion: 2,
      function: "metadata.member.security-string.set",
      arguments: {
        dimensionId: "Entity",
        memberId: "North",
        securityString: "read=NorthRead;write=NorthWrite",
        expectedMetadataRevision: 12,
      },
    },
  });
});

it("preserves the Python program read contracts", () => {
  expect(pythonProgramListArguments()).toEqual({ limit: 100 });
  expect(pythonProgramListArguments("forecast-builder")).toEqual({
    limit: 100,
    afterProgramId: "forecast-builder",
  });
  expect(pythonProgramReadArguments("forecast-builder", 2)).toEqual({
    programId: "forecast-builder",
    version: 2,
  });
});

it("preserves reviewed Python publication pins and endpoint contract", () => {
  expect(
    pythonProgramActionBody(
      {
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      },
      {
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: false,
        },
        enabledCapabilities: [],
        functions: { "python.program.publish": {} },
        revisions: {
          metadata: 12,
          data: 2,
          policy: 7,
          security: 3,
          commit: 10,
          schemaEpoch: 4,
        },
      },
      { programId: "forecast-builder", version: 2 },
      "publish",
      "python-publish-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "python-publish-1",
    program: {
      languageVersion: 2,
      function: "python.program.publish",
      arguments: {
        programId: "forecast-builder",
        version: 2,
        expectedMetadataRevision: 12,
        expectedPolicyRevision: 7,
        expectedSchemaEpoch: 4,
      },
    },
  });
});

it("preserves approved-environment paging and immutable Python save contracts", () => {
  expect(pythonEnvironmentListArguments()).toEqual({ limit: 50 });
  expect(pythonEnvironmentListArguments("approved-python")).toEqual({
    limit: 50,
    afterEnvironmentId: "approved-python",
  });
  expect(
    pythonProgramSaveBody(
      {
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      },
      {
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: false,
        },
        enabledCapabilities: [],
        functions: { "python.program.save": {} },
        revisions: {
          metadata: 12,
          data: 2,
          policy: 7,
          security: 3,
          commit: 10,
          schemaEpoch: 4,
        },
      },
      {
        programId: "forecast-builder",
        version: 3,
        entryPoint: "build",
        environmentId: "approved-python",
        environmentVersion: 1,
        parameterSchema: { type: "object" },
        sourceText: "def build(context, parameters):\n    return Program()",
      },
      "python-save-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "python-save-1",
    program: {
      languageVersion: 2,
      function: "python.program.save",
      arguments: {
        programId: "forecast-builder",
        version: 3,
        entryPoint: "build",
        environmentId: "approved-python",
        environmentVersion: 1,
        parameterSchema: { type: "object" },
        sourceText: "def build(context, parameters):\n    return Program()",
        expectedMetadataRevision: 12,
        expectedPolicyRevision: 7,
        expectedSchemaEpoch: 4,
      },
    },
  });
});

it("preserves exact execution-authority, build and run endpoint contracts", () => {
  const app = {
    workspaceId: "ws",
    applicationId: "app",
    name: "Plan",
    status: "Active",
  };
  const catalog = {
    applicationAccess: {
      role: "Administrator",
      workspaceAdministrator: false,
    },
    enabledCapabilities: [],
    functions: { "python.program.build": {}, "python.program.run": {} },
    revisions: {
      metadata: 12,
      data: 2,
      policy: 7,
      security: 3,
      commit: 10,
      schemaEpoch: 4,
    },
  };
  expect(executionDelegationReadBody(app, "owner-builder")).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    program: {
      languageVersion: 2,
      function: "execution.delegation.read",
      arguments: { delegationId: "owner-builder" },
    },
  });
  expect(executionDelegationListBody(app)).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    program: {
      languageVersion: 2,
      function: "execution.delegation.list",
      arguments: { limit: 50, afterDelegationId: null },
    },
  });
  expect(executionDelegationListBody(app, "owner-builder")).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    program: {
      languageVersion: 2,
      function: "execution.delegation.list",
      arguments: { limit: 50, afterDelegationId: "owner-builder" },
    },
  });
  expect(
    executionDelegationMutationBody(
      app,
      catalog,
      "create",
      {
        delegationId: "owner-builder",
        version: 3,
        issuer: "owner",
        subjectId: "builder",
        operationScope: ["python.program.build", "python.program.run"],
        validFrom: "2026-11-02T00:00:00.000Z",
        validUntil: "2027-11-02T00:00:00.000Z",
      },
      "delegation-create-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "delegation-create-1",
    program: {
      languageVersion: 2,
      function: "execution.delegation.create",
      arguments: {
        delegationId: "owner-builder",
        version: 3,
        issuer: "owner",
        subjectId: "builder",
        operationScope: ["python.program.build", "python.program.run"],
        validFrom: "2026-11-02T00:00:00.000Z",
        validUntil: "2027-11-02T00:00:00.000Z",
        scheduleId: null,
        scheduleVersion: null,
        expectedMetadataRevision: 12,
        expectedPolicyRevision: 7,
        expectedSchemaEpoch: 4,
      },
    },
  });
  expect(
    executionDelegationMutationBody(
      app,
      catalog,
      "revoke",
      { delegationId: "owner-builder", version: 3 },
      "delegation-revoke-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "delegation-revoke-1",
    program: {
      languageVersion: 2,
      function: "execution.delegation.revoke",
      arguments: {
        delegationId: "owner-builder",
        version: 3,
        expectedMetadataRevision: 12,
        expectedPolicyRevision: 7,
        expectedSchemaEpoch: 4,
      },
    },
  });
  expect(
    pythonBuildRequestBody(
      app,
      catalog,
      { programId: "forecast-builder", version: 3 },
      { scenario: "Forecast" },
      "owner-builder",
      2,
      "build-request-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    action: "request",
    idempotencyKey: "build-request-1",
    confirmed: true,
    program: {
      languageVersion: 2,
      function: "python.program.build",
      arguments: {
        programId: "forecast-builder",
        programVersion: 3,
        parameters: { scenario: "Forecast" },
        expectedMetadataRevision: 12,
        expectedPolicyRevision: 7,
        expectedSchemaEpoch: 4,
        delegationId: "owner-builder",
        delegationVersion: 2,
        scheduleId: null,
        scheduleVersion: null,
      },
    },
  });
  expect(pythonRunRequestBody(app, "build-1", "run-request-1")).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    action: "request",
    idempotencyKey: "run-request-1",
    confirmed: true,
    program: {
      languageVersion: 2,
      function: "python.program.run",
      arguments: { buildId: "build-1" },
    },
  });
  expect(pythonBuildControlBody(app, "read", "build-1")).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    action: "read",
    buildId: "build-1",
  });
  expect(pythonBuildControlBody(app, "cancel", "build-1")).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    action: "cancel",
    buildId: "build-1",
    confirmed: true,
  });
  expect(
    pythonArtifactReadBody(app, "build-1", "Plan", "signed-cursor"),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    action: "artifact",
    buildId: "build-1",
    section: "Plan",
    cursor: "signed-cursor",
  });
  expect(pythonRunControlBody(app, "cancel", "workflow-1")).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    action: "cancel",
    workflowId: "workflow-1",
    confirmed: true,
  });
});

it("preserves Python schedule and occurrence endpoint contracts", () => {
  const app = {
    workspaceId: "ws",
    applicationId: "app",
    name: "Plan",
    status: "Active",
  };
  const catalog = {
    applicationAccess: {
      role: "Administrator",
      workspaceAdministrator: false,
    },
    enabledCapabilities: [],
    functions: { "python.schedule.save": {} },
    revisions: {
      metadata: 12,
      data: 2,
      policy: 7,
      security: 3,
      commit: 10,
      schemaEpoch: 4,
    },
  };
  expect(pythonScheduleReadBody(app, "nightly-plan")).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    program: {
      languageVersion: 2,
      function: "python.schedule.read",
      arguments: { scheduleId: "nightly-plan" },
    },
  });
  expect(pythonScheduleListBody(app, "nightly-plan")).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    program: {
      languageVersion: 2,
      function: "python.schedule.list",
      arguments: { limit: 50, afterScheduleId: "nightly-plan" },
    },
  });
  expect(
    pythonScheduleMutationBody(
      app,
      catalog,
      "save",
      {
        scheduleId: "nightly-plan",
        version: 1,
        stateRevision: 2,
        programId: "forecast-builder",
        programVersion: 3,
        parameters: { scenario: "Forecast" },
        intervalSeconds: 3600,
        firstDueAt: "2026-11-03T01:00:00.000Z",
        catchUpPolicy: "latest",
        maxCatchUp: 1,
        delegationId: "owner-builder",
        delegationVersion: 2,
      },
      "schedule-save-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "schedule-save-1",
    program: {
      languageVersion: 2,
      function: "python.schedule.save",
      arguments: {
        scheduleId: "nightly-plan",
        expectedVersion: 1,
        expectedStateRevision: 2,
        programId: "forecast-builder",
        programVersion: 3,
        parameters: { scenario: "Forecast" },
        intervalSeconds: 3600,
        firstDueAt: "2026-11-03T01:00:00.000Z",
        catchUpPolicy: "latest",
        maxCatchUp: 1,
        delegationId: "owner-builder",
        delegationVersion: 2,
        expectedMetadataRevision: 12,
        expectedPolicyRevision: 7,
        expectedSchemaEpoch: 4,
      },
    },
  });
  expect(
    pythonScheduleMutationBody(
      app,
      catalog,
      "publish",
      { scheduleId: "nightly-plan", version: 2, stateRevision: 3 },
      "schedule-publish-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "schedule-publish-1",
    program: {
      languageVersion: 2,
      function: "python.schedule.publish",
      arguments: {
        scheduleId: "nightly-plan",
        version: 2,
        expectedStateRevision: 3,
        expectedMetadataRevision: 12,
        expectedPolicyRevision: 7,
        expectedSchemaEpoch: 4,
      },
    },
  });
  expect(
    pythonScheduleMutationBody(
      app,
      catalog,
      "run",
      { scheduleId: "nightly-plan", version: 2, stateRevision: 3 },
      "schedule-run-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "schedule-run-1",
    program: {
      languageVersion: 2,
      function: "python.schedule.run",
      arguments: { scheduleId: "nightly-plan" },
    },
  });
  expect(pythonOccurrenceBody(app, "read", "occurrence-1")).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    program: {
      languageVersion: 2,
      function: "python.schedule.occurrence.read",
      arguments: { occurrenceId: "occurrence-1" },
    },
  });
  expect(
    pythonOccurrenceBody(app, "cancel", "occurrence-1", "cancel-1"),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "cancel-1",
    program: {
      languageVersion: 2,
      function: "python.schedule.occurrence.cancel",
      arguments: { occurrenceId: "occurrence-1" },
    },
  });
});

it("requires approved environment and exact review before saving Python source", async () => {
  const calls: Array<Record<string, unknown>> = [];
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push({ path: String(input), ...body });
      if (body.program.function === "python.environment.list")
        return new Response(
          JSON.stringify({
            result: {
              environments: [
                {
                  environment_id: "approved-python",
                  version: 1,
                  status: "Active",
                  image_digest: "sha256:builder",
                },
              ],
              nextAfterEnvironmentId: null,
            },
          }),
        );
      if (body.program.function === "python.program.save")
        return new Response(
          JSON.stringify({
            result: { status: "Saved", operationId: "python-save-1" },
          }),
        );
      return new Response(
        JSON.stringify({
          result: { programs: [], nextAfterProgramId: null },
        }),
      );
    }),
  );
  render(
    <CapabilityArea
      area="rules"
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      }}
      catalog={{
        applicationAccess: { role: "Editor", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: {
          "python.program.list": {},
          "python.program.read": {},
          "python.program.save": {},
          "python.environment.list": {},
        },
        revisions: {
          metadata: 12,
          data: 1,
          policy: 7,
          security: 1,
          commit: 1,
          schemaEpoch: 4,
        },
      }}
      index={0}
    />,
  );
  const save = screen.getByRole("button", { name: "Save immutable version" });
  expect(save).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Read environments" }));
  await waitFor(() =>
    expect(screen.getByLabelText("Python program environment")).toHaveValue(
      '["approved-python",1]',
    ),
  );
  fireEvent.change(screen.getByLabelText("Python program ID"), {
    target: { value: "forecast-builder" },
  });
  fireEvent.change(screen.getByLabelText("Python program version"), {
    target: { value: "3" },
  });
  fireEvent.change(screen.getByLabelText("Python program source"), {
    target: {
      value: "def build(context, parameters):\n    return Program()",
    },
  });
  const review = screen.getByLabelText(
    "I reviewed this exact source, schema, environment and pinned application context.",
  );
  expect(review).toBeEnabled();
  fireEvent.click(review);
  expect(save).toBeEnabled();
  fireEvent.click(save);
  await waitFor(() =>
    expect(screen.getByText(/python-save-1/)).toBeInTheDocument(),
  );
  expect(calls).toEqual([
    expect.objectContaining({
      path: "/api/python-environment",
      program: expect.objectContaining({
        function: "python.environment.list",
        arguments: { limit: 50 },
      }),
    }),
    expect.objectContaining({
      path: "/api/python-program",
      confirmed: true,
      program: expect.objectContaining({
        function: "python.program.save",
        arguments: expect.objectContaining({
          programId: "forecast-builder",
          version: 3,
          environmentId: "approved-python",
          environmentVersion: 1,
          expectedMetadataRevision: 12,
          expectedPolicyRevision: 7,
          expectedSchemaEpoch: 4,
        }),
      }),
    }),
    expect.objectContaining({
      path: "/api/python-program",
      program: expect.objectContaining({ function: "python.program.list" }),
    }),
  ]);
});

it("reads immutable Python programs through the unchanged endpoint", async () => {
  const calls: Array<Record<string, unknown>> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push(body);
      if (body.program.function === "python.program.list")
        return new Response(
          JSON.stringify({
            result: {
              programs: [
                {
                  programId: "forecast-builder",
                  version: 2,
                  status: "Published",
                  entryPoint: "forecast:build",
                  environmentId: "approved-python",
                  environmentVersion: 1,
                  sourceDigest: "digest-2",
                },
              ],
              nextAfterProgramId: null,
            },
          }),
        );
      return new Response(
        JSON.stringify({
          result: {
            defined: true,
            programId: "forecast-builder",
            version: 2,
            status: "Published",
            entryPoint: "forecast:build",
            environmentId: "approved-python",
            environmentVersion: 1,
            sourceDigest: "digest-2",
            parameterSchema: { type: "object" },
            sourceText: "def build(context, parameters):\n    return Program()",
          },
        }),
      );
    }),
  );
  render(
    <CapabilityArea
      area="rules"
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      }}
      catalog={{
        applicationAccess: { role: "Editor", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: {
          "python.program.list": {},
          "python.program.read": {},
        },
        revisions: {
          metadata: 12,
          data: 1,
          policy: 1,
          security: 1,
          commit: 1,
        },
      }}
      index={0}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Read programs" }));
  await waitFor(() =>
    expect(
      screen.getByText("forecast-builder", { selector: "th" }),
    ).toBeInTheDocument(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Open" }));
  await waitFor(() =>
    expect(screen.getByLabelText("Python program detail")).toHaveTextContent(
      "digest-2",
    ),
  );
  expect(calls).toEqual([
    expect.objectContaining({
      workspaceId: "ws",
      applicationId: "app",
      program: {
        languageVersion: 2,
        function: "python.program.list",
        arguments: { limit: 100 },
      },
    }),
    expect.objectContaining({
      workspaceId: "ws",
      applicationId: "app",
      program: {
        languageVersion: 2,
        function: "python.program.read",
        arguments: { programId: "forecast-builder", version: 2 },
      },
    }),
  ]);
});

it("reads Metadata through unchanged authorized V2 programs", async () => {
  const calls: Array<{
    program: { function: string; arguments: Record<string, unknown> };
  }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push(body);
      if (body.program.function === "metadata.dimension.list")
        return new Response(
          JSON.stringify({
            result: {
              rows: [
                {
                  dimension_id: "Account",
                  name: "Account",
                  model_role: "Account",
                  status: "Active",
                },
              ],
              nextAfterDimensionId: null,
              metadataRevision: 12,
            },
          }),
        );
      return new Response(
        JSON.stringify({
          result: {
            rows: [
              {
                member_id: "Revenue",
                name: "Revenue",
                status: "Active",
              },
            ],
            nextAfterMemberId: null,
            metadataRevision: 12,
          },
        }),
      );
    }),
  );
  render(
    <CapabilityArea
      area="metadata"
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      }}
      catalog={{
        applicationAccess: { role: "Editor", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: {
          "metadata.dimension.list": {},
          "metadata.member.list": {},
        },
        revisions: {
          metadata: 12,
          data: 1,
          policy: 1,
          security: 1,
          commit: 1,
        },
      }}
      index={0}
    />,
  );
  await waitFor(() =>
    expect(screen.getByLabelText("Metadata dimension")).toHaveValue("Account"),
  );
  await waitFor(() =>
    expect(screen.getByText("Revenue", { selector: "th" })).toBeInTheDocument(),
  );
  expect(screen.getByText(/metadata revision 12/)).toBeInTheDocument();
  expect(calls).toEqual([
    expect.objectContaining({
      program: expect.objectContaining({
        function: "metadata.dimension.list",
        arguments: { limit: 100 },
      }),
    }),
    expect.objectContaining({
      program: expect.objectContaining({
        function: "metadata.member.list",
        arguments: { dimension: "Account", limit: 100 },
      }),
    }),
  ]);
});

it("derives journey availability only from authorized catalogue functions", () => {
  expect(
    matchingFunctions(
      {
        "metadata.member.list": {},
        "facts.numeric.batch": {},
        "metadata.dimension.list": {},
      },
      ["metadata."],
    ),
  ).toEqual(["metadata.dimension.list", "metadata.member.list"]);
});

it("groups saved expression rules into Rules and calculations", () => {
  expect(
    matchingFunctions(
      {
        "facts.expression.calculate": {},
        "rules.expression.version.list": {},
        "rules.expression.version.read": {},
      },
      [
        "facts.expression",
        "facts.rule",
        "rules.expression",
        "application.program",
      ],
    ),
  ).toEqual([
    "facts.expression.calculate",
    "rules.expression.version.list",
    "rules.expression.version.read",
  ]);
});

it("renders unavailable journeys without inventing access", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify({ tasks: [] }))),
  );
  render(
    <CapabilityArea
      area="data"
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      }}
      catalog={{
        applicationAccess: { role: "Reader", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: {
          "facts.transfer.export.request": {},
          "facts.line-detail.replace": {},
        },
        revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
      }}
      index={0}
    />,
  );
  expect(screen.getByText("Export snapshot")).toBeInTheDocument();
  expect(
    screen.getAllByText(
      "This journey is not available to the current role or application.",
    ).length,
  ).toBeGreaterThan(0);
  expect(screen.getByText("facts.transfer.export.request")).toBeInTheDocument();
  expect(screen.getByText("facts.line-detail.replace")).toBeInTheDocument();
  const loadHeading = screen.getByRole("heading", {
    name: "Load governed CSV data",
  });
  const scrollIntoView = vi.fn();
  loadHeading.scrollIntoView = scrollIntoView;
  fireEvent.click(screen.getByRole("button", { name: "Open load data ↓" }));
  expect(scrollIntoView).toHaveBeenCalledWith({
    behavior: "smooth",
    block: "start",
  });
  expect(loadHeading).toHaveFocus();
  expect(
    screen.getByRole("button", { name: "Open export snapshot ↓" }),
  ).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Open supporting detail ↓" }),
  ).toBeInTheDocument();
  await waitFor(() =>
    expect(
      screen.getByText("No recent governed data activity is visible."),
    ).toBeInTheDocument(),
  );
  expect(screen.getByRole("link", { name: "Open Monitor →" })).toHaveAttribute(
    "href",
    "#/monitor/0",
  );
});

it("does not claim a journey is unavailable while authorization is loading", () => {
  render(<CapabilityArea area="data" catalog={null} index={0} />);
  expect(screen.getAllByText("Checking current access…")).toHaveLength(3);
  expect(
    screen.queryByText(
      "This journey is not available to the current role or application.",
    ),
  ).not.toBeInTheDocument();
});

it("maps only existing durable task functions to data journeys", () => {
  expect(
    matchingJourney({ function: "facts.transfer.import.request" }, [
      {
        title: "Load data",
        description: "",
        prefixes: ["facts.transfer.import"],
        nativeAnchor: "data-load-heading",
      },
    ])?.title,
  ).toBe("Load data");
  expect(capabilityTaskListBody("ws", "app")).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    afterSequence: 0,
    limit: 100,
  });
});

it("shows governed data activity from the unchanged task-list contract", async () => {
  const bodies: unknown[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      bodies.push(JSON.parse(String(init?.body)));
      return new Response(
        JSON.stringify({
          tasks: [
            {
              taskId: "task-load-1",
              sourceFamily: "BusinessJob",
              function: "facts.source.begin",
              status: "Succeeded",
              initiatorKind: "MCPAgent",
              updatedAt: "2026-11-02T00:00:00Z",
            },
            {
              taskId: "task-unrelated",
              sourceFamily: "BusinessJob",
              function: "facts.expression.calculate",
              status: "Succeeded",
            },
          ],
        }),
      );
    }),
  );
  render(
    <CapabilityArea
      area="data"
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      }}
      catalog={{
        applicationAccess: { role: "Editor", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: { "facts.source.begin": {} },
        revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
      }}
      index={0}
    />,
  );
  await waitFor(() =>
    expect(screen.getByText("MCP agent", { exact: false })).toBeInTheDocument(),
  );
  expect(screen.getAllByText("facts.source.begin")).toHaveLength(2);
  expect(
    screen.queryByText("facts.expression.calculate"),
  ).not.toBeInTheDocument();
  expect(bodies).toEqual([capabilityTaskListBody("ws", "app")]);
});
