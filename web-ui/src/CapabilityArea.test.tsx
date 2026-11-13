import { discardUnsavedWork } from "./unsaved-work";
import { MetadataWorkspace } from "./MetadataWorkspace";
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { installOperationAdmissionFixture } from "./test-setup";
import {
  capabilityTaskListBody,
  ApplicationLifecycleSummary,
  CapabilityArea,
  dimensionListArguments,
  collectCapabilityDimensions,
  collectCapabilityMembers,
  collectPythonPrograms,
  pythonProgramAvailabilityLabel,
  pythonProgramDisplayName,
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
  pythonScheduleReadBody,
  pythonScheduleListBody,
  pythonScheduleMutationBody,
  pythonOccurrenceBody,
  pythonOccurrenceListBody,
} from "./CapabilityArea";
import type { PythonProgramSummary } from "./CapabilityArea";

vi.mock("./PythonRuleEditor", () => ({
  PythonRuleEditor: ({
    value,
    onChange,
    ariaLabel,
    readOnly,
    diagnostics,
    completions,
  }: {
    value: string;
    onChange: (value: string) => void;
    ariaLabel: string;
    readOnly?: boolean;
    diagnostics?: unknown;
    completions?: unknown[];
  }) => (
    <div>
      <textarea
        aria-label={ariaLabel}
        value={value}
        readOnly={readOnly}
        onChange={(event) => onChange(event.target.value)}
        data-diagnostics={diagnostics ? JSON.stringify(diagnostics) : ""}
        data-completions={JSON.stringify(completions || [])}
      />
    </div>
  ),
}));

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
  expect(screen.queryByText("ws-pilot / pilot-fpna")).not.toBeInTheDocument();
  expect(screen.getByText("Active")).toBeInTheDocument();
  expect(screen.getByText("Administrator")).toBeInTheDocument();
  expect(screen.getByText("Current")).toBeInTheDocument();
  expect(screen.queryByText("M46 · D136")).not.toBeInTheDocument();
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
    screen.getByRole("heading", { name: "Application lifecycle" }),
  ).toBeInTheDocument();
  expect(screen.queryByText(/authorized function/)).not.toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Application state" }),
  ).toHaveAttribute("aria-current", "page");
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
      section="reference"
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
  expect(
    screen.getByRole("heading", { name: "Function reference" }),
  ).toBeInTheDocument();
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
          stateToken: "b".repeat(64),
          sourceToken: "c".repeat(64),
          status: "Active",
          entryPoint: "build",
          environmentId: "python",
          environmentStateToken: "a".repeat(64),
          sourceDigest: "a".repeat(64),
          declaredOutput: {
            kind: "ApplicationRule",
            definitionId: `r-${current}-${row}`,
          },
          defined: true,
          valid: true,
          active: true,
          sourceCurrent: true,
          executable: true,
          reason: null,
        })),
        nextAfterProgramId:
          current === 10 ? null : `program-cursor-${current + 1}`,
      },
    };
  });
  expect(programs.rows).toHaveLength(1100);
  expect(pythonProgramAvailabilityLabel(programs.rows[0])).toBe("Executable");
  expect(pythonProgramDisplayName(programs.rows[0])).toBe("R 0 0");

  let environmentPage = 0;
  const environments = await collectPythonEnvironments(async () => {
    const current = environmentPage++;
    return {
      result: {
        environments: Array.from({ length: 50 }, (_unused, row) => ({
          environment_id: `e-${current}-${row}`,
          state_token: "b".repeat(64),
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

it("explains typed Python output lifecycle and rejects contradictory summaries", async () => {
  const base = {
    programId: "source-rule",
    stateToken: "b".repeat(64),
    sourceToken: "c".repeat(64),
    status: "Inactive" as const,
    entryPoint: "build",
    environmentId: "python",
    environmentStateToken: "a".repeat(64),
    sourceDigest: "d".repeat(64),
    declaredOutput: { kind: "ApplicationRule", definitionId: "rule" },
    defined: true,
    valid: false,
    active: false,
    sourceCurrent: true,
    executable: false,
    reason: "validation_required" as const,
  };
  const collect = (program: PythonProgramSummary) =>
    collectPythonPrograms(async () => ({
      result: { programs: [program], nextAfterProgramId: null },
    }));
  expect(pythonProgramAvailabilityLabel((await collect(base)).rows[0])).toBe(
    "Validation required",
  );
  const unresolved = {
    ...base,
    sourceCurrent: false,
    reason: "ownership_unresolved" as const,
  };
  expect(
    pythonProgramAvailabilityLabel((await collect(unresolved)).rows[0]),
  ).toBe("Output ownership unresolved");
  const sourceOnly = {
    programId: "conflict-source",
    stateToken: "b".repeat(64),
    sourceToken: "c".repeat(64),
    status: "Inactive" as const,
    entryPoint: "build",
    environmentId: "python",
    environmentStateToken: "a".repeat(64),
    sourceDigest: "d".repeat(64),
    declaredOutput: null,
  };
  const sourceOnlyResult = await collectPythonPrograms(async () => ({
    result: { programs: [sourceOnly], nextAfterProgramId: null },
  }));
  expect(pythonProgramAvailabilityLabel(sourceOnlyResult.rows[0])).toBe(
    "Source only · no typed output",
  );
  for (const malformed of [
    { ...base, executable: true },
    { ...base, status: "Active" as const },
    { ...unresolved, sourceCurrent: true },
  ]) {
    await expect(collect(malformed)).rejects.toThrow(
      "Python program lifecycle is invalid.",
    );
  }
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
  expect(pythonProgramReadArguments("forecast-builder")).toEqual({
    programId: "forecast-builder",
  });
});

it("preserves current Python activation pins and endpoint contract", () => {
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
        functions: { "python.program.activate": {} },
        revisions: {
          metadata: 12,
          data: 2,
          policy: 7,
          security: 3,
          commit: 10,
          schemaEpoch: 4,
        },
      },
      { programId: "forecast-builder", stateToken: "b".repeat(64) },
      "activate",
      "python-activate-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "python-activate-1",
    program: {
      languageVersion: 2,
      function: "python.program.activate",
      arguments: {
        programId: "forecast-builder",
        expectedStateToken: "b".repeat(64),
        expectedMetadataRevision: 12,
        expectedPolicyRevision: 7,
        expectedSchemaEpoch: 4,
      },
    },
  });
});

it("preserves approved-environment paging and current Python save contracts", () => {
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
        entryPoint: "build",
        environmentId: "approved-python",
        environmentStateToken: "c".repeat(64),
        parameterSchema: { type: "object" },
        sourceText: "def build(context, parameters):\n    return Program()",
        declaredOutput: {
          kind: "ApplicationRule",
          definitionId: "forecast-rule",
        },
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
        definition: {
          format: "openepm-current-python-source-v1",
          programId: "forecast-builder",
          entryPoint: "build",
          environmentId: "approved-python",
          environmentStateToken: "c".repeat(64),
          parameterSchema: { type: "object" },
          sourceText: "def build(context, parameters):\n    return Program()",
          declaredOutput: {
            kind: "ApplicationRule",
            definitionId: "forecast-rule",
          },
        },
        expectedMetadataRevision: 12,
        expectedPolicyRevision: 7,
        expectedSchemaEpoch: 4,
      },
    },
  });
});

it("preserves exact execution-authority and governed run request contracts", () => {
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
        issuer: "owner",
        subjectId: "builder",
        operationScope: ["python.program.build", "python.program.run"],
        validFrom: "2026-11-02T00:00:00.000Z",
        validUntil: "2027-11-02T00:00:00.000Z",
        scheduleId: null,
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
      { delegationId: "owner-builder", expectedStateToken: "a".repeat(64) },
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
        expectedStateToken: "a".repeat(64),
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
      { programId: "forecast-builder", sourceToken: "c".repeat(64) },
      { scenario: "Forecast" },
      "owner-builder",
      "a".repeat(64),
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
        programSourceToken: "c".repeat(64),
        parameters: { scenario: "Forecast" },
        expectedMetadataRevision: 12,
        expectedPolicyRevision: 7,
        expectedSchemaEpoch: 4,
        delegationId: "owner-builder",
        delegationStateToken: "a".repeat(64),
        scheduleId: null,
        scheduleStateToken: null,
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
});

it("uses governed user names for execution authorities while keeping identity keys internal", async () => {
  const subjectKey = "subject_7f89d1a5c39e4d38a3f67e1b8fbc120a";
  const issuerKey = "issuer_8f54c65bb43c4c5b914e825c9cd511a8";
  const calls: Array<{
    path: string;
    body: {
      program: { function: string; arguments: Record<string, unknown> };
    };
  }> = [];
  const authority = {
    delegation_id: "planning-operator",
    state_token: "a".repeat(64),
    status: "Active",
    issuer: issuerKey,
    subject_id: subjectKey,
    operation_scope: ["python.program.build", "python.program.run"],
    valid_from: "2026-11-01T00:00:00Z",
    valid_until: "2027-11-01T00:00:00Z",
  };
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      const body = JSON.parse(String(init?.body));
      calls.push({ path, body });
      const functionName = body.program.function;
      const result =
        functionName === "security.application.subject.list"
          ? {
              subjects: [
                {
                  selectionKey: subjectKey,
                  displayName: "Pat Planner",
                  username: "pat.planner",
                },
              ],
              nextAfterSelectionKey: null,
            }
          : functionName === "security.identity.current.read"
            ? { issuer: issuerKey, subjectId: "current-owner" }
            : functionName === "execution.delegation.list"
              ? {
                  delegations:
                    body.program.arguments.afterDelegationId === null
                      ? [authority]
                      : [],
                  nextAfterDelegationId: null,
                }
              : functionName === "execution.delegation.create"
                ? { status: "Created" }
                : {};
      return new Response(JSON.stringify({ result }));
    }),
  );
  installOperationAdmissionFixture("7");
  render(
    <CapabilityArea
      area="rules"
      section="authorities"
      index={0}
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      }}
      catalog={{
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: false,
        },
        enabledCapabilities: [],
        functions: {
          "security.application.subject.list": {},
          "security.identity.current.read": {},
          "execution.delegation.list": {},
          "execution.delegation.read": {},
          "execution.delegation.create": {},
        },
        revisions: {
          metadata: 12,
          data: 2,
          policy: 7,
          security: 3,
          commit: 10,
          schemaEpoch: 4,
        },
      }}
    />,
  );

  expect(
    await screen.findByRole("option", { name: "Pat Planner (pat.planner)" }),
  ).toBeInTheDocument();
  expect(
    screen.queryByLabelText("Execution authority issuer"),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByLabelText("Execution authority subject"),
  ).not.toBeInTheDocument();
  expect(screen.queryByText(issuerKey)).not.toBeInTheDocument();
  expect(screen.queryByText(subjectKey)).not.toBeInTheDocument();

  expect(
    await screen.findByText("Pat Planner (pat.planner)", { selector: "td" }),
  ).toBeInTheDocument();
  expect(screen.queryByText(issuerKey)).not.toBeInTheDocument();
  expect(screen.queryByText(subjectKey)).not.toBeInTheDocument();

  fireEvent.change(screen.getByLabelText("Execution authority code"), {
    target: { value: "month-end-builder" },
  });
  fireEvent.change(screen.getByLabelText("Execution authority user"), {
    target: { value: subjectKey },
  });
  fireEvent.change(screen.getByLabelText("Execution authority valid from"), {
    target: { value: "2026-12-01T00:00" },
  });
  fireEvent.change(screen.getByLabelText("Execution authority valid until"), {
    target: { value: "2027-12-01T00:00" },
  });
  const review = screen.getByRole("checkbox", {
    name: /I reviewed this authority, authorized user/,
  });
  expect(review).toBeEnabled();
  fireEvent.click(review);
  fireEvent.click(screen.getByRole("button", { name: "Create authority" }));
  await screen.findByText("Authority Created was recorded.");

  const createCall = calls.find(
    (call) => call.body.program.function === "execution.delegation.create",
  );
  expect(createCall?.body.program.arguments).toEqual(
    expect.objectContaining({
      delegationId: "month-end-builder",
      issuer: issuerKey,
      subjectId: subjectKey,
      operationScope: ["python.program.build", "python.program.run"],
    }),
  );
  expect(confirm).toHaveBeenCalledWith(
    "Create this current execution authority?",
  );
  expect(screen.queryByText(issuerKey)).not.toBeInTheDocument();
  expect(screen.queryByText(subjectKey)).not.toBeInTheDocument();
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
        expectedStateToken: "b".repeat(64),
        programId: "forecast-builder",
        programSourceToken: "c".repeat(64),
        parameters: { scenario: "Forecast" },
        intervalSeconds: 3600,
        firstDueAt: "2026-11-03T01:00:00.000Z",
        catchUpPolicy: "latest",
        maxCatchUp: 1,
        delegationId: "owner-builder",
        delegationStateToken: "a".repeat(64),
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
        expectedStateToken: "b".repeat(64),
        programId: "forecast-builder",
        programSourceToken: "c".repeat(64),
        parameters: { scenario: "Forecast" },
        intervalSeconds: 3600,
        firstDueAt: "2026-11-03T01:00:00.000Z",
        catchUpPolicy: "latest",
        maxCatchUp: 1,
        delegationId: "owner-builder",
        delegationStateToken: "a".repeat(64),
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
      "activate",
      { scheduleId: "nightly-plan", expectedStateToken: "b".repeat(64) },
      "schedule-activate-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "schedule-activate-1",
    program: {
      languageVersion: 2,
      function: "python.schedule.activate",
      arguments: {
        scheduleId: "nightly-plan",
        expectedStateToken: "b".repeat(64),
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
      { scheduleId: "nightly-plan", expectedStateToken: "b".repeat(64) },
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
  expect(pythonOccurrenceListBody(app)).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    program: {
      languageVersion: 2,
      function: "python.schedule.occurrence.list",
      arguments: { limit: 100 },
    },
  });
  expect(pythonOccurrenceListBody(app, "e".repeat(32))).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    program: {
      languageVersion: 2,
      function: "python.schedule.occurrence.list",
      arguments: { limit: 100, afterOccurrenceId: "e".repeat(32) },
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

it("selects schedule runs by business meaning without exposing occurrence keys", async () => {
  const occurrenceId = "e".repeat(32);
  const calls: Array<Record<string, any>> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push(body);
      const result =
        body.program.function === "python.schedule.occurrence.list"
          ? {
              occurrences: [
                {
                  occurrence_id: occurrenceId,
                  schedule_id: "nightly-plan",
                  due_at: "2026-11-13T12:00:00Z",
                  status: "running",
                },
              ],
              nextAfterOccurrenceId: null,
            }
          : body.program.function === "python.schedule.occurrence.read"
            ? {
                defined: true,
                occurrence: {
                  occurrence_id: occurrenceId,
                  schedule_id: "nightly-plan",
                  schedule_state_token: "a".repeat(64),
                  due_at: "2026-11-13T12:00:00Z",
                  status: "running",
                },
              }
            : { programs: [], nextAfterProgramId: null };
      return new Response(JSON.stringify({ result }));
    }),
  );

  render(
    <CapabilityArea
      area="rules"
      section="python-schedules"
      index={0}
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      }}
      catalog={{
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: false,
        },
        enabledCapabilities: [],
        functions: {
          "python.program.list": {},
          "python.program.read": {},
          "python.schedule.list": {},
          "python.schedule.read": {},
          "python.schedule.occurrence.list": {},
          "python.schedule.occurrence.read": {},
        },
        revisions: {
          metadata: 12,
          data: 2,
          policy: 7,
          security: 3,
          commit: 10,
          schemaEpoch: 4,
        },
      }}
    />,
  );

  const run = await screen.findByRole("option", {
    name: /nightly-plan · Running · due/,
  });
  expect(screen.queryByText(occurrenceId)).not.toBeInTheDocument();
  expect(
    screen.queryByLabelText("Python schedule occurrence ID"),
  ).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("Python schedule run"), {
    target: { value: occurrenceId },
  });
  await screen.findByText("Run Running");
  expect(run).toHaveValue(occurrenceId);
  expect(screen.queryByText(occurrenceId)).not.toBeInTheDocument();
  expect(
    calls.some(
      (body) =>
        body.program.function === "python.schedule.occurrence.read" &&
        body.program.arguments.occurrenceId === occurrenceId,
    ),
  ).toBe(true);
});

it("requires an approved environment and saves Python source without routine acknowledgement", async () => {
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
                  state_token: "c".repeat(64),
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
  installOperationAdmissionFixture("4");
  render(
    <CapabilityArea
      area="rules"
      section="python"
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
  const save = screen.getByRole("button", { name: "Save and validate" });
  expect(save).toBeDisabled();
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Refresh programs" }),
    ).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Read environments" }));
  await waitFor(() =>
    expect(screen.getByLabelText("Python program environment")).toHaveValue(
      `["approved-python","${"c".repeat(64)}"]`,
    ),
  );
  fireEvent.click(screen.getByText("Create a program"));
  fireEvent.change(screen.getByLabelText("Python rule key"), {
    target: { value: "forecast-builder" },
  });
  fireEvent.change(screen.getByLabelText("Python program source"), {
    target: {
      value: "def build(context, parameters):\n    return Program()",
    },
  });
  expect(
    screen.queryByText(
      "I reviewed this exact source, schema, environment and pinned application context.",
    ),
  ).not.toBeInTheDocument();
  expect(save).toBeEnabled();
  fireEvent.click(save);
  await waitFor(() =>
    expect(
      screen.getByText("Saved the new Python program."),
    ).toBeInTheDocument(),
  );
  expect(screen.queryByText(/python-save-1/)).not.toBeInTheDocument();
  expect(window.confirm).not.toHaveBeenCalled();
  expect(screen.getByLabelText("Python program source")).toHaveValue(
    "def build(context, parameters):\n    return Program()",
  );
  expect(calls).toEqual([
    expect.objectContaining({
      path: "/api/python-program",
      program: expect.objectContaining({ function: "python.program.list" }),
    }),
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
          definition: expect.objectContaining({
            programId: "forecast-builder",
            environmentId: "approved-python",
            environmentStateToken: "c".repeat(64),
          }),
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
                  stateToken: "b".repeat(64),
                  sourceToken: "c".repeat(64),
                  status: "Active",
                  entryPoint: "forecast:build",
                  environmentId: "approved-python",
                  environmentStateToken: "c".repeat(64),
                  sourceDigest: "a".repeat(64),
                  declaredOutput: {
                    kind: "ApplicationRule",
                    definitionId: "forecast",
                  },
                  defined: true,
                  valid: true,
                  active: true,
                  sourceCurrent: true,
                  executable: true,
                  reason: null,
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
            stateToken: "b".repeat(64),
            sourceToken: "c".repeat(64),
            status: "Active",
            entryPoint: "forecast:build",
            environmentId: "approved-python",
            environmentStateToken: "c".repeat(64),
            sourceDigest: "a".repeat(64),
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
      section="python"
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
  await waitFor(() =>
    expect(
      screen.getByText("Forecast", { selector: "th" }),
    ).toBeInTheDocument(),
  );
  expect(screen.queryByText("approved-python")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Open" }));
  await waitFor(() =>
    expect(screen.getByLabelText("Authorized Python source")).toHaveValue(
      "def build(context, parameters):\n    return Program()",
    ),
  );
  expect(screen.queryByText("a".repeat(64))).not.toBeInTheDocument();
  expect(
    screen.getByText("This program does not require parameters."),
  ).toBeInTheDocument();
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
        arguments: { programId: "forecast-builder" },
      },
    }),
  ]);
});

it("creates a schedule from its own workspace and invalidates review when its prerequisites change", async () => {
  const calls: Array<{
    program: { function: string; arguments: Record<string, unknown> };
  }> = [];
  const subjectKey = "planner-directory-key";
  const program = {
    programId: "forecast-builder",
    stateToken: "b".repeat(64),
    sourceToken: "c".repeat(64),
    status: "Active",
    entryPoint: "build",
    environmentId: "approved-python",
    environmentStateToken: "c".repeat(64),
    sourceDigest: "a".repeat(64),
    declaredOutput: {
      kind: "ApplicationRule",
      definitionId: "forecast",
    },
    defined: true,
    valid: true,
    active: true,
    sourceCurrent: true,
    executable: true,
    reason: null,
  };
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push(body);
      const result =
        body.program.function === "security.application.subject.list"
          ? {
              subjects: [
                {
                  selectionKey: subjectKey,
                  displayName: "Planning User",
                  username: "planner",
                },
              ],
              nextAfterSelectionKey: null,
            }
          : body.program.function === "security.identity.current.read"
            ? { issuer: "owner", subjectId: "owner" }
            : body.program.function === "python.program.list"
              ? { programs: [program], nextAfterProgramId: null }
              : body.program.function === "python.program.read"
                ? {
                    ...program,
                    parameterSchema: {
                      type: "object",
                      properties: {
                        rate: { type: "string" },
                        enabled: { type: "boolean" },
                      },
                      required: ["rate", "enabled"],
                    },
                    sourceText:
                      "def build(context, parameters):\n    return Program()",
                  }
                : body.program.function === "execution.delegation.list"
                  ? {
                      delegations: ["owner-builder", "other-authority"].map(
                        (delegationId) => ({
                          delegation_id: delegationId,
                          state_token: "a".repeat(64),
                          status: "Active",
                          issuer: "owner",
                          subject_id: subjectKey,
                          operation_scope: [
                            "python.program.build",
                            "python.program.run",
                          ],
                          valid_from: "2020-01-01T00:00:00Z",
                          valid_until: "2099-01-01T00:00:00Z",
                        }),
                      ),
                      nextAfterDelegationId: null,
                    }
                  : body.program.function === "execution.delegation.read"
                    ? {
                        defined: true,
                        delegation: {
                          delegation_id: body.program.arguments.delegationId,
                          state_token: "a".repeat(64),
                          status: "Active",
                          issuer: "owner",
                          subject_id: subjectKey,
                          operation_scope: [
                            "python.program.build",
                            "python.program.run",
                          ],
                          valid_from: "2020-01-01T00:00:00Z",
                          valid_until: "2099-01-01T00:00:00Z",
                        },
                      }
                    : body.program.function === "python.schedule.save"
                      ? { status: "Saved", operationId: "schedule-receipt" }
                      : { schedules: [], nextAfterScheduleId: null };
      return new Response(JSON.stringify({ result }));
    }),
  );
  installOperationAdmissionFixture("5");
  render(
    <CapabilityArea
      area="rules"
      section="python-schedules"
      index={0}
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      }}
      catalog={{
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: false,
        },
        enabledCapabilities: [],
        functions: {
          "python.program.list": {},
          "python.program.read": {},
          "security.application.subject.list": {},
          "security.identity.current.read": {},
          "execution.delegation.list": {},
          "execution.delegation.read": {},
          "python.schedule.save": {},
          "python.schedule.list": {},
          "python.schedule.read": {},
        },
        revisions: {
          metadata: 12,
          data: 2,
          policy: 7,
          security: 3,
          commit: 10,
          schemaEpoch: 4,
        },
      }}
    />,
  );
  const review = screen.getByRole("radio", { name: "Review save" });
  expect(review).toBeDisabled();
  fireEvent.click(await screen.findByRole("button", { name: "Open" }));
  await waitFor(() =>
    expect(screen.getByText(/Program:/)).toHaveTextContent(
      "forecast-builder (Active)",
    ),
  );
  fireEvent.change(screen.getByLabelText("rate"), {
    target: { value: "1.123456789012" },
  });
  fireEvent.change(screen.getByLabelText("enabled"), {
    target: { value: "false" },
  });
  fireEvent.change(screen.getByLabelText("Schedule execution authority"), {
    target: { value: "owner-builder" },
  });
  await screen.findByText(/Authorized user: Planning User \(planner\)/);
  fireEvent.change(screen.getByLabelText("Python schedule code"), {
    target: { value: "nightly-plan" },
  });
  fireEvent.change(screen.getByLabelText("Python schedule first due"), {
    target: { value: "2026-12-01T01:00" },
  });
  expect(review).toBeEnabled();
  fireEvent.click(review);
  expect(review).toBeChecked();
  fireEvent.click(screen.getByRole("button", { name: "Open" }));
  expect(review).not.toBeChecked();
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Refresh programs" }),
    ).toBeEnabled(),
  );
  fireEvent.click(review);
  fireEvent.change(screen.getByLabelText("Schedule execution authority"), {
    target: { value: "other-authority" },
  });
  expect(review).not.toBeChecked();
  expect(review).toBeDisabled();
  await waitFor(() => expect(review).toBeEnabled());
  fireEvent.click(review);
  fireEvent.click(
    screen.getByRole("button", { name: "Apply reviewed schedule action" }),
  );
  await screen.findByText("Schedule Saved was recorded.");
  const saves = calls.filter(
    (call) => call.program.function === "python.schedule.save",
  );
  expect(saves).toHaveLength(1);
  expect(saves[0].program.arguments).toEqual({
    scheduleId: "nightly-plan",
    programId: "forecast-builder",
    programSourceToken: "c".repeat(64),
    parameters: { rate: "1.123456789012", enabled: false },
    intervalSeconds: 3600,
    firstDueAt: new Date("2026-12-01T01:00").toISOString(),
    catchUpPolicy: "latest",
    maxCatchUp: 1,
    delegationId: "other-authority",
    delegationStateToken: "a".repeat(64),
    expectedMetadataRevision: 12,
    expectedPolicyRevision: 7,
    expectedSchemaEpoch: 4,
  });
  confirm.mockRestore();
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
    <MetadataWorkspace
      hrefForDestination={(destination) =>
        `#/metadata/0?metadataSection=${destination.section}`
      }
      section="members"
      dimensionId="Account"
      onNavigate={() => {}}
      onDimensionsChange={() => {}}
      onRequestTransition={(action) => action()}
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
    />,
  );
  await waitFor(() =>
    expect(screen.getByLabelText("Metadata dimension")).toHaveValue("Account"),
  );
  await waitFor(() =>
    expect(screen.getByRole("button", { name: /Revenue/ })).toBeInTheDocument(),
  );
  expect(screen.getByText("Current model loaded")).toBeInTheDocument();
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
        arguments: {
          dimension: "Account",
          limit: 100,
          expectedMetadataRevision: 12,
        },
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
        "rules.expression.list": {},
        "rules.expression.read": {},
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
    "rules.expression.list",
    "rules.expression.read",
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
  expect(
    screen.getByRole("heading", { name: "Load governed CSV data" }),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("heading", { name: "Export governed snapshot" }),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Export" }));
  expect(
    screen.queryByRole("heading", { name: "Load governed CSV data" }),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Function reference" }));
  expect(screen.getByText("facts.transfer.export.request")).toBeInTheDocument();
  expect(screen.getByText("facts.line-detail.replace")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Recent activity" }));
  await screen.findByText("No recent governed data activity is visible.");
  expect(screen.getByRole("link", { name: "Open Monitor →" })).toHaveAttribute(
    "href",
    "#/monitor/0",
  );
});

it("does not claim a journey is unavailable while authorization is loading", () => {
  render(<CapabilityArea area="data" catalog={null} index={0} />);
  expect(screen.getAllByText("Checking current access…")).toHaveLength(1);
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
      section="activity"
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
  expect(screen.getAllByText("facts.source.begin")).toHaveLength(1);
  expect(
    screen.queryByText("facts.expression.calculate"),
  ).not.toBeInTheDocument();
  expect(bodies).toEqual([capabilityTaskListBody("ws", "app")]);
});

it("guards a focused workspace change before unmounting the edited program", async () => {
  let accept: (() => void) | undefined;
  render(
    <CapabilityArea
      area="rules"
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Model",
        status: "Active",
      }}
      catalog={{
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: false,
        },
        enabledCapabilities: [],
        functions: {
          "python.program.list": {},
          "python.program.read": {},
          "python.environment.list": {},
          "python.program.save": {},
        },
        revisions: {
          metadata: 1,
          data: 1,
          policy: 1,
          security: 1,
          commit: 1,
          schemaEpoch: 1,
        },
      }}
      index={0}
      onRequestTransition={(action) => {
        accept = action;
      }}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Python programs" }));
  act(() => accept?.());
  fireEvent.click(screen.getByText("Create a program"));
  fireEvent.change(screen.getByLabelText("Python rule key"), {
    target: { value: "unsaved-builder" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Function reference" }));
  expect(screen.getByLabelText("Python rule key")).toHaveValue(
    "unsaved-builder",
  );
  expect(
    screen.queryByRole("heading", { name: "Function reference" }),
  ).not.toBeInTheDocument();
  act(() => {
    discardUnsavedWork();
    accept?.();
  });
  expect(screen.queryByLabelText("Python rule key")).not.toBeInTheDocument();
  expect(
    screen.getByRole("heading", { name: "Function reference" }),
  ).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Python programs" }));
  act(() => accept?.());
  fireEvent.click(screen.getByText("Create a program"));
  expect(screen.getByLabelText("Python rule key")).toHaveValue("");
});
