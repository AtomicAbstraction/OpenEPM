import {
  discardUnsavedWork,
  setDraftIdentity,
  unsavedWorkSnapshot,
} from "./unsaved-work";
import { MetadataWorkspace } from "./MetadataWorkspace";
import { PythonProgramRun } from "./PythonProgramRun";
import {
  act,
  fireEvent,
  render,
  renderHook,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  installOperationAdmissionFixture,
  operationAdmissionResponse,
} from "./test-setup";
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
import type { ApplicationCatalog } from "./types";
import { useExecutionDelegationChange } from "./execution-delegation-change";

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

it("shows the current schedule contract and removes its open example on catalogue change", async () => {
  const name = "schedule.read";
  const program = {
    languageVersion: 2,
    function: name,
    arguments: { scheduleId: "example-schedule" },
  };
  const firstRead = {
    languageVersion: 2,
    function: "application.state.read",
    arguments: {},
  };
  const catalog = {
    applicationAccess: { role: "Reader", workspaceAdministrator: false },
    enabledCapabilities: [],
    revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
    functions: {
      [firstRead.function]: {
        permission: "read",
        exampleUse: "authorized-read",
        programContract: { examples: [firstRead] },
      },
      [name]: {
        permission: "read",
        arguments: { scheduleId: "stable schedule ID" },
        optionalArguments: { occurrences: "current token and page limit" },
        result: "Current schedule and visible occurrences",
        programContract: {
          examples: [
            {
              name: "Read a schedule",
              binding: "Use an ID from the list.",
              program,
            },
          ],
          recovery: "Refresh the schedule after a stale token.",
        },
      },
    },
    operationContracts: {
      [name]: {
        effectClass: "read_or_preview_no_publication",
        structuralSchemas: {
          programSchema: {
            type: "object",
            required: ["languageVersion", "function", "arguments"],
          },
          resultSchema: { type: "object", required: ["result"] },
          resultSchemaScope: "envelope",
        },
      },
    },
  };
  const app = {
    workspaceId: "ws",
    applicationId: "app",
    name: "App",
    status: "Active",
  };
  const props = { app, area: "rules" as const, section: "reference", index: 0 };
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  const { rerender } = render(<CapabilityArea {...props} catalog={catalog} />);
  expect(
    screen.queryByText("Use an ID from the list."),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByText(name, { selector: "summary code" }));
  expect(await screen.findByText("Use an ID from the list.")).toBeVisible();
  expect(
    screen.getByText("Refresh the schedule after a stale token."),
  ).toBeVisible();
  expect(screen.getByText("Read or preview")).toBeVisible();
  fireEvent.click(screen.getByText("Arguments", { selector: "summary" }));
  expect(screen.getByText("Required", { selector: "span" })).toBeVisible();
  expect(screen.getByText("Optional", { selector: "span" })).toBeVisible();
  expect(screen.getByText("Result envelope schema")).toBeVisible();
  expect(
    screen.getByText(
      "Fixture only. Bind the example in a disposable application.",
    ),
  ).toBeVisible();
  expect(
    screen.getByLabelText("Read a schedule", { selector: "pre" }).textContent,
  ).toBe(JSON.stringify(program, null, 2));
  rerender(
    <CapabilityArea {...props} area="administration" catalog={catalog} />,
  );
  fireEvent.click(
    screen.getByText(firstRead.function, { selector: "summary code" }),
  );
  expect(
    await screen.findByText(
      "Use with the currently selected authorized application.",
    ),
  ).toBeVisible();
  expect(fetch).not.toHaveBeenCalled();
  rerender(<CapabilityArea {...props} catalog={null} />);
  expect(screen.getByRole("status")).toHaveTextContent(
    "Checking current access",
  );
  expect(screen.queryByText(name)).not.toBeInTheDocument();
  rerender(
    <CapabilityArea {...props} catalog={{ ...catalog, functions: {} }} />,
  );
  expect(screen.queryByText(name)).not.toBeInTheDocument();
  expect(
    screen.queryByText("Use an ID from the list."),
  ).not.toBeInTheDocument();
});

it.each([
  { target: "application.rule.list", example: "List the current rules" },
  { target: "application.rule.run.read", example: "Verify a rule run" },
])(
  "hides a retired sequence even in a stale catalogue while keeping $target inspectable",
  async ({ target, example }) => {
    const legacy = "rules.numeric_sequence.list";
    const replacement = "application.rule.list";
    const outcome = "application.rule.run.read";
    const code = "ORDERED_RULE_CURRENT_OWNER_UNSUPPORTED";
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    render(
      <CapabilityArea
        area="rules"
        section="reference"
        index={0}
        app={{
          workspaceId: "ws",
          applicationId: "app",
          name: "App",
          status: "Active",
        }}
        catalog={{
          applicationAccess: { role: "Reader", workspaceAdministrator: false },
          revisions: {
            metadata: 1,
            data: 1,
            policy: 1,
            security: 1,
            commit: 1,
          },
          enabledCapabilities: [],
          functions: {
            [legacy]: {
              permission: "legacy_rule_permission",
              programContract: {
                execution: { newExecutionAvailable: false, diagnostic: code },
                examples: [
                  {
                    name: "List legacy sequences",
                    expectedError: code,
                    program: {
                      languageVersion: 2,
                      function: legacy,
                      arguments: {},
                    },
                  },
                ],
                replacement: {
                  ownerKind: "ApplicationRule",
                  identity: "A legacy ID does not identify a current rule.",
                  inspection: "Inspect the current application rules.",
                  inspectionDiscovery: [
                    { view: "functions", function: replacement },
                  ],
                  authoringDiscovery: [
                    { view: "functions", function: "python.program.save" },
                  ],
                  authoring: "Save reviewed source.",
                  runDiscovery: {
                    view: "functions",
                    function: "application.rule.run",
                  },
                  runOutcome: {
                    discovery: { view: "functions", function: outcome },
                    workflowIdFromRun: "$.result.workflowId",
                    guidance: "Check the original committed checkpoints.",
                  },
                },
              },
            },
            [replacement]: {
              programContract: {
                examples: [
                  {
                    name: "List the current rules",
                    program: {
                      languageVersion: 2,
                      function: replacement,
                      arguments: { limit: 1 },
                    },
                  },
                ],
              },
            },
            [outcome]: {
              programContract: {
                examples: [
                  {
                    name: "Verify a rule run",
                    program: {
                      languageVersion: 2,
                      function: outcome,
                      arguments: { workflowId: "a".repeat(32) },
                    },
                  },
                ],
              },
            },
          },
          operationContracts: {
            [legacy]: { previewRequired: true, idempotencyRequired: true },
          },
        }}
      />,
    );
    expect(
      screen.queryByText(legacy, { selector: "summary code" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("List legacy sequences")).not.toBeInTheDocument();
    expect(
      screen.queryByText("legacy_rule_permission"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText("Required for this request."),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText("Required for the exact program."),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("python.program.save")).not.toBeInTheDocument();
    expect(screen.queryByText("Save reviewed source.")).not.toBeInTheDocument();
    expect(screen.queryByText("Run the reviewed rule")).not.toBeInTheDocument();
    fireEvent.click(screen.getByText(target, { selector: "summary code" }));
    const current = screen.getByText(target, { selector: "summary code" });
    expect(current.closest("details")).toHaveProperty("open", true);
    expect(
      await screen.findByRole("button", {
        name: `Copy program for ${example}`,
      }),
    ).toBeVisible();
    expect(fetch).not.toHaveBeenCalled();
  },
);

it("opens the metadata reference from the catalogue without reading model rows", async () => {
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  render(
    <MetadataWorkspace
      section="reference"
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "App",
        status: "Active",
      }}
      catalog={{
        applicationAccess: { role: "Reader", workspaceAdministrator: false },
        enabledCapabilities: [],
        revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
        functions: {
          "metadata.dimension.list": {
            permission: "read",
            arguments: {},
            optionalArguments: { limit: "Maximum page length" },
            result: "A page of dimensions",
          },
        },
      }}
      onNavigate={vi.fn()}
      hrefForDestination={() => "#"}
      onDimensionsChange={vi.fn()}
      onRequestTransition={(action) => action()}
    />,
  );
  fireEvent.click(
    screen.getByText("metadata.dimension.list", { selector: "summary code" }),
  );
  expect(await screen.findByText("A page of dimensions")).toBeVisible();
  expect(screen.getByText("Published guidance is descriptive.")).toBeVisible();
  expect(
    screen.queryByRole("button", { name: /Copy program/ }),
  ).not.toBeInTheDocument();
  expect(fetch).not.toHaveBeenCalled();
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
    "Current definition validation required",
  );
  for (const [reason, explanation] of [
    ["metadata_stale", "application metadata changed"],
    ["schema_stale", "application schema changed"],
    ["dependency_stale", "definition dependencies changed"],
    ["source_environment_stale", "source environment changed"],
    ["compiler_unavailable", "accepted compiler unavailable"],
  ] as const) {
    const activeStale = {
      ...base,
      status: "Active" as const,
      active: true,
      reason,
    };
    expect(
      pythonProgramAvailabilityLabel((await collect(activeStale)).rows[0]),
    ).toBe(`Revalidation required · ${explanation}`);
    await expect(collect({ ...activeStale, valid: true })).rejects.toThrow(
      "Python program lifecycle is invalid.",
    );
  }
  expect(
    pythonProgramAvailabilityLabel(
      (
        await collect({
          ...base,
          valid: true,
          reason: "inactive",
        })
      ).rows[0],
    ),
  ).toBe("Validated · inactive");
  // A technical Validation task may expire without retiring the accepted owner.
  expect(
    pythonProgramAvailabilityLabel(
      (
        await collect({
          ...base,
          status: "Active",
          active: true,
          valid: true,
          executable: true,
          reason: null,
          validation: {
            buildId: "old-build",
            status: "expired",
            purpose: "Validation",
          },
        })
      ).rows[0],
    ),
  ).toBe("Executable");
  const unresolved = {
    ...base,
    status: "Unavailable" as const,
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
    { ...base, defined: false },
    { ...base, reason: "inactive" as const },
    { ...base, valid: true, reason: null },
    { ...base, status: "Unavailable" as const },
    { ...base, reason: "not_defined" as PythonProgramSummary["reason"] },
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
  let releaseDirectory!: () => void;
  const pendingDirectory = new Promise<void>((resolve) => {
    releaseDirectory = resolve;
  });
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
      if (functionName === "security.application.subject.list")
        await pendingDirectory;
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
                ? {
                    operationId: body.idempotencyKey,
                    delegationId: body.program.arguments.delegationId,
                    status: "Active",
                    stateToken: "b".repeat(64),
                    policyRevision: 8,
                  }
                : {};
      return new Response(
        JSON.stringify({ languageVersion: 2, function: functionName, result }),
      );
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

  const pendingRow = await screen.findByRole("row", {
    name: /planning-operator/,
  });
  const pendingLabel = pendingRow.textContent;
  const userPickerDisabled = screen.getByRole<HTMLSelectElement>("combobox", {
    name: "Execution authority user",
  }).disabled;
  await act(async () => releaseDirectory());
  expect(pendingLabel).toContain("Loading directory identity…");
  expect(pendingLabel).not.toContain("Directory identity unavailable");
  expect(userPickerDisabled).toBe(true);

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
  await screen.findByText("Authority creation was recorded.");

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

it("recovers an exact revoked authority across remount, application and account changes", async () => {
  const app = {
    workspaceId: "workspace",
    applicationId: "recovery",
    name: "Planning",
    status: "Active",
  };
  const catalog: ApplicationCatalog = {
    applicationAccess: {
      role: "Administrator",
      workspaceAdministrator: false,
      issuer: "https://identity.example",
      subjectId: "administrator",
    },
    enabledCapabilities: [],
    functions: {
      "security.application.subject.list": {},
      "security.identity.current.read": {},
      "execution.delegation.list": {},
      "execution.delegation.read": {},
      "execution.delegation.create": {},
      "execution.delegation.revoke": {},
    },
    revisions: {
      metadata: 4,
      data: 5,
      policy: 7,
      security: 8,
      commit: 10,
      schemaEpoch: 3,
    },
  };
  const authority = {
    delegation_id: "monthly-close",
    state_token: "a".repeat(64),
    status: "Active",
    issuer: catalog.applicationAccess.issuer,
    subject_id: "departed-user",
    operation_scope: ["python.program.run"],
    valid_from: "2026-11-01T00:00:00Z",
    valid_until: "2027-11-01T00:00:00Z",
  };
  const effectBodies: string[] = [];
  let admissions = 0;
  let commits = 0;
  let result: Record<string, unknown> | undefined;
  const json = (value: unknown, status = 200) =>
    new Response(JSON.stringify(value), { status });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (String(url) === "/api/operation-admission") {
        admissions += 1;
        return operationAdmissionResponse("e");
      }
      const { function: name } = body.program;
      const envelope = (value: unknown) =>
        json({ languageVersion: 2, function: name, result: value });
      if (name === "security.application.subject.list")
        return envelope({ subjects: [], nextAfterSelectionKey: null });
      if (name === "security.identity.current.read")
        return envelope({
          issuer: catalog.applicationAccess.issuer,
          subjectId: catalog.applicationAccess.subjectId,
        });
      const current = commits
        ? { ...authority, status: "Revoked", state_token: "b".repeat(64) }
        : authority;
      if (name === "execution.delegation.list")
        return envelope({
          delegations: [current],
          nextAfterDelegationId: null,
        });
      if (name === "execution.delegation.read")
        return envelope({ defined: true, delegation: current });
      if (name !== "execution.delegation.revoke")
        throw new Error("Unexpected authority operation");
      effectBodies.push(String(init?.body));
      if (!commits) {
        commits += 1;
        result = {
          operationId: body.idempotencyKey,
          delegationId: authority.delegation_id,
          status: "Revoked",
          stateToken: "b".repeat(64),
          policyRevision: 8,
        };
        return json({ code: "WEB_OPERATION_OUTCOME_UNKNOWN" }, 503);
      }
      return envelope(
        effectBodies.length === 2
          ? { ...result, operationId: "different-operation" }
          : result,
      );
    }),
  );
  vi.spyOn(window, "confirm").mockReturnValue(true);
  const mount = (target = app, value = catalog) =>
    render(
      <CapabilityArea
        area="rules"
        section="authorities"
        index={0}
        app={target}
        catalog={value}
      />,
    );
  setDraftIdentity("administrator");
  const first = mount();
  fireEvent.click(
    await screen.findByRole("button", { name: "Use authority details" }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Open authority" }));
  await screen.findByText(/Current active authority/);
  fireEvent.click(
    screen.getByRole("checkbox", { name: /I freshly read and reviewed/ }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Revoke authority" }));
  await screen.findByText(
    "The original authority change is still unconfirmed.",
  );
  expect(
    screen.getByRole("button", { name: "Create authority" }),
  ).toBeDisabled();
  expect(effectBodies).toHaveLength(1);
  first.unmount();

  const control = mount({ ...app, applicationId: "control" });
  expect(
    screen.queryByRole("region", { name: "Original authority change" }),
  ).not.toBeInTheDocument();
  control.unmount();
  setDraftIdentity("different-administrator");
  const other = mount(app, {
    ...catalog,
    applicationAccess: {
      ...catalog.applicationAccess,
      subjectId: "different-administrator",
    },
  });
  expect(
    screen.queryByRole("region", { name: "Original authority change" }),
  ).not.toBeInTheDocument();
  other.unmount();
  setDraftIdentity("administrator");
  const restricted = mount(app, {
    ...catalog,
    functions: {
      "execution.delegation.list": {},
      "execution.delegation.read": {},
    },
  });
  expect(
    await screen.findByRole("button", { name: "Retry original change" }),
  ).toBeDisabled();
  restricted.unmount();

  mount(app, { ...catalog, revisions: { ...catalog.revisions, policy: 8 } });
  const retry = await screen.findByRole("button", {
    name: "Retry original change",
  });
  await waitFor(() => expect(retry).toBeEnabled());
  const writeText = vi.fn(async (_text: string) => {});
  vi.stubGlobal(
    "navigator",
    Object.assign(Object.create(navigator), {
      clipboard: { writeText },
    }),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Copy original change for MCP" }),
  );
  await screen.findByText("Original authority change copied for MCP.");
  const originalBody = JSON.parse(effectBodies[0]);
  expect(JSON.parse(writeText.mock.calls[0][0])).toEqual({
    tool: "execute_v2_execution_delegation",
    arguments: {
      workspace_id: app.workspaceId,
      application_id: app.applicationId,
      program: originalBody.program,
      idempotency_key: originalBody.idempotencyKey,
    },
  });
  expect(effectBodies).toHaveLength(1);
  fireEvent.click(retry);
  await screen.findByText(
    "The reply did not confirm the original authority change.",
  );
  expect(
    screen.queryByText("Authority revocation was recorded."),
  ).not.toBeInTheDocument();
  retry.focus();
  fireEvent.click(retry);
  await screen.findByText("Authority revocation was recorded.");
  expect(
    screen.getByRole("heading", { name: "Execution authorities", level: 3 }),
  ).toHaveFocus();
  expect(
    screen.queryByRole("region", { name: "Original authority change" }),
  ).not.toBeInTheDocument();
  expect(admissions).toBe(1);
  expect(commits).toBe(1);
  expect(unsavedWorkSnapshot()).toEqual([]);
  expect(effectBodies).toHaveLength(3);
  expect(new Set(effectBodies).size).toBe(1);
  expect(JSON.parse(effectBodies[0]).program.arguments).toEqual({
    delegationId: "monthly-close",
    expectedStateToken: "a".repeat(64),
    expectedMetadataRevision: 4,
    expectedPolicyRevision: 7,
    expectedSchemaEpoch: 3,
  });
});

it("keeps an expired authority request unconfirmed until recovery is explicitly closed", async () => {
  const scope = { workspaceId: "workspace", applicationId: "application" };
  const catalog: ApplicationCatalog = {
    applicationAccess: { role: "Administrator", workspaceAdministrator: false },
    enabledCapabilities: [],
    functions: { "execution.delegation.create": {} },
    revisions: {
      metadata: 1,
      data: 0,
      policy: 2,
      security: 0,
      commit: 2,
      schemaEpoch: 3,
    },
  };
  const effectBodies: string[] = [];
  const onRecorded = vi.fn();
  const confirmation = vi.spyOn(window, "confirm").mockReturnValue(false);
  const fetcher = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    if (String(url) === "/api/operation-admission")
      return operationAdmissionResponse();
    effectBodies.push(String(init?.body));
    return new Response(
      JSON.stringify({
        code:
          effectBodies.length === 1
            ? "WEB_OPERATION_OUTCOME_UNKNOWN"
            : "OPERATION_ADMISSION_EXPIRED",
      }),
      { status: effectBodies.length === 1 ? 503 : 400 },
    );
  });
  vi.stubGlobal("fetch", fetcher);
  const { result } = renderHook(() =>
    useExecutionDelegationChange(scope, catalog, "context", onRecorded),
  );
  await act(() =>
    result.current.submit(
      {
        ...scope,
        confirmed: true,
        idempotencyKey: "approved-intent",
        program: {
          languageVersion: 2,
          function: "execution.delegation.create",
          arguments: { delegationId: "monthly", expectedPolicyRevision: 2 },
        },
      },
      "monthly",
      "create",
    ),
  );
  await waitFor(() => expect(result.current.retryReady).toBe(true));
  await act(() => result.current.retry());
  expect(result.current.message).toBe(
    "The original request expired, and the server found no receipt.",
  );
  expect(result.current.canCloseRecovery).toBe(true);
  expect(result.current.pending).toBe(true);
  expect(onRecorded).not.toHaveBeenCalled();
  expect(result.current.closeRecovery()).toBeNull();
  confirmation.mockReturnValue(true);
  act(() => expect(result.current.closeRecovery()).toBe("monthly"));
  expect(result.current.pending).toBe(false);
  expect(unsavedWorkSnapshot()).toEqual([]);
  expect(new Set(effectBodies).size).toBe(1);
  expect(effectBodies).toHaveLength(2);
  expect(
    fetcher.mock.calls.filter(([url]) => url === "/api/operation-admission"),
  ).toHaveLength(1);
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
      arguments: {
        scheduleId: "nightly-plan",
        expectedStateToken: "b".repeat(64),
      },
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

it("retains a reviewed schedule start through remount and gives a later deliberate start a fresh admission", async () => {
  vi.spyOn(window, "confirm").mockReturnValue(true);
  const effects: string[] = [];
  const occurrenceId = "e".repeat(32);
  const issued = vi.fn(() =>
    operationAdmissionResponse(effects.length < 2 ? "a" : "b"),
  );
  const schedule = {
    schedule_id: "nightly",
    state_token: "d".repeat(64),
    status: "Active",
    program_id: "forecast",
    interval_seconds: 3600,
    first_due_at: "2026-11-13T12:00:00Z",
    catch_up_policy: "latest",
    max_catch_up: 1,
    delegation_id: "authority",
    delegation_state_token: "c".repeat(64),
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      if (path === "/api/operation-admission") return issued();
      const body = JSON.parse(String(init.body));
      const fn = body.program.function;
      if (fn === "python.schedule.run") {
        effects.push(String(init.body));
        if (effects.length === 1)
          throw new TypeError("Lost original schedule response");
        return Response.json({
          languageVersion: 2,
          function: fn,
          result:
            effects.length === 2
              ? { scheduleId: "nightly", status: "NotDue", occurrence: null }
              : {
                  scheduleId: "nightly",
                  status: "Materialized",
                  occurrenceId,
                  dueAt: schedule.first_due_at,
                },
        });
      }
      if (fn === "python.schedule.occurrence.list")
        return Response.json({
          result: { occurrences: [], nextAfterOccurrenceId: null },
        });
      if (fn === "python.schedule.occurrence.read") {
        expect(body.program.arguments).toEqual({ occurrenceId });
        return Response.json({
          result: {
            defined: true,
            occurrence: {
              occurrence_id: occurrenceId,
              schedule_id: schedule.schedule_id,
              schedule_state_token: schedule.state_token,
              due_at: schedule.first_due_at,
              status: "ready",
            },
          },
        });
      }
      return Response.json({
        result:
          fn === "python.schedule.read"
            ? { defined: true, schedule }
            : fn === "execution.delegation.read"
              ? { defined: false }
              : { schedules: [schedule], nextAfterScheduleId: null },
      });
    }),
  );
  const area = (
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
          "python.schedule.read": {},
          "python.schedule.list": {},
          "python.schedule.run": {},
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
    />
  );
  async function reviewedStart() {
    fireEvent.change(
      screen.getByRole("textbox", { name: "Python schedule code" }),
      {
        target: { value: schedule.schedule_id },
      },
    );
    fireEvent.click(screen.getByRole("button", { name: "Open schedule" }));
    await screen.findByText(/Current schedule · Active/);
    fireEvent.click(screen.getByRole("radio", { name: "Review run" }));
    fireEvent.click(
      screen.getByRole("button", { name: "Apply reviewed schedule action" }),
    );
  }
  const original = render(area);
  await reviewedStart();
  await screen.findByText("The original schedule change is still unconfirmed.");
  expect(screen.getByRole("radio", { name: "Review run" })).toBeDisabled();
  original.unmount();
  render(area);
  const retry = await screen.findByRole("button", {
    name: "Retry original schedule change",
  });
  expect(issued).toHaveBeenCalledTimes(1);
  expect(effects).toHaveLength(1);
  retry.focus();
  fireEvent.click(retry);
  await screen.findByText("No occurrence was due for the original request.");
  expect(
    screen.getByRole("heading", { name: "Program schedules", level: 3 }),
  ).toHaveFocus();
  expect(effects).toHaveLength(2);
  expect(effects[0]).toBe(effects[1]);
  expect(JSON.parse(effects[0]).program.arguments).toEqual({
    scheduleId: "nightly",
    expectedStateToken: schedule.state_token,
  });
  await reviewedStart();
  await waitFor(() => expect(effects).toHaveLength(3));
  expect(issued).toHaveBeenCalledTimes(2);
  expect(JSON.parse(effects[0]).idempotencyKey).not.toBe(
    JSON.parse(effects[2]).idempotencyKey,
  );
  expect(await screen.findByText("Run Ready")).toBeVisible();
  expect(screen.getByLabelText("Python schedule run")).toHaveValue(
    occurrenceId,
  );
});

it("selects schedule runs by business meaning without exposing occurrence keys", async () => {
  const occurrenceId = "e".repeat(32);
  const calls: Array<Record<string, any>> = [];
  let reads = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push(body);
      if (body.program.function === "python.schedule.occurrence.read") reads++;
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
                  occurrence_id: reads === 2 ? "f".repeat(32) : occurrenceId,
                  schedule_id: "nightly-plan",
                  schedule_state_token: "a".repeat(64),
                  ...(reads > 1 ? { due_at: "2026-11-13T12:00:00Z" } : {}),
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
          "python.schedule.occurrence.cancel": {},
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
  const picker = screen.getByLabelText("Python schedule run");
  for (const failure of [1, 2]) {
    fireEvent.change(picker, { target: { value: occurrenceId } });
    expect(
      await screen.findByText(/The schedule run could not be verified/),
    ).toBeVisible();
    expect(reads).toBe(failure);
    expect(
      screen.queryByRole("button", { name: "Cancel occurrence" }),
    ).toBeNull();
    fireEvent.change(picker, { target: { value: "" } });
  }
  fireEvent.change(picker, {
    target: { value: occurrenceId },
  });
  await screen.findByText("Run Running");
  expect(
    screen.getByRole("button", { name: "Cancel occurrence" }),
  ).toBeDisabled();
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

it("requires a fresh schedule run review after the application catalogue changes and preserves exact cancellation recovery", async () => {
  vi.spyOn(window, "confirm").mockReturnValue(true);
  const occurrenceId = "e".repeat(32);
  const occurrence = {
    occurrence_id: occurrenceId,
    schedule_id: "nightly-plan",
    due_at: "2026-11-13T12:00:00Z",
    status: "running",
  };
  const readSignals: AbortSignal[] = [];
  const admission = vi.fn(() => operationAdmissionResponse());
  const effects: string[] = [];
  let finishSecondRead: (response: Response) => void = () => {};
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      if (path === "/api/operation-admission") return admission();
      const body = JSON.parse(String(init.body));
      switch (body.program.function) {
        case "python.schedule.occurrence.list":
          return Response.json({
            result: { occurrences: [occurrence], nextAfterOccurrenceId: null },
          });
        case "python.schedule.occurrence.read":
          expect(body.program.arguments).toEqual({ occurrenceId });
          readSignals.push(init.signal);
          if (readSignals.length === 2)
            return new Promise<Response>((resolve) => {
              finishSecondRead = resolve;
            });
          return Response.json({ result: { defined: true, occurrence } });
        case "python.schedule.occurrence.cancel":
          effects.push(String(init.body));
          if (effects.length === 1)
            throw new TypeError("Lost cancellation reply");
          return Response.json({
            languageVersion: 2,
            function: body.program.function,
            result: { occurrenceId, status: "cancel_requested" },
          });
        case "python.schedule.list":
          return Response.json({
            result: { schedules: [], nextAfterScheduleId: null },
          });
        default:
          throw new Error(body.program.function);
      }
    }),
  );
  const catalog: ApplicationCatalog = {
    applicationAccess: {
      role: "Administrator",
      workspaceAdministrator: false,
      issuer: "issuer",
      subjectId: "reviewer",
    },
    enabledCapabilities: [],
    functions: {
      "python.schedule.list": {},
      "python.schedule.read": {},
      "python.schedule.occurrence.list": {},
      "python.schedule.occurrence.read": {},
      "python.schedule.occurrence.cancel": {},
    },
    revisions: { metadata: 12, data: 2, policy: 7, security: 3, commit: 10 },
  };
  const area = (security: number) => (
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
      catalog={{ ...catalog, revisions: { ...catalog.revisions, security } }}
    />
  );
  const { rerender } = render(area(3));
  await screen.findByRole("option", { name: /nightly-plan · Running/ });
  const picker = screen.getByRole("combobox", { name: "Python schedule run" });
  const review = () =>
    screen.getByRole("checkbox", {
      name: /reviewed this freshly read occurrence/,
    });
  const cancel = () =>
    screen.getByRole("button", { name: "Cancel occurrence" });
  fireEvent.change(picker, { target: { value: occurrenceId } });
  await screen.findByText("Run Running");
  fireEvent.click(review());
  expect(cancel()).toBeEnabled();

  rerender(area(4));
  expect(
    screen.queryByRole("button", { name: "Cancel occurrence" }),
  ).toBeNull();
  await waitFor(() => expect(readSignals).toHaveLength(2));
  expect(picker).toHaveValue(occurrenceId);
  expect(admission).not.toHaveBeenCalled();

  rerender(area(5));
  await screen.findByText("Run Running");
  expect(readSignals).toHaveLength(3);
  expect(readSignals[1].aborted).toBe(true);
  expect(review()).not.toBeChecked();
  expect(cancel()).toBeDisabled();
  await act(async () => {
    finishSecondRead(
      Response.json({ error: "LATE_GATEWAY_ERROR" }, { status: 503 }),
    );
  });
  expect(screen.queryByText("LATE_GATEWAY_ERROR")).not.toBeInTheDocument();
  expect(cancel()).toBeDisabled();

  fireEvent.click(review());
  fireEvent.click(cancel());
  await screen.findByText("The original schedule change is still unconfirmed.");
  rerender(area(6));
  expect(await screen.findByText("Run Running")).toBeVisible();
  expect(cancel()).toBeDisabled();
  expect(admission).toHaveBeenCalledTimes(1);
  const retry = screen.getByRole("button", {
    name: "Retry original schedule change",
  });
  fireEvent.click(retry);
  await screen.findByText("Original cancellation returned Cancel Requested.");
  expect(effects).toHaveLength(2);
  expect(effects[0]).toBe(effects[1]);
  expect(JSON.parse(effects[0]).program.arguments).toEqual({ occurrenceId });
  expect(admission).toHaveBeenCalledTimes(1);
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

it.each([false, true])(
  "reads current Python source and honors a keyboard focus change (%s)",
  async (movedFocus) => {
    const calls: Array<Record<string, unknown>> = [];
    let releaseRead: () => void = () => {};
    const reading = new Promise<void>((resolve) => {
      releaseRead = resolve;
    });
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
        await reading;
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
              declaredOutput: {
                kind: "ApplicationRule",
                definitionId: "forecast",
              },
              valid: true,
              active: true,
              sourceCurrent: true,
              executable: true,
              reason: null,
              parameterSchema: { type: "object" },
              sourceText:
                "def build(context, parameters):\n    return Program()",
            },
          }),
        );
      }),
    );
    render(
      <>
        <button type="button">Another action</button>
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
            applicationAccess: {
              role: "Editor",
              workspaceAdministrator: false,
            },
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
        />
      </>,
    );
    const viewCode = await screen.findByRole("button", {
      name: "View code for Forecast",
    });
    const anotherAction = screen.getByRole("button", {
      name: "Another action",
    });
    expect(screen.queryByText("approved-python")).not.toBeInTheDocument();
    viewCode.focus();
    fireEvent.click(viewCode);
    if (movedFocus) anotherAction.focus();
    await act(async () => releaseRead());
    await waitFor(() =>
      expect(screen.getByLabelText("Authorized Python source")).toHaveValue(
        "def build(context, parameters):\n    return Program()",
      ),
    );
    expect(screen.queryByText("a".repeat(64))).not.toBeInTheDocument();
    expect(
      screen.getByText("This program does not require parameters."),
    ).toBeInTheDocument();
    await act(async () => {
      await new Promise<void>((resolve) =>
        requestAnimationFrame(() => resolve()),
      );
    });
    expect(
      movedFocus
        ? anotherAction
        : screen.getByLabelText("Python program detail"),
    ).toHaveFocus();
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
  },
);

it.each([
  "active-expired",
  "active-stale",
  "inactive-validated",
  "inactive-stale-validation",
] as const)(
  "renders owner validity independently from technical Validation: %s",
  async (state) => {
    const active = state.startsWith("active-");
    const valid = state !== "active-stale";
    const currentValidation = state === "inactive-validated";
    const program: PythonProgramSummary = {
      programId: "forecast",
      stateToken: "b".repeat(64),
      sourceToken: "c".repeat(64),
      status: active ? "Active" : "Inactive",
      entryPoint: "build",
      environmentId: "approved",
      environmentStateToken: "d".repeat(64),
      sourceDigest: "a".repeat(64),
      declaredOutput: { kind: "ApplicationRule", definitionId: "forecast" },
      defined: true,
      valid,
      active,
      sourceCurrent: true,
      executable: valid && active,
      reason: !valid ? "metadata_stale" : active ? null : "inactive",
      validation: {
        buildId: "validation-1",
        purpose: "Validation",
        status:
          state === "inactive-stale-validation" || currentValidation
            ? "sealed"
            : "expired",
        current: currentValidation,
        definition:
          state === "active-expired"
            ? undefined
            : { kind: "ApplicationRule", definitionId: "forecast" },
      },
    };
    const effects: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url, init) => {
        const fn = JSON.parse(String(init?.body)).program.function;
        if (fn === "python.program.list")
          return new Response(
            JSON.stringify({
              result: { programs: [program], nextAfterProgramId: null },
            }),
          );
        if (fn === "python.environment.list")
          return new Response(
            JSON.stringify({
              result: { environments: [], nextAfterEnvironmentId: null },
            }),
          );
        if (fn !== "python.program.read") effects.push(fn);
        return new Response(
          JSON.stringify({
            result: {
              ...program,
              parameterSchema: { type: "object" },
              sourceText:
                "def build(context, parameters):\n    return definition",
            },
          }),
        );
      }),
    );
    render(
      <CapabilityArea
        area="rules"
        section="python"
        index={0}
        app={{
          workspaceId: "ws",
          applicationId: "app",
          name: "App",
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
            "python.program.activate": {},
            "python.program.deactivate": {},
            "python.program.build": {},
            "python.program.run": {},
          },
          revisions: {
            metadata: 1,
            policy: 1,
            data: 0,
            security: 1,
            commit: 0,
            schemaEpoch: 1,
          },
        }}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "View code for Forecast" }),
    );
    await screen.findByLabelText("Authorized Python source");
    expect(
      screen.queryByRole("region", { name: "Run current saved Python source" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/Use its current definition in Rules/),
    ).toBeInTheDocument();
    const activation = screen.getByRole("button", { name: "Activate source" });
    if (currentValidation) expect(activation).toBeEnabled();
    else expect(activation).toBeDisabled();
    expect(
      screen
        .getByRole("button", { name: "Deactivate source" })
        .hasAttribute("disabled"),
    ).toBe(!active);
    expect(
      screen.getByText(/An expired build does not itself deactivate/),
    ).toBeInTheDocument();
    expect(
      screen.getAllByText(pythonProgramAvailabilityLabel(program)),
    ).toHaveLength(2);
    // jsdom does not implement the browser's scrollIntoView method.
    Object.defineProperty(
      screen.getByLabelText("New Python program"),
      "scrollIntoView",
      { value: vi.fn() },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Edit current source" }),
    );
    await screen.findByText(/Saving changed source makes its owner Inactive/);
    expect(
      screen.getByText(
        /appropriate current Validation or supported private Test/,
      ),
    ).toBeInTheDocument();
    expect(effects).toEqual([]);
  },
);

it("keeps a design-only edit bound to its original source when another program opens", async () => {
  setDraftIdentity("designer");
  const draft = {
    programId: "forecast-source",
    stateToken: "b".repeat(64),
    sourceToken: "c".repeat(64),
    status: "Active",
    entryPoint: "build",
    environmentId: "forecast-builder",
    environmentStateToken: "d".repeat(64),
    sourceDigest: "a".repeat(64),
    declaredOutput: { kind: "ApplicationRule", definitionId: "Forecast" },
    defined: true,
    valid: true,
    active: true,
    sourceCurrent: true,
    executable: true,
    reason: null,
    parameterSchema: { type: "object" },
    sourceText: "def build(context, parameters):\n    return rule",
  };
  const other = {
    ...draft,
    programId: "operations-source",
    stateToken: "4".repeat(64),
    environmentId: "operations-builder",
    declaredOutput: { kind: "ApplicationRule", definitionId: "Operations" },
  };
  const runtimeRequests: string[] = [];
  const saved: Record<string, unknown>[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn<typeof fetch>(async (_url, init) => {
      const body = JSON.parse(String(init?.body));
      const name = body.program?.function;
      runtimeRequests.push(name);
      if (name === "python.program.list")
        return Response.json({
          result: { programs: [draft, other], nextAfterProgramId: null },
        });
      if (name === "python.program.read")
        return Response.json({
          result:
            body.program.arguments.programId === draft.programId
              ? draft
              : other,
        });
      if (name === "python.program.save") {
        saved.push(body.program.arguments);
        return Response.json({
          result: {
            status: "Inactive",
            stateToken: "8".repeat(64),
            validation: {
              buildId: "e".repeat(32),
              purpose: "Validation",
              status: "accepted",
            },
          },
        });
      }
      if (body.action === "read")
        return Response.json({
          result: {
            buildId: "e".repeat(32),
            purpose: "Validation",
            status: "sealed",
          },
        });
      throw new Error("Unexpected request: " + JSON.stringify(body));
    }),
  );
  installOperationAdmissionFixture("9");
  render(
    <CapabilityArea
      area="rules"
      section="python"
      index={0}
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
        },
        revisions: {
          metadata: 1,
          policy: 1,
          data: 0,
          security: 1,
          commit: 0,
          schemaEpoch: 1,
        },
      }}
    />,
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "View code for Forecast" }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Edit current source" }),
  );
  expect(
    screen.getByText("Approved environment: forecast-builder"),
  ).toBeInTheDocument();
  expect(screen.queryByText("Create a program")).toBeNull();
  expect(screen.queryByLabelText("Python program environment")).toBeNull();
  const replacement = draft.sourceText + "\n# revised forecast";
  const editor = screen.getByLabelText("Python program source");
  fireEvent.change(editor, { target: { value: replacement } });
  fireEvent.click(
    screen.getByRole("button", { name: "View code for Operations" }),
  );
  await waitFor(() =>
    expect(
      runtimeRequests.filter((name) => name === "python.program.read"),
    ).toHaveLength(2),
  );
  expect(editor).toHaveValue(replacement);
  expect(saved).toHaveLength(0);
  fireEvent.click(screen.getByRole("button", { name: "Save and validate" }));
  await waitFor(() => expect(saved).toHaveLength(1));
  expect(saved[0]).toMatchObject({
    expectedStateToken: draft.stateToken,
    definition: {
      programId: draft.programId,
      environmentId: draft.environmentId,
      environmentStateToken: draft.environmentStateToken,
      sourceText: replacement,
      declaredOutput: draft.declaredOutput,
    },
  });
  expect(runtimeRequests).not.toContain("python.environment.list");
});

it.each(["null", "missing", "unknown"] as const)(
  "permits a generic Plan control only for an explicit null declaration: %s",
  async (declaration) => {
    const source = {
      programId: "general-plan",
      stateToken: "b".repeat(64),
      sourceToken: "c".repeat(64),
      status: "Active",
      entryPoint: "build",
      environmentId: "approved",
      environmentStateToken: "d".repeat(64),
      sourceDigest: "a".repeat(64),
      ...(declaration === "null"
        ? { declaredOutput: null }
        : declaration === "unknown"
          ? {
              declaredOutput: { kind: "UnknownOwner", definitionId: "unknown" },
            }
          : {}),
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url, init) => {
        const fn = JSON.parse(String(init?.body)).program.function;
        return new Response(
          JSON.stringify({
            result:
              fn === "python.program.list"
                ? { programs: [source], nextAfterProgramId: null }
                : {
                    ...source,
                    defined: true,
                    sourceText:
                      "def build(context, parameters):\n    return Program()",
                    parameterSchema: { type: "object" },
                  },
          }),
        );
      }),
    );
    render(
      <CapabilityArea
        area="rules"
        section="python"
        index={0}
        app={{
          workspaceId: "ws",
          applicationId: "app",
          name: "App",
          status: "Active",
        }}
        catalog={{
          applicationAccess: { role: "Editor", workspaceAdministrator: false },
          enabledCapabilities: [],
          functions: {
            "python.program.list": {},
            "python.program.read": {},
            "python.program.build": {},
            "python.program.run": {},
          },
          revisions: {
            metadata: 1,
            policy: 1,
            data: 0,
            security: 1,
            commit: 0,
            schemaEpoch: 1,
          },
        }}
      />,
    );
    if (declaration === "null") {
      fireEvent.click(
        await screen.findByRole("button", {
          name: "View code for General Plan",
        }),
      );
      expect(
        await screen.findByRole("region", {
          name: "Run current saved Python source",
        }),
      ).toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: "Run current saved source" }),
      ).toBeDisabled();
    } else {
      await screen.findByText(
        declaration === "missing"
          ? "Python program summary is invalid."
          : "Python declared output is invalid.",
      );
      expect(
        screen.queryByRole("region", {
          name: "Run current saved Python source",
        }),
      ).not.toBeInTheDocument();
    }
  },
);

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
                      ? {
                          status: "Saved",
                          operationId: body.idempotencyKey,
                          scheduleId: body.program.arguments.scheduleId,
                          stateToken: "f".repeat(64),
                          policyRevision: 8,
                        }
                      : { schedules: [], nextAfterScheduleId: null };
      return Response.json({
        languageVersion: 2,
        function: body.program.function,
        result,
      });
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
  fireEvent.click(await screen.findByRole("button", { name: "Use Forecast" }));
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
  fireEvent.click(screen.getByRole("button", { name: "Use Forecast" }));
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

it("opens Calculation rules directly for a group runner and offers its authorized workspaces", async () => {
  const reads: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      reads.push(JSON.parse(String(init.body)).program.function);
      return Response.json({
        result: {
          rows: [],
          hasMore: false,
          nextAfterRuleId: null,
          metadataRevision: 1,
          policyRevision: 1,
        },
      });
    }),
  );
  render(
    <CapabilityArea
      area="rules"
      index={0}
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plant",
        status: "Active",
      }}
      catalog={{
        applicationAccess: {
          role: "Assigned",
          authorizationModel: "group_assignments",
          workspaceAdministrator: false,
        },
        enabledCapabilities: [],
        revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
        functions: {
          "application.rule.list": {},
          "application.rule.read": {},
          "application.rule.run": {},
          "application.rule.run.read": {},
        },
      }}
    />,
  );
  expect(
    screen.getByRole("button", { name: "Calculation rules" }),
  ).toHaveAttribute("aria-current", "page");
  expect(
    screen.getByRole("button", { name: "Function reference" }),
  ).toBeVisible();
  expect(
    screen.queryByRole("button", { name: "Python programs" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Schedules" }),
  ).not.toBeInTheDocument();
  await waitFor(() => expect(reads).toEqual(["application.rule.list"]));
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

it("reports an empty workspace catalogue without diagnosing a missing role", () => {
  const app = {
    workspaceId: "ws",
    applicationId: "app",
    name: "Plan",
    status: "Active",
  };
  const status =
    "This workspace has no matching functions in the current application catalogue. Choose another workspace or inspect Function reference.";
  const { rerender } = render(
    <CapabilityArea area="data" app={app} catalog={null} index={0} />,
  );
  expect(screen.getByText("Checking current access…")).toBeInTheDocument();
  expect(screen.queryByText(status)).not.toBeInTheDocument();
  rerender(
    <CapabilityArea
      area="data"
      app={app}
      catalog={{
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: true,
        },
        enabledCapabilities: [],
        functions: { "facts.transfer.export.request": {} },
        revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
      }}
      index={0}
    />,
  );
  expect(screen.getByText(status)).toHaveAttribute("role", "status");
  expect(
    screen.queryByText(/not available to your current application role/),
  ).not.toBeInTheDocument();
});

it("offers the group workspace only while its exact read is advertised", () => {
  const catalog = {
    applicationAccess: { role: "Administrator", workspaceAdministrator: false },
    enabledCapabilities: [],
    functions: { "security.application.group-access.set": {} },
    revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
  };
  const app = {
    workspaceId: "ws",
    applicationId: "app",
    name: "Plan",
    status: "Active",
  };
  const props = { app, area: "security" as const, section: "groups", index: 0 };
  const { rerender } = render(<CapabilityArea {...props} catalog={catalog} />);
  expect(
    screen.queryByRole("button", { name: "Groups & access" }),
  ).not.toBeInTheDocument();
  expect(
    screen.getByText(/Group access is unavailable in the current application/),
  ).toHaveAttribute("role", "status");
  rerender(
    <CapabilityArea
      {...props}
      catalog={{
        ...catalog,
        functions: {
          ...catalog.functions,
          "security.application.group-access.list": {},
        },
      }}
    />,
  );
  expect(
    screen.getByRole("button", { name: "Groups & access" }),
  ).toHaveAttribute("aria-current", "page");
  expect(
    screen.getByRole("heading", { name: "Application groups and roles" }),
  ).toBeInTheDocument();
});

it.each([
  ["authorities", "Execution authorities", "execution.delegation.list"],
  ["authorities", "Execution authorities", "execution.delegation.read"],
  ["python-schedules", "Program schedules", "python.schedule.list"],
  ["python-schedules", "Program schedules", "python.schedule.read"],
] as const)(
  "explains $0 with only $2 advertised and keeps unneeded reads closed",
  (section, label, partialFunction) => {
    const fetch = vi.fn(() => new Promise<Response>(() => undefined));
    vi.stubGlobal("fetch", fetch);
    const app = {
      workspaceId: "ws",
      applicationId: "app",
      name: "Plan",
      status: "Active",
    };
    const allowed: ApplicationCatalog = {
      applicationAccess: { role: "Editor", workspaceAdministrator: false },
      enabledCapabilities: [],
      functions: {
        [partialFunction]: {},
        "python.program.list": {},
        "python.program.read": {},
        "security.application.subject.list": {},
        "security.identity.current.read": {},
      },
      revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
    };
    const props = { app, area: "rules" as const, section, index: 0 };
    const { rerender } = render(<CapabilityArea {...props} catalog={null} />);
    expect(screen.getByRole("status")).toHaveTextContent(
      "Checking current access",
    );
    rerender(<CapabilityArea {...props} catalog={allowed} />);
    expect(screen.getByRole("status")).toHaveTextContent(
      `${label} are unavailable in the current application catalogue. Choose another workspace or inspect Function reference.`,
    );
    expect(
      screen.getByRole("heading", { name: label, level: 2 }),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", {
        name: /refresh programs|read schedules|read authorities/iu,
      }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(/required permission|current role/iu),
    ).not.toBeInTheDocument();
    expect(fetch).not.toHaveBeenCalled();
  },
);

it("describes an empty function reference using the current catalogue", () => {
  render(
    <CapabilityArea
      area="data"
      section="reference"
      catalog={{
        applicationAccess: { role: "Editor", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: {},
        revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
      }}
      index={0}
    />,
  );
  expect(
    screen.getByText(
      "The current application catalogue lists no functions for this workspace.",
    ),
  ).toBeVisible();
  expect(screen.queryByText(/available to your current role/)).toBeNull();
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

it("reports a missing Python list operation as unavailable rather than a role denial", () => {
  render(
    <CapabilityArea
      index={0}
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
        functions: {},
        revisions: {
          metadata: 1,
          policy: 1,
          data: 1,
          security: 1,
          commit: 1,
          schemaEpoch: 1,
        },
      }}
    />,
  );
  expect(
    screen.getByText(
      "Python programs are unavailable in the current application context.",
    ),
  ).toBeVisible();
  expect(
    screen.queryByText(/current role cannot read Python/),
  ).not.toBeInTheDocument();
});

it.each(["build unavailable", "run unavailable", "typed source"] as const)(
  "keeps original execution recovery reachable in the program inspector after %s",
  async (change) => {
    const app = {
      workspaceId: "ws",
      applicationId: "app",
      name: "App",
      status: "Active",
    };
    const catalog: ApplicationCatalog = {
      applicationAccess: {
        role: "Editor",
        workspaceAdministrator: false,
        issuer: "fixture",
        subjectId: "planner",
      },
      functions: {
        "python.program.list": {},
        "python.program.read": {},
        "python.program.build": {},
        "python.program.run": {},
      },
      enabledCapabilities: [],
      revisions: {
        metadata: 1,
        policy: 1,
        data: 0,
        security: 1,
        commit: 0,
        schemaEpoch: 1,
      },
    };
    const original = {
      programId: "forecast",
      stateToken: "b".repeat(64),
      sourceToken: "c".repeat(64),
      status: "Active",
      entryPoint: "build",
      environmentId: "approved",
      environmentStateToken: "d".repeat(64),
      sourceDigest: "a".repeat(64),
      declaredOutput: null,
      defined: true,
      sourceText: "def build(context, parameters):\n    return Program()",
      parameterSchema: { type: "object" },
    };
    const current =
      change === "typed source"
        ? {
            ...original,
            sourceToken: "e".repeat(64),
            sourceDigest: "f".repeat(64),
            declaredOutput: {
              kind: "ApplicationRule",
              definitionId: "forecast",
            },
            valid: true,
            active: true,
            executable: true,
            sourceCurrent: true,
            reason: null,
          }
        : original;
    const requests: Array<{ path: string; body: any }> = [];
    let firstBuild = true;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path, init) => {
        const body = JSON.parse(String(init?.body));
        requests.push({ path: String(path), body });
        if (String(path) === "/api/python-build") {
          if (firstBuild) {
            firstBuild = false;
            throw new TypeError("Original acceptance unknown");
          }
          return new Response(
            JSON.stringify({
              result: {
                buildId: "1".repeat(32),
                purpose: "Plan",
                status: "sealed",
                planDigest: "2".repeat(64),
              },
            }),
          );
        }
        if (String(path) === "/api/python-program")
          return new Response(
            JSON.stringify({
              result:
                body.program.function === "python.program.list"
                  ? {
                      programs: [
                        {
                          ...current,
                          defined:
                            current.declaredOutput === null ? undefined : true,
                        },
                      ],
                      nextAfterProgramId: null,
                    }
                  : current,
            }),
          );
        throw new Error(`Unexpected request: ${path}`);
      }),
    );
    installOperationAdmissionFixture("9");
    const first = render(
      <PythonProgramRun
        app={app}
        catalog={catalog}
        program={original}
        parameters="{}"
        authority={{
          delegation_id: "authority",
          state_token: "d".repeat(64),
          status: "Active",
          operation_scope: ["python.program.build", "python.program.run"],
          valid_from: "2020-01-01T00:00:00Z",
          valid_until: "2099-01-01T00:00:00Z",
        }}
        onSetupAuthority={() => undefined}
      />,
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Run current saved source" }),
    );
    await screen.findByText("Original acceptance unknown");
    first.unmount();
    const functions = { ...catalog.functions };
    if (change === "build unavailable")
      delete functions["python.program.build"];
    if (change === "run unavailable") delete functions["python.program.run"];
    render(
      <CapabilityArea
        area="rules"
        section="python"
        index={0}
        app={app}
        catalog={{ ...catalog, functions }}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "View code for Forecast" }),
    );
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Reconcile original execution",
      }),
    );
    await screen.findByText(/Original Plan: sealed/);
    expect(
      screen.queryByRole("button", { name: "Run current saved source" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Resume exact execution request" }),
    ).not.toBeInTheDocument();
    const effects = requests.filter(
      ({ path }) => path === "/api/python-build" || path === "/api/python-run",
    );
    expect(effects).toHaveLength(2);
    expect(effects[1]).toEqual({
      path: "/api/python-build",
      body: {
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
        action: "read",
        originalRequest: {
          program: effects[0].body.program,
          idempotencyKey: effects[0].body.idempotencyKey,
        },
      },
    });
    expect(
      effects.filter(({ body }) => body.action === "request"),
    ).toHaveLength(1);
  },
);
