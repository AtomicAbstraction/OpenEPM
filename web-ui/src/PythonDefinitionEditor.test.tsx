import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { PythonDefinitionEditor } from "./PythonDefinitionEditor";
import { PythonSourceValidation } from "./PythonSourceValidation";
import { installOperationAdmissionFixture } from "./test-setup";
import type { PythonDefinitionKind } from "./PythonDefinitionEditor";
import type { ApplicationCatalog } from "./types";
import {
  canPreserveUnsavedWork,
  resetUnsavedWorkForTests,
  setDraftIdentity,
  unsavedWorkSnapshot,
} from "./unsaved-work";
vi.mock("./PythonRuleEditor", () => ({
  PythonRuleEditor: ({
    value,
    onChange,
    readOnly,
    ariaLabel,
    diagnostics,
    completions,
  }: {
    value: string;
    onChange: (value: string) => void;
    readOnly: boolean;
    ariaLabel: string;
    diagnostics?: unknown;
    completions?: unknown[];
  }) => (
    <textarea
      aria-label={ariaLabel}
      value={value}
      readOnly={readOnly}
      data-diagnostics={diagnostics ? JSON.stringify(diagnostics) : ""}
      data-completions={JSON.stringify(completions || [])}
      onChange={(event) => onChange(event.target.value)}
    />
  ),
}));
afterEach(() => {
  vi.unstubAllGlobals();
  resetUnsavedWorkForTests();
});
const app = {
  workspaceId: "ws",
  applicationId: "app",
  name: "App",
  status: "Active",
};
const digest = "a".repeat(64);
const catalog: ApplicationCatalog = {
  applicationAccess: { role: "Editor", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: {
    "python.program.save": {},
    "python.program.read": {},
    "python.program.activate": {},
    "python.program.deactivate": {},
    "python.environment.list": {},
  },
  revisions: {
    metadata: 4,
    policy: 2,
    data: 1,
    security: 1,
    commit: 1,
    schemaEpoch: 1,
  },
};
const binding = {
  programId: "source",
  programSourceToken: "c".repeat(64),
  sourceDigest: digest,
  buildId: "old-build",
  active: true,
};
const source = {
  defined: true,
  valid: true,
  active: true,
  sourceCurrent: true,
  executable: true,
  reason: null,
  programId: "source",
  stateToken: "b".repeat(64),
  sourceToken: "c".repeat(64),
  status: "Active",
  sourceDigest: digest,
  sourceText: "def build(context, parameters):\n    return definition\n",
  entryPoint: "build",
  environmentId: "approved",
  environmentStateToken: "d".repeat(64),
  parameterSchema: { type: "object" },
  validation: {
    buildId: "old-build",
    status: "sealed",
    purpose: "Validation",
    current: false,
  },
};
const response = (result: unknown) => new Response(JSON.stringify({ result }));

it.each(["current", "changed source", "changed environment"] as const)(
  "lets a design-only user edit the bound source while preserving its exact state (%s)",
  async (caseName) => {
    setDraftIdentity("designer");
    let current: Omit<typeof source, "reason"> & { reason: string | null } =
      source;
    const saved: Record<string, unknown>[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>(async (_url, init) => {
        const body = JSON.parse(String(init?.body));
        if (body.program?.function === "python.program.read")
          return response(current);
        if (body.program?.function === "python.program.save") {
          saved.push(body.program.arguments);
          if (caseName === "changed environment")
            return Response.json(
              { error: "PYTHON_ENVIRONMENT_NOT_ACTIVE" },
              { status: 409 },
            );
          return response({
            status: "Inactive",
            stateToken: "e".repeat(64),
            sourceToken: "f".repeat(64),
            sourceDigest: "1".repeat(64),
            validation: {
              buildId: "a".repeat(32),
              purpose: "Validation",
              status: "accepted",
            },
          });
        }
        if (body.action === "read")
          return response({
            buildId: "a".repeat(32),
            purpose: "Validation",
            status: "failed",
          });
        throw new Error("Unexpected request: " + JSON.stringify(body));
      }),
    );
    installOperationAdmissionFixture("8");
    const view = (policy: number) => (
      <PythonDefinitionEditor
        app={app}
        catalog={{
          ...catalog,
          functions: { "python.program.read": {}, "python.program.save": {} },
          revisions: { ...catalog.revisions, policy },
        }}
        kind="ApplicationRule"
        definitionId="forecast"
        binding={binding}
      />
    );
    const browser = render(view(2));
    fireEvent.click(
      await screen.findByRole("button", { name: "Edit current source" }),
    );
    const editor = screen.getByLabelText(
      "ApplicationRule Python source editor",
    );
    await waitFor(() => expect(editor).not.toHaveAttribute("readonly"));
    expect(
      screen.getByText("Approved environment: approved"),
    ).toBeInTheDocument();
    expect(
      screen.queryByLabelText("ApplicationRule source environment"),
    ).toBeNull();
    expect(
      screen.queryByRole("button", { name: "Activate source" }),
    ).toBeNull();
    const replacement = source.sourceText + "# revised source\n";
    fireEvent.change(editor, { target: { value: replacement } });
    const save = screen.getByRole("button", {
      name: "Save and validate source",
    });
    expect(save).toBeEnabled();
    expect(saved).toHaveLength(0);
    if (caseName === "changed source") {
      current = {
        ...source,
        stateToken: "9".repeat(64),
        status: "Inactive",
        active: false,
        executable: false,
        reason: "inactive",
        sourceToken: "8".repeat(64),
        sourceDigest: "7".repeat(64),
      };
      browser.rerender(view(3));
      await screen.findByText(
        "The saved source changed. This draft is still available to copy.",
      );
      expect(editor).toHaveValue(replacement);
      expect(save).toBeDisabled();
      expect(saved).toHaveLength(0);
    } else {
      fireEvent.click(save);
      await waitFor(() => expect(saved).toHaveLength(1));
      expect(saved[0]).toMatchObject({
        expectedStateToken: source.stateToken,
        definition: {
          programId: source.programId,
          sourceText: replacement,
          environmentId: source.environmentId,
          environmentStateToken: source.environmentStateToken,
        },
      });
      if (caseName === "changed environment") {
        await screen.findByText(
          /The build environment binding is no longer active/,
        );
        expect(editor).toHaveValue(replacement);
      }
    }
  },
);

it("lets a publisher recover and activate only their own source validation", async () => {
  setDraftIdentity("publisher");
  const buildId = "9".repeat(32);
  const publisherCatalog = {
    ...catalog,
    applicationAccess: {
      ...catalog.applicationAccess,
      issuer: "issuer",
      subjectId: "publisher",
    },
    functions: {
      "python.program.read": {},
      "python.program.validate": {},
      "python.program.activate": {},
    },
  };
  const inactive = {
    ...source,
    active: false,
    executable: false,
    reason: "inactive",
    status: "Inactive",
    validation: { ...source.validation, current: true, ownedByCaller: false },
  };
  const own = {
    buildId,
    status: "sealed",
    purpose: "Validation",
    current: true,
    ownedByCaller: true,
    definition: { kind: "ApplicationRule", definitionId: "forecast" },
  };
  let original: { program: unknown; idempotencyKey: unknown } | undefined;
  let activated: Record<string, unknown> | undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn<typeof fetch>(async (_url, init) => {
      const body = JSON.parse(String(init?.body));
      if (body.program?.function === "python.program.read")
        return response(original ? { ...inactive, validation: own } : inactive);
      if (body.program?.function === "python.program.validate") {
        original = {
          program: body.program,
          idempotencyKey: body.idempotencyKey,
        };
        // The server accepted the build, but the client did not receive its acknowledgement.
        return new Response(JSON.stringify({ error: "APPLICATION_BUSY" }), {
          status: 409,
        });
      }
      if (body.action === "read" && body.originalRequest) {
        expect(body.originalRequest).toEqual(original);
        return response({ ...own, current: undefined, definition: undefined });
      }
      if (body.program?.function === "python.program.activate") {
        activated = body.program.arguments;
        return response({ status: "Active" });
      }
      throw new Error("Unexpected request: " + JSON.stringify(body));
    }),
  );
  installOperationAdmissionFixture("9");
  render(
    <PythonDefinitionEditor
      app={app}
      catalog={publisherCatalog}
      kind="ApplicationRule"
      definitionId="forecast"
      binding={{ ...binding, active: false }}
      template=""
    />,
  );
  const activate = await screen.findByRole("button", {
    name: "Activate source",
  });
  expect(activate).toBeDisabled();
  expect(
    screen.queryByRole("button", { name: "Edit current source" }),
  ).toBeNull();
  expect(screen.queryByRole("button", { name: "Test source" })).toBeNull();
  fireEvent.change(screen.getByLabelText("Validation sample parameters"), {
    target: { value: '{"rate":"0.123456789012345678"}' },
  });
  expect(unsavedWorkSnapshot().map((draft) => draft.label)).toEqual([
    "Unsubmitted Python validation samples",
  ]);
  fireEvent.click(
    screen.getByRole("button", { name: "Validate saved source" }),
  );
  const recover = await screen.findByRole("button", {
    name: "Check original validation",
  });
  expect(activate).toBeDisabled();
  expect(unsavedWorkSnapshot().map((draft) => draft.label)).toEqual(
    expect.arrayContaining([
      "Unsubmitted Python validation samples",
      "Python validation with an unconfirmed outcome",
    ]),
  );
  expect(original?.program).toMatchObject({
    function: "python.program.validate",
    arguments: {
      programId: "source",
      programSourceToken: source.sourceToken,
      parameters: { rate: "0.123456789012345678" },
    },
  });
  fireEvent.click(recover);
  await waitFor(() => expect(activate).toBeEnabled());
  expect(unsavedWorkSnapshot()).toEqual([]);
  fireEvent.click(activate);
  await waitFor(() =>
    expect(activated).toMatchObject({
      programId: "source",
      expectedStateToken: source.stateToken,
      validationBuildId: buildId,
    }),
  );
});

it("retains validation samples for the exact application, identity and saved source", async () => {
  setDraftIdentity("designer");
  const designerCatalog = {
    ...catalog,
    applicationAccess: {
      ...catalog.applicationAccess,
      issuer: "issuer",
      subjectId: "designer",
    },
    functions: { ...catalog.functions, "python.program.validate": {} },
  };
  const props = {
    app,
    catalog: designerCatalog,
    source: { ...source, validation: null },
    contextKey: "context",
    suspended: false,
    onAccepted: vi.fn(),
  };
  const { rerender } = render(<PythonSourceValidation {...props} />);
  const samples = () => screen.getByLabelText("Validation sample parameters");
  fireEvent.change(samples(), { target: { value: '{"period":"January"}' } });
  await waitFor(() => expect(unsavedWorkSnapshot()).toHaveLength(1));
  expect(canPreserveUnsavedWork()).toBe(true);

  const otherScopes = [
    { app: { ...app, workspaceId: "other" } },
    { source: { ...props.source, programId: "different-program" } },
    { source: { ...props.source, sourceToken: "e".repeat(64) } },
    {
      catalog: {
        ...designerCatalog,
        applicationAccess: {
          ...designerCatalog.applicationAccess,
          subjectId: "other-designer",
        },
      },
    },
  ];
  for (const other of otherScopes) {
    rerender(<PythonSourceValidation {...props} {...other} />);
    expect(samples()).toHaveValue("{}");
    rerender(<PythonSourceValidation {...props} />);
    await waitFor(() => expect(samples()).toHaveValue('{"period":"January"}'));
  }
  expect(props.onAccepted).not.toHaveBeenCalled();
});

it.each([
  null,
  "dependency_stale",
  "source_environment_stale",
  "metadata_stale",
] as const)(
  "explains Active source acceptance independently of expired Validation: %s",
  async (reason) => {
    const current = {
      ...source,
      valid: reason === null,
      executable: reason === null,
      reason,
      validation: { ...source.validation, status: "expired" },
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url, init) => {
        const body = JSON.parse(String(init?.body));
        if (body.program.function === "python.program.read")
          return response(current);
        throw new Error("Unexpected effect or authority lookup");
      }),
    );
    const view = render(
      <PythonDefinitionEditor
        app={app}
        catalog={catalog}
        kind="ApplicationRule"
        binding={binding}
        definitionId="definition"
      />,
    );
    const availability = await screen.findByLabelText(
      "Current definition availability",
    );
    expect(availability).toHaveTextContent(
      reason === null ? "Executable" : "Revalidation required",
    );
    expect(screen.getByText(/Validation: expired/)).toBeInTheDocument();
    expect(
      screen.getByText(/An expired build does not itself deactivate/),
    ).toHaveTextContent(
      "current actor authority, approved environment, dependencies and execution fences",
    );
    expect(
      screen.getByRole("button", { name: "Activate source" }),
    ).toBeDisabled();
    const revoked = {
      ...catalog,
      functions: {},
      revisions: { ...catalog.revisions, security: 99 },
    };
    view.rerender(
      <PythonDefinitionEditor
        app={app}
        catalog={revoked}
        kind="ApplicationRule"
        binding={binding}
        definitionId="definition"
      />,
    );
    expect(
      screen.queryByRole("button", { name: "Activate source" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Deactivate source" }),
    ).not.toBeInTheDocument();
  },
);

it("rejects contradictory current owner validity rather than trusting an Active label", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => response({ ...source, reason: "dependency_stale" })),
  );
  render(
    <PythonDefinitionEditor
      app={app}
      catalog={catalog}
      kind="ApplicationRule"
      binding={binding}
      definitionId="definition"
    />,
  );
  await screen.findByText("The bound Python source is unavailable.");
  expect(
    screen.queryByLabelText("Current definition availability"),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Activate source" }),
  ).not.toBeInTheDocument();
});

it.each([
  "ApplicationRule",
  "MemberList",
  "CalculatedMember",
] as PythonDefinitionKind[])(
  "reopens %s's current bound Python, replaces it, validates, and activates that exact displayed artifact",
  async (kind) => {
    const descriptor = { kind, definitionId: "definition" };
    const declaredOutput =
      kind === "MemberList"
        ? { ...descriptor, dimensionId: "Account" }
        : descriptor;
    const calls: any[] = [];
    let saved = false,
      activated = false;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url, init) => {
        const body = JSON.parse(init.body);
        calls.push(body);
        const fn = body.program?.function;
        if (fn === "python.environment.list")
          return response({
            environments: [
              {
                environment_id: "approved",
                state_token: "d".repeat(64),
                status: "Active",
              },
            ],
            nextAfterEnvironmentId: null,
          });
        if (fn === "python.program.read")
          return response(
            saved
              ? {
                  ...source,
                  declaredOutput,
                  stateToken: activated ? "e".repeat(64) : "f".repeat(64),
                  status: activated ? "Active" : "Inactive",
                  active: activated,
                  executable: activated,
                  reason: activated ? null : "inactive",
                  validation: {
                    buildId: "validation-five",
                    purpose: "Validation",
                    status: "sealed",
                    current: true,
                    definition: descriptor,
                  },
                }
              : { ...source, declaredOutput },
          );
        if (fn === "python.program.save") {
          saved = true;
          return response({
            stateToken: "f".repeat(64),
            sourceToken: "c".repeat(64),
            status: "Inactive",
            sourceDigest: digest,
            validation: {
              buildId: "validation-five",
              purpose: "Validation",
              status: "sealed",
            },
          });
        }
        if (fn === "python.program.activate") {
          activated = true;
          return response({});
        }
        throw new Error(`Unexpected ${JSON.stringify(body)}`);
      }),
    );
    installOperationAdmissionFixture("c");
    const changed = vi.fn();
    render(
      <PythonDefinitionEditor
        app={app}
        catalog={catalog}
        kind={kind}
        binding={binding}
        definitionId="definition"
        onChanged={changed}
      />,
    );
    const editor = await screen.findByLabelText(`${kind} Python source editor`);
    expect(editor).toHaveValue(source.sourceText);
    expect(editor).toHaveAttribute("readonly");
    fireEvent.click(
      screen.getByRole("button", { name: "Edit current source" }),
    );
    await waitFor(() => expect(editor).not.toHaveAttribute("readonly"));
    expect(editor).toHaveValue(source.sourceText);
    expect(editor).not.toHaveAttribute("readonly");
    fireEvent.change(editor, {
      target: { value: `${source.sourceText}# typed definition v3\n` },
    });
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Save and validate source" }),
      ).toBeEnabled(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Save and validate source" }),
    );
    const activate = await screen.findByRole("button", {
      name: "Activate source",
    });
    await waitFor(() => expect(activate).toBeEnabled());
    expect(
      calls.find((item) => item.program?.function === "python.program.save")
        .program.arguments,
    ).toMatchObject({
      definition: expect.objectContaining({
        programId: "source",
        sourceText: `${source.sourceText}# typed definition v3\n`,
        declaredOutput,
      }),
    });
    fireEvent.click(activate);
    await waitFor(() => expect(changed).toHaveBeenCalledWith(descriptor));
    expect(
      calls.find((item) => item.program?.function === "python.program.activate")
        .program.arguments,
    ).toMatchObject({
      programId: "source",
      expectedStateToken: "f".repeat(64),
      validationBuildId: "validation-five",
    });
    expect(
      calls.filter((item) => item.program?.function?.endsWith(".definition")),
    ).toHaveLength(0);
  },
);
it.each([
  [
    { sourceDigest: "b".repeat(64) },
    "The definition source digest does not match its immutable binding.",
  ],
  [
    { sourceToken: "e".repeat(64) },
    "The saved source no longer matches this definition. Refresh the definition before continuing.",
  ],
])(
  "refuses a source that does not match the selected definition (%j)",
  async (foreign, message) => {
    const currentness = vi.fn();
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => response({ ...source, ...foreign })),
    );
    installOperationAdmissionFixture("d");
    render(
      <PythonDefinitionEditor
        app={app}
        catalog={catalog}
        kind="MemberList"
        binding={binding}
        onSourceCurrentness={currentness}
      />,
    );
    await screen.findByText(message);
    expect(
      screen.queryByLabelText("MemberList Python source editor"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Activate source" }),
    ).not.toBeInTheDocument();
    expect(currentness).toHaveBeenNthCalledWith(1, "checking");
    expect(currentness).toHaveBeenLastCalledWith("unavailable");
  },
);
it("rejects a Validation that compiles a different definition and keeps its source readable", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      response({
        ...source,
        validation: {
          ...source.validation,
          current: true,
          definition: {
            kind: "ApplicationRule",
            definitionId: "foreign",
          },
        },
      }),
    ),
  );
  render(
    <PythonDefinitionEditor
      app={app}
      catalog={catalog}
      kind="ApplicationRule"
      definitionId="expected"
      binding={binding}
    />,
  );
  await screen.findByLabelText("ApplicationRule Python source editor");
  expect(
    screen.getByRole("button", { name: "Activate source" }),
  ).toBeDisabled();
});
it("ignores a late bound-source read after an application change", async () => {
  let finish: (value: Response) => void = () => undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn((_url, init) =>
      JSON.parse(init.body).applicationId === "app"
        ? new Promise<Response>((resolve) => {
            finish = resolve;
          })
        : Promise.resolve(
            response({ ...source, sourceText: "new application's source" }),
          ),
    ),
  );
  const { rerender } = render(
    <PythonDefinitionEditor
      app={app}
      catalog={catalog}
      kind="MemberList"
      binding={binding}
    />,
  );
  rerender(
    <PythonDefinitionEditor
      app={{ ...app, applicationId: "other" }}
      catalog={catalog}
      kind="MemberList"
      binding={binding}
    />,
  );
  await waitFor(() =>
    expect(
      screen.getByLabelText("MemberList Python source editor"),
    ).toHaveValue("new application's source"),
  );
  await act(async () => finish(response(source)));
  expect(screen.getByLabelText("MemberList Python source editor")).toHaveValue(
    "new application's source",
  );
});
it("retains authored source and exact mutation key when Save loses its response", async () => {
  const saves: any[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(init.body);
      if (body.program.function === "python.environment.list")
        return response({
          environments: [
            {
              environment_id: "approved",
              state_token: "d".repeat(64),
              status: "Active",
            },
          ],
          nextAfterEnvironmentId: null,
        });
      saves.push(body);
      throw new Error("Lost response");
    }),
  );
  installOperationAdmissionFixture("d");
  render(
    <PythonDefinitionEditor
      app={app}
      catalog={catalog}
      kind="MemberList"
      template="authored Python"
    />,
  );
  fireEvent.change(screen.getByLabelText("MemberList source ID"), {
    target: { value: "source" },
  });
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Save and validate source" }),
    ).toBeEnabled(),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Save and validate source" }),
  );
  await screen.findByText("Lost response");
  expect(screen.getByLabelText("MemberList Python source editor")).toHaveValue(
    "authored Python",
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Save and validate source" }),
  );
  await waitFor(() => expect(saves).toHaveLength(2));
  expect(saves[0]).toEqual(saves[1]);
});

it("preserves a bound source draft across navigation and late source readback without crossing source, application or identity", async () => {
  setDraftIdentity("designer");
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(init.body);
      if (body.program.function === "python.environment.list")
        return response({
          environments: [
            {
              environment_id: "approved",
              state_token: "d".repeat(64),
              status: "Active",
            },
          ],
          nextAfterEnvironmentId: null,
        });
      if (body.program.function === "python.program.read")
        return response(source);
      throw new Error("Unexpected draft request");
    }),
  );
  const element = (bound = binding, scope = app) => (
    <PythonDefinitionEditor
      app={scope}
      catalog={catalog}
      kind="ApplicationRule"
      definitionId="definition"
      binding={bound}
    />
  );
  const first = render(element());
  fireEvent.click(
    await screen.findByRole("button", { name: "Edit current source" }),
  );
  const editor = screen.getByLabelText("ApplicationRule Python source editor");
  await waitFor(() => expect(editor).not.toHaveAttribute("readonly"));
  fireEvent.change(editor, { target: { value: "unsaved exact next source" } });
  first.unmount();
  const other = render(
    element({ ...binding, programSourceToken: "e".repeat(64) }),
  );
  await screen.findByText(
    "The saved source no longer matches this definition. Refresh the definition before continuing.",
  );
  expect(
    screen.queryByLabelText("ApplicationRule Python source editor"),
  ).not.toBeInTheDocument();
  other.unmount();
  const otherApp = render(element(binding, { ...app, applicationId: "other" }));
  await waitFor(() =>
    expect(
      screen.getByLabelText("ApplicationRule Python source editor"),
    ).toHaveValue(source.sourceText),
  );
  otherApp.unmount();
  setDraftIdentity("other-designer");
  const foreign = render(element());
  await waitFor(() =>
    expect(
      screen.getByLabelText("ApplicationRule Python source editor"),
    ).toHaveValue(source.sourceText),
  );
  foreign.unmount();
  setDraftIdentity("designer");
  render(element());
  await waitFor(() =>
    expect(
      screen.getByLabelText("ApplicationRule Python source editor"),
    ).toHaveValue("unsaved exact next source"),
  );
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Save and validate source" }),
    ).toBeEnabled(),
  );
});

const diagnostic = {
  format: "openepm-diagnostics-v1",
  positionEncoding: "utf-16",
  sourceDigest: digest,
  truncated: false,
  diagnostics: [
    {
      code: "MEMBER_UNKNOWN",
      severity: "error",
      stage: "semantic",
      message: "Choose an available member",
      path: "operations[0]",
    },
  ],
};
const approvedEnvironments = {
  environments: [
    {
      environment_id: "approved",
      state_token: "d".repeat(64),
      status: "Active",
    },
  ],
  nextAfterEnvironmentId: null,
};

it.each(["worker", "synchronous"] as const)(
  "preserves authored source and binds exact %s diagnostics to the typed editor",
  async (delivery) => {
    const calls: any[] = [];
    vi.stubGlobal("confirm", vi.fn());
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_url, init) => {
        const body = JSON.parse(init.body);
        calls.push(body);
        if (body.program?.function === "python.environment.list")
          return response(approvedEnvironments);
        if (body.program?.function === "python.program.save") {
          if (delivery === "synchronous")
            return new Response(
              JSON.stringify({
                code: "PYTHON_SOURCE_VALIDATION_FAILED",
                details: diagnostic,
              }),
              { status: 400 },
            );
          return response({
            stateToken: source.stateToken,
            sourceToken: source.sourceToken,
            status: "Inactive",
            sourceDigest: digest,
            validation: {
              buildId: "saved-validation",
              purpose: "Validation",
              status: "accepted",
            },
          });
        }
        if (body.action === "read")
          return response({
            buildId: "saved-validation",
            purpose: "Validation",
            status: "failed",
            diagnostics: diagnostic,
          });
        if (body.program?.function === "python.program.read")
          return response({
            ...source,
            status: "Inactive",
            active: false,
            executable: false,
            reason: "inactive",
          });
        throw new Error(`Unexpected ${JSON.stringify(body)}`);
      }),
    );
    installOperationAdmissionFixture("e");
    render(
      <PythonDefinitionEditor
        app={app}
        catalog={catalog}
        kind="ApplicationRule"
        template={source.sourceText}
      />,
    );
    fireEvent.change(screen.getByLabelText("ApplicationRule source ID"), {
      target: { value: "source" },
    });
    const save = screen.getByRole("button", {
      name: "Save and validate source",
    });
    await waitFor(() => expect(save).toBeEnabled());
    fireEvent.click(save);
    const editor = screen.getByLabelText(
      "ApplicationRule Python source editor",
    );
    await waitFor(() =>
      expect(editor).toHaveAttribute(
        "data-diagnostics",
        JSON.stringify(diagnostic),
      ),
    );
    expect(editor).toHaveValue(source.sourceText);
    if (delivery === "worker") {
      await screen.findByText("Validation: failed");
      expect(calls.filter((body) => body.action === "read")).toEqual([
        expect.objectContaining({ buildId: "saved-validation" }),
      ]);
      fireEvent.click(
        screen.getByRole("button", { name: "Edit current source" }),
      );
      await waitFor(() => expect(editor).not.toHaveAttribute("readonly"));
    }
    fireEvent.change(editor, {
      target: { value: `${source.sourceText}# corrected\n` },
    });
    expect(editor).toHaveAttribute("data-diagnostics", "");
    expect(window.confirm).not.toHaveBeenCalled();
    expect(
      calls.find((body) => body.program?.function === "python.program.save")
        .program.arguments,
    ).toMatchObject({
      expectedMetadataRevision: 4,
      expectedPolicyRevision: 2,
      expectedSchemaEpoch: 1,
      definition: { programId: "source", sourceText: source.sourceText },
    });
    expect(
      screen.queryByRole("button", { name: /Run sealed/ }),
    ).not.toBeInTheDocument();
  },
);

it("immediately removes metadata suggestions on security revocation and rejects both stale and late responses", async () => {
  const contextCatalog = {
    ...catalog,
    applicationAccess: {
      ...catalog.applicationAccess,
      issuer: "issuer",
      subjectId: "author",
    },
    functions: { ...catalog.functions, "metadata.authoring.context": {} },
  };
  const metadata = {
    ...app,
    metadataRevision: 4,
    policyRevision: 2,
    securityRevision: 1,
    schemaEpoch: 1,
    authority: { issuer: "issuer", subjectId: "author" },
    references: {
      metadata: {
        ...app,
        metadataRevision: 4,
        authorizationScopeDigest: "a".repeat(64),
        dimensions: [
          {
            dimensionId: "account",
            name: "Account",
            referenceMode: "symbolic",
          },
        ],
      },
    },
  };
  const pending: Array<(value: Response) => void> = [];
  let reads = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(init.body);
      if (body.program?.function === "python.environment.list")
        return response(approvedEnvironments);
      if (body.program?.function === "metadata.authoring.context") {
        if (++reads === 1) return response(metadata);
        return new Promise<Response>((resolve) => pending.push(resolve));
      }
      throw new Error(`Unexpected ${JSON.stringify(body)}`);
    }),
  );
  installOperationAdmissionFixture("2");
  const element = (security: number) => (
    <PythonDefinitionEditor
      app={app}
      catalog={{
        ...contextCatalog,
        revisions: { ...catalog.revisions, security },
      }}
      kind="ApplicationRule"
      template={source.sourceText}
    />
  );
  const view = render(element(1));
  const editor = screen.getByLabelText("ApplicationRule Python source editor");
  await waitFor(() =>
    expect(editor.getAttribute("data-completions")).toContain("Account"),
  );
  view.rerender(element(2));
  expect(editor).toHaveAttribute("data-completions", "[]");
  view.rerender(element(3));
  await act(async () =>
    pending[0](response({ ...metadata, securityRevision: 2 })),
  );
  expect(editor).toHaveAttribute("data-completions", "[]");
  await act(async () => pending[1](response(metadata)));
  expect(editor).toHaveAttribute("data-completions", "[]");
});

it("reopens current source and activates only its exact current typed impact Test without confirmation", async () => {
  const definition = {
    kind: "ApplicationRule",
    definitionId: "definition",
  };
  const testedSource = {
    ...source,
    status: "Inactive",
    active: false,
    executable: false,
    reason: "inactive",
    latestImpactTest: {
      buildId: "exact-impact",
      purpose: "ImpactTest",
      status: "sealed",
      current: true,
      definition,
    },
  };
  const calls: any[] = [];
  let activated = false;
  vi.stubGlobal("confirm", vi.fn());
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(init.body);
      calls.push(body);
      if (body.program?.function === "python.program.read")
        return response({
          ...testedSource,
          status: activated ? "Active" : "Inactive",
          active: activated,
          executable: activated,
          reason: activated ? null : "inactive",
        });
      if (body.program?.function === "python.program.activate") {
        activated = true;
        return response({});
      }
      throw new Error(`Unexpected ${JSON.stringify(body)}`);
    }),
  );
  const changed = vi.fn();
  const element = (context = catalog) => (
    <PythonDefinitionEditor
      app={app}
      catalog={{
        ...context,
        functions: { ...context.functions, "python.program.test": {} },
      }}
      kind="ApplicationRule"
      binding={binding}
      definitionId="definition"
      onChanged={changed}
      onRefreshCatalog={async () => {
        const refreshed = {
          ...context,
          revisions: { ...context.revisions, metadata: 5 },
        };
        view.rerender(element(refreshed));
        return refreshed;
      }}
    />
  );
  installOperationAdmissionFixture("f");
  const view = render(element());
  const activate = await screen.findByRole("button", {
    name: "Activate source",
  });
  await waitFor(() => expect(activate).toBeEnabled());
  const editor = screen.getByLabelText("ApplicationRule Python source editor");
  expect(editor).toHaveValue(source.sourceText);
  expect(editor).toHaveAttribute("readonly");
  fireEvent.click(activate);
  await waitFor(() => expect(changed).toHaveBeenCalledWith(definition));
  expect(
    calls.find((body) => body.program?.function === "python.program.activate")
      .program.arguments,
  ).toMatchObject({
    programId: "source",
    expectedStateToken: source.stateToken,
    validationBuildId: "exact-impact",
  });
  expect(window.confirm).not.toHaveBeenCalled();
});

it.each(["issuer", "subjectId"] as const)(
  "clears an open bound source on a same-application %s switch and rejects its late response",
  async (field) => {
    const currentCatalog = {
      ...catalog,
      applicationAccess: {
        ...catalog.applicationAccess,
        issuer: "issuer-one",
        subjectId: "author-one",
      },
    };
    const pending: Array<(value: Response) => void> = [];
    let reads = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        if (++reads === 1) return response(source);
        return new Promise<Response>((resolve) => pending.push(resolve));
      }),
    );
    const element = (identity: string) => (
      <PythonDefinitionEditor
        app={app}
        catalog={{
          ...currentCatalog,
          applicationAccess: {
            ...currentCatalog.applicationAccess,
            [field]: identity,
          },
        }}
        kind="ApplicationRule"
        binding={binding}
      />
    );
    const initialIdentity = currentCatalog.applicationAccess[field];
    const view = render(element(initialIdentity));
    await screen.findByLabelText("ApplicationRule Python source editor");
    view.rerender(element("identity-two"));
    expect(
      screen.queryByLabelText("ApplicationRule Python source editor"),
    ).not.toBeInTheDocument();
    await waitFor(() => expect(pending).toHaveLength(1));
    view.rerender(element("identity-three"));
    await waitFor(() => expect(pending).toHaveLength(2));
    await act(async () =>
      pending[0](
        response({ ...source, sourceText: "second identity's source" }),
      ),
    );
    expect(
      screen.queryByLabelText("ApplicationRule Python source editor"),
    ).not.toBeInTheDocument();
    await act(async () =>
      pending[1](
        response({
          ...source,
          sourceText: "third identity's authorized source",
        }),
      ),
    );
    expect(
      screen.getByLabelText("ApplicationRule Python source editor"),
    ).toHaveValue("third identity's authorized source");
  },
);

it("hides revoked source while preserving an unsaved draft for an authorized context refresh", async () => {
  const pending: Array<(value: Response) => void> = [];
  let reads = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(init.body);
      if (body.program?.function === "python.environment.list")
        return response(approvedEnvironments);
      if (++reads <= 2) return response(source);
      return new Promise<Response>((resolve) => pending.push(resolve));
    }),
  );
  installOperationAdmissionFixture("1");
  const element = (security: number) => (
    <PythonDefinitionEditor
      app={app}
      catalog={{ ...catalog, revisions: { ...catalog.revisions, security } }}
      kind="ApplicationRule"
      binding={binding}
    />
  );
  const view = render(element(1));
  fireEvent.click(
    await screen.findByRole("button", { name: "Edit current source" }),
  );
  const editor = screen.getByLabelText("ApplicationRule Python source editor");
  await waitFor(() => expect(editor).not.toHaveAttribute("readonly"));
  fireEvent.change(editor, { target: { value: "unsaved authorized draft" } });
  view.rerender(element(2));
  expect(
    screen.queryByLabelText("ApplicationRule Python source editor"),
  ).not.toBeInTheDocument();
  await waitFor(() => expect(pending).toHaveLength(1));
  await act(async () =>
    pending[0](
      new Response(JSON.stringify({ code: "ACCESS_DENIED" }), { status: 403 }),
    ),
  );
  expect(
    screen.queryByLabelText("ApplicationRule Python source editor"),
  ).not.toBeInTheDocument();
  view.rerender(element(3));
  await waitFor(() => expect(pending).toHaveLength(2));
  await act(async () => pending[1](response(source)));
  expect(
    screen.getByLabelText("ApplicationRule Python source editor"),
  ).toHaveValue("unsaved authorized draft");
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Save and validate source" }),
    ).toBeEnabled(),
  );
});

it("releases a pending Save on authority change and ignores its late response", async () => {
  let finish: (value: Response) => void = () => undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(init.body);
      if (body.program?.function === "python.environment.list")
        return response(approvedEnvironments);
      return new Promise<Response>((resolve) => {
        finish = resolve;
      });
    }),
  );
  const element = (security: number) => (
    <PythonDefinitionEditor
      app={app}
      catalog={{ ...catalog, revisions: { ...catalog.revisions, security } }}
      kind="ApplicationRule"
      template={source.sourceText}
    />
  );
  const view = render(element(1));
  fireEvent.change(screen.getByLabelText("ApplicationRule source ID"), {
    target: { value: "source" },
  });
  const save = screen.getByRole("button", { name: "Save and validate source" });
  await waitFor(() => expect(save).toBeEnabled());
  fireEvent.click(save);
  expect(save).toBeDisabled();
  view.rerender(element(2));
  await waitFor(() => expect(save).toBeEnabled());
  await act(async () =>
    finish(
      response({
        stateToken: source.stateToken,
        sourceToken: source.sourceToken,
        status: "Inactive",
        sourceDigest: digest,
        validation: {
          buildId: "old-authority",
          purpose: "Validation",
          status: "accepted",
        },
      }),
    ),
  );
  expect(save).toBeEnabled();
  expect(
    screen.getByLabelText("ApplicationRule Python source editor"),
  ).not.toHaveAttribute("readonly");
  expect(screen.queryByText(/Validation:/)).not.toBeInTheDocument();
});

it("releases a pending bound-source read when opening a new draft", async () => {
  let finish: (value: Response) => void = () => undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      if (JSON.parse(init.body).program?.function === "python.environment.list")
        return response(approvedEnvironments);
      return new Promise<Response>((resolve) => {
        finish = resolve;
      });
    }),
  );
  const view = render(
    <PythonDefinitionEditor
      app={app}
      catalog={catalog}
      kind="ApplicationRule"
      binding={binding}
    />,
  );
  await screen.findByText("Working…");
  view.rerender(
    <PythonDefinitionEditor
      app={app}
      catalog={catalog}
      kind="ApplicationRule"
      template="new draft"
    />,
  );
  fireEvent.change(screen.getByLabelText("ApplicationRule source ID"), {
    target: { value: "new-source" },
  });
  const save = screen.getByRole("button", { name: "Save and validate source" });
  await waitFor(() => expect(save).toBeEnabled());
  await act(async () => finish(response(source)));
  expect(
    screen.getByLabelText("ApplicationRule Python source editor"),
  ).toHaveValue("new draft");
  expect(save).toBeEnabled();
});

it("keeps Save unavailable when its selected environment is no longer approved", async () => {
  let available = true;
  const requests: any[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(init.body);
      requests.push(body);
      return response(
        available
          ? approvedEnvironments
          : { environments: [], nextAfterEnvironmentId: null },
      );
    }),
  );
  const element = (security: number) => (
    <PythonDefinitionEditor
      app={app}
      catalog={{ ...catalog, revisions: { ...catalog.revisions, security } }}
      kind="ApplicationRule"
      template={source.sourceText}
    />
  );
  const view = render(element(1));
  fireEvent.change(screen.getByLabelText("ApplicationRule source ID"), {
    target: { value: "source" },
  });
  const save = screen.getByRole("button", { name: "Save and validate source" });
  await waitFor(() => expect(save).toBeEnabled());
  available = false;
  view.rerender(element(2));
  await waitFor(() => expect(requests).toHaveLength(2));
  expect(save).toBeDisabled();
  fireEvent.click(save);
  expect(
    requests.every(
      (body) => body.program.function === "python.environment.list",
    ),
  ).toBe(true);
});

it("reloads current validation after a restored draft is saved with a new source digest", async () => {
  setDraftIdentity("designer");
  let saved = false;
  const definition = {
    kind: "ApplicationRule",
    definitionId: "definition",
  };
  const accepted = {
    ...source,
    sourceDigest: "e".repeat(64),
    sourceText: "restored replacement",
    sourceToken: "f".repeat(64),
    status: "Inactive",
    active: false,
    executable: false,
    reason: "inactive",
    validation: {
      buildId: "replacement-validation",
      purpose: "Validation",
      status: "sealed",
      current: true,
      definition,
    },
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(init.body);
      if (body.program?.function === "python.environment.list")
        return response(approvedEnvironments);
      if (body.program?.function === "python.program.read")
        return response(saved ? accepted : source);
      if (body.program?.function === "python.program.save") {
        saved = true;
        return response(accepted);
      }
      throw new Error(`Unexpected ${JSON.stringify(body)}`);
    }),
  );
  installOperationAdmissionFixture("3");
  const element = (security: number) => (
    <PythonDefinitionEditor
      app={app}
      catalog={{ ...catalog, revisions: { ...catalog.revisions, security } }}
      kind="ApplicationRule"
      binding={binding}
      definitionId="definition"
    />
  );
  const initial = render(element(1));
  fireEvent.click(
    await screen.findByRole("button", { name: "Edit current source" }),
  );
  await waitFor(() =>
    expect(
      screen.getByLabelText("ApplicationRule Python source editor"),
    ).not.toHaveAttribute("readonly"),
  );
  fireEvent.change(
    screen.getByLabelText("ApplicationRule Python source editor"),
    { target: { value: accepted.sourceText } },
  );
  initial.unmount();
  const restored = render(element(1));
  await waitFor(() =>
    expect(
      screen.getByLabelText("ApplicationRule Python source editor"),
    ).toHaveValue(accepted.sourceText),
  );
  const save = screen.getByRole("button", { name: "Save and validate source" });
  await waitFor(() => expect(save).toBeEnabled());
  fireEvent.click(save);
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Activate source" }),
    ).toBeEnabled(),
  );
  restored.rerender(element(2));
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Activate source" }),
    ).toBeEnabled(),
  );
  expect(
    screen.getByLabelText("ApplicationRule Python source editor"),
  ).toHaveValue(accepted.sourceText);
  expect(
    screen.getByLabelText("ApplicationRule Python source editor"),
  ).toHaveAttribute("readonly");
  expect(screen.getByText("Validation: sealed")).toBeInTheDocument();
});

it("saves a declared group-owned rule and observes the author's validation through source inspection", async () => {
  const calls: Array<{
    url: string;
    program?: { function: string; arguments: Record<string, unknown> };
  }> = [];
  const validation = {
    buildId: "a".repeat(32),
    purpose: "Validation",
    status: "accepted",
  };
  const functions = Object.fromEntries(
    [
      "python.program.save",
      "python.program.read",
      "python.environment.list",
    ].map((name) => [name, {}]),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn<typeof fetch>(async (url, init) => {
      const body = JSON.parse(String(init?.body));
      calls.push({ url: String(url), program: body.program });
      if (body.program?.function === "python.environment.list")
        return response({
          environments: [
            {
              environment_id: "approved",
              state_token: digest,
              status: "Active",
            },
          ],
          nextAfterEnvironmentId: null,
        });
      if (body.program?.function === "python.program.save")
        return response({
          stateToken: source.stateToken,
          sourceToken: source.sourceToken,
          status: "Inactive",
          sourceDigest: digest,
          validation,
        });
      if (body.program?.function === "python.program.read")
        return response({
          defined: true,
          programId: "press-rule",
          validation: {
            ...validation,
            status: "sealed",
            current: true,
            ownedByCaller: true,
          },
        });
      throw new Error("Unexpected request");
    }),
  );
  installOperationAdmissionFixture("e");
  render(
    <PythonDefinitionEditor
      app={app}
      catalog={{
        ...catalog,
        functions,
        applicationAccess: {
          role: "Assigned",
          workspaceAdministrator: false,
          authorizationModel: "group_assignments",
        },
      }}
      kind="ApplicationRule"
      template={source.sourceText}
    />,
  );
  fireEvent.change(screen.getByLabelText("ApplicationRule source ID"), {
    target: { value: "press-rule" },
  });
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Save and validate source" }),
    ).toBeEnabled(),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Save and validate source" }),
  );
  await screen.findByText("Validation: sealed");
  expect(
    calls.find((c) => c.program?.function === "python.program.save")?.program
      ?.arguments.definition,
  ).toMatchObject({
    programId: "press-rule",
    declaredOutput: { kind: "ApplicationRule", definitionId: "press-rule" },
  });
  expect(calls.filter((c) => c.url === "/api/python-build")).toHaveLength(0);
  expect(
    screen.queryByRole("button", { name: "Refresh compiled definition" }),
  ).toBeNull();
});
