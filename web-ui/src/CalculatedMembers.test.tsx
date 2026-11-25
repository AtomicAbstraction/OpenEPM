import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import axe from "axe-core";
import { afterEach, expect, it, vi } from "vitest";
import {
  CalculatedMembers,
  exactCalculatedMemberDetail,
  readableCalculationLabel,
} from "./CalculatedMembers";

afterEach(() => vi.unstubAllGlobals());

const digest = "d".repeat(64);
const target = {
  definitionId: "margin.calculated",
  stateToken: "b".repeat(64),
  digest,
};
const activeLifecycle = {
  defined: true,
  status: "Active",
  valid: true,
  active: true,
  sourceCurrent: true,
  executable: true,
  reason: null,
};
const awaitingValidation = {
  ...activeLifecycle,
  status: "Inactive",
  valid: false,
  active: false,
  executable: false,
  reason: "validation_required",
};
const detail = {
  ...activeLifecycle,
  source: null,
  definitionId: target.definitionId,
  stateToken: target.stateToken,
  status: "Active",
  programDigest: digest,
  program: {
    function: "calculated.member.definition",
    arguments: {
      format: "openepm-calculated-member-v1",
      definitionId: target.definitionId,
      name: "Margin",
      evaluation: "materialized",
      sourceSelection: { dimensions: [] },
      expression: { op: "Subtract" },
      dependencies: [{ definitionId: "revenue.calculated" }],
      resultKey: "margin.result",
      target: { dimensionId: "Account", memberId: "Margin" },
      resultUnit: "amount",
      maxSourceCells: 1000,
      maxOutputCells: 100,
    },
  },
  definitionMetadataRevision: 7,
  currentMetadataRevision: 7,
  updatedAt: "2026-11-06T12:00:00+00:00",
  policyRevision: 3,
};

const inventoryCatalog = {
  applicationAccess: { role: "Reader", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: {
    "calculated.member.read": {},
    "calculated.member.list": {},
  },
  revisions: { metadata: 7, data: 1, policy: 3, security: 1, commit: 12 },
};
const inventoryApp = {
  workspaceId: "ws",
  applicationId: "alpha",
  name: "Alpha",
  status: "Active",
};
function inventoryResponse(definitionId?: string) {
  return new Response(
    JSON.stringify({
      result: {
        rows: definitionId
          ? [
              {
                ...activeLifecycle,
                definitionId,
                stateToken: "b".repeat(64),
                status: "Active",
                programDigest: digest,
                evaluation: "materialized",
                dependencies: [],
                metadataCurrent: true,
                definitionMetadataRevision: 7,
                target: { dimensionId: "Account", memberId: "Margin" },
                resultUnit: "amount",
              },
            ]
          : [],
        metadataRevision: 7,
        policyRevision: 3,
        hasMore: false,
        nextAfterDefinitionId: null,
      },
    }),
  );
}

it("distinguishes loading, a successful empty inventory and a failed refresh", async () => {
  let resolve!: (response: Response) => void;
  const fetchMock = vi
    .fn()
    .mockImplementationOnce(
      () =>
        new Promise<Response>((done) => {
          resolve = done;
        }),
    )
    .mockResolvedValueOnce(
      new Response(JSON.stringify({ code: "LIST_READ_REJECTED" }), {
        status: 400,
      }),
    );
  vi.stubGlobal("fetch", fetchMock);
  render(<CalculatedMembers app={inventoryApp} catalog={inventoryCatalog} />);
  expect(screen.getByRole("status")).toHaveTextContent(
    "Loading current calculated members",
  );
  expect(screen.queryByText("No calculated members")).not.toBeInTheDocument();
  await act(async () => resolve(inventoryResponse()));
  expect(await screen.findByText("No calculated members")).toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("button", { name: "Refresh calculated members" }),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "LIST_READ_REJECTED",
  );
  expect(screen.queryByText("No calculated members")).not.toBeInTheDocument();
});

it("discards an old application's late inventory response after switching scope", async () => {
  let resolveOld!: (response: Response) => void;
  let oldSignal: AbortSignal | undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input, init) => {
      const body = JSON.parse(init.body);
      if (body.applicationId === "alpha") {
        oldSignal = init.signal;
        return new Promise<Response>((done) => {
          resolveOld = done;
        });
      }
      return inventoryResponse("beta.calculation");
    }),
  );
  const view = render(
    <CalculatedMembers app={inventoryApp} catalog={inventoryCatalog} />,
  );
  await waitFor(() => expect(resolveOld).toBeDefined());
  view.rerender(
    <CalculatedMembers
      app={{ ...inventoryApp, applicationId: "beta" }}
      catalog={inventoryCatalog}
    />,
  );
  expect(
    await screen.findByRole("button", {
      name: "Open current beta.calculation",
    }),
  ).toBeInTheDocument();
  expect(oldSignal?.aborted).toBe(true);
  await act(async () => resolveOld(inventoryResponse("alpha.calculation")));
  expect(screen.queryByText("alpha.calculation")).not.toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Open current beta.calculation" }),
  ).toBeInTheDocument();
});

it.each([
  [409, "RULE_READ_AUTHORIZATION_STALE"],
  [403, "APPLICATION_GRANT_REQUIRED"],
] as const)(
  "hides the previous inventory during refresh and after %s %s",
  async (status, code) => {
    let reads = 0;
    let finish!: (response: Response) => void;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        if (++reads === 1) return inventoryResponse("previous.calculation");
        if (reads === 2)
          return new Promise<Response>((resolve) => {
            finish = resolve;
          });
        return inventoryResponse("current.calculation");
      }),
    );
    render(<CalculatedMembers app={inventoryApp} catalog={inventoryCatalog} />);
    await screen.findByRole("button", {
      name: "Open current previous.calculation",
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Refresh calculated members" }),
    );
    expect(
      screen.getByText("Loading current calculated members…"),
    ).toBeVisible();
    expect(screen.queryByText("previous.calculation")).toBeNull();
    await act(async () =>
      finish(new Response(JSON.stringify({ code }), { status })),
    );
    expect(await screen.findByRole("alert")).toBeVisible();
    expect(screen.queryByText("previous.calculation")).toBeNull();
    expect(screen.queryByText("No calculated members")).toBeNull();
    fireEvent.click(
      screen.getByRole("button", { name: "Refresh calculated members" }),
    );
    expect(
      await screen.findByRole("button", {
        name: "Open current current.calculation",
      }),
    ).toBeVisible();
  },
);

it("focuses an opened definition and restores its inventory trigger on close", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input, init) => {
      const body = JSON.parse(init.body);
      return body.program.function === "calculated.member.list"
        ? inventoryResponse(target.definitionId)
        : new Response(JSON.stringify({ result: detail }));
    }),
  );
  render(<CalculatedMembers app={inventoryApp} catalog={inventoryCatalog} />);
  const trigger = await screen.findByRole("button", {
    name: "Open current margin.calculated",
  });
  fireEvent.click(trigger);
  const heading = await screen.findByRole("heading", {
    name: "margin.calculated",
  });
  await waitFor(() => expect(heading).toHaveFocus());
  expect(trigger).toHaveAttribute("aria-expanded", "true");
  fireEvent.click(screen.getByRole("button", { name: "Close definition" }));
  expect(trigger).toHaveFocus();
  expect(trigger).toHaveAttribute("aria-expanded", "false");
  expect(
    screen.queryByLabelText("Calculated member detail"),
  ).not.toBeInTheDocument();
});

it("rejects substituted calculated-member identity, state and digest", () => {
  for (const changed of [
    { ...detail, definitionId: "other.calculated" },
    { ...detail, stateToken: "c".repeat(64) },
    { ...detail, programDigest: "e".repeat(64) },
    {
      ...detail,
      program: { ...detail.program, function: "application.rule.plan" },
    },
  ])
    expect(() => exactCalculatedMemberDetail(changed, target)).toThrow(
      "INVALID_CALCULATED_MEMBER_RESPONSE",
    );
});

it("rejects malformed calculated-member results", () => {
  for (const changed of [
    {
      ...detail,
      program: {
        ...detail.program,
        arguments: { ...detail.program.arguments, resultKey: null },
      },
    },
    {
      ...detail,
      program: {
        ...detail.program,
        arguments: {
          ...detail.program.arguments,
          target: { dimensionId: "Account", memberId: "Margin", extra: true },
        },
      },
    },
    { ...detail, updatedAt: "not-a-timestamp" },
  ])
    expect(() => exactCalculatedMemberDetail(changed, target)).toThrow(
      "INVALID_CALCULATED_MEMBER_RESPONSE",
    );
});

it("reads and explains the exact authorized calculated-member definition", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      expect(body.program).toEqual({
        languageVersion: 2,
        function: "calculated.member.read",
        arguments: { definitionId: target.definitionId },
      });
      return new Response(JSON.stringify({ result: detail }));
    }),
  );
  const rendered = render(
    <CalculatedMembers
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      }}
      catalog={{
        applicationAccess: { role: "Reader", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: { "calculated.member.read": {} },
        revisions: {
          metadata: 7,
          data: 1,
          policy: 3,
          security: 1,
          commit: 12,
        },
      }}
      target={target}
    />,
  );
  const inspector = await screen.findByLabelText("Calculated member detail");
  expect(inspector).toHaveTextContent("margin.calculated");
  expect(inspector).toHaveTextContent("revenue.calculated");
  expect(inspector).toHaveTextContent("Stored calculation result");
  expect(inspector).toHaveTextContent(
    "current calculation scope and a bounded server explanation",
  );
  expect(screen.getByRole("status")).toHaveTextContent(
    "Calculated-member definition loaded",
  );
  expect(
    (
      await axe.run(rendered.container, {
        rules: { "color-contrast": { enabled: false } },
      })
    ).violations,
  ).toEqual([]);
});

it("shows a bounded impact explanation without exposing backend identities", async () => {
  const bindingDigest = "b".repeat(64);
  const fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body));
    if (body.program.function === "calculated.member.read")
      return new Response(JSON.stringify({ result: detail }));
    if (body.program.function === "calculation.status.read")
      return new Response(
        JSON.stringify({
          result: {
            rows: [
              {
                bindingDigest,
                stage: "materialize",
                partitionKey: "Europe",
                freshness: "stale",
                coverage: "complete",
                presence: "present",
                reasons: ["data_changed"],
                requiredEpoch: 2,
                publishedEpoch: 1,
              },
            ],
            nextAfter: null,
            impactBarrier: { pending: false },
          },
        }),
      );
    expect(body.program.function).toBe("calculation.impact.explain");
    expect(body.program.arguments).toEqual({
      bindingDigest,
      mode: "affected",
    });
    return new Response(
      JSON.stringify({
        result: {
          format: "openepm-calculation-impact-explain-v1",
          affectedUnitCount: 1,
          planDigest: "c".repeat(64),
        },
      }),
    );
  });
  vi.stubGlobal("fetch", fetch);
  render(
    <CalculatedMembers
      app={inventoryApp}
      target={target}
      catalog={{
        ...inventoryCatalog,
        functions: {
          "calculated.member.read": {},
          "calculation.status.read": {},
          "calculation.impact.explain": {},
        },
      }}
    />,
  );
  expect(await screen.findByText("Data changed")).toBeInTheDocument();
  expect(screen.getByText("Europe")).toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("button", { name: "Explain affected work" }),
  );
  expect(
    await screen.findByLabelText("Affected-work explanation"),
  ).toHaveTextContent("1 calculation scope is affected.");
  expect(screen.queryByText("c".repeat(64))).not.toBeInTheDocument();
  expect(
    screen.queryByText("Compiled calculation inspection"),
  ).not.toBeInTheDocument();
});

it("suppresses opaque calculation labels while preserving business scope names", () => {
  expect(readableCalculationLabel("Europe")).toBe("Europe");
  expect(readableCalculationLabel("data_changed")).toBe("Data changed");
  expect(readableCalculationLabel("a".repeat(64))).toBe(
    "Current calculation scope",
  );
  expect(readableCalculationLabel(`oa1_x_${"A".repeat(43)}`)).toBe(
    "Current calculation scope",
  );
});

it("does not read an unavailable calculated-member function or infer denial", () => {
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  render(
    <CalculatedMembers
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      }}
      catalog={{
        applicationAccess: { role: "Reader", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: {},
        revisions: {
          metadata: 1,
          data: 1,
          policy: 1,
          security: 1,
          commit: 1,
        },
      }}
      target={target}
    />,
  );
  expect(screen.getByRole("status")).toHaveTextContent(
    "Calculated-member inspection is not available in the current application context",
  );
  expect(fetch).not.toHaveBeenCalled();
});

it("distinguishes catalogue loading from unavailable functions and verified server denial", async () => {
  const fetch = vi.fn(
    async () =>
      new Response(JSON.stringify({ code: "APPLICATION_ACCESS_DENIED" }), {
        status: 403,
      }),
  );
  vi.stubGlobal("fetch", fetch);
  const view = render(
    <CalculatedMembers app={inventoryApp} catalog={null} target={target} />,
  );
  expect(screen.getByRole("status")).toHaveTextContent(
    "Checking calculated-member availability",
  );
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  expect(fetch).not.toHaveBeenCalled();
  view.rerender(
    <CalculatedMembers
      app={inventoryApp}
      catalog={{
        ...inventoryCatalog,
        functions: { "calculated.member.read": {} },
      }}
      target={target}
    />,
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "APPLICATION_ACCESS_DENIED",
  );
});

it("discards old inventory on an in-place grant change even when both functions remain available", async () => {
  let finish!: (value: Response) => void;
  let signal: AbortSignal | undefined;
  let reads = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_path, init) => {
      if (++reads === 1) {
        signal = init.signal;
        return new Promise<Response>((done) => {
          finish = done;
        });
      }
      return inventoryResponse("current.calculation");
    }),
  );
  const view = render(
    <CalculatedMembers app={inventoryApp} catalog={inventoryCatalog} />,
  );
  await waitFor(() => expect(finish).toBeDefined());
  view.rerender(
    <CalculatedMembers
      app={inventoryApp}
      catalog={{
        ...inventoryCatalog,
        revisions: { ...inventoryCatalog.revisions, security: 2 },
      }}
    />,
  );
  expect(await screen.findByText("current.calculation")).toBeInTheDocument();
  expect(signal?.aborted).toBe(true);
  await act(async () => finish(inventoryResponse("old.private.calculation")));
  expect(screen.queryByText("old.private.calculation")).not.toBeInTheDocument();
  expect(reads).toBe(2);
});

it("does not claim empty status while loading or install status returned under a former grant", async () => {
  let finish!: (value: Response) => void;
  let oldSignal: AbortSignal | undefined;
  let statusReads = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_path, init) => {
      const fn = JSON.parse(init.body).program.function;
      if (fn === "calculated.member.read")
        return new Response(JSON.stringify({ result: detail }));
      expect(fn).toBe("calculation.status.read");
      if (++statusReads === 1) {
        oldSignal = init.signal;
        return new Promise<Response>((done) => {
          finish = done;
        });
      }
      return new Response(
        JSON.stringify({
          result: {
            rows: [],
            nextAfter: null,
            impactBarrier: { pending: false },
          },
        }),
      );
    }),
  );
  const current = {
    ...inventoryCatalog,
    functions: { "calculated.member.read": {}, "calculation.status.read": {} },
  };
  const view = render(
    <CalculatedMembers app={inventoryApp} catalog={current} target={target} />,
  );
  expect(
    await screen.findByText("Loading calculation status…"),
  ).toBeInTheDocument();
  expect(
    screen.queryByText(
      "No materialized calculation scope exists for this definition.",
    ),
  ).not.toBeInTheDocument();
  view.rerender(
    <CalculatedMembers
      app={inventoryApp}
      catalog={{ ...current, revisions: { ...current.revisions, security: 2 } }}
      target={target}
    />,
  );
  expect(
    await screen.findByText(
      "No materialized calculation scope exists for this definition.",
    ),
  ).toBeInTheDocument();
  expect(oldSignal?.aborted).toBe(true);
  await act(async () =>
    finish(
      new Response(
        JSON.stringify({
          result: {
            rows: [
              {
                bindingDigest: "b".repeat(64),
                stage: "materialize",
                partitionKey: "Former private scope",
                freshness: "stale",
                coverage: "complete",
                presence: "present",
                reasons: [],
                requiredEpoch: 2,
                publishedEpoch: 1,
              },
            ],
            nextAfter: null,
            impactBarrier: { pending: false },
          },
        }),
      ),
    ),
  );
  expect(screen.queryByText("Former private scope")).not.toBeInTheDocument();
});
vi.mock("./PythonDefinitionEditor", () => ({
  PythonDefinitionEditor: ({
    kind,
    binding,
  }: {
    kind: string;
    binding?: { programId: string };
  }) => (
    <div aria-label="Inline Python source">
      {kind}: {binding?.programId || "new"}
    </div>
  ),
}));
it("reopens an inactive source-bound calculated member as Python without a duplicate compiled payload", async () => {
  const value = {
    ...detail,
    ...awaitingValidation,
    program: null,
    programDigest: null,
    source: {
      programId: "calculation-source",
      programSourceToken: "c".repeat(64),
      sourceDigest: "b".repeat(64),
      buildId: null,
      active: false,
    },
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) =>
      JSON.parse(init.body).program.function.endsWith(".list")
        ? inventoryResponse()
        : new Response(JSON.stringify({ result: value })),
    ),
  );
  render(
    <CalculatedMembers
      app={inventoryApp}
      catalog={inventoryCatalog}
      target={{ ...target, digest: null }}
    />,
  );
  expect(
    await screen.findByLabelText("Inline Python source"),
  ).toHaveTextContent("CalculatedMember: calculation-source");
  expect(
    screen.queryByText("Compiled calculation inspection"),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByLabelText("Calculated-member expression"),
  ).not.toBeInTheDocument();
  expect(screen.getByLabelText("Calculated member detail")).toHaveTextContent(
    "Inactive · Current definition validation required",
  );
  expect(
    screen.getByText(/Current compiled details are unavailable/),
  ).toBeVisible();
  expect(
    screen.queryByText("No calculated-member dependencies."),
  ).not.toBeInTheDocument();
});
it("guards the new calculated member source editor transition", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => inventoryResponse()),
  );
  const transition = vi.fn();
  render(
    <CalculatedMembers
      app={inventoryApp}
      catalog={{
        ...inventoryCatalog,
        functions: {
          ...inventoryCatalog.functions,
          "python.program.save": {},
          "python.environment.list": {},
        },
      }}
      onRequestTransition={transition}
    />,
  );
  fireEvent.click(
    screen.getByRole("button", { name: "New calculated member" }),
  );
  expect(
    screen.queryByLabelText("Inline Python source"),
  ).not.toBeInTheDocument();
  await act(async () => transition.mock.calls[0][0]());
  expect(screen.getByLabelText("Inline Python source")).toHaveTextContent(
    "CalculatedMember: new",
  );
});

it("opens a native uncompiled inventory owner and keeps result inspection separate", async () => {
  const summary = {
    ...awaitingValidation,
    definitionId: target.definitionId,
    stateToken: target.stateToken,
    programDigest: null,
    metadataCurrent: true,
    definitionMetadataRevision: 7,
  };
  const value = {
    ...detail,
    ...awaitingValidation,
    program: null,
    programDigest: null,
    source: {
      programId: "calculation-source",
      programSourceToken: "c".repeat(64),
      sourceDigest: "b".repeat(64),
      buildId: null,
      active: false,
    },
  };
  const fetch = vi.fn(async (_path, init) => {
    const body = JSON.parse(init.body);
    let result;
    if (body.program.function === "calculated.member.list")
      result = {
        rows: [summary],
        metadataRevision: 7,
        policyRevision: 3,
        hasMore: false,
        nextAfterDefinitionId: null,
      };
    else if (body.program.function === "calculated.member.read") result = value;
    else {
      expect(body.program.function).toBe("calculation.status.read");
      expect(body.program.arguments).toEqual({
        definitionId: target.definitionId,
        definitionStateToken: target.stateToken,
        limit: 500,
      });
      result = { rows: [], nextAfter: null, impactBarrier: { pending: false } };
    }
    return new Response(JSON.stringify({ result }));
  });
  vi.stubGlobal("fetch", fetch);
  render(
    <CalculatedMembers
      app={inventoryApp}
      catalog={{
        ...inventoryCatalog,
        functions: {
          ...inventoryCatalog.functions,
          "calculation.status.read": {},
        },
      }}
    />,
  );
  const trigger = await screen.findByRole("button", {
    name: "Open current margin.calculated",
  });
  const inventory = screen.getByRole("table", {
    name: "Current calculated members",
  });
  expect(inventory).toHaveTextContent("Inactive");
  expect(inventory).toHaveTextContent("Current definition validation required");
  expect(
    within(inventory).getAllByText("Compiled details unavailable"),
  ).toHaveLength(2);
  fireEvent.change(
    screen.getByRole("textbox", { name: "Find a calculated member" }),
    { target: { value: "margin" } },
  );
  fireEvent.click(trigger);
  expect(
    await screen.findByLabelText("Inline Python source"),
  ).toHaveTextContent("calculation-source");
  expect(
    await screen.findByText(
      "No materialized calculation scope exists for this definition.",
    ),
  ).toBeVisible();
  expect(fetch).toHaveBeenCalledTimes(3);
});

it.each([
  ["metadata_stale", "Revalidation required · application metadata changed"],
  ["schema_stale", "Revalidation required · application schema changed"],
  [
    "dependency_stale",
    "Revalidation required · definition dependencies changed",
  ],
  [
    "source_environment_stale",
    "Revalidation required · source environment changed",
  ],
  [
    "compiler_unavailable",
    "Revalidation required · accepted compiler unavailable",
  ],
])(
  "explains active but invalid owner state %s independently of metadata",
  async (reason, label) => {
    const value = {
      ...detail,
      valid: false,
      executable: false,
      reason,
      ...(reason === "metadata_stale" ? { currentMetadataRevision: 8 } : {}),
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ result: value }))),
    );
    render(
      <CalculatedMembers
        app={inventoryApp}
        catalog={{
          ...inventoryCatalog,
          functions: { "calculated.member.read": {} },
        }}
        target={target}
      />,
    );
    const inspector = await screen.findByLabelText("Calculated member detail");
    expect(inspector).toHaveTextContent(`Active · ${label}`);
    expect(inspector).toHaveTextContent(
      reason === "metadata_stale" ? "Metadata changed" : "Metadata current",
    );
    expect(inspector).not.toHaveTextContent("Executable");
    expect(inspector).toHaveTextContent("revenue.calculated");
  },
);

it.each([
  { status: "Inactive", active: false, executable: false, reason: "inactive" },
  {
    status: "Unavailable",
    valid: false,
    active: false,
    sourceCurrent: false,
    executable: false,
    reason: "ownership_unresolved",
  },
])("accepts the native $status lifecycle without rewriting it", (lifecycle) => {
  const value = { ...detail, ...lifecycle };
  expect(exactCalculatedMemberDetail(value, target)).toBe(value);
});

it("rejects inconsistent lifecycle, payload and source binding instead of inventing a fallback", () => {
  const invalid = [
    { ...detail, status: "Saved" },
    { ...detail, reason: "diagnostic_build_expired" },
    { ...detail, valid: false },
    { ...detail, program: null },
    { ...detail, programDigest: null },
    { ...detail, program: null, programDigest: null },
    {
      ...detail,
      program: null,
      programDigest: null,
      valid: false,
      executable: false,
      reason: "dependency_stale",
    },
    { ...detail, defined: false },
    {
      ...detail,
      source: {
        programId: "source",
        programSourceToken: "c".repeat(64),
        sourceDigest: "b".repeat(64),
        buildId: null,
        active: false,
      },
    },
    {
      ...detail,
      source: {
        programId: "source",
        sourceToken: "c".repeat(64),
        sourceDigest: "b".repeat(64),
        buildId: null,
        active: true,
      },
    },
    {
      ...detail,
      status: "Unavailable",
      valid: false,
      active: false,
      sourceCurrent: false,
      executable: false,
      reason: "ownership_unresolved",
      source: {
        programId: "source",
        programSourceToken: "c".repeat(64),
        sourceDigest: "b".repeat(64),
        buildId: null,
        active: false,
      },
    },
  ];
  for (const value of invalid)
    expect(() =>
      exactCalculatedMemberDetail(value, {
        ...target,
        digest: value.programDigest,
      }),
    ).toThrow("INVALID_CALCULATED_MEMBER_RESPONSE");
  const missing = { ...detail } as Record<string, unknown>;
  delete missing.executable;
  expect(() => exactCalculatedMemberDetail(missing, target)).toThrow(
    "INVALID_CALCULATED_MEMBER_RESPONSE",
  );
  const replaced = {
    ...detail,
    ...awaitingValidation,
    program: null,
    programDigest: null,
  };
  expect(() => exactCalculatedMemberDetail(replaced, target)).toThrow(
    "INVALID_CALCULATED_MEMBER_RESPONSE",
  );
});

it.each([
  "retained_target",
  "valid_without_payload",
  "missing_axis",
  "legacy_status",
  "stale_without_payload",
])(
  "rejects a malformed inventory lifecycle (%s) without claiming empty",
  async (fault) => {
    const summary: Record<string, unknown> = {
      ...awaitingValidation,
      definitionId: target.definitionId,
      stateToken: target.stateToken,
      programDigest: null,
      metadataCurrent: true,
      definitionMetadataRevision: 7,
    };
    if (fault === "retained_target")
      summary.target = { dimensionId: "Account", memberId: "Old" };
    else if (fault === "valid_without_payload")
      Object.assign(summary, activeLifecycle);
    else if (fault === "missing_axis") delete summary.sourceCurrent;
    else if (fault === "stale_without_payload")
      summary.reason = "metadata_stale";
    else summary.status = "Saved";
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              result: {
                rows: [summary],
                metadataRevision: 7,
                policyRevision: 3,
                hasMore: false,
                nextAfterDefinitionId: null,
              },
            }),
          ),
      ),
    );
    render(<CalculatedMembers app={inventoryApp} catalog={inventoryCatalog} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "INVALID_CALCULATED_MEMBER_LIST_RESPONSE",
    );
    expect(screen.queryByText("No calculated members")).not.toBeInTheDocument();
  },
);
