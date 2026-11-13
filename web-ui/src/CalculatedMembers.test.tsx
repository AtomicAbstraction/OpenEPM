import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import axe from "axe-core";
import { afterEach, expect, it, vi } from "vitest";
import {
  CalculatedMembers,
  exactCalculatedMemberDetail,
} from "./CalculatedMembers";

afterEach(() => vi.unstubAllGlobals());

const digest = "d".repeat(64);
const target = {
  definitionId: "margin.calculated",
  stateToken: "b".repeat(64),
  digest,
};
const detail = {
  defined: true,
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

it("shows authorized calculation reasons and requests a bounded affected-work explanation", async () => {
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
  expect(await screen.findByText("data_changed")).toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("button", { name: "Explain affected work" }),
  );
  expect(
    await screen.findByLabelText("Affected-work explanation"),
  ).toHaveTextContent('"affectedUnitCount": 1');
});

it("does not issue an unauthorized calculated-member read", () => {
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
  expect(screen.getByRole("alert")).toHaveTextContent("not authorized");
  expect(fetch).not.toHaveBeenCalled();
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
it("reopens an inactive source-bound calculated member as Python with compiled JSON behind inspection", async () => {
  const value = {
    ...detail,
    status: "Saved",
    source: {
      programId: "calculation-source",
      sourceToken: "c".repeat(64),
      sourceDigest: "b".repeat(64),
      buildId: "build",
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
      target={target}
    />,
  );
  expect(
    await screen.findByLabelText("Inline Python source"),
  ).toHaveTextContent("CalculatedMember: calculation-source");
  expect(
    screen.getByText("Compiled calculation inspection").closest("details"),
  ).not.toHaveAttribute("open");
  expect(
    screen.getByLabelText("Calculated-member expression").closest("details"),
  ).not.toHaveAttribute("open");
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
