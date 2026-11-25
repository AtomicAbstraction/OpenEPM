import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, onTestFinished, vi } from "vitest";
import * as exactCellMutation from "./exact-cell-mutation";
import {
  Analyze,
  aggregateQueryIntent,
  aggregateReadProgram,
  aggregateRequestProgram,
  buildScanArguments,
  buildWritebackProgram,
  canOpenSavedGrid,
  collectAnalyzeDimensions,
  collectAnalyzeMembers,
  collectGenericTables,
  collectSavedGrids,
  cubeViewRowsToCells,
  genericSnapshotArguments,
  genericTableListArguments,
  genericValueText,
  gridDensityStorageKey,
  gridKeyTarget,
  hasResolvedNextPage,
  resolvedGridProgram,
  resolvedReadStatus,
  resolvedRowsToCells,
  resolvedPageCells,
  cellClass,
  cellPresence,
  cellValue,
  savedGridDeleteProgram,
  savedGridListArguments,
  savedGridSaveProgram,
} from "./Analyze";
import { operationAdmissionResponse } from "./test-setup";
import { unsavedWorkSnapshot } from "./unsaved-work";

it("waits for the catalogue and describes omitted metadata reads without a permission claim", () => {
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  const app = {
    workspaceId: "w",
    applicationId: "a",
    name: "Model",
    status: "Active",
  };
  const view = render(
    <Analyze app={app} catalog={null} index={0} subject="reader" />,
  );
  expect(screen.getByLabelText("Grid read unavailable")).toHaveTextContent(
    "Checking grid availability",
  );
  expect(fetch).not.toHaveBeenCalled();
  view.rerender(
    <Analyze
      app={app}
      catalog={{
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: true,
        },
        enabledCapabilities: [],
        functions: {},
        revisions: { metadata: 1, data: 1, security: 1, policy: 1, commit: 1 },
      }}
      index={0}
      subject="reader"
    />,
  );
  expect(screen.getByLabelText("Grid read unavailable")).toHaveTextContent(
    "Model metadata is not available in the current application context",
  );
  expect(
    screen.queryByText(/current role cannot|not authorized/),
  ).not.toBeInTheDocument();
  expect(fetch).not.toHaveBeenCalled();
});

it.each(["initial mount", "application switch"])(
  "initializes an exact native read from the loaded catalogue after %s",
  async (entry) => {
    const calls: any[] = [];
    const response = (result: unknown) =>
      new Response(JSON.stringify({ result }));
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_path, init) => {
        const body = JSON.parse(String(init?.body));
        calls.push(body);
        if (body.program.function === "metadata.dimension.list")
          return savedViewDimensions();
        if (body.program.function === "metadata.member.list")
          return response({
            rows: ["Cash", "Receivables"].map((member_id) => ({
              member_id,
              name: member_id,
              status: "Active",
            })),
            metadataRevision: 11,
            nextAfterMemberId: null,
          });
        if (body.program.function === "facts.cube.resolved.read")
          return response({
            rows: [],
            snapshot: { commitRevision: 9 },
            stages: [],
            presentation: {
              pageSize: 100,
              rowCount: 0,
              suppression: { missing: false, zero: false },
            },
          });
        throw new Error(`Unexpected ${body.program.function}`);
      }),
    );
    const catalog = {
      ...savedViewCatalog(),
      functions: {
        "metadata.dimension.list": {},
        "metadata.member.list": {},
        "facts.cube.resolved.read": {},
      },
    };
    const nextApp = { ...savedViewApp, applicationId: "next-app" };
    const view = render(
      <Analyze
        app={savedViewApp}
        catalog={entry === "initial mount" ? null : catalog}
        index={0}
        subject="owner"
      />,
    );
    if (entry === "application switch") {
      await waitFor(() =>
        expect(screen.getByLabelText("Value semantics")).toHaveValue("own"),
      );
      fireEvent.change(screen.getByLabelText("Value semantics"), {
        target: { value: "stored" },
      });
      view.rerender(
        <Analyze app={nextApp} catalog={null} index={1} subject="owner" />,
      );
    }
    expect(screen.getByLabelText("Grid read unavailable")).toHaveTextContent(
      "Checking grid availability",
    );
    const currentApp = entry === "application switch" ? nextApp : savedViewApp;
    view.rerender(
      <Analyze app={currentApp} catalog={catalog} index={1} subject="owner" />,
    );
    await waitFor(() =>
      expect(screen.getByLabelText("Value semantics")).toHaveValue("own"),
    );
    fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
    await waitFor(() =>
      expect(screen.getAllByRole("option", { name: "Account" })).toHaveLength(
        2,
      ),
    );
    fireEvent.change(screen.getByLabelText("Rows"), {
      target: { value: "Account" },
    });
    fireEvent.change(screen.getByLabelText("Columns"), {
      target: { value: "Period" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Choose row members" }));
    const dialog = within(
      await screen.findByRole("dialog", { name: "Choose row members" }),
    );
    fireEvent.click(dialog.getByRole("button", { name: "Search" }));
    fireEvent.click(
      dialog.getByRole("checkbox", {
        name: "Check Receivables · Receivables",
      }),
    );
    fireEvent.click(
      dialog.getByRole("checkbox", { name: "Check Cash · Cash" }),
    );
    fireEvent.click(
      dialog.getByRole("button", { name: "Add checked members" }),
    );
    fireEvent.click(dialog.getByRole("button", { name: "Apply selection" }));
    expect(screen.getByRole("button", { name: "Read grid" })).toBeEnabled();
    fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
    await waitFor(() =>
      expect(
        calls.filter(
          (call) => call.program.function === "facts.cube.resolved.read",
        ),
      ).toHaveLength(1),
    );
    const read = calls.find(
      (call) => call.program.function === "facts.cube.resolved.read",
    );
    expect(read).toMatchObject({
      workspaceId: currentApp.workspaceId,
      applicationId: currentApp.applicationId,
      program: { arguments: { source: { semantics: "own" } } },
    });
    expect(
      read.program.arguments.selection.dimensions.find(
        (item: any) => item.dimensionId === "Account",
      ),
    ).toMatchObject({
      include: { kind: "members", memberIds: ["Receivables", "Cash"] },
      exclude: null,
    });
  },
);

it("preserves an explicit read policy across catalogue loading, grant refresh and capability changes", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => savedViewDimensions()),
  );
  const catalog = {
    ...savedViewCatalog(),
    functions: {
      "metadata.dimension.list": {},
      "facts.cube.resolved.read": {},
    },
  };
  const view = render(
    <Analyze app={savedViewApp} catalog={catalog} index={0} subject="owner" />,
  );
  expect(screen.getByLabelText("Value semantics")).toHaveValue("own");
  fireEvent.change(screen.getByLabelText("Value semantics"), {
    target: { value: "stored" },
  });
  view.rerender(
    <Analyze app={savedViewApp} catalog={null} index={0} subject="owner" />,
  );
  view.rerender(
    <Analyze
      app={savedViewApp}
      catalog={{ ...catalog, revisions: { ...catalog.revisions, security: 2 } }}
      index={0}
      subject="owner"
    />,
  );
  expect(screen.getByLabelText("Value semantics")).toHaveValue("stored");
  fireEvent.change(screen.getByLabelText("Value semantics"), {
    target: { value: "effective" },
  });
  view.rerender(
    <Analyze
      app={savedViewApp}
      catalog={{ ...catalog, functions: { "metadata.dimension.list": {} } }}
      index={0}
      subject="owner"
    />,
  );
  view.rerender(
    <Analyze app={savedViewApp} catalog={catalog} index={0} subject="owner" />,
  );
  expect(screen.getByLabelText("Value semantics")).toHaveValue("effective");
  expect(screen.getByLabelText("Grid read unavailable")).toHaveTextContent(
    "Choose a current active binding",
  );
});

it("discards old dimension evidence after an in-place grant change", async () => {
  let finish!: (value: Response) => void;
  let oldSignal: AbortSignal | undefined;
  let reads = 0;
  const response = (name: string) =>
    new Response(
      JSON.stringify({
        result: {
          rows: [
            {
              dimension_id: "Account",
              name,
              model_role: "Account",
              status: "Active",
            },
          ],
          nextAfterDimensionId: null,
          metadataRevision: 1,
        },
      }),
    );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_path, init) => {
      if (++reads === 1) {
        oldSignal = init.signal;
        return new Promise<Response>((done) => {
          finish = done;
        });
      }
      return response("Current dimension");
    }),
  );
  const app = {
    workspaceId: "w",
    applicationId: "a",
    name: "Model",
    status: "Active",
  };
  const catalog = {
    applicationAccess: { role: "Reader", workspaceAdministrator: false },
    enabledCapabilities: [],
    functions: { "metadata.dimension.list": {} },
    revisions: { metadata: 1, data: 1, security: 1, policy: 1, commit: 1 },
  };
  const view = render(
    <Analyze app={app} catalog={catalog} index={0} subject="reader" />,
  );
  await waitFor(() => expect(finish).toBeDefined());
  view.rerender(
    <Analyze
      app={app}
      catalog={{ ...catalog, revisions: { ...catalog.revisions, security: 2 } }}
      index={0}
      subject="reader"
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
  await waitFor(() =>
    expect(
      screen.getAllByRole("option", { name: "Current dimension" }),
    ).toHaveLength(2),
  );
  expect(oldSignal?.aborted).toBe(true);
  await act(async () => finish(response("Old private dimension")));
  expect(
    screen.queryByRole("option", { name: "Old private dimension" }),
  ).not.toBeInTheDocument();
  expect(reads).toBe(2);
});

function viewDefinition({
  id = "grid-a",
  name = "Grid A",
  rows = ["Account"],
  columns = ["Period"],
  pov = {} as Record<string, string>,
  selectedMembers = {} as Record<string, string>,
  kind = "raw" as "raw" | "calculated" | "combined",
  resultKey = null as string | null,
  metadataRevision = 11,
} = {}) {
  const placed = [...rows, ...columns, ...Object.keys(pov)];
  return {
    format: "openepm-cube-view-v1" as const,
    viewId: id,
    name,
    selection: {
      format: "openepm-cube-selection-v1" as const,
      metadataRevision,
      dimensions: placed.map((dimensionId) => ({
        dimensionId,
        include:
          pov[dimensionId] || selectedMembers[dimensionId]
            ? ({
                kind: "member",
                memberId: pov[dimensionId] || selectedMembers[dimensionId],
              } as const)
            : ({
                kind: "members",
                memberIds: [`${dimensionId}-member`] as string[],
              } as const),
        exclude: null,
      })),
    },
    layout: {
      pages: [] as string[],
      rows,
      columns,
      filters: Object.keys(pov),
    },
    dataSource: { kind, resultKey: kind === "raw" ? null : resultKey },
    suppression: { missing: false, zero: false },
    pageSize: 100,
  };
}

it("builds complete pinned own and effective resolved-grid reads", () => {
  const dimensions = [
    {
      dimension_id: "Scenario",
      name: "Scenario",
      model_role: "Scenario",
      status: "Active",
    },
    {
      dimension_id: "Account",
      name: "Account",
      model_role: "Account",
      status: "Active",
    },
  ];
  const members = {
    Scenario: [{ member_id: "Actual", name: "Actual", status: "Active" }],
    Account: [
      { member_id: "Revenue", name: "Revenue", status: "Active" },
      { member_id: "Cost", name: "Cost", status: "Active" },
    ],
  };
  const own = resolvedGridProgram(
    dimensions,
    members,
    { Scenario: "Actual" },
    19,
    { semantics: "own" },
  );
  expect(own.arguments.selection.metadataRevision).toBe(19);
  expect(own.arguments.selection.dimensions).toEqual([
    {
      dimensionId: "Scenario",
      include: { kind: "member", memberId: "Actual" },
      exclude: null,
    },
    {
      dimensionId: "Account",
      include: {
        kind: "members",
        memberIds: ["Revenue", "Cost"],
      },
      exclude: null,
    },
  ]);
  expect(own.arguments.source).toEqual({ semantics: "own" });
  const effective = resolvedGridProgram(
    dimensions,
    members,
    { Scenario: "Actual" },
    19,
    {
      semantics: "effective",
      bindingId: "gross-profit",
      bindingStateToken: "b".repeat(64),
      hierarchies: [],
    },
  );
  expect(effective.arguments.source).toEqual({
    semantics: "effective",
    bindingId: "gross-profit",
    bindingStateToken: "b".repeat(64),
    hierarchies: [],
  });
  expect(effective.arguments.freshness).toBe("current");
  expect(effective.arguments.dynamicFallback).toBe(false);
  const symbolicSelection = {
    format: "openepm-cube-selection-v1" as const,
    metadataRevision: 19,
    dimensions: [
      {
        dimensionId: "Scenario",
        include: { kind: "member", memberId: "Actual" },
        exclude: null,
      },
      {
        dimensionId: "Account",
        include: {
          kind: "hierarchy",
          operator: "base",
          hierarchyId: "accounts",
          memberId: "ProfitAndLoss",
          includeSelf: false,
        },
        exclude: null,
      },
    ],
  };
  const reopened = resolvedGridProgram(
    dimensions,
    members,
    {},
    19,
    { semantics: "own" },
    symbolicSelection,
  );
  expect(reopened.arguments.selection).toEqual(symbolicSelection);
  expect(reopened.arguments.presentation).toEqual({
    pageSize: 100,
    suppression: { missing: false, zero: false },
  });
  const editedAxis = resolvedGridProgram(
    dimensions,
    members,
    { Scenario: "Actual" },
    19,
    { semantics: "own" },
    undefined,
    undefined,
    {
      Account: {
        kind: "hierarchy",
        operator: "descendants",
        hierarchyId: "accounts",
        memberId: "OperatingAccounts",
        includeSelf: false,
      },
    },
  );
  expect(editedAxis.arguments.selection.dimensions).toEqual([
    {
      dimensionId: "Scenario",
      include: { kind: "member", memberId: "Actual" },
      exclude: null,
    },
    {
      dimensionId: "Account",
      include: {
        kind: "hierarchy",
        operator: "descendants",
        hierarchyId: "accounts",
        memberId: "OperatingAccounts",
        includeSelf: false,
      },
      exclude: null,
    },
  ]);
});

it("applies an ordered axis member selection to the canonical resolved read", async () => {
  const calls: Array<{ function: string; arguments: Record<string, unknown> }> =
    [];
  const response = (result: unknown) =>
    new Response(JSON.stringify({ result }), {
      headers: { "Content-Type": "application/json" },
    });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push(body.program);
      if (body.program.function === "metadata.dimension.list")
        return response({
          rows: [
            {
              dimension_id: "Account",
              name: "Account",
              model_role: "Account",
              status: "Active",
            },
            {
              dimension_id: "Period",
              name: "Period",
              model_role: "Period",
              status: "Active",
            },
            {
              dimension_id: "Scenario",
              name: "Scenario",
              model_role: "Scenario",
              status: "Active",
            },
          ],
          nextAfterDimensionId: null,
          metadataRevision: 11,
        });
      if (body.program.function === "metadata.member.list") {
        const dimensionId = body.program.arguments.dimension;
        return response({
          rows:
            dimensionId === "Account"
              ? [
                  { member_id: "Revenue", name: "Revenue", status: "Active" },
                  { member_id: "Cost", name: "Cost", status: "Active" },
                ]
              : dimensionId === "Period"
                ? [
                    { member_id: "Jan", name: "January", status: "Active" },
                    { member_id: "Feb", name: "February", status: "Active" },
                  ]
                : [{ member_id: "Plan", name: "Plan", status: "Active" }],
          nextAfterMemberId: null,
          metadataRevision: 11,
        });
      }
      if (body.program.function === "facts.cube.resolved.read")
        return response({
          rows: ["Revenue", "Cost"].map((Account) => ({
            members: { Account, Period: "Jan", Scenario: "Plan" },
            present: true,
            value: "1",
            resultUnit: "numeric",
          })),
          snapshot: { commitRevision: 3 },
          stages: [],
          presentation: {
            pageSize: 1,
            suppression: { missing: false, zero: false },
            rowCount: 2,
          },
        });
      throw new Error(`Unexpected function ${body.program.function}`);
    }),
  );

  render(
    <Analyze
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Cube",
        status: "Active",
      }}
      catalog={{
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: true,
        },
        enabledCapabilities: [],
        functions: {
          "metadata.dimension.list": {},
          "metadata.member.list": {},
          "facts.cube.resolved.read": {},
        },
        revisions: {
          metadata: 11,
          data: 3,
          policy: 2,
          security: 1,
          commit: 3,
        },
      }}
      index={0}
      subject="owner"
    />,
  );

  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Configure layout" }),
    ).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
  await waitFor(() => expect(screen.getByLabelText("Rows")).toBeEnabled());
  fireEvent.change(screen.getByLabelText("Rows"), {
    target: { value: "Account" },
  });
  fireEvent.change(screen.getByLabelText("Columns"), {
    target: { value: "Period" },
  });
  fireEvent.click(
    await screen.findByRole("button", { name: "Choose row members" }),
  );
  const chooser = await screen.findByRole("dialog", {
    name: "Choose row members",
  });
  expect(
    within(chooser).getByRole("button", { name: "Apply selection" }),
  ).toBeDisabled();
  fireEvent.click(
    within(chooser).getByRole("checkbox", { name: /^Check Cost ·/ }),
  );
  fireEvent.click(
    within(chooser).getByRole("checkbox", { name: /^Check Revenue ·/ }),
  );
  fireEvent.click(
    within(chooser).getByRole("button", { name: "Add checked members" }),
  );
  fireEvent.click(
    within(chooser).getByRole("button", { name: "Apply selection" }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  await waitFor(() =>
    expect(
      calls.some((call) => call.function === "facts.cube.resolved.read"),
    ).toBe(true),
  );
  const read = calls.find(
    (call) => call.function === "facts.cube.resolved.read",
  )!;
  expect(read.arguments).toMatchObject({
    selection: {
      format: "openepm-cube-selection-v1",
      metadataRevision: 11,
      dimensions: [
        {
          dimensionId: "Account",
          include: { kind: "members", memberIds: ["Cost", "Revenue"] },
          exclude: null,
        },
        {
          dimensionId: "Period",
          include: { kind: "members", memberIds: ["Jan", "Feb"] },
          exclude: null,
        },
        {
          dimensionId: "Scenario",
          include: { kind: "members", memberIds: ["Plan"] },
          exclude: null,
        },
      ],
    },
    source: { semantics: "own" },
  });
  await waitFor(() =>
    expect(
      within(screen.getByRole("region", { name: "Grid results" }))
        .getAllByRole("rowheader")
        .map((row) => row.textContent),
    ).toEqual(["Cost"]),
  );
  fireEvent.click(screen.getByRole("button", { name: "Next page" }));
  expect(
    within(screen.getByRole("region", { name: "Grid results" }))
      .getAllByRole("rowheader")
      .map((row) => row.textContent),
  ).toEqual(["Revenue"]);
});

it("pages one fixed resolved snapshot without refetching or overlap", () => {
  const cells = ["a", "b", "c"].map((member) => ({
    members: { Account: member },
    kind: "numeric" as const,
    amount: member,
  }));
  expect(resolvedPageCells(cells, 2, 0).map((cell) => cell.amount)).toEqual([
    "a",
    "b",
  ]);
  expect(resolvedPageCells(cells, 2, 2).map((cell) => cell.amount)).toEqual([
    "c",
  ]);
  expect(hasResolvedNextPage(cells, 2, 0)).toBe(true);
  expect(hasResolvedNextPage(cells, 2, 2)).toBe(false);
  expect(hasResolvedNextPage(cells.slice(0, 1), 1, 0)).toBe(false);
});

it("does not infer another page from a one-row authorized snapshot", () => {
  const authorized = [
    {
      members: { Account: "Visible" },
      kind: "numeric" as const,
      amount: "0.00000000",
    },
  ];
  expect(resolvedPageCells(authorized, 1, 0)).toEqual(authorized);
  expect(hasResolvedNextPage(authorized, 1, 0)).toBe(false);
});

it("preserves governed origin, currentness, unit, state and lineage", () => {
  expect(
    resolvedRowsToCells({
      snapshot: { commitRevision: 29 },
      presentation: {
        pageSize: 100,
        suppression: { missing: false, zero: false },
        rowCount: 1,
      },
      stages: [],
      rows: [
        {
          members: { Account: "GrossProfit" },
          present: true,
          value: "12.50000000",
          resultUnit: "Currency:USD",
          origin: "materialized",
          currentness: "current",
          resultStateToken: "d".repeat(64),
          lineage: [{ resultKey: "gross-profit" }],
        },
      ],
    }),
  ).toEqual([
    {
      members: { Account: "GrossProfit" },
      kind: "numeric",
      amount: "12.50000000",
      lastRevision: 29,
      resultUnit: "Currency:USD",
      origin: "materialized",
      currentness: "current",
      resultStateToken: "d".repeat(64),
      lineage: [{ resultKey: "gross-profit" }],
    },
  ]);
});

it("keeps resolved text zero and empty text typed as text", () => {
  const page = {
    snapshot: { commitRevision: 29 },
    presentation: {
      pageSize: 2,
      suppression: { missing: false, zero: true },
      rowCount: 2,
    },
    stages: [],
    rows: ["0", ""].map((value) => ({
      members: { Account: value || "empty" },
      present: true,
      value,
      resultUnit: "text",
      origin: "input",
      currentness: "current",
      resultStateToken: null,
      lineage: [],
    })),
  };
  expect(
    resolvedRowsToCells(page).map((cell) => ({
      kind: cell.kind,
      text: cell.text,
      amount: cell.amount,
    })),
  ).toEqual([
    { kind: "text", text: "0", amount: undefined },
    { kind: "text", text: "", amount: undefined },
  ]);
});

it("renders missing, numeric zero, and empty text as distinct browser states", () => {
  const states = [
    { members: {}, kind: "numeric" as const, amount: null },
    { members: {}, kind: "numeric" as const, amount: "0.00000000" },
    { members: {}, kind: "text" as const, text: null },
    { members: {}, kind: "text" as const, text: "" },
  ];
  expect(
    states.map((cell) => ({
      value: cellValue(cell),
      className: cellClass(cell),
      presence: cellPresence(cell),
    })),
  ).toEqual([
    { value: "—", className: "numeric", presence: "Missing" },
    {
      value: "0.00000000",
      className: "zero",
      presence: "Present numeric zero",
    },
    { value: "—", className: "text", presence: "Missing" },
    { value: "“”", className: "empty-text", presence: "Present empty text" },
  ]);
});

afterEach(() => {
  vi.unstubAllGlobals();
  localStorage.clear();
});

it("reads complete Analyze discovery catalogues beyond former caps", async () => {
  let dimensionPage = 0;
  const dimensions = await collectAnalyzeDimensions(
    async (_cursor, revision) => {
      const current = dimensionPage++;
      if (current) expect(revision).toBe(11);
      return {
        rows: Array.from({ length: 100 }, (_unused, row) => ({
          dimension_id: `d-${current}-${row}`,
          name: "Dimension",
          model_role: "Custom",
          status: "Active",
        })),
        nextAfterDimensionId: current === 10 ? null : `d-cursor-${current + 1}`,
        metadataRevision: 11,
      };
    },
  );
  expect(dimensions.rows).toHaveLength(1100);

  let memberPage = 0;
  const members = await collectAnalyzeMembers(async (_cursor, revision) => {
    const current = memberPage++;
    if (current) expect(revision).toBe(11);
    return {
      rows: Array.from({ length: 100 }, (_unused, row) => ({
        member_id: `m-${current}-${row}`,
        name: "Member",
        status: "Active",
      })),
      nextAfterMemberId: current === 100 ? null : `m-cursor-${current + 1}`,
      metadataRevision: 11,
    };
  });
  expect(members.rows).toHaveLength(10100);

  let tablePage = 0;
  const tables = await collectGenericTables(async () => {
    const current = tablePage++;
    return {
      rows: Array.from({ length: 100 }, (_unused, row) => ({
        table_id: `t-${current}-${row}`,
        name: "Table",
        status: "Active",
      })),
      nextAfterTableId: current === 10 ? null : `t-cursor-${current + 1}`,
    };
  });
  expect(tables.rows).toHaveLength(1100);

  let gridPage = 0;
  const grids = await collectSavedGrids(async () => {
    const current = gridPage++;
    return {
      grids: Array.from({ length: 100 }, (_unused, row) => ({
        gridId: `g-${current}-${row}`,
        stateToken: "a".repeat(64),
        name: "Grid",
        definition: viewDefinition({ id: `g-${current}-${row}`, name: "Grid" }),
        metadataRevision: 11,
        canonicalDigest: "a".repeat(64),
      })),
      nextAfterGridId: current === 10 ? null : `g-cursor-${current + 1}`,
      collectionToken: "b".repeat(64),
    };
  });
  expect(grids.rows).toHaveLength(1100);
});

it("rejects malformed, repeated, duplicate, and drifting Analyze continuations", async () => {
  await expect(
    collectGenericTables(async () => ({
      rows: [],
      nextAfterTableId: "" as never,
    })),
  ).rejects.toThrow("cursor is invalid");
  let page = 0;
  await expect(
    collectSavedGrids(async () => ({
      grids: [],
      nextAfterGridId: page++ < 1 ? "same" : "same",
      collectionToken: "b".repeat(64),
    })),
  ).rejects.toThrow("cursor repeated");
  let revisionPage = 0;
  await expect(
    collectAnalyzeDimensions(async () => ({
      rows: [
        {
          dimension_id: `d-${revisionPage}`,
          name: "D",
          model_role: "Custom",
          status: "Active",
        },
      ],
      nextAfterDimensionId: revisionPage++ < 1 ? "more" : null,
      metadataRevision: revisionPage === 1 ? 11 : 12,
    })),
  ).rejects.toThrow("changed while reading");
  let duplicatePage = 0;
  await expect(
    collectAnalyzeMembers(async () => ({
      rows: [{ member_id: "same", name: "Member", status: "Active" }],
      nextAfterMemberId: duplicatePage++ < 1 ? "more" : null,
      metadataRevision: 11,
    })),
  ).rejects.toThrow("repeated a row");
});

it("scopes grid density to identity and application without changing data", async () => {
  expect(gridDensityStorageKey("owner@example.com", "ws", "plan")).toBe(
    "openepm:grid-density:owner%40example.com:ws:plan",
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: {
              rows: [],
              nextAfterDimensionId: null,
              metadataRevision: 11,
            },
          }),
        ),
    ),
  );
  render(
    <Analyze
      app={{
        workspaceId: "ws",
        applicationId: "plan",
        name: "Plan",
        status: "active",
      }}
      catalog={{
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: true,
        },
        enabledCapabilities: [],
        functions: {
          "metadata.dimension.list": {},
          "metadata.member.list": {},
        },
        revisions: {
          metadata: 11,
          data: 12,
          policy: 13,
          security: 14,
          commit: 15,
        },
      }}
      index={0}
      subject="owner@example.com"
    />,
  );
  const compact = await screen.findByRole("button", {
    name: "Use compact grid",
  });
  expect(compact.closest("section")).toHaveClass("grid-density-comfortable");
  fireEvent.click(compact);
  expect(
    screen.getByRole("button", { name: "Use comfortable grid" }),
  ).toHaveAttribute("aria-pressed", "true");
  expect(
    localStorage.getItem(
      gridDensityStorageKey("owner@example.com", "ws", "plan"),
    ),
  ).toBe("compact");
  expect(
    screen
      .getByRole("button", { name: "Use comfortable grid" })
      .closest("section"),
  ).toHaveClass("grid-density-compact");
});

it("defers effective binding discovery until effective semantics are selected", async () => {
  const functionsCalled: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      functionsCalled.push(body.program.function);
      if (body.program.function === "metadata.dimension.list")
        return new Response(
          JSON.stringify({
            result: {
              rows: [],
              nextAfterDimensionId: null,
              metadataRevision: 11,
            },
          }),
        );
      if (body.program.function === "facts.cube.resolved.binding.list")
        return new Response(
          JSON.stringify({
            result: {
              bindings: [
                {
                  bindingId: "active-binding",
                  stateToken: "a".repeat(64),
                  bindingDigest: "b".repeat(64),
                  metadataRevision: 11,
                  stages: [{ stageId: "total", kind: "hierarchy_node" }],
                },
              ],
              nextAfterBindingId: null,
            },
          }),
        );
      throw new Error(`Unexpected function ${body.program.function}`);
    }),
  );
  render(
    <Analyze
      app={{
        workspaceId: "ws",
        applicationId: "plan",
        name: "Plan",
        status: "active",
      }}
      catalog={{
        applicationAccess: {
          role: "Editor",
          workspaceAdministrator: false,
        },
        enabledCapabilities: [],
        functions: {
          "metadata.dimension.list": {},
          "metadata.member.list": {},
          "facts.cube.resolved.read": {},
          "facts.cube.resolved.binding.list": {},
        },
        revisions: {
          metadata: 11,
          data: 12,
          policy: 13,
          security: 14,
          commit: 15,
        },
      }}
      index={0}
      subject="editor"
    />,
  );
  await waitFor(() =>
    expect(functionsCalled).toContain("metadata.dimension.list"),
  );
  expect(functionsCalled).not.toContain("facts.cube.resolved.binding.list");
  fireEvent.change(screen.getByLabelText("Value semantics"), {
    target: { value: "effective" },
  });
  await waitFor(() =>
    expect(functionsCalled).toContain("facts.cube.resolved.binding.list"),
  );
  await waitFor(() =>
    expect(screen.getByLabelText("Effective binding")).toHaveValue(
      `active-binding:${"a".repeat(64)}`,
    ),
  );
  expect(screen.getByLabelText("Value semantics")).toHaveValue("effective");
});

it("preserves shared saved-grid list and current-save contracts", () => {
  expect(savedGridListArguments()).toEqual({ limit: 100 });
  expect(savedGridListArguments("grid-a", "b".repeat(64))).toEqual({
    limit: 100,
    afterGridId: "grid-a",
    expectedCollectionToken: "b".repeat(64),
  });
  expect(
    savedGridSaveProgram(
      "actual-by-period",
      viewDefinition({
        id: "actual-by-period",
        name: "Actual by period",
        pov: { Scenario: "Actual" },
      }),
      11,
      "c".repeat(64),
    ),
  ).toEqual({
    languageVersion: 2,
    function: "grid.definition.save",
    arguments: {
      gridId: "actual-by-period",
      definition: viewDefinition({
        id: "actual-by-period",
        name: "Actual by period",
        pov: { Scenario: "Actual" },
      }),
      expectedMetadataRevision: 11,
      expectedStateToken: "c".repeat(64),
    },
  });
  expect(savedGridDeleteProgram("actual-by-period", "c".repeat(64))).toEqual({
    languageVersion: 2,
    function: "grid.definition.delete",
    arguments: {
      gridId: "actual-by-period",
      expectedStateToken: "c".repeat(64),
    },
  });
  const base = {
    gridId: "grid-a",
    stateToken: "a".repeat(64),
    name: "Grid A",
    metadataRevision: 11,
    canonicalDigest: "digest",
  };
  expect(
    canOpenSavedGrid({
      ...base,
      definition: viewDefinition(),
    }),
  ).toBe(true);
  expect(
    canOpenSavedGrid({
      ...base,
      definition: viewDefinition({ rows: ["Account", "Entity"] }),
    }),
  ).toBe(true);
  expect(
    canOpenSavedGrid({
      ...base,
      definition: viewDefinition({
        rows: ["Account", "Entity"],
        pov: { Scenario: "Actual" },
        kind: "calculated",
      }),
    }),
  ).toBe(false);
  expect(
    canOpenSavedGrid({
      ...base,
      definition: viewDefinition({
        rows: ["Account", "Entity"],
        pov: { Scenario: "Actual" },
        kind: "calculated",
        resultKey: "forecast.calculated",
      }),
    }),
  ).toBe(true);
});

it("builds the qualified exact aggregate request and page contracts", () => {
  const query = aggregateQueryIntent(
    [
      { dimension_id: "Account", model_role: "Account" },
      { dimension_id: "Period", model_role: "Period" },
      { dimension_id: "Scenario", model_role: "Scenario" },
      { dimension_id: "Channel", model_role: "Custom" },
      { dimension_id: "Currency", model_role: "Currency" },
    ],
    "Account",
    "Period",
    { Scenario: "Actual" },
    ["SumAmount", "CountPresent"],
  );
  expect(query).toEqual({
    source: "raw_numeric",
    grain: {
      inputDimensions: ["Account", "Period", "Scenario", "Channel"],
      groupBy: ["Account", "Period"],
      reduceDimensions: ["Channel"],
    },
    selectors: {
      Scenario: { kind: "Members", memberIds: ["Actual"] },
    },
    measures: [{ kind: "SumAmount" }, { kind: "CountPresent" }],
    missing: "exclude",
    aggregation: "unique_coordinate_sum",
  });
  expect(aggregateRequestProgram(query, 100)).toEqual({
    languageVersion: 2,
    function: "facts.cube.aggregate.request",
    arguments: { query, limits: { pageSize: 100 } },
  });
  expect(aggregateReadProgram("query-1", 100, "cursor-2")).toEqual({
    languageVersion: 2,
    function: "facts.cube.aggregate.read",
    arguments: { queryId: "query-1", pageSize: 100, cursor: "cursor-2" },
  });
  expect(() =>
    aggregateQueryIntent(
      [
        { dimension_id: "Account", model_role: "Account" },
        { dimension_id: "Period", model_role: "Period" },
        { dimension_id: "Scenario", model_role: "Scenario" },
      ],
      "Account",
      "Period",
      {},
      ["SumAmount"],
    ),
  ).toThrow("Fix non-custom dimensions before reduction: Scenario.");
});

it("moves keyboard focus within bounded grid coordinates", () => {
  expect(gridKeyTarget("ArrowRight", 1, 1, 3, 4)).toEqual({
    row: 1,
    column: 2,
  });
  expect(gridKeyTarget("ArrowUp", 0, 2, 3, 4)).toEqual({ row: 0, column: 2 });
  expect(gridKeyTarget("End", 2, 0, 3, 4)).toEqual({ row: 2, column: 3 });
  expect(gridKeyTarget("Enter", 1, 1, 3, 4)).toBeNull();
});

it("preserves the qualified first-page cube scan arguments", () => {
  expect(buildScanArguments({ Scenario: "Actual", Year: "FY27" }, 100)).toEqual(
    {
      members: { Scenario: "Actual", Year: "FY27" },
      limit: 100,
      includeMissing: false,
      includeZero: true,
    },
  );
});

it("labels only exact current materialized empty evidence as empty", () => {
  const emptyPage = {
    snapshot: { commitRevision: 29 },
    presentation: {
      pageSize: 100,
      suppression: { missing: false, zero: false },
      rowCount: 0,
    },
    rows: [],
    stages: [
      {
        stage: "input" as const,
        sourceDigest: "input",
        resolutionDigest: "resolution",
        currentness: "current" as const,
      },
      {
        stage: "materialized" as const,
        sourceDigest: "calculation",
        currentness: "current" as const,
        definitions: [
          {
            stageId: "gross-profit",
            resultStateToken: "d".repeat(64),
            presence: "empty" as const,
            definitionStatus: "active",
          },
        ],
      },
    ],
  };
  expect(resolvedReadStatus(emptyPage)).toBe("current-empty");
  expect(
    resolvedReadStatus({
      ...emptyPage,
      stages: [{ ...emptyPage.stages[1], currentness: "stale" }],
    }),
  ).toBe("current");
  expect(resolvedReadStatus({ ...emptyPage, stages: [] })).toBe("current");
  expect(
    resolvedReadStatus({
      ...emptyPage,
      stages: [
        {
          ...emptyPage.stages[1],
          definitions: [
            {
              ...emptyPage.stages[1].definitions![0],
              presence: "present",
            },
          ],
        },
      ],
    }),
  ).toBe("current");
});

it("preserves the qualified cursor page contract", () => {
  expect(buildScanArguments({ Scenario: "Ignored" }, 100, "cursor-2")).toEqual({
    cursor: "cursor-2",
  });
});

it("maps saved-view suppression to explicit server inclusion flags", () => {
  expect(
    buildScanArguments({ Scenario: "Actual" }, 25, null, {
      missing: false,
      zero: true,
    }),
  ).toEqual({
    members: { Scenario: "Actual" },
    limit: 25,
    includeMissing: true,
    includeZero: false,
  });
});

it("preserves the generic-fact read contracts", () => {
  expect(genericTableListArguments()).toEqual({
    afterTableId: null,
    limit: 100,
  });
  expect(genericTableListArguments("table-1")).toEqual({
    afterTableId: "table-1",
    limit: 100,
  });
  expect(genericSnapshotArguments("table-1")).toEqual({
    tableId: "table-1",
    cursor: null,
    limit: 100,
  });
  expect(genericSnapshotArguments("table-1", "cursor-2")).toEqual({
    tableId: "table-1",
    cursor: "cursor-2",
    limit: 100,
  });
  expect(genericValueText({ amount: "1.25000000" })).toBe(
    '{"amount":"1.25000000"}',
  );
});

it("reads generic facts through unchanged authorized V2 programs", async () => {
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
              rows: [],
              nextAfterDimensionId: null,
              metadataRevision: 11,
            },
          }),
        );
      if (body.program.function === "facts.generic.table.list")
        return new Response(
          JSON.stringify({
            result: {
              rows: [
                {
                  table_id: "rates",
                  name: "External rates",
                  status: "Active",
                },
              ],
              nextAfterTableId: null,
            },
          }),
        );
      return new Response(
        JSON.stringify({
          result: {
            rows: [
              {
                series_key: "USD:FY27:P1",
                value: { amount: "1.25000000" },
                change_id: "change-9",
                last_revision: 14,
              },
            ],
            nextCursor: null,
            snapshotRevision: 14,
          },
        }),
      );
    }),
  );

  render(
    <Analyze
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "active",
      }}
      catalog={{
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: true,
        },
        enabledCapabilities: [],
        functions: {
          "metadata.dimension.list": {},
          "metadata.member.list": {},
          "facts.generic.table.list": {},
          "facts.generic.value.snapshot.scan": {},
        },
        revisions: {
          metadata: 11,
          data: 14,
          policy: 1,
          security: 1,
          commit: 14,
        },
      }}
      index={0}
      subject="owner"
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Generic facts" }));
  expect(
    screen.getByRole("button", { name: "KPI" }),
  ).toHaveAccessibleDescription(/Read the grid/);
  expect(
    screen.getByRole("button", { name: "Chart" }),
  ).toHaveAccessibleDescription(/Read the grid/);
  await waitFor(() =>
    expect(screen.getByLabelText("Generic fact table")).toHaveValue("rates"),
  );
  fireEvent.click(screen.getByRole("button", { name: "Read records" }));
  await waitFor(() =>
    expect(screen.getByLabelText("Generic facts")).toHaveTextContent(
      "USD:FY27:P1",
    ),
  );
  expect(screen.getByLabelText("Generic facts")).toHaveTextContent(
    '{"amount":"1.25000000"}',
  );
  expect(screen.getByLabelText("Generic facts")).toHaveTextContent(
    "1 current records",
  );
  expect(screen.getByLabelText("Generic facts")).not.toHaveTextContent(
    "source snapshot 14",
  );
  expect(calls).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        program: expect.objectContaining({
          function: "facts.generic.table.list",
          arguments: { afterTableId: null, limit: 100 },
        }),
      }),
      expect.objectContaining({
        program: expect.objectContaining({
          function: "facts.generic.value.snapshot.scan",
          arguments: { tableId: "rates", cursor: null, limit: 100 },
        }),
      }),
    ]),
  );
});

it("preserves exact Add and Clear writeback literals", () => {
  expect(
    buildWritebackProgram(
      "numeric",
      "add",
      { Account: "Revenue" },
      "1.25",
      "change-1",
    ),
  ).toEqual({
    languageVersion: 2,
    function: "facts.numeric.batch",
    arguments: {
      mutations: [
        {
          coordinate: { Account: "Revenue" },
          op: "add",
          expectedChangeId: "change-1",
          value: { type: "AmountLiteral", decimal: "1.25" },
        },
      ],
    },
  });
  expect(
    buildWritebackProgram(
      "text",
      "clear",
      { Account: "Comment" },
      "ignored",
      "text-1",
    ),
  ).toEqual({
    languageVersion: 2,
    function: "facts.text.batch",
    arguments: {
      mutations: [
        {
          coordinate: { Account: "Comment" },
          op: "clear",
          expectedChangeId: "text-1",
        },
      ],
    },
  });
});

it("reads and saves shared grid definitions through unchanged governed contracts", async () => {
  const calls: Array<{
    path: string;
    body: {
      program: { function: string; arguments: Record<string, unknown> };
      confirmed?: boolean;
      idempotencyKey?: string;
    };
  }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      const body = JSON.parse(String(init?.body));
      calls.push({ path, body });
      if (path === "/api/operation-admission")
        return operationAdmissionResponse("a");
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
                {
                  dimension_id: "Period",
                  name: "Period",
                  model_role: "Period",
                  status: "Active",
                },
              ],
              nextAfterDimensionId: null,
              metadataRevision: 11,
            },
          }),
        );
      if (body.program.function === "grid.definition.list")
        return new Response(
          JSON.stringify({
            result: {
              grids: [],
              nextAfterGridId: null,
              collectionToken: "b".repeat(64),
            },
          }),
        );
      if (body.program.function === "metadata.member.list")
        return new Response(
          JSON.stringify({
            result: {
              rows: [
                {
                  member_id: `${body.program.arguments.dimension}-member`,
                  name: "Member",
                  status: "Active",
                },
              ],
              nextAfterMemberId: null,
              metadataRevision: 11,
            },
          }),
        );
      return new Response(
        JSON.stringify({
          result: {
            gridId: "actual-by-period",
            stateToken: "c".repeat(64),
            name: "Actual by period",
            definition: viewDefinition({
              id: "actual-by-period",
              name: "Actual by period",
            }),
            metadataRevision: 11,
            canonicalDigest: "digest-1",
          },
        }),
      );
    }),
  );

  render(
    <Analyze
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "active",
      }}
      catalog={{
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: true,
        },
        enabledCapabilities: [],
        functions: {
          "metadata.dimension.list": {},
          "metadata.member.list": {},
          "grid.definition.list": {},
          "grid.definition.save": {},
        },
        revisions: {
          metadata: 11,
          data: 9,
          policy: 1,
          security: 1,
          commit: 9,
        },
      }}
      index={0}
      subject="owner"
    />,
  );
  await waitFor(() => expect(screen.getByLabelText("Rows")).toHaveValue(""));
  fireEvent.change(screen.getByLabelText("Rows"), {
    target: { value: "Account" },
  });
  fireEvent.change(screen.getByLabelText("Columns"), {
    target: { value: "Period" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Refresh views" }));
  await waitFor(() =>
    expect(screen.getByText("0 saved views")).toBeInTheDocument(),
  );
  fireEvent.click(screen.getByText("Save current view"));
  fireEvent.change(screen.getByLabelText("Stable grid ID"), {
    target: { value: "actual-by-period" },
  });
  fireEvent.change(screen.getByLabelText("Display name"), {
    target: { value: "Actual by period" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save view" }));
  await waitFor(() =>
    expect(screen.getByText("Saved Actual by period.")).toHaveAttribute(
      "role",
      "status",
    ),
  );
  expect(calls).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        path: "/api/read",
        body: expect.objectContaining({
          program: {
            languageVersion: 2,
            function: "grid.definition.list",
            arguments: { limit: 100 },
          },
        }),
      }),
      expect.objectContaining({
        path: "/api/metadata-action",
        body: expect.objectContaining({
          confirmed: true,
          idempotencyKey: expect.any(String),
          program: {
            languageVersion: 2,
            function: "grid.definition.save",
            arguments: {
              gridId: "actual-by-period",
              definition: viewDefinition({
                id: "actual-by-period",
                name: "Actual by period",
              }),
              expectedMetadataRevision: 11,
            },
          },
        }),
      }),
    ]),
  );
});

it("uses the shared two-pane chooser instead of a native POV member dropdown", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
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
                {
                  dimension_id: "Period",
                  name: "Period",
                  model_role: "Period",
                  status: "Active",
                },
                {
                  dimension_id: "Entity",
                  name: "Entity",
                  model_role: "Entity",
                  status: "Active",
                },
              ],
              nextAfterDimensionId: null,
              metadataRevision: 11,
            },
          }),
        );
      if (body.program.function === "metadata.member.list")
        return new Response(
          JSON.stringify({
            result: {
              rows:
                body.program.arguments.dimension === "Entity"
                  ? [
                      {
                        member_id: "CH",
                        name: "Switzerland",
                        status: "Active",
                      },
                      { member_id: "DE", name: "Germany", status: "Active" },
                    ]
                  : [],
              nextAfterMemberId: null,
              metadataRevision: 11,
            },
          }),
        );
      throw new Error(`Unexpected function ${body.program.function}`);
    }),
  );

  render(
    <Analyze
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "active",
      }}
      catalog={{
        applicationAccess: {
          role: "Planner",
          workspaceAdministrator: false,
        },
        enabledCapabilities: [],
        functions: {
          "metadata.dimension.list": {},
          "metadata.member.list": {},
        },
        revisions: {
          metadata: 11,
          data: 9,
          policy: 1,
          security: 1,
          commit: 9,
        },
      }}
      index={0}
      subject="planner"
    />,
  );
  await waitFor(() => expect(screen.getByLabelText("Rows")).toHaveValue(""));
  fireEvent.change(screen.getByLabelText("Rows"), {
    target: { value: "Account" },
  });
  fireEvent.change(screen.getByLabelText("Columns"), {
    target: { value: "Period" },
  });
  expect(
    screen.queryByRole("combobox", { name: "Entity point of view" }),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Entity point of view" }));
  const dialog = await screen.findByRole("dialog", {
    name: "Choose one Entity member",
  });
  fireEvent.click(within(dialog).getByRole("button", { name: /Germany/ }));
  fireEvent.click(
    within(dialog).getByRole("button", { name: "Add selected member" }),
  );
  fireEvent.click(
    within(dialog).getByRole("button", { name: "Apply selection" }),
  );
  expect(
    screen.getByRole("button", { name: "Entity point of view" }),
  ).toHaveTextContent("Germany");
});

it("opens an exact multi-axis calculated grid through the existing scan contract", async () => {
  const calls: Array<{
    program: { function: string; arguments: Record<string, unknown> };
  }> = [];
  let canInspect = true;
  const refreshCatalogue = vi
    .fn()
    .mockRejectedValue(new Error("Application access not confirmed"));
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
                {
                  dimension_id: "Entity",
                  name: "Entity",
                  model_role: "Entity",
                  status: "Active",
                },
                {
                  dimension_id: "Period",
                  name: "Period",
                  model_role: "Period",
                  status: "Active",
                },
                {
                  dimension_id: "Scenario",
                  name: "Scenario",
                  model_role: "Scenario",
                  status: "Active",
                },
              ],
              nextAfterDimensionId: null,
              metadataRevision: 11,
            },
          }),
        );
      if (body.program.function === "grid.definition.list")
        return new Response(
          JSON.stringify({
            result: {
              grids: [
                {
                  gridId: "forecast-grid",
                  stateToken: "c".repeat(64),
                  name: "Forecast calculation",
                  definition: viewDefinition({
                    id: "forecast-grid",
                    name: "Forecast calculation",
                    rows: ["Account", "Entity"],
                    pov: { Scenario: "Forecast" },
                    selectedMembers: {
                      Account: "Revenue",
                      Entity: "CH",
                      Period: "P1",
                    },
                    kind: "calculated",
                    resultKey: "forecast.calculated",
                  }),
                  metadataRevision: 11,
                  canonicalDigest: "digest-2",
                },
              ],
              nextAfterGridId: null,
              collectionToken: "b".repeat(64),
            },
          }),
        );
      if (body.program.function === "metadata.member.list")
        return new Response(
          JSON.stringify({
            result: {
              rows: [],
              nextAfterMemberId: null,
              metadataRevision: 11,
            },
          }),
        );
      if (body.program.function === "facts.cell.editability.read")
        return canInspect
          ? new Response(
              JSON.stringify({
                result: {
                  editable: false,
                  reasonCode: "CALCULATED_RESULT_READ_ONLY",
                  message:
                    "Calculated result cells are read-only; update an authorized raw input cell or run its governing rule.",
                },
              }),
            )
          : new Response(
              JSON.stringify({ code: "APPLICATION_GRANT_REQUIRED" }),
              {
                status: 403,
              },
            );
      return new Response(
        JSON.stringify({
          result: {
            resultKey: "forecast.calculated",
            resultStateToken: "a".repeat(64),
            inputRevisionStatus: { matchesAtRead: true },
            rows: [
              {
                members: {
                  Account: "Revenue",
                  Entity: "CH",
                  Period: "P1",
                  Scenario: "Forecast",
                },
                amount: "125.00000000",
              },
            ],
            nextCursor: null,
            layer: "calculated",
          },
        }),
      );
    }),
  );

  render(
    <Analyze
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "active",
      }}
      catalog={{
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: true,
        },
        enabledCapabilities: [],
        functions: {
          "metadata.dimension.list": {},
          "metadata.member.list": {},
          "grid.definition.list": {},
          "facts.calculation.scan": {},
          "facts.cell.editability.read": {},
        },
        revisions: {
          metadata: 11,
          data: 19,
          policy: 1,
          security: 1,
          commit: 19,
        },
      }}
      index={0}
      subject="owner"
      onRefreshCatalog={refreshCatalogue}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Refresh views" }));
  await waitFor(() =>
    expect(screen.getByLabelText("Saved view")).toHaveValue("forecast-grid"),
  );
  fireEvent.click(screen.getByRole("button", { name: "Open view" }));
  expect(screen.getByLabelText("Opened grid layout")).toHaveTextContent(
    "Account / Entity",
  );
  expect(screen.getByLabelText("Opened grid layout")).not.toHaveTextContent(
    "forecast.calculated",
  );
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  await waitFor(() =>
    expect(screen.getByText("125.00000000")).toBeInTheDocument(),
  );
  expect(
    screen.getByLabelText("Calculated result context"),
  ).not.toHaveTextContent("a".repeat(64));
  expect(screen.getByLabelText("Calculated result context")).toHaveTextContent(
    "Match",
  );
  expect(screen.getByLabelText("Loaded grid read")).toHaveTextContent(
    "Stored calculated result",
  );
  expect(screen.getByLabelText("Grid snapshot status")).toHaveTextContent(
    "1 loaded cells",
  );
  expect(screen.queryByText("No snapshot read")).not.toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("button", {
      name: /Account Revenue, Entity CH, Period P1, Scenario Forecast/,
    }),
  );
  expect(
    screen.getByRole("complementary", {
      name: "Cell details and writeback",
    }),
  ).toHaveTextContent("Calculated result details");
  expect(
    screen.getByLabelText("Calculated result provenance"),
  ).not.toHaveTextContent("a".repeat(64));
  expect(
    screen.getByLabelText("Calculated result provenance"),
  ).toHaveTextContent("Matches at read");
  expect(
    screen.queryByRole("button", { name: "Submit durable writeback" }),
  ).not.toBeInTheDocument();
  await waitFor(() =>
    expect(
      screen.getByLabelText("Authoritative editability decision"),
    ).not.toHaveTextContent("CALCULATED_RESULT_READ_ONLY"),
  );
  fireEvent.click(screen.getByRole("button", { name: "Close writeback" }));
  canInspect = false;
  fireEvent.click(
    screen.getByRole("button", {
      name: /Account Revenue, Entity CH, Period P1, Scenario Forecast/,
    }),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(/access|grant/i);
  expect(screen.queryAllByText("125.00000000")).toHaveLength(0);
  expect(
    screen.queryByLabelText("Calculated result context"),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByLabelText("Calculated result provenance"),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByLabelText("Cell details and writeback"),
  ).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Loaded grid read")).not.toBeInTheDocument();
  expect(screen.getByLabelText("Grid snapshot status")).not.toHaveTextContent(
    "1 loaded cells",
  );
  expect(refreshCatalogue).toHaveBeenCalledTimes(1);
  expect(
    calls.filter(({ program }) => program.function === "facts.cube.scan"),
  ).toEqual([]);
  canInspect = true;
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  expect(await screen.findByText("125.00000000")).toBeVisible();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  expect(calls).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        program: {
          languageVersion: 2,
          function: "facts.calculation.scan",
          arguments: {
            members: {
              Account: "Revenue",
              Entity: "CH",
              Period: "P1",
              Scenario: "Forecast",
            },
            limit: 100,
            includeZero: true,
            resultKey: "forecast.calculated",
          },
        },
      }),
    ]),
  );
});

it("opens the exact digest-pinned grid supplied by a workflow destination", async () => {
  const digest = "d".repeat(64);
  const calls: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push(body.program.function);
      if (body.program.function === "metadata.dimension.list")
        return new Response(
          JSON.stringify({
            result: {
              rows: [],
              nextAfterDimensionId: null,
              metadataRevision: 11,
            },
          }),
        );
      return new Response(
        JSON.stringify({
          result: {
            gridId: "workflow-view",
            stateToken: "c".repeat(64),
            name: "Workflow review",
            definition: viewDefinition({
              id: "workflow-view",
              name: "Workflow review",
            }),
            metadataRevision: 11,
            canonicalDigest: digest,
          },
        }),
      );
    }),
  );
  render(
    <Analyze
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "active",
      }}
      catalog={{
        applicationAccess: {
          role: "Reader",
          workspaceAdministrator: false,
        },
        enabledCapabilities: [],
        functions: {
          "metadata.dimension.list": {},
          "metadata.member.list": {},
          "grid.definition.read": {},
        },
        revisions: {
          metadata: 11,
          data: 19,
          policy: 1,
          security: 1,
          commit: 19,
        },
      }}
      index={0}
      subject="reviewer"
      targetViewId="workflow-view"
      targetViewDigest={digest}
    />,
  );
  await waitFor(() => expect(calls).toContain("grid.definition.read"));
  expect(screen.getByLabelText("Current grid layout")).toHaveTextContent(
    "Account",
  );
  expect(screen.getByLabelText("Current grid layout")).toHaveTextContent(
    "Period",
  );
});

it.each(["cancellation", "incompatible amount measure"])(
  "reports durable aggregate %s through the native contract",
  async (outcome) => {
    const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
    let ratioRefused = false;
    vi.stubGlobal(
      "confirm",
      vi.fn(() => true),
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const path = String(input);
        const body = JSON.parse(String(init?.body)) as Record<
          string,
          unknown
        > & {
          program: { function: string; arguments: Record<string, unknown> };
        };
        calls.push({ path, body });
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
                  {
                    dimension_id: "Period",
                    name: "Period",
                    model_role: "Period",
                    status: "Active",
                  },
                ],
                nextAfterDimensionId: null,
                metadataRevision: 11,
              },
            }),
          );
        if (body.program.function === "facts.cube.aggregate.request")
          return new Response(
            JSON.stringify({ result: { queryId: "query-1", status: "ready" } }),
          );
        if (body.program.function === "facts.cube.aggregate.read")
          return new Response(
            JSON.stringify({
              result: {
                queryId: "query-1",
                status: ratioRefused ? "failed" : "running",
                ...(ratioRefused
                  ? { errorCode: "CUBE_AGGREGATE_AMOUNT_MEASURE_REQUIRED" }
                  : {}),
              },
            }),
          );
        return new Response(
          JSON.stringify({
            result: { queryId: "query-1", status: "cancel_requested" },
          }),
        );
      }),
    );

    render(
      <Analyze
        app={{
          workspaceId: "ws",
          applicationId: "app",
          name: "Plan",
          status: "active",
        }}
        catalog={{
          applicationAccess: {
            role: "Administrator",
            workspaceAdministrator: true,
          },
          enabledCapabilities: [],
          functions: {
            "metadata.dimension.list": {},
            "metadata.member.list": {},
            "facts.cube.aggregate.request": {},
            "facts.cube.aggregate.read": {},
            "facts.cube.aggregate.cancel": {},
          },
          revisions: {
            metadata: 11,
            data: 9,
            policy: 1,
            security: 1,
            commit: 9,
          },
        }}
        index={0}
        subject="owner"
      />,
    );
    await waitFor(() =>
      expect(screen.getByLabelText("Rows")).toHaveTextContent("Account"),
    );
    fireEvent.change(screen.getByLabelText("Rows"), {
      target: { value: "Account" },
    });
    fireEvent.change(screen.getByLabelText("Columns"), {
      target: { value: "Period" },
    });
    fireEvent.click(screen.getByText("Aggregate large cube selections"));
    fireEvent.click(
      screen.getByLabelText("I reviewed this exact aggregate query"),
    );
    const aggregateRequest = screen.getByRole("button", {
      name: "Request durable aggregate",
    });
    await waitFor(() => expect(aggregateRequest).toBeEnabled());
    fireEvent.click(aggregateRequest);
    await waitFor(() =>
      expect(screen.getByText(/Aggregate request · ready/)).toHaveAttribute(
        "role",
        "status",
      ),
    );
    expect(screen.queryByText("query-1")).not.toBeInTheDocument();
    expect(
      screen.queryByLabelText("Aggregate query ID"),
    ).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Refresh status and results" }),
    );
    await waitFor(() =>
      expect(
        screen.getByText(/Aggregate request · running/),
      ).toBeInTheDocument(),
    );
    expect(
      screen.queryByLabelText("Aggregate results"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(/CubeAggregateTechnical/),
    ).not.toBeInTheDocument();
    if (outcome === "incompatible amount measure") {
      ratioRefused = true;
      fireEvent.click(
        screen.getByRole("button", { name: "Refresh status and results" }),
      );
      expect(await screen.findByRole("alert")).toHaveTextContent(
        "This query includes ratios. Select Count present alone to count cells, or calculate the rate from its underlying quantities.",
      );
      expect(screen.getByText("Aggregate request · failed")).toHaveAttribute(
        "role",
        "status",
      );
      expect(
        screen.queryByLabelText("Aggregate results"),
      ).not.toBeInTheDocument();
      expect(
        calls.filter(
          ({ body }) =>
            (body.program as { function?: string })?.function ===
            "facts.cube.aggregate.request",
        ),
      ).toHaveLength(1);
      return;
    }
    fireEvent.click(
      screen.getByLabelText(
        "I reviewed cancellation of this exact query state",
      ),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Request cancellation" }),
    );
    await waitFor(() =>
      expect(
        screen.getByText(/Aggregate request · cancel_requested/),
      ).toHaveAttribute("role", "status"),
    );
    expect(calls).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          path: "/api/aggregate",
          body: expect.objectContaining({
            confirmed: true,
            program: expect.objectContaining({
              function: "facts.cube.aggregate.request",
              arguments: expect.objectContaining({ limits: { pageSize: 100 } }),
            }),
          }),
        }),
        expect.objectContaining({
          path: "/api/aggregate",
          body: expect.objectContaining({
            program: {
              languageVersion: 2,
              function: "facts.cube.aggregate.read",
              arguments: { queryId: "query-1", pageSize: 100 },
            },
          }),
        }),
        expect.objectContaining({
          path: "/api/aggregate",
          body: expect.objectContaining({
            confirmed: true,
            program: {
              languageVersion: 2,
              function: "facts.cube.aggregate.cancel",
              arguments: { queryId: "query-1" },
            },
          }),
        }),
      ]),
    );
  },
);

it("reads the authorized metadata and cube through unchanged V2 programs", async () => {
  const calls: Array<Record<string, unknown>> = [];
  let acceptTransition: (() => void) | undefined;
  let denyGrid = false;
  let cellUnavailable = false;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as {
        program: { function: string; arguments: Record<string, unknown> };
      };
      calls.push(body as unknown as Record<string, unknown>);
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
                {
                  dimension_id: "Period",
                  name: "Period",
                  model_role: "Period",
                  status: "Active",
                },
                {
                  dimension_id: "Scenario",
                  name: "Scenario",
                  model_role: "Scenario",
                  status: "Active",
                },
              ],
              nextAfterDimensionId: null,
              metadataRevision: 11,
            },
          }),
        );
      if (body.program.function === "metadata.member.list")
        return new Response(
          JSON.stringify({
            result: {
              rows: [
                { member_id: "Actual", name: "Actual", status: "Active" },
                { member_id: "Plan", name: "Plan", status: "Active" },
              ],
              nextAfterMemberId: null,
              metadataRevision: 11,
            },
          }),
        );
      if (body.program.function === "facts.cell.editability.read")
        return new Response(
          JSON.stringify({
            result: {
              editable: false,
              reasonCode: cellUnavailable
                ? "CELL_UNAVAILABLE"
                : "PLANNING_INTERSECTION_LOCKED",
              message: cellUnavailable
                ? "The selected cell is unavailable."
                : "This cell is locked by the current planning workflow.",
            },
          }),
        );
      if (denyGrid)
        return new Response(
          JSON.stringify({ error: "METADATA_SELECTION_SCOPE_UNAVAILABLE" }),
          { status: 403 },
        );
      return new Response(
        JSON.stringify({
          result: {
            rows: [
              {
                members: {
                  Account: "Revenue",
                  Period: "P1",
                  Scenario: "Actual",
                },
                kind: "numeric",
                amount: "0.00000000",
                changeId: "change-1",
                lastRevision: 9,
              },
            ],
            nextCursor: null,
            snapshotRevision: 9,
            source: "current_projection",
          },
        }),
      );
    }),
  );

  render(
    <Analyze
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Cube",
        status: "active",
      }}
      catalog={{
        applicationAccess: {
          role: "Administrator",
          workspaceAdministrator: true,
        },
        enabledCapabilities: [],
        functions: {
          "metadata.dimension.list": {},
          "metadata.member.list": {},
          "facts.numeric.batch": {},
          "facts.text.batch": {},
          "facts.cell.editability.read": {},
        },
        revisions: {
          metadata: 11,
          data: 9,
          policy: 1,
          security: 1,
          commit: 9,
        },
      }}
      index={0}
      subject="owner"
      onRequestTransition={(action) => {
        acceptTransition = action;
      }}
    />,
  );
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Configure layout" }),
    ).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
  expect(
    screen.getByRole("complementary", {
      name: "Pages, rows, columns and filters",
    }),
  ).toBeVisible();
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Suggest layout" }),
    ).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Suggest layout" }));
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Read grid" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  await waitFor(() =>
    expect(screen.getByText("0.00000000")).toBeInTheDocument(),
  );
  fireEvent.click(
    screen.getByRole("button", {
      name: "Account Revenue, Period P1, Scenario Actual. 0.00000000",
    }),
  );
  await waitFor(() =>
    expect(
      screen.getByRole("complementary", {
        name: "Cell details and writeback",
      }),
    ).toHaveTextContent("Present numeric zero"),
  );
  expect(
    screen.getByRole("complementary", {
      name: "Cell details and writeback",
    }),
  ).not.toHaveTextContent("change-1");
  expect(
    screen.getByRole("heading", { name: "Details and exact writeback" }),
  ).toHaveFocus();
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Close writeback" }),
    ).toBeEnabled(),
  );
  expect(
    screen.getByLabelText("Authoritative editability decision"),
  ).not.toHaveTextContent("PLANNING_INTERSECTION_LOCKED");
  expect(
    screen.getByRole("button", { name: "Submit durable writeback" }),
  ).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Value"), {
    target: { value: "12.50000000" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Close writeback" }));
  expect(screen.getByLabelText("Value")).toHaveValue("12.50000000");
  expect(
    screen.getByRole("button", {
      name: "Account Revenue, Period P1, Scenario Actual. 0.00000000",
    }),
  ).toHaveAttribute("aria-pressed", "true");
  expect(acceptTransition).toBeTypeOf("function");
  act(() => acceptTransition?.());
  expect(
    screen.queryByRole("complementary", { name: "Cell details and writeback" }),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "KPI" }));
  expect(screen.getByLabelText("Snapshot KPI cards")).toHaveTextContent(
    "Revenue · P1",
  );
  expect(screen.getByLabelText("Snapshot KPI cards")).toHaveTextContent(
    "0.00000000",
  );
  fireEvent.click(screen.getByRole("button", { name: "Chart" }));
  expect(screen.getByLabelText("Snapshot value chart")).toHaveTextContent(
    "Labels retain the exact values from the current authorized read",
  );
  expect(screen.getByLabelText("Snapshot value chart")).toHaveTextContent(
    "0.00000000",
  );
  const scan = calls.find(
    (call) =>
      (call.program as { function: string }).function === "facts.cube.scan",
  ) as {
    workspaceId: string;
    applicationId: string;
    program: { languageVersion: number; function: string; arguments: unknown };
  };
  expect(scan).toMatchObject({
    workspaceId: "ws",
    applicationId: "app",
    program: {
      languageVersion: 2,
      function: "facts.cube.scan",
      arguments: { members: { Scenario: "Actual" }, limit: 100 },
    },
  });
  fireEvent.click(screen.getByRole("button", { name: "Grid" }));
  denyGrid = true;
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent(
      "METADATA_SELECTION_SCOPE_UNAVAILABLE",
    ),
  );
  expect(screen.queryByText("0.00000000")).not.toBeInTheDocument();
  expect(screen.getByText("No snapshot read")).toBeInTheDocument();
  denyGrid = false;
  cellUnavailable = true;
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  const zeroCell = await screen.findByRole("button", {
    name: "Account Revenue, Period P1, Scenario Actual. 0.00000000",
  });
  fireEvent.click(zeroCell);
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "The selected cell is unavailable.",
  );
  expect(zeroCell).not.toBeInTheDocument();
  expect(
    screen.queryByLabelText("Cell details and writeback"),
  ).not.toBeInTheDocument();
});

it("clears cell context on application change and ignores its late identity read", async () => {
  let resolveCell: ((response: Response) => void) | undefined;
  const functions = {
    "metadata.dimension.list": {},
    "metadata.member.list": {},
    "facts.numeric.batch": {},
  };
  const catalog = {
    applicationAccess: { role: "Editor", workspaceAdministrator: false },
    enabledCapabilities: [],
    functions,
    revisions: { metadata: 2, data: 1, policy: 1, security: 1, commit: 1 },
  };
  const app = {
    workspaceId: "ws",
    applicationId: "first",
    name: "First",
    status: "Active",
  };
  const cell = {
    members: { Account: "Revenue", Period: "Jan" },
    kind: "numeric",
    amount: "12.50",
    lastRevision: 1,
  };
  const response = (result: unknown) =>
    new Response(JSON.stringify({ result }));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (body.program.function === "metadata.dimension.list")
        return response({
          rows: ["Account", "Period"].map((id) => ({
            dimension_id: id,
            name: id,
            model_role: id,
            status: "Active",
          })),
          nextAfterDimensionId: null,
          metadataRevision: 2,
        });
      if (body.program.function === "metadata.member.list")
        return response({
          rows: [],
          nextAfterMemberId: null,
          metadataRevision: 2,
        });
      if (body.program.arguments.includeMissing)
        return new Promise<Response>((resolve) => {
          resolveCell = resolve;
        });
      return response({
        rows: [cell],
        nextCursor: null,
        snapshotRevision: 1,
        source: "raw",
      });
    }),
  );
  const rendered = render(
    <Analyze app={app} catalog={catalog} index={0} subject="editor" />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Suggest layout" }),
    ).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Suggest layout" }));
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Read grid" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  const trigger = await screen.findByRole("button", {
    name: "Account Revenue, Period Jan. 12.50",
  });
  fireEvent.click(trigger);
  expect(screen.getByRole("button", { name: "Close writeback" })).toBeEnabled();
  expect(trigger).toBeDisabled();
  expect(resolveCell).toBeTypeOf("function");
  rendered.rerender(
    <Analyze
      app={{ ...app, applicationId: "second", name: "Second" }}
      catalog={catalog}
      index={1}
      subject="editor"
    />,
  );
  await act(async () =>
    resolveCell?.(
      response({
        rows: [{ ...cell, numericChangeId: "first-app-change" }],
        snapshotRevision: 1,
      }),
    ),
  );
  expect(
    screen.queryByRole("complementary", { name: "Cell details and writeback" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByDisplayValue("first-app-change"),
  ).not.toBeInTheDocument();
  expect(screen.queryByText("12.50")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Read grid" })).toBeDisabled();
});

it("reviews the reread value with its identity and preserves an exact proposal across conflict recovery", async () => {
  const readyPrograms: Record<string, any>[] = [];
  const useActualMutation = exactCellMutation.useExactCellMutation;
  const mutationProbe = vi
    .spyOn(exactCellMutation, "useExactCellMutation")
    .mockImplementation((...args) => {
      if (args[3]) readyPrograms.push(structuredClone(args[3]));
      return useActualMutation(...args);
    });
  onTestFinished(() => mutationProbe.mockRestore());
  const calls: any[] = [];
  let currentAmount = "120.00000001";
  let currentIdentity = "current-1";
  const response = (result: unknown) =>
    new Response(JSON.stringify({ result }));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input, init) => {
      const body = JSON.parse(String(init?.body));
      calls.push({ path: String(input), ...body });
      if (String(input) === "/api/preview")
        return new Response(
          JSON.stringify({
            previewToken: "exact-cell-preview",
            programDigest: "a".repeat(64),
            revisionVector: { data_revision: 2 },
          }),
        );
      if (String(input) === "/api/operation-admission")
        return operationAdmissionResponse();
      if (String(input) === "/api/submit")
        return new Response(
          JSON.stringify({ jobId: "c".repeat(32), status: "ready" }),
        );
      if (body.program.function === "metadata.dimension.list")
        return response({
          rows: ["Account", "Period"].map((id) => ({
            dimension_id: id,
            name: id,
            model_role: id,
            status: "Active",
          })),
          metadataRevision: 2,
          nextAfterDimensionId: null,
        });
      if (body.program.function === "metadata.member.list")
        return response({
          rows: [],
          metadataRevision: 2,
          nextAfterMemberId: null,
        });
      if (body.program.function === "facts.cell.editability.read")
        return response({
          editable: true,
          reasonCode: "RAW_INPUT_EDITABLE",
          message: "Current raw input is editable.",
        });
      return response({
        rows: [
          {
            members: { Account: "Revenue", Period: "Jan" },
            kind: "numeric",
            amount: body.program.arguments.includeMissing
              ? currentAmount
              : "100.00000000",
            numericChangeId: currentIdentity,
          },
        ],
        snapshotRevision: 2,
        nextCursor: null,
        source: "raw",
      });
    }),
  );
  render(
    <Analyze
      app={{
        workspaceId: "ws",
        applicationId: "edit",
        name: "Edit",
        status: "Active",
      }}
      catalog={{
        applicationAccess: { role: "Editor", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: {
          "metadata.dimension.list": {},
          "metadata.member.list": {},
          "facts.numeric.batch": {},
          "facts.cell.editability.read": {},
        },
        revisions: { metadata: 2, data: 2, policy: 1, security: 1, commit: 2 },
      }}
      index={0}
      subject="editor"
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Suggest layout" }),
    ).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Suggest layout" }));
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Account Revenue, Period Jan. 100.00000000",
    }),
  );
  await waitFor(() => expect(screen.getByLabelText("Value")).toBeEnabled());
  expect(screen.getByLabelText("Authoritative cell details")).toHaveTextContent(
    "120.00000001",
  );
  expect(screen.getByLabelText("Value")).toHaveValue("120.00000001");
  fireEvent.change(screen.getByLabelText("Operation"), {
    target: { value: "add" },
  });
  await waitFor(() => expect(screen.getByLabelText("Value")).toBeEnabled());
  fireEvent.change(screen.getByLabelText("Value"), {
    target: { value: "5.00000001" },
  });
  currentAmount = "130.00000001";
  currentIdentity = "current-2";
  readyPrograms.length = 0;
  await act(async () => {
    fireEvent.click(
      screen.getByRole("button", {
        name: "Reread current cell and keep my edit",
      }),
    );
  });
  await waitFor(() => expect(screen.getByLabelText("Value")).toBeEnabled());
  expect(screen.getByLabelText("Value")).toHaveValue("5.00000001");
  expect(screen.getByLabelText("Operation")).toHaveValue("add");
  expect(screen.getByLabelText("Authoritative cell details")).toHaveTextContent(
    "130.00000001",
  );
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Preview exact mutation" }),
    ).toBeEnabled(),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Preview exact mutation" }),
  );
  await waitFor(() => {
    const previews = calls.filter((call) => call.path === "/api/preview");
    expect(previews).toHaveLength(1);
    expect(previews[0].program).toEqual(
      buildWritebackProgram(
        "numeric",
        "add",
        { Account: "Revenue", Period: "Jan" },
        "5.00000001",
        "current-2",
      ),
    );
  });
  expect(readyPrograms.length).toBeGreaterThan(0);
  expect(readyPrograms).toEqual(
    readyPrograms.map(() =>
      buildWritebackProgram(
        "numeric",
        "add",
        { Account: "Revenue", Period: "Jan" },
        "5.00000001",
        "current-2",
      ),
    ),
  );
  const reviewed = screen.getByLabelText("I reviewed this exact cell mutation");
  await waitFor(() => expect(reviewed).toBeEnabled());
  fireEvent.click(reviewed);
  fireEvent.click(
    screen.getByRole("button", { name: "Submit durable writeback" }),
  );
  expect(await screen.findByText(/Request status: ready/)).toBeInTheDocument();
  const submitted = calls.find((call) => call.path === "/api/submit");
  expect(submitted.program).toEqual(
    buildWritebackProgram(
      "numeric",
      "add",
      { Account: "Revenue", Period: "Jan" },
      "5.00000001",
      "current-2",
    ),
  );
  expect(screen.getByLabelText("Value")).toBeDisabled();
});

const savedViewApp = {
  workspaceId: "ws",
  applicationId: "app",
  name: "Plan",
  status: "active",
};
function savedViewCatalog(security = 1, canRead = true, issuer = "issuer") {
  return {
    applicationAccess: {
      issuer,
      role: "Administrator" as const,
      workspaceAdministrator: true,
    },
    enabledCapabilities: [],
    functions: {
      "metadata.dimension.list": {},
      "metadata.member.list": {},
      ...(canRead ? { "grid.definition.list": {} } : {}),
      "grid.definition.save": {},
    },
    revisions: { metadata: 11, data: 9, policy: 1, security, commit: 9 },
  };
}
function savedView(id: string) {
  return {
    gridId: id,
    stateToken: "c".repeat(64),
    name: `View ${id}`,
    creator: { issuer: "issuer", subjectId: "another-client" },
    definition: viewDefinition({ id, name: `View ${id}` }),
    metadataRevision: 11,
    canonicalDigest: `digest-${id}`,
  };
}
function savedViewResponse(
  grids: ReturnType<typeof savedView>[],
  nextAfterGridId: string | null = null,
) {
  return new Response(
    JSON.stringify({
      result: {
        grids,
        nextAfterGridId,
        collectionToken: "b".repeat(64),
      },
    }),
  );
}
function savedViewDimensions() {
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
          {
            dimension_id: "Period",
            name: "Period",
            model_role: "Period",
            status: "Active",
          },
        ],
        nextAfterDimensionId: null,
        metadataRevision: 11,
      },
    }),
  );
}

function canonicalReshapeFixture(
  kind: "raw" | "calculated" | "combined" = "combined",
  withPovSets = false,
) {
  const base = viewDefinition({
    id: "complete-view",
    rows: ["Company", "Region", "Product", "Channel", "Measure", "Currency"],
    columns: ["Year", "Month"],
    pov: { Scenario: "Plan", Version: "Current" },
    kind,
    resultKey: kind === "raw" ? null : "forecast.result",
  });
  const definition = {
    ...base,
    selection: {
      ...base.selection,
      dimensions: base.selection.dimensions.map((axis, index) => ({
        ...axis,
        exclude:
          index === 1
            ? { kind: "member" as const, memberId: "Region-excluded" }
            : null,
        ...(withPovSets && ["Scenario", "Version"].includes(axis.dimensionId)
          ? {
              include: {
                kind: "members" as const,
                memberIds:
                  axis.dimensionId === "Scenario"
                    ? ["Plan", "Actual"]
                    : ["Current", "Prior"],
              },
              exclude: {
                kind: "member" as const,
                memberId: axis.dimensionId === "Scenario" ? "Actual" : "Prior",
              },
            }
          : {}),
      })),
    },
    layout: { ...base.layout, pages: ["Scenario"], filters: ["Version"] },
    suppression: { missing: true, zero: true },
    pageSize: 37,
  };
  const calls: Array<{ function: string; arguments: any }> = [];
  const response = (result: unknown) =>
    new Response(JSON.stringify({ result }));
  const grid = {
    ...savedView(definition.viewId),
    name: definition.name,
    definition,
  };
  const control: {
    save?: (body: any) => Promise<Response>;
    remove?: (body: any) => Promise<Response>;
    list?: () => Response;
    rows?: any[];
  } = {};
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      if (String(path) === "/api/operation-admission")
        return operationAdmissionResponse();
      const body = JSON.parse(String(init?.body));
      const program = body.program;
      calls.push(program);
      if (program.function === "metadata.dimension.list")
        return response({
          rows: definition.selection.dimensions.map(({ dimensionId }) => ({
            dimension_id: dimensionId,
            name: dimensionId,
            model_role: "Custom",
            status: "Active",
          })),
          metadataRevision: 11,
          nextAfterDimensionId: null,
        });
      if (program.function === "metadata.member.list")
        return response({
          rows: [
            {
              member_id: `${program.arguments.dimension}-member`,
              name: "Member",
              status: "Active",
            },
          ],
          metadataRevision: 11,
          nextAfterMemberId: null,
        });
      if (program.function === "grid.definition.list")
        return control.list
          ? control.list()
          : response({
              grids: [grid],
              nextAfterGridId: null,
              collectionToken: "b".repeat(64),
            });
      if (program.function === "grid.definition.save")
        return control.save ? control.save(body) : response(grid);
      if (program.function === "grid.definition.delete")
        return control.remove
          ? control.remove(body)
          : response({ gridId: grid.gridId, status: "Deleted" });
      if (program.function === "facts.cube.resolved.read")
        return response({
          format: "openepm-cube-view-read-v1",
          dataSource:
            program.arguments.view?.dataSource || definition.dataSource,
          readPolicy: program.arguments.readPolicy,
          complete: true,
          rows: control.rows || [],
          snapshot: { commitRevision: 9 },
          presentation: { pageSize: 37, rowCount: control.rows?.length || 0 },
        });
      if (program.function === "facts.cell.editability.read")
        return response({
          editable: false,
          reasonCode: "CALCULATED_RESULT_READ_ONLY",
          message: "Calculated values are read only.",
        });
      throw new Error(`Unexpected ${program.function}`);
    }),
  );
  const catalog = {
    ...savedViewCatalog(),
    functions: {
      ...savedViewCatalog().functions,
      "facts.cube.resolved.read": {
        canonicalViewRead: "openepm-cube-view-read-v1",
      },
      "grid.definition.delete": {},
      "facts.cell.editability.read": {},
    },
  };
  const view = render(
    <Analyze app={savedViewApp} catalog={catalog} index={0} subject="owner" />,
  );
  return { definition, grid, calls, control, response, view, catalog };
}

it.each(["raw", "calculated", "combined"] as const)(
  "reshapes an opened %s canonical view without resetting its other meaning",
  async (kind) => {
    const fixture = canonicalReshapeFixture(kind);
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Open view" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Open view" }));
    fireEvent.change(screen.getByLabelText("Rows"), {
      target: { value: "Region" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
    await waitFor(() =>
      expect(
        fixture.calls.some(
          ({ function: fn }) => fn === "facts.cube.resolved.read",
        ),
      ).toBe(true),
    );
    const actual = fixture.calls.find(
      ({ function: fn }) => fn === "facts.cube.resolved.read",
    )!;
    expect(actual.arguments.view).toEqual({
      ...fixture.definition,
      layout: {
        ...fixture.definition.layout,
        rows: [
          "Region",
          "Company",
          "Product",
          "Channel",
          "Measure",
          "Currency",
        ],
      },
    });
    expect(actual.arguments.readPolicy).toEqual({
      semantics: kind === "raw" ? "own" : "stored",
    });
    expect(unsavedWorkSnapshot()).toHaveLength(1);
  },
);

it("describes canonical layout and explicit read links without a conflicting scalar summary", async () => {
  const fixture = canonicalReshapeFixture("combined", true);
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Open view" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Open view" }));
  fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
  const layout = screen.getByLabelText("Current grid layout");
  expect(layout).toHaveTextContent("PAGES1 axis · Scenario");
  expect(layout).toHaveTextContent("FILTERS1 axis · Version");
  const drawer = screen.getByRole("complementary", {
    name: "Pages, rows, columns and filters",
  });
  expect(
    within(drawer).getByRole("group", { name: "Pages" }),
  ).toHaveTextContent("Scenario");
  expect(
    within(drawer).getByRole("group", { name: "Filters" }),
  ).toHaveTextContent("Version");
  expect(drawer.querySelector(".layout-drawer-summary")).toBeNull();
  expect(drawer).not.toHaveTextContent("No fixed members");
  const semantics = screen.getByLabelText("Grid value semantics");
  expect(semantics).toHaveTextContent(
    "an explicit view link restores its stated supported read policy or refuses the read",
  );
  expect(semantics).toHaveTextContent(
    "Effective bindings are session-only and are not restored by saved views or view links",
  );
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  await waitFor(() =>
    expect(
      fixture.calls.find(
        ({ function: fn }) => fn === "facts.cube.resolved.read",
      )?.arguments.view,
    ).toEqual(fixture.definition),
  );
});

it("does not clear a newer view draft when an earlier save acknowledgement arrives", async () => {
  const fixture = canonicalReshapeFixture();
  let finish!: (response: Response) => void;
  fixture.control.save = () =>
    new Promise<Response>((resolve) => {
      finish = resolve;
    });
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Open view" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Open view" }));
  fireEvent.click(screen.getByText("Save current view"));
  fireEvent.change(screen.getByLabelText("Display name"), {
    target: { value: "Original reviewed view" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save view" }));
  await waitFor(() => expect(finish).toBeDefined());
  fireEvent.change(screen.getByLabelText("Display name"), {
    target: { value: "Newer unsaved view" },
  });
  await act(async () =>
    finish(
      fixture.response({ ...fixture.grid, name: "Original reviewed view" }),
    ),
  );
  expect(screen.getByLabelText("Display name")).toHaveValue(
    "Newer unsaved view",
  );
  expect(unsavedWorkSnapshot()).toHaveLength(1);
});

it("keeps canonical selection and source when swapping first axes across layout roles", async () => {
  const fixture = canonicalReshapeFixture();
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Open view" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Open view" }));
  fireEvent.change(screen.getByLabelText("Rows"), {
    target: { value: "Month" },
  });
  fireEvent.change(screen.getByLabelText("Columns"), {
    target: { value: "Scenario" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  await waitFor(() =>
    expect(
      fixture.calls.some(
        ({ function: fn }) => fn === "facts.cube.resolved.read",
      ),
    ).toBe(true),
  );
  expect(
    fixture.calls.find(({ function: fn }) => fn === "facts.cube.resolved.read")!
      .arguments.view,
  ).toEqual({
    ...fixture.definition,
    layout: {
      rows: ["Month", "Region", "Product", "Channel", "Measure", "Currency"],
      columns: ["Scenario", "Company"],
      pages: ["Year"],
      filters: ["Version"],
    },
  });
});

it("moves and reorders every canonical layout role without changing selection or emptying a required axis", async () => {
  const fixture = canonicalReshapeFixture();
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Open view" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Open view" }));
  fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
  fireEvent.change(screen.getByLabelText("Company axis location"), {
    target: { value: "filters" },
  });
  fireEvent.change(screen.getByLabelText("Version axis location"), {
    target: { value: "columns" },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Move Month earlier in Columns" }),
  );
  fireEvent.change(screen.getByLabelText("Scenario axis location"), {
    target: { value: "rows" },
  });
  fireEvent.change(screen.getByLabelText("Company axis location"), {
    target: { value: "pages" },
  });
  fireEvent.change(screen.getByLabelText("Year axis location"), {
    target: { value: "rows" },
  });
  fireEvent.change(screen.getByLabelText("Version axis location"), {
    target: { value: "rows" },
  });
  expect(
    within(screen.getByLabelText("Month axis location")).getByRole("option", {
      name: "Rows",
    }),
  ).toBeDisabled();
  // The transition itself also refuses an invalid event; the UI is not the only guard.
  fireEvent.change(screen.getByLabelText("Month axis location"), {
    target: { value: "rows" },
  });
  expect(screen.getByLabelText("Month axis location")).toHaveValue("columns");
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  await waitFor(() =>
    expect(
      fixture.calls.some(
        ({ function: fn }) => fn === "facts.cube.resolved.read",
      ),
    ).toBe(true),
  );
  expect(
    fixture.calls.find(({ function: fn }) => fn === "facts.cube.resolved.read")!
      .arguments.view,
  ).toEqual({
    ...fixture.definition,
    layout: {
      rows: [
        "Region",
        "Product",
        "Channel",
        "Measure",
        "Currency",
        "Scenario",
        "Year",
        "Version",
      ],
      columns: ["Month"],
      pages: ["Company"],
      filters: [],
    },
  });
  expect(unsavedWorkSnapshot()).toHaveLength(1);
});

it("suggests primary axes for an opened canonical view without regenerating its selection or layer", async () => {
  const fixture = canonicalReshapeFixture("calculated");
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Open view" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Open view" }));
  fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
  fireEvent.click(screen.getByRole("button", { name: "Suggest layout" }));
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  await waitFor(() =>
    expect(
      fixture.calls.some(
        ({ function: fn }) => fn === "facts.cube.resolved.read",
      ),
    ).toBe(true),
  );
  expect(
    fixture.calls.find(({ function: fn }) => fn === "facts.cube.resolved.read")!
      .arguments.view,
  ).toEqual({
    ...fixture.definition,
    layout: {
      ...fixture.definition.layout,
      rows: ["Company", "Year", "Product", "Channel", "Measure", "Currency"],
      columns: ["Region", "Month"],
    },
  });
});

it.each(["same-values-again", "changed-authority", "newer-layout"] as const)(
  "fences an earlier save acknowledgement after %s",
  async (change) => {
    const fixture = canonicalReshapeFixture();
    let finish!: (response: Response) => void;
    fixture.control.save = () =>
      new Promise<Response>((resolve) => {
        finish = resolve;
      });
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Open view" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Open view" }));
    fireEvent.click(screen.getByText("Save current view"));
    fireEvent.change(screen.getByLabelText("Display name"), {
      target: { value: "Reviewed view" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save view" }));
    await waitFor(() => expect(finish).toBeDefined());
    if (change === "changed-authority")
      fixture.view.rerender(
        <Analyze
          app={savedViewApp}
          catalog={{
            ...fixture.catalog,
            revisions: { ...fixture.catalog.revisions, security: 2 },
          }}
          index={0}
          subject="owner"
        />,
      );
    else if (change === "newer-layout")
      fireEvent.change(screen.getByLabelText("Rows"), {
        target: { value: "Region" },
      });
    else {
      fireEvent.change(screen.getByLabelText("Display name"), {
        target: { value: "Intervening edit" },
      });
      fireEvent.change(screen.getByLabelText("Display name"), {
        target: { value: "Reviewed view" },
      });
    }
    await act(async () =>
      finish(fixture.response({ ...fixture.grid, name: "Reviewed view" })),
    );
    expect(unsavedWorkSnapshot()).toHaveLength(1);
    if (change === "changed-authority")
      expect(
        screen.queryByText(/^Saved Reviewed view/),
      ).not.toBeInTheDocument();
    else
      expect(
        screen.getByText(/Your newer view edits are still unsaved/),
      ).toBeVisible();
  },
);

it.each(["save", "delete"] as const)(
  "releases obsolete %s presentation on authority refresh without clearing a newer operation's busy state",
  async (operation) => {
    const fixture = canonicalReshapeFixture();
    const pending: Array<(response: Response) => void> = [];
    fixture.control.save = () =>
      new Promise<Response>((resolve) => {
        pending.push(resolve);
      });
    fixture.control.remove = fixture.control.save;
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Open view" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Open view" }));
    fireEvent.click(screen.getByText("Save current view"));
    fireEvent.change(screen.getByLabelText("Display name"), {
      target: { value: "Earlier authority" },
    });
    fireEvent.click(
      screen.getByRole("button", {
        name: operation === "save" ? "Save view" : "Delete view",
      }),
    );
    await waitFor(() => expect(pending).toHaveLength(1));
    fixture.view.rerender(
      <Analyze
        app={savedViewApp}
        catalog={{
          ...fixture.catalog,
          revisions: { ...fixture.catalog.revisions, security: 2 },
        }}
        index={0}
        subject="owner"
      />,
    );
    const save = screen.getByRole("button", { name: "Save view" });
    await waitFor(() => expect(save).toBeEnabled());
    fireEvent.change(screen.getByLabelText("Display name"), {
      target: { value: "Current authority" },
    });
    fireEvent.click(save);
    await waitFor(() => expect(pending).toHaveLength(2));
    await act(async () =>
      pending[0](
        fixture.response(
          operation === "save"
            ? { ...fixture.grid, name: "Earlier authority" }
            : { gridId: fixture.grid.gridId, status: "Deleted" },
        ),
      ),
    );
    expect(save).toBeDisabled();
    expect(
      screen.queryByText(/^Saved Earlier authority/),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/^Deleted /)).not.toBeInTheDocument();
    expect(screen.getByLabelText("Stable grid ID")).toHaveValue(
      fixture.definition.viewId,
    );
    expect(screen.getByLabelText("Display name")).toHaveValue(
      "Current authority",
    );
    expect(unsavedWorkSnapshot()).toHaveLength(1);
    await act(async () =>
      pending[1](
        fixture.response({ ...fixture.grid, name: "Current authority" }),
      ),
    );
    await waitFor(() => expect(save).toBeEnabled());
    expect(screen.getByText("Saved Current authority.")).toBeVisible();
    expect(unsavedWorkSnapshot()).toHaveLength(0);
  },
);

it.each(["filtered", "refused"] as const)(
  "clears an opened saved view and its catalogue entry when the current list is %s",
  async (outcome) => {
    const fixture = canonicalReshapeFixture();
    const open = screen.getByRole("button", { name: "Open view" });
    await waitFor(() => expect(open).toBeEnabled());
    fireEvent.click(open);
    expect(screen.getByLabelText("Configured grid source")).toHaveTextContent(
      "combined",
    );
    fixture.control.list = () =>
      outcome === "filtered"
        ? fixture.response({
            grids: [],
            nextAfterGridId: null,
            collectionToken: "c".repeat(64),
          })
        : new Response(
            JSON.stringify({
              code: "SAVED_GRID_SCOPE_UNAVAILABLE",
              message:
                "The complete saved-view selection is unavailable under your current dimensional access.",
            }),
            { status: 403 },
          );
    fireEvent.click(screen.getByRole("button", { name: "Refresh views" }));
    await waitFor(() => expect(open).toBeDisabled());
    await waitFor(() =>
      expect(screen.getByLabelText("Configured grid source")).toHaveTextContent(
        "raw",
      ),
    );
    expect(
      screen.queryByRole("option", { name: fixture.grid.name }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/^Opened /)).not.toBeInTheDocument();
  },
);

it("keeps a newer local view draft after deletion of its original saved definition completes", async () => {
  const fixture = canonicalReshapeFixture();
  let finish!: (response: Response) => void;
  fixture.control.remove = () =>
    new Promise<Response>((resolve) => {
      finish = resolve;
    });
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Open view" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Open view" }));
  fireEvent.click(screen.getByText("Save current view"));
  fireEvent.click(screen.getByRole("button", { name: "Delete view" }));
  await waitFor(() => expect(finish).toBeDefined());
  fireEvent.change(screen.getByLabelText("Display name"), {
    target: { value: "Newer local definition" },
  });
  await act(async () =>
    finish(
      fixture.response({ gridId: fixture.grid.gridId, status: "Deleted" }),
    ),
  );
  expect(screen.getByLabelText("Display name")).toHaveValue(
    "Newer local definition",
  );
  expect(screen.getByLabelText("Configured grid source")).toHaveTextContent(
    "combined",
  );
  expect(unsavedWorkSnapshot()).toHaveLength(1);
});

it("retains the reshaped canonical draft when inspecting a cell and returning to it", async () => {
  const fixture = canonicalReshapeFixture("calculated");
  fixture.control.rows = [
    {
      members: Object.fromEntries(
        fixture.definition.selection.dimensions.map((axis) => [
          axis.dimensionId,
          axis.include.kind === "member"
            ? axis.include.memberId
            : axis.include.memberIds[0],
        ]),
      ),
      values: {
        calculated: [
          {
            present: true,
            value: "125.00000000",
            unit: "amount",
            origin: "materialized",
            currentness: "current",
            resultStateToken: "a".repeat(64),
          },
        ],
      },
    },
  ];
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Open view" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Open view" }));
  fireEvent.click(screen.getByText("Save current view"));
  fireEvent.change(screen.getByLabelText("Rows"), {
    target: { value: "Region" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  const cell = await screen.findByRole("button", { name: /125\.00000000/ });
  fireEvent.click(cell);
  const close = await screen.findByRole("button", { name: "Close writeback" });
  await waitFor(() => expect(close).toBeEnabled());
  fireEvent.click(close);
  expect(cell).toHaveFocus();
  expect(screen.getByLabelText("Stable grid ID")).toHaveValue(
    fixture.definition.viewId,
  );
  expect(screen.getByLabelText("Display name")).toHaveValue(
    fixture.definition.name,
  );
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  fireEvent.click(screen.getByRole("button", { name: "Save view" }));
  await waitFor(() =>
    expect(
      fixture.calls.some(({ function: fn }) => fn === "grid.definition.save"),
    ).toBe(true),
  );
  expect(
    fixture.calls.find(({ function: fn }) => fn === "grid.definition.save")!
      .arguments.definition,
  ).toEqual({
    ...fixture.definition,
    layout: {
      ...fixture.definition.layout,
      rows: ["Region", "Company", "Product", "Channel", "Measure", "Currency"],
    },
  });
});

it("automatically discovers all shared saved views in a visible region without a refresh ritual", async () => {
  const requests: Record<string, unknown>[] = [];
  let completeFirst!: (response: Response) => void;
  const firstPage = new Promise<Response>((resolve) => {
    completeFirst = resolve;
  });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input, init) => {
      const body = JSON.parse(String(init?.body));
      if (body.program.function === "metadata.dimension.list")
        return savedViewDimensions();
      expect(body.program.function).toBe("grid.definition.list");
      requests.push(body);
      return body.program.arguments.afterGridId
        ? savedViewResponse([savedView("four"), savedView("five")])
        : firstPage;
    }),
  );
  render(
    <Analyze
      app={savedViewApp}
      catalog={savedViewCatalog()}
      index={0}
      subject="owner"
    />,
  );
  expect(screen.getByRole("region", { name: "Saved views" }).tagName).toBe(
    "SECTION",
  );
  expect(screen.getByRole("combobox", { name: "Saved view" })).toBeVisible();
  expect(
    screen.queryByRole("option", { name: "No saved views" }),
  ).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Open view" })).toBeDisabled();
  await act(async () => {
    completeFirst(
      savedViewResponse(
        [savedView("one"), savedView("two"), savedView("three")],
        "three",
      ),
    );
  });
  await waitFor(() => expect(screen.getByText("5 saved views")).toBeVisible());
  expect(screen.getByRole("option", { name: /View five/ })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Open view" })).toBeEnabled();
  expect(requests).toEqual([
    {
      workspaceId: "ws",
      applicationId: "app",
      program: {
        languageVersion: 2,
        function: "grid.definition.list",
        arguments: { limit: 100 },
      },
    },
    {
      workspaceId: "ws",
      applicationId: "app",
      program: {
        languageVersion: 2,
        function: "grid.definition.list",
        arguments: {
          limit: 100,
          afterGridId: "three",
          expectedCollectionToken: "b".repeat(64),
        },
      },
    },
  ]);
  expect(screen.getByLabelText("Rows")).toHaveValue(""); // Discovery never replaces an editor layout.
});

it.each(["application", "authority", "issuer", "security"] as const)(
  "rejects late saved-view replies after the %s context changes",
  async (change) => {
    const pending: Array<{
      resolve: (response: Response) => void;
      signal: AbortSignal;
      applicationId: string;
    }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input, init) => {
        const body = JSON.parse(String(init?.body));
        if (body.program.function === "metadata.dimension.list")
          return savedViewDimensions();
        return new Promise<Response>((resolve) =>
          pending.push({
            resolve,
            signal: init?.signal as AbortSignal,
            applicationId: body.applicationId,
          }),
        );
      }),
    );
    const { rerender, unmount } = render(
      <Analyze
        app={savedViewApp}
        catalog={savedViewCatalog()}
        index={0}
        subject="owner"
      />,
    );
    await waitFor(() => expect(pending).toHaveLength(1));
    rerender(
      <Analyze
        app={
          change === "application"
            ? { ...savedViewApp, applicationId: "other" }
            : savedViewApp
        }
        catalog={savedViewCatalog(
          change === "security" ? 2 : 1,
          true,
          change === "issuer" ? "another-issuer" : "issuer",
        )}
        index={0}
        subject={change === "authority" ? "second-owner" : "owner"}
      />,
    );
    await waitFor(() => expect(pending).toHaveLength(2));
    expect(pending[0].signal.aborted).toBe(true);
    await act(async () => {
      pending[0].resolve(savedViewResponse([savedView("stale-private-view")]));
    });
    expect(
      screen.queryByRole("option", { name: /stale-private-view/ }),
    ).not.toBeInTheDocument();
    await act(async () => {
      pending[1].resolve(savedViewResponse([savedView("current-view")]));
    });
    await waitFor(() =>
      expect(
        screen.getByRole("option", { name: /current-view/ }),
      ).toBeInTheDocument(),
    );
    expect(pending[1].applicationId).toBe(
      change === "application" ? "other" : "app",
    );
    unmount();
    expect(pending[1].signal.aborted).toBe(true);
  },
);

it("clears loaded view names immediately on permission revocation and loads when authorized discovery arrives", async () => {
  let reads = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input, init) => {
      const body = JSON.parse(String(init?.body));
      if (body.program.function === "metadata.dimension.list")
        return savedViewDimensions();
      reads += 1;
      return savedViewResponse([savedView("authorized")]);
    }),
  );
  const { rerender } = render(
    <Analyze app={savedViewApp} catalog={null} index={0} subject="owner" />,
  );
  await waitFor(() => expect(screen.getByLabelText("Rows")).toHaveValue(""));
  expect(reads).toBe(0);
  rerender(
    <Analyze
      app={savedViewApp}
      catalog={savedViewCatalog()}
      index={0}
      subject="owner"
    />,
  );
  await waitFor(() =>
    expect(
      screen.getByRole("option", { name: /View authorized/ }),
    ).toBeInTheDocument(),
  );
  expect(reads).toBe(1);
  rerender(
    <Analyze
      app={savedViewApp}
      catalog={savedViewCatalog(2, false)}
      index={0}
      subject="owner"
    />,
  );
  expect(
    screen.queryByRole("option", { name: /View authorized/ }),
  ).not.toBeInTheDocument();
  expect(reads).toBe(1);
});

it("distinguishes a saved-view read failure from a verified empty catalog and retries explicitly", async () => {
  let reads = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input, init) => {
      const body = JSON.parse(String(init?.body));
      if (body.program.function === "metadata.dimension.list")
        return savedViewDimensions();
      reads += 1;
      return reads === 1
        ? new Response(JSON.stringify({ code: "READ_UNAVAILABLE" }), {
            status: 503,
          })
        : savedViewResponse([]);
    }),
  );
  render(
    <Analyze
      app={savedViewApp}
      catalog={savedViewCatalog()}
      index={0}
      subject="owner"
    />,
  );
  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent("READ_UNAVAILABLE"),
  );
  expect(
    screen.queryByRole("option", { name: "No saved views" }),
  ).not.toBeInTheDocument();
  expect(screen.queryByText("0 saved views")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Refresh views" }));
  await waitFor(() =>
    expect(
      screen.getByRole("option", { name: "No saved views" }),
    ).toBeInTheDocument(),
  );
  expect(screen.getByText("0 saved views")).toBeVisible();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  expect(reads).toBe(2);
});

it("refreshes view discovery without losing a draft and guards opening another view", async () => {
  let reads = 0;
  const transition = vi.fn();
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input, init) => {
      const body = JSON.parse(String(init?.body));
      if (body.program.function === "metadata.dimension.list")
        return savedViewDimensions();
      reads += 1;
      return savedViewResponse([savedView("shared")]);
    }),
  );
  render(
    <Analyze
      app={savedViewApp}
      catalog={savedViewCatalog()}
      index={0}
      subject="owner"
      onRequestTransition={transition}
    />,
  );
  await waitFor(() => expect(screen.getByText("1 saved view")).toBeVisible());
  fireEvent.click(screen.getByText("Save current view"));
  fireEvent.change(screen.getByLabelText("Stable grid ID"), {
    target: { value: "my-draft" },
  });
  fireEvent.change(screen.getByLabelText("Display name"), {
    target: { value: "Unsaved draft" },
  });
  fireEvent.change(screen.getByLabelText("Rows"), {
    target: { value: "Period" },
  });
  fireEvent.change(screen.getByLabelText("Columns"), {
    target: { value: "Account" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Refresh views" }));
  await waitFor(() => expect(reads).toBe(2));
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Open view" })).toBeEnabled(),
  );
  expect(screen.getByLabelText("Stable grid ID")).toHaveValue("my-draft");
  expect(screen.getByLabelText("Display name")).toHaveValue("Unsaved draft");
  fireEvent.click(screen.getByRole("button", { name: "Open view" }));
  expect(transition).toHaveBeenCalledOnce();
  expect(screen.getByLabelText("Rows")).toHaveValue("Period");
  expect(screen.getByLabelText("Stable grid ID")).toHaveValue("my-draft");
  act(() => transition.mock.calls[0][0]());
  expect(screen.getByLabelText("Rows")).toHaveValue("Account");
  expect(screen.getByLabelText("Stable grid ID")).toHaveValue("shared");
});

it("shows every configured saved axis and labels the own read actually executed", async () => {
  const rowIds = [
    "Company",
    "Region",
    "Product",
    "Channel",
    "Measure",
    "Currency",
  ];
  const columnIds = ["Year", "Month"];
  const fixedIds = [
    "Scenario",
    "View",
    "Value",
    "DataType",
    "Team",
    "Site",
    "Skill",
  ];
  const definition = viewDefinition({
    id: "many-axes",
    rows: rowIds,
    columns: columnIds,
    pov: Object.fromEntries(fixedIds.map((id) => [id, `${id}-member`])),
  });
  definition.layout.pages = [fixedIds[0]];
  definition.layout.filters = fixedIds.slice(1);
  const calls: Array<{ function: string; arguments: Record<string, unknown> }> =
    [];
  const response = (result: unknown) =>
    new Response(JSON.stringify({ result }));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input, init) => {
      const body = JSON.parse(String(init?.body));
      const program = body.program;
      calls.push(program);
      if (program.function === "metadata.dimension.list")
        return response({
          rows: [...rowIds, ...columnIds, ...fixedIds].map((id) => ({
            dimension_id: id,
            name: id,
            model_role: "Custom",
            status: "Active",
          })),
          metadataRevision: 11,
          nextAfterDimensionId: null,
        });
      if (program.function === "grid.definition.list")
        return response({
          grids: [
            { ...savedView("many-axes"), name: definition.name, definition },
          ],
          nextAfterGridId: null,
          collectionToken: "b".repeat(64),
        });
      if (program.function === "metadata.member.list")
        return response({
          rows: [
            {
              member_id: `${program.arguments.dimension}-member`,
              name: `${program.arguments.dimension}-member`,
              status: "Active",
            },
          ],
          metadataRevision: 11,
          nextAfterMemberId: null,
        });
      if (program.function === "facts.cube.resolved.binding.list")
        return response({ bindings: [] });
      if (program.function === "facts.cube.resolved.read")
        return response({
          rows: [
            {
              members: Object.fromEntries(
                [...rowIds, ...columnIds, ...fixedIds].map((id) => [
                  id,
                  `${id}-member`,
                ]),
              ),
              present: true,
              value: "25.00",
              resultUnit: "amount",
              origin: "input",
              currentness: "current",
              resultStateToken: null,
              lineage: [],
            },
          ],
          snapshot: { commitRevision: 20 },
          stages: [
            { stage: "input", sourceDigest: "source", currentness: "current" },
          ],
          presentation: {
            pageSize: 100,
            suppression: { missing: false, zero: false },
            rowCount: 1,
          },
        });
      throw new Error(`Unexpected ${program.function}`);
    }),
  );
  render(
    <Analyze
      app={savedViewApp}
      catalog={{
        ...savedViewCatalog(),
        functions: {
          ...savedViewCatalog().functions,
          "facts.cube.resolved.read": {},
          "facts.cube.resolved.binding.list": {},
        },
      }}
      index={0}
      subject="owner"
    />,
  );
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Open view" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Open view" }));
  const summary = screen.getByLabelText("Current grid layout");
  expect(summary).toHaveTextContent(`6 axes · ${rowIds.join(" / ")}`);
  expect(summary).toHaveTextContent(`2 axes · ${columnIds.join(" / ")}`);
  expect(summary).toHaveTextContent("1 axis · Scenario");
  expect(summary).toHaveTextContent(
    `6 axes · ${fixedIds.slice(1).join(" / ")}`,
  );
  const secondary = screen.getByLabelText("Opened grid layout");
  for (const id of [...rowIds, ...columnIds, ...fixedIds])
    expect(secondary).toHaveTextContent(id);
  expect(screen.getByText("No snapshot read")).toBeInTheDocument();
  expect(screen.getByLabelText("Value semantics")).toHaveValue("own");
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  await waitFor(() => expect(screen.getByText("25.00")).toBeInTheDocument());
  expect(screen.getByLabelText("Loaded grid read")).toHaveTextContent(
    "Own input at each member · input · current",
  );
  expect(screen.getByLabelText("Loaded grid read")).not.toHaveTextContent(
    "effective",
  );
  const read = calls.find(
    (call) => call.function === "facts.cube.resolved.read",
  );
  expect(read?.arguments).toMatchObject({
    source: { semantics: "own" },
    selection: definition.selection,
    dynamicFallback: false,
  });
  fireEvent.change(screen.getByLabelText("Value semantics"), {
    target: { value: "effective" },
  });
  expect(screen.getByRole("button", { name: "Read grid" })).toBeDisabled();
  expect(screen.getByLabelText("Grid read unavailable")).toHaveTextContent(
    "cannot replace that source layer",
  );
  expect(screen.queryByText("25.00")).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Loaded grid read")).not.toBeInTheDocument();
  expect(
    calls.filter((call) => call.function === "facts.cube.resolved.read"),
  ).toHaveLength(1);
});

it("ignores a delayed grid result after its read policy changes", async () => {
  let resolveRead!: (response: Response) => void;
  let readSignal: AbortSignal | undefined;
  const response = (result: unknown) =>
    new Response(JSON.stringify({ result }));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input, init) => {
      const { program } = JSON.parse(String(init?.body));
      if (program.function === "metadata.dimension.list")
        return savedViewDimensions();
      if (program.function === "metadata.member.list")
        return response({
          rows: [{ member_id: "member", name: "Member", status: "Active" }],
          metadataRevision: 11,
          nextAfterMemberId: null,
        });
      if (program.function === "facts.cube.resolved.read") {
        readSignal = init?.signal as AbortSignal;
        return new Promise<Response>((resolve) => {
          resolveRead = resolve;
        });
      }
      throw new Error(`Unexpected ${program.function}`);
    }),
  );
  render(
    <Analyze
      app={savedViewApp}
      catalog={{
        ...savedViewCatalog(),
        functions: {
          "metadata.dimension.list": {},
          "metadata.member.list": {},
          "facts.cube.resolved.read": {},
        },
      }}
      index={0}
      subject="owner"
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Suggest layout" }),
    ).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Suggest layout" }));
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  await waitFor(() => expect(resolveRead).toBeTypeOf("function"));
  fireEvent.change(screen.getByLabelText("Value semantics"), {
    target: { value: "stored" },
  });
  expect(readSignal?.aborted).toBe(true);
  await act(async () =>
    resolveRead(
      response({
        rows: [
          {
            members: { Account: "member", Period: "member" },
            present: true,
            value: "stale-private-value",
            resultUnit: "text",
            origin: "input",
            currentness: "current",
            resultStateToken: null,
            lineage: [],
          },
        ],
        snapshot: { commitRevision: 20 },
        stages: [],
        presentation: {
          pageSize: 100,
          suppression: { missing: false, zero: false },
          rowCount: 1,
        },
      }),
    ),
  );
  expect(screen.queryByText("stale-private-value")).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Loaded grid read")).not.toBeInTheDocument();
  expect(screen.getByText("No snapshot read")).toBeInTheDocument();
  expect(screen.getByLabelText("Configured read policy")).toHaveTextContent(
    "Stored raw values",
  );
});

it("reports a failed effective read without substituting own or raw values", async () => {
  const reads: Array<Record<string, unknown>> = [];
  const response = (result: unknown) =>
    new Response(JSON.stringify({ result }));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input, init) => {
      const { program } = JSON.parse(String(init?.body));
      if (program.function === "metadata.dimension.list")
        return savedViewDimensions();
      if (program.function === "metadata.member.list")
        return response({
          rows: [{ member_id: "member", name: "Member", status: "Active" }],
          metadataRevision: 11,
          nextAfterMemberId: null,
        });
      if (program.function === "facts.cube.resolved.binding.list")
        return response({
          bindings: [
            {
              bindingId: "governed-result",
              stateToken: "b".repeat(64),
              stages: [],
            },
          ],
        });
      reads.push(program);
      return new Response(JSON.stringify({ code: "CALCULATION_REQUIRED" }), {
        status: 409,
      });
    }),
  );
  render(
    <Analyze
      app={savedViewApp}
      catalog={{
        ...savedViewCatalog(),
        functions: {
          "metadata.dimension.list": {},
          "metadata.member.list": {},
          "facts.cube.resolved.read": {},
          "facts.cube.resolved.binding.list": {},
        },
      }}
      index={0}
      subject="owner"
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Suggest layout" }),
    ).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Suggest layout" }));
  fireEvent.change(screen.getByLabelText("Value semantics"), {
    target: { value: "effective" },
  });
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Read grid" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent("CALCULATION_REQUIRED"),
  );
  expect(reads).toHaveLength(1);
  expect(reads[0]).toMatchObject({
    function: "facts.cube.resolved.read",
    arguments: {
      source: {
        semantics: "effective",
        bindingId: "governed-result",
        bindingStateToken: "b".repeat(64),
      },
      dynamicFallback: false,
    },
  });
  expect(screen.getByText("No snapshot read")).toBeInTheDocument();
  expect(screen.queryByLabelText("Loaded grid read")).not.toBeInTheDocument();
});

it("reads the complete canonical combined selection and keeps its two values separate", async () => {
  const definition = viewDefinition({
    id: "combined-view",
    kind: "combined",
    resultKey: "forecast.result",
  });
  definition.selection.dimensions[0].include = {
    kind: "members",
    memberIds: ["Revenue", "Cost"],
  };
  const calls: Array<{ function: string; arguments: Record<string, unknown> }> =
    [];
  const response = (result: unknown) =>
    new Response(JSON.stringify({ result }));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input, init) => {
      const { program } = JSON.parse(String(init?.body));
      calls.push(program);
      if (program.function === "metadata.dimension.list")
        return savedViewDimensions();
      if (program.function === "grid.definition.list")
        return response({
          grids: [
            {
              ...savedView("combined-view"),
              name: definition.name,
              definition,
            },
          ],
          nextAfterGridId: null,
          collectionToken: "b".repeat(64),
        });
      if (program.function === "metadata.member.list")
        return response({
          rows: [],
          nextAfterMemberId: null,
          metadataRevision: 11,
        });
      if (program.function === "facts.cell.editability.read")
        return response({
          editable: false,
          reasonCode: "CALCULATED_RESULT_READ_ONLY",
          message: "Separate result layers are read-only.",
        });
      if (program.function !== "facts.cube.resolved.read")
        throw new Error(`Unexpected ${program.function}`);
      return response({
        format: "openepm-cube-view-read-v1",
        dataSource: definition.dataSource,
        readPolicy: { semantics: "stored" },
        complete: true,
        snapshot: { commitRevision: 23 },
        presentation: { pageSize: 100, rowCount: 1 },
        rows: [
          {
            members: { Account: "Revenue", Period: "Period-member" },
            values: {
              raw: [
                {
                  present: true,
                  value: "100.00000000",
                  unit: "amount",
                  origin: "input",
                  currentness: "current",
                  resultStateToken: null,
                },
              ],
              calculated: [
                {
                  present: true,
                  value: "105.00000000",
                  unit: "amount",
                  origin: "materialized",
                  currentness: "current",
                  resultStateToken: "a".repeat(64),
                },
              ],
            },
          },
        ],
        calculation: {
          resultKey: "forecast.result",
          resultStateToken: "a".repeat(64),
          inputRevisionStatus: { matchesAtRead: true },
        },
      });
    }),
  );
  render(
    <Analyze
      app={savedViewApp}
      catalog={{
        ...savedViewCatalog(),
        functions: {
          ...savedViewCatalog().functions,
          "facts.cube.resolved.read": {
            canonicalViewRead: "openepm-cube-view-read-v1",
          },
          "facts.cell.editability.read": {},
        },
      }}
      index={0}
      subject="owner"
    />,
  );
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Open view" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Open view" }));
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  await waitFor(() =>
    expect(
      screen.getByText("Raw: 100.00000000 · Calculated: 105.00000000"),
    ).toBeInTheDocument(),
  );
  expect(screen.getByLabelText("Loaded grid read")).toHaveTextContent(
    "Separate raw and calculated values",
  );
  expect(screen.getByRole("button", { name: "KPI" })).toBeDisabled();
  expect(screen.getByRole("button", { name: "Chart" })).toBeDisabled();
  expect(
    screen.getByText(
      /KPI and chart presentations require a single source layer/,
    ),
  ).toBeInTheDocument();
  const actual = calls.find(
    (call) => call.function === "facts.cube.resolved.read",
  );
  expect(actual?.arguments).toEqual({
    format: "openepm-cube-view-read-v1",
    view: definition,
    readPolicy: { semantics: "stored" },
    limits: { maxRows: 500, maxSourceRows: 100_000, timeoutMs: 30_000 },
  });
  expect(
    calls.some(
      (call) =>
        call.function === "facts.calculation.scan" ||
        call.function === "facts.cube.scan",
    ),
  ).toBe(false);
  fireEvent.click(
    screen.getByRole("button", {
      name: /Account Revenue, Period Period-member\. Raw:/,
    }),
  );
  expect(screen.getByLabelText("Separate source values")).toHaveTextContent(
    "Raw100.00000000Calculated105.00000000",
  );
  expect(
    screen.queryByRole("button", { name: "Submit durable writeback" }),
  ).not.toBeInTheDocument();
});

const presentationValue = (
  value: string | null,
  unit: string | Record<string, unknown> = "amount",
) => ({
  value,
  unit,
  present: value !== null,
  origin: "input",
  currentness: "current",
  resultStateToken: null,
});

it.each([
  { name: "empty results", values: [], reason: /loaded page has none/ },
  {
    name: "missing values",
    values: [[presentationValue(null)]],
    reason: /missing values are not treated as zero/,
  },
  {
    name: "present empty text",
    values: [[presentationValue("", "text")]],
    reason: /loaded page contains text/,
  },
  {
    name: "mixed text and numbers",
    values: [
      [presentationValue("0.00000000")],
      [presentationValue("note", "text")],
    ],
    reason: /loaded page contains text/,
  },
  {
    name: "different currencies",
    values: [
      [presentationValue("1.20000000", { type: "currency", memberId: "CHF" })],
      [presentationValue("1.30000000", { type: "currency", memberId: "USD" })],
    ],
    reason: /loaded page contains different units/,
  },
  {
    name: "multiple values at one coordinate",
    values: [
      [presentationValue("1.00000000"), presentationValue("2.00000000")],
    ],
    reason: /require one value per coordinate/,
  },
  {
    name: "zero alongside a missing value in another unit",
    values: [
      [presentationValue("0.00000000")],
      [presentationValue(null, "ratio")],
    ],
    reason: null,
    label: "0.00000000",
    scope: /Showing 1 of 1 present numeric values.*Missing values are omitted/,
  },
  {
    name: "matching currencies with differently ordered unit fields",
    values: [
      [presentationValue("1.20000000", { type: "currency", memberId: "CHF" })],
      [presentationValue("1.30000000", { memberId: "CHF", type: "currency" })],
    ],
    reason: null,
    label: "1.20000000 CHF",
    scope: /Showing 2 of 2 present numeric values/,
  },
  {
    name: "bounded cards within a larger page",
    values: Array.from({ length: 25 }, () => [presentationValue("0.00000000")]),
    reason: null,
    label: "0.00000000",
    scope: /Showing 24 of 25 present numeric values/,
  },
  {
    name: "an intermediate presentation page",
    values: [
      [presentationValue("1.00000000")],
      [presentationValue("2.00000000")],
    ],
    pageSize: 1,
    reason: null,
    label: "1.00000000",
    scope: /More grid pages are available; this is not the complete selection/,
  },
])(
  "explains KPI/chart availability for $name without changing the read",
  async (scenario) => {
    const definition = viewDefinition();
    const rows = scenario.values.map((values, index) => ({
      members: { Account: `Account-${index}`, Period: "Period-member" },
      values: { raw: values },
    }));
    definition.selection.dimensions[0].include = {
      kind: "members",
      memberIds: rows.length
        ? rows.map((row) => row.members.Account)
        : ["Account-empty"],
    };
    const calls: string[] = [];
    let finishRead: ((response: Response) => void) | undefined;
    const response = (result: unknown) =>
      new Response(JSON.stringify({ result }));
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input, init) => {
        const { program } = JSON.parse(String(init?.body));
        calls.push(program.function);
        if (program.function === "metadata.dimension.list")
          return savedViewDimensions();
        if (program.function === "grid.definition.list")
          return response({
            grids: [
              { ...savedView("grid-a"), name: definition.name, definition },
            ],
            nextAfterGridId: null,
            collectionToken: "b".repeat(64),
          });
        if (program.function === "metadata.member.list")
          return response({
            rows: [],
            nextAfterMemberId: null,
            metadataRevision: 11,
          });
        if (program.function !== "facts.cube.resolved.read")
          throw new Error(`Unexpected ${program.function}`);
        return new Promise<Response>((resolve) => {
          finishRead = resolve;
        });
      }),
    );
    render(
      <Analyze
        app={savedViewApp}
        catalog={{
          ...savedViewCatalog(),
          functions: {
            ...savedViewCatalog().functions,
            "facts.cube.resolved.read": {
              canonicalViewRead: "openepm-cube-view-read-v1",
            },
          },
        }}
        index={0}
        subject="owner"
      />,
    );
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Open view" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Open view" }));
    expect(screen.getByRole("button", { name: "KPI" })).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "KPI" }),
    ).toHaveAccessibleDescription(/Read the grid/);
    expect(screen.getByText("No snapshot read")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
    await waitFor(() => expect(finishRead).toBeDefined());
    expect(
      screen.getByRole("button", { name: "Chart" }),
    ).toHaveAccessibleDescription(/Reading the grid/);
    expect(screen.queryByLabelText("Loaded grid read")).not.toBeInTheDocument();
    const result = {
      format: "openepm-cube-view-read-v1",
      dataSource: definition.dataSource,
      readPolicy: { semantics: "own" },
      complete: true,
      snapshot: { commitRevision: 23 },
      presentation: {
        pageSize: scenario.pageSize || 100,
        rowCount: rows.length,
      },
      rows,
    };
    await act(async () => finishRead!(response(result)));
    expect(screen.getByLabelText("Loaded grid read")).toBeInTheDocument();
    if (scenario.reason) {
      for (const name of ["KPI", "Chart"]) {
        expect(screen.getByRole("button", { name })).toBeDisabled();
        expect(
          screen.getByRole("button", { name }),
        ).toHaveAccessibleDescription(scenario.reason);
      }
      expect(screen.getByRole("button", { name: "Grid" })).toHaveAttribute(
        "aria-pressed",
        "true",
      );
      expect(
        screen.queryByLabelText("Snapshot KPI cards"),
      ).not.toBeInTheDocument();
      expect(
        screen.queryByLabelText("Snapshot value chart"),
      ).not.toBeInTheDocument();
    } else {
      fireEvent.click(screen.getByRole("button", { name: "KPI" }));
      const cards = screen.getByLabelText("Snapshot KPI cards");
      expect(
        within(cards).getAllByText(scenario.label!)[0],
      ).toBeInTheDocument();
      expect(cards.querySelectorAll("article")).toHaveLength(
        Math.min(
          24,
          scenario.pageSize ||
            scenario.values.filter((values) => values[0].present).length,
        ),
      );
      expect(
        screen.getByRole("button", { name: "KPI" }),
      ).toHaveAccessibleDescription(scenario.scope!);
      fireEvent.click(screen.getByRole("button", { name: "Chart" }));
      expect(
        within(screen.getByLabelText("Snapshot value chart")).getAllByText(
          scenario.label!,
        )[0],
      ).toBeInTheDocument();
      // A later valid read of text invalidates the selected numeric presentation.
      finishRead = undefined;
      fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
      await waitFor(() => expect(finishRead).toBeDefined());
      await act(async () =>
        finishRead!(
          response({
            ...result,
            presentation: { pageSize: 100, rowCount: 1 },
            rows: [
              {
                members: rows[0].members,
                values: { raw: [presentationValue("", "text")] },
              },
            ],
          }),
        ),
      );
      expect(screen.getByRole("button", { name: "Grid" })).toHaveAttribute(
        "aria-pressed",
        "true",
      );
      expect(screen.getByRole("button", { name: "Chart" })).toBeDisabled();
      expect(
        screen.queryByLabelText("Snapshot value chart"),
      ).not.toBeInTheDocument();
    }
    expect(
      calls.every((name) =>
        [
          "metadata.dimension.list",
          "metadata.member.list",
          "grid.definition.list",
          "facts.cube.resolved.read",
        ].includes(name),
      ),
    ).toBe(true);
  },
);

it("preserves empty text, missing values and multiple calculation units in canonical results", () => {
  const value = {
    present: true,
    origin: "materialized",
    currentness: "current",
    resultStateToken: "a".repeat(64),
  };
  const cells = cubeViewRowsToCells({
    format: "openepm-cube-view-read-v1",
    dataSource: { kind: "calculated", resultKey: "forecast.result" },
    readPolicy: { semantics: "stored" },
    complete: true,
    snapshot: { commitRevision: 4 },
    presentation: { pageSize: 100, rowCount: 3 },
    rows: [
      {
        members: { Account: "text" },
        values: { calculated: [{ ...value, value: "", unit: "text" }] },
      },
      {
        members: { Account: "missing" },
        values: {
          calculated: [{ ...value, present: false, value: null, unit: null }],
        },
      },
      {
        members: { Account: "currency" },
        values: {
          calculated: [
            {
              ...value,
              value: "1.20",
              unit: { type: "Currency", memberId: "CHF" },
            },
            {
              ...value,
              value: "1.30",
              unit: { type: "Currency", memberId: "USD" },
            },
          ],
        },
      },
    ],
  });
  expect(cellPresence(cells[0])).toBe("Present empty text");
  expect(cellPresence(cells[1])).toBe("Missing");
  expect(cellValue(cells[2])).toBe("Calculated: 1.20 CHF / 1.30 USD");
  expect(cellPresence(cells[2])).toBe("Separate source values");
});

it.each(["own", "effective"] as const)(
  "restores or refuses an explicit %s saved-view handoff without fallback",
  async (semantics) => {
    const digest = "d".repeat(64);
    const context = vi.fn();
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_input, init) => {
        const { program } = JSON.parse(String(init?.body));
        calls.push(program.function);
        if (program.function === "metadata.dimension.list")
          return savedViewDimensions();
        if (program.function === "grid.definition.read")
          return new Response(
            JSON.stringify({
              result: { ...savedView("linked-view"), canonicalDigest: digest },
            }),
          );
        throw new Error(`Unexpected ${program.function}`);
      }),
    );
    render(
      <Analyze
        app={savedViewApp}
        catalog={{
          ...savedViewCatalog(),
          functions: {
            "metadata.dimension.list": {},
            "metadata.member.list": {},
            "grid.definition.read": {},
            "facts.cube.resolved.read": {
              canonicalViewRead: "openepm-cube-view-read-v1",
            },
          },
        }}
        index={0}
        subject="owner"
        targetViewId="linked-view"
        targetViewDigest={digest}
        targetAnalyticalRead={
          semantics === "own"
            ? { semantics }
            : {
                semantics,
                bindingId: "bound",
                bindingStateToken: "b".repeat(64),
              }
        }
        onViewContextChange={context}
      />,
    );
    if (semantics === "own") {
      await waitFor(() =>
        expect(context).toHaveBeenLastCalledWith({
          viewId: "linked-view",
          viewDigest: digest,
          analyticalRead: { semantics: "own" },
        }),
      );
      expect(screen.getByLabelText("Value semantics")).toHaveValue("own");
      expect(screen.getByText("No snapshot read")).toBeInTheDocument();
      fireEvent.change(screen.getByLabelText("Rows"), {
        target: { value: "Period" },
      });
      await waitFor(() => expect(context).toHaveBeenLastCalledWith(null));
    } else {
      await waitFor(() =>
        expect(screen.getByRole("alert")).toHaveTextContent(
          "cannot restore an effective binding",
        ),
      );
      expect(context).toHaveBeenLastCalledWith(null);
      expect(screen.getByRole("button", { name: "Read grid" })).toBeDisabled();
    }
    expect(
      calls.every(
        (call) =>
          call === "metadata.dimension.list" || call === "grid.definition.read",
      ),
    ).toBe(true);
  },
);

it("never reports the prior view through a new same-application target callback", async () => {
  let finishSecond!: (response: Response) => void;
  const second = new Promise<Response>((resolve) => {
    finishSecond = resolve;
  });
  const firstContext = vi.fn();
  const secondContext = vi.fn();
  const digest = "d".repeat(64);
  const catalog = {
    ...savedViewCatalog(),
    functions: {
      "metadata.dimension.list": {},
      "metadata.member.list": {},
      "grid.definition.read": {},
      "facts.cube.resolved.read": {
        canonicalViewRead: "openepm-cube-view-read-v1",
      },
    },
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input, init) => {
      const { program } = JSON.parse(String(init?.body));
      if (program.function === "metadata.dimension.list")
        return savedViewDimensions();
      if (program.function === "grid.definition.read") {
        if (program.arguments.gridId === "second-view") return second;
        return new Response(
          JSON.stringify({
            result: { ...savedView("first-view"), canonicalDigest: digest },
          }),
        );
      }
      throw new Error(`Unexpected ${program.function}`);
    }),
  );
  const { rerender } = render(
    <Analyze
      app={savedViewApp}
      catalog={catalog}
      index={0}
      subject="owner"
      targetViewId="first-view"
      targetViewDigest={digest}
      targetAnalyticalRead={{ semantics: "own" }}
      onViewContextChange={firstContext}
    />,
  );
  await waitFor(() =>
    expect(firstContext).toHaveBeenLastCalledWith({
      viewId: "first-view",
      viewDigest: digest,
      analyticalRead: { semantics: "own" },
    }),
  );
  rerender(
    <Analyze
      app={savedViewApp}
      catalog={catalog}
      index={0}
      subject="owner"
      targetViewId="second-view"
      targetViewDigest={digest}
      targetAnalyticalRead={{ semantics: "stored" }}
      onViewContextChange={secondContext}
    />,
  );
  expect(secondContext).toHaveBeenCalled();
  expect(secondContext.mock.calls.every(([context]) => context === null)).toBe(
    true,
  );
  finishSecond(
    new Response(
      JSON.stringify({
        result: { ...savedView("second-view"), canonicalDigest: digest },
      }),
    ),
  );
  await waitFor(() =>
    expect(secondContext).toHaveBeenLastCalledWith({
      viewId: "second-view",
      viewDigest: digest,
      analyticalRead: { semantics: "stored" },
    }),
  );
  expect(
    secondContext.mock.calls.every(
      ([context]) => context === null || context.viewId === "second-view",
    ),
  ).toBe(true);
});

it("preserves a reopened saved-view exclusion when editing only its includes", async () => {
  const original = viewDefinition({ id: "excluded", name: "View excluded" });
  const definition = {
    ...original,
    selection: {
      ...original.selection,
      dimensions: original.selection.dimensions.map((dimension) =>
        dimension.dimensionId === "Account"
          ? {
              ...dimension,
              include: {
                kind: "members" as const,
                memberIds: ["Revenue", "Cost"],
              },
              exclude: { kind: "member" as const, memberId: "Cost" },
            }
          : dimension,
      ),
    },
  };
  const reads: any[] = [];
  const response = (result: unknown) =>
    new Response(JSON.stringify({ result }));
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_path, init) => {
      const { program } = JSON.parse(String(init?.body));
      if (program.function === "metadata.dimension.list")
        return savedViewDimensions();
      if (program.function === "grid.definition.list")
        return response({
          grids: [{ ...savedView("excluded"), definition }],
          nextAfterGridId: null,
          collectionToken: "b".repeat(64),
        });
      if (program.function === "metadata.member.list")
        return response({
          rows: (program.arguments.dimension === "Account"
            ? ["Revenue", "Cost"]
            : ["Period-member"]
          ).map((member_id) => ({
            member_id,
            name: member_id,
            status: "Active",
          })),
          metadataRevision: 11,
          nextAfterMemberId: null,
        });
      if (program.function === "facts.cube.resolved.read") {
        reads.push(program.arguments);
        return response({
          format: "openepm-cube-view-read-v1",
          dataSource: definition.dataSource,
          readPolicy: { semantics: "stored" },
          complete: true,
          snapshot: { commitRevision: 9 },
          presentation: { pageSize: 100, rowCount: 0 },
          rows: [],
        });
      }
      throw new Error(`Unexpected ${program.function}`);
    }),
  );
  render(
    <Analyze
      app={savedViewApp}
      catalog={{
        ...savedViewCatalog(),
        functions: {
          ...savedViewCatalog().functions,
          "facts.cube.resolved.read": {
            canonicalViewRead: "openepm-cube-view-read-v1",
          },
        },
      }}
      index={0}
      subject="owner"
    />,
  );
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Open view" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Open view" }));
  fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
  fireEvent.click(screen.getByRole("button", { name: "Choose row members" }));
  const picker = await screen.findByRole("dialog", {
    name: "Choose row members",
  });
  expect(picker).toHaveTextContent(/Existing exclusion is kept/);
  fireEvent.click(within(picker).getByRole("button", { name: "Remove Cost" }));
  fireEvent.click(
    within(picker).getByRole("button", { name: "Apply selection" }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  await waitFor(() => expect(reads).toHaveLength(1));
  expect(
    reads[0].view.selection.dimensions.find(
      (dimension: any) => dimension.dimensionId === "Account",
    ),
  ).toMatchObject({
    include: { kind: "members", memberIds: ["Revenue"] },
    exclude: { kind: "member", memberId: "Cost" },
  });
});

it.each(["raw", "calculated", "combined"] as const)(
  "does not discover effective bindings for an opened %s canonical view",
  async (kind) => {
    const fixture = canonicalReshapeFixture(kind);
    fixture.view.rerender(
      <Analyze
        app={savedViewApp}
        catalog={{
          ...fixture.catalog,
          functions: {
            ...fixture.catalog.functions,
            "facts.cube.resolved.binding.list": {},
          },
        }}
        index={0}
        subject="owner"
      />,
    );
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Open view" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Open view" }));
    expect(screen.getByLabelText("Value semantics")).toHaveValue(
      kind === "raw" ? "own" : "stored",
    );
    fireEvent.change(screen.getByLabelText("Value semantics"), {
      target: { value: "effective" },
    });
    await act(async () => {});
    expect(screen.getByLabelText("Value semantics")).toHaveValue("effective");
    expect(screen.getByRole("button", { name: "Read grid" })).toBeDisabled();
    expect(screen.getByLabelText("Grid read unavailable")).toHaveTextContent(
      "This saved source layer cannot be replaced by an effective binding.",
    );
    expect(
      fixture.calls.filter(
        (call) => call.function === "facts.cube.resolved.binding.list",
      ),
    ).toHaveLength(0);
    expect(
      fixture.calls.filter(
        (call) => call.function === "facts.cube.resolved.read",
      ),
    ).toHaveLength(0);
    expect(screen.getByLabelText("Current grid layout")).toHaveTextContent(
      "Company",
    );
  },
);
