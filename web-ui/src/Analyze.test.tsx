import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
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

function viewDefinition({
  id = "grid-a",
  name = "Grid A",
  rows = ["Account"],
  columns = ["Period"],
  pov = {} as Record<string, string>,
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
        include: pov[dimensionId]
          ? ({ kind: "member", memberId: pov[dimensionId] } as const)
          : ({
              kind: "members",
              memberIds: [`${dimensionId}-member`],
            } as const),
        exclude: null,
      })),
    },
    layout: {
      pages: [],
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
        functions: {},
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
            result: { bindings: [], nextAfterBindingId: null },
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
    expect(screen.getByRole("status")).toHaveTextContent(
      "Saved Actual by period.",
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

it("opens an exact multi-axis calculated grid through the existing scan contract", async () => {
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
        return new Response(
          JSON.stringify({
            result: {
              editable: false,
              reasonCode: "CALCULATED_RESULT_READ_ONLY",
              message:
                "Calculated result cells are read-only; update an authorized raw input cell or run its governing rule.",
            },
          }),
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
  fireEvent.click(screen.getByRole("button", { name: /Revenue, CH, P1/ }));
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
  expect(calls).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        program: {
          languageVersion: 2,
          function: "facts.calculation.scan",
          arguments: {
            members: { Scenario: "Forecast" },
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
        functions: { "grid.definition.read": {} },
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

it("requests, reads and cancels an aggregate through unchanged contracts", async () => {
  const calls: Array<{ path: string; body: Record<string, unknown> }> = [];
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      const body = JSON.parse(String(init?.body)) as Record<string, unknown> & {
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
              status: "computed",
              rows: [
                {
                  members: { Account: "Revenue", Period: "P1" },
                  sumAmount: "12.50000000",
                  countPresent: "2",
                },
              ],
              nextCursor: "cursor-2",
              technicalCertificate: { kind: "CubeAggregateTechnical" },
            },
          }),
        );
      return new Response(
        JSON.stringify({ result: { queryId: "query-1", status: "cancelled" } }),
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
    expect(screen.getByRole("status")).toHaveTextContent(
      "Aggregate request · ready",
    ),
  );
  expect(screen.queryByText("query-1")).not.toBeInTheDocument();
  expect(screen.queryByLabelText("Aggregate query ID")).not.toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("button", { name: "Refresh status and results" }),
  );
  await waitFor(() =>
    expect(screen.getByText("12.50000000")).toBeInTheDocument(),
  );
  expect(screen.queryByText(/CubeAggregateTechnical/)).not.toBeInTheDocument();
  fireEvent.click(
    screen.getByLabelText("I reviewed cancellation of this exact query state"),
  );
  fireEvent.click(screen.getByRole("button", { name: "Request cancellation" }));
  await waitFor(() =>
    expect(screen.getByRole("status")).toHaveTextContent(
      "Aggregate request · cancelled",
    ),
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
});

it("reads the authorized metadata and cube through unchanged V2 programs", async () => {
  const calls: Array<Record<string, unknown>> = [];
  let acceptTransition: (() => void) | undefined;
  let denyGrid = false;
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
              reasonCode: "PLANNING_INTERSECTION_LOCKED",
              message: "This cell is locked by the current planning workflow.",
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
    screen.getByRole("button", { name: "Revenue, P1: 0.00000000" }),
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
    screen.getByRole("button", { name: "Revenue, P1: 0.00000000" }),
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
});

it("clears cell context on application change and ignores its late identity read", async () => {
  let resolveCell: ((response: Response) => void) | undefined;
  const functions = { "facts.numeric.batch": {} };
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
  fireEvent.click(
    await screen.findByRole("button", { name: "Revenue, Jan: 12.50" }),
  );
  expect(
    screen.getByRole("button", { name: "Close writeback" }),
  ).toBeDisabled();
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
