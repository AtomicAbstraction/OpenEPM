import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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
  savedGridListArguments,
  savedGridSaveProgram,
} from "./Analyze";

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
        version: 1,
        name: "Grid",
        definition: {
          rowDimensions: ["Account"],
          columnDimensions: ["Period"],
          pov: {},
          dataLayer: "raw" as const,
          pageSize: 100,
        },
        metadataRevision: 11,
        canonicalDigest: "a".repeat(64),
      })),
      nextAfterGridId: current === 10 ? null : `g-cursor-${current + 1}`,
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

it("preserves shared saved-grid list and immutable-save contracts", () => {
  expect(savedGridListArguments()).toEqual({ limit: 100 });
  expect(savedGridListArguments("grid-a")).toEqual({
    limit: 100,
    afterGridId: "grid-a",
  });
  expect(
    savedGridSaveProgram(
      "actual-by-period",
      2,
      "Actual by period",
      {
        rowDimensions: ["Account"],
        columnDimensions: ["Period"],
        pov: { Scenario: "Actual" },
        dataLayer: "raw",
        pageSize: 100,
      },
      11,
    ),
  ).toEqual({
    languageVersion: 2,
    function: "grid.definition.save",
    arguments: {
      gridId: "actual-by-period",
      version: 2,
      name: "Actual by period",
      definition: {
        rowDimensions: ["Account"],
        columnDimensions: ["Period"],
        pov: { Scenario: "Actual" },
        dataLayer: "raw",
        pageSize: 100,
      },
      expectedMetadataRevision: 11,
    },
  });
  const base = {
    gridId: "grid-a",
    version: 1,
    name: "Grid A",
    metadataRevision: 11,
    canonicalDigest: "digest",
  };
  expect(
    canOpenSavedGrid({
      ...base,
      definition: {
        rowDimensions: ["Account"],
        columnDimensions: ["Period"],
        pov: {},
        dataLayer: "raw",
        pageSize: 100,
      },
    }),
  ).toBe(true);
  expect(
    canOpenSavedGrid({
      ...base,
      definition: {
        rowDimensions: ["Account", "Entity"],
        columnDimensions: ["Period"],
        pov: {},
        dataLayer: "raw",
        pageSize: 100,
      },
    }),
  ).toBe(true);
  expect(
    canOpenSavedGrid({
      ...base,
      definition: {
        rowDimensions: ["Account", "Entity"],
        columnDimensions: ["Period"],
        pov: { Scenario: "Actual" },
        dataLayer: "calculated",
        pageSize: 100,
      },
    }),
  ).toBe(false);
  expect(
    canOpenSavedGrid({
      ...base,
      definition: {
        rowDimensions: ["Account", "Entity"],
        columnDimensions: ["Period"],
        pov: { Scenario: "Actual" },
        dataLayer: "calculated",
        pageSize: 100,
        resultKey: "forecast.calculated",
      },
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
    },
  );
});

it("preserves the qualified cursor page contract", () => {
  expect(buildScanArguments({ Scenario: "Ignored" }, 100, "cursor-2")).toEqual({
    cursor: "cursor-2",
    limit: 100,
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
    "1 records · source snapshot 14",
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
            },
          }),
        );
      return new Response(
        JSON.stringify({
          result: {
            gridId: "actual-by-period",
            version: 1,
            name: "Actual by period",
            definition: {
              rowDimensions: ["Account"],
              columnDimensions: ["Period"],
              pov: {},
              dataLayer: "raw",
              pageSize: 100,
            },
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
  fireEvent.click(
    screen.getByRole("button", { name: "Refresh shared definitions" }),
  );
  await waitFor(() =>
    expect(screen.getByText("0 shared definitions")).toBeInTheDocument(),
  );
  fireEvent.change(screen.getByLabelText("Stable grid ID"), {
    target: { value: "actual-by-period" },
  });
  fireEvent.change(screen.getByLabelText("Display name"), {
    target: { value: "Actual by period" },
  });
  fireEvent.click(
    screen.getByLabelText("I reviewed this exact shared grid definition"),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Save immutable definition" }),
  );
  await waitFor(() =>
    expect(screen.getByRole("status")).toHaveTextContent(
      "Saved Actual by period v1 · digest digest-1",
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
              version: 1,
              name: "Actual by period",
              definition: {
                rowDimensions: ["Account"],
                columnDimensions: ["Period"],
                pov: {},
                dataLayer: "raw",
                pageSize: 100,
              },
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
                  version: 2,
                  name: "Forecast calculation",
                  definition: {
                    rowDimensions: ["Account", "Entity"],
                    columnDimensions: ["Period"],
                    pov: { Scenario: "Forecast" },
                    dataLayer: "calculated",
                    pageSize: 100,
                    resultKey: "forecast.calculated",
                  },
                  metadataRevision: 11,
                  canonicalDigest: "digest-2",
                },
              ],
              nextAfterGridId: null,
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
      return new Response(
        JSON.stringify({
          result: {
            resultKey: "forecast.calculated",
            generationId: "0123456789abcdef0123456789abcdef",
            publishedRevision: 19,
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
        functions: { "grid.definition.list": {}, "facts.calculation.scan": {} },
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
  fireEvent.click(screen.getByText("Saved governed grid views"));
  fireEvent.click(
    screen.getByRole("button", { name: "Refresh shared definitions" }),
  );
  await waitFor(() =>
    expect(screen.getByLabelText("Shared grid definition")).toHaveValue(
      "forecast-grid:2",
    ),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Open shared definition" }),
  );
  expect(screen.getByLabelText("Opened grid layout")).toHaveTextContent(
    "Account / Entity",
  );
  expect(screen.getByLabelText("Opened grid layout")).toHaveTextContent(
    "forecast.calculated",
  );
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  await waitFor(() =>
    expect(screen.getByText("125.00000000")).toBeInTheDocument(),
  );
  expect(screen.getByLabelText("Calculated result context")).toHaveTextContent(
    "0123456789abcdef0123456789abcdef",
  );
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
  ).toHaveTextContent("0123456789abcdef0123456789abcdef");
  expect(
    screen.getByLabelText("Calculated result provenance"),
  ).toHaveTextContent("Matches at read");
  expect(
    screen.queryByRole("button", { name: "Submit durable writeback" }),
  ).not.toBeInTheDocument();
  expect(calls).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        program: {
          languageVersion: 2,
          function: "facts.calculation.scan",
          arguments: {
            members: { Scenario: "Forecast" },
            limit: 100,
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
            version: 3,
            name: "Workflow review",
            definition: {
              rowDimensions: ["Account"],
              columnDimensions: ["Period"],
              pov: {},
              dataLayer: "raw",
              pageSize: 100,
            },
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
      targetViewVersion={3}
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
      "Query query-1 · ready",
    ),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Read status and results" }),
  );
  await waitFor(() =>
    expect(screen.getByText("12.50000000")).toBeInTheDocument(),
  );
  expect(screen.getByText(/CubeAggregateTechnical/)).toBeInTheDocument();
  fireEvent.click(
    screen.getByLabelText("I reviewed cancellation of this exact query state"),
  );
  fireEvent.click(screen.getByRole("button", { name: "Request cancellation" }));
  await waitFor(() =>
    expect(screen.getByRole("status")).toHaveTextContent(
      "Query query-1 · cancelled",
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
  ).toHaveTextContent("change-1");
  fireEvent.click(screen.getByRole("button", { name: "Close writeback" }));
  fireEvent.click(screen.getByRole("button", { name: "KPI" }));
  expect(screen.getByLabelText("Snapshot KPI cards")).toHaveTextContent(
    "Revenue · P1",
  );
  expect(screen.getByLabelText("Snapshot KPI cards")).toHaveTextContent(
    "0.00000000",
  );
  fireEvent.click(screen.getByRole("button", { name: "Chart" }));
  expect(screen.getByLabelText("Snapshot value chart")).toHaveTextContent(
    "Labels retain the exact values from snapshot 9",
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
});
