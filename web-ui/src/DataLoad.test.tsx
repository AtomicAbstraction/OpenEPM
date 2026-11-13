import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import axe from "axe-core";
import { afterEach, expect, it, vi } from "vitest";
import { installOperationAdmissionFixture } from "./test-setup";
import {
  DataLoad,
  csvChunks,
  exactImportExecution,
  exportBundleToCsv,
  parseExactScope,
  sourceProgramBody,
} from "./DataLoad";

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`)
    .join(",")}}`;
}

async function digest(value: unknown) {
  const result = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonical(value)),
  );
  return Array.from(new Uint8Array(result))
    .map((item) => item.toString(16).padStart(2, "0"))
    .join("");
}

async function sealedManifest(
  rows: unknown[],
  typeCounts: { amount: number; text: number; lineDetail: number },
) {
  const page = {
    pageIndex: 0,
    requestCursorDigest: null,
    nextCursorDigest: null,
    contentDigest: "f".repeat(64),
    rowCount: rows.length,
    rowBytes: new TextEncoder().encode(canonical(rows)).length,
    typeCounts,
    firstKey: "1".repeat(64),
    lastKey: String(rows.length).repeat(64).slice(0, 64),
    hasMore: false,
  };
  const unsigned = {
    contractVersion: "openepm-complete-export-manifest-v2",
    status: "complete",
    scope: { workspaceId: "ws", applicationId: "app" },
    schema: {
      id: "openepm.fact-transfer-page",
      version: 1,
      coordinate: "stable-dimension-member-map",
      literalTypes: ["AmountLiteral", "TextLiteral", "LineDetailLiteral"],
      sourceReference: "required-stable-origin",
    },
    snapshotRevision: 12,
    metadataRevision: 7,
    securityRevision: 1,
    expiresAt: 2_000_000_000,
    limits: { maxPages: 100, maxRows: 100_000, maxBytes: 134_217_728 },
    pages: [page],
    pageCount: 1,
    totalRowCount: rows.length,
    totalRowBytes: page.rowBytes,
    typeCounts,
    cumulativeDigest: "e".repeat(64),
  };
  return { ...unsigned, manifestDigest: await digest(unsigned) };
}

async function oneRowExportBundle() {
  const artifactId = "a".repeat(32);
  const rows = [
    {
      members: { Account: "Revenue" },
      value: { type: "AmountLiteral", decimal: "1.00000000" },
      sourceRef: `export:${"1".repeat(64)}`,
    },
  ];
  const manifest = await sealedManifest(rows, {
    amount: 1,
    text: 0,
    lineDetail: 0,
  });
  const manifestDigest = manifest.manifestDigest;
  const unsigned = {
    contractVersion: "openepm-export-payload-v2",
    artifactId,
    manifestDigest,
    pageIndex: 0,
    chunkIndex: 0,
    pageEntryDigest: await digest(manifest.pages[0]),
    pageContentDigest: manifest.pages[0].contentDigest,
    rows,
    rowCount: 1,
    rowBytes: new TextEncoder().encode(canonical(rows)).length,
    typeCounts: { amount: 1, text: 0, lineDetail: 0 },
    firstKey: "1".repeat(64),
    lastKey: "1".repeat(64),
    finalChunkForPage: true,
    ciphertextRef: null,
  };
  const chunk = { ...unsigned, chunkDigest: await digest(unsigned) };
  const payloadDigest = await digest({
    contractVersion: "openepm-export-payload-v2",
    status: "complete",
    artifactId,
    manifestDigest,
    scope: manifest.scope,
    snapshotRevision: manifest.snapshotRevision,
    metadataRevision: manifest.metadataRevision,
    securityRevision: manifest.securityRevision,
    chunkCount: 1,
    rowCount: 1,
    rowBytes: manifest.totalRowBytes,
    typeCounts: manifest.typeCounts,
    chunks: [chunk],
  });
  return JSON.stringify({
    contractVersion: "openepm-export-download-v1",
    artifactId,
    manifest,
    chunks: [
      {
        artifactId,
        manifestDigest,
        payloadDigest,
        ordinal: 0,
        hasMore: false,
        chunk,
      },
    ],
    chunkCount: 1,
  });
}

it("downloads every active fact axis from a revision-consistent metadata inventory", async () => {
  const axes = [
    "Account",
    "Entity",
    "Year",
    "Period",
    "View",
    "Value",
    "Scenario",
    "DataType",
    "Product,region",
  ];
  const dimension = (id: string, model_role = id, status = "Active") => ({
    dimension_id: id,
    name: id,
    model_role,
    status,
  });
  const calls: Record<string, unknown>[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(String(init?.body));
      calls.push(body);
      expect(body).toMatchObject({
        workspaceId: "ws",
        applicationId: "app",
        program: { function: "metadata.dimension.list" },
      });
      const continued = Boolean(body.program.arguments.afterDimensionId);
      if (continued)
        expect(body.program.arguments).toEqual({
          limit: 100,
          afterDimensionId: "Value",
          expectedMetadataRevision: 7,
        });
      return new Response(
        JSON.stringify({
          result: {
            rows: continued
              ? [
                  ...axes.slice(6).map((id) => dimension(id, "Custom")),
                  dimension("CurrencyRegistry", "Currency"),
                  dimension("Archived", "Custom", "Inactive"),
                ]
              : axes.slice(0, 6).map((id) => dimension(id)),
            nextAfterDimensionId: continued ? null : "Value",
            metadataRevision: 7,
          },
        }),
      );
    }),
  );
  render(
    <DataLoad
      app={app}
      catalog={{
        ...catalog,
        functions: { ...catalog.functions, "metadata.dimension.list": {} },
      }}
    />,
  );
  fireEvent.click(screen.getByText("Required columns"));
  const link = await screen.findByRole("link", {
    name: "Download example CSV",
  });
  expect(link).toHaveAttribute("download", "openepm-import-example.csv");
  const csv = decodeURIComponent(
    link.getAttribute("href")!.split(",").slice(1).join(","),
  );
  expect(csv.split("\n")[0]).toBe(
    'axis.Account,axis.Entity,axis.Year,axis.Period,axis.View,axis.Value,axis.Scenario,axis.DataType,"axis.Product,region",literalType,value,sourceRef',
  );
  expect(csv).not.toContain("CurrencyRegistry");
  expect(csv).not.toContain("Archived");
  expect(csv).toContain("AmountLiteral,0.00000000");
  expect(csv).toContain('TextLiteral,"",example-empty-text');
  expect(csvChunks(csv)).toHaveLength(1);
  expect(
    screen.getByText(/Replace every example member ID/),
  ).toBeInTheDocument();
  expect(calls).toHaveLength(2);
});

it("never exposes a late or cached template after scope or read authority changes", async () => {
  const authorized = {
    ...catalog,
    applicationAccess: {
      ...catalog.applicationAccess,
      issuer: "issuer",
      subjectId: "designer",
    },
    functions: { ...catalog.functions, "metadata.dimension.list": {} },
  };
  const pending: {
    scope: string;
    signal: AbortSignal;
    resolve: (value: Response) => void;
  }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(
      (_url, init) =>
        new Promise<Response>((resolve) => {
          pending.push({
            scope: JSON.parse(String(init?.body)).applicationId,
            signal: init?.signal as AbortSignal,
            resolve,
          });
        }),
    ),
  );
  const page = (id: string) =>
    new Response(
      JSON.stringify({
        result: {
          rows: [
            {
              dimension_id: id,
              name: id,
              model_role: "Custom",
              status: "Active",
            },
          ],
          metadataRevision: 7,
          nextAfterDimensionId: null,
        },
      }),
    );
  const { rerender } = render(<DataLoad app={app} catalog={authorized} />);
  await waitFor(() => expect(pending).toHaveLength(1));
  rerender(
    <DataLoad app={{ ...app, applicationId: "other" }} catalog={authorized} />,
  );
  await waitFor(() => expect(pending).toHaveLength(2));
  expect(pending[0].signal.aborted).toBe(true);
  await act(async () => pending[0].resolve(page("PrivateOldAxis")));
  expect(
    screen.queryByRole("link", { name: "Download example CSV" }),
  ).not.toBeInTheDocument();
  await act(async () => pending[1].resolve(page("CurrentAxis")));
  const link = await screen.findByRole("link", {
    name: "Download example CSV",
  });
  expect(decodeURIComponent(link.getAttribute("href")!)).toContain(
    "axis.CurrentAxis",
  );
  expect(decodeURIComponent(link.getAttribute("href")!)).not.toContain(
    "PrivateOldAxis",
  );
  rerender(
    <DataLoad
      app={{ ...app, applicationId: "other" }}
      catalog={{
        ...authorized,
        revisions: { ...authorized.revisions, security: 2 },
      }}
    />,
  );
  expect(
    screen.queryByRole("link", { name: "Download example CSV" }),
  ).not.toBeInTheDocument();
  await waitFor(() => expect(pending).toHaveLength(3));
  rerender(
    <DataLoad app={{ ...app, applicationId: "other" }} catalog={catalog} />,
  );
  await act(async () => pending[2].resolve(page("RevokedAxis")));
  expect(
    screen.queryByRole("link", { name: "Download example CSV" }),
  ).not.toBeInTheDocument();
  expect(
    screen.getByText(/metadata read access is required/),
  ).toBeInTheDocument();
});

afterEach(() => vi.unstubAllGlobals());

const app = {
  workspaceId: "ws",
  applicationId: "app",
  name: "Plan",
  status: "Active",
};
const names = [
  "facts.source.begin",
  "facts.source.csv.append",
  "facts.source.seal",
  "facts.source.manifest.attach",
  "facts.source.preview",
  "facts.transfer.import.request",
  "facts.transfer.import.read",
  "facts.transfer.import.diagnostics.read",
  "application.operation.receipt.read",
];
const catalog = {
  applicationAccess: { role: "Editor", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: Object.fromEntries(names.map((name) => [name, {}])),
  revisions: { metadata: 7, data: 9, policy: 1, security: 1, commit: 12 },
};
function renderDataLoad() {
  installOperationAdmissionFixture("b");
  return render(<DataLoad app={app} catalog={catalog} />);
}
const BATCH = "b".repeat(32);
const RECONCILED_BATCH = "c".repeat(32);
const CONTENT_DIGEST = "d".repeat(64);
const MANIFEST_DIGEST = "e".repeat(64);
const IMPORT_REQUEST = "1".repeat(32);

it("hydrates the exact unpublished data-load draft after remount", async () => {
  const first = renderDataLoad();
  fireEvent.change(screen.getByLabelText("UTF-8 CSV text"), {
    target: {
      value:
        "axis.Account,literalType,value,sourceRef\nRevenue,AmountLiteral,1,test",
    },
  });
  fireEvent.click(screen.getByLabelText("Whole application scope"));
  await waitFor(() =>
    expect(
      (screen.getByLabelText("UTF-8 CSV text") as HTMLTextAreaElement).value,
    ).toContain("Revenue"),
  );
  first.unmount();
  renderDataLoad();
  await waitFor(() =>
    expect(
      (screen.getByLabelText("UTF-8 CSV text") as HTMLTextAreaElement).value,
    ).toContain("Revenue"),
  );
  expect(screen.getByLabelText("Whole application scope")).toBeChecked();
});

function manifestResult(
  requestKey: string,
  schemaVersion = "openepm.typed-csv.v1",
  batchId = BATCH,
) {
  return {
    batchId,
    requestKey,
    schemaVersion,
    contentDigest: CONTENT_DIGEST,
    manifestDigest: MANIFEST_DIGEST,
  };
}

function completedExecution(overrides: Record<string, unknown> = {}) {
  return {
    requestId: IMPORT_REQUEST,
    batchId: BATCH,
    status: "Completed",
    claimGeneration: 2,
    cancelRequested: false,
    errorCode: null,
    duplicate: true,
    result: {
      batchId: BATCH,
      mode: "merge",
      setCount: 1,
      clearCount: 0,
      changedCount: 1,
      committedRevision: 13,
      contentDigest: CONTENT_DIGEST,
    },
    ...overrides,
  };
}

const expectedExecution = {
  batchId: BATCH,
  contentDigest: CONTENT_DIGEST,
  mode: "merge",
  setCount: 1,
  clearCount: 0,
};

it("reconciles a lost request acknowledgement with its exact completed execution", () => {
  expect(
    exactImportExecution(completedExecution(), expectedExecution),
  ).toMatchObject({
    requestId: IMPORT_REQUEST,
    batchId: BATCH,
    status: "Completed",
    duplicate: true,
    result: { committedRevision: 13, contentDigest: CONTENT_DIGEST },
  });
});

it.each([
  ["request", { requestId: "2".repeat(32) }],
  ["batch", { batchId: "2".repeat(32) }],
  [
    "digest",
    {
      result: {
        ...completedExecution().result,
        contentDigest: "2".repeat(64),
      },
    },
  ],
  ["counts", { result: { ...completedExecution().result, setCount: 2 } }],
  [
    "revision",
    { result: { ...completedExecution().result, committedRevision: 0 } },
  ],
  ["terminal result", { status: "Failed", result: {}, errorCode: "FAILED" }],
])("rejects a substituted or malformed import %s", (_label, override) => {
  expect(() =>
    exactImportExecution(completedExecution(override), {
      ...expectedExecution,
      requestId: IMPORT_REQUEST,
    }),
  ).toThrow(/INVALID_IMPORT_(EXECUTION|COMPLETION)_RESPONSE/);
});

it("parses deterministic exact import scopes", () => {
  expect(parseExactScope("Period=2027-01; Entity=North")).toEqual({
    Entity: "North",
    Period: "2027-01",
  });
  expect(() => parseExactScope("Entity=North; Entity=South")).toThrow(
    "Scope repeats dimension Entity.",
  );
});

it("chunks 501 CSV records and repeats the exact header", () => {
  const rows = Array.from(
    { length: 501 },
    (_, index) => `Account-${index},AmountLiteral,${index},test`,
  );
  const chunks = csvChunks(
    ["axis.Account,literalType,value,sourceRef", ...rows].join("\n"),
  );
  expect(chunks).toHaveLength(2);
  expect(chunks[0].split("\n")).toHaveLength(501);
  expect(chunks[1].split("\n")).toHaveLength(2);
});

it("preserves quoted newlines and escaped quotes while chunking", () => {
  const source =
    'axis.Account,literalType,value,sourceRef\nRevenue,TextLiteral,"line 1\nline ""2""",test';
  expect(csvChunks(source)).toEqual([source]);
});

it("verifies and converts a complete governed export bundle losslessly", async () => {
  const artifactId = "a".repeat(32);
  const rows = [
    {
      members: { Account: "Revenue", Entity: "Zürich" },
      value: { type: "AmountLiteral", decimal: "0.00000000" },
      sourceRef: `export:${"1".repeat(64)}`,
    },
    {
      members: { Account: "Comment", Entity: "Zürich" },
      value: { type: "TextLiteral", text: 'line 1\nline "2"' },
      sourceRef: `export:${"2".repeat(64)}`,
    },
    {
      members: { Account: "Detail", Entity: "Zürich" },
      value: {
        type: "LineDetailLiteral",
        items: [{ description: "Item, one", decimal: "1.25000000" }],
      },
      sourceRef: `export:${"3".repeat(64)}`,
    },
  ];
  const manifest = await sealedManifest(rows, {
    amount: 1,
    text: 1,
    lineDetail: 1,
  });
  const manifestDigest = manifest.manifestDigest;
  const unsigned = {
    contractVersion: "openepm-export-payload-v2",
    artifactId,
    manifestDigest,
    pageIndex: 0,
    chunkIndex: 0,
    pageEntryDigest: await digest(manifest.pages[0]),
    pageContentDigest: manifest.pages[0].contentDigest,
    rows,
    rowCount: rows.length,
    rowBytes: new TextEncoder().encode(canonical(rows)).length,
    typeCounts: { amount: 1, text: 1, lineDetail: 1 },
    firstKey: "1".repeat(64),
    lastKey: "3".repeat(64),
    finalChunkForPage: true,
    ciphertextRef: null,
  };
  const chunk = { ...unsigned, chunkDigest: await digest(unsigned) };
  const payloadDigest = await digest({
    contractVersion: "openepm-export-payload-v2",
    status: "complete",
    artifactId,
    manifestDigest,
    scope: manifest.scope,
    snapshotRevision: manifest.snapshotRevision,
    metadataRevision: manifest.metadataRevision,
    securityRevision: manifest.securityRevision,
    chunkCount: 1,
    rowCount: rows.length,
    rowBytes: manifest.totalRowBytes,
    typeCounts: manifest.typeCounts,
    chunks: [chunk],
  });
  const bundle = {
    contractVersion: "openepm-export-download-v1",
    artifactId,
    manifest,
    chunks: [
      {
        artifactId,
        manifestDigest,
        payloadDigest,
        ordinal: 0,
        hasMore: false,
        chunk,
      },
    ],
    chunkCount: 1,
  };
  const converted = await exportBundleToCsv(JSON.stringify(bundle));
  expect(converted).toMatchObject({
    artifactId,
    manifestDigest,
    payloadDigest,
    chunkCount: 1,
    rowCount: 3,
  });
  expect(csvChunks(converted.csv)).toHaveLength(1);
  expect(converted.csv).toContain("0.00000000");
  expect(converted.csv).toContain('"line 1\nline ""2"""');
  expect(converted.csv).toContain('"[{""decimal"":""1.25000000""');

  bundle.chunks[0].payloadDigest = "c".repeat(64);
  await expect(exportBundleToCsv(JSON.stringify(bundle))).rejects.toThrow(
    "aggregate payload digest does not match",
  );
  bundle.chunks[0].payloadDigest = payloadDigest;
  bundle.chunks[0].chunk.rows[0].value = {
    type: "AmountLiteral",
    decimal: "99.00000000",
  };
  await expect(exportBundleToCsv(JSON.stringify(bundle))).rejects.toThrow(
    "digest does not match",
  );
});

it("rejects malformed CSV before starting a batch", () => {
  expect(() =>
    csvChunks(
      "axis.Account,literalType,value,sourceRef\nRevenue,AmountLiteral",
    ),
  ).toThrow(/same number of columns/);
});

it("preserves source-load envelope and confirmation", () => {
  expect(
    sourceProgramBody(app, "facts.source.begin", { scopeAll: true }, true),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    program: {
      languageVersion: 2,
      function: "facts.source.begin",
      arguments: { scopeAll: true },
    },
  });
});

it("keeps publication disabled until staged preview is reviewed", async () => {
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: {
      randomUUID: () => "request-1",
      subtle: { digest: async () => new Uint8Array(32).buffer },
    },
  });
  const calls: Array<{ path: string; body: any }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      const body = JSON.parse(String(init?.body));
      calls.push({ path, body });
      if (
        path === "/api/read" &&
        body.program.function === "application.operation.receipt.read"
      )
        return new Response(
          JSON.stringify({
            result: {
              operationId: BATCH,
              commandDigest: CONTENT_DIGEST,
              actorId: "editor-1",
              committedRevision: 13,
              committedAt: "2026-11-06T12:00:00Z",
              outcome: { setCount: 1, clearCount: 0 },
            },
          }),
        );
      if (path === "/api/catalog")
        return new Response(
          JSON.stringify({
            revisions: {
              metadata: 7,
              data: 9,
              policy: 1,
              security: 1,
              commit: 12,
            },
          }),
        );
      const fn = body.program.function;
      if (fn === "facts.source.begin")
        return new Response(
          JSON.stringify({
            result: {
              batchId: BATCH,
              status: "staging",
              rowCount: 0,
              contentDigest: CONTENT_DIGEST,
              duplicate: false,
            },
          }),
        );
      if (fn === "facts.source.csv.append")
        return new Response(
          JSON.stringify({
            result: {
              batchId: BATCH,
              chunkIndex: 0,
              rowCount: 1,
              contentDigest: CONTENT_DIGEST,
              duplicate: false,
            },
          }),
        );
      if (fn === "facts.source.seal")
        return new Response(
          JSON.stringify({
            result: {
              batchId: BATCH,
              status: "ready",
              rowCount: 1,
              contentDigest: CONTENT_DIGEST,
            },
          }),
        );
      if (fn === "facts.source.manifest.attach")
        return new Response(
          JSON.stringify({
            result: manifestResult(
              body.program.arguments.requestKey,
              body.program.arguments.schemaVersion,
            ),
          }),
        );
      if (fn === "facts.source.preview")
        return new Response(
          JSON.stringify({
            result: {
              batchId: BATCH,
              contentDigest: CONTENT_DIGEST,
              previewToken: "preview-1",
              setCount: 1,
              clearCount: 0,
              diagnostics: {
                artifactId: "artifact-1",
                errorCount: 0,
                warningCount: 0,
              },
            },
          }),
        );
      if (fn === "facts.transfer.import.request")
        return new Response(
          JSON.stringify({
            result: {
              requestId: IMPORT_REQUEST,
              batchId: BATCH,
              status: "Accepted",
              claimGeneration: 0,
              cancelRequested: false,
              result: null,
              errorCode: null,
              duplicate: false,
            },
          }),
        );
      if (fn === "facts.transfer.import.read")
        return new Response(
          JSON.stringify({
            result: completedExecution({ duplicate: undefined }),
          }),
        );
      return new Response(JSON.stringify({ result: {} }));
    }),
  );
  const rendered = renderDataLoad();
  expect(
    screen.queryByRole("button", { name: "Start durable publication" }),
  ).not.toBeInTheDocument();
  fireEvent.change(screen.getByLabelText("UTF-8 CSV text"), {
    target: {
      value:
        "axis.Account,literalType,value,sourceRef\nRevenue,AmountLiteral,1,test",
    },
  });
  fireEvent.click(screen.getByRole("button", { name: "Prepare pasted CSV" }));
  await screen.findByText(/Prepared \d+ bytes/);
  fireEvent.click(screen.getByLabelText("Whole application scope"));
  fireEvent.click(
    screen.getByLabelText("I reviewed the exact input and target scope"),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Stage and validate CSV" }),
  );
  await screen.findByRole("button", { name: "Preview exact changes" });
  fireEvent.click(
    screen.getByRole("button", { name: "Preview exact changes" }),
  );
  await waitFor(() =>
    expect(screen.getByText("1", { selector: "strong" })).toBeInTheDocument(),
  );
  expect(
    screen.getByRole("button", { name: "Start durable publication" }),
  ).toBeDisabled();
  fireEvent.click(
    screen.getByLabelText("I reviewed the exact set and clear counts"),
  );
  expect(
    screen.getByRole("button", { name: "Start durable publication" }),
  ).toBeEnabled();
  fireEvent.click(
    screen.getByRole("button", { name: "Start durable publication" }),
  );
  await screen.findByText("Submitted");
  expect(
    screen.getByRole("listitem", { name: "Receipt: current" }),
  ).not.toHaveClass("complete");
  expect(
    calls.map((call) => [call.path, call.body.program?.function || null]),
  ).toEqual([
    ["/api/catalog", null],
    ["/api/source-load", "facts.source.begin"],
    ["/api/source-load", "facts.source.csv.append"],
    ["/api/source-load", "facts.source.seal"],
    ["/api/source-load", "facts.source.manifest.attach"],
    ["/api/source-load", "facts.source.preview"],
    ["/api/source-load", "facts.transfer.import.request"],
  ]);
  expect(calls.at(-1)?.body).toMatchObject({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    program: {
      languageVersion: 2,
      function: "facts.transfer.import.request",
      arguments: {
        batchId: BATCH,
        previewToken: "preview-1",
      },
    },
  });
  fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
  expect(await screen.findByText("Completed")).toBeInTheDocument();
  expect(
    screen.getByRole("listitem", { name: "Receipt: complete" }),
  ).toHaveClass("complete");
  fireEvent.click(
    screen.getByRole("button", { name: "View publication outcome" }),
  );
  expect(
    await screen.findByText("Activity outcome loaded."),
  ).toBeInTheDocument();
  expect(screen.queryByText("editor-1")).not.toBeInTheDocument();
  expect(calls.at(-1)?.body.program).toEqual({
    languageVersion: 2,
    function: "application.operation.receipt.read",
    arguments: { operationId: BATCH },
  });
  expect(screen.getAllByRole("status").length).toBeGreaterThan(0);
  expect(
    (
      await axe.run(rendered.container, {
        rules: { "color-contrast": { enabled: false } },
      })
    ).violations,
  ).toEqual([]);
});

it("reuses the source intent keys when staging is retried", async () => {
  let uuid = 0;
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: {
      randomUUID: () => `intent-${++uuid}`,
      subtle: { digest: async () => new Uint8Array(32).buffer },
    },
  });
  const beginKeys: string[] = [];
  const beginAdmissionKeys: string[] = [];
  let beginAttempts = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      const body = JSON.parse(String(init?.body));
      if (path === "/api/catalog")
        return new Response(JSON.stringify({ revisions: catalog.revisions }));
      const fn = body.program.function;
      if (fn === "facts.source.begin") {
        beginKeys.push(body.program.arguments.idempotencyKey);
        beginAdmissionKeys.push(body.idempotencyKey);
        beginAttempts += 1;
        if (beginAttempts === 1)
          return new Response(JSON.stringify({ error: "OUTCOME_UNCERTAIN" }), {
            status: 409,
          });
        return new Response(
          JSON.stringify({
            result: {
              batchId: RECONCILED_BATCH,
              status: "staging",
              rowCount: 0,
              contentDigest: CONTENT_DIGEST,
              duplicate: true,
            },
          }),
        );
      }
      if (fn === "facts.source.csv.append")
        return new Response(
          JSON.stringify({
            result: {
              batchId: RECONCILED_BATCH,
              chunkIndex: 0,
              rowCount: 1,
              contentDigest: CONTENT_DIGEST,
              duplicate: false,
            },
          }),
        );
      if (fn === "facts.source.seal")
        return new Response(
          JSON.stringify({
            result: {
              batchId: RECONCILED_BATCH,
              status: "ready",
              rowCount: 1,
              contentDigest: CONTENT_DIGEST,
            },
          }),
        );
      if (fn === "facts.source.manifest.attach")
        return new Response(
          JSON.stringify({
            result: manifestResult(
              body.program.arguments.requestKey,
              body.program.arguments.schemaVersion,
              RECONCILED_BATCH,
            ),
          }),
        );
      return new Response(JSON.stringify({ result: {} }));
    }),
  );
  renderDataLoad();
  fireEvent.change(screen.getByLabelText("UTF-8 CSV text"), {
    target: {
      value:
        "axis.Account,literalType,value,sourceRef\nRevenue,AmountLiteral,1,test",
    },
  });
  fireEvent.click(screen.getByRole("button", { name: "Prepare pasted CSV" }));
  await screen.findByText(/Prepared \d+ bytes/);
  fireEvent.click(screen.getByLabelText("Whole application scope"));
  fireEvent.click(
    screen.getByLabelText("I reviewed the exact input and target scope"),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Stage and validate CSV" }),
  );
  await screen.findByText("OUTCOME_UNCERTAIN");
  fireEvent.click(
    screen.getByRole("button", { name: "Stage and validate CSV" }),
  );
  await screen.findByRole("button", { name: "Preview exact changes" });
  expect(beginKeys).toHaveLength(2);
  expect(beginKeys[1]).toBe(beginKeys[0]);
  expect(beginAdmissionKeys).toHaveLength(2);
  expect(beginAdmissionKeys[0]).toMatch(/^oa1_/);
  expect(beginAdmissionKeys[1]).toBe(beginAdmissionKeys[0]);
});

it("fails closed before sealing when an append response changes batch identity", async () => {
  const functions: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      const body = JSON.parse(String(init?.body));
      if (path === "/api/catalog")
        return new Response(JSON.stringify({ revisions: catalog.revisions }));
      const fn = body.program.function;
      functions.push(fn);
      if (fn === "facts.source.begin")
        return new Response(
          JSON.stringify({
            result: {
              batchId: BATCH,
              status: "staging",
              rowCount: 0,
              contentDigest: CONTENT_DIGEST,
              duplicate: false,
            },
          }),
        );
      if (fn === "facts.source.csv.append")
        return new Response(
          JSON.stringify({
            result: {
              batchId: "f".repeat(32),
              chunkIndex: 0,
              rowCount: 1,
              contentDigest: CONTENT_DIGEST,
              duplicate: false,
            },
          }),
        );
      throw new Error(`unexpected function ${fn}`);
    }),
  );
  renderDataLoad();
  fireEvent.change(screen.getByLabelText("UTF-8 CSV text"), {
    target: {
      value:
        "axis.Account,literalType,value,sourceRef\nRevenue,AmountLiteral,1,test",
    },
  });
  fireEvent.click(screen.getByRole("button", { name: "Prepare pasted CSV" }));
  await screen.findByText(/Prepared \d+ bytes/);
  fireEvent.click(screen.getByLabelText("Whole application scope"));
  fireEvent.click(
    screen.getByLabelText("I reviewed the exact input and target scope"),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Stage and validate CSV" }),
  );
  await screen.findByText("INVALID_SOURCE_BATCH_RESPONSE");
  expect(functions).toEqual(["facts.source.begin", "facts.source.csv.append"]);
});

it("reconciles a fully appended 501-row batch by replaying both exact chunks", async () => {
  const rows = Array.from(
    { length: 501 },
    (_, index) => `Account-${index},AmountLiteral,${index},source-${index}`,
  );
  const calls: Array<Record<string, any>> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      const body = JSON.parse(String(init?.body));
      if (path === "/api/catalog")
        return new Response(JSON.stringify({ revisions: catalog.revisions }));
      calls.push(body);
      const fn = body.program.function;
      if (fn === "facts.source.begin")
        return new Response(
          JSON.stringify({
            result: {
              batchId: BATCH,
              status: "staging",
              rowCount: 501,
              contentDigest: CONTENT_DIGEST,
              duplicate: true,
            },
          }),
        );
      if (fn === "facts.source.csv.append")
        return new Response(
          JSON.stringify({
            result: {
              batchId: BATCH,
              chunkIndex: body.program.arguments.chunkIndex,
              rowCount: 501,
              contentDigest: CONTENT_DIGEST,
              duplicate: true,
            },
          }),
        );
      if (fn === "facts.source.seal")
        return new Response(
          JSON.stringify({
            result: {
              batchId: BATCH,
              status: "ready",
              rowCount: 501,
              contentDigest: CONTENT_DIGEST,
            },
          }),
        );
      if (fn === "facts.source.manifest.attach")
        return new Response(
          JSON.stringify({
            result: manifestResult(
              body.program.arguments.requestKey,
              body.program.arguments.schemaVersion,
            ),
          }),
        );
      throw new Error(`unexpected function ${fn}`);
    }),
  );
  renderDataLoad();
  fireEvent.change(screen.getByLabelText("UTF-8 CSV text"), {
    target: {
      value: ["axis.Account,literalType,value,sourceRef", ...rows].join("\n"),
    },
  });
  fireEvent.click(screen.getByRole("button", { name: "Prepare pasted CSV" }));
  await screen.findByText(/Prepared \d+ bytes/);
  fireEvent.click(screen.getByLabelText("Whole application scope"));
  fireEvent.click(
    screen.getByLabelText("I reviewed the exact input and target scope"),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Stage and validate CSV" }),
  );
  await screen.findByRole("button", { name: "Preview exact changes" });
  const appends = calls.filter(
    (body) => body.program.function === "facts.source.csv.append",
  );
  expect(appends.map((body) => body.program.arguments.chunkIndex)).toEqual([
    0, 1,
  ]);
  const seal = calls.find(
    (body) => body.program.function === "facts.source.seal",
  );
  expect(seal?.program.arguments).toMatchObject({
    batchId: BATCH,
    expectedRows: 501,
    expectedContentDigest: CONTENT_DIGEST,
  });
});

it("binds verified export provenance into the re-import manifest", async () => {
  const bundle = await oneRowExportBundle();
  const sourceManifestDigest = JSON.parse(bundle).manifest.manifestDigest;
  const sourcePayloadDigest = JSON.parse(bundle).chunks[0].payloadDigest;
  const subtle = crypto.subtle;
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: { randomUUID: () => "request-1", subtle },
  });
  const calls: any[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      const body = JSON.parse(String(init?.body));
      calls.push(body);
      if (path === "/api/catalog")
        return new Response(JSON.stringify({ revisions: catalog.revisions }));
      const fn = body.program.function;
      if (fn === "facts.source.begin")
        return new Response(
          JSON.stringify({
            result: {
              batchId: BATCH,
              status: "staging",
              rowCount: 0,
              contentDigest: CONTENT_DIGEST,
              duplicate: false,
            },
          }),
        );
      if (fn === "facts.source.csv.append")
        return new Response(
          JSON.stringify({
            result: {
              batchId: BATCH,
              chunkIndex: 0,
              rowCount: 1,
              contentDigest: CONTENT_DIGEST,
              duplicate: false,
            },
          }),
        );
      if (fn === "facts.source.seal")
        return new Response(
          JSON.stringify({
            result: {
              batchId: BATCH,
              status: "ready",
              rowCount: 1,
              contentDigest: CONTENT_DIGEST,
            },
          }),
        );
      if (fn === "facts.source.manifest.attach")
        return new Response(
          JSON.stringify({
            result: manifestResult(
              body.program.arguments.requestKey,
              body.program.arguments.schemaVersion,
            ),
          }),
        );
      return new Response(JSON.stringify({ result: {} }));
    }),
  );
  renderDataLoad();
  fireEvent.change(
    screen.getByLabelText("Choose CSV or governed export bundle"),
    {
      target: {
        files: [
          new File([bundle], "snapshot.json", { type: "application/json" }),
        ],
      },
    },
  );
  await screen.findByText(/Prepared \d+ bytes/);
  fireEvent.click(screen.getByLabelText("Whole application scope"));
  fireEvent.click(
    screen.getByLabelText("I reviewed the exact input and target scope"),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Stage and validate CSV" }),
  );
  await screen.findByRole("button", { name: "Preview exact changes" });
  const manifest = calls.find(
    (body) => body.program?.function === "facts.source.manifest.attach",
  );
  expect(manifest.program.arguments).toMatchObject({
    originKind: "file",
    originRef: "snapshot.json",
    schemaVersion: "openepm.export-bundle-reimport.v1",
    schema: {
      sourceExportBundle: {
        artifactId: "a".repeat(32),
        manifestDigest: sourceManifestDigest,
        payloadDigest: sourcePayloadDigest,
        chunkCount: 1,
      },
    },
  });
  expect(
    manifest.program.arguments.schema.sourceExportBundle.bundleDigest,
  ).toMatch(/^[0-9a-f]{64}$/);
});
