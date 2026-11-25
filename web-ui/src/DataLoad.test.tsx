import {
  act,
  fireEvent,
  render,
  renderHook,
  screen,
  waitFor,
} from "@testing-library/react";
import axe from "axe-core";
import { afterEach, expect, it, vi } from "vitest";
import {
  installOperationAdmissionFixture,
  operationAdmissionResponse,
} from "./test-setup";
import {
  canPreserveUnsavedWork,
  usePreservedDraft,
  unsavedWorkSnapshot,
  discardUnsavedWork,
  setDraftIdentity,
} from "./unsaved-work";
import {
  DataLoad,
  correctedCsvRemainder,
  csvChunks,
  stagingCsvChunks,
  exactImportExecution,
  exportBundleToCsv,
  parseExactScope,
  sourceProgramBody,
} from "./DataLoad";

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => {
      // UTF-8 byte order independently matches native code-point ordering.
      const a = new TextEncoder().encode(left);
      const b = new TextEncoder().encode(right);
      for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
        if (a[index] !== b[index]) return a[index] - b[index];
      }
      return a.length - b.length;
    })
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

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

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
  "facts.source.staging.read",
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

function importReview() {
  return {
    format: "openepm-source-change-review-v1",
    mode: "merge",
    scopeMembers: {},
    scopeAll: true,
    periodSelection: null,
    metadataRevision: 7,
    dataRevision: 9,
    commitRevision: 12,
    sampleLimitPerAction: 20,
    setsComplete: true,
    clearsComplete: true,
    readRestricted: false,
    examples: [
      {
        action: "set",
        members: { Account: "Revenue" },
        valueKind: "numeric",
        sourceRef: "test",
        before: { present: false },
        after: { present: true, amount: "1.00000000" },
      },
    ],
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

it("splits by serialized UTF-8 size so valid text values fit staging and recovery bodies", () => {
  const header = "axis.Account,literalType,value,sourceRef";
  const value = "\u001f".repeat(24_000);
  const rows = Array.from(
    { length: 72 },
    (_, index) => `Account-${index},TextLiteral,${value},fixture`,
  );
  const original = [header, ...rows].join("\n");
  const bytes = (body: unknown) =>
    new TextEncoder().encode(JSON.stringify(body)).length;
  const append = (csvText: string, chunkIndex: number) =>
    sourceProgramBody(
      app,
      "facts.source.csv.append",
      { batchId: "a".repeat(32), chunkIndex, csvText },
      true,
    );
  expect(stagingCsvChunks(original, [], "raw")).toEqual([original]);
  expect(bytes(append(original, 0))).toBeGreaterThan(10_000_000);

  const chunks = csvChunks(original);
  expect(chunks).toHaveLength(3);
  expect(chunks.flatMap((chunk) => chunk.split("\n").slice(1))).toEqual(rows);
  for (const [index, chunk] of chunks.entries()) {
    const submission = append(chunk, index);
    expect(bytes(submission)).toBeLessThan(4_001_000);
    expect(
      bytes(
        sourceProgramBody(app, "facts.source.staging.read", {
          originalProgram: submission.program,
          operationId: `oa1_123456789abcd_${"a".repeat(32)}_${"b".repeat(43)}`,
        }),
      ),
    ).toBeLessThan(4_001_000);
  }
  expect(stagingCsvChunks(original, [29])[0]).toBe(
    [header, ...rows.slice(0, 29)].join("\n"),
  );
  expect(() => correctedCsvRemainder(original, 0, original, [], "raw")).toThrow(
    "Correct the rejected input",
  );
});

it("corrects only unsubmitted CSV rows while preserving an acknowledged 500-row prefix", () => {
  const header = "axis.Account,literalType,value,sourceRef";
  const original = [
    header,
    ...Array.from(
      { length: 501 },
      (_, i) => `A${i},AmountLiteral,${i},source-${i}`,
    ),
  ].join("\n");
  const corrected = correctedCsvRemainder(
    original,
    1,
    `${header}\nA500,TextLiteral,"corrected\ntext",source-500`,
  );
  expect(corrected.acknowledgedChunkRows).toEqual([500]);
  const chunks = stagingCsvChunks(
    corrected.text,
    corrected.acknowledgedChunkRows,
  );
  expect(chunks[0]).toBe(csvChunks(original)[0]);
  expect(chunks[1]).toBe(
    `${header}\nA500,TextLiteral,"corrected\ntext",source-500`,
  );
  expect(() =>
    correctedCsvRemainder(
      original,
      1,
      `axis.Other,literalType,value,sourceRef\nA500,AmountLiteral,1,source-500`,
    ),
  ).toThrow("original CSV header");
  expect(() =>
    correctedCsvRemainder(original, 1, csvChunks(original)[1]),
  ).toThrow("Correct the rejected input");
});

it("preserves acknowledged byte-limited chunk boundaries after shorter corrected input", () => {
  const header = "axis.Account,literalType,value,sourceRef";
  // A legitimate native prefix may end before 500 rows because it reached the byte bound.
  // Explicit retained boundaries remain authoritative even after the remainder shrinks.
  const original = `${header}\nA,AmountLiteral,1,a\nB,TextLiteral,bad,b\nC,AmountLiteral,3,c`;
  const corrected = correctedCsvRemainder(
    original,
    1,
    `${header}\nB,TextLiteral,,b\nC,AmountLiteral,4,c`,
    [1],
  );
  expect(
    stagingCsvChunks(corrected.text, corrected.acknowledgedChunkRows),
  ).toEqual([
    `${header}\nA,AmountLiteral,1,a`,
    `${header}\nB,TextLiteral,,b\nC,AmountLiteral,4,c`,
  ]);
  expect(() => stagingCsvChunks(original, [0])).toThrow("boundaries");
  expect(() => stagingCsvChunks(original, [4])).toThrow("boundaries");
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

it.each([false, true])(
  "keeps reviewed publication identity through lost response=%s",
  async (loseResponse) => {
    vi.stubGlobal("crypto", {
      randomUUID: () => "request-1",
      subtle: { digest: async () => new Uint8Array(32).buffer },
    });
    const calls: Array<{ path: string; body: any }> = [];
    let publicationAttempts = 0;
    let publicationStatusReads = 0;
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
                body.idempotencyKey,
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
                review: importReview(),
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
        if (
          fn === "facts.transfer.import.request" &&
          ++publicationAttempts === 1 &&
          loseResponse
        )
          throw new TypeError("connection lost after publication admission");
        if (
          fn === "facts.transfer.import.request" ||
          (fn === "facts.transfer.import.read" &&
            body.program.arguments.operationId)
        )
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
              result: completedExecution(
                ++publicationStatusReads === 1
                  ? {
                      status: "Accepted",
                      claimGeneration: 1,
                      result: null,
                      errorCode: "IMPORT_EXECUTION_RETRYABLE_DATABASE",
                      duplicate: undefined,
                    }
                  : { duplicate: undefined },
              ),
            }),
          );
        return new Response(JSON.stringify({ result: {} }));
      }),
    );
    let rendered = renderDataLoad();
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
    ).toHaveAttribute("aria-disabled", "true");
    fireEvent.click(
      screen.getByLabelText("I reviewed the exact set and clear counts"),
    );
    expect(
      screen.getByRole("button", { name: "Start durable publication" }),
    ).not.toHaveAttribute("aria-disabled");
    fireEvent.click(
      screen.getByRole("button", { name: "Start durable publication" }),
    );
    if (loseResponse) {
      await screen.findByText("Publication outcome unknown");
      expect(screen.getByLabelText("UTF-8 CSV text")).toBeDisabled();
      expect(screen.getByLabelText("Whole application scope")).toBeDisabled();
      expect(
        screen.getByRole("button", { name: "Preview exact changes" }),
      ).toHaveAttribute("aria-disabled", "true");
      expect(screen.getByLabelText("Permit reviewed warnings")).toBeDisabled();
      fireEvent.click(
        screen.getByRole("button", {
          name: "Check original publication status",
        }),
      );
    }
    await screen.findByText("Submitted");
    rendered.unmount();
    rendered = renderDataLoad();
    await screen.findByText("Submitted");
    expect(screen.getByLabelText("UTF-8 CSV text")).toBeDisabled();
    expect(
      unsavedWorkSnapshot().some(
        (item) => item.label === "Unpublished data load",
      ),
    ).toBe(true);
    expect(canPreserveUnsavedWork()).toBe(true);
    const attempts = calls.filter(
      (call) => call.body.program?.function === "facts.transfer.import.request",
    );
    expect(attempts).toHaveLength(1);
    if (loseResponse) {
      const read = calls.find(
        (call) => call.body.program?.function === "facts.transfer.import.read",
      );
      expect(read?.body.program.arguments).toEqual({
        operationId: attempts[0].body.idempotencyKey,
      });
      expect(
        screen.queryByRole("button", { name: "Retry original publication" }),
      ).toBeNull();
    }
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
      ...(loseResponse
        ? [["/api/source-load", "facts.transfer.import.read"]]
        : []),
    ]);
    expect(attempts[0].body).toMatchObject({
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
    expect(await screen.findByText("Import retry pending")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "View publication outcome" }),
    ).not.toBeInTheDocument();
    expect(unsavedWorkSnapshot().map((item) => item.label)).toContain(
      "Unpublished data load",
    );
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(await screen.findByText("Completed")).toBeInTheDocument();
    expect(
      calls
        .filter(
          (call) =>
            call.body.program?.function === "facts.transfer.import.read",
        )
        .map((call) => call.body.program.arguments),
    ).toEqual([
      ...(loseResponse
        ? [{ operationId: attempts[0].body.idempotencyKey }]
        : []),
      { requestId: IMPORT_REQUEST },
      { requestId: IMPORT_REQUEST },
    ]);
    expect(
      unsavedWorkSnapshot().some(
        (item) => item.label === "Unpublished data load",
      ),
    ).toBe(false);
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
  },
);

it("reuses the source intent keys when staging is retried", async () => {
  let uuid = 0;
  vi.stubGlobal("crypto", {
    randomUUID: () => `intent-${++uuid}`,
    subtle: { digest: async () => new Uint8Array(32).buffer },
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
      if (fn === "facts.source.staging.read") {
        expect(body.program.arguments.operationId).toBe(beginAdmissionKeys[0]);
        return nativeRefusal("SOURCE_STAGING_STATUS_UNAVAILABLE");
      }
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
              body.idempotencyKey,
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
  expect(
    screen.getByRole("button", { name: "Continue original staging" }),
  ).toHaveAttribute("aria-disabled", "true");
  fireEvent.click(
    screen.getByRole("button", { name: "Check original staging status" }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Retry original staging step" }),
  );
  await screen.findByText(/next step is append/);
  fireEvent.click(
    screen.getByRole("button", { name: "Continue original staging" }),
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

it("refuses unexpected prior batch progress instead of inventing acknowledged chunk ownership", async () => {
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
              body.idempotencyKey,
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
  await screen.findByText("INVALID_SOURCE_BEGIN_RESPONSE");
  expect(calls.map((body) => body.program.function)).toEqual([
    "facts.source.begin",
  ]);
  expect(
    screen.getByRole("button", { name: "Check original staging status" }),
  ).not.toHaveAttribute("aria-disabled");
  expect(
    screen.queryByRole("button", { name: "Leave staged input unpublished" }),
  ).not.toBeInTheDocument();
});

it("binds verified export provenance into the re-import manifest", async () => {
  const bundle = await oneRowExportBundle();
  const sourceManifestDigest = JSON.parse(bundle).manifest.manifestDigest;
  const sourcePayloadDigest = JSON.parse(bundle).chunks[0].payloadDigest;
  const subtle = crypto.subtle;
  vi.stubGlobal("crypto", { randomUUID: () => "request-1", subtle });
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
              body.idempotencyKey,
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

const sourceText =
  "axis.Account,literalType,value,sourceRef\nRevenue,AmountLiteral,1,test";
function previewResult() {
  return {
    batchId: BATCH,
    contentDigest: CONTENT_DIGEST,
    previewToken: "review-current",
    setCount: 1,
    clearCount: 0,
    review: importReview(),
  };
}
function installImportJourney(
  preview: () => Promise<unknown> = async () => previewResult(),
  sealedRows = 1,
  numericPublication?: (input: string, body: any) => Promise<unknown>,
  currentCatalog = catalog,
) {
  const calls: any[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input, init) => {
      const body = JSON.parse(String(init?.body));
      calls.push(body);
      if (String(input) === "/api/catalog")
        return new Response(JSON.stringify(currentCatalog));
      const fn = body.program.function;
      const result =
        fn === "facts.source.publish" && numericPublication
          ? await numericPublication(String(input), body)
          : fn === "facts.source.begin"
            ? {
                batchId: BATCH,
                status: "staging",
                rowCount: 0,
                contentDigest: CONTENT_DIGEST,
                duplicate: false,
              }
            : fn === "facts.source.csv.append"
              ? {
                  batchId: BATCH,
                  chunkIndex: 0,
                  rowCount: 1,
                  contentDigest: CONTENT_DIGEST,
                  duplicate: false,
                }
              : fn === "facts.source.seal"
                ? {
                    batchId: BATCH,
                    status: "ready",
                    rowCount: sealedRows,
                    contentDigest: CONTENT_DIGEST,
                  }
                : fn === "facts.source.manifest.attach"
                  ? manifestResult(body.idempotencyKey)
                  : fn === "facts.source.preview"
                    ? await preview()
                    : {};
      if (result instanceof Response) return result;
      return new Response(JSON.stringify({ result }));
    }),
  );
  installOperationAdmissionFixture("b");
  return calls;
}
async function prepareStageFixture(text = sourceText) {
  fireEvent.change(screen.getByLabelText("UTF-8 CSV text"), {
    target: { value: text },
  });
  fireEvent.click(screen.getByRole("button", { name: "Prepare pasted CSV" }));
  await screen.findByText(/Prepared \d+ bytes/);
  fireEvent.click(screen.getByLabelText("Whole application scope"));
  fireEvent.click(
    screen.getByLabelText("I reviewed the exact input and target scope"),
  );
}
async function stageFixture() {
  await prepareStageFixture();
  fireEvent.click(
    screen.getByRole("button", { name: "Stage and validate CSV" }),
  );
  await screen.findByRole("button", { name: "Preview exact changes" });
}

it("reviews a numeric group import and retries its exact signed publication after a lost response", async () => {
  const groupedCatalog = {
    ...catalog,
    applicationAccess: {
      role: "Assigned",
      workspaceAdministrator: false,
      authorizationModel: "group_assignments" as const,
    },
    functions: Object.fromEntries(
      [
        "facts.source.begin",
        "facts.source.csv.append",
        "facts.source.seal",
        "facts.source.staging.read",
        "facts.source.preview",
        "facts.source.publish",
      ].map((name) => [name, { sourceImportProfile: "numeric_merge" }]),
    ),
  };
  const publications: any[] = [];
  const calls = installImportJourney(
    undefined,
    1,
    async (path, body) => {
      expect(path).toBe("/api/source-action");
      publications.push(body);
      if (publications.length === 1)
        throw new Error("Connection closed after sending");
      return completedExecution().result;
    },
    groupedCatalog,
  );
  const component = render(<DataLoad app={app} catalog={groupedCatalog} />);
  expect(screen.queryByLabelText("Whole application scope")).toBeNull();
  expect(screen.queryByLabelText("Target handling")).toBeNull();
  expect(screen.getByLabelText("Choose numeric CSV")).toHaveAttribute(
    "accept",
    ".csv,text/csv",
  );
  async function prepareInput(text: string) {
    fireEvent.change(screen.getByLabelText("UTF-8 CSV text"), {
      target: { value: text },
    });
    fireEvent.click(screen.getByRole("button", { name: "Prepare pasted CSV" }));
    await screen.findByText(/Prepared \d+ bytes/);
  }
  await prepareInput(sourceText.replace("AmountLiteral", "TextLiteral"));
  expect(
    await screen.findByText(
      "Each input row must use AmountLiteral for this import.",
    ),
  ).toBeVisible();
  expect(
    screen.getByLabelText("I reviewed the exact input and target scope"),
  ).toBeDisabled();
  await prepareInput(sourceText);
  fireEvent.click(
    screen.getByLabelText("I reviewed the exact input and target scope"),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Stage and validate CSV" }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Preview exact changes" }),
  );
  await screen.findByText("Exact changes ready for review");
  expect(screen.queryByLabelText("Permit reviewed warnings")).toBeNull();
  fireEvent.click(
    screen.getByLabelText("I reviewed the exact set and clear counts"),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Publish reviewed numeric rows" }),
  );
  const retry = await screen.findByRole("button", {
    name: "Retry the same reviewed publication",
  });
  // After the request left the browser an active policy may withdraw new
  // writes. Discovery explicitly retains exact recovery for this caller.
  component.rerender(
    <DataLoad
      app={app}
      catalog={{
        ...groupedCatalog,
        revisions: { ...groupedCatalog.revisions, policy: 2 },
        functions: {
          "facts.source.staging.read": {
            publicationRecovery: "facts.source.publish",
          },
        },
      }}
    />,
  );
  await waitFor(() =>
    expect(retry).not.toHaveAttribute("aria-disabled", "true"),
  );
  fireEvent.click(retry);
  expect(await screen.findByText("Import completed")).toBeVisible();
  expect(screen.getByText("Publication receipt")).toBeVisible();
  expect(screen.getByText("Committed revision")).toBeVisible();
  expect(publications).toHaveLength(2);
  expect(publications[0]).toEqual(publications[1]);
  expect(publications[0].program.arguments).toEqual({
    batchId: BATCH,
    previewToken: "review-current",
  });
  expect(calls.map((body) => body.program?.function)).not.toContain(
    "facts.source.manifest.attach",
  );
  expect(calls.map((body) => body.program?.function)).not.toContain(
    "facts.transfer.import.request",
  );
});

it("stages an intentional empty replacement only at full grain and reviews the exact clear", async () => {
  const coordinate = { Account: "Revenue", Period: "Jan" };
  let reviewCount = 0;
  const calls = installImportJourney(
    async () => ({
      ...previewResult(),
      mode: "replace",
      setCount: 0,
      clearCount: ++reviewCount === 1 ? 2 : 1,
      review: {
        ...importReview(),
        mode: "replace",
        scopeAll: false,
        scopeMembers: coordinate,
        clearsComplete: reviewCount > 1,
        examples: [
          {
            action: "clear",
            members: coordinate,
            valueKind: "numeric",
            sourceRef: null,
            before: { present: true, amount: "7.00000000" },
            after: { present: false },
          },
        ],
      },
    }),
    0,
  );
  const fixture = fetch;
  vi.stubGlobal(
    "fetch",
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const program = JSON.parse(String(init?.body)).program;
      const result = { metadataRevision: 7 };
      if (program?.function === "metadata.dimension.list")
        return Response.json({
          result: {
            ...result,
            nextAfterDimensionId: null,
            rows: Object.keys(coordinate).map((id) => ({
              dimension_id: id,
              name: id,
              model_role: id,
              status: "Active",
            })),
          },
        });
      if (program?.function === "metadata.member.list") {
        const member =
          coordinate[program.arguments.dimension as keyof typeof coordinate];
        return Response.json({
          result: {
            ...result,
            nextAfterMemberId: null,
            rows: [{ member_id: member, name: member, status: "Active" }],
          },
        });
      }
      if (
        String(input) === "/api/source-load" &&
        program?.function === "facts.transfer.import.request"
      ) {
        const response = completedExecution();
        response.result = {
          ...response.result,
          mode: "replace",
          setCount: 0,
          clearCount: 1,
        };
        calls.push(JSON.parse(String(init?.body)));
        return Response.json({ result: response });
      }
      return fixture(input, init);
    },
  );
  const functions = {
    ...catalog.functions,
    "metadata.dimension.list": {},
    "metadata.member.list": {},
  };
  render(<DataLoad app={app} catalog={{ ...catalog, functions }} />);
  const handling = screen.getByLabelText("Target handling");
  const whole = screen.getByLabelText("Whole application scope");
  const prepare = () =>
    screen.getByRole("button", { name: "Prepare empty replacement" });
  const stage = screen.getByRole("button", { name: "Stage and validate CSV" });
  expect(
    screen.queryByRole("button", { name: "Prepare empty replacement" }),
  ).toBeNull();
  fireEvent.change(handling, { target: { value: "replace" } });
  expect(prepare()).toHaveAttribute("aria-disabled", "true");
  for (const dimension of Object.keys(coordinate)) {
    await screen.findByRole("option", { name: dimension });
    fireEvent.change(screen.getByLabelText("Add dimension"), {
      target: { value: dimension },
    });
    fireEvent.click(screen.getByRole("button", { name: "Choose member" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Apply selection" }),
    );
    if (dimension === "Account")
      expect(prepare()).toHaveAttribute("aria-disabled", "true");
  }
  fireEvent.click(prepare());
  await screen.findByText(/Prepared an empty source/);
  fireEvent.click(whole);
  expect(screen.queryByText(/Prepared an empty source/)).toBeNull();
  expect(stage).toHaveAttribute("aria-disabled", "true");
  expect(
    calls.filter(({ program }) =>
      program?.function?.startsWith("facts.source."),
    ),
  ).toHaveLength(0);
  fireEvent.click(whole);
  fireEvent.click(prepare());
  await screen.findByText(/Prepared an empty source/);
  fireEvent.click(
    screen.getByLabelText("I reviewed the exact input and target scope"),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Stage empty replacement" }),
  );
  const preview = await screen.findByRole("button", {
    name: "Preview exact changes",
  });
  fireEvent.click(preview);
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "The replacement preview would clear more than the selected cell.",
  );
  expect(
    screen.getByRole("button", { name: "Start durable publication" }),
  ).toHaveAttribute("aria-disabled", "true");
  fireEvent.click(preview);
  expect(await screen.findByText("7.00000000")).toBeVisible();
  expect(screen.getByText("Absent", { exact: true })).toBeVisible();
  const publish = screen.getByRole("button", {
    name: "Start durable publication",
  });
  expect(publish).toHaveAttribute("aria-disabled", "true");
  fireEvent.click(
    screen.getByLabelText("I reviewed the exact set and clear counts"),
  );
  fireEvent.click(publish);
  expect(await screen.findByText("Import completed")).toBeVisible();
  const programs = calls.flatMap(({ program, confirmed }) =>
    confirmed && program ? [program] : [],
  );
  expect(programs.map(({ function: name }) => name)).toEqual([
    "facts.source.begin",
    "facts.source.seal",
    "facts.transfer.import.request",
  ]);
  expect(programs[0].arguments).toMatchObject({
    mode: "replace",
    scopeMembers: coordinate,
    scopeAll: false,
  });
  expect(programs[1].arguments).toEqual({
    batchId: BATCH,
    expectedRows: 0,
    expectedContentDigest: CONTENT_DIGEST,
  });
  expect(programs[2].arguments).toMatchObject({
    batchId: BATCH,
    previewToken: "review-current",
  });
});

it.each([
  {
    fault: "set count",
    bad: { setCount: 2, review: { ...importReview(), setsComplete: false } },
    message: "The preview set count does not match the sealed row count.",
  },
  {
    fault: "fact dimensions",
    bad: {
      review: {
        ...importReview(),
        examples: [
          {
            ...importReview().examples[0],
            members: { FormerAccount: "Revenue" },
          },
        ],
      },
    },
    message: "A change example does not match the reviewed fact dimensions.",
  },
  {
    fault: "metadata revision",
    bad: { review: { ...importReview(), metadataRevision: 6 } },
    message: "The preview revisions do not match the sealed import.",
  },
  {
    fault: "merge data revision",
    bad: { review: { ...importReview(), dataRevision: 10 } },
    message: "The preview revisions do not match the sealed import.",
  },
  {
    fault: "merge clear count",
    bad: {
      clearCount: 1,
      review: { ...importReview(), clearsComplete: false },
    },
    message: "A merge preview cannot clear omitted values.",
  },
])(
  "rejects a preview with a mismatched $fault and rereads the original sealed import",
  async ({ bad, message }) => {
    let previews = 0;
    const calls = installImportJourney(async () =>
      ++previews === 2 ? { ...previewResult(), ...bad } : previewResult(),
    );
    render(<DataLoad app={app} catalog={catalog} />);
    await stageFixture();
    const preview = screen.getByRole("button", {
      name: "Preview exact changes",
    });
    const publish = screen.getByRole("button", {
      name: "Start durable publication",
    });
    fireEvent.click(preview);
    await screen.findByRole("region", { name: "Import change examples" });
    fireEvent.click(
      screen.getByLabelText("I reviewed the exact set and clear counts"),
    );
    expect(publish).not.toHaveAttribute("aria-disabled");
    fireEvent.click(preview);
    expect(await screen.findByRole("alert")).toHaveTextContent(message);
    expect(
      screen.queryByRole("region", { name: "Import change examples" }),
    ).not.toBeInTheDocument();
    expect(publish).toHaveAttribute("aria-disabled", "true");
    fireEvent.click(preview);
    expect(
      await screen.findByRole("region", { name: "Import change examples" }),
    ).toBeVisible();
    expect(
      screen.getByLabelText("I reviewed the exact set and clear counts"),
    ).not.toBeChecked();
    expect(
      calls.filter(({ program }) => program?.function === "facts.source.seal"),
    ).toHaveLength(1);
    expect(
      calls.some(
        ({ program }) => program?.function === "facts.transfer.import.request",
      ),
    ).toBe(false);
  },
);

it("reviews a sealed replacement at the newer data revision returned by the core", async () => {
  const result = previewResult();
  const calls = installImportJourney(async () => ({
    ...result,
    mode: "replace",
    review: {
      ...result.review,
      mode: "replace",
      dataRevision: 10,
      commitRevision: 13,
    },
  }));
  const view = render(<DataLoad app={app} catalog={catalog} />);
  fireEvent.change(screen.getByLabelText("Target handling"), {
    target: { value: "replace" },
  });
  await stageFixture();
  view.rerender(
    <DataLoad
      app={app}
      catalog={{
        ...catalog,
        revisions: { ...catalog.revisions, data: 10, commit: 13 },
      }}
    />,
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Preview exact changes" }),
  );
  await screen.findByRole("region", { name: "Import change examples" });
  const approval = screen.getByLabelText(
    "I reviewed the exact set and clear counts",
  );
  expect(approval).not.toBeChecked();
  fireEvent.click(approval);
  expect(
    screen.getByRole("button", { name: "Start durable publication" }),
  ).not.toHaveAttribute("aria-disabled");
  expect(
    calls.filter(({ program }) => program?.function === "facts.source.seal"),
  ).toHaveLength(1);
});

it.each(["metadata", "data", "security", "policy"] as const)(
  "invalidates current import review after %s changes and on draft restoration",
  async (revision) => {
    installImportJourney();
    const view = render(<DataLoad app={app} catalog={catalog} />);
    await stageFixture();
    fireEvent.click(
      screen.getByRole("button", { name: "Preview exact changes" }),
    );
    await screen.findByText("1.00000000");
    fireEvent.click(
      screen.getByLabelText("I reviewed the exact set and clear counts"),
    );
    expect(
      screen.getByRole("button", { name: "Start durable publication" }),
    ).not.toHaveAttribute("aria-disabled");
    const changed = {
      ...catalog,
      revisions: {
        ...catalog.revisions,
        [revision]: catalog.revisions[revision] + 1,
      },
    };
    if (revision === "data") {
      view.unmount();
      render(<DataLoad app={app} catalog={changed} />);
      await screen.findByRole("button", { name: "Preview exact changes" });
    } else view.rerender(<DataLoad app={app} catalog={changed} />);
    expect(screen.queryByText("1.00000000")).not.toBeInTheDocument();
    expect(
      screen.getByLabelText("I reviewed the exact set and clear counts"),
    ).not.toBeChecked();
    expect(
      screen.getByRole("button", { name: "Start durable publication" }),
    ).toHaveAttribute("aria-disabled", "true");
  },
);

it("discards a late preview after current permission revision changes", async () => {
  let resolve!: (value: unknown) => void;
  installImportJourney(
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  const view = render(<DataLoad app={app} catalog={catalog} />);
  await stageFixture();
  fireEvent.click(
    screen.getByRole("button", { name: "Preview exact changes" }),
  );
  await waitFor(() => expect(resolve).toBeTypeOf("function"));
  view.rerender(
    <DataLoad
      app={app}
      catalog={{ ...catalog, revisions: { ...catalog.revisions, security: 2 } }}
    />,
  );
  await act(async () => {
    resolve(previewResult());
  });
  expect(screen.queryByText("1.00000000")).not.toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Start durable publication" }),
  ).toHaveAttribute("aria-disabled", "true");
});

it("withdraws the import summary and diagnostic link when preview access changes", async () => {
  let previews = 0;
  const calls = installImportJourney(async () =>
    ++previews === 2
      ? new Response(
          JSON.stringify({
            code: "SOURCE_PREVIEW_AUTHORIZATION_STALE",
            message: "Access changed while preparing the import preview.",
          }),
          { status: 409 },
        )
      : {
          ...previewResult(),
          diagnostics: { artifactId: "d".repeat(32), warningCount: 4 },
        },
  );
  render(<DataLoad app={app} catalog={catalog} />);
  await stageFixture();
  const preview = screen.getByRole("button", { name: "Preview exact changes" });
  const count = (label: string) =>
    screen.getByText(label, { exact: true }).parentElement;
  fireEvent.click(preview);
  await screen.findByRole("button", { name: "Read validation diagnostics" });
  expect(count("Sets")).toHaveTextContent("1");
  expect(count("Warnings")).toHaveTextContent("4");

  fireEvent.click(preview);
  expect(await screen.findByRole("alert")).toHaveTextContent("Access changed");
  for (const label of ["Sets", "Clears", "Errors", "Warnings"])
    expect(count(label)).toHaveTextContent("—");
  expect(
    screen.queryByRole("button", { name: "Read validation diagnostics" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("region", { name: "Import change examples" }),
  ).not.toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Start durable publication" }),
  ).toHaveAttribute("aria-disabled", "true");

  fireEvent.click(preview);
  await screen.findByRole("button", { name: "Read validation diagnostics" });
  expect(count("Warnings")).toHaveTextContent("4");
  expect(
    calls.filter(({ program }) => program?.function === "facts.source.seal"),
  ).toHaveLength(1);
});

it("requires the versioned business change review before publication", async () => {
  installImportJourney(async () => ({ ...previewResult(), review: undefined }));
  render(<DataLoad app={app} catalog={catalog} />);
  await stageFixture();
  fireEvent.click(
    screen.getByRole("button", { name: "Preview exact changes" }),
  );
  await screen.findByText("INVALID_SOURCE_CHANGE_REVIEW");
  expect(
    screen.getByRole("button", { name: "Start durable publication" }),
  ).toHaveAttribute("aria-disabled", "true");
});

it("ignores an old pasted-input digest after the user edits the source", async () => {
  let resolve!: (value: ArrayBuffer) => void;
  const digestSpy = vi.spyOn(crypto.subtle, "digest").mockImplementationOnce(
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  renderDataLoad();
  fireEvent.change(screen.getByLabelText("UTF-8 CSV text"), {
    target: { value: sourceText },
  });
  fireEvent.click(screen.getByRole("button", { name: "Prepare pasted CSV" }));
  fireEvent.change(screen.getByLabelText("UTF-8 CSV text"), {
    target: { value: sourceText.replace(",1,test", ",2,new") },
  });
  await act(async () => {
    resolve(new Uint8Array(32).buffer);
  });
  expect(screen.queryByText(/Prepared \d+ bytes/)).not.toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Stage and validate CSV" }),
  ).toHaveAttribute("aria-disabled", "true");
  digestSpy.mockRestore();
});

it("ignores a late file read when another source has been entered", async () => {
  let resolve!: (text: string) => void;
  const file = new File([sourceText], "old.csv", { type: "text/csv" });
  Object.defineProperty(file, "text", {
    value: () =>
      new Promise((done) => {
        resolve = done;
      }),
  });
  renderDataLoad();
  fireEvent.change(
    screen.getByLabelText("Choose CSV or governed export bundle"),
    { target: { files: [file] } },
  );
  fireEvent.change(screen.getByLabelText("UTF-8 CSV text"), {
    target: { value: sourceText.replace(",1,test", ",3,latest") },
  });
  await act(async () => {
    resolve(sourceText);
  });
  expect(screen.getByLabelText("UTF-8 CSV text")).toHaveValue(
    sourceText.replace(",1,test", ",3,latest"),
  );
  expect(screen.queryByText(/Prepared \d+ bytes/)).not.toBeInTheDocument();
});

it("restores input but requires a fresh preview even with unchanged cached revisions", async () => {
  installImportJourney();
  const first = render(<DataLoad app={app} catalog={catalog} />);
  await stageFixture();
  fireEvent.click(
    screen.getByRole("button", { name: "Preview exact changes" }),
  );
  await screen.findByText("1.00000000");
  fireEvent.click(
    screen.getByLabelText("I reviewed the exact set and clear counts"),
  );
  expect(
    screen.getByRole("button", { name: "Start durable publication" }),
  ).not.toHaveAttribute("aria-disabled");
  first.unmount();
  render(<DataLoad app={app} catalog={catalog} />);
  await screen.findByRole("button", { name: "Preview exact changes" });
  expect(screen.queryByText("1.00000000")).not.toBeInTheDocument();
  expect(
    screen.getByLabelText("I reviewed the exact set and clear counts"),
  ).not.toBeChecked();
  expect(
    screen.getByRole("button", { name: "Start durable publication" }),
  ).toHaveAttribute("aria-disabled", "true");
});

it("reserves staging before any effect when all recovery slots are pinned", async () => {
  const calls = installImportJourney();
  render(<DataLoad app={app} catalog={catalog} />);
  await prepareStageFixture();
  for (let index = 0; index < 24; index += 1) {
    const retained = renderHook(() =>
      usePreservedDraft(
        "other",
        String(index),
        "pending",
        "Other pending operation",
        false,
        { packet: index },
        () => undefined,
      ),
    );
    act(() => {
      retained.result.current.retain({ packet: index });
    });
  }
  fireEvent.click(
    screen.getByRole("button", { name: "Stage and validate CSV" }),
  );
  await screen.findByText(
    "This tab cannot retain another recovery record. Reconcile existing operations before submitting more work.",
  );
  expect(
    calls.some((call) => call.program?.function?.startsWith("facts.source.")),
  ).toBe(false);
  expect(
    unsavedWorkSnapshot().filter(
      (item) => item.label === "Other pending operation",
    ),
  ).toHaveLength(24);
});

function stagingReply(
  fn: string,
  args: Record<string, any>,
  operationId?: string,
) {
  if (fn === "facts.source.begin")
    return {
      batchId: BATCH,
      status: "staging",
      rowCount: 0,
      contentDigest: CONTENT_DIGEST,
    };
  if (fn === "facts.source.csv.append")
    return {
      batchId: BATCH,
      chunkIndex: args.chunkIndex,
      rowCount: 1,
      contentDigest: CONTENT_DIGEST,
    };
  if (fn === "facts.source.seal")
    return {
      batchId: BATCH,
      status: "ready",
      rowCount: args.expectedRows,
      contentDigest: args.expectedContentDigest,
    };
  if (fn === "facts.source.manifest.attach")
    return manifestResult(operationId!, args.schemaVersion);
  throw new Error(`Unexpected staging function ${fn}`);
}

function stagingStatusRequest(packet: any) {
  return {
    workspaceId: packet.workspaceId,
    applicationId: packet.applicationId,
    program: {
      languageVersion: 2,
      function: "facts.source.staging.read",
      arguments: {
        originalProgram: packet.program,
        operationId: packet.idempotencyKey,
      },
    },
  };
}

function stagingStatusResponse(packet: any, outcome?: unknown) {
  return new Response(
    JSON.stringify({
      result: {
        originalFunction: packet.program.function,
        outcome:
          outcome ??
          stagingReply(
            packet.program.function,
            packet.program.arguments,
            packet.idempotencyKey,
          ),
      },
    }),
  );
}

it.each([
  "facts.source.begin",
  "facts.source.csv.append",
  "facts.source.seal",
  "facts.source.manifest.attach",
])(
  "retains the exact %s packet through remount, admission expiry and a later denial without restarting earlier steps",
  async (lostStep) => {
    const calls: any[] = [];
    let catalogReads = 0;
    let admissions = 0;
    let lost = false;
    let deny = false;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input, init) => {
        const body = JSON.parse(String(init?.body));
        if (String(input) === "/api/catalog") {
          catalogReads += 1;
          return new Response(
            JSON.stringify({
              revisions: {
                ...catalog.revisions,
                data: catalog.revisions.data + catalogReads - 1,
              },
            }),
          );
        }
        if (String(input) === "/api/operation-admission") {
          admissions += 1;
          return operationAdmissionResponse(String(admissions));
        }
        calls.push(body);
        const fn = body.program.function;
        if (fn === "facts.source.staging.read") {
          const packet = calls.find(
            (value) => value.program.function === lostStep,
          );
          expect(body).toEqual(stagingStatusRequest(packet));
          return deny
            ? new Response(JSON.stringify({ error: "CURRENT_ACCESS_DENIED" }), {
                status: 403,
              })
            : stagingStatusResponse(packet);
        }
        if (fn === lostStep && !lost) {
          lost = true;
          throw new TypeError("Staging response lost");
        }
        return new Response(
          JSON.stringify({
            result: stagingReply(
              fn,
              body.program.arguments,
              body.idempotencyKey,
            ),
          }),
        );
      }),
    );
    const first = render(<DataLoad app={app} catalog={catalog} />);
    await prepareStageFixture();
    fireEvent.click(
      screen.getByRole("button", { name: "Stage and validate CSV" }),
    );
    await screen.findByText("Staging response lost");
    const original = calls.at(-1);
    expect(screen.getByLabelText("UTF-8 CSV text")).toBeDisabled();
    expect(
      screen.queryByRole("button", { name: "Leave staged input unpublished" }),
    ).not.toBeInTheDocument();
    const admissionsBefore = admissions;
    first.unmount();
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 7_200_000);
    deny = true;
    render(<DataLoad app={app} catalog={catalog} />);
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Check original staging status",
      }),
    );
    await screen.findByText("CURRENT_ACCESS_DENIED");
    expect(calls.at(-1)).toEqual(stagingStatusRequest(original));
    expect(admissions).toBe(admissionsBefore);
    expect(unsavedWorkSnapshot()).toHaveLength(1);
    deny = false;
    fireEvent.click(
      screen.getByRole("button", {
        name: "Check original staging status",
      }),
    );
    await waitFor(() =>
      expect(
        screen.queryByRole("button", {
          name: "Check original staging status",
        }),
      ).not.toBeInTheDocument(),
    );
    expect(calls.at(-1)).toEqual(stagingStatusRequest(original));
    expect(admissions).toBe(admissionsBefore);
    expect(catalogReads).toBe(1);
    if (lostStep !== "facts.source.manifest.attach")
      fireEvent.click(
        screen.getByRole("button", { name: "Continue original staging" }),
      );
    await screen.findByRole("button", { name: "Preview exact changes" });
    expect(
      calls.filter((body) => body.program.function === "facts.source.begin"),
    ).toHaveLength(1);
    expect(
      calls.filter((body) => body.program.function === lostStep),
    ).toHaveLength(1);
    expect(catalogReads).toBe(1);
    expect(unsavedWorkSnapshot()).toHaveLength(1);
    fireEvent.click(
      screen.getByRole("button", { name: "Leave staged input unpublished" }),
    );
    expect(
      screen.queryByRole("region", { name: "Original CSV staging recovery" }),
    ).not.toBeInTheDocument();
    expect(screen.getByLabelText("UTF-8 CSV text")).toBeEnabled();
    expect(
      calls.some(
        (body) => body.program.function === "facts.transfer.import.request",
      ),
    ).toBe(false);
  },
);

it.each(["unmount", "context"] as const)(
  "retains acknowledged staging before the %s fence and never silently admits its next step",
  async (change) => {
    let finish!: (response: Response) => void;
    const calls: any[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input, init) => {
        const body = JSON.parse(String(init?.body));
        if (String(input) === "/api/catalog")
          return new Response(JSON.stringify(catalog));
        calls.push(body);
        if (calls.length === 1)
          return new Promise<Response>((resolve) => {
            finish = resolve;
          });
        return new Response(
          JSON.stringify({
            result: stagingReply(
              body.program.function,
              body.program.arguments,
              body.idempotencyKey,
            ),
          }),
        );
      }),
    );
    installOperationAdmissionFixture("9");
    const view = render(<DataLoad app={app} catalog={catalog} />);
    await prepareStageFixture();
    fireEvent.click(
      screen.getByRole("button", { name: "Stage and validate CSV" }),
    );
    await waitFor(() => expect(finish).toBeTypeOf("function"));
    if (change === "unmount") view.unmount();
    else
      view.rerender(
        <DataLoad
          app={app}
          catalog={{
            ...catalog,
            revisions: { ...catalog.revisions, security: 2 },
          }}
        />,
      );
    await act(async () =>
      finish(
        new Response(
          JSON.stringify({ result: stagingReply("facts.source.begin", {}) }),
        ),
      ),
    );
    expect(calls).toHaveLength(1);
    if (change === "unmount") render(<DataLoad app={app} catalog={catalog} />);
    const resume = await screen.findByRole("button", {
      name: "Continue original staging",
    });
    await screen.findByText(/next step is append/);
    expect(
      screen.queryByRole("button", {
        name: "Check original staging status",
      }),
    ).not.toBeInTheDocument();
    if (change === "unmount") {
      expect(resume).not.toHaveAttribute("aria-disabled");
      fireEvent.click(resume);
      await screen.findByRole("button", { name: "Preview exact changes" });
      expect(
        calls.filter((body) => body.program.function === "facts.source.begin"),
      ).toHaveLength(1);
    } else {
      expect(resume).toHaveAttribute("aria-disabled", "true");
      fireEvent.click(
        screen.getByRole("button", { name: "Leave staged input unpublished" }),
      );
      expect(calls).toHaveLength(1);
    }
  },
);

it("resumes the exact second chunk of a 501-row upload without replaying its acknowledged first chunk or rebasing begin", async () => {
  const text = [
    "axis.Account,literalType,value,sourceRef",
    ...Array.from(
      { length: 501 },
      (_, i) => `Account-${i},AmountLiteral,${i},source-${i}`,
    ),
  ].join("\n");
  const calls: any[] = [];
  let lost = false;
  let catalogReads = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input, init) => {
      const body = JSON.parse(String(init?.body));
      if (String(input) === "/api/catalog") {
        catalogReads++;
        return new Response(JSON.stringify(catalog));
      }
      calls.push(body);
      const fn = body.program.function;
      const args = body.program.arguments;
      if (fn === "facts.source.staging.read") {
        const original = calls[2];
        expect(body).toEqual(stagingStatusRequest(original));
        return stagingStatusResponse(original, {
          batchId: BATCH,
          chunkIndex: 1,
          rowCount: 501,
          contentDigest: CONTENT_DIGEST,
        });
      }
      if (fn === "facts.source.csv.append" && args.chunkIndex === 1 && !lost) {
        lost = true;
        throw new TypeError("Second chunk accepted; response lost");
      }
      const result =
        fn === "facts.source.csv.append"
          ? {
              batchId: BATCH,
              chunkIndex: args.chunkIndex,
              rowCount: args.chunkIndex === 0 ? 500 : 501,
              contentDigest: CONTENT_DIGEST,
            }
          : stagingReply(fn, args, body.idempotencyKey);
      return new Response(JSON.stringify({ result }));
    }),
  );
  installOperationAdmissionFixture("5");
  const first = render(<DataLoad app={app} catalog={catalog} />);
  await prepareStageFixture(text);
  fireEvent.click(
    screen.getByRole("button", { name: "Stage and validate CSV" }),
  );
  await screen.findByText("Second chunk accepted; response lost");
  first.unmount();
  render(<DataLoad app={app} catalog={catalog} />);
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Check original staging status",
    }),
  );
  await screen.findByText(/next step is seal/);
  fireEvent.click(
    await screen.findByRole("button", { name: "Continue original staging" }),
  );
  await screen.findByRole("button", { name: "Preview exact changes" });
  expect(catalogReads).toBe(1);
  expect(
    calls.map((body) => [
      body.program.function,
      body.program.arguments.chunkIndex ?? null,
    ]),
  ).toEqual([
    ["facts.source.begin", null],
    ["facts.source.csv.append", 0],
    ["facts.source.csv.append", 1],
    ["facts.source.staging.read", null],
    ["facts.source.seal", null],
    ["facts.source.manifest.attach", null],
  ]);
  expect(calls[3]).toEqual(stagingStatusRequest(calls[2]));
  expect(calls[4].program.arguments).toMatchObject({
    expectedRows: 501,
    expectedContentDigest: CONTENT_DIGEST,
  });
});

it.each(["client intent", "another admission"])(
  "refuses a manifest acknowledgement bound to %s and retains its original packet",
  async (mismatch) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input, init) => {
        const body = JSON.parse(String(init?.body));
        if (String(input) === "/api/catalog")
          return new Response(JSON.stringify(catalog));
        const fn = body.program.function;
        const result = stagingReply(
          fn,
          body.program.arguments,
          body.idempotencyKey,
        );
        if (fn === "facts.source.manifest.attach")
          Object.assign(result, {
            requestKey:
              mismatch === "client intent"
                ? body.program.arguments.requestKey
                : "oa1_wrong_admission",
          });
        return new Response(JSON.stringify({ result }));
      }),
    );
    installOperationAdmissionFixture("5");
    render(<DataLoad app={app} catalog={catalog} />);
    await prepareStageFixture();
    fireEvent.click(
      screen.getByRole("button", { name: "Stage and validate CSV" }),
    );
    await screen.findByText("INVALID_SOURCE_MANIFEST_RESPONSE");
    expect(
      screen.queryByRole("button", { name: "Preview exact changes" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", {
        name: "Check original staging status",
      }),
    ).not.toHaveAttribute("aria-disabled");
    expect(
      screen.queryByRole("button", { name: "Leave staged input unpublished" }),
    ).not.toBeInTheDocument();
    expect(unsavedWorkSnapshot()).toHaveLength(1);
  },
);

it("does not recreate old-actor staging after explicit identity abandonment and a late native acknowledgement", async () => {
  let finish!: (response: Response) => void;
  const calls: any[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input, init) => {
      const body = JSON.parse(String(init?.body));
      if (String(input) === "/api/catalog")
        return new Response(JSON.stringify(catalog));
      calls.push(body);
      return new Promise<Response>((resolve) => {
        finish = resolve;
      });
    }),
  );
  installOperationAdmissionFixture("6");
  setDraftIdentity("original-actor");
  const view = render(<DataLoad app={app} catalog={catalog} />);
  await prepareStageFixture();
  fireEvent.click(
    screen.getByRole("button", { name: "Stage and validate CSV" }),
  );
  await waitFor(() => expect(finish).toBeTypeOf("function"));
  act(() => discardUnsavedWork({ abandonRecovery: true }));
  setDraftIdentity("new-actor");
  view.rerender(
    <DataLoad
      app={app}
      catalog={{
        ...catalog,
        applicationAccess: {
          ...catalog.applicationAccess,
          issuer: "new",
          subjectId: "new",
        },
      }}
    />,
  );
  await act(async () =>
    finish(
      new Response(
        JSON.stringify({ result: stagingReply("facts.source.begin", {}) }),
      ),
    ),
  );
  expect(
    screen.queryByRole("region", { name: "Original CSV staging recovery" }),
  ).not.toBeInTheDocument();
  expect(screen.getByLabelText("UTF-8 CSV text")).toHaveValue("");
  expect(unsavedWorkSnapshot()).toEqual([]);
  expect(calls).toHaveLength(1);
});

it("transfers the existing ready-batch pin into publication with all 24 recovery slots occupied", async () => {
  const calls = installImportJourney();
  const delegate = globalThis.fetch;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input, init) => {
      const body = JSON.parse(String(init?.body));
      if (
        body.program?.function === "facts.transfer.import.request" &&
        String(input) !== "/api/operation-admission"
      ) {
        calls.push(body);
        return new Response(JSON.stringify({ result: completedExecution() }));
      }
      return delegate(input, init);
    }),
  );
  render(<DataLoad app={app} catalog={catalog} />);
  await stageFixture();
  for (let index = 0; index < 23; index++) {
    const pin = renderHook(() =>
      usePreservedDraft(
        "other",
        String(index),
        "pending",
        "Other pending operation",
        false,
        { packet: index },
        () => undefined,
      ),
    );
    act(() => {
      pin.result.current.retain({ packet: index });
    });
    pin.unmount();
  }
  expect(unsavedWorkSnapshot()).toHaveLength(24);
  fireEvent.click(
    screen.getByRole("button", { name: "Preview exact changes" }),
  );
  await screen.findByText("1.00000000");
  fireEvent.click(
    screen.getByLabelText("I reviewed the exact set and clear counts"),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Start durable publication" }),
  );
  await screen.findByText("Import completed");
  fireEvent.click(
    screen.getByLabelText("I reviewed the exact input and target scope"),
  );
  expect(
    screen.getByRole("button", { name: "Stage and validate CSV" }),
  ).toHaveAttribute("aria-disabled", "true");
  expect(
    calls.filter(
      (body) => body.program?.function === "facts.transfer.import.request",
    ),
  ).toHaveLength(1);
  expect(unsavedWorkSnapshot()).toHaveLength(23);
});

it("does not let a late unmounted step overwrite a newer original staging packet", async () => {
  let finishOld!: (response: Response) => void;
  const calls: any[] = [];
  let begins = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input, init) => {
      const body = JSON.parse(String(init?.body));
      if (String(input) === "/api/catalog")
        return new Response(JSON.stringify(catalog));
      calls.push(body);
      if (body.program.function === "facts.source.staging.read") {
        if (
          body.program.arguments.originalProgram.function ===
          "facts.source.begin"
        ) {
          expect(body).toEqual(stagingStatusRequest(calls[0]));
          return nativeRefusal("SOURCE_STAGING_STATUS_UNAVAILABLE");
        }
        throw new TypeError("Original append response lost");
      }
      if (body.program.function === "facts.source.begin" && ++begins === 1)
        return new Promise<Response>((resolve) => {
          finishOld = resolve;
        });
      if (body.program.function === "facts.source.csv.append")
        throw new TypeError("Original append response lost");
      return new Response(
        JSON.stringify({
          result: stagingReply(
            body.program.function,
            body.program.arguments,
            body.idempotencyKey,
          ),
        }),
      );
    }),
  );
  installOperationAdmissionFixture("7");
  const first = render(<DataLoad app={app} catalog={catalog} />);
  await prepareStageFixture();
  fireEvent.click(
    screen.getByRole("button", { name: "Stage and validate CSV" }),
  );
  await waitFor(() => expect(finishOld).toBeTypeOf("function"));
  first.unmount();
  const second = render(<DataLoad app={app} catalog={catalog} />);
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Check original staging status",
    }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Retry original staging step" }),
  );
  await screen.findByText(/next step is append/);
  fireEvent.click(
    await screen.findByRole("button", { name: "Continue original staging" }),
  );
  await screen.findByText("Original append response lost");
  const originalAppend = calls.at(-1);
  await act(async () =>
    finishOld(
      new Response(
        JSON.stringify({ result: stagingReply("facts.source.begin", {}) }),
      ),
    ),
  );
  second.unmount();
  render(<DataLoad app={app} catalog={catalog} />);
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Check original staging status",
    }),
  );
  await screen.findByText("Original append response lost");
  expect(calls.at(-1)).toEqual(stagingStatusRequest(originalAppend));
  expect(
    calls.filter((body) => body.program.function === "facts.source.begin"),
  ).toHaveLength(2);
});

const inputRejections = {
  format: "openepm-csv-input-rejections-v1",
  phase: "before_chunk_write",
  httpStatus: 400,
  firstDispatchOnly: true,
  priorUncertainty: "retain_original",
  changedInput: "new_admission",
  codes: ["SOURCE_AMOUNT_INVALID"],
};
const correctionCatalog = {
  ...catalog,
  functions: {
    ...catalog.functions,
    "facts.source.csv.append": { inputRejections },
  },
};
const invalidRemainder =
  "axis.Account,literalType,value,sourceRef\nAccount-500,AmountLiteral,wrong,source-500";
const correctedRemainder = invalidRemainder.replace(",wrong,", ",2.50000000,");
const correctionInput = [
  "axis.Account,literalType,value,sourceRef",
  ...Array.from(
    { length: 500 },
    (_, i) => `Account-${i},AmountLiteral,${i},source-${i}`,
  ),
  "Account-500,AmountLiteral,wrong,source-500",
].join("\n");
function nativeRefusal(code = "SOURCE_AMOUNT_INVALID", status = 400) {
  return new Response(JSON.stringify({ error: code }), { status });
}

it("corrects only a rejected remainder after 500 accepted rows using a fresh exact request, preserving its prefix across remount", async () => {
  const calls: any[] = [];
  let admissions = 0;
  let loseCorrected = true;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input, init) => {
      const body = JSON.parse(String(init?.body));
      if (String(input) === "/api/catalog")
        return new Response(JSON.stringify(correctionCatalog));
      if (String(input) === "/api/operation-admission")
        return operationAdmissionResponse(String(++admissions));
      calls.push(body);
      const fn = body.program.function;
      const args = body.program.arguments;
      if (fn === "facts.source.staging.read") {
        expect(body).toEqual(stagingStatusRequest(calls[3]));
        return stagingStatusResponse(calls[3], {
          batchId: BATCH,
          chunkIndex: 1,
          rowCount: 501,
          contentDigest: CONTENT_DIGEST,
        });
      }
      if (fn === "facts.source.csv.append") {
        if (args.csvText.includes(",wrong,")) return nativeRefusal();
        if (args.chunkIndex === 1 && loseCorrected) {
          loseCorrected = false;
          throw new TypeError("Corrected response lost");
        }
        return new Response(
          JSON.stringify({
            result: {
              batchId: BATCH,
              chunkIndex: args.chunkIndex,
              rowCount: args.chunkIndex === 0 ? 500 : 501,
              contentDigest: CONTENT_DIGEST,
            },
          }),
        );
      }
      return new Response(
        JSON.stringify({ result: stagingReply(fn, args, body.idempotencyKey) }),
      );
    }),
  );
  const first = render(<DataLoad app={app} catalog={correctionCatalog} />);
  await prepareStageFixture(correctionInput);
  fireEvent.click(
    screen.getByRole("button", { name: "Stage and validate CSV" }),
  );
  const rejected = await screen.findByLabelText("Rejected and remaining CSV");
  expect(rejected).toHaveValue(invalidRemainder);
  expect(rejected).toHaveAccessibleDescription(/SOURCE_AMOUNT_INVALID/);
  expect(
    screen.getByText(/500 acknowledged rows remain unchanged/),
  ).toBeInTheDocument();
  expect(calls).toHaveLength(3);
  expect(admissions).toBe(3);
  fireEvent.change(rejected, { target: { value: correctedRemainder } });
  first.unmount();
  const second = render(<DataLoad app={app} catalog={correctionCatalog} />);
  expect(
    await screen.findByLabelText("Rejected and remaining CSV"),
  ).toHaveValue(correctedRemainder);
  fireEvent.click(
    screen.getByRole("button", { name: "Review corrected remainder" }),
  );
  const resume = await screen.findByRole("button", {
    name: "Continue original staging",
  });
  expect(calls).toHaveLength(3);
  fireEvent.click(resume);
  await screen.findByText("Corrected response lost");
  expect(calls).toHaveLength(4);
  expect(admissions).toBe(4);
  expect(calls[3].program.arguments).toEqual({
    batchId: BATCH,
    chunkIndex: 1,
    csvText: correctedRemainder,
  });
  expect(calls[3].idempotencyKey).not.toBe(calls[2].idempotencyKey);
  expect(
    screen.queryByLabelText("Rejected and remaining CSV"),
  ).not.toBeInTheDocument();
  second.unmount();
  render(<DataLoad app={app} catalog={correctionCatalog} />);
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Check original staging status",
    }),
  );
  await waitFor(() =>
    expect(
      screen.queryByRole("button", {
        name: "Check original staging status",
      }),
    ).not.toBeInTheDocument(),
  );
  expect(calls[4]).toEqual(stagingStatusRequest(calls[3]));
  expect(admissions).toBe(4);
  fireEvent.click(
    screen.getByRole("button", { name: "Continue original staging" }),
  );
  await screen.findByRole("button", { name: "Preview exact changes" });
  expect(
    calls.map((body) => [
      body.program.function,
      body.program.arguments.chunkIndex ?? null,
    ]),
  ).toEqual([
    ["facts.source.begin", null],
    ["facts.source.csv.append", 0],
    ["facts.source.csv.append", 1],
    ["facts.source.csv.append", 1],
    ["facts.source.staging.read", null],
    ["facts.source.seal", null],
    ["facts.source.manifest.attach", null],
  ]);
  expect(calls[1].program.arguments.csvText).toBe(
    csvChunks(correctionInput)[0],
  );
  expect(calls[5].program.arguments).toEqual({
    batchId: BATCH,
    expectedRows: 501,
    expectedContentDigest: CONTENT_DIGEST,
  });
  expect(calls[6].program.arguments.schemaVersion).toBe("openepm.typed-csv.v1");
  expect(unsavedWorkSnapshot()).toHaveLength(1);
});

it("never reclassifies a lost first append response as correctable after remount and a later declared refusal", async () => {
  const calls: any[] = [];
  let admissions = 0;
  let lost = false;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input, init) => {
      const body = JSON.parse(String(init?.body));
      if (String(input) === "/api/catalog")
        return new Response(JSON.stringify(correctionCatalog));
      if (String(input) === "/api/operation-admission")
        return operationAdmissionResponse(String(++admissions));
      calls.push(body);
      if (body.program.function === "facts.source.staging.read")
        return nativeRefusal();
      if (body.program.function === "facts.source.csv.append") {
        if (!lost) {
          lost = true;
          throw new TypeError("Initial outcome unknown");
        }
        return nativeRefusal();
      }
      return new Response(
        JSON.stringify({
          result: stagingReply(body.program.function, body.program.arguments),
        }),
      );
    }),
  );
  const first = render(<DataLoad app={app} catalog={correctionCatalog} />);
  await prepareStageFixture(invalidRemainder);
  fireEvent.click(
    screen.getByRole("button", { name: "Stage and validate CSV" }),
  );
  await screen.findByText("Initial outcome unknown");
  first.unmount();
  render(<DataLoad app={app} catalog={correctionCatalog} />);
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Check original staging status",
    }),
  );
  await screen.findByText("SOURCE_AMOUNT_INVALID");
  expect(calls[2]).toEqual(stagingStatusRequest(calls[1]));
  expect(admissions).toBe(2);
  expect(
    screen.queryByLabelText("Rejected and remaining CSV"),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Leave staged input unpublished" }),
  ).not.toBeInTheDocument();
  expect(unsavedWorkSnapshot()).toHaveLength(1);
});

it.each([
  {
    name: "missing declaration",
    declaration: undefined,
    status: 400,
    code: "SOURCE_AMOUNT_INVALID",
  },
  {
    name: "extra declaration field",
    declaration: { ...inputRejections, safe: true },
    status: 400,
    code: "SOURCE_AMOUNT_INVALID",
  },
  {
    name: "wrong phase",
    declaration: { ...inputRejections, phase: "after_write" },
    status: 400,
    code: "SOURCE_AMOUNT_INVALID",
  },
  {
    name: "duplicate codes",
    declaration: {
      ...inputRejections,
      codes: ["SOURCE_AMOUNT_INVALID", "SOURCE_AMOUNT_INVALID"],
    },
    status: 400,
    code: "SOURCE_AMOUNT_INVALID",
  },
  {
    name: "authorization denial",
    declaration: inputRejections,
    status: 403,
    code: "SOURCE_AMOUNT_INVALID",
  },
  {
    name: "conflict",
    declaration: inputRejections,
    status: 409,
    code: "SOURCE_AMOUNT_INVALID",
  },
  {
    name: "generic failure",
    declaration: inputRejections,
    status: 400,
    code: "WEB_OPERATION_FAILED",
  },
])(
  "retains first-dispatch uncertainty for $name",
  async ({ declaration, status, code }) => {
    const current = {
      ...catalog,
      functions: {
        ...catalog.functions,
        "facts.source.csv.append": { inputRejections: declaration },
      },
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input, init) => {
        const body = JSON.parse(String(init?.body));
        if (String(input) === "/api/catalog")
          return new Response(JSON.stringify(current));
        if (body.program.function === "facts.source.csv.append")
          return nativeRefusal(code, status);
        return new Response(
          JSON.stringify({
            result: stagingReply(body.program.function, body.program.arguments),
          }),
        );
      }),
    );
    installOperationAdmissionFixture("e");
    render(<DataLoad app={app} catalog={current} />);
    await prepareStageFixture(invalidRemainder);
    fireEvent.click(
      screen.getByRole("button", { name: "Stage and validate CSV" }),
    );
    await screen.findByText(code);
    expect(
      screen.queryByLabelText("Rejected and remaining CSV"),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", {
        name: "Check original staging status",
      }),
    ).not.toHaveAttribute("aria-disabled");
    expect(
      screen.queryByRole("button", { name: "Leave staged input unpublished" }),
    ).not.toBeInTheDocument();
    expect(unsavedWorkSnapshot()).toHaveLength(1);
  },
);

it.each(["security", "declaration", "loading"])(
  "does not classify a late refusal after current catalogue %s changes",
  async (change) => {
    let finish!: (response: Response) => void;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input, init) => {
        const body = JSON.parse(String(init?.body));
        if (String(input) === "/api/catalog")
          return new Response(JSON.stringify(correctionCatalog));
        if (body.program.function === "facts.source.csv.append")
          return new Promise<Response>((resolve) => {
            finish = resolve;
          });
        return new Response(
          JSON.stringify({
            result: stagingReply(body.program.function, body.program.arguments),
          }),
        );
      }),
    );
    installOperationAdmissionFixture("e");
    const view = render(<DataLoad app={app} catalog={correctionCatalog} />);
    await prepareStageFixture(invalidRemainder);
    fireEvent.click(
      screen.getByRole("button", { name: "Stage and validate CSV" }),
    );
    await waitFor(() => expect(finish).toBeTypeOf("function"));
    view.rerender(
      <DataLoad
        app={app}
        catalog={
          change === "loading"
            ? null
            : change === "security"
              ? {
                  ...correctionCatalog,
                  revisions: { ...catalog.revisions, security: 2 },
                }
              : {
                  ...catalog,
                  functions: {
                    ...catalog.functions,
                    "facts.source.csv.append": {
                      inputRejections: { ...inputRejections, codes: [] },
                    },
                  },
                }
        }
      />,
    );
    await act(async () => finish(nativeRefusal()));
    expect(
      screen.queryByLabelText("Rejected and remaining CSV"),
    ).not.toBeInTheDocument();
    expect(unsavedWorkSnapshot()).toHaveLength(1);
  },
);

it("allows a corrected header only before any rows or chunk boundaries are acknowledged", () => {
  const original =
    "axis.Wrong,literalType,value,sourceRef\nRevenue,AmountLiteral,wrong,r";
  const corrected =
    "axis.Account,literalType,value,sourceRef\nRevenue,AmountLiteral,1,r";
  expect(correctedCsvRemainder(original, 0, corrected, [])).toEqual({
    text: corrected,
    acknowledgedChunkRows: [],
  });
  expect(() => correctedCsvRemainder(original, 0, corrected, [1])).toThrow(
    /boundary/,
  );
  expect(() =>
    correctedCsvRemainder(
      correctionInput,
      1,
      corrected.replace("axis.Account", "axis.Other"),
      [500],
    ),
  ).toThrow(/header/);
});

it("reviews a rejected first header as a new intent on the original empty batch", async () => {
  const calls: any[] = [];
  const current = {
    ...correctionCatalog,
    functions: {
      ...correctionCatalog.functions,
      "facts.source.csv.append": {
        inputRejections: {
          ...inputRejections,
          codes: ["SOURCE_CSV_HEADER_INVALID"],
        },
      },
    },
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input, init) => {
      const body = JSON.parse(String(init?.body));
      if (String(input) === "/api/catalog")
        return new Response(JSON.stringify(current));
      calls.push(body);
      if (
        body.program.function === "facts.source.csv.append" &&
        body.program.arguments.csvText.startsWith("axis.,")
      )
        return nativeRefusal("SOURCE_CSV_HEADER_INVALID");
      return new Response(
        JSON.stringify({
          result: stagingReply(
            body.program.function,
            body.program.arguments,
            body.idempotencyKey,
          ),
        }),
      );
    }),
  );
  installOperationAdmissionFixture("e");
  render(<DataLoad app={app} catalog={current} />);
  await prepareStageFixture(
    "axis.,literalType,value,sourceRef\nRevenue,AmountLiteral,1,r",
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Stage and validate CSV" }),
  );
  const correction = await screen.findByLabelText("Rejected and remaining CSV");
  expect(screen.getByText(/No rows are acknowledged/)).toBeInTheDocument();
  fireEvent.change(correction, {
    target: {
      value:
        "axis.Account,literalType,value,sourceRef\nRevenue,AmountLiteral,1,r",
    },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Review corrected remainder" }),
  );
  await screen.findByRole("button", { name: "Continue original staging" });
  expect(calls).toHaveLength(2);
  expect(calls[0].program.function).toBe("facts.source.begin");
  expect(screen.getByText(`Original batch: ${BATCH}`)).toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("button", { name: "Continue original staging" }),
  );
  await screen.findByRole("button", { name: "Preview exact changes" });
  expect(
    calls.filter((body) => body.program.function === "facts.source.begin"),
  ).toHaveLength(1);
  expect(calls[2].program.arguments).toEqual({
    batchId: BATCH,
    chunkIndex: 0,
    csvText:
      "axis.Account,literalType,value,sourceRef\nRevenue,AmountLiteral,1,r",
  });
});

// Immutable golden generated by the actual Python ExportArtifactBuilder and
// compile_export_payload owners (V2, scope golden-workspace/golden-application,
// revisions 11/3/1, expiry 2000000000, max_chunk_rows=3). Checksums are native
// constants, never regenerated by the JavaScript fixture helper. Mixed-case,
// accented, BMP and supplementary keys distinguish locale/UTF-16/code-point order.
const nativeCodePointExportBundle = {
  contractVersion: "openepm-export-download-v1",
  artifactId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  manifest: {
    contractVersion: "openepm-complete-export-manifest-v2",
    status: "complete",
    scope: {
      workspaceId: "golden-workspace",
      applicationId: "golden-application",
    },
    schema: {
      coordinate: "stable-dimension-member-map",
      id: "openepm.fact-transfer-page",
      literalTypes: ["AmountLiteral", "TextLiteral", "LineDetailLiteral"],
      sourceReference: "required-stable-origin",
      version: 1,
    },
    snapshotRevision: 11,
    metadataRevision: 3,
    securityRevision: 1,
    expiresAt: 2000000000,
    limits: {
      maxPages: 10000,
      maxRows: 5000000,
      maxBytes: 1073741824,
    },
    pages: [
      {
        contentDigest:
          "8daaba0d45f5c49bea0e5a9424c378f15b701d845eba45ca47b573cd6c99992a",
        firstKey:
          "0000000000000000000000000000000000000000000000000000000000000001",
        hasMore: false,
        lastKey:
          "0000000000000000000000000000000000000000000000000000000000000008",
        nextCursorDigest: null,
        pageIndex: 0,
        requestCursorDigest: null,
        rowBytes: 2254,
        rowCount: 8,
        typeCounts: {
          amount: 4,
          lineDetail: 2,
          text: 2,
        },
      },
    ],
    pageCount: 1,
    totalRowCount: 8,
    totalRowBytes: 2254,
    typeCounts: {
      amount: 4,
      text: 2,
      lineDetail: 2,
    },
    cumulativeDigest:
      "b9c88203a1ab68e0c8482d1628510365a136ed207344a119e5edf966a471480e",
    manifestDigest:
      "1061dfdaf582faa84f409dae316f34cc3eac6ae78fa707aaf214bf81a30de678",
  },
  chunks: [
    {
      artifactId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      manifestDigest:
        "1061dfdaf582faa84f409dae316f34cc3eac6ae78fa707aaf214bf81a30de678",
      payloadDigest:
        "f1ff8e0fd723b59e1f9439a7f7744b5996726c0e9ff66d9aa0a9e2642e43489d",
      ordinal: 0,
      hasMore: true,
      chunk: {
        contractVersion: "openepm-export-payload-v2",
        artifactId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        manifestDigest:
          "1061dfdaf582faa84f409dae316f34cc3eac6ae78fa707aaf214bf81a30de678",
        pageIndex: 0,
        chunkIndex: 0,
        pageEntryDigest:
          "f81ba8efaa09b5414321c1d3ef24978976b850d5dcca5933aba8395478684df6",
        pageContentDigest:
          "8daaba0d45f5c49bea0e5a9424c378f15b701d845eba45ca47b573cd6c99992a",
        rows: [
          {
            members: {
              TransferScope: "inside",
              "custom-axis": "rt-zero",
              "\u00e9": "accent",
              "\ue000": "bmp-private",
              "\ud800\udc00": "supplementary",
            },
            sourceRef:
              "export:0000000000000000000000000000000000000000000000000000000000000001",
            value: {
              decimal: "0.00000000",
              type: "AmountLiteral",
            },
          },
          {
            members: {
              TransferScope: "inside",
              "custom-axis": "rt-tiny",
              "\u00e9": "accent",
              "\ue000": "bmp-private",
              "\ud800\udc00": "supplementary",
            },
            sourceRef:
              "export:0000000000000000000000000000000000000000000000000000000000000002",
            value: {
              decimal: "0.00000001",
              type: "AmountLiteral",
            },
          },
          {
            members: {
              TransferScope: "inside",
              "custom-axis": "rt-maximum",
              "\u00e9": "accent",
              "\ue000": "bmp-private",
              "\ud800\udc00": "supplementary",
            },
            sourceRef:
              "export:0000000000000000000000000000000000000000000000000000000000000003",
            value: {
              decimal: "99999999999999999999.99999999",
              type: "AmountLiteral",
            },
          },
        ],
        rowCount: 3,
        rowBytes: 809,
        typeCounts: {
          amount: 3,
          text: 0,
          lineDetail: 0,
        },
        firstKey:
          "0000000000000000000000000000000000000000000000000000000000000001",
        lastKey:
          "0000000000000000000000000000000000000000000000000000000000000003",
        finalChunkForPage: false,
        ciphertextRef: null,
        chunkDigest:
          "5a1be2afef548afeeafff5840a5bcf1a49a9f42d672de52c04f5fb0fd5a729a3",
      },
    },
    {
      artifactId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      manifestDigest:
        "1061dfdaf582faa84f409dae316f34cc3eac6ae78fa707aaf214bf81a30de678",
      payloadDigest:
        "f1ff8e0fd723b59e1f9439a7f7744b5996726c0e9ff66d9aa0a9e2642e43489d",
      ordinal: 1,
      hasMore: true,
      chunk: {
        contractVersion: "openepm-export-payload-v2",
        artifactId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        manifestDigest:
          "1061dfdaf582faa84f409dae316f34cc3eac6ae78fa707aaf214bf81a30de678",
        pageIndex: 0,
        chunkIndex: 1,
        pageEntryDigest:
          "f81ba8efaa09b5414321c1d3ef24978976b850d5dcca5933aba8395478684df6",
        pageContentDigest:
          "8daaba0d45f5c49bea0e5a9424c378f15b701d845eba45ca47b573cd6c99992a",
        rows: [
          {
            members: {
              TransferScope: "inside",
              "custom-axis": "rt-minimum",
              "\u00e9": "accent",
              "\ue000": "bmp-private",
              "\ud800\udc00": "supplementary",
            },
            sourceRef:
              "export:0000000000000000000000000000000000000000000000000000000000000004",
            value: {
              decimal: "-99999999999999999999.99999999",
              type: "AmountLiteral",
            },
          },
          {
            members: {
              TransferScope: "inside",
              "custom-axis": "rt-blank",
              "\u00e9": "accent",
              "\ue000": "bmp-private",
              "\ud800\udc00": "supplementary",
            },
            sourceRef:
              "export:0000000000000000000000000000000000000000000000000000000000000005",
            value: {
              text: "",
              type: "TextLiteral",
            },
          },
          {
            members: {
              TransferScope: "inside",
              "custom-axis": "rt-text",
              "\u00e9": "accent",
              "\ue000": "bmp-private",
              "\ud800\udc00": "supplementary",
            },
            sourceRef:
              "export:0000000000000000000000000000000000000000000000000000000000000006",
            value: {
              text: 'Cr\u00e8me,"\u6771\u4eac"\nsecond\ud83d\ude42',
              type: "TextLiteral",
            },
          },
        ],
        rowCount: 3,
        rowBytes: 810,
        typeCounts: {
          amount: 1,
          text: 2,
          lineDetail: 0,
        },
        firstKey:
          "0000000000000000000000000000000000000000000000000000000000000004",
        lastKey:
          "0000000000000000000000000000000000000000000000000000000000000006",
        finalChunkForPage: false,
        ciphertextRef: null,
        chunkDigest:
          "e25ba71ac94dc3b5f1469c95d02d25b107948e3d02b2bbfd23079839a7ebc0a6",
      },
    },
    {
      artifactId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      manifestDigest:
        "1061dfdaf582faa84f409dae316f34cc3eac6ae78fa707aaf214bf81a30de678",
      payloadDigest:
        "f1ff8e0fd723b59e1f9439a7f7744b5996726c0e9ff66d9aa0a9e2642e43489d",
      ordinal: 2,
      hasMore: false,
      chunk: {
        contractVersion: "openepm-export-payload-v2",
        artifactId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        manifestDigest:
          "1061dfdaf582faa84f409dae316f34cc3eac6ae78fa707aaf214bf81a30de678",
        pageIndex: 0,
        chunkIndex: 2,
        pageEntryDigest:
          "f81ba8efaa09b5414321c1d3ef24978976b850d5dcca5933aba8395478684df6",
        pageContentDigest:
          "8daaba0d45f5c49bea0e5a9424c378f15b701d845eba45ca47b573cd6c99992a",
        rows: [
          {
            members: {
              TransferScope: "inside",
              "custom-axis": "rt-empty-detail",
              "\u00e9": "accent",
              "\ue000": "bmp-private",
              "\ud800\udc00": "supplementary",
            },
            sourceRef:
              "export:0000000000000000000000000000000000000000000000000000000000000007",
            value: {
              items: [],
              type: "LineDetailLiteral",
            },
          },
          {
            members: {
              TransferScope: "inside",
              "custom-axis": "rt-detail",
              "\u00e9": "accent",
              "\ue000": "bmp-private",
              "\ud800\udc00": "supplementary",
            },
            sourceRef:
              "export:0000000000000000000000000000000000000000000000000000000000000008",
            value: {
              items: [
                {
                  decimal: "1.25000000",
                  description: 'quoted,"\u6771\u4eac"\nline',
                },
                {
                  decimal: "-0.00000001",
                  description: "signed tiny",
                },
              ],
              type: "LineDetailLiteral",
            },
          },
        ],
        rowCount: 2,
        rowBytes: 637,
        typeCounts: {
          amount: 0,
          text: 0,
          lineDetail: 2,
        },
        firstKey:
          "0000000000000000000000000000000000000000000000000000000000000007",
        lastKey:
          "0000000000000000000000000000000000000000000000000000000000000008",
        finalChunkForPage: true,
        ciphertextRef: null,
        chunkDigest:
          "9237357f7b1e8221a0b94dda881c725abf91890fb90cc3c8fdf0c0721749033a",
      },
    },
  ],
  chunkCount: 3,
};

it("verifies native code-point canonical export digests and exact typed CSV", async () => {
  const converted = await exportBundleToCsv(
    JSON.stringify(nativeCodePointExportBundle),
  );
  expect(converted).toMatchObject({
    artifactId: nativeCodePointExportBundle.artifactId,
    manifestDigest: nativeCodePointExportBundle.manifest.manifestDigest,
    payloadDigest: nativeCodePointExportBundle.chunks[0].payloadDigest,
    rowCount: 8,
    chunkCount: 3,
  });
  expect(converted.csv).toBe(
    'axis.TransferScope,axis.custom-axis,axis.\u00e9,axis.\ud800\udc00,axis.\ue000,literalType,value,sourceRef\ninside,rt-zero,accent,supplementary,bmp-private,AmountLiteral,0.00000000,export:0000000000000000000000000000000000000000000000000000000000000001\ninside,rt-tiny,accent,supplementary,bmp-private,AmountLiteral,0.00000001,export:0000000000000000000000000000000000000000000000000000000000000002\ninside,rt-maximum,accent,supplementary,bmp-private,AmountLiteral,99999999999999999999.99999999,export:0000000000000000000000000000000000000000000000000000000000000003\ninside,rt-minimum,accent,supplementary,bmp-private,AmountLiteral,-99999999999999999999.99999999,export:0000000000000000000000000000000000000000000000000000000000000004\ninside,rt-blank,accent,supplementary,bmp-private,TextLiteral,,export:0000000000000000000000000000000000000000000000000000000000000005\ninside,rt-text,accent,supplementary,bmp-private,TextLiteral,"Cr\u00e8me,""\u6771\u4eac""\nsecond\ud83d\ude42",export:0000000000000000000000000000000000000000000000000000000000000006\ninside,rt-empty-detail,accent,supplementary,bmp-private,LineDetailLiteral,[],export:0000000000000000000000000000000000000000000000000000000000000007\ninside,rt-detail,accent,supplementary,bmp-private,LineDetailLiteral,"[{""decimal"":""1.25000000"",""description"":""quoted,\\""\u6771\u4eac\\""\\nline""},{""decimal"":""-0.00000001"",""description"":""signed tiny""}]",export:0000000000000000000000000000000000000000000000000000000000000008',
  );
  expect(csvChunks(converted.csv)).toHaveLength(1);
});

it("rejects every tampered native chunk while preserving its original digest", async () => {
  for (const index of [0, 1, 2]) {
    const tampered = structuredClone(nativeCodePointExportBundle);
    tampered.chunks[index].chunk.rows[0].members["TransferScope"] = "outside";
    await expect(exportBundleToCsv(JSON.stringify(tampered))).rejects.toThrow(
      "Export bundle payload digest does not match.",
    );
  }
});

it("requires a new source preview after explicitly leaving staged input unpublished", async () => {
  const calls: any[] = [];
  let source = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input, init) => {
      const body = JSON.parse(String(init?.body));
      if (String(input) === "/api/catalog")
        return new Response(JSON.stringify(catalog));
      calls.push(body);
      const fn = body.program.function;
      if (fn === "facts.source.begin") source += 1;
      const batchId = source === 1 ? BATCH : RECONCILED_BATCH;
      const contentDigest = source === 1 ? CONTENT_DIGEST : "f".repeat(64);
      const result =
        fn === "facts.source.begin"
          ? {
              batchId,
              contentDigest,
              status: "staging",
              rowCount: 0,
              duplicate: false,
            }
          : fn === "facts.source.csv.append"
            ? {
                batchId,
                contentDigest,
                chunkIndex: 0,
                rowCount: 1,
                duplicate: false,
              }
            : fn === "facts.source.seal"
              ? { batchId, contentDigest, status: "ready", rowCount: 1 }
              : fn === "facts.source.manifest.attach"
                ? {
                    ...manifestResult(body.idempotencyKey, undefined, batchId),
                    contentDigest,
                  }
                : fn === "facts.source.preview"
                  ? {
                      ...previewResult(),
                      batchId,
                      contentDigest,
                      previewToken:
                        source === 1 ? "review-source-A" : "review-source-B",
                      review: {
                        ...importReview(),
                        examples: [
                          {
                            ...importReview().examples[0],
                            sourceRef: source === 1 ? "test" : "source-B",
                            after: {
                              present: true,
                              amount:
                                source === 1 ? "1.00000000" : "2.00000000",
                            },
                          },
                        ],
                      },
                    }
                  : fn === "facts.transfer.import.request"
                    ? {
                        requestId: IMPORT_REQUEST,
                        batchId,
                        status: "Accepted",
                        claimGeneration: 0,
                        cancelRequested: false,
                        result: null,
                        errorCode: null,
                        duplicate: false,
                      }
                    : {};
      return new Response(JSON.stringify({ result }));
    }),
  );
  installOperationAdmissionFixture("b");
  render(<DataLoad app={app} catalog={catalog} />);
  await stageFixture();
  fireEvent.click(
    screen.getByRole("button", { name: "Preview exact changes" }),
  );
  await screen.findByText("1.00000000");
  fireEvent.click(
    screen.getByLabelText("I reviewed the exact set and clear counts"),
  );
  expect(
    screen.getByRole("button", { name: "Start durable publication" }),
  ).not.toHaveAttribute("aria-disabled");
  fireEvent.click(
    screen.getByRole("button", { name: "Leave staged input unpublished" }),
  );
  expect(screen.queryByText("1.00000000")).not.toBeInTheDocument();
  expect(screen.getByLabelText("UTF-8 CSV text")).toBeEnabled();
  expect(
    screen.queryByRole("button", { name: "Start durable publication" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByLabelText("I reviewed the exact set and clear counts"),
  ).not.toBeInTheDocument();
  expect(
    calls.filter((x) => x.program.function === "facts.transfer.import.request"),
  ).toHaveLength(0);

  fireEvent.change(screen.getByLabelText("UTF-8 CSV text"), {
    target: { value: sourceText.replace(",1,test", ",2,source-B") },
  });
  fireEvent.click(screen.getByRole("button", { name: "Prepare pasted CSV" }));
  await screen.findByText(/Prepared \d+ bytes/);
  expect(screen.getByLabelText("Whole application scope")).toBeChecked();
  expect(
    screen.getByLabelText("I reviewed the exact input and target scope"),
  ).not.toBeChecked();
  fireEvent.click(
    screen.getByLabelText("I reviewed the exact input and target scope"),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Stage and validate CSV" }),
  );
  await waitFor(() => expect(source).toBe(2));
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Preview exact changes" }),
    ).not.toHaveAttribute("aria-disabled"),
  );
  expect(screen.queryByText("1.00000000")).not.toBeInTheDocument();
  expect(
    screen.getByLabelText("I reviewed the exact set and clear counts"),
  ).not.toBeChecked();
  expect(
    screen.getByRole("button", { name: "Start durable publication" }),
  ).toHaveAttribute("aria-disabled", "true");
  expect(
    calls.filter((x) => x.program.function === "facts.source.preview"),
  ).toHaveLength(1);
  expect(
    calls.filter((x) => x.program.function === "facts.transfer.import.request"),
  ).toHaveLength(0);

  fireEvent.click(
    screen.getByRole("button", { name: "Preview exact changes" }),
  );
  await screen.findByText("2.00000000");
  expect(
    screen.getByRole("button", { name: "Start durable publication" }),
  ).toHaveAttribute("aria-disabled", "true");
  fireEvent.click(
    screen.getByLabelText("I reviewed the exact set and clear counts"),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Start durable publication" }),
  );
  await waitFor(() =>
    expect(
      calls.filter(
        (x) => x.program.function === "facts.transfer.import.request",
      ),
    ).toHaveLength(1),
  );
  const sent = calls.find(
    (x) => x.program.function === "facts.transfer.import.request",
  );
  expect(sent.program.arguments).toMatchObject({
    batchId: RECONCILED_BATCH,
    previewToken: "review-source-B",
  });
  expect(
    calls
      .filter((x) => x.program.function === "facts.source.preview")
      .map((x) => x.program.arguments.batchId),
  ).toEqual([BATCH, RECONCILED_BATCH]);
  expect(
    calls.filter((x) => x.program.function === "facts.source.begin"),
  ).toHaveLength(2);
  expect(screen.queryByText("1.00000000")).not.toBeInTheDocument();
});
