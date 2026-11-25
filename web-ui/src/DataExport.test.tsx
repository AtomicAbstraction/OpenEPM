import {
  act,
  fireEvent,
  render,
  renderHook,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import axe from "axe-core";
import { afterEach, expect, it, vi } from "vitest";
import {
  DataExport,
  exactExportResult,
  exportFileName,
  exportRequestArguments,
  streamCompleteExportBundle,
} from "./DataExport";
import { installOperationAdmissionFixture } from "./test-setup";
import { unsavedWorkSnapshot, usePreservedDraft } from "./unsaved-work";
import { ApiError } from "./api";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  delete (window as Window & { showSaveFilePicker?: unknown })
    .showSaveFilePicker;
});

const app = {
  workspaceId: "ws",
  applicationId: "app",
  name: "Plan",
  status: "Active",
};
const catalog = {
  applicationAccess: { role: "Editor", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: Object.fromEntries(
    [
      "facts.transfer.export.request",
      "facts.transfer.export.read",
      "facts.transfer.export.cancel",
      "facts.transfer.export.manifest.read",
      "facts.transfer.export.payload.page",
    ].map((name) => [name, {}]),
  ),
  revisions: { metadata: 7, data: 9, policy: 1, security: 1, commit: 12 },
};

const REQUEST_ID = "1".repeat(32);
let fixtureExpiry = 0;
function exportOutcome(body: any, overrides: Record<string, unknown> = {}) {
  fixtureExpiry = body.program.arguments.expiresAt ?? fixtureExpiry;
  return {
    requestId: REQUEST_ID,
    status: "Accepted",
    snapshotRevision: 12,
    metadataRevision: 7,
    securityRevision: 1,
    expiresAt: fixtureExpiry,
    pageCount: 0,
    cancelRequested: false,
    artifactId: null,
    errorCode: null,
    ...overrides,
  };
}

function manifestSnapshot() {
  return {
    status: "complete",
    scope: { workspaceId: "ws", applicationId: "app" },
    snapshotRevision: 12,
    metadataRevision: 7,
    securityRevision: 1,
    expiresAt: fixtureExpiry,
    pageCount: 0,
  };
}

it("pins exact export revisions and expiry", () => {
  expect(
    exportRequestArguments(
      { Scenario: "Plan" },
      { metadataRevision: 7, commitRevision: 12 },
      3600,
      1000,
      "export-1",
    ),
  ).toEqual({
    idempotencyKey: "export-1",
    members: { Scenario: "Plan" },
    expectedSnapshotRevision: 12,
    expectedMetadataRevision: 7,
    expiresAt: 4600,
  });
});

it("creates a readable snapshot filename without a backend artifact identity", () => {
  expect(exportFileName("Plan & Forecast 2027")).toBe(
    "openepm-plan-forecast-2027-snapshot.json",
  );
  expect(exportFileName("É")).toBe("openepm-e-snapshot.json");
  expect(exportFileName("***")).toBe("openepm-application-snapshot.json");
});

it("streams every ordered payload chunk into one complete bundle", async () => {
  const artifactId = "a".repeat(32);
  const manifest = {
    contractVersion: "openepm-complete-export-manifest-v2",
    manifestDigest: "b".repeat(64),
  };
  const requests: Array<Record<string, string>> = [];
  const output: string[] = [];
  const pages = [
    {
      artifactId,
      manifestDigest: manifest.manifestDigest,
      ordinal: 0,
      hasMore: true,
      nextCursor: "cursor-1",
      chunk: { rowCount: 1, rows: [{ value: "α" }] },
    },
    {
      artifactId,
      manifestDigest: manifest.manifestDigest,
      ordinal: 1,
      hasMore: false,
      nextCursor: null,
      chunk: { rowCount: 1, rows: [{ value: "0" }] },
    },
  ];
  const count = await streamCompleteExportBundle(
    artifactId,
    manifest,
    async (arguments_) => {
      requests.push(arguments_);
      return pages[requests.length - 1];
    },
    async (value) => {
      output.push(value);
    },
  );
  expect(count).toBe(2);
  expect(requests).toEqual([{ artifactId }, { cursor: "cursor-1" }]);
  expect(JSON.parse(output.join(""))).toEqual({
    contractVersion: "openepm-export-download-v1",
    artifactId,
    manifest,
    chunks: pages.map(({ nextCursor: _nextCursor, ...page }) => page),
    chunkCount: 2,
  });
});

it("fails a repeated or discontinuous export continuation", async () => {
  const artifactId = "b".repeat(32);
  const manifest = {
    contractVersion: "openepm-complete-export-manifest-v2",
    manifestDigest: "c".repeat(64),
  };
  let ordinal = 0;
  await expect(
    streamCompleteExportBundle(
      artifactId,
      manifest,
      async () => ({
        artifactId,
        manifestDigest: manifest.manifestDigest,
        ordinal: ordinal++,
        hasMore: true,
        nextCursor: "repeated-cursor",
        chunk: { rows: [] },
      }),
      async () => undefined,
    ),
  ).rejects.toThrow("repeated a cursor");

  await expect(
    streamCompleteExportBundle(
      artifactId,
      manifest,
      async () => ({
        artifactId,
        manifestDigest: manifest.manifestDigest,
        ordinal: 2,
        hasMore: false,
        nextCursor: null,
        chunk: { rows: [] },
      }),
      async () => undefined,
    ),
  ).rejects.toThrow("incomplete or invalid");
});

it("uses the unchanged read and export contracts", async () => {
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: { randomUUID: () => "request-1" },
  });
  vi.spyOn(Date, "now").mockReturnValue(1_000_000);
  const calls: Array<{ path: string; body: any }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push({ path: String(input), body });
      if (body.program?.function === "metadata.dimension.list")
        return new Response(
          JSON.stringify({
            result: {
              rows: [
                {
                  dimension_id: "Scenario",
                  name: "Scenario",
                  model_role: "Scenario",
                  status: "Active",
                },
              ],
              nextAfterDimensionId: null,
              metadataRevision: 7,
            },
          }),
        );
      if (body.program?.function === "metadata.member.list")
        return new Response(
          JSON.stringify({
            result: {
              rows: [
                { member_id: "Plan", name: "Plan", status: "Active" },
                { member_id: "Actual", name: "Actual", status: "Active" },
              ],
              nextAfterMemberId: null,
              metadataRevision: 7,
            },
          }),
        );
      if (String(input) === "/api/catalog")
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
      return new Response(
        JSON.stringify({
          result: exportOutcome(body),
        }),
      );
    }),
  );
  installOperationAdmissionFixture("7");
  render(
    <DataExport
      app={app}
      catalog={{
        ...catalog,
        functions: {
          ...catalog.functions,
          "metadata.dimension.list": {},
          "metadata.member.list": {},
        },
      }}
    />,
  );
  expect(
    screen.getByRole("button", { name: "Start snapshot export" }),
  ).toHaveAttribute("aria-disabled", "true");
  fireEvent.change(await screen.findByLabelText("Add dimension"), {
    target: { value: "Scenario" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Choose member" }));
  const chooser = await screen.findByRole("dialog", {
    name: "Choose one Scenario member",
  });
  fireEvent.click(
    within(chooser).getByRole("button", { name: "Apply selection" }),
  );
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact export scope and availability",
    ),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Start snapshot export" }),
  );
  await screen.findByText("Accepted");
  expect(screen.queryByText("export-1")).not.toBeInTheDocument();
  expect(
    calls
      .filter(
        (call) =>
          call.path === "/api/catalog" ||
          call.body.program?.function === "facts.transfer.export.request",
      )
      .map((call) => [call.path, call.body.program?.function || null]),
  ).toEqual([
    ["/api/catalog", null],
    ["/api/export", "facts.transfer.export.request"],
  ]);
  const exportCall = calls.find(
    (call) => call.body.program?.function === "facts.transfer.export.request",
  )!;
  expect(exportCall.body).toMatchObject({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: `oa1_zz_${"7".repeat(32)}_${"A".repeat(43)}`,
    program: {
      languageVersion: 2,
      function: "facts.transfer.export.request",
      arguments: {
        idempotencyKey: "export-ui-request-1",
        members: { Scenario: "Plan" },
        expectedSnapshotRevision: 12,
        expectedMetadataRevision: 7,
        expiresAt: 4600,
      },
    },
  });
});

it("reuses one logical export key when the response must be retried", async () => {
  let now = 1_000_000;
  vi.spyOn(Date, "now").mockImplementation(() => (now += 1_000));
  let uuid = 0;
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: { randomUUID: () => `intent-${++uuid}` },
  });
  const clientKeys: string[] = [];
  const expiries: number[] = [];
  const admissionKeys: string[] = [];
  let attempts = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (String(input) === "/api/catalog")
        return new Response(JSON.stringify({ revisions: catalog.revisions }));
      if (body.program.function === "facts.transfer.export.read") {
        expect(body.program.arguments).toEqual({
          operationId: admissionKeys[0],
        });
        return new Response(
          JSON.stringify({ code: "EXPORT_PRODUCER_REQUEST_UNAVAILABLE" }),
          {
            status: 400,
          },
        );
      }
      clientKeys.push(body.program.arguments.idempotencyKey);
      expiries.push(body.program.arguments.expiresAt);
      admissionKeys.push(body.idempotencyKey);
      attempts += 1;
      if (attempts === 1)
        return new Response(JSON.stringify({ error: "OUTCOME_UNCERTAIN" }), {
          status: 409,
        });
      return new Response(
        JSON.stringify({
          result: exportOutcome(body),
        }),
      );
    }),
  );
  installOperationAdmissionFixture("8");
  render(<DataExport app={app} catalog={catalog} />);
  fireEvent.click(screen.getByLabelText("Whole application"));
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact export scope and availability",
    ),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Start snapshot export" }),
  );
  await screen.findByText("OUTCOME_UNCERTAIN");
  fireEvent.click(
    screen.getByRole("button", { name: "Check original export status" }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Retry original export" }),
  );
  await screen.findByText("Accepted");
  expect(screen.queryByText("export-reconciled")).not.toBeInTheDocument();
  expect(clientKeys).toHaveLength(2);
  expect(clientKeys[1]).toBe(clientKeys[0]);
  expect(expiries[1]).toBe(expiries[0]);
  expect(admissionKeys).toHaveLength(2);
  expect(admissionKeys[0]).toMatch(/^oa1_/);
  expect(admissionKeys[1]).toBe(admissionKeys[0]);
});

it("requires a reviewed current state before cancellation", async () => {
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (String(input) === "/api/catalog")
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
      if (body.program.function === "facts.transfer.export.read")
        return new Response(
          JSON.stringify({
            result: exportOutcome(body),
          }),
        );
      return new Response(
        JSON.stringify({
          result: exportOutcome(body, {
            cancelRequested:
              body.program.function === "facts.transfer.export.cancel",
          }),
        }),
      );
    }),
  );
  installOperationAdmissionFixture("9");
  // Seed the durable request through the public component contract.
  render(<DataExport app={app} catalog={catalog} />);
  fireEvent.click(screen.getByLabelText("Whole application"));
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact export scope and availability",
    ),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Start snapshot export" }),
  );
  await screen.findByText("Accepted");
  expect(screen.queryByText("export-1")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Cancel export" })).toHaveAttribute(
    "aria-disabled",
    "true",
  );
  fireEvent.click(
    screen.getByLabelText("Review cancellation of this exact current state"),
  );
  expect(
    screen.getByRole("button", { name: "Cancel export" }),
  ).not.toHaveAttribute("aria-disabled");
});

it("downloads the verified manifest and every payload page as one file", async () => {
  const artifactId = "a".repeat(32);
  const manifest = {
    contractVersion: "openepm-complete-export-manifest-v2",
    manifestDigest: "b".repeat(64),
  };
  Object.defineProperty(globalThis, "crypto", {
    configurable: true,
    value: { randomUUID: () => "request-1" },
  });
  const written: string[] = [];
  const close = vi.fn(async () => undefined);
  const showSaveFilePicker = vi.fn(async () => ({
    createWritable: async () => ({
      write: async (value: string) => written.push(value),
      close,
      abort: vi.fn(async () => undefined),
    }),
  }));
  Object.defineProperty(window, "showSaveFilePicker", {
    configurable: true,
    value: showSaveFilePicker,
  });
  const functions: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (String(input) === "/api/catalog")
        return new Response(JSON.stringify({ revisions: catalog.revisions }));
      const fn = body.program.function;
      functions.push(fn);
      if (fn === "facts.transfer.export.request")
        return new Response(
          JSON.stringify({
            result: exportOutcome(body, { artifactId, status: "Completed" }),
          }),
        );
      if (fn === "facts.transfer.export.manifest.read")
        return new Response(
          JSON.stringify({
            result: {
              artifactId,
              artifact: { ...manifest, ...manifestSnapshot() },
            },
          }),
        );
      return new Response(
        JSON.stringify({
          result: {
            artifactId,
            manifestDigest: manifest.manifestDigest,
            payloadDigest: "c".repeat(64),
            ordinal: 0,
            hasMore: false,
            nextCursor: null,
            chunk: { rows: [] },
          },
        }),
      );
    }),
  );
  installOperationAdmissionFixture("a");
  const rendered = render(<DataExport app={app} catalog={catalog} />);
  fireEvent.click(screen.getByLabelText("Whole application"));
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact export scope and availability",
    ),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Start snapshot export" }),
  );
  await screen.findByText("Ready to download");
  expect(screen.queryByText(artifactId)).not.toBeInTheDocument();
  const downloadStep = within(
    screen.getByRole("list", { name: "Export progress" }),
  ).getByText("Download");
  expect(downloadStep).not.toHaveClass("complete");
  fireEvent.click(
    screen.getByRole("button", { name: "Download complete JSON bundle" }),
  );
  await screen.findByRole("button", {
    name: "Complete bundle downloaded · 1 chunks",
  });
  expect(downloadStep).toHaveClass("complete");
  expect(close).toHaveBeenCalledOnce();
  expect(showSaveFilePicker).toHaveBeenCalledWith(
    expect.objectContaining({ suggestedName: "openepm-plan-snapshot.json" }),
  );
  expect(JSON.parse(written.join(""))).toMatchObject({
    contractVersion: "openepm-export-download-v1",
    artifactId,
    manifest,
    chunkCount: 1,
  });
  expect(functions).toEqual([
    "facts.transfer.export.request",
    "facts.transfer.export.manifest.read",
    "facts.transfer.export.payload.page",
  ]);
  expect(
    (
      await axe.run(rendered.container, {
        rules: { "color-contrast": { enabled: false } },
      })
    ).violations,
  ).toEqual([]);
});

function exportFixture(handler?: (body: any) => Promise<unknown>) {
  const calls: Array<{ path: string; body: any }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input, init) => {
      const path = String(input);
      const body = JSON.parse(String(init?.body));
      calls.push({ path, body });
      if (path === "/api/catalog") return new Response(JSON.stringify(catalog));
      if (
        body.program.function === "facts.transfer.export.read" &&
        body.program.arguments.operationId
      ) {
        const original = calls.find(
          (call) =>
            call.body.idempotencyKey === body.program.arguments.operationId,
        );
        expect(original?.body.program.function).toBe(
          "facts.transfer.export.request",
        );
        return new Response(
          JSON.stringify({ result: exportOutcome(original!.body) }),
        );
      }
      const result = handler ? await handler(body) : exportOutcome(body);
      return new Response(JSON.stringify({ result }));
    }),
  );
  installOperationAdmissionFixture("a");
  return calls;
}
async function startFixtureExport() {
  fireEvent.click(screen.getByLabelText("Whole application"));
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact export scope and availability",
    ),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Start snapshot export" }),
  );
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

it("retains one exact export across remount, expiry and accepted processing", async () => {
  let attempts = 0;
  const calls = exportFixture(async (body) => {
    if (++attempts === 1) throw new TypeError("Reply lost");
    return exportOutcome(body);
  });
  let view = render(<DataExport app={app} catalog={catalog} />);
  await startFixtureExport();
  await screen.findByText("Reply lost");
  expect(screen.getByLabelText("Whole application")).toBeDisabled();
  const before = Date.now();
  vi.spyOn(Date, "now").mockReturnValue(before + 7_200_000);
  view.unmount();
  view = render(<DataExport app={app} catalog={catalog} />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Check original export status" }),
  );
  await screen.findByText("Accepted");
  const writes = calls.filter(
    (call) => call.body.program?.function === "facts.transfer.export.request",
  );
  expect(writes).toHaveLength(1);
  expect(calls.filter((call) => call.path === "/api/catalog")).toHaveLength(1);
  view.unmount();
  render(<DataExport app={app} catalog={catalog} />);
  await screen.findByText("Accepted");
  expect(screen.getByLabelText("Whole application")).toBeDisabled();
  expect(
    unsavedWorkSnapshot().some(
      (item) => item.label === "Export snapshot and recovery",
    ),
  ).toBe(true);
});

it("refuses an export effect when all recovery slots are pinned", async () => {
  const calls = exportFixture();
  render(<DataExport app={app} catalog={catalog} />);
  for (let index = 0; index < 24; index += 1) {
    const pin = renderHook(() =>
      usePreservedDraft(
        "other",
        String(index),
        "pending",
        "Other pending operation",
        false,
        { index },
        () => undefined,
      ),
    );
    act(() => {
      pin.result.current.retain({ index });
    });
  }
  await startFixtureExport();
  await screen.findByText(
    "This tab cannot retain another recovery record. Reconcile existing operations before submitting more work.",
  );
  expect(
    calls.filter(
      (call) => call.body.program?.function === "facts.transfer.export.request",
    ),
  ).toHaveLength(0);
  expect(
    unsavedWorkSnapshot().filter(
      (item) => item.label === "Other pending operation",
    ),
  ).toHaveLength(24);
});

it.each([
  { requestId: "wrong" },
  { status: "Invented" },
  { snapshotRevision: 13 },
  { metadataRevision: 8 },
  { expiresAt: 99 },
  { pageCount: -1 },
  { cancelRequested: "true" },
  { artifactId: "" },
  { status: "Completed", artifactId: null },
  { errorCode: {} },
  { duplicate: "yes" },
])("rejects a mismatched native export outcome %j", (change) => {
  const original = exportOutcome({
    program: { arguments: { expiresAt: 4600 } },
  });
  expect(() =>
    exactExportResult(
      { ...original, ...change },
      {
        expectedSnapshotRevision: 12,
        expectedMetadataRevision: 7,
        expiresAt: 4600,
      },
    ),
  ).toThrow();
});

it("rejects status for a different request without releasing original recovery", async () => {
  exportFixture(async (body) =>
    exportOutcome(
      body,
      body.program.function === "facts.transfer.export.read"
        ? {
            requestId: "2".repeat(32),
            status: "Completed",
            artifactId: "a".repeat(32),
          }
        : {},
    ),
  );
  render(<DataExport app={app} catalog={catalog} />);
  await startFixtureExport();
  await screen.findByText("Accepted");
  fireEvent.click(screen.getByRole("button", { name: "Refresh status" }));
  await screen.findByText(
    "Export outcome does not match the original request.",
  );
  expect(screen.getByText("Accepted")).toBeInTheDocument();
  expect(screen.getByLabelText("Whole application")).toBeDisabled();
});

it("fences an old application reply and restores only its original packet", async () => {
  const delayed = deferred<unknown>();
  let attempts = 0;
  const calls = exportFixture(async (body) =>
    ++attempts === 1 ? delayed.promise : exportOutcome(body),
  );
  const view = render(<DataExport app={app} catalog={catalog} />);
  await startFixtureExport();
  await screen.findByText("Submitting snapshot request…");
  await waitFor(() => expect(attempts).toBe(1));
  expect(screen.queryByText(/Export outcome unknown/)).not.toBeInTheDocument();
  view.rerender(
    <DataExport app={{ ...app, applicationId: "other" }} catalog={catalog} />,
  );
  await act(async () => {
    delayed.resolve(
      exportOutcome({ program: { arguments: { expiresAt: 4600 } } }),
    );
  });
  expect(screen.queryByText("Accepted")).not.toBeInTheDocument();
  view.rerender(<DataExport app={app} catalog={catalog} />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Check original export status" }),
  );
  await screen.findByText("Accepted");
  const writes = calls.filter(
    (call) => call.body.program?.function === "facts.transfer.export.request",
  );
  expect(writes).toHaveLength(1);
});

it.each(["picker", "writer", "page"])(
  "aborts an export download on application change during %s",
  async (phase) => {
    const artifactId = "a".repeat(32);
    const manifest = {
      contractVersion: "openepm-complete-export-manifest-v2",
      manifestDigest: "b".repeat(64),
    };
    const delayedPicker = deferred<any>();
    const delayedWriter = deferred<any>();
    const delayedPage = deferred<any>();
    const writer = {
      write: vi.fn(async () => undefined),
      close: vi.fn(async () => undefined),
      abort: vi.fn(async () => undefined),
    };
    const handle = {
      createWritable: vi.fn(async () =>
        phase === "writer" ? delayedWriter.promise : writer,
      ),
    };
    const picker = vi.fn(async () =>
      phase === "picker" ? delayedPicker.promise : handle,
    );
    Object.defineProperty(window, "showSaveFilePicker", {
      configurable: true,
      value: picker,
    });
    const calls = exportFixture(async (body) => {
      if (body.program.function === "facts.transfer.export.request")
        return exportOutcome(body, { status: "Completed", artifactId });
      if (body.program.function === "facts.transfer.export.manifest.read")
        return { artifactId, artifact: { ...manifest, ...manifestSnapshot() } };
      return delayedPage.promise;
    });
    const view = render(<DataExport app={app} catalog={catalog} />);
    await startFixtureExport();
    await screen.findByText("Ready to download");
    fireEvent.click(
      screen.getByRole("button", { name: "Download complete JSON bundle" }),
    );
    await waitFor(() => expect(picker).toHaveBeenCalledOnce());
    if (phase === "writer")
      await waitFor(() => expect(handle.createWritable).toHaveBeenCalledOnce());
    if (phase === "page")
      await waitFor(() =>
        expect(
          calls.some(
            (call) =>
              call.body.program?.function ===
              "facts.transfer.export.payload.page",
          ),
        ).toBe(true),
      );
    view.rerender(
      <DataExport app={{ ...app, applicationId: "other" }} catalog={catalog} />,
    );
    await act(async () => {
      delayedPicker.resolve(handle);
      delayedWriter.resolve(writer);
      delayedPage.resolve({
        artifactId,
        manifestDigest: manifest.manifestDigest,
        ordinal: 0,
        hasMore: false,
        nextCursor: null,
        chunk: { rows: [] },
      });
    });
    if (phase === "picker")
      expect(handle.createWritable).not.toHaveBeenCalled();
    else expect(writer.abort).toHaveBeenCalled();
    expect(writer.close).not.toHaveBeenCalled();
    expect(
      screen.queryByRole("button", { name: /Complete bundle downloaded/ }),
    ).not.toBeInTheDocument();
  },
);

it("keeps an unknown cancellation through remount and settles only its exact native reply", async () => {
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  let cancelAttempts = 0;
  const calls = exportFixture(async (body) => {
    if (body.program.function === "facts.transfer.export.cancel") {
      if (++cancelAttempts === 1)
        throw new TypeError("Cancellation reply lost");
      return exportOutcome(body, {
        status: "Cancelled",
        cancelRequested: true,
      });
    }
    return exportOutcome(body);
  });
  const view = render(<DataExport app={app} catalog={catalog} />);
  await startFixtureExport();
  await screen.findByText("Accepted");
  fireEvent.click(
    screen.getByLabelText("Review cancellation of this exact current state"),
  );
  fireEvent.click(screen.getByRole("button", { name: "Cancel export" }));
  await screen.findByText("Cancellation reply lost");
  view.unmount();
  render(<DataExport app={app} catalog={catalog} />);
  await screen.findByRole("button", {
    name: "Reconcile original cancellation",
  });
  fireEvent.click(screen.getByRole("button", { name: "Refresh status" }));
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Reconcile original cancellation" }),
    ).not.toHaveAttribute("aria-disabled"),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Reconcile original cancellation" }),
  );
  await screen.findByText("Export status: Cancelled.");
  const writes = calls.filter(
    (call) => call.body.program?.function === "facts.transfer.export.cancel",
  );
  expect(writes).toHaveLength(2);
  expect(writes[1]).toEqual(writes[0]);
  expect(screen.getByLabelText("Whole application")).toBeEnabled();
  expect(
    screen.queryByText(/Cancellation outcome unknown/),
  ).not.toBeInTheDocument();
});

it.each(["Accepted", "Cancelled", "Completed", "Failed"])(
  "reconciles expired unknown cancellation by authorized %s status without another admission",
  async (status) => {
    vi.stubGlobal(
      "confirm",
      vi.fn(() => true),
    );
    let cancelAttempts = 0;
    const calls = exportFixture(async (body) => {
      if (body.program.function === "facts.transfer.export.cancel") {
        if (++cancelAttempts === 1)
          throw new TypeError("Cancellation reply lost");
        throw new ApiError(400, "OPERATION_ADMISSION_EXPIRED");
      }
      return exportOutcome(
        body,
        body.program.function === "facts.transfer.export.read"
          ? {
              status,
              cancelRequested: status !== "Completed",
              artifactId: status === "Completed" ? "a".repeat(32) : null,
            }
          : {},
      );
    });
    const view = render(<DataExport app={app} catalog={catalog} />);
    await startFixtureExport();
    await screen.findByText("Accepted");
    fireEvent.click(
      screen.getByLabelText("Review cancellation of this exact current state"),
    );
    fireEvent.click(screen.getByRole("button", { name: "Cancel export" }));
    await screen.findByText("Cancellation reply lost");
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 7_200_000);
    view.unmount();
    const restored = render(<DataExport app={app} catalog={catalog} />);
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Reconcile original cancellation",
      }),
    );
    await screen.findByText("OPERATION_ADMISSION_EXPIRED");
    expect(
      screen.getByText(/Cancellation outcome unknown/),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Refresh status" }));
    const label =
      status === "Completed" ? status : `${status} · cancellation requested`;
    await screen.findByText(label);
    expect(
      screen.queryByText(/Cancellation outcome unknown/),
    ).not.toBeInTheDocument();
    if (status === "Accepted")
      expect(screen.getByLabelText("Whole application")).toBeDisabled();
    else expect(screen.getByLabelText("Whole application")).toBeEnabled();
    if (status === "Cancelled" || status === "Failed")
      expect(screen.getByText("No complete bundle")).toBeInTheDocument();
    const writes = calls.filter(
      (call) => call.body.program?.function === "facts.transfer.export.cancel",
    );
    expect(writes).toHaveLength(2);
    expect(writes[1]).toEqual(writes[0]);
    expect(
      calls.filter(
        (call) =>
          call.body.program?.function === "facts.transfer.export.request",
      ),
    ).toHaveLength(1);
    restored.unmount();
    render(<DataExport app={app} catalog={catalog} />);
    await screen.findByText(label);
    expect(
      screen.queryByText(/Cancellation outcome unknown/),
    ).not.toBeInTheDocument();
  },
);

it("does not forget a cancellation when its response has no cancellation evidence", async () => {
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  const calls = exportFixture();
  render(<DataExport app={app} catalog={catalog} />);
  await startFixtureExport();
  await screen.findByText("Accepted");
  fireEvent.click(
    screen.getByLabelText("Review cancellation of this exact current state"),
  );
  fireEvent.click(screen.getByRole("button", { name: "Cancel export" }));
  await screen.findByText(
    "Export cancellation was not confirmed. Reconcile the original cancellation.",
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Reconcile original cancellation" }),
  );
  await waitFor(() =>
    expect(
      calls.filter(
        (call) =>
          call.body.program?.function === "facts.transfer.export.cancel",
      ),
    ).toHaveLength(2),
  );
  const writes = calls.filter(
    (call) => call.body.program?.function === "facts.transfer.export.cancel",
  );
  expect(writes[1]).toEqual(writes[0]);
  expect(screen.getByLabelText("Whole application")).toBeDisabled();
});

it.each(["request", "status"])(
  "a late original export %s reply cannot erase a newer cancellation after remount",
  async (phase) => {
    vi.stubGlobal(
      "confirm",
      vi.fn(() => true),
    );
    const delayed = deferred<unknown>();
    let requestCalls = 0;
    let cancelCalls = 0;
    let delayedStarted = false;
    let originalBody: any;
    const calls = exportFixture(async (body) => {
      const fn = body.program.function;
      if (fn === "facts.transfer.export.request") {
        requestCalls += 1;
        originalBody = body;
        if (phase === "request" && requestCalls === 1) {
          delayedStarted = true;
          return delayed.promise;
        }
      }
      if (fn === "facts.transfer.export.read" && phase === "status") {
        delayedStarted = true;
        return delayed.promise;
      }
      if (fn === "facts.transfer.export.cancel") {
        if (++cancelCalls === 1)
          throw new TypeError("Newer cancellation reply lost");
        return exportOutcome(body, {
          status: "Cancelled",
          cancelRequested: true,
        });
      }
      return exportOutcome(body);
    });
    let view = render(<DataExport app={app} catalog={catalog} />);
    await startFixtureExport();
    if (phase === "status") {
      await screen.findByText("Accepted");
      fireEvent.click(screen.getByRole("button", { name: "Refresh status" }));
    }
    await waitFor(() => expect(delayedStarted).toBe(true));
    if (phase === "request") {
      await screen.findByText("Submitting snapshot request…");
      expect(
        screen.queryByText(/Export outcome unknown/),
      ).not.toBeInTheDocument();
    }
    view.unmount();
    view = render(<DataExport app={app} catalog={catalog} />);
    if (phase === "request")
      fireEvent.click(
        await screen.findByRole("button", {
          name: "Check original export status",
        }),
      );
    await screen.findByText("Accepted");
    fireEvent.click(
      screen.getByLabelText("Review cancellation of this exact current state"),
    );
    fireEvent.click(screen.getByRole("button", { name: "Cancel export" }));
    await screen.findByText("Newer cancellation reply lost");
    await act(async () => delayed.resolve(exportOutcome(originalBody)));
    expect(
      screen.getByRole("button", { name: "Reconcile original cancellation" }),
    ).not.toHaveAttribute("aria-disabled");
    view.unmount();
    render(<DataExport app={app} catalog={catalog} />);
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Reconcile original cancellation",
      }),
    );
    await screen.findByText(/^Cancelled · cancellation requested$/);
    const cancellations = calls.filter(
      (call) => call.body.program?.function === "facts.transfer.export.cancel",
    );
    expect(cancellations).toHaveLength(2);
    expect(cancellations[1]).toEqual(cancellations[0]);
    expect(requestCalls).toBe(1);
  },
);
