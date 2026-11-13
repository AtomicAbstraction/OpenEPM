import { fireEvent, render, screen, within } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, expect, it, vi } from "vitest";
import {
  DataExport,
  exportRequestArguments,
  streamCompleteExportBundle,
} from "./DataExport";
import { installOperationAdmissionFixture } from "./test-setup";

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
          result: { requestId: "export-1", status: "Accepted" },
        }),
      );
    }),
  );
  installOperationAdmissionFixture("7");
  render(<DataExport app={app} catalog={catalog} />);
  expect(
    screen.getByRole("button", { name: "Start snapshot export" }),
  ).toBeDisabled();
  fireEvent.change(screen.getByLabelText("Exact scope"), {
    target: { value: "Scenario=Plan" },
  });
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact export scope and availability",
    ),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Start snapshot export" }),
  );
  await screen.findByText("export-1");
  expect(
    calls.map((call) => [call.path, call.body.program?.function || null]),
  ).toEqual([
    ["/api/catalog", null],
    ["/api/export", "facts.transfer.export.request"],
  ]);
  expect(calls[1].body).toMatchObject({
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
          result: { requestId: "export-reconciled", status: "Accepted" },
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
    screen.getByRole("button", { name: "Start snapshot export" }),
  );
  await screen.findByText("export-reconciled");
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
            result: {
              requestId: "export-1",
              status: "Accepted",
              artifactId: "",
              cancelRequested: false,
            },
          }),
        );
      return new Response(
        JSON.stringify({
          result: {
            requestId: "export-1",
            status: "Accepted",
            artifactId: "",
            cancelRequested: true,
          },
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
  await screen.findByText("export-1");
  expect(screen.getByRole("button", { name: "Cancel export" })).toBeDisabled();
  fireEvent.click(
    screen.getByLabelText("Review cancellation of this exact current state"),
  );
  expect(screen.getByRole("button", { name: "Cancel export" })).toBeEnabled();
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
  Object.defineProperty(window, "showSaveFilePicker", {
    configurable: true,
    value: vi.fn(async () => ({
      createWritable: async () => ({
        write: async (value: string) => written.push(value),
        close,
        abort: vi.fn(async () => undefined),
      }),
    })),
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
            result: { requestId: "export-1", artifactId, status: "Completed" },
          }),
        );
      if (fn === "facts.transfer.export.manifest.read")
        return new Response(
          JSON.stringify({ result: { artifactId, artifact: manifest } }),
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
  await screen.findByText(artifactId);
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
