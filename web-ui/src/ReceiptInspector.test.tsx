import { render, screen } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, expect, it, vi } from "vitest";
import { exactOperationReceipt, ReceiptInspector } from "./ReceiptInspector";

afterEach(() => vi.unstubAllGlobals());

const catalog = {
  applicationAccess: { role: "Reader", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: { "application.operation.receipt.read": {} },
  revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
};
const OPERATION = "1".repeat(32);
const OTHER_OPERATION = "2".repeat(32);

function receipt(overrides: Record<string, unknown> = {}) {
  return {
    operationId: OPERATION,
    commandDigest: "a".repeat(64),
    actorId: "analyst-1",
    committedRevision: 42,
    committedAt: "2026-11-06T12:00:00+00:00",
    outcome: {
      function: "facts.source.publish",
      setCount: 501,
      batchId: "b".repeat(32),
      resultKey: "c".repeat(64),
    },
    ...overrides,
  };
}

it.each([
  ["wrong operation", { operationId: OTHER_OPERATION }],
  ["short digest", { commandDigest: "a".repeat(63) }],
  ["non-hex digest", { commandDigest: "g".repeat(64) }],
  ["empty actor", { actorId: "" }],
  ["control actor", { actorId: "actor\nother" }],
  ["zero revision", { committedRevision: 0 }],
  ["unsafe revision", { committedRevision: Number.MAX_SAFE_INTEGER + 1 }],
  ["impossible timestamp", { committedAt: "2026-02-30T12:00:00Z" }],
  ["timestamp without zone", { committedAt: "2026-11-06T12:00:00" }],
  ["unknown outcome field", { outcome: { secret: "must-not-display" } }],
  ["nested outcome", { outcome: { status: { nested: true } } }],
  ["array outcome", { outcome: { status: ["Completed"] } }],
  ["negative count", { outcome: { changedCount: -1 } }],
  ["fractional count", { outcome: { changedCount: 1.5 } }],
  ["malformed batch ID", { outcome: { batchId: "batch-1" } }],
  ["malformed result digest", { outcome: { resultKey: "d".repeat(63) } }],
  ["extra envelope field", { rawResult: "private" }],
])("rejects %s before receipt display", (_label, override) => {
  expect(() => exactOperationReceipt(receipt(override), OPERATION)).toThrow(
    "INVALID_OPERATION_RECEIPT_RESPONSE",
  );
});

it("reads and explains an exact authorized receipt without raw payload data", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      expect(body.program).toEqual({
        languageVersion: 2,
        function: "application.operation.receipt.read",
        arguments: { operationId: OPERATION },
      });
      return new Response(
        JSON.stringify({
          result: {
            operationId: OPERATION,
            commandDigest: "a".repeat(64),
            actorId: "analyst-1",
            committedRevision: 42,
            committedAt: "2026-11-06T12:00:00Z",
            outcome: { function: "facts.source.publish", setCount: 501 },
          },
        }),
      );
    }),
  );
  const rendered = render(
    <ReceiptInspector
      scope={{ workspaceId: "ws", applicationId: "cube" }}
      catalog={catalog}
      operationId={OPERATION}
      close={() => undefined}
    />,
  );
  await screen.findByText("analyst-1");
  expect(
    screen.getByRole("heading", { name: "Operation receipt" }),
  ).toHaveFocus();
  expect(screen.getByRole("status")).toHaveTextContent("Receipt loaded");
  expect(screen.getByText("facts.source.publish")).toBeInTheDocument();
  expect(screen.getByText("501")).toBeInTheDocument();
  expect(
    (
      await axe.run(rendered.container, {
        rules: { "color-contrast": { enabled: false } },
      })
    ).violations,
  ).toEqual([]);
});

it("does not issue an unregistered read", () => {
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  render(
    <ReceiptInspector
      scope={{ workspaceId: "ws", applicationId: "cube" }}
      catalog={{ ...catalog, functions: {} }}
      operationId={OPERATION}
      close={() => undefined}
    />,
  );
  expect(screen.getByRole("alert")).toHaveTextContent("unavailable");
  expect(fetch).not.toHaveBeenCalled();
});

it("fails closed when the server returns another receipt", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: {
              operationId: OTHER_OPERATION,
              commandDigest: "b".repeat(64),
              actorId: "actor",
              committedRevision: 2,
              committedAt: "2026-11-06T12:00:00Z",
              outcome: {},
            },
          }),
        ),
    ),
  );
  render(
    <ReceiptInspector
      scope={{ workspaceId: "ws", applicationId: "cube" }}
      catalog={catalog}
      operationId={OPERATION}
      close={() => undefined}
    />,
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "INVALID_OPERATION_RECEIPT_RESPONSE",
  );
});
