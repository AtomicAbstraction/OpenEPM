import { act, fireEvent, render, screen } from "@testing-library/react";
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
const ws = { workspaceId: "ws", applicationId: "cube" };

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

it("accepts the full workflow identifier grammar only on a return target", () => {
  const target = "prepare/" + "x".repeat(292);
  const outcome = {
    function: "application.workflow.activity.return",
    activityId: "review@division/" + "y".repeat(250),
    returnedToActivityId: target,
  };
  expect(
    exactOperationReceipt(receipt({ outcome }), OPERATION).outcome,
  ).toEqual(outcome);
  for (const invalid of [
    { ...outcome, returnedToActivityId: `${target}x` },
    { ...outcome, returnedToActivityId: `${target}\n` },
    { ...outcome, function: "facts.source.publish" },
  ])
    expect(() =>
      exactOperationReceipt(receipt({ outcome: invalid }), OPERATION),
    ).toThrow("INVALID_OPERATION_RECEIPT_RESPONSE");
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
  await screen.findByText("Activity outcome loaded.");
  expect(
    screen.getByRole("heading", { name: "Activity outcome" }),
  ).toHaveFocus();
  expect(screen.getByRole("status")).toHaveTextContent(
    "Activity outcome loaded",
  );
  expect(screen.getByText("facts.source.publish")).toBeInTheDocument();
  expect(screen.getByText("501")).toBeInTheDocument();
  expect(screen.queryByText("analyst-1")).not.toBeInTheDocument();
  expect(screen.queryByText(OPERATION)).not.toBeInTheDocument();
  expect(screen.queryByText("a".repeat(64))).not.toBeInTheDocument();
  expect(screen.queryByText("b".repeat(32))).not.toBeInTheDocument();
  expect(screen.queryByText("c".repeat(64))).not.toBeInTheDocument();
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

it("checks the original receipt again after access changes and preserves focus", async () => {
  let complete!: (response: Response) => void;
  const fetch = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
    expect(init?.method).toBe("POST");
    expect(JSON.parse(String(init?.body))).toEqual({
      ...ws,
      program: {
        languageVersion: 2,
        function: "application.operation.receipt.read",
        arguments: { operationId: OPERATION },
      },
    });
    if (fetch.mock.calls.length === 1)
      return Response.json(
        { code: "OPERATION_RECEIPT_AUTHORIZATION_STALE" },
        { status: 409 },
      );
    return new Promise<Response>((resolve) => (complete = resolve));
  });
  vi.stubGlobal("fetch", fetch);
  render(
    <ReceiptInspector
      scope={ws}
      catalog={catalog}
      operationId={OPERATION}
      close={vi.fn()}
    />,
  );
  expect(await screen.findByRole("alert")).toHaveTextContent("Access changed");
  expect(screen.queryByText("Outcome summary")).toBeNull();
  const retry = screen.getByRole("button", { name: "Check outcome again" });
  retry.focus();
  fireEvent.click(retry);
  expect(screen.getByRole("status")).toHaveTextContent("Reading outcome");
  expect(retry).toHaveAttribute("aria-disabled", "true");
  expect(retry).toHaveFocus();
  fireEvent.click(retry);
  expect(fetch).toHaveBeenCalledTimes(2);
  await act(async () => complete(Response.json({ result: receipt() })));
  expect(screen.getByText("Activity outcome loaded.")).toBeVisible();
  expect(retry).toHaveFocus();
  expect(fetch.mock.calls.map(([url]) => url)).toEqual([
    "/api/read",
    "/api/read",
  ]);
});

it("focuses a replacement receipt and returns to the control that opened it", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url: RequestInfo | URL, request?: RequestInit) =>
      Response.json({
        result: receipt({
          operationId: JSON.parse(String(request?.body)).program.arguments
            .operationId,
        }),
      }),
    ),
  );
  function view(operationId?: string) {
    return (
      <>
        <button>Inspect first operation</button>
        <button>Inspect second operation</button>
        {operationId && (
          <ReceiptInspector
            scope={ws}
            catalog={catalog}
            operationId={operationId}
            close={() => undefined}
          />
        )}
      </>
    );
  }
  const { rerender } = render(view());
  screen.getByRole("button", { name: "Inspect first operation" }).focus();
  rerender(view(OPERATION));
  await screen.findByText("Activity outcome loaded.");
  const heading = screen.getByRole("heading", { name: "Activity outcome" });
  expect(heading).toHaveFocus();
  const second = screen.getByRole("button", {
    name: "Inspect second operation",
  });
  second.focus();
  rerender(view(OTHER_OPERATION));
  expect(heading).toHaveFocus();
  await screen.findByText("Activity outcome loaded.");
  rerender(view());
  expect(second).toHaveFocus();
});

it("waits for the catalogue and withdraws a loaded outcome if capability is removed", async () => {
  const fetch = vi.fn(async () => Response.json({ result: receipt() }));
  vi.stubGlobal("fetch", fetch);
  const props = { scope: ws, operationId: OPERATION, close: vi.fn() };
  const { rerender } = render(<ReceiptInspector {...props} catalog={null} />);
  expect(screen.getByRole("status")).toHaveTextContent("Checking");
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  expect(fetch).not.toHaveBeenCalled();

  rerender(<ReceiptInspector {...props} catalog={catalog} />);
  await screen.findByText("501");
  rerender(
    <ReceiptInspector {...props} catalog={{ ...catalog, functions: {} }} />,
  );
  expect(screen.getByRole("alert")).toHaveTextContent(
    "unavailable in the current application",
  );
  expect(screen.queryByText("501")).not.toBeInTheDocument();
  expect(fetch).toHaveBeenCalledTimes(1);

  rerender(<ReceiptInspector {...props} catalog={null} />);
  expect(screen.getByRole("status")).toHaveTextContent("Checking");
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  expect(
    screen.getByRole("heading", { name: "Activity outcome" }),
  ).toHaveFocus();
});

it("withdraws older evidence while revalidating authority and clears a denial on regrant", async () => {
  let respond!: (value: Response) => void;
  const deferred = new Promise<Response>((resolve) => {
    respond = resolve;
  });
  const fetch = vi
    .fn<(...args: Parameters<typeof globalThis.fetch>) => Promise<Response>>()
    .mockResolvedValueOnce(Response.json({ result: receipt() }))
    .mockReturnValueOnce(deferred)
    .mockResolvedValueOnce(
      Response.json({ result: receipt({ outcome: { changedCount: 702 } }) }),
    );
  vi.stubGlobal("fetch", fetch);
  const props = { scope: ws, operationId: OPERATION, close: vi.fn() };
  const { rerender } = render(
    <ReceiptInspector {...props} catalog={catalog} />,
  );
  await screen.findByText("501");
  screen.getByRole("button", { name: "Close" }).focus();

  rerender(
    <ReceiptInspector
      {...props}
      catalog={{ ...catalog, revisions: { ...catalog.revisions, security: 2 } }}
    />,
  );
  expect(screen.queryByText("501")).not.toBeInTheDocument();
  expect(screen.getByRole("status")).toHaveTextContent("Reading outcome");
  expect(fetch).toHaveBeenCalledTimes(2);
  await act(async () =>
    respond(
      Response.json(
        { code: "ACCESS_DENIED", message: "private record details" },
        { status: 403 },
      ),
    ),
  );
  expect(screen.getByRole("alert")).toHaveTextContent(
    "Current access does not allow this outcome to be read",
  );
  expect(
    screen.queryByText(/private record details|501/),
  ).not.toBeInTheDocument();

  rerender(
    <ReceiptInspector
      {...props}
      catalog={{ ...catalog, revisions: { ...catalog.revisions, security: 3 } }}
    />,
  );
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  await screen.findByText("702");
  expect(screen.getByRole("button", { name: "Close" })).toHaveFocus();
});

it.each(["identity", "application"])(
  "ignores a read from the previous %s",
  async (change) => {
    let respond!: (value: Response) => void;
    const deferred = new Promise<Response>((resolve) => {
      respond = resolve;
    });
    const fetch = vi
      .fn<(...args: Parameters<typeof globalThis.fetch>) => Promise<Response>>()
      .mockReturnValueOnce(deferred)
      .mockResolvedValueOnce(
        Response.json(
          {
            code: "OPERATION_RECEIPT_NOT_FOUND",
            message: "private receipt reference",
          },
          { status: 400 },
        ),
      );
    vi.stubGlobal("fetch", fetch);
    const initial = {
      ...catalog,
      applicationAccess: {
        ...catalog.applicationAccess,
        issuer: "issuer-a",
        subjectId: "first",
      },
    };
    const props = {
      scope: ws,
      catalog: initial,
      operationId: OPERATION,
      close: vi.fn(),
    };
    const { rerender } = render(<ReceiptInspector {...props} />);
    const signal = fetch.mock.calls[0][1]?.signal;
    if (change === "identity") {
      rerender(
        <ReceiptInspector
          {...props}
          catalog={{
            ...initial,
            applicationAccess: {
              ...initial.applicationAccess,
              subjectId: "second",
            },
          }}
        />,
      );
    } else {
      rerender(
        <ReceiptInspector
          {...props}
          scope={{ ...ws, applicationId: "other" }}
        />,
      );
    }
    expect(signal?.aborted).toBe(true);
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "No activity outcome is available in the current application",
    );
    await act(async () => respond(Response.json({ result: receipt() })));
    expect(
      screen.queryByText(
        /private receipt reference|501|Activity outcome loaded/,
      ),
    ).not.toBeInTheDocument();
  },
);

it("explains an outcome containing only undisplayed technical fields", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      Response.json({
        result: receipt({ outcome: { batchId: "b".repeat(32) } }),
      }),
    ),
  );
  render(
    <ReceiptInspector
      scope={ws}
      catalog={catalog}
      operationId={OPERATION}
      close={vi.fn()}
    />,
  );
  await screen.findByText("No additional safe outcome fields were recorded.");
  expect(screen.queryByText("b".repeat(32))).not.toBeInTheDocument();
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
