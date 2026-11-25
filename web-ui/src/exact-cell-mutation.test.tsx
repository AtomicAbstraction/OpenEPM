import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  ExactMutationOutcome,
  exactMutationOutcome,
  useExactCellMutation,
} from "./exact-cell-mutation";
import { operationAdmissionResponse } from "./test-setup";
import { fillRecoverySlots } from "./draft-recovery-test-fixture";
import {
  canPreserveUnsavedWork,
  setDraftIdentity,
  unsavedWorkSnapshot,
} from "./unsaved-work";

afterEach(() => vi.unstubAllGlobals());
const scope = { workspaceId: "w", applicationId: "a" };
const program = {
  languageVersion: 2,
  function: "facts.numeric.batch",
  arguments: {
    statements: [
      {
        action: "add",
        coordinate: { Measure: "Cost" },
        amount: "5",
        expectedChangeId: "old",
      },
    ],
  },
};
function Harness({
  context = "authority-1",
  value = program,
  owner = "owner-1",
}: {
  context?: string;
  value?: Record<string, unknown>;
  owner?: string;
}) {
  const mutation = useExactCellMutation(
    scope,
    context,
    "test-mutation",
    value,
    owner,
  );
  return (
    <>
      <button
        onClick={() => void mutation.preview()}
        disabled={mutation.busy || mutation.frozen}
      >
        Preview
      </button>
      <button
        disabled={!mutation.review || mutation.busy || mutation.frozen}
        onClick={() => void mutation.submit()}
      >
        Submit
      </button>
      <span>{mutation.frozen ? "Frozen intent" : "Editable draft"}</span>
      {mutation.error && <p role="alert">{mutation.error}</p>}
      <ExactMutationOutcome mutation={mutation} scope={scope} catalog={null} />
    </>
  );
}

it.each([
  { changedAccess: false, opaqueResponse: false },
  { changedAccess: true, opaqueResponse: false },
  { changedAccess: false, opaqueResponse: true },
])(
  "reads the original receipt after remount with changing access $changedAccess and opaque response $opaqueResponse",
  async ({ changedAccess, opaqueResponse }) => {
    const calls: Array<{ path: string; body: any }> = [];
    let submits = 0;
    let reads = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path, init) => {
        calls.push({ path: String(path), body: JSON.parse(init.body) });
        if (path === "/api/preview")
          return new Response(
            JSON.stringify({
              previewToken: "original-preview-token",
              programDigest: "b".repeat(64),
              revisionVector: { data_revision: 1 },
            }),
          );
        if (path === "/api/operation-admission")
          return operationAdmissionResponse("c");
        if (path === "/api/submit") {
          expect(canPreserveUnsavedWork()).toBe(true);
          expect(unsavedWorkSnapshot()).toHaveLength(1);
          submits += 1;
          if (opaqueResponse)
            return new Response("<h1>Forbidden</h1>", { status: 403 });
          throw new TypeError("lost response");
        }
        if (path === "/api/job") {
          reads += 1;
          if (changedAccess && reads === 1)
            return Response.json({ code: "JOB_UNAVAILABLE" }, { status: 400 });
          if (changedAccess && reads === 2)
            return Response.json(
              {
                code: "JOB_READ_AUTHORIZATION_STALE",
                message: "Access changed while checking this outcome.",
              },
              { status: 409 },
            );
          return new Response(
            JSON.stringify({
              job_id: "d".repeat(32),
              status: "published",
              receipt_revision: 2,
            }),
          );
        }
        throw new Error("Unexpected request");
      }),
    );
    const first = render(<Harness />);
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Submit" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Submit" }));
    expect(
      await screen.findByText(/Mutation outcome unknown/),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Preview" })).toBeDisabled();
    first.unmount();
    render(<Harness />);
    const check = await screen.findByRole("button", {
      name: "Check original mutation status",
    });
    fireEvent.click(check);
    if (changedAccess) {
      await screen.findByRole("button", { name: "Retry exact submission" });
      fireEvent.click(check);
      expect(await screen.findByRole("alert")).toHaveTextContent(
        "Access changed",
      );
      expect(
        screen.queryByRole("button", { name: "Retry exact submission" }),
      ).toBeNull();
      expect(screen.getByText("Frozen intent")).toBeVisible();
      expect(unsavedWorkSnapshot()).toHaveLength(1);
      fireEvent.click(check);
    }
    expect(
      await screen.findByText("Committed at revision 2."),
    ).toBeInTheDocument();
    expect(screen.getByText("Editable draft")).toBeInTheDocument();
    expect(unsavedWorkSnapshot()).toHaveLength(0);
    expect(submits).toBe(1);
    for (const { body } of calls.slice(3))
      expect(body).toEqual({
        ...scope,
        operationId: calls[2].body.idempotencyKey,
      });
    expect(calls.map((call) => call.path)).toEqual([
      "/api/preview",
      "/api/operation-admission",
      "/api/submit",
      ...Array.from({ length: changedAccess ? 3 : 1 }, () => "/api/job"),
    ]);
  },
);

it("refuses stale preview responses and invalidates a changed exact proposal", async () => {
  let release!: (response: Response) => void;
  const pending = new Promise<Response>((resolve) => {
    release = resolve;
  });
  vi.stubGlobal(
    "fetch",
    vi.fn(() => pending),
  );
  const { rerender } = render(<Harness />);
  fireEvent.click(screen.getByRole("button", { name: "Preview" }));
  rerender(<Harness context="authority-2" />);
  release(
    new Response(
      JSON.stringify({
        previewToken: "old-preview-token",
        programDigest: "b".repeat(64),
        revisionVector: { data_revision: 1 },
      }),
    ),
  );
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Preview" })).toBeEnabled(),
  );
  expect(screen.getByRole("button", { name: "Submit" })).toBeDisabled();
});

it("never promotes a mismatched or receipt-free job read into a committed outcome", () => {
  expect(() =>
    exactMutationOutcome(
      { job_id: "b".repeat(32), status: "published", receipt_revision: 1 },
      "a".repeat(32),
    ),
  ).toThrow("INVALID_MUTATION_OUTCOME");
  expect(() =>
    exactMutationOutcome(
      { job_id: "a".repeat(32), status: "published" },
      "a".repeat(32),
    ),
  ).toThrow("COMMIT_EVIDENCE_UNAVAILABLE");
  expect(() =>
    exactMutationOutcome({
      job_id: "a".repeat(32),
      status: "running",
      receipt_revision: 1,
    }),
  ).toThrow("INVALID_MUTATION_RECEIPT");
});

it("rejects a floating-point detail preview instead of displaying it as exact", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            previewToken: "detail-preview-token",
            programDigest: "a".repeat(64),
            revisionVector: { data_revision: 1 },
            detail: {
              coordinate: { Measure: "Cost" },
              replacement: "complete_set",
              itemCount: 0,
              present: true,
              total: { type: "AmountLiteral", decimal: 0 },
            },
          }),
        ),
    ),
  );
  render(
    <Harness
      value={{
        languageVersion: 2,
        function: "facts.line-detail.replace",
        arguments: {
          coordinate: { Measure: "Cost" },
          items: [],
          expectedCellChangeId: "c",
          expectedDetailChangeId: "c",
        },
      }}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Preview" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "INVALID_DETAIL_PREVIEW_EVIDENCE",
  );
  expect(screen.getByRole("button", { name: "Submit" })).toBeDisabled();
});

it("refuses dispatch when all recovery slots are pinned, preserving every existing intent", async () => {
  fillRecoverySlots();
  const sent: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path) => {
      sent.push(String(path));
      if (path === "/api/preview")
        return new Response(
          JSON.stringify({
            previewToken: "exact-preview-token",
            programDigest: "a".repeat(64),
            revisionVector: { data_revision: 1 },
          }),
        );
      if (path === "/api/operation-admission")
        return operationAdmissionResponse("c");
      throw new Error(
        "No business dispatch is permitted without recovery capacity",
      );
    }),
  );
  render(<Harness />);
  fireEvent.click(screen.getByRole("button", { name: "Preview" }));
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Submit" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Submit" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "This tab cannot retain another recovery record",
  );
  expect(sent).toEqual(["/api/preview", "/api/operation-admission"]);
  expect(unsavedWorkSnapshot()).toHaveLength(24);
  expect(canPreserveUnsavedWork()).toBe(true);
});

it("retains an accepted job arriving after unmount without repeating admission or submission", async () => {
  let resolve!: (value: Response) => void;
  const delayed = new Promise<Response>((done) => {
    resolve = done;
  });
  const sent: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path) => {
      sent.push(String(path));
      if (path === "/api/preview")
        return new Response(
          JSON.stringify({
            previewToken: "exact-preview-token",
            programDigest: "a".repeat(64),
            revisionVector: { data_revision: 1 },
          }),
        );
      if (path === "/api/operation-admission")
        return operationAdmissionResponse("c");
      if (path === "/api/submit") {
        expect(unsavedWorkSnapshot()).toHaveLength(1);
        return delayed;
      }
      throw new Error("Unexpected request");
    }),
  );
  const first = render(<Harness />);
  fireEvent.click(screen.getByRole("button", { name: "Preview" }));
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Submit" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Submit" }));
  await waitFor(() => expect(sent).toContain("/api/submit"));
  first.unmount();
  await act(async () =>
    resolve(
      new Response(
        JSON.stringify({ jobId: "d".repeat(32), status: "accepted" }),
      ),
    ),
  );
  render(<Harness />);
  expect(
    await screen.findByText(/Request status: accepted/),
  ).toBeInTheDocument();
  expect(screen.getByText("Frozen intent")).toBeInTheDocument();
  expect(sent).toEqual([
    "/api/preview",
    "/api/operation-admission",
    "/api/submit",
  ]);
  expect(unsavedWorkSnapshot()).toHaveLength(1);
});

it("keeps the original identity's packet private across an in-place subject change", async () => {
  let resolve!: (value: Response) => void;
  const delayed = new Promise<Response>((done) => {
    resolve = done;
  });
  let submits = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path) => {
      if (path === "/api/preview")
        return new Response(
          JSON.stringify({
            previewToken: "exact-preview-token",
            programDigest: "a".repeat(64),
            revisionVector: { data_revision: 1 },
          }),
        );
      if (path === "/api/operation-admission")
        return operationAdmissionResponse("c");
      if (path === "/api/submit") {
        submits += 1;
        return delayed;
      }
      throw new Error("Unexpected request");
    }),
  );
  setDraftIdentity("owner-1");
  const view = render(<Harness owner="owner-1" />);
  fireEvent.click(screen.getByRole("button", { name: "Preview" }));
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Submit" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Submit" }));
  await waitFor(() => expect(submits).toBe(1));
  setDraftIdentity("owner-2");
  view.rerender(<Harness owner="owner-2" context="authority-2" />);
  await act(async () => undefined);
  expect(
    screen.queryByLabelText("Exact mutation outcome"),
  ).not.toBeInTheDocument();
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  expect(unsavedWorkSnapshot()[0].id).toMatch(/^owner-1:/);
  await act(async () =>
    resolve(
      new Response(
        JSON.stringify({ jobId: "d".repeat(32), status: "accepted" }),
      ),
    ),
  );
  expect(
    screen.queryByLabelText("Exact mutation outcome"),
  ).not.toBeInTheDocument();
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  setDraftIdentity("owner-1");
  view.rerender(<Harness owner="owner-1" />);
  expect(
    await screen.findByRole("button", {
      name: "Check original mutation status",
    }),
  ).toBeInTheDocument();
  expect(submits).toBe(1);
});

it.each(["failed", "cancelled", "stale"])(
  "releases recovery only after a native %s outcome",
  async (status) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path) => {
        if (path === "/api/preview")
          return new Response(
            JSON.stringify({
              previewToken: "exact-preview-token",
              programDigest: "a".repeat(64),
              revisionVector: { data_revision: 1 },
            }),
          );
        if (path === "/api/operation-admission")
          return operationAdmissionResponse("c");
        if (path === "/api/submit")
          return new Response(
            JSON.stringify({ jobId: "d".repeat(32), status: "accepted" }),
          );
        if (path === "/api/job")
          return new Response(
            JSON.stringify({ job_id: "d".repeat(32), status }),
          );
        throw new Error("Unexpected request");
      }),
    );
    render(<Harness />);
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Submit" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Submit" }));
    expect(
      await screen.findByText(/Request status: accepted/),
    ).toBeInTheDocument();
    expect(unsavedWorkSnapshot()).toHaveLength(1);
    fireEvent.click(
      screen.getByRole("button", { name: "Refresh mutation status" }),
    );
    expect(
      await screen.findByText(
        `Request status: ${status}. This is not a confirmed value change.`,
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("Editable draft")).toBeInTheDocument();
    expect(unsavedWorkSnapshot()).toHaveLength(0);
  },
);

it.each([false, true])(
  "preserves a prior unknown across denial: %s",
  async (lostFirst) => {
    const packets: unknown[] = [];
    let admissions = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path, init) => {
        if (path === "/api/preview")
          return new Response(
            JSON.stringify({
              previewToken: "exact-preview-token",
              programDigest: "a".repeat(64),
              revisionVector: { data_revision: 1 },
            }),
          );
        if (path === "/api/operation-admission") {
          admissions += 1;
          return operationAdmissionResponse("c");
        }
        if (path === "/api/submit") {
          packets.push(JSON.parse(init.body));
          if (lostFirst && packets.length === 1)
            throw new TypeError("lost response");
          return new Response(
            JSON.stringify({
              code: "APPLICATION_GRANT_REQUIRED",
              message: "current authority denied",
            }),
            { status: 403 },
          );
        }
        if (path === "/api/job")
          return new Response(
            JSON.stringify({ error: "current authority denied" }),
            { status: 403 },
          );
        throw new Error("Unexpected request");
      }),
    );
    render(<Harness />);
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Submit" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Submit" }));
    if (lostFirst)
      fireEvent.click(
        await screen.findByRole("button", {
          name: "Check original mutation status",
        }),
      );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "current authority denied",
    );
    expect(unsavedWorkSnapshot()).toHaveLength(lostFirst ? 1 : 0);
    expect(
      screen.getByText(lostFirst ? "Frozen intent" : "Editable draft"),
    ).toBeInTheDocument();
    expect(admissions).toBe(1);
    expect(packets).toHaveLength(1);
    expect(
      screen.queryByRole("button", { name: "Retry exact submission" }),
    ).toBeNull();
  },
);

it.each(["accepted", "cancelled", "denied"])(
  "rejects a late old %s reply after a remounted owner retains a newer unknown replay",
  async (lateOutcome) => {
    let finishOld!: (value: Response) => void;
    const packets: unknown[] = [];
    let admissions = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path, init) => {
        if (path === "/api/preview")
          return new Response(
            JSON.stringify({
              previewToken: "original-preview-token",
              programDigest: "a".repeat(64),
              revisionVector: { data_revision: 1 },
            }),
          );
        if (path === "/api/operation-admission") {
          admissions += 1;
          return operationAdmissionResponse();
        }
        if (path === "/api/job")
          return new Response(JSON.stringify({ error: "JOB_UNAVAILABLE" }), {
            status: 400,
          });
        if (path === "/api/submit") {
          packets.push(JSON.parse(init.body));
          if (packets.length === 1)
            return new Promise<Response>((resolve) => {
              finishOld = resolve;
            });
          if (packets.length === 2)
            throw new TypeError("new replay response lost");
          return new Response(
            JSON.stringify({
              jobId: "d".repeat(32),
              status: "published",
              receipt_revision: 3,
            }),
          );
        }
        throw new Error("Unexpected request");
      }),
    );
    const first = render(<Harness />);
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Submit" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Submit" }));
    await waitFor(() => expect(finishOld).toBeDefined());
    first.unmount();
    const second = render(<Harness />);
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Check original mutation status",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Retry exact submission" }),
    );
    await screen.findByText("new replay response lost");
    await act(async () =>
      finishOld(
        lateOutcome === "denied"
          ? new Response(JSON.stringify({ error: "old denial" }), {
              status: 403,
            })
          : new Response(
              JSON.stringify({ jobId: "d".repeat(32), status: lateOutcome }),
            ),
      ),
    );
    expect(unsavedWorkSnapshot()).toHaveLength(1);
    second.unmount();
    render(<Harness />);
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Check original mutation status",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Retry exact submission" }),
    );
    await screen.findByText("Committed at revision 3.");
    expect(unsavedWorkSnapshot()).toHaveLength(0);
    expect(admissions).toBe(1);
    expect(packets).toHaveLength(3);
    expect(packets[1]).toEqual(packets[0]);
    expect(packets[2]).toEqual(packets[0]);
  },
);

it("a late terminal status from an unmounted owner cannot settle a newer current status read", async () => {
  let finishOld!: (value: Response) => void;
  let reads = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path) => {
      if (path === "/api/preview")
        return new Response(
          JSON.stringify({
            previewToken: "original-preview-token",
            programDigest: "a".repeat(64),
            revisionVector: { data_revision: 1 },
          }),
        );
      if (path === "/api/operation-admission")
        return operationAdmissionResponse();
      if (path === "/api/submit")
        return new Response(
          JSON.stringify({ jobId: "d".repeat(32), status: "accepted" }),
        );
      if (path === "/api/job") {
        if (++reads === 1)
          return new Promise<Response>((resolve) => {
            finishOld = resolve;
          });
        return new Response(
          JSON.stringify({ job_id: "d".repeat(32), status: "running" }),
        );
      }
      throw new Error("Unexpected request");
    }),
  );
  const first = render(<Harness />);
  fireEvent.click(screen.getByRole("button", { name: "Preview" }));
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Submit" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Submit" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Refresh mutation status" }),
  );
  await waitFor(() => expect(finishOld).toBeDefined());
  first.unmount();
  const second = render(<Harness />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Refresh mutation status" }),
  );
  await screen.findByText(/Request status: running/);
  await act(async () =>
    finishOld(
      new Response(
        JSON.stringify({
          job_id: "d".repeat(32),
          status: "published",
          receipt_revision: 3,
        }),
      ),
    ),
  );
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  second.unmount();
  render(<Harness />);
  await screen.findByText(/Request status: running/);
  expect(screen.getByText("Frozen intent")).toBeInTheDocument();
});

it.each(["published", "denied"])(
  "retains the original request when an old %s acknowledgement arrives after a same-owner context change",
  async (late) => {
    let held:
      | { signal: AbortSignal; resolve: (value: Response) => void }
      | undefined;
    const submissions: unknown[] = [];
    let admissions = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path, init) => {
        if (path === "/api/preview")
          return new Response(
            JSON.stringify({
              previewToken: "original-preview-token",
              programDigest: "a".repeat(64),
              revisionVector: { data_revision: 1 },
            }),
          );
        if (path === "/api/operation-admission") {
          admissions++;
          return operationAdmissionResponse();
        }
        if (path === "/api/submit") {
          submissions.push(JSON.parse(init.body));
          if (submissions.length === 1)
            return new Promise<Response>((resolve) => {
              held = { signal: init.signal, resolve };
            });
          return new Response(
            JSON.stringify({ jobId: "a".repeat(32), status: "published" }),
          );
        }
        if (path === "/api/job")
          return new Response(
            JSON.stringify({
              job_id: "a".repeat(32),
              status: "published",
              receipt_revision: 7,
            }),
          );
        throw new Error("Unexpected request");
      }),
    );
    const view = render(<Harness />);
    fireEvent.click(screen.getByRole("button", { name: "Preview" }));
    const submit = screen.getByRole("button", { name: "Submit" });
    await waitFor(() => expect(submit).toBeEnabled());
    fireEvent.click(submit);
    expect(
      await screen.findByText(/Waiting for acknowledgement/),
    ).toBeVisible();
    expect(screen.queryByText(/Mutation outcome unknown/)).toBeNull();
    view.rerender(<Harness context="changed-authority" />);
    expect(held?.signal.aborted).toBe(true);
    await act(async () =>
      held?.resolve(
        late === "denied"
          ? new Response(JSON.stringify({ error: "old authority refused" }), {
              status: 403,
            })
          : new Response(
              JSON.stringify({
                jobId: "a".repeat(32),
                status: "published",
                receipt_revision: 7,
              }),
            ),
      ),
    );
    expect(await screen.findByText(/Mutation outcome unknown/)).toBeVisible();
    expect(screen.queryByText(/Committed at revision/)).toBeNull();
    expect(unsavedWorkSnapshot()).toHaveLength(1);
    view.unmount();
    render(<Harness context="changed-authority" />);
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Check original mutation status",
      }),
    );
    expect(await screen.findByText("Committed at revision 7.")).toBeVisible();
    expect(unsavedWorkSnapshot()).toHaveLength(0);
    expect(admissions).toBe(1);
    expect(submissions).toHaveLength(1);
  },
);

it("keeps an inspected job pinned through cancellation and receipt uncertainty under current access", async () => {
  let held:
    | { signal: AbortSignal; resolve: (value: Response) => void }
    | undefined;
  const readStates = ["cancel_requested", "needs_inspection"];
  let reads = 0;
  const jobId = "d".repeat(32);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      if (path === "/api/preview")
        return new Response(
          JSON.stringify({
            previewToken: "original-preview-token",
            programDigest: "a".repeat(64),
            revisionVector: { data_revision: 1 },
          }),
        );
      if (path === "/api/operation-admission")
        return operationAdmissionResponse();
      if (path === "/api/submit")
        return new Response(JSON.stringify({ jobId, status: "accepted" }));
      if (path === "/api/job") {
        expect(JSON.parse(init.body).jobId).toBe(jobId);
        const index = reads++;
        if (!index)
          return new Promise<Response>((resolve) => {
            held = { signal: init.signal, resolve };
          });
        return new Response(
          JSON.stringify({
            job_id: jobId,
            status: readStates[index - 1],
            ...(index === 2 ? { receipt_revision: 2 } : {}),
          }),
        );
      }
      throw new Error("Unexpected request");
    }),
  );
  const view = render(<Harness />);
  fireEvent.click(screen.getByRole("button", { name: "Preview" }));
  const submit = screen.getByRole("button", { name: "Submit" });
  await waitFor(() => expect(submit).toBeEnabled());
  fireEvent.click(submit);
  fireEvent.click(
    await screen.findByRole("button", { name: "Refresh mutation status" }),
  );
  expect(
    await screen.findByText(/Reading current mutation status/),
  ).toBeVisible();
  view.rerender(<Harness context="changed-authority" />);
  expect(held?.signal.aborted).toBe(true);
  await act(async () =>
    held?.resolve(
      new Response(
        JSON.stringify({
          job_id: jobId,
          status: "published",
          receipt_revision: 2,
        }),
      ),
    ),
  );
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  expect(screen.queryByText(/Committed at revision/)).toBeNull();
  fireEvent.click(
    screen.getByRole("button", { name: "Refresh mutation status" }),
  );
  expect(await screen.findByText(/Cancellation requested/)).toBeVisible();
  fireEvent.click(
    screen.getByRole("button", { name: "Refresh mutation status" }),
  );
  expect(
    await screen.findByText(/This mutation needs inspection/),
  ).toBeVisible();
  expect(screen.queryByText(/Committed at revision/)).toBeNull();
  expect(screen.getByText("Frozen intent")).toBeVisible();
  expect(submit).toBeDisabled();
  expect(unsavedWorkSnapshot()).toHaveLength(1);
});
