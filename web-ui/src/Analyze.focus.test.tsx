import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { Analyze } from "./Analyze";
import { operationAdmissionResponse } from "./test-setup";

const app = {
  workspaceId: "focus",
  applicationId: "grid",
  name: "Grid",
  status: "Active",
};
const catalog = {
  applicationAccess: { role: "Editor", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: Object.fromEntries(
    [
      "metadata.dimension.list",
      "metadata.member.list",
      "facts.cube.scan",
      "facts.numeric.batch",
      "facts.cell.editability.read",
    ].map((name) => [name, {}]),
  ),
  revisions: { metadata: 2, data: 2, policy: 1, security: 1, commit: 2 },
};
const rows = ["Cost", "Hours"].flatMap((Account, row) =>
  ["Jan", "Feb"].map((Period, column) => ({
    members: { Account, Period },
    kind: "numeric",
    amount: `${100 + row * 10 + column}.00000000`,
    numericChangeId: `id-${row}-${column}`,
  })),
);
const response = (result: unknown) => new Response(JSON.stringify({ result }));
async function setup(flat = false) {
  const state = {
    rows: flat ? [...rows, { ...rows[0], kind: "text", text: "Note" }] : rows,
    nextCursor: "page-2" as string | null,
    outcome: "conflict" as "conflict" | "unknown" | "ready",
    read: null as null | (() => Promise<Response>),
    cellRead: null as null | ((signal: AbortSignal) => Promise<Response>),
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      const body = JSON.parse(String(init?.body));
      if (String(path) === "/api/operation-admission")
        return operationAdmissionResponse();
      if (String(path) === "/api/preview")
        return new Response(
          JSON.stringify({
            previewToken: "focus-exact-preview-token",
            programDigest: "a".repeat(64),
            revisionVector: { data_revision: 2 },
          }),
        );
      if (String(path) === "/api/submit") {
        if (state.outcome === "unknown")
          throw new TypeError("Network interrupted");
        if (state.outcome === "ready")
          return new Response(
            JSON.stringify({ jobId: "d".repeat(32), status: "ready" }),
          );
        return new Response(
          JSON.stringify({ code: "STALE_OR_MISMATCHED_V2_PREVIEW" }),
          {
            status: 400,
          },
        );
      }
      if (String(path) === "/api/job")
        return new Response(
          JSON.stringify({ job_id: "d".repeat(32), status: "ready" }),
        );
      const { function: fn, arguments: args } = body.program;
      if (fn === "metadata.dimension.list")
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
      if (fn === "metadata.member.list")
        return response({
          rows: [],
          metadataRevision: 2,
          nextAfterMemberId: null,
        });
      if (fn === "facts.cell.editability.read")
        return response({
          editable: true,
          reasonCode: "RAW_INPUT_EDITABLE",
          message: "Current raw input is editable.",
        });
      if (fn === "facts.cube.scan") {
        if (args.includeMissing && state.cellRead)
          return state.cellRead(init.signal);
        if (args.includeMissing)
          return response({
            rows: rows.filter((cell) =>
              Object.entries(args.members).every(
                ([k, v]) => cell.members[k as keyof typeof cell.members] === v,
              ),
            ),
            snapshotRevision: 2,
          });
        if (state.read) return state.read();
        return response({
          rows: state.rows,
          nextCursor: state.nextCursor,
          snapshotRevision: 2,
        });
      }
      throw new Error(`Unexpected fixture call ${fn}`);
    }),
  );
  const view = render(
    <Analyze app={app} catalog={catalog} index={0} subject="reader" />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Suggest layout" }),
    ).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Suggest layout" }));
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  await screen.findByRole("button", {
    name: "Account Cost, Period Jan. 100.00000000",
  });
  const cell = (row: number, column = 0) =>
    view.container.querySelector<HTMLButtonElement>(
      `[data-grid-row="${row}"][data-grid-column="${column}"]`,
    )!;
  return { state, view, cell };
}

it("keeps the focused drawer control when the authoritative cell arrives", async () => {
  const { state, cell } = await setup();
  let finishRead!: (value: Response) => void;
  state.cellRead = () => new Promise((resolve) => (finishRead = resolve));
  fireEvent.click(cell(0));
  const heading = screen.getByRole("heading", {
    name: "Details and exact writeback",
  });
  expect(heading).toHaveFocus();
  const coordinate = screen.getByText("Exact coordinate IDs");
  act(() => coordinate.focus());
  await act(async () => finishRead(response({ rows: [rows[0]] })));
  expect(
    screen.getByLabelText("Authoritative editability decision"),
  ).toBeVisible();
  expect(coordinate).toHaveFocus();
});

it("closes the drawer on Escape during a read and restores the exact cell", async () => {
  const { state, cell } = await setup();
  let requestSignal!: AbortSignal;
  let finishRead!: (value: Response) => void;
  state.cellRead = (signal) => {
    requestSignal = signal;
    return new Promise((resolve) => (finishRead = resolve));
  };
  const origin = cell(1, 1);
  act(() => origin.focus());
  fireEvent.click(origin);
  const heading = screen.getByRole("heading", {
    name: "Details and exact writeback",
  });
  expect(heading).toHaveFocus();
  fireEvent.keyDown(heading, { key: "Escape" });
  expect(requestSignal.aborted).toBe(true);
  expect(origin).toHaveFocus();
  await act(async () => finishRead(response({ rows: [rows[3]] })));
  expect(heading).not.toBeInTheDocument();
  expect(origin).toHaveFocus();
});

it.each([false, true])(
  "keeps one roving tab stop after arrow and direct focus in flat=%s",
  async (flat) => {
    const { cell, view } = await setup(flat);
    act(() => cell(0).focus());
    fireEvent.keyDown(cell(0), { key: "ArrowDown" });
    expect(cell(1)).toHaveFocus();
    expect(cell(1).tabIndex).toBe(0);
    expect(cell(0).tabIndex).toBe(-1);
    const announcement = view.container.querySelector(
      ".grid-keyboard-announcement",
    );
    expect(announcement).toHaveTextContent(cell(1).getAttribute("aria-label")!);
    act(() => cell(flat ? 3 : 0).focus());
    expect(cell(flat ? 3 : 0).tabIndex).toBe(0);
    expect(announcement).toBeEmptyDOMElement();
    expect(
      view.container.querySelectorAll(".cell-button[tabindex='0']"),
    ).toHaveLength(1);
  },
);

it("keeps a coordinate across reordering and chooses the closest visible cell on the final page", async () => {
  const { state, cell } = await setup(true);
  act(() => cell(2).focus());
  const oldLabel = cell(2).getAttribute("aria-label");
  state.rows = [...state.rows].reverse();
  const read = screen.getByRole("button", { name: "Read grid" });
  act(() => read.focus());
  fireEvent.click(read);
  await waitFor(() => expect(read).toBeEnabled());
  expect(read).toHaveFocus();
  expect(screen.getByRole("button", { name: oldLabel! })).toHaveAttribute(
    "tabindex",
    "0",
  );
  state.rows = [
    { ...rows[0], members: { Account: "Replacement", Period: "Jan" } },
  ];
  state.nextCursor = null;
  const next = screen.getByRole("button", { name: "Next page" });
  act(() => next.focus());
  fireEvent.click(next);
  const replacement = await screen.findByRole("button", {
    name: "Account Replacement, Period Jan. 100.00000000",
  });
  await waitFor(() => expect(replacement).toHaveFocus());
  expect(next).toBeDisabled();
});

it("keeps the exact numeric coordinate when a text layer changes matrix to flat presentation", async () => {
  const { state } = await setup();
  expect(screen.getByRole("grid", { name: "Pivot results" })).toBeVisible();
  const target = screen.getByRole("button", {
    name: "Account Hours, Period Jan. 110.00000000",
  });
  act(() => target.focus());
  state.rows = [...rows, { ...rows[0], kind: "text", text: "Note" }];
  const read = screen.getByRole("button", { name: "Read grid" });
  act(() => read.focus());
  fireEvent.click(read);
  await screen.findByRole("button", {
    name: "Account Cost, Period Jan. Text Note",
  });
  expect(
    screen.getByRole("grid", { name: "Coordinate results" }),
  ).toBeVisible();
  expect(
    screen.getByRole("button", {
      name: "Account Hours, Period Jan. 110.00000000",
    }),
  ).toHaveAttribute("tabindex", "0");
  expect(
    screen.getByRole("button", { name: "Account Cost, Period Jan. Text Note" }),
  ).toHaveAttribute("tabindex", "-1");
});

it.each(["move", "context", "empty", "denied"])(
  "fences or deliberately restores delayed read focus: %s",
  async (kind) => {
    const { state, view } = await setup();
    let finish!: (response: Response) => void;
    state.read = () =>
      new Promise<Response>((done) => {
        finish = done;
      });
    const read = screen.getByRole("button", { name: "Read grid" });
    act(() => read.focus());
    fireEvent.click(read);
    await waitFor(() => expect(finish).toBeDefined());
    if (kind === "move")
      act(() => screen.getByRole("button", { name: "Close layout" }).focus());
    if (kind === "context") {
      view.rerender(
        <Analyze
          app={app}
          catalog={{
            ...catalog,
            revisions: { ...catalog.revisions, security: 2 },
          }}
          index={0}
          subject="reader"
        />,
      );
      act(() => screen.getByRole("button", { name: "Close layout" }).focus());
    }
    await act(async () =>
      finish(
        kind === "denied"
          ? new Response(JSON.stringify({ code: "READ_DENIED" }), {
              status: 403,
            })
          : response({ rows: [], nextCursor: null, snapshotRevision: 2 }),
      ),
    );
    if (kind === "move" || kind === "context")
      expect(
        screen.getByRole("button", { name: "Close layout" }),
      ).toHaveFocus();
    else if (kind === "denied") expect(screen.getByRole("alert")).toHaveFocus();
    else
      expect(
        view.container.querySelector("[data-grid-focus-status]"),
      ).toHaveFocus();
  },
);

it("focuses a confirmed conflict beside recovery while preserving the exact edit", async () => {
  const { cell } = await setup();
  fireEvent.click(cell(0));
  const value = await screen.findByLabelText("Value");
  await waitFor(() => expect(value).toBeEnabled());
  fireEvent.change(value, { target: { value: "5.00000001" } });
  const preview = screen.getByRole("button", {
    name: "Preview exact mutation",
  });
  await waitFor(() => expect(preview).toBeEnabled());
  fireEvent.click(preview);
  const reviewed = screen.getByLabelText("I reviewed this exact cell mutation");
  await waitFor(() => expect(reviewed).toBeEnabled());
  fireEvent.click(reviewed);
  const submit = screen.getByRole("button", {
    name: "Submit durable writeback",
  });
  act(() => submit.focus());
  fireEvent.click(submit);
  const conflict = await screen.findByRole("alert");
  await waitFor(() => expect(conflict).toHaveFocus());
  expect(conflict).toHaveTextContent(
    "Reread the current values and preview the edit again.",
  );
  expect(conflict.nextElementSibling).toBe(
    screen.getByRole("button", {
      name: "Reread current cell and keep my edit",
    }),
  );
  expect(conflict.nextElementSibling).toBeEnabled();
  expect(value).toHaveValue("5.00000001");
});

it("focuses current-owner recovery after remount and its original status result", async () => {
  const { state, view, cell } = await setup();
  state.outcome = "unknown";
  fireEvent.click(cell(0));
  await waitFor(() =>
    expect(screen.getByLabelText("Value")).toHaveValue("101.00000000"),
  );
  fireEvent.change(screen.getByLabelText("Value"), {
    target: { value: "7.00000001" },
  });
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Preview exact mutation" }),
    ).toBeEnabled(),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Preview exact mutation" }),
  );
  const reviewed = screen.getByLabelText("I reviewed this exact cell mutation");
  await waitFor(() => expect(reviewed).toBeEnabled());
  fireEvent.click(reviewed);
  const submit = screen.getByRole("button", {
    name: "Submit durable writeback",
  });
  act(() => submit.focus());
  fireEvent.click(submit);
  await screen.findByRole("button", { name: "Check original mutation status" });
  view.rerender(
    <Analyze
      app={app}
      catalog={catalog}
      index={0}
      subject="reader"
      interactionBlocked
    />,
  );
  const retry = document.createElement("button");
  retry.textContent = "Retry connection";
  document.body.append(retry);
  act(() => retry.focus());
  expect(retry).toHaveFocus();
  act(() => retry.remove());
  view.rerender(
    <Analyze
      app={app}
      catalog={catalog}
      index={0}
      subject="reader"
      interactionBlocked={false}
    />,
  );
  await waitFor(() =>
    expect(
      view.container.querySelector("[data-grid-focus-outcome]"),
    ).toHaveFocus(),
  );
  view.unmount();
  const restored = render(
    <Analyze app={app} catalog={catalog} index={0} subject="reader" />,
  );
  const reconcile = await screen.findByRole("button", {
    name: "Check original mutation status",
  });
  const outcome = restored.container.querySelector("[data-grid-focus-outcome]");
  await waitFor(() => expect(outcome).toHaveFocus());
  state.outcome = "ready";
  act(() => reconcile.focus());
  fireEvent.click(reconcile);
  await screen.findByText(/Request status: ready/);
  expect(outcome).toHaveFocus();
  const elsewhere = document.createElement("button");
  elsewhere.textContent = "Other workspace control";
  document.body.append(elsewhere);
  act(() => elsewhere.focus());
  restored.rerender(
    <Analyze app={app} catalog={catalog} index={0} subject="different-actor" />,
  );
  expect(
    restored.container.querySelector("[data-grid-focus-outcome]"),
  ).toBeNull();
  expect(elsewhere).toHaveFocus();
  elsewhere.remove();
});
