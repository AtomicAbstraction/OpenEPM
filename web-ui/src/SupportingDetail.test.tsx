import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  SupportingDetail,
  supportingDetailProgram,
  validDetailItems,
} from "./SupportingDetail";
import { unsavedWorkSnapshot } from "./unsaved-work";
import { installOperationAdmissionFixture } from "./test-setup";

afterEach(() => vi.unstubAllGlobals());

const app = {
  workspaceId: "ws",
  applicationId: "app",
  name: "Plan",
  status: "Active",
};
const catalog = {
  applicationAccess: { role: "Editor", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: {
    "facts.export.page": {},
    "facts.cube.scan": {},
    "facts.line-detail.replace": {},
  },
  revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
};

it("preserves exact line-detail replacement semantics", () => {
  expect(
    supportingDetailProgram(
      { Account: "Sales" },
      [{ description: "Units", decimal: "12.50" }],
      "change-1",
    ),
  ).toEqual({
    languageVersion: 2,
    function: "facts.line-detail.replace",
    arguments: {
      coordinate: { Account: "Sales" },
      items: [
        {
          description: "Units",
          amount: "12.50",
        },
      ],
      expectedCellChangeId: "change-1",
      expectedDetailChangeId: "change-1",
    },
  });
  expect(validDetailItems([{ description: "", decimal: "0" }])).toBe(false);
  expect(validDetailItems([{ description: "Zero", decimal: "0" }])).toBe(true);
  expect(validDetailItems([{ description: "x", decimal: "1e2" }])).toBe(false);
});

it("resolves a pinned authoritative detail before enabling reviewed replacement", async () => {
  const calls: Array<{ url: string; body: any }> = [];
  let acceptTransition: (() => void) | undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push({ url: String(input), body });
      if (String(input) === "/api/preview")
        return new Response(
          JSON.stringify({
            previewToken: "detail-preview-token",
            programDigest: "2".repeat(64),
            revisionVector: { data: 9 },
            detail: {
              coordinate: { Account: "Sales" },
              replacement: "complete_set",
              itemCount: 1,
              present: true,
              total: { type: "AmountLiteral", decimal: "12.50" },
            },
          }),
        );
      if (String(input) === "/api/submit")
        return new Response(
          JSON.stringify({ jobId: "a".repeat(32), status: "ready" }),
        );
      if (body.program.function === "facts.cube.scan")
        return new Response(
          JSON.stringify({
            result: {
              snapshotRevision: 9,
              rows: [
                {
                  members: { Account: "Sales" },
                  kind: "numeric",
                  numericChangeId: "change-1",
                  amount: "12.50",
                },
              ],
            },
          }),
        );
      return new Response(
        JSON.stringify({
          result: {
            snapshotRevision: 9,
            nextCursor: null,
            rows: [
              {
                members: { Account: "Sales" },
                sourceRef: "export:key",
                value: {
                  type: "LineDetailLiteral",
                  items: [{ description: "Units", decimal: "12.50" }],
                },
              },
            ],
          },
        }),
      );
    }),
  );
  installOperationAdmissionFixture("6");
  vi.spyOn(window, "confirm").mockReturnValue(true);
  render(
    <SupportingDetail
      app={app}
      catalog={catalog}
      onRequestTransition={(action) => {
        acceptTransition = action;
      }}
    />,
  );
  fireEvent.click(screen.getByRole("button", { name: "Read detail" }));
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Open" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Open" }));
  await waitFor(() =>
    expect(
      screen.getByLabelText("Supporting detail editor"),
    ).toBeInTheDocument(),
  );
  expect(calls[2].body.program.arguments).toEqual({
    members: { Account: "Sales" },
    limit: 2,
    snapshotRevision: 9,
  });
  fireEvent.click(screen.getByRole("button", { name: "Add line" }));
  expect(unsavedWorkSnapshot()).toContainEqual(
    expect.objectContaining({ label: "Unsaved supporting-detail replacement" }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Remove line 2" }));
  fireEvent.change(screen.getByLabelText("Description"), {
    target: { value: "Preserve these edits" },
  });
  const beforeSelection = calls.length;
  fireEvent.click(screen.getByRole("button", { name: "Open" }));
  expect(screen.getByLabelText("Description")).toHaveValue(
    "Preserve these edits",
  );
  expect(calls).toHaveLength(beforeSelection);
  expect(acceptTransition).toBeTypeOf("function");
  act(() => acceptTransition?.());
  await waitFor(() =>
    expect(screen.getByLabelText("Description")).toHaveValue("Units"),
  );
  const review = screen.getByLabelText(
    "I reviewed this exact replacement and its total.",
  );
  expect(review).toBeDisabled();
  fireEvent.click(
    screen.getByRole("button", { name: "Preview exact replacement" }),
  );
  expect(
    await screen.findByText(/Proposed exact total: 12.50/),
  ).toBeInTheDocument();
  await waitFor(() => expect(review).toBeEnabled());
  fireEvent.click(review);
  expect(review).toBeChecked();
  const replace = screen.getByRole("button", {
    name: "Replace supporting detail",
  });
  await waitFor(() => expect(replace).toBeEnabled());
  act(() => replace.focus());
  fireEvent.click(replace);
  await waitFor(
    () => expect(screen.getByText(/Request status: ready/)).toBeInTheDocument(),
    { timeout: 3000 },
  );
  expect(
    screen.getByRole("region", { name: "Supporting detail outcome" }),
  ).toHaveFocus();
  expect(calls.at(-1)?.body.program).toEqual(
    supportingDetailProgram(
      { Account: "Sales" },
      [{ description: "Units", decimal: "12.50" }],
      "change-1",
    ),
  );
});

it("retains the proposal while rereading a concurrently changed complete detail set", async () => {
  let training = "40";
  let identity = "first";
  const calls: any[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input, init) => {
      const body = JSON.parse(String(init?.body));
      calls.push({ path: String(input), ...body });
      if (String(input) === "/api/preview")
        return new Response(
          JSON.stringify({
            previewToken: "detail-current-preview",
            programDigest: "a".repeat(64),
            revisionVector: { data_revision: 2 },
            detail: {
              coordinate: { Account: "Sales" },
              replacement: "complete_set",
              itemCount: 2,
              present: true,
              total: {
                type: "AmountLiteral",
                decimal: training === "40" ? "110" : "115",
              },
            },
          }),
        );
      if (body.program.function === "facts.cube.scan")
        return new Response(
          JSON.stringify({
            result: {
              snapshotRevision: 2,
              rows: [
                {
                  members: { Account: "Sales" },
                  kind: "numeric",
                  amount: training === "40" ? "100" : "105",
                  numericChangeId: identity,
                },
              ],
            },
          }),
        );
      return new Response(
        JSON.stringify({
          result: {
            snapshotRevision: 2,
            nextCursor: null,
            rows: [
              {
                members: { Account: "Sales" },
                sourceRef: "detail",
                value: {
                  type: "LineDetailLiteral",
                  items: [
                    { description: "Travel", decimal: "60" },
                    { description: "Training", decimal: training },
                  ],
                },
              },
            ],
          },
        }),
      );
    }),
  );
  const { rerender } = render(<SupportingDetail app={app} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Read detail" }));
  fireEvent.click(await screen.findByRole("button", { name: "Open" }));
  await waitFor(() =>
    expect(screen.getAllByLabelText("Exact amount")[0]).toBeEnabled(),
  );
  fireEvent.change(screen.getAllByLabelText("Exact amount")[0], {
    target: { value: "70" },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Preview exact replacement" }),
  );
  const review = screen.getByLabelText(
    "I reviewed this exact replacement and its total.",
  );
  await waitFor(() => expect(review).toBeEnabled());
  fireEvent.click(review);
  training = "45";
  identity = "second";
  fireEvent.click(
    screen.getByRole("button", {
      name: "Reread current detail and keep my edits",
    }),
  );
  expect(await screen.findByText("Training: 45")).toBeInTheDocument();
  expect(screen.getAllByLabelText("Exact amount")[0]).toHaveValue("70");
  expect(screen.getAllByLabelText("Exact amount")[1]).toHaveValue("40");
  expect(review).not.toBeChecked();
  expect(review).toBeDisabled();
  fireEvent.change(screen.getAllByLabelText("Exact amount")[1], {
    target: { value: "45" },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Preview exact replacement" }),
  );
  expect(
    await screen.findByText(/Proposed exact total: 115/),
  ).toBeInTheDocument();
  expect(calls.at(-1).program).toEqual(
    supportingDetailProgram(
      { Account: "Sales" },
      [
        { description: "Travel", decimal: "70" },
        { description: "Training", decimal: "45" },
      ],
      "second",
    ),
  );
  rerender(
    <SupportingDetail
      app={app}
      catalog={{ ...catalog, revisions: { ...catalog.revisions, security: 2 } }}
    />,
  );
  expect(
    screen.queryByText(/Current stored total: 105/),
  ).not.toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Preview exact replacement" }),
  ).toHaveAttribute("aria-disabled", "true");
});
