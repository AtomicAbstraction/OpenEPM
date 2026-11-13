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
          amount: { type: "AmountLiteral", decimal: "12.50" },
        },
      ],
      expectedCellChangeId: "change-1",
      expectedDetailChangeId: "change-1",
    },
  });
  expect(validDetailItems([{ description: "", decimal: "0" }])).toBe(true);
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
          }),
        );
      if (String(input) === "/api/submit")
        return new Response(JSON.stringify({ jobId: "job-detail-1" }));
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
  await waitFor(() => expect(review).toBeEnabled());
  fireEvent.click(review);
  expect(review).toBeChecked();
  const replace = screen.getByRole("button", {
    name: "Replace supporting detail",
  });
  await waitFor(() => expect(replace).toBeEnabled());
  fireEvent.click(replace);
  await waitFor(
    () =>
      expect(
        screen.getByText("Replacement request accepted."),
      ).toBeInTheDocument(),
    { timeout: 3000 },
  );
  expect(calls.at(-1)?.body.program).toEqual(
    supportingDetailProgram(
      { Account: "Sales" },
      [{ description: "Units", decimal: "12.50" }],
      "change-1",
    ),
  );
});
