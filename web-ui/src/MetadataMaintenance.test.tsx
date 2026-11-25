import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  MetadataMaintenance,
  metadataMaintenanceBody,
} from "./MetadataMaintenance";
import { operationAdmissionResponse } from "./test-setup";
import { resetUnsavedWorkForTests } from "./unsaved-work";

afterEach(() => {
  resetUnsavedWorkForTests();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const app = {
  workspaceId: "ws",
  applicationId: "app",
  name: "Plan",
  status: "Active",
};
const receiptFunction = "application.operation.receipt.read";

const catalog = {
  applicationAccess: {
    role: "Administrator",
    workspaceAdministrator: false,
    issuer: "https://issuer",
    subjectId: "admin",
  },
  enabledCapabilities: [],
  functions: {
    "metadata.dimension.rename": {},
    "metadata.dimension.describe": {},
    "metadata.dimension.status.set": {},
    "metadata.dimension.delete": {},
    "metadata.member.rename": {},
    "metadata.member.describe": {},
    "metadata.member.numeric-kind.set": {},
    "metadata.member.status.set": {},
    "application.operation.receipt.read": {},
  },
  revisions: { metadata: 46, data: 1, policy: 1, security: 1, commit: 1 },
};

const dimension = {
  dimension_id: "Account",
  name: "Account",
  model_role: "Account",
  status: "Active",
  short_description: "Chart",
  detailed_description: "Chart of accounts",
};

const members = [
  {
    member_id: "Sales",
    name: "Sales",
    status: "Active",
    short_description: "Revenue",
    detailed_description: "Sales revenue",
    numeric_value_kind: "amount" as const,
  },
];

it("preserves the governed maintenance envelope", () => {
  expect(
    metadataMaintenanceBody(
      app,
      "metadata.member.numeric-kind.set",
      {
        dimensionId: "Account",
        memberId: "Margin",
        numericValueKind: "ratio",
        expectedMetadataRevision: 46,
      },
      "metadata-maintenance-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "metadata-maintenance-1",
    program: {
      languageVersion: 2,
      function: "metadata.member.numeric-kind.set",
      arguments: {
        dimensionId: "Account",
        memberId: "Margin",
        numericValueKind: "ratio",
        expectedMetadataRevision: 46,
      },
    },
  });
});

it("keeps maintenance unavailable without an authoritative snapshot", () => {
  render(
    <MetadataMaintenance
      app={app}
      catalog={catalog}
      members={[]}
      metadataRevision={null}
      onChanged={async () => undefined}
    />,
  );
  expect(
    screen.getByText(/Read the current dimension catalogue/),
  ).toBeInTheDocument();
});

it("invalidates exact review when a proposed rename changes", () => {
  render(
    <MetadataMaintenance
      app={app}
      catalog={catalog}
      dimension={dimension}
      members={members}
      metadataRevision={46}
      onChanged={async () => undefined}
    />,
  );
  const name = screen.getByLabelText("Dimension display name");
  fireEvent.change(name, { target: { value: "Accounts" } });
  const review = screen.getByLabelText(
    "I reviewed this exact dimension name against the current model.",
  );
  fireEvent.click(review);
  expect(review).toBeChecked();
  expect(
    screen.getByRole("button", { name: "Rename dimension" }),
  ).toBeEnabled();
  fireEvent.change(name, { target: { value: "Financial accounts" } });
  expect(review).not.toBeChecked();
  expect(
    screen.getByRole("button", { name: "Rename dimension" }),
  ).toBeDisabled();
});

it("requires the exact inactive dimension identity before delete review", () => {
  render(
    <MetadataMaintenance
      app={app}
      catalog={catalog}
      dimension={{ ...dimension, status: "Inactive" }}
      members={[]}
      metadataRevision={46}
      onChanged={async () => undefined}
    />,
  );
  const identity = screen.getByLabelText(
    "Type Account to delete this inactive dimension",
  );
  const review = screen.getByLabelText(
    "I reviewed this exact inactive dimension deletion against the current model.",
  );
  fireEvent.change(identity, { target: { value: "Accounts" } });
  expect(review).toBeDisabled();
  fireEvent.change(identity, { target: { value: "Account" } });
  expect(review).toBeEnabled();
});

it("uses the Metadata Manager selection as the member property editor selection", () => {
  const onSelectedMemberIdChange = vi.fn();
  render(
    <MetadataMaintenance
      app={app}
      catalog={catalog}
      dimension={dimension}
      members={[
        ...members,
        {
          member_id: "Margin",
          name: "Margin",
          status: "Active",
          short_description: "Profitability",
          detailed_description: "Calculated margin",
          numeric_value_kind: "ratio" as const,
        },
      ]}
      selectedMemberId="Margin"
      onSelectedMemberIdChange={onSelectedMemberIdChange}
      metadataRevision={46}
      onChanged={async () => undefined}
    />,
  );

  expect(screen.getByLabelText("Member")).toHaveValue("Margin");
  expect(screen.getByLabelText("Member display name")).toHaveValue("Margin");
  fireEvent.change(screen.getByLabelText("Member"), {
    target: { value: "Sales" },
  });
  expect(onSelectedMemberIdChange).toHaveBeenCalledWith("Sales");
});

it("offers separate dimension and member property workspaces", () => {
  const props = {
    app,
    catalog,
    dimension,
    members,
    metadataRevision: 46,
    onChanged: async () => undefined,
  };
  const view = render(<MetadataMaintenance {...props} mode="dimension" />);
  expect(
    screen.getByRole("heading", { name: "Dimension properties" }),
  ).toBeInTheDocument();
  expect(screen.queryByLabelText("Member display name")).toBeNull();
  view.rerender(<MetadataMaintenance {...props} mode="member" />);
  expect(
    screen.getByRole("heading", { name: "Member properties" }),
  ).toBeInTheDocument();
  expect(screen.getByLabelText("Member display name")).toBeVisible();
  expect(screen.queryByLabelText("Dimension display name")).toBeNull();
});

it("retains a stale draft and requires explicit current-revision review", () => {
  const props = {
    app,
    catalog,
    dimension,
    members,
    onChanged: async () => undefined,
    mode: "dimension" as const,
  };
  const view = render(<MetadataMaintenance {...props} metadataRevision={46} />);
  fireEvent.change(screen.getByLabelText("Dimension display name"), {
    target: { value: "Operating accounts" },
  });
  const review = screen.getByLabelText(
    "I reviewed this exact dimension name against the current model.",
  );
  fireEvent.click(review);
  view.rerender(<MetadataMaintenance {...props} metadataRevision={47} />);
  expect(screen.getByLabelText("Dimension display name")).toHaveValue(
    "Operating accounts",
  );
  expect(review).not.toBeChecked();
  expect(review).toBeDisabled();
  expect(
    screen.getByRole("button", { name: "Rename dimension" }),
  ).toBeDisabled();
  fireEvent.click(
    screen.getByRole("button", { name: "Review against current metadata" }),
  );
  expect(review).toBeEnabled();
  expect(review).not.toBeChecked();
  fireEvent.click(review);
  expect(
    screen.getByRole("button", { name: "Rename dimension" }),
  ).toBeEnabled();
});

it("restores typed values without restoring prior review authorization", async () => {
  const props = {
    app,
    catalog,
    dimension,
    members,
    metadataRevision: 46,
    onChanged: async () => undefined,
    mode: "dimension" as const,
  };
  const first = render(<MetadataMaintenance {...props} />);
  fireEvent.change(screen.getByLabelText("Dimension display name"), {
    target: { value: "Retained name" },
  });
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact dimension name against the current model.",
    ),
  );
  first.unmount();
  render(<MetadataMaintenance {...props} metadataRevision={47} />);
  await waitFor(() =>
    expect(screen.getByLabelText("Dimension display name")).toHaveValue(
      "Retained name",
    ),
  );
  expect(
    screen.getByLabelText(
      "I reviewed this exact dimension name against the current model.",
    ),
  ).not.toBeChecked();
  expect(
    screen.getByRole("button", { name: "Rename dimension" }),
  ).toBeDisabled();
  expect(
    screen.getByRole("button", { name: "Review against current metadata" }),
  ).toBeInTheDocument();
});

it("requires reconciliation if the response to a reviewed dimension rename is interrupted", async () => {
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  const fetcher = vi.fn(async (input: RequestInfo | URL) => {
    if (String(input) === "/api/operation-admission")
      return operationAdmissionResponse("46");
    throw new Error("Interrupted response");
  });
  vi.stubGlobal("fetch", fetcher);
  const view = render(
    <div>
      <MetadataMaintenance
        app={app}
        catalog={catalog}
        dimension={dimension}
        members={[]}
        metadataRevision={46}
        onChanged={vi.fn(async () => undefined)}
        mode="dimension"
      />
    </div>,
  );
  fireEvent.change(screen.getByLabelText("Dimension display name"), {
    target: { value: "Operating accounts" },
  });
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact dimension name against the current model.",
    ),
  );
  const rename = screen.getByRole("button", { name: "Rename dimension" });
  fireEvent.click(rename);
  const workarea = view.container.firstElementChild!;
  workarea.setAttribute("inert", "");
  const pending = await screen.findByText(
    "Metadata change awaiting confirmation",
  );
  expect(pending).not.toHaveFocus();
  workarea.removeAttribute("inert");
  await waitFor(() => expect(pending).toHaveFocus());
  expect(
    await screen.findByRole("button", {
      name: "Check original metadata receipt",
    }),
  ).toBeEnabled();
  expect(rename).toBeDisabled();
  expect(fetcher.mock.calls.map(([path]) => path)).toEqual([
    "/api/operation-admission",
    "/api/metadata-action",
  ]);
});

it("reports a fixed-core lifecycle refusal as uncommitted", async () => {
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  const fetcher = vi.fn(async (input: RequestInfo | URL) => {
    if (String(input) === "/api/operation-admission")
      return operationAdmissionResponse("46");
    return new Response(
      JSON.stringify({
        code: "DIMENSION_HAS_ACTIVE_MEMBERS",
        message: "The dimension still has active members.",
      }),
      { status: 409 },
    );
  });
  vi.stubGlobal("fetch", fetcher);
  const refresh = vi.fn(async () => undefined);
  render(
    <MetadataMaintenance
      app={app}
      catalog={catalog}
      dimension={dimension}
      members={members}
      metadataRevision={46}
      onChanged={refresh}
      mode="dimension"
    />,
  );
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed changing this dimension to Inactive in the current model.",
    ),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Set dimension inactive" }),
  );
  await waitFor(() =>
    expect(screen.getByRole("alert")).toHaveTextContent(
      "The dimension still has active members.",
    ),
  );
  expect(
    screen.queryByRole("button", { name: "Check original metadata receipt" }),
  ).toBeNull();
  expect(refresh).not.toHaveBeenCalled();
  expect(fetcher.mock.calls.map(([path]) => path)).toEqual([
    "/api/operation-admission",
    "/api/metadata-action",
  ]);
});

it("clears only the exact recorded fields and requires a current snapshot for the retained draft", async () => {
  const calls: Array<{
    path: string;
    body: {
      idempotencyKey: string;
      program: { function: string; arguments: object };
    };
  }> = [];
  let finishRefresh!: () => void;
  const refresh = vi.fn(
    () =>
      new Promise<void>((resolve) => {
        finishRefresh = resolve;
      }),
  );
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      const body = JSON.parse(String(init?.body));
      calls.push({ path, body });
      if (path === "/api/operation-admission")
        return operationAdmissionResponse("46");
      if (path === "/api/metadata-action") throw new Error("Interrupted reply");
      return new Response(
        JSON.stringify({
          result: {
            operationId: calls.find(
              (entry) => entry.path === "/api/metadata-action",
            )!.body.idempotencyKey,
            actorId: "admin",
            committedAt: "2026-11-20T15:00:00Z",
            committedRevision: 47,
            commandDigest: "a".repeat(64),
            outcome: { changedCount: 1 },
          },
        }),
      );
    }),
  );

  const props = {
    app,
    catalog,
    dimension,
    members: [],
    metadataRevision: 46,
    onChanged: refresh,
    mode: "dimension" as const,
  };
  const name = "Dimension display name";
  const detail = "Dimension short description";
  const reviewName =
    "I reviewed this exact dimension name against the current model.";
  const view = render(<MetadataMaintenance {...props} />);
  fireEvent.change(screen.getByLabelText(detail), {
    target: { value: "My notes" },
  });
  fireEvent.change(screen.getByLabelText(name), {
    target: { value: "Submitted name" },
  });
  fireEvent.click(screen.getByLabelText(reviewName));
  fireEvent.click(screen.getByRole("button", { name: "Rename dimension" }));
  const receiptButton = await screen.findByRole("button", {
    name: "Check original metadata receipt",
  });
  await waitFor(() => expect(receiptButton).toBeEnabled());
  fireEvent.click(receiptButton);
  const recorded = await screen.findByText(
    "The original metadata change was recorded.",
  );
  await waitFor(() => expect(refresh).toHaveBeenCalledTimes(1));
  expect(recorded).not.toHaveFocus();
  await act(async () => finishRefresh());
  await waitFor(() => expect(recorded).toHaveFocus());
  expect(screen.getByLabelText(name)).toHaveValue("Account");
  expect(screen.getByLabelText(detail)).toHaveValue("My notes");
  expect(screen.getByLabelText(reviewName)).toBeDisabled();
  expect(
    screen.getByRole("button", { name: "Refresh current model" }),
  ).toBeEnabled();
  expect(calls[2].body.program).toEqual({
    languageVersion: 2,
    function: receiptFunction,
    arguments: { operationId: calls[1].body.idempotencyKey },
  });

  view.unmount();
  render(
    <MetadataMaintenance
      {...props}
      dimension={{ ...dimension, name: "Submitted name" }}
      metadataRevision={47}
    />,
  );
  await waitFor(() =>
    expect(screen.getByLabelText(detail)).toHaveValue("My notes"),
  );
  expect(screen.getByLabelText(name)).toHaveValue("Submitted name");
  expect(
    screen.queryByRole("button", { name: "Check original metadata receipt" }),
  ).toBeNull();
  const descriptionsReview = screen.getByLabelText(
    "I reviewed these exact dimension descriptions against the current model.",
  );
  expect(descriptionsReview).toBeDisabled();
  fireEvent.click(
    screen.getByRole("button", { name: "Review against current metadata" }),
  );
  expect(descriptionsReview).toBeEnabled();
  expect(descriptionsReview).not.toBeChecked();
});

it("recovers the original member change with read-only access after a reconnect", async () => {
  const effects: string[] = [];
  const refresh = vi.fn(async () => undefined);
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      const body = JSON.parse(String(init?.body));
      if (path === "/api/operation-admission")
        return operationAdmissionResponse("46");
      if (path === "/api/metadata-action") {
        effects.push(body.idempotencyKey);
        throw new Error("Interrupted reply");
      }
      expect(body.program.arguments).toEqual({ operationId: effects[0] });
      return new Response(
        JSON.stringify({
          result: {
            operationId: effects[0],
            actorId: "admin",
            committedAt: "2026-11-20T15:00:00Z",
            committedRevision: 47,
            commandDigest: "b".repeat(64),
            outcome: { changedCount: 1 },
          },
        }),
      );
    }),
  );
  const props = {
    app,
    catalog,
    dimension,
    members,
    metadataRevision: 46,
    selectedMemberId: "Sales",
    onChanged: refresh,
    mode: "member" as const,
  };
  const first = render(<MetadataMaintenance {...props} />);
  fireEvent.change(screen.getByLabelText("Numeric value kind"), {
    target: { value: "ratio" },
  });
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact member numeric kind against the current model.",
    ),
  );
  fireEvent.click(screen.getByRole("button", { name: "Set numeric kind" }));
  await screen.findByText("The original metadata change is still unconfirmed.");
  first.unmount();

  const reader = {
    ...catalog,
    applicationAccess: { ...catalog.applicationAccess, role: "Reader" },
    functions: { [receiptFunction]: {} },
  };
  const other = render(
    <MetadataMaintenance
      {...props}
      catalog={reader}
      dimension={{ ...dimension, dimension_id: "Other" }}
    />,
  );
  expect(
    screen.queryByRole("button", { name: "Check original metadata receipt" }),
  ).toBeNull();
  other.unmount();

  render(
    <MetadataMaintenance {...props} catalog={reader} metadataRevision={47} />,
  );
  const check = await screen.findByRole("button", {
    name: "Check original metadata receipt",
  });
  await waitFor(() => expect(check).toBeEnabled());
  expect(screen.queryByRole("button", { name: "Set numeric kind" })).toBeNull();
  fireEvent.click(check);
  await screen.findByText("The original metadata change was recorded.");
  expect(effects).toHaveLength(1);
});
