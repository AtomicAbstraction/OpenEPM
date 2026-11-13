import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { useState } from "react";
import { MetadataWorkspace } from "./MetadataWorkspace";
import type { MetadataDestination } from "./metadata-navigation";
import type { ApplicationCatalog } from "./types";
import { installOperationAdmissionFixture } from "./test-setup";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const app = {
  workspaceId: "workspace",
  applicationId: "model",
  name: "Model",
  status: "Active",
};
const dimensions = [
  {
    dimension_id: "Account",
    name: "Accounts",
    model_role: "Account",
    status: "Active",
    short_description: "Measures in the model",
  },
  {
    dimension_id: "Entity",
    name: "Entities",
    model_role: "Entity",
    status: "Active",
  },
];
const members = [
  { member_id: "Revenue", name: "Revenue", status: "Active" },
  { member_id: "Costs", name: "Costs", status: "Active" },
];

const readFunctions = ["metadata.dimension.list", "metadata.member.list"];
function catalog(
  functions = [
    ...readFunctions,
    "metadata.dimension.create",
    "metadata.member.create",
    "metadata.dimension.rename",
    "metadata.member.rename",
  ],
): ApplicationCatalog {
  return {
    applicationAccess: { role: "Administrator", workspaceAdministrator: false },
    enabledCapabilities: [],
    functions: Object.fromEntries(functions.map((name) => [name, {}])),
    revisions: { metadata: 7, data: 1, policy: 1, security: 3, commit: 7 },
  };
}

type Call = {
  path: string;
  body: { program: { function: string; arguments: Record<string, any> } };
  signal?: AbortSignal | null;
};
const response = (result: unknown) =>
  new Response(JSON.stringify({ result }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });

function installApi(
  handler?: (call: Call) => Response | Promise<Response> | undefined,
) {
  const calls: Call[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const call = {
        path: String(input),
        body: JSON.parse(String(init?.body)),
        signal: init?.signal,
      };
      calls.push(call);
      const custom = handler?.(call);
      if (custom !== undefined) return custom;
      switch (call.body.program.function) {
        case "metadata.dimension.list":
          return response({
            rows: dimensions,
            nextAfterDimensionId: null,
            metadataRevision: 7,
          });
        case "metadata.member.list":
          return response({
            rows: members,
            nextAfterMemberId: null,
            metadataRevision: 7,
          });
        default:
          throw new Error(`Unexpected function: ${call.body.program.function}`);
      }
    }),
  );
  installOperationAdmissionFixture("2");
  return calls;
}

function props(destination: MetadataDestination = { section: "dimensions" }) {
  return {
    app,
    catalog: catalog(),
    ...destination,
    onNavigate: vi.fn(),
    hrefForDestination: (destination: MetadataDestination) =>
      `#/metadata/0?${new URLSearchParams({ metadataSection: destination.section, ...(destination.dimensionId ? { dimension: destination.dimensionId } : {}) })}`,

    onDimensionsChange: vi.fn(),
    onRequestTransition: vi.fn((action: () => void) => action()),
  };
}

it("links metadata ancestors without retaining the selected member or dimension", async () => {
  installApi();
  const options = props({
    section: "members",
    dimensionId: "Account",
    memberId: "Revenue",
  });
  render(<MetadataWorkspace {...options} />);
  const trail = within(
    screen.getByRole("navigation", { name: "Metadata breadcrumb" }),
  );
  const dimension = await trail.findByRole("link", { name: "Accounts" });
  expect(trail.getByText("Members")).toHaveAttribute("aria-current", "page");
  fireEvent.click(dimension);
  expect(options.onNavigate).toHaveBeenLastCalledWith({
    section: "members",
    dimensionId: "Account",
  });
  fireEvent.click(trail.getByRole("link", { name: "Metadata" }));
  expect(options.onNavigate).toHaveBeenLastCalledWith({
    section: "dimensions",
  });
});

it("opens the requested member access after accepted selection and keeps it closed after cancellation", async () => {
  installApi(({ body }) =>
    body.program.function === "metadata.relationship.list"
      ? response({ rows: [], nextCursor: null, metadataRevision: 7 })
      : undefined,
  );
  const options = props({
    section: "members",
    dimensionId: "Account",
    memberId: "Revenue",
  });
  options.catalog = catalog([
    ...readFunctions,
    "metadata.relationship.list",
    "security.application.member-tags.read",
  ]);
  function GuardedWorkspace() {
    const [destination, setDestination] = useState<MetadataDestination>({
      section: "members",
      dimensionId: "Account",
      memberId: "Revenue",
    });
    const [pending, setPending] = useState<(() => void) | null>(null);
    return (
      <>
        <MetadataWorkspace
          {...options}
          {...destination}
          onNavigate={setDestination}
          onRequestTransition={(action) => setPending(() => action)}
        />
        {pending && (
          <div role="alertdialog">
            <button onClick={() => setPending(null)}>Keep editing</button>
            <button
              onClick={() => {
                pending();
                setPending(null);
              }}
            >
              Continue
            </button>
          </div>
        )}
      </>
    );
  }
  render(<GuardedWorkspace />);
  const grid = await screen.findByRole("table", {
    name: "Member attribute grid",
  });
  const costs = within(grid).getByRole("row", { name: /Costs/ });
  fireEvent.click(
    within(costs).getByRole("button", { name: "Edit Security String" }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Keep editing" }));
  expect(screen.getByRole("button", { name: "Member access" })).toHaveAttribute(
    "aria-expanded",
    "false",
  );
  expect(
    within(
      screen.getByRole("complementary", { name: "Member properties" }),
    ).getByRole("heading", { name: "Revenue" }),
  ).toBeInTheDocument();
  fireEvent.click(
    within(costs).getByRole("button", { name: "Edit Security String" }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Continue" }));
  expect(
    await screen.findByRole("button", { name: "Hide member access" }),
  ).toHaveAttribute("aria-expanded", "true");
  expect(
    within(
      screen.getByRole("complementary", { name: "Member properties" }),
    ).getByRole("heading", { name: "Costs" }),
  ).toBeInTheDocument();
});

it("opens a dimension directory without unrelated forms or member requests", async () => {
  const calls = installApi();
  const options = props();
  render(<MetadataWorkspace {...options} />);
  expect(
    await screen.findByRole("region", { name: "Dimensions grid" }),
  ).toBeInTheDocument();
  expect(
    await screen.findByRole("button", { name: "Properties for Accounts" }),
  ).toBeInTheDocument();
  expect(
    screen.getByRole("heading", { name: "Dimensions", level: 1 }),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("table", { name: "Member attribute grid" }),
  ).toBeNull();
  expect(screen.queryByLabelText("Dimension display name")).toBeNull();
  expect(screen.queryByLabelText("Member display name")).toBeNull();
  expect(
    screen.queryByRole("complementary", { name: "New dimension editor" }),
  ).toBeNull();
  expect(calls.map((call) => call.body.program.function)).toEqual([
    "metadata.dimension.list",
  ]);
  expect(options.onDimensionsChange).toHaveBeenCalledWith(dimensions);
});

it("separates member and dimension-property pages and pins the first member read", async () => {
  const calls = installApi();
  const options = props({
    section: "members",
    dimensionId: "Account",
    memberId: "Revenue",
  });
  const { rerender } = render(<MetadataWorkspace {...options} />);
  await waitFor(() =>
    expect(screen.getByLabelText("Member display name")).toHaveValue("Revenue"),
  );
  expect(
    screen.getByRole("table", { name: "Member attribute grid" }),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("table", {
      name: "Relationship placement attribute grid",
    }),
  ).toBeNull();
  expect(screen.queryByLabelText("Dimension display name")).toBeNull();
  const memberRead = calls.find(
    (call) => call.body.program.function === "metadata.member.list",
  );
  expect(memberRead?.body.program.arguments).toEqual({
    dimension: "Account",
    limit: 100,
    expectedMetadataRevision: 7,
  });

  fireEvent.click(
    screen.getByRole("button", { name: "Close member properties" }),
  );
  expect(options.onNavigate).toHaveBeenCalledWith({
    section: "members",
    dimensionId: "Account",
    memberId: undefined,
  });
  rerender(
    <MetadataWorkspace {...options} section="settings" memberId={undefined} />,
  );
  await waitFor(() =>
    expect(screen.getByLabelText("Dimension display name")).toHaveValue(
      "Accounts",
    ),
  );
  expect(screen.queryByLabelText("Member display name")).toBeNull();
  expect(
    screen.queryByRole("table", { name: "Member attribute grid" }),
  ).toBeNull();
  expect(
    screen.getByRole("heading", { name: "Properties & access", level: 1 }),
  ).toBeInTheDocument();
});

it("keeps the selected member after a governed mutation and explicit refresh", async () => {
  let revision = 7;
  let currentMembers = members;
  const calls = installApi((call) => {
    if (call.body.program.function === "metadata.dimension.list")
      return response({
        rows: dimensions,
        nextAfterDimensionId: null,
        metadataRevision: revision,
      });
    if (call.body.program.function === "metadata.member.list")
      return response({
        rows: currentMembers,
        nextAfterMemberId: null,
        metadataRevision: revision,
      });
    if (call.body.program.function === "metadata.member.rename") {
      currentMembers = members.map((member) =>
        member.member_id === call.body.program.arguments.memberId
          ? { ...member, name: call.body.program.arguments.name }
          : member,
      );
      revision = 8;
      return response({
        receiptId: "rename-receipt",
        metadataRevision: revision,
      });
    }
  });
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  const options = props({
    section: "members",
    dimensionId: "Account",
    memberId: "Revenue",
  });
  render(<MetadataWorkspace {...options} />);
  fireEvent.change(await screen.findByLabelText("Member display name"), {
    target: { value: "Revenue updated" },
  });
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact member name against the current model.",
    ),
  );
  fireEvent.click(screen.getByRole("button", { name: "Rename member" }));
  const inspector = await screen.findByRole("complementary", {
    name: "Member properties",
  });
  await waitFor(() =>
    expect(
      within(inspector).getByRole("heading", { name: "Revenue updated" }),
    ).toBeInTheDocument(),
  );
  expect(screen.getByLabelText("Metadata dimension")).toHaveValue("Account");
  expect(
    screen.getByRole("button", {
      name: "Select member Revenue updated (Revenue)",
    }),
  ).toHaveAttribute("aria-pressed", "true");
  expect(options.onNavigate).not.toHaveBeenCalled();
  expect(
    calls.find(
      (call) => call.body.program.function === "metadata.member.rename",
    )?.body.program.arguments,
  ).toMatchObject({
    dimensionId: "Account",
    memberId: "Revenue",
    expectedMetadataRevision: 7,
  });
  fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
  await waitFor(() =>
    expect(screen.getByLabelText("Member display name")).toHaveValue(
      "Revenue updated",
    ),
  );
  expect(
    screen.getByRole("button", {
      name: "Select member Revenue updated (Revenue)",
    }),
  ).toHaveAttribute("aria-pressed", "true");
});

it("retains a failed-refresh grid for orientation but makes its editor workarea inert", async () => {
  let fail = false;
  installApi((call) => {
    if (fail && call.body.program.function === "metadata.dimension.list")
      throw new Error("Unavailable snapshot");
  });
  const options = props({
    section: "members",
    dimensionId: "Account",
    memberId: "Revenue",
  });
  render(<MetadataWorkspace {...options} />);
  await waitFor(() =>
    expect(screen.getByLabelText("Member display name")).toHaveValue("Revenue"),
  );
  fail = true;
  fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Unavailable snapshot",
  );
  expect(screen.getByRole("button", { name: "+ New member" })).toBeDisabled();
  const editor = screen.getByLabelText("Member display name");
  expect(editor.closest(".metadata-workarea")).toHaveAttribute("inert");
  expect(editor).toHaveValue("Revenue");
});

it("rejects members read against a different metadata revision", async () => {
  installApi((call) =>
    call.body.program.function === "metadata.member.list"
      ? response({
          rows: members,
          nextAfterMemberId: null,
          metadataRevision: 8,
        })
      : undefined,
  );
  render(
    <MetadataWorkspace
      {...props({
        section: "members",
        dimensionId: "Account",
        memberId: "Revenue",
      })}
    />,
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Metadata changed while reading members",
  );
  expect(screen.getByRole("button", { name: "+ New member" })).toBeDisabled();
  expect(screen.queryByLabelText("Member display name")).toBeNull();
  expect(
    screen.queryByRole("table", { name: "Member attribute grid" }),
  ).toBeNull();
});

it("ignores late member responses after changing the selected dimension", async () => {
  let releaseOld: (response: Response) => void = () => undefined;
  const calls = installApi((call) => {
    if (call.body.program.function !== "metadata.member.list") return;
    if (call.body.program.arguments.dimension === "Account")
      return new Promise<Response>((resolve) => {
        releaseOld = resolve;
      });
    return response({
      rows: [{ member_id: "Europe", name: "Europe entity", status: "Active" }],
      nextAfterMemberId: null,
      metadataRevision: 7,
    });
  });
  const options = props({ section: "members", dimensionId: "Account" });
  const { rerender } = render(<MetadataWorkspace {...options} />);
  await waitFor(() =>
    expect(
      calls.some((call) => call.body.program.arguments.dimension === "Account"),
    ).toBe(true),
  );
  rerender(<MetadataWorkspace {...options} dimensionId="Entity" />);
  expect(
    await screen.findByRole("button", {
      name: "Select member Europe entity (Europe)",
    }),
  ).toBeInTheDocument();
  await act(async () => {
    releaseOld(
      response({ rows: members, nextAfterMemberId: null, metadataRevision: 7 }),
    );
  });
  expect(screen.getByLabelText("Metadata dimension")).toHaveValue("Entity");
  expect(
    screen.queryByRole("button", { name: "Select member Revenue (Revenue)" }),
  ).toBeNull();
  expect(
    calls.find((call) => call.body.program.arguments.dimension === "Account")
      ?.signal?.aborted,
  ).toBe(true);
  expect(options.onDimensionsChange).toHaveBeenCalledTimes(1);
});

it("does not replace an unavailable explicit dimension with the first accessible one", async () => {
  const calls = installApi();
  render(
    <MetadataWorkspace
      {...props({ section: "members", dimensionId: "Removed" })}
    />,
  );
  expect(
    await screen.findByRole("heading", {
      name: "This dimension is unavailable",
    }),
  ).toBeInTheDocument();
  expect(screen.getByLabelText("Metadata dimension")).toHaveValue("Removed");
  expect(screen.getByRole("button", { name: "+ New member" })).toBeDisabled();
  expect(
    calls.some((call) => call.body.program.function === "metadata.member.list"),
  ).toBe(false);
});

it("delegates navigation and create/close transitions to the supplied guards", async () => {
  installApi();
  const options = props();
  const transitions = vi.fn<(action: () => void) => void>();
  render(<MetadataWorkspace {...options} onRequestTransition={transitions} />);
  const properties = await screen.findByRole("button", {
    name: "Properties for Accounts",
  });
  fireEvent.click(properties);
  expect(options.onNavigate).toHaveBeenCalledWith({
    section: "settings",
    dimensionId: "Account",
    memberId: undefined,
  });
  fireEvent.click(screen.getByRole("button", { name: "+ New dimension" }));
  expect(transitions).toHaveBeenCalledOnce();
  expect(
    screen.queryByRole("complementary", { name: "New dimension editor" }),
  ).toBeNull();
  act(() => transitions.mock.calls[0][0]());
  expect(
    screen.getByRole("complementary", { name: "New dimension editor" }),
  ).toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("button", { name: "Close creation editor" }),
  );
  expect(transitions).toHaveBeenCalledTimes(2);
  expect(
    screen.getByRole("complementary", { name: "New dimension editor" }),
  ).toBeInTheDocument();
  act(() => transitions.mock.calls[1][0]());
  expect(
    screen.queryByRole("complementary", { name: "New dimension editor" }),
  ).toBeNull();
});

it("windows role-limited member grids while collecting all server pages under the same revision", async () => {
  const manyMembers = Array.from({ length: 120 }, (_, index) => ({
    member_id: `M${String(index).padStart(3, "0")}`,
    name: `Member ${index}`,
    status: "Active",
  }));
  const calls = installApi((call) => {
    if (call.body.program.function !== "metadata.member.list") return;
    const next = Boolean(call.body.program.arguments.afterMemberId);
    return response({
      rows: next ? manyMembers.slice(100) : manyMembers.slice(0, 100),
      nextAfterMemberId: next ? null : "M099",
      metadataRevision: 7,
    });
  });
  render(
    <MetadataWorkspace
      {...props({ section: "members", dimensionId: "Account" })}
      catalog={catalog(readFunctions)}
    />,
  );
  const grid = await screen.findByRole("table", {
    name: "Member attribute grid",
  });
  expect(within(grid).getAllByRole("row")).toHaveLength(51);
  expect(screen.queryByText("Member 50", { exact: true })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Next rows" }));
  expect(screen.getByText("Rows 51–100")).toBeInTheDocument();
  expect(screen.getByText("Member 50", { exact: true })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Next rows" }));
  expect(screen.getByText("Rows 101–120")).toBeInTheDocument();
  expect(screen.getByText("Member 119", { exact: true })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Next rows" })).toBeDisabled();
  expect(
    screen.queryByRole("table", {
      name: "Relationship placement attribute grid",
    }),
  ).toBeNull();
  expect(screen.queryByRole("button", { name: "+ New member" })).toBeNull();
  expect(
    calls
      .filter((call) => call.body.program.function === "metadata.member.list")
      .map((call) => call.body.program.arguments),
  ).toEqual([
    { dimension: "Account", limit: 100, expectedMetadataRevision: 7 },
    {
      dimension: "Account",
      limit: 100,
      afterMemberId: "M099",
      expectedMetadataRevision: 7,
    },
  ]);
});
