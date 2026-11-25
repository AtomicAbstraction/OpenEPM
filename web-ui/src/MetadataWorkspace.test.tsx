import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { useLayoutEffect, useState } from "react";
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
    applicationAccess: {
      role: "Administrator",
      workspaceAdministrator: false,
      issuer: "https://issuer",
      subjectId: "administrator",
    },
    enabledCapabilities: [],
    functions: Object.fromEntries(functions.map((name) => [name, {}])),
    revisions: { metadata: 7, data: 1, policy: 1, security: 3, commit: 7 },
  };
}

type Call = {
  path: string;
  body: {
    program: { function: string; arguments: Record<string, any> };
    idempotencyKey?: string;
  };
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

it("shows catalogue loading and neutral missing-function availability without inventing denial", async () => {
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  const view = render(<MetadataWorkspace {...props()} catalog={null} />);
  expect(
    screen.getByText("Checking metadata availability…"),
  ).toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  view.rerender(<MetadataWorkspace {...props()} catalog={catalog([])} />);
  expect(
    screen.getByRole("heading", {
      name: "Metadata is not available in this application context",
    }),
  ).toBeInTheDocument();
  expect(
    screen.queryByText(/permissions do not|to your role/),
  ).not.toBeInTheDocument();
  expect(fetch).not.toHaveBeenCalled();
});

it.each([
  [
    "Dimension",
    "settings",
    "security.application.dimension-metadata-tags.read",
  ],
  ["Member", "members", "security.application.member-tags.read"],
] as const)(
  "opens an exact %s classification link without listing metadata",
  async (kind, section, fn) => {
    const args =
      kind === "Member"
        ? { dimensionId: "Entity", memberId: "North" }
        : { dimensionId: "Entity" };
    let unavailable = false;
    const calls = installApi((call) => {
      expect(call.path).toBe("/api/security");
      expect(call.body.program).toEqual({
        languageVersion: 2,
        function: fn,
        arguments: args,
      });
      if (unavailable)
        return new Response(
          JSON.stringify({
            code:
              kind === "Member"
                ? "MEMBER_UNAVAILABLE"
                : "SECURITY_READ_AUTHORIZATION_STALE",
          }),
          { status: kind === "Member" ? 400 : 403 },
        );
      return response({
        ...args,
        metadataRevision: 7,
        securityRevision: 2,
        securityString: "read=Review;write=",
      });
    });
    const grant = catalog([
      fn,
      `metadata.${kind.toLowerCase()}.security-string.set`,
    ]);
    const view = render(<MetadataWorkspace {...props()} catalog={grant} />);
    expect(
      screen.getByText(
        "Open a link to the dimension or member you want to classify.",
      ),
    ).toBeInTheDocument();
    view.rerender(
      <MetadataWorkspace {...props({ section, ...args })} catalog={grant} />,
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Edit Security String" }),
    );
    expect(await screen.findByLabelText(`${kind} Security String`)).toHaveValue(
      "read=Review;write=",
    );
    expect(calls).toHaveLength(1);
    fireEvent.change(screen.getByLabelText(`${kind} Security String`), {
      target: { value: "read=Unsaved;write=" },
    });
    unavailable = true;
    fireEvent.click(
      screen.getByRole("button", { name: "Refresh current security" }),
    );
    await screen.findByRole("alert");
    expect(screen.queryByLabelText(`${kind} Security String`)).toBeNull();
    expect(screen.queryByDisplayValue("read=Unsaved;write=")).toBeNull();
    expect(calls).toHaveLength(2);
    view.rerender(
      <MetadataWorkspace
        {...props({ section, ...args })}
        catalog={catalog([])}
      />,
    );
    expect(screen.queryByDisplayValue("read=Review;write=")).toBeNull();
    expect(
      screen.queryByRole("button", { name: "Edit Security String" }),
    ).toBeNull();
  },
);

it("rejects an old metadata projection after a same-app security change", async () => {
  let finish!: (value: Response) => void;
  let oldSignal: AbortSignal | null | undefined;
  let reads = 0;
  installApi((call) => {
    if (
      call.body.program.function === "metadata.dimension.list" &&
      ++reads === 1
    ) {
      oldSignal = call.signal;
      return new Promise<Response>((done) => {
        finish = done;
      });
    }
    if (call.body.program.function === "metadata.dimension.list")
      return response({
        rows: [{ ...dimensions[1], name: "Current dimension" }],
        nextAfterDimensionId: null,
        metadataRevision: 7,
      });
  });
  const initial = catalog();
  const view = render(<MetadataWorkspace {...props()} catalog={initial} />);
  await waitFor(() => expect(finish).toBeDefined());
  view.rerender(
    <MetadataWorkspace
      {...props()}
      catalog={{ ...initial, revisions: { ...initial.revisions, security: 4 } }}
    />,
  );
  expect(
    await screen.findByRole("button", {
      name: "Properties for Current dimension",
    }),
  ).toBeInTheDocument();
  expect(oldSignal?.aborted).toBe(true);
  await act(async () =>
    finish(
      response({
        rows: [{ ...dimensions[0], name: "Old private dimension" }],
        nextAfterDimensionId: null,
        metadataRevision: 7,
      }),
    ),
  );
  expect(screen.queryByText("Old private dimension")).not.toBeInTheDocument();
  expect(reads).toBe(2);
});

it.each(["Account", "Removed"])(
  "does not call dimension %s unavailable before its scoped read completes",
  async (dimensionId) => {
    let finish: (value: Response) => void = () => undefined;
    installApi((call) =>
      call.body.program.function === "metadata.dimension.list"
        ? new Promise<Response>((resolve) => {
            finish = resolve;
          })
        : undefined,
    );
    render(
      <MetadataWorkspace {...props({ section: "members", dimensionId })} />,
    );
    expect(
      screen.getByRole("option", { name: "Loading dimensions…" }),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Metadata dimension")).toBeDisabled();
    expect(
      screen.queryByRole("option", { name: "Dimension unavailable" }),
    ).toBeNull();
    expect(
      screen.queryByRole("heading", { name: "This dimension is unavailable" }),
    ).toBeNull();
    await act(async () =>
      finish(
        response({
          rows: dimensions,
          nextAfterDimensionId: null,
          metadataRevision: 7,
        }),
      ),
    );
    if (dimensionId === "Account") {
      await waitFor(() =>
        expect(screen.getByLabelText("Metadata dimension")).toBeEnabled(),
      );
      expect(
        screen.getByRole("option", { name: "Accounts" }),
      ).toBeInTheDocument();
      expect(
        screen.queryByRole("option", { name: "Dimension unavailable" }),
      ).toBeNull();
    } else {
      expect(
        await screen.findByRole("heading", {
          name: "This dimension is unavailable",
        }),
      ).toBeInTheDocument();
      expect(
        screen.getByRole("option", { name: "Dimension unavailable" }),
      ).toBeInTheDocument();
      expect(screen.getByLabelText("Metadata dimension")).toHaveValue(
        "Removed",
      );
    }
  },
);

it("distinguishes a failed dimension read from a confirmed unavailable dimension", async () => {
  installApi((call) => {
    if (call.body.program.function === "metadata.dimension.list")
      throw new Error("Read interrupted");
  });
  render(
    <MetadataWorkspace
      {...props({ section: "members", dimensionId: "Account" })}
    />,
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Read interrupted",
  );
  expect(
    screen.getByRole("option", { name: "Unable to load dimensions" }),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("option", { name: "Dimension unavailable" }),
  ).toBeNull();
  expect(screen.getByLabelText("Metadata dimension")).toBeDisabled();
});

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

it("opens governed member-attribute authoring beside the member grid", async () => {
  installApi((call) =>
    call.body.program.function === "metadata.attribute-definition.list"
      ? response({
          rows: [],
          nextAfterAttributeId: null,
          metadataRevision: 7,
        })
      : undefined,
  );
  render(
    <MetadataWorkspace
      {...props({ section: "members", dimensionId: "Account" })}
      catalog={catalog([
        ...readFunctions,
        "metadata.attribute-definition.list",
        "metadata.attribute-definition.create",
      ])}
    />,
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "+ Add attribute" }),
  );
  const tray = await screen.findByRole("complementary", {
    name: "Add member attribute",
  });
  expect(tray).toHaveTextContent("Add attribute to Accounts");
  expect(within(tray).getByLabelText("Attribute scope")).toHaveValue("Member");
  expect(
    screen.getByRole("table", { name: "Member attribute grid" }),
  ).toBeInTheDocument();
  fireEvent.click(
    within(tray).getByRole("button", { name: "Close attribute tray" }),
  );
  expect(
    screen.queryByRole("complementary", { name: "Add member attribute" }),
  ).toBeNull();
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
  expect(options.onDimensionsChange).toHaveBeenCalledWith(dimensions, 7);
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

it("reopens an identity-scoped member draft without forcing it through the discard guard", async () => {
  installApi();
  const options = props({ section: "members", dimensionId: "Account" });
  render(<MetadataWorkspace {...options} />);

  fireEvent.click(
    await screen.findByRole("button", {
      name: "Select member Revenue (Revenue)",
    }),
  );

  expect(options.onNavigate).toHaveBeenCalledWith({
    section: "members",
    dimensionId: "Account",
    memberId: "Revenue",
  });
  expect(options.onRequestTransition).not.toHaveBeenCalled();
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
      return new Response(
        JSON.stringify({
          languageVersion: 2,
          function: "metadata.member.rename",
          result: {
            operationId: call.body.idempotencyKey,
            committedRevision: revision,
            changedCount: 1,
          },
        }),
      );
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
  await waitFor(
    () =>
      expect(
        within(inspector).getByRole("heading", { name: "Revenue updated" }),
      ).toBeInTheDocument(),
    {
      // This assertion spans admission, the governed effect, two revision-pinned
      // refresh reads, and React rendering. Keep the default one-second budget
      // elsewhere; an image build can legitimately need longer for this path.
      timeout: 4_000,
    },
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
  expect(
    screen.getByRole("button", { name: "+ New member row" }),
  ).toBeDisabled();
  const editor = screen.getByLabelText("Member display name");
  expect(editor.closest(".metadata-workarea")).toHaveAttribute("inert");
  expect(editor).toHaveValue("Revenue");
});

it("requires a settled dimension read before reporting the selected dimension unavailable", async () => {
  const reads: ((result: Response) => void)[] = [];
  installApi((call) =>
    call.body.program.function === "metadata.dimension.list"
      ? new Promise<Response>((resolve) => reads.push(resolve))
      : undefined,
  );
  render(
    <MetadataWorkspace
      {...props({ section: "members", dimensionId: "Account" })}
    />,
  );

  const pending = async (readCount: number) => {
    await waitFor(() => expect(reads).toHaveLength(readCount));
    expect(
      screen.getByText("Loading the current metadata snapshot…"),
    ).toBeVisible();
    expect(
      screen.getByRole("option", { name: "Loading dimensions…" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: /^This dimension is/ }),
    ).toBeNull();
  };
  const fail = async (index: number) => {
    await act(async () =>
      reads[index](
        Response.json({ code: "METADATA_READ_INTERRUPTED" }, { status: 500 }),
      ),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The model could not be refreshed.",
    );
    expect(
      screen.getByRole("option", { name: "Unable to load dimensions" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("heading", { name: /^This dimension is/ }),
    ).toBeNull();
  };
  const refresh = () =>
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
  const page = (rows: typeof dimensions) =>
    response({ rows, nextAfterDimensionId: null, metadataRevision: 7 });

  await pending(1);
  await fail(0);
  expect(screen.queryByText(/Your last view is retained/)).toBeNull();
  refresh();
  await pending(2);
  await act(async () => reads[1](page([dimensions[1]])));
  expect(
    await screen.findByRole("heading", {
      name: "This dimension is unavailable",
    }),
  ).toBeVisible();
  refresh();
  await pending(3);
  await fail(2);
  refresh();
  await pending(4);
  await act(async () => reads[3](page(dimensions)));
  expect(
    await screen.findByRole("button", {
      name: "Select member Revenue (Revenue)",
    }),
  ).toBeVisible();
  expect(screen.queryByRole("alert")).toBeNull();
});

it.each([
  [409, "METADATA_DIRECTORY_READ_AUTHORIZATION_STALE"],
  [403, "APPLICATION_GRANT_REQUIRED"],
] as const)("clears previous metadata after %s %s", async (status, code) => {
  let refuse = false;
  installApi((call) =>
    refuse && call.body.program.function === "metadata.member.list"
      ? Response.json({ code }, { status })
      : undefined,
  );
  const options = props({
    section: "members",
    dimensionId: "Account",
    memberId: "Revenue",
  });
  render(<MetadataWorkspace {...options} />);
  await waitFor(() =>
    expect(screen.getByLabelText("Member display name")).toHaveValue("Revenue"),
  );
  refuse = true;
  fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(code);
  expect(screen.queryByLabelText("Member display name")).toBeNull();
  expect(
    screen.queryByRole("table", { name: "Member attribute grid" }),
  ).toBeNull();
  expect(options.onDimensionsChange).toHaveBeenLastCalledWith([], null);

  refuse = false;
  fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
  await waitFor(() =>
    expect(screen.getByLabelText("Member display name")).toHaveValue("Revenue"),
  );
  expect(options.onDimensionsChange).toHaveBeenLastCalledWith(dimensions, 7);
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
  expect(screen.queryByRole("button", { name: "+ New member row" })).toBeNull();
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

it("commits the new dimension as loading before any passive refresh effect", async () => {
  let finishEntity: ((result: Response) => void) | undefined;
  installApi((call) => {
    if (
      call.body.program.function === "metadata.member.list" &&
      call.body.program.arguments.dimension === "Entity"
    )
      return new Promise<Response>((resolve) => {
        finishEntity = resolve;
      });
  });
  const options = props({ section: "members", dimensionId: "Account" });
  const routeCommits: { dimension: string; previousMember: boolean }[] = [];
  function Route({ dimensionId }: { dimensionId: string }) {
    useLayoutEffect(() => {
      routeCommits.push({
        dimension: (
          screen.getByLabelText("Metadata dimension") as HTMLSelectElement
        ).value,
        previousMember: Boolean(
          screen.queryByRole("button", {
            name: "Select member Revenue (Revenue)",
          }),
        ),
      });
    }, [dimensionId]);
    return <MetadataWorkspace {...options} dimensionId={dimensionId} />;
  }
  const view = render(<Route dimensionId="Account" />);
  expect(
    await screen.findByRole("button", {
      name: "Select member Revenue (Revenue)",
    }),
  ).toBeInTheDocument();
  view.rerender(<Route dimensionId="Entity" />);
  expect(routeCommits.at(-1)).toEqual({
    dimension: "Entity",
    previousMember: false,
  });
  expect(
    screen.getByText("Loading the current metadata snapshot…"),
  ).toBeVisible();
  await waitFor(() => expect(finishEntity).toBeTypeOf("function"));
  await act(async () => {
    finishEntity!(
      response({
        rows: [
          { member_id: "Europe", name: "Europe entity", status: "Active" },
        ],
        nextAfterMemberId: null,
        metadataRevision: 7,
      }),
    );
  });
  expect(
    await screen.findByRole("button", {
      name: "Select member Europe entity (Europe)",
    }),
  ).toBeVisible();
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
  expect(screen.queryByRole("button", { name: "+ New member row" })).toBeNull();
  expect(
    calls.some((call) => call.body.program.function === "metadata.member.list"),
  ).toBe(false);
});

it("delegates navigation and opening an inline creation row to the supplied guards", async () => {
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
  fireEvent.click(screen.getByRole("button", { name: "+ New dimension row" }));
  expect(transitions).toHaveBeenCalledOnce();
  expect(screen.queryByLabelText("New dimension stable ID")).toBeNull();
  act(() => transitions.mock.calls[0][0]());
  expect(screen.getByLabelText("New dimension stable ID")).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Cancel row" }));
  expect(screen.queryByLabelText("New dimension stable ID")).toBeNull();
  expect(transitions).toHaveBeenCalledTimes(1);
});

it("routes a populated dimension draft to a read-only mapping and leaves Currency on the existing path", async () => {
  const source = {
    format: "openepm-populated-layout-source-v1",
    pins: {
      metadataRevision: 7,
      dataRevision: 1,
      policyRevision: 1,
      schemaEpoch: 1,
      sourceCommitRevision: 7,
    },
    complete: true,
    sourceAxes: [{ dimensionId: "Account", valueKind: "member" }],
    coordinateCount: 1,
    sourceCoordinates: [
      { sourceCoordinateId: 1, sourceMembers: { Account: "Revenue" } },
    ],
  };
  const sourceRead = "metadata.layout.populated.source.read";
  const previewRead = "metadata.layout.populated.preview";
  const calls = installApi((call) => {
    if (call.body.program.function === sourceRead) return response(source);
    if (call.body.program.function === previewRead)
      return new Response(JSON.stringify({ code: "STALE_LAYOUT_PINS" }), {
        status: 409,
      });
  });
  const currentCatalog = catalog([
    ...readFunctions,
    "metadata.dimension.create",
    sourceRead,
    previewRead,
  ]);
  currentCatalog.revisions.schemaEpoch = 1;
  render(<MetadataWorkspace {...props()} catalog={currentCatalog} />);
  fireEvent.click(
    await screen.findByRole("button", { name: "+ New dimension row" }),
  );
  await screen.findByRole("region", { name: "Populated layout review" });
  expect(screen.queryByRole("button", { name: "Create dimension" })).toBeNull();
  for (const [label, value] of [
    ["New dimension stable ID", "Channel"],
    ["New dimension name", "Channel"],
    ["Existing data member ID", "legacy"],
    ["Existing data member name", "Legacy channel"],
  ])
    fireEvent.change(screen.getByLabelText(label), { target: { value } });
  fireEvent.click(
    screen.getByRole("button", { name: "Preview mapping 1 coordinate" }),
  );
  await screen.findByText(
    "The model changed. Refresh the current layout and review the mapping again.",
  );
  expect(
    calls.find((call) => call.body.program.function === previewRead),
  ).toMatchObject({
    path: "/api/read",
    body: {
      program: {
        arguments: {
          expectedPins: source.pins,
          axisMapping: { Account: "Account" },
          coordinateMappings: [
            {
              sourceCoordinateId: 1,
              sourceMembers: { Account: "Revenue" },
              targetMembers: { Account: "Revenue", Channel: "legacy" },
            },
          ],
        },
      },
    },
  });
  expect(
    screen.queryByRole("button", { name: "Download reviewed mapping" }),
  ).toBeNull();
  expect(calls.every((call) => call.path === "/api/read")).toBe(true);
  fireEvent.change(screen.getByLabelText("New dimension model role"), {
    target: { value: "Currency" },
  });
  expect(
    screen.queryByRole("region", { name: "Populated layout review" }),
  ).toBeNull();
  expect(
    screen.getByRole("button", { name: "Create dimension" }),
  ).toBeDisabled();
});

it.each([null, "2000000000." + "b".repeat(64)])(
  "windows role-limited member grids while keeping paging context %s",
  async (pageToken) => {
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
        ...(pageToken ? { nextPageToken: next ? null : pageToken } : {}),
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
    await screen.findByText("Current model loaded", { exact: true });
    expect(within(grid).getAllByRole("row")).toHaveLength(51);
    expect(screen.queryByText("Member 50", { exact: true })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Next rows" }));
    expect(await screen.findByText("Rows 51–100")).toBeInTheDocument();
    expect(screen.getByText("Member 50", { exact: true })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Next rows" }));
    expect(await screen.findByText("Rows 101–120")).toBeInTheDocument();
    expect(screen.getByText("Member 119", { exact: true })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next rows" })).toBeDisabled();
    expect(
      screen.queryByRole("table", {
        name: "Relationship placement attribute grid",
      }),
    ).toBeNull();
    expect(
      screen.queryByRole("button", { name: "+ New member row" }),
    ).toBeNull();
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
        ...(pageToken ? { expectedPageToken: pageToken } : {}),
      },
    ]);
  },
);

function DimensionNavigationFixture({
  currentApp = app,
  currentCatalog = catalog(),
  transition = (action: () => void) => action(),
}: {
  currentApp?: typeof app;
  currentCatalog?: ApplicationCatalog;
  transition?: (action: () => void) => void;
}) {
  const [destination, setDestination] = useState<MetadataDestination>({
    section: "members",
    dimensionId: "Account",
  });
  return (
    <>
      <button
        onClick={() =>
          setDestination({ section: "members", dimensionId: "Account" })
        }
      >
        Fixture members destination
      </button>
      <button onClick={() => setDestination({ section: "dimensions" })}>
        Fixture dimensions destination
      </button>
      <MetadataWorkspace
        {...props(destination)}
        app={currentApp}
        catalog={currentCatalog}
        onNavigate={setDestination}
        onRequestTransition={transition}
      />
    </>
  );
}

it("carries the approved Add dimension intent into the Dimensions route once", async () => {
  const calls = installApi();
  render(<DimensionNavigationFixture />);
  fireEvent.click(
    await screen.findByRole("button", { name: "+ Add dimension" }),
  );
  await screen.findByLabelText("New dimension stable ID");
  expect(screen.queryByRole("button", { name: "+ Add dimension" })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Cancel row" }));
  expect(screen.queryByLabelText("New dimension stable ID")).toBeNull();
  fireEvent.click(
    screen.getByRole("button", { name: "Fixture members destination" }),
  );
  await screen.findByRole("button", { name: "+ Add dimension" });
  fireEvent.click(
    screen.getByRole("button", { name: "Fixture dimensions destination" }),
  );
  await screen.findByRole("button", { name: "+ New dimension row" });
  expect(screen.queryByLabelText("New dimension stable ID")).toBeNull();
  expect(
    calls.every((call) => readFunctions.includes(call.body.program.function)),
  ).toBe(true);
});

it("does not install an Add dimension intent until the supplied navigation guard approves", async () => {
  installApi();
  const transitions = vi.fn<(action: () => void) => void>();
  render(<DimensionNavigationFixture transition={transitions} />);
  fireEvent.click(
    await screen.findByRole("button", { name: "+ Add dimension" }),
  );
  expect(transitions).toHaveBeenCalledOnce();
  expect(screen.queryByLabelText("New dimension stable ID")).toBeNull();
  expect(
    screen.getByRole("button", { name: "+ Add dimension" }),
  ).toBeInTheDocument();
  act(() => transitions.mock.calls[0][0]());
  await screen.findByLabelText("New dimension stable ID");
});

it.each(["application", "catalogue"])(
  "drops the inline creation row on a current %s change",
  async (kind) => {
    installApi();
    const currentCatalog = catalog();
    const view = render(
      <DimensionNavigationFixture currentCatalog={currentCatalog} />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "+ Add dimension" }),
    );
    await screen.findByLabelText("New dimension stable ID");
    view.rerender(
      <DimensionNavigationFixture
        currentApp={
          kind === "application" ? { ...app, applicationId: "other" } : app
        }
        currentCatalog={
          kind === "catalogue"
            ? {
                ...currentCatalog,
                revisions: { ...currentCatalog.revisions, policy: 2 },
              }
            : currentCatalog
        }
      />,
    );
    await waitFor(() =>
      expect(screen.queryByLabelText("New dimension stable ID")).toBeNull(),
    );
    await screen.findByRole("button", { name: "+ New dimension row" });
  },
);

it("does not carry a pending Add dimension request across an application change", async () => {
  installApi();
  const navigate = vi.fn();
  const currentCatalog = catalog();
  const options = props({ section: "members", dimensionId: "Account" });
  const view = render(
    <MetadataWorkspace
      {...options}
      catalog={currentCatalog}
      onNavigate={navigate}
    />,
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "+ Add dimension" }),
  );
  expect(navigate).toHaveBeenCalledWith({ section: "dimensions" });
  view.rerender(
    <MetadataWorkspace
      {...options}
      section="dimensions"
      dimensionId={undefined}
      app={{ ...app, applicationId: "other" }}
      catalog={currentCatalog}
      onNavigate={navigate}
    />,
  );
  await screen.findByRole("button", { name: "+ New dimension row" });
  expect(screen.queryByLabelText("New dimension stable ID")).toBeNull();
});

it("retains the exact shared placement through real Relationships and Tree route changes", async () => {
  const placementMembers = [
    { member_id: "BalanceSheet", name: "Balance Sheet", status: "Active" },
    { member_id: "CashFlow", name: "Cash Flow", status: "Active" },
    { member_id: "Cash", name: "Cash", status: "Active" },
  ];
  const placements = [
    {
      relationship_id: "balance-cash",
      dimension_id: "Account",
      name: "Balance cash",
      parent_member_id: "BalanceSheet",
      child_member_id: "Cash",
      status: "Active",
    },
    {
      relationship_id: "cashflow-cash",
      dimension_id: "Account",
      name: "Cashflow cash",
      parent_member_id: "CashFlow",
      child_member_id: "Cash",
      status: "Active",
    },
  ];
  const calls = installApi((call) => {
    if (call.body.program.function === "metadata.member.list")
      return response({
        rows: placementMembers,
        nextAfterMemberId: null,
        metadataRevision: 7,
      });
    if (call.body.program.function === "metadata.relationship.list")
      return response({
        rows: placements,
        nextCursor: null,
        metadataRevision: 7,
      });
  });
  const currentCatalog = catalog([
    ...readFunctions,
    "metadata.relationship.list",
    "metadata.relationship.rename",
    "metadata.relationship.status.set",
  ]);
  function RoutedWorkspace() {
    const [destination, setDestination] = useState<MetadataDestination>({
      section: "relationships",
      dimensionId: "Account",
      memberId: "Cash",
    });
    return (
      <MetadataWorkspace
        {...props(destination)}
        catalog={currentCatalog}
        onNavigate={setDestination}
      />
    );
  }
  render(<RoutedWorkspace />);
  const second = await screen.findByRole("button", {
    name: "Select placement Cashflow cash",
  });
  fireEvent.click(second);
  const properties = () =>
    screen.getByLabelText("Selected metadata properties");
  await waitFor(() =>
    expect(properties()).toHaveTextContent("Cash under Cash Flow"),
  );
  await waitFor(() =>
    expect(screen.getByLabelText("Relationship display name")).toHaveValue(
      "Cashflow cash",
    ),
  );
  const views = screen.getByRole("navigation", {
    name: "Accounts metadata views",
  });
  fireEvent.click(within(views).getByRole("button", { name: "Tree" }));
  await screen.findByRole("button", {
    name: "Select Cash in hierarchy under Cash Flow",
  });
  await waitFor(() =>
    expect(properties()).toHaveTextContent("Cash under Cash Flow"),
  );
  expect(screen.getByLabelText("Relationship")).toHaveValue("cashflow-cash");
  expect(
    screen.getByRole("button", {
      name: "Select Cash in hierarchy under Cash Flow",
    }),
  ).toHaveClass("selected");
  expect(
    screen.getByRole("button", {
      name: "Select Cash in hierarchy under Balance Sheet",
    }),
  ).not.toHaveClass("selected");
  fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
  await waitFor(() =>
    expect(screen.getByText("Current model loaded")).toBeInTheDocument(),
  );
  expect(properties()).toHaveTextContent("Cash under Cash Flow");
  fireEvent.click(within(views).getByRole("button", { name: "Relationships" }));
  await screen.findByRole("button", {
    name: "Select placement Cashflow cash",
  });
  await waitFor(() =>
    expect(properties()).toHaveTextContent("Cash under Cash Flow"),
  );
  await waitFor(() =>
    expect(screen.getByLabelText("Relationship display name")).toHaveValue(
      "Cashflow cash",
    ),
  );
  expect(calls.every((call) => call.path === "/api/read")).toBe(true);
});
