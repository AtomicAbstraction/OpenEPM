import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { MetadataRelationships } from "./MetadataRelationships";
import { MetadataHierarchyEditor } from "./MetadataHierarchyEditor";
import {
  collectMetadataHierarchies,
  collectHierarchyMembers,
  type MetadataHierarchy,
} from "./metadata-hierarchies";
import type { ApplicationCatalog } from "./types";
import { installOperationAdmissionFixture } from "./test-setup";
import { discardUnsavedWork, unsavedWorkSnapshot } from "./unsaved-work";

const app = {
  workspaceId: "ws",
  applicationId: "app",
  name: "Application",
  status: "Active",
};
const catalog: ApplicationCatalog = {
  applicationAccess: {
    role: "Administrator",
    workspaceAdministrator: false,
    issuer: "https://issuer",
    subjectId: "owner",
  },
  enabledCapabilities: [],
  functions: Object.fromEntries(
    [
      "metadata.relationship.list",
      "metadata.relationship.create",
      "metadata.relationship.status.set",
      "metadata.relationship.aggregation-operator.set",
      "metadata.hierarchy.build",
      "metadata.hierarchy.relationships.preview",
      "metadata.hierarchy.relationships.apply",
      "application.operation.receipt.read",
      ...[
        "list",
        "members.list",
        "create",
        "rename",
        "members.set",
        "default.set",
        "status.set",
      ].map((name) => `metadata.hierarchy.${name}`),
    ].map((name) => [name, {}]),
  ),
  revisions: { metadata: 46, data: 0, commit: 1, policy: 0, security: 1 },
};
const hierarchy = (
  id: string,
  name: string,
  isDefault = false,
): MetadataHierarchy => ({
  hierarchyId: id,
  name,
  isDefault,
  membershipMode: "explicit",
  status: "Active",
  stateToken: (isDefault ? "3" : "8").repeat(64),
  builtMetadataRevision: 46,
  current: true,
});
const trees = [
  hierarchy("H_DEFAULT", "Default", true),
  hierarchy("H_ALT", "Alternate"),
];
const members = ["Root", "A", "B", "C", "Isolated", "Outside"].map((id) => ({
  member_id: id,
  name: id,
  status: "Active",
}));
const response = (result: unknown) =>
  new Response(JSON.stringify({ result }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
const page = <T,>(rows: T[]) => ({
  dimensionId: "Account",
  rows,
  metadataRevision: 46,
  hasMore: false,
  nextAfterId: null,
});
function mockReads(hierarchies = trees) {
  const calls: Array<Record<string, any>> = [];
  const fetcher = vi.fn(async (_url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    calls.push(body);
    const p = body.program;
    if (p.function === "metadata.hierarchy.list")
      return response(page(hierarchies));
    if (p.function === "metadata.hierarchy.members.list")
      return response(
        page(
          (p.arguments.hierarchyId === "H_ALT"
            ? ["Root", "B", "C"]
            : ["Root", "A", "Isolated"]
          ).map((memberId) => ({ memberId, status: "Active" })),
        ),
      );
    if (p.function === "metadata.relationship.list") {
      const id = p.arguments.hierarchyId;
      const child = id === "H_ALT" ? "B" : "A";
      return response({
        hierarchyId: id,
        metadataRevision: 46,
        nextCursor: null,
        rows: [
          {
            relationship_id: `${id}-edge`,
            hierarchy_id: id,
            dimension_id: "Account",
            name: `${id} placement`,
            parent_member_id: "Root",
            child_member_id: child,
            status: "Active",
            aggregation_operator_override:
              id === "H_ALT" ? "NeverAggregate" : "Add",
          },
        ],
      });
    }
    if (p.function === "metadata.hierarchy.relationships.preview")
      return response({
        previewToken: "signed-hierarchy-preview",
        hierarchyId: p.arguments.hierarchyId,
        memberCount: 3,
        graphDigest: "a".repeat(64),
        closureDigest: "b".repeat(64),
        edgeCount: 2,
        closureCount: 5,
        affectedPathCount: 1,
        affectedRelationshipIds: ["hidden"],
      });
    if (p.function === "metadata.hierarchy.relationships.apply")
      return placementApplied(p.arguments.hierarchyId);
    if (p.function === "metadata.hierarchy.build")
      return hierarchyBuilt(p.arguments.hierarchyId, body.idempotencyKey);
    if (
      _url === "/api/metadata-action" &&
      p.function.startsWith("metadata.hierarchy.")
    )
      return namedHierarchyApplied(p.function, body.idempotencyKey);
    return response({ metadataRevision: 47, operationId: "saved" });
  });
  vi.stubGlobal("fetch", fetcher);
  installOperationAdmissionFixture("5");
  return { calls, fetcher };
}
function namedHierarchyApplied(functionName: string, operationId: string) {
  return new Response(
    JSON.stringify({
      languageVersion: 2,
      function: functionName,
      result: { operationId, committedRevision: 49, changedCount: 1 },
    }),
    { status: 200 },
  );
}
function hierarchyBuilt(hierarchyId: string, operationId: string) {
  return Response.json({
    languageVersion: 2,
    function: "metadata.hierarchy.build",
    result: {
      operationId,
      hierarchyId,
      stateToken: "c".repeat(64),
      closureCount: 4,
      membershipSemantics: "unique_member",
      committedRevision: 49,
    },
  });
}
function placementApplied(hierarchyId: string) {
  return new Response(
    JSON.stringify({
      languageVersion: 2,
      function: "metadata.hierarchy.relationships.apply",
      result: {
        kind: "hierarchy.build",
        operation: "relationship.patch",
        hierarchyId,
        metadataRevision: 47,
        committedRevision: 49,
        stateToken: "c".repeat(64),
        graphDigest: "a".repeat(64),
        closureDigest: "b".repeat(64),
        memberCount: 3,
        edgeCount: 2,
        closureCount: 5,
        affectedPathCount: 1,
        affectedRelationshipIds: ["hidden"],
      },
    }),
    { status: 200 },
  );
}

afterEach(() => {
  discardUnsavedWork();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

it("switches independent named trees with isolated roots and placement-specific operators", async () => {
  const { calls } = mockReads();
  const guard = vi.fn((change: () => void) => change());
  render(
    <MetadataRelationships
      app={app}
      catalog={catalog}
      dimensionId="Account"
      members={members}
      metadataRevision={46}
      mode="relationships"
      onChanged={async () => {}}
      onRequestTransition={guard}
    />,
  );
  await screen.findByText(/1 current relationships/);
  fireEvent.click(screen.getByRole("button", { name: "Tree View" }));
  let tree = screen.getByRole("tree");
  expect(
    within(tree).getByRole("button", { name: "Select Isolated in hierarchy" }),
  ).toBeVisible();
  expect(
    within(tree).queryByRole("button", { name: "Select Outside in hierarchy" }),
  ).toBeNull();
  fireEvent.change(screen.getByRole("combobox", { name: "Hierarchy" }), {
    target: { value: "H_ALT" },
  });
  await waitFor(() =>
    expect(
      within(screen.getByRole("tree")).getByRole("button", {
        name: "Select B in hierarchy under Root",
      }),
    ).toBeVisible(),
  );
  tree = screen.getByRole("tree");
  expect(
    within(tree).queryByRole("button", { name: "Select A in hierarchy" }),
  ).toBeNull();
  expect(
    within(tree).queryByRole("button", {
      name: "Select Isolated in hierarchy",
    }),
  ).toBeNull();
  fireEvent.click(
    within(tree).getByRole("button", {
      name: "Select B in hierarchy under Root",
    }),
  );
  expect(
    screen.getByLabelText("Selected metadata properties"),
  ).toHaveTextContent("NeverAggregate");
  expect(guard).toHaveBeenCalled();
  expect(
    calls
      .filter((c) => c.program.function === "metadata.relationship.list")
      .map((c) => c.program.arguments.hierarchyId),
  ).toEqual(["H_DEFAULT", "H_ALT"]);
});

async function openPlacementReview() {
  await screen.findByText(/1 current relationships/);
  fireEvent.change(screen.getByRole("combobox", { name: "Hierarchy" }), {
    target: { value: "H_ALT" },
  });
  await waitFor(() =>
    expect(
      screen.getByRole("combobox", { name: "Hierarchy" }),
    ).not.toBeDisabled(),
  );
  expect(screen.queryByLabelText("Stable ID")).toBeNull();
  fireEvent.click(screen.getByLabelText("Parent member"));
  const parentChooser = await screen.findByRole("dialog", {
    name: "Choose one Account member",
  });
  fireEvent.click(
    within(parentChooser).getByRole("button", { name: "Apply selection" }),
  );
  fireEvent.click(screen.getByLabelText("Child member"));
  const chooser = await screen.findByRole("dialog", {
    name: "Choose one Account member",
  });
  const cChoice = (
    await within(chooser).findByText("C", { selector: "strong" })
  ).closest("button");
  expect(cChoice).not.toBeNull();
  fireEvent.click(cChoice!);
  fireEvent.click(
    within(chooser).getByRole("button", { name: "Add selected member" }),
  );
  fireEvent.click(
    within(chooser).getByRole("button", { name: "Apply selection" }),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Preview exact changes" }),
  );
  await screen.findByText("Exact server preview");
}

it("creates a placement and builds only the selected canonical hierarchy", async () => {
  const { calls } = mockReads();
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  const changed = vi.fn(async () => {});
  const view = render(
    <MetadataRelationships
      app={app}
      catalog={catalog}
      dimensionId="Account"
      members={members}
      metadataRevision={46}
      mode="relationships"
      onChanged={changed}
    />,
  );
  await openPlacementReview();
  fireEvent.click(
    screen.getByRole("button", { name: "Apply reviewed changeset" }),
  );
  await waitFor(() => expect(changed).toHaveBeenCalledTimes(1));
  expect(
    calls.find(
      (c) => c.program.function === "metadata.hierarchy.relationships.preview",
    )?.program.arguments,
  ).toMatchObject({
    dimensionId: "Account",
    hierarchyId: "H_ALT",
    expectedMetadataRevision: 46,
    expectedHierarchyStateToken: "8".repeat(64),
    changes: [
      {
        action: "Create",
        parentMemberId: "Root",
        childMemberId: "C",
      },
    ],
  });
  view.unmount();
  render(
    <MetadataRelationships
      app={app}
      catalog={catalog}
      dimensionId="Account"
      members={members}
      metadataRevision={46}
      mode="relationships"
      onChanged={changed}
    />,
  );
  await screen.findByText(/1 current relationships/);
  fireEvent.click(screen.getByLabelText(/I reviewed this dimension/));
  fireEvent.click(screen.getByRole("button", { name: "Build hierarchy" }));
  await waitFor(() =>
    expect(
      calls.some((c) => c.program.function === "metadata.hierarchy.build"),
    ).toBe(true),
  );
  expect(
    calls.find((c) => c.program.function === "metadata.hierarchy.build")
      ?.program.arguments,
  ).toEqual({
    dimensionId: "Account",
    hierarchyId: "H_DEFAULT",
    expectedMetadataRevision: 46,
    expectedStateToken: "3".repeat(64),
  });
  await screen.findByText("The reviewed hierarchy was built.");
});

it("omits the prior token when the reviewed named hierarchy is unbuilt", async () => {
  const { calls } = mockReads(
    trees.map((tree) =>
      tree.isDefault
        ? {
            ...tree,
            stateToken: null,
            builtMetadataRevision: null,
            current: false,
          }
        : tree,
    ),
  );
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  render(
    <MetadataRelationships
      app={app}
      catalog={catalog}
      dimensionId="Account"
      members={members}
      metadataRevision={46}
      mode="relationships"
      onChanged={async () => {}}
    />,
  );
  await screen.findByText(/1 current relationships/);
  fireEvent.click(screen.getByLabelText(/I reviewed this dimension/));
  fireEvent.click(screen.getByRole("button", { name: "Build hierarchy" }));
  await screen.findByText("The reviewed hierarchy was built.");
  expect(
    calls.find((c) => c.program.function === "metadata.hierarchy.build")
      ?.program.arguments,
  ).toEqual({
    dimensionId: "Account",
    hierarchyId: "H_DEFAULT",
    expectedMetadataRevision: 46,
  });
});

it.each(["lost", "wrong hierarchy"])(
  "reconciles a %s build reply using its original historical receipt",
  async (result) => {
    mockReads();
    vi.stubGlobal(
      "confirm",
      vi.fn(() => true),
    );
    const supportedFetch = globalThis.fetch;
    const writes: Array<Record<string, any>> = [];
    const receipts: Array<Record<string, any>> = [];
    const refresh = vi.fn(async () => {});
    let receiptFunction = "metadata.hierarchy.rename";
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init?: RequestInit) => {
        const body = JSON.parse(String(init?.body));
        if (url === "/api/metadata-action") {
          writes.push(body);
          if (result === "lost") throw new TypeError("Failed to fetch");
          return hierarchyBuilt("H_ALT", body.idempotencyKey);
        }
        if (body.program.function === "application.operation.receipt.read") {
          receipts.push(body);
          return response({
            operationId: writes[0].idempotencyKey,
            actorId: "owner",
            commandDigest: "e".repeat(64),
            committedRevision: 48,
            committedAt: "2026-11-21T11:12:00Z",
            outcome: { function: receiptFunction },
          });
        }
        return supportedFetch(url, init);
      }),
    );
    function editor(access: ApplicationCatalog) {
      return (
        <MetadataRelationships
          app={app}
          catalog={access}
          dimensionId="Account"
          members={members}
          metadataRevision={46}
          mode="relationships"
          onChanged={refresh}
        />
      );
    }
    const original = render(editor(catalog));
    await screen.findByText(/1 current relationships/);
    fireEvent.click(screen.getByLabelText(/I reviewed this dimension/));
    fireEvent.click(screen.getByRole("button", { name: "Build hierarchy" }));
    const pending = await screen.findByRole("heading", {
      name: "Hierarchy build awaiting confirmation",
    });
    await waitFor(() => expect(pending).toHaveFocus());
    expect(screen.queryByText("The reviewed hierarchy was built.")).toBeNull();
    expect(refresh).not.toHaveBeenCalled();
    original.unmount();
    const { "metadata.hierarchy.build": _build, ...readerFunctions } =
      catalog.functions;
    render(
      editor({
        ...catalog,
        functions: readerFunctions,
        applicationAccess: { ...catalog.applicationAccess, role: "Reader" },
      }),
    );
    const receipt = await screen.findByRole("button", {
      name: "Check original hierarchy build receipt",
    });
    await waitFor(() => expect(receipt).toBeEnabled());
    fireEvent.click(receipt);
    await screen.findByText(
      "The receipt could not confirm the original hierarchy build.",
    );
    expect(refresh).not.toHaveBeenCalled();
    receiptFunction = "metadata.hierarchy.build";
    fireEvent.click(receipt);
    const recorded = await screen.findByText(
      "The original hierarchy build was recorded.",
    );
    await waitFor(() => expect(recorded).toHaveFocus());
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(writes).toHaveLength(1);
    expect(
      receipts.map((body) => [
        body.workspaceId,
        body.applicationId,
        body.program.arguments,
      ]),
    ).toEqual(
      Array.from({ length: 2 }, () => [
        "ws",
        "app",
        { operationId: writes[0].idempotencyKey },
      ]),
    );
  },
);

it("hides old hierarchy context immediately and discards late responses after authority changes", async () => {
  let resolve!: (value: Response) => void;
  let priorSignal: AbortSignal | undefined;
  const fetcher = vi.fn((_url: string, init: RequestInit) => {
    const p = JSON.parse(String(init.body)).program;
    if (fetcher.mock.calls.length === 1) {
      priorSignal = init.signal as AbortSignal;
      return new Promise<Response>((done) => {
        resolve = done;
      });
    }
    if (p.function === "metadata.hierarchy.list")
      return Promise.resolve(
        response(page([hierarchy("H_NEW", "New authorized tree", true)])),
      );
    if (p.function === "metadata.hierarchy.members.list")
      return Promise.resolve(
        response(page([{ memberId: "C", status: "Active" }])),
      );
    return Promise.resolve(
      response({
        hierarchyId: "H_NEW",
        metadataRevision: 46,
        nextCursor: null,
        rows: [],
      }),
    );
  });
  vi.stubGlobal("fetch", fetcher);
  const props = {
    app,
    dimensionId: "Account",
    members,
    metadataRevision: 46,
    mode: "relationships" as const,
    onChanged: async () => {},
  };
  const view = render(<MetadataRelationships {...props} catalog={catalog} />);
  await waitFor(() => expect(fetcher).toHaveBeenCalledTimes(1));
  view.rerender(
    <MetadataRelationships
      {...props}
      catalog={{ ...catalog, revisions: { ...catalog.revisions, security: 2 } }}
    />,
  );
  expect(priorSignal?.aborted).toBe(true);
  await screen.findByRole("option", { name: "New authorized tree" });
  await act(async () => resolve(response(page(trees))));
  expect(screen.queryByRole("option", { name: "Alternate" })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Tree View" }));
  expect(
    within(screen.getByRole("tree")).getByRole("button", {
      name: "Select C in hierarchy",
    }),
  ).toBeVisible();
  expect(
    within(screen.getByRole("tree")).queryByRole("button", {
      name: "Select A in hierarchy",
    }),
  ).toBeNull();
});

it("uses ordinary typed controls for hierarchy creation, renaming and membership changes", async () => {
  const { calls } = mockReads();
  const changed = vi.fn(async () => {});
  const props = {
    app,
    catalog,
    dimensionId: "Account",
    metadataRevision: 46,
    members,
    current: true,
    onChanged: changed,
  };
  const view = render(
    <MetadataHierarchyEditor {...props} hierarchies={[]} memberships={[]} />,
  );
  fireEvent.click(
    screen.getByText("Create hierarchy", { selector: "summary" }),
  );
  fireEvent.change(screen.getByLabelText("New hierarchy ID"), {
    target: { value: "H_FIRST" },
  });
  fireEvent.change(screen.getByLabelText("New hierarchy name"), {
    target: { value: "First tree" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Create hierarchy" }));
  await waitFor(() => expect(changed).toHaveBeenCalledTimes(1));
  expect(calls.at(-1)?.program.arguments).toEqual({
    dimensionId: "Account",
    hierarchyId: "H_FIRST",
    name: "First tree",
    membershipMode: "explicit",
    isDefault: true,
    expectedMetadataRevision: 46,
  });
  view.unmount();
  const membershipView = render(
    <MetadataHierarchyEditor
      {...props}
      hierarchy={trees[1]}
      hierarchies={trees}
      memberships={[{ memberId: "Root", status: "Active" }]}
    />,
  );
  fireEvent.click(
    screen.getByText("Hierarchy properties and membership", {
      selector: "summary",
    }),
  );
  fireEvent.click(screen.getByLabelText("Include Isolated in Alternate"));
  fireEvent.click(
    screen.getByRole("button", { name: "Save hierarchy membership" }),
  );
  await waitFor(() => expect(changed).toHaveBeenCalledTimes(2));
  expect(calls.at(-1)?.program.arguments).toEqual({
    dimensionId: "Account",
    hierarchyId: "H_ALT",
    members: [{ memberId: "Isolated", status: "Active" }],
    expectedMetadataRevision: 46,
  });
  expect(
    screen.getByRole("button", { name: "Save hierarchy name" }),
  ).toBeDisabled();
  membershipView.rerender(
    <MetadataHierarchyEditor
      {...props}
      metadataRevision={47}
      hierarchy={trees[1]}
      hierarchies={trees}
      memberships={[
        { memberId: "Root", status: "Active" },
        { memberId: "Isolated", status: "Active" },
      ]}
    />,
  );
  fireEvent.change(screen.getByLabelText("Hierarchy name"), {
    target: { value: "Renamed alternate" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save hierarchy name" }));
  await waitFor(() => expect(changed).toHaveBeenCalledTimes(3));
  expect(calls.at(-1)?.program.function).toBe("metadata.hierarchy.rename");
  expect(calls.at(-1)?.program.arguments.name).toBe("Renamed alternate");
});

it("paginates hierarchy membership with revision pins and rejects foreign or stale pages", async () => {
  const calls: Record<string, unknown>[] = [];
  const nextPageToken = "2000000000." + "a".repeat(64);
  const result = await collectHierarchyMembers(
    "Account",
    "H_ALT",
    46,
    async (args) => {
      calls.push(args);
      return calls.length === 1
        ? {
            ...page([{ memberId: "A", status: "Active" as const }]),
            hasMore: true,
            nextAfterId: "A",
            nextPageToken,
          }
        : page([{ memberId: "B", status: "Inactive" as const }]);
    },
  );
  expect(result.rows).toHaveLength(2);
  expect(calls[1]).toMatchObject({
    hierarchyId: "H_ALT",
    afterId: "A",
    expectedMetadataRevision: 46,
    expectedPageToken: nextPageToken,
  });
  await expect(
    collectMetadataHierarchies("Account", 46, async () => ({
      ...page(trees),
      metadataRevision: 47,
    })),
  ).rejects.toThrow(/Metadata changed/);
  await expect(
    collectMetadataHierarchies("Account", 46, async () => ({
      ...page(trees),
      dimensionId: "Other",
    })),
  ).rejects.toThrow(/Invalid/);
});

it("rejects unavailable explicit route identity instead of rendering the default graph", async () => {
  const { calls } = mockReads();
  render(
    <MetadataRelationships
      app={app}
      catalog={catalog}
      dimensionId="Account"
      hierarchyId="H_MISSING"
      members={members}
      metadataRevision={46}
      mode="relationships"
      onChanged={async () => {}}
    />,
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "selected hierarchy is unavailable",
  );
  expect(
    screen.getByRole("combobox", { name: "Hierarchy" }),
  ).toHaveDisplayValue("Unavailable hierarchy · H_MISSING");
  expect(
    calls.some(
      (call) => call.program.function === "metadata.relationship.list",
    ),
  ).toBe(false);
});

it("does not expose mutation controls to readers and keeps draft membership changes through navigation", async () => {
  const { discardUnsavedWork } = await import("./unsaved-work");
  discardUnsavedWork();
  const props = {
    app,
    catalog,
    dimensionId: "Account",
    metadataRevision: 46,
    members,
    current: true,
    onChanged: async () => {},
    hierarchy: trees[1],
    hierarchies: trees,
    memberships: [{ memberId: "Root", status: "Active" as const }],
  };
  let view = render(<MetadataHierarchyEditor {...props} />);
  fireEvent.click(
    screen.getByText("Hierarchy properties and membership", {
      selector: "summary",
    }),
  );
  fireEvent.click(screen.getByLabelText("Include Isolated in Alternate"));
  await waitFor(() =>
    expect(screen.getByText(/1 pending changes/)).toBeVisible(),
  );
  view.unmount();
  view = render(<MetadataHierarchyEditor {...props} hierarchy={trees[0]} />);
  fireEvent.click(
    screen.getByText("Hierarchy properties and membership", {
      selector: "summary",
    }),
  );
  expect(
    screen.getByLabelText("Include Isolated in Default"),
  ).not.toBeChecked();
  view.unmount();
  view = render(<MetadataHierarchyEditor {...props} />);
  fireEvent.click(
    screen.getByText("Hierarchy properties and membership", {
      selector: "summary",
    }),
  );
  await waitFor(() =>
    expect(
      screen.getByLabelText("Include Isolated in Alternate"),
    ).toBeChecked(),
  );
  view.unmount();
  discardUnsavedWork();
  render(
    <MetadataHierarchyEditor
      {...props}
      catalog={{ ...catalog, functions: {} }}
    />,
  );
  fireEvent.click(
    screen.getByText("Hierarchy properties and membership", {
      selector: "summary",
    }),
  );
  expect(
    screen.queryByRole("button", { name: "Save hierarchy membership" }),
  ).toBeNull();
  expect(
    screen.queryByRole("button", { name: "Save hierarchy name" }),
  ).toBeNull();
  expect(screen.getByLabelText("Include Isolated in Alternate")).toBeDisabled();
});

it("pins a changed placement operator to its exact named-graph relationship", async () => {
  const { calls } = mockReads();
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  render(
    <MetadataRelationships
      app={app}
      catalog={catalog}
      dimensionId="Account"
      hierarchyId="H_ALT"
      members={members}
      metadataRevision={46}
      mode="relationships"
      onChanged={async () => {}}
    />,
  );
  await screen.findByText(/1 current relationships/);
  fireEvent.click(screen.getByRole("button", { name: "Tree View" }));
  fireEvent.click(
    within(screen.getByRole("tree")).getByRole("button", {
      name: "Select B in hierarchy under Root",
    }),
  );
  expect(screen.getByLabelText("Placement aggregation operator")).toHaveValue(
    "NeverAggregate",
  );
  fireEvent.change(screen.getByLabelText("Placement aggregation operator"), {
    target: { value: "Subtract" },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Save placement operator" }),
  );
  await waitFor(() =>
    expect(
      calls.some(
        (call) =>
          call.program.function ===
          "metadata.relationship.aggregation-operator.set",
      ),
    ).toBe(true),
  );
  const mutation = calls.find(
    (call) =>
      call.program.function ===
      "metadata.relationship.aggregation-operator.set",
  );
  expect(mutation?.program.arguments).toEqual({
    relationshipId: "H_ALT-edge",
    aggregationOperatorOverride: "Subtract",
    expectedMetadataRevision: 46,
  });
});

it("checks only the original receipt after a lost response and preserves the attempt across remount", async () => {
  mockReads();
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  const changed = vi.fn(async () => {});
  const fetchWithAdmission = globalThis.fetch;
  const packets: Array<{ path: string; body: any }> = [];
  let operationId: string;
  let receiptActor = "wrong-actor";
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      packets.push({ path: url, body });
      if (url === "/api/metadata-action") {
        operationId = body.idempotencyKey;
        throw new TypeError("Failed to fetch");
      }
      if (body.program.function === "application.operation.receipt.read") {
        return response({
          operationId,
          actorId: receiptActor,
          committedRevision: 49,
          committedAt: "2026-11-20T14:25:00Z",
          commandDigest: "d".repeat(64),
          outcome: {},
        });
      }
      return fetchWithAdmission(url, init);
    }),
  );
  function editor(currentApp = app, access = catalog) {
    return (
      <MetadataRelationships
        app={currentApp}
        catalog={access}
        dimensionId="Account"
        members={members}
        metadataRevision={46}
        mode="relationships"
        onChanged={changed}
      />
    );
  }
  const first = render(editor());
  await openPlacementReview();
  fireEvent.click(
    screen.getByRole("button", { name: "Apply reviewed changeset" }),
  );
  const heading = await screen.findByRole("heading", {
    name: "Placement change awaiting confirmation",
  });
  await waitFor(() => expect(heading).toHaveFocus());
  expect(
    screen.queryByRole("button", { name: "Apply reviewed changeset" }),
  ).toBeNull();
  expect(
    screen.getByRole("button", { name: "Preview exact changes" }),
  ).toBeDisabled();
  expect(
    packets.filter(({ path }) => path === "/api/metadata-action"),
  ).toHaveLength(1);
  first.unmount();

  const other = render(editor({ ...app, applicationId: "other" }));
  await screen.findByText(/current relationships/);
  expect(
    screen.queryByRole("button", { name: "Check original placement receipt" }),
  ).toBeNull();
  other.unmount();
  const readerCatalog: ApplicationCatalog = {
    ...catalog,
    applicationAccess: { ...catalog.applicationAccess, role: "Reader" },
    functions: Object.fromEntries(
      Object.entries(catalog.functions).filter(
        ([name]) => name !== "metadata.hierarchy.relationships.apply",
      ),
    ),
  };
  render(editor(app, readerCatalog));
  const check = await screen.findByRole("button", {
    name: "Check original placement receipt",
  });
  await waitFor(() => expect(check).toBeEnabled());
  fireEvent.click(check);
  await screen.findByText(
    "The receipt could not confirm the original placement change.",
  );
  expect(changed).not.toHaveBeenCalled();
  receiptActor = "owner";
  fireEvent.click(check);
  await screen.findByText("The original placement creation was recorded.");
  await screen.findByText(/1 current relationships/);
  expect(changed).toHaveBeenCalledTimes(1);
  const receipts = packets.filter(
    ({ body }) =>
      body.program.function === "application.operation.receipt.read",
  );
  expect(
    receipts.map(({ path, body }) => [
      path,
      body.workspaceId,
      body.applicationId,
      body.program.arguments,
    ]),
  ).toEqual(
    Array.from({ length: 2 }, () => [
      "/api/read",
      "ws",
      "app",
      { operationId },
    ]),
  );
  expect(
    packets.filter(({ path }) => path === "/api/metadata-action"),
  ).toHaveLength(1);
  expect(
    packets.filter(({ path }) => path === "/api/operation-admission"),
  ).toHaveLength(1);
});

it("retries only the exact admitted placement packet after an absent receipt", async () => {
  mockReads();
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  const changed = vi.fn(async () => {});
  const fetchWithAdmission = globalThis.fetch;
  const sent: unknown[] = [];
  let admissions = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (url === "/api/operation-admission") admissions += 1;
      if (url === "/api/metadata-action") {
        sent.push(body);
        if (sent.length === 1) throw new TypeError("Failed to fetch");
        return placementApplied(body.program.arguments.hierarchyId);
      }
      if (body.program.function === "application.operation.receipt.read") {
        return new Response(
          JSON.stringify({ code: "OPERATION_RECEIPT_NOT_FOUND" }),
          { status: 400 },
        );
      }
      return fetchWithAdmission(url, init);
    }),
  );
  render(
    <MetadataRelationships
      app={app}
      catalog={catalog}
      dimensionId="Account"
      members={members}
      metadataRevision={46}
      mode="relationships"
      onChanged={changed}
    />,
  );
  await openPlacementReview();
  fireEvent.click(
    screen.getByRole("button", { name: "Apply reviewed changeset" }),
  );
  const check = await screen.findByRole("button", {
    name: "Check original placement receipt",
  });
  await waitFor(() => expect(check).toBeEnabled());
  expect(
    screen.queryByRole("button", { name: "Retry original placement change" }),
  ).toBeNull();
  fireEvent.click(check);
  const retry = await screen.findByRole("button", {
    name: "Retry original placement change",
  });
  expect(
    screen.getByText(
      "No receipt is visible yet. The original placement change remains unconfirmed.",
    ),
  ).toBeVisible();
  fireEvent.click(retry);
  await screen.findByText(
    "The reviewed placement creation was applied atomically.",
  );
  expect(admissions).toBe(1);
  expect(sent).toHaveLength(2);
  expect(sent[0]).toEqual(sent[1]);
  expect(changed).toHaveBeenCalledTimes(1);
});

function fillNewHierarchy(id: string, name: string) {
  fireEvent.click(
    screen.getByText("Create hierarchy", { selector: "summary" }),
  );
  fireEvent.change(screen.getByLabelText("New hierarchy ID"), {
    target: { value: id },
  });
  fireEvent.change(screen.getByLabelText("New hierarchy name"), {
    target: { value: name },
  });
}

function hierarchyEditorProps(onChanged: () => Promise<void>) {
  return {
    app,
    catalog,
    dimensionId: "Account",
    metadataRevision: 46,
    members,
    current: true,
    onChanged,
    hierarchies: [],
    memberships: [],
  };
}

it("recovers the original named hierarchy creation after remount under current read access", async () => {
  mockReads();
  const changed = vi.fn(async () => {});
  const props = hierarchyEditorProps(changed);
  const fetchWithAdmission = globalThis.fetch;
  const effectPackets: Record<string, any>[] = [];
  const receiptRequests: Record<string, any>[] = [];
  let admissions = 0;
  let changedCount = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (path === "/api/operation-admission") admissions += 1;
      if (path === "/api/metadata-action") {
        effectPackets.push(body);
        throw new TypeError("Failed to fetch");
      }
      if (body.program.function === "application.operation.receipt.read") {
        receiptRequests.push(body);
        return response({
          operationId: effectPackets[0].idempotencyKey,
          actorId: "owner",
          committedRevision: 49,
          committedAt: "2026-11-20T14:25:00Z",
          commandDigest: "d".repeat(64),
          outcome: { changedCount },
        });
      }
      return fetchWithAdmission(path, init);
    }),
  );
  const original = render(<MetadataHierarchyEditor {...props} />);
  fillNewHierarchy("H_FIRST", "First hierarchy");
  fireEvent.click(screen.getByRole("button", { name: /^Create hierarchy$/ }));
  const pending = await screen.findByRole("heading", {
    name: "Hierarchy change awaiting confirmation",
  });
  await waitFor(() => expect(pending).toHaveFocus());
  expect(
    screen.getByRole("button", { name: /^Create hierarchy$/ }),
  ).toBeDisabled();
  original.unmount();

  const other = render(
    <MetadataHierarchyEditor
      {...props}
      app={{ ...app, applicationId: "other" }}
    />,
  );
  expect(
    screen.queryByRole("button", { name: "Check original hierarchy receipt" }),
  ).toBeNull();
  other.unmount();
  render(
    <MetadataHierarchyEditor
      {...props}
      hierarchy={hierarchy("H_FIRST", "First hierarchy", true)}
      hierarchies={[hierarchy("H_FIRST", "First hierarchy", true)]}
      catalog={{
        ...catalog,
        applicationAccess: { ...catalog.applicationAccess, role: "Reader" },
        functions: { "application.operation.receipt.read": {} },
      }}
    />,
  );
  const check = await screen.findByRole("button", {
    name: "Check original hierarchy receipt",
  });
  await waitFor(() => expect(check).toBeEnabled());
  fireEvent.click(check);
  await screen.findByText(
    "The receipt could not confirm the original hierarchy change.",
  );
  expect(changed).not.toHaveBeenCalled();

  changedCount = 1;
  fireEvent.click(check);
  await screen.findByText("The original hierarchy change was recorded.");
  expect(changed).toHaveBeenCalledTimes(1);
  await waitFor(() => expect(unsavedWorkSnapshot()).toHaveLength(0));
  expect(effectPackets).toHaveLength(1);
  expect(admissions).toBe(1);
  expect(receiptRequests).toEqual(
    Array.from({ length: 2 }, () => ({
      workspaceId: "ws",
      applicationId: "app",
      program: {
        languageVersion: 2,
        function: "application.operation.receipt.read",
        arguments: { operationId: effectPackets[0].idempotencyKey },
      },
    })),
  );
});

it("retries the exact hierarchy packet after an absent receipt and keeps a denied retry unconfirmed", async () => {
  mockReads();
  const changed = vi.fn(async () => {});
  const props = hierarchyEditorProps(changed);
  const fetchWithAdmission = globalThis.fetch;
  const writes: unknown[] = [];
  let admissions = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (path === "/api/operation-admission") admissions += 1;
      if (path === "/api/metadata-action") {
        writes.push(body);
        if (writes.length === 1) throw new TypeError("Failed to fetch");
        if (writes.length === 2)
          return new Response(
            JSON.stringify({ code: "APPLICATION_GRANT_REQUIRED" }),
            { status: 403 },
          );
        return namedHierarchyApplied(
          body.program.function,
          body.idempotencyKey,
        );
      }
      if (body.program.function === "application.operation.receipt.read")
        return new Response(
          JSON.stringify({ code: "OPERATION_RECEIPT_NOT_FOUND" }),
          { status: 400 },
        );
      return fetchWithAdmission(path, init);
    }),
  );
  render(<MetadataHierarchyEditor {...props} />);
  fillNewHierarchy("H_FIRST", "First hierarchy");
  fireEvent.click(screen.getByRole("button", { name: /^Create hierarchy$/ }));
  const check = await screen.findByRole("button", {
    name: "Check original hierarchy receipt",
  });
  await waitFor(() => expect(check).toBeEnabled());
  expect(
    screen.queryByRole("button", { name: "Retry original hierarchy change" }),
  ).toBeNull();
  fireEvent.click(check);
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Retry original hierarchy change",
    }),
  );
  await screen.findByText(
    "The original hierarchy change is still unconfirmed.",
  );
  expect(changed).not.toHaveBeenCalled();
  expect(
    screen.getByRole("button", { name: /^Create hierarchy$/ }),
  ).toBeDisabled();
  fireEvent.click(check);
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Retry original hierarchy change",
    }),
  );
  await screen.findByText("Hierarchy change saved.");
  expect(admissions).toBe(1);
  expect(writes).toHaveLength(3);
  expect(writes[1]).toEqual(writes[0]);
  expect(writes[2]).toEqual(writes[0]);
  expect(changed).toHaveBeenCalledTimes(1);
});
