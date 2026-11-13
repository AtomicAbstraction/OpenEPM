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
function mockReads() {
  const calls: Array<Record<string, any>> = [];
  const fetcher = vi.fn(async (_url: string, init: RequestInit) => {
    const body = JSON.parse(String(init.body));
    calls.push(body);
    const p = body.program;
    if (p.function === "metadata.hierarchy.list") return response(page(trees));
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
    return response({ metadataRevision: 47, operationId: "saved" });
  });
  vi.stubGlobal("fetch", fetcher);
  installOperationAdmissionFixture("5");
  return { calls, fetcher };
}
afterEach(() => {
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
        name: "Select B in hierarchy",
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
    within(tree).getByRole("button", { name: "Select B in hierarchy" }),
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
  await screen.findByText(/1 current relationships/);
  fireEvent.change(screen.getByRole("combobox", { name: "Hierarchy" }), {
    target: { value: "H_ALT" },
  });
  await waitFor(() =>
    expect(
      screen.getByRole("combobox", { name: "Hierarchy" }),
    ).not.toBeDisabled(),
  );
  fireEvent.change(screen.getByLabelText("Stable ID"), {
    target: { value: "new-placement" },
  });
  fireEvent.change(screen.getByLabelText("Parent member"), {
    target: { value: "Root" },
  });
  fireEvent.change(screen.getByLabelText("Child member"), {
    target: { value: "C" },
  });
  fireEvent.click(screen.getByLabelText(/I reviewed this exact parent-child/));
  fireEvent.click(screen.getByRole("button", { name: "Create relationship" }));
  await waitFor(() => expect(changed).toHaveBeenCalledTimes(1));
  expect(
    calls.find((c) => c.program.function === "metadata.relationship.create")
      ?.program.arguments,
  ).toEqual({
    dimensionId: "Account",
    hierarchyId: "H_ALT",
    relationshipId: "new-placement",
    parentMemberId: "Root",
    childMemberId: "C",
    expectedMetadataRevision: 46,
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
  });
});

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
  await screen.findByRole("option", { name: "New authorized tree · H_NEW" });
  await act(async () => resolve(response(page(trees))));
  expect(
    screen.queryByRole("option", { name: "Alternate · H_ALT" }),
  ).toBeNull();
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
          }
        : page([{ memberId: "B", status: "Inactive" as const }]);
    },
  );
  expect(result.rows).toHaveLength(2);
  expect(calls[1]).toMatchObject({
    hierarchyId: "H_ALT",
    afterId: "A",
    expectedMetadataRevision: 46,
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
      name: "Select B in hierarchy",
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
  expect(calls.at(-1)?.program.arguments).toEqual({
    relationshipId: "H_ALT-edge",
    aggregationOperatorOverride: "Subtract",
    expectedMetadataRevision: 46,
  });
});
