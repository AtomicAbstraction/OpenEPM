import { useState } from "react";
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { NativeSelectionEditor } from "./NativeSelectionEditor";
import { MemberLists } from "./MemberLists";
import type { ApplicationCatalog } from "./types";
import { resetUnsavedWorkForTests, unsavedWorkSnapshot } from "./unsaved-work";
import { installOperationAdmissionFixture } from "./test-setup";

const app = {
  workspaceId: "ws",
  applicationId: "cube",
  name: "Cube",
  status: "Active",
};
const catalog = {
  applicationAccess: {
    role: "Editor",
    workspaceAdministrator: false,
    issuer: "issuer",
    subjectId: "alice",
  },
  enabledCapabilities: [],
  functions: Object.fromEntries(
    [
      "save",
      "list",
      "read",
      "activate",
      "deactivate",
      "delete",
      "evaluate",
    ].map((name) => [`metadata.member_list.${name}`, {}]),
  ),
  revisions: { metadata: 7, data: 1, policy: 3, security: 1, commit: 4 },
} as ApplicationCatalog;
const definition = {
  format: "openepm-member-list-v1",
  listId: "review",
  name: "Review scope",
  dimensionId: "Product",
  parameters: [],
  expression: { kind: "explicit", memberIds: ["P1"] },
};
const selection = {
  currentMetadataRevision: 7,
  policyRevision: 3,
  listId: "review",
  name: "Review scope",
  dimensionId: "Product",
  definition,
  stateToken: "a".repeat(64),
  canonicalDigest: "d".repeat(64),
  status: "Inactive",
  valid: true,
  active: false,
  executable: false,
  sourceCurrent: true,
  source: null,
};
const response = (result: unknown) => new Response(JSON.stringify({ result }));
function editor(
  props: Partial<React.ComponentProps<typeof NativeSelectionEditor>> = {},
) {
  return (
    <NativeSelectionEditor
      app={app}
      catalog={catalog}
      current
      busy={false}
      onSave={vi.fn()}
      onDirtyChange={vi.fn()}
      {...props}
    />
  );
}
function fillIdentity() {
  fireEvent.change(screen.getByLabelText("Selection ID"), {
    target: { value: "review" },
  });
  fireEvent.change(screen.getByLabelText("Selection name"), {
    target: { value: "Review scope" },
  });
  fireEvent.change(screen.getByLabelText("Dimension"), {
    target: { value: "Product" },
  });
}
afterEach(() => {
  resetUnsavedWorkForTests();
  vi.unstubAllGlobals();
});

it("saves, activates and evaluates an inert named selection using exact current pins", async () => {
  const calls: any[] = [];
  let item: typeof selection | null = null;
  let policy = 3;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(init.body);
      calls.push(body);
      const fn = body.program.function;
      if (fn === "metadata.member_list.save") {
        item = {
          ...selection,
          definition: body.program.arguments.definition,
          stateToken: "b".repeat(64),
        };
        return response({
          listId: "review",
          stateToken: item.stateToken,
          status: "Saved",
          metadataRevision: 7,
          policyRevision: policy,
        });
      }
      if (fn === "metadata.member_list.activate") {
        policy = 4;
        item = {
          ...item!,
          stateToken: "c".repeat(64),
          status: "Active",
          policyRevision: policy,
          active: true,
          executable: true,
        };
        return response({
          listId: "review",
          stateToken: item.stateToken,
          status: "Published",
          metadataRevision: 7,
          policyRevision: policy,
        });
      }
      if (fn === "metadata.member_list.list")
        return response({
          memberLists: item ? [item] : [],
          nextAfterListId: null,
          collectionToken: "f".repeat(64),
        });
      if (fn === "metadata.member_list.read") return response(item);
      if (fn === "metadata.member_list.evaluate")
        return response({
          listId: "review",
          stateToken: item!.stateToken,
          dimensionId: "Product",
          canonicalDigest: item!.canonicalDigest,
          memberIds: ["P1", "P2"],
          memberCount: 2,
          metadataRevision: 7,
        });
      throw new Error(`Unexpected ${fn}`);
    }),
  );
  installOperationAdmissionFixture("3");
  function Workspace() {
    const [current, setCurrent] = useState(catalog);
    return (
      <MemberLists
        app={app}
        catalog={current}
        onRefreshCatalog={async () => {
          const next = {
            ...current,
            revisions: { ...current.revisions, policy },
          };
          setCurrent(next);
          return next;
        }}
      />
    );
  }
  render(<Workspace />);
  fireEvent.click(screen.getByRole("button", { name: "New member list" }));
  fillIdentity();
  const members = screen.getByLabelText("Member IDs, one per line");
  fireEvent.change(members, { target: { value: "P1\n" } });
  expect(members).toHaveValue("P1\n");
  fireEvent.change(members, { target: { value: "P1\nP2" } });
  fireEvent.click(screen.getByRole("button", { name: "Save named selection" }));
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Activate member list" }),
    ).toBeEnabled(),
  );
  const save = calls.find(
    (body) => body.program.function === "metadata.member_list.save",
  );
  expect(save.program.arguments).toEqual({
    definition: {
      ...definition,
      expression: { kind: "explicit", memberIds: ["P1", "P2"] },
    },
    expectedMetadataRevision: 7,
    expectedPolicyRevision: 3,
  });
  await waitFor(() => expect(unsavedWorkSnapshot()).toEqual([]));
  expect(
    screen.getByRole("button", { name: "Evaluate member list" }),
  ).toBeDisabled();
  fireEvent.click(screen.getByRole("button", { name: "Activate member list" }));
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Evaluate member list" }),
    ).toBeEnabled(),
  );
  expect(
    calls.find((body) => body.program.function.endsWith(".activate")).program
      .arguments,
  ).toEqual({
    listId: "review",
    expectedStateToken: "b".repeat(64),
    expectedMetadataRevision: 7,
    expectedPolicyRevision: 3,
  });
  fireEvent.click(screen.getByRole("button", { name: "Evaluate member list" }));
  await screen.findByText("2 selected members");
  expect(
    calls.every((body) =>
      body.program.function.startsWith("metadata.member_list."),
    ),
  ).toBe(true);
  fireEvent.change(screen.getByLabelText("Selection name"), {
    target: { value: "Changed scope" },
  });
  expect(
    screen.getByRole("button", { name: "Evaluate member list" }),
  ).toBeDisabled();
  expect(
    screen.getByRole("button", { name: "Deactivate member list" }),
  ).toBeDisabled();
  expect(
    screen.getByRole("button", { name: "Delete member list" }),
  ).toBeDisabled();
});

it.each(["parents", "base", "children"])(
  "builds the %s selector through domain controls without Python",
  async (kind) => {
    const save = vi.fn(async (_value: unknown) => {});
    render(editor({ onSave: save }));
    fillIdentity();
    fireEvent.change(screen.getByLabelText("Selection method"), {
      target: { value: kind },
    });
    fireEvent.change(screen.getByLabelText("Hierarchy"), {
      target: { value: "main" },
    });
    fireEvent.change(screen.getByLabelText("Starting member ID"), {
      target: { value: "Total" },
    });
    if (kind === "base")
      expect(
        screen.queryByLabelText("Include starting member"),
      ).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Save named selection" }),
    );
    await waitFor(() => expect(save).toHaveBeenCalledOnce());
    expect(save.mock.calls[0][0]).toEqual({
      ...definition,
      expression: {
        kind,
        hierarchyId: "main",
        memberId: "Total",
        includeSelf: false,
      },
    });
  },
);

it("reads attributes only in the selected dimension and preserves Boolean values", async () => {
  const calls: any[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(init.body);
      calls.push(body);
      expect(body.program.function).toBe("metadata.attribute-definition.list");
      expect(body.program.arguments.dimensionId).toBe("Product");
      return response({
        rows: [
          {
            attribute_id: "Enabled",
            display_name: "Enabled",
            value_type: "Boolean",
            status: "Active",
          },
        ],
        hasMore: false,
        nextAfterAttributeId: null,
        metadataRevision: 7,
      });
    }),
  );
  const save = vi.fn(async (_value: unknown) => {});
  render(
    editor({
      onSave: save,
      catalog: {
        ...catalog,
        functions: {
          ...catalog.functions,
          "metadata.attribute-definition.list": {} as never,
        },
      },
    }),
  );
  fillIdentity();
  fireEvent.change(screen.getByLabelText("Selection method"), {
    target: { value: "attribute" },
  });
  await screen.findByText("Enabled (Boolean)");
  fireEvent.change(screen.getByLabelText("Member attribute"), {
    target: { value: "Enabled" },
  });
  fireEvent.change(screen.getByLabelText("Attribute value"), {
    target: { value: "false" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save named selection" }));
  await waitFor(() => expect(save).toHaveBeenCalledOnce());
  expect(save.mock.calls[0][0]).toEqual({
    ...definition,
    expression: {
      kind: "attribute",
      attributeId: "Enabled",
      operator: "eq",
      value: false,
    },
  });
  expect(calls).toHaveLength(1);
});

it("preserves compound expressions and typed parameter declarations through advanced editing", async () => {
  const initial = {
    ...definition,
    parameters: [{ name: "Chosen", type: "Member", required: true }],
    expression: {
      kind: "order",
      source: {
        kind: "union",
        items: [
          { kind: "explicit", memberIds: ["P1"] },
          { kind: "parameter", name: "Chosen" },
        ],
      },
      by: "member_id",
      direction: "descending",
      attributeId: null,
    },
    limits: { nodeCount: 4, memberReferenceCount: 1 },
  };
  const save = vi.fn(async (_value: unknown) => {});
  render(editor({ initial, onSave: save }));
  expect(screen.getByLabelText("Edit expression JSON")).toBeChecked();
  fireEvent.click(screen.getByLabelText("Edit expression JSON"));
  await screen.findByText(
    "This compound selection requires the advanced editor.",
  );
  fireEvent.change(screen.getByLabelText("Selection name"), {
    target: { value: "Changed scope" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save named selection" }));
  await waitFor(() => expect(save).toHaveBeenCalledOnce());
  const { limits: _limits, ...expected } = initial;
  expect(save.mock.calls[0][0]).toEqual({ ...expected, name: "Changed scope" });
});

it("rejects inexact advanced expression and parameter numbers before save", async () => {
  const save = vi.fn(async (_value: unknown) => {});
  render(editor({ onSave: save }));
  fillIdentity();
  fireEvent.change(screen.getByLabelText("Member IDs, one per line"), {
    target: { value: "P1" },
  });
  fireEvent.click(screen.getByLabelText("Edit expression JSON"));
  const inexactExpression =
    '{"kind":"attribute","attributeId":"Rate","operator":"eq","value":0.99999999999999999}';
  fireEvent.change(screen.getByLabelText("Selection expression JSON"), {
    target: { value: inexactExpression },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save named selection" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "exact safe integers",
  );
  expect(save).not.toHaveBeenCalled();
  expect(screen.getByLabelText("Selection expression JSON")).toHaveValue(
    inexactExpression,
  );
  fireEvent.click(screen.getByLabelText("Edit expression JSON"));
  expect(screen.getByLabelText("Edit expression JSON")).toBeChecked();
  expect(screen.getByLabelText("Selection expression JSON")).toHaveValue(
    inexactExpression,
  );
  expect(unsavedWorkSnapshot()).toHaveLength(1);

  const exactExpression =
    '{"kind":"attribute","attributeId":"Rate","operator":"eq","value":"0.99999999999999999"}';
  fireEvent.change(screen.getByLabelText("Selection expression JSON"), {
    target: { value: exactExpression },
  });
  fireEvent.change(screen.getByLabelText("Parameter declarations JSON"), {
    target: {
      value: '[{"name":"Count","type":"Integer","default":9007199254740993}]',
    },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save named selection" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "exact safe integers",
  );
  expect(save).not.toHaveBeenCalled();
  expect(screen.getByLabelText("Selection expression JSON")).toHaveValue(
    exactExpression,
  );
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  fireEvent.change(screen.getByLabelText("Parameter declarations JSON"), {
    target: { value: "[]" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save named selection" }));
  await waitFor(() => expect(save).toHaveBeenCalledOnce());
  expect(save.mock.calls[0][0]).toEqual({
    ...definition,
    expression: {
      kind: "attribute",
      attributeId: "Rate",
      operator: "eq",
      value: "0.99999999999999999",
    },
  });
});

it("retains a same-user draft but fences it when metadata or authority changes", async () => {
  const view = render(<MemberLists app={app} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "New member list" }));
  fillIdentity();
  fireEvent.change(screen.getByLabelText("Member IDs, one per line"), {
    target: { value: "P1" },
  });
  view.rerender(
    <MemberLists
      app={app}
      catalog={{ ...catalog, revisions: { ...catalog.revisions, security: 2 } }}
    />,
  );
  expect(screen.getByLabelText("Selection name")).toHaveValue("Review scope");
  expect(
    screen.getByRole("button", { name: "Save named selection" }),
  ).toBeDisabled();
  expect(unsavedWorkSnapshot()).toEqual([
    { id: "native-selection-definition", label: "Unsaved named selection" },
  ]);
  view.rerender(
    <MemberLists
      app={app}
      catalog={{
        ...catalog,
        applicationAccess: { ...catalog.applicationAccess, subjectId: "bob" },
      }}
    />,
  );
  expect(
    screen.queryByLabelText("Named selection editor"),
  ).not.toBeInTheDocument();
  expect(unsavedWorkSnapshot()).toEqual([]);
});

it("does not expose a late list response to a different identity in the same application", async () => {
  let resolve!: (value: Response) => void;
  vi.stubGlobal(
    "fetch",
    vi.fn(
      () =>
        new Promise<Response>((done) => {
          resolve = done;
        }),
    ),
  );
  const view = render(<MemberLists app={app} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Read member lists" }));
  view.rerender(
    <MemberLists
      app={app}
      catalog={{
        ...catalog,
        applicationAccess: {
          ...catalog.applicationAccess,
          issuer: "other-issuer",
        },
      }}
    />,
  );
  await act(async () =>
    resolve(
      response({
        memberLists: [selection],
        nextAfterListId: null,
        collectionToken: "f".repeat(64),
      }),
    ),
  );
  expect(
    screen.queryByRole("button", { name: "Review scope" }),
  ).not.toBeInTheDocument();
  expect(screen.queryByText("Working…")).not.toBeInTheDocument();
});

it("opens a legacy draft with no compiled payload without enabling native editing or execution", async () => {
  const item = {
    ...selection,
    definition: null,
    sourceCurrent: false,
    valid: false,
    source: { programId: "legacy", sourceDigest: "f".repeat(64) },
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) =>
      response(
        JSON.parse(init.body).program.function.endsWith(".list")
          ? {
              memberLists: [item],
              nextAfterListId: null,
              collectionToken: "f".repeat(64),
            }
          : item,
      ),
    ),
  );
  render(<MemberLists app={app} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Read member lists" }));
  fireEvent.click(await screen.findByRole("button", { name: "Review scope" }));
  await screen.findByText(/This legacy selection is owned by source/);
  expect(
    screen.queryByLabelText("Named selection editor"),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Delete member list" }),
  ).not.toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Evaluate member list" }),
  ).toBeDisabled();
});

it("rejects an evaluation response for a replaced saved definition", async () => {
  const item = {
    ...selection,
    status: "Active",
    active: true,
    executable: true,
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const fn = JSON.parse(init.body).program.function;
      if (fn.endsWith(".list"))
        return response({
          memberLists: [item],
          nextAfterListId: null,
          collectionToken: "f".repeat(64),
        });
      if (fn.endsWith(".read")) return response(item);
      return response({
        listId: item.listId,
        stateToken: "b".repeat(64),
        canonicalDigest: item.canonicalDigest,
        memberCount: 1,
        memberIds: ["Unexpected"],
        metadataRevision: 7,
      });
    }),
  );
  render(<MemberLists app={app} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Read member lists" }));
  fireEvent.click(await screen.findByRole("button", { name: "Review scope" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Evaluate member list" }),
  );
  await screen.findByText(
    "The saved selection changed. Reopen it before evaluating again.",
  );
  expect(screen.queryByText("Unexpected")).not.toBeInTheDocument();
});

it("reuses the same Save intent after a rejected request without losing the draft", async () => {
  const saves: any[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) => {
      const body = JSON.parse(init.body);
      if (body.program.function.endsWith(".save")) {
        saves.push(body);
        if (saves.length === 1)
          return new Response(JSON.stringify({ code: "SERVICE_UNAVAILABLE" }), {
            status: 503,
          });
        return response({
          listId: "review",
          stateToken: selection.stateToken,
          metadataRevision: 7,
          policyRevision: 3,
        });
      }
      if (body.program.function.endsWith(".list"))
        return response({
          memberLists: [selection],
          nextAfterListId: null,
          collectionToken: "f".repeat(64),
        });
      return response(selection);
    }),
  );
  installOperationAdmissionFixture("4");
  render(<MemberLists app={app} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "New member list" }));
  fillIdentity();
  fireEvent.change(screen.getByLabelText("Member IDs, one per line"), {
    target: { value: "P1" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save named selection" }));
  await screen.findByText("SERVICE_UNAVAILABLE");
  expect(screen.getByLabelText("Selection name")).toHaveValue("Review scope");
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  fireEvent.click(screen.getByRole("button", { name: "Save named selection" }));
  await screen.findByRole("button", { name: "Activate member list" });
  expect(saves).toHaveLength(2);
  expect(saves[0]).toEqual(saves[1]);
});

it("keeps a pending Save draft dirty after authority invalidation and allows an explicit fresh draft", async () => {
  let resolve!: (value: Response) => void;
  vi.stubGlobal(
    "fetch",
    vi.fn(
      () =>
        new Promise<Response>((done) => {
          resolve = done;
        }),
    ),
  );
  const view = render(<MemberLists app={app} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "New member list" }));
  fillIdentity();
  fireEvent.change(screen.getByLabelText("Member IDs, one per line"), {
    target: { value: "P1" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save named selection" }));
  view.rerender(
    <MemberLists
      app={app}
      catalog={{ ...catalog, revisions: { ...catalog.revisions, security: 2 } }}
    />,
  );
  await act(async () =>
    resolve(
      response({
        listId: "review",
        stateToken: selection.stateToken,
        metadataRevision: 7,
        policyRevision: 3,
      }),
    ),
  );
  expect(screen.getByLabelText("Selection name")).toHaveValue("Review scope");
  expect(
    screen.getByRole("button", { name: "Save named selection" }),
  ).toBeDisabled();
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  fireEvent.click(screen.getByRole("button", { name: "New member list" }));
  expect(screen.getByLabelText("Selection name")).toHaveValue("");
  expect(
    screen.getByRole("button", { name: "Save named selection" }),
  ).toBeEnabled();
});

it("refuses to combine a newer definition metadata cut with the displayed application context", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url, init) =>
      response(
        JSON.parse(init.body).program.function.endsWith(".list")
          ? {
              memberLists: [selection],
              nextAfterListId: null,
              collectionToken: "f".repeat(64),
            }
          : { ...selection, currentMetadataRevision: 8 },
      ),
    ),
  );
  render(<MemberLists app={app} catalog={catalog} />);
  fireEvent.click(screen.getByRole("button", { name: "Read member lists" }));
  fireEvent.click(await screen.findByRole("button", { name: "Review scope" }));
  await screen.findByText(
    "The application changed while opening this selection. Refresh the application and try again.",
  );
  expect(
    screen.queryByLabelText("Named selection editor"),
  ).not.toBeInTheDocument();
});
