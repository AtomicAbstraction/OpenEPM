import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { Profiler, useState } from "react";
import { MemberSelectionDialog } from "./MemberSelectionDialog";
import type { ApplicationCatalog } from "../types";

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

const members = [
  {
    member_id: "World",
    name: "All Entities",
    status: "Active",
    short_description: "Application root",
  },
  {
    member_id: "Europe",
    name: "Europe",
    status: "Active",
    short_description: "Management region",
  },
  {
    member_id: "CH",
    name: "Switzerland",
    status: "Active",
    short_description: "Swiss entity",
  },
  {
    member_id: "DE",
    name: "Germany",
    status: "Active",
    short_description: "German entity",
  },
];

const scalarRequest = {
  dimensionId: "Entity",
  dimensionName: "Entity",
  metadataRevision: 7,
  cardinality: { kind: "exactly-one" as const },
  capability: {
    allowExplicitMembers: true,
    allowHierarchySelector: false,
    allowNamedMemberList: false,
    allowAttributeSelector: false,
    allowInlineExpression: false,
    allowExclusion: false,
    orderMatters: false,
  },
  initial: { kind: "member" as const, memberId: "CH" },
};

const multiRequest = {
  ...scalarRequest,
  title: "Choose reporting entities",
  cardinality: { kind: "one-or-more" as const, maximum: 10 },
  capability: {
    ...scalarRequest.capability,
    allowHierarchySelector: true,
    allowInlineExpression: true,
    allowNamedMemberList: true,
    orderMatters: true,
  },
  initial: { kind: "members" as const, memberIds: ["CH"] },
};

function catalog(): ApplicationCatalog {
  return {
    applicationAccess: { role: "Administrator", workspaceAdministrator: false },
    enabledCapabilities: [],
    functions: Object.fromEntries(
      ["metadata.hierarchy.list", "metadata.member.select"].map((name) => [
        name,
        {},
      ]),
    ),
    revisions: { metadata: 7, data: 1, policy: 2, security: 3, commit: 8 },
  };
}

const response = (result: unknown) =>
  new Response(JSON.stringify({ result }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });

function installApi() {
  const calls: Array<{
    functionName: string;
    arguments: Record<string, unknown>;
  }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      const functionName = body.program.function;
      const arguments_ = body.program.arguments;
      calls.push({ functionName, arguments: arguments_ });
      if (functionName === "metadata.hierarchy.list")
        return response({
          dimensionId: "Entity",
          metadataRevision: 7,
          rows: [
            {
              hierarchyId: "primary",
              name: "Primary hierarchy",
              status: "Active",
              membershipMode: "all_active",
              isDefault: true,
              stateToken: "a".repeat(64),
              builtMetadataRevision: 7,
              current: true,
            },
          ],
          hasMore: false,
          nextAfterId: null,
        });
      if (functionName === "metadata.member.select") {
        const { expression, resultMode } = arguments_;
        const placement = [
          ["World", [], ["World"]],
          ["Europe", ["world-europe"], ["World", "Europe"]],
          ["DE", ["world-europe", "europe-de"], ["World", "Europe", "DE"]],
          ["CH", ["world-europe", "europe-ch"], ["World", "Europe", "CH"]],
        ] as const;
        const rows = placement
          .filter(
            ([id]) =>
              expression.operation === "all" ||
              (["leaves", "descendants"].includes(expression.operation) &&
                ["DE", "CH"].includes(id)),
          )
          .map(([id, edges, path]) => {
            const member = members.find((item) => item.member_id === id)!;
            return {
              memberId: id,
              name: member.name,
              status: member.status,
              shortDescription: member.short_description,
              ...(resultMode === "placements"
                ? { pathRelationshipIds: edges, pathMemberIds: path }
                : {}),
            };
          });
        return response({
          dimensionId: "Entity",
          metadataRevision: 7,
          selectionContextToken: "a".repeat(64),
          rows,
          hasMore: false,
          nextCursor: null,
          resultKind:
            expression.operation === "top"
              ? "scope"
              : (resultMode ?? "unique_member"),
          scope: {
            kind: "scope",
            dimensionId: "Entity",
            scope: expression.scope,
            hierarchyId: expression.hierarchyId,
            name: "Entity",
            shortDescription: "",
            semanticDescription: "Structural Entity top",
            businessCoordinate: false,
            supportedOperations: ["top", "all", "leaves", "descendants"],
          },
        });
      }
      throw new Error(`Unexpected function ${functionName}`);
    }),
  );
  return calls;
}

it.each(["available", "unavailable", "retry"] as const)(
  "checks a saved member outside the first hierarchy page before claiming %s",
  async (outcome) => {
    installApi();
    const fallback = globalThis.fetch;
    let finishHierarchy!: () => void;
    const hierarchy = new Promise<void>((resolve) => {
      finishHierarchy = resolve;
    });
    const exactReads: {
      args: Record<string, unknown>;
      finish: (value: Response) => void;
    }[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url, init) => {
        const program = JSON.parse(String(init?.body)).program;
        if (program.function === "metadata.hierarchy.list") await hierarchy;
        if (program.arguments.expression?.kind === "explicit")
          return new Promise<Response>((finish) => {
            exactReads.push({ args: program.arguments, finish });
          });
        const result = await fallback(url, init);
        if (program.arguments.expression?.operation !== "all") return result;
        const { result: page } = await result.json();
        return response({
          ...page,
          rows: page.rows.filter(
            (row: { memberId: string }) => row.memberId !== "CH",
          ),
          hasMore: true,
          nextCursor: "second-page",
        });
      }),
    );
    const apply = vi.fn();
    const commits: string[] = [];
    const renderCount = () => {
      commits.push(document.querySelector("dialog")?.textContent || "");
    };
    render(
      <Profiler id="member-verification" onRender={renderCount}>
        <MemberSelectionDialog
          app={app}
          catalog={catalog()}
          request={scalarRequest}
          members={members.filter((member) => member.member_id !== "CH")}
          onCancel={vi.fn()}
          onApply={apply}
        />
      </Profiler>,
    );
    const submit = screen.getByRole("button", { name: "Apply selection" });
    expect(submit).toBeDisabled();
    expect(screen.getByText("Loading selection context…")).toBeVisible();
    await act(async () => finishHierarchy());
    await waitFor(() => expect(exactReads).toHaveLength(1));
    expect(screen.getByText("Checking this member…")).toBeVisible();
    expect(submit).toBeDisabled();
    expect(commits.join("\n")).not.toMatch(/unavailable|no longer active/i);
    expect(exactReads[0].args).toMatchObject({
      dimensionId: "Entity",
      expression: { kind: "explicit", memberIds: ["CH"] },
      expectedMetadataRevision: 7,
      expectedSecurityRevision: 3,
      expectedPolicyRevision: 2,
      selectionContext: { expectedToken: "a".repeat(64) },
    });
    expect(apply).not.toHaveBeenCalled();

    if (outcome === "unavailable") {
      await act(async () =>
        exactReads[0].finish(
          new Response(
            JSON.stringify({ code: "METADATA_SELECTION_SCOPE_UNAVAILABLE" }),
            { status: 403 },
          ),
        ),
      );
      expect(
        screen.getByText(
          "Some selected members are unavailable in the current context.",
        ),
      ).toBeVisible();
      expect(submit).toBeDisabled();
      return;
    }
    if (outcome === "retry") {
      await act(async () =>
        exactReads[0].finish(
          new Response(JSON.stringify({ code: "GATEWAY_UNAVAILABLE" }), {
            status: 503,
          }),
        ),
      );
      expect(
        screen.getByText("The selected members could not be confirmed."),
      ).toBeVisible();
      expect(submit).toBeDisabled();
      fireEvent.click(
        screen.getByRole("button", { name: "Retry member check" }),
      );
      await waitFor(() => expect(exactReads).toHaveLength(2));
      expect(screen.getByText("Checking this member…")).toBeVisible();
    }
    await act(async () =>
      exactReads.at(-1)!.finish(
        response({
          dimensionId: "Entity",
          metadataRevision: 7,
          selectionContextToken: "a".repeat(64),
          hasMore: false,
          nextCursor: null,
          rows: [
            {
              memberId: "CH",
              name: "Switzerland",
              status: "Active",
              shortDescription: "Swiss entity",
            },
          ],
        }),
      ),
    );
    expect(screen.getByText("Switzerland")).toBeVisible();
    expect(commits.join("\n")).not.toMatch(/unavailable|no longer active/i);
    expect(submit).toBeEnabled();
    fireEvent.click(submit);
    expect(apply).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ include: { kind: "member", memberId: "CH" } }),
    );
  },
);

it("does not install a partial verification when a later exact batch is denied", async () => {
  installApi();
  const fallback = globalThis.fetch;
  const ids = Array.from({ length: 51 }, (_, index) => `Selected-${index + 1}`);
  const exactReads: { memberIds: string[]; selectionContext: unknown }[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init) => {
      const args = JSON.parse(String(init?.body)).program.arguments;
      if (args.expression?.kind !== "explicit") return fallback(url, init);
      const { memberIds } = args.expression as { memberIds: string[] };
      exactReads.push({ memberIds, selectionContext: args.selectionContext });
      if (memberIds.includes("Selected-51"))
        return new Response(
          JSON.stringify({ code: "METADATA_SELECTION_SCOPE_UNAVAILABLE" }),
          { status: 403 },
        );
      return response({
        dimensionId: "Entity",
        metadataRevision: 7,
        selectionContextToken: "a".repeat(64),
        hasMore: false,
        nextCursor: null,
        rows: memberIds.map((memberId) => ({
          memberId,
          name: `Read label for ${memberId}`,
          status: "Active",
          shortDescription: "",
        })),
      });
    }),
  );
  const apply = vi.fn();
  render(
    <MemberSelectionDialog
      app={app}
      catalog={catalog()}
      request={{
        ...multiRequest,
        cardinality: { kind: "one-or-more", maximum: 100 },
        initial: { kind: "members", memberIds: ids },
      }}
      members={members}
      onCancel={vi.fn()}
      onApply={apply}
    />,
  );
  await screen.findByText(
    "Some selected members are unavailable in the current context.",
  );
  expect(exactReads).toEqual([
    {
      memberIds: ids.slice(0, 50),
      selectionContext: { expectedToken: "a".repeat(64) },
    },
    {
      memberIds: ids.slice(50),
      selectionContext: { expectedToken: "a".repeat(64) },
    },
  ]);
  expect(screen.queryByText(/Read label for/)).not.toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Apply selection" }),
  ).toBeDisabled();
  expect(apply).not.toHaveBeenCalled();
});

it("keeps and explains an existing exclusion during an include-only edit", async () => {
  const calls = installApi();
  const apply = vi.fn();
  const exclude = {
    kind: "attribute" as const,
    attributeId: "Status",
    operator: "eq" as const,
    value: "Closed",
  };
  render(
    <MemberSelectionDialog
      app={app}
      catalog={catalog()}
      request={{ ...multiRequest, initialExclude: exclude }}
      members={members}
      onCancel={vi.fn()}
      onApply={apply}
    />,
  );
  expect(
    await screen.findByRole("region", {
      name: "Preserved selection exclusion",
    }),
  ).toHaveTextContent('Excludes: Status equals "Closed"');
  fireEvent.click(screen.getByRole("button", { name: "Apply selection" }));
  expect(apply).toHaveBeenCalledWith(
    expect.objectContaining({
      include: multiRequest.initial,
      exclude,
      displaySummary: expect.stringContaining(
        'excluding (Status equals "Closed")',
      ),
    }),
  );
  expect(
    calls.every((call) =>
      ["metadata.hierarchy.list", "metadata.member.select"].includes(
        call.functionName,
      ),
    ),
  ).toBe(true);
});

it("keeps an empty strict-descendant preview dynamic without broadening it to all members", async () => {
  installApi();
  const apply = vi.fn();
  render(
    <MemberSelectionDialog
      app={app}
      catalog={catalog()}
      request={{ ...multiRequest, initial: null }}
      members={members}
      onCancel={vi.fn()}
      onApply={apply}
    />,
  );
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Use Switzerland as starting point · World / Europe / CH",
    }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Base descendants" }));
  expect(
    await screen.findByText(
      "This is a complete empty result. Keeping the dynamic rule does not select the whole dimension.",
    ),
  ).toBeVisible();
  expect(
    screen.getByText(/Base descendants are strict descendants/),
  ).toBeVisible();
  fireEvent.click(
    screen.getByRole("button", { name: "Use dynamic selection" }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Apply selection" }));
  expect(apply).toHaveBeenCalledWith(
    expect.objectContaining({
      include: {
        kind: "inline_expression",
        expressionFormat: "openepm-member-list-expression-v1",
        expression: {
          kind: "navigation",
          operation: "leaf_descendants",
          scope: "hierarchy",
          hierarchyId: "primary",
          anchor: {
            memberId: "CH",
            pathRelationshipIds: ["world-europe", "europe-ch"],
          },
          includeSelf: false,
          allParents: false,
        },
      },
    }),
  );
});

it("distinguishes a shared member's two placements even for scalar selection", async () => {
  installApi();
  const onApply = vi.fn();
  const delegate = globalThis.fetch;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init) => {
      const body = JSON.parse(String(init?.body));
      const result = await delegate(url, init);
      if (body.program.arguments.resultMode !== "placements") return result;
      const data = await result.json();
      data.result.rows.push({
        memberId: "CH",
        name: "Switzerland",
        status: "Active",
        shortDescription: "Shared entity",
        pathRelationshipIds: ["world-ch"],
        pathMemberIds: ["World", "CH"],
      });
      return response(data.result);
    }),
  );
  render(
    <MemberSelectionDialog
      app={app}
      catalog={catalog()}
      request={{
        ...scalarRequest,
        initial: { kind: "member", memberId: "DE" },
      }}
      members={members}
      onCancel={vi.fn()}
      onApply={onApply}
    />,
  );
  const first = await screen.findByRole("button", {
    name: "Choose Switzerland (CH) · World / Europe / CH [world-europe / europe-ch]",
  });
  const second = screen.getByRole("button", {
    name: "Choose Switzerland (CH) · World / CH [world-ch]",
  });
  expect(first).not.toBe(second);
  fireEvent.click(second);
  fireEvent.click(screen.getByRole("button", { name: "Parents" }));
  await waitFor(() =>
    expect(
      vi.mocked(globalThis.fetch).mock.calls.some(([, init]) => {
        const body = JSON.parse(String(init?.body));
        return (
          body.program.arguments.expression?.operation === "parents" &&
          JSON.stringify(
            body.program.arguments.expression.anchor.pathRelationshipIds,
          ) === '["world-ch"]'
        );
      }),
    ).toBe(true),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Back to hierarchy" }),
  );
  fireEvent.click(screen.getByRole("button", { name: "All base members" }));
  const uniqueResult = await screen.findByRole("button", {
    name: "Choose Switzerland (CH)",
  });
  expect(screen.queryByRole("button", { name: "Switzerland" })).toBeNull();
  fireEvent.doubleClick(uniqueResult);
  fireEvent.click(screen.getByRole("button", { name: "Apply selection" }));
  expect(onApply).toHaveBeenCalledWith(
    expect.objectContaining({
      dimensionId: "Entity",
      include: { kind: "member", memberId: "CH" },
      exclude: null,
    }),
  );
});

it("keeps duplicate display names distinguishable by member identity", () => {
  const duplicateMembers = [
    { member_id: "east", name: "Operations", status: "Active" },
    { member_id: "west", name: "Operations", status: "Active" },
  ];
  render(
    <MemberSelectionDialog
      app={app}
      catalog={{ ...catalog(), functions: {} }}
      request={{ ...scalarRequest, initial: null }}
      members={duplicateMembers}
      onCancel={vi.fn()}
      onApply={vi.fn()}
    />,
  );
  expect(
    screen.getByRole("button", { name: "Choose Operations (east)" }),
  ).toBeVisible();
  expect(
    screen.getByRole("button", { name: "Choose Operations (west)" }),
  ).toBeVisible();
});

it("names expansion controls by exact member and placement when parent labels repeat", async () => {
  installApi();
  const delegate = globalThis.fetch;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init) => {
      const result = await delegate(url, init);
      if (
        JSON.parse(String(init?.body)).program.arguments.resultMode !==
        "placements"
      )
        return result;
      const data = await result.json();
      data.result.rows.find(
        (row: { memberId: string }) => row.memberId === "Europe",
      ).name = "Region";
      data.result.rows.push(
        {
          memberId: "Other",
          name: "Region",
          status: "Active",
          shortDescription: "Alternative region",
          pathRelationshipIds: ["world-other"],
          pathMemberIds: ["World", "Other"],
        },
        {
          memberId: "CH",
          name: "Switzerland",
          status: "Active",
          shortDescription: "Shared entity",
          pathRelationshipIds: ["world-other", "other-ch"],
          pathMemberIds: ["World", "Other", "CH"],
        },
      );
      return response(data.result);
    }),
  );
  render(
    <MemberSelectionDialog
      app={app}
      catalog={catalog()}
      request={scalarRequest}
      members={members}
      onCancel={vi.fn()}
      onApply={vi.fn()}
    />,
  );
  const europe = await screen.findByRole("button", {
    name: "Collapse Region (Europe) · World / Europe [world-europe]",
  });
  const other = screen.getByRole("button", {
    name: "Collapse Region (Other) · World / Other [world-other]",
  });
  fireEvent.click(europe);
  expect(
    screen.getByRole("button", {
      name: "Expand Region (Europe) · World / Europe [world-europe]",
    }),
  ).toHaveAttribute("aria-expanded", "false");
  expect(other).toHaveAttribute("aria-expanded", "true");
  expect(
    screen.getByRole("button", {
      name: "Choose Switzerland (CH) · World / Other / CH [world-other / other-ch]",
    }),
  ).toBeVisible();
  fireEvent.click(
    screen.getByRole("button", {
      name: "Expand Region (Europe) · World / Europe [world-europe]",
    }),
  );
  fireEvent.click(
    screen.getByRole("button", {
      name: "Choose Switzerland (CH) · World / Europe / CH [world-europe / europe-ch]",
    }),
  );
  fireEvent.click(screen.getByRole("button", { name: "Base descendants" }));
  expect(
    await screen.findByText(
      /placement All Entities \(World\) \/ Region \(Europe\) \/ Switzerland \(CH\) \[world-europe \/ europe-ch\]/,
    ),
  ).toBeVisible();
});

it.each(["first read", "cursor", "different token"])(
  "keeps the picker on one authorized hierarchy context after a stale %s",
  async (where) => {
    const discovery = catalog();
    discovery.revisions.schemaEpoch = 9;
    installApi();
    const delegate = globalThis.fetch;
    const requests: Array<Record<string, unknown>> = [];
    const denied = (code: string) =>
      new Response(JSON.stringify({ code }), { status: 409 });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url, init) => {
        const raw = JSON.parse(String(init?.body)).program;
        if (raw.function !== "metadata.member.select")
          return delegate(url, init);
        requests.push(raw.arguments);
        if (raw.arguments.cursor)
          return denied("METADATA_SELECTION_CURSOR_STALE");
        if (raw.arguments.expression.operation !== "leaves")
          return delegate(url, init);
        if (where === "first read")
          return denied("METADATA_SELECTION_CONTEXT_STALE");
        const page = (await (await delegate(url, init)).json()).result;
        if (where === "different token")
          return response({ ...page, selectionContextToken: "b".repeat(64) });
        return response({
          ...page,
          rows: page.rows.slice(0, 1),
          hasMore: true,
          nextCursor: "next-placement-page",
        });
      }),
    );
    const apply = vi.fn();
    const cancel = vi.fn();
    render(
      <MemberSelectionDialog
        app={app}
        catalog={discovery}
        request={multiRequest}
        members={members}
        onCancel={cancel}
        onApply={apply}
      />,
    );
    const leaves = await screen.findByRole("button", {
      name: "All base members",
    });
    expect(
      screen.getByRole("button", { name: "Apply selection" }),
    ).toBeEnabled();
    fireEvent.click(leaves);
    if (where === "cursor") {
      expect(await screen.findByText(/more available/)).toBeVisible();
      fireEvent.click(screen.getByRole("button", { name: "More results" }));
    }
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Refresh the application and reopen the picker before selecting members.",
    );
    expect(
      screen.queryByRole("region", { name: "Available Entity members" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("region", { name: "Selected Entity members" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/complete empty result/)).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Apply selection" }),
    ).toBeDisabled();
    expect(apply).not.toHaveBeenCalled();
    const pinned = requests.filter((args) => !("cursor" in args));
    expect(pinned).toHaveLength(3);
    for (const args of pinned)
      expect(args).toMatchObject({
        expectedMetadataRevision: 7,
        expectedPolicyRevision: 2,
        expectedSecurityRevision: 3,
        expectedSchemaEpoch: 9,
      });
    expect(pinned.map((args) => args.selectionContext)).toEqual([
      {},
      { expectedToken: "a".repeat(64) },
      { expectedToken: "a".repeat(64) },
    ]);
    if (where === "cursor")
      expect(requests.at(-1)).toEqual({ cursor: "next-placement-page" });
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(cancel).toHaveBeenCalledOnce();
  },
);

it("keeps keyboard cancel and focus return through a denied hierarchy read without reporting empty", async () => {
  installApi();
  const delegate = globalThis.fetch;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init) =>
      JSON.parse(String(init?.body)).program.function ===
      "metadata.member.select"
        ? new Response(
            JSON.stringify({ error: "METADATA_SELECTION_SCOPE_UNAVAILABLE" }),
            { status: 403 },
          )
        : delegate(url, init),
    ),
  );
  const apply = vi.fn();
  function Harness() {
    const [open, setOpen] = useState(false);
    return (
      <>
        <button onClick={() => setOpen(true)}>Choose entity</button>
        {open && (
          <MemberSelectionDialog
            app={app}
            catalog={catalog()}
            request={scalarRequest}
            members={members}
            onCancel={() => setOpen(false)}
            onApply={apply}
          />
        )}
      </>
    );
  }
  render(<Harness />);
  const trigger = screen.getByRole("button", { name: "Choose entity" });
  trigger.focus();
  fireEvent.click(trigger);
  expect(
    await screen.findByText(
      "Hierarchy browsing is unavailable in this context. Close and reopen the selection to retry.",
    ),
  ).toBeVisible();
  expect(
    screen.queryByText("No placements were returned for this hierarchy."),
  ).toBeNull();
  const cancel = screen.getByRole("button", { name: "Cancel" });
  cancel.focus();
  fireEvent.keyDown(cancel, { key: "Escape" });
  expect(trigger).toHaveFocus();
  expect(apply).not.toHaveBeenCalled();
});

it("loads one pinned authorized hierarchy and applies only the right-pane member", async () => {
  const calls = installApi();
  const onApply = vi.fn();
  render(
    <MemberSelectionDialog
      app={app}
      catalog={catalog()}
      request={scalarRequest}
      members={members}
      onCancel={vi.fn()}
      onApply={onApply}
    />,
  );

  const dialog = screen.getByRole("dialog", {
    name: "Choose one Entity member",
  });
  await within(dialog).findByText("Primary hierarchy");
  expect(
    within(dialog).getByRole("region", { name: "Selected Entity member" }),
  ).toHaveTextContent("Switzerland");
  const germany = await within(dialog).findByRole("button", {
    name: /Germany/,
  });
  expect(within(dialog).queryByRole("checkbox")).toBeNull();
  fireEvent.click(germany);
  expect(
    within(dialog).getByRole("region", { name: "Selected Entity member" }),
  ).not.toHaveTextContent("Germany");
  fireEvent.click(
    within(dialog).getByRole("button", { name: "Add selected member" }),
  );
  expect(
    within(dialog).getByRole("region", { name: "Selected Entity member" }),
  ).toHaveTextContent("Germany");
  fireEvent.click(
    within(dialog).getByRole("button", { name: "Apply selection" }),
  );
  expect(onApply).toHaveBeenCalledWith({
    dimensionId: "Entity",
    metadataRevision: 7,
    include: { kind: "member", memberId: "DE" },
    exclude: null,
    displaySummary: "Germany",
  });
  await waitFor(() =>
    expect(
      calls.find((call) => call.functionName === "metadata.hierarchy.list")
        ?.arguments,
    ).toMatchObject({ dimensionId: "Entity", expectedMetadataRevision: 7 }),
  );
});

it("returns focus to the caller after the modal closes", async () => {
  installApi();
  function Harness() {
    const [open, setOpen] = useState(false);
    return (
      <>
        <button type="button" onClick={() => setOpen(true)}>
          Choose entity
        </button>
        {open && (
          <MemberSelectionDialog
            app={app}
            catalog={catalog()}
            request={scalarRequest}
            members={members}
            onCancel={() => setOpen(false)}
            onApply={() => setOpen(false)}
          />
        )}
      </>
    );
  }
  render(<Harness />);
  const trigger = screen.getByRole("button", { name: "Choose entity" });
  trigger.focus();
  fireEvent.click(trigger);
  expect(
    await screen.findByRole("button", { name: "Close member selection" }),
  ).toHaveFocus();
  fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(trigger).toHaveFocus();
});

it("supports native base-member filtering without changing the pending member", async () => {
  installApi();
  render(
    <MemberSelectionDialog
      app={app}
      catalog={catalog()}
      request={scalarRequest}
      members={members}
      onCancel={vi.fn()}
      onApply={vi.fn()}
    />,
  );
  const dialog = screen.getByRole("dialog");
  await within(dialog).findByText("Primary hierarchy");
  expect(
    await within(dialog).findByRole("button", { name: "Entity top" }),
  ).toBeInTheDocument();
  fireEvent.click(
    await within(dialog).findByRole("button", { name: "All base members" }),
  );
  expect(
    await within(dialog).findByText(
      "All base members: 2 members loaded · complete result",
    ),
  ).toBeInTheDocument();
  const available = within(dialog).getByRole("region", {
    name: "Available Entity members",
  });
  expect(
    within(available).getByRole("button", { name: /Switzerland/ }),
  ).toBeInTheDocument();
  expect(
    within(available).getByRole("button", { name: /Germany/ }),
  ).toBeInTheDocument();
  expect(
    within(dialog).getByRole("region", { name: "Selected Entity member" }),
  ).toHaveTextContent("Switzerland");
});

it("reads and verifies an exact saved member-list definition before evaluation", async () => {
  const calls: string[] = [];
  const list = {
    listId: "swiss-and-german",
    stateToken: "b".repeat(64),
    dimensionId: "Entity",
    name: "Swiss and German entities",
    definition: null,
    canonicalDigest: "c".repeat(64),
    status: "Active",
    active: true,
    executable: true,
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      const functionName = body.program.function as string;
      calls.push(functionName);
      if (functionName === "metadata.member_list.list")
        return response({
          memberLists: [list],
          nextAfterListId: null,
          collectionToken: "d".repeat(64),
        });
      if (functionName === "metadata.member_list.read")
        return response({
          ...list,
          definition: { operator: "explicit", parameters: [] },
          currentMetadataRevision: 7,
          policyRevision: 2,
        });
      if (functionName === "metadata.member_list.evaluate")
        return response({
          listId: list.listId,
          stateToken: list.stateToken,
          dimensionId: "Entity",
          memberIds: ["CH", "DE"],
          memberCount: 2,
          canonicalDigest: list.canonicalDigest,
          metadataRevision: 7,
        });
      throw new Error(`Unexpected function ${functionName}`);
    }),
  );
  const listCatalog: ApplicationCatalog = {
    ...catalog(),
    functions: Object.fromEntries(
      [
        "metadata.member_list.list",
        "metadata.member_list.read",
        "metadata.member_list.evaluate",
      ].map((name) => [name, {}]),
    ),
  };
  render(
    <MemberSelectionDialog
      app={app}
      catalog={listCatalog}
      request={scalarRequest}
      members={members}
      onCancel={vi.fn()}
      onApply={vi.fn()}
    />,
  );

  const dialog = screen.getByRole("dialog");
  fireEvent.click(
    await within(dialog).findByRole("button", { name: "Member lists" }),
  );
  fireEvent.click(
    await within(dialog).findByRole("button", {
      name: /Swiss and German entities/,
    }),
  );
  expect(
    await within(dialog).findByText("2 available members"),
  ).toBeInTheDocument();
  expect(calls).toEqual([
    "metadata.member_list.list",
    "metadata.member_list.read",
    "metadata.member_list.evaluate",
  ]);
});

it("preserves an ordered multi-member basket and rejects duplicate additions", async () => {
  installApi();
  const onApply = vi.fn();
  render(
    <MemberSelectionDialog
      app={app}
      catalog={catalog()}
      request={multiRequest}
      members={members}
      onCancel={vi.fn()}
      onApply={onApply}
    />,
  );

  const dialog = screen.getByRole("dialog", {
    name: "Choose reporting entities",
  });
  await within(dialog).findByText("Primary hierarchy");
  const germany = await within(dialog).findByRole("checkbox", {
    name: /^Check Germany ·/,
  });
  const anchor = within(dialog).getByRole("button", {
    name: /^Use Germany as starting point/,
  });
  const transfer = within(dialog).getByRole("button", {
    name: "Add checked members",
  });
  fireEvent.click(anchor);
  fireEvent.doubleClick(anchor);
  expect(transfer).toBeDisabled();
  fireEvent.click(germany);
  fireEvent.click(transfer);
  expect(germany).toBeDisabled();
  expect(transfer).toBeDisabled();
  const selected = within(dialog).getByRole("region", {
    name: "Selected Entity members",
  });
  expect(within(selected).getAllByRole("article")).toHaveLength(2);
  fireEvent.click(
    within(selected).getByRole("button", { name: "Move Germany up" }),
  );
  fireEvent.click(
    within(dialog).getByRole("button", { name: "Apply selection" }),
  );
  expect(onApply).toHaveBeenCalledWith({
    dimensionId: "Entity",
    metadataRevision: 7,
    include: { kind: "members", memberIds: ["DE", "CH"] },
    exclude: null,
    displaySummary: "Germany, Switzerland",
  });
});

it("transfers checked parents and leaves as one ordered set of explicit members", async () => {
  installApi();
  const onApply = vi.fn();
  render(
    <MemberSelectionDialog
      app={app}
      catalog={catalog()}
      request={{ ...multiRequest, initial: null }}
      members={members}
      onCancel={vi.fn()}
      onApply={onApply}
    />,
  );
  const dialog = within(screen.getByRole("dialog"));
  const tree = within(
    await dialog.findByRole("list", { name: "Hierarchy members" }),
  );
  const leaf = await tree.findByRole("checkbox", { name: /^Check Germany ·/ });
  const parent = tree.getByRole("checkbox", { name: /^Check Europe ·/ });
  const selected = within(
    dialog.getByRole("region", {
      name: "Selected Entity members",
    }),
  );
  fireEvent.click(leaf);
  fireEvent.click(parent);
  expect(leaf).toBeChecked();
  expect(parent).toBeChecked();
  expect(selected.queryByRole("article")).toBeNull();

  fireEvent.click(dialog.getByRole("button", { name: "Add checked members" }));
  expect(leaf).toBeDisabled();
  expect(parent).toBeDisabled();
  expect(selected.getAllByRole("article")).toHaveLength(2);
  fireEvent.click(dialog.getByRole("button", { name: "Apply selection" }));
  expect(onApply).toHaveBeenCalledWith({
    dimensionId: "Entity",
    metadataRevision: 7,
    include: { kind: "members", memberIds: ["DE", "Europe"] },
    exclude: null,
    displaySummary: "Germany, Europe",
  });
});

it("keeps the checked set intact when the batch exceeds the selection limit", async () => {
  installApi();
  render(
    <MemberSelectionDialog
      app={app}
      catalog={catalog()}
      request={{
        ...multiRequest,
        cardinality: { kind: "one-or-more", maximum: 2 },
      }}
      members={members}
      onCancel={vi.fn()}
      onApply={vi.fn()}
    />,
  );
  const dialog = within(screen.getByRole("dialog"));
  const tree = within(
    await dialog.findByRole("list", { name: "Hierarchy members" }),
  );
  const leaf = await tree.findByRole("checkbox", { name: /^Check Germany ·/ });
  const parent = tree.getByRole("checkbox", { name: /^Check Europe ·/ });
  fireEvent.click(leaf);
  fireEvent.click(parent);
  const transfer = dialog.getByRole("button", { name: "Add checked members" });
  fireEvent.click(transfer);
  expect(dialog.getByRole("alert")).toHaveTextContent(
    "Select no more than 2 members.",
  );
  expect(leaf).toBeChecked();
  expect(parent).toBeChecked();
  const selected = within(
    dialog.getByRole("region", {
      name: "Selected Entity members",
    }),
  );
  expect(selected.getAllByRole("article")).toHaveLength(1);

  fireEvent.click(leaf);
  fireEvent.click(transfer);
  expect(selected.getAllByRole("article")).toHaveLength(2);
  expect(selected.queryByText("Germany")).toBeNull();
});

it("returns a symbolic hierarchy selector only when the caller allows it", async () => {
  installApi();
  const onApply = vi.fn();
  render(
    <MemberSelectionDialog
      app={app}
      catalog={catalog()}
      request={multiRequest}
      members={members}
      onCancel={vi.fn()}
      onApply={onApply}
    />,
  );

  const dialog = screen.getByRole("dialog");
  await within(dialog).findByText("Primary hierarchy");
  fireEvent.click(
    await within(dialog).findByRole("button", {
      name: /^Use Europe as starting point/,
    }),
  );
  fireEvent.click(within(dialog).getByRole("button", { name: "Descendants" }));
  fireEvent.click(
    await within(dialog).findByRole("button", {
      name: "Replace selection with this dynamic rule",
    }),
  );
  fireEvent.click(
    within(dialog).getByRole("button", {
      name: "Replace selection",
    }),
  );
  expect(
    within(dialog).getByRole("region", { name: "Selected Entity members" }),
  ).toHaveTextContent("Descendants · Europe · Primary hierarchy");
  fireEvent.click(
    within(dialog).getByRole("button", { name: "Apply selection" }),
  );
  expect(onApply).toHaveBeenCalledWith({
    dimensionId: "Entity",
    metadataRevision: 7,
    include: {
      kind: "inline_expression",
      expressionFormat: "openepm-member-list-expression-v1",
      expression: {
        kind: "navigation",
        operation: "descendants",
        scope: "hierarchy",
        hierarchyId: "primary",
        anchor: { memberId: "Europe", pathRelationshipIds: ["world-europe"] },
        includeSelf: false,
        allParents: false,
      },
    },
    exclude: null,
    displaySummary:
      "Descendants · Europe · Primary hierarchy · placement All Entities (World) / Europe (Europe) [world-europe]",
  });
});

it("collects typed saved-list parameters and preserves the dynamic selector", async () => {
  const calls: Array<{
    functionName: string;
    arguments: Record<string, unknown>;
  }> = [];
  const list = {
    listId: "regional-entities",
    stateToken: "b".repeat(64),
    dimensionId: "Entity",
    name: "Regional entities",
    definition: null,
    canonicalDigest: "c".repeat(64),
    status: "Active",
    active: true,
    executable: true,
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      const functionName = body.program.function as string;
      calls.push({ functionName, arguments: body.program.arguments });
      if (functionName === "metadata.member_list.list")
        return response({
          memberLists: [list],
          nextAfterListId: null,
          collectionToken: "d".repeat(64),
        });
      if (functionName === "metadata.member_list.read")
        return response({
          ...list,
          definition: {
            parameters: [
              {
                name: "Year",
                type: "String",
                required: true,
              },
              {
                name: "IncludeInactive",
                type: "Boolean",
                required: false,
              },
            ],
          },
          currentMetadataRevision: 7,
          policyRevision: 2,
        });
      if (functionName === "metadata.member_list.evaluate")
        return response({
          listId: list.listId,
          stateToken: list.stateToken,
          dimensionId: "Entity",
          memberIds: ["CH", "DE"],
          memberCount: 2,
          canonicalDigest: list.canonicalDigest,
          metadataRevision: 7,
        });
      throw new Error(`Unexpected function ${functionName}`);
    }),
  );
  const listCatalog: ApplicationCatalog = {
    ...catalog(),
    functions: Object.fromEntries(
      [
        "metadata.member_list.list",
        "metadata.member_list.read",
        "metadata.member_list.evaluate",
      ].map((name) => [name, {}]),
    ),
  };
  const onApply = vi.fn();
  render(
    <MemberSelectionDialog
      app={app}
      catalog={listCatalog}
      request={multiRequest}
      members={members}
      onCancel={vi.fn()}
      onApply={onApply}
    />,
  );

  const dialog = screen.getByRole("dialog");
  fireEvent.click(
    await within(dialog).findByRole("button", { name: "Member lists" }),
  );
  fireEvent.click(
    await within(dialog).findByRole("button", { name: /Regional entities/ }),
  );
  fireEvent.change(await within(dialog).findByLabelText(/Year/), {
    target: { value: "FY26" },
  });
  fireEvent.change(within(dialog).getByLabelText(/IncludeInactive/), {
    target: { value: "true" },
  });
  fireEvent.click(
    within(dialog).getByRole("button", { name: "Preview members" }),
  );
  await within(dialog).findByText("2 available members");
  expect(calls.at(-1)).toEqual({
    functionName: "metadata.member_list.evaluate",
    arguments: {
      listId: "regional-entities",
      parameters: { Year: "FY26", IncludeInactive: true },
      expectedMetadataRevision: 7,
    },
  });
  fireEvent.click(
    within(dialog).getByRole("button", {
      name: "Use dynamic member list",
    }),
  );
  fireEvent.click(
    within(dialog).getByRole("button", {
      name: "Replace selection",
    }),
  );
  fireEvent.click(
    within(dialog).getByRole("button", { name: "Apply selection" }),
  );
  expect(onApply).toHaveBeenCalledWith({
    dimensionId: "Entity",
    metadataRevision: 7,
    include: {
      kind: "member_list",
      listId: "regional-entities",
      parameters: { IncludeInactive: true, Year: "FY26" },
    },
    exclude: null,
    displaySummary:
      'Regional entities · parameters {"IncludeInactive":true,"Year":"FY26"}',
  });
});

it("reviews hidden checks and removes only checked members from the selected pane", async () => {
  installApi();
  const onApply = vi.fn();
  render(
    <MemberSelectionDialog
      app={app}
      catalog={catalog()}
      request={multiRequest}
      members={members}
      onCancel={vi.fn()}
      onApply={onApply}
    />,
  );
  const dialog = within(screen.getByRole("dialog"));
  const selected = within(
    await dialog.findByRole("region", { name: "Selected Entity members" }),
  );
  fireEvent.click(
    await dialog.findByRole("checkbox", { name: /^Check Germany ·/ }),
  );
  fireEvent.click(dialog.getByRole("button", { name: "Search" }));
  fireEvent.change(dialog.getByRole("textbox", { name: "Find a member" }), {
    target: { value: "Europe" },
  });
  fireEvent.click(dialog.getByRole("checkbox", { name: /^Check Europe ·/ }));
  expect(dialog.getByText("2 checked · 1 outside this view")).toBeVisible();
  fireEvent.click(dialog.getByRole("button", { name: "Review checks" }));
  expect(
    dialog.getByRole("button", { name: "Uncheck Germany (DE)" }),
  ).toBeVisible();
  fireEvent.click(dialog.getByRole("button", { name: "Add checked members" }));
  expect(
    selected.getAllByRole("article").map((row) => row.dataset.memberId),
  ).toEqual(["CH", "DE", "Europe"]);
  fireEvent.click(selected.getByRole("checkbox", { name: /Mark Europe/ }));
  fireEvent.click(selected.getByRole("checkbox", { name: /Mark Switzerland/ }));
  fireEvent.click(
    dialog.getByRole("button", { name: "Remove checked members" }),
  );
  expect(
    selected.getAllByRole("article").map((row) => row.dataset.memberId),
  ).toEqual(["DE"]);
  fireEvent.click(dialog.getByRole("button", { name: "Apply selection" }));
  expect(onApply).toHaveBeenCalledOnce();
  expect(onApply).toHaveBeenCalledWith(
    expect.objectContaining({
      include: { kind: "members", memberIds: ["DE"] },
    }),
  );
});

it.each([false, true])(
  "collects all result pages atomically or rejects overlapping pages (%s)",
  async (overlap) => {
    installApi();
    const baseFetch = globalThis.fetch;
    const calls: string[] = [];
    const page = (id: string, nextCursor: string | null) => ({
      selectionContextToken: "a".repeat(64),
      dimensionId: "Entity",
      metadataRevision: 7,
      resultKind: "unique_member",
      scope: {
        kind: "scope",
        dimensionId: "Entity",
        scope: "hierarchy",
        hierarchyId: "primary",
        name: "Entity",
        businessCoordinate: false,
      },
      rows: [
        { memberId: id, name: id, status: "Active", shortDescription: "" },
      ],
      nextCursor,
      hasMore: nextCursor !== null,
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const args = JSON.parse(String(init?.body)).program.arguments;
        if (args.expression?.operation === "leaves")
          return response(page("DE", "second"));
        if (args.cursor) {
          calls.push(args.cursor);
          return response(
            args.cursor === "second"
              ? page("Europe", "third")
              : page(overlap ? "DE" : "World", null),
          );
        }
        return baseFetch(input, init);
      }),
    );
    render(
      <MemberSelectionDialog
        app={app}
        catalog={catalog()}
        request={multiRequest}
        members={members}
        onCancel={vi.fn()}
        onApply={vi.fn()}
      />,
    );
    const dialog = within(screen.getByRole("dialog"));
    const selected = within(
      await dialog.findByRole("region", { name: "Selected Entity members" }),
    );
    fireEvent.click(
      await dialog.findByRole("button", { name: "All base members" }),
    );
    fireEvent.click(
      await dialog.findByRole("button", { name: "Add all results" }),
    );
    await waitFor(() => expect(calls).toEqual(["second", "third"]));
    await waitFor(() =>
      expect(
        selected.getAllByRole("article").map((row) => row.dataset.memberId),
      ).toEqual(overlap ? ["CH"] : ["CH", "DE", "Europe", "World"]),
    );
    if (overlap)
      expect(dialog.getByRole("alert")).toHaveTextContent(
        "invalid or repeated member",
      );
  },
);

it("requires a deliberate conversion before changing a dynamic draft to a fixed list", async () => {
  installApi();
  const onApply = vi.fn();
  render(
    <MemberSelectionDialog
      app={app}
      catalog={catalog()}
      request={{
        ...multiRequest,
        initial: {
          kind: "inline_expression",
          expressionFormat: "openepm-member-list-expression-v1",
          expression: {
            kind: "navigation",
            operation: "leaves",
            scope: "hierarchy",
            hierarchyId: "primary",
            anchor: null,
            includeSelf: false,
            allParents: false,
          },
        },
      }}
      members={members}
      onCancel={vi.fn()}
      onApply={onApply}
    />,
  );
  const dialog = within(screen.getByRole("dialog"));
  expect(
    await dialog.findByRole("checkbox", { name: /^Check Germany ·/ }),
  ).toBeDisabled();
  fireEvent.click(
    dialog.getByRole("button", {
      name: "Convert current results to explicit members",
    }),
  );
  fireEvent.click(
    dialog.getByRole("button", { name: "Keep current selection" }),
  );
  expect(
    dialog.getByText("Dynamic selection · evaluated when used"),
  ).toBeVisible();
  fireEvent.click(
    dialog.getByRole("button", {
      name: "Convert current results to explicit members",
    }),
  );
  fireEvent.click(
    dialog.getByRole("button", { name: "Convert to explicit members" }),
  );
  const selected = within(
    dialog.getByRole("region", { name: "Selected Entity members" }),
  );
  await waitFor(() =>
    expect(
      selected.getAllByRole("article").map((row) => row.dataset.memberId),
    ).toEqual(["DE", "CH"]),
  );
  fireEvent.click(dialog.getByRole("button", { name: "Apply selection" }));
  expect(onApply).toHaveBeenCalledWith(
    expect.objectContaining({
      include: { kind: "members", memberIds: ["DE", "CH"] },
    }),
  );
});

it("ignores a saved-list response that arrives after a newer list was opened", async () => {
  installApi();
  const baseFetch = globalThis.fetch;
  const list = (listId: string, name: string) => ({
    listId,
    name,
    dimensionId: "Entity",
    active: true,
    executable: true,
    stateToken: "a".repeat(64),
    canonicalDigest: "b".repeat(64),
    definition: { parameters: [] },
    currentMetadataRevision: 7,
    policyRevision: 2,
  });
  const first = list("first", "First business list");
  const second = list("second", "Second business list");
  let releaseFirst!: (value: Response) => void;
  const delayed = new Promise<Response>((resolve) => {
    releaseFirst = resolve;
  });
  let firstSignal: AbortSignal | undefined;
  const evaluated = (item: typeof first, memberId: string) =>
    response({
      listId: item.listId,
      stateToken: item.stateToken,
      canonicalDigest: item.canonicalDigest,
      dimensionId: item.dimensionId,
      memberIds: [memberId],
      memberCount: 1,
      metadataRevision: 7,
    });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const program = JSON.parse(String(init?.body)).program;
      if (program.function === "metadata.member_list.list")
        return response({
          memberLists: [first, second],
          nextAfterListId: null,
          collectionToken: "c".repeat(64),
        });
      if (program.function === "metadata.member_list.read")
        return response(
          program.arguments.listId === first.listId ? first : second,
        );
      if (program.function === "metadata.member_list.evaluate") {
        if (program.arguments.listId === first.listId) {
          firstSignal = init?.signal ?? undefined;
          return delayed;
        }
        return evaluated(second, "DE");
      }
      return baseFetch(input, init);
    }),
  );
  const base = catalog();
  render(
    <MemberSelectionDialog
      app={app}
      catalog={{
        ...base,
        functions: {
          ...base.functions,
          "metadata.member_list.list": {},
          "metadata.member_list.read": {},
          "metadata.member_list.evaluate": {},
        },
      }}
      request={multiRequest}
      members={members}
      onCancel={vi.fn()}
      onApply={vi.fn()}
    />,
  );
  const dialog = within(screen.getByRole("dialog"));
  fireEvent.click(await dialog.findByRole("button", { name: "Member lists" }));
  fireEvent.click(dialog.getByRole("button", { name: /^First business list/ }));
  await waitFor(() => expect(firstSignal).toBeDefined());
  fireEvent.click(
    dialog.getByRole("button", { name: /^Second business list/ }),
  );
  await dialog.findByRole("checkbox", { name: /^Check Germany ·/ });
  await act(async () => releaseFirst(evaluated(first, "CH")));
  expect(firstSignal?.aborted).toBe(true);
  expect(
    dialog.getByRole("checkbox", { name: /^Check Germany ·/ }),
  ).toBeVisible();
  expect(
    dialog.queryByRole("checkbox", { name: /^Check Switzerland ·/ }),
  ).toBeNull();
});

it("keeps authorized hierarchy selection available when policy refuses the saved catalogue", async () => {
  installApi();
  const baseFetch = globalThis.fetch;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const program = JSON.parse(String(init?.body)).program;
      if (program.function === "metadata.member_list.list")
        return new Response(
          JSON.stringify({
            code: "MEMBER_LIST_SCOPE_UNAVAILABLE",
            message:
              "The saved selections catalogue is unavailable under your current dimensional access.",
          }),
          { status: 403 },
        );
      return baseFetch(input, init);
    }),
  );
  const base = catalog();
  const onApply = vi.fn();
  render(
    <MemberSelectionDialog
      app={app}
      catalog={{
        ...base,
        functions: { ...base.functions, "metadata.member_list.list": {} },
      }}
      request={multiRequest}
      members={members}
      onCancel={vi.fn()}
      onApply={onApply}
    />,
  );
  const dialog = within(screen.getByRole("dialog"));
  const lists = await dialog.findByRole("button", { name: "Member lists" });
  await waitFor(() => expect(lists).toBeEnabled());
  fireEvent.click(lists);
  await dialog.findByText(
    /catalogue is unavailable under your current dimensional access/,
  );
  const apply = dialog.getByRole("button", { name: "Apply selection" });
  expect(apply).toBeEnabled();
  fireEvent.click(apply);
  expect(onApply).toHaveBeenCalledWith(
    expect.objectContaining({
      include: { kind: "members", memberIds: ["CH"] },
    }),
  );
});

it("invalidates a pending native result when the metadata revision changes", async () => {
  installApi();
  const baseFetch = globalThis.fetch;
  let resolvePreview!: (value: Response) => void;
  const delayed = new Promise<Response>((resolve) => {
    resolvePreview = resolve;
  });
  let previewSignal: AbortSignal | null | undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const args = JSON.parse(String(init?.body)).program.arguments;
      if (args.expression?.operation === "leaves") {
        previewSignal = init?.signal;
        return delayed;
      }
      return baseFetch(input, init);
    }),
  );
  const onApply = vi.fn();
  const base = catalog();
  const picker = (catalog: ApplicationCatalog) => (
    <MemberSelectionDialog
      app={app}
      catalog={catalog}
      request={multiRequest}
      members={members}
      onCancel={vi.fn()}
      onApply={onApply}
    />
  );
  const { rerender } = render(picker(base));
  const dialog = within(screen.getByRole("dialog"));
  fireEvent.click(
    await dialog.findByRole("button", { name: "All base members" }),
  );
  await waitFor(() => expect(previewSignal).toBeDefined());
  rerender(picker({ ...base, revisions: { ...base.revisions, metadata: 8 } }));
  expect(
    dialog.getByRole("button", { name: "Apply selection" }),
  ).toBeDisabled();
  await act(async () => resolvePreview(response({ rows: [] })));
  expect(previewSignal?.aborted).toBe(true);
  expect(
    dialog.queryByRole("region", { name: "Selected Entity members" }),
  ).toBeNull();
  expect(dialog.getByText(/Metadata changed. Reopen the picker/)).toBeVisible();
  expect(onApply).not.toHaveBeenCalled();
});

it("keeps Escape reachable when clearing the selected pane removes its focused control", async () => {
  installApi();
  const cancel = vi.fn();
  render(
    <MemberSelectionDialog
      app={app}
      catalog={catalog()}
      request={multiRequest}
      members={members}
      onCancel={cancel}
      onApply={vi.fn()}
    />,
  );
  const dialog = screen.getByRole("dialog");
  const clear = await within(dialog).findByRole("button", {
    name: "Clear selection",
  });
  clear.focus();
  fireEvent.click(clear);
  expect(
    within(dialog).getByRole("button", { name: "Close member selection" }),
  ).toHaveFocus();
  fireEvent.keyDown(document.activeElement!, { key: "Escape" });
  expect(cancel).toHaveBeenCalledOnce();
});

it.each(["unchanged", "application", "identity", "grant", "metadata"] as const)(
  "preserves the first interactive member choice and still invalidates it for %s context",
  async (change) => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    let clicked = false;
    let currentApp = app;
    let currentCatalog: ApplicationCatalog = {
      ...catalog(),
      functions: {},
      applicationAccess: {
        ...catalog().applicationAccess,
        issuer: "issuer",
        subjectId: "actor-one",
      },
    };
    const applied = vi.fn();
    const element = () => (
      <Profiler
        id="first-ready-member-choice"
        onRender={() => {
          if (clicked) return;
          const choice = screen.queryByRole("button", {
            name: /Germany/,
          }) as HTMLButtonElement | null;
          if (!clicked && choice && !choice.disabled) {
            clicked = true;
            choice.click();
          }
        }}
      >
        <MemberSelectionDialog
          app={currentApp}
          catalog={currentCatalog}
          request={{ ...scalarRequest, initial: null }}
          members={members}
          onApply={applied}
          onCancel={() => undefined}
        />
      </Profiler>
    );
    const view = render(element());
    expect(clicked).toBe(true);
    expect(screen.getByRole("button", { name: /Germany/ })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    const add = screen.getByRole("button", { name: "Add selected member" });
    expect(add).toBeEnabled();
    if (change === "unchanged") {
      fireEvent.click(add);
      const apply = screen.getByRole("button", { name: "Apply selection" });
      expect(apply).toBeEnabled();
      fireEvent.click(apply);
      expect(applied).toHaveBeenCalledExactlyOnceWith(
        expect.objectContaining({
          dimensionId: "Entity",
          metadataRevision: 7,
          include: { kind: "member", memberId: "DE" },
        }),
      );
    } else {
      if (change === "application")
        currentApp = { ...currentApp, applicationId: "another" };
      if (change === "identity")
        currentCatalog = {
          ...currentCatalog,
          applicationAccess: {
            ...currentCatalog.applicationAccess,
            subjectId: "actor-two",
          },
        };
      if (change === "grant")
        currentCatalog = {
          ...currentCatalog,
          revisions: { ...currentCatalog.revisions, security: 4 },
        };
      if (change === "metadata")
        currentCatalog = {
          ...currentCatalog,
          revisions: { ...currentCatalog.revisions, metadata: 8 },
        };
      view.rerender(element());
      if (change === "metadata")
        expect(
          screen.queryByRole("button", { name: "Add selected member" }),
        ).not.toBeInTheDocument();
      else
        expect(
          screen.getByRole("button", { name: "Add selected member" }),
        ).toBeDisabled();
      expect(
        screen.getByRole("button", { name: "Apply selection" }),
      ).toBeDisabled();
      expect(applied).not.toHaveBeenCalled();
    }
    expect(fetch).not.toHaveBeenCalled();
  },
);

it.each(["native-only", "discovery-flat"] as const)(
  "does not advertise a member choice before %s native initialization finishes",
  async (mode) => {
    installApi();
    const originalFetch = globalThis.fetch;
    let releaseTop!: () => void;
    const topGate = new Promise<void>((resolve) => {
      releaseTop = resolve;
    });
    let topStarted = false;
    let topReleased = false;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const program = JSON.parse(String(init?.body)).program;
        if (program.function === "metadata.hierarchy.list")
          return response({
            dimensionId: "Entity",
            metadataRevision: 7,
            rows: [],
            hasMore: false,
            nextAfterId: null,
          });
        if (
          program.function === "metadata.member.select" &&
          program.arguments.expression.operation === "top"
        ) {
          topStarted = true;
          await topGate;
        }
        return originalFetch(input, init);
      }),
    );
    let clicked = false;
    let clickedBeforeReady = false;
    const applied = vi.fn();
    render(
      <Profiler
        id="native-first-ready"
        onRender={() => {
          if (clicked) return;
          const available = screen.queryByRole("region", {
            name: "Available Entity members",
          });
          const choice = available
            ? (within(available).queryByRole("button", {
                name: /Germany/,
              }) as HTMLButtonElement | null)
            : null;
          if (choice && !choice.disabled) {
            clicked = true;
            clickedBeforeReady = !topReleased;
            choice.click();
          }
        }}
      >
        <MemberSelectionDialog
          app={app}
          catalog={{
            ...catalog(),
            functions: {
              "metadata.member.select": {},
              ...(mode === "discovery-flat"
                ? { "metadata.hierarchy.list": {} }
                : {}),
            },
          }}
          request={{ ...scalarRequest, initial: null }}
          members={members}
          onApply={applied}
          onCancel={() => undefined}
        />
      </Profiler>,
    );
    await waitFor(() => expect(topStarted).toBe(true));
    await act(async () => {
      topReleased = true;
      releaseTop();
    });
    await waitFor(() => expect(clicked).toBe(true));
    expect(clickedBeforeReady).toBe(false);
    const available = within(
      screen.getByRole("region", { name: "Available Entity members" }),
    );
    expect(available.getByRole("button", { name: /Germany/ })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    const add = screen.getByRole("button", { name: "Add selected member" });
    expect(add).toBeEnabled();
    fireEvent.click(add);
    const apply = screen.getByRole("button", { name: "Apply selection" });
    expect(apply).toBeEnabled();
    fireEvent.click(apply);
    expect(applied).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ include: { kind: "member", memberId: "DE" } }),
    );
  },
);

it("waits for the replacement native hierarchy before accepting its first member choice and preserves the selected set", async () => {
  installApi();
  const originalFetch = globalThis.fetch;
  let releaseTop!: () => void;
  const topGate = new Promise<void>((resolve) => {
    releaseTop = resolve;
  });
  let replacementStarted = false;
  let replacementReleased = false;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const program = JSON.parse(String(init?.body)).program;
      const result = await originalFetch(input, init);
      if (program.function === "metadata.hierarchy.list") {
        const body = await result.json();
        body.result.rows.push({
          ...body.result.rows[0],
          hierarchyId: "secondary",
          name: "Secondary hierarchy",
          isDefault: false,
        });
        return response(body.result);
      }
      if (
        program.function === "metadata.member.select" &&
        program.arguments.expression.hierarchyId === "secondary" &&
        program.arguments.expression.operation === "top"
      ) {
        replacementStarted = true;
        await topGate;
      }
      return result;
    }),
  );
  let clicked = false;
  let clickedBeforeReady = false;
  const applied = vi.fn();
  render(
    <Profiler
      id="replacement-first-ready"
      onRender={() => {
        if (clicked) return;
        const hierarchy = screen.queryByRole("combobox", {
          name: "Hierarchy",
        }) as HTMLSelectElement | null;
        if (hierarchy?.value !== "secondary") return;
        const available = screen.queryByRole("region", {
          name: "Available Entity members",
        });
        const choice = available
          ? (within(available).queryByRole("button", {
              name: /Germany/,
            }) as HTMLButtonElement | null)
          : null;
        if (choice && !choice.disabled) {
          clicked = true;
          clickedBeforeReady = !replacementReleased;
          choice.click();
        }
      }}
    >
      <MemberSelectionDialog
        app={app}
        catalog={catalog()}
        request={scalarRequest}
        members={members}
        onApply={applied}
        onCancel={() => undefined}
      />
    </Profiler>,
  );
  const available = within(
    await screen.findByRole("region", { name: "Available Entity members" }),
  );
  const initialChoice = await available.findByRole("button", {
    name: /^Europe/,
  });
  fireEvent.click(initialChoice);
  expect(initialChoice).toHaveAttribute("aria-pressed", "true");
  fireEvent.change(screen.getByRole("combobox", { name: "Hierarchy" }), {
    target: { value: "secondary" },
  });
  await waitFor(() => expect(replacementStarted).toBe(true));
  expect(
    within(
      screen.getByRole("region", { name: "Selected Entity member" }),
    ).getByText("Switzerland"),
  ).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Add selected member" }),
  ).toBeDisabled();
  await act(async () => {
    replacementReleased = true;
    releaseTop();
  });
  await waitFor(() => expect(clicked).toBe(true));
  expect(clickedBeforeReady).toBe(false);
  expect(available.getByRole("button", { name: /Germany/ })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  expect(available.getByRole("button", { name: /^Europe/ })).toHaveAttribute(
    "aria-pressed",
    "false",
  );
  const add = screen.getByRole("button", { name: "Add selected member" });
  expect(add).toBeEnabled();
  fireEvent.click(add);
  fireEvent.click(screen.getByRole("button", { name: "Apply selection" }));
  expect(applied).toHaveBeenCalledExactlyOnceWith(
    expect.objectContaining({ include: { kind: "member", memberId: "DE" } }),
  );
});

it.each(["success", "denied"] as const)(
  "rejects a late %s from a departed native hierarchy without clearing the current choice",
  async (outcome) => {
    installApi();
    const originalFetch = globalThis.fetch;
    let releasePrior!: () => void;
    const priorGate = new Promise<void>((resolve) => {
      releasePrior = resolve;
    });
    let priorSignal: AbortSignal | null = null;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const program = JSON.parse(String(init?.body)).program;
        const result = await originalFetch(input, init);
        if (program.function === "metadata.hierarchy.list") {
          const body = await result.json();
          body.result.rows.push({
            ...body.result.rows[0],
            hierarchyId: "secondary",
            name: "Secondary hierarchy",
            isDefault: false,
          });
          return response(body.result);
        }
        if (
          program.function === "metadata.member.select" &&
          program.arguments.expression.hierarchyId === "primary" &&
          program.arguments.expression.operation === "top"
        ) {
          priorSignal = init?.signal as AbortSignal;
          await priorGate;
          if (outcome === "denied")
            return new Response(
              JSON.stringify({ error: "OLD_HIERARCHY_DENIED" }),
              { status: 403, headers: { "Content-Type": "application/json" } },
            );
          const body = await result.json();
          body.result.scope.name = "Departed private scope";
          return response(body.result);
        }
        return result;
      }),
    );
    render(
      <MemberSelectionDialog
        app={app}
        catalog={catalog()}
        request={{ ...scalarRequest, initial: null }}
        members={members}
        onApply={vi.fn()}
        onCancel={() => undefined}
      />,
    );
    await waitFor(() => expect(priorSignal).not.toBeNull());
    fireEvent.change(screen.getByRole("combobox", { name: "Hierarchy" }), {
      target: { value: "secondary" },
    });
    const available = within(
      screen.getByRole("region", { name: "Available Entity members" }),
    );
    const germany = await available.findByRole("button", { name: /Germany/ });
    expect(germany).toBeEnabled();
    fireEvent.click(germany);
    expect(germany).toHaveAttribute("aria-pressed", "true");
    expect(priorSignal!.aborted).toBe(true);
    await act(async () => {
      releasePrior();
    });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(
      screen.queryByText(/Departed private scope/),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Hierarchy" })).toHaveValue(
      "secondary",
    );
    expect(available.getByRole("button", { name: /Germany/ })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(
      screen.getByRole("button", { name: "Add selected member" }),
    ).toBeEnabled();
  },
);

it("keeps the authorized flat-member fallback usable after current native initialization fails", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(JSON.stringify({ error: "NATIVE_READ_UNAVAILABLE" }), {
          status: 503,
          headers: { "Content-Type": "application/json" },
        }),
    ),
  );
  const applied = vi.fn();
  render(
    <MemberSelectionDialog
      app={app}
      catalog={{ ...catalog(), functions: { "metadata.member.select": {} } }}
      request={{ ...scalarRequest, initial: null }}
      members={members}
      onApply={applied}
      onCancel={() => undefined}
    />,
  );
  await screen.findByRole("alert");
  const germany = screen.getByRole("button", { name: /Germany/ });
  expect(germany).toBeEnabled();
  fireEvent.click(germany);
  expect(germany).toHaveAttribute("aria-pressed", "true");
  fireEvent.click(screen.getByRole("button", { name: "Add selected member" }));
  fireEvent.click(screen.getByRole("button", { name: "Apply selection" }));
  expect(applied).toHaveBeenCalledExactlyOnceWith(
    expect.objectContaining({ include: { kind: "member", memberId: "DE" } }),
  );
});

it("does not offer loaded members from a departed hierarchy during the replacement commit", async () => {
  installApi();
  const originalFetch = globalThis.fetch;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const program = JSON.parse(String(init?.body)).program;
      const result = await originalFetch(input, init);
      if (program.function === "metadata.hierarchy.list") {
        const body = await result.json();
        body.result.rows.push({
          ...body.result.rows[0],
          hierarchyId: "secondary",
          name: "Secondary hierarchy",
          isDefault: false,
        });
        return response(body.result);
      }
      return result;
    }),
  );
  let checkedTransition = false;
  const readiness: boolean[] = [];
  render(
    <Profiler
      id="departed-loaded-members"
      onRender={() => {
        if (checkedTransition) return;
        const hierarchy = screen.queryByRole("combobox", {
          name: "Hierarchy",
        }) as HTMLSelectElement | null;
        if (hierarchy?.value !== "secondary") return;
        checkedTransition = true;
        for (const name of ["Check 2 loaded results", "Add all results"]) {
          const button = screen.queryByRole("button", {
            name,
          }) as HTMLButtonElement | null;
          readiness.push(button?.disabled ?? true);
          button?.click();
        }
      }}
    >
      <MemberSelectionDialog
        app={app}
        catalog={catalog()}
        request={{ ...multiRequest, initial: null }}
        members={members}
        onApply={vi.fn()}
        onCancel={() => undefined}
      />
    </Profiler>,
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "All base members" }),
  );
  await screen.findByText(
    "All base members: 2 members loaded · complete result",
  );
  expect(
    screen.getByRole("button", { name: "Check 2 loaded results" }),
  ).toBeEnabled();
  expect(screen.getByRole("button", { name: "Add all results" })).toBeEnabled();
  fireEvent.change(screen.getByRole("combobox", { name: "Hierarchy" }), {
    target: { value: "secondary" },
  });
  expect(checkedTransition).toBe(true);
  expect(readiness).toEqual([true, true]);
  await screen.findByText(
    "4 placements loaded · complete result. A shared member can have more than one placement; an explicit selected set keeps each member identity once.",
  );
  const selected = within(
    screen.getByRole("region", { name: "Selected Entity members" }),
  );
  expect(selected.queryByRole("article")).not.toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Add checked members" }),
  ).toBeDisabled();
});
