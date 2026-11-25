import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  MemberLists,
  collectMemberLists,
  memberListArguments,
  memberListMutationBody,
  parseMemberListJson,
} from "./MemberLists";
import { operationAdmissionResponse } from "./test-setup";
import { canonicalProgramDigest } from "./canonical-program-digest";
import {
  discardUnsavedWork,
  resetUnsavedWorkForTests,
  setUnsavedWork,
  unsavedWorkSnapshot,
} from "./unsaved-work";

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
  functions: {
    "metadata.member_list.save": {},
    "metadata.member_list.list": {},
    "metadata.member_list.activate": {},
    "metadata.member_list.deactivate": {},
    "metadata.member_list.delete": {},
    "metadata.member_list.evaluate": {},
  },
  revisions: { metadata: 7, data: 1, policy: 3, security: 1, commit: 4 },
};

afterEach(() => {
  resetUnsavedWorkForTests();
  vi.unstubAllGlobals();
});

it("reads every member list beyond the former catalogue cap", async () => {
  expect(memberListArguments("list-a", "b".repeat(64))).toEqual({
    limit: 100,
    afterListId: "list-a",
    expectedCollectionToken: "b".repeat(64),
  });
  let page = 0;
  const result = await collectMemberLists(async (arguments_) => {
    const current = page++;
    if (current) {
      expect(arguments_.expectedCollectionToken).toBe("b".repeat(64));
    }
    return {
      memberLists: Array.from({ length: 100 }, (_unused, row) => ({
        listId: `list-${current}-${row}`,
        stateToken: "a".repeat(64),
        dimensionId: "Product",
        name: "List",
        definition: {},
        canonicalDigest: "a".repeat(64),
        status: "Saved" as const,
      })),
      nextAfterListId: current === 10 ? null : `cursor-${current + 1}`,
      collectionToken: "b".repeat(64),
    };
  });
  expect(result.rows).toHaveLength(1100);
});

it("rejects malformed, repeated, duplicate, and drifting member-list pages", async () => {
  await expect(
    collectMemberLists(async () => ({
      memberLists: [],
      nextAfterListId: "" as never,
      collectionToken: "b".repeat(64),
    })),
  ).rejects.toThrow("cursor is invalid");
  let page = 0;
  await expect(
    collectMemberLists(async () => ({
      memberLists: [],
      nextAfterListId: page++ < 1 ? "same" : "same",
      collectionToken: "b".repeat(64),
    })),
  ).rejects.toThrow("cursor repeated");
  let duplicatePage = 0;
  await expect(
    collectMemberLists(async () => ({
      memberLists: [
        {
          listId: "same",
          stateToken: "a".repeat(64),
          dimensionId: "Product",
          name: "List",
          definition: {},
          canonicalDigest: "a".repeat(64),
          status: "Saved",
        },
      ],
      nextAfterListId: duplicatePage++ < 1 ? "more" : null,
      collectionToken: "b".repeat(64),
    })),
  ).rejects.toThrow("repeated a row");
  let revisionPage = 0;
  await expect(
    collectMemberLists(async () => ({
      memberLists: [],
      nextAfterListId: revisionPage++ < 1 ? "more" : null,
      collectionToken: (revisionPage === 1 ? "b" : "c").repeat(64),
    })),
  ).rejects.toThrow("changed while reading");
});

it("constructs only the existing confirmed metadata-action envelope", () => {
  expect(
    memberListMutationBody(
      app,
      "metadata.member_list.activate",
      { listId: "active", expectedStateToken: "a".repeat(64) },
      "member-list-123",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "cube",
    program: {
      languageVersion: 2,
      function: "metadata.member_list.activate",
      arguments: { listId: "active", expectedStateToken: "a".repeat(64) },
    },
    idempotencyKey: "member-list-123",
    confirmed: true,
  });
});

it("rejects malformed JSON before any governed request", () => {
  expect(() => parseMemberListJson("[]", "Expression", "object")).toThrow(
    "Expression must be a JSON object.",
  );
  expect(() => parseMemberListJson("{}", "Parameters", "array")).toThrow(
    "Parameters must be a JSON array.",
  );
  expect(() =>
    parseMemberListJson(
      '{"unsafe":9007199254740993}',
      "Evaluation parameters",
      "object",
    ),
  ).toThrow("exact safe integers");
});

it("opens a legacy source-owned current selection read-only and evaluates its saved definition", async () => {
  const item = {
    currentMetadataRevision: 7,
    policyRevision: 3,
    listId: "selection",
    stateToken: "a".repeat(64),
    dimensionId: "Product",
    name: "Products",
    definition: {
      parameters: [
        { name: "region", type: "String", required: true },
        { name: "rate", type: "Decimal", required: true },
        { name: "enabled", type: "Boolean", required: false },
      ],
    },
    canonicalDigest: "a".repeat(64),
    status: "Active",
    active: true,
    valid: true,
    executable: true,
    sourceCurrent: true,
    source: {
      programId: "selection-source",
      sourceToken: "c".repeat(64),
      sourceDigest: "b".repeat(64),
      buildId: "build",
      active: true,
    },
  };
  const calls: any[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init) => {
      if (String(url) === "/api/operation-admission")
        return operationAdmissionResponse("9");
      const body = JSON.parse(init.body);
      calls.push(body);
      const result = body.program.function.endsWith(".list")
        ? {
            memberLists: [item],
            nextAfterListId: null,
            collectionToken: "b".repeat(64),
          }
        : body.program.function.endsWith(".read")
          ? item
          : {
              currentMetadataRevision: 7,
              policyRevision: 3,
              listId: "selection",
              stateToken: "a".repeat(64),
              dimensionId: "Product",
              memberIds: Array.from(
                { length: 101 },
                (_, index) => `member-${index}`,
              ),
              memberCount: 101,
              metadataRevision: 7,
              canonicalDigest: "a".repeat(64),
            };
      return new Response(JSON.stringify({ result }));
    }),
  );
  render(
    <MemberLists
      app={app}
      catalog={{
        ...catalog,
        functions: {
          ...catalog.functions,
          "metadata.member_list.read": {},
        },
      }}
    />,
  );
  fireEvent.click(await screen.findByRole("button", { name: "Products" }));
  await screen.findByText(/This selection is managed by its Python source/);
  expect(
    screen.queryByLabelText("Named selection editor"),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Save named selection" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByText("Selection definition inspection"),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByLabelText("Member-list definition"),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Deactivate historical member list" }),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Evaluate member list" }));
  await screen.findByText("Parameters.region: provide a value.");
  fireEvent.change(screen.getByLabelText("region"), {
    target: { value: "Europe" },
  });
  fireEvent.change(screen.getByLabelText("rate"), {
    target: { value: "1.123456789012" },
  });
  fireEvent.change(screen.getByLabelText("enabled"), {
    target: { value: "false" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Evaluate member list" }));
  await screen.findByText("101 selected members");
  expect(screen.queryByText(/metadata revision/i)).not.toBeInTheDocument();
  expect(calls[2].program.arguments).toEqual({
    listId: "selection",
    parameters: { region: "Europe", rate: "1.123456789012", enabled: false },
    expectedMetadataRevision: 7,
  });
  expect(screen.getAllByRole("listitem")).toHaveLength(100);
  fireEvent.click(
    screen.getByRole("button", { name: "Next selected members" }),
  );
  expect(screen.getByText("member-100")).toBeInTheDocument();
});
it("guards opening native selection authoring through the existing transition handler", async () => {
  const transition = vi.fn();
  render(
    <MemberLists
      app={app}
      catalog={{
        ...catalog,
        functions: {
          ...catalog.functions,
          "python.program.save": {},
          "python.environment.list": {},
        },
      }}
      onRequestTransition={transition}
    />,
  );
  const newList = screen.getByRole("button", { name: "New member list" });
  await waitFor(() => expect(newList).toBeEnabled());
  fireEvent.click(newList);
  expect(
    screen.queryByLabelText("Inline Python source"),
  ).not.toBeInTheDocument();
  await act(async () => transition.mock.calls[0][0]());
  expect(screen.getByLabelText("Named selection editor")).toBeInTheDocument();
  expect(
    screen.getByRole("button", { name: "Save named selection" }),
  ).toBeInTheDocument();
  expect(screen.getByLabelText("Selection method")).toHaveValue("explicit");
  expect(
    screen.queryByRole("button", { name: /Save immutable member/ }),
  ).not.toBeInTheDocument();
});

it("clears saved definitions and evaluated members when a catalogue refresh loses access", async () => {
  const item = {
    listId: "prior-selection",
    dimensionId: "Product",
    name: "Prior selection",
    stateToken: "a".repeat(64),
    canonicalDigest: "b".repeat(64),
    definition: null,
    status: "Active",
    executable: true,
    currentMetadataRevision: 7,
    policyRevision: 3,
  };
  let allowed = true;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_path, init) => {
      const { function: name } = JSON.parse(init.body).program;
      if (!allowed)
        return new Response(
          JSON.stringify({
            code: "MEMBER_LIST_SCOPE_UNAVAILABLE",
            message:
              "The saved selections catalogue is unavailable under your current dimensional access.",
          }),
          { status: 403 },
        );
      const result = name.endsWith(".list")
        ? {
            memberLists: [item],
            nextAfterListId: null,
            collectionToken: "c".repeat(64),
          }
        : name.endsWith(".read")
          ? item
          : {
              ...item,
              memberIds: ["formerly-readable-member"],
              memberCount: 1,
              metadataRevision: 7,
            };
      return new Response(JSON.stringify({ result }));
    }),
  );
  render(
    <MemberLists
      app={app}
      catalog={{
        ...catalog,
        functions: {
          ...catalog.functions,
          "metadata.member_list.read": {},
        },
      }}
    />,
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Prior selection" }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Evaluate member list" }),
  );
  await screen.findByText("formerly-readable-member");
  allowed = false;
  fireEvent.click(screen.getByRole("button", { name: "Refresh member lists" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "current dimensional access",
  );
  expect(screen.queryByText("Prior selection")).not.toBeInTheDocument();
  expect(
    screen.queryByText("formerly-readable-member"),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("article", { name: "Member list detail" }),
  ).not.toBeInTheDocument();
});

it.each([
  "acknowledged",
  "lost after commit",
  "lost before commit",
  "refused",
  "authority changed",
])(
  "deletes an unbound current member list with its exact state token when %s",
  async (outcome) => {
    const item = {
      currentMetadataRevision: 7,
      policyRevision: 3,
      listId: "temporary-selection",
      stateToken: "a".repeat(64),
      dimensionId: "Product",
      name: "Temporary products",
      definition: {
        parameters: [],
        expression: { kind: "explicit", memberIds: ["P1"] },
      },
      canonicalDigest: "c".repeat(64),
      status: "Inactive" as const,
    };
    const calls: any[] = [];
    let deleted = false;
    let admissions = 0;
    let tries = 0;
    let checks = 0;
    let first: any;
    const staleMessage =
      "Member-list access changed during the request. Refresh the application and review the current list.";
    vi.stubGlobal(
      "confirm",
      vi.fn(() => true),
    );
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url, init) => {
        if (String(url) === "/api/operation-admission") {
          admissions++;
          return operationAdmissionResponse("f");
        }
        const body = JSON.parse(init.body);
        calls.push(body);
        if (body.program.function === "metadata.member_list.delete") {
          tries++;
          first ??= body;
          expect(body).toEqual(first);
          if (outcome === "refused")
            return Response.json(
              {
                code: "DEFINITION_REFERENCES_BLOCK_REMOVAL",
                message: "Current definitions still use this list.",
              },
              { status: 400 },
            );
          if (outcome === "authority changed")
            return Response.json(
              {
                code: "MEMBER_LIST_AUTHORIZATION_STALE",
                message: staleMessage,
              },
              { status: 409 },
            );
          if (outcome === "lost before commit" && tries === 1)
            throw new TypeError("Network interruption");
          deleted = true;
          if (outcome === "lost after commit" && tries === 1)
            throw new TypeError("Network interruption");
          return new Response(
            JSON.stringify({
              languageVersion: 2,
              function: body.program.function,
              result: {
                operationId: body.idempotencyKey,
                listId: item.listId,
                stateToken: null,
                status: "Deleted",
                metadataRevision: 7,
                policyRevision: 4,
              },
            }),
          );
        }
        if (body.program.function === "application.operation.receipt.read") {
          checks++;
          expect(body.program.arguments).toEqual({
            operationId: first.idempotencyKey,
          });
          if (!deleted)
            return Response.json(
              { code: "OPERATION_RECEIPT_NOT_FOUND" },
              { status: 404 },
            );
          return Response.json({
            result: {
              operationId: first.idempotencyKey,
              actorId: "alice",
              commandDigest:
                checks === 1
                  ? "a".repeat(64)
                  : await canonicalProgramDigest({
                      scope: [app.workspaceId, app.applicationId],
                      identity: ["issuer", "alice"],
                      program: first.program,
                    }),
              committedAt: "2026-11-21T06:00:00Z",
              committedRevision: 5,
              outcome: { status: "Deleted" },
            },
          });
        }
        if (body.program.function === "application.state.read")
          return Response.json({
            result: { metadataRevision: 7, policyRevision: 4 },
          });
        if (body.program.function === "metadata.member_list.read")
          return new Response(
            JSON.stringify({
              result: body.program.arguments.retirementConsumers
                ? {
                    ...item,
                    retirementConsumers: {
                      items: [],
                      nextAfter: null,
                      collectionToken: "b".repeat(64),
                    },
                  }
                : item,
            }),
          );
        return new Response(
          JSON.stringify({
            result: {
              memberLists: deleted ? [] : [item],
              nextAfterListId: null,
              collectionToken: (deleted ? "d" : "b").repeat(64),
            },
          }),
        );
      }),
    );
    const functions = {
      ...catalog.functions,
      "metadata.member_list.read": {},
      "application.operation.receipt.read": {},
    };
    const view = render(
      <MemberLists app={app} catalog={{ ...catalog, functions }} />,
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Temporary products" }),
    );
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Review member-list deletion",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Delete member list" }),
    );
    if (outcome === "refused" || outcome === "authority changed") {
      await screen.findByText(
        outcome === "refused"
          ? "Current definitions still use this list."
          : staleMessage,
      );
      expect(
        screen.queryByRole("region", { name: "Member-list change outcome" }),
      ).not.toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: "Review member-list deletion" }),
      ).toBeEnabled();
      expect(admissions).toBe(1);
      expect(tries).toBe(1);
      return;
    }
    if (outcome !== "acknowledged") {
      const read = await screen.findByRole("button", {
        name: "Read original member-list outcome",
      });
      expect(
        screen.queryByRole("button", {
          name: "Retry original member-list request",
        }),
      ).not.toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: "New member list" }),
      ).toBeDisabled();
      fireEvent.click(read);
      if (outcome === "lost before commit") {
        fireEvent.click(
          await screen.findByRole("button", {
            name: "Retry original member-list request",
          }),
        );
      } else {
        await screen.findByText(
          "The receipt could not confirm the original member-list change.",
        );
        expect(
          screen.queryByRole("button", {
            name: "Retry original member-list request",
          }),
        ).not.toBeInTheDocument();
        const readable = {
          "metadata.member_list.read": {},
          "metadata.member_list.list": {},
          "application.operation.receipt.read": {},
        };
        view.rerender(
          <MemberLists
            app={app}
            catalog={{
              ...catalog,
              functions: readable,
              revisions: { ...catalog.revisions, security: 2 },
            }}
          />,
        );
        expect(
          screen.queryByRole("button", {
            name: "Copy original member-list request for MCP",
          }),
        ).not.toBeInTheDocument();
        fireEvent.click(
          screen.getByRole("button", {
            name: "Read original member-list outcome",
          }),
        );
      }
    }
    await screen.findByText("Member list temporary-selection deleted.");
    await waitFor(() =>
      expect(screen.queryByText("Temporary products")).not.toBeInTheDocument(),
    );
    const request = calls.find(
      (body) => body.program.function === "metadata.member_list.delete",
    );
    expect(request.program.arguments).toEqual({
      listId: item.listId,
      expectedStateToken: item.stateToken,
      expectedMetadataRevision: 7,
      expectedPolicyRevision: 3,
    });
    expect(admissions).toBe(1);
    expect(tries).toBe(outcome === "lost before commit" ? 2 : 1);
  },
);

it("names the current consumers and pages them without offering deletion", async () => {
  const item = {
    currentMetadataRevision: 7,
    policyRevision: 3,
    listId: "branch",
    stateToken: "a".repeat(64),
    dimensionId: "Product",
    name: "Reporting branch",
    definition: null,
    canonicalDigest: "c".repeat(64),
    status: "Active",
  };
  const view = { kind: "saved-view", id: "margin-review" };
  const schedule = { kind: "schedule", id: "monthly-margin" };
  const first = { kind: "workflow", id: "branch/@" + "x".repeat(292) };
  const second = { kind: "workflow", id: "quarter-close" };
  const token = "d".repeat(64);
  const requests: string[] = [];
  const confirm = vi.fn();
  let finishNext!: () => void;
  const nextPage = new Promise<void>((resolve) => (finishNext = resolve));
  vi.stubGlobal("confirm", confirm);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init) => {
      requests.push(String(url));
      const { program } = JSON.parse(init.body);
      if (program.function === "metadata.member_list.list")
        return Response.json({
          result: {
            memberLists: [item],
            nextAfterListId: null,
            collectionToken: "b".repeat(64),
          },
        });
      expect(program.function).toBe("metadata.member_list.read");
      const page = program.arguments.retirementConsumers;
      if (!page) return Response.json({ result: item });
      if (page.after) {
        expect(page).toEqual({ after: first, expectedCollectionToken: token });
        await nextPage;
      }
      return Response.json({
        result: {
          ...item,
          retirementConsumers: {
            items: page.after ? [second] : [view, schedule, first],
            nextAfter: page.after ? null : first,
            collectionToken: token,
          },
        },
      });
    }),
  );
  render(
    <MemberLists
      app={app}
      catalog={{
        ...catalog,
        functions: {
          ...catalog.functions,
          "metadata.member_list.read": {},
        },
      }}
    />,
  );
  fireEvent.click(await screen.findByRole("button", { name: item.name }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Review member-list deletion" }),
  );
  expect(
    await screen.findByText("Saved view margin-review"),
  ).toBeInTheDocument();
  expect(screen.getByText("Schedule monthly-margin")).toBeInTheDocument();
  expect(screen.getByText(`Workflow ${first.id}`)).toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Delete member list" }),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Next dependencies" }));
  const region = screen.getByRole("region", { name: "Member-list retirement" });
  expect(region).toHaveFocus();
  expect(within(region).getByRole("status")).toHaveTextContent(
    "Checking current dependencies",
  );
  finishNext();
  expect(await screen.findByText("Workflow quarter-close")).toBeInTheDocument();
  expect(region).toHaveFocus();
  expect(
    screen.queryByRole("button", { name: "Delete member list" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Next dependencies" }),
  ).not.toBeInTheDocument();
  expect(requests).toEqual(Array(4).fill("/api/read"));
  expect(confirm).not.toHaveBeenCalled();
});

it("requires a complete first dependency page before enabling deletion", async () => {
  const item = {
    currentMetadataRevision: 7,
    policyRevision: 3,
    listId: "branch",
    stateToken: "a".repeat(64),
    dimensionId: "Product",
    name: "Reporting branch",
    definition: null,
    canonicalDigest: "c".repeat(64),
    status: "Active",
  };
  const first = { kind: "workflow", id: "branch/@review" };
  const token = "d".repeat(64);
  const pages = [
    { items: [], collectionToken: token },
    { items: [first], nextAfter: first, collectionToken: token },
    { items: [], nextAfter: null, collectionToken: token },
    { items: [], nextAfter: null, collectionToken: token },
  ];
  const cursors: unknown[] = [];
  const fetch = vi.fn(async (_url, init) => {
    const { program } = JSON.parse(init.body);
    if (program.function === "metadata.member_list.list")
      return Response.json({
        result: {
          memberLists: [item],
          nextAfterListId: null,
          collectionToken: token,
        },
      });
    expect(program.function).toBe("metadata.member_list.read");
    const cursor = program.arguments.retirementConsumers;
    if (!cursor) return Response.json({ result: item });
    cursors.push(cursor);
    return Response.json({
      result: { ...item, retirementConsumers: pages.shift() },
    });
  });
  vi.stubGlobal("fetch", fetch);
  render(
    <MemberLists
      app={app}
      catalog={{
        ...catalog,
        functions: {
          ...catalog.functions,
          "metadata.member_list.read": {},
        },
      }}
    />,
  );
  fireEvent.click(await screen.findByRole("button", { name: item.name }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Review member-list deletion" }),
  );
  const region = screen.getByRole("region", { name: "Member-list retirement" });
  expect(await within(region).findByRole("alert")).toHaveTextContent(
    "The dependency review is incomplete.",
  );
  expect(region).toHaveFocus();
  expect(
    within(region).queryByRole("button", { name: "Delete member list" }),
  ).toBeNull();

  fireEvent.click(
    within(region).getByRole("button", { name: "Check dependencies again" }),
  );
  fireEvent.click(
    await within(region).findByRole("button", { name: "Next dependencies" }),
  );
  expect(await within(region).findByRole("alert")).toHaveTextContent(
    "Dependencies changed.",
  );
  expect(region).toHaveFocus();
  expect(
    within(region).queryByRole("button", { name: "Delete member list" }),
  ).toBeNull();

  fireEvent.click(
    within(region).getByRole("button", { name: "Check dependencies again" }),
  );
  expect(
    await within(region).findByRole("button", { name: "Delete member list" }),
  ).toBeEnabled();
  expect(cursors).toEqual([
    {},
    {},
    { after: first, expectedCollectionToken: token },
    {},
  ]);
  expect(fetch.mock.calls.every(([path]) => path === "/api/read")).toBe(true);
});
