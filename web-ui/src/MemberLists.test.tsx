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
  applicationAccess: { role: "Editor", workspaceAdministrator: false },
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
  fireEvent.click(screen.getByRole("button", { name: "Read member lists" }));
  fireEvent.click(await screen.findByRole("button", { name: "Products" }));
  await screen.findByText(/This legacy selection is owned by source/);
  expect(
    screen.queryByLabelText("Named selection editor"),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Save named selection" }),
  ).not.toBeInTheDocument();
  expect(
    screen.getByText("Selection definition inspection").closest("details"),
  ).not.toHaveAttribute("open");
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
  fireEvent.click(screen.getByRole("button", { name: "New member list" }));
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

it("deletes an unbound current member list with its exact state token", async () => {
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
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url, init) => {
      if (String(url) === "/api/operation-admission")
        return operationAdmissionResponse("f");
      const body = JSON.parse(init.body);
      calls.push(body);
      if (body.program.function === "metadata.member_list.delete") {
        deleted = true;
        return new Response(
          JSON.stringify({
            result: {
              listId: item.listId,
              stateToken: null,
              status: "Deleted",
            },
          }),
        );
      }
      if (body.program.function === "metadata.member_list.read")
        return new Response(JSON.stringify({ result: item }));
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
  fireEvent.click(screen.getByRole("button", { name: "Read member lists" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Temporary products" }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Delete member list" }),
  );
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
});
