import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { EffectiveApplicationAccess } from "./EffectiveApplicationAccess";
import type { ApplicationCatalog } from "./types";

const app = {
  workspaceId: "operations",
  applicationId: "capacity",
  name: "Capacity",
  status: "Active",
};
const program = "security.application.effective-access.list";
const catalog: ApplicationCatalog = {
  applicationAccess: {
    role: "Assigned",
    authorizationModel: "group_assignments",
    roles: ["Access Reviewer"],
    workspaceAdministrator: false,
  },
  enabledCapabilities: [],
  functions: { [program]: {} },
  revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
};
const person = {
  subjectId: "person-one",
  displayName: "Example Planner",
  username: "eplanner",
  directoryStatus: "Active",
  admitted: true,
  applicationRole: null,
  workspaceAdministrator: null,
  originsComplete: true,
  origins: [
    {
      kind: "application_group",
      groupId: "night-team",
      groupName: "Night Team",
      role: "contributor",
      roleName: "Capacity Contributor",
      privileges: [
        {
          action: "facts.write",
          scopeId: "night-shift",
          scopeKind: "dimension_tags",
          selector: { Shift: ["Night"], Machine: ["Press"] },
        },
      ],
      readTags: {},
      writeTags: {},
      rulePermissions: null,
    },
  ],
};
const report = {
  workspaceId: app.workspaceId,
  applicationId: app.applicationId,
  authorizationMode: "group_assignments",
  coverage: "complete_in_application",
  coverageReasons: [],
  asOf: "2026-11-25T08:00:00Z",
  people: [person],
  nextCursor: null,
};
function reply(value: unknown) {
  return new Response(JSON.stringify({ result: value }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

afterEach(() => vi.unstubAllGlobals());

it("finds named people in this application and reads their scoped assignments from the governed read", async () => {
  const fetch = vi.fn(async (url: string, init: RequestInit) => {
    expect(url).toBe("/api/security");
    const request = JSON.parse(String(init.body));
    expect(request).toMatchObject({
      workspaceId: "operations",
      applicationId: "capacity",
      program: { languageVersion: 2, function: program },
    });
    return reply(report);
  });
  vi.stubGlobal("fetch", fetch);
  render(<EffectiveApplicationAccess app={app} catalog={catalog} />);
  expect(fetch).not.toHaveBeenCalled();
  fireEvent.change(
    screen.getByRole("searchbox", { name: "Name or username" }),
    { target: { value: "  Planner " } },
  );
  fireEvent.click(screen.getByRole("button", { name: "Find person" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Example Planner" }),
  );
  expect(
    await screen.findByText("Application group assignment · Night Team"),
  ).toBeVisible();
  expect(screen.getByText("Capacity Contributor")).toBeVisible();
  expect(screen.getByText("facts.write")).toBeVisible();
  expect(screen.getByText(/Shift: Night.*Machine: Press/)).toBeVisible();
  expect(
    screen.getByRole("heading", { name: "Person’s access" }),
  ).toHaveFocus();
  const params = fetch.mock.calls.map(
    ([, init]) => JSON.parse(String(init.body)).program.arguments,
  );
  expect(params).toEqual([
    { query: "Planner", limit: 25 },
    { subjectId: "person-one", limit: 25 },
  ]);
});

it("pages roster and person sources with their separate cursor and filter contexts", async () => {
  const fetch = vi.fn(async (_url: string, init: RequestInit) => {
    const args = JSON.parse(String(init.body)).program.arguments;
    return reply({
      ...report,
      nextCursor: args.cursor
        ? null
        : args.subjectId
          ? "more-sources"
          : "more-people",
    });
  });
  vi.stubGlobal("fetch", fetch);
  render(<EffectiveApplicationAccess app={app} catalog={catalog} />);
  fireEvent.change(screen.getByRole("searchbox"), {
    target: { value: "Example" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Find person" }));
  fireEvent.click(await screen.findByRole("button", { name: "Next people" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Example Planner" }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Next assignment sources" }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Return to people" }),
  );
  expect(
    await screen.findByRole("heading", { name: "Application roster" }),
  ).toBeVisible();
  expect(
    fetch.mock.calls.map(
      ([, init]) => JSON.parse(String(init.body)).program.arguments,
    ),
  ).toEqual([
    { query: "Example", limit: 25 },
    { query: "Example", cursor: "more-people", limit: 25 },
    { subjectId: "person-one", limit: 25 },
    { subjectId: "person-one", cursor: "more-sources", limit: 25 },
    { query: "Example", cursor: "more-people", limit: 25 },
  ]);
});

it("shows incomplete directory evidence separately from a confirmed empty report", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      reply({
        ...report,
        people: [],
        coverage: "partial",
        coverageReasons: ["unresolved_directory_identities"],
      }),
    ),
  );
  render(<EffectiveApplicationAccess app={app} catalog={catalog} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Show application roster" }),
  );
  expect(
    await screen.findByText(/Partial coverage in this application/),
  ).toBeVisible();
  expect(screen.getByText(/available information/)).toBeVisible();
  expect(
    screen.queryByText("No matching access was found in this application."),
  ).toBeNull();
});

it("keeps legacy grant sources and their read and write tags distinct", async () => {
  const legacyPerson = {
    ...person,
    applicationRole: "Editor",
    workspaceAdministrator: false,
    origins: [
      {
        ...person.origins[0],
        kind: "application_direct",
        groupId: null,
        groupName: null,
        role: "Editor",
        roleName: "Editor",
        privileges: [],
        readTags: { Entity: ["region-a"] },
        writeTags: { Account: ["expense"] },
        rulePermissions: { design: true },
      },
    ],
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      reply({ ...report, authorizationMode: "legacy", people: [legacyPerson] }),
    ),
  );
  render(<EffectiveApplicationAccess app={app} catalog={catalog} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Show application roster" }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Example Planner" }),
  );
  expect(await screen.findByText("Direct application grant")).toBeVisible();
  expect(screen.getByText("Entity: region-a")).toBeVisible();
  expect(screen.getByText("Account: expense")).toBeVisible();
  expect(screen.getByText("design")).toBeVisible();
});

it("discards a late report when the reviewer's authority changes", async () => {
  let finish!: (response: Response) => void;
  const fetch = vi.fn(
    () =>
      new Promise<Response>((resolve) => {
        finish = resolve;
      }),
  );
  vi.stubGlobal("fetch", fetch);
  const { rerender } = render(
    <EffectiveApplicationAccess app={app} catalog={catalog} />,
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Show application roster" }),
  );
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
  rerender(
    <EffectiveApplicationAccess
      app={app}
      catalog={{ ...catalog, accessContext: "refreshed" }}
    />,
  );
  await act(async () => finish(reply(report)));
  expect(screen.queryByText("Example Planner")).toBeNull();
  rerender(
    <EffectiveApplicationAccess
      app={app}
      catalog={{ ...catalog, functions: {} }}
    />,
  );
  expect(screen.queryByRole("searchbox")).toBeNull();
});

it("does not render a mismatched scope or a malformed privilege as a decision", async () => {
  const fetch = vi
    .fn()
    .mockResolvedValueOnce(reply({ ...report, workspaceId: "elsewhere" }))
    .mockResolvedValueOnce(
      reply({
        ...report,
        people: [
          {
            ...person,
            origins: [
              {
                ...person.origins[0],
                privileges: [
                  {
                    action: "facts.write",
                    scopeId: "bad",
                    scopeKind: "dimension_tags",
                    selector: { Shift: "All" },
                  },
                ],
              },
            ],
          },
        ],
      }),
    );
  vi.stubGlobal("fetch", fetch);
  render(<EffectiveApplicationAccess app={app} catalog={catalog} />);
  for (const _ of [1, 2]) {
    fireEvent.click(
      screen.getByRole("button", { name: "Show application roster" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The access report is unavailable",
    );
    expect(within(document.body).queryByText("Example Planner")).toBeNull();
  }
});
