import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import axe from "axe-core";
import { useLayoutEffect, useRef } from "react";
import { afterEach, expect, it, vi } from "vitest";
import {
  MyWork,
  readCompleteWaitingTasks,
  readCompleteWorkflowWorklist,
} from "./MyWork";

afterEach(() => vi.unstubAllGlobals());

const scope = { workspaceId: "ws", applicationId: "app" };

const workCatalog = {
  applicationAccess: { role: "Reader", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: { "application.workflow.worklist": {} },
  revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
};

const nativeWaitingCatalog = {
  ...workCatalog,
  functions: {
    "application.workflow.worklist": {
      programSchema: {
        properties: {
          arguments: { properties: { includeWaiting: { type: "boolean" } } },
        },
      },
    },
  },
};

it("keeps pagination focus on the boundary and opens the exact activity from the new page", async () => {
  const open = vi.fn();
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      Response.json({
        result: {
          items: Array.from({ length: 51 }, (_, index) => ({
            occurrenceId: `occurrence-${index + 1}`,
            activityId: "review",
            name: `Review forecast ${index + 1}`,
            flowId: "forecast",
          })),
          blockedItems: [],
          waitingItems: [],
          nextCursor: null,
        },
      }),
    ),
  );
  render(
    <MyWork
      app={{ ...scope, name: "Plan", status: "Active" }}
      catalog={nativeWaitingCatalog}
      open={open}
    />,
  );
  const next = await screen.findByRole("button", {
    name: "Next ready activities",
  });
  const previous = screen.getByRole("button", {
    name: "Previous ready activities",
  });
  expect(screen.getByRole("status")).toHaveTextContent(
    "1–50 of 51 ready activities",
  );
  next.focus();
  fireEvent.click(next);
  expect(next).toHaveFocus();
  expect(next).toHaveAttribute("aria-disabled", "true");
  fireEvent.click(next);
  expect(screen.getByRole("status")).toHaveTextContent(
    "51–51 of 51 ready activities",
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Open activity Review forecast 51" }),
  );
  expect(open).toHaveBeenCalledWith("flows", {
    ...scope,
    occurrenceId: "occurrence-51",
    activityId: "review",
  });
  previous.focus();
  fireEvent.click(previous);
  expect(previous).toHaveFocus();
  expect(previous).toHaveAttribute("aria-disabled", "true");
  expect(screen.getByRole("status")).toHaveTextContent(
    "1–50 of 51 ready activities",
  );
});

it("uses only the discovered workflow worklist for Ready, Waiting and Blocked", async () => {
  const open = vi.fn();
  const row = {
    occurrenceId: "occurrence",
    activityId: "prepare",
    name: "Prepare forecast",
    flowId: "forecast",
  };
  const fetchWork = vi.fn(async (url, init) => {
    expect(String(url)).toBe("/api/read");
    const args = JSON.parse(String(init.body)).program.arguments;
    const continuing = Boolean(args.afterActivityId);
    expect(args).toEqual({
      limit: 100,
      includeBlocked: true,
      includeWaiting: true,
      ...(continuing
        ? {
            afterOccurrenceId: row.occurrenceId,
            afterActivityId: row.activityId,
          }
        : {}),
    });
    return new Response(
      JSON.stringify({
        result: {
          items: continuing ? [] : [row],
          blockedItems: continuing
            ? [
                {
                  ...row,
                  occurrenceId: "previous",
                  name: "Previous forecast",
                  reason: "WorkflowDefinitionUnavailable",
                },
              ]
            : [],
          waitingItems: continuing
            ? [
                {
                  ...row,
                  activityId: "review",
                  name: "Review forecast",
                  reason: "ReturnedForRework",
                },
              ]
            : [],
          nextCursor: continuing
            ? null
            : {
                afterOccurrenceId: row.occurrenceId,
                afterActivityId: row.activityId,
              },
        },
      }),
    );
  });
  vi.stubGlobal("fetch", fetchWork);

  render(
    <MyWork
      app={{ ...scope, name: "Plan", status: "Active" }}
      catalog={nativeWaitingCatalog}
      open={open}
    />,
  );
  const waiting = await screen.findByText("Review forecast");
  expect(
    screen.getByText("Waiting for the returned work to be completed"),
  ).toBeVisible();
  expect(screen.getByText("Prepare forecast")).toBeVisible();
  expect(screen.getByText("Previous forecast")).toBeVisible();
  expect(screen.getByRole("button", { name: "All 3" })).toBeEnabled();
  fireEvent.click(
    within(waiting.closest("article")!).getByRole("button", {
      name: /Open activity/,
    }),
  );
  expect(open).toHaveBeenCalledWith("flows", {
    ...scope,
    occurrenceId: "occurrence",
    activityId: "review",
  });
  expect(fetchWork).toHaveBeenCalledTimes(2);
});

it.each([{ blockedItems: [] }, { waitingItems: [] }])(
  "fails closed when the advertised worklist omits a requested projection (%j)",
  async (present) => {
    const fetchWork = vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: { items: [], ...present, nextCursor: null },
          }),
        ),
    );
    vi.stubGlobal("fetch", fetchWork);

    render(
      <MyWork
        app={{ ...scope, name: "Plan", status: "Active" }}
        catalog={nativeWaitingCatalog}
        open={vi.fn()}
      />,
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Workflow worklist rows are invalid",
    );
    expect(screen.queryByText("No work waiting on dependencies")).toBeNull();
    expect(screen.getByRole("button", { name: "Waiting —" })).toBeDisabled();
    expect(fetchWork).toHaveBeenCalledOnce();
  },
);

it("withdraws an old assignment before painting a renewed catalogue", async () => {
  const layouts: string[] = [];
  let finishRead: (value: Response) => void = () => undefined;
  let readCount = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url) => {
      if (String(url) === "/api/tasks")
        return new Response(JSON.stringify({ tasks: [], hasMore: false }));
      if (readCount++ > 0)
        return new Promise<Response>((resolve) => {
          finishRead = resolve;
        });
      return new Response(
        JSON.stringify({
          result: {
            items: [
              {
                occurrenceId: "one",
                activityId: "review",
                name: "Previously assigned review",
                flowId: "close",
              },
            ],
            nextCursor: null,
          },
        }),
      );
    }),
  );
  function Host({ catalog }: { catalog: typeof workCatalog }) {
    const host = useRef<HTMLDivElement>(null);
    useLayoutEffect(() => {
      layouts.push(host.current?.textContent || "");
    }, [catalog]);
    return (
      <div ref={host}>
        <MyWork
          app={{ ...scope, name: "Plan", status: "Active" }}
          catalog={catalog}
          open={vi.fn()}
        />
      </div>
    );
  }
  const view = render(<Host catalog={workCatalog} />);
  await screen.findByText("Previously assigned review");
  view.rerender(
    <Host
      catalog={{
        ...workCatalog,
        revisions: { ...workCatalog.revisions, policy: 2 },
      }}
    />,
  );
  expect(layouts.at(-1)).toContain("Loading your work");
  expect(layouts.at(-1)).not.toContain("Previously assigned review");
  expect(
    screen.queryByText("No work is currently ready"),
  ).not.toBeInTheDocument();
  await act(async () =>
    finishRead(
      new Response(JSON.stringify({ result: { items: [], nextCursor: null } })),
    ),
  );
  await screen.findByText("No work is currently ready");
});

it.each([
  "WORK_READ_FAILED",
  "APPLICATION_WORKFLOW_WORKLIST_SEARCH_INCOMPLETE",
])(
  "distinguishes %s from an empty worklist and supports an explicit retry",
  async (error) => {
    let failed = true;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url) =>
        failed
          ? new Response(JSON.stringify({ error }), {
              status: 400,
            })
          : new Response(
              JSON.stringify(
                String(url) === "/api/tasks"
                  ? { tasks: [], hasMore: false, nextSequence: 0 }
                  : { result: { items: [], nextCursor: null } },
              ),
            ),
      ),
    );
    render(
      <MyWork
        app={{ ...scope, name: "Work fixture", status: "Active" }}
        catalog={workCatalog}
        open={vi.fn()}
      />,
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(error);
    expect(screen.queryByText("No work is currently ready")).toBeNull();
    expect(screen.getByRole("button", { name: "Ready —" })).toBeDisabled();
    failed = false;
    const retry = screen.getByRole("button", { name: "Retry worklist" });
    retry.focus();
    fireEvent.click(retry);
    expect(screen.getByRole("heading", { name: "My Work" })).toHaveFocus();
    expect(await screen.findByText("No work is currently ready")).toBeVisible();
    expect(screen.getByRole("button", { name: "Ready 0" })).toBeEnabled();
  },
);

it("opens confirmed Ready work while Waiting loads and retries only an unavailable Waiting list", async () => {
  const open = vi.fn();
  const requestWaiting: Array<(response: Response) => void> = [];
  const fetchWork = vi.fn(async (url) => {
    if (String(url) === "/api/tasks")
      return new Promise<Response>((resolve) => {
        requestWaiting.push(resolve);
      });
    return new Response(
      JSON.stringify({
        result: {
          items: [
            {
              occurrenceId: "occurrence",
              activityId: "review",
              name: "Review export",
              flowId: "review-flow",
            },
          ],
          nextCursor: null,
        },
      }),
    );
  });
  vi.stubGlobal("fetch", fetchWork);
  render(
    <MyWork
      app={{ ...scope, name: "Plan", status: "Active" }}
      catalog={workCatalog}
      open={open}
    />,
  );
  const review = await screen.findByText("Review export");
  expect(screen.getByRole("status")).toHaveTextContent("Loading waiting work");
  expect(screen.getByRole("button", { name: "All —" })).toBeEnabled();
  expect(screen.getByRole("button", { name: "Ready 1" })).toBeEnabled();
  fireEvent.click(within(review.closest("article")!).getByRole("button"));
  expect(open).toHaveBeenCalledWith("flows", {
    ...scope,
    occurrenceId: "occurrence",
    activityId: "review",
  });

  await act(async () =>
    requestWaiting[0](
      new Response(
        JSON.stringify({ code: "TASK_VISIBILITY_SEARCH_INCOMPLETE" }),
        { status: 400 },
      ),
    ),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "TASK_VISIBILITY_SEARCH_INCOMPLETE",
  );
  expect(screen.queryByText("No work waiting on dependencies")).toBeNull();
  const retry = screen.getByRole("button", { name: "Retry Waiting" });
  const waitingHeader = retry.closest(".work-column")?.querySelector("header");
  retry.focus();
  fireEvent.click(retry);
  expect(waitingHeader).toHaveFocus();
  expect(screen.getByText("Review export")).toBe(review);
  expect(
    fetchWork.mock.calls.filter(([url]) => String(url) === "/api/read"),
  ).toHaveLength(1);

  await act(async () =>
    requestWaiting[1](
      new Response(
        JSON.stringify({
          tasks: [
            {
              sourceFamily: "ApplicationWorkflowActivity",
              status: "Waiting",
              taskId: "stale",
              sourceId: "occurrence/review",
            },
          ],
          hasMore: false,
        }),
      ),
    ),
  );
  expect(
    await screen.findByText("No work waiting on dependencies"),
  ).toBeVisible();
  expect(screen.getByRole("button", { name: "All 1" })).toBeEnabled();
  expect(waitingHeader).toHaveFocus();
});

it("withdraws previously loaded Ready work after a Waiting read denies application access", async () => {
  let waiting: (response: Response) => void = () => undefined;
  let attempts = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (url) => {
      if (String(url) === "/api/tasks") {
        if (attempts++ === 0)
          return new Promise<Response>((resolve) => {
            waiting = resolve;
          });
        return new Response(JSON.stringify({ tasks: [], hasMore: false }));
      }
      return new Response(
        JSON.stringify({
          result: {
            items: [
              {
                occurrenceId: "current",
                activityId: "prepare",
                name: "Prepare forecast",
                flowId: "forecast",
              },
            ],
            nextCursor: null,
          },
        }),
      );
    }),
  );
  render(
    <MyWork
      app={{ ...scope, name: "Plan", status: "Active" }}
      catalog={workCatalog}
      open={vi.fn()}
    />,
  );
  await screen.findByText("Prepare forecast");
  await act(async () =>
    waiting(
      new Response(JSON.stringify({ code: "APPLICATION_GRANT_REQUIRED" }), {
        status: 403,
      }),
    ),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "APPLICATION_GRANT_REQUIRED",
  );
  expect(screen.queryByText("Prepare forecast")).toBeNull();
  expect(screen.getByRole("button", { name: "Ready —" })).toBeDisabled();
  expect(screen.queryByRole("button", { name: "Retry Waiting" })).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Retry worklist" }));
  expect(await screen.findByText("Prepare forecast")).toBeVisible();
  expect(
    await screen.findByText("No work waiting on dependencies"),
  ).toBeVisible();
});

it("discards a late Waiting response when the application changes", async () => {
  let finishOld: (response: Response) => void = () => undefined;
  const open = vi.fn();
  const fetchWork = vi.fn(async (url, init) => {
    const payload = JSON.parse(String(init?.body));
    if (String(url) !== "/api/tasks")
      return new Response(
        JSON.stringify({ result: { items: [], nextCursor: null } }),
      );
    if (payload.applicationId === scope.applicationId)
      return new Promise<Response>((resolve) => {
        finishOld = resolve;
      });
    return new Response(JSON.stringify({ tasks: [], hasMore: false }));
  });
  vi.stubGlobal("fetch", fetchWork);
  const view = render(
    <MyWork
      app={{ ...scope, name: "Old", status: "Active" }}
      catalog={workCatalog}
      open={open}
    />,
  );
  await screen.findByText("No work is currently ready");
  expect(screen.getByText("Loading waiting work…")).toBeVisible();

  view.rerender(
    <MyWork
      app={{ ...scope, applicationId: "other", name: "New", status: "Active" }}
      catalog={workCatalog}
      open={open}
    />,
  );
  await screen.findByText("No work waiting on dependencies");
  await act(async () =>
    finishOld(
      new Response(
        JSON.stringify({
          tasks: [
            {
              taskId: "old",
              sourceFamily: "ApplicationWorkflowActivity",
              sourceId: "old/review",
              status: "Waiting",
            },
          ],
          hasMore: false,
        }),
      ),
    ),
  );
  expect(screen.getByText("No work waiting on dependencies")).toBeVisible();
  expect(screen.queryByRole("button", { name: /Open activity/ })).toBeNull();
  expect(
    fetchWork.mock.calls.find(([url]) => String(url) === "/api/tasks")?.[1]
      .signal.aborted,
  ).toBe(true);
});

it("reports a missing worklist in the catalogue without inferring a role denial or zero assignments", () => {
  render(
    <MyWork
      app={{ ...scope, name: "Work fixture", status: "Active" }}
      catalog={{ ...workCatalog, functions: {} }}
      open={vi.fn()}
    />,
  );
  expect(
    screen.getByText(
      "The current application catalogue does not include assigned work.",
    ),
  ).toBeVisible();
  expect(screen.queryByText("No work is currently ready")).toBeNull();
  expect(screen.getByRole("button", { name: "All —" })).toBeDisabled();
});

it.each([0, 8, 9, 7.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1])(
  "rejects a repeated, increasing or inexact task continuation %s",
  async (next) => {
    let page = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              tasks: [],
              hasMore: true,
              nextSequence: page++ ? next : 8,
            }),
          ),
      ),
    );
    await expect(readCompleteWaitingTasks(scope)).rejects.toThrow(
      "Task worklist continuation is invalid",
    );
  },
);

it("rejects repeated task rows across continuation pages", async () => {
  let page = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            tasks: [
              {
                taskId: "same",
                sourceFamily: "ApplicationWorkflowActivity",
                sourceId: "occ/activity",
                status: "Waiting",
              },
            ],
            hasMore: page++ === 0,
            nextSequence: 8,
          }),
        ),
    ),
  );
  await expect(readCompleteWaitingTasks(scope)).rejects.toThrow(
    "invalid or repeated task",
  );
});

it("presents populated ready and waiting work with semantic keyboard controls", async () => {
  const open = vi.fn();
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      if (String(input) === "/api/tasks")
        return new Response(
          JSON.stringify({
            tasks: [
              {
                taskId: "task-waiting",
                sourceFamily: "ApplicationWorkflowActivity",
                sourceId: `${"2".repeat(32)}/review`,
                status: "Waiting",
              },
            ],
            nextSequence: 1,
            hasMore: false,
          }),
        );
      return new Response(
        JSON.stringify({
          result: {
            items: [
              {
                occurrenceId: "1".repeat(32),
                activityId: "prepare",
                name: "Prepare forecast",
                flowId: "forecast-flow",
                version: 3,
              },
            ],
            nextCursor: null,
          },
        }),
      );
    }),
  );
  const rendered = render(
    <MyWork
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      }}
      catalog={{
        applicationAccess: { role: "Reader", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: { "application.workflow.worklist": {} },
        revisions: {
          metadata: 1,
          data: 1,
          policy: 1,
          security: 1,
          commit: 1,
        },
      }}
      open={open}
    />,
  );
  await screen.findByText("Prepare forecast");
  expect(screen.getByText("Ready for your action")).toBeInTheDocument();
  await screen.findByText("Waiting on an earlier workflow dependency");
  expect(screen.queryByText("forecast-flow")).not.toBeInTheDocument();
  expect(screen.queryByText("prepare")).not.toBeInTheDocument();
  expect(screen.queryByText("2".repeat(32))).not.toBeInTheDocument();
  expect(screen.queryByText("review")).not.toBeInTheDocument();
  expect(
    screen.getByRole("group", { name: "Filter work by state" }),
  ).toBeInTheDocument();
  const waiting = screen.getByRole("button", { name: "Waiting 1" });
  waiting.focus();
  expect(waiting).toHaveFocus();
  fireEvent.click(waiting);
  expect(waiting).toHaveAttribute("aria-pressed", "true");
  const continueWork = screen.getByRole("button", {
    name: /Open activity/,
  });
  fireEvent.click(continueWork);
  expect(open).toHaveBeenCalledWith(
    "flows",
    expect.objectContaining({
      occurrenceId: "2".repeat(32),
      activityId: "review",
    }),
  );
  await waitFor(async () =>
    expect(
      (
        await axe.run(rendered.container, {
          rules: { "color-contrast": { enabled: false } },
        })
      ).violations,
    ).toEqual([]),
  );
});

it("continues from an assigned blocked activity to the next Ready activity", async () => {
  const calls: Record<string, unknown>[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      calls.push(body.program.arguments);
      const continued = Boolean(body.program.arguments.afterOccurrenceId);
      return new Response(
        JSON.stringify({
          result: {
            items: continued
              ? [
                  {
                    occurrenceId: "2".repeat(32),
                    activityId: "review",
                    name: "Review",
                    flowId: "close",
                  },
                ]
              : [],
            blockedItems: continued
              ? []
              : [
                  {
                    occurrenceId: "1".repeat(32),
                    activityId: "prepare",
                    name: "Prepare",
                    flowId: "close",
                    reason: "SelectionMetadataChanged",
                  },
                ],
            nextCursor: continued
              ? null
              : {
                  afterOccurrenceId: "1".repeat(32),
                  afterActivityId: "prepare",
                },
          },
        }),
      );
    }),
  );

  const result = await readCompleteWorkflowWorklist(scope);
  expect(result.items.map((item) => item.name)).toEqual(["Review"]);
  expect(result.blockedItems.map((item) => [item.name, item.reason])).toEqual([
    ["Prepare", "SelectionMetadataChanged"],
  ]);
  expect(calls).toEqual([
    { limit: 100, includeBlocked: true },
    {
      limit: 100,
      includeBlocked: true,
      afterOccurrenceId: "1".repeat(32),
      afterActivityId: "prepare",
    },
  ]);
});

it("shows blocked work alongside Ready activities and opens its exact history", async () => {
  const open = vi.fn();
  const blocked = {
    occurrenceId: "stale",
    activityId: "prepare",
    name: "Prepare old plan",
    flowId: "close",
    reason: "SelectionMetadataChanged",
  };
  const ready = {
    occurrenceId: "current",
    activityId: "review",
    name: "Review new plan",
    flowId: "current",
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async (url) =>
        new Response(
          JSON.stringify(
            String(url) === "/api/tasks"
              ? { tasks: [], hasMore: false }
              : {
                  result: {
                    items: [ready],
                    blockedItems: [blocked],
                    nextCursor: null,
                  },
                },
          ),
        ),
    ),
  );

  render(
    <MyWork
      app={{ ...scope, name: "Plan", status: "Active" }}
      catalog={workCatalog}
      open={open}
    />,
  );
  expect(await screen.findByText("Review new plan")).toBeVisible();
  const card = screen.getByText("Prepare old plan").closest("article");
  expect(card).toHaveTextContent(
    "The model changed after this workflow was published.",
  );
  fireEvent.click(within(card!).getByRole("button", { name: /Open activity/ }));
  expect(open).toHaveBeenCalledWith("flows", {
    ...scope,
    occurrenceId: "stale",
    activityId: "prepare",
  });
});

it("rejects duplicate workflow rows and malformed continuation cursors", async () => {
  const row = {
    occurrenceId: "1".repeat(32),
    activityId: "prepare",
    name: "Prepare",
    flowId: "close",
    version: 1,
  };
  let calls = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => {
      calls += 1;
      return new Response(
        JSON.stringify({
          result: {
            items: [row],
            nextCursor:
              calls === 1
                ? {
                    afterOccurrenceId: row.occurrenceId,
                    afterActivityId: row.activityId,
                  }
                : null,
          },
        }),
      );
    }),
  );
  await expect(readCompleteWorkflowWorklist(scope)).rejects.toThrow(
    "Workflow worklist continuation repeated a row.",
  );

  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({
            result: {
              items: [row],
              nextCursor: {
                afterOccurrenceId: row.occurrenceId,
                afterActivityId: "",
              },
            },
          }),
        ),
    ),
  );
  await expect(readCompleteWorkflowWorklist(scope)).rejects.toThrow(
    "Workflow worklist cursor is invalid.",
  );
});

it("consumes three descending durable-task pages and rejects repeated cursors", async () => {
  let calls = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      calls += 1;
      const body = JSON.parse(String(init?.body));
      expect(body.afterSequence).toBe([0, 80, 40][calls - 1]);
      return new Response(
        JSON.stringify({
          tasks: [
            {
              taskId: `task-${calls}`,
              sourceFamily: "ApplicationWorkflowActivity",
              sourceId: `${"1".repeat(32)}/activity-${calls}`,
              status: "Waiting",
            },
          ],
          nextSequence: [80, 40, 10][calls - 1],
          hasMore: calls < 3,
        }),
      );
    }),
  );
  expect(
    (await readCompleteWaitingTasks(scope)).map((task) => task.taskId),
  ).toEqual(["task-1", "task-2", "task-3"]);

  calls = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(
      async () =>
        new Response(
          JSON.stringify({ tasks: [], nextSequence: 8, hasMore: true }),
        ),
    ),
  );
  await expect(readCompleteWaitingTasks(scope)).rejects.toThrow(
    "Task worklist continuation is invalid.",
  );
});
