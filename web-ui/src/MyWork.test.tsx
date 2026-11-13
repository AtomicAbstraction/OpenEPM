import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, expect, it, vi } from "vitest";
import {
  MyWork,
  readCompleteWaitingTasks,
  readCompleteWorkflowWorklist,
} from "./MyWork";

afterEach(() => vi.unstubAllGlobals());

const scope = { workspaceId: "ws", applicationId: "app" };

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

it("consumes every authoritative workflow-worklist continuation", async () => {
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
            items: [
              {
                occurrenceId: continued ? "2".repeat(32) : "1".repeat(32),
                activityId: continued ? "review" : "prepare",
                name: continued ? "Review" : "Prepare",
                flowId: "close",
                version: 1,
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

  const items = await readCompleteWorkflowWorklist(scope);
  expect(items.map((item) => item.name)).toEqual(["Prepare", "Review"]);
  expect(calls).toEqual([
    { limit: 100 },
    {
      limit: 100,
      afterOccurrenceId: "1".repeat(32),
      afterActivityId: "prepare",
    },
  ]);
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

it("consumes every durable-task continuation and rejects repeated cursors", async () => {
  let calls = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      calls += 1;
      const body = JSON.parse(String(init?.body));
      expect(body.afterSequence).toBe(calls === 1 ? 0 : 8);
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
          nextSequence: 8,
          hasMore: calls < 2,
        }),
      );
    }),
  );
  expect(
    (await readCompleteWaitingTasks(scope)).map((task) => task.taskId),
  ).toEqual(["task-1", "task-2"]);

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
