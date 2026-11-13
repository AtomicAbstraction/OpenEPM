import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { GlobalSearch, Notifications } from "./GlobalPanels";

afterEach(() => vi.unstubAllGlobals());

it("searches only accessible applications, destinations and authorized functions", () => {
  const go = vi.fn();
  render(
    <GlobalSearch
      open
      close={() => undefined}
      applications={[
        {
          workspaceId: "ws",
          applicationId: "plan",
          name: "FP&A Plan",
          status: "Active",
        },
      ]}
      selectedApplication={{
        workspaceId: "ws",
        applicationId: "plan",
        name: "FP&A Plan",
        status: "Active",
      }}
      targets={[{ id: "analyze", label: "Analyze" }]}
      catalog={{
        applicationAccess: { role: "Reader", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: { "facts.cube.scan": {} },
        revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
      }}
      go={go}
      chooseApplication={() => undefined}
    />,
  );
  fireEvent.change(
    screen.getByPlaceholderText(
      "Search applications, pages or authorized functions",
    ),
    { target: { value: "cube" } },
  );
  expect(screen.getByText("facts.cube.scan")).toBeInTheDocument();
  expect(screen.queryByText("facts.numeric.batch")).not.toBeInTheDocument();
  fireEvent.change(
    screen.getByPlaceholderText(
      "Search applications, pages or authorized functions",
    ),
    { target: { value: "Analyze" } },
  );
  fireEvent.click(screen.getByRole("button", { name: /Analyze/ }));
  expect(go).toHaveBeenCalledWith("analyze");
});

it("derives notifications from the existing durable task list", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      expect(JSON.parse(String(init?.body))).toEqual({
        workspaceId: "ws",
        applicationId: "app",
        afterSequence: 0,
        limit: 100,
        attentionOnly: true,
      });
      return new Response(
        JSON.stringify({
          tasks: [
            {
              taskId: "task-1",
              function: "python.program.build",
              sourceFamily: "PythonBuild",
              status: "Failed",
            },
          ],
        }),
      );
    }),
  );
  render(
    <Notifications
      open
      close={() => undefined}
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      }}
      goMonitor={() => undefined}
    />,
  );
  await waitFor(() =>
    expect(screen.getByText("python.program.build")).toBeInTheDocument(),
  );
  expect(screen.getByText("Failed")).toBeInTheDocument();
  expect(screen.getByText("Work needing attention")).toBeInTheDocument();
  expect(screen.queryByText("task-1")).not.toBeInTheDocument();
});
