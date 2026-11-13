import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { PythonProgramRun } from "./PythonProgramRun";
import { installOperationAdmissionFixture } from "./test-setup";
import type { ApplicationCatalog } from "./types";

const app = {
  workspaceId: "ws",
  applicationId: "app",
  name: "Plan",
  status: "Active",
};
const catalog: ApplicationCatalog = {
  applicationAccess: { role: "Editor", workspaceAdministrator: false },
  functions: {},
  enabledCapabilities: [],
  revisions: {
    metadata: 4,
    policy: 2,
    schemaEpoch: 1,
    data: 0,
    commit: 0,
    security: 0,
  },
};
const program = {
  programId: "forecast",
  sourceToken: "c".repeat(64),
  status: "Active",
  sourceDigest: "a".repeat(64),
  sourceText: "def build(context, parameters):\n    return Program()",
};
const authority = {
  delegation_id: "authority",
  state_token: "c".repeat(64),
  status: "Active" as const,
  operation_scope: ["python.program.build", "python.program.run"],
  valid_from: "2020-01-01T00:00:00Z",
  valid_until: "2099-01-01T00:00:00Z",
};
const props = {
  app,
  catalog,
  program,
  authority,
  parameters: '{"ratio":"2"}',
  onSetupAuthority: vi.fn(),
};
const plan = {
  buildId: "plan-1",
  purpose: "Plan",
  status: "sealed",
  planDigest: "b".repeat(64),
};
const workflow = {
  buildId: "plan-1",
  workflowId: "run-1",
  status: "published",
  unitCount: 1,
  committedUnits: 1,
  remainingUnits: 0,
  receiptId: "receipt-1",
};
const response = (result: unknown) => new Response(JSON.stringify({ result }));
afterEach(() => vi.unstubAllGlobals());

it("builds the active source under the read authority and runs only that sealed Plan", async () => {
  const calls: { path: string; body: Record<string, unknown> }[] = [];
  vi.stubGlobal("confirm", vi.fn());
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      const body = JSON.parse(init.body);
      calls.push({ path, body });
      if (path === "/api/python-build")
        return response(
          body.action === "request" ? { ...plan, status: "accepted" } : plan,
        );
      return response(
        body.action === "request"
          ? { ...workflow, status: "accepted" }
          : workflow,
      );
    }),
  );
  installOperationAdmissionFixture("8");
  render(<PythonProgramRun {...props} />);
  fireEvent.click(screen.getByRole("button", { name: "Run active version" }));
  await screen.findByText(/Run: published/);
  expect(screen.getByText(/0 remaining units/)).toBeInTheDocument();
  expect(calls.map((call) => [call.path, call.body.action])).toEqual([
    ["/api/python-build", "request"],
    ["/api/python-build", "read"],
    ["/api/python-run", "request"],
    ["/api/python-run", "read"],
  ]);
  expect(calls[0].body).toMatchObject({
    program: {
      function: "python.program.build",
      arguments: {
        programId: "forecast",
        programSourceToken: "c".repeat(64),
        parameters: { ratio: "2" },
        delegationId: "authority",
        delegationStateToken: "c".repeat(64),
        scheduleId: null,
        scheduleStateToken: null,
        expectedMetadataRevision: 4,
        expectedPolicyRevision: 2,
        expectedSchemaEpoch: 1,
      },
    },
  });
  expect(calls[2].body).toMatchObject({
    program: {
      function: "python.program.run",
      arguments: { buildId: "plan-1" },
    },
  });
  expect(window.confirm).not.toHaveBeenCalled();
  expect(
    screen.queryByRole("button", { name: "Resume exact execution request" }),
  ).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Run again" }));
  await waitFor(() => expect(calls.length).toBe(8));
  expect(calls[0].body.idempotencyKey).toMatch(/_8{32}_/);
  expect(calls[4].body.idempotencyKey).toMatch(/_a{32}_/);
  expect(calls[4].body.idempotencyKey).not.toBe(calls[0].body.idempotencyKey);
});

it.each(["build", "run"])(
  "reuses exact mutation identities after a lost %s response",
  async (lost) => {
    const mutations: Record<string, unknown>[] = [];
    let lostOnce = false;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path, init) => {
        const body = JSON.parse(init.body);
        if (body.action === "request") {
          mutations.push({ path, ...body });
          if (path === `/api/python-${lost}` && !lostOnce) {
            lostOnce = true;
            throw new TypeError("Response lost");
          }
        }
        return response(path === "/api/python-build" ? plan : workflow);
      }),
    );
    installOperationAdmissionFixture("9");
    render(<PythonProgramRun {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Run active version" }));
    await screen.findByText("Response lost");
    fireEvent.click(
      screen.getByRole("button", { name: "Resume exact execution request" }),
    );
    await screen.findByText(/Run: published/);
    const retried = mutations.filter(
      (item) => item.path === `/api/python-${lost}`,
    );
    expect(retried).toHaveLength(2);
    expect(retried[0]).toEqual(retried[1]);
    expect(
      mutations.filter(
        (item) =>
          item.path === `/api/python-${lost === "build" ? "run" : "build"}`,
      ),
    ).toHaveLength(1);
  },
);

it.each(["parameters", "activeVersion", "workspace", "suspended"])(
  "stops chaining after %s changes, even if a late build seals",
  async (change) => {
    let finish: (value: Response) => void = () => undefined;
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((path, init) => {
        calls.push(path);
        const body = JSON.parse(init.body);
        return body.action === "request"
          ? Promise.resolve(response({ ...plan, status: "accepted" }))
          : new Promise<Response>((resolve) => {
              finish = resolve;
            });
      }),
    );
    installOperationAdmissionFixture("a");
    const { rerender } = render(<PythonProgramRun {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Run active version" }));
    await waitFor(() => expect(calls).toHaveLength(2));
    rerender(
      <PythonProgramRun
        {...props}
        parameters={change === "parameters" ? "{}" : props.parameters}
        suspended={change === "suspended"}
        program={
          change === "activeVersion"
            ? { ...program, status: "Inactive" }
            : program
        }
        app={change === "workspace" ? { ...app, workspaceId: "other" } : app}
      />,
    );
    await act(async () => finish(response(plan)));
    expect(calls).toEqual(["/api/python-build", "/api/python-build"]);
    await screen.findByText(/Automatic chaining stopped/);
  },
);

it("rejects Test builds and never grants missing execution authority", async () => {
  const fetch = vi.fn(async () => response({ ...plan, purpose: "ImpactTest" }));
  vi.stubGlobal("fetch", fetch);
  installOperationAdmissionFixture("b");
  const { rerender } = render(<PythonProgramRun {...props} authority={null} />);
  expect(
    screen.getByRole("button", { name: "Run active version" }),
  ).toBeDisabled();
  fireEvent.click(
    screen.getByRole("button", { name: "Set up execution authority" }),
  );
  expect(props.onSetupAuthority).toHaveBeenCalled();
  expect(fetch).not.toHaveBeenCalled();
  rerender(<PythonProgramRun {...props} />);
  fireEvent.click(screen.getByRole("button", { name: "Run active version" }));
  await screen.findByText("Run requires a Plan build.");
  expect(fetch).toHaveBeenCalledTimes(1);
});

it("does not submit rounded or underflowed advanced numeric parameters", () => {
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  const { rerender } = render(
    <PythonProgramRun
      {...props}
      parameters='{"count":0.999999999999999999999}'
    />,
  );
  expect(
    screen.getByRole("button", { name: "Run active version" }),
  ).toBeDisabled();
  expect(screen.getByRole("alert")).toHaveTextContent("exact safe integers");
  rerender(<PythonProgramRun {...props} parameters='{"count":1e-1000}' />);
  expect(
    screen.getByRole("button", { name: "Run active version" }),
  ).toBeDisabled();
  expect(fetch).not.toHaveBeenCalled();
  rerender(
    <PythonProgramRun
      {...props}
      parameters='{"amount":"0.999999999999999999999","count":1}'
    />,
  );
  expect(
    screen.getByRole("button", { name: "Run active version" }),
  ).toBeEnabled();
  expect(screen.queryByRole("alert")).toBeNull();
});
