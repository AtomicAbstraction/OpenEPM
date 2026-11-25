import {
  act,
  fireEvent,
  render,
  renderHook,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { PythonProgramRun } from "./PythonProgramRun";
import {
  installOperationAdmissionFixture,
  operationAdmissionResponse,
} from "./test-setup";
import {
  usePreservedDraft,
  unsavedWorkSnapshot,
  discardUnsavedWork,
  setDraftIdentity,
} from "./unsaved-work";
import type { ApplicationCatalog } from "./types";

const app = {
  workspaceId: "ws",
  applicationId: "app",
  name: "Plan",
  status: "Active",
};
const catalog: ApplicationCatalog = {
  applicationAccess: { role: "Editor", workspaceAdministrator: false },
  functions: { "python.program.build": {}, "python.program.run": {} },
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
  declaredOutput: null,
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
const planId = "1".repeat(32);
const runId = "2".repeat(32);
const plan = {
  buildId: planId,
  purpose: "Plan",
  status: "sealed",
  planDigest: "b".repeat(64),
};
const workflow = {
  buildId: planId,
  workflowId: runId,
  planDigest: plan.planDigest,
  checkpoints: [
    { ordinal: 1, jobId: "job-1", committed: true, receiptId: "receipt-1" },
  ],
  status: "published",
  unitCount: 1,
  committedUnits: 1,
  remainingUnits: 0,
  receiptId: "receipt-1",
};
const response = (result: unknown) => new Response(JSON.stringify({ result }));
function originalReferenceRead(body: any) {
  return {
    workspaceId: body.workspaceId,
    applicationId: body.applicationId,
    action: "read",
    originalRequest: {
      program: body.program,
      idempotencyKey: body.idempotencyKey,
    },
  };
}
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

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
  fireEvent.click(
    screen.getByRole("button", { name: "Run current saved source" }),
  );
  await screen.findByText(/Run: published/);
  expect(screen.getByText(/0 remaining units/)).toBeInTheDocument();
  expect(screen.getByText(/Run: published/)).toHaveTextContent(
    "1 receipt-confirmed committed units",
  );
  expect(
    screen.queryByText(/Cancellation reconciliation is still pending/),
  ).not.toBeInTheDocument();
  expect(screen.getByText("Every unit has a confirmed receipt.")).toBeVisible();
  expect(screen.queryByText(/unresolved work/)).not.toBeInTheDocument();
  expect(
    screen.queryByText(/These counts do not claim rollback/),
  ).not.toBeInTheDocument();
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
      arguments: { buildId: planId },
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
  "reads the exact original reference after a lost %s response without redispatch",
  async (lost) => {
    const mutations: Record<string, unknown>[] = [];
    const originalReads: Record<string, unknown>[] = [];
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
        if (body.originalRequest) originalReads.push({ path, ...body });
        return response(path === "/api/python-build" ? plan : workflow);
      }),
    );
    installOperationAdmissionFixture("9");
    const view = render(<PythonProgramRun {...props} />);
    fireEvent.click(
      screen.getByRole("button", { name: "Run current saved source" }),
    );
    await screen.findByText("Response lost");
    view.unmount();
    act(discardUnsavedWork);
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 7_200_000);
    render(<PythonProgramRun {...props} />);
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Resume exact execution request",
      }),
    );
    await screen.findByText(/Run: published/);
    const retried = mutations.filter(
      (item) => item.path === `/api/python-${lost}`,
    );
    expect(retried).toHaveLength(1);
    expect(originalReads).toEqual([
      { path: `/api/python-${lost}`, ...originalReferenceRead(retried[0]) },
    ]);
    expect(
      mutations.filter(
        (item) =>
          item.path === `/api/python-${lost === "build" ? "run" : "build"}`,
      ),
    ).toHaveLength(1);
  },
);

it.each([
  "parameters",
  "activeVersion",
  "workspace",
  "application",
  "identity",
  "security",
  "authority",
  "suspended",
])(
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
    fireEvent.click(
      screen.getByRole("button", { name: "Run current saved source" }),
    );
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
        app={
          change === "workspace"
            ? { ...app, workspaceId: "other" }
            : change === "application"
              ? { ...app, applicationId: "other" }
              : app
        }
        catalog={
          change === "identity"
            ? {
                ...catalog,
                applicationAccess: {
                  ...catalog.applicationAccess,
                  issuer: "issuer",
                  subjectId: "other",
                },
              }
            : change === "security"
              ? { ...catalog, revisions: { ...catalog.revisions, security: 1 } }
              : catalog
        }
        authority={
          change === "authority"
            ? { ...authority, status: "Revoked" }
            : authority
        }
      />,
    );
    await act(async () => finish(response(plan)));
    expect(calls).toEqual(["/api/python-build", "/api/python-build"]);
    if (["identity", "workspace", "application"].includes(change))
      expect(
        screen.queryByText(/Automatic chaining stopped/),
      ).not.toBeInTheDocument();
    else await screen.findByText(/Automatic chaining stopped/);
    expect(
      screen.queryByLabelText("Python execution progress"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Resume exact execution request" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/Plan: sealed/)).not.toBeInTheDocument();
  },
);

it("rejects Test builds and never grants missing execution authority", async () => {
  const fetch = vi.fn(async () => response({ ...plan, purpose: "ImpactTest" }));
  vi.stubGlobal("fetch", fetch);
  installOperationAdmissionFixture("b");
  const { rerender } = render(<PythonProgramRun {...props} authority={null} />);
  expect(
    screen.getByRole("button", { name: "Run current saved source" }),
  ).toBeDisabled();
  fireEvent.click(
    screen.getByRole("button", { name: "Open execution authorities" }),
  );
  expect(props.onSetupAuthority).toHaveBeenCalled();
  rerender(
    <PythonProgramRun
      {...props}
      authority={null}
      onSetupAuthority={undefined}
    />,
  );
  expect(
    screen.queryByRole("button", { name: "Open execution authorities" }),
  ).not.toBeInTheDocument();
  expect(
    screen.getByText(/build and run permission is required/),
  ).toBeVisible();
  expect(fetch).not.toHaveBeenCalled();
  rerender(<PythonProgramRun {...props} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Run current saved source" }),
  );
  await screen.findByText("Run requires a Plan build.");
  expect(fetch).toHaveBeenCalledTimes(1);
});

it.each(["result", "error"])(
  "does not expose a late workflow %s after an identity change",
  async (outcome) => {
    let finish: (value: Response) => void = () => undefined;
    let fail: (reason: Error) => void = () => undefined;
    const calls: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((path, init) => {
        const body = JSON.parse(init.body);
        calls.push(`${path}:${body.action}`);
        if (path === "/api/python-build")
          return Promise.resolve(response(plan));
        if (body.action === "request")
          return Promise.resolve(response({ ...workflow, status: "accepted" }));
        return new Promise<Response>((resolve, reject) => {
          finish = resolve;
          fail = reject;
        });
      }),
    );
    installOperationAdmissionFixture("c");
    const { rerender } = render(<PythonProgramRun {...props} />);
    fireEvent.click(
      screen.getByRole("button", { name: "Run current saved source" }),
    );
    await waitFor(() => expect(calls).toHaveLength(3));
    expect(screen.getByText(/Run: accepted/)).toBeInTheDocument();
    rerender(
      <PythonProgramRun
        {...props}
        catalog={{
          ...catalog,
          applicationAccess: {
            ...catalog.applicationAccess,
            issuer: "new",
            subjectId: "new",
          },
        }}
      />,
    );
    await act(async () =>
      outcome === "result"
        ? finish(response(workflow))
        : fail(new Error("Original actor's private failure")),
    );
    expect(
      screen.queryByLabelText("Python execution progress"),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/Run: accepted/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Original actor/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Run: published/)).not.toBeInTheDocument();
    expect(calls).toHaveLength(3);
  },
);

it("refuses a workflow response for another sealed build and keeps the original retry identity", async () => {
  const mutations: unknown[] = [];
  let mismatched = true;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      const body = JSON.parse(init.body);
      if (path === "/api/python-build") return response(plan);
      mutations.push(body);
      return response(
        mismatched ? { ...workflow, buildId: "foreign-build" } : workflow,
      );
    }),
  );
  installOperationAdmissionFixture("d");
  render(<PythonProgramRun {...props} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Run current saved source" }),
  );
  await screen.findByText(
    "Run returned a different build identity or invalid workflow outcome.",
  );
  expect(screen.queryByText(/Run: published/)).not.toBeInTheDocument();
  mismatched = false;
  fireEvent.click(
    screen.getByRole("button", { name: "Resume exact execution request" }),
  );
  await screen.findByText(/Run: published/);
  expect(mutations).toHaveLength(2);
  expect(mutations[1]).toEqual(originalReferenceRead(mutations[0]));
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
    screen.getByRole("button", { name: "Run current saved source" }),
  ).toBeDisabled();
  expect(screen.getByRole("alert")).toHaveTextContent("exact safe integers");
  rerender(<PythonProgramRun {...props} parameters='{"count":1e-1000}' />);
  expect(
    screen.getByRole("button", { name: "Run current saved source" }),
  ).toBeDisabled();
  expect(fetch).not.toHaveBeenCalled();
  rerender(
    <PythonProgramRun
      {...props}
      parameters='{"amount":"0.999999999999999999999","count":1}'
    />,
  );
  expect(
    screen.getByRole("button", { name: "Run current saved source" }),
  ).toBeEnabled();
  expect(screen.queryByRole("alert")).toBeNull();
});

it("refuses a build effect when all exact recovery slots are pinned", async () => {
  let admissions = 0;
  const effects = vi.fn();
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path) => {
      if (String(path) === "/api/operation-admission") {
        admissions += 1;
        return operationAdmissionResponse("4");
      }
      effects(path);
      return response(plan);
    }),
  );
  for (let index = 0; index < 24; index += 1) {
    const pin = renderHook(() =>
      usePreservedDraft(
        "ws",
        "app",
        `pending-${index}`,
        "Other original operation",
        false,
        { packet: "" },
        () => undefined,
      ),
    );
    act(() => {
      pin.result.current.retain({ packet: `packet-${index}` });
    });
    pin.unmount();
  }
  render(<PythonProgramRun {...props} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Run current saved source" }),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "cannot retain another recovery record",
  );
  expect(admissions).toBe(1);
  expect(effects).not.toHaveBeenCalled();
  expect(
    unsavedWorkSnapshot().filter(
      (item) => item.label === "Other original operation",
    ),
  ).toHaveLength(24);
});

it("reads the original accepted build after source and authority change without chaining a run, and can leave only a verified unrun Plan", async () => {
  const calls: Array<{ path: string; body: any }> = [];
  let reads = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      const body = JSON.parse(String(init?.body));
      calls.push({ path: String(path), body });
      if (body.action === "request")
        return response({ ...plan, status: "accepted" });
      if (++reads === 1) throw new TypeError("Status unavailable");
      return response(plan);
    }),
  );
  installOperationAdmissionFixture("5");
  const view = render(<PythonProgramRun {...props} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Run current saved source" }),
  );
  await screen.findByText("Status unavailable");
  expect(
    screen.queryByRole("button", { name: "Leave this Plan unrun" }),
  ).not.toBeInTheDocument();
  const changed = {
    ...props,
    program: { ...program, sourceToken: "d".repeat(64), status: "Inactive" },
    authority: { ...authority, status: "Revoked" as const },
  };
  view.rerender(<PythonProgramRun {...changed} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Reconcile original execution" }),
  );
  await screen.findByText(/Original Plan: sealed/);
  expect(calls.filter((call) => call.path === "/api/python-run")).toHaveLength(
    0,
  );
  expect(calls.at(-1)?.body).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    action: "read",
    buildId: planId,
  });
  expect(
    unsavedWorkSnapshot().some(
      (item) => item.label === "Original Python execution recovery",
    ),
  ).toBe(true);
  fireEvent.click(
    screen.getByRole("button", { name: "Leave this Plan unrun" }),
  );
  expect(unsavedWorkSnapshot()).toEqual([]);
  expect(calls).toHaveLength(3);
});

it("retains an expired unknown original packet after historical READ denial without readmission or resend", async () => {
  const bodies: unknown[] = [];
  let denied = false;
  let admissions = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      if (String(path) === "/api/operation-admission") {
        admissions += 1;
        return operationAdmissionResponse("6");
      }
      bodies.push(JSON.parse(String(init?.body)));
      if (!denied) throw new TypeError("Build reply lost");
      return new Response(JSON.stringify({ error: "ACCESS_DENIED" }), {
        status: 403,
      });
    }),
  );
  const view = render(<PythonProgramRun {...props} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Run current saved source" }),
  );
  await screen.findByText("Build reply lost");
  view.unmount();
  denied = true;
  vi.spyOn(Date, "now").mockReturnValue(Date.now() + 7_200_000);
  render(
    <PythonProgramRun
      {...props}
      program={{ ...program, status: "Inactive" }}
      authority={null}
    />,
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Reconcile original execution" }),
  );
  await screen.findByText("ACCESS_DENIED");
  expect(admissions).toBe(1);
  expect(bodies).toHaveLength(2);
  expect(bodies[1]).toEqual(originalReferenceRead(bodies[0]));
  expect(
    screen.queryByRole("button", { name: "Retry original request" }),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Leave this Plan unrun" }),
  ).not.toBeInTheDocument();
  expect(unsavedWorkSnapshot()).toHaveLength(1);
});

it("keeps an accepted workflow across remount and reads its exact original identity under changed source", async () => {
  const calls: Array<{ path: string; body: any }> = [];
  let workflowReads = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      const body = JSON.parse(String(init?.body));
      calls.push({ path: String(path), body });
      if (String(path) === "/api/python-build") return response(plan);
      if (body.action === "request")
        return response({
          ...workflow,
          status: "accepted",
          committedUnits: 0,
          remainingUnits: 1,
          checkpoints: [],
        });
      if (++workflowReads === 1)
        throw new TypeError("Workflow status unavailable");
      if (workflowReads === 2)
        return new Response(
          JSON.stringify({ error: "Current authority denied" }),
          {
            status: 403,
          },
        );
      return response(workflow);
    }),
  );
  installOperationAdmissionFixture("7");
  const first = render(<PythonProgramRun {...props} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Run current saved source" }),
  );
  await screen.findByText("Workflow status unavailable");
  first.unmount();
  render(
    <PythonProgramRun {...props} parameters='{"ratio":"9"}' authority={null} />,
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Reconcile original execution" }),
  );
  await screen.findByText("Current authority denied");
  expect(screen.queryByLabelText("Reconciled original execution")).toBeNull();
  fireEvent.click(
    screen.getByRole("button", { name: "Reconcile original execution" }),
  );
  await screen.findByText(/Original run: published/);
  expect(calls.filter((call) => call.body.action === "request")).toHaveLength(
    2,
  );
  expect(calls.at(-1)?.body).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    action: "read",
    workflowId: runId,
  });
  expect(unsavedWorkSnapshot()).toEqual([]);
});

it.each(["build", "run"] as const)(
  "recovers unknown %s by historical reference after source and execution authority change",
  async (lost) => {
    const effects: Array<{ path: string; body: any }> = [];
    const reads: Array<{ path: string; body: any }> = [];
    let admissions = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path, init) => {
        const body = JSON.parse(String(init?.body));
        if (String(path) === "/api/operation-admission") {
          admissions++;
          return operationAdmissionResponse(String(admissions));
        }
        if (body.action === "request") {
          effects.push({ path: String(path), body });
          if (String(path) === `/api/python-${lost}`)
            throw new TypeError("Original acknowledgement lost");
        } else reads.push({ path: String(path), body });
        return response(String(path) === "/api/python-build" ? plan : workflow);
      }),
    );
    const first = render(<PythonProgramRun {...props} />);
    fireEvent.click(
      screen.getByRole("button", { name: "Run current saved source" }),
    );
    await screen.findByText("Original acknowledgement lost");
    first.unmount();
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 7_200_000);
    render(
      <PythonProgramRun
        {...props}
        program={{
          ...program,
          sourceToken: "f".repeat(64),
          sourceDigest: "e".repeat(64),
          status: "Inactive",
        }}
        catalog={{
          ...catalog,
          functions: {},
          revisions: { ...catalog.revisions, security: 2 },
        }}
        parameters='{"ratio":"9"}'
        authority={null}
      />,
    );
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Reconcile original execution",
      }),
    );
    await screen.findByText(
      lost === "build" ? /Original Plan: sealed/ : /Original run: published/,
    );
    const original = effects.find(
      (effect) => effect.path === `/api/python-${lost}`,
    )!;
    expect(reads).toEqual([
      { path: original.path, body: originalReferenceRead(original.body) },
    ]);
    expect(effects).toHaveLength(lost === "build" ? 1 : 2);
    expect(admissions).toBe(effects.length);
    expect(
      screen.queryByRole("button", { name: "Run current saved source" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Retry original request" }),
    ).not.toBeInTheDocument();
    expect(unsavedWorkSnapshot()).toHaveLength(lost === "build" ? 1 : 0);
  },
);

it.each([
  ["build", 403, "ACCESS_DENIED"],
  ["run", 403, "ACCESS_DENIED"],
  ["build", 400, "OPERATION_ADMISSION_MISMATCH"],
  ["run", 400, "OPERATION_ADMISSION_MISMATCH"],
  ["build", 400, "PYTHON_BUILD_AUTHORIZATION_SCOPE_CHANGED"],
  ["run", 400, "PYTHON_WORKFLOW_AUTHORIZATION_SCOPE_CHANGED"],
  ["build", 403, "PYTHON_BUILD_UNAVAILABLE"],
  ["run", 403, "PYTHON_WORKFLOW_UNAVAILABLE"],
] as const)(
  "keeps %s reference recovery pinned after %s %s without offering an effect retry",
  async (lost, status, code) => {
    const effects: any[] = [];
    const reads: any[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path, init) => {
        const body = JSON.parse(String(init?.body));
        if (body.action === "request") {
          effects.push(body);
          if (String(path) === `/api/python-${lost}`)
            throw new TypeError("Lost acknowledgement");
          return response(plan);
        }
        reads.push(body);
        return new Response(JSON.stringify({ code }), { status });
      }),
    );
    installOperationAdmissionFixture("4");
    render(<PythonProgramRun {...props} />);
    fireEvent.click(
      screen.getByRole("button", { name: "Run current saved source" }),
    );
    await screen.findByText("Lost acknowledgement");
    fireEvent.click(
      screen.getByRole("button", { name: "Reconcile original execution" }),
    );
    await screen.findByText(code);
    expect(reads).toEqual([originalReferenceRead(effects.at(-1))]);
    expect(effects).toHaveLength(lost === "build" ? 1 : 2);
    expect(unsavedWorkSnapshot()).toHaveLength(1);
    expect(
      screen.queryByRole("button", { name: "Retry original request" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Run current saved source" }),
    ).toBeDisabled();
  },
);

it.each([
  ["build", false],
  ["run", false],
  ["build", true],
  ["run", true],
] as const)(
  "offers only an explicit unchanged %s retry after exact unavailable lookup, expired=%s",
  async (lost, expired) => {
    let lostOnce = false;
    let admissions = 0;
    const effects: Array<{ path: string; body: any }> = [];
    const reads: any[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path, init) => {
        const body = JSON.parse(String(init?.body));
        if (String(path) === "/api/operation-admission") {
          admissions++;
          return operationAdmissionResponse(String(admissions));
        }
        if (body.action === "request") {
          effects.push({ path: String(path), body });
          if (String(path) === `/api/python-${lost}`) {
            if (!lostOnce) {
              lostOnce = true;
              throw new TypeError("Request delivery unknown");
            }
            if (expired)
              return new Response(
                JSON.stringify({ code: "OPERATION_ADMISSION_EXPIRED" }),
                { status: 400 },
              );
          }
          return response(
            String(path) === "/api/python-build" ? plan : workflow,
          );
        }
        reads.push(body);
        return new Response(
          JSON.stringify({
            code:
              lost === "build"
                ? "PYTHON_BUILD_UNAVAILABLE"
                : "PYTHON_WORKFLOW_UNAVAILABLE",
          }),
          { status: 400 },
        );
      }),
    );
    const first = render(<PythonProgramRun {...props} />);
    fireEvent.click(
      screen.getByRole("button", { name: "Run current saved source" }),
    );
    await screen.findByText("Request delivery unknown");
    expect(
      screen.queryByRole("button", { name: "Retry original request" }),
    ).not.toBeInTheDocument();
    const original = effects.at(-1)!;
    if (expired) vi.spyOn(Date, "now").mockReturnValue(Date.now() + 7_200_000);
    fireEvent.click(
      screen.getByRole("button", { name: "Reconcile original execution" }),
    );
    await screen.findByRole("button", { name: "Retry original request" });
    expect(reads).toEqual([originalReferenceRead(original.body)]);
    expect(effects).toHaveLength(lost === "build" ? 1 : 2);
    first.unmount();
    render(<PythonProgramRun {...props} />);
    fireEvent.click(
      await screen.findByRole("button", { name: "Retry original request" }),
    );
    if (expired) await screen.findByText("OPERATION_ADMISSION_EXPIRED");
    else
      await screen.findByText(
        lost === "build" ? /Plan: sealed/ : /Run: published/,
      );
    expect(effects.at(-1)).toEqual(original);
    expect(effects).toHaveLength(lost === "build" ? 2 : 3);
    expect(admissions).toBe(lost === "build" ? 1 : 2);
    expect(
      screen.queryByRole("button", { name: "Retry original request" }),
    ).not.toBeInTheDocument();
    expect(unsavedWorkSnapshot()).toHaveLength(
      !expired && lost === "run" ? 0 : 1,
    );
    if (lost === "build")
      expect(effects.some((effect) => effect.path === "/api/python-run")).toBe(
        false,
      );
  },
);

it("rejects an old missing-reference reply after a remounted owner has recovered the workflow", async () => {
  let finishOld!: (value: Response) => void;
  let originalReads = 0;
  const effects: any[] = [];
  const reads: any[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      const body = JSON.parse(String(init?.body));
      if (body.action === "request") {
        effects.push(body);
        if (String(path) === "/api/python-run")
          throw new TypeError("Original run unknown");
        return response(plan);
      }
      reads.push(body);
      if (body.originalRequest && ++originalReads === 1)
        return new Promise<Response>((resolve) => {
          finishOld = resolve;
        });
      return response(
        body.originalRequest
          ? {
              ...workflow,
              status: "running",
              checkpoints: [],
              committedUnits: 0,
              remainingUnits: 1,
            }
          : workflow,
      );
    }),
  );
  installOperationAdmissionFixture("7");
  const first = render(<PythonProgramRun {...props} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Run current saved source" }),
  );
  await screen.findByText("Original run unknown");
  fireEvent.click(
    screen.getByRole("button", { name: "Reconcile original execution" }),
  );
  await waitFor(() => expect(finishOld).toBeTypeOf("function"));
  first.unmount();
  const second = render(<PythonProgramRun {...props} />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Reconcile original execution" }),
  );
  await screen.findByText(/Run: running/);
  await act(async () =>
    finishOld(
      new Response(JSON.stringify({ code: "PYTHON_WORKFLOW_UNAVAILABLE" }), {
        status: 400,
      }),
    ),
  );
  expect(
    screen.queryByRole("button", { name: "Retry original request" }),
  ).not.toBeInTheDocument();
  second.unmount();
  render(<PythonProgramRun {...props} />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Reconcile original execution" }),
  );
  await screen.findByText(/Run: published/);
  expect(reads.slice(0, 2)).toEqual([
    originalReferenceRead(effects[1]),
    originalReferenceRead(effects[1]),
  ]);
  expect(reads[2]).toEqual({
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    action: "read",
    workflowId: runId,
  });
  expect(effects).toHaveLength(2);
  expect(unsavedWorkSnapshot()).toEqual([]);
});

it.each([
  { status: "invented" },
  { workflowId: "wrong" },
  { planDigest: "f".repeat(64) },
  { committedUnits: undefined },
  { committedUnits: null },
  { committedUnits: false },
  { remainingUnits: undefined },
  { remainingUnits: null },
  { remainingUnits: false },
  { committedUnits: -1 },
  { remainingUnits: 1 },
  { unitCount: 0, committedUnits: 0, remainingUnits: 0, checkpoints: [] },
  {
    unitCount: 10001,
    committedUnits: 0,
    remainingUnits: 10001,
    checkpoints: [],
  },
  { committedUnits: 0, remainingUnits: 1, checkpoints: [] },
  { status: "failed" },
  { status: "cancelled" },
  {
    status: "partially_published",
    committedUnits: 0,
    remainingUnits: 1,
    checkpoints: [],
  },
  { checkpoints: [] },
  {
    checkpoints: [
      { ordinal: 2, jobId: "job-1", committed: true, receiptId: "receipt-1" },
    ],
  },
  {
    checkpoints: [
      { ordinal: 1, jobId: "job-1", committed: true, receiptId: null },
    ],
  },
])(
  "keeps original run recovery for malformed terminal evidence %j",
  async (invalid) => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path) =>
        response(
          String(path) === "/api/python-build"
            ? plan
            : { ...workflow, ...invalid },
        ),
      ),
    );
    installOperationAdmissionFixture("8");
    render(<PythonProgramRun {...props} />);
    fireEvent.click(
      screen.getByRole("button", { name: "Run current saved source" }),
    );
    await screen.findByText(
      "Run returned a different build identity or invalid workflow outcome.",
    );
    expect(
      screen.getByRole("button", { name: "Run current saved source" }),
    ).toBeDisabled();
    expect(
      screen.queryByRole("button", { name: "Leave this Plan unrun" }),
    ).not.toBeInTheDocument();
    expect(unsavedWorkSnapshot()).toHaveLength(1);
  },
);

it("keeps NeedsInspection pinned instead of enabling another execution", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path) =>
      response(
        String(path) === "/api/python-build"
          ? plan
          : {
              ...workflow,
              status: "needs_inspection",
              committedUnits: 0,
              remainingUnits: 1,
              checkpoints: [],
            },
      ),
    ),
  );
  installOperationAdmissionFixture("9");
  render(<PythonProgramRun {...props} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Run current saved source" }),
  );
  await screen.findByText(/original workflow needs inspection/);
  expect(
    screen.queryByRole("button", { name: "Run again" }),
  ).not.toBeInTheDocument();
  expect(unsavedWorkSnapshot()).toHaveLength(1);
});

it("never recreates a private attempt from a late build response after explicit identity abandonment", async () => {
  let finish!: (response: Response) => void;
  const calls: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn((path) => {
      calls.push(String(path));
      return new Promise<Response>((resolve) => {
        finish = resolve;
      });
    }),
  );
  installOperationAdmissionFixture("a");
  setDraftIdentity("actor-one");
  const view = render(<PythonProgramRun {...props} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Run current saved source" }),
  );
  await waitFor(() => expect(calls).toHaveLength(1));
  act(() => discardUnsavedWork({ abandonRecovery: true }));
  setDraftIdentity("actor-two");
  view.rerender(
    <PythonProgramRun
      {...props}
      catalog={{
        ...catalog,
        applicationAccess: {
          ...catalog.applicationAccess,
          issuer: "other",
          subjectId: "other",
        },
      }}
    />,
  );
  await act(async () => finish(response(plan)));
  expect(unsavedWorkSnapshot()).toEqual([]);
  expect(
    screen.queryByLabelText("Original execution recovery"),
  ).not.toBeInTheDocument();
  expect(screen.queryByText(/Plan: sealed/)).not.toBeInTheDocument();
  expect(calls).toHaveLength(1);
});

it("accepts native partial publication after the last committed unit without rerunning it", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path) =>
      response(
        String(path) === "/api/python-build"
          ? plan
          : { ...workflow, status: "partially_published" },
      ),
    ),
  );
  installOperationAdmissionFixture("b");
  render(<PythonProgramRun {...props} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Run current saved source" }),
  );
  expect(await screen.findByText(/Run: partially published/)).toHaveRole(
    "status",
  );
  expect(unsavedWorkSnapshot()).toEqual([]);
  expect(screen.getByRole("button", { name: "Run again" })).toBeEnabled();
});

it.each(["capability", "source kind"] as const)(
  "stops chaining and preserves original status recovery when the %s changes during acceptance",
  async (change) => {
    let finish!: (response: Response) => void;
    const calls: Array<{ path: string; body: any }> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn((path, init) => {
        const body = JSON.parse(String(init?.body));
        calls.push({ path: String(path), body });
        if (calls.length === 1)
          return new Promise<Response>((resolve) => {
            finish = resolve;
          });
        return Promise.resolve(response(plan));
      }),
    );
    installOperationAdmissionFixture("b");
    const view = render(<PythonProgramRun {...props} />);
    fireEvent.click(
      screen.getByRole("button", { name: "Run current saved source" }),
    );
    await waitFor(() => expect(calls).toHaveLength(1));
    view.rerender(
      <PythonProgramRun
        {...props}
        catalog={
          change === "capability" ? { ...catalog, functions: {} } : catalog
        }
        program={
          change === "source kind"
            ? {
                ...program,
                declaredOutput: {
                  kind: "ApplicationRule",
                  definitionId: "forecast",
                },
              }
            : program
        }
      />,
    );
    await act(async () => finish(response(plan)));
    expect(
      screen.queryByRole("button", { name: "Run current saved source" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Resume exact execution request" }),
    ).not.toBeInTheDocument();
    expect(calls).toHaveLength(1);
    fireEvent.click(
      screen.getByRole("button", { name: "Reconcile original execution" }),
    );
    await screen.findByText(/Original Plan: sealed/);
    // The aborted transport discards its late response; recovery selects the
    // original signed reference before any known-ID read is possible.
    expect(calls[1]).toEqual({
      path: calls[0].path,
      body: originalReferenceRead(calls[0].body),
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Reconcile original execution" }),
    );
    await waitFor(() => expect(calls).toHaveLength(3));
    expect(calls[2]).toEqual({
      path: "/api/python-build",
      body: {
        workspaceId: "ws",
        applicationId: "app",
        action: "read",
        buildId: planId,
      },
    });
    expect(unsavedWorkSnapshot()).toHaveLength(1);
    view.rerender(
      <PythonProgramRun
        {...props}
        catalog={{
          ...catalog,
          functions: {},
          applicationAccess: {
            ...catalog.applicationAccess,
            issuer: "new",
            subjectId: "new",
          },
        }}
      />,
    );
    expect(
      screen.queryByRole("button", { name: "Reconcile original execution" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/Original Plan:/)).not.toBeInTheDocument();
    expect(calls).toHaveLength(3);
  },
);

it("preserves a remounted original run packet when the first mount's late build response arrives", async () => {
  let finishOld!: (response: Response) => void;
  const calls: Array<{ path: string; body: any }> = [];
  let builds = 0;
  let loseRun = true;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      const body = JSON.parse(String(init?.body));
      calls.push({ path: String(path), body });
      if (
        String(path) === "/api/python-build" &&
        body.action === "request" &&
        ++builds === 1
      )
        return new Promise<Response>((resolve) => {
          finishOld = resolve;
        });
      if (String(path) === "/api/python-run" && loseRun)
        throw new TypeError("Original run response lost");
      return response(String(path) === "/api/python-build" ? plan : workflow);
    }),
  );
  installOperationAdmissionFixture("8");
  const first = render(<PythonProgramRun {...props} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Run current saved source" }),
  );
  await waitFor(() => expect(finishOld).toBeTypeOf("function"));
  first.unmount();
  const second = render(<PythonProgramRun {...props} />);
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Resume exact execution request",
    }),
  );
  await screen.findByText("Original run response lost");
  const originalRun = calls.at(-1);
  await act(async () => finishOld(response(plan)));
  second.unmount();
  loseRun = false;
  render(<PythonProgramRun {...props} />);
  fireEvent.click(
    await screen.findByRole("button", { name: "Reconcile original execution" }),
  );
  await screen.findByText(/Run: published/);
  expect(calls.at(-1)).toEqual({
    path: originalRun!.path,
    body: originalReferenceRead(originalRun!.body),
  });
  expect(
    calls.filter((call) => call.path === "/api/python-build"),
  ).toHaveLength(2);
  expect(unsavedWorkSnapshot()).toEqual([]);
});

it("reports cancelled-workflow counts as confirmed evidence while independent child outcomes remain pending", async () => {
  const effects: unknown[] = [];
  const calls: Array<{ path: string; body: any }> = [];
  const pending = {
    ...workflow,
    status: "cancel_requested",
    unitCount: 3,
    committedUnits: 1,
    remainingUnits: 2,
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      const body = JSON.parse(init.body);
      calls.push({ path: String(path), body });
      if (path === "/api/python-build") return response(plan);
      if (body.action === "request") {
        effects.push(body);
        throw new TypeError("Original run response lost");
      }
      return response(pending);
    }),
  );
  installOperationAdmissionFixture("7");
  render(<PythonProgramRun {...props} />);
  fireEvent.click(
    screen.getByRole("button", { name: "Run current saved source" }),
  );
  await screen.findByText("Original run response lost");
  fireEvent.click(
    screen.getByRole("button", { name: "Reconcile original execution" }),
  );
  await screen.findByText(/Run: cancellation requested/);
  expect(screen.getByText(/Run: cancellation requested/)).toHaveTextContent(
    "1 receipt-confirmed committed units · 2 remaining units without a confirmed receipt",
  );
  fireEvent.click(screen.getByText("Workflow checkpoint evidence"));
  expect(screen.getByText("Committed with receipt")).toBeVisible();
  expect(screen.getAllByText("No checkpoint recorded")).toHaveLength(2);
  expect(
    screen.queryByRole("button", { name: /Inspect receipt for step/ }),
  ).toBeNull();
  expect(
    screen.getByText(/Cancellation reconciliation is still pending/),
  ).toHaveTextContent(
    "unstarted, cancelled or unresolved work, including any child whose effect may already have committed",
  );
  expect(
    screen.getByText(/Cancellation reconciliation is still pending/),
  ).toHaveTextContent("These counts do not claim rollback");
  expect(effects).toHaveLength(1);
  expect(calls.at(-1)?.body).toMatchObject({
    action: "read",
    originalRequest: { program: { function: "python.program.run" } },
  });
  expect(
    screen.queryByRole("button", { name: "Prepare another run" }),
  ).not.toBeInTheDocument();
});
