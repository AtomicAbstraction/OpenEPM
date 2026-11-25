import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { Monitor } from "./Monitor";
import type { ApplicationCatalog, Scope } from "./types";

afterEach(() => vi.unstubAllGlobals());

const scope = { workspaceId: "workspace", applicationId: "forecast" };
const app = { ...scope, name: "Forecast", status: "Active" };
const admin: ApplicationCatalog = {
  applicationAccess: {
    role: "Administrator",
    workspaceAdministrator: false,
    subjectId: "actor",
    issuer: "issuer",
  },
  enabledCapabilities: [],
  revisions: { metadata: 3, data: 2, policy: 0, security: 4, commit: 9 },
  functions: {},
};

function snapshot({ workspaceId, applicationId }: Scope = scope) {
  return {
    scope: { workspaceId, applicationId },
    queueObservedAt: "2026-11-21T10:25:11.120Z",
    metricScopes: {
      queueDepths: "authorized_application_only",
      queueOldestAgeSeconds: "authorized_application_fixed_family_only",
      workers: "authorized_application_only",
    },
    queueDepths: { exportProducer: 3, pythonSchedule: 0 },
    queueOldestAgeSeconds: { exportProducer: 305, pythonSchedule: 0 },
    workers: {
      byFamily: {
        exportProducer: { activeClaims: 2, liveClaims: 1, expiredClaims: 1 },
        pythonSchedule: { activeClaims: 0, liveClaims: 0, expiredClaims: 0 },
      },
    },
    databaseTempBytes: 76344518,
  };
}

function impactSnapshot(impact: Record<string, unknown>, depth: number) {
  const value = snapshot();
  return {
    ...value,
    metricScopes: {
      ...value.metricScopes,
      calculationImpact: "authorized_application_only",
    },
    queueDepths: { ...value.queueDepths, calculationImpact: depth },
    queueOldestAgeSeconds: {
      ...value.queueOldestAgeSeconds,
      calculationImpact: depth ? 71 : 0,
    },
    workers: {
      byFamily: {
        ...value.workers.byFamily,
        calculationImpact: { activeClaims: 0, liveClaims: 0, expiredClaims: 0 },
      },
    },
    calculationImpact: impact,
  };
}

const json = (value: unknown, status = 200) =>
  new Response(JSON.stringify(value), { status });

function install(
  read: (
    body: Scope & { view: "queues" },
    signal: AbortSignal,
  ) => Response | Promise<Response>,
) {
  const calls = vi.fn(read);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path: string, init: RequestInit) => {
      if (path === "/api/tasks")
        return json({ tasks: [], nextSequence: 0, hasMore: false });
      if (path === "/api/capacity-metrics")
        return calls(JSON.parse(String(init.body)), init.signal!);
      throw new Error("Unexpected Monitor request");
    }),
  );
  return calls;
}

it("opens the scoped queue on request and preserves keyboard focus through refresh", async () => {
  let finish: ((response: Response) => void) | undefined;
  const calls = install(
    () =>
      new Promise<Response>((resolve) => {
        finish = resolve;
      }),
  );
  render(<Monitor app={app} catalog={admin} />);
  const show = screen.getByRole("button", { name: "Show queue" });
  expect(show).toHaveAttribute("aria-expanded", "false");
  expect(calls).not.toHaveBeenCalled();
  show.focus();
  fireEvent.click(show);
  expect(await screen.findByText("Reading queue observations…")).toBeVisible();
  expect(show).toHaveFocus();
  expect(calls.mock.calls[0][0]).toEqual({ ...scope, view: "queues" });
  expect(screen.queryByRole("table", { name: /queue/i })).toBeNull();
  await act(async () => finish!(json(snapshot())));
  expect(screen.getByText("2026-11-21 10:25:11 UTC")).toHaveAttribute(
    "datetime",
    "2026-11-21T10:25:11.120Z",
  );
  expect(screen.getByText(/Some worker leases had expired/)).toBeVisible();
  const queue = within(
    await screen.findByRole("region", {
      name: "Queue observations by work family",
    }),
  );
  expect(
    queue.getByRole("row", { name: "Export production 3 305 1 1" }),
  ).toBeVisible();
  expect(
    queue.getByRole("row", { name: "Python schedules 0 — 0 0" }),
  ).toBeVisible();
  expect(screen.queryByText("76344518")).toBeNull();
  const refresh = screen.getByRole("button", { name: "Refresh queue" });
  refresh.focus();
  fireEvent.click(refresh);
  fireEvent.click(refresh);
  expect(calls).toHaveBeenCalledTimes(2);
  expect(refresh).toHaveFocus();
  expect(refresh).toHaveAttribute("aria-disabled", "true");
  expect(
    screen.queryByRole("region", { name: "Queue observations by work family" }),
  ).toBeNull();
  expect(screen.queryByText("2026-11-21 10:25:11 UTC")).toBeNull();
  const settled = snapshot();
  settled.queueObservedAt = "2026-11-21T10:29:01.032Z";
  settled.workers.byFamily.exportProducer = {
    activeClaims: 2,
    liveClaims: 2,
    expiredClaims: 0,
  };
  await act(async () => finish!(json(settled)));
  expect(
    await screen.findByRole("row", { name: "Export production 3 305 2 0" }),
  ).toBeVisible();
  expect(screen.getByText("2026-11-21 10:29:01 UTC")).toHaveAttribute(
    "datetime",
    settled.queueObservedAt,
  );
  expect(screen.queryByText("2026-11-21 10:25:11 UTC")).toBeNull();
  expect(refresh).toHaveFocus();
});

it("distinguishes a saturated queue read from a new observation", async () => {
  let reads = 0;
  install(() =>
    ++reads === 2
      ? json({ code: "PROCESSING_LOCK_BUSY_RETRY" }, 429)
      : json(snapshot()),
  );
  render(<Monitor app={app} catalog={admin} />);
  fireEvent.click(screen.getByRole("button", { name: "Show queue" }));
  await screen.findByRole("region", {
    name: "Queue observations by work family",
  });
  const refresh = screen.getByRole("button", { name: "Refresh queue" });
  refresh.focus();
  fireEvent.click(refresh);
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "The application is busy and could not return a queue observation.",
  );
  expect(
    screen.queryByRole("region", { name: "Queue observations by work family" }),
  ).not.toBeInTheDocument();
  expect(refresh).toHaveFocus();
  fireEvent.click(refresh);
  await screen.findByRole("region", {
    name: "Queue observations by work family",
  });
  expect(reads).toBe(3);
});

it.each([
  ["another application", () => snapshot({ ...scope, applicationId: "other" })],
  [
    "no observation time",
    () => ({ ...snapshot(), queueObservedAt: undefined }),
  ],
  [
    "an invalid observation time",
    () => ({ ...snapshot(), queueObservedAt: "2026-02-30T10:29:01.032Z" }),
  ],
  [
    "an incomplete family",
    () => ({ ...snapshot(), queueOldestAgeSeconds: { exportProducer: 1 } }),
  ],
  [
    "different metric scope",
    () => ({ ...snapshot(), metricScopes: { workers: "host" } }),
  ],
  [
    "unsupported negative counts",
    () => ({
      ...snapshot(),
      queueDepths: { exportProducer: -1, pythonSchedule: 0 },
    }),
  ],
  [
    "a failed impact with an empty queue",
    () =>
      impactSnapshot(
        { status: "failed", failureCode: "CALCULATION_IMPACT_FANOUT_LIMIT" },
        0,
      ),
  ],
  [
    "a raw worker diagnostic",
    () =>
      impactSnapshot(
        { status: "failed", failureCode: "private query and source row" },
        2,
      ),
  ],
] as const)(
  "withholds numbers when a response contains %s",
  async (_description, response) => {
    install(() => json(response()));
    render(<Monitor app={app} catalog={admin} />);
    fireEvent.click(screen.getByRole("button", { name: "Show queue" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The queue snapshot could not be verified",
    );
    expect(
      screen.queryByRole("row", { name: /^Export production/ }),
    ).toBeNull();
    expect(screen.getByRole("button", { name: "Refresh queue" })).toBeEnabled();
  },
);

it("shows a blocking impact and clears the warning after recovery", async () => {
  const failure = {
    status: "failed",
    failureCode: "CALCULATION_IMPACT_FANOUT_LIMIT",
  };
  let response = impactSnapshot(failure, 2);
  install(() => json(response));
  render(<Monitor app={app} catalog={admin} />);
  fireEvent.click(screen.getByRole("button", { name: "Show queue" }));
  expect(
    await screen.findByRole("row", { name: "Calculation impacts 2 71 0 0" }),
  ).toBeVisible();
  const queue = within(
    screen.getByRole("region", { name: "Application queue and leases" }),
  );
  expect(queue.getByRole("status")).toHaveTextContent(
    /later impacts were waiting at that time/,
  );
  expect(screen.getByText(failure.failureCode)).toBeVisible();

  response = impactSnapshot({ status: "pending" }, 1);
  const refresh = screen.getByRole("button", { name: "Refresh queue" });
  refresh.focus();
  fireEvent.click(refresh);
  expect(
    await screen.findByRole("row", { name: "Calculation impacts 1 71 0 0" }),
  ).toBeVisible();
  expect(screen.queryByText(failure.failureCode)).toBeNull();
  expect(refresh).toHaveFocus();

  response = impactSnapshot({ status: "clear" }, 0);
  fireEvent.click(refresh);
  expect(
    await screen.findByRole("row", { name: "Calculation impacts 0 — 0 0" }),
  ).toBeVisible();
  expect(refresh).toHaveFocus();
});

it.each([
  [
    "APPLICATION_GRANT_REQUIRED",
    403,
    "Current access does not allow queue observations",
  ],
  [
    "CAPACITY_READ_AUTHORIZATION_STALE",
    409,
    "Access changed while reading the queue. Check current application access and refresh the queue.",
  ],
])(
  "clears the previous snapshot after a %s refresh failure",
  async (code, status, message) => {
    let denied = false;
    install(() =>
      denied
        ? json({ code, message: "private diagnostic" }, status)
        : json(snapshot()),
    );
    render(<Monitor app={app} catalog={admin} />);
    fireEvent.click(screen.getByRole("button", { name: "Show queue" }));
    await screen.findByRole("row", { name: /^Export production/ });
    expect(screen.getByText("2026-11-21 10:25:11 UTC")).toBeVisible();
    denied = true;
    fireEvent.click(screen.getByRole("button", { name: "Refresh queue" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(message);
    expect(screen.queryByText(/private diagnostic/)).toBeNull();
    expect(screen.queryByText("2026-11-21 10:25:11 UTC")).toBeNull();
    expect(
      screen.queryByRole("row", { name: /^Export production/ }),
    ).toBeNull();
  },
);

it("reports an unavailable collector without inventing empty queue readings", async () => {
  install(() => json({ code: "POSTGRES_OPERATION_FAILED" }, 503));
  render(<Monitor app={app} catalog={admin} />);
  fireEvent.click(screen.getByRole("button", { name: "Show queue" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Queue observations are unavailable. Refresh queue to try again.",
  );
  expect(
    screen.queryByRole("region", { name: "Queue observations by work family" }),
  ).toBeNull();
});

it("discards a pending snapshot on administrator downgrade and does not read as an Editor", async () => {
  let finish: ((response: Response) => void) | undefined;
  const calls = install(
    () =>
      new Promise<Response>((resolve) => {
        finish = resolve;
      }),
  );
  const { rerender } = render(<Monitor app={app} catalog={admin} />);
  fireEvent.click(screen.getByRole("button", { name: "Show queue" }));
  const signal = calls.mock.calls[0][1];
  rerender(
    <Monitor
      app={app}
      catalog={{
        ...admin,
        applicationAccess: { ...admin.applicationAccess, role: "Editor" },
      }}
    />,
  );
  expect(signal.aborted).toBe(true);
  await act(async () => finish!(json(snapshot())));
  expect(
    screen.queryByRole("region", { name: "Application queue and leases" }),
  ).toBeNull();
  expect(calls).toHaveBeenCalledTimes(1);
  rerender(<Monitor app={app} catalog={admin} />);
  expect(screen.getByRole("button", { name: "Show queue" })).toHaveAttribute(
    "aria-expanded",
    "false",
  );
  expect(screen.queryByRole("row", { name: /^Export production/ })).toBeNull();
});

it("reads a new application only on request and discards a late result from the first scope", async () => {
  let finish: ((response: Response) => void) | undefined;
  const calls = install((requested) =>
    requested.applicationId === scope.applicationId
      ? new Promise<Response>((resolve) => {
          finish = resolve;
        })
      : json(snapshot(requested)),
  );
  const { rerender } = render(<Monitor app={app} catalog={admin} />);
  fireEvent.click(screen.getByRole("button", { name: "Show queue" }));
  const other = { ...app, applicationId: "operations" };
  rerender(<Monitor app={other} catalog={admin} />);
  expect(calls.mock.calls[0][1].aborted).toBe(true);
  await act(async () => finish!(json(snapshot())));
  const show = screen.getByRole("button", { name: "Show queue" });
  expect(show).toHaveAttribute("aria-expanded", "false");
  expect(calls).toHaveBeenCalledTimes(1);
  fireEvent.click(show);
  expect(
    await screen.findByRole("row", { name: /^Export production/ }),
  ).toBeVisible();
  expect(calls.mock.calls[1][0]).toEqual({
    ...scope,
    applicationId: "operations",
    view: "queues",
  });
});
