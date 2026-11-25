import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { Profiler } from "react";
import { Analyze } from "./Analyze";
import type { ApplicationCatalog } from "./types";

afterEach(() => vi.unstubAllGlobals());
type Call = {
  function: string;
  arguments: Record<string, any>;
  applicationId: string;
  signal?: AbortSignal;
};
const result = (value: unknown) =>
  new Response(JSON.stringify({ result: value }));
const denied = () =>
  new Response(JSON.stringify({ code: "OLD_READ_DENIED" }), { status: 403 });
const tables = (name: string, nextAfterTableId: string | null = null) =>
  result({
    rows: [
      { table_id: "table_a", name: `${name} A`, status: "Active" },
      { table_id: "table_b", name: `${name} B`, status: "Active" },
    ],
    nextAfterTableId,
  });
const facts = (label: string, nextCursor: string | null = null) =>
  result({
    rows: [{ series_key: label, value: { exact: label }, change_id: label }],
    snapshotRevision: 1,
    nextCursor,
  });
const members = (label: string) =>
  result({
    rows: [{ member_id: label, name: label, status: "Active" }],
    metadataRevision: 1,
    nextAfterMemberId: null,
  });
const defer = () => {
  let resolve!: (response: Response) => void;
  const promise = new Promise<Response>((done) => {
    resolve = done;
  });
  return { promise, resolve };
};
async function setup(
  handler?: (call: Call) => Response | Promise<Response> | undefined,
  onCommit?: () => void,
) {
  const calls: Call[] = [];
  let app = {
    workspaceId: "w",
    applicationId: "a",
    name: "Model",
    status: "Active",
  };
  let subject = "actor-one";
  let catalog: ApplicationCatalog = {
    applicationAccess: {
      issuer: "issuer",
      subjectId: subject,
      role: "Editor",
      workspaceAdministrator: false,
    },
    functions: Object.fromEntries(
      [
        "metadata.dimension.list",
        "metadata.member.list",
        "facts.generic.table.list",
        "facts.generic.value.snapshot.scan",
      ].map((name) => [name, {}]),
    ),
    enabledCapabilities: [],
    revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_path, init) => {
      const body = JSON.parse(String(init.body));
      const call = {
        ...body.program,
        applicationId: body.applicationId,
        signal: init.signal,
      } as Call;
      calls.push(call);
      const custom = handler?.(call);
      if (custom !== undefined) return custom;
      if (call.function === "metadata.dimension.list")
        return result({
          rows: ["Account", "Period", "Scenario", "Region"].map((id) => ({
            dimension_id: id,
            name: id === "Region" ? "Region taxonomy" : id,
            model_role: id === "Region" ? "Custom" : id,
            status: "Active",
          })),
          metadataRevision: 1,
          nextAfterDimensionId: null,
        });
      if (call.function === "metadata.member.list")
        return result({
          rows: ["Default", "Manual"].map((prefix) => ({
            member_id: `${prefix}-${call.arguments.dimension}`,
            name: `${prefix} ${call.arguments.dimension}`,
            status: "Active",
          })),
          metadataRevision: 1,
          nextAfterMemberId: null,
        });
      if (call.function === "facts.generic.table.list")
        return tables("Current");
      if (call.function === "facts.generic.value.snapshot.scan")
        return facts(`Current-${call.arguments.tableId}`);
      throw new Error(`Unexpected function ${call.function}`);
    }),
  );
  const element = () => {
    const analyze = (
      <Analyze app={app} catalog={catalog} index={0} subject={subject} />
    );
    return onCommit ? (
      <Profiler id="generic-context-readiness" onRender={onCommit}>
        {analyze}
      </Profiler>
    ) : (
      analyze
    );
  };
  const view = render(element());
  await waitFor(() =>
    expect(
      calls.some((call) => call.function === "metadata.dimension.list"),
    ).toBe(true),
  );
  async function switchContext(kind: "application" | "identity" | "grant") {
    if (kind === "application") app = { ...app, applicationId: "b" };
    if (kind === "identity") {
      subject = "actor-two";
      catalog = {
        ...catalog,
        applicationAccess: { ...catalog.applicationAccess, subjectId: subject },
      };
    }
    if (kind === "grant")
      catalog = {
        ...catalog,
        revisions: { ...catalog.revisions, security: 2 },
      };
    view.rerender(element());
    await act(async () => undefined);
  }
  return { calls, view, switchContext };
}
const changes = ["application", "identity", "grant"] as const;
const outcomes = ["success", "denial"] as const;

it("offers only current fact axes in the Grid layout", async () => {
  await setup((call) =>
    call.function === "metadata.dimension.list"
      ? result({
          rows: [
            {
              dimension_id: "Account",
              name: "Account",
              model_role: "Account",
              status: "Active",
            },
            {
              dimension_id: "Period",
              name: "Period",
              model_role: "Period",
              status: "Active",
            },
            {
              dimension_id: "Region",
              name: "Region",
              model_role: "Custom",
              status: "Active",
            },
            {
              dimension_id: "QuoteCurrency",
              name: "Quote currency",
              model_role: "Currency",
              status: "Active",
            },
            {
              dimension_id: "FormerChannel",
              name: "Former channel",
              model_role: "Custom",
              status: "Inactive",
            },
          ],
          metadataRevision: 1,
          nextAfterDimensionId: null,
        })
      : undefined,
  );
  fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
  const rows = within(screen.getByRole("combobox", { name: "Rows" }));
  expect(
    await rows.findByRole("option", { name: "Region" }),
  ).toBeInTheDocument();
  expect(rows.queryByRole("option", { name: "Quote currency" })).toBeNull();
  expect(rows.queryByRole("option", { name: "Former channel" })).toBeNull();
});

it.each(
  changes.flatMap((change) =>
    outcomes.map((outcome) => [change, outcome] as const),
  ),
)(
  "ignores late generic discovery %s context / %s, including continuation and finalization",
  async (change, outcome) => {
    const old = defer(),
      current = defer();
    let lists = 0;
    const { calls, switchContext } = await setup((call) =>
      call.function === "facts.generic.table.list"
        ? ++lists === 1
          ? old.promise
          : current.promise
        : undefined,
    );
    fireEvent.click(screen.getByRole("button", { name: "Generic facts" }));
    await waitFor(() => expect(lists).toBe(1));
    const oldCall = calls.find(
      (call) => call.function === "facts.generic.table.list",
    )!;
    await switchContext(change);
    expect(oldCall.signal?.aborted).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Generic facts" }));
    await waitFor(() => expect(lists).toBe(2));
    await act(async () =>
      old.resolve(
        outcome === "success"
          ? tables("Old private table", "old-continuation")
          : denied(),
      ),
    );
    expect(
      screen.getByRole("button", { name: "Generic facts" }),
    ).toBeDisabled();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByText(/Old private table/)).not.toBeInTheDocument();
    expect(lists).toBe(2);
    await act(async () => current.resolve(tables("Current table")));
    expect(screen.getByLabelText("Generic fact table")).toHaveValue("table_a");
    expect(
      screen.getByRole("option", { name: "Current table A" }),
    ).toBeInTheDocument();
  },
);

it.each(
  changes.flatMap((change) =>
    outcomes.map((outcome) => [change, outcome] as const),
  ),
)(
  "hides loaded generic records and rejects late page %s context / %s",
  async (change, outcome) => {
    const old = defer(),
      current = defer();
    let reads = 0;
    const { calls, switchContext } = await setup((call) =>
      call.function === "facts.generic.value.snapshot.scan"
        ? ++reads === 1
          ? facts("Old private record", "old-page")
          : reads === 2
            ? old.promise
            : current.promise
        : undefined,
    );
    fireEvent.click(screen.getByRole("button", { name: "Generic facts" }));
    await screen.findByLabelText("Generic fact table");
    fireEvent.click(screen.getByRole("button", { name: "Read records" }));
    await screen.findByText("Old private record", { selector: "th" });
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    await waitFor(() => expect(reads).toBe(2));
    await switchContext(change);
    expect(screen.queryByText("Old private record")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Generic fact table")).toHaveValue("");
    fireEvent.click(screen.getByRole("button", { name: "Generic facts" }));
    await waitFor(() =>
      expect(screen.getByLabelText("Generic fact table")).toHaveValue(
        "table_a",
      ),
    );
    fireEvent.click(screen.getByRole("button", { name: "Read records" }));
    await waitFor(() => expect(reads).toBe(3));
    const currentRead = calls.filter(
      (call) => call.function === "facts.generic.value.snapshot.scan",
    )[2];
    expect(currentRead.signal?.aborted).toBe(false);
    await act(async () =>
      old.resolve(
        outcome === "success" ? facts("Late private page") : denied(),
      ),
    );
    expect(currentRead.signal?.aborted).toBe(false);
    expect(
      within(screen.getByLabelText("Generic facts")).getByRole("button", {
        name: "Reading…",
      }),
    ).toBeDisabled();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByText("Late private page")).not.toBeInTheDocument();
    await act(async () => current.resolve(facts("Current record")));
    expect(
      screen.getByText("Current record", { selector: "th" }),
    ).toBeInTheDocument();
  },
);

it.each([
  [403, "APPLICATION_GRANT_REQUIRED"],
  [409, "GENERIC_FACT_READ_AUTHORIZATION_STALE"],
  [400, "FACT_TABLE_UNAVAILABLE"],
] as const)(
  "clears old generic tables when the current read returns %s %s",
  async (status, code) => {
    let directoryReads = 0;
    let snapshots = 0;
    await setup((call) => {
      if (call.function === "facts.generic.table.list")
        return ++directoryReads === 1
          ? tables("Previous table")
          : tables("Current table");
      if (call.function === "facts.generic.value.snapshot.scan")
        return ++snapshots === 1
          ? facts("Prior authorized row", "prior-next")
          : new Response(JSON.stringify({ code }), { status });
    });
    fireEvent.click(screen.getByRole("button", { name: "Generic facts" }));
    await screen.findByRole("option", { name: "Previous table A" });
    fireEvent.click(screen.getByRole("button", { name: "Read records" }));
    await screen.findByRole("rowheader", { name: "Prior authorized row" });
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    await screen.findByRole("alert");
    expect(
      screen.queryByRole("rowheader", { name: "Prior authorized row" }),
    ).toBeNull();
    expect(
      screen.queryByRole("option", { name: "Previous table A" }),
    ).toBeNull();
    expect(
      screen.getByRole("option", {
        name: "Choose Generic facts to reload tables",
      }),
    ).toBeVisible();
    expect(screen.getByRole("button", { name: "Read records" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Next page" })).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Generic facts" }));
    expect(
      await screen.findByRole("option", { name: "Current table A" }),
    ).toBeVisible();
  },
);

it("keeps a current read started when refreshed tables become actionable before passive cleanup", async () => {
  const old = defer();
  const current = defer();
  let reads = 0;
  let armed = false;
  let started = false;
  const { calls, switchContext } = await setup(
    (call) =>
      call.function === "facts.generic.value.snapshot.scan"
        ? ++reads === 1
          ? old.promise
          : current.promise
        : undefined,
    () => {
      // Commit-time observation exercises the earliest actionable DOM, before
      // passive cleanup of the prior table context. Use the real button handler.
      if (!armed || started) return;
      const table = screen.queryByLabelText(
        "Generic fact table",
      ) as HTMLSelectElement | null;
      const button = screen.queryByRole("button", {
        name: "Read records",
      }) as HTMLButtonElement | null;
      if (table?.value !== "table_a" || !button || button.disabled) return;
      started = true;
      button.click();
    },
  );
  fireEvent.click(screen.getByRole("button", { name: "Generic facts" }));
  await screen.findByLabelText("Generic fact table");
  fireEvent.click(screen.getByRole("button", { name: "Read records" }));
  await waitFor(() => expect(reads).toBe(1));
  await switchContext("grant");
  const oldRead = calls.find(
    (call) => call.function === "facts.generic.value.snapshot.scan",
  )!;
  expect(oldRead.signal?.aborted).toBe(true);
  armed = true;
  fireEvent.click(screen.getByRole("button", { name: "Generic facts" }));
  await waitFor(() => expect(reads).toBe(2));
  const currentRead = calls.filter(
    (call) => call.function === "facts.generic.value.snapshot.scan",
  )[1];
  expect(currentRead.signal?.aborted).toBe(false);
  await act(async () => old.resolve(facts("Late private record")));
  expect(currentRead.signal?.aborted).toBe(false);
  expect(
    within(screen.getByLabelText("Generic facts")).getByRole("button", {
      name: "Reading…",
    }),
  ).toBeDisabled();
  expect(screen.queryByText("Late private record")).not.toBeInTheDocument();
  await act(async () => current.resolve(facts("Current record")));
  expect(
    screen.getByText("Current record", { selector: "th" }),
  ).toBeInTheDocument();
});

it("aborts the current generic request when the editor unmounts", async () => {
  const pending = defer();
  const { calls, view } = await setup((call) =>
    call.function === "facts.generic.value.snapshot.scan"
      ? pending.promise
      : undefined,
  );
  fireEvent.click(screen.getByRole("button", { name: "Generic facts" }));
  await screen.findByLabelText("Generic fact table");
  fireEvent.click(screen.getByRole("button", { name: "Read records" }));
  await waitFor(() =>
    expect(
      calls.some(
        (call) => call.function === "facts.generic.value.snapshot.scan",
      ),
    ).toBe(true),
  );
  const currentRead = calls.find(
    (call) => call.function === "facts.generic.value.snapshot.scan",
  )!;
  expect(currentRead.signal?.aborted).toBe(false);
  view.unmount();
  expect(currentRead.signal?.aborted).toBe(true);
  await act(async () => pending.resolve(facts("Unmounted private record")));
  expect(
    screen.queryByText("Unmounted private record"),
  ).not.toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

it.each(outcomes)(
  "table selection cancels its old %s response without ending the newer read",
  async (outcome) => {
    const old = defer(),
      current = defer();
    let reads = 0;
    const { calls } = await setup((call) =>
      call.function === "facts.generic.value.snapshot.scan"
        ? ++reads === 1
          ? old.promise
          : current.promise
        : undefined,
    );
    fireEvent.click(screen.getByRole("button", { name: "Generic facts" }));
    await screen.findByLabelText("Generic fact table");
    fireEvent.click(screen.getByRole("button", { name: "Read records" }));
    await waitFor(() => expect(reads).toBe(1));
    fireEvent.change(screen.getByLabelText("Generic fact table"), {
      target: { value: "table_b" },
    });
    expect(
      calls.find(
        (call) => call.function === "facts.generic.value.snapshot.scan",
      )?.signal?.aborted,
    ).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Read records" }));
    await waitFor(() => expect(reads).toBe(2));
    await act(async () =>
      old.resolve(outcome === "success" ? facts("Old table row") : denied()),
    );
    expect(
      within(screen.getByLabelText("Generic facts")).getByRole("button", {
        name: "Reading…",
      }),
    ).toBeDisabled();
    await act(async () => current.resolve(facts("New table row")));
    expect(screen.getByLabelText("Generic fact table")).toHaveValue("table_b");
    expect(
      screen.getByText("New table row", { selector: "th" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByText("Old table row")).not.toBeInTheDocument();
  },
);

it("choosing Grid cancels a pending generic discovery even when Grid was already selected", async () => {
  const pending = defer();
  await setup((call) =>
    call.function === "facts.generic.table.list" ? pending.promise : undefined,
  );
  fireEvent.click(screen.getByRole("button", { name: "Generic facts" }));
  fireEvent.click(screen.getByRole("button", { name: "Grid" }));
  await act(async () => pending.resolve(tables("Old table")));
  expect(screen.queryByLabelText("Generic fact table")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Grid" })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
});

it("preserves legitimate pagination and clears previously shown records on a current denial", async () => {
  let reads = 0;
  await setup((call) =>
    call.function === "facts.generic.value.snapshot.scan"
      ? ++reads === 1
        ? facts("First row", "page-2")
        : reads === 2
          ? facts("Second row", "page-3")
          : denied()
      : undefined,
  );
  fireEvent.click(screen.getByRole("button", { name: "Generic facts" }));
  await screen.findByLabelText("Generic fact table");
  fireEvent.click(screen.getByRole("button", { name: "Read records" }));
  await screen.findByText("First row", { selector: "th" });
  fireEvent.click(screen.getByRole("button", { name: "Next page" }));
  await screen.findByText("Second row", { selector: "th" });
  expect(screen.getByText("First row", { selector: "th" })).toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Next page" }));
  await screen.findByRole("alert");
  expect(
    screen.queryByLabelText("Generic fact records"),
  ).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Next page" })).toBeDisabled();
});

it.each(
  [...changes, "axes" as const].flatMap((change) =>
    outcomes.map((outcome) => [change, outcome] as const),
  ),
)(
  "commits a layout suggestion atomically and ignores %s change / late %s",
  async (change, outcome) => {
    const old = defer();
    let memberReads = 0;
    const { calls, switchContext } = await setup((call) =>
      call.function === "metadata.member.list"
        ? ++memberReads === 1
          ? old.promise
          : members("Current member")
        : undefined,
    );
    fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Suggest layout" }),
      ).toBeEnabled(),
    );
    fireEvent.change(screen.getByLabelText("Rows"), {
      target: { value: "Region" },
    });
    fireEvent.change(screen.getByLabelText("Columns"), {
      target: { value: "Account" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Suggest layout" }));
    await waitFor(() => expect(memberReads).toBe(1));
    expect(screen.getByLabelText("Rows")).toHaveValue("Region");
    expect(screen.getByLabelText("Columns")).toHaveValue("Account");
    if (change === "axes") {
      fireEvent.change(screen.getByLabelText("Rows"), {
        target: { value: "Scenario" },
      });
      fireEvent.change(screen.getByLabelText("Rows"), {
        target: { value: "Region" },
      });
    } else await switchContext(change);
    expect(
      calls.find((call) => call.function === "metadata.member.list")?.signal
        ?.aborted,
    ).toBe(true);
    await act(async () =>
      old.resolve(
        outcome === "success" ? members("Old private member") : denied(),
      ),
    );
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByText("Old private member")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Rows")).toHaveValue(
      change === "application" ? "" : "Region",
    );
    expect(screen.getByLabelText("Columns")).toHaveValue(
      change === "application" ? "" : "Account",
    );
    expect(memberReads).toBe(1);
    fireEvent.click(screen.getByRole("button", { name: "Suggest layout" }));
    await waitFor(() =>
      expect(screen.getByLabelText("Rows")).toHaveValue("Account"),
    );
    expect(screen.getByLabelText("Columns")).toHaveValue("Period");
    expect(
      screen.getByRole("button", { name: "Region taxonomy point of view" }),
    ).toHaveTextContent("Current member");
  },
);

it.each(outcomes)(
  "a manual POV choice cancels the awaited layout suggestion's %s",
  async (outcome) => {
    const old = defer();
    await setup((call) =>
      call.function === "metadata.member.list" &&
      call.arguments.dimension === "Region"
        ? old.promise
        : undefined,
    );
    fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Suggest layout" }),
      ).toBeEnabled(),
    );
    fireEvent.change(screen.getByLabelText("Rows"), {
      target: { value: "Account" },
    });
    fireEvent.change(screen.getByLabelText("Columns"), {
      target: { value: "Period" },
    });
    const choosePov = async (label: string) => {
      fireEvent.click(
        screen.getByRole("button", { name: "Scenario point of view" }),
      );
      const dialog = await screen.findByRole("dialog", {
        name: "Choose one Scenario member",
      });
      fireEvent.click(
        within(dialog).getByRole("button", { name: new RegExp(label) }),
      );
      fireEvent.click(
        within(dialog).getByRole("button", { name: "Add selected member" }),
      );
      fireEvent.click(
        within(dialog).getByRole("button", { name: "Apply selection" }),
      );
    };
    await choosePov("Default Scenario");
    fireEvent.click(screen.getByRole("button", { name: "Suggest layout" }));
    await choosePov("Manual Scenario");
    await act(async () =>
      old.resolve(outcome === "success" ? members("Old region") : denied()),
    );
    expect(
      screen.getByRole("button", { name: "Scenario point of view" }),
    ).toHaveTextContent("Manual Scenario");
    expect(
      screen.getByRole("button", { name: "Region taxonomy point of view" }),
    ).toHaveTextContent("Choose member");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  },
);

async function aggregateSetup(
  handler: (call: Call) => Response | Promise<Response> | undefined,
  onCommit?: () => void,
) {
  const calls: Call[] = [];
  const app = {
    workspaceId: "w",
    applicationId: "a",
    name: "Model",
    status: "Active",
  };
  let catalog: ApplicationCatalog = {
    applicationAccess: {
      issuer: "issuer",
      subjectId: "actor-one",
      role: "Editor",
      workspaceAdministrator: false,
    },
    functions: Object.fromEntries(
      [
        "metadata.dimension.list",
        "metadata.member.list",
        "facts.cube.aggregate.request",
        "facts.cube.aggregate.read",
        "facts.cube.aggregate.cancel",
        "facts.generic.table.list",
        "facts.generic.value.snapshot.scan",
      ].map((name) => [name, {}]),
    ),
    enabledCapabilities: [],
    revisions: { metadata: 1, data: 1, policy: 1, security: 1, commit: 1 },
  };
  vi.stubGlobal(
    "confirm",
    vi.fn(() => true),
  );
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_path, init) => {
      const body = JSON.parse(String(init.body));
      const call = {
        ...body.program,
        applicationId: body.applicationId,
        signal: init.signal,
      } as Call;
      calls.push(call);
      const custom = handler(call);
      if (custom !== undefined) return custom;
      if (call.function === "metadata.dimension.list")
        return result({
          rows: ["Account", "Period", "Region"].map((id) => ({
            dimension_id: id,
            name: id,
            model_role: id === "Region" ? "Custom" : id,
            status: "Active",
          })),
          metadataRevision: 1,
          nextAfterDimensionId: null,
        });
      if (call.function === "metadata.member.list")
        return result({
          rows: [{ member_id: "Default", name: "Default", status: "Active" }],
          metadataRevision: 1,
          nextAfterMemberId: null,
        });
      if (call.function === "facts.generic.table.list")
        return tables("Current");
      if (call.function === "facts.generic.value.snapshot.scan")
        return facts("Current generic record");
      throw new Error(`Unexpected aggregate test function ${call.function}`);
    }),
  );
  const element = () => {
    const analyze = (
      <Analyze app={app} catalog={catalog} index={0} subject="actor-one" />
    );
    return onCommit ? (
      <Profiler id="aggregate-authority-readiness" onRender={onCommit}>
        {analyze}
      </Profiler>
    ) : (
      analyze
    );
  };
  const view = render(element());
  await waitFor(() =>
    expect(screen.getByLabelText("Rows")).toHaveTextContent("Account"),
  );
  fireEvent.change(screen.getByLabelText("Rows"), {
    target: { value: "Account" },
  });
  fireEvent.change(screen.getByLabelText("Columns"), {
    target: { value: "Period" },
  });
  fireEvent.click(screen.getByText("Aggregate large cube selections"));
  const request = async () => {
    const checkbox = screen.getByLabelText(
      "I reviewed this exact aggregate query",
    );
    await waitFor(() => expect(checkbox).toBeEnabled());
    fireEvent.click(checkbox);
    const button = screen.getByRole("button", {
      name: "Request durable aggregate",
    });
    await waitFor(() => expect(button).toBeEnabled());
    fireEvent.click(button);
  };
  const refresh = () =>
    fireEvent.click(
      screen.getByRole("button", { name: "Refresh status and results" }),
    );
  const changeAuthority = async (accessContextOnly = false) => {
    catalog = accessContextOnly
      ? { ...catalog, accessContext: "b".repeat(64) }
      : {
          ...catalog,
          revisions: {
            ...catalog.revisions,
            security: catalog.revisions.security + 1,
          },
        };
    view.rerender(element());
    await act(async () => undefined);
  };
  return { calls, view, request, refresh, changeAuthority };
}
const aggregateResult = (
  queryId = "query-1",
  value = "12.50000000",
  nextCursor: string | null = "next-private",
) =>
  result({
    queryId,
    status: "sealed",
    rows: [
      {
        ordinal: 1,
        members: { Account: "Revenue", Period: "P1" },
        sumAmount: value,
        countPresent: "2",
      },
    ],
    nextCursor,
  });
const aggregateRefusal = (code: string, status = 403) =>
  new Response(JSON.stringify({ code, error: code }), { status });

it.each(["APPLICATION_GRANT_REQUIRED", "CUBE_AGGREGATE_STALE_CONTEXT"])(
  "hides aggregate values, original intent and continuation after current-authority refusal %s, retaining only the known handle",
  async (code) => {
    let reads = 0;
    const { calls, request, refresh } = await aggregateSetup((call) => {
      if (call.function === "facts.cube.aggregate.request")
        return result({ queryId: "query-1", status: "ready" });
      if (call.function === "facts.cube.aggregate.read")
        return ++reads === 1
          ? aggregateResult()
          : reads === 2
            ? aggregateRefusal(code, code.includes("STALE") ? 409 : 403)
            : result({ queryId: "query-1", status: "ready" });
    });
    await request();
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Refresh status and results" }),
      ).toBeEnabled(),
    );
    refresh();
    await screen.findByText("12.50000000");
    expect(
      screen.getByLabelText(
        "I reviewed cancellation of this exact query state",
      ),
    ).toBeDisabled();
    refresh();
    await screen.findByText(code);
    expect(screen.queryByText("12.50000000")).not.toBeInTheDocument();
    expect(
      screen.queryByLabelText("Accepted aggregate query"),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Next result page" }),
    ).toBeDisabled();
    expect(
      screen.getByLabelText(
        "I reviewed cancellation of this exact query state",
      ),
    ).toBeDisabled();
    refresh();
    await waitFor(() => expect(reads).toBe(3));
    expect(
      calls
        .filter((x) => x.function === "facts.cube.aggregate.read")
        .map((x) => x.arguments),
    ).toEqual([
      { queryId: "query-1", pageSize: 100 },
      { queryId: "query-1", pageSize: 100 },
      { queryId: "query-1", pageSize: 100 },
    ]);
    expect(
      calls.filter((x) => x.function === "facts.cube.aggregate.request"),
    ).toHaveLength(1);
    expect(
      calls.filter((x) => x.function === "facts.cube.aggregate.cancel"),
    ).toHaveLength(0);
  },
);

it("keeps native ready/running cancellation separate from sealed result pages", async () => {
  const { calls, request, refresh } = await aggregateSetup((call) => {
    if (call.function === "facts.cube.aggregate.request")
      return result({ queryId: "query-1", status: "ready" });
    if (call.function === "facts.cube.aggregate.read")
      return result({ queryId: "query-1", status: "running" });
    if (call.function === "facts.cube.aggregate.cancel")
      return result({ queryId: "query-1", status: "cancel_requested" });
  });
  await request();
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Refresh status and results" }),
    ).toBeEnabled(),
  );
  expect(
    screen.getByLabelText("I reviewed cancellation of this exact query state"),
  ).toBeDisabled();
  refresh();
  await waitFor(() =>
    expect(
      screen.getByLabelText(
        "I reviewed cancellation of this exact query state",
      ),
    ).toBeEnabled(),
  );
  fireEvent.click(
    screen.getByLabelText("I reviewed cancellation of this exact query state"),
  );
  fireEvent.click(screen.getByRole("button", { name: "Request cancellation" }));
  await screen.findByText(/Aggregate request · cancel_requested/);
  expect(
    screen.queryByRole("table", { name: "Aggregate results" }),
  ).not.toBeInTheDocument();
  expect(
    calls.filter((x) => x.function === "facts.cube.aggregate.cancel")[0]
      .arguments,
  ).toEqual({ queryId: "query-1" });
});

it.each(
  (["request", "read", "cancel"] as const).flatMap((action) =>
    (["success", "denial"] as const).map(
      (outcome) => [action, outcome] as const,
    ),
  ),
)(
  "fences old aggregate %s / %s after a same-mounted authority change without clearing a newer pending request",
  async (action, outcome) => {
    const old = defer(),
      current = defer();
    let requests = 0;
    let reads = 0;
    const { calls, request, refresh, changeAuthority } = await aggregateSetup(
      (call) => {
        if (call.function === "facts.cube.aggregate.request")
          return ++requests === 1
            ? action === "request"
              ? old.promise
              : result({ queryId: "query-1", status: "ready" })
            : current.promise;
        if (call.function === "facts.cube.aggregate.read")
          return ++reads === 1 && action === "read"
            ? old.promise
            : result({ queryId: "query-1", status: "running" });
        if (call.function === "facts.cube.aggregate.cancel") return old.promise;
      },
    );
    await request();
    if (action !== "request") {
      await waitFor(() =>
        expect(
          screen.getByRole("button", { name: "Refresh status and results" }),
        ).toBeEnabled(),
      );
      refresh();
      if (action === "cancel") {
        await waitFor(() =>
          expect(
            screen.getByLabelText(
              "I reviewed cancellation of this exact query state",
            ),
          ).toBeEnabled(),
        );
        fireEvent.click(
          screen.getByLabelText(
            "I reviewed cancellation of this exact query state",
          ),
        );
        fireEvent.click(
          screen.getByRole("button", { name: "Request cancellation" }),
        );
      }
    }
    const oldCall = calls.findLast(
      (x) => x.function === `facts.cube.aggregate.${action}`,
    )!;
    await changeAuthority();
    expect(oldCall.signal?.aborted).toBe(true);
    expect(
      screen.queryByLabelText("Accepted aggregate query"),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("Revenue")).not.toBeInTheDocument();
    await request();
    const currentCall = calls.findLast(
      (x) => x.function === "facts.cube.aggregate.request",
    )!;
    expect(currentCall.signal?.aborted).toBe(false);
    await act(async () =>
      old.resolve(
        outcome === "denial"
          ? aggregateRefusal("OLD_AGGREGATE_DENIED")
          : action === "read"
            ? aggregateResult("query-1", "999.00000000")
            : result({ queryId: "query-1", status: "ready" }),
      ),
    );
    expect(screen.queryByText("999.00000000")).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Request durable aggregate" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Refresh status and results" }),
    ).toBeDisabled();
    expect(currentCall.signal?.aborted).toBe(false);
    await act(async () =>
      current.resolve(result({ queryId: "query-2", status: "ready" })),
    );
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Refresh status and results" }),
      ).toBeEnabled(),
    );
    expect(requests).toBe(2);
    expect(
      calls.filter((x) => x.function === "facts.cube.aggregate.cancel"),
    ).toHaveLength(action === "cancel" ? 1 : 0);
  },
);

it("keeps accepted aggregate intent and paging immutable while later layout and measure edits form a separate draft", async () => {
  const pending = defer();
  const { calls, request, refresh } = await aggregateSetup((call) => {
    if (call.function === "facts.cube.aggregate.request")
      return pending.promise;
    if (call.function === "facts.cube.aggregate.read") return aggregateResult();
  });
  await request();
  const original = calls.find(
    (x) => x.function === "facts.cube.aggregate.request",
  )!.arguments;
  fireEvent.change(screen.getByLabelText("Rows"), {
    target: { value: "Period" },
  });
  fireEvent.click(screen.getByLabelText("Count present"));
  await act(async () =>
    pending.resolve(result({ queryId: "query-1", status: "ready" })),
  );
  const summary = screen.getByLabelText("Accepted aggregate query");
  expect(summary).toHaveTextContent("Account → Period");
  expect(summary).toHaveTextContent("Count present");
  expect(screen.getByLabelText("Count present")).not.toBeChecked();
  fireEvent.change(screen.getByLabelText("Aggregate result page size"), {
    target: { value: "20" },
  });
  refresh();
  await screen.findByText("12.50000000");
  expect(
    calls.find((x) => x.function === "facts.cube.aggregate.read")!.arguments,
  ).toEqual({ queryId: "query-1", pageSize: 100 });
  expect(original).toMatchObject({
    query: {
      grain: { groupBy: ["Account", "Period"] },
      measures: [{ kind: "SumAmount" }, { kind: "CountPresent" }],
    },
    limits: { pageSize: 100 },
  });
  expect(
    screen.getByLabelText("I reviewed this exact aggregate query"),
  ).not.toBeChecked();
});

it.each([false, true])(
  "hides loaded aggregate intent and rows without another effect when only the access context changes (%s)",
  async (accessContextOnly) => {
    const { calls, request, refresh, changeAuthority } = await aggregateSetup(
      (call) => {
        if (call.function === "facts.cube.aggregate.request")
          return result({ queryId: "query-1", status: "ready" });
        if (call.function === "facts.cube.aggregate.read")
          return aggregateResult();
      },
    );
    await request();
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Refresh status and results" }),
      ).toBeEnabled(),
    );
    refresh();
    await screen.findByText("12.50000000");
    await changeAuthority(accessContextOnly);
    expect(screen.queryByText("12.50000000")).not.toBeInTheDocument();
    expect(
      screen.queryByLabelText("Accepted aggregate query"),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Next result page" }),
    ).toBeDisabled();
    expect(
      screen.getByLabelText(
        "I reviewed cancellation of this exact query state",
      ),
    ).toBeDisabled();
    expect(
      calls.filter((x) => x.function.startsWith("facts.cube.aggregate.")),
    ).toHaveLength(2);
  },
);

it("aborts only aggregate HTTP observation on unmount and never automatically cancels the durable query", async () => {
  const pending = defer();
  const { calls, view, request, refresh } = await aggregateSetup((call) => {
    if (call.function === "facts.cube.aggregate.request")
      return result({ queryId: "query-1", status: "ready" });
    if (call.function === "facts.cube.aggregate.read") return pending.promise;
  });
  await request();
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Refresh status and results" }),
    ).toBeEnabled(),
  );
  refresh();
  const read = calls.find((x) => x.function === "facts.cube.aggregate.read")!;
  view.unmount();
  expect(read.signal?.aborted).toBe(true);
  await act(async () => pending.resolve(aggregateResult()));
  expect(
    calls.filter((x) => x.function === "facts.cube.aggregate.request"),
  ).toHaveLength(1);
  expect(
    calls.filter((x) => x.function === "facts.cube.aggregate.cancel"),
  ).toHaveLength(0);
});

it.each(["different-query", "unsealed-rows"] as const)(
  "refuses aggregate response %s without replacing the original query or retaining prior result values",
  async (invalid) => {
    let reads = 0;
    const { calls, request, refresh } = await aggregateSetup((call) => {
      if (call.function === "facts.cube.aggregate.request")
        return result({ queryId: "query-1", status: "ready" });
      if (call.function === "facts.cube.aggregate.read")
        return ++reads === 1
          ? aggregateResult()
          : reads > 2
            ? result({ queryId: "query-1", status: "ready" })
            : invalid === "different-query"
              ? aggregateResult("another-query")
              : result({
                  queryId: "query-1",
                  status: "computed",
                  rows: [{ members: {}, sumAmount: "100.00000000" }],
                });
    });
    await request();
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Refresh status and results" }),
      ).toBeEnabled(),
    );
    refresh();
    await screen.findByText("12.50000000");
    refresh();
    await screen.findByText(
      invalid === "different-query"
        ? "The aggregate response does not match the requested query."
        : "Aggregate results are unavailable until the query is sealed.",
    );
    expect(
      screen.queryByLabelText("Aggregate results"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByLabelText("Accepted aggregate query"),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Next result page" }),
    ).toBeDisabled();
    refresh();
    await waitFor(() => expect(reads).toBe(3));
    expect(
      calls
        .filter((call) => call.function === "facts.cube.aggregate.read")
        .every((call) => call.arguments.queryId === "query-1"),
    ).toBe(true);
  },
);

it("hides the formerly authorized intent when an explicitly requested aggregate cancellation is refused", async () => {
  const { calls, request, refresh } = await aggregateSetup((call) => {
    if (call.function === "facts.cube.aggregate.request")
      return result({ queryId: "query-1", status: "ready" });
    if (call.function === "facts.cube.aggregate.read")
      return result({ queryId: "query-1", status: "running" });
    if (call.function === "facts.cube.aggregate.cancel")
      return aggregateRefusal("CUBE_AGGREGATE_STALE_CONTEXT", 409);
  });
  await request();
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Refresh status and results" }),
    ).toBeEnabled(),
  );
  refresh();
  await waitFor(() =>
    expect(
      screen.getByLabelText(
        "I reviewed cancellation of this exact query state",
      ),
    ).toBeEnabled(),
  );
  fireEvent.click(
    screen.getByLabelText("I reviewed cancellation of this exact query state"),
  );
  fireEvent.click(screen.getByRole("button", { name: "Request cancellation" }));
  await screen.findByText("CUBE_AGGREGATE_STALE_CONTEXT");
  expect(
    screen.queryByLabelText("Accepted aggregate query"),
  ).not.toBeInTheDocument();
  expect(
    screen.getByLabelText("I reviewed cancellation of this exact query state"),
  ).toBeDisabled();
  expect(
    calls.filter((call) => call.function === "facts.cube.aggregate.cancel"),
  ).toHaveLength(1);
  expect(
    calls.filter((call) => call.function === "facts.cube.aggregate.read"),
  ).toHaveLength(1);
});

it("preserves a current aggregate refresh dispatched from the real ready button before authority-change effects finish", async () => {
  const old = defer(),
    current = defer();
  let reads = 0,
    armed = false,
    dispatched = false;
  const { calls, request, refresh, changeAuthority } = await aggregateSetup(
    (call) => {
      if (call.function === "facts.cube.aggregate.request")
        return result({ queryId: "query-1", status: "ready" });
      if (call.function === "facts.cube.aggregate.read")
        return ++reads === 1 ? old.promise : current.promise;
    },
    () => {
      const button = screen.queryByRole("button", {
        name: "Refresh status and results",
      }) as HTMLButtonElement | null;
      if (armed && button && !button.disabled) {
        armed = false;
        dispatched = true;
        button.click();
      }
    },
  );
  await request();
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Refresh status and results" }),
    ).toBeEnabled(),
  );
  refresh();
  await waitFor(() => expect(reads).toBe(1));
  armed = true;
  await changeAuthority();
  expect(dispatched).toBe(true);
  expect(reads).toBe(2);
  const [previous, active] = calls.filter(
    (call) => call.function === "facts.cube.aggregate.read",
  );
  expect(previous.signal?.aborted).toBe(true);
  expect(active.signal?.aborted).toBe(false);
  expect(
    screen.getByRole("button", { name: "Refresh status and results" }),
  ).toBeDisabled();
  await act(async () =>
    old.resolve(aggregateResult("query-1", "999.00000000")),
  );
  expect(screen.queryByText("999.00000000")).not.toBeInTheDocument();
  expect(
    screen.queryByLabelText("Accepted aggregate query"),
  ).not.toBeInTheDocument();
  expect(active.signal?.aborted).toBe(false);
  expect(
    screen.getByRole("button", { name: "Refresh status and results" }),
  ).toBeDisabled();
  await act(async () =>
    current.resolve(aggregateResult("query-1", "25.00000000", null)),
  );
  await screen.findByText("25.00000000");
  expect(active.signal?.aborted).toBe(false);
  expect(screen.getByLabelText("Accepted aggregate query")).toBeVisible();
  expect(
    calls.filter((call) => call.function === "facts.cube.aggregate.request"),
  ).toHaveLength(1);
  expect(
    calls.filter((call) => call.function === "facts.cube.aggregate.cancel"),
  ).toHaveLength(0);
});

it.each(["success", "denial"] as const)(
  "does not let a departed aggregate %s callback clear a newer unrelated current-authority generic read",
  async (outcome) => {
    const old = defer(),
      current = defer();
    const { calls, request, refresh, changeAuthority } = await aggregateSetup(
      (call) => {
        if (call.function === "facts.cube.aggregate.request")
          return result({ queryId: "query-1", status: "ready" });
        if (call.function === "facts.cube.aggregate.read") return old.promise;
        if (call.function === "facts.generic.table.list")
          return current.promise;
      },
    );
    await request();
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Refresh status and results" }),
      ).toBeEnabled(),
    );
    refresh();
    await changeAuthority();
    fireEvent.click(screen.getByRole("button", { name: "Generic facts" }));
    await waitFor(() =>
      expect(
        calls.filter((call) => call.function === "facts.generic.table.list"),
      ).toHaveLength(1),
    );
    const generic = calls.find(
      (call) => call.function === "facts.generic.table.list",
    )!;
    expect(generic.signal?.aborted).toBe(false);
    await act(async () =>
      old.resolve(
        outcome === "success"
          ? aggregateResult("query-1", "999.00000000")
          : aggregateRefusal("OLD_AGGREGATE_DENIED"),
      ),
    );
    expect(screen.getByRole("button", { name: "Reading…" })).toBeDisabled();
    expect(generic.signal?.aborted).toBe(false);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByText("999.00000000")).not.toBeInTheDocument();
    await act(async () => current.resolve(tables("Current")));
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Read records" }),
      ).toBeEnabled(),
    );
    expect(
      calls.filter((call) => call.function === "facts.cube.aggregate.request"),
    ).toHaveLength(1);
    expect(
      calls.filter((call) => call.function === "facts.cube.aggregate.cancel"),
    ).toHaveLength(0);
  },
);

it.each(["deferred", "immediate"] as const)(
  "preserves a %s grid read dispatched from the first enabled button after layout suggestion commits",
  async (delivery) => {
    const pending = defer();
    const NativeAbortController = globalThis.AbortController;
    const created: AbortController[] = [];
    vi.stubGlobal(
      "AbortController",
      class extends NativeAbortController {
        constructor() {
          super();
          created.push(this);
        }
      },
    );
    let clicked = false;
    let gridController: AbortController | undefined;
    const { calls } = await setup(
      (call) =>
        call.function === "facts.cube.scan"
          ? delivery === "deferred"
            ? pending.promise
            : currentGridPage("0.00000000")
          : undefined,
      () => {
        if (clicked) return;
        const rows = screen.queryByLabelText(
          "Rows",
        ) as HTMLSelectElement | null;
        const columns = screen.queryByLabelText(
          "Columns",
        ) as HTMLSelectElement | null;
        const button = screen.queryByRole("button", {
          name: "Read grid",
        }) as HTMLButtonElement | null;
        if (
          rows?.value !== "Account" ||
          columns?.value !== "Period" ||
          !button ||
          button.disabled
        )
          return;
        clicked = true;
        const before = created.length;
        button.click();
        gridController = created[before];
      },
    );
    fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Suggest layout" }),
      ).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Suggest layout" }));
    await waitFor(() => expect(clicked).toBe(true));
    expect(gridController).toBeDefined();
    expect(gridController!.signal.aborted).toBe(false);
    const axisMemberReads = calls.filter(
      (call) =>
        call.function === "metadata.member.list" &&
        ["Account", "Period"].includes(String(call.arguments.dimension)),
    );
    expect(axisMemberReads).toHaveLength(2);
    for (const memberRead of axisMemberReads)
      expect(memberRead.signal).toBe(gridController!.signal);
    await waitFor(() =>
      expect(
        calls.filter((call) => call.function === "facts.cube.scan"),
      ).toHaveLength(1),
    );
    if (delivery === "deferred") {
      expect(screen.getByRole("button", { name: "Reading…" })).toBeDisabled();
      await act(async () => pending.resolve(currentGridPage("0.00000000")));
    }
    await screen.findByText("0.00000000");
    expect(screen.getByText("0.00000000")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Read grid" })).toBeEnabled();
    expect(gridController!.signal.aborted).toBe(false);
  },
);

it("preserves a suggestion dispatched from the first enabled button after metadata discovery commits", async () => {
  const metadata = defer();
  const pendingMember = defer();
  let clicked = false;
  const { calls } = await setup(
    (call) => {
      if (call.function === "metadata.dimension.list") return metadata.promise;
      if (
        call.function === "metadata.member.list" &&
        call.arguments.dimension === "Scenario"
      )
        return pendingMember.promise;
    },
    () => {
      if (clicked) return;
      const button = screen.queryByRole("button", {
        name: "Suggest layout",
      }) as HTMLButtonElement | null;
      if (!button || button.disabled) return;
      clicked = true;
      button.click();
    },
  );
  fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
  await act(async () =>
    metadata.resolve(
      result({
        rows: ["Account", "Period", "Scenario"].map((id) => ({
          dimension_id: id,
          name: id,
          model_role: id,
          status: "Active",
        })),
        metadataRevision: 1,
        nextAfterDimensionId: null,
      }),
    ),
  );
  expect(clicked).toBe(true);
  const memberRead = calls.find(
    (call) => call.function === "metadata.member.list",
  )!;
  expect(memberRead).toBeDefined();
  expect(memberRead.signal?.aborted).toBe(false);
  expect(screen.getByRole("button", { name: "Suggest layout" })).toBeDisabled();
  await act(async () => pendingMember.resolve(members("Default-Scenario")));
  expect(screen.getByLabelText("Rows")).toHaveValue("Account");
  expect(screen.getByLabelText("Columns")).toHaveValue("Period");
  expect(screen.getByRole("button", { name: "Read grid" })).toBeEnabled();
});

function currentGridPage(amount: string, nextCursor: string | null = null) {
  return result({
    rows: [
      {
        members: {
          Account: "Default-Account",
          Period: "Default-Period",
          Scenario: "Default-Scenario",
          Region: "Default-Region",
        },
        kind: "numeric",
        amount,
        changeId: `change-${amount}`,
        lastRevision: 1,
      },
    ],
    nextCursor,
    snapshotRevision: 1,
    source: "current_projection",
  });
}

it.each(outcomes)(
  "preserves a newer current-authority grid read through a departed page %s",
  async (outcome) => {
    const old = defer(),
      current = defer();
    let reads = 0;
    const { calls, switchContext } = await setup((call) =>
      call.function === "facts.cube.scan"
        ? ++reads === 1
          ? currentGridPage("1.00000000", "page-two")
          : reads === 2
            ? old.promise
            : current.promise
        : undefined,
    );
    fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Suggest layout" }),
      ).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Suggest layout" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Read grid" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
    await screen.findByText("1.00000000");
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    await waitFor(() => expect(reads).toBe(2));
    const oldRead = calls.filter(
      (call) => call.function === "facts.cube.scan",
    )[1];
    await switchContext("grant");
    expect(oldRead.signal?.aborted).toBe(true);
    expect(screen.queryByText("1.00000000")).not.toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Read grid" })).toBeEnabled(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
    await waitFor(() => expect(reads).toBe(3));
    const currentRead = calls.filter(
      (call) => call.function === "facts.cube.scan",
    )[2];
    expect(currentRead.signal?.aborted).toBe(false);
    await act(async () =>
      old.resolve(
        outcome === "success" ? currentGridPage("999.00000000") : denied(),
      ),
    );
    expect(currentRead.signal?.aborted).toBe(false);
    expect(screen.getByRole("button", { name: "Reading…" })).toBeDisabled();
    expect(screen.queryByText("999.00000000")).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    await act(async () => current.resolve(currentGridPage("2.00000000")));
    expect(screen.getByText("2.00000000")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Read grid" })).toBeEnabled();
  },
);

it("aborts the current pending grid HTTP read on unmount and ignores its late response", async () => {
  const pending = defer();
  const { calls, view } = await setup((call) =>
    call.function === "facts.cube.scan" ? pending.promise : undefined,
  );
  fireEvent.click(screen.getByRole("button", { name: "Configure layout" }));
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Suggest layout" }),
    ).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Suggest layout" }));
  await waitFor(() =>
    expect(screen.getByRole("button", { name: "Read grid" })).toBeEnabled(),
  );
  fireEvent.click(screen.getByRole("button", { name: "Read grid" }));
  await waitFor(() =>
    expect(
      calls.filter((call) => call.function === "facts.cube.scan"),
    ).toHaveLength(1),
  );
  const read = calls.find((call) => call.function === "facts.cube.scan")!;
  expect(read.signal?.aborted).toBe(false);
  view.unmount();
  expect(read.signal?.aborted).toBe(true);
  await act(async () => pending.resolve(currentGridPage("888.00000000")));
  expect(screen.queryByText("888.00000000")).not.toBeInTheDocument();
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  expect(
    calls.filter((call) => call.function === "facts.cube.scan"),
  ).toHaveLength(1);
});
