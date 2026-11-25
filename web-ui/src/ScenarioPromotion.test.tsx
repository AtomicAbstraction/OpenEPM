import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { createRef } from "react";
import {
  ScenarioPromotion,
  type ScenarioPromotionControl,
} from "./ScenarioPromotion";
import { operationAdmissionResponse } from "./test-setup";
import type { ApplicationCatalog } from "./types";
import { fillRecoverySlots } from "./draft-recovery-test-fixture";
import { canPreserveUnsavedWork, unsavedWorkSnapshot } from "./unsaved-work";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});
const app = {
  workspaceId: "w",
  applicationId: "a",
  name: "Model",
  status: "Active",
};
const dimensions = [
  "Account",
  "Entity",
  "Year",
  "Period",
  "View",
  "Value",
  "Scenario",
  "DataType",
].map((axis) => ({
  dimension_id: axis,
  name: axis,
  model_role: axis,
  status: "Active",
}));
const catalog: ApplicationCatalog = {
  applicationAccess: {
    role: "Editor",
    workspaceAdministrator: false,
    issuer: "i",
    subjectId: "s",
  },
  enabledCapabilities: [],
  revisions: { metadata: 8, data: 1, policy: 0, security: 0, commit: 8 },
  functions: Object.fromEntries(
    [
      "facts.slice.copy.prepare",
      "facts.source.preview",
      "facts.source.publish",
      "facts.slice.copy.status.read",
      "application.operation.receipt.read",
    ].map((name) => [name, {}]),
  ),
};
const batchId = "b".repeat(32),
  contentDigest = "c".repeat(64);
const coordinate = Object.fromEntries(
  dimensions.map((axis) => [
    axis.dimension_id,
    axis.dimension_id === "Scenario" ? "Approved" : "One",
  ]),
);
const prepared = { batchId, contentDigest, status: "ready", rowCount: 1 };
const preview = {
  batchId,
  contentDigest,
  mode: "merge",
  setCount: 1,
  clearCount: 0,
  previewToken: "exact-preview",
  review: {
    format: "openepm-source-change-review-v1",
    mode: "merge",
    scopeMembers: { Scenario: "Approved" },
    scopeAll: false,
    periodSelection: null,
    metadataRevision: 8,
    dataRevision: 1,
    commitRevision: 8,
    sampleLimitPerAction: 20,
    setsComplete: true,
    clearsComplete: true,
    readRestricted: false,
    examples: [
      {
        action: "set",
        members: coordinate,
        valueKind: "numeric",
        sourceRef: "scenario-copy:source",
        before: { present: false },
        after: { present: true, amount: "0.00000000" },
      },
    ],
  },
};
const receipt = {
  batchId,
  contentDigest,
  mode: "merge",
  setCount: 1,
  clearCount: 0,
  committedRevision: 9,
};
const response = (result: unknown) => new Response(JSON.stringify({ result }));
const recordedPublication = {
  operationId: batchId,
  commandDigest: contentDigest,
  actorId: catalog.applicationAccess.subjectId,
  committedRevision: receipt.committedRevision,
  committedAt: "2026-11-19T12:00:00+00:00",
  outcome: { batchId, setCount: 1, clearCount: 0, changedCount: 1 },
};
function install(
  handler?: (
    name: string,
    value: any,
  ) => Promise<Response> | Response | undefined,
) {
  const calls: Array<{ path: string; body: any }> = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      const value = JSON.parse(init.body);
      calls.push({ path: String(path), body: value });
      if (path === "/api/operation-admission")
        return operationAdmissionResponse(calls.length.toString(16));
      const name = value.program.function;
      // Match the real router: preview is a read; prepare/publication are source actions.
      if (
        path !==
        (name === "facts.source.preview"
          ? "/api/source-load"
          : [
                "application.operation.receipt.read",
                "facts.slice.copy.status.read",
              ].includes(name)
            ? "/api/read"
            : "/api/source-action")
      )
        return new Response(JSON.stringify({ error: "INVALID_SOURCE_ROUTE" }), {
          status: 400,
        });
      expect(Object.keys(value).sort()).toEqual(
        path !== "/api/source-action"
          ? ["applicationId", "program", "workspaceId"]
          : [
              "applicationId",
              "confirmed",
              "idempotencyKey",
              "program",
              "workspaceId",
            ],
      );
      if (path === "/api/source-action") {
        expect(value.confirmed).toBe(true);
        expect(canPreserveUnsavedWork()).toBe(true);
        expect(
          unsavedWorkSnapshot().some((entry) =>
            entry.id.endsWith(":scenario-copy"),
          ),
        ).toBe(true);
      }
      const custom = handler?.(name, value);
      if (custom !== undefined) return custom;
      if (name === "facts.slice.copy.prepare") return response(prepared);
      if (name === "facts.slice.copy.status.read") return response(prepared);
      if (name === "facts.source.preview") return response(preview);
      if (name === "facts.source.publish") return response(receipt);
      if (name === "application.operation.receipt.read")
        return response(recordedPublication);
      throw new Error("Unexpected request");
    }),
  );
  return calls;
}
function choose() {
  fireEvent.click(screen.getByText("Copy scenario facts"));
  fireEvent.change(screen.getByLabelText("Copy source scenario ID"), {
    target: { value: "Baseline" },
  });
  fireEvent.change(screen.getByLabelText("Copy destination scenario ID"), {
    target: { value: "Approved" },
  });
  for (const axis of dimensions.filter(
    (axis) => axis.dimension_id !== "Scenario",
  ))
    fireEvent.change(screen.getByLabelText(`Copy scope ${axis.dimension_id}`), {
      target: { value: "all" },
    });
  fireEvent.change(screen.getByLabelText("Copy destination policy"), {
    target: { value: "merge" },
  });
}
async function review() {
  choose();
  fireEvent.click(screen.getByRole("button", { name: "Prepare copy review" }));
  await screen.findByLabelText("Scenario copy review");
  fireEvent.click(screen.getByRole("checkbox"));
}

const pickerCatalog = {
  ...catalog,
  functions: { ...catalog.functions, "metadata.member.list": {} },
};
const pickerMembers = {
  Scenario: [
    { member_id: "Baseline", name: "Working forecast", status: "Active" },
    { member_id: "Approved", name: "Approved forecast", status: "Active" },
    { member_id: "Former", name: "Retired forecast", status: "Inactive" },
  ],
  Account: [{ member_id: "One", name: "Total demand", status: "Active" }],
};

const comparedAlternative = {
  dimensionId: "Scenario",
  sourceMemberId: "Alternative",
  members: Object.fromEntries(
    Object.entries(coordinate).filter(([axis]) => axis !== "Scenario"),
  ),
};

it("keeps an existing setup until explicit adoption and sends only the newly reviewed scope", async () => {
  const calls = install((name) =>
    name === "facts.source.preview"
      ? response({
          ...preview,
          review: { ...preview.review, scopeMembers: coordinate },
        })
      : undefined,
  );
  const control = createRef<ScenarioPromotionControl>();
  render(
    <ScenarioPromotion
      app={app}
      catalog={catalog}
      dimensions={dimensions}
      comparisonControl={control}
    />,
  );
  choose();
  act(() =>
    expect(control.current?.offerComparedSource(comparedAlternative)).toBe(
      true,
    ),
  );
  expect(screen.getByLabelText("Copy source scenario ID")).toHaveValue(
    "Baseline",
  );
  expect(screen.getByLabelText("Copy destination scenario ID")).toHaveValue(
    "Approved",
  );
  expect(screen.getByLabelText("Copy destination policy")).toHaveValue("merge");
  expect(
    screen.getByText("Using the comparison replaces the current copy setup."),
  ).toBeVisible();
  expect(calls).toHaveLength(0);

  const destination = screen.getByLabelText("Copy destination scenario ID");
  const setupAtFocus = vi.fn(() => [
    (screen.getByLabelText("Copy source scenario ID") as HTMLInputElement)
      .value,
    (destination as HTMLInputElement).value,
    (screen.getByLabelText("Copy destination policy") as HTMLSelectElement)
      .value,
  ]);
  destination.addEventListener("focus", setupAtFocus, { once: true });
  const adopt = screen.getByRole("button", {
    name: "Use compared source and scope",
  });
  adopt.focus();
  fireEvent.click(adopt);
  expect(destination).toHaveFocus();
  expect(setupAtFocus.mock.results).toEqual([
    { type: "return", value: ["Alternative", "", ""] },
  ]);
  expect(screen.getByLabelText("Copy source scenario ID")).toHaveValue(
    "Alternative",
  );
  expect(screen.getByLabelText("Copy destination scenario ID")).toHaveValue("");
  expect(screen.getByLabelText("Copy destination policy")).toHaveValue("");
  expect(
    screen.getByRole("button", { name: "Prepare copy review" }),
  ).toHaveAttribute("aria-disabled", "true");
  expect(calls).toHaveLength(0);
  fireEvent.change(screen.getByLabelText("Copy destination scenario ID"), {
    target: { value: "Approved" },
  });
  fireEvent.change(screen.getByLabelText("Copy destination policy"), {
    target: { value: "merge" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Prepare copy review" }));
  expect(await screen.findByLabelText("Scenario copy review")).toBeVisible();
  expect(
    calls.find(({ path }) => path === "/api/source-action")?.body.program
      .arguments,
  ).toMatchObject({
    dimensionId: "Scenario",
    sourceMemberId: "Alternative",
    targetMemberId: "Approved",
    filterMembers: comparedAlternative.members,
    mode: "merge",
    expectedMetadataRevision: 8,
    expectedDataRevision: 1,
  });
  expect(
    calls.filter(({ path }) => path === "/api/source-action"),
  ).toHaveLength(1);
});

it("protects the original unconfirmed copy and withdraws a comparison offer when access changes", async () => {
  const calls = install((name) =>
    name === "facts.slice.copy.prepare"
      ? new Response(null, { status: 503 })
      : undefined,
  );
  const control = createRef<ScenarioPromotionControl>();
  const view = render(
    <ScenarioPromotion
      app={app}
      catalog={catalog}
      dimensions={dimensions}
      comparisonControl={control}
    />,
  );
  choose();
  fireEvent.click(screen.getByRole("button", { name: "Prepare copy review" }));
  await screen.findByRole("button", {
    name: "Check original preparation status",
  });
  act(() =>
    expect(control.current?.offerComparedSource(comparedAlternative)).toBe(
      true,
    ),
  );
  expect(
    screen.getByText(
      "Finish or reconcile the current copy before using this comparison.",
    ),
  ).toBeVisible();
  expect(
    screen.queryByRole("button", { name: "Use compared source and scope" }),
  ).toBeNull();
  expect(
    calls.filter(({ path }) => path === "/api/source-action"),
  ).toHaveLength(1);

  view.rerender(
    <ScenarioPromotion
      app={app}
      catalog={{ ...catalog, revisions: { ...catalog.revisions, security: 1 } }}
      dimensions={dimensions}
      comparisonControl={control}
    />,
  );
  expect(
    screen.queryByRole("region", { name: "Compared copy source" }),
  ).toBeNull();
  expect(
    screen.getByRole("button", { name: "Check original preparation status" }),
  ).toBeVisible();
  expect(
    calls.filter(({ path }) => path === "/api/source-action"),
  ).toHaveLength(1);
});

it("chooses named members in the shared picker and prepares their exact IDs and scope", async () => {
  const calls = install((name) =>
    name === "facts.source.preview"
      ? response({
          ...preview,
          review: {
            ...preview.review,
            scopeMembers: { Account: "One", Scenario: "Approved" },
          },
        })
      : undefined,
  );
  const loadMembers = vi.fn(
    async (dimensionId: string) =>
      pickerMembers[dimensionId as keyof typeof pickerMembers],
  );
  render(
    <ScenarioPromotion
      app={app}
      catalog={pickerCatalog}
      dimensions={dimensions}
      memberCatalog={pickerMembers}
      loadMembers={loadMembers}
    />,
  );
  fireEvent.click(screen.getByText("Copy scenario facts"));
  expect(loadMembers).not.toHaveBeenCalled();
  expect(screen.queryByLabelText("Copy source scenario ID")).toBeNull();
  async function pick(label: string, name: string) {
    const origin = screen.getByRole("button", { name: `Choose ${label}` });
    origin.focus();
    fireEvent.click(origin);
    const dialog = within(
      await screen.findByRole("dialog", { name: `Choose ${label}` }),
    );
    expect(
      dialog.queryByRole("button", { name: /Retired forecast/ }),
    ).toBeNull();
    fireEvent.click(
      dialog.getByRole("button", { name: new RegExp(`^${name}`) }),
    );
    fireEvent.click(
      dialog.getByRole("button", { name: "Add selected member" }),
    );
    fireEvent.click(dialog.getByRole("button", { name: "Apply selection" }));
    expect(
      screen.getByRole("button", { name: `Change ${label}, ${name}` }),
    ).toHaveFocus();
  }
  await pick("source scenario", "Working forecast");
  await pick("destination scenario", "Approved forecast");
  for (const axis of dimensions.filter(
    (axis) => axis.dimension_id !== "Scenario",
  ))
    fireEvent.change(screen.getByLabelText(`Copy scope ${axis.dimension_id}`), {
      target: { value: axis.dimension_id === "Account" ? "member" : "all" },
    });
  await pick("Account scope member", "Total demand");
  const prepare = screen.getByRole("button", { name: "Prepare copy review" });
  expect(prepare).toHaveAttribute("aria-disabled", "true");
  expect(calls).toHaveLength(0);
  fireEvent.change(screen.getByLabelText("Copy destination policy"), {
    target: { value: "merge" },
  });
  fireEvent.click(prepare);
  const review = within(
    await screen.findByRole("region", { name: "Scenario copy review" }),
  );
  expect(
    review.getByText(/Source Working forecast; destination Approved forecast/),
  ).toBeVisible();
  expect(review.getByRole("checkbox")).not.toBeChecked();
  expect(
    calls.find((entry) => entry.path === "/api/source-action")?.body.program
      .arguments,
  ).toMatchObject({
    dimensionId: "Scenario",
    sourceMemberId: "Baseline",
    targetMemberId: "Approved",
    expectedMetadataRevision: 8,
    expectedDataRevision: 1,
    filterMembers: { Account: "One" },
    mode: "merge",
  });
  expect(
    calls.some(
      (entry) => entry.body.program.function === "facts.source.publish",
    ),
  ).toBe(false);
});

it("abandons a member read and hides the choice when authority changes", async () => {
  let finish!: (members: typeof pickerMembers.Scenario) => void;
  let readSignal: AbortSignal | undefined;
  const loadMembers = vi.fn((_dimensionId: string, signal: AbortSignal) => {
    readSignal = signal;
    return new Promise<typeof pickerMembers.Scenario>((resolve) => {
      finish = resolve;
    });
  });
  const props = { app, dimensions, memberCatalog: pickerMembers, loadMembers };
  const { rerender } = render(
    <ScenarioPromotion {...props} catalog={pickerCatalog} />,
  );
  fireEvent.click(screen.getByText("Copy scenario facts"));
  fireEvent.click(
    screen.getByRole("button", { name: "Choose source scenario" }),
  );
  expect(screen.getByRole("status")).toHaveTextContent(
    "Reading authorized members",
  );
  rerender(
    <ScenarioPromotion
      {...props}
      catalog={{ ...catalog, revisions: { ...catalog.revisions, security: 1 } }}
    />,
  );
  expect(readSignal?.aborted).toBe(true);
  await act(async () => finish(pickerMembers.Scenario));
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(
    screen.getByText(/Current member discovery is unavailable/),
  ).toBeVisible();
  expect(
    screen.queryByRole("button", { name: "Prepare copy review" }),
  ).toBeNull();
});

it("requires exact fact-axis scope and policy, then publishes the native reviewed batch", async () => {
  const calls = install();
  const model = [
    ...dimensions,
    {
      dimension_id: "QuoteCurrency",
      name: "Quote currency policy",
      model_role: "Currency",
      status: "Active",
    },
    {
      dimension_id: "FormerChannel",
      name: "Former channel",
      model_role: "Custom",
      status: "Inactive",
    },
  ];
  render(<ScenarioPromotion app={app} catalog={catalog} dimensions={model} />);
  fireEvent.click(screen.getByText("Copy scenario facts"));
  expect(screen.queryByLabelText("Copy scope QuoteCurrency")).toBeNull();
  expect(screen.queryByLabelText("Copy scope FormerChannel")).toBeNull();
  expect(
    screen.getByRole("button", { name: "Prepare copy review" }),
  ).toHaveAttribute("aria-disabled", "true");
  fireEvent.click(screen.getByText("Copy scenario facts"));
  await review();
  const changes = within(
    screen.getByRole("region", { name: "Scenario copy change examples" }),
  );
  expect(
    changes.getByRole("columnheader", { name: "Destination coordinate" }),
  ).toBeVisible();
  expect(
    changes.getByRole("columnheader", { name: "Source coordinate" }),
  ).toBeVisible();
  expect(
    changes.getByRole("cell", {
      name: /Account: One.*Scenario: Baseline.*DataType: One/,
    }),
  ).toBeVisible();
  expect(
    changes.getByRole("cell", {
      name: /Account: One.*Scenario: Approved.*DataType: One/,
    }),
  ).toBeVisible();
  const copy = calls.find(
    (call) =>
      call.path === "/api/source-action" &&
      call.body.program?.function === "facts.slice.copy.prepare",
  )!.body.program.arguments;
  expect(copy).toMatchObject({
    dimensionId: "Scenario",
    sourceMemberId: "Baseline",
    targetMemberId: "Approved",
    filterMembers: {},
    mode: "merge",
    expectedMetadataRevision: 8,
    expectedDataRevision: 1,
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Publish scenario copy" }),
  );
  expect(await screen.findByText(/committed revision 9/)).toBeInTheDocument();
  expect(unsavedWorkSnapshot()).toHaveLength(0);
  expect(
    calls.find(
      (call) =>
        call.path === "/api/source-action" &&
        call.body.program?.function === "facts.source.publish",
    )!.body.program.arguments,
  ).toEqual({ batchId, previewToken: "exact-preview" });
});

it.each([
  {
    name: "another destination",
    members: { ...coordinate, Scenario: "Baseline" },
    message: "A change example falls outside the reviewed destination scope.",
  },
  {
    name: "missing fact axis",
    members: Object.fromEntries(
      Object.entries(coordinate).filter(([axis]) => axis !== "Entity"),
    ),
    message: "A change example does not match the reviewed fact dimensions.",
  },
  {
    name: "different fact axis",
    members: {
      ...Object.fromEntries(
        Object.entries(coordinate).filter(([axis]) => axis !== "Entity"),
      ),
      FormerEntity: "One",
    },
    message: "A change example does not match the reviewed fact dimensions.",
  },
])(
  "rejects a preview example with $name before review and can recover the same batch",
  async ({ members, message }) => {
    let attempts = 0;
    const calls = install((name) =>
      name === "facts.source.preview" && ++attempts === 1
        ? response({
            ...preview,
            review: {
              ...preview.review,
              examples: [{ ...preview.review.examples[0], members }],
            },
          })
        : undefined,
    );
    render(
      <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
    );
    choose();
    fireEvent.click(
      screen.getByRole("button", { name: "Prepare copy review" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(message);
    expect(
      screen.queryByRole("button", { name: "Publish scenario copy" }),
    ).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Review prepared copy" }),
    );
    expect(
      await screen.findByRole("region", {
        name: "Scenario copy change examples",
      }),
    ).toBeVisible();
    expect(screen.getByRole("checkbox")).not.toBeChecked();
    expect(
      calls.filter(
        ({ body }) =>
          body.program.function === "facts.slice.copy.prepare" &&
          body.confirmed,
      ),
    ).toHaveLength(1);
    expect(
      calls.some(
        ({ body }) => body.program.function === "facts.source.publish",
      ),
    ).toBe(false);
  },
);

it.each(["disconnected", "denied"])(
  "retains a confirmed prepared batch across %s preview and remount without repeating preparation",
  async (failure) => {
    let reads = 0;
    const calls = install((name) =>
      name === "facts.source.preview" && ++reads === 1
        ? failure === "disconnected"
          ? Promise.reject(new TypeError("preview disconnected"))
          : Promise.resolve(
              new Response(JSON.stringify({ error: "preview denied" }), {
                status: 403,
              }),
            )
        : undefined,
    );
    const first = render(
      <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
    );
    choose();
    fireEvent.click(
      screen.getByRole("button", { name: "Prepare copy review" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      failure === "denied"
        ? "This copy step is unavailable under your current access"
        : "preview disconnected",
    );
    expect(unsavedWorkSnapshot()).toHaveLength(1);
    expect(screen.getByLabelText("Prepared scenario copy")).toHaveTextContent(
      "Copy status ready",
    );
    expect(
      screen.getByLabelText("Prepared scenario copy"),
    ).not.toHaveTextContent(/source values|Baseline|Approved/);
    first.unmount();
    render(
      <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
    );
    fireEvent.click(screen.getByText("Copy scenario facts"));
    fireEvent.click(
      await screen.findByRole("button", { name: "Review prepared copy" }),
    );
    expect(
      await screen.findByLabelText("Scenario copy review"),
    ).toBeInTheDocument();
    expect(
      calls.filter(
        (call) =>
          call.path === "/api/source-action" &&
          call.body.program?.function === "facts.slice.copy.prepare",
      ),
    ).toHaveLength(1);
    expect(
      calls.filter((call) => call.path === "/api/operation-admission"),
    ).toHaveLength(1);
  },
);

it("rejects a preview for a different batch while retaining the accepted preparation", async () => {
  install((name) =>
    name === "facts.source.preview"
      ? response({ ...preview, batchId: "d".repeat(32) })
      : undefined,
  );
  render(
    <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
  );
  choose();
  fireEvent.click(screen.getByRole("button", { name: "Prepare copy review" }));
  expect(
    await screen.findByText(/copy preview is incomplete/),
  ).toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Publish scenario copy" }),
  ).not.toBeInTheDocument();
  expect(screen.getByLabelText("Prepared scenario copy")).toHaveTextContent(
    "Copy status ready",
  );
});

it("distinguishes publication in progress from a lost response without dispatching twice", async () => {
  let disconnect: ((error: Error) => void) | undefined;
  const calls = install((functionName) =>
    functionName === "facts.source.publish"
      ? new Promise<Response>((_resolve, reject) => {
          disconnect = reject;
        })
      : undefined,
  );
  render(
    <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
  );
  await review();
  const publish = screen.getByRole("button", { name: "Publish scenario copy" });
  publish.focus();
  fireEvent.click(publish);
  await waitFor(() => expect(disconnect).toBeDefined());
  expect(screen.getByRole("status")).toHaveTextContent(
    "Publishing scenario copy",
  );
  expect(screen.queryByText(/outcome is uncertain/)).not.toBeInTheDocument();
  expect(publish).toHaveFocus();
  fireEvent.click(publish);
  expect(
    calls.filter(
      ({ path, body }) =>
        path === "/api/source-action" &&
        body.program.function === "facts.source.publish",
    ),
  ).toHaveLength(1);
  await act(async () =>
    disconnect!(new TypeError("Publication connection lost")),
  );
  expect(screen.getByRole("status")).toHaveTextContent(
    "publication outcome is uncertain",
  );
  expect(screen.queryByLabelText("Scenario copy review")).toBeNull();
  expect(
    screen.getByRole("button", { name: "Check original publication status" }),
  ).toHaveFocus();
});

it("moves keyboard focus into the ready review and respects leaving during publication", async () => {
  let finish: ((value: Response) => void) | undefined;
  const calls = install((functionName) =>
    functionName === "facts.source.publish"
      ? new Promise<Response>((resolve) => {
          finish = resolve;
        })
      : undefined,
  );
  render(
    <>
      <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />
      <button>Continue to another task</button>
    </>,
  );
  choose();
  const prepare = screen.getByRole("button", { name: "Prepare copy review" });
  prepare.focus();
  fireEvent.click(prepare);
  expect(
    await screen.findByRole("heading", { name: "Scenario copy review" }),
  ).toHaveFocus();
  fireEvent.click(screen.getByRole("checkbox"));
  const publish = screen.getByRole("button", { name: "Publish scenario copy" });
  publish.focus();
  fireEvent.click(publish);
  await waitFor(() => expect(finish).toBeDefined());
  const outside = screen.getByRole("button", {
    name: "Continue to another task",
  });
  outside.focus();
  await act(async () => finish!(response(receipt)));
  expect(outside).toHaveFocus();
  expect(screen.getByRole("status")).toHaveTextContent("committed revision 9");
  expect(
    calls.filter(({ path }) => path === "/api/operation-admission"),
  ).toHaveLength(2);
});

it("reports an already published original preparation without previewing or publishing again", async () => {
  const calls = install((name) =>
    name === "facts.slice.copy.prepare"
      ? response({ ...prepared, status: "published" })
      : undefined,
  );
  render(
    <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
  );
  choose();
  fireEvent.click(screen.getByRole("button", { name: "Prepare copy review" }));
  expect(
    await screen.findByLabelText("Prepared scenario copy"),
  ).toHaveTextContent("published");
  expect(
    screen.queryByRole("button", { name: "Review prepared copy" }),
  ).not.toBeInTheDocument();
  expect(
    calls
      .filter((call) => call.path === "/api/source-action")
      .map((call) => call.body.program.function),
  ).toEqual(["facts.slice.copy.prepare"]);
});

it.each(["wrong receipt", "denied"])(
  "keeps the publication unconfirmed after %s and checks the same receipt again",
  async (failure) => {
    let reads = 0;
    const calls = install((name) => {
      if (name === "facts.source.publish")
        throw new TypeError("lost publication");
      if (name !== "application.operation.receipt.read") return undefined;
      if (++reads === 1)
        return failure === "denied"
          ? new Response(JSON.stringify({ code: "ACCESS_DENIED" }), {
              status: 403,
            })
          : response({
              ...recordedPublication,
              outcome: { ...recordedPublication.outcome, setCount: 2 },
            });
    });
    const first = render(
      <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
    );
    await review();
    fireEvent.click(
      screen.getByRole("button", { name: "Publish scenario copy" }),
    );
    await screen.findByText("lost publication");
    first.unmount();
    vi.spyOn(Date, "now").mockReturnValue(Date.now() + 2_000_000);
    render(
      <ScenarioPromotion
        app={app}
        catalog={{
          ...catalog,
          revisions: { ...catalog.revisions, security: 1 },
        }}
        dimensions={dimensions}
      />,
    );
    fireEvent.click(screen.getByText("Copy scenario facts"));
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Check original publication status",
      }),
    );
    expect(
      await screen.findByText(
        failure === "denied"
          ? /This copy step is unavailable under your current access/
          : /does not match the reviewed copy/,
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Retry original publication" }),
    ).toBeNull();
    expect(
      screen.getByRole("button", { name: "Check original publication status" }),
    ).toBeEnabled();
    fireEvent.click(
      screen.getByRole("button", { name: "Check original publication status" }),
    );
    expect(await screen.findByText(/committed revision 9/)).toBeInTheDocument();
    const sent = calls
      .filter(
        (call) =>
          call.path === "/api/source-action" &&
          call.body.program?.function === "facts.source.publish",
      )
      .map((call) => call.body);
    expect(sent).toHaveLength(1);
    expect(calls.filter((call) => call.path === "/api/read")).toEqual(
      Array(2).fill({
        path: "/api/read",
        body: {
          workspaceId: "w",
          applicationId: "a",
          program: {
            languageVersion: 2,
            function: "application.operation.receipt.read",
            arguments: { operationId: batchId },
          },
        },
      }),
    );
    expect(
      calls.filter((call) => call.path === "/api/operation-admission"),
    ).toHaveLength(2);
  },
);

it("only offers a manual retry after a missing receipt and reuses the original admitted packet", async () => {
  let sends = 0;
  const calls = install((name) => {
    if (name === "facts.source.publish" && ++sends === 1)
      throw new TypeError("publication response lost");
    if (name === "application.operation.receipt.read")
      return new Response(
        JSON.stringify({ code: "OPERATION_RECEIPT_NOT_FOUND" }),
        { status: 400 },
      );
  });
  render(
    <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
  );
  await review();
  fireEvent.click(
    screen.getByRole("button", { name: "Publish scenario copy" }),
  );
  await screen.findByText("publication response lost");
  expect(
    screen.queryByRole("button", { name: "Retry original publication" }),
  ).toBeNull();
  fireEvent.click(
    screen.getByRole("button", { name: "Check original publication status" }),
  );
  const retry = await screen.findByRole("button", {
    name: "Retry original publication",
  });
  expect(screen.getByRole("status")).toHaveTextContent(
    "publication remains unconfirmed",
  );
  expect(sends).toBe(1);
  fireEvent.click(retry);
  await screen.findByText(/committed revision 9/);
  const publications = calls.filter(
    ({ body }) => body.program.function === "facts.source.publish",
  );
  expect(
    publications.filter(({ path }) => path === "/api/operation-admission"),
  ).toHaveLength(1);
  const effects = publications.filter(
    ({ path }) => path === "/api/source-action",
  );
  expect(effects).toHaveLength(2);
  expect(effects[1]).toEqual(effects[0]);
});

it("keeps a pending copy through changed authority and lets the same subject read it as a Reader", async () => {
  let finish: ((value: Response) => void) | undefined;
  let readAttempts = 0;
  const calls = install((name) => {
    if (name === "facts.source.publish")
      throw new TypeError("publication response lost");
    if (name === "application.operation.receipt.read" && ++readAttempts === 1)
      return new Promise<Response>((resolve) => {
        finish = resolve;
      });
  });
  const subjectCatalog = (role: "Reader" | "Editor"): ApplicationCatalog => ({
    ...catalog,
    applicationAccess: { ...catalog.applicationAccess, role },
    revisions: { ...catalog.revisions, security: Number(role === "Reader") },
    functions:
      role === "Reader"
        ? { "application.operation.receipt.read": {} }
        : catalog.functions,
  });
  const view = (role: "Reader" | "Editor") => (
    <ScenarioPromotion
      app={app}
      catalog={subjectCatalog(role)}
      dimensions={dimensions}
    />
  );
  const { rerender } = render(view("Editor"));
  await review();
  fireEvent.click(
    screen.getByRole("button", { name: "Publish scenario copy" }),
  );
  await screen.findByText("publication response lost");
  fireEvent.click(
    screen.getByRole("button", { name: "Check original publication status" }),
  );
  await waitFor(() => expect(finish).toBeDefined());
  rerender(view("Reader"));
  await act(async () => finish!(response(recordedPublication)));
  expect(screen.queryByText(/committed revision 9/)).toBeNull();
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  fireEvent.click(
    screen.getByRole("button", { name: "Check original publication status" }),
  );

  // The read-only user can settle retained evidence without source actions.
  expect(await screen.findByText(/committed revision 9/)).toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Prepare copy review" }),
  ).toBeNull();
  expect(unsavedWorkSnapshot()).toHaveLength(0);
  expect(
    calls.filter(({ path }) => path === "/api/source-action"),
  ).toHaveLength(2);
  expect(calls.filter(({ path }) => path === "/api/read")).toHaveLength(2);
});

it("blocks preparation before dispatch when pinned recovery capacity is full", async () => {
  fillRecoverySlots();
  const calls = install();
  render(
    <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
  );
  choose();
  fireEvent.click(screen.getByRole("button", { name: "Prepare copy review" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "This tab cannot retain another recovery record",
  );
  expect(calls.map((call) => call.path)).toEqual(["/api/operation-admission"]);
  expect(unsavedWorkSnapshot()).toHaveLength(24);
  expect(canPreserveUnsavedWork()).toBe(true);
});

it("retains a ready batch returned after unmount and rereads it without another prepare effect", async () => {
  let resolve!: (value: Response) => void;
  const delayed = new Promise<Response>((done) => {
    resolve = done;
  });
  const calls = install((name) =>
    name === "facts.slice.copy.prepare" ? delayed : undefined,
  );
  const first = render(
    <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
  );
  choose();
  fireEvent.click(screen.getByRole("button", { name: "Prepare copy review" }));
  await waitFor(() =>
    expect(calls.some((call) => call.path === "/api/source-action")).toBe(true),
  );
  first.unmount();
  await act(async () => resolve(response(prepared)));
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  render(
    <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
  );
  fireEvent.click(screen.getByText("Copy scenario facts"));
  fireEvent.click(
    await screen.findByRole("button", { name: "Review prepared copy" }),
  );
  expect(
    await screen.findByLabelText("Scenario copy review"),
  ).toBeInTheDocument();
  expect(calls.map((call) => call.path)).toEqual([
    "/api/operation-admission",
    "/api/source-action",
    "/api/source-load",
  ]);
  fireEvent.click(screen.getByRole("button", { name: "Start a new copy" }));
  expect(unsavedWorkSnapshot()).toHaveLength(0);
});

it("keeps the prepared batch pinned when its first publication is definitively denied", async () => {
  const calls = install((name) =>
    name === "facts.source.publish"
      ? new Response(
          JSON.stringify({
            code: "DIMENSIONAL_SCOPE_DENIED",
            message: "Dimensional scope denied",
          }),
          { status: 403 },
        )
      : undefined,
  );
  const first = render(
    <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
  );
  await review();
  const publish = screen.getByRole("button", { name: "Publish scenario copy" });
  publish.focus();
  fireEvent.click(publish);
  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent(
    "This copy step is unavailable under your current access",
  );
  expect(alert).toHaveFocus();
  expect(screen.queryByLabelText("Scenario copy review")).toBeNull();
  expect(screen.getByLabelText("Prepared scenario copy")).not.toHaveTextContent(
    /source values|Baseline|Approved/,
  );
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  expect(
    screen.queryByLabelText("Scenario copy reconciliation"),
  ).not.toBeInTheDocument();
  first.unmount();
  render(
    <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
  );
  fireEvent.click(screen.getByText("Copy scenario facts"));
  expect(
    await screen.findByRole("button", { name: "Review prepared copy" }),
  ).toBeEnabled();
  expect(
    calls.filter((call) => call.path === "/api/source-action"),
  ).toHaveLength(2);
});

it("rereads the same batch after an access revision changes and requires fresh approval", async () => {
  let previews = 0;
  const calls = install((name) => {
    if (name === "facts.source.preview" && ++previews > 1)
      return response({ ...preview, previewToken: "renewed-preview" });
  });
  const { rerender } = render(
    <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
  );
  await review();
  rerender(
    <ScenarioPromotion
      app={app}
      catalog={{
        ...catalog,
        revisions: { ...catalog.revisions, security: 2, commit: 10 },
      }}
      dimensions={dimensions}
    />,
  );
  expect(screen.queryByLabelText("Scenario copy review")).toBeNull();
  expect(screen.getByLabelText("Prepared scenario copy")).not.toHaveTextContent(
    /source values|Baseline|Approved/,
  );
  const reviewAgain = screen.getByRole("button", {
    name: "Review prepared copy",
  });
  expect(reviewAgain).not.toHaveAttribute("aria-disabled", "true");
  fireEvent.click(reviewAgain);
  await screen.findByLabelText("Scenario copy review");
  expect(screen.getByRole("checkbox")).not.toBeChecked();
  const publish = screen.getByRole("button", { name: "Publish scenario copy" });
  fireEvent.click(publish);
  expect(
    calls.filter(({ path }) => path === "/api/source-action"),
  ).toHaveLength(1);
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(publish);
  await screen.findByText(/committed revision 9/);
  expect(
    calls
      .filter(({ path }) => path === "/api/source-load")
      .map(({ body }) => body.program.arguments),
  ).toEqual([{ batchId }, { batchId }]);
  expect(
    calls
      .filter(({ path }) => path === "/api/source-action")
      .map(({ body }) => body.program.function),
  ).toEqual(["facts.slice.copy.prepare", "facts.source.publish"]);
  expect(calls.at(-1)?.body.program.arguments).toEqual({
    batchId,
    previewToken: "renewed-preview",
  });
});

it.each(["metadata", "data"] as const)(
  "requires a new preparation after the original %s revision changes",
  async (revision) => {
    const calls = install();
    const { rerender } = render(
      <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
    );
    await review();
    rerender(
      <ScenarioPromotion
        app={app}
        catalog={{
          ...catalog,
          revisions: {
            ...catalog.revisions,
            [revision]: catalog.revisions[revision] + 1,
          },
        }}
        dimensions={dimensions}
      />,
    );
    const reviewAgain = screen.getByRole("button", {
      name: "Review prepared copy",
    });
    expect(reviewAgain).toHaveAttribute("aria-disabled", "true");
    fireEvent.click(reviewAgain);
    expect(screen.getByText(/The model or facts changed/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Scenario copy review")).toBeNull();
    expect(
      calls.filter(({ path }) => path === "/api/source-load"),
    ).toHaveLength(1);
    expect(
      calls.filter(({ path }) => path === "/api/source-action"),
    ).toHaveLength(1);
  },
);

it.each([
  ["facts.slice.copy.prepare", "STALE_SCENARIO_COPY_REVISION"],
  ["facts.source.preview", "STALE_SOURCE_BATCH_REVISION"],
  ["facts.source.publish", "STALE_SOURCE_BATCH_REVISION"],
])("refreshes before replacing a stale copy after %s", async (step, code) => {
  const updated = {
    ...catalog,
    revisions: { ...catalog.revisions, data: 2, commit: 9 },
  };
  const updatedBatchId = "d".repeat(32);
  let refreshed = false;
  const calls = install((name) => {
    if (name === step && !refreshed)
      return new Response(JSON.stringify({ code }), { status: 400 });
    if (!refreshed) return;
    if (name === "facts.slice.copy.prepare")
      return response({ ...prepared, batchId: updatedBatchId });
    if (name === "facts.source.preview")
      return response({
        ...preview,
        batchId: updatedBatchId,
        previewToken: "updated-preview",
        review: { ...preview.review, dataRevision: 2, commitRevision: 9 },
      });
    if (name === "facts.source.publish")
      return response({
        ...receipt,
        batchId: updatedBatchId,
        committedRevision: 10,
      });
  });
  const refreshCatalog = vi
    .fn<() => Promise<ApplicationCatalog>>()
    .mockRejectedValueOnce(new Error("Application context is unavailable"))
    .mockImplementationOnce(async () => {
      refreshed = true;
      mounted.rerender(view(updated));
      return updated;
    });
  const view = (value: ApplicationCatalog) => (
    <ScenarioPromotion
      app={app}
      catalog={value}
      dimensions={dimensions}
      onRefreshCatalog={refreshCatalog}
    />
  );
  const mounted = render(view(catalog));
  if (step === "facts.source.publish") {
    await review();
    const publish = screen.getByRole("button", {
      name: "Publish scenario copy",
    });
    publish.focus();
    fireEvent.click(publish);
  } else {
    choose();
    const prepare = screen.getByRole("button", { name: "Prepare copy review" });
    prepare.focus();
    fireEvent.click(prepare);
  }
  const alert = await screen.findByRole("alert");
  expect(alert).toHaveTextContent(
    "Refresh the application context before preparing a new copy",
  );
  expect(alert).toHaveFocus();
  expect(screen.queryByLabelText("Scenario copy review")).toBeNull();
  expect(screen.queryByLabelText("Scenario copy reconciliation")).toBeNull();

  const prepare = screen.getByRole("button", { name: "Prepare copy review" });
  const oldReview = screen.queryByRole("button", {
    name: "Review prepared copy",
  });
  const oldCopy = screen.queryByRole("button", { name: "Start a new copy" });
  expect(prepare).toHaveAttribute("aria-disabled", "true");
  if (oldReview) expect(oldReview).toHaveAttribute("aria-disabled", "true");
  if (oldCopy) expect(oldCopy).toBeDisabled();
  const firstCalls = calls.length;
  fireEvent.click(prepare);
  if (oldReview) fireEvent.click(oldReview);
  expect(calls).toHaveLength(firstCalls);

  const refresh = screen.getByRole("button", {
    name: "Refresh application context",
  });
  fireEvent.click(refresh);
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Application context is unavailable",
  );
  expect(prepare).toHaveAttribute("aria-disabled", "true");
  fireEvent.click(refresh);
  await screen.findByText("Application context refreshed.");
  expect(refreshCatalog).toHaveBeenCalledTimes(2);
  expect(calls).toHaveLength(firstCalls);
  if (oldReview) expect(oldReview).toHaveAttribute("aria-disabled", "true");
  if (oldCopy) fireEvent.click(oldCopy);
  fireEvent.click(prepare);
  await screen.findByLabelText("Scenario copy review");
  expect(screen.getByRole("checkbox")).not.toBeChecked();

  const preparations = calls.filter(
    ({ path, body }) =>
      path === "/api/source-action" &&
      body.program.function === "facts.slice.copy.prepare",
  );
  expect(preparations).toHaveLength(2);
  expect(preparations[1].body.program.arguments.expectedDataRevision).toBe(2);
  expect(preparations[1].body.idempotencyKey).not.toBe(
    preparations[0].body.idempotencyKey,
  );
  expect(calls.at(-1)?.body.program.arguments).toEqual({
    batchId: updatedBatchId,
  });
  fireEvent.click(screen.getByRole("checkbox"));
  fireEvent.click(
    screen.getByRole("button", { name: "Publish scenario copy" }),
  );
  await screen.findByText(/committed revision 10/);
  expect(calls.at(-1)?.body.program.arguments).toEqual({
    batchId: updatedBatchId,
    previewToken: "updated-preview",
  });
});

it.each(["status", "retry"] as const)(
  "requires refresh when %s recovers a preparation whose preview is now stale",
  async (recovery) => {
    let prepares = 0;
    const calls = install((name) => {
      if (name === "facts.slice.copy.prepare" && ++prepares === 1)
        throw new TypeError("preparation response lost");
      if (name === "facts.slice.copy.status.read" && recovery === "retry")
        return new Response(
          JSON.stringify({ code: "SCENARIO_COPY_STATUS_UNAVAILABLE" }),
          { status: 400 },
        );
      if (name === "facts.source.preview")
        return new Response(
          JSON.stringify({ code: "STALE_SOURCE_BATCH_REVISION" }),
          { status: 400 },
        );
    });
    const refreshCatalog = vi.fn(async () => catalog);
    render(
      <ScenarioPromotion
        app={app}
        catalog={catalog}
        dimensions={dimensions}
        onRefreshCatalog={refreshCatalog}
      />,
    );
    choose();
    fireEvent.click(
      screen.getByRole("button", { name: "Prepare copy review" }),
    );
    await screen.findByText("preparation response lost");
    fireEvent.click(
      screen.getByRole("button", { name: "Check original preparation status" }),
    );
    if (recovery === "retry")
      fireEvent.click(
        await screen.findByRole("button", {
          name: "Retry original preparation",
        }),
      );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Refresh the application context before preparing a new copy",
    );
    expect(screen.queryByLabelText("Scenario copy reconciliation")).toBeNull();
    expect(screen.getByLabelText("Prepared scenario copy")).toHaveTextContent(
      "Copy status ready",
    );
    expect(
      screen.getByRole("button", { name: "Refresh application context" }),
    ).toBeVisible();
    expect(calls.at(-1)?.body.program.arguments).toEqual({ batchId });
    expect(
      calls.filter(({ path }) => path === "/api/operation-admission"),
    ).toHaveLength(1);
    expect(refreshCatalog).not.toHaveBeenCalled();
  },
);

it("keeps the original packet if a retry after a lost acknowledgement is refused as stale", async () => {
  let sends = 0;
  const calls = install((name) => {
    if (name === "application.operation.receipt.read")
      return new Response(
        JSON.stringify({ code: "OPERATION_RECEIPT_NOT_FOUND" }),
        { status: 400 },
      );
    if (name === "facts.source.publish") {
      if (++sends === 1) throw new TypeError("publication response lost");
      return new Response(
        JSON.stringify({ code: "STALE_SOURCE_BATCH_REVISION" }),
        { status: 400 },
      );
    }
  });
  const refreshCatalog = vi.fn(async () => catalog);
  render(
    <ScenarioPromotion
      app={app}
      catalog={catalog}
      dimensions={dimensions}
      onRefreshCatalog={refreshCatalog}
    />,
  );
  await review();
  fireEvent.click(
    screen.getByRole("button", { name: "Publish scenario copy" }),
  );
  await screen.findByText("publication response lost");
  fireEvent.click(
    screen.getByRole("button", { name: "Check original publication status" }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Retry original publication" }),
  );
  await screen.findByText(
    /Check the original outcome before starting another copy/,
  );
  expect(
    screen.queryByRole("button", { name: "Refresh application context" }),
  ).toBeNull();
  expect(screen.queryByRole("button", { name: "Start a new copy" })).toBeNull();
  expect(
    screen.getByRole("button", { name: "Check original publication status" }),
  ).toBeVisible();
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  const publications = calls.filter(
    ({ path, body }) =>
      path === "/api/source-action" &&
      body.program.function === "facts.source.publish",
  );
  expect(publications).toHaveLength(2);
  expect(publications[1]).toEqual(publications[0]);
  expect(refreshCatalog).not.toHaveBeenCalled();
});

it("ignores a late preview denial after the same subject's access context changes", async () => {
  let finish: ((value: Response) => void) | undefined;
  const calls = install((name) =>
    name === "facts.source.preview"
      ? new Promise<Response>((resolve) => {
          finish = resolve;
        })
      : undefined,
  );
  const { rerender } = render(
    <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
  );
  choose();
  fireEvent.click(screen.getByRole("button", { name: "Prepare copy review" }));
  await waitFor(() => expect(finish).toBeDefined());
  rerender(
    <ScenarioPromotion
      app={app}
      catalog={{
        ...catalog,
        revisions: { ...catalog.revisions, security: 1 },
      }}
      dimensions={dimensions}
    />,
  );
  await act(async () =>
    finish!(
      new Response(JSON.stringify({ code: "DIMENSIONAL_SCOPE_DENIED" }), {
        status: 403,
      }),
    ),
  );
  expect(screen.queryByRole("alert")).toBeNull();
  expect(screen.queryByLabelText("Scenario copy review")).toBeNull();
  expect(unsavedWorkSnapshot()).toHaveLength(1);
  expect(
    calls.filter(({ path }) => path === "/api/source-action"),
  ).toHaveLength(1);
});

it("ignores a late preview after unmount and a new application", async () => {
  let finish: ((value: Response) => void) | undefined;
  install((name) =>
    name === "facts.source.preview"
      ? new Promise<Response>((resolve) => {
          finish = resolve;
        })
      : undefined,
  );
  const first = render(
    <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
  );
  choose();
  fireEvent.click(screen.getByRole("button", { name: "Prepare copy review" }));
  await waitFor(() => expect(finish).toBeDefined());
  first.unmount();
  render(
    <ScenarioPromotion
      app={{ ...app, applicationId: "other" }}
      catalog={catalog}
      dimensions={dimensions}
    />,
  );
  await act(async () => finish!(response(preview)));
  expect(
    screen.queryByLabelText("Scenario copy review"),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByLabelText("Prepared scenario copy"),
  ).not.toBeInTheDocument();
});

it("recovers a lost preparation by admission identity and opens the same review only once", async () => {
  const calls = install((name) => {
    if (name === "facts.slice.copy.prepare")
      throw new TypeError("preparation response lost");
  });
  render(
    <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
  );
  choose();
  fireEvent.click(screen.getByRole("button", { name: "Prepare copy review" }));
  await screen.findByText("preparation response lost");
  expect(
    screen.queryByRole("button", { name: "Retry original preparation" }),
  ).toBeNull();
  fireEvent.click(
    screen.getByRole("button", { name: "Check original preparation status" }),
  );
  await screen.findByLabelText("Scenario copy review");
  const prepare = calls.filter(({ path }) => path === "/api/source-action");
  expect(prepare).toHaveLength(1);
  expect(
    calls.filter(({ path }) => path === "/api/operation-admission"),
  ).toHaveLength(1);
  expect(
    calls
      .filter(({ path }) => path === "/api/read")
      .map(({ body }) => body.program),
  ).toEqual([
    {
      languageVersion: 2,
      function: "facts.slice.copy.status.read",
      arguments: { operationId: prepare[0].body.idempotencyKey },
    },
  ]);
  expect(calls.filter(({ path }) => path === "/api/source-load")).toHaveLength(
    1,
  );
  expect(
    screen.getByRole("button", { name: "Publish scenario copy" }),
  ).toHaveAttribute("aria-disabled", "true");
});

it.each(["cancelled", "denied", "access changed"])(
  "handles the %s outcome of the original preparation without starting a new operation",
  async (outcome) => {
    const calls = install((name) => {
      if (name === "facts.slice.copy.prepare")
        throw new TypeError("preparation response lost");
      if (name === "facts.slice.copy.status.read")
        return outcome === "denied"
          ? new Response(JSON.stringify({ code: "ACCESS_DENIED" }), {
              status: 403,
            })
          : outcome === "access changed"
            ? Response.json(
                { code: "CUBE_READ_AUTHORIZATION_STALE" },
                { status: 409 },
              )
            : response({ ...prepared, status: "cancelled" });
    });
    render(
      <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
    );
    choose();
    fireEvent.click(
      screen.getByRole("button", { name: "Prepare copy review" }),
    );
    await screen.findByText("preparation response lost");
    fireEvent.click(
      screen.getByRole("button", { name: "Check original preparation status" }),
    );
    await screen.findByText(
      outcome === "denied"
        ? /This copy step is unavailable under your current access/
        : outcome === "access changed"
          ? /Access changed during this copy step/
          : /Copy status cancelled/,
    );
    expect(
      screen.queryByRole("button", { name: "Retry original preparation" }),
    ).toBeNull();
    expect(
      calls.filter(({ path }) => path === "/api/source-action"),
    ).toHaveLength(1);
    expect(
      calls.filter(({ path }) => path === "/api/source-load"),
    ).toHaveLength(0);
    expect(unsavedWorkSnapshot()).toHaveLength(outcome === "cancelled" ? 0 : 1);
  },
);

it.each(["ready", "published", "denied"])(
  "a late old prepare %s response cannot overwrite or release a remounted owner's unknown publication",
  async (lateOutcome) => {
    let finishOld!: (value: Response) => void;
    let prepares = 0;
    let publications = 0;
    const calls = install((name) => {
      if (name === "facts.slice.copy.prepare" && ++prepares === 1)
        return new Promise<Response>((resolve) => {
          finishOld = resolve;
        });
      if (name === "facts.source.publish" && ++publications === 1)
        throw new TypeError("new publication response lost");
      if (name === "facts.slice.copy.status.read")
        return new Response(
          JSON.stringify({ code: "SCENARIO_COPY_STATUS_UNAVAILABLE" }),
          { status: 400 },
        );
      return undefined;
    });
    const first = render(
      <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
    );
    choose();
    fireEvent.click(
      screen.getByRole("button", { name: "Prepare copy review" }),
    );
    await waitFor(() => expect(finishOld).toBeDefined());
    first.unmount();
    const second = render(
      <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
    );
    fireEvent.click(screen.getByText("Copy scenario facts"));
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Check original preparation status",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Retry original preparation" }),
    );
    await screen.findByLabelText("Scenario copy review");
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(
      screen.getByRole("button", { name: "Publish scenario copy" }),
    );
    await screen.findByText("new publication response lost");
    await act(async () =>
      finishOld(
        lateOutcome === "denied"
          ? new Response(JSON.stringify({ error: "old preparation denied" }), {
              status: 403,
            })
          : response({ ...prepared, status: lateOutcome }),
      ),
    );
    expect(unsavedWorkSnapshot()).toHaveLength(1);
    second.unmount();
    render(
      <ScenarioPromotion app={app} catalog={catalog} dimensions={dimensions} />,
    );
    fireEvent.click(screen.getByText("Copy scenario facts"));
    await screen.findByLabelText("Scenario copy reconciliation");
    expect(screen.getByRole("status")).toHaveTextContent(
      "publication outcome is uncertain",
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Check original publication status" }),
    );
    await screen.findByText(/committed revision 9/);
    expect(unsavedWorkSnapshot()).toHaveLength(0);
    const effects = calls
      .filter((call) => call.path === "/api/source-action")
      .map((call) => call.body);
    expect(effects.map((body) => body.program.function)).toEqual([
      "facts.slice.copy.prepare",
      "facts.slice.copy.prepare",
      "facts.source.publish",
    ]);
    expect(effects[1]).toEqual(effects[0]);
    expect(calls.filter((call) => call.path === "/api/read")).toHaveLength(2);
    expect(
      calls.filter((call) => call.path === "/api/operation-admission"),
    ).toHaveLength(2);
  },
);
