import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import type { ComponentProps } from "react";
import { afterEach, expect, it, vi } from "vitest";
import { ModelMeaning, workedCoordinateRows } from "./ModelMeaning";
import { operationAdmissionResponse } from "./test-setup";
import type { ApplicationCatalog } from "./types";
import { setDraftIdentity, unsavedWorkSnapshot } from "./unsaved-work";
import { WorkedCalendarPeriod } from "./WorkedCalendarPeriod";

afterEach(() => vi.unstubAllGlobals());
const app = {
  workspaceId: "w",
  applicationId: "a",
  name: "Capacity",
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
  detailed_description: `Accepted ${axis} meaning`,
}));
const catalog: ApplicationCatalog = {
  applicationAccess: {
    role: "Reader",
    workspaceAdministrator: false,
    issuer: "https://issuer.example",
    subjectId: "designer",
  },
  enabledCapabilities: [],
  revisions: {
    metadata: 8,
    data: 1,
    policy: 0,
    security: 0,
    commit: 8,
    schemaEpoch: 2,
  },
  functions: {
    "metadata.authoring.context": {},
    "metadata.member.resolve": {},
    "facts.cube.resolved.read": {
      canonicalViewRead: "openepm-cube-view-read-v1",
    },
  },
};
const response = (result: unknown) => new Response(JSON.stringify({ result }));
function authorizedGrain(
  context = catalog,
  cubeGrainAvailable = true,
  axes = dimensions,
) {
  return response({
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    metadataRevision: context.revisions.metadata,
    policyRevision: context.revisions.policy,
    securityRevision: context.revisions.security,
    schemaEpoch: context.revisions.schemaEpoch,
    authority: {
      issuer: context.applicationAccess.issuer,
      subjectId: context.applicationAccess.subjectId,
    },
    references: {
      metadata: {
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
        metadataRevision: context.revisions.metadata,
        authorizationScopeDigest: "a".repeat(64),
        cubeGrainAvailable,
        dimensions: axes.map((dimension) => ({
          dimensionId: dimension.dimension_id,
          name: dimension.name,
          referenceMode: "symbolic",
        })),
      },
    },
  });
}
const coordinate = Object.fromEntries(
  dimensions.map((dimension) => [
    dimension.dimension_id,
    dimension.dimension_id + "-member",
  ]),
);
const evidence = (present = true) => ({
  format: "openepm-cube-view-read-v1",
  complete: true,
  dataSource: { kind: "raw", resultKey: null },
  readPolicy: { semantics: "stored" },
  snapshot: {
    metadataRevision: 8,
    dataRevision: 1,
    commitRevision: 8,
    policyRevision: 0,
    securityRevision: 0,
  },
  presentation: { rowCount: 1 },
  rows: [
    {
      members: coordinate,
      values: {
        raw: [
          {
            present,
            value: present ? "0.00000000" : null,
            unit: present ? "amount" : null,
            origin: "input",
            currentness: "current",
            resultStateToken: null,
          },
        ],
      },
    },
  ],
});
async function openPanelAndPopulate() {
  fireEvent.click(screen.getByText("Model meaning and one worked coordinate"));
  await screen.findByLabelText("Example Account");
  for (const dimension of dimensions)
    fireEvent.change(
      screen.getByLabelText(`Example ${dimension.dimension_id}`),
      { target: { value: dimension.dimension_id + "-member" } },
    );
}
it("reads a complete explicit eight-axis example and preserves zero versus absence", async () => {
  const calls: any[] = [];
  let present = true;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_path, init) => {
      const value = JSON.parse(init.body);
      calls.push(value);
      if (value.program.function === "metadata.authoring.context")
        return authorizedGrain();
      if (value.program.function === "metadata.member.resolve")
        return response({
          member_id: value.program.arguments.reference,
          dimension_id: value.program.arguments.dimension,
          status: "Active",
          detailed_description: "Hours per resource",
          numeric_value_kind: "amount",
        });
      return response(evidence(present));
    }),
  );
  render(
    <ModelMeaning
      app={app}
      catalog={catalog}
      dimensions={[
        {
          dimension_id: "QuoteCurrency",
          name: "Quote currencies",
          model_role: "Currency",
          status: "Active",
          detailed_description: "Units for conversion policy",
        },
        ...dimensions,
        {
          dimension_id: "OldAllocation",
          name: "Old allocation",
          model_role: "Custom",
          status: "Inactive",
        },
      ]}
      metadataRevision={8}
    />,
  );
  expect(screen.getByText("Accepted Value meaning")).toBeInTheDocument();
  expect(screen.getByText("Units for conversion policy")).toBeInTheDocument();
  expect(calls).toHaveLength(0);
  await openPanelAndPopulate();
  expect(screen.getByText(/The current grain is/)).toHaveTextContent(
    "The current grain is Account × Entity × Year × Period × View × Value × Scenario × DataType.",
  );
  expect(screen.queryByLabelText("Example QuoteCurrency")).toBeNull();
  expect(screen.queryByLabelText("Example OldAllocation")).toBeNull();
  fireEvent.click(
    screen.getByRole("button", { name: "Inspect worked coordinate" }),
  );
  expect(
    await screen.findByText("Stored numeric value: 0.00000000"),
  ).toBeInTheDocument();
  expect(
    calls
      .filter((call) => call.program.function === "metadata.member.resolve")
      .map((call) => call.program.arguments.dimension),
  ).toEqual(dimensions.map((dimension) => dimension.dimension_id));
  const read = calls.at(-1).program.arguments;
  expect(
    read.view.selection.dimensions.map((item: any) => item.dimensionId),
  ).toEqual(dimensions.map((dimension) => dimension.dimension_id));
  expect(
    read.view.selection.dimensions.every(
      (item: any) => item.include.kind === "member" && item.exclude === null,
    ),
  ).toBe(true);
  expect(read.readPolicy).toEqual({ semantics: "stored" });
  expect(read.view.dataSource).toEqual({ kind: "raw", resultKey: null });
  present = false;
  fireEvent.click(
    screen.getByRole("button", { name: "Inspect worked coordinate" }),
  );
  expect(
    await screen.findByText(/No stored value is visible/),
  ).toBeInTheDocument();
  expect(calls.every((call) => !call.confirmed && !call.idempotencyKey)).toBe(
    true,
  );
});

it("browses a paged native axis and applies the exact member behind a duplicate label", async () => {
  const browserCatalog = {
    ...catalog,
    functions: { ...catalog.functions, "metadata.member.select": {} },
  };
  const reads: Array<{ function: string; arguments: Record<string, unknown> }> =
    [];
  const scope = {
    kind: "scope",
    scope: "dimension",
    dimensionId: "Account",
    hierarchyId: null,
    name: "Account",
    businessCoordinate: false,
    supportedOperations: ["top", "all"],
  };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      expect(path).toBe("/api/read");
      const body = JSON.parse(init.body);
      expect(body).not.toHaveProperty("idempotencyKey");
      reads.push(body.program);
      const { function: name, arguments: args } = body.program;
      if (name === "metadata.authoring.context") return authorizedGrain();
      if (name === "metadata.member.resolve")
        return response({
          member_id: args.reference,
          dimension_id: args.dimension,
          status: "Active",
        });
      if (name === "facts.cube.resolved.read") return response(evidence(true));
      expect(name).toBe("metadata.member.select");
      const top = args.expression?.operation === "top";
      const next = !top && !args.cursor;
      return response({
        dimensionId: "Account",
        metadataRevision: 8,
        resultKind: top ? "scope" : "unique_member",
        selectionContextToken: "a".repeat(64),
        scope,
        rows: top
          ? []
          : [
              {
                memberId: next ? "Other-account" : "Account-member",
                name: "Shared label",
                status: "Active",
              },
            ],
        nextCursor: next ? "current-page-two" : null,
        hasMore: next,
      });
    }),
  );
  render(
    <ModelMeaning
      app={app}
      catalog={browserCatalog}
      dimensions={dimensions}
      metadataRevision={8}
    />,
  );
  await openPanelAndPopulate();
  const input = screen.getByLabelText("Example Account");
  fireEvent.change(input, { target: { value: "" } });
  expect(reads.map((item) => item.function)).toEqual([
    "metadata.authoring.context",
  ]);
  const inspect = screen.getByRole("button", {
    name: "Inspect worked coordinate",
  });
  expect(inspect).toBeDisabled();
  const opener = screen.getByRole("button", { name: "Choose Account member" });
  opener.focus();
  fireEvent.click(opener);
  const dialog = within(screen.getByRole("dialog"));
  fireEvent.click(
    await dialog.findByRole("button", { name: "All active members" }),
  );
  fireEvent.click(await dialog.findByRole("button", { name: "More results" }));
  fireEvent.click(
    await dialog.findByRole("button", {
      name: "Choose Shared label (Account-member)",
    }),
  );
  fireEvent.click(dialog.getByRole("button", { name: "Add selected member" }));
  fireEvent.click(dialog.getByRole("button", { name: "Apply selection" }));
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(opener).toHaveFocus();
  expect(input).toHaveValue("Account-member");
  expect(inspect).toBeEnabled();
  expect(reads.at(-1)?.arguments).toEqual({ cursor: "current-page-two" });

  fireEvent.click(opener);
  fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(input).toHaveValue("Account-member");
  expect(opener).toHaveFocus();

  fireEvent.click(inspect);
  expect(
    await screen.findByText("Stored numeric value: 0.00000000"),
  ).toBeVisible();
  expect(
    reads.filter((item) => item.function === "metadata.member.resolve")[0]
      ?.arguments,
  ).toEqual({ dimension: "Account", reference: "Account-member" });
});

it("closes and aborts the member picker when the active catalogue loses its capability", async () => {
  const pending: Array<AbortSignal | undefined> = [];
  const fetch = vi.fn((_path: string, init: RequestInit) => {
    const { program } = JSON.parse(init.body as string);
    if (program.function === "metadata.authoring.context")
      return Promise.resolve(authorizedGrain());
    expect(program.function).toBe("metadata.member.select");
    pending.push(init.signal || undefined);
    return new Promise<Response>(() => {});
  });
  vi.stubGlobal("fetch", fetch);
  const props = { app, dimensions, metadataRevision: 8 };
  const { rerender } = render(
    <ModelMeaning
      {...props}
      catalog={{
        ...catalog,
        functions: { ...catalog.functions, "metadata.member.select": {} },
      }}
    />,
  );
  await openPanelAndPopulate();
  fireEvent.click(
    screen.getByRole("button", { name: "Choose Account member" }),
  );
  expect(screen.getByRole("dialog")).toBeVisible();
  await waitFor(() => expect(pending).toHaveLength(1));
  rerender(<ModelMeaning {...props} catalog={catalog} />);
  expect(screen.queryByRole("dialog")).toBeNull();
  expect(pending[0]?.aborted).toBe(true);
  expect(await screen.findByLabelText("Example Account")).toHaveValue("");
  expect(
    screen.queryByRole("button", { name: "Choose Account member" }),
  ).toBeNull();
  expect(
    screen.getByRole("button", { name: "Inspect worked coordinate" }),
  ).toBeDisabled();
});

it("shows a modeled unit only after an exact current attribute read", async () => {
  const calls: Array<{ function: string; arguments: Record<string, unknown> }> =
    [];
  const definition = {
    attribute_id: "billing-uom",
    display_name: "Billing unit",
    value_type: "Text",
    status: "Active",
    state_token: "a".repeat(64),
    validation_constraints: { allowedValues: ["hours", "cases"] },
  };
  let revision = 8;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_path, init) => {
      const { program } = JSON.parse(init.body);
      const args = program.arguments;
      calls.push(program);
      switch (program.function) {
        case "metadata.authoring.context":
          return authorizedGrain();
        case "metadata.member.resolve":
          return response({
            member_id: args.reference,
            dimension_id: args.dimension,
            status: "Active",
            numeric_value_kind: args.dimension === "Account" ? "ratio" : null,
          });
        case "metadata.attribute-definition.list":
          return response({
            scope: "Member",
            dimensionId: "Account",
            rows: [definition],
            hasMore: false,
            nextAfterAttributeId: null,
            metadataRevision: 8,
          });
        case "metadata.attribute-value.read":
          return response({
            scope: "Member",
            dimensionId: "Account",
            objectId: coordinate.Account,
            definition,
            present: true,
            value: "cases",
            metadataRevision: revision,
          });
        default:
          return response(evidence());
      }
    }),
  );
  render(
    <ModelMeaning
      app={app}
      dimensions={dimensions}
      metadataRevision={8}
      catalog={{
        ...catalog,
        functions: {
          ...catalog.functions,
          "metadata.attribute-definition.list": {},
          "metadata.attribute-value.read": {},
        },
      }}
    />,
  );
  await openPanelAndPopulate();
  fireEvent.click(
    screen.getByRole("button", { name: "Inspect worked coordinate" }),
  );
  const axis = await screen.findByLabelText("Attribute dimension");
  expect(
    calls.filter((program) =>
      program.function.startsWith("metadata.attribute-"),
    ),
  ).toHaveLength(0);
  fireEvent.change(axis, { target: { value: "Account" } });
  await screen.findByRole("option", { name: "Billing unit (billing-uom)" });
  const attribute = screen.getByLabelText("Member attribute");
  fireEvent.change(attribute, { target: { value: "billing-uom" } });
  expect(await screen.findByText("cases")).toBeVisible();
  expect(screen.getByText("Text value")).toBeVisible();
  expect(screen.getByText(/arithmetic kind ratio/)).toBeVisible();
  expect(calls.at(-1)).toMatchObject({
    function: "metadata.attribute-value.read",
    arguments: {
      scope: "Member",
      dimensionId: "Account",
      objectId: coordinate.Account,
      attributeId: "billing-uom",
    },
  });

  revision = 9;
  fireEvent.change(attribute, { target: { value: "" } });
  fireEvent.change(attribute, { target: { value: "billing-uom" } });
  expect(
    await screen.findByText(/attribute evidence could not be verified/),
  ).toBeVisible();
  expect(screen.queryByText("cases")).toBeNull();
});

it("refreshes worked-coordinate context when a member directory read races an access change", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      expect(path).toBe("/api/read");
      const { program } = JSON.parse(init.body);
      switch (program.function) {
        case "metadata.authoring.context":
          return authorizedGrain();
        case "metadata.member.resolve":
          return Response.json(
            { code: "METADATA_DIRECTORY_READ_AUTHORIZATION_STALE" },
            { status: 409 },
          );
        default:
          throw new Error(`Unexpected read: ${program.function}`);
      }
    }),
  );
  render(
    <ModelMeaning
      app={app}
      dimensions={dimensions}
      metadataRevision={8}
      catalog={catalog}
      onRefreshCatalog={async () => catalog}
    />,
  );
  await openPanelAndPopulate();
  const button = screen.getByRole("button", {
    name: "Inspect worked coordinate",
  });
  button.focus();
  fireEvent.click(button);
  expect(await screen.findByRole("alert")).toHaveTextContent("context changed");
  expect(screen.queryByLabelText("Example Account")).toBeNull();
  expect(
    await screen.findByRole("button", {
      name: "Refresh application context",
    }),
  ).toBeVisible();
});

it.each([
  [409, "METADATA_ATTRIBUTE_READ_AUTHORIZATION_STALE", "context changed"],
  [409, "METADATA_DIRECTORY_CURSOR_STALE", "context changed"],
  [400, "STALE_METADATA_REVISION", "context changed"],
  [
    403,
    "APPLICATION_GRANT_REQUIRED",
    "Access to the worked coordinate was refused",
  ],
] as const)(
  "settles a worked-coordinate read after %s %s through a fresh application context",
  async (status, code, message) => {
    const unit = {
      attribute_id: "worked-unit",
      display_name: "Work unit",
      value_type: "Text",
      status: "Active",
      state_token: "a".repeat(64),
    };
    const functions = {
      ...catalog.functions,
      "metadata.attribute-definition.list": {},
      "metadata.attribute-value.read": {},
    };
    const currentCatalog = { ...catalog, functions };
    const refresh =
      vi.fn<(signal?: AbortSignal) => Promise<ApplicationCatalog>>();
    refresh.mockRejectedValueOnce(new Error("Temporary catalogue failure"));
    let finishRefresh = () => {};
    refresh.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finishRefresh = () => resolve(currentCatalog);
        }),
    );
    const reads: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path, init) => {
        expect(path).toBe("/api/read");
        const { applicationId, workspaceId, program } = JSON.parse(init.body);
        expect({ applicationId, workspaceId }).toEqual({
          applicationId: "a",
          workspaceId: "w",
        });
        const args = program.arguments;
        reads.push(program.function);
        switch (program.function) {
          case "metadata.authoring.context":
            return authorizedGrain();
          case "metadata.member.resolve":
            return response({
              member_id: args.reference,
              dimension_id: args.dimension,
              status: "Active",
            });
          case "facts.cube.resolved.read":
            return response(evidence());
          case "metadata.attribute-definition.list":
            if (args.afterAttributeId)
              return Response.json({ code }, { status });
            return response({
              scope: "Member",
              dimensionId: "Account",
              rows: [unit],
              hasMore: true,
              nextAfterAttributeId: unit.attribute_id,
              metadataRevision: 8,
            });
          case "metadata.attribute-value.read":
            return response({
              scope: "Member",
              dimensionId: "Account",
              objectId: coordinate.Account,
              definition: unit,
              present: true,
              value: "hours",
              metadataRevision: 8,
            });
          default:
            throw new Error(`Unexpected read: ${program.function}`);
        }
      }),
    );
    render(
      <ModelMeaning
        app={app}
        dimensions={dimensions}
        metadataRevision={8}
        catalog={currentCatalog}
        onRefreshCatalog={refresh}
      />,
    );
    await openPanelAndPopulate();
    fireEvent.click(
      screen.getByRole("button", { name: "Inspect worked coordinate" }),
    );
    fireEvent.change(await screen.findByLabelText("Attribute dimension"), {
      target: { value: "Account" },
    });
    fireEvent.change(await screen.findByLabelText("Member attribute"), {
      target: { value: unit.attribute_id },
    });
    expect(
      await screen.findByText("hours", { selector: "output" }),
    ).toBeVisible();
    const oldPage = screen.getByRole("button", {
      name: "Load more attributes",
    });
    oldPage.focus();
    fireEvent.click(oldPage);
    expect(await screen.findByRole("alert")).toHaveTextContent(message);
    expect(
      screen.queryByRole("region", { name: "Worked coordinate evidence" }),
    ).toBeNull();
    expect(screen.queryByLabelText("Example Account")).toBeNull();
    const heading = screen.getByText("Model meaning and one worked coordinate");
    expect(heading).toHaveFocus();
    expect(refresh).not.toHaveBeenCalled();

    const retry = screen.getByRole("button", {
      name: "Refresh application context",
    });
    retry.focus();
    fireEvent.click(retry);
    expect(
      await screen.findByText(
        "The application context could not be refreshed. Try again.",
      ),
    ).toBeVisible();
    expect(retry).toHaveFocus();
    fireEvent.click(retry);
    fireEvent.click(retry);
    expect(refresh).toHaveBeenCalledTimes(2);
    expect(screen.getByRole("status")).toHaveTextContent(
      "Refreshing the application context",
    );
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.queryByLabelText("Example Account")).toBeNull();
    await act(async () => finishRefresh());
    expect(await screen.findByLabelText("Example Account")).toHaveValue("");
    expect(
      screen.getByRole("button", { name: "Inspect worked coordinate" }),
    ).toBeDisabled();
    expect(
      screen.queryByRole("region", { name: "Worked coordinate evidence" }),
    ).toBeNull();
    expect(heading).toHaveFocus();
    expect(
      reads.filter((read) => read === "metadata.authoring.context"),
    ).toHaveLength(2);
    expect(
      reads.filter((read) => read === "facts.cube.resolved.read"),
    ).toHaveLength(1);
    expect(
      reads.filter((read) => read === "metadata.attribute-value.read"),
    ).toHaveLength(1);
  },
);

it("reads the exact declared fiscal period without interpreting member labels as dates", async () => {
  const axes = dimensions.map((axis) =>
    axis.model_role === "Year"
      ? { ...axis, dimension_id: "fiscal-cycle", name: "Fiscal cycle" }
      : axis.model_role === "Period"
        ? { ...axis, dimension_id: "work-window", name: "Work window" }
        : axis,
  );
  const members = Object.fromEntries(
    axes.map((axis) => [
      axis.dimension_id,
      axis.model_role === "Year"
        ? "FY26"
        : axis.model_role === "Period"
          ? "P04"
          : coordinate[axis.dimension_id],
    ]),
  );
  const context = {
    ...catalog,
    functions: { ...catalog.functions, "metadata.calendar.period.read": {} },
  };
  const calendar = vi.fn();
  const declared = {
    yearId: "FY26",
    periodId: "P04",
    defined: true,
    ordinal: 4,
    startsOn: "2025-04-01",
    endsBefore: "2025-05-01",
    changeId: "a".repeat(32),
    metadataRevision: 8,
    commitRevision: 8,
  };
  let period: unknown = declared;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_path, init) => {
      const { program } = JSON.parse(init.body);
      if (program.function === "metadata.authoring.context")
        return authorizedGrain(context, true, axes);
      if (program.function === "metadata.member.resolve")
        return response({
          member_id: program.arguments.reference,
          dimension_id: program.arguments.dimension,
          status: "Active",
        });
      if (program.function === "metadata.calendar.period.read") {
        calendar(program.arguments);
        return response(period);
      }
      const value = evidence();
      return response({ ...value, rows: [{ ...value.rows[0], members }] });
    }),
  );
  render(
    <ModelMeaning
      app={app}
      catalog={context}
      dimensions={axes}
      metadataRevision={8}
    />,
  );
  fireEvent.click(screen.getByText("Model meaning and one worked coordinate"));
  await screen.findByLabelText("Example fiscal-cycle");
  for (const axis of axes)
    fireEvent.change(screen.getByLabelText(`Example ${axis.dimension_id}`), {
      target: { value: members[axis.dimension_id] },
    });
  fireEvent.click(
    screen.getByRole("button", { name: "Inspect worked coordinate" }),
  );
  const read = await screen.findByRole("button", {
    name: "Read declared calendar period",
  });
  expect(calendar).not.toHaveBeenCalled();
  read.focus();
  fireEvent.click(read);
  expect(await screen.findByText("2025-04-01")).toHaveAttribute(
    "datetime",
    "2025-04-01",
  );
  expect(screen.getByText("2025-05-01")).toHaveAttribute(
    "datetime",
    "2025-05-01",
  );
  expect(read).toHaveFocus();
  expect(
    screen.queryByRole("button", { name: "Edit calendar period" }),
  ).toBeNull();
  expect(calendar).toHaveBeenCalledWith({ yearId: "FY26", periodId: "P04" });
  for (const change of [
    { periodId: "P05" },
    { startsOn: "2025-02-29" },
    { metadataRevision: 9 },
    { commitRevision: 7 },
  ]) {
    period = { ...declared, ...change };
    fireEvent.click(read);
    expect(
      await screen.findByText(/calendar period could not be verified/),
    ).toBeVisible();
    expect(screen.queryByText("2025-04-01")).toBeNull();
  }
  period = {
    ...declared,
    defined: false,
    ordinal: null,
    startsOn: null,
    endsBefore: null,
    changeId: "",
  };
  fireEvent.click(read);
  expect(
    await screen.findByText(
      "No calendar interval is defined for this year and period.",
    ),
  ).toBeVisible();
  expect(screen.getByText("Stored numeric value: 0.00000000")).toBeVisible();
});

const periodRead = "metadata.calendar.period.read";
const periodSet = "metadata.calendar.period.set";
const calendarTarget = { yearId: coordinate.Year, periodId: coordinate.Period };
const adminCalendar: ApplicationCatalog = {
  ...catalog,
  applicationAccess: { ...catalog.applicationAccess, role: "Administrator" },
  functions: {
    ...catalog.functions,
    [periodRead]: {},
    [periodSet]: {},
    "application.operation.receipt.read": {},
  },
};
const currentCalendar = {
  ...calendarTarget,
  defined: true,
  ordinal: 4,
  startsOn: "2026-04-01",
  endsBefore: "2026-05-01",
  changeId: "c".repeat(32),
  metadataRevision: 8,
  commitRevision: 10,
};
const admittedId = `oa1_zz_${"a".repeat(32)}_${"A".repeat(43)}`;

function calendarFailure(status: number, code: string) {
  return new Response(JSON.stringify({ code }), { status });
}

it("defines an exact calendar period from the worked coordinate through signed review", async () => {
  const effect = vi.fn();
  const admission = vi.fn();
  const refresh = vi.fn(async () => adminCalendar);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      const body = JSON.parse(init.body);
      if (path === "/api/operation-admission") {
        admission(body);
        return operationAdmissionResponse();
      }
      if (path === "/api/metadata-action") {
        effect(body);
        const { ordinal, startsOn, endsBefore } = body.program.arguments;
        return new Response(
          JSON.stringify({
            languageVersion: 2,
            function: periodSet,
            result: {
              ...calendarTarget,
              ordinal,
              startsOn,
              endsBefore,
              operationId: admittedId,
              metadataRevision: 9,
              committedRevision: 11,
              changeId: "b".repeat(32),
              impactDigest: "e".repeat(64),
            },
          }),
        );
      }
      if (body.program.function === "metadata.authoring.context")
        return authorizedGrain(adminCalendar);
      if (body.program.function === "metadata.member.resolve")
        return response({
          member_id: body.program.arguments.reference,
          dimension_id: body.program.arguments.dimension,
          status: "Active",
        });
      if (body.program.function === periodRead)
        return response({
          ...currentCalendar,
          defined: false,
          ordinal: null,
          startsOn: null,
          endsBefore: null,
          changeId: "",
        });
      return response(evidence());
    }),
  );
  render(
    <ModelMeaning
      app={app}
      catalog={adminCalendar}
      dimensions={dimensions}
      metadataRevision={8}
      onRefreshCatalog={refresh}
    />,
  );
  await openPanelAndPopulate();
  fireEvent.click(
    screen.getByRole("button", { name: "Inspect worked coordinate" }),
  );
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Read declared calendar period",
    }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Define calendar period" }),
  );
  const ordinal = screen.getByLabelText("Period ordinal");
  expect(ordinal).toHaveFocus();
  expect(ordinal).toHaveValue(null);
  const review = screen.getByRole("button", { name: "Review calendar change" });
  fireEvent.change(ordinal, { target: { value: "4" } });
  fireEvent.change(screen.getByLabelText("First date included"), {
    target: { value: "2026-04-01" },
  });
  fireEvent.change(screen.getByLabelText("First date excluded"), {
    target: { value: "2026-03-31" },
  });
  expect(review).toBeDisabled();
  fireEvent.change(screen.getByLabelText("First date excluded"), {
    target: { value: "2026-05-01" },
  });
  fireEvent.click(review);
  expect(
    screen.getByRole("region", { name: "Reviewed calendar change" }),
  ).toHaveTextContent("through the day before 2026-05-01");
  fireEvent.change(ordinal, { target: { value: "5" } });
  expect(
    screen.queryByRole("button", { name: "Save reviewed calendar change" }),
  ).toBeNull();
  expect(admission).not.toHaveBeenCalled();
  expect(effect).not.toHaveBeenCalled();
  fireEvent.click(review);
  fireEvent.click(
    screen.getByRole("button", { name: "Save reviewed calendar change" }),
  );
  expect(await screen.findByText(/Calendar change recorded/)).toBeVisible();
  const expected = {
    workspaceId: "w",
    applicationId: "a",
    program: {
      languageVersion: 2,
      function: periodSet,
      arguments: {
        ...calendarTarget,
        ordinal: 5,
        startsOn: "2026-04-01",
        endsBefore: "2026-05-01",
        expectedMetadataRevision: 8,
        expectedChangeId: "",
      },
    },
  };
  expect(admission.mock.calls).toEqual([[expected]]);
  expect(effect.mock.calls).toEqual([
    [{ ...expected, confirmed: true, idempotencyKey: admittedId }],
  ]);
  await waitFor(() => expect(unsavedWorkSnapshot()).toEqual([]));
  expect(
    screen.queryByRole("region", { name: "Worked coordinate evidence" }),
  ).toBeNull();
  await act(async () => {
    fireEvent.click(
      screen.getByRole("button", { name: "Refresh application context" }),
    );
  });
  expect(refresh).toHaveBeenCalledOnce();
});

function calendarEditor(
  onRecorded: () => void,
  props: Partial<ComponentProps<typeof WorkedCalendarPeriod>> = {},
) {
  return (
    <WorkedCalendarPeriod
      scope={app}
      catalog={adminCalendar}
      context="metadata-8"
      contextBlocked={false}
      selection={calendarTarget}
      metadataRevision={8}
      onReadFailure={() => false}
      onRecorded={onRecorded}
      {...props}
    />
  );
}

it("recovers an ambiguous calendar commit after leaving the coordinate without re-admission", async () => {
  setDraftIdentity("calendar-designer");
  const effect = vi.fn();
  const admission = vi.fn();
  const receipt = vi.fn();
  const recorded = vi.fn();
  let receiptActor = "another-user";
  let replay = false;
  const events: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      const body = JSON.parse(init.body);
      if (path === "/api/operation-admission") {
        events.push("admission");
        admission(body);
        return operationAdmissionResponse();
      }
      if (path === "/api/metadata-action") {
        events.push("effect");
        effect(body);
        if (replay) return calendarFailure(400, "OPERATION_ADMISSION_EXPIRED");
        return new Response(
          JSON.stringify({
            languageVersion: 2,
            function: periodSet,
            result: {
              ...body.program.arguments,
              operationId: admittedId,
              metadataRevision: 9,
              periodId: "different-period",
              committedRevision: 11,
              changeId: "d".repeat(32),
              impactDigest: "e".repeat(64),
            },
          }),
        );
      }
      if (body.program.function === "application.operation.receipt.read") {
        events.push("receipt");
        receipt(body);
        if (receiptActor === "absent")
          return calendarFailure(400, "OPERATION_RECEIPT_NOT_FOUND");
        return response({
          operationId: admittedId,
          actorId: receiptActor,
          committedRevision: 11,
          committedAt: "2026-11-22T01:02:03+00:00",
          commandDigest: "f".repeat(64),
          outcome: {},
        });
      }
      return response(currentCalendar);
    }),
  );
  const first = render(calendarEditor(recorded));
  fireEvent.click(
    screen.getByRole("button", { name: "Read declared calendar period" }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Edit calendar period" }),
  );
  fireEvent.change(screen.getByLabelText("First date excluded"), {
    target: { value: "2026-04-29" },
  });
  expect(unsavedWorkSnapshot().map((item) => item.label)).toContain(
    "Calendar period draft",
  );
  first.unmount();

  const restored = render(calendarEditor(recorded, { selection: null }));
  expect(await screen.findByLabelText("First date excluded")).toHaveValue(
    "2026-04-29",
  );
  expect(
    screen.getByRole("button", { name: "Review calendar change" }),
  ).toBeDisabled();
  fireEvent.click(
    screen.getByRole("button", { name: "Read declared calendar period" }),
  );
  await waitFor(() =>
    expect(
      screen.getByRole("button", { name: "Review calendar change" }),
    ).toBeEnabled(),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Review calendar change" }),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Save reviewed calendar change" }),
  );
  expect(await screen.findByText(/reply did not confirm/)).toBeVisible();
  expect(recorded).not.toHaveBeenCalled();
  expect(effect.mock.calls[0][0].program.arguments.expectedChangeId).toBe(
    currentCalendar.changeId,
  );
  expect(unsavedWorkSnapshot().map((item) => item.label)).toEqual([
    "Calendar change with an unconfirmed outcome",
  ]);
  restored.unmount();

  const pending = render(calendarEditor(recorded, { selection: null }));
  const check = await screen.findByRole("button", {
    name: "Check original calendar receipt",
  });
  expect(
    screen.queryByRole("button", { name: "Retry original calendar request" }),
  ).toBeNull();
  fireEvent.click(check);
  expect(await screen.findByText(/receipt could not confirm/)).toBeVisible();
  const readerCatalog = {
    ...adminCalendar,
    functions: {
      ...catalog.functions,
      [periodRead]: {},
      "application.operation.receipt.read": {},
    },
  };
  pending.rerender(
    calendarEditor(recorded, { selection: null, catalog: readerCatalog }),
  );
  expect(
    screen.queryByRole("button", { name: "Check original calendar receipt" }),
  ).toBeNull();
  expect(screen.queryByText(/Year Year-member/)).toBeNull();
  pending.rerender(calendarEditor(recorded, { selection: null }));

  receiptActor = "absent";
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Check original calendar receipt",
    }),
  );
  replay = true;
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Retry original calendar request",
    }),
  );
  expect(await screen.findByText(/original admission expired/)).toBeVisible();
  expect(effect.mock.calls[0]).toEqual(effect.mock.calls[1]);
  receiptActor = "designer";
  fireEvent.click(
    screen.getByRole("button", { name: "Check original calendar receipt" }),
  );
  await waitFor(() => expect(recorded).toHaveBeenCalledOnce());
  expect(admission).toHaveBeenCalledOnce();
  expect(events).toEqual([
    "admission",
    "effect",
    "receipt",
    "receipt",
    "effect",
    "receipt",
  ]);
  expect(
    receipt.mock.calls.every(
      ([body]) => body.program.arguments.operationId === admittedId,
    ),
  ).toBe(true);
  expect(unsavedWorkSnapshot()).toEqual([]);
});

it("requires a fresh period read and renewed review after a stale calendar write", async () => {
  const recorded = vi.fn();
  const invalidate = vi.fn(() => true);
  const admissions: unknown[] = [];
  const packets: Array<{
    idempotencyKey: string;
    program: { arguments: Record<string, unknown> };
  }> = [];
  let current = currentCalendar;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (path, init) => {
      const body = JSON.parse(init.body);
      if (path === "/api/operation-admission") {
        admissions.push(body);
        return operationAdmissionResponse(admissions.length === 1 ? "a" : "b");
      }
      if (path === "/api/metadata-action") {
        packets.push(body);
        if (packets.length === 1)
          return calendarFailure(409, "STALE_CALENDAR_CHANGE_ID");
        const { ordinal, startsOn, endsBefore } = body.program.arguments;
        return new Response(
          JSON.stringify({
            languageVersion: 2,
            function: periodSet,
            result: {
              ...calendarTarget,
              ordinal,
              startsOn,
              endsBefore,
              operationId: body.idempotencyKey,
              metadataRevision: 10,
              committedRevision: 12,
              changeId: "e".repeat(32),
              impactDigest: "f".repeat(64),
            },
          }),
        );
      }
      return response(current);
    }),
  );
  const result = render(
    calendarEditor(recorded, { onReadFailure: invalidate }),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Read declared calendar period" }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Edit calendar period" }),
  );
  fireEvent.change(screen.getByLabelText("First date excluded"), {
    target: { value: "2026-04-28" },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Review calendar change" }),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Save reviewed calendar change" }),
  );
  expect(
    await screen.findByText(/Read the current period before reviewing/),
  ).toBeVisible();
  expect(invalidate).toHaveBeenCalledWith(
    expect.objectContaining({ code: "STALE_CALENDAR_CHANGE_ID" }),
  );
  expect(recorded).not.toHaveBeenCalled();
  expect(
    screen.queryByRole("button", { name: "Save reviewed calendar change" }),
  ).toBeNull();
  expect(screen.getByLabelText("First date excluded")).toHaveValue(
    "2026-04-28",
  );

  current = {
    ...current,
    endsBefore: "2026-04-30",
    changeId: "d".repeat(32),
    metadataRevision: 9,
    commitRevision: 11,
  };
  const refreshed = {
    ...adminCalendar,
    revisions: { ...adminCalendar.revisions, metadata: 9, commit: 11 },
  };
  result.rerender(
    calendarEditor(recorded, {
      catalog: refreshed,
      metadataRevision: 9,
      context: "metadata-9",
    }),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Read declared calendar period" }),
  );
  expect(await screen.findByText("2026-04-30")).toBeVisible();
  expect(
    screen.queryByRole("button", { name: "Save reviewed calendar change" }),
  ).toBeNull();
  expect(admissions).toHaveLength(1);
  fireEvent.click(
    screen.getByRole("button", { name: "Review calendar change" }),
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Save reviewed calendar change" }),
  );
  await waitFor(() => expect(recorded).toHaveBeenCalledOnce());
  expect(packets).toHaveLength(2);
  expect(packets[1].idempotencyKey).not.toBe(packets[0].idempotencyKey);
  expect(packets[1].program.arguments).toMatchObject({
    expectedMetadataRevision: 9,
    expectedChangeId: current.changeId,
    endsBefore: "2026-04-28",
  });
});

it("keeps verified attributes usable while loading later pages for the same coordinate", async () => {
  const first = {
    attribute_id: "cost-centre",
    display_name: "Cost centre",
    status: "Active",
    value_type: "Text",
    state_token: "a".repeat(64),
  };
  const unit = {
    ...first,
    attribute_id: "quantity-unit",
    display_name: "Quantity unit",
    state_token: "b".repeat(64),
  };
  const list = vi.fn();
  const pageToken = `1890000000.${"c".repeat(64)}`;
  let rejectContinuation = true;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_path, init) => {
      const { program } = JSON.parse(init.body);
      const args = program.arguments;
      if (program.function === "metadata.authoring.context")
        return authorizedGrain();
      if (program.function === "metadata.member.resolve")
        return response({
          dimension_id: args.dimension,
          member_id: args.reference,
          status: "Active",
        });
      if (program.function === "metadata.attribute-definition.list") {
        list(args);
        return response({
          scope: "Member",
          dimensionId: "Account",
          metadataRevision: 8,
          rows: args.afterAttributeId
            ? [rejectContinuation ? first : unit]
            : [first],
          hasMore: !args.afterAttributeId,
          nextAfterAttributeId: args.afterAttributeId
            ? null
            : first.attribute_id,
          nextPageToken: args.afterAttributeId ? null : pageToken,
        });
      }
      if (program.function === "metadata.attribute-value.read")
        return response({
          scope: "Member",
          dimensionId: "Account",
          objectId: coordinate.Account,
          definition: args.attributeId === first.attribute_id ? first : unit,
          metadataRevision: 8,
          present: true,
          value:
            args.attributeId === first.attribute_id ? "Operations" : "hours",
        });
      return response(evidence());
    }),
  );
  render(
    <ModelMeaning
      app={app}
      dimensions={dimensions}
      metadataRevision={8}
      catalog={{
        ...catalog,
        functions: {
          ...catalog.functions,
          "metadata.attribute-definition.list": {},
          "metadata.attribute-value.read": {},
        },
      }}
    />,
  );
  await openPanelAndPopulate();
  fireEvent.click(
    screen.getByRole("button", { name: "Inspect worked coordinate" }),
  );
  fireEvent.change(await screen.findByLabelText("Attribute dimension"), {
    target: { value: "Account" },
  });
  const load = await screen.findByRole("button", {
    name: "Load more attributes",
  });
  const select = screen.getByLabelText("Member attribute");
  fireEvent.change(select, { target: { value: first.attribute_id } });
  expect(await screen.findByText("Operations")).toBeVisible();
  expect(list).toHaveBeenCalledTimes(1);
  fireEvent.click(load);
  expect(
    await screen.findByText(/attribute evidence could not be verified/),
  ).toBeVisible();
  expect(screen.getByText("Operations")).toBeVisible();
  expect(
    screen.getAllByRole("option", { name: "Cost centre (cost-centre)" }),
  ).toHaveLength(1);
  rejectContinuation = false;
  load.focus();
  fireEvent.click(load);
  expect(
    await screen.findByRole("option", {
      name: "Quantity unit (quantity-unit)",
    }),
  ).toBeVisible();
  expect(load).toHaveFocus();
  expect(load).toHaveAttribute("aria-disabled", "true");
  expect(load).toHaveTextContent("All attributes loaded");
  expect(select).toHaveValue(first.attribute_id);
  expect(list).toHaveBeenLastCalledWith({
    scope: "Member",
    dimensionId: "Account",
    status: "Active",
    limit: 200,
    afterAttributeId: first.attribute_id,
    expectedMetadataRevision: 8,
    expectedPageToken: pageToken,
  });
  fireEvent.change(select, { target: { value: unit.attribute_id } });
  expect(await screen.findByText("hours")).toBeVisible();
});

it("does not describe a late coordinate as absent", async () => {
  let finish: ((value: Response) => void) | undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_path, init) => {
      const value = JSON.parse(init.body);
      if (value.program.function === "metadata.authoring.context")
        return authorizedGrain();
      if (value.program.function === "metadata.member.resolve")
        return response({
          member_id: value.program.arguments.reference,
          dimension_id: value.program.arguments.dimension,
          status: "Active",
        });
      return new Promise<Response>((resolve) => {
        finish = resolve;
      });
    }),
  );
  const view = render(
    <ModelMeaning
      app={app}
      catalog={catalog}
      dimensions={dimensions}
      metadataRevision={8}
    />,
  );
  await openPanelAndPopulate();
  fireEvent.click(
    screen.getByRole("button", { name: "Inspect worked coordinate" }),
  );
  await waitFor(() => expect(finish).toBeDefined());
  view.rerender(
    <ModelMeaning
      app={app}
      catalog={{ ...catalog, revisions: { ...catalog.revisions, security: 1 } }}
      dimensions={dimensions}
      metadataRevision={8}
    />,
  );
  await act(async () =>
    finish!(
      response({ complete: true, snapshot: { metadataRevision: 8 }, rows: [] }),
    ),
  );
  expect(
    screen.queryByLabelText("Worked coordinate evidence"),
  ).not.toBeInTheDocument();
  expect(
    screen.queryByText(/No stored value is visible/),
  ).not.toBeInTheDocument();
});

it("rejects malformed presence, source, coordinates and revision evidence while preserving empty text", () => {
  const valid = evidence();
  expect(workedCoordinateRows(valid, coordinate, catalog, 8)).toEqual([
    { kind: "amount", amount: "0.00000000" },
  ]);
  const text = structuredClone(valid);
  text.rows[0].values.raw[0] = {
    ...text.rows[0].values.raw[0],
    unit: "text",
    value: "",
  };
  expect(workedCoordinateRows(text, coordinate, catalog, 8)).toEqual([
    { kind: "text", text: "" },
  ]);
  const malformed: any[] = [];
  for (const change of [
    (value: any) => {
      value.rows[0].values.raw[0].value = null;
    },
    (value: any) => {
      value.rows[0].members = { ...coordinate, Account: "wrong" };
    },
    (value: any) => {
      value.dataSource.kind = "calculated";
    },
    (value: any) => {
      value.readPolicy.semantics = "own";
    },
    (value: any) => {
      value.snapshot.securityRevision = 1;
    },
    (value: any) => {
      value.rows[0].values.raw[0].unit = null;
    },
    (value: any) => {
      value.rows[0].values.raw[0].value = 0;
    },
    (value: any) => {
      value.complete = false;
    },
  ]) {
    const value = structuredClone(valid);
    change(value);
    malformed.push(value);
  }
  for (const value of malformed)
    expect(() => workedCoordinateRows(value, coordinate, catalog, 8)).toThrow(
      /evidence is incomplete/,
    );
});

it("refuses the same member ID resolved in a different dimension", async () => {
  const calls: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_path, init) => {
      const value = JSON.parse(init.body);
      calls.push(value.program.function);
      if (value.program.function === "metadata.authoring.context")
        return authorizedGrain();
      return response({
        member_id: value.program.arguments.reference,
        dimension_id: "wrong-dimension",
        status: "Active",
      });
    }),
  );
  render(
    <ModelMeaning
      app={app}
      catalog={catalog}
      dimensions={dimensions}
      metadataRevision={8}
    />,
  );
  await openPanelAndPopulate();
  fireEvent.click(
    screen.getByRole("button", { name: "Inspect worked coordinate" }),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    /exact ID for every fact dimension/,
  );
  expect(
    screen.queryByLabelText("Worked coordinate evidence"),
  ).not.toBeInTheDocument();
  expect(calls).not.toContain("facts.cube.resolved.read");
});

it("does not offer a complete coordinate when the authorized grain is partial", async () => {
  const fetch = vi.fn(async () =>
    authorizedGrain(catalog, false, dimensions.slice(0, -1)),
  );
  vi.stubGlobal("fetch", fetch);
  render(
    <ModelMeaning
      app={app}
      catalog={catalog}
      dimensions={dimensions}
      metadataRevision={8}
    />,
  );
  expect(fetch).not.toHaveBeenCalled();
  fireEvent.click(screen.getByText("Model meaning and one worked coordinate"));
  expect(
    await screen.findByText(
      "A complete fact coordinate is unavailable in the current application context.",
    ),
  ).toBeVisible();
  expect(screen.queryByText(/The current grain is/)).not.toBeInTheDocument();
  expect(
    screen.queryByRole("button", { name: "Inspect worked coordinate" }),
  ).not.toBeInTheDocument();
  expect(fetch).toHaveBeenCalledTimes(1);
});

it("refuses a complete grain that disagrees with the current metadata axes", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () =>
      authorizedGrain(
        catalog,
        true,
        dimensions.map((dimension) =>
          dimension.dimension_id === "Account"
            ? { ...dimension, dimension_id: "OtherAccount" }
            : dimension,
        ),
      ),
    ),
  );
  render(
    <ModelMeaning
      app={app}
      catalog={catalog}
      dimensions={dimensions}
      metadataRevision={8}
    />,
  );
  fireEvent.click(screen.getByText("Model meaning and one worked coordinate"));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "The current grain could not be verified",
  );
  expect(screen.queryByLabelText("Example Account")).not.toBeInTheDocument();
});

it("waits for current grain authority and ignores the earlier authorized response after a grant change", async () => {
  const changed = {
    ...catalog,
    revisions: { ...catalog.revisions, security: 1 },
  };
  let finishOld: ((value: Response) => void) | undefined;
  let finishCurrent: ((value: Response) => void) | undefined;
  const fetch = vi
    .fn()
    .mockImplementationOnce(
      () =>
        new Promise<Response>((resolve) => {
          finishOld = resolve;
        }),
    )
    .mockImplementationOnce(
      () =>
        new Promise<Response>((resolve) => {
          finishCurrent = resolve;
        }),
    );
  vi.stubGlobal("fetch", fetch);
  const view = render(
    <ModelMeaning
      app={app}
      catalog={catalog}
      dimensions={dimensions}
      metadataRevision={8}
    />,
  );
  fireEvent.click(screen.getByText("Model meaning and one worked coordinate"));
  await waitFor(() => expect(finishOld).toBeDefined());
  expect(screen.getByRole("status")).toHaveTextContent(
    "Checking the active fact dimensions",
  );
  view.rerender(
    <ModelMeaning
      app={app}
      catalog={changed}
      dimensions={dimensions}
      metadataRevision={8}
    />,
  );
  await waitFor(() => expect(finishCurrent).toBeDefined());
  expect(fetch.mock.calls[0][1].signal.aborted).toBe(true);
  await act(async () =>
    finishCurrent!(authorizedGrain(changed, false, dimensions.slice(0, -1))),
  );
  await act(async () => finishOld!(authorizedGrain()));
  expect(
    screen.getByText(/A complete fact coordinate is unavailable/),
  ).toBeVisible();
  expect(screen.queryByLabelText("Example Account")).not.toBeInTheDocument();
  expect(fetch).toHaveBeenCalledTimes(2);
});
