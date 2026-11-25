import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { Analyze } from "./Analyze";
import { SCENARIO_COMPARISON, ScenarioComparison } from "./ScenarioComparison";

const app = {
  workspaceId: "ws",
  applicationId: "app",
  name: "Staff plan",
  status: "Active",
};
const catalog = {
  applicationAccess: { role: "Reader", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: { [SCENARIO_COMPARISON]: {}, "metadata.member.select": {} },
  revisions: { metadata: 8, data: 5, policy: 0, security: 3, commit: 9 },
};
const axis = {
  dimension_id: "Scenario",
  name: "Scenarios",
  status: "Active",
  model_role: "Scenario",
};
const coordinate = { Scenario: "Baseline", Account: "Hours", Period: "M01" };
const aligned = { Account: "Hours", Period: "M01" };

afterEach(() => vi.unstubAllGlobals());

it.each([false, true])(
  "opens stored Grid comparison and offers copy only with current copy capabilities (%s)",
  async (canCopy) => {
    const response = (result: unknown) => Response.json({ result });
    const paths: string[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path, init) => {
        paths.push(String(path));
        const { program } = JSON.parse(String(init.body));
        if (program.function === "metadata.dimension.list")
          return response({
            rows: [
              {
                dimension_id: "Account",
                model_role: "Account",
                name: "Account",
                status: "Active",
              },
              {
                dimension_id: "Period",
                model_role: "Period",
                name: "Period",
                status: "Active",
              },
              axis,
            ],
            metadataRevision: 8,
            nextAfterDimensionId: null,
          });
        if (program.function === "metadata.member.list") {
          const member =
            coordinate[program.arguments.dimension as keyof typeof coordinate];
          return response({
            rows: [
              { member_id: member, name: member, status: "Active" },
              ...(program.arguments.dimension === "Scenario"
                ? [
                    {
                      member_id: "SecretAlternative",
                      name: "Restricted",
                      status: "Active",
                    },
                  ]
                : []),
            ],
            metadataRevision: 8,
            nextAfterMemberId: null,
          });
        }
        if (program.function === "facts.cube.scan")
          return response({
            rows: [
              {
                members: coordinate,
                kind: "numeric",
                amount: "1.00000000",
                lastRevision: 9,
              },
            ],
            nextCursor: null,
            snapshotRevision: 9,
            source: "postgres_current",
          });
        if (program.function === "facts.cell.editability.read")
          return Response.json(
            { code: "WRITEBACK_UNAVAILABLE" },
            { status: 403 },
          );
        if (program.function === "metadata.member.select") {
          if (program.arguments.expression.operation === "all")
            return Response.json(
              { code: "METADATA_SELECTION_SCOPE_UNAVAILABLE" },
              { status: 403 },
            );
          return response({
            dimensionId: "Scenario",
            metadataRevision: 8,
            resultKind: "scope",
            selectionContextToken: "a".repeat(64),
            scope: {
              kind: "scope",
              scope: "dimension",
              dimensionId: "Scenario",
              hierarchyId: null,
              name: "Scenarios",
              businessCoordinate: false,
              supportedOperations: ["top", "all"],
            },
            rows: [],
            hasMore: false,
            nextCursor: null,
          });
        }
        if (program.function === SCENARIO_COMPARISON) {
          expect(program.arguments).toEqual({
            baselineMemberId: "Baseline",
            alternativeMemberId: "Approved",
            expectedMetadataRevision: 8,
            coordinates: [aligned],
          });
          return response({
            complete: true,
            layer: "raw",
            scenarioDimensionId: "Scenario",
            baselineMemberId: "Baseline",
            alternativeMemberId: "Approved",
            snapshot: {
              metadataRevision: 8,
              securityRevision: 3,
              policyRevision: 0,
              dataRevision: 5,
              commitRevision: 9,
            },
            comparisons: [
              {
                members: aligned,
                baseline: {
                  kind: "numeric",
                  value: "1.00000000",
                  lastRevision: 9,
                },
                alternative: {
                  kind: "numeric",
                  value: "2.00000000",
                  lastRevision: 9,
                },
                status: "numeric",
                difference: "1.00000000",
              },
            ],
          });
        }
        throw new Error(`Unexpected read: ${program.function}`);
      }),
    );
    render(
      <Analyze
        app={app}
        index={0}
        subject="reader"
        catalog={{
          ...catalog,
          functions: {
            ...catalog.functions,
            "metadata.dimension.list": {},
            "metadata.member.list": {},
            "facts.cube.scan": {},
            ...(canCopy
              ? {
                  "facts.slice.copy.prepare": {},
                  "facts.source.preview": {},
                  "facts.source.publish": {},
                }
              : {}),
          },
        }}
      />,
    );
    const layout = await screen.findByRole("button", {
      name: "Configure layout",
    });
    await waitFor(() => expect(layout).toBeEnabled());
    fireEvent.click(layout);
    const suggest = await screen.findByRole("button", {
      name: "Suggest layout",
    });
    await waitFor(() => expect(suggest).toBeEnabled());
    fireEvent.click(suggest);
    const read = await screen.findByRole("button", { name: "Read grid" });
    await waitFor(() => expect(read).toBeEnabled());
    fireEvent.click(read);
    fireEvent.click(
      await screen.findByRole("button", { name: /Account Hours.*1\.00000000/ }),
    );
    const inspector = within(
      screen.getByRole("complementary", { name: "Cell details and writeback" }),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "WRITEBACK_UNAVAILABLE",
    );
    expect(inspector.getByText("Compare scenarios")).toBeVisible();
    expect(
      inspector.getByRole("button", { name: "Submit durable writeback" }),
    ).toBeDisabled();
    fireEvent.click(inspector.getByText("Compare scenarios"));
    const opener = inspector.getByRole("button", {
      name: "Choose alternative scenario",
    });
    opener.focus();
    fireEvent.click(opener);
    const dialog = await screen.findByRole("dialog", {
      name: "Choose alternative scenario",
    });
    expect(dialog.closest(".writeback-drawer")).toBeNull();
    expect(dialog.closest(".analyze-page")).toBeInTheDocument();
    fireEvent.click(
      await within(dialog).findByRole("button", { name: "All active members" }),
    );
    expect(await within(dialog).findByRole("alert")).toHaveTextContent(
      "METADATA_SELECTION_SCOPE_UNAVAILABLE",
    );
    fireEvent.click(within(dialog).getByRole("button", { name: "Search" }));
    expect(
      within(dialog).getByText("No members match this search."),
    ).toBeVisible();
    expect(within(dialog).queryByText("Restricted")).toBeNull();
    fireEvent.keyDown(dialog, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(opener).toHaveFocus();
    fireEvent.change(inspector.getByLabelText("Alternative scenario ID"), {
      target: { value: "Approved" },
    });
    fireEvent.click(inspector.getByRole("button", { name: "Read comparison" }));
    const readback = within(
      await inspector.findByRole("region", {
        name: "Stored scenario comparison",
      }),
    );
    expect(readback.getByText("2.00000000")).toBeVisible();
    const setup = readback.queryByRole("button", {
      name: "Set up copy from alternative",
    });
    if (!canCopy) {
      expect(setup).toBeNull();
      return;
    }
    const summary = screen.getByText("Copy scenario facts", {
      selector: "summary",
    });
    expect(summary.parentElement).not.toHaveAttribute("open");
    expect(setup).toBeVisible();
    fireEvent.click(setup!);
    expect(summary.parentElement).toHaveAttribute("open");
    expect(summary).toHaveFocus();
    const offer = screen.getByRole("region", { name: "Compared copy source" });
    expect(offer).toHaveTextContent("alternative Approved");
    fireEvent.click(
      within(offer).getByRole("button", {
        name: "Use compared source and scope",
      }),
    );
    expect(
      screen.getByRole("button", { name: "Change source scenario, Approved" }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Choose destination scenario" }),
    ).toHaveFocus();
    expect(screen.getByLabelText("Copy scope Account")).toHaveValue("member");
    expect(screen.getByLabelText("Copy scope Period")).toHaveValue("member");
    expect(
      screen.getByRole("button", {
        name: "Change Account scope member, Hours",
      }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Change Period scope member, M01" }),
    ).toBeVisible();
    expect(screen.getByLabelText("Copy destination policy")).toHaveValue("");
    expect(
      screen.getByRole("button", { name: "Prepare copy review" }),
    ).toHaveAttribute("aria-disabled", "true");
    expect(paths.filter((path) => path !== "/api/read")).toEqual([]);
  },
);

it.each([
  [
    "APPLICATION_GRANT_REQUIRED",
    403,
    "Current access to this cell could not be confirmed.",
  ],
  [
    "CUBE_READ_AUTHORIZATION_STALE",
    409,
    "Current access to this cell could not be confirmed.",
  ],
  [
    "CALCULATION_REQUIRED",
    400,
    "The published calculation changed or is out of date.",
  ],
  [
    "CALCULATION_RESULT_STATE_CHANGED_RESTART",
    409,
    "The published calculation changed or is out of date.",
  ],
] as const)(
  "compares a published Grid cell and withdraws it after %s",
  async (code, status, notice) => {
    const resultKey = "staffing.current";
    const resultStateToken = "a".repeat(64);
    const canonicalDigest = "d".repeat(64);
    const currencyUnits = ["CHF", "USD"].map((memberId) => ({
      type: "Currency",
      dimensionId: "Currency",
      memberId,
    }));
    const ratio = code === "CALCULATION_REQUIRED";
    const ratioUnit = { type: "Ratio", scale: 12 };
    const selectedUnit = ratio ? ratioUnit : currencyUnits[1];
    const values = ratio
      ? {
          baseline: "5.000000000000",
          alternative: "5.333333333333",
          difference: "0.333333333333",
        }
      : {
          baseline: "100.00000000",
          alternative: "125.00000000",
          difference: "25.00000000",
        };
    const definition = {
      viewId: "staffing-view",
      name: "Staffing review",
      format: "openepm-cube-view-v1",
      selection: {
        format: "openepm-cube-selection-v1",
        metadataRevision: 8,
        dimensions: Object.entries(coordinate).map(
          ([dimensionId, memberId]) => ({
            dimensionId,
            include: { kind: "member", memberId },
            exclude: null,
          }),
        ),
      },
      layout: {
        rows: ["Account"],
        columns: ["Period"],
        pages: [],
        filters: ["Scenario"],
      },
      dataSource: { kind: "calculated", resultKey },
      suppression: { zero: false, missing: false },
      pageSize: 1,
    };
    const response = (result: unknown) => Response.json({ result });
    const refreshCatalogue = vi
      .fn()
      .mockRejectedValue(new Error("Application access not confirmed"));
    let calls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (_path, init) => {
        const { program } = JSON.parse(String(init.body));
        if (program.function === "metadata.dimension.list")
          return response({
            rows: [
              {
                dimension_id: "Account",
                model_role: "Account",
                name: "Account",
                status: "Active",
              },
              {
                dimension_id: "Period",
                model_role: "Period",
                name: "Period",
                status: "Active",
              },
              axis,
            ],
            metadataRevision: 8,
            nextAfterDimensionId: null,
          });
        if (program.function === "metadata.member.list")
          return response({
            rows: [],
            metadataRevision: 8,
            nextAfterMemberId: null,
          });
        if (program.function === "grid.definition.read")
          return response({
            gridId: definition.viewId,
            name: definition.name,
            metadataRevision: definition.selection.metadataRevision,
            definition,
            canonicalDigest,
            stateToken: resultStateToken,
          });
        if (program.function === "facts.cube.resolved.read")
          return response({
            format: "openepm-cube-view-read-v1",
            dataSource: definition.dataSource,
            readPolicy: { semantics: "stored" },
            snapshot: { commitRevision: 9 },
            complete: true,
            presentation: { pageSize: 1, rowCount: 1 },
            calculation: {
              resultKey,
              resultStateToken,
              inputRevisionStatus: { matchesAtRead: true },
            },
            rows: [
              {
                members: coordinate,
                values: {
                  calculated: (ratio ? [ratioUnit] : currencyUnits).map(
                    (unit) => ({
                      present: true,
                      value:
                        "memberId" in unit && unit.memberId === "CHF"
                          ? "88.00000000"
                          : values.baseline,
                      unit,
                      resultStateToken,
                      origin: "materialized",
                      currentness: "current",
                    }),
                  ),
                },
              },
            ],
          });
        if (program.function === "facts.cell.editability.read")
          return response({
            editable: false,
            reasonCode: "CALCULATED_RESULT_READ_ONLY",
          });
        if (program.function === SCENARIO_COMPARISON) {
          calls++;
          expect(program.arguments).toEqual({
            baselineMemberId: "Baseline",
            alternativeMemberId: "Approved",
            expectedMetadataRevision: 8,
            coordinates: [aligned],
            calculation: { resultKey, resultStateToken, unit: selectedUnit },
          });
          if (calls === 3)
            return Response.json(
              { code: "SCENARIO_COMPARISON_MEMBER_UNAVAILABLE" },
              { status: 400 },
            );
          if (calls === 4) return Response.json({ code }, { status });
          return response({
            complete: true,
            layer: "calculated",
            calculation: {
              resultKey,
              resultStateToken: calls === 1 ? resultStateToken : "b".repeat(64),
              unit: selectedUnit,
            },
            scenarioDimensionId: "Scenario",
            baselineMemberId: "Baseline",
            alternativeMemberId: "Approved",
            snapshot: {
              metadataRevision: 8,
              securityRevision: 3,
              policyRevision: 0,
              dataRevision: 5,
              commitRevision: 9,
            },
            comparisons: [
              {
                members: aligned,
                baseline: { kind: "numeric", value: values.baseline },
                alternative: { kind: "numeric", value: values.alternative },
                status: "numeric",
                difference: values.difference,
              },
            ],
          });
        }
        throw new Error(`Unexpected read: ${program.function}`);
      }),
    );
    render(
      <Analyze
        app={app}
        index={0}
        subject="reader"
        targetViewId={definition.viewId}
        targetViewDigest={canonicalDigest}
        targetAnalyticalRead={{ semantics: "stored" }}
        onRefreshCatalog={refreshCatalogue}
        catalog={{
          ...catalog,
          functions: {
            "metadata.dimension.list": {},
            "metadata.member.list": {},
            "grid.definition.read": {},
            "facts.cell.editability.read": {},
            "facts.cube.resolved.read": {
              canonicalViewRead: "openepm-cube-view-read-v1",
            },
            [SCENARIO_COMPARISON]: { calculatedScenarioComparison: true },
            "facts.slice.copy.prepare": {},
            "facts.source.preview": {},
            "facts.source.publish": {},
          },
        }}
      />,
    );
    const read = await screen.findByRole("button", { name: "Read grid" });
    await waitFor(() => expect(read).toBeEnabled());
    fireEvent.click(read);
    fireEvent.click(
      await screen.findByRole("button", {
        name: ratio
          ? /Account Hours.*5\.000000000000/
          : /Account Hours.*100\.00000000 USD/,
      }),
    );
    const inspector = within(
      screen.getByRole("complementary", { name: "Cell details and writeback" }),
    );
    fireEvent.click(inspector.getByText("Compare scenarios"));
    fireEvent.change(inspector.getByLabelText("Alternative scenario ID"), {
      target: { value: "Approved" },
    });
    const compare = inspector.getByRole("button", { name: "Read comparison" });
    if (ratio) {
      expect(inspector.getByText("Output unit is Ratio.")).toBeVisible();
    } else {
      expect(compare).toHaveAttribute("aria-disabled", "true");
      const option = inspector.getByRole<HTMLOptionElement>("option", {
        name: "USD (Currency)",
      });
      fireEvent.change(inspector.getByLabelText("Output unit"), {
        target: { value: option.value },
      });
    }
    fireEvent.click(compare);
    const region = await inspector.findByRole("region", {
      name: "Calculated scenario comparison",
    });
    expect(within(region).getByText(values.difference)).toBeVisible();
    expect(
      screen.getByLabelText("Configured grid source"),
    ).not.toHaveTextContent(resultKey);
    expect(screen.getByLabelText("Loaded grid read")).not.toHaveTextContent(
      /Snapshot 9|staffing\.current/,
    );
    expect(
      inspector.getByText(/Both scenarios use the same output unit/),
    ).not.toHaveTextContent(resultKey);
    expect(within(region).getByRole("status")).toHaveTextContent(
      /^Scenarios read together\.$/,
    );
    expect(
      within(region).queryByRole("button", {
        name: "Set up copy from alternative",
      }),
    ).toBeNull();
    fireEvent.click(compare);
    expect(await inspector.findByRole("alert")).toHaveTextContent(
      "did not match",
    );
    expect(
      inspector.queryByRole("region", {
        name: "Calculated scenario comparison",
      }),
    ).toBeNull();
    fireEvent.click(compare);
    await waitFor(() =>
      expect(inspector.getByRole("alert")).toHaveTextContent(
        "SCENARIO_COMPARISON_MEMBER_UNAVAILABLE",
      ),
    );
    expect(screen.getByLabelText("Loaded grid read")).toBeVisible();
    expect(refreshCatalogue).not.toHaveBeenCalled();

    fireEvent.click(compare);
    await waitFor(() => expect(refreshCatalogue).toHaveBeenCalledTimes(1));
    expect(screen.queryByLabelText("Loaded grid read")).not.toBeInTheDocument();
    expect(
      screen.queryByLabelText("Cell details and writeback"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByLabelText("Calculated result provenance"),
    ).not.toBeInTheDocument();
    for (const value of Object.values(values))
      expect(
        screen.queryAllByText((text) => text.includes(value)),
      ).toHaveLength(0);
    expect(screen.getByRole("alert")).toHaveTextContent(notice);
    expect(read).toBeEnabled();
  },
);

it.each(["numeric", "missing", "stale"] as const)(
  "uses the native scenario picker and one read of both aligned values (%s)",
  async (caseName) => {
    const requests: Array<{ function: string; arguments: unknown }> = [];
    const offerCopySource = vi.fn(() => true);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (path, init) => {
        expect(path).toBe("/api/read");
        const body = JSON.parse(String(init.body));
        expect(body).toEqual({
          workspaceId: app.workspaceId,
          applicationId: app.applicationId,
          program: body.program,
        });
        requests.push(body.program);
        if (body.program.function === "metadata.member.select") {
          const top = body.program.arguments.expression?.operation === "top";
          return Response.json({
            result: {
              dimensionId: "Scenario",
              metadataRevision: 8,
              resultKind: top ? "scope" : "unique_member",
              selectionContextToken: "a".repeat(64),
              scope: {
                kind: "scope",
                scope: "dimension",
                dimensionId: "Scenario",
                hierarchyId: null,
                name: "Scenarios",
                businessCoordinate: false,
                supportedOperations: ["top", "all"],
              },
              rows: top
                ? []
                : [
                    {
                      memberId: "ExtraHours",
                      name: "Extra hours",
                      status: "Active",
                    },
                  ],
              hasMore: false,
              nextCursor: null,
            },
          });
        }
        expect(body.program).toEqual({
          languageVersion: 2,
          function: SCENARIO_COMPARISON,
          arguments: {
            baselineMemberId: "Baseline",
            alternativeMemberId: "ExtraHours",
            expectedMetadataRevision: 8,
            coordinates: [aligned],
          },
        });
        return Response.json({
          result: {
            complete: true,
            layer: "raw",
            scenarioDimensionId: "Scenario",
            baselineMemberId: "Baseline",
            alternativeMemberId: "ExtraHours",
            snapshot: {
              metadataRevision: 8,
              securityRevision: caseName === "stale" ? 4 : 3,
              policyRevision: 0,
              dataRevision: 5,
              commitRevision: 9,
            },
            comparisons: [
              {
                members: aligned,
                baseline: {
                  kind: "numeric",
                  value: "0.00000000",
                  lastRevision: 8,
                },
                alternative:
                  caseName === "missing"
                    ? { kind: "missing", value: null, lastRevision: null }
                    : {
                        kind: "numeric",
                        value: "9007199254740993.12345678",
                        lastRevision: 9,
                      },
                status: caseName === "missing" ? "missing_input" : "numeric",
                difference:
                  caseName === "missing" ? null : "9007199254740993.12345678",
              },
            ],
          },
        });
      }),
    );
    render(
      <ScenarioComparison
        app={app}
        catalog={catalog}
        axis={axis}
        coordinate={coordinate}
        dialogHost={document.body}
        offerCopySource={offerCopySource}
      />,
    );
    fireEvent.click(
      screen.getByText("Compare scenarios", { selector: "summary" }),
    );
    const picker = screen.getByRole("button", {
      name: "Choose alternative scenario",
    });
    picker.focus();
    fireEvent.click(picker);
    const dialog = within(screen.getByRole("dialog"));
    fireEvent.click(
      await dialog.findByRole("button", { name: "All active members" }),
    );
    fireEvent.click(
      await dialog.findByRole("button", {
        name: "Extra hours",
      }),
    );
    fireEvent.click(
      dialog.getByRole("button", { name: "Add selected member" }),
    );
    fireEvent.click(dialog.getByRole("button", { name: "Apply selection" }));
    expect(picker).toHaveFocus();
    const run = screen.getByRole("button", { name: "Read comparison" });
    run.focus();
    fireEvent.click(run);
    if (caseName === "stale") {
      expect(await screen.findByRole("alert")).toHaveTextContent(
        "current application context",
      );
      expect(
        screen.queryByRole("region", { name: "Stored scenario comparison" }),
      ).toBeNull();
    } else {
      const result = within(
        await screen.findByRole("region", {
          name: "Stored scenario comparison",
        }),
      );
      expect(result.getByRole("status")).toHaveTextContent(
        /^Scenarios read together\.$/,
      );
      expect(result.getByText("0.00000000")).toBeVisible();
      if (caseName === "numeric")
        expect(result.getAllByText("9007199254740993.12345678")).toHaveLength(
          2,
        );
      else {
        expect(result.getByText("Missing", { exact: true })).toBeVisible();
        expect(result.getByText("A stored value is missing")).toBeVisible();
      }
    }
    expect(run).toHaveFocus();
    const setup = screen.queryByRole("button", {
      name: "Set up copy from alternative",
    });
    if (caseName === "numeric") {
      fireEvent.click(setup!);
      expect(offerCopySource).toHaveBeenCalledOnce();
      expect(offerCopySource).toHaveBeenCalledWith({
        dimensionId: "Scenario",
        sourceMemberId: "ExtraHours",
        members: aligned,
      });
    } else {
      expect(setup).toBeNull();
      expect(offerCopySource).not.toHaveBeenCalled();
    }
    expect(
      requests.filter(({ function: name }) => name === SCENARIO_COMPARISON),
    ).toHaveLength(1);
  },
);
