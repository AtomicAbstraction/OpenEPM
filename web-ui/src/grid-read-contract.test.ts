import { expect, it } from "vitest";
import {
  gridLayoutSummary,
  gridReadPlan,
  type GridReadSemantics,
} from "./grid-read-contract";
import type { CubeSelection } from "./member-selection/selection-types";

const selection: CubeSelection = {
  format: "openepm-cube-selection-v1",
  metadataRevision: 4,
  dimensions: [
    {
      dimensionId: "Account",
      include: { kind: "member", memberId: "Revenue" },
      exclude: null,
    },
    {
      dimensionId: "Period",
      include: { kind: "members", memberIds: ["Jan"] },
      exclude: null,
    },
  ],
};
const input = {
  view: null,
  semantics: "stored" as GridReadSemantics,
  pov: { Scenario: "Plan" },
  hasNativeSelection: false,
  bindingId: "current-binding",
  bindingStateToken: "b".repeat(64),
};

it("keeps stored, own and effective requests distinct without a saved source layer", () => {
  expect(gridReadPlan(input)).toMatchObject({
    kind: "stored",
    function: "facts.cube.scan",
    members: { Scenario: "Plan" },
    label: "Stored raw values",
  });
  expect(gridReadPlan({ ...input, semantics: "own" })).toMatchObject({
    function: "facts.cube.resolved.read",
    source: { semantics: "own" },
    label: "Own input at each member",
  });
  expect(gridReadPlan({ ...input, semantics: "effective" })).toMatchObject({
    source: {
      semantics: "effective",
      bindingId: "current-binding",
      bindingStateToken: "b".repeat(64),
      hierarchies: [],
    },
    label: "Effective governed value · binding current-binding",
  });
});

it("never widens scalar scans or substitutes own input for an unrepresentable request", () => {
  expect(() => gridReadPlan({ ...input, hasNativeSelection: true })).toThrow(
    "Choose Own input",
  );
  const view = {
    dataSource: { kind: "raw" as const, resultKey: null },
    selection,
  };
  expect(gridReadPlan({ ...input, view })).toMatchObject({
    members: { Account: "Revenue", Period: "Jan" },
  });
  const multiple = structuredClone(view);
  multiple.selection.dimensions[0].include = {
    kind: "members",
    memberIds: ["Revenue", "Cost"],
  };
  expect(() => gridReadPlan({ ...input, view: multiple })).toThrow(
    "cannot represent",
  );
  expect(
    gridReadPlan({ ...input, view: multiple, semantics: "own" }),
  ).toMatchObject({ source: { semantics: "own" } });
  expect(() =>
    gridReadPlan({ ...input, view, semantics: "effective" }),
  ).toThrow("cannot replace that source layer");
});

it("uses the named calculated result with every scalar axis and never treats its key as a binding", () => {
  const view = {
    dataSource: { kind: "calculated" as const, resultKey: "forecast.result" },
    selection,
  };
  expect(gridReadPlan({ ...input, view })).toEqual({
    kind: "calculated",
    function: "facts.calculation.scan",
    resultKey: "forecast.result",
    members: { Account: "Revenue", Period: "Jan" },
    label: "Stored calculated result",
  });
  for (const semantics of ["own", "effective"] as const)
    expect(() => gridReadPlan({ ...input, view, semantics })).toThrow(
      "Stored values only",
    );
  const excluded = structuredClone(view);
  excluded.selection.dimensions[0].exclude = {
    kind: "member",
    memberId: "Cost",
  };
  expect(() => gridReadPlan({ ...input, view: excluded })).toThrow(
    "cannot be read exactly",
  );
  const multiple = structuredClone(view);
  multiple.selection.dimensions[0].include = {
    kind: "members",
    memberIds: ["Revenue", "Cost"],
  };
  expect(() => gridReadPlan({ ...input, view: multiple })).toThrow(
    "cannot be read exactly",
  );
});

it.each(["stored", "own", "effective"] as const)(
  "rejects combined/%s until a shared mapping preserves its named result",
  (semantics) => {
    expect(() =>
      gridReadPlan({
        ...input,
        semantics,
        view: {
          dataSource: { kind: "combined", resultKey: "forecast.result" },
          selection,
        },
      }),
    ).toThrow("combined source layer");
  },
);

it("requires a current binding identity for effective reads", () => {
  expect(() =>
    gridReadPlan({ ...input, semantics: "effective", bindingId: "" }),
  ).toThrow("current active binding");
  expect(() =>
    gridReadPlan({
      ...input,
      semantics: "effective",
      bindingStateToken: "expired",
    }),
  ).toThrow("current active binding");
});

it("routes advertised canonical reads with the complete unchanged view and separate policy", () => {
  for (const kind of ["raw", "calculated", "combined"] as const) {
    const view = {
      dataSource: {
        kind,
        resultKey: kind === "raw" ? null : "forecast.result",
      },
      selection,
    };
    const plan = gridReadPlan({ ...input, view, canonicalViewRead: true });
    expect(plan).toMatchObject({
      kind: "canonical",
      function: "facts.cube.resolved.read",
      view,
      readPolicy: { semantics: "stored" },
    });
    expect(plan.kind === "canonical" && plan.view).toBe(view);
    expect(view).not.toHaveProperty("readPolicy");
    expect(() =>
      gridReadPlan({
        ...input,
        view,
        canonicalViewRead: true,
        semantics: "effective",
      }),
    ).toThrow("separate governed binding");
  }
});

it("summarizes every ordered canonical axis, including pages and non-scalar filters", () => {
  const rows = ["A", "B", "C", "D", "E", "F"];
  const summary = gridLayoutSummary(
    { rows, columns: ["G", "H"], pages: ["I"], filters: ["J", "K"] },
    [{ dimension_id: "A", name: "Company" }],
  );
  expect(summary.map((group) => group.text)).toEqual([
    "6 axes · Company / B / C / D / E / F",
    "2 axes · G / H",
    "1 axis · I",
    "2 axes · J / K",
  ]);
  expect(summary.map((group) => group.key)).toEqual([
    "rows",
    "columns",
    "pages",
    "filters",
  ]);
});
