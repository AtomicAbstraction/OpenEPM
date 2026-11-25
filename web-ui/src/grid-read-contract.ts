import type { CubeSelection } from "./member-selection/selection-types";

export type GridReadSemantics = "stored" | "own" | "effective";
export type GridDataSource = {
  kind: "raw" | "calculated" | "combined";
  resultKey: string | null;
};
export type GridLayout = {
  rows: string[];
  columns: string[];
  pages: string[];
  filters: string[];
};
export type GridResolvedSource =
  | { semantics: "own" }
  | {
      semantics: "effective";
      bindingId: string;
      bindingStateToken: string;
      hierarchies: never[];
    };
export type GridReadPlan =
  | {
      kind: "canonical";
      function: "facts.cube.resolved.read";
      view: { dataSource: GridDataSource; selection: CubeSelection };
      readPolicy: { semantics: "stored" | "own" };
      label: string;
    }
  | {
      kind: "resolved";
      function: "facts.cube.resolved.read";
      source: GridResolvedSource;
      label: string;
    }
  | {
      kind: "stored";
      function: "facts.cube.scan";
      members: Record<string, string>;
      label: string;
    }
  | {
      kind: "calculated";
      function: "facts.calculation.scan";
      resultKey: string;
      members: Record<string, string>;
      label: string;
    };

export function canonicalGridReadLabel(
  source: GridDataSource,
  semantics: "stored" | "own",
) {
  return semantics === "own"
    ? "Own input at each member"
    : source.kind === "raw"
      ? "Stored raw values"
      : source.kind === "combined"
        ? "Separate raw and calculated values"
        : "Stored calculated result";
}

// The scalar scan contracts cannot encode a native set, exclusion or hierarchy.
// Reject those selections instead of broadening the request or filtering a
// broader business read in the browser.
function exactScalarMembers(selection: CubeSelection) {
  const members: Record<string, string> = {};
  for (const dimension of selection.dimensions) {
    if (dimension.exclude !== null) return null;
    if (dimension.include.kind === "member")
      members[dimension.dimensionId] = dimension.include.memberId;
    else if (
      dimension.include.kind === "members" &&
      dimension.include.memberIds.length === 1
    )
      members[dimension.dimensionId] = dimension.include.memberIds[0];
    else return null;
  }
  return members;
}

export function gridReadPlan({
  view,
  semantics,
  pov,
  hasNativeSelection,
  bindingId,
  bindingStateToken,
  canonicalViewRead = false,
}: {
  view: { dataSource: GridDataSource; selection: CubeSelection } | null;
  semantics: GridReadSemantics;
  pov: Record<string, string>;
  hasNativeSelection: boolean;
  bindingId: string;
  bindingStateToken: string;
  canonicalViewRead?: boolean;
}): GridReadPlan {
  const layer = view?.dataSource.kind;
  if (view && canonicalViewRead) {
    if (semantics === "effective")
      throw new Error(
        "This saved source layer cannot be replaced by an effective binding. Use the separate governed binding read.",
      );
    if (semantics === "own" && layer !== "raw")
      throw new Error(
        "Own input cannot replace the named calculated or combined source layer. Choose Stored values.",
      );
    return {
      kind: "canonical",
      function: "facts.cube.resolved.read",
      view,
      readPolicy: { semantics },
      label: canonicalGridReadLabel(view.dataSource, semantics),
    };
  }
  if (layer === "combined")
    throw new Error(
      "This client cannot read the combined source layer while preserving its named result. Open a supported raw or calculated view.",
    );
  if (view && layer === "calculated") {
    if (semantics !== "stored")
      throw new Error(
        "A named calculated result supports Stored values only. Own and effective reads do not identify that result.",
      );
    const members = exactScalarMembers(view.selection);
    if (!members)
      throw new Error(
        "The calculated-result read supports one member per dimension. This view's set or exclusion selection cannot be read exactly by this client.",
      );
    if (!view.dataSource.resultKey)
      throw new Error("The calculated view has no named result.");
    return {
      kind: "calculated",
      function: "facts.calculation.scan",
      resultKey: view.dataSource.resultKey,
      members,
      label: canonicalGridReadLabel(view.dataSource, semantics),
    };
  }
  if (semantics === "stored") {
    const members = view ? exactScalarMembers(view.selection) : pov;
    if (!members || (!view && hasNativeSelection))
      throw new Error(
        "Stored reads cannot represent this member selection. Choose Own input to read the exact raw selection.",
      );
    return {
      kind: "stored",
      function: "facts.cube.scan",
      members,
      label: "Stored raw values",
    };
  }
  if (semantics === "own")
    return {
      kind: "resolved",
      function: "facts.cube.resolved.read",
      source: { semantics: "own" },
      label: "Own input at each member",
    };
  if (layer === "raw")
    throw new Error(
      "This saved view declares raw input. An effective binding may include calculated values and cannot replace that source layer.",
    );
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(bindingId) ||
    !/^[0-9a-f]{64}$/.test(bindingStateToken)
  )
    throw new Error("Choose a current active binding for the effective read.");
  return {
    kind: "resolved",
    function: "facts.cube.resolved.read",
    source: {
      semantics: "effective",
      bindingId,
      bindingStateToken,
      hierarchies: [],
    },
    label: `Effective governed value · binding ${bindingId}`,
  };
}

export function gridLayoutSummary(
  layout: GridLayout,
  dimensions: ReadonlyArray<{ dimension_id: string; name: string }>,
) {
  return (["rows", "columns", "pages", "filters"] as const).map((key) => {
    const ids = layout[key];
    const names = ids.map(
      (id) =>
        dimensions.find((dimension) => dimension.dimension_id === id)?.name ||
        id,
    );
    return {
      key,
      label: key[0].toUpperCase() + key.slice(1),
      text: ids.length
        ? `${ids.length} ${ids.length === 1 ? "axis" : "axes"} · ${names.join(" / ")}`
        : "None",
    };
  });
}
