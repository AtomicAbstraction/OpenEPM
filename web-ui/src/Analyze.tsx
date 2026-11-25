import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
} from "react";
import {
  ApiError,
  isApplicationAccessDenied,
  readProgram,
  request,
  requestAdmittedEffect,
} from "./api";
import {
  canCopyScenario,
  ScenarioPromotion,
  type ScenarioPromotionControl,
} from "./ScenarioPromotion";
import {
  isComparisonUnit,
  SCENARIO_COMPARISON,
  ScenarioComparison,
} from "./ScenarioComparison";
import {
  ExactMutationOutcome,
  useExactCellMutation,
} from "./exact-cell-mutation";
import type { ApplicationCatalog, ApplicationSummary, Scope } from "./types";
import type { AnalyticalRead, SavedViewContext } from "./reference-handoff";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { gridCoordinateKey, useGridFocus } from "./grid-focus";
import { collectAllContinuations } from "./continuation";
import { activeFactDimensions } from "./metadata-data";
import { MemberSelectionDialog } from "./member-selection/MemberSelectionDialog";
import {
  canonicalCubeSelection,
  explicitMemberIds,
  type CubeSelection,
  type CubeSelector,
} from "./member-selection/selection-types";
import { selectorSummary } from "./member-selection/selection-summary";
import { scalarPovFromCubeSelection } from "./member-selection/selection-adapter";
import {
  canonicalGridReadLabel,
  gridLayoutSummary,
  gridReadPlan,
  type GridReadPlan,
  type GridReadSemantics,
} from "./grid-read-contract";
import "./data-workspaces.css";

type Dimension = {
  dimension_id: string;
  name: string;
  model_role: string;
  status: string;
};

type Member = { member_id: string; name: string; status: string };

type ResolvedCubeRow = {
  members: Record<string, string>;
  present: boolean;
  value: string | null;
  resultUnit: string;
  origin: string;
  currentness: string;
  resultStateToken: string | null;
  lineage: unknown[];
};

type ResolvedCubePage = {
  rows: ResolvedCubeRow[];
  snapshot: { commitRevision: number };
  stages: Array<{
    stage: "input" | "materialized";
    sourceDigest: string;
    resolutionDigest?: string;
    currentness: "current" | "stale";
    definitions?: Array<{
      stageId: string;
      resultStateToken: string;
      presence: "empty" | "present";
      definitionStatus: string;
    }>;
  }>;
  presentation: {
    pageSize: number;
    suppression: { missing: boolean; zero: boolean };
    rowCount: number;
  };
};

type ResolvedReadStatus = "current" | "current-empty";
type CubeLayerValue = {
  present: boolean;
  value: string | null;
  unit: string | Record<string, unknown> | null;
  origin: string;
  currentness: string;
  resultStateToken: string | null;
};
type CubeViewReadPage = {
  format: "openepm-cube-view-read-v1";
  dataSource: SavedGridDefinition["dataSource"];
  readPolicy: { semantics: "stored" | "own" };
  rows: Array<{
    members: Record<string, string>;
    values: Partial<Record<"raw" | "calculated", CubeLayerValue[]>>;
  }>;
  snapshot: { commitRevision: number };
  complete: boolean;
  presentation: { pageSize: number; rowCount: number };
  calculation?: {
    resultKey: string;
    resultStateToken: string;
    inputRevisionStatus: { matchesAtRead: boolean };
  };
};

export function layerValueText(value: CubeLayerValue) {
  if (!value.present) return "Missing";
  const unit =
    typeof value.unit === "object" && value.unit
      ? value.unit.memberId || value.unit.type || ""
      : "";
  return `${value.unit === "text" && value.value === "" ? "Empty text" : value.value}${unit ? ` ${unit}` : ""}`;
}

export function cubeViewRowsToCells(page: CubeViewReadPage): CubeCell[] {
  return page.rows.map((row) => {
    const layers = Object.entries(row.values) as Array<
      ["raw" | "calculated", CubeLayerValue[]]
    >;
    const single =
      layers.length === 1 && layers[0][1].length === 1 ? layers[0][1][0] : null;
    const text = single?.unit === "text" || !single;
    return {
      members: row.members,
      kind: text ? "text" : "numeric",
      ...(text
        ? {
            text: single
              ? single.value
              : layers
                  .map(
                    ([layer, values]) =>
                      `${layer === "raw" ? "Raw" : "Calculated"}: ${values.map(layerValueText).join(" / ")}`,
                  )
                  .join(" · "),
          }
        : { amount: single?.value }),
      lastRevision: page.snapshot.commitRevision,
      resultUnit: typeof single?.unit === "string" ? single.unit : undefined,
      origin: single?.origin,
      currentness: single?.currentness,
      resultStateToken: single?.resultStateToken,
      layerValues: row.values,
    };
  });
}

export function resolvedReadStatus(page: ResolvedCubePage): ResolvedReadStatus {
  const materializedDefinitions = page.stages.flatMap((stage) =>
    stage.stage === "materialized" ? stage.definitions || [] : [],
  );
  const certifiedEmpty =
    page.stages.length > 0 &&
    page.stages.every((stage) => stage.currentness === "current") &&
    materializedDefinitions.length > 0 &&
    materializedDefinitions.every(
      (definition) => definition.presence === "empty",
    ) &&
    page.rows.every((row) => !row.present);
  return certifiedEmpty ? "current-empty" : "current";
}

export function resolvedRowsToCells(page: ResolvedCubePage): CubeCell[] {
  return page.rows.map((row) => ({
    members: row.members,
    ...(row.resultUnit === "text"
      ? { kind: "text" as const, text: row.present ? row.value : null }
      : { kind: "numeric" as const, amount: row.present ? row.value : null }),
    lastRevision: page.snapshot.commitRevision,
    resultUnit: row.resultUnit,
    origin: row.origin,
    currentness: row.currentness,
    resultStateToken: row.resultStateToken,
    lineage: row.lineage,
  }));
}

function gridMemberComparator(
  dimensions: readonly string[],
  members: Record<string, Member[]>,
  selectorFor: (dimensionId: string) => CubeSelector | null,
) {
  const ranks = dimensions.map((dimension) => {
    const selected = explicitMemberIds(selectorFor(dimension));
    const order = selected.length
      ? selected
      : (members[dimension] || []).map((member) => member.member_id);
    return new Map(order.map((id, index) => [id, index]));
  });
  return (left: readonly string[], right: readonly string[]) => {
    for (let index = 0; index < dimensions.length; index += 1) {
      const a = ranks[index].get(left[index]) ?? Number.MAX_SAFE_INTEGER;
      const b = ranks[index].get(right[index]) ?? Number.MAX_SAFE_INTEGER;
      if (a !== b) return a - b;
      const fallback = String(left[index]).localeCompare(String(right[index]));
      if (fallback) return fallback;
    }
    return 0;
  };
}

export function resolvedPageCells(
  cells: CubeCell[],
  pageSize: number,
  offset: number,
): CubeCell[] {
  return cells.slice(offset, offset + pageSize);
}

export function hasResolvedNextPage(
  cells: CubeCell[],
  pageSize: number,
  offset: number,
): boolean {
  return offset + pageSize < cells.length;
}

type ResolvedBinding = {
  bindingId: string;
  stateToken: string;
  bindingDigest: string;
  stages: Array<{ stageId: string; kind: string }>;
};

export type CubeCell = {
  members: Record<string, string>;
  kind: "numeric" | "text";
  amount?: string | null;
  text?: string | null;
  changeId?: string;
  numericChangeId?: string;
  textChangeId?: string;
  lastRevision?: number;
  resultUnit?: string;
  origin?: string;
  currentness?: string;
  resultStateToken?: string | null;
  lineage?: unknown[];
  layerValues?: Partial<Record<"raw" | "calculated", CubeLayerValue[]>>;
};

type CubePage = {
  rows: CubeCell[];
  nextCursor?: string | null;
  snapshotRevision?: number;
  source?: string;
  resultKey?: string;
  resultStateToken?: string;
  inputRevisionStatus?: { matchesAtRead?: boolean };
  aggregateContext?: { accountingPolicyStatus?: string };
  contributionContext?: { accountingPolicyStatus?: string };
};

type CellEditability = {
  editable: boolean;
  reasonCode: string;
  message: string;
  policy?: unknown;
};

type SavedGridDefinition = {
  format: "openepm-cube-view-v1";
  viewId: string;
  name: string;
  selection: CubeSelection;
  layout: {
    pages: string[];
    rows: string[];
    columns: string[];
    filters: string[];
  };
  dataSource: {
    kind: "raw" | "calculated" | "combined";
    resultKey: string | null;
  };
  suppression: { missing: boolean; zero: boolean };
  pageSize: number;
};

const layoutRoles = ["rows", "columns", "pages", "filters"] as const;
type LayoutRole = (typeof layoutRoles)[number];
const layoutRoleLabels: Record<LayoutRole, string> = {
  rows: "Rows",
  columns: "Columns",
  pages: "Pages",
  filters: "Filters",
};

function swapPrimaryAxis(
  layout: SavedGridDefinition["layout"],
  role: "rows" | "columns",
  dimensionId: string,
) {
  const origin = layoutRoles.find((key) => layout[key].includes(dimensionId));
  if (!origin || !layout[role].length || layout[role][0] === dimensionId)
    return layout;
  const next = structuredClone(layout);
  const index = next[origin].indexOf(dimensionId);
  next[origin][index] = next[role][0];
  next[role][0] = dimensionId;
  return next;
}

type SavedGrid = {
  gridId: string;
  stateToken: string;
  name: string;
  definition: SavedGridDefinition;
  metadataRevision: number;
  canonicalDigest: string;
};

type AggregateMeasure =
  | "SumAmount"
  | "CountPresent"
  | "MinAmount"
  | "MaxAmount";

type AggregateRow = {
  members: Record<string, string>;
  sumAmount?: string | null;
  countPresent?: string | null;
  minAmount?: string | null;
  maxAmount?: string | null;
};

type AggregateResult = {
  queryId: string;
  status: string;
  errorCode?: string;
  rows?: AggregateRow[];
  nextCursor?: string | null;
  technicalCertificate?: unknown;
};

type AggregateQueryState = {
  owner: string;
  queryId: string;
  query: ReturnType<typeof aggregateQueryIntent>;
  pageSize: number;
  context: string;
  status: string;
  errorCode?: string;
  rows: AggregateRow[];
  cursor: string | null;
  stateRead: boolean;
};

const aggregateMeasureLabels: Record<AggregateMeasure, string> = {
  SumAmount: "Sum",
  CountPresent: "Count present",
  MinAmount: "Minimum",
  MaxAmount: "Maximum",
};

type AnalyzePresentation = "grid" | "kpi" | "chart" | "generic";

type GenericTable = {
  table_id: string;
  name: string;
  status: string;
  short_description?: string;
  semantic_definition?: string;
};

type GenericFactRow = {
  series_key: string;
  value: unknown;
  change_id: string;
  last_revision: number;
};

type GenericFactPage = {
  rows: GenericFactRow[];
  nextCursor?: string | null;
  snapshotRevision: number;
};

type GenericTablePage = {
  rows: GenericTable[];
  nextAfterTableId: string | null;
};

type DimensionPage = {
  rows: Dimension[];
  nextAfterDimensionId: string | null;
  metadataRevision: number;
};

type MemberPage = {
  rows: Member[];
  nextAfterMemberId: string | null;
  metadataRevision: number;
};

export function gridDensityStorageKey(
  subject: string,
  workspaceId: string,
  applicationId: string,
) {
  return `openepm:grid-density:${encodeURIComponent(subject)}:${encodeURIComponent(workspaceId)}:${encodeURIComponent(applicationId)}`;
}

function readGridDensity(key: string): "comfortable" | "compact" {
  if (!key) return "comfortable";
  try {
    return localStorage.getItem(key) === "compact" ? "compact" : "comfortable";
  } catch {
    return "comfortable";
  }
}

export function buildScanArguments(
  members: Record<string, string>,
  limit: number,
  cursor?: string | null,
  suppression: { missing: boolean; zero: boolean } = {
    missing: true,
    zero: false,
  },
) {
  return cursor
    ? { cursor }
    : {
        members,
        limit,
        includeMissing: !suppression.missing,
        includeZero: !suppression.zero,
      };
}

export function resolvedGridProgram(
  dimensions: Dimension[],
  members: Record<string, Member[]>,
  pov: Record<string, string>,
  metadataRevision: number,
  source:
    | { semantics: "own" }
    | {
        semantics: "effective";
        bindingId: string;
        bindingStateToken: string;
        hierarchies: never[];
      },
  savedSelection?: unknown,
  presentation: {
    pageSize: number;
    suppression: { missing: boolean; zero: boolean };
  } = { pageSize: 100, suppression: { missing: false, zero: false } },
  dimensionSelectors: Record<string, CubeSelector> = {},
) {
  const selection: CubeSelection = savedSelection
    ? (canonicalCubeSelection(savedSelection), savedSelection as CubeSelection)
    : {
        format: "openepm-cube-selection-v1",
        metadataRevision,
        dimensions: dimensions.map((dimension) => ({
          dimensionId: dimension.dimension_id,
          include:
            dimensionSelectors[dimension.dimension_id] ||
            (pov[dimension.dimension_id]
              ? { kind: "member", memberId: pov[dimension.dimension_id] }
              : {
                  kind: "members",
                  memberIds: (members[dimension.dimension_id] || []).map(
                    (member) => member.member_id,
                  ),
                }),
          exclude: null,
        })),
      };
  return {
    languageVersion: 2,
    function: "facts.cube.resolved.read",
    arguments: {
      format: "openepm-resolved-cube-read-v1",
      selection,
      source,
      outputGrain: dimensions.map((dimension) => dimension.dimension_id),
      freshness: "current",
      // A normal current read must never silently substitute a dynamic
      // calculation for a stale governed result. The server returns
      // CALCULATION_REQUIRED and the user can run the declared workflow.
      dynamicFallback: false,
      delivery: "direct",
      presentation,
      limits: { maxRows: 500, maxSourceRows: 100_000, timeoutMs: 30_000 },
    },
  };
}

export function genericTableListArguments(afterTableId?: string | null) {
  return { afterTableId: afterTableId ?? null, limit: 100 };
}

export function genericSnapshotArguments(
  tableId: string,
  cursor?: string | null,
) {
  return { tableId, cursor: cursor ?? null, limit: 100 };
}

export function genericValueText(value: unknown) {
  try {
    const rendered = JSON.stringify(value);
    return rendered === undefined ? "null" : rendered;
  } catch {
    return "Unrenderable value";
  }
}

export function savedGridListArguments(
  afterGridId?: string | null,
  expectedCollectionToken?: string,
) {
  return afterGridId
    ? { limit: 100, afterGridId, expectedCollectionToken }
    : { limit: 100 };
}

export function collectAnalyzeDimensions(
  readPage: (
    cursor: string | null,
    revision?: number,
  ) => Promise<DimensionPage>,
) {
  let revision: number | undefined;
  return collectAllContinuations<DimensionPage, Dimension>({
    label: "Analyze dimensions",
    readPage: async (cursor) => {
      const page = await readPage(cursor, revision);
      revision = page.metadataRevision;
      return page;
    },
    rows: (page) => page.rows,
    nextCursor: (page) => page.nextAfterDimensionId,
    rowIdentity: (row) => row.dimension_id,
    consistencyIdentity: (page) => page.metadataRevision,
  });
}

export function collectAnalyzeMembers(
  readPage: (cursor: string | null, revision?: number) => Promise<MemberPage>,
) {
  let revision: number | undefined;
  return collectAllContinuations<MemberPage, Member>({
    label: "Analyze members",
    readPage: async (cursor) => {
      const page = await readPage(cursor, revision);
      revision = page.metadataRevision;
      return page;
    },
    rows: (page) => page.rows,
    nextCursor: (page) => page.nextAfterMemberId,
    rowIdentity: (row) => row.member_id,
    consistencyIdentity: (page) => page.metadataRevision,
  });
}

export function collectGenericTables(
  readPage: (cursor: string | null) => Promise<GenericTablePage>,
) {
  return collectAllContinuations<GenericTablePage, GenericTable>({
    label: "Generic fact tables",
    readPage,
    rows: (page) => page.rows,
    nextCursor: (page) => page.nextAfterTableId,
    rowIdentity: (row) => row.table_id,
  });
}

type SavedGridPage = {
  grids: SavedGrid[];
  nextAfterGridId: string | null;
  collectionToken: string;
};

export function collectSavedGrids(
  readPage: (cursor: string | null) => Promise<SavedGridPage>,
) {
  return collectAllContinuations<SavedGridPage, SavedGrid>({
    label: "Saved grids",
    readPage,
    rows: (page) => page.grids,
    nextCursor: (page) => page.nextAfterGridId,
    rowIdentity: (row) => row.gridId,
    consistencyIdentity: (page) => page.collectionToken,
  });
}

export function savedGridSaveProgram(
  gridId: string,
  definition: SavedGridDefinition,
  expectedMetadataRevision: number,
  expectedStateToken?: string,
) {
  return {
    languageVersion: 2,
    function: "grid.definition.save",
    arguments: {
      gridId,
      definition,
      expectedMetadataRevision,
      ...(expectedStateToken ? { expectedStateToken } : {}),
    },
  };
}

export function savedGridDeleteProgram(
  gridId: string,
  expectedStateToken: string,
) {
  return {
    languageVersion: 2,
    function: "grid.definition.delete",
    arguments: { gridId, expectedStateToken },
  };
}

export function canOpenSavedGrid(grid: SavedGrid) {
  const definition = grid.definition;
  if (
    !definition ||
    !definition.layout ||
    !definition.selection ||
    !definition.dataSource ||
    !definition.suppression ||
    !Array.isArray(definition.layout.pages) ||
    !Array.isArray(definition.layout.rows) ||
    !Array.isArray(definition.layout.columns) ||
    !Array.isArray(definition.layout.filters) ||
    !Array.isArray(definition.selection.dimensions) ||
    definition.selection.dimensions.some(
      (item) =>
        !item ||
        typeof item.dimensionId !== "string" ||
        !item.dimensionId ||
        !item.include ||
        typeof item.include.kind !== "string",
    ) ||
    typeof definition.suppression.missing !== "boolean" ||
    typeof definition.suppression.zero !== "boolean"
  )
    return false;
  const placed = [
    ...definition.layout.pages,
    ...definition.layout.rows,
    ...definition.layout.columns,
    ...definition.layout.filters,
  ];
  const selected = definition.selection.dimensions.map(
    (item) => item.dimensionId,
  );
  try {
    canonicalCubeSelection(definition.selection, selected);
  } catch {
    return false;
  }
  return Boolean(
    definition.format === "openepm-cube-view-v1" &&
      ["raw", "calculated", "combined"].includes(definition.dataSource.kind) &&
      definition.viewId === grid.gridId &&
      definition.name === grid.name &&
      definition.selection.format === "openepm-cube-selection-v1" &&
      definition.selection.metadataRevision === grid.metadataRevision &&
      definition.layout.rows.length &&
      definition.layout.columns.length &&
      placed.length === selected.length &&
      new Set(placed).size === placed.length &&
      new Set(selected).size === selected.length &&
      placed.every((dimension) => selected.includes(dimension)) &&
      Number.isInteger(definition.pageSize) &&
      definition.pageSize >= 1 &&
      definition.pageSize <= 500 &&
      (definition.dataSource.kind === "raw"
        ? definition.dataSource.resultKey === null
        : Boolean(definition.dataSource.resultKey?.trim())),
  );
}

function savedGridPointOfView(definition: SavedGridDefinition) {
  return scalarPovFromCubeSelection(definition.selection, [
    ...definition.layout.pages,
    ...definition.layout.filters,
  ]);
}

export function currentSavedGridDefinition(
  gridId: string,
  name: string,
  dimensions: Dimension[],
  members: Record<string, Member[]>,
  metadataRevision: number,
  rows: string[],
  columns: string[],
  pov: Record<string, string>,
  dimensionSelectors: Record<string, CubeSelector> = {},
): SavedGridDefinition {
  return {
    format: "openepm-cube-view-v1",
    viewId: gridId,
    name,
    selection: {
      format: "openepm-cube-selection-v1",
      metadataRevision,
      dimensions: dimensions.map((dimension) => ({
        dimensionId: dimension.dimension_id,
        include:
          dimensionSelectors[dimension.dimension_id] ||
          (pov[dimension.dimension_id]
            ? { kind: "member", memberId: pov[dimension.dimension_id] }
            : {
                kind: "members",
                memberIds: (members[dimension.dimension_id] || []).map(
                  (member) => member.member_id,
                ),
              }),
        exclude: null,
      })),
    },
    layout: {
      pages: [],
      rows: [...rows],
      columns: [...columns],
      filters: dimensions
        .map((dimension) => dimension.dimension_id)
        .filter(
          (dimension) =>
            !rows.includes(dimension) && !columns.includes(dimension),
        ),
    },
    dataSource: { kind: "raw", resultKey: null },
    suppression: { missing: false, zero: false },
    pageSize: 100,
  };
}

export function aggregateQueryIntent(
  dimensions: Array<Pick<Dimension, "dimension_id" | "model_role">>,
  rowDimension: string,
  columnDimension: string,
  pov: Record<string, string>,
  measures: AggregateMeasure[],
) {
  const input = dimensions.filter(
    (dimension) => dimension.model_role !== "Currency",
  );
  const inputDimensions = input.map((dimension) => dimension.dimension_id);
  const groupBy = [rowDimension, columnDimension].filter(Boolean);
  if (
    groupBy.length !== 2 ||
    new Set(groupBy).size !== groupBy.length ||
    groupBy.some((dimension) => !inputDimensions.includes(dimension))
  )
    throw new Error("Choose two distinct non-currency aggregate axes.");
  if (
    Object.keys(pov).some(
      (dimension) =>
        !inputDimensions.includes(dimension) || groupBy.includes(dimension),
    )
  )
    throw new Error("Each aggregate POV must fix a non-axis fact dimension.");
  const remaining = input.filter(
    (dimension) =>
      !groupBy.includes(dimension.dimension_id) &&
      !Object.hasOwn(pov, dimension.dimension_id),
  );
  const unsafe = remaining.filter(
    (dimension) => dimension.model_role && dimension.model_role !== "Custom",
  );
  if (unsafe.length)
    throw new Error(
      `Fix non-custom dimensions before reduction: ${unsafe.map((item) => item.dimension_id).join(", ")}.`,
    );
  if (!measures.length)
    throw new Error("Choose at least one aggregate measure.");
  const uniqueMeasures = [...new Set(measures)];
  return {
    source: "raw_numeric",
    grain: {
      inputDimensions,
      groupBy,
      reduceDimensions: remaining.map((dimension) => dimension.dimension_id),
    },
    selectors: Object.fromEntries(
      Object.entries(pov).map(([dimension, member]) => [
        dimension,
        { kind: "Members", memberIds: [member] },
      ]),
    ),
    measures: uniqueMeasures.map((kind) => ({ kind })),
    missing: "exclude",
    aggregation: uniqueMeasures.some((kind) =>
      ["MinAmount", "MaxAmount"].includes(kind),
    )
      ? "unique_coordinate_reduction"
      : "unique_coordinate_sum",
  };
}

export function aggregateRequestProgram(
  query: ReturnType<typeof aggregateQueryIntent>,
  pageSize: number,
) {
  return {
    languageVersion: 2,
    function: "facts.cube.aggregate.request",
    arguments: { query, limits: { pageSize } },
  };
}

export function aggregateReadProgram(
  queryId: string,
  pageSize: number,
  cursor?: string | null,
) {
  return {
    languageVersion: 2,
    function: "facts.cube.aggregate.read",
    arguments: { queryId, pageSize, ...(cursor ? { cursor } : {}) },
  };
}

export function buildWritebackProgram(
  kind: "numeric" | "text",
  operation: "set" | "add" | "clear",
  coordinate: Record<string, string>,
  value: string,
  expectedChangeId: string,
) {
  const mutation: Record<string, unknown> = {
    coordinate,
    op: operation,
    expectedChangeId,
  };
  if (operation !== "clear")
    mutation.value =
      kind === "numeric"
        ? { type: "AmountLiteral", decimal: value }
        : { type: "TextLiteral", text: value };
  return {
    languageVersion: 2,
    function: kind === "numeric" ? "facts.numeric.batch" : "facts.text.batch",
    arguments: { mutations: [mutation] },
  };
}

export function gridKeyTarget(
  key: string,
  row: number,
  column: number,
  rowCount: number,
  columnCount: number,
) {
  const next = { row, column };
  if (key === "ArrowUp") next.row = Math.max(0, row - 1);
  else if (key === "ArrowDown") next.row = Math.min(rowCount - 1, row + 1);
  else if (key === "ArrowLeft") next.column = Math.max(0, column - 1);
  else if (key === "ArrowRight")
    next.column = Math.min(columnCount - 1, column + 1);
  else if (key === "Home") next.column = 0;
  else if (key === "End") next.column = Math.max(0, columnCount - 1);
  else return null;
  return next;
}

function moveGridFocus(
  event: KeyboardEvent<HTMLButtonElement>,
  row: number,
  column: number,
  rowCount: number,
  columnCount: number,
  announce: (label: string) => void,
) {
  const target = gridKeyTarget(event.key, row, column, rowCount, columnCount);
  if (!target) return;
  event.preventDefault();
  const next = event.currentTarget
    .closest("table")
    ?.querySelector<HTMLButtonElement>(
      `[data-grid-row="${target.row}"][data-grid-column="${target.column}"]`,
    );
  if (!next || next === event.currentTarget) return;
  next.focus();
  const label = next.getAttribute("aria-label");
  if (label && document.activeElement === next) announce(label);
}

async function readAllDimensions(scope: Scope, signal: AbortSignal) {
  const collected = await collectAnalyzeDimensions(
    (afterDimensionId, expectedMetadataRevision) =>
      readProgram(
        scope,
        "metadata.dimension.list",
        {
          limit: 100,
          ...(afterDimensionId
            ? { afterDimensionId, expectedMetadataRevision }
            : {}),
        },
        signal,
      ),
  );
  return {
    rows: activeFactDimensions(collected.rows),
    metadataRevision: collected.finalPage.metadataRevision,
  };
}

async function readAllMembers(
  scope: Scope,
  dimension: string,
  revision: number,
  signal?: AbortSignal,
) {
  const collected = await collectAnalyzeMembers(
    (afterMemberId, expectedMetadataRevision) => {
      if (signal?.aborted)
        throw new DOMException("Member read cancelled", "AbortError");
      return readProgram(
        scope,
        "metadata.member.list",
        {
          dimension,
          limit: 100,
          expectedMetadataRevision: expectedMetadataRevision ?? revision,
          ...(afterMemberId ? { afterMemberId } : {}),
        },
        signal,
      );
    },
  );
  if (collected.finalPage.metadataRevision !== revision)
    throw new Error("Member metadata changed. Refresh the grid and try again.");
  return collected.rows.filter((item) => item.status === "Active");
}

export function cellValue(cell?: CubeCell) {
  if (!cell) return "—";
  if (cell.kind === "numeric") return cell.amount ?? "—";
  if (cell.text === null || cell.text === undefined) return "—";
  return cell.text === "" ? "“”" : cell.text;
}

export function cellClass(cell?: CubeCell) {
  if (!cell) return "missing";
  if (cell.kind === "text" && cell.text === "") return "empty-text";
  if (cell.kind === "numeric" && /^[-+]?0(?:\.0+)?$/.test(cell.amount || ""))
    return "zero";
  return cell.kind === "text" ? "text" : "numeric";
}

export function cellPresence(cell: CubeCell) {
  if (
    cell.layerValues &&
    (Object.keys(cell.layerValues).length > 1 ||
      Object.values(cell.layerValues).some(
        (values) => (values?.length || 0) > 1,
      ))
  )
    return "Separate source values";
  if (cell.kind === "text") {
    if (typeof cell.text !== "string") return "Missing";
    return cell.text === "" ? "Present empty text" : "Present text";
  }
  if (typeof cell.amount !== "string" || cell.amount === "") return "Missing";
  return /^[-+]?0(?:\.0+)?$/.test(cell.amount)
    ? "Present numeric zero"
    : "Present numeric";
}

function cellAccessibleName(members: Record<string, string>, cell?: CubeCell) {
  const coordinate = Object.entries(members)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([dimension, member]) => `${dimension} ${member}`)
    .join(", ");
  const presence = cell ? cellPresence(cell) : "Missing";
  const value =
    presence === "Missing" || presence === "Present empty text"
      ? presence
      : presence === "Present text"
        ? `Text ${cellValue(cell)}`
        : cellValue(cell);
  return `${coordinate}. ${value}`;
}

export function Analyze({
  app,
  catalog,
  index,
  subject,
  targetViewId,
  targetViewDigest,
  targetAnalyticalRead,
  interactionBlocked = false,
  onViewContextChange,
  onRefreshCatalog,
  onRequestTransition = (action) => action(),
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  index: number;
  subject: string;
  targetViewId?: string;
  targetViewDigest?: string;
  targetAnalyticalRead?: AnalyticalRead;
  interactionBlocked?: boolean;
  onViewContextChange?: (context: SavedViewContext | null) => void;
  onRefreshCatalog?: () => Promise<ApplicationCatalog>;
  onRequestTransition?: (action: () => void) => void;
}) {
  const scope = app
    ? { workspaceId: app.workspaceId, applicationId: app.applicationId }
    : null;
  const catalogueContext = JSON.stringify([
    app?.workspaceId,
    app?.applicationId,
    subject,
    catalog?.accessContext,
    catalog?.applicationAccess,
    catalog?.revisions.metadata,
    catalog?.revisions.policy,
    catalog?.revisions.security,
    catalog?.revisions.schemaEpoch,
    Object.keys(catalog?.functions || {}).sort(),
  ]);
  const currentCatalogueContext = useRef(catalogueContext);
  currentCatalogueContext.current = catalogueContext;
  const scenarioCopyControl = useRef<ScenarioPromotionControl>(null);
  const [metadataSnapshot, setMetadataSnapshot] = useState<{
    context: string;
    rows: Dimension[];
    metadataRevision: number;
  } | null>(null);
  const dimensions =
    metadataSnapshot?.context === catalogueContext ? metadataSnapshot.rows : [];
  const metadataRevision =
    metadataSnapshot?.context === catalogueContext
      ? metadataSnapshot.metadataRevision
      : null;
  const [rowDimension, setRowDimension] = useState("");
  const [columnDimension, setColumnDimension] = useState("");
  const [layoutOpen, setLayoutOpen] = useState(false);
  const [pov, setPov] = useState<Record<string, string>>({});
  const [povDialogDimensionId, setPovDialogDimensionId] = useState("");
  const [axisDialogDimensionId, setAxisDialogDimensionId] = useState("");
  const [axisSelections, setAxisSelections] = useState<
    Record<string, CubeSelector>
  >({});
  const [axisSelectionSummaries, setAxisSelectionSummaries] = useState<
    Record<string, string>
  >({});
  const memberContext = JSON.stringify([
    catalogueContext,
    app?.workspaceId,
    app?.applicationId,
    subject,
    metadataRevision,
    catalog?.revisions.metadata,
    catalog?.revisions.policy,
    catalog?.revisions.security,
    catalog?.applicationAccess.role,
  ]);
  const memberContextRef = useRef(memberContext);
  memberContextRef.current = memberContext;
  const [memberCache, setMemberCache] = useState<{
    context: string;
    rows: Record<string, Member[]>;
  } | null>(null);
  const memberCatalog = useMemo(
    () => (memberCache?.context === memberContext ? memberCache.rows : {}),
    [memberCache, memberContext],
  );
  const [rows, setRows] = useState<CubeCell[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [resolvedPage, setResolvedPage] = useState<{
    cells: CubeCell[];
    pageSize: number;
    offset: number;
  } | null>(null);
  const [source, setSource] = useState("");
  const [resolvedStatus, setResolvedStatus] =
    useState<ResolvedReadStatus | null>(null);
  // A loading catalogue is not evidence that the resolved read is unavailable.
  // Initialize once per application when discovery arrives; later refreshes
  // must preserve the selected policy, including an explicit unavailable one.
  const [selectedReadSemantics, setReadSemantics] =
    useState<GridReadSemantics | null>(null);
  const defaultReadSemantics: GridReadSemantics = catalog?.functions[
    "facts.cube.resolved.read"
  ]
    ? "own"
    : "stored";
  const readSemantics = selectedReadSemantics ?? defaultReadSemantics;
  const [completedRead, setCompletedRead] = useState<{
    context: string;
    plan: GridReadPlan;
  } | null>(null);
  const gridReadController = useRef<{
    context: string;
    controller: AbortController;
    pending: boolean;
  } | null>(null);
  const gridReadVersion = useRef(0);
  const layoutSuggestionController = useRef<{
    context: string;
    controller: AbortController;
  } | null>(null);
  const layoutSuggestionVersion = useRef(0);
  const [resolvedBindingId, setResolvedBindingId] = useState("");
  const [resolvedBindingStateToken, setResolvedBindingStateToken] =
    useState("");
  const [resolvedBindings, setResolvedBindings] = useState<ResolvedBinding[]>(
    [],
  );
  const [otherBusy, setBusy] = useState(false);
  const [cellReadBusy, setCellReadBusy] = useState(false);
  const [aggregatePending, setAggregatePending] = useState<{
    context: string;
    token: number;
    controller: AbortController;
  } | null>(null);
  const gridBusy = otherBusy || aggregatePending?.context === catalogueContext;
  const busy = gridBusy || cellReadBusy;
  const [errorRecord, setErrorRecord] = useState<{
    context: string;
    value: string;
  } | null>(null);
  const error =
    errorRecord?.context === catalogueContext ? errorRecord.value : "";
  const setError = (value: string) =>
    setErrorRecord({ context: catalogueContext, value });
  const [selectedCell, setSelectedCell] = useState<CubeCell | null>(null);
  const [cellInspectorOpening, setCellInspectorOpening] = useState(0);
  const cellInspectorHeading = useRef<HTMLHeadingElement | null>(null);
  const cellTrigger = useRef<HTMLButtonElement | null>(null);
  const cellReturn = useRef<HTMLButtonElement | null>(null);
  const cellReadVersion = useRef(0);
  const cellReadController = useRef<AbortController | null>(null);
  const activeScopeKey = `${app?.workspaceId || ""}:${app?.applicationId || ""}`;
  const activeScope = useRef(activeScopeKey);
  activeScope.current = activeScopeKey;
  useEffect(() => {
    cellInspectorHeading.current?.focus({
      preventScroll: window.innerWidth > 1240,
    });
  }, [cellInspectorOpening]);
  useEffect(
    () => () => {
      cellReadVersion.current += 1;
      cellReadController.current?.abort();
    },
    [activeScopeKey],
  );
  const [writeKind, setWriteKind] = useState<"numeric" | "text">("numeric");
  const [writeOperation, setWriteOperation] = useState<"set" | "add" | "clear">(
    "set",
  );
  const [writeValue, setWriteValue] = useState("");
  const [writeTouched, setWriteTouched] = useState(false);
  const [resolvedChangeIds, setResolvedChangeIds] = useState({
    numeric: "",
    text: "",
  });
  const expectedChangeId = resolvedChangeIds[writeKind];
  const [cellResolved, setCellResolved] = useState(false);
  const [cellEditability, setCellEditability] =
    useState<CellEditability | null>(null);
  const [reviewed, setReviewed] = useState(false);
  const [writeResult, setWriteResult] = useState("");
  const [inspectorSnapshot, setInspectorSnapshot] = useState<number | null>(
    null,
  );
  const [savedGrids, setSavedGrids] = useState<SavedGrid[]>([]);
  const [savedGridsRead, setSavedGridsRead] = useState(false);
  const [savedGridsLoading, setSavedGridsLoading] = useState(false);
  const [savedGridsError, setSavedGridsError] = useState("");
  const [savedGridsAccessFailed, setSavedGridsAccessFailed] = useState(false);
  const [savedGridsContext, setSavedGridsContext] = useState("");
  const canReadSavedGrids = Boolean(catalog?.functions["grid.definition.list"]);
  const savedGridReadKey = JSON.stringify([
    app?.workspaceId,
    app?.applicationId,
    catalog?.accessContext,
    catalog?.applicationAccess.issuer,
    subject,
    catalog?.revisions.metadata,
    catalog?.revisions.policy,
    catalog?.revisions.security,
    canReadSavedGrids,
  ]);
  const currentSavedGridReadKey = useRef(savedGridReadKey);
  currentSavedGridReadKey.current = savedGridReadKey;
  const savedGridReadController = useRef<AbortController | null>(null);
  const savedGridReadVersion = useRef(0);
  const currentSavedGrids =
    savedGridsContext === savedGridReadKey ? savedGrids : [];
  const currentSavedGridsRead =
    savedGridsContext === savedGridReadKey && savedGridsRead;
  const currentSavedGridsError =
    savedGridsContext === savedGridReadKey ? savedGridsError : "";
  const readingSavedGrids =
    canReadSavedGrids &&
    (savedGridsLoading || savedGridsContext !== savedGridReadKey);
  const [selectedSavedGrid, setSelectedSavedGrid] = useState("");
  const [savedGridId, setSavedGridId] = useState("");
  const [savedGridName, setSavedGridName] = useState("");
  const [savedGridTouched, setSavedGridTouched] = useState(false);
  const [savedGridResult, setSavedGridResult] = useState("");
  const viewMutationSequence = useRef(0);
  const pendingViewMutation = useRef<number | null>(null);
  useEffect(() => {
    // The departed authority's effect can still finish on the server. Release
    // its presentation lock without letting that callback settle a new request.
    if (pendingViewMutation.current !== null) {
      pendingViewMutation.current = null;
      setBusy(false);
    }
  }, [catalogueContext]);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      gridReadController.current?.controller.abort();
      gridReadController.current = null;
      layoutSuggestionController.current?.controller.abort();
      layoutSuggestionController.current = null;
    };
  }, []);
  const [openedGridDefinition, setOpenedGridDefinition] =
    useState<SavedGridDefinition | null>(null);
  const layoutControls = useRef(new Map<string, HTMLSelectElement>());
  const layoutFocus = useRef<{
    dimensionId: string;
    previous: Element | null;
  } | null>(null);
  useEffect(() => {
    const pending = layoutFocus.current;
    layoutFocus.current = null;
    if (
      pending &&
      (document.activeElement === document.body ||
        document.activeElement === pending.previous)
    )
      layoutControls.current.get(pending.dimensionId)?.focus();
  }, [openedGridDefinition?.layout]);
  const requestedViewContext = JSON.stringify({
    targetViewId,
    targetViewDigest,
    targetAnalyticalRead,
  });
  const [openedGridReference, setOpenedGridReference] = useState<{
    viewId: string;
    viewDigest: string;
    definition: string;
    authority: string;
    requestedContext: string;
  } | null>(null);
  const [calculationContext, setCalculationContext] = useState<{
    resultKey: string;
    resultStateToken: string;
    inputsMatch: boolean;
    accountingStatus?: string;
  } | null>(null);
  const [aggregateMeasures, setAggregateMeasures] = useState<
    AggregateMeasure[]
  >(["SumAmount", "CountPresent"]);
  const [aggregatePageSize, setAggregatePageSize] = useState(100);
  const [aggregateReviewedIntent, setAggregateReviewed] = useState<
    string | null
  >(null);
  const [aggregateQueryState, setAggregateQueryState] =
    useState<AggregateQueryState | null>(null);
  const aggregateOwner = JSON.stringify([
    app?.workspaceId,
    app?.applicationId,
    catalog?.applicationAccess.issuer,
    subject,
  ]);
  const aggregateQuery =
    aggregateQueryState?.owner === aggregateOwner ? aggregateQueryState : null;
  const aggregateObservation =
    aggregateQuery?.context === catalogueContext ? aggregateQuery : null;
  const aggregateQueryId = aggregateQuery?.queryId || "";
  const aggregateStatus = aggregateObservation?.status || "";
  const aggregateRows = aggregateObservation?.rows || [];
  const aggregateCursor = aggregateObservation?.cursor || null;
  const aggregateStateRead = aggregateObservation?.stateRead || false;
  const [aggregateCancelReviewed, setAggregateCancelReviewed] = useState(false);
  const aggregateRequestSequence = useRef(0);
  const pendingAggregateRequest = useRef<{
    context: string;
    token: number;
    controller: AbortController;
  } | null>(null);
  useEffect(() => {
    // Release only the departed authority's HTTP/presentation owner. This
    // does not cancel the durable query or issue another request to the server.
    if (currentCatalogueContext.current !== catalogueContext) return;
    const pending = pendingAggregateRequest.current;
    if (pending && pending.context !== catalogueContext) {
      pending.controller.abort();
      pendingAggregateRequest.current = null;
      setAggregatePending((current) => (current === pending ? null : current));
    }
    setAggregateReviewed(null);
    setAggregateCancelReviewed(false);
  }, [catalogueContext]);
  useEffect(
    () => () => {
      pendingAggregateRequest.current?.controller.abort();
      pendingAggregateRequest.current = null;
    },
    [],
  );
  const [presentation, setPresentation] = useState<AnalyzePresentation>("grid");
  const densityStorageKey =
    app && subject
      ? gridDensityStorageKey(subject, app.workspaceId, app.applicationId)
      : "";
  const [gridDensity, setGridDensity] = useState<"comfortable" | "compact">(
    () => readGridDensity(densityStorageKey),
  );
  const [genericState, setGenericState] = useState<{
    context: string;
    tables: GenericTable[];
    tableId: string;
    rows: GenericFactRow[];
    cursor: string | null;
    snapshot: number | null;
  } | null>(null);
  const currentGenericState =
    genericState?.context === catalogueContext ? genericState : null;
  const genericTables = currentGenericState?.tables || [];
  const selectedGenericTable = currentGenericState?.tableId || "";
  const genericRows = currentGenericState?.rows || [];
  const genericCursor = currentGenericState?.cursor || null;
  const genericSnapshot = currentGenericState?.snapshot ?? null;
  const genericReadContext = JSON.stringify([
    catalogueContext,
    presentation,
    selectedGenericTable,
  ]);
  const currentGenericReadContext = useRef(genericReadContext);
  currentGenericReadContext.current = genericReadContext;
  const genericReadController = useRef<{
    context: string;
    controller: AbortController;
  } | null>(null);
  const genericReadVersion = useRef(0);
  function cancelGenericRead(expectedContext?: string) {
    const pending = genericReadController.current;
    if (expectedContext !== undefined && pending?.context !== expectedContext)
      return;
    genericReadVersion.current += 1;
    if (pending) {
      pending.controller.abort();
      genericReadController.current = null;
      setBusy(false);
    }
  }
  function choosePresentation(next: AnalyzePresentation) {
    cancelGenericRead();
    setPresentation(next);
  }
  useEffect(() => {
    const pending = genericReadController.current;
    if (
      currentGenericReadContext.current === genericReadContext &&
      pending &&
      pending.context !== genericReadContext
    )
      cancelGenericRead(pending.context);
    // A current read can start as the new table is committed, before the
    // previous context's passive cleanup. Cancel only that departed owner.
    return () => cancelGenericRead(genericReadContext);
  }, [genericReadContext]);
  const mutationIntentKey = useStableMutationIntentKey("grid-ui");
  useUnsavedWork(
    `analyze:${app?.workspaceId || "none"}:${app?.applicationId || "none"}`,
    "Unsaved grid writeback or definition",
    Boolean((selectedCell && writeTouched) || savedGridTouched),
  );
  useEffect(() => {
    setGridDensity(readGridDensity(densityStorageKey));
  }, [densityStorageKey]);

  function toggleGridDensity() {
    const next = gridDensity === "compact" ? "comfortable" : "compact";
    setGridDensity(next);
    if (!densityStorageKey) return;
    try {
      localStorage.setItem(densityStorageKey, next);
    } catch {
      // A display preference must never block the governed grid.
    }
  }

  useEffect(() => {
    setMetadataSnapshot(null);
    setRows([]);
    setRowDimension("");
    setColumnDimension("");
    setMemberCache(null);
    setSource("");
    setResolvedStatus(null);
    setReadSemantics(null);
    setResolvedBindingId("");
    setResolvedBindingStateToken("");
    setResolvedBindings([]);
    setNextCursor(null);
    setResolvedPage(null);
    setSelectedCell(null);
    setWriteValue("");
    setWriteTouched(false);
    setReviewed(false);
    setWriteResult("");
    setResolvedChangeIds({ numeric: "", text: "" });
    setCellResolved(false);
    setCellEditability(null);
    setCellReadBusy(false);
    setBusy(false);
    setError("");
    setPov({});
    setPovDialogDimensionId("");
    setAxisDialogDimensionId("");
    setAxisSelections({});
    setAxisSelectionSummaries({});
    setGenericState(null);
    setSavedGrids([]);
    setSavedGridsRead(false);
    setSelectedSavedGrid("");
    setSavedGridId("");
    setSavedGridName("");
    setSavedGridTouched(false);
    setSavedGridResult("");
    setOpenedGridDefinition(null);
    setCalculationContext(null);
    setAggregateMeasures(["SumAmount", "CountPresent"]);
    setAggregatePageSize(100);
    setAggregateReviewed(null);
    setAggregateQueryState(null);
    setAggregateCancelReviewed(false);
  }, [app?.workspaceId, app?.applicationId]);

  useEffect(() => {
    if (catalog) setReadSemantics((current) => current ?? defaultReadSemantics);
  }, [app?.workspaceId, app?.applicationId, catalog, defaultReadSemantics]);

  useEffect(() => {
    if (!scope || !catalog?.functions["metadata.dimension.list"]) return;
    const controller = new AbortController();
    readAllDimensions(scope, controller.signal)
      .then((result) => {
        if (
          controller.signal.aborted ||
          currentCatalogueContext.current !== catalogueContext
        )
          return;
        setMetadataSnapshot({ context: catalogueContext, ...result });
      })
      .catch((reason: Error) => {
        if (
          controller.signal.aborted ||
          currentCatalogueContext.current !== catalogueContext
        )
          return;
        if (reason.name !== "AbortError") setError(reason.message);
      });
    return () => controller.abort();
  }, [catalogueContext]);

  useEffect(() => {
    if (
      !scope ||
      readSemantics !== "effective" ||
      openedGridDefinition !== null ||
      !catalog?.functions["facts.cube.resolved.binding.list"]
    )
      return;
    const controller = new AbortController();
    readProgram<{ bindings: ResolvedBinding[] }>(
      scope,
      "facts.cube.resolved.binding.list",
      { limit: 100 },
      controller.signal,
    )
      .then((value) => {
        if (controller.signal.aborted) return;
        setResolvedBindings(value.bindings);
        if (value.bindings[0]) {
          setResolvedBindingId(value.bindings[0].bindingId);
          setResolvedBindingStateToken(value.bindings[0].stateToken);
        }
      })
      .catch(() => {
        if (!controller.signal.aborted) setResolvedBindings([]);
      });
    return () => controller.abort();
  }, [
    app?.workspaceId,
    app?.applicationId,
    readSemantics,
    Boolean(openedGridDefinition),
    Boolean(catalog?.functions["facts.cube.resolved.binding.list"]),
  ]);

  useEffect(
    () => setReviewed(false),
    [writeKind, writeOperation, writeValue, expectedChangeId, selectedCell],
  );

  useEffect(() => {
    setAggregateReviewed(null);
    setAggregateCancelReviewed(false);
  }, [
    rowDimension,
    columnDimension,
    pov,
    aggregateMeasures,
    aggregatePageSize,
  ]);

  const activeRowDimensions = openedGridDefinition
    ? openedGridDefinition.layout.rows
    : rowDimension
      ? [rowDimension]
      : [];
  const activeColumnDimensions = openedGridDefinition
    ? openedGridDefinition.layout.columns
    : columnDimension
      ? [columnDimension]
      : [];
  const calculatedGrid = Boolean(
    openedGridDefinition && openedGridDefinition.dataSource.kind !== "raw",
  );
  const axisIds = useMemo(
    () => new Set([...activeRowDimensions, ...activeColumnDimensions]),
    [activeRowDimensions.join("\u0000"), activeColumnDimensions.join("\u0000")],
  );
  const povDimensions = dimensions.filter(
    (item) => !axisIds.has(item.dimension_id),
  );
  function axisSelectorFor(dimensionId: string): CubeSelector | null {
    return (
      openedGridDefinition?.selection.dimensions.find(
        (dimension) => dimension.dimensionId === dimensionId,
      )?.include ||
      axisSelections[dimensionId] ||
      null
    );
  }
  function semanticAxisSummary(dimensionId: string) {
    if (axisSelectionSummaries[dimensionId])
      return axisSelectionSummaries[dimensionId];
    const selector = axisSelectorFor(dimensionId);
    if (!selector) return "All current authorized members";
    if (selector.kind === "member") return "1 selected member";
    if (selector.kind === "members")
      return `${selector.memberIds.length} selected ${selector.memberIds.length === 1 ? "member" : "members"}`;
    if (selector.kind === "hierarchy")
      return `${selector.operator.replace("_", " ")} hierarchy selection`;
    if (selector.kind === "member_list") return "Governed member list";
    if (selector.kind === "attribute") return "Attribute-based selection";
    return "Dynamic member expression";
  }
  const currentAxisSelections = Object.fromEntries(
    [...axisIds].flatMap((dimensionId) => {
      const selector = axisSelectorFor(dimensionId);
      return selector ? [[dimensionId, selector]] : [];
    }),
  );
  const hasCustomAxisSelection = Object.keys(currentAxisSelections).length > 0;
  // Count every rendered authoring transition, including A -> B -> A. Exact
  // value equality alone cannot let an earlier acknowledgement settle a later edit.
  const viewAuthoringContext = JSON.stringify([
    catalogueContext,
    requestedViewContext,
    selectedSavedGrid,
    savedGridId,
    savedGridName,
    openedGridDefinition,
    rowDimension,
    columnDimension,
    pov,
    currentAxisSelections,
  ]);
  const viewAuthoring = useRef({ context: viewAuthoringContext, version: 0 });
  if (viewAuthoring.current.context !== viewAuthoringContext) {
    viewAuthoring.current = {
      context: viewAuthoringContext,
      version: viewAuthoring.current.version + 1,
    };
  }

  function applyCanonicalLayout(
    layout: SavedGridDefinition["layout"],
    focusDimension?: string,
  ) {
    if (!openedGridDefinition || layout === openedGridDefinition.layout) return;
    const version = viewAuthoring.current.version;
    const apply = () => {
      if (
        !mounted.current ||
        currentCatalogueContext.current !== catalogueContext ||
        viewAuthoring.current.version !== version
      )
        return;
      const definition = { ...openedGridDefinition, layout };
      if (focusDimension)
        layoutFocus.current = {
          dimensionId: focusDimension,
          previous: document.activeElement,
        };
      setOpenedGridDefinition(definition);
      setRowDimension(layout.rows[0]);
      setColumnDimension(layout.columns[0]);
      setPov(savedGridPointOfView(definition));
      setSavedGridTouched(true);
      setSavedGridResult("");
      setWriteTouched(false);
      setReviewed(false);
    };
    if (writeTouched) onRequestTransition(apply);
    else apply();
  }

  function choosePrimaryAxis(role: "rows" | "columns", dimensionId: string) {
    if (openedGridDefinition) {
      applyCanonicalLayout(
        swapPrimaryAxis(openedGridDefinition.layout, role, dimensionId),
      );
      return;
    }
    setCalculationContext(null);
    if (role === "rows") setRowDimension(dimensionId);
    else setColumnDimension(dimensionId);
    setPov((current) => {
      const next = { ...current };
      delete next[dimensionId];
      return next;
    });
  }

  function moveCanonicalAxis(
    dimensionId: string,
    source: LayoutRole,
    target: LayoutRole,
  ) {
    if (!openedGridDefinition || source === target) return;
    if (!layoutRoles.includes(target)) return;
    const layout = structuredClone(openedGridDefinition.layout);
    if (
      !layout[source].includes(dimensionId) ||
      ((source === "rows" || source === "columns") &&
        layout[source].length === 1)
    )
      return;
    layout[source] = layout[source].filter((id) => id !== dimensionId);
    layout[target].push(dimensionId);
    applyCanonicalLayout(layout, dimensionId);
  }

  function reorderCanonicalAxis(
    role: LayoutRole,
    index: number,
    direction: -1 | 1,
  ) {
    if (!openedGridDefinition) return;
    const layout = structuredClone(openedGridDefinition.layout);
    const destination = index + direction;
    if (destination < 0 || destination >= layout[role].length) return;
    [layout[role][index], layout[role][destination]] = [
      layout[role][destination],
      layout[role][index],
    ];
    applyCanonicalLayout(layout);
  }
  const gridReadContext = JSON.stringify([
    catalogueContext,
    activeScopeKey,
    subject,
    catalog?.applicationAccess.issuer,
    catalog?.applicationAccess.role,
    catalog?.revisions.security,
    catalog?.revisions.metadata,
    catalog?.revisions.policy,
    metadataRevision,
    openedGridDefinition,
    rowDimension,
    columnDimension,
    pov,
    currentAxisSelections,
    readSemantics,
    resolvedBindingId,
    resolvedBindingStateToken,
  ]);
  const activeGridReadContext = useRef(gridReadContext);
  activeGridReadContext.current = gridReadContext;
  const layoutSuggestionContext = JSON.stringify([
    gridReadContext,
    dimensions.map(({ dimension_id, name, model_role, status }) => [
      dimension_id,
      name,
      model_role,
      status,
    ]),
  ]);
  const activeLayoutSuggestionContext = useRef(layoutSuggestionContext);
  activeLayoutSuggestionContext.current = layoutSuggestionContext;
  const loadedRead =
    completedRead?.context === gridReadContext ? completedRead : null;
  const readingGrid =
    gridReadController.current?.pending &&
    gridReadController.current.context === gridReadContext;
  let plannedRead: GridReadPlan | null = null;
  let readUnavailable = "";
  try {
    plannedRead = gridReadPlan({
      view: openedGridDefinition,
      semantics: readSemantics,
      pov,
      hasNativeSelection: hasCustomAxisSelection,
      bindingId: resolvedBindingId,
      bindingStateToken: resolvedBindingStateToken,
      canonicalViewRead:
        (
          catalog?.functions["facts.cube.resolved.read"] as
            | { canonicalViewRead?: string }
            | undefined
        )?.canonicalViewRead === "openepm-cube-view-read-v1",
    });
    if (
      plannedRead.kind !== "stored" &&
      !catalog?.functions[plannedRead.function]
    )
      readUnavailable =
        "This read is not available in the current application context.";
  } catch (reason) {
    readUnavailable =
      reason instanceof Error
        ? reason.message
        : "This view cannot be read exactly.";
  }
  if (!catalog) readUnavailable = "Checking grid availability…";
  else if (!catalog.functions["metadata.dimension.list"])
    readUnavailable =
      "Model metadata is not available in the current application context.";
  function cancelLayoutSuggestion(expectedContext: string) {
    const pending = layoutSuggestionController.current;
    if (pending?.context !== expectedContext) return;
    layoutSuggestionVersion.current += 1;
    pending.controller.abort();
    layoutSuggestionController.current = null;
    if (mounted.current) setBusy(false);
  }
  useEffect(() => {
    const pending = layoutSuggestionController.current;
    if (
      activeLayoutSuggestionContext.current === layoutSuggestionContext &&
      pending &&
      pending.context !== layoutSuggestionContext
    )
      cancelLayoutSuggestion(pending.context);
    return () => cancelLayoutSuggestion(layoutSuggestionContext);
  }, [layoutSuggestionContext]);
  function cancelGridRead(expectedContext: string) {
    const read = gridReadController.current;
    if (read?.context !== expectedContext) return;
    gridReadVersion.current += 1;
    read.controller.abort();
    gridReadController.current = null;
    if (read.pending && mounted.current) setBusy(false);
  }
  function cancelCellRead() {
    cellReadVersion.current += 1;
    cellReadController.current?.abort();
    cellReadController.current = null;
    setCellReadBusy(false);
  }
  function clearGridSnapshot() {
    cancelCellRead();
    setRows([]);
    setNextCursor(null);
    setResolvedPage(null);
    setSource("");
    setResolvedStatus(null);
    setCalculationContext(null);
    setCompletedRead(null);
    setSelectedCell(null);
  }
  useEffect(() => {
    // A new-context request may already have started (or completed) at the
    // first actionable commit. Only a departed owner may be cancelled/reset.
    const read = gridReadController.current;
    if (
      activeGridReadContext.current === gridReadContext &&
      read?.context !== gridReadContext
    ) {
      if (read) cancelGridRead(read.context);
      clearGridSnapshot();
    }
    return () => cancelGridRead(gridReadContext);
  }, [gridReadContext]);
  const axisDialogInitialSelection = axisDialogDimensionId
    ? axisSelectorFor(axisDialogDimensionId)
    : null;
  const povDialogSelector = openedGridDefinition?.selection.dimensions.find(
    (dimension) => dimension.dimensionId === povDialogDimensionId,
  )?.include;
  const povDialogInitialMemberId =
    povDialogSelector?.kind === "member"
      ? povDialogSelector.memberId
      : pov[povDialogDimensionId] || "";

  async function ensureMembers(dimensionId: string, signal?: AbortSignal) {
    if (signal?.aborted)
      throw new DOMException("Member read cancelled", "AbortError");
    if (!scope || metadataRevision === null)
      throw new Error(
        "Load the current application metadata before choosing members.",
      );
    if (memberCatalog[dimensionId]) return memberCatalog[dimensionId];
    const members = await readAllMembers(
      scope,
      dimensionId,
      metadataRevision,
      signal,
    );
    if (signal?.aborted)
      throw new DOMException("Member read cancelled", "AbortError");
    if (memberContextRef.current !== memberContext)
      throw new Error(
        "The application or access changed while loading members.",
      );
    setMemberCache((current) => ({
      context: memberContext,
      rows: {
        ...(current?.context === memberContext ? current.rows : {}),
        [dimensionId]: members,
      },
    }));
    return members;
  }

  async function openPovSelector(dimensionId: string) {
    setError("");
    try {
      await ensureMembers(dimensionId);
      setPovDialogDimensionId(dimensionId);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read members for this point of view.",
      );
    }
  }

  async function openAxisSelector(dimensionId: string) {
    setError("");
    try {
      const available = await ensureMembers(dimensionId);
      if (!available.some((member) => member.status === "Active"))
        throw new Error(
          "No active authorized members are available for this axis.",
        );
      setAxisDialogDimensionId(dimensionId);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read members for this axis.",
      );
    }
  }

  function applyAxisSelection(
    dimensionId: string,
    selector: CubeSelector,
    displaySummary: string,
  ) {
    setAxisSelections((current) => ({ ...current, [dimensionId]: selector }));
    setAxisSelectionSummaries((current) => ({
      ...current,
      [dimensionId]: displaySummary,
    }));
    setOpenedGridDefinition((current) =>
      current
        ? {
            ...current,
            selection: {
              ...current.selection,
              dimensions: current.selection.dimensions.map((dimension) =>
                dimension.dimensionId === dimensionId
                  ? { ...dimension, include: selector }
                  : dimension,
              ),
            },
          }
        : current,
    );
    setCalculationContext(null);
    if (openedGridDefinition) setSavedGridTouched(true);
    setRows([]);
    setResolvedPage(null);
    setAxisDialogDimensionId("");
  }

  function applyPovMember(dimensionId: string, memberId: string) {
    setPov((current) => ({ ...current, [dimensionId]: memberId }));
    setOpenedGridDefinition((current) =>
      current
        ? {
            ...current,
            selection: {
              ...current.selection,
              dimensions: current.selection.dimensions.map((dimension) =>
                dimension.dimensionId === dimensionId
                  ? {
                      ...dimension,
                      include: { kind: "member", memberId },
                      exclude: null,
                    }
                  : dimension,
              ),
            },
          }
        : current,
    );
    setCalculationContext(null);
    if (openedGridDefinition) setSavedGridTouched(true);
    setPovDialogDimensionId("");
  }

  async function openGenericFacts() {
    if (!scope || !catalog?.functions["facts.generic.table.list"]) return;
    const version = ++genericReadVersion.current;
    genericReadController.current?.controller.abort();
    const controller = new AbortController();
    genericReadController.current = { context: genericReadContext, controller };
    const current = () =>
      !controller.signal.aborted &&
      genericReadVersion.current === version &&
      currentGenericReadContext.current === genericReadContext;
    setBusy(true);
    setError("");
    try {
      const collected = await collectGenericTables((afterTableId) => {
        if (!current())
          throw new DOMException("Table read cancelled", "AbortError");
        return readProgram<GenericTablePage>(
          scope,
          "facts.generic.table.list",
          genericTableListArguments(afterTableId),
          controller.signal,
        );
      });
      if (!current()) return;
      const tables = collected.rows.filter(
        (table) => table.status === "Active",
      );
      setGenericState({
        context: catalogueContext,
        tables,
        tableId: tables.some((table) => table.table_id === selectedGenericTable)
          ? selectedGenericTable
          : tables[0]?.table_id || "",
        rows: [],
        cursor: null,
        snapshot: null,
      });
      setPresentation("generic");
    } catch (reason) {
      if (!current()) return;
      setGenericState(null);
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read generic-fact tables",
      );
    } finally {
      if (current()) {
        genericReadController.current = null;
        setBusy(false);
      }
    }
  }

  async function readGenericFacts(cursor?: string | null) {
    if (
      !scope ||
      !selectedGenericTable ||
      !catalog?.functions["facts.generic.value.snapshot.scan"]
    )
      return;
    const version = ++genericReadVersion.current;
    genericReadController.current?.controller.abort();
    const controller = new AbortController();
    genericReadController.current = { context: genericReadContext, controller };
    const current = () =>
      !controller.signal.aborted &&
      genericReadVersion.current === version &&
      currentGenericReadContext.current === genericReadContext;
    setBusy(true);
    setError("");
    try {
      const page = await readProgram<GenericFactPage>(
        scope,
        "facts.generic.value.snapshot.scan",
        genericSnapshotArguments(selectedGenericTable, cursor),
        controller.signal,
      );
      if (!current()) return;
      setGenericState((state) =>
        state?.context === catalogueContext &&
        state.tableId === selectedGenericTable
          ? {
              ...state,
              rows: cursor ? [...state.rows, ...page.rows] : page.rows,
              cursor: page.nextCursor || null,
              snapshot: page.snapshotRevision,
            }
          : state,
      );
    } catch (reason) {
      if (!current()) return;
      const tableAccessUnconfirmed =
        reason instanceof ApiError &&
        (reason.kind === "authorization" ||
          [
            "GENERIC_FACT_READ_AUTHORIZATION_STALE",
            "FACT_TABLE_UNAVAILABLE",
            "STALE_METADATA_REVISION",
          ].includes(reason.code));
      setGenericState((state) => {
        if (
          state?.context !== catalogueContext ||
          state.tableId !== selectedGenericTable
        )
          return state;
        return tableAccessUnconfirmed
          ? null
          : { ...state, rows: [], cursor: null, snapshot: null };
      });
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read generic facts",
      );
    } finally {
      if (current()) {
        genericReadController.current = null;
        setBusy(false);
      }
    }
  }

  async function suggestLayout() {
    if (!scope || dimensions.length < 2) return;
    const version = ++layoutSuggestionVersion.current;
    layoutSuggestionController.current?.controller.abort();
    const controller = new AbortController();
    const pending = { context: layoutSuggestionContext, controller };
    layoutSuggestionController.current = pending;
    const current = () =>
      mounted.current &&
      layoutSuggestionController.current === pending &&
      !controller.signal.aborted &&
      layoutSuggestionVersion.current === version &&
      activeLayoutSuggestionContext.current === layoutSuggestionContext;
    setBusy(true);
    setError("");
    try {
      const primary =
        dimensions.find((item) =>
          ["Account", "Entity"].includes(item.model_role),
        ) ||
        dimensions.find(
          (item) => !["Period", "Year", "Scenario"].includes(item.model_role),
        ) ||
        dimensions[0];
      const column =
        dimensions.find(
          (item) => item.model_role === "Period" && item !== primary,
        ) || dimensions.find((item) => item !== primary);
      if (!column)
        throw new Error("No distinct column dimension is available.");
      if (openedGridDefinition) {
        applyCanonicalLayout(
          swapPrimaryAxis(
            swapPrimaryAxis(
              openedGridDefinition.layout,
              "rows",
              primary.dimension_id,
            ),
            "columns",
            column.dimension_id,
          ),
        );
        return;
      }
      const fixed: Record<string, string> = {};
      for (const dimension of dimensions) {
        if (
          [primary.dimension_id, column.dimension_id].includes(
            dimension.dimension_id,
          )
        )
          continue;
        const members = await ensureMembers(
          dimension.dimension_id,
          controller.signal,
        );
        if (!current()) return;
        if (members[0]) fixed[dimension.dimension_id] = members[0].member_id;
      }
      if (!current()) return;
      setOpenedGridDefinition(null);
      setCalculationContext(null);
      setRowDimension(primary.dimension_id);
      setColumnDimension(column.dimension_id);
      setPov(fixed);
    } catch (reason) {
      if (!current()) return;
      setError(
        reason instanceof Error ? reason.message : "Unable to build layout",
      );
    } finally {
      if (current()) {
        layoutSuggestionController.current = null;
        setBusy(false);
      }
    }
  }

  const readSavedGrids = useCallback(async () => {
    if (
      !app?.workspaceId ||
      !app.applicationId ||
      !canReadSavedGrids ||
      currentSavedGridReadKey.current !== savedGridReadKey
    )
      return;
    savedGridReadController.current?.abort();
    const controller = new AbortController();
    savedGridReadController.current = controller;
    const requestVersion = ++savedGridReadVersion.current;
    const isCurrent = () =>
      !controller.signal.aborted &&
      requestVersion === savedGridReadVersion.current &&
      currentSavedGridReadKey.current === savedGridReadKey;
    setSavedGridsContext(savedGridReadKey);
    setSavedGridsLoading(true);
    setSavedGridsError("");
    try {
      let collectionToken: string | undefined;
      const collected = await collectSavedGrids(async (afterGridId) => {
        if (!isCurrent())
          throw new DOMException("Saved view read cancelled", "AbortError");
        const page = await readProgram<SavedGridPage>(
          { workspaceId: app.workspaceId, applicationId: app.applicationId },
          "grid.definition.list",
          savedGridListArguments(afterGridId, collectionToken),
          controller.signal,
        );
        collectionToken = page.collectionToken;
        return page;
      });
      if (!isCurrent()) return;
      const grids = collected.rows;
      setSavedGrids(grids);
      setSavedGridsRead(true);
      setSavedGridsAccessFailed(false);
      setSelectedSavedGrid((current) =>
        grids.some((grid) => grid.gridId === current)
          ? current
          : grids[0]
            ? grids[0].gridId
            : "",
      );
    } catch (reason) {
      if (!isCurrent()) return;
      if (
        reason instanceof ApiError &&
        (reason.kind === "authorization" ||
          reason.kind === "authentication" ||
          ["SAVED_GRID_AUTHORIZATION_STALE", "SAVED_GRID_LIST_STALE"].includes(
            reason.code,
          ))
      ) {
        setSavedGrids([]);
        setSavedGridsRead(false);
        setSelectedSavedGrid("");
        setSavedGridsAccessFailed(true);
      }
      setSavedGridsError(
        reason instanceof Error ? reason.message : "Unable to load saved views",
      );
    } finally {
      if (isCurrent()) setSavedGridsLoading(false);
    }
  }, [
    app?.workspaceId,
    app?.applicationId,
    canReadSavedGrids,
    savedGridReadKey,
  ]);

  useEffect(() => {
    setSavedGrids([]);
    setSavedGridsRead(false);
    setSelectedSavedGrid("");
    setSavedGridsError("");
    setSavedGridsLoading(false);
    setSavedGridsAccessFailed(false);
    setSavedGridsContext(savedGridReadKey);
    if (canReadSavedGrids) void readSavedGrids();
    return () => {
      savedGridReadVersion.current += 1;
      savedGridReadController.current?.abort();
    };
  }, [readSavedGrids, savedGridReadKey, canReadSavedGrids]);

  useEffect(() => {
    if (!openedGridReference || savedGridsContext !== savedGridReadKey) return;
    const unavailable =
      savedGridsAccessFailed ||
      (savedGridsRead &&
        !savedGrids.some((grid) => grid.gridId === openedGridReference.viewId));
    if (!unavailable) return;
    const read = gridReadController.current;
    if (read) cancelGridRead(read.context);
    clearGridSnapshot();
    setOpenedGridReference(null);
    setOpenedGridDefinition(null);
    setReadSemantics(null);
    setResolvedBindingId("");
    setResolvedBindingStateToken("");
    setRowDimension("");
    setColumnDimension("");
    setPov({});
    setAxisSelections({});
    setAxisSelectionSummaries({});
    setSavedGridId("");
    setSavedGridName("");
    setSavedGridTouched(false);
    setSavedGridResult("");
  }, [
    openedGridReference,
    savedGrids,
    savedGridsRead,
    savedGridsAccessFailed,
    savedGridsContext,
    savedGridReadKey,
  ]);

  function openSavedGrid(grid: SavedGrid, analyticalRead?: AnalyticalRead) {
    if (!canOpenSavedGrid(grid)) {
      setError(
        "This saved definition is invalid or cannot be represented without changing its declared semantics.",
      );
      return;
    }
    const semantics =
      analyticalRead?.semantics ||
      (grid.definition.dataSource.kind === "raw" &&
      catalog?.functions["facts.cube.resolved.read"]
        ? "own"
        : "stored");
    if (analyticalRead) {
      if (semantics === "effective")
        throw new Error(
          "This saved-view reference cannot restore an effective binding without changing its declared source layer. Request a compatible reference.",
        );
      const restored = gridReadPlan({
        view: grid.definition,
        semantics,
        pov: {},
        hasNativeSelection: true,
        bindingId: "",
        bindingStateToken: "",
        canonicalViewRead:
          (
            catalog?.functions["facts.cube.resolved.read"] as
              | { canonicalViewRead?: string }
              | undefined
          )?.canonicalViewRead === "openepm-cube-view-read-v1",
      });
      if (!catalog?.functions[restored.function])
        throw new Error(
          "The referenced read policy is unavailable in the current application context. Request a supported reference.",
        );
    }
    const fixed = savedGridPointOfView(grid.definition);
    setOpenedGridDefinition(structuredClone(grid.definition));
    setOpenedGridReference({
      viewId: grid.gridId,
      viewDigest: grid.canonicalDigest,
      definition: JSON.stringify(grid.definition),
      authority: savedGridReadKey,
      requestedContext: requestedViewContext,
    });
    // Read policy is session context, not a field in the saved-view contract.
    // The visible selector is reset explicitly; no stale binding is restored.
    setReadSemantics(semantics);
    setResolvedBindingId("");
    setResolvedBindingStateToken("");
    setCalculationContext(null);
    setRowDimension(grid.definition.layout.rows[0] || "");
    setColumnDimension(grid.definition.layout.columns[0] || "");
    const savedAxes = new Set([
      ...grid.definition.layout.rows,
      ...grid.definition.layout.columns,
    ]);
    setAxisSelections(
      Object.fromEntries(
        grid.definition.selection.dimensions.flatMap((dimension) =>
          savedAxes.has(dimension.dimensionId)
            ? [[dimension.dimensionId, dimension.include]]
            : [],
        ),
      ),
    );
    setAxisSelectionSummaries({});
    setPov(fixed);
    setSavedGridId(grid.gridId);
    setSelectedSavedGrid(grid.gridId);
    setSavedGridName(grid.name);
    setSavedGridTouched(false);
    setRows([]);
    setResolvedStatus(null);
    setNextCursor(null);
    setResolvedPage(null);
    setSelectedCell(null);
    setSavedGridResult(
      `Opened ${grid.name} · ${grid.definition.dataSource.kind} · ${grid.definition.layout.rows.length} row axes · ${grid.definition.layout.columns.length} column axes`,
    );
  }

  useEffect(() => {
    if (!scope || !targetViewId || !catalog?.functions["grid.definition.read"])
      return;
    const controller = new AbortController();
    setOpenedGridReference(null);
    setOpenedGridDefinition(null);
    setRowDimension("");
    setColumnDimension("");
    setPov({});
    setAxisSelections({});
    setError("");
    readProgram<SavedGrid>(
      scope,
      "grid.definition.read",
      { gridId: targetViewId },
      controller.signal,
    )
      .then((grid) => {
        if (controller.signal.aborted) return;
        if (targetViewDigest && grid.canonicalDigest !== targetViewDigest)
          throw new Error(
            "Workflow destination no longer matches its pinned grid digest.",
          );
        openSavedGrid(grid, targetAnalyticalRead);
      })
      .catch((reason: Error) => {
        if (!controller.signal.aborted && reason.name !== "AbortError")
          setError(reason.message);
      });
    return () => controller.abort();
  }, [
    app?.workspaceId,
    app?.applicationId,
    targetViewId,
    targetViewDigest,
    JSON.stringify(targetAnalyticalRead),
    savedGridReadKey,
    Boolean(catalog?.functions["grid.definition.read"]),
  ]);

  const selectedGrid = currentSavedGrids.find(
    (grid) => grid.gridId === selectedSavedGrid,
  );
  const currentGridForSave = currentSavedGrids.find(
    (grid) => grid.gridId === savedGridId.trim(),
  );
  const savedGridDefinition = openedGridDefinition
    ? {
        ...structuredClone(openedGridDefinition),
        viewId: savedGridId,
        name: savedGridName,
      }
    : currentSavedGridDefinition(
        savedGridId,
        savedGridName,
        dimensions,
        memberCatalog,
        metadataRevision || 0,
        rowDimension ? [rowDimension] : [],
        columnDimension ? [columnDimension] : [],
        pov,
        currentAxisSelections,
      );
  const configuredLayout = gridLayoutSummary(
    savedGridDefinition.layout,
    dimensions,
  );
  const shareableViewContext: SavedViewContext | null =
    openedGridReference &&
    openedGridDefinition &&
    !savedGridTouched &&
    openedGridReference.authority === savedGridReadKey &&
    openedGridReference.requestedContext === requestedViewContext &&
    openedGridReference.definition === JSON.stringify(openedGridDefinition) &&
    openedGridDefinition.selection.metadataRevision === metadataRevision &&
    /^[0-9a-f]{64}$/.test(openedGridReference.viewDigest) &&
    plannedRead &&
    !readUnavailable &&
    readSemantics !== "effective"
      ? {
          viewId: openedGridReference.viewId,
          viewDigest: openedGridReference.viewDigest,
          analyticalRead: { semantics: readSemantics },
        }
      : null;
  const shareableViewContextKey = JSON.stringify(shareableViewContext);
  useEffect(() => {
    onViewContextChange?.(JSON.parse(shareableViewContextKey));
  }, [shareableViewContextKey, onViewContextChange]);
  useEffect(() => () => onViewContextChange?.(null), [onViewContextChange]);
  const savedGridIdValid = /^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/.test(
    savedGridId,
  );
  const savedGridNameValid = Boolean(
    savedGridName &&
      savedGridName === savedGridName.trim() &&
      savedGridName.length <= 200 &&
      ![...savedGridName].some((character) => character.charCodeAt(0) < 32),
  );
  const savedGridReady = Boolean(
    catalog?.functions["grid.definition.save"] &&
      metadataRevision &&
      savedGridIdValid &&
      savedGridNameValid &&
      savedGridDefinition.layout.rows.length &&
      savedGridDefinition.layout.columns.length,
  );

  async function saveSharedGrid() {
    if (!scope || !metadataRevision || !savedGridReady) return;
    const version = viewAuthoring.current.version;
    const requestVersion = ++viewMutationSequence.current;
    pendingViewMutation.current = requestVersion;
    const sameContext = () =>
      mounted.current &&
      currentCatalogueContext.current === catalogueContext &&
      pendingViewMutation.current === requestVersion;
    setBusy(true);
    setError("");
    try {
      const definition = openedGridDefinition
        ? savedGridDefinition
        : currentSavedGridDefinition(
            savedGridId,
            savedGridName,
            dimensions,
            Object.fromEntries(
              await Promise.all(
                dimensions.map(async (dimension) => [
                  dimension.dimension_id,
                  await ensureMembers(dimension.dimension_id),
                ]),
              ),
            ),
            metadataRevision,
            rowDimension ? [rowDimension] : [],
            columnDimension ? [columnDimension] : [],
            pov,
            currentAxisSelections,
          );
      if (!sameContext() || viewAuthoring.current.version !== version) return;
      if (
        !canOpenSavedGrid({
          gridId: savedGridId,
          stateToken: currentGridForSave?.stateToken || "a".repeat(64),
          name: savedGridName,
          definition,
          metadataRevision,
          canonicalDigest: "candidate",
        })
      )
        throw new Error(
          "The current grid selection is incomplete or invalid. Choose current members before saving this view.",
        );
      const response = await requestAdmittedEffect<{ result: SavedGrid }>(
        "/api/metadata-action",
        {
          ...scope,
          program: savedGridSaveProgram(
            savedGridId,
            definition,
            metadataRevision,
            currentGridForSave?.stateToken,
          ),
          idempotencyKey: mutationIntentKey({
            scope,
            function: "grid.definition.save",
            gridId: savedGridId,
            stateToken: currentGridForSave?.stateToken,
            definition,
            metadataRevision,
          }),
          confirmed: true,
        },
      );
      if (!sameContext()) return;
      if (viewAuthoring.current.version === version) {
        setSavedGridResult(`Saved ${response.result.name}.`);
        setSavedGridTouched(false);
      } else {
        setSavedGridResult(
          `Saved ${response.result.name}. Your newer view edits are still unsaved.`,
        );
      }
      await readSavedGrids();
    } catch (reason) {
      if (!sameContext()) return;
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to save shared grid definition",
      );
    } finally {
      if (sameContext()) {
        pendingViewMutation.current = null;
        setBusy(false);
      }
    }
  }

  async function deleteSharedGrid() {
    if (
      !scope ||
      !selectedGrid ||
      !catalog?.functions["grid.definition.delete"]
    )
      return;
    const version = viewAuthoring.current.version;
    const requestVersion = ++viewMutationSequence.current;
    pendingViewMutation.current = requestVersion;
    const sameContext = () =>
      mounted.current &&
      currentCatalogueContext.current === catalogueContext &&
      pendingViewMutation.current === requestVersion;
    setBusy(true);
    setError("");
    try {
      await requestAdmittedEffect<{
        result: { gridId: string; status: "Deleted" };
      }>("/api/metadata-action", {
        ...scope,
        program: savedGridDeleteProgram(
          selectedGrid.gridId,
          selectedGrid.stateToken,
        ),
        idempotencyKey: mutationIntentKey({
          scope,
          function: "grid.definition.delete",
          gridId: selectedGrid.gridId,
          stateToken: selectedGrid.stateToken,
        }),
        confirmed: true,
      });
      if (!sameContext()) return;
      setSavedGridResult(`Deleted ${selectedGrid.name}`);
      setOpenedGridReference((current) =>
        current?.viewId === selectedGrid.gridId ? null : current,
      );
      if (
        viewAuthoring.current.version === version &&
        savedGridId === selectedGrid.gridId
      ) {
        setSelectedSavedGrid("");
        setSavedGridId("");
        setSavedGridName("");
        setOpenedGridDefinition(null);
        setSavedGridTouched(false);
      }
      await readSavedGrids();
    } catch (reason) {
      if (!sameContext()) return;
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to delete saved view",
      );
    } finally {
      if (sameContext()) {
        pendingViewMutation.current = null;
        setBusy(false);
      }
    }
  }

  let aggregateIntent: ReturnType<typeof aggregateQueryIntent> | null = null;
  let aggregateIntentError = "";
  try {
    if (hasCustomAxisSelection)
      throw new Error(
        "Aggregate requests do not support member-restricted axes. Use the resolved grid read for this selection.",
      );
    if (
      calculatedGrid ||
      activeRowDimensions.length !== 1 ||
      activeColumnDimensions.length !== 1
    )
      throw new Error(
        "Aggregate requests require one raw row axis and one raw column axis.",
      );
    aggregateIntent = aggregateQueryIntent(
      dimensions,
      activeRowDimensions[0] || "",
      activeColumnDimensions[0] || "",
      pov,
      aggregateMeasures,
    );
  } catch (reason) {
    aggregateIntentError =
      reason instanceof Error ? reason.message : "Aggregate intent is invalid.";
  }
  const aggregatePageSizeValid =
    Number.isInteger(aggregatePageSize) &&
    aggregatePageSize >= 1 &&
    aggregatePageSize <= 500;
  const aggregateReady = Boolean(
    aggregateIntent &&
      aggregatePageSizeValid &&
      catalog?.functions["facts.cube.aggregate.request"],
  );
  const aggregateReviewKey = JSON.stringify([
    catalogueContext,
    aggregateIntent,
    aggregatePageSize,
  ]);
  const aggregateReviewed = aggregateReviewedIntent === aggregateReviewKey;
  const aggregateCanCancel = Boolean(
    aggregateQueryId &&
      aggregateStateRead &&
      ["accepted", "ready", "running", "computed"].includes(
        aggregateStatus.toLowerCase(),
      ) &&
      catalog?.functions["facts.cube.aggregate.cancel"],
  );

  function beginAggregateRequest() {
    pendingAggregateRequest.current?.controller.abort();
    const pending = {
      context: catalogueContext,
      token: ++aggregateRequestSequence.current,
      controller: new AbortController(),
    };
    pendingAggregateRequest.current = pending;
    setAggregatePending(pending);
    setError("");
    setAggregateCancelReviewed(false);
    const current = () =>
      mounted.current &&
      currentCatalogueContext.current === pending.context &&
      pendingAggregateRequest.current === pending &&
      !pending.controller.signal.aborted;
    return { pending, current };
  }

  function hideAggregateObservation() {
    // Retain the known query handle for a later authorized inspection; neither
    // a refusal nor a context change authorizes displaying its old intent/data.
    setAggregateQueryState((query) =>
      query?.owner === aggregateOwner
        ? {
            ...query,
            context: "",
            status: "",
            errorCode: undefined,
            rows: [],
            cursor: null,
            stateRead: false,
          }
        : query,
    );
    setAggregateCancelReviewed(false);
  }

  async function requestAggregate() {
    if (!scope || !aggregateIntent || !aggregateReady || !aggregateReviewed)
      return;
    const query = aggregateIntent;
    const pageSize = aggregatePageSize;
    const { pending, current } = beginAggregateRequest();
    setAggregateReviewed(null);
    hideAggregateObservation();
    try {
      const response = await request<{ result: AggregateResult }>(
        "/api/aggregate",
        {
          ...scope,
          confirmed: true,
          program: aggregateRequestProgram(query, pageSize),
        },
        pending.controller.signal,
      );
      if (!current()) return;
      if (
        typeof response.result.queryId !== "string" ||
        !response.result.queryId
      )
        throw new Error(
          "The aggregate response did not identify the accepted query.",
        );
      setAggregateQueryState({
        owner: aggregateOwner,
        queryId: response.result.queryId,
        query,
        pageSize,
        context: catalogueContext,
        status: response.result.status,
        rows: [],
        cursor: null,
        stateRead: false,
      });
    } catch (reason) {
      if (!current()) return;
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to request aggregate query",
      );
    } finally {
      if (current()) {
        pendingAggregateRequest.current = null;
        setAggregatePending((current) =>
          current === pending ? null : current,
        );
      }
    }
  }

  async function readAggregate(cursor?: string | null) {
    if (
      !scope ||
      !aggregateQuery ||
      !catalog?.functions["facts.cube.aggregate.read"]
    )
      return;
    const query = aggregateQuery;
    const { pending, current } = beginAggregateRequest();
    try {
      const response = await request<{ result: AggregateResult }>(
        "/api/aggregate",
        {
          ...scope,
          program: aggregateReadProgram(query.queryId, query.pageSize, cursor),
        },
        pending.controller.signal,
      );
      if (!current()) return;
      if (response.result.queryId !== query.queryId)
        throw new Error(
          "The aggregate response does not match the requested query.",
        );
      const sealed = response.result.status === "sealed";
      if (
        !sealed &&
        (response.result.rows !== undefined || response.result.nextCursor)
      )
        throw new Error(
          "Aggregate results are unavailable until the query is sealed.",
        );
      setAggregateQueryState({
        ...query,
        context: catalogueContext,
        status: response.result.status,
        errorCode: response.result.errorCode,
        rows: sealed
          ? cursor
            ? [
                ...(aggregateObservation?.rows || []),
                ...(response.result.rows || []),
              ]
            : response.result.rows || []
          : [],
        cursor: sealed ? response.result.nextCursor || null : null,
        stateRead: true,
      });
    } catch (reason) {
      if (!current()) return;
      hideAggregateObservation();
      setError(
        reason instanceof Error ? reason.message : "Unable to read aggregate",
      );
    } finally {
      if (current()) {
        pendingAggregateRequest.current = null;
        setAggregatePending((current) =>
          current === pending ? null : current,
        );
      }
    }
  }

  async function cancelAggregate() {
    if (
      !scope ||
      !aggregateQuery ||
      !aggregateCanCancel ||
      !aggregateCancelReviewed
    )
      return;
    if (!window.confirm("Request cancellation of this aggregate query?"))
      return;
    const query = aggregateQuery;
    const { pending, current } = beginAggregateRequest();
    try {
      const response = await request<{ result: AggregateResult }>(
        "/api/aggregate",
        {
          ...scope,
          confirmed: true,
          program: {
            languageVersion: 2,
            function: "facts.cube.aggregate.cancel",
            arguments: { queryId: query.queryId },
          },
        },
        pending.controller.signal,
      );
      if (!current()) return;
      if (response.result.queryId !== query.queryId)
        throw new Error(
          "The aggregate response does not match the requested query.",
        );
      setAggregateQueryState({
        ...query,
        context: catalogueContext,
        status: response.result.status,
        rows: [],
        cursor: null,
        stateRead: false,
      });
    } catch (reason) {
      if (!current()) return;
      hideAggregateObservation();
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to cancel aggregate query",
      );
    } finally {
      if (current()) {
        pendingAggregateRequest.current = null;
        setAggregatePending((current) =>
          current === pending ? null : current,
        );
      }
    }
  }

  async function scan(cursor?: string | null) {
    if (!scope || !plannedRead || readUnavailable) return;
    const focusRequest = gridFocus.begin();
    const plan = plannedRead;
    const context = gridReadContext;
    const version = ++gridReadVersion.current;
    const prior = gridReadController.current;
    prior?.controller.abort();
    if (prior?.context !== context) clearGridSnapshot();
    const controller = new AbortController();
    const pending = { context, controller, pending: true };
    gridReadController.current = pending;
    const current = () =>
      mounted.current &&
      gridReadController.current === pending &&
      !controller.signal.aborted &&
      version === gridReadVersion.current &&
      activeGridReadContext.current === context;
    setBusy(true);
    setError("");
    try {
      const requiredDimensions = [
        ...new Set(
          plan.kind === "resolved"
            ? dimensions.map((dimension) => dimension.dimension_id)
            : [...activeRowDimensions, ...activeColumnDimensions],
        ),
      ];
      const resolvedMemberCatalog = { ...memberCatalog };
      if (!cursor) {
        const loaded = await Promise.all(
          requiredDimensions.map(
            async (dimension) =>
              [
                dimension,
                await ensureMembers(dimension, controller.signal),
              ] as const,
          ),
        );
        for (const [dimension, members] of loaded)
          resolvedMemberCatalog[dimension] = members;
      }
      if (!current()) return;
      const orderCells = (cells: CubeCell[]) => {
        const axes = [...activeRowDimensions, ...activeColumnDimensions];
        if (
          axes.some(
            (dimension) => explicitMemberIds(axisSelectorFor(dimension)).length,
          )
        ) {
          const compare = gridMemberComparator(
            axes,
            resolvedMemberCatalog,
            axisSelectorFor,
          );
          const members = (cell: CubeCell) =>
            axes.map((dimension) => cell.members[dimension]);
          cells.sort((left, right) => compare(members(left), members(right)));
        }
        return cells;
      };
      if (!cursor && plan.kind === "canonical") {
        const page = await readProgram<CubeViewReadPage>(
          scope,
          plan.function,
          {
            format: "openepm-cube-view-read-v1",
            view: plan.view,
            readPolicy: plan.readPolicy,
            limits: { maxRows: 500, maxSourceRows: 100_000, timeoutMs: 30_000 },
          },
          controller.signal,
        );
        if (!current()) return;
        if (
          page.format !== "openepm-cube-view-read-v1" ||
          !page.complete ||
          page.dataSource.kind !== plan.view.dataSource.kind ||
          page.dataSource.resultKey !== plan.view.dataSource.resultKey ||
          page.readPolicy.semantics !== plan.readPolicy.semantics ||
          page.presentation.rowCount !== page.rows.length
        )
          throw new Error(
            "The returned read does not match the requested view and read policy.",
          );
        const cells = orderCells(cubeViewRowsToCells(page));
        const pageSize = page.presentation.pageSize;
        setResolvedPage({ cells, pageSize, offset: 0 });
        setRows(resolvedPageCells(cells, pageSize, 0));
        setNextCursor(null);
        setSource(
          canonicalGridReadLabel(page.dataSource, page.readPolicy.semantics),
        );
        setResolvedStatus(cells.length ? "current" : "current-empty");
        setCalculationContext(
          page.calculation
            ? {
                resultKey: page.calculation.resultKey,
                resultStateToken: page.calculation.resultStateToken,
                inputsMatch: page.calculation.inputRevisionStatus.matchesAtRead,
              }
            : null,
        );
        setCompletedRead({ context, plan });
        return;
      }
      if (!cursor && plan.kind === "resolved") {
        const page = await readProgram<ResolvedCubePage>(
          scope,
          "facts.cube.resolved.read",
          resolvedGridProgram(
            dimensions,
            resolvedMemberCatalog,
            pov,
            metadataRevision || 0,
            plan.source,
            openedGridDefinition?.selection,
            {
              pageSize: openedGridDefinition?.pageSize || 100,
              suppression: openedGridDefinition?.suppression || {
                missing: false,
                zero: false,
              },
            },
            currentAxisSelections,
          ).arguments,
          controller.signal,
        );
        if (!current()) return;
        const cells = orderCells(resolvedRowsToCells(page));
        const pageSize = page.presentation.pageSize;
        setResolvedPage({ cells, pageSize, offset: 0 });
        setRows(resolvedPageCells(cells, pageSize, 0));
        setNextCursor(null);
        const readStatus = resolvedReadStatus(page);
        setResolvedStatus(readStatus);
        const origins = [...new Set(page.rows.map((row) => row.origin))].sort();
        const currentness = [
          ...new Set(page.rows.map((row) => row.currentness)),
        ].sort();
        setSource(
          `${plan.label} · ${origins.join(", ") || "no rows"} · ${
            currentness.join(", ") || "currentness unavailable"
          }`,
        );
        setCalculationContext(null);
        setCompletedRead({ context, plan });
        return;
      }
      setResolvedStatus(null);
      setResolvedPage(null);
      const pageSize = openedGridDefinition?.pageSize || 100;
      if (plan.kind === "resolved" || plan.kind === "canonical") return;
      const page = await readProgram<CubePage>(
        scope,
        plan.function,
        cursor
          ? { cursor }
          : plan.kind === "calculated"
            ? {
                members: plan.members,
                limit: pageSize,
                includeZero: !(openedGridDefinition?.suppression.zero ?? false),
                resultKey: plan.resultKey,
              }
            : buildScanArguments(
                plan.members,
                pageSize,
                undefined,
                openedGridDefinition?.suppression,
              ),
        controller.signal,
      );
      if (!current()) return;
      setRows(
        plan.kind === "calculated"
          ? page.rows.map((cell) => ({ ...cell, kind: "numeric" as const }))
          : page.rows,
      );
      setNextCursor(page.nextCursor || null);
      setSource(plan.label);
      setCompletedRead({ context, plan });
      setCalculationContext(
        plan.kind === "calculated"
          ? {
              resultKey: page.resultKey || plan.resultKey || "",
              resultStateToken: page.resultStateToken || "",
              inputsMatch: page.inputRevisionStatus?.matchesAtRead === true,
              accountingStatus:
                page.aggregateContext?.accountingPolicyStatus ||
                page.contributionContext?.accountingPolicyStatus,
            }
          : null,
      );
    } catch (reason) {
      if (!current()) return;
      // A failed authorization, stale pin or unavailable read invalidates the
      // displayed snapshot. Never leave values from an earlier authority cut
      // visible beside the new failure.
      setRows([]);
      setNextCursor(null);
      setResolvedPage(null);
      setSource("");
      setResolvedStatus(null);
      setCalculationContext(null);
      setCompletedRead(null);
      setSelectedCell(null);
      setError(
        reason instanceof Error ? reason.message : "Unable to read grid",
      );
    } finally {
      if (current()) {
        pending.pending = false;
        setBusy(false);
        gridFocus.finish(focusRequest);
      }
    }
  }

  function withdrawGridSnapshot(message: string) {
    if (!mounted.current || activeGridReadContext.current !== gridReadContext)
      return;
    cellReturn.current = cellTrigger.current;
    cellTrigger.current = null;
    cancelGridRead(gridReadContext);
    clearGridSnapshot();
    setError(message);
    void onRefreshCatalog?.().catch(() => undefined);
  }

  function withdrawGridAfterAuthorityFailure(reason: unknown) {
    const invalidated =
      isApplicationAccessDenied(reason) ||
      (reason instanceof ApiError &&
        [
          "CUBE_READ_AUTHORIZATION_STALE",
          "DIMENSIONAL_SECURITY_REVISION_CHANGED",
          "IDENTITY_INACTIVE",
          "IDENTITY_SESSION_REVOKED",
          "STALE_SECURITY_REVISION",
          "STALE_METADATA_REVISION",
        ].includes(reason.code));
    if (invalidated)
      withdrawGridSnapshot(
        "Current access to this cell could not be confirmed. Read the grid again to check what is available.",
      );
    return invalidated;
  }

  function reportCellReadFailure(reason: unknown, fallback: string) {
    if (!withdrawGridAfterAuthorityFailure(reason))
      setError(reason instanceof Error ? reason.message : fallback);
  }

  function applyCellEditability(editability: CellEditability) {
    if (editability.reasonCode === "CELL_UNAVAILABLE") {
      withdrawGridSnapshot(
        "The selected cell is unavailable. Read the grid again to check what is available.",
      );
      return false;
    }
    setCellEditability(editability);
    return true;
  }

  async function selectCell(cell: CubeCell, preserveDraft = false) {
    if (!scope || !loadedRead) return;
    const version = ++cellReadVersion.current;
    const selectionScope = activeScopeKey;
    cellReadController.current?.abort();
    const controller = new AbortController();
    cellReadController.current = controller;
    const current = () =>
      version === cellReadVersion.current &&
      activeScope.current === selectionScope &&
      activeGridReadContext.current === gridReadContext &&
      !controller.signal.aborted;
    setSelectedCell(cell);
    if (!preserveDraft) {
      setWriteKind(cell.kind || "numeric");
      setWriteOperation("set");
      setWriteValue(
        cell.kind === "text" ? (cell.text ?? "") : (cell.amount ?? ""),
      );
      setWriteTouched(false);
    }
    setInspectorSnapshot(null);
    setResolvedChangeIds({ numeric: "", text: "" });
    setCellResolved(false);
    setCellEditability(null);
    setWriteResult("");
    setCellReadBusy(true);
    setError("");
    try {
      const page = await readProgram<CubePage>(
        scope,
        "facts.cube.scan",
        {
          members: cell.members,
          limit: 2,
          includeMissing: true,
        },
        controller.signal,
      );
      if (!current()) return;
      const exact = page.rows.find(
        (candidate) =>
          Object.keys(candidate.members || {}).length ===
            Object.keys(cell.members).length &&
          Object.entries(cell.members).every(
            ([dimension, member]) => candidate.members?.[dimension] === member,
          ),
      );
      setResolvedChangeIds({
        numeric: exact?.numericChangeId || "",
        text: exact?.textChangeId || "",
      });
      const currentCell: CubeCell = {
        members: cell.members,
        kind: exact?.kind === "text" ? "text" : "numeric",
        ...(exact?.kind === "text"
          ? { text: exact.text ?? null }
          : { amount: exact?.amount ?? null }),
        numericChangeId: exact?.numericChangeId,
        textChangeId: exact?.textChangeId,
        lastRevision: exact?.lastRevision,
      };
      setSelectedCell(currentCell);
      setInspectorSnapshot(page.snapshotRevision ?? null);
      if (!preserveDraft) {
        setWriteKind(currentCell.kind);
        setWriteValue(
          currentCell.kind === "text"
            ? (currentCell.text ?? "")
            : (currentCell.amount ?? ""),
        );
      }
      const editability = await readProgram<CellEditability>(
        scope,
        "facts.cell.editability.read",
        {
          coordinate: cell.members,
          source: "raw",
          action: preserveDraft ? writeOperation : "set",
          kind: preserveDraft ? writeKind : currentCell.kind,
        },
        controller.signal,
      );
      if (!current()) return;
      if (applyCellEditability(editability)) setCellResolved(true);
    } catch (reason) {
      if (!current()) return;
      reportCellReadFailure(reason, "Unable to resolve cell");
    } finally {
      if (current()) setCellReadBusy(false);
    }
  }

  async function inspectCalculatedCell(cell: CubeCell) {
    if (!scope || !loadedRead) return;
    const version = ++cellReadVersion.current;
    const selectionScope = activeScopeKey;
    cellReadController.current?.abort();
    const controller = new AbortController();
    cellReadController.current = controller;
    const current = () =>
      version === cellReadVersion.current &&
      activeScope.current === selectionScope &&
      activeGridReadContext.current === gridReadContext &&
      !controller.signal.aborted;
    setSelectedCell(cell);
    setReviewed(false);
    setWriteResult("");
    setResolvedChangeIds({ numeric: "", text: "" });
    setCellResolved(false);
    setCellEditability(null);
    setCellReadBusy(true);
    setError("");
    try {
      const editability = await readProgram<CellEditability>(
        scope,
        "facts.cell.editability.read",
        {
          coordinate: cell.members,
          source: "calculated",
          action: "set",
          kind: "numeric",
        },
        controller.signal,
      );
      if (current()) applyCellEditability(editability);
    } catch (reason) {
      if (current())
        reportCellReadFailure(reason, "Unable to inspect cell editability");
    } finally {
      if (current()) setCellReadBusy(false);
    }
  }

  async function refreshRawCellEditability(
    cell: CubeCell,
    action: "set" | "add" | "clear",
    kind: "numeric" | "text" = writeKind,
  ) {
    if (!scope) return;
    const version = ++cellReadVersion.current;
    const selectionScope = activeScopeKey;
    cellReadController.current?.abort();
    const controller = new AbortController();
    cellReadController.current = controller;
    const current = () =>
      version === cellReadVersion.current &&
      activeScope.current === selectionScope &&
      activeGridReadContext.current === gridReadContext &&
      !controller.signal.aborted;
    setCellEditability(null);
    setCellReadBusy(true);
    setError("");
    try {
      const editability = await readProgram<CellEditability>(
        scope,
        "facts.cell.editability.read",
        { coordinate: cell.members, source: "raw", action, kind },
        controller.signal,
      );
      if (current()) applyCellEditability(editability);
    } catch (reason) {
      if (current())
        reportCellReadFailure(reason, "Unable to inspect cell editability");
    } finally {
      if (current()) setCellReadBusy(false);
    }
  }

  const coordinateComplete = Boolean(
    selectedCell &&
      dimensions.length &&
      Object.keys(selectedCell.members).length === dimensions.length &&
      dimensions.every(
        (dimension) => selectedCell.members[dimension.dimension_id],
      ),
  );
  const exactDecimal = /^[+-]?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/;
  const writeFunction =
    writeKind === "numeric" ? "facts.numeric.batch" : "facts.text.batch";
  const writeAuthorized = Boolean(catalog?.functions[writeFunction]);
  const writeReady = Boolean(
    coordinateComplete &&
      cellResolved &&
      cellEditability?.editable === true &&
      writeAuthorized &&
      !(writeKind === "text" && writeOperation === "add") &&
      (writeOperation === "clear" ||
        writeKind === "text" ||
        exactDecimal.test(writeValue)),
  );
  const exactWriteProgram =
    selectedCell && writeReady
      ? buildWritebackProgram(
          writeKind,
          writeOperation,
          selectedCell.members,
          writeValue,
          expectedChangeId,
        )
      : null;
  const cellMutation = useExactCellMutation(
    scope,
    JSON.stringify([
      activeScopeKey,
      subject,
      catalog?.applicationAccess.issuer,
      catalog?.applicationAccess.role,
      catalog?.applicationAccess.workspaceAdministrator,
      catalog?.revisions,
    ]),
    "grid-cell-mutation",
    exactWriteProgram,
    JSON.stringify([catalog?.applicationAccess.issuer, subject]),
  );
  useEffect(() => {
    if (!cellMutation.review) setReviewed(false);
  }, [cellMutation.review]);

  async function submitWriteback() {
    if (!writeReady || !reviewed || !cellMutation.review) return;
    await runFocusedMutation(cellMutation.submit);
    setReviewed(false);
  }

  async function runFocusedMutation(action: () => Promise<void>) {
    const focusRequest = gridFocus.begin("mutation");
    try {
      await action();
    } finally {
      gridFocus.finish(focusRequest);
    }
  }

  const visibleRows = loadedRead ? rows : [];
  const hasMoreGridPages = Boolean(
    loadedRead &&
      (resolvedPage
        ? hasResolvedNextPage(
            resolvedPage.cells,
            resolvedPage.pageSize,
            resolvedPage.offset,
          )
        : nextCursor),
  );
  const matrix = useMemo(() => {
    if (!activeRowDimensions.length || !activeColumnDimensions.length)
      return null;
    const compareRows = gridMemberComparator(
      activeRowDimensions,
      memberCatalog,
      axisSelectorFor,
    );
    const compareColumns = gridMemberComparator(
      activeColumnDimensions,
      memberCatalog,
      axisSelectorFor,
    );
    const key = (values: string[]) => JSON.stringify(values);
    const columnTuples = new Map<string, string[]>();
    const rowTuples = new Map<string, string[]>();
    const cells = new Map<string, CubeCell>();
    for (const cell of visibleRows) {
      const row = activeRowDimensions.map(
        (dimension) => cell.members[dimension],
      );
      const column = activeColumnDimensions.map(
        (dimension) => cell.members[dimension],
      );
      if (row.some((value) => !value) || column.some((value) => !value))
        return null;
      const rowKey = key(row);
      const columnKey = key(column);
      const cellKey = `${rowKey}\u0000${columnKey}`;
      if (cells.has(cellKey)) return null;
      rowTuples.set(rowKey, row);
      columnTuples.set(columnKey, column);
      cells.set(cellKey, cell);
    }
    if (!rowTuples.size || !columnTuples.size) return null;
    return {
      rowTuples: [...rowTuples.entries()].sort((left, right) =>
        compareRows(left[1], right[1]),
      ),
      columnTuples: [...columnTuples.entries()].sort((left, right) =>
        compareColumns(left[1], right[1]),
      ),
      cells,
    };
  }, [
    visibleRows,
    activeRowDimensions.join("\u0000"),
    activeColumnDimensions.join("\u0000"),
    memberCatalog,
    axisSelections,
    openedGridDefinition?.selection,
  ]);

  const matrixCoordinate = (row: string[], column: string[]) => ({
    ...pov,
    ...Object.fromEntries(activeRowDimensions.map((id, i) => [id, row[i]])),
    ...Object.fromEntries(
      activeColumnDimensions.map((id, i) => [id, column[i]]),
    ),
  });
  const gridFocus = useGridFocus(
    `${gridReadContext}:${presentation}`,
    matrix
      ? matrix.rowTuples.map(([rowKey, row]) =>
          matrix.columnTuples.map(([columnKey, column]) =>
            gridCoordinateKey(
              matrix.cells.get(`${rowKey}\u0000${columnKey}`)?.members ||
                matrixCoordinate(row, column),
              matrix.cells.get(`${rowKey}\u0000${columnKey}`)?.kind ||
                "numeric",
            ),
          ),
        )
      : visibleRows.map((cell) => [gridCoordinateKey(cell.members, cell.kind)]),
    busy || cellMutation.busy,
    Boolean(cellMutation.pending),
    interactionBlocked,
  );
  const gridRoot = gridFocus.root;
  useLayoutEffect(() => {
    if (interactionBlocked) cellReturn.current = null;
    if (selectedCell || busy || !cellReturn.current) return;
    const origin = cellReturn.current;
    cellReturn.current = null;
    const root = gridRoot.current;
    if (root?.contains(origin) && !origin.disabled) origin.focus();
    else
      root
        ?.querySelector<HTMLElement>(
          "button[data-grid-row][tabindex='0']:not(:disabled), [data-grid-focus-status]",
        )
        ?.focus();
  }, [selectedCell, busy, interactionBlocked, gridRoot]);

  const numericPresentationCells = useMemo(
    () =>
      visibleRows.filter(
        (cell): cell is CubeCell & { amount: string } =>
          cell.kind === "numeric" &&
          typeof cell.amount === "string" &&
          cell.amount !== "",
      ),
    [visibleRows],
  );
  const presentedNumericCells = numericPresentationCells.slice(0, 24);
  const hasPresentText = visibleRows.some((cell) =>
    cell.layerValues
      ? Object.values(cell.layerValues).some((values) =>
          values?.some((value) => value.present && value.unit === "text"),
        )
      : cell.kind === "text" && typeof cell.text === "string",
  );
  const hasSeparateValues = visibleRows.some(
    (cell) => cellPresence(cell) === "Separate source values",
  );
  const presentationUnits = new Set(
    visibleRows.flatMap((cell) =>
      cell.layerValues
        ? Object.values(cell.layerValues).flatMap((values) =>
            (values || [])
              .filter((value) => value.present && value.unit !== "text")
              .map((value) =>
                typeof value.unit === "object" && value.unit
                  ? JSON.stringify(
                      Object.entries(value.unit).sort(([left], [right]) =>
                        left.localeCompare(right),
                      ),
                    )
                  : JSON.stringify(value.unit),
              ),
          )
        : cell.kind === "numeric" &&
            typeof cell.amount === "string" &&
            cell.amount !== ""
          ? [JSON.stringify(cell.resultUnit || "amount")]
          : [],
    ),
  );
  const numericPresentationUnavailable =
    openedGridDefinition?.dataSource.kind === "combined"
      ? "KPI and chart presentations require a single source layer. Raw and calculated values remain separate in this view."
      : !loadedRead
        ? readingGrid
          ? "Reading the grid. KPI and chart presentations will be available after a successful numeric read."
          : "Read the grid to enable KPI and chart presentations."
        : hasPresentText
          ? "KPI and chart presentations require numeric values. The loaded page contains text, including any present empty text; these values remain in the grid."
          : presentationUnits.size > 1
            ? "KPI and chart presentations require compatible units. The loaded page contains different units."
            : hasSeparateValues
              ? "KPI and chart presentations require one value per coordinate. Separate source values remain in the grid."
              : !numericPresentationCells.length
                ? "KPI and chart presentations require a present numeric value. The loaded page has none; missing values are not treated as zero."
                : "";
  const numericPresentationNoteId = useId();
  useEffect(() => {
    if (
      numericPresentationUnavailable &&
      (presentation === "kpi" || presentation === "chart")
    )
      setPresentation("grid");
  }, [numericPresentationUnavailable, presentation]);
  const numericPresentationScope = `Showing ${presentedNumericCells.length} of ${numericPresentationCells.length} present numeric values on the loaded page.${visibleRows.length > numericPresentationCells.length ? " Missing values are omitted, not converted to zero." : ""}${hasMoreGridPages ? " More grid pages are available; this is not the complete selection." : ""}`;
  const numericPresentationNote =
    numericPresentationUnavailable ||
    (presentation === "kpi" || presentation === "chart"
      ? numericPresentationScope
      : "");
  const chartMaximum = useMemo(
    () =>
      Math.max(
        0,
        ...numericPresentationCells.slice(0, 24).map((cell) => {
          const value = Math.abs(Number(cell.amount));
          return Number.isFinite(value) ? value : 0;
        }),
      ),
    [numericPresentationCells],
  );

  function presentationLabel(cell: CubeCell) {
    return (
      [...activeRowDimensions, ...activeColumnDimensions]
        .map((dimension) => cell.members[dimension])
        .filter(Boolean)
        .join(" · ") || "Selected coordinate"
    );
  }

  function presentationValue(cell: CubeCell & { amount: string }) {
    const value = cell.layerValues && Object.values(cell.layerValues)[0]?.[0];
    return value ? layerValueText(value) : cell.amount;
  }

  function changeGridContext(action: () => void, replaceView = false) {
    const apply = () => {
      setWriteTouched(false);
      setReviewed(false);
      if (replaceView && savedGridTouched) {
        setSavedGridId("");
        setSavedGridName("");
        setSavedGridTouched(false);
      }
      action();
    };
    if (writeTouched || (replaceView && savedGridTouched))
      onRequestTransition(apply);
    else apply();
  }

  function openCellInspector(cell: CubeCell, trigger: HTMLButtonElement) {
    changeGridContext(() => {
      cellTrigger.current = trigger;
      setCellInspectorOpening((opening) => opening + 1);
      if (calculatedGrid) void inspectCalculatedCell(cell);
      else void selectCell(cell);
    });
  }

  const inspectorCloseBlocked = gridBusy || cellMutation.busy;
  function closeCellInspector() {
    if (inspectorCloseBlocked) return;
    changeGridContext(() => {
      cancelCellRead();
      cellReturn.current = cellTrigger.current;
      cellTrigger.current = null;
      setSelectedCell(null);
    });
  }

  const selectedCoordinate = selectedCell
    ? JSON.stringify(Object.entries(selectedCell.members).sort())
    : "";
  const isSelected = (cell: CubeCell) =>
    selectedCoordinate === JSON.stringify(Object.entries(cell.members).sort());
  const scenarioAxis = dimensions.find(
    (axis) => axis.status === "Active" && axis.model_role === "Scenario",
  );
  // Like the other Grid pickers, the modal sits above the sticky cell drawer.
  const comparisonDialogHost = gridFocus.root.current;
  const comparisonCapability = catalog?.functions[SCENARIO_COMPARISON] as
    | { calculatedScenarioComparison?: boolean }
    | undefined;
  const comparisonUnits =
    selectedCell?.layerValues?.calculated?.flatMap((value) =>
      value.present &&
      value.currentness === "current" &&
      value.resultStateToken === calculationContext?.resultStateToken &&
      isComparisonUnit(value.unit)
        ? [value.unit]
        : [],
    ) ?? [];
  const publishedComparison =
    comparisonCapability?.calculatedScenarioComparison === true &&
    calculationContext?.inputsMatch &&
    calculationContext.resultKey ===
      openedGridDefinition?.dataSource.resultKey &&
    comparisonUnits.length
      ? {
          resultKey: calculationContext.resultKey,
          resultStateToken: calculationContext.resultStateToken,
          units: comparisonUnits,
        }
      : undefined;

  return (
    <div className="page analyze-page" ref={gridFocus.root}>
      <div className="page-heading data-workspace-header">
        <div>
          <span>{app?.name || "Application"}</span>
          <h1>Grid</h1>
          <p>
            Choose your view, read a snapshot and inspect or update exact cell
            values.
          </p>
        </div>
        <div className="data-stage-summary" aria-label="Grid snapshot status">
          <span className={`task-state ${loadedRead ? "active" : "neutral"}`}>
            {readingGrid
              ? "Reading grid…"
              : !loadedRead
                ? "Ready to configure"
                : resolvedStatus === "current-empty"
                  ? "Current · Empty"
                  : `${visibleRows.length} loaded cells`}
          </span>
          {calculatedGrid && (
            <span className="task-state neutral">
              {openedGridDefinition?.dataSource.kind === "combined"
                ? "Combined"
                : "Calculated"}{" "}
              · read only
            </span>
          )}
        </div>
      </div>

      {app && catalog && metadataRevision === catalog.revisions.metadata && (
        <ScenarioPromotion
          app={app}
          catalog={catalog}
          dimensions={dimensions}
          memberCatalog={memberCatalog}
          loadMembers={ensureMembers}
          onRefreshCatalog={onRefreshCatalog}
          comparisonControl={scenarioCopyControl}
        />
      )}
      <section className="layout-summary" aria-label="Current grid layout">
        {configuredLayout.map((axis) => (
          <div key={axis.key}>
            <small>{axis.label.toUpperCase()}</small>
            <strong>{axis.text}</strong>
          </div>
        ))}
        <button
          type="button"
          aria-controls="grid-layout-drawer"
          aria-expanded={layoutOpen}
          onClick={() => setLayoutOpen((current) => !current)}
        >
          {layoutOpen ? "Close layout" : "Configure layout"}
        </button>
      </section>
      <p className="context-note" aria-label="Configured grid source">
        Configured source layer: {savedGridDefinition.dataSource.kind}.
        Configuration does not mean a snapshot has been read.
      </p>
      {Boolean(catalog?.functions["facts.cube.resolved.read"]) && (
        <section className="context-note" aria-label="Grid value semantics">
          <label>
            Value semantics
            <select
              value={readSemantics}
              onChange={(event) => {
                setReadSemantics(event.target.value as GridReadSemantics);
                setRows([]);
              }}
            >
              <option value="stored">Stored values</option>
              <option value="own">Own input at each member</option>
              <option value="effective">Effective governed value</option>
            </select>
          </label>
          {readSemantics === "effective" && (
            <>
              <label>
                Effective binding
                <select
                  value={`${resolvedBindingId}:${resolvedBindingStateToken}`}
                  onChange={(event) => {
                    const binding = resolvedBindings.find(
                      (item) =>
                        `${item.bindingId}:${item.stateToken}` ===
                        event.target.value,
                    );
                    if (binding) {
                      setResolvedBindingId(binding.bindingId);
                      setResolvedBindingStateToken(binding.stateToken);
                    }
                  }}
                >
                  <option value=":">Choose an active binding</option>
                  {resolvedBindings.map((binding) => (
                    <option
                      key={`${binding.bindingId}:${binding.stateToken}`}
                      value={`${binding.bindingId}:${binding.stateToken}`}
                    >
                      {binding.bindingId} · {binding.stages.length} stages
                    </option>
                  ))}
                </select>
              </label>
            </>
          )}
          <p>
            Own reads preserve direct parent input. Effective reads apply the
            selected active calculation and hierarchy binding; they never write
            or silently recalculate data. Saved definitions store the source
            layer, not the read policy. Opening a view selects its displayed
            supported default policy; an explicit view link restores its stated
            supported read policy or refuses the read. Effective bindings are
            session-only and are not restored by saved views or view links.
          </p>
        </section>
      )}
      {plannedRead && !readUnavailable && (
        <p className="context-note" aria-label="Configured read policy">
          Next read: {plannedRead.label}
        </p>
      )}
      {readUnavailable && (
        <p
          className="context-note"
          role="status"
          aria-label="Grid read unavailable"
        >
          {readUnavailable}
        </p>
      )}
      {loadedRead && (
        <p className="context-note" aria-label="Loaded grid read">
          {source}
          {hasMoreGridPages && " · More pages available"}
        </p>
      )}
      {targetViewId && savedGridResult && (
        <p className="context-note" role="status">
          {savedGridResult}
        </p>
      )}

      <aside
        id="grid-layout-drawer"
        className={layoutOpen ? "layout-drawer open" : "layout-drawer"}
        aria-label="Pages, rows, columns and filters"
        hidden={!layoutOpen}
      >
        <div className="drawer-heading">
          <div>
            <span>Grid designer</span>
            <h2>Pages, rows, columns and filters</h2>
          </div>
          <button
            type="button"
            aria-label="Close grid layout"
            onClick={() => setLayoutOpen(false)}
          >
            ×
          </button>
        </div>
        <p>
          {openedGridDefinition
            ? "Rows and Columns choose the first axis by swapping its position with the selected dimension. Every dimension keeps its member selection and exclusions. Use the ordered layout below to move or reorder any axis; source layer, suppression and page size stay unchanged."
            : "Choose the two initial axes here. The point of view below selects members for the remaining dimensions. Open a saved view to arrange all of its ordered axes."}
        </p>
        <section className="layout-builder" aria-label="Grid layout">
          <label>
            Rows
            <select
              aria-label="Rows"
              value={rowDimension}
              onChange={(event) =>
                choosePrimaryAxis("rows", event.target.value)
              }
            >
              <option value="" disabled={Boolean(openedGridDefinition)}>
                Choose dimension
              </option>
              {dimensions.map((dimension) => (
                <option
                  key={dimension.dimension_id}
                  value={dimension.dimension_id}
                  disabled={
                    !openedGridDefinition &&
                    dimension.dimension_id === columnDimension
                  }
                >
                  {dimension.name}
                </option>
              ))}
            </select>
          </label>
          {rowDimension && (
            <div className="axis-member-selection">
              <span>Row members</span>
              <strong>{semanticAxisSummary(rowDimension)}</strong>
              <button
                type="button"
                disabled={
                  calculatedGrid ||
                  !catalog?.functions["facts.cube.resolved.read"]
                }
                onClick={() => void openAxisSelector(rowDimension)}
              >
                Choose row members
              </button>
            </div>
          )}
          <label>
            Columns
            <select
              aria-label="Columns"
              value={columnDimension}
              onChange={(event) =>
                choosePrimaryAxis("columns", event.target.value)
              }
            >
              <option value="" disabled={Boolean(openedGridDefinition)}>
                Choose dimension
              </option>
              {dimensions.map((dimension) => (
                <option
                  key={dimension.dimension_id}
                  value={dimension.dimension_id}
                  disabled={
                    !openedGridDefinition &&
                    dimension.dimension_id === rowDimension
                  }
                >
                  {dimension.name}
                </option>
              ))}
            </select>
          </label>
          {columnDimension && (
            <div className="axis-member-selection">
              <span>Column members</span>
              <strong>{semanticAxisSummary(columnDimension)}</strong>
              <button
                type="button"
                disabled={
                  calculatedGrid ||
                  !catalog?.functions["facts.cube.resolved.read"]
                }
                onClick={() => void openAxisSelector(columnDimension)}
              >
                Choose column members
              </button>
            </div>
          )}
          <button
            onClick={suggestLayout}
            disabled={busy || dimensions.length < 2}
          >
            Suggest layout
          </button>
        </section>
        {openedGridDefinition && (
          <section aria-label="Ordered view layout">
            <h3>Ordered axes</h3>
            <p>
              Rows and Columns each require at least one axis. Moving an axis
              appends it to its destination; use Earlier and Later to change its
              order. Pages and Filters retain the exact existing member
              selections, including sets and exclusions.
            </p>
            {layoutRoles.map((role) => (
              <fieldset key={role}>
                <legend>{layoutRoleLabels[role]}</legend>
                {openedGridDefinition.layout[role].length === 0 && (
                  <p>No axes</p>
                )}
                {openedGridDefinition.layout[role].map(
                  (dimensionId, position) => {
                    const name =
                      dimensions.find(
                        (item) => item.dimension_id === dimensionId,
                      )?.name || dimensionId;
                    const requiredLast =
                      (role === "rows" || role === "columns") &&
                      openedGridDefinition.layout[role].length === 1;
                    return (
                      <div key={dimensionId}>
                        <label>
                          {position + 1}. {name}
                          <select
                            aria-label={`${name} axis location`}
                            ref={(node) => {
                              if (node)
                                layoutControls.current.set(dimensionId, node);
                              else layoutControls.current.delete(dimensionId);
                            }}
                            value={role}
                            onChange={(event) =>
                              moveCanonicalAxis(
                                dimensionId,
                                role,
                                event.target.value as LayoutRole,
                              )
                            }
                          >
                            {layoutRoles.map((target) => (
                              <option
                                key={target}
                                value={target}
                                disabled={requiredLast && target !== role}
                              >
                                {layoutRoleLabels[target]}
                              </option>
                            ))}
                          </select>
                        </label>
                        <button
                          type="button"
                          aria-label={`Move ${name} earlier in ${layoutRoleLabels[role]}`}
                          disabled={position === 0}
                          onClick={() =>
                            reorderCanonicalAxis(role, position, -1)
                          }
                        >
                          Earlier
                        </button>
                        <button
                          type="button"
                          aria-label={`Move ${name} later in ${layoutRoleLabels[role]}`}
                          disabled={
                            position ===
                            openedGridDefinition.layout[role].length - 1
                          }
                          onClick={() =>
                            reorderCanonicalAxis(role, position, 1)
                          }
                        >
                          Later
                        </button>
                      </div>
                    );
                  },
                )}
              </fieldset>
            ))}
          </section>
        )}
        {!openedGridDefinition && (
          <dl className="layout-drawer-summary">
            <div>
              <dt>Pages</dt>
              <dd>
                {Object.keys(pov).length
                  ? "Point of view"
                  : "Choose axes first"}
              </dd>
            </div>
            <div>
              <dt>Filters</dt>
              <dd>
                {Object.entries(pov).length
                  ? Object.entries(pov)
                      .map(([dimension, member]) => `${dimension}: ${member}`)
                      .join(" · ")
                  : "No fixed members"}
              </dd>
            </div>
          </dl>
        )}
      </aside>

      <div className="analysis-tools">
        {Boolean(
          catalog?.functions["grid.definition.list"] ||
            catalog?.functions["grid.definition.save"],
        ) && (
          <section
            className="shared-grid-definitions saved-grid-browser"
            aria-label="Saved views"
            aria-busy={readingSavedGrids}
          >
            <h2>Saved views</h2>
            <p>
              Views shared with this application. Open one to use its saved
              rows, columns and point of view.
            </p>
            {canReadSavedGrids && (
              <>
                <div className="shared-grid-row">
                  <label>
                    Saved view
                    <select
                      aria-label="Saved view"
                      value={selectedSavedGrid}
                      disabled={readingSavedGrids || !currentSavedGrids.length}
                      onChange={(event) =>
                        setSelectedSavedGrid(event.target.value)
                      }
                    >
                      {!currentSavedGrids.length && (
                        <option value="">
                          {readingSavedGrids
                            ? "Loading saved views…"
                            : currentSavedGridsError
                              ? "Unable to load saved views"
                              : currentSavedGridsRead
                                ? "No saved views"
                                : "Saved views not loaded"}
                        </option>
                      )}
                      {currentSavedGrids.map((grid) => (
                        <option key={grid.gridId} value={grid.gridId}>
                          {grid.name}
                          {!canOpenSavedGrid(grid)
                            ? " · unavailable in the current application"
                            : ""}
                        </option>
                      ))}
                    </select>
                  </label>
                  <button
                    type="button"
                    onClick={() =>
                      selectedGrid &&
                      changeGridContext(() => openSavedGrid(selectedGrid), true)
                    }
                    disabled={
                      busy ||
                      readingSavedGrids ||
                      !selectedGrid ||
                      !canOpenSavedGrid(selectedGrid)
                    }
                  >
                    Open view
                  </button>
                  <button
                    type="button"
                    onClick={() => void readSavedGrids()}
                    disabled={readingSavedGrids}
                  >
                    Refresh views
                  </button>
                  {Boolean(catalog?.functions["grid.definition.delete"]) && (
                    <button
                      type="button"
                      onClick={() => void deleteSharedGrid()}
                      disabled={busy || readingSavedGrids || !selectedGrid}
                    >
                      Delete view
                    </button>
                  )}
                </div>
                <p className="saved-grid-list-status" aria-live="polite">
                  {readingSavedGrids
                    ? "Loading saved views…"
                    : currentSavedGridsError
                      ? "Saved views could not be loaded. Refresh to retry."
                      : currentSavedGridsRead
                        ? `${currentSavedGrids.length} saved view${currentSavedGrids.length === 1 ? "" : "s"}`
                        : "Saved views not loaded."}
                </p>
                {currentSavedGridsError && (
                  <p role="alert">{currentSavedGridsError}</p>
                )}
              </>
            )}
            {Boolean(catalog?.functions["grid.definition.save"]) && (
              <details className="saved-grid-save">
                <summary>Save current view</summary>
                <div className="shared-grid-authoring">
                  <label>
                    Stable grid ID
                    <input
                      value={savedGridId}
                      maxLength={128}
                      onChange={(event) => {
                        setSavedGridId(event.target.value);
                        setSavedGridTouched(true);
                      }}
                    />
                  </label>
                  <label>
                    Display name
                    <input
                      value={savedGridName}
                      maxLength={200}
                      onChange={(event) => {
                        setSavedGridName(event.target.value);
                        setSavedGridTouched(true);
                      }}
                    />
                  </label>
                  <button
                    type="button"
                    onClick={() => void saveSharedGrid()}
                    disabled={!savedGridReady || busy}
                  >
                    Save view
                  </button>
                </div>
              </details>
            )}
            {savedGridResult && <p role="status">{savedGridResult}</p>}
            {openedGridDefinition && (
              <dl
                className="saved-grid-open-context"
                aria-label="Opened grid layout"
              >
                {configuredLayout.map((axis) => (
                  <div key={axis.key}>
                    <dt>{axis.label}</dt>
                    <dd>{axis.text}</dd>
                  </div>
                ))}
                <div>
                  <dt>Layer</dt>
                  <dd>{openedGridDefinition.dataSource.kind}</dd>
                </div>
              </dl>
            )}
          </section>
        )}

        {Boolean(
          catalog?.functions["facts.cube.aggregate.request"] ||
            catalog?.functions["facts.cube.aggregate.read"],
        ) && (
          <details className="aggregate-workspace">
            <summary>Aggregate large cube selections</summary>
            <p>
              Reduce authorized raw numeric facts into durable exact result
              pages. The current layout, point of view and measures define a new
              query draft. An accepted query keeps its original intent when this
              draft changes. The fixed core owns snapshots, execution,
              authorization and the technical certificate.
            </p>
            <fieldset>
              <legend>Measures</legend>
              {(
                [
                  ["SumAmount", "Sum"],
                  ["CountPresent", "Count present"],
                  ["MinAmount", "Minimum"],
                  ["MaxAmount", "Maximum"],
                ] as Array<[AggregateMeasure, string]>
              ).map(([kind, label]) => (
                <label key={kind}>
                  <input
                    type="checkbox"
                    checked={aggregateMeasures.includes(kind)}
                    onChange={(event) =>
                      setAggregateMeasures((current) =>
                        event.target.checked
                          ? [...current, kind]
                          : current.filter((item) => item !== kind),
                      )
                    }
                  />
                  {label}
                </label>
              ))}
            </fieldset>
            <div className="aggregate-controls">
              <label>
                Result page size
                <input
                  aria-label="Aggregate result page size"
                  type="number"
                  min={1}
                  max={500}
                  value={aggregatePageSize}
                  disabled={busy}
                  onChange={(event) =>
                    setAggregatePageSize(Number(event.target.value))
                  }
                />
              </label>
              <button
                type="button"
                disabled={
                  busy ||
                  !aggregateQueryId ||
                  !catalog?.functions["facts.cube.aggregate.read"]
                }
                onClick={() => void readAggregate()}
              >
                Refresh status and results
              </button>
            </div>
            <p className={aggregateReady ? "ready-copy" : "muted-copy"}>
              {!aggregatePageSizeValid
                ? "Page size must be an integer from 1 to 500."
                : aggregateIntentError ||
                  "The exact aggregate intent is ready for review."}
            </p>
            <label className="review-check">
              <input
                type="checkbox"
                checked={aggregateReviewed}
                disabled={!aggregateReady || busy}
                onChange={(event) =>
                  setAggregateReviewed(
                    event.target.checked ? aggregateReviewKey : null,
                  )
                }
              />
              I reviewed this exact aggregate query
            </label>
            <button
              type="button"
              disabled={!aggregateReady || !aggregateReviewed || busy}
              onClick={() => void requestAggregate()}
            >
              Request durable aggregate
            </button>
            <p role="status">
              {aggregateQueryId
                ? `Aggregate request · ${aggregateStatus || "status not read"}`
                : "No aggregate request has been made."}
            </p>
            {aggregateObservation?.status === "failed" &&
              aggregateObservation.errorCode ===
                "CUBE_AGGREGATE_AMOUNT_MEASURE_REQUIRED" && (
                <p role="alert">
                  This query includes ratios. Select Count present alone to
                  count cells, or calculate the rate from its underlying
                  quantities.
                </p>
              )}
            {aggregateObservation && (
              <section aria-label="Accepted aggregate query">
                <h3>Accepted query</h3>
                <p>
                  These results belong to the accepted query below. Later layout
                  or measure edits apply only to a new reviewed request.
                </p>
                <dl>
                  <dt>Group by</dt>
                  <dd>
                    {aggregateObservation.query.grain.groupBy.join(" → ")}
                  </dd>
                  <dt>Fixed members</dt>
                  <dd>
                    {Object.entries(aggregateObservation.query.selectors)
                      .map(
                        ([dimension, selector]) =>
                          `${dimension}: ${selector.memberIds.join(", ")}`,
                      )
                      .join(" · ") || "None"}
                  </dd>
                  <dt>Reduced dimensions</dt>
                  <dd>
                    {aggregateObservation.query.grain.reduceDimensions.join(
                      ", ",
                    ) || "None"}
                  </dd>
                  <dt>Measures</dt>
                  <dd>
                    {aggregateObservation.query.measures
                      .map((measure) => aggregateMeasureLabels[measure.kind])
                      .join(" · ")}
                  </dd>
                  <dt>Result page size</dt>
                  <dd>{aggregateObservation.pageSize}</dd>
                </dl>
              </section>
            )}
            {aggregateQueryId && !aggregateObservation && (
              <p>
                A known aggregate request is retained. Refresh to inspect its
                currently authorized state. Its prior intent and results are
                hidden.
              </p>
            )}
            {aggregateRows.length > 0 && (
              <div className="react-grid-scroll">
                <table
                  className="react-cube-grid aggregate-result-grid"
                  aria-label="Aggregate results"
                >
                  <thead>
                    <tr>
                      <th>Grouped members</th>
                      <th>Sum</th>
                      <th>Count present</th>
                      <th>Minimum</th>
                      <th>Maximum</th>
                    </tr>
                  </thead>
                  <tbody>
                    {aggregateRows.map((row, rowIndex) => (
                      <tr key={`${rowIndex}-${JSON.stringify(row.members)}`}>
                        <th>
                          {Object.entries(row.members)
                            .map(
                              ([dimension, member]) =>
                                `${dimension}: ${member}`,
                            )
                            .join(" · ") || "Scalar result"}
                        </th>
                        <td>{row.sumAmount ?? "—"}</td>
                        <td>{row.countPresent ?? "—"}</td>
                        <td>{row.minAmount ?? "—"}</td>
                        <td>{row.maxAmount ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <div className="aggregate-actions">
              <button
                type="button"
                disabled={busy || !aggregateCursor}
                onClick={() => void readAggregate(aggregateCursor)}
              >
                Next result page
              </button>
              <label className="review-check">
                <input
                  type="checkbox"
                  checked={aggregateCancelReviewed}
                  disabled={!aggregateCanCancel || busy}
                  onChange={(event) =>
                    setAggregateCancelReviewed(event.target.checked)
                  }
                />
                I reviewed cancellation of this exact query state
              </label>
              <button
                type="button"
                disabled={
                  !aggregateCanCancel || !aggregateCancelReviewed || busy
                }
                onClick={() => void cancelAggregate()}
              >
                Request cancellation
              </button>
            </div>
          </details>
        )}
      </div>

      <div className="pov-bar" aria-label="Point of view">
        {povDimensions.map((dimension) => {
          const savedSelector = openedGridDefinition?.selection.dimensions.find(
            (item) => item.dimensionId === dimension.dimension_id,
          )?.include;
          const selectedMemberId =
            savedSelector?.kind === "member"
              ? savedSelector.memberId
              : pov[dimension.dimension_id] || "";
          const memberLabels = Object.fromEntries(
            (memberCatalog[dimension.dimension_id] || []).map((member) => [
              member.member_id,
              member.name,
            ]),
          );
          const summary: CubeSelector | null =
            savedSelector ||
            (selectedMemberId
              ? { kind: "member", memberId: selectedMemberId }
              : null);
          return (
            <div className="pov-selector-control" key={dimension.dimension_id}>
              <span>{dimension.name}</span>
              <button
                type="button"
                aria-label={`${dimension.name} point of view`}
                aria-haspopup="dialog"
                onClick={() => void openPovSelector(dimension.dimension_id)}
              >
                <strong>
                  {summary
                    ? selectorSummary(summary, { members: memberLabels })
                    : "Choose member"}
                </strong>
                <span aria-hidden="true">▾</span>
              </button>
            </div>
          );
        })}
        <span className="pov-spacer" />
        <button
          onClick={() => scan()}
          disabled={
            busy ||
            !dimensions.length ||
            !activeRowDimensions.length ||
            !activeColumnDimensions.length ||
            Boolean(readUnavailable)
          }
        >
          {busy ? "Reading…" : "Read grid"}
        </button>
      </div>

      {axisDialogDimensionId && app && catalog && metadataRevision !== null && (
        <MemberSelectionDialog
          app={app}
          catalog={catalog}
          request={{
            dimensionId: axisDialogDimensionId,
            dimensionName:
              dimensions.find(
                (dimension) => dimension.dimension_id === axisDialogDimensionId,
              )?.name || axisDialogDimensionId,
            metadataRevision,
            title: `Choose ${
              axisDialogDimensionId === rowDimension ? "row" : "column"
            } members`,
            cardinality: { kind: "one-or-more", maximum: 10_000 },
            capability: {
              allowExplicitMembers: true,
              allowHierarchySelector: true,
              allowNamedMemberList: true,
              allowAttributeSelector: false,
              allowInlineExpression: true,
              allowExclusion: false,
              orderMatters: true,
            },
            initial: axisDialogInitialSelection,
            initialExclude:
              openedGridDefinition?.selection.dimensions.find(
                (dimension) => dimension.dimensionId === axisDialogDimensionId,
              )?.exclude ?? null,
          }}
          members={memberCatalog[axisDialogDimensionId] || []}
          onCancel={() => setAxisDialogDimensionId("")}
          onApply={(result) =>
            applyAxisSelection(
              axisDialogDimensionId,
              result.include,
              result.displaySummary,
            )
          }
        />
      )}

      {povDialogDimensionId && app && catalog && metadataRevision !== null && (
        <MemberSelectionDialog
          app={app}
          catalog={catalog}
          request={{
            dimensionId: povDialogDimensionId,
            dimensionName:
              dimensions.find(
                (dimension) => dimension.dimension_id === povDialogDimensionId,
              )?.name || povDialogDimensionId,
            metadataRevision,
            cardinality: { kind: "exactly-one" },
            capability: {
              allowExplicitMembers: true,
              allowHierarchySelector: false,
              allowNamedMemberList: false,
              allowAttributeSelector: false,
              allowInlineExpression: false,
              allowExclusion: false,
              orderMatters: false,
            },
            initial: povDialogInitialMemberId
              ? { kind: "member", memberId: povDialogInitialMemberId }
              : null,
          }}
          members={memberCatalog[povDialogDimensionId] || []}
          onCancel={() => setPovDialogDimensionId("")}
          onApply={(result) => {
            if (result.include.kind === "member")
              applyPovMember(povDialogDimensionId, result.include.memberId);
          }}
        />
      )}

      {error && (
        <div
          className="inline-error"
          role="alert"
          tabIndex={-1}
          data-grid-focus-error="read"
        >
          {error}
        </div>
      )}
      <div
        className={`analysis-data-layout${selectedCell ? " has-cell-inspector" : ""}`}
      >
        <section
          className={`grid-panel grid-density-${gridDensity}`}
          aria-label="Grid results"
        >
          {presentation === "grid" && (
            <div className="grid-keyboard-announcement" role="status">
              {gridFocus.keyboardAnnouncement}
            </div>
          )}
          <div className="grid-toolbar">
            <div role="group" aria-label="Analyze presentation">
              <button
                aria-pressed={presentation === "grid"}
                className={presentation === "grid" ? "selected" : ""}
                onClick={() => choosePresentation("grid")}
              >
                Grid
              </button>
              <button
                aria-pressed={presentation === "kpi"}
                aria-describedby={
                  numericPresentationNote
                    ? numericPresentationNoteId
                    : undefined
                }
                className={presentation === "kpi" ? "selected" : ""}
                disabled={
                  !numericPresentationCells.length ||
                  Boolean(numericPresentationUnavailable)
                }
                onClick={() => choosePresentation("kpi")}
              >
                KPI
              </button>
              <button
                aria-pressed={presentation === "chart"}
                aria-describedby={
                  numericPresentationNote
                    ? numericPresentationNoteId
                    : undefined
                }
                className={presentation === "chart" ? "selected" : ""}
                disabled={
                  !numericPresentationCells.length ||
                  Boolean(numericPresentationUnavailable)
                }
                onClick={() => choosePresentation("chart")}
              >
                Chart
              </button>
              {Boolean(catalog?.functions["facts.generic.table.list"]) &&
                Boolean(
                  catalog?.functions["facts.generic.value.snapshot.scan"],
                ) && (
                  <button
                    aria-pressed={presentation === "generic"}
                    className={presentation === "generic" ? "selected" : ""}
                    disabled={busy}
                    onClick={() => void openGenericFacts()}
                  >
                    Generic facts
                  </button>
                )}
            </div>
            <div className="grid-toolbar-display">
              <span>
                <span className="legend numeric" /> Numeric{" "}
                <span className="legend text" /> Text{" "}
                <span className="legend empty-text" /> Empty text{" "}
                <span className="legend zero" /> Present zero{" "}
                <span className="legend missing" /> Missing
              </span>
              <button
                type="button"
                aria-pressed={gridDensity === "compact"}
                onClick={toggleGridDensity}
              >
                {gridDensity === "compact"
                  ? "Use comfortable grid"
                  : "Use compact grid"}
              </button>
            </div>
          </div>
          {numericPresentationNote && (
            <p
              id={numericPresentationNoteId}
              className="context-note"
              role="status"
            >
              {numericPresentationNote}
            </p>
          )}
          {presentation === "generic" ? (
            <div className="snapshot-compare" aria-label="Generic facts">
              <div className="snapshot-compare-controls">
                <label>
                  Fact table
                  <select
                    aria-label="Generic fact table"
                    value={selectedGenericTable}
                    onChange={(event) => {
                      cancelGenericRead();
                      const tableId = event.target.value;
                      setGenericState((state) =>
                        state?.context === catalogueContext
                          ? {
                              ...state,
                              tableId,
                              rows: [],
                              cursor: null,
                              snapshot: null,
                            }
                          : state,
                      );
                    }}
                  >
                    {!genericTables.length && (
                      <option value="">
                        {currentGenericState
                          ? "No active tables"
                          : "Choose Generic facts to reload tables"}
                      </option>
                    )}
                    {genericTables.map((table) => (
                      <option key={table.table_id} value={table.table_id}>
                        {table.name}
                      </option>
                    ))}
                  </select>
                </label>
                <button
                  disabled={busy || !selectedGenericTable}
                  onClick={() => void readGenericFacts()}
                >
                  {busy ? "Reading…" : "Read records"}
                </button>
              </div>
              <p>
                Application-owned, non-dimensional JSON facts. PostgreSQL row
                security and the fixed core remain authoritative; these records
                are not cube coordinates.
              </p>
              {genericRows.length ? (
                <div
                  className="react-grid-scroll"
                  role="region"
                  aria-label="Generic fact records"
                  tabIndex={0}
                >
                  <table className="react-cube-grid generic-fact-grid">
                    <thead>
                      <tr>
                        <th>Series key</th>
                        <th>Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {genericRows.map((row) => (
                        <tr key={`${row.series_key}-${row.change_id}`}>
                          <th scope="row">{row.series_key}</th>
                          <td>
                            <code>{genericValueText(row.value)}</code>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="grid-placeholder compact">
                  <h2>Browse authorized generic facts</h2>
                  <p>
                    Choose an active table, then read one stable server
                    snapshot.
                  </p>
                </div>
              )}
              <footer className="grid-status" aria-live="polite">
                <span>
                  {genericSnapshot === null
                    ? "No generic-fact snapshot read"
                    : `${genericRows.length} current records`}
                </span>
                <button
                  disabled={busy || !genericCursor}
                  onClick={() => void readGenericFacts(genericCursor)}
                >
                  Next page
                </button>
              </footer>
            </div>
          ) : presentation === "kpi" &&
            !numericPresentationUnavailable &&
            numericPresentationCells.length ? (
            <div className="snapshot-kpis" aria-label="Snapshot KPI cards">
              {presentedNumericCells.map((cell, cellIndex) => (
                <article key={`${cell.changeId || "cell"}-${cellIndex}`}>
                  <span>{presentationLabel(cell)}</span>
                  <strong>{presentationValue(cell)}</strong>
                  <small>Exact snapshot value</small>
                </article>
              ))}
            </div>
          ) : presentation === "chart" &&
            !numericPresentationUnavailable &&
            numericPresentationCells.length ? (
            <div className="snapshot-chart" aria-label="Snapshot value chart">
              <p>
                Bar lengths are a visual aid. Labels retain the exact values
                from the current authorized read.
              </p>
              {presentedNumericCells.map((cell, cellIndex) => {
                const numeric = Math.abs(Number(cell.amount));
                const width =
                  chartMaximum && Number.isFinite(numeric)
                    ? Math.max(1, (numeric / chartMaximum) * 100)
                    : 0;
                return (
                  <div
                    className="snapshot-chart-row"
                    key={`${cell.changeId || "cell"}-${cellIndex}`}
                  >
                    <span>{presentationLabel(cell)}</span>
                    <div className="snapshot-chart-track" aria-hidden="true">
                      <i style={{ width: `${width}%` }} />
                    </div>
                    <strong>{presentationValue(cell)}</strong>
                  </div>
                );
              })}
            </div>
          ) : matrix ? (
            <div className="react-grid-scroll analytical-grid-scroll">
              <table
                className="react-cube-grid"
                role="grid"
                aria-label="Pivot results"
              >
                <thead>
                  <tr>
                    {activeRowDimensions.map((dimension) => (
                      <th key={dimension} scope="col">
                        <span className="grid-axis-label">{dimension}</span>
                      </th>
                    ))}
                    {matrix.columnTuples.map(([columnKey, values]) => (
                      <th key={columnKey} scope="col">
                        <span className="grid-axis-label">
                          {values.join(" / ")}
                        </span>
                        <small>{activeColumnDimensions.join(" / ")}</small>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {matrix.rowTuples.map(([rowKey, rowValues], rowIndex) => (
                    <tr key={rowKey}>
                      {rowValues.map((value, valueIndex) => (
                        <th
                          scope="row"
                          key={`${activeRowDimensions[valueIndex]}:${value}`}
                        >
                          <span className="grid-axis-label">{value}</span>
                        </th>
                      ))}
                      {matrix.columnTuples.map(
                        ([columnKey, columnValues], columnIndex) => {
                          const cell = matrix.cells.get(
                            `${rowKey}\u0000${columnKey}`,
                          );
                          const coordinate = matrixCoordinate(
                            rowValues,
                            columnValues,
                          );
                          const selectable = cell || {
                            members: coordinate,
                            kind: "numeric" as const,
                            amount: "",
                            changeId: "",
                          };
                          return (
                            <td
                              className={`${cellClass(cell)}${isSelected(selectable) ? " selected-cell" : ""}`}
                              key={columnKey}
                              title={cell ? `${cell.kind} value` : "Missing"}
                            >
                              <button
                                className="cell-button"
                                disabled={busy}
                                data-grid-row={rowIndex}
                                data-grid-column={columnIndex}
                                aria-pressed={isSelected(selectable)}
                                tabIndex={gridFocus.tabIndex(
                                  rowIndex,
                                  columnIndex,
                                )}
                                onFocus={(event) =>
                                  gridFocus.onCellFocus(
                                    event.currentTarget,
                                    rowIndex,
                                    columnIndex,
                                  )
                                }
                                aria-label={cellAccessibleName(
                                  selectable.members,
                                  cell,
                                )}
                                onKeyDown={(event) =>
                                  moveGridFocus(
                                    event,
                                    rowIndex,
                                    columnIndex,
                                    matrix.rowTuples.length,
                                    matrix.columnTuples.length,
                                    gridFocus.announceKeyboardPosition,
                                  )
                                }
                                onClick={(event) =>
                                  openCellInspector(
                                    selectable,
                                    event.currentTarget,
                                  )
                                }
                              >
                                {cellValue(cell)}
                              </button>
                            </td>
                          );
                        },
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : visibleRows.length ? (
            <div className="react-grid-scroll analytical-grid-scroll">
              <table
                className="react-cube-grid flat-grid"
                role="grid"
                aria-label="Coordinate results"
              >
                <thead>
                  <tr>
                    <th scope="col">Coordinate</th>
                    <th scope="col">Type</th>
                    <th scope="col">Value</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleRows.map((cell, rowIndex) => (
                    <tr key={`${rowIndex}-${cell.changeId || "cell"}`}>
                      <th scope="row">
                        <span className="grid-axis-label">
                          {Object.entries(cell.members)
                            .map(
                              ([dimension, member]) =>
                                `${dimension}: ${member}`,
                            )
                            .join(" · ")}
                        </span>
                      </th>
                      <td>{cell.kind}</td>
                      <td
                        className={`${cellClass(cell)}${isSelected(cell) ? " selected-cell" : ""}`}
                      >
                        <button
                          className="cell-button"
                          disabled={busy}
                          data-grid-row={rowIndex}
                          data-grid-column={0}
                          tabIndex={gridFocus.tabIndex(rowIndex, 0)}
                          onFocus={(event) =>
                            gridFocus.onCellFocus(
                              event.currentTarget,
                              rowIndex,
                              0,
                            )
                          }
                          aria-label={cellAccessibleName(cell.members, cell)}
                          onKeyDown={(event) =>
                            moveGridFocus(
                              event,
                              rowIndex,
                              0,
                              visibleRows.length,
                              1,
                              gridFocus.announceKeyboardPosition,
                            )
                          }
                          aria-pressed={isSelected(cell)}
                          onClick={(event) =>
                            openCellInspector(cell, event.currentTarget)
                          }
                        >
                          {cellValue(cell)}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : resolvedStatus === "current-empty" ||
            (loadedRead && !visibleRows.length) ? (
            <div className="grid-placeholder" aria-label="Current empty result">
              <span>∅</span>
              <h2>
                {resolvedStatus === "current-empty"
                  ? "Current · Empty"
                  : "Empty loaded page"}
              </h2>
              <p>
                {loadedRead?.plan.kind === "resolved" &&
                resolvedStatus === "current-empty"
                  ? "The governed calculation completed successfully and certified that this selection currently contains no values."
                  : hasMoreGridPages
                    ? "The loaded page contains no values. More pages are available; continue to inspect the remaining results."
                    : "The requested view was read successfully and returned no values for this selection."}
              </p>
            </div>
          ) : (
            <div className="grid-placeholder">
              <span>▦</span>
              <h2>Start with a view of your data</h2>
              <p>
                Choose row and column dimensions, set the remaining point of
                view, then select Read grid. Open a cell to inspect its value
                and review an update.
              </p>
              <button className="primary" onClick={() => setLayoutOpen(true)}>
                Choose grid axes
              </button>
            </div>
          )}
          {presentation !== "generic" && (
            <footer
              className="grid-status"
              aria-live="polite"
              tabIndex={-1}
              data-grid-focus-status
            >
              <span>
                {readingGrid
                  ? "Reading grid…"
                  : !loadedRead
                    ? "No snapshot read"
                    : `${visibleRows.length} loaded cells${hasMoreGridPages ? " · more pages available" : ""}`}
              </span>
              <button
                onClick={() => {
                  if (resolvedPage) {
                    const focusRequest = gridFocus.begin();
                    const offset = resolvedPage.offset + resolvedPage.pageSize;
                    setRows(
                      resolvedPageCells(
                        resolvedPage.cells,
                        resolvedPage.pageSize,
                        offset,
                      ),
                    );
                    setResolvedPage({ ...resolvedPage, offset });
                    gridFocus.finish(focusRequest);
                  } else void scan(nextCursor);
                }}
                disabled={
                  busy ||
                  !loadedRead ||
                  (resolvedPage
                    ? !hasResolvedNextPage(
                        resolvedPage.cells,
                        resolvedPage.pageSize,
                        resolvedPage.offset,
                      )
                    : !nextCursor)
                }
              >
                Next page
              </button>
            </footer>
          )}
          {loadedRead && calculationContext && (
            <dl
              className="calculation-read-context"
              aria-label="Calculated result context"
            >
              <div>
                <dt>Input freshness</dt>
                <dd>
                  {calculationContext.inputsMatch
                    ? "Match"
                    : "Changed or unavailable"}
                </dd>
              </div>
              {calculationContext.accountingStatus && (
                <div>
                  <dt>Accounting status</dt>
                  <dd>{calculationContext.accountingStatus}</dd>
                </div>
              )}
            </dl>
          )}
        </section>
        {cellMutation.error &&
          (!loadedRead || !selectedCell || calculatedGrid) && (
            <p role="alert" tabIndex={-1} data-grid-focus-error="mutation">
              {cellMutation.error}
            </p>
          )}
        {scope && cellMutation.pending && (
          <div tabIndex={-1} data-grid-focus-outcome>
            <ExactMutationOutcome
              mutation={{
                ...cellMutation,
                retrySubmission: () =>
                  runFocusedMutation(cellMutation.retrySubmission),
                readOutcome: () => runFocusedMutation(cellMutation.readOutcome),
              }}
              scope={scope}
              catalog={catalog}
              refresh={
                selectedCell
                  ? () => void selectCell(selectedCell)
                  : () => void scan()
              }
            />
          </div>
        )}
        {loadedRead && selectedCell && (
          <aside
            className="writeback-drawer"
            aria-label="Cell details and writeback"
            onKeyDown={(event) => {
              if (
                event.key !== "Escape" ||
                event.defaultPrevented ||
                event.nativeEvent.isComposing
              )
                return;
              event.preventDefault();
              event.stopPropagation();
              closeCellInspector();
            }}
          >
            <div className="drawer-heading">
              <div>
                <span>Selected cell</span>
                <h2 ref={cellInspectorHeading} tabIndex={-1}>
                  {calculatedGrid
                    ? openedGridDefinition?.dataSource.kind === "combined"
                      ? "Raw and calculated result details"
                      : "Calculated result details"
                    : "Details and exact writeback"}
                </h2>
              </div>
              <button
                aria-label="Close writeback"
                disabled={inspectorCloseBlocked}
                onClick={closeCellInspector}
              >
                ×
              </button>
            </div>
            <dl className="coordinate-list">
              {Object.entries(selectedCell.members)
                .sort(([left], [right]) => left.localeCompare(right))
                .map(([dimension, member]) => (
                  <div key={dimension}>
                    <dt>
                      {dimensions.find(
                        (candidate) => candidate.dimension_id === dimension,
                      )?.name || dimension}
                    </dt>
                    <dd>
                      {memberCatalog[dimension]?.find(
                        (candidate) => candidate.member_id === member,
                      )?.name || member}
                    </dd>
                  </div>
                ))}
            </dl>
            <details>
              <summary>Exact coordinate IDs</summary>
              <dl>
                {Object.entries(selectedCell.members).map(
                  ([dimension, member]) => (
                    <div key={dimension}>
                      <dt>{dimension}</dt>
                      <dd>{member}</dd>
                    </div>
                  ),
                )}
              </dl>
            </details>
            <section
              className="cell-details"
              aria-label="Authoritative cell details"
            >
              <h3>Current authoritative state</h3>
              {!calculatedGrid && (
                <p>
                  {cellResolved
                    ? `Raw input reread${inspectorSnapshot === null ? "" : ` at revision ${inspectorSnapshot}`}. This value and its concurrency identity were read together.`
                    : "Reading the current input and editability policy…"}
                </p>
              )}
              <dl>
                <div>
                  <dt>Presence</dt>
                  <dd>{cellPresence(selectedCell)}</dd>
                </div>
                <div>
                  <dt>Exact value</dt>
                  <dd>
                    {cellPresence(selectedCell) === "Missing"
                      ? "Missing"
                      : selectedCell.kind === "text" && selectedCell.text === ""
                        ? "Empty text"
                        : cellValue(selectedCell)}
                  </dd>
                </div>
                <div>
                  <dt>Source</dt>
                  <dd>
                    {!calculatedGrid && cellResolved
                      ? "Stored raw input for this edit"
                      : source || "Not available"}
                  </dd>
                </div>
                {selectedCell.origin && (
                  <div>
                    <dt>Resolved origin</dt>
                    <dd>{selectedCell.origin}</dd>
                  </div>
                )}
                {selectedCell.currentness && (
                  <div>
                    <dt>Resolved currentness</dt>
                    <dd>{selectedCell.currentness}</dd>
                  </div>
                )}
                {selectedCell.resultUnit && (
                  <div>
                    <dt>Resolved unit</dt>
                    <dd>{selectedCell.resultUnit}</dd>
                  </div>
                )}
              </dl>
              {selectedCell.layerValues && (
                <dl aria-label="Separate source values">
                  {Object.entries(selectedCell.layerValues).map(
                    ([layer, values]) => (
                      <div key={layer}>
                        <dt>{layer === "raw" ? "Raw" : "Calculated"}</dt>
                        <dd>{values?.map(layerValueText).join(" / ")}</dd>
                      </div>
                    ),
                  )}
                </dl>
              )}
              <p>
                {calculatedGrid
                  ? "This cell belongs to the governed current calculated result below. The browser displays only provenance supplied by the current result contract."
                  : "This view shows the current authorized value and governed source information. Internal concurrency controls remain enforced without exposing backend identifiers."}
              </p>
            </section>
            {app &&
              catalog &&
              (!calculatedGrid || publishedComparison) &&
              metadataRevision === catalog.revisions.metadata &&
              scenarioAxis &&
              comparisonDialogHost &&
              selectedCell.members[scenarioAxis.dimension_id] &&
              Boolean(comparisonCapability) && (
                <ScenarioComparison
                  key={JSON.stringify([
                    app.workspaceId,
                    app.applicationId,
                    catalog.applicationAccess,
                    catalog.revisions,
                    selectedCoordinate,
                    publishedComparison,
                  ])}
                  app={app}
                  catalog={catalog}
                  axis={scenarioAxis}
                  coordinate={selectedCell.members}
                  baselineName={
                    memberCatalog[scenarioAxis.dimension_id]?.find(
                      (member) =>
                        member.member_id ===
                        selectedCell.members[scenarioAxis.dimension_id],
                    )?.name
                  }
                  dialogHost={comparisonDialogHost}
                  published={publishedComparison}
                  onGridAuthorityFailure={withdrawGridAfterAuthorityFailure}
                  onStalePublication={withdrawGridSnapshot}
                  offerCopySource={
                    !writeTouched &&
                    !inspectorCloseBlocked &&
                    canCopyScenario(catalog) &&
                    catalog.functions["metadata.member.list"]
                      ? (source) =>
                          scenarioCopyControl.current?.offerComparedSource(
                            source,
                          ) ?? false
                      : undefined
                  }
                />
              )}
            {calculatedGrid && calculationContext && (
              <section
                className="cell-details calculated-details"
                aria-label="Calculated result provenance"
              >
                <h3>Governed result provenance</h3>
                <dl>
                  <div>
                    <dt>Input freshness</dt>
                    <dd>
                      {calculationContext.inputsMatch
                        ? "Matches at read"
                        : "Changed or unavailable"}
                    </dd>
                  </div>
                  {calculationContext.accountingStatus && (
                    <div>
                      <dt>Accounting status</dt>
                      <dd>{calculationContext.accountingStatus}</dd>
                    </div>
                  )}
                </dl>
              </section>
            )}
            {cellEditability && (
              <section
                className="cell-details"
                aria-label="Authoritative editability decision"
              >
                <h3>{cellEditability.editable ? "Editable" : "Read only"}</h3>
                <p>{cellEditability.message}</p>
              </section>
            )}
            {!calculatedGrid && (
              <>
                <fieldset
                  className="drawer-fields"
                  disabled={
                    busy ||
                    cellMutation.busy ||
                    cellMutation.frozen ||
                    !cellResolved
                  }
                >
                  <label>
                    Cell type
                    <select
                      value={writeKind}
                      onChange={(event) => {
                        setWriteTouched(true);
                        const kind = event.target.value as "numeric" | "text";
                        setWriteKind(kind);
                        const action =
                          kind === "text" && writeOperation === "add"
                            ? "set"
                            : writeOperation;
                        if (action !== writeOperation)
                          setWriteOperation(action);
                        void refreshRawCellEditability(
                          selectedCell,
                          action,
                          kind,
                        );
                      }}
                    >
                      <option value="numeric">Numeric amount</option>
                      <option value="text">Text</option>
                    </select>
                  </label>
                  <label>
                    Operation
                    <select
                      value={writeOperation}
                      onChange={(event) => {
                        setWriteTouched(true);
                        const action = event.target.value as
                          | "set"
                          | "add"
                          | "clear";
                        setWriteOperation(action);
                        void refreshRawCellEditability(selectedCell, action);
                      }}
                    >
                      <option value="set">Set</option>
                      <option value="add" disabled={writeKind === "text"}>
                        Add
                      </option>
                      <option value="clear">Clear</option>
                    </select>
                  </label>
                  <label>
                    Value
                    <input
                      value={writeValue}
                      disabled={writeOperation === "clear"}
                      onChange={(event) => {
                        setWriteValue(event.target.value);
                        setWriteTouched(true);
                      }}
                    />
                  </label>
                </fieldset>
                <p>
                  {writeOperation === "clear"
                    ? "Clear removes presence. It does not set numeric zero or empty text."
                    : writeOperation === "add"
                      ? "Add applies this exact decimal to the current numeric input once."
                      : writeKind === "text"
                        ? "Set replaces the text. An empty string remains a present text value."
                        : "Set replaces the numeric input. Zero remains a present value."}
                </p>
                {cellMutation.error && (
                  <p
                    role="alert"
                    tabIndex={-1}
                    data-grid-focus-error="mutation"
                  >
                    {cellMutation.error}
                  </p>
                )}
                <button
                  disabled={busy || cellMutation.busy || cellMutation.frozen}
                  onClick={() => void selectCell(selectedCell, true)}
                >
                  Reread current cell and keep my edit
                </button>
                <button
                  disabled={
                    !writeReady ||
                    busy ||
                    cellMutation.busy ||
                    cellMutation.frozen
                  }
                  onClick={() => {
                    setReviewed(false);
                    void cellMutation.preview();
                  }}
                >
                  Preview exact mutation
                </button>
                {cellMutation.review && (
                  <p role="status">
                    The server preview matches this exact mutation. Review its
                    coordinate, operation and value before submission.
                  </p>
                )}
                <p
                  className={
                    writeReady ? "drawer-readiness ready" : "drawer-readiness"
                  }
                >
                  {!writeAuthorized
                    ? !catalog
                      ? "Checking cell-write availability…"
                      : "Writing this cell type is not available in the current application context."
                    : !cellEditability
                      ? "Resolve the current server editability policy before review."
                      : !cellEditability.editable
                        ? cellEditability.message
                        : !coordinateComplete
                          ? "The coordinate does not cover the complete active model."
                          : !cellResolved
                            ? "Resolve the current cell before review."
                            : writeKind === "numeric" &&
                                writeOperation !== "clear" &&
                                !exactDecimal.test(writeValue)
                              ? "Enter an exact decimal without exponent notation."
                              : "Current cell identity and exact mutation are ready for review."}
                </p>
                <label className="review-check">
                  <input
                    type="checkbox"
                    checked={reviewed}
                    disabled={
                      !writeReady ||
                      !cellMutation.review ||
                      busy ||
                      cellMutation.busy ||
                      cellMutation.frozen
                    }
                    onChange={(event) => setReviewed(event.target.checked)}
                  />
                  I reviewed this exact cell mutation
                </label>
                <button
                  className="primary"
                  disabled={
                    !writeReady ||
                    !reviewed ||
                    !cellMutation.review ||
                    busy ||
                    cellMutation.busy ||
                    cellMutation.frozen
                  }
                  onClick={() => void submitWriteback()}
                >
                  Submit durable writeback
                </button>
                {writeResult && (
                  <p className="write-result" role="status">
                    {writeResult}
                  </p>
                )}
              </>
            )}
          </aside>
        )}
      </div>
    </div>
  );
}
