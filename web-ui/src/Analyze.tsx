import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
} from "react";
import {
  readProgram,
  request,
  requestAdmittedEffect,
  reviewAndSubmit,
} from "./api";
import type { ApplicationCatalog, ApplicationSummary, Scope } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { collectAllContinuations } from "./continuation";
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

type CubeSelector =
  | { kind: "member"; memberId: string }
  | { kind: "members"; memberIds: string[] }
  | Record<string, unknown>;

type SavedGridDefinition = {
  format: "openepm-cube-view-v1";
  viewId: string;
  name: string;
  selection: {
    format: "openepm-cube-selection-v1";
    metadataRevision: number;
    dimensions: Array<{
      dimensionId: string;
      include: CubeSelector;
      exclude: CubeSelector | null;
    }>;
  };
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
  rows?: AggregateRow[];
  nextCursor?: string | null;
  technicalCertificate?: unknown;
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
  savedSelection?: SavedGridDefinition["selection"],
  presentation: {
    pageSize: number;
    suppression: { missing: boolean; zero: boolean };
  } = { pageSize: 100, suppression: { missing: false, zero: false } },
) {
  return {
    languageVersion: 2,
    function: "facts.cube.resolved.read",
    arguments: {
      format: "openepm-resolved-cube-read-v1",
      selection: savedSelection || {
        format: "openepm-cube-selection-v1",
        metadataRevision,
        dimensions: dimensions.map((dimension) => ({
          dimensionId: dimension.dimension_id,
          include: pov[dimension.dimension_id]
            ? { kind: "member", memberId: pov[dimension.dimension_id] }
            : {
                kind: "members",
                memberIds: (members[dimension.dimension_id] || []).map(
                  (member) => member.member_id,
                ),
              },
          exclude: null,
        })),
      },
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
  return Boolean(
    definition.format === "openepm-cube-view-v1" &&
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
  const fixed = new Set([
    ...definition.layout.pages,
    ...definition.layout.filters,
  ]);
  return Object.fromEntries(
    definition.selection.dimensions.flatMap((item) =>
      fixed.has(item.dimensionId) &&
      item.include.kind === "member" &&
      typeof item.include.memberId === "string"
        ? [[item.dimensionId, item.include.memberId]]
        : [],
    ),
  );
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
        include: pov[dimension.dimension_id]
          ? { kind: "member", memberId: pov[dimension.dimension_id] }
          : {
              kind: "members",
              memberIds: (members[dimension.dimension_id] || []).map(
                (member) => member.member_id,
              ),
            },
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
) {
  const target = gridKeyTarget(event.key, row, column, rowCount, columnCount);
  if (!target) return;
  event.preventDefault();
  event.currentTarget
    .closest("table")
    ?.querySelector<HTMLButtonElement>(
      `[data-grid-row="${target.row}"][data-grid-column="${target.column}"]`,
    )
    ?.focus();
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
    rows: collected.rows.filter((item) => item.status === "Active"),
    metadataRevision: collected.finalPage.metadataRevision,
  };
}

async function readAllMembers(
  scope: Scope,
  dimension: string,
  signal?: AbortSignal,
) {
  const collected = await collectAnalyzeMembers(
    (afterMemberId, expectedMetadataRevision) =>
      readProgram(
        scope,
        "metadata.member.list",
        {
          dimension,
          limit: 100,
          ...(afterMemberId ? { afterMemberId, expectedMetadataRevision } : {}),
        },
        signal,
      ),
  );
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
  if (cell.kind === "text") {
    if (typeof cell.text !== "string") return "Missing";
    return cell.text === "" ? "Present empty text" : "Present text";
  }
  if (typeof cell.amount !== "string" || cell.amount === "") return "Missing";
  return /^[-+]?0(?:\.0+)?$/.test(cell.amount)
    ? "Present numeric zero"
    : "Present numeric";
}

export function Analyze({
  app,
  catalog,
  index,
  subject,
  targetViewId,
  targetViewDigest,
  onRequestTransition = (action) => action(),
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  index: number;
  subject: string;
  targetViewId?: string;
  targetViewDigest?: string;
  onRequestTransition?: (action: () => void) => void;
}) {
  const scope = app
    ? { workspaceId: app.workspaceId, applicationId: app.applicationId }
    : null;
  const [dimensions, setDimensions] = useState<Dimension[]>([]);
  const [metadataRevision, setMetadataRevision] = useState<number | null>(null);
  const [rowDimension, setRowDimension] = useState("");
  const [columnDimension, setColumnDimension] = useState("");
  const [layoutOpen, setLayoutOpen] = useState(false);
  const [pov, setPov] = useState<Record<string, string>>({});
  const [memberCatalog, setMemberCatalog] = useState<Record<string, Member[]>>(
    {},
  );
  const [rows, setRows] = useState<CubeCell[]>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [resolvedPage, setResolvedPage] = useState<{
    cells: CubeCell[];
    pageSize: number;
    offset: number;
  } | null>(null);
  const [snapshot, setSnapshot] = useState<number | null>(null);
  const [source, setSource] = useState("");
  const [resolvedStatus, setResolvedStatus] =
    useState<ResolvedReadStatus | null>(null);
  const [readSemantics, setReadSemantics] = useState<
    "stored" | "own" | "effective"
  >("stored");
  const [resolvedBindingId, setResolvedBindingId] = useState("");
  const [resolvedBindingStateToken, setResolvedBindingStateToken] =
    useState("");
  const [resolvedBindings, setResolvedBindings] = useState<ResolvedBinding[]>(
    [],
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [selectedCell, setSelectedCell] = useState<CubeCell | null>(null);
  const cellInspectorHeading = useRef<HTMLHeadingElement | null>(null);
  const cellTrigger = useRef<HTMLButtonElement | null>(null);
  const cellReadVersion = useRef(0);
  const cellReadController = useRef<AbortController | null>(null);
  const activeScopeKey = `${app?.workspaceId || ""}:${app?.applicationId || ""}`;
  const activeScope = useRef(activeScopeKey);
  activeScope.current = activeScopeKey;
  useEffect(() => {
    if (selectedCell)
      cellInspectorHeading.current?.focus({
        preventScroll: window.innerWidth > 1240,
      });
  }, [selectedCell]);
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
  const [expectedChangeId, setExpectedChangeId] = useState("");
  const [resolvedChangeIds, setResolvedChangeIds] = useState({
    numeric: "",
    text: "",
  });
  const [cellResolved, setCellResolved] = useState(false);
  const [cellEditability, setCellEditability] =
    useState<CellEditability | null>(null);
  const [reviewed, setReviewed] = useState(false);
  const [writeResult, setWriteResult] = useState("");
  const [savedGrids, setSavedGrids] = useState<SavedGrid[]>([]);
  const [savedGridsRead, setSavedGridsRead] = useState(false);
  const [savedGridsLoading, setSavedGridsLoading] = useState(false);
  const [savedGridsError, setSavedGridsError] = useState("");
  const [savedGridsContext, setSavedGridsContext] = useState("");
  const canReadSavedGrids = Boolean(catalog?.functions["grid.definition.list"]);
  const savedGridReadKey = JSON.stringify([
    app?.workspaceId,
    app?.applicationId,
    catalog?.applicationAccess.issuer,
    subject,
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
  const [openedGridDefinition, setOpenedGridDefinition] =
    useState<SavedGridDefinition | null>(null);
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
  const [aggregateReviewed, setAggregateReviewed] = useState(false);
  const [aggregateQueryId, setAggregateQueryId] = useState("");
  const [aggregateStatus, setAggregateStatus] = useState("");
  const [aggregateRows, setAggregateRows] = useState<AggregateRow[]>([]);
  const [aggregateCursor, setAggregateCursor] = useState<string | null>(null);
  const [aggregateCancelReviewed, setAggregateCancelReviewed] = useState(false);
  const [aggregateStateRead, setAggregateStateRead] = useState(false);
  const [presentation, setPresentation] = useState<AnalyzePresentation>("grid");
  const densityStorageKey =
    app && subject
      ? gridDensityStorageKey(subject, app.workspaceId, app.applicationId)
      : "";
  const [gridDensity, setGridDensity] = useState<"comfortable" | "compact">(
    () => readGridDensity(densityStorageKey),
  );
  const [genericTables, setGenericTables] = useState<GenericTable[]>([]);
  const [selectedGenericTable, setSelectedGenericTable] = useState("");
  const [genericRows, setGenericRows] = useState<GenericFactRow[]>([]);
  const [genericCursor, setGenericCursor] = useState<string | null>(null);
  const [genericSnapshot, setGenericSnapshot] = useState<number | null>(null);
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
    setDimensions([]);
    setMetadataRevision(null);
    setRows([]);
    setRowDimension("");
    setColumnDimension("");
    setMemberCatalog({});
    setSnapshot(null);
    setSource("");
    setResolvedStatus(null);
    setReadSemantics("stored");
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
    setExpectedChangeId("");
    setResolvedChangeIds({ numeric: "", text: "" });
    setCellResolved(false);
    setCellEditability(null);
    setBusy(false);
    setError("");
    setPov({});
    setGenericTables([]);
    setSelectedGenericTable("");
    setGenericRows([]);
    setGenericCursor(null);
    setGenericSnapshot(null);
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
    setAggregateReviewed(false);
    setAggregateQueryId("");
    setAggregateStatus("");
    setAggregateRows([]);
    setAggregateCursor(null);
    setAggregateCancelReviewed(false);
    setAggregateStateRead(false);
    if (!scope) return;
    const controller = new AbortController();
    readAllDimensions(scope, controller.signal)
      .then((result) => {
        if (controller.signal.aborted || activeScope.current !== activeScopeKey)
          return;
        setDimensions(result.rows);
        setMetadataRevision(result.metadataRevision);
      })
      .catch((reason: Error) => {
        if (controller.signal.aborted || activeScope.current !== activeScopeKey)
          return;
        if (reason.name !== "AbortError") setError(reason.message);
      });
    return () => controller.abort();
  }, [app?.workspaceId, app?.applicationId]);

  useEffect(() => {
    if (
      !scope ||
      readSemantics !== "effective" ||
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
    Boolean(catalog?.functions["facts.cube.resolved.binding.list"]),
  ]);

  useEffect(
    () => setReviewed(false),
    [writeKind, writeOperation, writeValue, expectedChangeId, selectedCell],
  );

  useEffect(() => {
    setAggregateReviewed(false);
    setAggregateCancelReviewed(false);
  }, [
    rowDimension,
    columnDimension,
    pov,
    aggregateMeasures,
    aggregatePageSize,
  ]);

  useEffect(
    () => setExpectedChangeId(resolvedChangeIds[writeKind]),
    [resolvedChangeIds, writeKind],
  );

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
  const calculatedGrid = openedGridDefinition?.dataSource.kind === "calculated";
  const axisIds = useMemo(
    () => new Set([...activeRowDimensions, ...activeColumnDimensions]),
    [activeRowDimensions.join("\u0000"), activeColumnDimensions.join("\u0000")],
  );
  const povDimensions = dimensions.filter(
    (item) => !axisIds.has(item.dimension_id),
  );

  async function ensureMembers(dimensionId: string) {
    if (!scope || memberCatalog[dimensionId])
      return memberCatalog[dimensionId] || [];
    const members = await readAllMembers(scope, dimensionId);
    setMemberCatalog((current) => ({ ...current, [dimensionId]: members }));
    return members;
  }

  async function openGenericFacts() {
    if (!scope) return;
    setBusy(true);
    setError("");
    try {
      const collected = await collectGenericTables((afterTableId) =>
        readProgram<GenericTablePage>(
          scope,
          "facts.generic.table.list",
          genericTableListArguments(afterTableId),
        ),
      );
      const tables = collected.rows.filter(
        (table) => table.status === "Active",
      );
      setGenericTables(tables);
      setSelectedGenericTable((current) =>
        tables.some((table) => table.table_id === current)
          ? current
          : tables[0]?.table_id || "",
      );
      setGenericRows([]);
      setGenericCursor(null);
      setGenericSnapshot(null);
      setPresentation("generic");
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read generic-fact tables",
      );
    } finally {
      setBusy(false);
    }
  }

  async function readGenericFacts(cursor?: string | null) {
    if (!scope || !selectedGenericTable) return;
    setBusy(true);
    setError("");
    try {
      const page = await readProgram<GenericFactPage>(
        scope,
        "facts.generic.value.snapshot.scan",
        genericSnapshotArguments(selectedGenericTable, cursor),
      );
      setGenericRows((current) =>
        cursor ? [...current, ...page.rows] : page.rows,
      );
      setGenericCursor(page.nextCursor || null);
      setGenericSnapshot(page.snapshotRevision);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read generic facts",
      );
    } finally {
      setBusy(false);
    }
  }

  async function suggestLayout() {
    if (!scope || dimensions.length < 2) return;
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
      setOpenedGridDefinition(null);
      setCalculationContext(null);
      setRowDimension(primary.dimension_id);
      setColumnDimension(column.dimension_id);
      const fixed: Record<string, string> = {};
      for (const dimension of dimensions) {
        if (
          [primary.dimension_id, column.dimension_id].includes(
            dimension.dimension_id,
          )
        )
          continue;
        const members = await ensureMembers(dimension.dimension_id);
        if (members[0]) fixed[dimension.dimension_id] = members[0].member_id;
      }
      setPov(fixed);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to build layout",
      );
    } finally {
      setBusy(false);
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
      setSelectedSavedGrid((current) =>
        grids.some((grid) => grid.gridId === current)
          ? current
          : grids[0]
            ? grids[0].gridId
            : "",
      );
    } catch (reason) {
      if (!isCurrent()) return;
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
    setSavedGridsContext(savedGridReadKey);
    if (canReadSavedGrids) void readSavedGrids();
    return () => {
      savedGridReadVersion.current += 1;
      savedGridReadController.current?.abort();
    };
  }, [readSavedGrids, savedGridReadKey, canReadSavedGrids]);

  function openSavedGrid(grid: SavedGrid) {
    if (!canOpenSavedGrid(grid)) {
      setError(
        "This saved definition is invalid or cannot be represented without changing its declared semantics.",
      );
      return;
    }
    const fixed = savedGridPointOfView(grid.definition);
    setOpenedGridDefinition(structuredClone(grid.definition));
    setCalculationContext(null);
    setRowDimension(grid.definition.layout.rows[0] || "");
    setColumnDimension(grid.definition.layout.columns[0] || "");
    setPov(fixed);
    setSavedGridId(grid.gridId);
    setSelectedSavedGrid(grid.gridId);
    setSavedGridName(grid.name);
    setSavedGridTouched(false);
    setRows([]);
    setSnapshot(null);
    setResolvedStatus(null);
    setNextCursor(null);
    setResolvedPage(null);
    setSelectedCell(null);
    setSavedGridResult(
      `Opened ${grid.name} · ${grid.definition.dataSource.kind} · ${grid.definition.layout.rows.length} row axes · ${grid.definition.layout.columns.length} column axes`,
    );
  }

  useEffect(() => {
    if (
      !scope ||
      !targetViewId ||
      !targetViewDigest ||
      !catalog?.functions["grid.definition.read"]
    )
      return;
    const controller = new AbortController();
    readProgram<SavedGrid>(
      scope,
      "grid.definition.read",
      { gridId: targetViewId },
      controller.signal,
    )
      .then((grid) => {
        if (grid.canonicalDigest !== targetViewDigest)
          throw new Error(
            "Workflow destination no longer matches its pinned grid digest.",
          );
        openSavedGrid(grid);
      })
      .catch((reason: Error) => {
        if (reason.name !== "AbortError") setError(reason.message);
      });
    return () => controller.abort();
  }, [
    app?.workspaceId,
    app?.applicationId,
    targetViewId,
    targetViewDigest,
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
      );
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
      savedGridDefinition.layout.columns.length &&
      canOpenSavedGrid({
        gridId: savedGridId || "candidate",
        stateToken: currentGridForSave?.stateToken || "a".repeat(64),
        name: savedGridName || "candidate",
        definition: savedGridDefinition,
        metadataRevision: metadataRevision || 0,
        canonicalDigest: "candidate",
      }),
  );

  async function saveSharedGrid() {
    if (!scope || !metadataRevision || !savedGridReady) return;
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
      setSavedGridResult(`Saved ${response.result.name}.`);
      setSavedGridTouched(false);
      await readSavedGrids();
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to save shared grid definition",
      );
    } finally {
      setBusy(false);
    }
  }

  async function deleteSharedGrid() {
    if (
      !scope ||
      !selectedGrid ||
      !catalog?.functions["grid.definition.delete"]
    )
      return;
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
      setSavedGridResult(`Deleted ${selectedGrid.name}`);
      setSelectedSavedGrid("");
      if (savedGridId === selectedGrid.gridId) {
        setSavedGridId("");
        setSavedGridName("");
        setOpenedGridDefinition(null);
        setSavedGridTouched(false);
      }
      await readSavedGrids();
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to delete saved view",
      );
    } finally {
      setBusy(false);
    }
  }

  let aggregateIntent: ReturnType<typeof aggregateQueryIntent> | null = null;
  let aggregateIntentError = "";
  try {
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
  const aggregateCanCancel = Boolean(
    aggregateQueryId &&
      aggregateStateRead &&
      ["accepted", "ready", "running", "computed"].includes(
        aggregateStatus.toLowerCase(),
      ) &&
      catalog?.functions["facts.cube.aggregate.cancel"],
  );

  async function requestAggregate() {
    if (!scope || !aggregateIntent || !aggregateReady || !aggregateReviewed)
      return;
    setBusy(true);
    setError("");
    try {
      const response = await request<{ result: AggregateResult }>(
        "/api/aggregate",
        {
          ...scope,
          confirmed: true,
          program: aggregateRequestProgram(aggregateIntent, aggregatePageSize),
        },
      );
      setAggregateQueryId(response.result.queryId);
      setAggregateStatus(response.result.status);
      setAggregateRows([]);
      setAggregateCursor(null);
      setAggregateReviewed(false);
      setAggregateCancelReviewed(false);
      setAggregateStateRead(false);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to request aggregate query",
      );
    } finally {
      setBusy(false);
    }
  }

  async function readAggregate(cursor?: string | null) {
    if (
      !scope ||
      !aggregateQueryId ||
      !catalog?.functions["facts.cube.aggregate.read"]
    )
      return;
    setBusy(true);
    setError("");
    try {
      const response = await request<{ result: AggregateResult }>(
        "/api/aggregate",
        {
          ...scope,
          program: aggregateReadProgram(
            aggregateQueryId,
            aggregatePageSize,
            cursor,
          ),
        },
      );
      setAggregateStatus(response.result.status);
      setAggregateRows((current) =>
        cursor
          ? [...current, ...(response.result.rows || [])]
          : response.result.rows || [],
      );
      setAggregateCursor(response.result.nextCursor || null);
      setAggregateCancelReviewed(false);
      setAggregateStateRead(true);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to read aggregate",
      );
    } finally {
      setBusy(false);
    }
  }

  async function cancelAggregate() {
    if (!scope || !aggregateCanCancel || !aggregateCancelReviewed) return;
    if (!window.confirm("Request cancellation of this aggregate query?"))
      return;
    setBusy(true);
    setError("");
    try {
      const response = await request<{ result: AggregateResult }>(
        "/api/aggregate",
        {
          ...scope,
          confirmed: true,
          program: {
            languageVersion: 2,
            function: "facts.cube.aggregate.cancel",
            arguments: { queryId: aggregateQueryId },
          },
        },
      );
      setAggregateStatus(response.result.status);
      setAggregateCursor(null);
      setAggregateCancelReviewed(false);
      setAggregateStateRead(false);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to cancel aggregate query",
      );
    } finally {
      setBusy(false);
    }
  }

  async function scan(cursor?: string | null) {
    if (!scope) return;
    setBusy(true);
    setError("");
    try {
      const requiredDimensions = [
        ...new Set(
          readSemantics === "stored"
            ? [...activeRowDimensions, ...activeColumnDimensions]
            : dimensions.map((dimension) => dimension.dimension_id),
        ),
      ];
      const resolvedMemberCatalog = { ...memberCatalog };
      if (!cursor) {
        const loaded = await Promise.all(
          requiredDimensions.map(
            async (dimension) =>
              [dimension, await ensureMembers(dimension)] as const,
          ),
        );
        for (const [dimension, members] of loaded)
          resolvedMemberCatalog[dimension] = members;
      }
      if (
        !cursor &&
        !calculatedGrid &&
        (openedGridDefinition || readSemantics !== "stored")
      ) {
        const source =
          openedGridDefinition?.dataSource.kind === "raw" ||
          readSemantics === "own"
            ? { semantics: "own" as const }
            : {
                semantics: "effective" as const,
                bindingId: resolvedBindingId,
                bindingStateToken: resolvedBindingStateToken,
                hierarchies: [] as never[],
              };
        const page = await readProgram<ResolvedCubePage>(
          scope,
          "facts.cube.resolved.read",
          resolvedGridProgram(
            dimensions,
            resolvedMemberCatalog,
            pov,
            metadataRevision || 0,
            source,
            openedGridDefinition?.selection,
            {
              pageSize: openedGridDefinition?.pageSize || 100,
              suppression: openedGridDefinition?.suppression || {
                missing: false,
                zero: false,
              },
            },
          ).arguments,
        );
        const cells = resolvedRowsToCells(page);
        const pageSize = page.presentation.pageSize;
        setResolvedPage({ cells, pageSize, offset: 0 });
        setRows(resolvedPageCells(cells, pageSize, 0));
        setNextCursor(null);
        setSnapshot(page.snapshot.commitRevision);
        const readStatus = resolvedReadStatus(page);
        setResolvedStatus(readStatus);
        const origins = [...new Set(page.rows.map((row) => row.origin))].sort();
        const currentness = [
          ...new Set(page.rows.map((row) => row.currentness)),
        ].sort();
        setSource(
          `${
            readSemantics === "own"
              ? "resolved own input"
              : `effective binding ${resolvedBindingId}`
          } · ${origins.join(", ") || "no rows"} · ${
            currentness.join(", ") || "currentness unavailable"
          }`,
        );
        setCalculationContext(null);
        return;
      }
      setResolvedStatus(null);
      setResolvedPage(null);
      const pageSize = openedGridDefinition?.pageSize || 100;
      const scanFunction = calculatedGrid
        ? "facts.calculation.scan"
        : "facts.cube.scan";
      const page = await readProgram<CubePage>(
        scope,
        scanFunction,
        cursor
          ? calculatedGrid
            ? { cursor }
            : { cursor }
          : calculatedGrid
            ? {
                members: pov,
                limit: pageSize,
                includeZero: !(openedGridDefinition?.suppression.zero ?? false),
                resultKey: openedGridDefinition?.dataSource.resultKey,
              }
            : buildScanArguments(
                pov,
                pageSize,
                undefined,
                openedGridDefinition?.suppression,
              ),
      );
      setRows(
        calculatedGrid
          ? page.rows.map((cell) => ({ ...cell, kind: "numeric" as const }))
          : page.rows,
      );
      setNextCursor(page.nextCursor || null);
      setSnapshot(calculatedGrid ? null : (page.snapshotRevision ?? null));
      setSource(
        calculatedGrid ? "current calculated result" : page.source || "raw",
      );
      setCalculationContext(
        calculatedGrid
          ? {
              resultKey:
                page.resultKey ||
                openedGridDefinition?.dataSource.resultKey ||
                "",
              resultStateToken: page.resultStateToken || "",
              inputsMatch: page.inputRevisionStatus?.matchesAtRead === true,
              accountingStatus:
                page.aggregateContext?.accountingPolicyStatus ||
                page.contributionContext?.accountingPolicyStatus,
            }
          : null,
      );
    } catch (reason) {
      // A failed authorization, stale pin or unavailable read invalidates the
      // displayed snapshot. Never leave values from an earlier authority cut
      // visible beside the new failure.
      setRows([]);
      setNextCursor(null);
      setResolvedPage(null);
      setSnapshot(null);
      setSource("");
      setResolvedStatus(null);
      setCalculationContext(null);
      setSelectedCell(null);
      setError(
        reason instanceof Error ? reason.message : "Unable to read grid",
      );
    } finally {
      setBusy(false);
    }
  }

  async function selectCell(cell: CubeCell) {
    if (!scope) return;
    const version = ++cellReadVersion.current;
    const selectionScope = activeScopeKey;
    cellReadController.current?.abort();
    const controller = new AbortController();
    cellReadController.current = controller;
    const current = () =>
      version === cellReadVersion.current &&
      activeScope.current === selectionScope &&
      !controller.signal.aborted;
    setSelectedCell(cell);
    setWriteKind(cell.kind || "numeric");
    setWriteOperation("set");
    setWriteValue(
      cell.kind === "text" ? (cell.text ?? "") : (cell.amount ?? ""),
    );
    setWriteTouched(false);
    setExpectedChangeId("");
    setResolvedChangeIds({ numeric: "", text: "" });
    setCellResolved(false);
    setCellEditability(null);
    setWriteResult("");
    setBusy(true);
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
      const editability = await readProgram<CellEditability>(
        scope,
        "facts.cell.editability.read",
        {
          coordinate: cell.members,
          source: "raw",
          action: "set",
          kind: cell.kind || "numeric",
        },
        controller.signal,
      );
      if (!current()) return;
      setCellEditability(editability);
      setCellResolved(true);
    } catch (reason) {
      if (!current()) return;
      setError(
        reason instanceof Error ? reason.message : "Unable to resolve cell",
      );
    } finally {
      if (current()) setBusy(false);
    }
  }

  async function inspectCalculatedCell(cell: CubeCell) {
    if (!scope) return;
    const version = ++cellReadVersion.current;
    const selectionScope = activeScopeKey;
    cellReadController.current?.abort();
    const controller = new AbortController();
    cellReadController.current = controller;
    const current = () =>
      version === cellReadVersion.current &&
      activeScope.current === selectionScope &&
      !controller.signal.aborted;
    setSelectedCell(cell);
    setReviewed(false);
    setWriteResult("");
    setExpectedChangeId("");
    setResolvedChangeIds({ numeric: "", text: "" });
    setCellResolved(false);
    setCellEditability(null);
    setBusy(true);
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
      if (current()) setCellEditability(editability);
    } catch (reason) {
      if (current())
        setError(
          reason instanceof Error
            ? reason.message
            : "Unable to inspect cell editability",
        );
    } finally {
      if (current()) setBusy(false);
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
    setCellEditability(null);
    setBusy(true);
    setError("");
    try {
      const editability = await readProgram<CellEditability>(
        scope,
        "facts.cell.editability.read",
        { coordinate: cell.members, source: "raw", action, kind },
        controller.signal,
      );
      if (
        version === cellReadVersion.current &&
        activeScope.current === selectionScope &&
        !controller.signal.aborted
      )
        setCellEditability(editability);
    } catch (reason) {
      if (
        version === cellReadVersion.current &&
        activeScope.current === selectionScope &&
        !controller.signal.aborted
      )
        setError(
          reason instanceof Error
            ? reason.message
            : "Unable to inspect cell editability",
        );
    } finally {
      if (
        version === cellReadVersion.current &&
        activeScope.current === selectionScope &&
        !controller.signal.aborted
      )
        setBusy(false);
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

  async function submitWriteback() {
    if (!scope || !selectedCell || !writeReady || !reviewed) return;
    setBusy(true);
    setError("");
    try {
      const program = buildWritebackProgram(
        writeKind,
        writeOperation,
        selectedCell.members,
        writeValue,
        expectedChangeId,
      );
      const result = await reviewAndSubmit<{ jobId?: string }>(
        {
          ...scope,
          program,
          idempotencyKey: mutationIntentKey({ scope, program }),
          dependsOnJobIds: [],
          confirmed: true,
        },
        "Review the selected-cell writeback preview.",
      );
      if (!result) return;
      setWriteResult("Writeback request accepted.");
      setWriteTouched(false);
      setReviewed(false);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to submit writeback",
      );
    } finally {
      setBusy(false);
    }
  }

  const matrix = useMemo(() => {
    if (!activeRowDimensions.length || !activeColumnDimensions.length)
      return null;
    const memberOrder = (dimension: string) =>
      (memberCatalog[dimension] || []).map((member) => member.member_id);
    const compareTuple = (
      left: string[],
      right: string[],
      dimensions: string[],
    ) => {
      for (let index = 0; index < dimensions.length; index += 1) {
        const order = memberOrder(dimensions[index]);
        const leftIndex = order.indexOf(left[index]);
        const rightIndex = order.indexOf(right[index]);
        const governedLeft =
          leftIndex < 0 ? Number.MAX_SAFE_INTEGER : leftIndex;
        const governedRight =
          rightIndex < 0 ? Number.MAX_SAFE_INTEGER : rightIndex;
        if (governedLeft !== governedRight) return governedLeft - governedRight;
        const fallback = String(left[index]).localeCompare(
          String(right[index]),
        );
        if (fallback) return fallback;
      }
      return 0;
    };
    const key = (values: string[]) => JSON.stringify(values);
    const columnTuples = new Map<string, string[]>();
    const rowTuples = new Map<string, string[]>();
    const cells = new Map<string, CubeCell>();
    for (const cell of rows) {
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
        compareTuple(left[1], right[1], activeRowDimensions),
      ),
      columnTuples: [...columnTuples.entries()].sort((left, right) =>
        compareTuple(left[1], right[1], activeColumnDimensions),
      ),
      cells,
    };
  }, [
    rows,
    activeRowDimensions.join("\u0000"),
    activeColumnDimensions.join("\u0000"),
    memberCatalog,
  ]);

  const numericPresentationCells = useMemo(
    () =>
      rows
        .filter(
          (cell): cell is CubeCell & { amount: string } =>
            cell.kind === "numeric" && typeof cell.amount === "string",
        )
        .slice(0, 24),
    [rows],
  );
  const chartMaximum = useMemo(
    () =>
      Math.max(
        0,
        ...numericPresentationCells.map((cell) => {
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

  function changeGridContext(action: () => void) {
    const apply = () => {
      setWriteTouched(false);
      setReviewed(false);
      if (savedGridTouched) {
        setSavedGridId("");
        setSavedGridName("");
        setSavedGridTouched(false);
      }
      action();
    };
    if (writeTouched || savedGridTouched) onRequestTransition(apply);
    else apply();
  }

  const selectedCoordinate = selectedCell
    ? JSON.stringify(Object.entries(selectedCell.members).sort())
    : "";
  const isSelected = (cell: CubeCell) =>
    selectedCoordinate === JSON.stringify(Object.entries(cell.members).sort());

  return (
    <div className="page analyze-page">
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
          <span
            className={`task-state ${snapshot === null ? "neutral" : "active"}`}
          >
            {snapshot === null
              ? "Ready to configure"
              : resolvedStatus === "current-empty"
                ? "Current · Empty"
                : `${rows.length} loaded cells`}
          </span>
          {calculatedGrid && (
            <span className="task-state neutral">Calculated · read only</span>
          )}
        </div>
      </div>

      <section className="layout-summary" aria-label="Current grid layout">
        <div>
          <small>ROWS</small>
          <strong>
            {dimensions.find((item) => item.dimension_id === rowDimension)
              ?.name ||
              rowDimension ||
              "Not selected"}
          </strong>
        </div>
        <div>
          <small>COLUMNS</small>
          <strong>
            {dimensions.find((item) => item.dimension_id === columnDimension)
              ?.name ||
              columnDimension ||
              "Not selected"}
          </strong>
        </div>
        <div>
          <small>PAGES / FILTERS</small>
          <strong>
            {Object.keys(pov).length
              ? `${Object.keys(pov).length} fixed`
              : "Not fixed"}
          </strong>
        </div>
        <button
          type="button"
          aria-controls="grid-layout-drawer"
          aria-expanded={layoutOpen}
          onClick={() => setLayoutOpen((current) => !current)}
        >
          {layoutOpen ? "Close layout" : "Configure layout"}
        </button>
      </section>
      {!calculatedGrid &&
        Boolean(catalog?.functions["facts.cube.resolved.read"]) && (
          <section className="context-note" aria-label="Grid value semantics">
            <label>
              Value semantics
              <select
                value={readSemantics}
                onChange={(event) => {
                  setReadSemantics(
                    event.target.value as "stored" | "own" | "effective",
                  );
                  setRows([]);
                  setSnapshot(null);
                }}
              >
                <option value="stored">Stored raw values</option>
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
              selected active calculation and hierarchy binding; they never
              write or silently recalculate data.
            </p>
          </section>
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
          Choose the two visible axes here. The persistent point of view below
          fixes every remaining page and filter dimension.
        </p>
        <section className="layout-builder" aria-label="Grid layout">
          <label>
            Rows
            <select
              value={rowDimension}
              onChange={(event) => {
                const dimension = event.target.value;
                setOpenedGridDefinition(null);
                setCalculationContext(null);
                setRowDimension(dimension);
                setPov((current) => {
                  const next = { ...current };
                  delete next[dimension];
                  return next;
                });
              }}
            >
              <option value="">Choose dimension</option>
              {dimensions.map((dimension) => (
                <option
                  key={dimension.dimension_id}
                  value={dimension.dimension_id}
                  disabled={dimension.dimension_id === columnDimension}
                >
                  {dimension.name}
                </option>
              ))}
            </select>
          </label>
          <label>
            Columns
            <select
              value={columnDimension}
              onChange={(event) => {
                const dimension = event.target.value;
                setOpenedGridDefinition(null);
                setCalculationContext(null);
                setColumnDimension(dimension);
                setPov((current) => {
                  const next = { ...current };
                  delete next[dimension];
                  return next;
                });
              }}
            >
              <option value="">Choose dimension</option>
              {dimensions.map((dimension) => (
                <option
                  key={dimension.dimension_id}
                  value={dimension.dimension_id}
                  disabled={dimension.dimension_id === rowDimension}
                >
                  {dimension.name}
                </option>
              ))}
            </select>
          </label>
          <button
            onClick={suggestLayout}
            disabled={busy || dimensions.length < 2}
          >
            Suggest layout
          </button>
        </section>
        <dl className="layout-drawer-summary">
          <div>
            <dt>Pages</dt>
            <dd>
              {Object.keys(pov).length ? "Point of view" : "Choose axes first"}
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
                      changeGridContext(() => openSavedGrid(selectedGrid))
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
                <div>
                  <dt>Rows</dt>
                  <dd>{openedGridDefinition.layout.rows.join(" / ")}</dd>
                </div>
                <div>
                  <dt>Columns</dt>
                  <dd>{openedGridDefinition.layout.columns.join(" / ")}</dd>
                </div>
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
              pages. The current rows, columns and point of view define the
              query; the fixed core owns snapshots, execution, authorization and
              the technical certificate.
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
                  disabled={Boolean(aggregateQueryId)}
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
                onChange={(event) => setAggregateReviewed(event.target.checked)}
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
            {aggregateRows.length > 0 && (
              <div className="react-grid-scroll">
                <table className="react-cube-grid aggregate-result-grid">
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
        {povDimensions.map((dimension) => (
          <label key={dimension.dimension_id}>
            {dimension.name}
            <select
              aria-label={`${dimension.name} point of view`}
              value={pov[dimension.dimension_id] || ""}
              onFocus={() => void ensureMembers(dimension.dimension_id)}
              onChange={(event) =>
                setPov((current) => ({
                  ...current,
                  [dimension.dimension_id]: event.target.value,
                }))
              }
            >
              <option value="">All permitted members</option>
              {(memberCatalog[dimension.dimension_id] || []).map((member) => (
                <option key={member.member_id} value={member.member_id}>
                  {member.name}
                </option>
              ))}
            </select>
          </label>
        ))}
        <span className="pov-spacer" />
        <button
          onClick={() => scan()}
          disabled={
            busy ||
            !dimensions.length ||
            !activeRowDimensions.length ||
            !activeColumnDimensions.length ||
            (calculatedGrid && !catalog?.functions["facts.calculation.scan"]) ||
            (readSemantics !== "stored" &&
              !catalog?.functions["facts.cube.resolved.read"]) ||
            (readSemantics === "effective" &&
              (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(resolvedBindingId) ||
                !/^[0-9a-f]{64}$/.test(resolvedBindingStateToken)))
          }
        >
          {busy ? "Reading…" : "Read grid"}
        </button>
      </div>

      {error && (
        <div className="inline-error" role="alert">
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
          <div className="grid-toolbar">
            <div role="group" aria-label="Analyze presentation">
              <button
                aria-pressed={presentation === "grid"}
                className={presentation === "grid" ? "selected" : ""}
                onClick={() => setPresentation("grid")}
              >
                Grid
              </button>
              <button
                aria-pressed={presentation === "kpi"}
                className={presentation === "kpi" ? "selected" : ""}
                disabled={!numericPresentationCells.length}
                onClick={() => setPresentation("kpi")}
              >
                KPI
              </button>
              <button
                aria-pressed={presentation === "chart"}
                className={presentation === "chart" ? "selected" : ""}
                disabled={!numericPresentationCells.length}
                onClick={() => setPresentation("chart")}
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
          {presentation === "generic" ? (
            <div className="snapshot-compare" aria-label="Generic facts">
              <div className="snapshot-compare-controls">
                <label>
                  Fact table
                  <select
                    aria-label="Generic fact table"
                    value={selectedGenericTable}
                    onChange={(event) => {
                      setSelectedGenericTable(event.target.value);
                      setGenericRows([]);
                      setGenericCursor(null);
                      setGenericSnapshot(null);
                    }}
                  >
                    {!genericTables.length && (
                      <option value="">No active tables</option>
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
                          <th>{row.series_key}</th>
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
          ) : presentation === "kpi" && numericPresentationCells.length ? (
            <div className="snapshot-kpis" aria-label="Snapshot KPI cards">
              {numericPresentationCells.map((cell, cellIndex) => (
                <article key={`${cell.changeId || "cell"}-${cellIndex}`}>
                  <span>{presentationLabel(cell)}</span>
                  <strong>{cell.amount}</strong>
                  <small>Exact snapshot value</small>
                </article>
              ))}
            </div>
          ) : presentation === "chart" && numericPresentationCells.length ? (
            <div className="snapshot-chart" aria-label="Snapshot value chart">
              <p>
                Bar lengths are a visual aid. Labels retain the exact values
                from the current authorized read.
              </p>
              {numericPresentationCells.map((cell, cellIndex) => {
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
                    <strong>{cell.amount}</strong>
                  </div>
                );
              })}
            </div>
          ) : matrix ? (
            <div className="react-grid-scroll">
              <table className="react-cube-grid">
                <thead>
                  <tr>
                    {activeRowDimensions.map((dimension) => (
                      <th key={dimension}>{dimension}</th>
                    ))}
                    {matrix.columnTuples.map(([columnKey, values]) => (
                      <th key={columnKey}>
                        {values.join(" / ")}
                        <small>{activeColumnDimensions.join(" / ")}</small>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {matrix.rowTuples.map(([rowKey, rowValues], rowIndex) => (
                    <tr key={rowKey}>
                      {rowValues.map((value, valueIndex) => (
                        <th key={`${activeRowDimensions[valueIndex]}:${value}`}>
                          {value}
                        </th>
                      ))}
                      {matrix.columnTuples.map(
                        ([columnKey, columnValues], columnIndex) => {
                          const cell = matrix.cells.get(
                            `${rowKey}\u0000${columnKey}`,
                          );
                          const coordinate = {
                            ...pov,
                          };
                          activeRowDimensions.forEach(
                            (dimension, dimensionIndex) => {
                              coordinate[dimension] = rowValues[dimensionIndex];
                            },
                          );
                          activeColumnDimensions.forEach(
                            (dimension, dimensionIndex) => {
                              coordinate[dimension] =
                                columnValues[dimensionIndex];
                            },
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
                                tabIndex={
                                  rowIndex === 0 && columnIndex === 0 ? 0 : -1
                                }
                                aria-label={`${rowValues.join(", ")}, ${columnValues.join(", ")}: ${cellValue(cell)}`}
                                onKeyDown={(event) =>
                                  moveGridFocus(
                                    event,
                                    rowIndex,
                                    columnIndex,
                                    matrix.rowTuples.length,
                                    matrix.columnTuples.length,
                                  )
                                }
                                onClick={(event) => {
                                  const trigger = event.currentTarget;
                                  changeGridContext(() => {
                                    cellTrigger.current = trigger;
                                    if (calculatedGrid)
                                      void inspectCalculatedCell(selectable);
                                    else void selectCell(selectable);
                                  });
                                }}
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
          ) : rows.length ? (
            <div className="react-grid-scroll">
              <table className="react-cube-grid flat-grid">
                <thead>
                  <tr>
                    <th>Coordinate</th>
                    <th>Type</th>
                    <th>Value</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((cell, rowIndex) => (
                    <tr key={`${rowIndex}-${cell.changeId || "cell"}`}>
                      <th>
                        {Object.entries(cell.members)
                          .map(
                            ([dimension, member]) => `${dimension}: ${member}`,
                          )
                          .join(" · ")}
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
                          tabIndex={rowIndex === 0 ? 0 : -1}
                          aria-label={`${Object.values(cell.members).join(", ")}: ${cellValue(cell)}`}
                          onKeyDown={(event) =>
                            moveGridFocus(event, rowIndex, 0, rows.length, 1)
                          }
                          aria-pressed={isSelected(cell)}
                          onClick={(event) => {
                            const trigger = event.currentTarget;
                            changeGridContext(() => {
                              cellTrigger.current = trigger;
                              if (calculatedGrid)
                                void inspectCalculatedCell(cell);
                              else void selectCell(cell);
                            });
                          }}
                        >
                          {cellValue(cell)}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : resolvedStatus === "current-empty" ? (
            <div className="grid-placeholder" aria-label="Current empty result">
              <span>∅</span>
              <h2>Current · Empty</h2>
              <p>
                The governed calculation completed successfully and certified
                that this selection currently contains no values.
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
            <footer className="grid-status" aria-live="polite">
              <span>
                {snapshot === null
                  ? "No snapshot read"
                  : `${rows.length} current cells`}
              </span>
              <button
                onClick={() => {
                  if (resolvedPage) {
                    const offset = resolvedPage.offset + resolvedPage.pageSize;
                    setRows(
                      resolvedPageCells(
                        resolvedPage.cells,
                        resolvedPage.pageSize,
                        offset,
                      ),
                    );
                    setResolvedPage({ ...resolvedPage, offset });
                  } else void scan(nextCursor);
                }}
                disabled={
                  busy ||
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
          {calculationContext && (
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
        {selectedCell && (
          <aside
            className="writeback-drawer"
            aria-label="Cell details and writeback"
          >
            <div className="drawer-heading">
              <div>
                <span>Selected cell</span>
                <h2 ref={cellInspectorHeading} tabIndex={-1}>
                  {calculatedGrid
                    ? "Calculated result details"
                    : "Details and exact writeback"}
                </h2>
              </div>
              <button
                aria-label="Close writeback"
                disabled={busy}
                onClick={() =>
                  changeGridContext(() => {
                    setSelectedCell(null);
                    cellTrigger.current?.focus();
                  })
                }
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
            <section
              className="cell-details"
              aria-label="Authoritative cell details"
            >
              <h3>Current authoritative state</h3>
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
                  <dd>{source || "Not available"}</dd>
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
              <p>
                {calculatedGrid
                  ? "This cell belongs to the governed current calculated result below. The browser displays only provenance supplied by the current result contract."
                  : "This view shows the current authorized value and governed source information. Internal concurrency controls remain enforced without exposing backend identifiers."}
              </p>
            </section>
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
                <div className="drawer-fields">
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
                </div>
                <p
                  className={
                    writeReady ? "drawer-readiness ready" : "drawer-readiness"
                  }
                >
                  {!writeAuthorized
                    ? "Your current role cannot write this cell type."
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
                    disabled={!writeReady || busy}
                    onChange={(event) => setReviewed(event.target.checked)}
                  />
                  I reviewed this exact cell mutation
                </label>
                <button
                  className="primary"
                  disabled={!writeReady || !reviewed || busy}
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
