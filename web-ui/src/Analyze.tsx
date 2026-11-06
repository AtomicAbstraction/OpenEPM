import { useEffect, useMemo, useState, type KeyboardEvent } from "react";
import { readProgram, request, reviewAndSubmit } from "./api";
import type { ApplicationCatalog, ApplicationSummary, Scope } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { collectAllContinuations } from "./continuation";

type Dimension = {
  dimension_id: string;
  name: string;
  model_role: string;
  status: string;
};

type Member = { member_id: string; name: string; status: string };

export type CubeCell = {
  members: Record<string, string>;
  kind: "numeric" | "text";
  amount?: string | null;
  text?: string | null;
  changeId?: string;
  numericChangeId?: string;
  textChangeId?: string;
  lastRevision?: number;
};

type CubePage = {
  rows: CubeCell[];
  nextCursor?: string | null;
  snapshotRevision?: number;
  source?: string;
  resultKey?: string;
  generationId?: string;
  publishedRevision?: number;
  inputRevisionStatus?: { matchesAtRead?: boolean };
  aggregateContext?: { accountingPolicyStatus?: string };
  contributionContext?: { accountingPolicyStatus?: string };
};

type SavedGridDefinition = {
  rowDimensions: string[];
  columnDimensions: string[];
  pov: Record<string, string>;
  dataLayer: "raw" | "calculated";
  pageSize: number;
  resultKey?: string;
};

type SavedGrid = {
  gridId: string;
  version: number;
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
) {
  return cursor ? { cursor, limit } : { members, limit };
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

export function savedGridListArguments(afterGridId?: string | null) {
  return afterGridId ? { limit: 100, afterGridId } : { limit: 100 };
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
};

export function collectSavedGrids(
  readPage: (cursor: string | null) => Promise<SavedGridPage>,
) {
  return collectAllContinuations<SavedGridPage, SavedGrid>({
    label: "Saved grids",
    readPage,
    rows: (page) => page.grids,
    nextCursor: (page) => page.nextAfterGridId,
    rowIdentity: (row) => `${row.gridId}\u0000${row.version}`,
  });
}

export function savedGridSaveProgram(
  gridId: string,
  version: number,
  name: string,
  definition: SavedGridDefinition,
  expectedMetadataRevision: number,
) {
  return {
    languageVersion: 2,
    function: "grid.definition.save",
    arguments: {
      gridId,
      version,
      name,
      definition,
      expectedMetadataRevision,
    },
  };
}

export function canOpenSavedGrid(grid: SavedGrid) {
  const definition = grid.definition;
  const axes = [...definition.rowDimensions, ...definition.columnDimensions];
  return Boolean(
    definition.rowDimensions.length &&
      definition.columnDimensions.length &&
      axes.length <= 20 &&
      new Set(axes).size === axes.length &&
      !Object.keys(definition.pov).some((dimension) =>
        axes.includes(dimension),
      ) &&
      Number.isInteger(definition.pageSize) &&
      definition.pageSize >= 1 &&
      definition.pageSize <= 500 &&
      (definition.dataLayer === "raw" ||
        (definition.dataLayer === "calculated" &&
          Boolean(definition.resultKey?.trim()))),
  );
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

function cellValue(cell?: CubeCell) {
  if (!cell) return "—";
  return cell.kind === "numeric" ? (cell.amount ?? "—") : (cell.text ?? "");
}

function cellClass(cell?: CubeCell) {
  if (!cell) return "missing";
  if (cell.kind === "text" && cell.text === "") return "empty-text";
  if (cell.kind === "numeric" && /^[-+]?0(?:\.0+)?$/.test(cell.amount || ""))
    return "zero";
  return cell.kind === "text" ? "text" : "numeric";
}

function cellPresence(cell: CubeCell) {
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
  targetViewVersion,
  targetViewDigest,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  index: number;
  subject: string;
  targetViewId?: string;
  targetViewVersion?: number;
  targetViewDigest?: string;
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
  const [snapshot, setSnapshot] = useState<number | null>(null);
  const [source, setSource] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [selectedCell, setSelectedCell] = useState<CubeCell | null>(null);
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
  const [reviewed, setReviewed] = useState(false);
  const [writeResult, setWriteResult] = useState("");
  const [savedGrids, setSavedGrids] = useState<SavedGrid[]>([]);
  const [savedGridsRead, setSavedGridsRead] = useState(false);
  const [selectedSavedGrid, setSelectedSavedGrid] = useState("");
  const [savedGridId, setSavedGridId] = useState("");
  const [savedGridName, setSavedGridName] = useState("");
  const [savedGridTouched, setSavedGridTouched] = useState(false);
  const [savedGridReviewed, setSavedGridReviewed] = useState(false);
  const [savedGridResult, setSavedGridResult] = useState("");
  const [openedGridDefinition, setOpenedGridDefinition] =
    useState<SavedGridDefinition | null>(null);
  const [calculationContext, setCalculationContext] = useState<{
    resultKey: string;
    generationId: string;
    publishedRevision: number;
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
  const [aggregateCertificate, setAggregateCertificate] = useState<unknown>();
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
    setSavedGridReviewed(false);
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
    setAggregateCertificate(undefined);
    setAggregateCancelReviewed(false);
    setAggregateStateRead(false);
    if (!scope) return;
    const controller = new AbortController();
    readAllDimensions(scope, controller.signal)
      .then((result) => {
        setDimensions(result.rows);
        setMetadataRevision(result.metadataRevision);
      })
      .catch((reason: Error) => {
        if (reason.name !== "AbortError") setError(reason.message);
      });
    return () => controller.abort();
  }, [app?.workspaceId, app?.applicationId]);

  useEffect(
    () => setReviewed(false),
    [writeKind, writeOperation, writeValue, expectedChangeId, selectedCell],
  );

  useEffect(
    () => setSavedGridReviewed(false),
    [
      savedGridId,
      savedGridName,
      rowDimension,
      columnDimension,
      pov,
      metadataRevision,
      openedGridDefinition,
    ],
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
    ? openedGridDefinition.rowDimensions
    : rowDimension
      ? [rowDimension]
      : [];
  const activeColumnDimensions = openedGridDefinition
    ? openedGridDefinition.columnDimensions
    : columnDimension
      ? [columnDimension]
      : [];
  const calculatedGrid = openedGridDefinition?.dataLayer === "calculated";
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

  async function readSavedGrids() {
    if (!scope || !catalog?.functions["grid.definition.list"]) return;
    setBusy(true);
    setError("");
    try {
      const collected = await collectSavedGrids((afterGridId) =>
        readProgram(
          scope,
          "grid.definition.list",
          savedGridListArguments(afterGridId),
        ),
      );
      const grids = collected.rows;
      setSavedGrids(grids);
      setSavedGridsRead(true);
      setSelectedSavedGrid((current) =>
        grids.some((grid) => `${grid.gridId}:${grid.version}` === current)
          ? current
          : grids[0]
            ? `${grids[0].gridId}:${grids[0].version}`
            : "",
      );
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read shared grid definitions",
      );
    } finally {
      setBusy(false);
    }
  }

  function openSavedGrid(grid: SavedGrid) {
    if (!canOpenSavedGrid(grid)) {
      setError(
        "This saved definition is invalid or cannot be represented without changing its declared semantics.",
      );
      return;
    }
    setOpenedGridDefinition({
      ...grid.definition,
      rowDimensions: [...grid.definition.rowDimensions],
      columnDimensions: [...grid.definition.columnDimensions],
      pov: { ...grid.definition.pov },
    });
    setCalculationContext(null);
    setRowDimension(grid.definition.rowDimensions[0] || "");
    setColumnDimension(grid.definition.columnDimensions[0] || "");
    setPov({ ...grid.definition.pov });
    setSavedGridId(grid.gridId);
    setSelectedSavedGrid(`${grid.gridId}:${grid.version}`);
    setSavedGridName(grid.name);
    setSavedGridTouched(false);
    setRows([]);
    setSnapshot(null);
    setNextCursor(null);
    setSelectedCell(null);
    setSavedGridResult(
      `Opened ${grid.name} v${grid.version} · ${grid.definition.dataLayer} · ${grid.definition.rowDimensions.length} row axes · ${grid.definition.columnDimensions.length} column axes · metadata revision ${grid.metadataRevision}`,
    );
  }

  useEffect(() => {
    if (
      !scope ||
      !targetViewId ||
      !targetViewVersion ||
      !targetViewDigest ||
      !catalog?.functions["grid.definition.read"]
    )
      return;
    const controller = new AbortController();
    readProgram<SavedGrid>(
      scope,
      "grid.definition.read",
      { gridId: targetViewId, version: targetViewVersion },
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
    targetViewVersion,
    targetViewDigest,
    Boolean(catalog?.functions["grid.definition.read"]),
  ]);

  const selectedGrid = savedGrids.find(
    (grid) => `${grid.gridId}:${grid.version}` === selectedSavedGrid,
  );
  const latestSavedGridVersion = savedGrids.find(
    (grid) => grid.gridId === savedGridId.trim(),
  )?.version;
  const nextSavedGridVersion = (latestSavedGridVersion || 0) + 1;
  const savedGridDefinition: SavedGridDefinition = openedGridDefinition
    ? {
        ...openedGridDefinition,
        rowDimensions: [...openedGridDefinition.rowDimensions],
        columnDimensions: [...openedGridDefinition.columnDimensions],
        pov: { ...openedGridDefinition.pov },
      }
    : {
        rowDimensions: rowDimension ? [rowDimension] : [],
        columnDimensions: columnDimension ? [columnDimension] : [],
        pov: { ...pov },
        dataLayer: "raw",
        pageSize: 100,
      };
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
      savedGridDefinition.rowDimensions.length &&
      savedGridDefinition.columnDimensions.length &&
      canOpenSavedGrid({
        gridId: savedGridId || "candidate",
        version: nextSavedGridVersion,
        name: savedGridName || "candidate",
        definition: savedGridDefinition,
        metadataRevision: metadataRevision || 0,
        canonicalDigest: "candidate",
      }),
  );

  async function saveSharedGrid() {
    if (!scope || !metadataRevision || !savedGridReady || !savedGridReviewed)
      return;
    setBusy(true);
    setError("");
    try {
      const response = await request<{ result: SavedGrid }>(
        "/api/metadata-action",
        {
          ...scope,
          program: savedGridSaveProgram(
            savedGridId,
            nextSavedGridVersion,
            savedGridName,
            savedGridDefinition,
            metadataRevision,
          ),
          idempotencyKey: mutationIntentKey({
            scope,
            function: "grid.definition.save",
            gridId: savedGridId,
            version: nextSavedGridVersion,
            name: savedGridName,
            definition: savedGridDefinition,
            metadataRevision,
          }),
          confirmed: true,
        },
      );
      setSavedGridResult(
        `Saved ${response.result.name} v${response.result.version} · digest ${response.result.canonicalDigest}`,
      );
      setSavedGridReviewed(false);
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
      setAggregateCertificate(undefined);
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
      setAggregateCertificate(response.result.technicalCertificate);
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
      if (!cursor)
        await Promise.all(
          [...new Set([...activeRowDimensions, ...activeColumnDimensions])].map(
            (dimension) => ensureMembers(dimension),
          ),
        );
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
            : { cursor, limit: pageSize }
          : calculatedGrid
            ? {
                members: pov,
                limit: pageSize,
                resultKey: openedGridDefinition?.resultKey,
              }
            : buildScanArguments(pov, pageSize),
      );
      setRows(
        calculatedGrid
          ? page.rows.map((cell) => ({
              ...cell,
              kind: "numeric" as const,
              lastRevision: page.publishedRevision,
            }))
          : page.rows,
      );
      setNextCursor(page.nextCursor || null);
      setSnapshot(page.snapshotRevision ?? page.publishedRevision ?? null);
      setSource(
        calculatedGrid
          ? `calculated generation ${page.generationId || "—"}`
          : page.source || "raw",
      );
      setCalculationContext(
        calculatedGrid
          ? {
              resultKey:
                page.resultKey || openedGridDefinition?.resultKey || "",
              generationId: page.generationId || "",
              publishedRevision: page.publishedRevision || 0,
              inputsMatch: page.inputRevisionStatus?.matchesAtRead === true,
              accountingStatus:
                page.aggregateContext?.accountingPolicyStatus ||
                page.contributionContext?.accountingPolicyStatus,
            }
          : null,
      );
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to read grid",
      );
    } finally {
      setBusy(false);
    }
  }

  async function selectCell(cell: CubeCell) {
    if (!scope) return;
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
    setWriteResult("");
    setBusy(true);
    setError("");
    try {
      const page = await readProgram<CubePage>(scope, "facts.cube.scan", {
        members: cell.members,
        limit: 2,
        includeMissing: true,
      });
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
      setCellResolved(true);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to resolve cell",
      );
    } finally {
      setBusy(false);
    }
  }

  function inspectCalculatedCell(cell: CubeCell) {
    setSelectedCell(cell);
    setReviewed(false);
    setWriteResult("");
    setExpectedChangeId("");
    setResolvedChangeIds({ numeric: "", text: "" });
    setCellResolved(false);
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
      setWriteResult(
        result.jobId
          ? `Writeback accepted as durable job ${result.jobId}.`
          : "Writeback request accepted.",
      );
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

  return (
    <div className="page analyze-page">
      <div className="page-heading">
        <div>
          <span>{app?.name || "Application"}</span>
          <h1>Grid</h1>
          <p>
            A governed multidimensional grid with persistent point-of-view
            controls.
          </p>
        </div>
      </div>

      <section className="layout-summary" aria-label="Current grid layout">
        <div>
          <small>ROWS</small>
          <strong>{rowDimension || "Not selected"}</strong>
        </div>
        <div>
          <small>COLUMNS</small>
          <strong>{columnDimension || "Not selected"}</strong>
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

      {Boolean(
        catalog?.functions["grid.definition.list"] ||
          catalog?.functions["grid.definition.save"],
      ) && (
        <details className="shared-grid-definitions">
          <summary>Saved governed grid views</summary>
          <p>
            Saved layouts are immutable application definitions governed by the
            fixed core. Dimension, member and POV metadata is never persisted in
            browser storage.
          </p>
          <div className="shared-grid-row">
            <label>
              Shared definition
              <select
                aria-label="Shared grid definition"
                value={selectedSavedGrid}
                onChange={(event) => setSelectedSavedGrid(event.target.value)}
              >
                {!savedGrids.length && <option value="">No definitions</option>}
                {savedGrids.map((grid) => (
                  <option
                    key={`${grid.gridId}:${grid.version}`}
                    value={`${grid.gridId}:${grid.version}`}
                  >
                    {grid.name} ({grid.gridId} v{grid.version})
                    {!canOpenSavedGrid(grid) ? " · retained grid required" : ""}
                  </option>
                ))}
              </select>
            </label>
            <button
              type="button"
              onClick={() => void readSavedGrids()}
              disabled={busy || !catalog?.functions["grid.definition.list"]}
            >
              Refresh shared definitions
            </button>
            <button
              type="button"
              onClick={() => selectedGrid && openSavedGrid(selectedGrid)}
              disabled={!selectedGrid || !canOpenSavedGrid(selectedGrid)}
            >
              Open shared definition
            </button>
          </div>
          <small>
            {savedGridsRead
              ? `${savedGrids.length} shared definition${savedGrids.length === 1 ? "" : "s"}`
              : "Shared definitions have not been read yet."}
          </small>
          {Boolean(catalog?.functions["grid.definition.save"]) && (
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
              <span>Next immutable version {nextSavedGridVersion}</span>
              <label className="review-check">
                <input
                  type="checkbox"
                  checked={savedGridReviewed}
                  disabled={!savedGridReady || busy}
                  onChange={(event) =>
                    setSavedGridReviewed(event.target.checked)
                  }
                />
                I reviewed this exact shared grid definition
              </label>
              <button
                type="button"
                onClick={() => void saveSharedGrid()}
                disabled={!savedGridReady || !savedGridReviewed || busy}
              >
                Save immutable definition
              </button>
            </div>
          )}
          {savedGridResult && <p role="status">{savedGridResult}</p>}
          {openedGridDefinition && (
            <dl
              className="saved-grid-open-context"
              aria-label="Opened grid layout"
            >
              <div>
                <dt>Rows</dt>
                <dd>{openedGridDefinition.rowDimensions.join(" / ")}</dd>
              </div>
              <div>
                <dt>Columns</dt>
                <dd>{openedGridDefinition.columnDimensions.join(" / ")}</dd>
              </div>
              <div>
                <dt>Layer</dt>
                <dd>{openedGridDefinition.dataLayer}</dd>
              </div>
              {openedGridDefinition.resultKey && (
                <div>
                  <dt>Result key</dt>
                  <dd>
                    <code>{openedGridDefinition.resultKey}</code>
                  </dd>
                </div>
              )}
            </dl>
          )}
        </details>
      )}

      {Boolean(
        catalog?.functions["facts.cube.aggregate.request"] ||
          catalog?.functions["facts.cube.aggregate.read"],
      ) && (
        <details className="aggregate-workspace">
          <summary>Aggregate large cube selections</summary>
          <p>
            Reduce authorized raw numeric facts into durable exact result pages.
            The current rows, columns and point of view define the query; the
            fixed core owns snapshots, execution, authorization and the
            technical certificate.
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
            <label>
              Query ID
              <input
                aria-label="Aggregate query ID"
                value={aggregateQueryId}
                maxLength={200}
                onChange={(event) => {
                  setAggregateQueryId(event.target.value.trim());
                  setAggregateStatus("");
                  setAggregateRows([]);
                  setAggregateCursor(null);
                  setAggregateCertificate(undefined);
                  setAggregateCancelReviewed(false);
                  setAggregateStateRead(false);
                }}
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
              Read status and results
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
              ? `Query ${aggregateQueryId} · ${aggregateStatus || "status not read"}`
              : "No aggregate query requested."}
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
                            ([dimension, member]) => `${dimension}: ${member}`,
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
              disabled={!aggregateCanCancel || !aggregateCancelReviewed || busy}
              onClick={() => void cancelAggregate()}
            >
              Request cancellation
            </button>
          </div>
          {aggregateCertificate !== undefined && (
            <details>
              <summary>Technical query certificate</summary>
              <pre>{JSON.stringify(aggregateCertificate, null, 2)}</pre>
            </details>
          )}
        </details>
      )}

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
            (calculatedGrid && !catalog?.functions["facts.calculation.scan"])
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
      <section className={`grid-panel grid-density-${gridDensity}`}>
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
              <div className="react-grid-scroll">
                <table className="react-cube-grid generic-fact-grid">
                  <thead>
                    <tr>
                      <th>Series key</th>
                      <th>Value</th>
                      <th>Revision</th>
                      <th>Change ID</th>
                    </tr>
                  </thead>
                  <tbody>
                    {genericRows.map((row) => (
                      <tr key={`${row.series_key}-${row.change_id}`}>
                        <th>{row.series_key}</th>
                        <td>
                          <code>{genericValueText(row.value)}</code>
                        </td>
                        <td>{row.last_revision}</td>
                        <td>
                          <code>{row.change_id}</code>
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
                  Choose an active table, then read one stable server snapshot.
                </p>
              </div>
            )}
            <footer className="grid-status" aria-live="polite">
              <span>
                {genericSnapshot === null
                  ? "No generic-fact snapshot read"
                  : `${genericRows.length} records · source snapshot ${genericSnapshot}`}
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
              Bar lengths are a visual aid. Labels retain the exact values from
              snapshot {snapshot ?? "—"}.
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
                            className={cellClass(cell)}
                            key={columnKey}
                            title={
                              cell
                                ? `${cell.kind} · revision ${cell.lastRevision ?? "—"}`
                                : "Missing"
                            }
                          >
                            <button
                              className="cell-button"
                              data-grid-row={rowIndex}
                              data-grid-column={columnIndex}
                              aria-disabled={calculatedGrid}
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
                              onClick={() =>
                                calculatedGrid
                                  ? inspectCalculatedCell(selectable)
                                  : void selectCell(selectable)
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
        ) : rows.length ? (
          <div className="react-grid-scroll">
            <table className="react-cube-grid flat-grid">
              <thead>
                <tr>
                  <th>Coordinate</th>
                  <th>Type</th>
                  <th>Revision</th>
                  <th>Value</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((cell, rowIndex) => (
                  <tr key={`${rowIndex}-${cell.changeId || "cell"}`}>
                    <th>
                      {Object.entries(cell.members)
                        .map(([dimension, member]) => `${dimension}: ${member}`)
                        .join(" · ")}
                    </th>
                    <td>{cell.kind}</td>
                    <td>{cell.lastRevision ?? "—"}</td>
                    <td className={cellClass(cell)}>
                      <button
                        className="cell-button"
                        data-grid-row={rowIndex}
                        data-grid-column={0}
                        tabIndex={rowIndex === 0 ? 0 : -1}
                        aria-label={`${Object.values(cell.members).join(", ")}: ${cellValue(cell)}`}
                        onKeyDown={(event) =>
                          moveGridFocus(event, rowIndex, 0, rows.length, 1)
                        }
                        onClick={() =>
                          calculatedGrid
                            ? inspectCalculatedCell(cell)
                            : void selectCell(cell)
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
        ) : (
          <div className="grid-placeholder">
            <span>▦</span>
            <h2>Build a governed grid</h2>
            <p>
              Choose row and column dimensions, fix the remaining point of view,
              then read the exact authorized snapshot. Select a cell to resolve
              its current concurrency identity and review an exact Set, Add or
              Clear writeback.
            </p>
          </div>
        )}
        <footer className="grid-status" aria-live="polite">
          <span>
            {snapshot === null
              ? "No snapshot read"
              : `${rows.length} cells · snapshot ${snapshot} · ${source}`}
          </span>
          <button
            onClick={() => scan(nextCursor)}
            disabled={busy || !nextCursor}
          >
            Next page
          </button>
        </footer>
        {calculationContext && (
          <dl
            className="calculation-read-context"
            aria-label="Calculated result context"
          >
            <div>
              <dt>Result key</dt>
              <dd>
                <code>{calculationContext.resultKey}</code>
              </dd>
            </div>
            <div>
              <dt>Generation</dt>
              <dd>
                <code>{calculationContext.generationId}</code>
              </dd>
            </div>
            <div>
              <dt>Published revision</dt>
              <dd>{calculationContext.publishedRevision}</dd>
            </div>
            <div>
              <dt>Inputs at read</dt>
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
              <h2>
                {calculatedGrid
                  ? "Calculated result details"
                  : "Details and exact writeback"}
              </h2>
            </div>
            <button
              aria-label="Close writeback"
              onClick={() => setSelectedCell(null)}
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
                    <small>{member}</small>
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
                <dt>Snapshot</dt>
                <dd>{snapshot ?? "Not available"}</dd>
              </div>
              <div>
                <dt>Source</dt>
                <dd>{source || "Not available"}</dd>
              </div>
              <div>
                <dt>Last revision</dt>
                <dd>{selectedCell.lastRevision ?? "Not available"}</dd>
              </div>
              <div>
                <dt>Read change ID</dt>
                <dd>
                  {selectedCell.changeId ? (
                    <code>{selectedCell.changeId}</code>
                  ) : (
                    "No present value"
                  )}
                </dd>
              </div>
            </dl>
            <p>
              {calculatedGrid
                ? "This cell belongs to the governed calculated generation below. The browser displays only provenance supplied by the existing result contract."
                : "Raw-cell reads expose exact presence, revision and concurrency identity. Source lineage is shown only when an existing governed result contract supplies it; this view does not infer lineage in the browser."}
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
                  <dt>Result key</dt>
                  <dd>
                    <code>{calculationContext.resultKey}</code>
                  </dd>
                </div>
                <div>
                  <dt>Generation</dt>
                  <dd>
                    <code>{calculationContext.generationId}</code>
                  </dd>
                </div>
                <div>
                  <dt>Published revision</dt>
                  <dd>{calculationContext.publishedRevision}</dd>
                </div>
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
          {!calculatedGrid && (
            <>
              <div className="drawer-fields">
                <label>
                  Cell type
                  <select
                    value={writeKind}
                    onChange={(event) => {
                      setWriteTouched(true);
                      setWriteKind(event.target.value as "numeric" | "text");
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
                      setWriteOperation(
                        event.target.value as "set" | "add" | "clear",
                      );
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
                <label>
                  Current change ID
                  <input
                    value={expectedChangeId}
                    readOnly
                    placeholder={
                      cellResolved
                        ? "No prior value of this type"
                        : "Resolving current cell…"
                    }
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
  );
}
