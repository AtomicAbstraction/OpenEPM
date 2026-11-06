import { useMemo, useState } from "react";
import { readCatalog, request } from "./api";
import { ReceiptInspector } from "./ReceiptInspector";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { usePreservedDraft } from "./unsaved-work";

type PreparedInput = {
  text: string;
  bytes: number;
  digest: string;
  name: string;
  sourceBundle?: {
    artifactId: string;
    bundleDigest: string;
    manifestDigest: string;
    payloadDigest: string;
    chunkCount: number;
  };
};

type Diagnostic = {
  severity: string;
  code: string;
  rowIndex?: number | null;
  field?: string | null;
  coordinate?: Record<string, string> | null;
  message: string;
};

type ImportState = {
  batchId: string;
  contentDigest: string;
  rowCount: number;
  previewToken: string;
  setCount: number;
  clearCount: number;
  artifactId: string;
  errorCount: number;
  warningCount: number;
  requestId: string;
  status: string;
  committedRevision: number | null;
  receiptId: string;
};

type ImportIntentKeys = {
  begin: string;
  manifest: string;
  publish: string;
};

export function newImportIntentKeys(): ImportIntentKeys {
  return {
    begin: `source-load-ui-${crypto.randomUUID()}`,
    manifest: `source-manifest-ui-${crypto.randomUUID()}`,
    publish: `source-import-ui-${crypto.randomUUID()}`,
  };
}

const EMPTY_STATE: ImportState = {
  batchId: "",
  contentDigest: "",
  rowCount: 0,
  previewToken: "",
  setCount: 0,
  clearCount: 0,
  artifactId: "",
  errorCount: 0,
  warningCount: 0,
  requestId: "",
  status: "",
  committedRevision: null,
  receiptId: "",
};

export function parseExactScope(value: string): Record<string, string> {
  const result: Record<string, string> = {};
  for (const entry of value.split(";")) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const separator = trimmed.indexOf("=");
    if (separator < 1 || separator === trimmed.length - 1)
      throw new Error("Use Dimension=Member pairs separated by semicolons.");
    const dimension = trimmed.slice(0, separator).trim();
    const member = trimmed.slice(separator + 1).trim();
    if (!dimension || !member)
      throw new Error("Every scope pair needs a dimension and member.");
    if (Object.hasOwn(result, dimension))
      throw new Error(`Scope repeats dimension ${dimension}.`);
    result[dimension] = member;
  }
  return Object.fromEntries(
    Object.entries(result).sort(([left], [right]) => left.localeCompare(right)),
  );
}

export const sourceProgramBody = (
  app: ApplicationSummary,
  functionName: string,
  args: Record<string, unknown>,
  confirmed = false,
) => ({
  workspaceId: app.workspaceId,
  applicationId: app.applicationId,
  ...(confirmed ? { confirmed: true } : {}),
  program: { languageVersion: 2, function: functionName, arguments: args },
});

async function sha256(text: string) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
    .join(",")}}`;
}

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export async function exportBundleToCsv(text: string): Promise<{
  csv: string;
  artifactId: string;
  bundleDigest: string;
  manifestDigest: string;
  payloadDigest: string;
  chunkCount: number;
  rowCount: number;
}> {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error("Export bundle must be valid JSON.");
  }
  if (
    !object(value) ||
    value.contractVersion !== "openepm-export-download-v1" ||
    typeof value.artifactId !== "string" ||
    !/^[0-9a-f]{32}$/.test(value.artifactId) ||
    !object(value.manifest) ||
    !Array.isArray(value.chunks) ||
    !Number.isInteger(value.chunkCount) ||
    value.chunkCount !== value.chunks.length ||
    value.chunks.length < 1
  )
    throw new Error("Export bundle envelope is incomplete or invalid.");
  const artifactId = value.artifactId;
  const manifest = value.manifest;
  const claimedManifestDigest = manifest.manifestDigest;
  const unsignedManifest = { ...manifest };
  delete unsignedManifest.manifestDigest;
  if (
    manifest.contractVersion !== "openepm-complete-export-manifest-v2" ||
    manifest.status !== "complete" ||
    typeof claimedManifestDigest !== "string" ||
    !/^[0-9a-f]{64}$/.test(claimedManifestDigest) ||
    (await sha256(canonicalJson(unsignedManifest))) !== claimedManifestDigest ||
    !Number.isInteger(manifest.pageCount) ||
    !Number.isInteger(manifest.totalRowCount) ||
    !Number.isInteger(manifest.totalRowBytes) ||
    !object(manifest.scope) ||
    typeof manifest.scope.workspaceId !== "string" ||
    typeof manifest.scope.applicationId !== "string" ||
    !Number.isInteger(manifest.snapshotRevision) ||
    !Number.isInteger(manifest.metadataRevision) ||
    !Number.isInteger(manifest.securityRevision) ||
    !Array.isArray(manifest.pages) ||
    manifest.pages.length !== manifest.pageCount ||
    !object(manifest.typeCounts)
  )
    throw new Error("Export bundle manifest is incomplete or invalid.");
  let manifestDigest = "";
  let payloadDigest = "";
  let priorSource = "";
  let expectedPageIndex = 0;
  let expectedChunkIndex = 0;
  let pageRows: unknown[] = [];
  let axes: string[] | null = null;
  const rows: Array<{
    members: Record<string, string>;
    literalType: string;
    value: string;
    sourceRef: string;
  }> = [];
  for (const [ordinal, wrapper] of value.chunks.entries()) {
    if (
      !object(wrapper) ||
      wrapper.artifactId !== artifactId ||
      wrapper.ordinal !== ordinal ||
      wrapper.hasMore !== ordinal < value.chunks.length - 1 ||
      typeof wrapper.manifestDigest !== "string" ||
      typeof wrapper.payloadDigest !== "string" ||
      !/^[0-9a-f]{64}$/.test(wrapper.manifestDigest) ||
      !/^[0-9a-f]{64}$/.test(wrapper.payloadDigest) ||
      !object(wrapper.chunk)
    )
      throw new Error("Export bundle chunk sequence is invalid.");
    manifestDigest ||= wrapper.manifestDigest;
    payloadDigest ||= wrapper.payloadDigest;
    if (
      wrapper.manifestDigest !== manifestDigest ||
      wrapper.payloadDigest !== payloadDigest
    )
      throw new Error("Export bundle identity changes between chunks.");
    const chunk = wrapper.chunk;
    const claimedDigest = chunk.chunkDigest;
    const expectedChunkFields = [
      "artifactId",
      "chunkDigest",
      "chunkIndex",
      "ciphertextRef",
      "contractVersion",
      "finalChunkForPage",
      "firstKey",
      "lastKey",
      "manifestDigest",
      "pageContentDigest",
      "pageEntryDigest",
      "pageIndex",
      "rowBytes",
      "rowCount",
      "rows",
      "typeCounts",
    ];
    if (
      Object.keys(chunk).sort().join("\0") !== expectedChunkFields.join("\0") ||
      chunk.contractVersion !== "openepm-export-payload-v2" ||
      chunk.artifactId !== artifactId ||
      chunk.manifestDigest !== manifestDigest ||
      chunk.pageIndex !== expectedPageIndex ||
      chunk.chunkIndex !== expectedChunkIndex ||
      typeof chunk.finalChunkForPage !== "boolean" ||
      typeof claimedDigest !== "string" ||
      !/^[0-9a-f]{64}$/.test(claimedDigest) ||
      !Array.isArray(chunk.rows) ||
      chunk.rowCount !== chunk.rows.length
    )
      throw new Error("Export bundle payload chunk is invalid.");
    const unsigned = { ...chunk };
    delete unsigned.chunkDigest;
    if ((await sha256(canonicalJson(unsigned))) !== claimedDigest)
      throw new Error("Export bundle payload digest does not match.");
    const rowBytes = new TextEncoder().encode(canonicalJson(chunk.rows)).length;
    const typeCounts = { amount: 0, text: 0, lineDetail: 0 };
    for (const row of chunk.rows) {
      const kind = object(row) && object(row.value) ? row.value.type : null;
      if (kind === "AmountLiteral") typeCounts.amount += 1;
      else if (kind === "TextLiteral") typeCounts.text += 1;
      else if (kind === "LineDetailLiteral") typeCounts.lineDetail += 1;
    }
    const firstKey = chunk.rows.length
      ? String((chunk.rows[0] as Record<string, unknown>).sourceRef).slice(7)
      : null;
    const lastKey = chunk.rows.length
      ? String((chunk.rows.at(-1) as Record<string, unknown>).sourceRef).slice(
          7,
        )
      : null;
    if (
      chunk.rowBytes !== rowBytes ||
      canonicalJson(chunk.typeCounts) !== canonicalJson(typeCounts) ||
      chunk.firstKey !== firstKey ||
      chunk.lastKey !== lastKey
    )
      throw new Error("Export bundle payload completeness check failed.");
    for (const row of chunk.rows) {
      if (
        !object(row) ||
        !object(row.members) ||
        !object(row.value) ||
        typeof row.sourceRef !== "string" ||
        !/^export:[0-9a-f]{64}$/.test(row.sourceRef) ||
        row.sourceRef <= priorSource ||
        Object.keys(row.members).length < 1 ||
        Object.values(row.members).some(
          (member) => typeof member !== "string" || !member,
        )
      )
        throw new Error("Export bundle contains an invalid or unordered row.");
      priorSource = row.sourceRef;
      const rowAxes = Object.keys(row.members).sort();
      axes ||= rowAxes;
      if (rowAxes.join("\0") !== axes.join("\0"))
        throw new Error("Export bundle row dimensions are inconsistent.");
      const literal = row.value;
      let literalValue: string;
      if (
        literal.type === "AmountLiteral" &&
        typeof literal.decimal === "string"
      )
        literalValue = literal.decimal;
      else if (
        literal.type === "TextLiteral" &&
        typeof literal.text === "string"
      )
        literalValue = literal.text;
      else if (
        literal.type === "LineDetailLiteral" &&
        Array.isArray(literal.items) &&
        literal.items.every(
          (item) =>
            object(item) &&
            Object.keys(item).sort().join("\0") === "decimal\0description" &&
            typeof item.description === "string" &&
            typeof item.decimal === "string",
        )
      )
        literalValue = canonicalJson(literal.items);
      else throw new Error("Export bundle contains an unsupported literal.");
      rows.push({
        members: row.members as Record<string, string>,
        literalType: String(literal.type),
        value: literalValue,
        sourceRef: row.sourceRef,
      });
    }
    pageRows.push(...chunk.rows);
    if (chunk.finalChunkForPage) {
      const entry = manifest.pages[expectedPageIndex];
      const firstPageKey = pageRows.length
        ? String((pageRows[0] as Record<string, unknown>).sourceRef).slice(7)
        : null;
      const lastPageKey = pageRows.length
        ? String((pageRows.at(-1) as Record<string, unknown>).sourceRef).slice(
            7,
          )
        : null;
      if (
        !object(entry) ||
        entry.pageIndex !== expectedPageIndex ||
        entry.hasMore !== expectedPageIndex < manifest.pages.length - 1 ||
        entry.contentDigest !== chunk.pageContentDigest ||
        (await sha256(canonicalJson(entry))) !== chunk.pageEntryDigest ||
        entry.rowCount !== pageRows.length ||
        entry.firstKey !== firstPageKey ||
        entry.lastKey !== lastPageKey ||
        entry.rowBytes !==
          new TextEncoder().encode(canonicalJson(pageRows)).length ||
        canonicalJson(entry.typeCounts) !==
          canonicalJson(
            pageRows.reduce<{
              amount: number;
              text: number;
              lineDetail: number;
            }>(
              (counts, item) => {
                const kind =
                  object(item) && object(item.value) ? item.value.type : null;
                if (kind === "AmountLiteral") counts.amount += 1;
                else if (kind === "TextLiteral") counts.text += 1;
                else if (kind === "LineDetailLiteral") counts.lineDetail += 1;
                return counts;
              },
              { amount: 0, text: 0, lineDetail: 0 },
            ),
          )
      )
        throw new Error("Export bundle page does not match its manifest.");
      pageRows = [];
      expectedPageIndex += 1;
      expectedChunkIndex = 0;
    } else expectedChunkIndex += 1;
  }
  if (expectedChunkIndex !== 0)
    throw new Error("Export bundle ends before its final page chunk.");
  const observedTypeCounts = { amount: 0, text: 0, lineDetail: 0 };
  for (const row of rows) {
    if (row.literalType === "AmountLiteral") observedTypeCounts.amount += 1;
    else if (row.literalType === "TextLiteral") observedTypeCounts.text += 1;
    else observedTypeCounts.lineDetail += 1;
  }
  if (
    manifest.manifestDigest !== manifestDigest ||
    manifest.pageCount !== expectedPageIndex ||
    manifest.totalRowCount !== rows.length ||
    manifest.totalRowBytes !==
      manifest.pages.reduce(
        (total: number, page: unknown) =>
          total +
          (object(page) && Number.isInteger(page.rowBytes)
            ? Number(page.rowBytes)
            : Number.NaN),
        0,
      ) ||
    canonicalJson(manifest.typeCounts) !== canonicalJson(observedTypeCounts)
  )
    throw new Error("Export bundle does not match its complete manifest.");
  const reconstructedPayload = {
    contractVersion: "openepm-export-payload-v2",
    status: "complete",
    artifactId,
    manifestDigest,
    scope: manifest.scope,
    snapshotRevision: manifest.snapshotRevision,
    metadataRevision: manifest.metadataRevision,
    securityRevision: manifest.securityRevision,
    chunkCount: value.chunks.length,
    rowCount: rows.length,
    rowBytes: manifest.totalRowBytes,
    typeCounts: observedTypeCounts,
    chunks: value.chunks.map(
      (wrapper) => (wrapper as Record<string, unknown>).chunk,
    ),
  };
  if ((await sha256(canonicalJson(reconstructedPayload))) !== payloadDigest)
    throw new Error("Export bundle aggregate payload digest does not match.");
  if (!axes || !rows.length)
    throw new Error("Export bundle contains no re-importable rows.");
  const header = [
    ...axes.map((axis) => `axis.${axis}`),
    "literalType",
    "value",
    "sourceRef",
  ];
  const csv = [
    header.map(encodeCsvCell).join(","),
    ...rows.map((row) =>
      [
        ...axes!.map((axis) => row.members[axis]),
        row.literalType,
        row.value,
        row.sourceRef,
      ]
        .map(encodeCsvCell)
        .join(","),
    ),
  ].join("\n");
  return {
    csv,
    artifactId,
    bundleDigest: await sha256(text),
    manifestDigest,
    payloadDigest,
    chunkCount: value.chunks.length,
    rowCount: rows.length,
  };
}

const MAX_CSV_ROWS_PER_CHUNK = 500;
const MAX_CSV_CHUNK_BYTES = 4_000_000;
const BATCH_ID = /^[0-9a-f]{32}$/;
const CONTENT_DIGEST = /^[0-9a-f]{64}$/;

export const EXAMPLE_IMPORT_CSV = [
  "axis.Account,axis.Entity,axis.Year,axis.Period,axis.View,axis.Value,literalType,value,sourceRef",
  "Revenue,ExampleEntity,2027,Jan,Periodic,Input,AmountLiteral,100.00000000,example-amount",
  "Revenue,ExampleEntity,2027,Feb,Periodic,Input,AmountLiteral,0.00000000,example-zero",
  'Comment,ExampleEntity,2027,Jan,Periodic,Input,TextLiteral,"",example-empty-text',
].join("\n");

export const EXAMPLE_IMPORT_CSV_URL = `data:text/csv;charset=utf-8,${encodeURIComponent(
  EXAMPLE_IMPORT_CSV,
)}`;

function encodeCsvCell(value: string) {
  return /[",\r\n]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value;
}

function parseCsvRecords(text: string): string[][] {
  const records: string[][] = [];
  let record: string[] = [];
  let field = "";
  let quoted = false;
  let afterQuote = false;
  const pushRecord = () => {
    record.push(field);
    records.push(record);
    record = [];
    field = "";
    afterQuote = false;
  };
  for (let index = 0; index < text.length; index += 1) {
    const value = text[index];
    if (quoted) {
      if (value === '"') {
        if (text[index + 1] === '"') {
          field += '"';
          index += 1;
        } else {
          quoted = false;
          afterQuote = true;
        }
      } else field += value;
      continue;
    }
    if (afterQuote && value !== "," && value !== "\n" && value !== "\r")
      throw new Error("CSV has characters after a closing quote.");
    if (value === '"') {
      if (field) throw new Error("CSV quote must begin a field.");
      quoted = true;
    } else if (value === ",") {
      record.push(field);
      field = "";
      afterQuote = false;
    } else if (value === "\n" || value === "\r") {
      if (value === "\r" && text[index + 1] === "\n") index += 1;
      pushRecord();
    } else field += value;
  }
  if (quoted) throw new Error("CSV has an unterminated quoted field.");
  if (field || record.length) pushRecord();
  while (records.length && records.at(-1)?.every((value) => value === ""))
    records.pop();
  if (records.length < 2)
    throw new Error("CSV needs a header and at least one data row.");
  const [header, ...rows] = records;
  if (rows.some((row) => row.length !== header.length))
    throw new Error(
      "Every CSV row must have the same number of columns as the header.",
    );
  return records;
}

export function csvRowCount(text: string): number {
  return parseCsvRecords(text).length - 1;
}

export function csvChunks(text: string): string[] {
  const [header, ...rows] = parseCsvRecords(text);
  const line = (row: string[]) => row.map(encodeCsvCell).join(",");
  const headerLine = line(header);
  const chunks: string[] = [];
  let current: string[] = [];
  for (const row of rows) {
    const encoded = line(row);
    const candidate = [headerLine, ...current, encoded].join("\n");
    if (
      current.length &&
      (current.length >= MAX_CSV_ROWS_PER_CHUNK ||
        new TextEncoder().encode(candidate).length > MAX_CSV_CHUNK_BYTES)
    ) {
      chunks.push([headerLine, ...current].join("\n"));
      current = [];
    }
    if (
      new TextEncoder().encode([headerLine, encoded].join("\n")).length >
      MAX_CSV_CHUNK_BYTES
    )
      throw new Error(
        "A single CSV record is too large for the bounded upload envelope.",
      );
    current.push(encoded);
  }
  if (current.length) chunks.push([headerLine, ...current].join("\n"));
  return chunks;
}

type BatchProgress = {
  batchId: string;
  rowCount: number;
  contentDigest: string;
  status?: string;
  chunkIndex?: number;
};

type ImportExecution = {
  requestId: string;
  batchId: string;
  status:
    | "Accepted"
    | "Claimed"
    | "Publishing"
    | "Completed"
    | "Failed"
    | "Cancelled";
  result: Record<string, unknown> | null;
  errorCode: string | null;
};

type ImportPreview = {
  previewToken: string;
  setCount: number;
  clearCount: number;
  diagnostics?: {
    artifactId?: string;
    errorCount?: number;
    warningCount?: number;
  };
};

function exactImportPreview(
  value: unknown,
  batchId: string,
  contentDigest: string,
): ImportPreview {
  if (
    !object(value) ||
    value.batchId !== batchId ||
    value.contentDigest !== contentDigest ||
    typeof value.previewToken !== "string" ||
    !value.previewToken ||
    !Number.isSafeInteger(value.setCount) ||
    Number(value.setCount) < 0 ||
    !Number.isSafeInteger(value.clearCount) ||
    Number(value.clearCount) < 0 ||
    (value.diagnostics !== undefined &&
      (!object(value.diagnostics) ||
        (value.diagnostics.artifactId !== undefined &&
          typeof value.diagnostics.artifactId !== "string") ||
        (value.diagnostics.errorCount !== undefined &&
          (!Number.isSafeInteger(value.diagnostics.errorCount) ||
            Number(value.diagnostics.errorCount) < 0)) ||
        (value.diagnostics.warningCount !== undefined &&
          (!Number.isSafeInteger(value.diagnostics.warningCount) ||
            Number(value.diagnostics.warningCount) < 0))))
  )
    throw new Error("INVALID_SOURCE_PREVIEW_RESPONSE");
  return value as unknown as ImportPreview;
}

const IMPORT_STATUSES = new Set([
  "Accepted",
  "Claimed",
  "Publishing",
  "Completed",
  "Failed",
  "Cancelled",
]);

export function exactImportExecution(
  value: unknown,
  expected: {
    requestId?: string;
    batchId: string;
    contentDigest: string;
    mode: string;
    setCount: number;
    clearCount: number;
    committedRevision?: number | null;
    terminalStatus?: string;
  },
): ImportExecution {
  if (
    !object(value) ||
    typeof value.requestId !== "string" ||
    !BATCH_ID.test(value.requestId) ||
    (expected.requestId !== undefined &&
      value.requestId !== expected.requestId) ||
    value.batchId !== expected.batchId ||
    typeof value.status !== "string" ||
    !IMPORT_STATUSES.has(value.status) ||
    !Number.isSafeInteger(value.claimGeneration) ||
    Number(value.claimGeneration) < 0 ||
    typeof value.cancelRequested !== "boolean" ||
    (value.duplicate !== undefined && typeof value.duplicate !== "boolean") ||
    !(value.errorCode === null || typeof value.errorCode === "string")
  )
    throw new Error("INVALID_IMPORT_EXECUTION_RESPONSE");

  if (
    expected.terminalStatus !== undefined &&
    value.status !== expected.terminalStatus
  )
    throw new Error("INVALID_IMPORT_EXECUTION_RESPONSE");

  const terminal = ["Completed", "Failed", "Cancelled"].includes(value.status);
  if (!terminal && (value.result !== null || value.errorCode !== null))
    throw new Error("INVALID_IMPORT_EXECUTION_RESPONSE");

  if (value.status === "Completed") {
    const result = value.result;
    if (
      !object(result) ||
      result.batchId !== expected.batchId ||
      result.contentDigest !== expected.contentDigest ||
      result.mode !== expected.mode ||
      result.setCount !== expected.setCount ||
      result.clearCount !== expected.clearCount ||
      result.changedCount !== expected.setCount + expected.clearCount ||
      !Number.isSafeInteger(result.committedRevision) ||
      Number(result.committedRevision) < 1 ||
      (expected.committedRevision != null &&
        result.committedRevision !== expected.committedRevision) ||
      value.errorCode !== null
    )
      throw new Error("INVALID_IMPORT_COMPLETION_RESPONSE");
  } else if (terminal) {
    if (value.result !== null)
      throw new Error("INVALID_IMPORT_EXECUTION_RESPONSE");
    if (
      value.status === "Failed" &&
      (typeof value.errorCode !== "string" || !value.errorCode)
    )
      throw new Error("INVALID_IMPORT_EXECUTION_RESPONSE");
    if (value.status === "Cancelled" && !value.cancelRequested)
      throw new Error("INVALID_IMPORT_EXECUTION_RESPONSE");
  }
  return value as unknown as ImportExecution;
}

function exactBatchProgress(
  value: unknown,
  batchId?: string,
  chunkIndex?: number,
): BatchProgress {
  if (
    !object(value) ||
    typeof value.batchId !== "string" ||
    !BATCH_ID.test(value.batchId) ||
    (batchId !== undefined && value.batchId !== batchId) ||
    !Number.isSafeInteger(value.rowCount) ||
    Number(value.rowCount) < 0 ||
    Number(value.rowCount) > 100_000 ||
    typeof value.contentDigest !== "string" ||
    !CONTENT_DIGEST.test(value.contentDigest) ||
    (chunkIndex !== undefined && value.chunkIndex !== chunkIndex)
  )
    throw new Error("INVALID_SOURCE_BATCH_RESPONSE");
  return value as BatchProgress;
}

export function DataLoad({
  app,
  catalog,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
}) {
  const [csv, setCsv] = useState("");
  const [prepared, setPrepared] = useState<PreparedInput | null>(null);
  const [mode, setMode] = useState("merge");
  const [scopeText, setScopeText] = useState("");
  const [scopeAll, setScopeAll] = useState(false);
  const [allowWarnings, setAllowWarnings] = useState(false);
  const [reviewedStage, setReviewedStage] = useState(false);
  const [reviewedPublish, setReviewedPublish] = useState(false);
  const [state, setState] = useState(EMPTY_STATE);
  const [diagnostics, setDiagnostics] = useState<Diagnostic[]>([]);
  const [intentKeys, setIntentKeys] = useState(newImportIntentKeys);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [inspectReceipt, setInspectReceipt] = useState(false);

  const functions = catalog?.functions || {};
  const canStage = [
    "facts.source.begin",
    "facts.source.csv.append",
    "facts.source.seal",
    "facts.source.manifest.attach",
  ].every((name) => Object.hasOwn(functions, name));
  const canPreview = Object.hasOwn(functions, "facts.source.preview");
  const canPublish = Object.hasOwn(functions, "facts.transfer.import.request");
  const canRead = Object.hasOwn(functions, "facts.transfer.import.read");
  const canReadDiagnostics = Object.hasOwn(
    functions,
    "facts.transfer.import.diagnostics.read",
  );
  const scope = useMemo(() => {
    try {
      return parseExactScope(scopeText);
    } catch {
      return null;
    }
  }, [scopeText]);
  const scopeReady = scopeAll || Boolean(scope && Object.keys(scope).length);
  const stageReady = Boolean(
    app && prepared && scopeReady && canStage && reviewedStage,
  );
  const publishReady = Boolean(
    state.batchId &&
      state.previewToken &&
      !state.errorCount &&
      (!state.warningCount || allowWarnings) &&
      canPublish &&
      reviewedPublish,
  );
  const hasUnpublishedInput = Boolean(
    !state.requestId &&
      (csv ||
        prepared ||
        mode !== "merge" ||
        scopeText ||
        scopeAll ||
        allowWarnings ||
        reviewedStage ||
        reviewedPublish ||
        state.batchId ||
        state.previewToken),
  );
  usePreservedDraft(
    app?.workspaceId || "none",
    app?.applicationId || "none",
    "data-load-publication",
    "Unpublished data load",
    hasUnpublishedInput,
    {
      csv,
      prepared,
      mode,
      scopeText,
      scopeAll,
      allowWarnings,
      reviewedStage,
      reviewedPublish,
      state,
      diagnostics,
      intentKeys,
    },
    (draft) => {
      setCsv(draft.csv);
      setPrepared(draft.prepared);
      setMode(draft.mode);
      setScopeText(draft.scopeText);
      setScopeAll(draft.scopeAll);
      setAllowWarnings(draft.allowWarnings);
      setReviewedStage(draft.reviewedStage);
      setReviewedPublish(draft.reviewedPublish);
      setState(draft.state);
      setDiagnostics(draft.diagnostics);
      setIntentKeys(draft.intentKeys);
    },
  );

  function resetAfterDraftChange() {
    setIntentKeys(newImportIntentKeys());
    setPrepared(null);
    setReviewedStage(false);
    setReviewedPublish(false);
    setState(EMPTY_STATE);
    setDiagnostics([]);
  }

  function invalidateTarget() {
    setIntentKeys(newImportIntentKeys());
    setReviewedStage(false);
    setReviewedPublish(false);
    setState(EMPTY_STATE);
    setDiagnostics([]);
  }

  async function prepare() {
    setError("");
    const bytes = new TextEncoder().encode(csv).length;
    if (!bytes) return setError("Paste UTF-8 CSV text first.");
    if (bytes > 8_000_000)
      return setError("UTF-8 CSV content is limited to 8 MB.");
    try {
      csvChunks(csv);
    } catch (reason) {
      return setError(
        reason instanceof Error ? reason.message : "CSV is invalid.",
      );
    }
    setPrepared({
      text: csv,
      bytes,
      digest: await sha256(csv),
      name: "pasted.csv",
    });
    setReviewedStage(false);
  }

  async function prepareFile(file?: File) {
    if (!file) return;
    setError("");
    const isBundle =
      file.name.toLowerCase().endsWith(".json") ||
      file.type === "application/json";
    const limit = isBundle ? 128 * 1024 * 1024 : 8_000_000;
    if (file.size > limit)
      return setError(
        isBundle
          ? "Export bundles are limited to 128 MiB in the browser re-import journey."
          : "CSV files are limited to 8 MB.",
      );
    const original = await file.text();
    if (new TextEncoder().encode(original).length > limit)
      return setError("The UTF-8 source exceeds the browser import limit.");
    let text = original;
    let sourceBundle: PreparedInput["sourceBundle"];
    if (isBundle) {
      try {
        const converted = await exportBundleToCsv(original);
        if (converted.rowCount > 100_000)
          return setError(
            "Export bundle exceeds the 100,000-row import limit.",
          );
        text = converted.csv;
        sourceBundle = {
          artifactId: converted.artifactId,
          bundleDigest: converted.bundleDigest,
          manifestDigest: converted.manifestDigest,
          payloadDigest: converted.payloadDigest,
          chunkCount: converted.chunkCount,
        };
      } catch (reason) {
        return setError(
          reason instanceof Error
            ? reason.message
            : "Export bundle is invalid.",
        );
      }
    }
    const bytes = new TextEncoder().encode(text).length;
    try {
      csvChunks(text);
    } catch (reason) {
      return setError(
        reason instanceof Error ? reason.message : "CSV is invalid.",
      );
    }
    setCsv("");
    resetAfterDraftChange();
    setPrepared({
      text,
      bytes,
      digest: await sha256(text),
      name:
        file.name.replace(/[\u0000-\u001f\u007f]/g, "_").slice(0, 1000) ||
        "upload.csv",
      sourceBundle,
    });
  }

  async function stage() {
    if (!app || !prepared || !scope || !stageReady) return;
    setBusy(true);
    setError("");
    try {
      const current = await readCatalog({
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
      });
      const revisions = {
        metadataRevision: current.revisions.metadata,
        dataRevision: current.revisions.data,
      };
      const begin = await request<{ result: unknown }>(
        "/api/source-load",
        sourceProgramBody(
          app,
          "facts.source.begin",
          {
            idempotencyKey: intentKeys.begin,
            mode,
            scopeMembers: scopeAll ? {} : scope,
            scopeAll,
            expectedMetadataRevision: revisions.metadataRevision,
            expectedDataRevision: revisions.dataRevision,
          },
          true,
        ),
      );
      const beginProgress = exactBatchProgress(begin.result);
      const chunks = csvChunks(prepared.text);
      const totalRows = csvRowCount(prepared.text);
      let minimumRows = 0;
      let appended: BatchProgress | null = null;
      for (const [chunkIndex, csvText] of chunks.entries()) {
        minimumRows += csvRowCount(csvText);
        const response = await request<{ result: unknown }>(
          "/api/source-load",
          sourceProgramBody(
            app,
            "facts.source.csv.append",
            {
              batchId: beginProgress.batchId,
              chunkIndex,
              csvText,
            },
            true,
          ),
        );
        appended = exactBatchProgress(
          response.result,
          beginProgress.batchId,
          chunkIndex,
        );
        if (appended.rowCount < minimumRows || appended.rowCount > totalRows)
          throw new Error("INVALID_SOURCE_BATCH_PROGRESS");
      }
      if (!appended) throw new Error("CSV produced no upload chunks.");
      if (appended.rowCount !== totalRows)
        throw new Error("INVALID_SOURCE_BATCH_PROGRESS");
      const sealedResponse = await request<{ result: unknown }>(
        "/api/source-load",
        sourceProgramBody(
          app,
          "facts.source.seal",
          {
            batchId: beginProgress.batchId,
            expectedRows: appended.rowCount,
            expectedContentDigest: appended.contentDigest,
          },
          true,
        ),
      );
      const sealed = exactBatchProgress(
        sealedResponse.result,
        beginProgress.batchId,
      );
      if (
        sealed.status !== "ready" ||
        sealed.rowCount !== appended.rowCount ||
        sealed.contentDigest !== appended.contentDigest
      )
        throw new Error("INVALID_SOURCE_SEAL_RESPONSE");
      const schemaVersion = prepared.sourceBundle
        ? "openepm.export-bundle-reimport.v1"
        : "openepm.typed-csv.v1";
      const manifestResponse = await request<{ result: unknown }>(
        "/api/source-load",
        sourceProgramBody(
          app,
          "facts.source.manifest.attach",
          {
            batchId: sealed.batchId,
            requestKey: intentKeys.manifest,
            originKind: "file",
            originRef: prepared.name,
            schemaVersion,
            schema: {
              format: "text/csv",
              encoding: "UTF-8",
              coordinateColumns: "axis.<dimensionId>",
              valueColumns: ["literalType", "value", "sourceRef"],
              ...(prepared.sourceBundle
                ? { sourceExportBundle: prepared.sourceBundle }
                : {}),
            },
            contentDigest: sealed.contentDigest,
          },
          true,
        ),
      );
      const manifest = manifestResponse.result;
      if (
        !object(manifest) ||
        manifest.batchId !== sealed.batchId ||
        manifest.requestKey !== intentKeys.manifest ||
        manifest.schemaVersion !== schemaVersion ||
        manifest.contentDigest !== sealed.contentDigest ||
        typeof manifest.manifestDigest !== "string" ||
        !CONTENT_DIGEST.test(manifest.manifestDigest)
      )
        throw new Error("INVALID_SOURCE_MANIFEST_RESPONSE");
      setState({
        ...EMPTY_STATE,
        batchId: sealed.batchId,
        contentDigest: sealed.contentDigest,
        rowCount: sealed.rowCount,
      });
      setReviewedStage(false);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to stage CSV",
      );
    } finally {
      setBusy(false);
    }
  }

  async function preview() {
    if (!app || !state.batchId || !canPreview) return;
    setBusy(true);
    setError("");
    try {
      const response = await request<{ result: unknown }>(
        "/api/source-load",
        sourceProgramBody(app, "facts.source.preview", {
          batchId: state.batchId,
          allowWarnings,
        }),
      );
      const result = exactImportPreview(
        response.result,
        state.batchId,
        state.contentDigest,
      );
      setState((current) => ({
        ...current,
        previewToken: result.previewToken,
        setCount: result.setCount,
        clearCount: result.clearCount,
        artifactId: result.diagnostics?.artifactId || "",
        errorCount: result.diagnostics?.errorCount || 0,
        warningCount: result.diagnostics?.warningCount || 0,
      }));
      setReviewedPublish(false);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to preview CSV",
      );
    } finally {
      setBusy(false);
    }
  }

  async function publish() {
    if (!app || !publishReady) return;
    setBusy(true);
    setError("");
    try {
      const response = await request<{ result: unknown }>(
        "/api/source-load",
        sourceProgramBody(
          app,
          "facts.transfer.import.request",
          {
            idempotencyKey: intentKeys.publish,
            batchId: state.batchId,
            previewToken: state.previewToken,
          },
          true,
        ),
      );
      const execution = exactImportExecution(response.result, {
        batchId: state.batchId,
        contentDigest: state.contentDigest,
        mode,
        setCount: state.setCount,
        clearCount: state.clearCount,
        committedRevision: state.committedRevision,
        terminalStatus: ["Completed", "Failed", "Cancelled"].includes(
          state.status,
        )
          ? state.status
          : undefined,
      });
      const completion =
        execution.status === "Completed" ? execution.result : null;
      setState((current) => ({
        ...current,
        previewToken: "",
        requestId: execution.requestId,
        status: execution.status,
        committedRevision: completion
          ? Number(completion.committedRevision)
          : null,
        receiptId: completion ? current.batchId : "",
      }));
      setReviewedPublish(false);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to publish CSV",
      );
    } finally {
      setBusy(false);
    }
  }

  async function readStatus() {
    if (!app || !state.requestId || !canRead) return;
    setBusy(true);
    setError("");
    try {
      const response = await request<{ result: unknown }>(
        "/api/source-load",
        sourceProgramBody(app, "facts.transfer.import.read", {
          requestId: state.requestId,
        }),
      );
      const execution = exactImportExecution(response.result, {
        requestId: state.requestId,
        batchId: state.batchId,
        contentDigest: state.contentDigest,
        mode,
        setCount: state.setCount,
        clearCount: state.clearCount,
        committedRevision: state.committedRevision,
        terminalStatus: ["Completed", "Failed", "Cancelled"].includes(
          state.status,
        )
          ? state.status
          : undefined,
      });
      const completion =
        execution.status === "Completed" ? execution.result : null;
      setState((current) => ({
        ...current,
        status: execution.status,
        committedRevision: completion
          ? Number(completion.committedRevision)
          : null,
        receiptId: completion ? current.batchId : "",
      }));
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to read import",
      );
    } finally {
      setBusy(false);
    }
  }

  async function readDiagnostics() {
    if (!app || !state.artifactId || !canReadDiagnostics) return;
    setBusy(true);
    setError("");
    try {
      const response = await request<{
        result: { artifact: { diagnostics: Diagnostic[] } };
      }>(
        "/api/source-load",
        sourceProgramBody(app, "facts.transfer.import.diagnostics.read", {
          artifactId: state.artifactId,
        }),
      );
      setDiagnostics(response.result.artifact.diagnostics || []);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to read diagnostics",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <section
      className="panel data-load-journey"
      aria-labelledby="data-load-heading"
    >
      <div className="section-heading-row">
        <div>
          <small>GUIDED DATA JOURNEY</small>
          <h2 id="data-load-heading" tabIndex={-1}>
            Load governed CSV data
          </h2>
          <p>Prepare → Stage → Validate → Review scope → Publish → Receipt</p>
        </div>
        <span className="task-state neutral">No change before Publish</span>
      </div>
      <ol className="journey-steps" aria-label="CSV load progress">
        {[
          ["1", "Source", Boolean(prepared)],
          ["2", "Stage", state.batchId],
          ["3", "Validate", state.previewToken || state.requestId],
          ["4", "Publish", state.requestId],
          ["5", "Receipt", state.status],
        ].map(([number, label, complete]) => (
          <li className={complete ? "complete" : ""} key={String(label)}>
            <span>{number}</span>
            {label}
          </li>
        ))}
      </ol>
      {!canStage && catalog && (
        <div className="inline-error" role="status">
          Your current role cannot stage CSV data.
        </div>
      )}
      <div className="data-load-layout">
        <div className="data-load-form">
          <label>
            Choose CSV or governed export bundle
            <input
              type="file"
              accept=".csv,.json,text/csv,application/json"
              onChange={(event) =>
                void prepareFile(event.currentTarget.files?.[0])
              }
            />
          </label>
          <div className="data-load-separator" aria-hidden="true">
            or paste
          </div>
          <label>
            UTF-8 CSV text
            <textarea
              rows={7}
              spellCheck={false}
              value={csv}
              placeholder="axis.Account,axis.Department,…,literalType,value,sourceRef"
              onChange={(event) => {
                setCsv(event.target.value);
                resetAfterDraftChange();
              }}
            />
          </label>
          <button disabled={busy || !csv} onClick={() => void prepare()}>
            Prepare pasted CSV
          </button>
          {prepared && (
            <p role="status">
              Prepared {prepared.bytes} bytes · SHA-256{" "}
              <code>{prepared.digest.slice(0, 12)}…</code>
            </p>
          )}
          <details>
            <summary>Required columns</summary>
            <p>
              One <code>axis.&lt;dimensionId&gt;</code> column per active
              dimension, followed by <code>literalType</code>,{" "}
              <code>value</code> and <code>sourceRef</code>.
            </p>
            <p>
              The example demonstrates an amount, an explicit numeric zero and
              an explicit empty text value. Replace every sample axis and member
              ID with the exact IDs shown in Metadata Manager before staging.
            </p>
            <a
              href={EXAMPLE_IMPORT_CSV_URL}
              download="openepm-import-example.csv"
            >
              Download example CSV
            </a>
          </details>
        </div>
        <div className="data-load-form">
          <label>
            Target handling
            <select
              value={mode}
              onChange={(event) => {
                setMode(event.target.value);
                invalidateTarget();
              }}
            >
              <option value="merge">Merge supplied cells</option>
              <option value="replace">Replace exact selected scope</option>
            </select>
          </label>
          <label>
            Exact scope
            <input
              disabled={scopeAll}
              value={scopeText}
              placeholder="Scenario=Plan; Period=2027-01"
              onChange={(event) => {
                setScopeText(event.target.value);
                invalidateTarget();
              }}
            />
          </label>
          <label className="review-check">
            <input
              type="checkbox"
              checked={scopeAll}
              onChange={(event) => {
                setScopeAll(event.target.checked);
                invalidateTarget();
              }}
            />
            Whole application scope
          </label>
          {!scopeAll && scopeText && !scope && (
            <p className="inline-error" role="alert">
              Use Dimension=Member pairs separated by semicolons.
            </p>
          )}
          <label className="review-check">
            <input
              type="checkbox"
              checked={reviewedStage}
              disabled={!prepared || !scopeReady || !canStage}
              onChange={(event) => setReviewedStage(event.target.checked)}
            />
            I reviewed the exact input and target scope
          </label>
          <button disabled={busy || !stageReady} onClick={() => void stage()}>
            Stage and validate CSV
          </button>
        </div>
      </div>
      {state.batchId && (
        <div className="data-load-review">
          <div className="kpi-strip compact">
            <article>
              <span>Rows</span>
              <strong>{state.rowCount}</strong>
            </article>
            <article>
              <span>Sets</span>
              <strong>{state.setCount}</strong>
            </article>
            <article>
              <span>Clears</span>
              <strong>{state.clearCount}</strong>
            </article>
            <article>
              <span>Errors</span>
              <strong>{state.errorCount}</strong>
            </article>
            <article>
              <span>Warnings</span>
              <strong>{state.warningCount}</strong>
            </article>
          </div>
          <div className="reviewed-inline-action">
            <label className="review-check">
              <input
                type="checkbox"
                checked={allowWarnings}
                onChange={(event) => {
                  setAllowWarnings(event.target.checked);
                  setReviewedPublish(false);
                }}
              />
              Permit reviewed warnings
            </label>
            <button
              disabled={busy || !canPreview}
              onClick={() => void preview()}
            >
              Preview exact changes
            </button>
            <label className="review-check">
              <input
                type="checkbox"
                checked={reviewedPublish}
                disabled={
                  !state.previewToken ||
                  Boolean(state.errorCount) ||
                  Boolean(state.warningCount && !allowWarnings)
                }
                onChange={(event) => setReviewedPublish(event.target.checked)}
              />
              I reviewed the exact set and clear counts
            </label>
            <button
              disabled={busy || !publishReady}
              onClick={() => void publish()}
            >
              Start durable publication
            </button>
          </div>
          <dl className="receipt-facts">
            <dt>Batch</dt>
            <dd>
              <code>{state.batchId}</code>
            </dd>
            {state.requestId && (
              <>
                <dt>Import request</dt>
                <dd>
                  <code>{state.requestId}</code>
                </dd>
                <dt>Durable status</dt>
                <dd>
                  {state.status || "Accepted"}{" "}
                  <button
                    disabled={busy || !canRead}
                    onClick={() => void readStatus()}
                  >
                    Refresh
                  </button>
                </dd>
                {state.committedRevision !== null && (
                  <>
                    <dt>Committed revision</dt>
                    <dd>{state.committedRevision}</dd>
                    <dt>Publication receipt</dt>
                    <dd>
                      <button onClick={() => setInspectReceipt(true)}>
                        Inspect exact receipt
                      </button>
                    </dd>
                  </>
                )}
              </>
            )}
          </dl>
          {state.artifactId && (
            <button
              disabled={busy || !canReadDiagnostics}
              onClick={() => void readDiagnostics()}
            >
              Read validation diagnostics
            </button>
          )}
        </div>
      )}
      {diagnostics.length > 0 && (
        <div className="react-grid-scroll">
          <table className="react-cube-grid">
            <caption>CSV validation diagnostics</caption>
            <thead>
              <tr>
                <th scope="col">Severity</th>
                <th scope="col">Code</th>
                <th scope="col">Row</th>
                <th scope="col">Field</th>
                <th scope="col">Coordinate</th>
                <th scope="col">Message</th>
              </tr>
            </thead>
            <tbody>
              {diagnostics.map((item, index) => (
                <tr key={`${item.code}-${index}`}>
                  <td>{item.severity}</td>
                  <td>{item.code}</td>
                  <td>{item.rowIndex ?? "—"}</td>
                  <td>{item.field || "—"}</td>
                  <td>
                    {item.coordinate ? JSON.stringify(item.coordinate) : "—"}
                  </td>
                  <td>{item.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {inspectReceipt && app && state.receiptId && (
        <ReceiptInspector
          scope={{
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
          }}
          catalog={catalog}
          operationId={state.receiptId}
          close={() => setInspectReceipt(false)}
        />
      )}
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      <p className="authority-note">
        The browser only assembles the reviewed request. The fixed core
        validates, stages and publishes it through the unchanged governed
        contracts.
      </p>
    </section>
  );
}
