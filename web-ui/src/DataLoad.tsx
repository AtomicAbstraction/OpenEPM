import { useEffect, useId, useMemo, useRef, useState } from "react";
import {
  ApiError,
  prepareAdmittedProgramEffect,
  replayAdmittedEffect,
  type AdmittedEffectPacket,
  readCatalog,
  readProgram,
  request,
} from "./api";
import {
  activeFactDimensions,
  collectCapabilityDimensions,
  type MetadataDimension,
} from "./metadata-data";
import { ReceiptInspector } from "./ReceiptInspector";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { usePreservedDraft } from "./unsaved-work";
import { ExactScopeSelector, serializedExactScope } from "./ExactScopeSelector";
import { transferAction } from "./data-transfer-action";
import {
  ImportChangeReview,
  validateImportReview,
  type ImportReview,
} from "./ImportChangeReview";
import "./data-workspaces.css";

type PreparedInput = {
  text: string;
  bytes: number;
  digest: string;
  name: string;
  emptyReplacementDimensions?: string[];
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

type StagingAttempt = {
  identity: string;
  context: string;
  inputDigest: string;
  mode: string;
  scopeMembers: Record<string, string>;
  scopeAll: boolean;
  metadataRevision: number;
  dataRevision: number;
  step: "begin" | "append" | "seal" | "manifest" | "ready";
  nextChunk: number;
  acknowledgedChunkRows?: number[];
  // Older drafts used raw UTF-8 sizes. Their admitted chunk boundaries still apply.
  chunkEncoding?: "json";
  batch: BatchProgress | null;
  packet: AdmittedEffectPacket | null;
  // Undefined on older restored records means the packet may already have run.
  packetDispatched?: boolean;
  inputRejection?: {
    code: string;
    packet: AdmittedEffectPacket;
    correctionText: string;
  };
};

type ImportState = {
  staging: StagingAttempt | null;
  review: ImportReview | null;
  publicationUncertain: boolean;
  publicationPacket: AdmittedEffectPacket | null;
  reviewContext: string;
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
  retryPending: boolean;
  committedRevision: number | null;
  receiptId: string;
};

type ImportIntentKeys = {
  begin: string;
  append?: string;
  manifest: string;
  publish: string;
};

const importActivityMessages = {
  stage: "Staging CSV…",
  reconcileStage: "Checking the original staging step…",
  correct: "Reviewing corrected CSV…",
  preview: "Checking exact import changes…",
  publish: "Submitting publication request…",
  reconcilePublication: "Checking the original publication…",
  status: "Checking publication status…",
  diagnostics: "Reading validation diagnostics…",
};
type StagingControl = "reconcile" | "continue" | "correct";

export function newImportIntentKeys(): ImportIntentKeys {
  return {
    begin: `source-load-ui-${crypto.randomUUID()}`,
    manifest: `source-manifest-ui-${crypto.randomUUID()}`,
    publish: `source-import-ui-${crypto.randomUUID()}`,
  };
}

const EMPTY_STATE: ImportState = {
  staging: null,
  review: null,
  publicationUncertain: false,
  publicationPacket: null,
  reviewContext: "",
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
  retryPending: false,
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

function compareUnicodeCodePoints(left: string, right: string): number {
  // Native export identities use Python's Unicode code-point key ordering.
  // Locale collation and JavaScript's UTF-16 ordering both produce different
  // hashed bytes for valid dimension IDs; neither may define a checksum.
  const a = Array.from(left, (character) => character.codePointAt(0)!);
  const b = Array.from(right, (character) => character.codePointAt(0)!);
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return a.length - b.length;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => compareUnicodeCodePoints(left, right))
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
type CsvChunkEncoding = "raw" | "json";
const BATCH_ID = /^[0-9a-f]{32}$/;
const CONTENT_DIGEST = /^[0-9a-f]{64}$/;

function exampleImportCsv(dimensions: string[], numericOnly: boolean): string {
  const header = [
    ...dimensions.map((dimension) => `axis.${dimension}`),
    "literalType",
    "value",
    "sourceRef",
  ]
    .map(encodeCsvCell)
    .join(",");
  const examples = [
    ["AmountLiteral", "100.00000000", "example-amount"],
    ["AmountLiteral", "0.00000000", "example-zero"],
    ...(numericOnly ? [] : [["TextLiteral", "", "example-empty-text"]]),
  ];
  return [
    header,
    ...examples.map(([kind, value, source], index) =>
      [
        ...dimensions.map(() => `ExampleMember${index + 1}`),
        kind,
        value,
        source,
      ]
        .map((cell) => (cell === "" ? '\"\"' : encodeCsvCell(cell)))
        .join(","),
    ),
  ].join("\n");
}

function encodeCsvCell(value: string) {
  return /[",\r\n]/.test(value) ? `"${value.replaceAll('"', '""')}"` : value;
}

function encodeCsvRecord(record: string[]): string {
  return record.map(encodeCsvCell).join(",");
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
  return planCsvChunks(header, rows, "json");
}

function planCsvChunks(
  header: string[],
  rows: string[][],
  encoding: CsvChunkEncoding,
): string[] {
  const encoder = new TextEncoder();
  const lineBytes = (line: string) =>
    encoding === "raw"
      ? encoder.encode(line).length
      : encoder.encode(JSON.stringify(line)).length - 2;
  const separatorBytes = encoding === "raw" ? 1 : 2;
  const headerLine = encodeCsvRecord(header);
  // Leave room for the program and its recovery reference outside the CSV string.
  const headerBytes = lineBytes(headerLine);
  const chunks: string[] = [];
  let current: string[] = [];
  let currentBytes = headerBytes;
  for (const row of rows) {
    const encoded = encodeCsvRecord(row);
    const rowBytes = separatorBytes + lineBytes(encoded);
    if (headerBytes + rowBytes > MAX_CSV_CHUNK_BYTES)
      throw new Error(
        "A single CSV record is too large for the bounded upload envelope.",
      );
    if (
      current.length &&
      (current.length >= MAX_CSV_ROWS_PER_CHUNK ||
        currentBytes + rowBytes > MAX_CSV_CHUNK_BYTES)
    ) {
      chunks.push([headerLine, ...current].join("\n"));
      current = [];
      currentBytes = headerBytes;
    }
    current.push(encoded);
    currentBytes += rowBytes;
  }
  if (current.length) chunks.push([headerLine, ...current].join("\n"));
  return chunks;
}

/** Retain the acknowledged prefix exactly; only unsubmitted rows may change. */
export function correctedCsvRemainder(
  original: string,
  nextChunk: number,
  correction: string,
  acknowledgedChunkRows?: number[],
  encoding: CsvChunkEncoding = "json",
): { text: string; acknowledgedChunkRows: number[] } {
  const chunks = stagingCsvChunks(original, acknowledgedChunkRows, encoding);
  if (
    !Number.isSafeInteger(nextChunk) ||
    nextChunk < 0 ||
    nextChunk >= chunks.length ||
    (acknowledgedChunkRows !== undefined &&
      acknowledgedChunkRows.length !== nextChunk)
  )
    throw new Error("The original CSV correction boundary is unavailable.");
  const [header, ...originalRows] = parseCsvRecords(original);
  const [correctedHeader, ...remaining] = parseCsvRecords(correction);
  if (nextChunk > 0 && canonicalJson(header) !== canonicalJson(correctedHeader))
    throw new Error("Keep the original CSV header and coordinate columns.");
  const prefix = chunks
    .slice(0, nextChunk)
    .flatMap((chunk) => parseCsvRecords(chunk).slice(1));
  const text = [
    nextChunk === 0 ? correctedHeader : header,
    ...prefix,
    ...remaining,
  ]
    .map(encodeCsvRecord)
    .join("\n");
  if (prefix.length + remaining.length > 100_000)
    throw new Error("Corrected CSV exceeds the 100,000-row import limit.");
  if (new TextEncoder().encode(text).length > 8_000_000)
    throw new Error("Corrected UTF-8 CSV content is limited to 8 MB.");
  const boundaries = chunks.slice(0, nextChunk).map(csvRowCount);
  const revised = stagingCsvChunks(text, boundaries);
  if (
    chunks.slice(0, nextChunk).some((chunk, index) => revised[index] !== chunk)
  )
    throw new Error("Correction must preserve every acknowledged CSV chunk.");
  if (text === [header, ...originalRows].map(encodeCsvRecord).join("\n"))
    throw new Error(
      "Correct the rejected input before reviewing a new request.",
    );
  return { text, acknowledgedChunkRows: boundaries };
}

export function stagingCsvChunks(
  text: string,
  acknowledgedChunkRows: number[] = [],
  encoding: CsvChunkEncoding = "json",
): string[] {
  const [header, ...rows] = parseCsvRecords(text);
  let offset = 0;
  const chunks: string[] = [];
  for (const count of acknowledgedChunkRows) {
    if (
      !Number.isSafeInteger(count) ||
      count < 1 ||
      count > MAX_CSV_ROWS_PER_CHUNK ||
      offset + count > rows.length
    )
      throw new Error("The acknowledged CSV chunk boundaries are unavailable.");
    const chunk = [header, ...rows.slice(offset, offset + count)]
      .map(encodeCsvRecord)
      .join("\n");
    if (new TextEncoder().encode(chunk).length > MAX_CSV_CHUNK_BYTES)
      throw new Error(
        "An acknowledged CSV chunk exceeds the original upload bound.",
      );
    chunks.push(chunk);
    offset += count;
  }
  if (offset < rows.length)
    chunks.push(...planCsvChunks(header, rows.slice(offset), encoding));
  return chunks;
}

function csvRemainder(chunks: string[], nextChunk: number): string {
  const remaining = chunks
    .slice(nextChunk)
    .flatMap((chunk, index) => parseCsvRecords(chunk).slice(index ? 1 : 0));
  return remaining.map(encodeCsvRecord).join("\n");
}

function csvInputRejected(
  reason: unknown,
  operation: unknown,
): reason is ApiError {
  if (
    !(reason instanceof ApiError) ||
    reason.status !== 400 ||
    !object(operation)
  )
    return false;
  const declaration = operation.inputRejections;
  return (
    object(declaration) &&
    Object.keys(declaration).sort().join(",") ===
      "changedInput,codes,firstDispatchOnly,format,httpStatus,phase,priorUncertainty" &&
    declaration.format === "openepm-csv-input-rejections-v1" &&
    declaration.phase === "before_chunk_write" &&
    declaration.httpStatus === 400 &&
    declaration.firstDispatchOnly === true &&
    declaration.priorUncertainty === "retain_original" &&
    declaration.changedInput === "new_admission" &&
    Array.isArray(declaration.codes) &&
    declaration.codes.length > 0 &&
    declaration.codes.length <= 32 &&
    declaration.codes.every(
      (code) =>
        typeof code === "string" && /^[A-Z][A-Z0-9_]{2,127}$/.test(code),
    ) &&
    new Set(declaration.codes).size === declaration.codes.length &&
    declaration.codes.includes(reason.code)
  );
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
  review: ImportReview;
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
  staged: StagingAttempt & { batch: BatchProgress },
  factDimensions: readonly string[],
): ImportPreview {
  if (
    !object(value) ||
    value.batchId !== staged.batch.batchId ||
    value.contentDigest !== staged.batch.contentDigest ||
    (value.mode !== undefined && value.mode !== staged.mode) ||
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
  if (value.setCount !== staged.batch.rowCount)
    throw new Error(
      "The preview set count does not match the sealed row count.",
    );
  const review = validateImportReview(
    value.review,
    staged.mode,
    { setCount: Number(value.setCount), clearCount: Number(value.clearCount) },
    factDimensions,
  );
  if (
    review.scopeAll !== staged.scopeAll ||
    canonicalJson(review.scopeMembers) !== canonicalJson(staged.scopeMembers) ||
    review.periodSelection !== null
  )
    throw new Error("SOURCE_PREVIEW_SCOPE_MISMATCH");
  // The core may preview a replacement at a newer data revision after
  // proving the replacement scope has not changed.
  if (
    review.metadataRevision !== staged.metadataRevision ||
    review.dataRevision < staged.dataRevision ||
    (staged.mode === "merge" && review.dataRevision !== staged.dataRevision)
  )
    throw new Error("The preview revisions do not match the sealed import.");
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

type CompletionIdentity = {
  batchId: string;
  contentDigest: string;
  mode: string;
  setCount: number;
  clearCount: number;
  committedRevision?: number | null;
};

function exactImportReceipt(result: unknown, expected: CompletionIdentity) {
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
      result.committedRevision !== expected.committedRevision)
  )
    throw new Error("INVALID_IMPORT_COMPLETION_RESPONSE");
  return result;
}

export function exactImportExecution(
  value: unknown,
  expected: CompletionIdentity & {
    requestId?: string;
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
  const retryPending =
    value.status === "Accepted" &&
    typeof value.errorCode === "string" &&
    value.errorCode.length > 0 &&
    value.errorCode.length <= 200;
  if (
    !terminal &&
    (value.result !== null || (!retryPending && value.errorCode !== null))
  )
    throw new Error("INVALID_IMPORT_EXECUTION_RESPONSE");

  if (value.status === "Completed") {
    exactImportReceipt(value.result, expected);
    if (value.errorCode !== null)
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
  const grouped =
    catalog?.applicationAccess.authorizationModel === "group_assignments";
  const [csv, setCsv] = useState("");
  const [prepared, setPrepared] = useState<PreparedInput | null>(null);
  const [selectedMode, setMode] = useState("merge");
  const [selectedScopeText, setScopeText] = useState("");
  const [selectedScopeAll, setScopeAll] = useState(false);
  const [selectedWarnings, setAllowWarnings] = useState(false);
  const mode = grouped ? "merge" : selectedMode;
  const scopeText = grouped ? "" : selectedScopeText;
  const scopeAll = grouped || selectedScopeAll;
  const allowWarnings = !grouped && selectedWarnings;
  const [reviewedStage, setReviewedStage] = useState(false);
  const [reviewedPublish, setReviewedPublish] = useState(false);
  const [state, setState] = useState(EMPTY_STATE);
  const [diagnostics, setDiagnostics] = useState<Diagnostic[]>([]);
  const [intentKeys, setIntentKeys] = useState(newImportIntentKeys);
  const [activity, setActivity] = useState<
    keyof typeof importActivityMessages | null
  >(null);
  const busy = activity !== null;
  const [focusedStagingControl, setFocusedStagingControl] =
    useState<StagingControl | null>(null);
  const rejectionDescriptionId = useId();
  const stageRunning = useRef(false);
  const [error, setError] = useState("");
  const [inspectReceipt, setInspectReceipt] = useState(false);
  const [missingStage, setMissingStage] = useState<string | null>(null);
  const [missingPublication, setMissingPublication] = useState<string | null>(
    null,
  );
  const identity = JSON.stringify([
    app?.workspaceId,
    app?.applicationId,
    catalog?.applicationAccess.issuer,
    catalog?.applicationAccess.subjectId,
    ...(grouped ? ["numeric_merge"] : []),
  ]);
  const appendOperation = catalog?.functions["facts.source.csv.append"];
  const context = JSON.stringify([
    identity,
    catalog?.accessContext,
    catalog?.applicationAccess,
    catalog?.revisions,
    Object.keys(catalog?.functions || {}).sort(),
    object(appendOperation) ? appendOperation.inputRejections : null,
  ]);
  const live = useRef({ identity, context, generation: 0, mounted: true });
  if (live.current.context !== context) live.current.generation += 1;
  live.current.identity = identity;
  live.current.context = context;
  useEffect(() => {
    live.current.mounted = true;
    return () => {
      live.current.mounted = false;
      live.current.generation += 1;
    };
  }, []);
  const priorIdentity = useRef(identity);
  useEffect(() => {
    if (priorIdentity.current !== identity) {
      priorIdentity.current = identity;
      setCsv("");
      setPrepared(null);
      setMode("merge");
      setScopeText("");
      setScopeAll(false);
      setAllowWarnings(false);
      setInspectReceipt(false);
      setFocusedStagingControl(null);
      setState(EMPTY_STATE);
      setIntentKeys(newImportIntentKeys());
      setReviewedStage(false);
    } else {
      setState((current) =>
        current.reviewContext && current.reviewContext !== context
          ? {
              ...current,
              review: null,
              reviewContext: "",
              previewToken: current.publicationUncertain
                ? current.previewToken
                : "",
            }
          : current,
      );
    }
    setReviewedPublish(false);
    setDiagnostics([]);
    setError("");
    setActivity(null);
    setMissingPublication(null);
    setMissingStage(null);
  }, [context, identity]);
  function ticket() {
    const generation = ++live.current.generation;
    return () =>
      live.current.mounted &&
      live.current.context === context &&
      live.current.generation === generation;
  }
  function stagingAction(
    control: StagingControl,
    blocked: boolean,
    run: () => Promise<void>,
  ) {
    return {
      ...transferAction(blocked, run),
      onFocus: () => setFocusedStagingControl(control),
      onBlur: () => setFocusedStagingControl(null),
    };
  }
  const reviewCurrent = state.reviewContext === context;
  const showReview = reviewCurrent && state.review !== null;
  const showCounts =
    showReview ||
    (!grouped && (state.publicationUncertain || !!state.requestId)) ||
    (reviewCurrent && !!state.receiptId);

  const sourceGrain = useMemo(() => {
    if (!prepared) return null;
    if (prepared.emptyReplacementDimensions)
      return { dimensions: prepared.emptyReplacementDimensions, types: [] };
    const [header, ...rows] = parseCsvRecords(prepared.text);
    const typeColumn = header.indexOf("literalType");
    const types = new Map<string, number>();
    for (const row of rows) {
      const kind = row[typeColumn] || "Missing type";
      types.set(kind, (types.get(kind) || 0) + 1);
    }
    return {
      dimensions: header
        .filter((name) => name.startsWith("axis."))
        .map((name) => name.slice(5)),
      types: [...types.entries()],
    };
  }, [prepared]);

  const [example, setExample] = useState<{
    context: string;
    csv?: string;
    error?: string;
  } | null>(null);
  const [scopeDimensions, setScopeDimensions] = useState<MetadataDimension[]>(
    [],
  );
  const [scopeMetadataRevision, setScopeMetadataRevision] = useState<
    number | null
  >(null);
  const canReadDimensions = Boolean(
    catalog?.functions["metadata.dimension.list"],
  );
  const exampleContext = JSON.stringify([
    app?.workspaceId,
    app?.applicationId,
    catalog?.accessContext,
    catalog?.applicationAccess.issuer,
    catalog?.applicationAccess.subjectId,
    catalog?.revisions.metadata,
    catalog?.revisions.security,
    canReadDimensions,
    grouped,
  ]);
  useEffect(() => {
    setScopeDimensions([]);
    setScopeMetadataRevision(null);
    if (!app || !canReadDimensions) return;
    const controller = new AbortController();
    const context = exampleContext;
    void collectCapabilityDimensions((arguments_) =>
      readProgram(
        app,
        "metadata.dimension.list",
        arguments_,
        controller.signal,
      ),
    )
      .then(({ rows, finalPage }) => {
        if (controller.signal.aborted) return;
        const active = activeFactDimensions(rows);
        setScopeDimensions(active);
        setScopeMetadataRevision(finalPage.metadataRevision);
        const dimensions = active.map((row) => row.dimension_id);
        if (!dimensions.length)
          throw new Error("No active fact dimensions are available.");
        setExample({ context, csv: exampleImportCsv(dimensions, grouped) });
      })
      .catch((reason: unknown) => {
        if (controller.signal.aborted) return;
        setScopeDimensions([]);
        setScopeMetadataRevision(null);
        setExample({
          context,
          error:
            reason instanceof Error
              ? reason.message
              : "Unable to read the current dimensions.",
        });
      });
    return () => controller.abort();
  }, [
    exampleContext,
    app?.workspaceId,
    app?.applicationId,
    canReadDimensions,
    grouped,
  ]);
  const currentExample = example?.context === exampleContext ? example : null;

  const functions = catalog?.functions || {};
  const beginSpec = functions["facts.source.begin"];
  const numericProfile =
    object(beginSpec) && beginSpec.sourceImportProfile === "numeric_merge";
  const supportedInput =
    !grouped || sourceGrain?.types.every(([kind]) => kind === "AmountLiteral");
  const emptyReplacementDimensions = prepared?.emptyReplacementDimensions;
  const emptyReplacement = Boolean(emptyReplacementDimensions);
  const canStage =
    ["facts.source.begin", "facts.source.seal"].every((name) =>
      Object.hasOwn(functions, name),
    ) &&
    (emptyReplacement ||
      (Object.hasOwn(functions, "facts.source.csv.append") &&
        (grouped
          ? numericProfile
          : Object.hasOwn(functions, "facts.source.manifest.attach"))));
  const canPreview = Object.hasOwn(functions, "facts.source.preview");
  const canPublish = Object.hasOwn(
    functions,
    grouped ? "facts.source.publish" : "facts.transfer.import.request",
  );
  const canRead = Object.hasOwn(functions, "facts.transfer.import.read");
  const canCheckStage = Object.hasOwn(functions, "facts.source.staging.read");
  const stagingRead = functions["facts.source.staging.read"];
  const canRecoverOriginal =
    grouped &&
    state.publicationUncertain &&
    object(stagingRead) &&
    stagingRead.publicationRecovery === "facts.source.publish";
  const stagingPacket = state.staging?.packet;
  const stagingMayHaveRun = Boolean(
    stagingPacket && state.staging?.packetDispatched !== false,
  );
  const canRetryStage =
    stagingMayHaveRun &&
    canCheckStage &&
    missingStage === stagingPacket?.body.idempotencyKey;
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
  const exactReplacementReady = Boolean(
    mode === "replace" &&
      !scopeAll &&
      currentExample?.csv &&
      scopeMetadataRevision === catalog?.revisions.metadata &&
      scope &&
      Object.keys(scope).length === scopeDimensions.length &&
      scopeDimensions.every(({ dimension_id }) =>
        Object.hasOwn(scope, dimension_id),
      ),
  );
  const scopeReady = emptyReplacementDimensions
    ? exactReplacementReady &&
      scope &&
      emptyReplacementDimensions.length === scopeDimensions.length &&
      emptyReplacementDimensions.every((dimension) =>
        Object.hasOwn(scope, dimension),
      )
    : scopeAll || Boolean(scope && Object.keys(scope).length);
  const terminalPublication = ["Completed", "Failed", "Cancelled"].includes(
    state.status,
  );
  const unresolvedPublication =
    state.publicationUncertain ||
    Boolean(state.requestId && !terminalPublication);
  const retainedStaging = Boolean(
    state.staging && !state.requestId && !state.receiptId,
  );
  const inputLocked = busy || unresolvedPublication || retainedStaging;
  const stageReady = Boolean(
    app &&
      prepared &&
      supportedInput &&
      scopeReady &&
      canStage &&
      reviewedStage &&
      !state.staging,
  );
  const publishReady = Boolean(
    (canPublish || canRecoverOriginal) &&
      !state.requestId &&
      !state.receiptId &&
      state.batchId &&
      (state.publicationUncertain
        ? grouped
          ? !!state.publicationPacket
          : missingPublication &&
            missingPublication === state.publicationPacket?.body.idempotencyKey
        : reviewCurrent &&
          state.previewToken &&
          state.review &&
          !state.errorCount &&
          (!state.warningCount || allowWarnings) &&
          reviewedPublish),
  );
  const hasUnpublishedInput = Boolean(
    !state.requestId &&
      !state.receiptId &&
      (csv ||
        prepared ||
        mode !== "merge" ||
        scopeText ||
        (selectedScopeAll && !grouped) ||
        allowWarnings ||
        reviewedStage ||
        reviewedPublish ||
        state.batchId ||
        state.previewToken),
  );
  const draftValue = {
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
    identity,
  };
  const recovery = usePreservedDraft(
    app?.workspaceId || "none",
    app?.applicationId || "none",
    "data-load-publication",
    "Unpublished data load",
    hasUnpublishedInput || unresolvedPublication,
    draftValue,
    (draft) => {
      if (draft.identity !== identity) return;
      live.current.generation += 1;
      setCsv(draft.csv);
      setPrepared(draft.prepared);
      setMode(draft.mode);
      setScopeText(draft.scopeText);
      setScopeAll(draft.scopeAll);
      setAllowWarnings(draft.allowWarnings);
      setReviewedStage(draft.reviewedStage);
      // The server preview may expire while away even if cached revisions
      // are unchanged. Restore input, never an unsubmitted approval.
      setReviewedPublish(false);
      setState({
        ...draft.state,
        review: null,
        reviewContext: "",
        previewToken: draft.state.publicationUncertain
          ? draft.state.previewToken
          : "",
      });
      setDiagnostics([]);
      setIntentKeys(draft.intentKeys);
    },
  );

  function resetAfterDraftChange() {
    if (unresolvedPublication || retainedStaging) return;
    live.current.generation += 1;
    setIntentKeys(newImportIntentKeys());
    setPrepared(null);
    setReviewedStage(false);
    setReviewedPublish(false);
    setState(EMPTY_STATE);
    setDiagnostics([]);
  }

  function invalidateTarget() {
    if (unresolvedPublication || retainedStaging) return;
    live.current.generation += 1;
    if (emptyReplacement) setPrepared(null);
    setIntentKeys(newImportIntentKeys());
    setReviewedStage(false);
    setReviewedPublish(false);
    setState(EMPTY_STATE);
    setDiagnostics([]);
  }

  async function prepareEmptyReplacement() {
    if (inputLocked || !exactReplacementReady || !scope) return;
    resetAfterDraftChange();
    setCsv("");
    setError("");
    const current = ticket();
    const dimensions = scopeDimensions.map(({ dimension_id }) => dimension_id);
    try {
      const digest = await sha256(canonicalJson({ emptyReplacement: scope }));
      if (current())
        setPrepared({
          text: "",
          bytes: 0,
          digest,
          name: "Empty replacement",
          emptyReplacementDimensions: dimensions,
        });
    } catch (reason) {
      if (current())
        setError(
          reason instanceof Error
            ? reason.message
            : "Unable to prepare the empty replacement.",
        );
    }
  }

  async function prepare() {
    if (retainedStaging || unresolvedPublication) return;
    const current = ticket();
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
    try {
      const digest = await sha256(csv);
      if (!current()) return;
      setPrepared({ text: csv, bytes, digest, name: "pasted.csv" });
      setReviewedStage(false);
    } catch (reason) {
      if (current())
        setError(
          reason instanceof Error ? reason.message : "Unable to prepare CSV",
        );
    }
  }

  async function prepareFile(file?: File) {
    if (!file || retainedStaging || unresolvedPublication) return;
    resetAfterDraftChange();
    const current = ticket();
    setError("");
    try {
      const isBundle =
        file.name.toLowerCase().endsWith(".json") ||
        file.type === "application/json";
      if (grouped && isBundle)
        return setError("Choose a CSV containing numeric amounts.");
      const limit = isBundle ? 128 * 1024 * 1024 : 8_000_000;
      if (file.size > limit)
        return setError(
          isBundle
            ? "Export bundles are limited to 128 MiB in the browser re-import journey."
            : "CSV files are limited to 8 MB.",
        );
      const original = await file.text();
      if (!current()) return;
      if (new TextEncoder().encode(original).length > limit)
        return setError("The UTF-8 source exceeds the browser import limit.");
      let text = original;
      let sourceBundle: PreparedInput["sourceBundle"];
      if (isBundle) {
        try {
          const converted = await exportBundleToCsv(original);
          if (!current()) return;
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
          if (!current()) return;
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
      const digest = await sha256(text);
      if (!current()) return;
      setCsv("");
      setPrepared({
        text,
        bytes,
        digest,
        name:
          file.name.replace(/[\u0000-\u001f\u007f]/g, "_").slice(0, 1000) ||
          "upload.csv",
        sourceBundle,
      });
    } catch (reason) {
      if (current())
        setError(
          reason instanceof Error
            ? reason.message
            : "Unable to read source file",
        );
    }
  }

  async function stage(action: "continue" | "inspect" = "continue") {
    if (
      !app ||
      !prepared ||
      !scope ||
      busy ||
      stageRunning.current ||
      unresolvedPublication
    )
      return;
    const original = state.staging;
    if (
      original
        ? original.identity !== identity ||
          original.inputDigest !== prepared.digest ||
          Boolean(original.inputRejection) ||
          original.step === "ready"
        : !stageReady || action === "inspect"
    )
      return;
    if (
      action === "continue" &&
      original &&
      (original.context !== context ||
        !canStage ||
        (stagingMayHaveRun && !canRetryStage))
    )
      return;
    if (action === "inspect" && (!canCheckStage || !original?.packet)) return;
    const isCurrent = ticket();
    const sameIdentity = () =>
      live.current.mounted && live.current.identity === identity;
    stageRunning.current = true;
    setMissingStage(null);
    setActivity(action === "inspect" ? "reconcileStage" : "stage");
    setError("");
    let lease = recovery.lease;
    let work = original ? structuredClone(original) : null;
    const baseState = {
      ...state,
      review: null,
      reviewContext: "",
      previewToken: "",
    };
    const persist = () => {
      if (!work) throw new Error("Original staging context is unavailable.");
      const next: ImportState = {
        ...baseState,
        staging: structuredClone(work),
      };
      if (work.step === "ready" && work.batch) {
        next.batchId = work.batch.batchId;
        next.contentDigest = work.batch.contentDigest;
        next.rowCount = work.batch.rowCount;
      }
      lease = recovery.retain(
        {
          ...draftValue,
          state: next,
          reviewedStage: false,
          reviewedPublish: false,
        },
        lease,
      );
      if (sameIdentity()) {
        setState(next);
        setReviewedStage(false);
        setReviewedPublish(false);
      }
    };
    try {
      if (original && !lease)
        throw new Error(
          "Original staging recovery is unavailable. No request was sent.",
        );
      if (!work) {
        const current = await readCatalog({
          workspaceId: app.workspaceId,
          applicationId: app.applicationId,
        });
        if (!isCurrent()) return;
        const activeBegin = current.functions?.["facts.source.begin"];
        if (
          (current.applicationAccess?.authorizationModel ===
            "group_assignments") !==
            grouped ||
          (grouped &&
            (!object(activeBegin) ||
              activeBegin.sourceImportProfile !== "numeric_merge"))
        )
          throw new Error(
            "Import access changed. Refresh the application before staging.",
          );
        if (
          ![current.revisions.metadata, current.revisions.data].every(
            (value) => Number.isSafeInteger(value) && value >= 0,
          )
        )
          throw new Error("Current import revisions are unavailable.");
        if (
          emptyReplacement &&
          current.revisions.metadata !== scopeMetadataRevision
        )
          throw new Error(
            "The target dimensions changed. Refresh the application and choose the exact cell again.",
          );
        work = {
          identity,
          context,
          inputDigest: prepared.digest,
          mode,
          scopeMembers: scopeAll ? {} : { ...scope },
          scopeAll,
          metadataRevision: current.revisions.metadata,
          dataRevision: current.revisions.data,
          step: "begin",
          nextChunk: 0,
          acknowledgedChunkRows: [],
          chunkEncoding: "json",
          batch: null,
          packet: null,
        };
        persist(); // Reserve the reviewed input and original revisions before admission.
      }
      const chunks = emptyReplacement
        ? []
        : stagingCsvChunks(
            prepared.text,
            work.acknowledgedChunkRows,
            work.chunkEncoding ?? "raw",
          );
      let cumulativeRows = 0;
      const expectedRowsByChunk = chunks.map((chunk) => {
        cumulativeRows += csvRowCount(chunk);
        return cumulativeRows;
      });
      const schemaVersion = prepared.sourceBundle
        ? "openepm.export-bundle-reimport.v1"
        : "openepm.typed-csv.v1";
      while (work.step !== "ready") {
        if (!isCurrent()) return;
        let firstDispatch = false;
        if (!work.packet) {
          if (
            action === "inspect" ||
            work.context !== live.current.context ||
            !canStage
          )
            return;
          let fn: string;
          let args: Record<string, unknown>;
          if (work.step === "begin") {
            fn = "facts.source.begin";
            args = {
              idempotencyKey: intentKeys.begin,
              mode: work.mode,
              scopeMembers: work.scopeMembers,
              scopeAll: work.scopeAll,
              expectedMetadataRevision: work.metadataRevision,
              expectedDataRevision: work.dataRevision,
            };
          } else if (work.step === "append") {
            fn = "facts.source.csv.append";
            args = {
              batchId: work.batch!.batchId,
              chunkIndex: work.nextChunk,
              csvText: chunks[work.nextChunk],
            };
          } else if (work.step === "seal") {
            fn = "facts.source.seal";
            args = {
              batchId: work.batch!.batchId,
              expectedRows: work.batch!.rowCount,
              expectedContentDigest: work.batch!.contentDigest,
            };
          } else {
            fn = "facts.source.manifest.attach";
            args = {
              batchId: work.batch!.batchId,
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
              contentDigest: work.batch!.contentDigest,
            };
          }
          const packet = await prepareAdmittedProgramEffect(
            "/api/source-load",
            sourceProgramBody(app, fn, args, true),
            work.step === "manifest"
              ? intentKeys.manifest
              : work.step === "append"
                ? intentKeys.append || intentKeys.begin
                : intentKeys.begin,
          );
          if (!isCurrent() || work.context !== live.current.context) return;
          work.packet = packet;
          work.packetDispatched = false;
          persist(); // Failed capacity update leaves the previous acknowledged state intact.
          firstDispatch = true;
        }
        let response: { result: unknown };
        try {
          if (action === "inspect") {
            const originalPacket = work.packet;
            const checked = await request<{ result: unknown }>(
              "/api/source-load",
              sourceProgramBody(app, "facts.source.staging.read", {
                originalProgram: originalPacket.body.program,
                operationId: originalPacket.body.idempotencyKey,
              }),
            );
            if (!isCurrent()) return;
            if (
              !object(checked.result) ||
              checked.result.originalFunction !==
                originalPacket.body.program.function
            )
              throw new Error(
                "The staging status does not match the original step.",
              );
            response = { result: checked.result.outcome };
          } else {
            work.packetDispatched = true;
            persist(); // A remount must treat a dispatched packet as possibly accepted.
            response = await replayAdmittedEffect<{ result: unknown }>(
              work.packet,
            );
          }
        } catch (reason) {
          if (
            action === "inspect" &&
            isCurrent() &&
            reason instanceof ApiError &&
            reason.code === "SOURCE_STAGING_STATUS_UNAVAILABLE"
          ) {
            setMissingStage(work.packet!.body.idempotencyKey);
            setError(
              "The recorded staging step is unavailable. Its outcome remains unconfirmed.",
            );
            return;
          }
          // Only a fresh packet's first response in the same current authorized
          // catalogue may establish this narrow owner-declared pre-write refusal.
          if (
            firstDispatch &&
            isCurrent() &&
            work.step === "append" &&
            csvInputRejected(reason, functions["facts.source.csv.append"])
          ) {
            work.inputRejection = {
              code: reason.code,
              packet: work.packet,
              correctionText: csvRemainder(chunks, work.nextChunk),
            };
            work.packet = null;
            work.packetDispatched = false;
            persist();
          }
          throw reason;
        }
        // Acknowledged progress belongs to the captured owner even after navigation.
        // Retention rejects explicit identity/logout abandonment; no old actor is recreated.
        if (work.step === "manifest") {
          const manifest = response.result;
          if (
            !object(manifest) ||
            manifest.batchId !== work.batch!.batchId ||
            manifest.requestKey !== work.packet.body.idempotencyKey ||
            manifest.schemaVersion !== schemaVersion ||
            manifest.contentDigest !== work.batch!.contentDigest ||
            typeof manifest.manifestDigest !== "string" ||
            !CONTENT_DIGEST.test(manifest.manifestDigest)
          )
            throw new Error("INVALID_SOURCE_MANIFEST_RESPONSE");
          work.step = "ready";
        } else {
          const progress = exactBatchProgress(
            response.result,
            work.batch?.batchId,
            work.step === "append" ? work.nextChunk : undefined,
          );
          if (work.step === "begin") {
            if (progress.status !== "staging" || progress.rowCount !== 0)
              throw new Error("INVALID_SOURCE_BEGIN_RESPONSE");
            work.step = chunks.length ? "append" : "seal";
          } else if (work.step === "append") {
            if (progress.rowCount !== expectedRowsByChunk[work.nextChunk])
              throw new Error("INVALID_SOURCE_BATCH_PROGRESS");
            work.nextChunk += 1;
            work.acknowledgedChunkRows = chunks
              .slice(0, work.nextChunk)
              .map(csvRowCount);
            if (work.nextChunk === chunks.length) work.step = "seal";
          } else {
            if (
              progress.status !== "ready" ||
              progress.rowCount !== work.batch!.rowCount ||
              progress.contentDigest !== work.batch!.contentDigest
            )
              throw new Error("INVALID_SOURCE_SEAL_RESPONSE");
            work.step = grouped || emptyReplacement ? "ready" : "manifest";
          }
          work.batch = progress;
        }
        work.packet = null;
        work.packetDispatched = false;
        persist(); // If this fails, the stored exact packet remains the recovery witness.
        if (action === "inspect" || canRetryStage || !isCurrent()) return;
      }
    } catch (reason) {
      if (sameIdentity())
        setError(
          reason instanceof Error ? reason.message : "Unable to stage CSV",
        );
    } finally {
      stageRunning.current = false;
      if (sameIdentity()) setActivity(null);
    }
  }

  function editRejectedRemainder(text: string) {
    const work = state.staging;
    if (
      busy ||
      !work?.inputRejection ||
      work.packet ||
      work.identity !== identity ||
      work.context !== context ||
      !recovery.lease
    )
      return;
    try {
      const next = {
        ...state,
        staging: {
          ...work,
          inputRejection: {
            ...work.inputRejection,
            correctionText: text,
          },
        },
      };
      recovery.retain({ ...draftValue, state: next }, recovery.lease);
      live.current.generation += 1;
      setState(next);
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    }
  }

  async function reviewRejectedRemainder() {
    const work = state.staging;
    if (
      busy ||
      !prepared ||
      !canStage ||
      !work?.inputRejection ||
      work.packet ||
      work.identity !== identity ||
      work.context !== context ||
      !recovery.lease
    )
      return;
    const current = ticket();
    const lease = recovery.lease;
    setActivity("correct");
    setError("");
    try {
      if (work.nextChunk === 0 && work.batch?.rowCount !== 0)
        throw new Error(
          "The acknowledged CSV correction boundary is unavailable.",
        );
      const corrected = correctedCsvRemainder(
        prepared.text,
        work.nextChunk,
        work.inputRejection.correctionText,
        work.acknowledgedChunkRows,
        work.chunkEncoding ?? "raw",
      );
      const digest = await sha256(corrected.text);
      if (!current()) return;
      const nextPrepared: PreparedInput = {
        text: corrected.text,
        digest,
        bytes: new TextEncoder().encode(corrected.text).length,
        name: prepared.name,
      }; // Edited rows no longer claim the original export-bundle provenance.
      const { inputRejection: _rejected, ...accepted } = work;
      const next = {
        ...EMPTY_STATE,
        staging: {
          ...accepted,
          inputDigest: digest,
          acknowledgedChunkRows: corrected.acknowledgedChunkRows,
          chunkEncoding: "json" as const,
          packet: null,
          packetDispatched: false,
        },
      };
      const keys = {
        ...intentKeys,
        append: `source-correction-ui-${crypto.randomUUID()}`,
        manifest: `source-manifest-ui-${crypto.randomUUID()}`,
        publish: `source-import-ui-${crypto.randomUUID()}`,
      };
      recovery.retain(
        {
          ...draftValue,
          csv: "",
          prepared: nextPrepared,
          state: next,
          intentKeys: keys,
          reviewedStage: false,
          reviewedPublish: false,
          diagnostics: [],
        },
        lease,
      );
      setCsv("");
      setPrepared(nextPrepared);
      setState(next);
      setIntentKeys(keys);
      setReviewedStage(false);
      setReviewedPublish(false);
      setDiagnostics([]);
    } catch (reason) {
      if (current())
        setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      if (current()) setActivity(null);
    }
  }

  function leaveStagingUnpublished() {
    if (
      busy ||
      stageRunning.current ||
      !state.staging ||
      state.staging.packet ||
      unresolvedPublication ||
      state.requestId ||
      !recovery.lease
    )
      return;
    const nextKeys = newImportIntentKeys();
    try {
      recovery.release(
        recovery.lease,
        {
          ...draftValue,
          state: EMPTY_STATE,
          intentKeys: nextKeys,
          reviewedStage: false,
          reviewedPublish: false,
        },
        true,
      );
      setState(EMPTY_STATE);
      setIntentKeys(nextKeys);
      setReviewedStage(false);
      setReviewedPublish(false);
      setDiagnostics([]);
      setError("");
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    }
  }

  async function preview() {
    if (
      !app ||
      !state.batchId ||
      !canPreview ||
      unresolvedPublication ||
      state.receiptId ||
      busy
    )
      return;
    const isCurrent = ticket();
    setActivity("preview");
    setError("");
    setReviewedPublish(false);
    setDiagnostics([]);
    setState((current) => ({ ...current, previewToken: "", review: null }));
    try {
      const staged = state.staging;
      const batch = staged?.batch;
      if (
        staged?.step !== "ready" ||
        batch?.batchId !== state.batchId ||
        batch.contentDigest !== state.contentDigest ||
        staged.inputDigest !== prepared?.digest ||
        !sourceGrain?.dimensions.length
      )
        throw new Error(
          "The sealed import context could not be verified. Check the original staging before previewing.",
        );
      const response = await request<{ result: unknown }>(
        "/api/source-load",
        sourceProgramBody(app, "facts.source.preview", {
          batchId: batch.batchId,
          allowWarnings,
        }),
      );
      if (!isCurrent()) return;
      const result = exactImportPreview(
        response.result,
        { ...staged, batch },
        sourceGrain.dimensions,
      );
      if (emptyReplacement && result.clearCount > 1)
        throw new Error(
          "The replacement preview would clear more than the selected cell.",
        );
      setState((current) => ({
        ...current,
        review: result.review,
        reviewContext: context,
        previewToken: result.previewToken,
        setCount: result.setCount,
        clearCount: result.clearCount,
        artifactId: result.diagnostics?.artifactId || "",
        errorCount: result.diagnostics?.errorCount || 0,
        warningCount: result.diagnostics?.warningCount || 0,
      }));
      setReviewedPublish(false);
    } catch (reason) {
      if (!isCurrent()) return;
      setError(
        reason instanceof Error ? reason.message : "Unable to preview CSV",
      );
    } finally {
      if (isCurrent()) setActivity(null);
    }
  }

  async function publish(checkOriginal = false) {
    const original = state.publicationPacket;
    if (!app || busy || (checkOriginal ? !canRead || !original : !publishReady))
      return;
    const isCurrent = ticket();
    setActivity(checkOriginal ? "reconcilePublication" : "publish");
    setMissingPublication(null);
    setError("");
    const wasUncertain = state.publicationUncertain;
    let sent = false;
    let reserved = false;
    let lease = recovery.lease;
    try {
      const packet =
        original ||
        (await prepareAdmittedProgramEffect(
          grouped ? "/api/source-action" : "/api/source-load",
          sourceProgramBody(
            app,
            grouped ? "facts.source.publish" : "facts.transfer.import.request",
            {
              ...(grouped ? {} : { idempotencyKey: intentKeys.publish }),
              batchId: state.batchId,
              previewToken: state.previewToken,
            },
            true,
          ),
          intentKeys.publish,
        ));
      if (!isCurrent() || (!wasUncertain && live.current.context !== context))
        return;
      let response: { result: unknown };
      if (checkOriginal) {
        if (!lease)
          throw new Error("Original publication recovery is unavailable.");
        response = await request(
          "/api/source-load",
          sourceProgramBody(app, "facts.transfer.import.read", {
            operationId: packet.body.idempotencyKey,
          }),
        );
      } else {
        const pending = {
          ...state,
          publicationUncertain: true,
          publicationPacket: packet,
        };
        lease = recovery.retain({ ...draftValue, state: pending }, lease);
        reserved = true;
        setState(pending);
        sent = true;
        response = await replayAdmittedEffect(packet);
      }
      if (!isCurrent()) return;
      const expected = {
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
      };
      const execution = grouped
        ? null
        : exactImportExecution(response.result, expected);
      const completion = grouped
        ? exactImportReceipt(response.result, expected)
        : execution?.status === "Completed"
          ? execution.result
          : null;
      const next = {
        ...state,
        publicationUncertain: false,
        publicationPacket: null,
        previewToken: "",
        requestId: execution?.requestId ?? "",
        reviewContext: grouped ? context : state.reviewContext,
        status: execution?.status ?? "Completed",
        retryPending:
          execution?.status === "Accepted" && execution.errorCode !== null,
        committedRevision: completion
          ? Number(completion.committedRevision)
          : null,
        receiptId: completion ? state.batchId : "",
      };
      const nextDraft = { ...draftValue, state: next, reviewedPublish: false };
      if (["Completed", "Failed", "Cancelled"].includes(next.status))
        recovery.release(lease, nextDraft);
      else lease = recovery.retain(nextDraft, lease);
      setState(next);
      setReviewedPublish(false);
    } catch (reason) {
      if (!isCurrent()) return;
      if (
        checkOriginal &&
        reason instanceof ApiError &&
        reason.code === "IMPORT_EXECUTION_UNAVAILABLE"
      ) {
        setMissingPublication(original!.body.idempotencyKey);
        setError(
          "The recorded publication is unavailable. The outcome remains unconfirmed.",
        );
        return;
      }
      if (!reserved) {
        setError(
          reason instanceof Error
            ? reason.message
            : checkOriginal
              ? "Unable to check the original publication."
              : "Unable to reserve publication recovery.",
        );
        return; // Failed CAS/capacity admission leaves the prior record untouched.
      }
      // A previously unknown attempt stays unknown even if current authority
      // is now denied. Retain its exact preview and request identity.
      if (
        !wasUncertain &&
        (!sent ||
          (reason instanceof ApiError &&
            [400, 401, 403, 409, 412, 422].includes(reason.status)))
      ) {
        const next = {
          ...state,
          publicationUncertain: false,
          publicationPacket: null,
          previewToken: "",
          review: null,
        };
        if (lease) {
          const nextDraft = {
            ...draftValue,
            state: next,
            reviewedPublish: false,
          };
          try {
            if (state.staging) lease = recovery.retain(nextDraft, lease);
            else recovery.release(lease, nextDraft, true);
          } catch (changed) {
            setError(
              changed instanceof Error ? changed.message : String(changed),
            );
            return; // A later replay or status read owns the current recovery record.
          }
        }
        setState(next);
        setReviewedPublish(false);
      }
      setError(
        reason instanceof Error ? reason.message : "Unable to publish CSV",
      );
    } finally {
      if (isCurrent()) setActivity(null);
    }
  }

  async function readStatus() {
    if (!app || !state.requestId || !canRead || busy) return;
    const isCurrent = ticket();
    let lease = recovery.lease;
    setActivity("status");
    setError("");
    try {
      const response = await request<{ result: unknown }>(
        "/api/source-load",
        sourceProgramBody(app, "facts.transfer.import.read", {
          requestId: state.requestId,
        }),
      );
      if (!isCurrent()) return;
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
      const next = {
        ...state,
        status: execution.status,
        retryPending:
          execution.status === "Accepted" && execution.errorCode !== null,
        committedRevision: completion
          ? Number(completion.committedRevision)
          : null,
        receiptId: completion ? state.batchId : "",
      };
      if (lease) {
        const nextDraft = { ...draftValue, state: next };
        if (["Completed", "Failed", "Cancelled"].includes(execution.status))
          recovery.release(lease, nextDraft);
        else lease = recovery.retain(nextDraft, lease);
      }
      setState(next);
    } catch (reason) {
      if (!isCurrent()) return;
      setError(
        reason instanceof Error ? reason.message : "Unable to read import",
      );
    } finally {
      if (isCurrent()) setActivity(null);
    }
  }

  async function readDiagnostics() {
    if (!app || !showReview || !state.artifactId || !canReadDiagnostics || busy)
      return;
    const isCurrent = ticket();
    setActivity("diagnostics");
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
      if (!isCurrent()) return;
      setDiagnostics(response.result.artifact.diagnostics || []);
    } catch (reason) {
      if (!isCurrent()) return;
      setError(
        reason instanceof Error ? reason.message : "Unable to read diagnostics",
      );
    } finally {
      if (isCurrent()) setActivity(null);
    }
  }

  const progress = [
    { label: "Source", complete: Boolean(prepared) },
    { label: "Stage", complete: Boolean(state.batchId) },
    {
      label: "Validate",
      complete: Boolean(
        state.previewToken || state.requestId || state.receiptId,
      ),
    },
    { label: "Submit", complete: Boolean(state.requestId || state.receiptId) },
    {
      label: "Receipt",
      complete:
        state.status === "Completed" &&
        state.committedRevision !== null &&
        Boolean(state.receiptId),
    },
  ];
  const currentStep = progress.findIndex((step) => !step.complete);
  const statusMessage = activity
    ? importActivityMessages[activity]
    : state.publicationUncertain
      ? "Publication outcome unknown"
      : state.status
        ? state.retryPending
          ? "Import retry pending"
          : `Import ${state.status.toLowerCase()}`
        : state.staging?.inputRejection
          ? "CSV correction required"
          : state.staging?.packet
            ? "Staging outcome unknown"
            : reviewCurrent && state.review
              ? state.errorCount
                ? `Preview has ${state.errorCount} validation errors`
                : "Exact changes ready for review"
              : state.staging?.step === "ready"
                ? "Staging complete"
                : state.staging
                  ? "Staging ready to continue"
                  : "No change before Publish";

  return (
    <section
      className="panel data-load-journey"
      aria-labelledby="data-load-heading"
    >
      <div className="section-heading-row">
        <div>
          <small>IMPORT WORKSPACE</small>
          <h2 id="data-load-heading" tabIndex={-1}>
            Load governed CSV data
          </h2>
          <p>Prepare a file, review its target and changes, then publish.</p>
        </div>
        <span
          className={`task-state ${state.status === "Completed" ? "active" : "neutral"}`}
          role="status"
        >
          {statusMessage}
        </span>
      </div>
      <ol className="journey-steps" aria-label="CSV load progress">
        {progress.map(({ label, complete }, index) => (
          <li
            className={
              complete ? "complete" : index === currentStep ? "current" : ""
            }
            key={label}
            aria-current={index === currentStep ? "step" : undefined}
            aria-label={`${label}: ${complete ? "complete" : index === currentStep ? "current" : "pending"}`}
          >
            <span aria-hidden="true">{complete ? "✓" : index + 1}</span>
            {label}
          </li>
        ))}
      </ol>
      {!canStage && catalog && (
        <div className="inline-error" role="status">
          CSV staging is not available in the current application context.
        </div>
      )}
      <div
        className="data-load-layout"
        role="group"
        aria-busy={busy}
        aria-label="Import input and target"
      >
        <div className="data-load-form">
          <div className="data-section-heading">
            <span>01</span>
            <div>
              <h3>Prepare your source</h3>
              <p>
                {grouped
                  ? "Upload or paste a CSV of numeric amounts."
                  : "Upload a CSV or a complete Open EPM export bundle."}
              </p>
            </div>
          </div>
          <label>
            {grouped
              ? "Choose numeric CSV"
              : "Choose CSV or governed export bundle"}
            <input
              type="file"
              disabled={inputLocked}
              accept={
                grouped
                  ? ".csv,text/csv"
                  : ".csv,.json,text/csv,application/json"
              }
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
              disabled={inputLocked}
              value={csv}
              placeholder="axis.Account,axis.Department,…,literalType,value,sourceRef"
              onChange={(event) => {
                setCsv(event.target.value);
                resetAfterDraftChange();
              }}
            />
          </label>
          <button {...transferAction(inputLocked || !csv, prepare)}>
            Prepare pasted CSV
          </button>
          {emptyReplacement ? (
            <p role="status">
              Prepared an empty source. The reviewed replacement can clear the
              selected cell.
            </p>
          ) : (
            prepared && (
              <p role="status">
                Prepared {prepared.bytes} bytes for governed validation.
              </p>
            )
          )}
          {sourceGrain && (
            <div aria-label="Prepared input mapping">
              <p>
                Dimension columns (exact IDs):{" "}
                {sourceGrain.dimensions.join(", ") || "none"}.
              </p>
              {sourceGrain.types.length > 0 && (
                <p>
                  Value types:{" "}
                  {sourceGrain.types
                    .slice(0, 10)
                    .map(([kind, count]) => `${kind}: ${count} rows`)
                    .join("; ")}
                  {sourceGrain.types.length > 10
                    ? "; additional types require correction during validation"
                    : ""}
                  .
                </p>
              )}
              <p>
                {grouped && !supportedInput
                  ? "Each input row must use AmountLiteral for this import."
                  : "Staging validates members and declared value rules before publication."}
              </p>
            </div>
          )}
          <details>
            <summary>Required columns</summary>
            <p>
              One <code>axis.&lt;dimensionId&gt;</code> column per active
              dimension, followed by <code>literalType</code>,{" "}
              <code>value</code> and <code>sourceRef</code>.
            </p>
            <p>
              {grouped
                ? "The example includes a numeric amount and an explicit zero."
                : "The example demonstrates an amount, an explicit numeric zero and an explicit empty text value."}{" "}
              Its columns use this application's active fact dimensions. Replace
              every example member ID with the exact IDs shown in Metadata
              before staging.
            </p>
            {currentExample?.csv ? (
              <a
                href={`data:text/csv;charset=utf-8,${encodeURIComponent(currentExample.csv)}`}
                download="openepm-import-example.csv"
              >
                Download example CSV
              </a>
            ) : (
              <p role="status">
                {!app
                  ? "Choose an application to prepare an example CSV."
                  : !canReadDimensions
                    ? "Current metadata read access is required for an example CSV."
                    : currentExample?.error ||
                      "Reading the current dimensions for the example CSV…"}
              </p>
            )}
          </details>
        </div>
        <div className="data-load-form">
          <div className="data-section-heading">
            <span>02</span>
            <div>
              <h3>Choose the target</h3>
              <p>Define which cells this import is allowed to change.</p>
            </div>
          </div>
          {grouped ? (
            <p>
              Only the numeric cells listed in your CSV can change. Every
              destination requires current read and write access.
            </p>
          ) : (
            <>
              <label>
                Target handling
                <select
                  value={mode}
                  disabled={inputLocked}
                  onChange={(event) => {
                    setMode(event.target.value);
                    invalidateTarget();
                  }}
                >
                  <option value="merge">Merge supplied cells</option>
                  <option value="replace">Replace exact selected scope</option>
                </select>
              </label>
              <ExactScopeSelector
                app={app}
                catalog={catalog}
                value={scope || {}}
                dimensions={scopeDimensions}
                metadataRevision={scopeMetadataRevision}
                disabled={inputLocked || scopeAll}
                onChange={(next) => {
                  setScopeText(serializedExactScope(next));
                  invalidateTarget();
                }}
              />
              <label className="review-check">
                <input
                  type="checkbox"
                  checked={scopeAll}
                  disabled={inputLocked}
                  onChange={(event) => {
                    setScopeAll(event.target.checked);
                    invalidateTarget();
                  }}
                />
                Whole application scope
              </label>
              <p className="data-field-help">
                {mode === "replace"
                  ? "Replace can clear values inside this scope that are absent from the source. Review the clear count before publishing."
                  : "Merge updates the supplied cells. Other cells in the selected scope remain unchanged."}
              </p>
            </>
          )}
          {mode === "replace" && !scopeAll && (
            <>
              <button
                {...transferAction(
                  inputLocked || !exactReplacementReady,
                  prepareEmptyReplacement,
                )}
              >
                Prepare empty replacement
              </button>
              <p className="data-field-help">
                Choose one member for every fact dimension to review clearing
                that cell.
              </p>
            </>
          )}
          <label className="review-check">
            <input
              type="checkbox"
              checked={reviewedStage}
              disabled={
                inputLocked ||
                !prepared ||
                !supportedInput ||
                !scopeReady ||
                !canStage
              }
              onChange={(event) => setReviewedStage(event.target.checked)}
            />
            I reviewed the exact input and target scope
          </label>
          <button
            {...transferAction(inputLocked || !stageReady, () => stage())}
          >
            {emptyReplacement
              ? "Stage empty replacement"
              : "Stage and validate CSV"}
          </button>
        </div>
      </div>
      {retainedStaging && state.staging && (
        <section aria-label="Original CSV staging recovery">
          <h3>Original staged input</h3>
          <p
            id={
              state.staging.inputRejection ? rejectionDescriptionId : undefined
            }
          >
            {state.staging.inputRejection
              ? `The original chunk was rejected before staging: ${state.staging.inputRejection.code}. No rows from that chunk were accepted.`
              : state.staging.packet && !busy
                ? `The ${state.staging.step} response is unconfirmed. This tab retains its exact request.`
                : state.staging.step === "ready"
                  ? grouped
                    ? "The sealed numeric batch is ready for review."
                    : "The original batch and manifest are ready for review."
                  : busy
                    ? "The original staging request is retained in this tab."
                    : `Acknowledged staging is retained; the next step is ${state.staging.step}.`}
          </p>
          {state.staging.batch && (
            <p>Original batch: {state.staging.batch.batchId}</p>
          )}
          {state.staging.inputRejection && (
            <fieldset
              disabled={busy || state.staging.context !== context || !canStage}
            >
              <legend>Correct rejected input</legend>
              <p>
                {state.staging.batch?.rowCount || 0} acknowledged rows remain
                unchanged in the original batch. Edit only the rejected and
                remaining rows below.
                {state.staging.nextChunk === 0
                  ? " No rows are acknowledged, so you may also correct the header."
                  : " Keep the exact original header and coordinate columns."}{" "}
                Review creates a new input intent; continuing staging requests a
                fresh admission and never resends acknowledged chunks.
              </p>
              <label>
                Rejected and remaining CSV
                <textarea
                  value={state.staging.inputRejection.correctionText}
                  aria-describedby={rejectionDescriptionId}
                  onChange={(event) =>
                    editRejectedRemainder(event.target.value)
                  }
                />
              </label>
            </fieldset>
          )}
          {(state.staging.inputRejection ||
            focusedStagingControl === "correct") && (
            <button
              {...stagingAction(
                "correct",
                busy ||
                  !state.staging.inputRejection ||
                  state.staging.context !== context ||
                  !canStage,
                reviewRejectedRemainder,
              )}
            >
              Review corrected remainder
            </button>
          )}
          {state.staging.context !== context &&
            state.staging.step !== "ready" && (
              <p>
                The application context changed. No later staging step will
                start automatically.
                {state.staging.packet
                  ? " Check the original request before leaving this input unpublished."
                  : " This acknowledged input may be left unpublished; continuing requires its original context."}
              </p>
            )}
          {(state.staging.packet || focusedStagingControl === "reconcile") && (
            <button
              {...stagingAction(
                "reconcile",
                busy || !state.staging.packet || !canCheckStage,
                () => stage("inspect"),
              )}
            >
              Check original staging status
            </button>
          )}
          {((state.staging.step !== "ready" && !state.staging.inputRejection) ||
            focusedStagingControl === "continue") && (
            <button
              {...stagingAction(
                "continue",
                busy ||
                  !canStage ||
                  (stagingMayHaveRun && !canRetryStage) ||
                  state.staging.context !== context ||
                  state.staging.step === "ready" ||
                  Boolean(state.staging.inputRejection),
                () => stage(),
              )}
            >
              {canRetryStage
                ? "Retry original staging step"
                : "Continue original staging"}
            </button>
          )}
          {!state.staging.packet && (
            <>
              <p>
                Leaving this input unpublished clears this tab's staging intent.
                Any native batch remains recorded under its existing lifecycle;
                this action does not cancel it or publish data.
              </p>
              <button disabled={busy} onClick={leaveStagingUnpublished}>
                Leave staged input unpublished
              </button>
            </>
          )}
        </section>
      )}
      {state.batchId && (
        <div className="data-load-review">
          <div className="data-section-heading">
            <span>03</span>
            <div>
              <h3>Review and publish</h3>
              <p>
                Check every set, clear and validation finding before submitting.
              </p>
            </div>
          </div>
          <div className="kpi-strip compact">
            <article>
              <span>Rows</span>
              <strong>{state.rowCount}</strong>
            </article>
            <article>
              <span>Sets</span>
              <strong>{showCounts ? state.setCount : "—"}</strong>
            </article>
            <article>
              <span>Clears</span>
              <strong>{showCounts ? state.clearCount : "—"}</strong>
            </article>
            <article>
              <span>Errors</span>
              <strong>{showReview ? state.errorCount : "—"}</strong>
            </article>
            <article>
              <span>Warnings</span>
              <strong>{showReview ? state.warningCount : "—"}</strong>
            </article>
          </div>
          <ImportChangeReview review={reviewCurrent ? state.review : null} />
          {state.publicationUncertain && !busy && (
            <p>
              {grouped
                ? "The publication outcome is unconfirmed. Retry the same reviewed publication to receive its original receipt or complete it once."
                : "The publication outcome is unconfirmed. Check the original publication before retrying."}
            </p>
          )}
          <div
            className="reviewed-inline-action data-review-actions"
            role="group"
            aria-label="Import review and publication"
          >
            {!grouped && (
              <label className="review-check">
                <input
                  type="checkbox"
                  checked={allowWarnings}
                  disabled={busy || state.publicationUncertain}
                  onChange={(event) => {
                    setAllowWarnings(event.target.checked);
                    setReviewedPublish(false);
                    setState((current) => ({
                      ...current,
                      previewToken: "",
                      review: null,
                    }));
                  }}
                />
                Permit reviewed warnings
              </label>
            )}
            <button
              {...transferAction(
                busy ||
                  !canPreview ||
                  unresolvedPublication ||
                  !!state.receiptId,
                preview,
              )}
            >
              Preview exact changes
            </button>
            <label className="review-check">
              <input
                type="checkbox"
                checked={reviewedPublish}
                disabled={
                  busy ||
                  !reviewCurrent ||
                  !state.previewToken ||
                  Boolean(state.errorCount) ||
                  state.publicationUncertain ||
                  Boolean(state.warningCount && !allowWarnings)
                }
                onChange={(event) => setReviewedPublish(event.target.checked)}
              />
              I reviewed the exact set and clear counts
            </label>
            <button
              {...transferAction(
                busy ||
                  (state.publicationUncertain && !grouped
                    ? !canRead
                    : !publishReady),
                () => publish(state.publicationUncertain && !grouped),
              )}
            >
              {grouped
                ? state.publicationUncertain
                  ? "Retry the same reviewed publication"
                  : "Publish reviewed numeric rows"
                : state.publicationUncertain && activity !== "publish"
                  ? "Check original publication status"
                  : "Start durable publication"}
            </button>
            {!grouped && state.publicationUncertain && publishReady && (
              <button {...transferAction(busy, () => publish())}>
                Retry original publication
              </button>
            )}
          </div>
          <dl className="receipt-facts">
            <dt>Publication</dt>
            <dd>
              {state.receiptId
                ? "Published"
                : state.requestId
                  ? "Submitted"
                  : "Prepared"}
            </dd>
            {grouped && reviewCurrent && state.receiptId && (
              <>
                <dt>Publication receipt</dt>
                <dd>{state.receiptId}</dd>
                <dt>Committed revision</dt>
                <dd>{state.committedRevision}</dd>
              </>
            )}
            {state.requestId && (
              <>
                <dt>Durable status</dt>
                <dd>
                  {state.status || "Accepted"}{" "}
                  <button {...transferAction(busy || !canRead, readStatus)}>
                    Refresh
                  </button>
                </dd>
                {state.committedRevision !== null && (
                  <>
                    <dt>Publication outcome</dt>
                    <dd>
                      <button onClick={() => setInspectReceipt(true)}>
                        View publication outcome
                      </button>
                    </dd>
                  </>
                )}
              </>
            )}
          </dl>
          {showReview && state.artifactId && (
            <button
              {...transferAction(busy || !canReadDiagnostics, readDiagnostics)}
            >
              Read validation diagnostics
            </button>
          )}
        </div>
      )}
      {showReview && canReadDiagnostics && diagnostics.length > 0 && (
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
        {grouped
          ? "A successful publication returns the batch receipt and committed revision."
          : "Submitting starts publication. Wait for Completed and view the outcome to confirm the committed result."}
      </p>
    </section>
  );
}
