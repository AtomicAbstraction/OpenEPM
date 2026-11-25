export const METADATA_CLIPBOARD_MAX_ROWS = 50;
export const METADATA_CLIPBOARD_MAX_COLUMNS = 20;
export const METADATA_CLIPBOARD_MAX_CELLS = 1_000;

export type MetadataGridCoordinate = {
  row: number;
  column: number;
};

export type MetadataGridRange = {
  firstRow: number;
  lastRow: number;
  firstColumn: number;
  lastColumn: number;
};

export function metadataGridRange(
  anchor: MetadataGridCoordinate,
  focus: MetadataGridCoordinate,
): MetadataGridRange {
  return {
    firstRow: Math.min(anchor.row, focus.row),
    lastRow: Math.max(anchor.row, focus.row),
    firstColumn: Math.min(anchor.column, focus.column),
    lastColumn: Math.max(anchor.column, focus.column),
  };
}

export function coordinateInMetadataGridRange(
  coordinate: MetadataGridCoordinate,
  range: MetadataGridRange | null,
) {
  return Boolean(
    range &&
      coordinate.row >= range.firstRow &&
      coordinate.row <= range.lastRow &&
      coordinate.column >= range.firstColumn &&
      coordinate.column <= range.lastColumn,
  );
}

/** Parse the bounded rectangular TSV shape produced by spreadsheet copy.
 *
 * A single trailing line ending is ignored because spreadsheet clipboard
 * payloads commonly include it. Empty cells and empty interior rows retain
 * their clearing meaning. Quoted CSV is deliberately not accepted here: the
 * browser grid consumes TSV, while file import owns CSV parsing.
 */
export function parseMetadataClipboard(text: string): string[][] {
  if (typeof text !== "string" || text.includes("\u0000"))
    throw new Error("The pasted cells contain unsupported text.");
  const normalized = text.replace(/\r\n?/g, "\n");
  const lines = normalized.split("\n");
  if (lines.length > 1 && lines.at(-1) === "") lines.pop();
  const rows = lines.map((line) => line.split("\t"));
  const columns = Math.max(0, ...rows.map((row) => row.length));
  const cells = rows.reduce((total, row) => total + row.length, 0);
  if (
    rows.length > METADATA_CLIPBOARD_MAX_ROWS ||
    columns > METADATA_CLIPBOARD_MAX_COLUMNS ||
    cells > METADATA_CLIPBOARD_MAX_CELLS
  )
    throw new Error(
      `Paste at most ${METADATA_CLIPBOARD_MAX_ROWS} rows, ${METADATA_CLIPBOARD_MAX_COLUMNS} columns and ${METADATA_CLIPBOARD_MAX_CELLS} cells at once.`,
    );
  return rows;
}

export function metadataClipboardDraft(
  valueType: "Text" | "Decimal" | "Boolean" | "MemberReference",
  value: string,
) {
  if (valueType === "MemberReference")
    throw new Error(
      "Referenced-member columns must use the governed member chooser and cannot accept pasted identifiers.",
    );
  if (valueType === "Boolean") {
    const normalized = value.trim().toLowerCase();
    if (normalized === "") return "";
    if (normalized === "true") return "true";
    if (normalized === "false") return "false";
    throw new Error('Boolean cells accept only "True", "False" or blank.');
  }
  return valueType === "Decimal" ? value.trim() : value;
}
