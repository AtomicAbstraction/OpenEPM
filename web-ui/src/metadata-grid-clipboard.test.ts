import { describe, expect, it } from "vitest";
import {
  coordinateInMetadataGridRange,
  metadataClipboardDraft,
  metadataGridRange,
  parseMetadataClipboard,
} from "./metadata-grid-clipboard";

describe("metadata grid clipboard", () => {
  it("preserves a rectangular TSV payload and ignores one final line ending", () => {
    expect(parseMetadataClipboard("A\t1\r\nB\t\r\n")).toEqual([
      ["A", "1"],
      ["B", ""],
    ]);
  });

  it("rejects a paste beyond the visible grid bounds", () => {
    expect(() =>
      parseMetadataClipboard(
        Array.from({ length: 51 }, (_, row) => String(row)).join("\n"),
      ),
    ).toThrow("Paste at most 50 rows");
    expect(() =>
      parseMetadataClipboard(Array.from({ length: 21 }, () => "x").join("\t")),
    ).toThrow("20 columns");
  });

  it("normalizes typed spreadsheet values without accepting member IDs", () => {
    expect(metadataClipboardDraft("Boolean", " TRUE ")).toBe("true");
    expect(metadataClipboardDraft("Boolean", "")).toBe("");
    expect(metadataClipboardDraft("Decimal", " 12.5000 ")).toBe("12.5000");
    expect(metadataClipboardDraft("Text", "  exact text  ")).toBe(
      "  exact text  ",
    );
    expect(() => metadataClipboardDraft("Boolean", "yes")).toThrow("True");
    expect(() => metadataClipboardDraft("MemberReference", "Revenue")).toThrow(
      "governed member chooser",
    );
  });

  it("normalizes an inclusive rectangle", () => {
    const range = metadataGridRange(
      { row: 4, column: 3 },
      { row: 1, column: 5 },
    );
    expect(range).toEqual({
      firstRow: 1,
      lastRow: 4,
      firstColumn: 3,
      lastColumn: 5,
    });
    expect(coordinateInMetadataGridRange({ row: 2, column: 4 }, range)).toBe(
      true,
    );
    expect(coordinateInMetadataGridRange({ row: 0, column: 4 }, range)).toBe(
      false,
    );
  });
});
