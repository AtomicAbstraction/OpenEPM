import { describe, expect, it } from "vitest";
import { collectAllContinuations } from "./continuation";

type Page = { rows: { id: string }[]; next: string | null; revision: number };

const collect = (pages: Page[]) => {
  let index = 0;
  return collectAllContinuations({
    label: "Catalogue",
    readPage: async () => pages[index++]!,
    rows: (page) => page.rows,
    nextCursor: (page) => page.next,
    rowIdentity: (row) => row.id,
    consistencyIdentity: (page) => page.revision,
  });
};

describe("collectAllContinuations", () => {
  it("collects every page without a silent item cap", async () => {
    const pages = Array.from({ length: 101 }, (_, index) => ({
      rows: Array.from({ length: 100 }, (_unused, row) => ({
        id: `${index}-${row}`,
      })),
      next: index === 100 ? null : `cursor-${index + 1}`,
      revision: 7,
    }));
    expect((await collect(pages)).rows).toHaveLength(10100);
  });

  it("rejects repeated cursors, rows, and changed consistency", async () => {
    await expect(
      collect([
        { rows: [{ id: "a" }], next: "same", revision: 1 },
        { rows: [{ id: "b" }], next: "same", revision: 1 },
      ]),
    ).rejects.toThrow("cursor repeated");
    await expect(
      collect([
        { rows: [{ id: "a" }], next: "more", revision: 1 },
        { rows: [{ id: "a" }], next: null, revision: 1 },
      ]),
    ).rejects.toThrow("repeated a row");
    await expect(
      collect([
        { rows: [{ id: "a" }], next: "more", revision: 1 },
        { rows: [{ id: "b" }], next: null, revision: 2 },
      ]),
    ).rejects.toThrow("changed while reading");
  });

  it("rejects malformed continuation cursors", async () => {
    await expect(
      collect([{ rows: [], next: "" as never, revision: 1 }]),
    ).rejects.toThrow("cursor is invalid");
  });
});
