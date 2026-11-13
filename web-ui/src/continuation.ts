export type ContinuationOptions<Page, Row> = {
  label: string;
  readPage: (cursor: string | null) => Promise<Page>;
  rows: (page: Page) => Row[];
  nextCursor: (page: Page) => string | null;
  rowIdentity?: (row: Row) => string;
  consistencyIdentity?: (page: Page) => string | number;
};

export async function collectAllContinuations<Page, Row>({
  label,
  readPage,
  rows,
  nextCursor,
  rowIdentity,
  consistencyIdentity,
}: ContinuationOptions<Page, Row>): Promise<{ rows: Row[]; finalPage: Page }> {
  const found: Row[] = [];
  const seenCursors = new Set<string>();
  const seenRows = new Set<string>();
  let expectedConsistency: string | number | undefined;
  let cursor: string | null = null;
  let finalPage: Page | undefined;
  do {
    const page = await readPage(cursor);
    const pageRows = rows(page);
    if (!Array.isArray(pageRows))
      throw new Error(`${label} continuation rows are invalid.`);
    const consistency = consistencyIdentity?.(page);
    if (consistencyIdentity) {
      if (typeof consistency !== "string" && typeof consistency !== "number")
        throw new Error(`${label} continuation consistency is invalid.`);
      if (
        expectedConsistency !== undefined &&
        consistency !== expectedConsistency
      )
        throw new Error(`${label} changed while reading continuations.`);
      expectedConsistency = consistency;
    }
    for (const row of pageRows) {
      const identity = rowIdentity?.(row);
      if (rowIdentity) {
        if (!identity) throw new Error(`${label} returned an invalid row.`);
        if (seenRows.has(identity))
          throw new Error(`${label} continuation repeated a row.`);
        seenRows.add(identity);
      }
      found.push(row);
    }
    const next = nextCursor(page);
    if (next !== null && (typeof next !== "string" || !next))
      throw new Error(`${label} continuation cursor is invalid.`);
    if (next !== null) {
      if (next === cursor || seenCursors.has(next))
        throw new Error(`${label} continuation cursor repeated.`);
      seenCursors.add(next);
    }
    cursor = next;
    finalPage = page;
  } while (cursor !== null);
  if (finalPage === undefined)
    throw new Error(`${label} returned no continuation page.`);
  return { rows: found, finalPage };
}
