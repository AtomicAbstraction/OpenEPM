import { collectAllContinuations } from "./continuation";
import { readPlatformProgram } from "./api";

export type SecuritySubject = {
  selectionKey: string;
  displayName: string;
  username: string;
};

export type DirectoryGroup = {
  groupId: string;
  groupName: string;
  displayName: string;
  shortDescription: string;
  semanticDescription: string;
  status: "Active" | "Inactive";
};

type OffsetPage<T> = { items: T[]; nextOffset: number | null };
const directoryPageSize = 100;

export function readOffsetDirectory<Row>(
  functionName: string,
  label: string,
  rowIdentity: (row: Row) => string,
  signal: AbortSignal,
) {
  return collectAllContinuations<OffsetPage<Row>, Row>({
    label,
    readPage: async (cursor) => {
      const offset = cursor === null ? 0 : Number(cursor);
      const page = await readPlatformProgram<OffsetPage<Row>>(
        functionName,
        { offset, limit: directoryPageSize },
        signal,
      );
      if (
        !Array.isArray(page?.items) ||
        page.items.length > directoryPageSize ||
        (page.nextOffset !== null &&
          (!Number.isSafeInteger(page.nextOffset) ||
            page.nextOffset !== offset + directoryPageSize))
      )
        throw new Error(`${label} returned an invalid page.`);
      return page;
    },
    rows: (page) => page.items,
    nextCursor: (page) =>
      page.nextOffset === null ? null : String(page.nextOffset),
    rowIdentity,
  });
}

export function readDirectoryGroups(signal: AbortSignal) {
  return readOffsetDirectory<DirectoryGroup>(
    "identity.group.list",
    "Directory groups",
    (row) =>
      typeof row?.groupId === "string" &&
      typeof row.groupName === "string" &&
      row.groupName.length > 0 &&
      typeof row.displayName === "string" &&
      typeof row.shortDescription === "string" &&
      typeof row.semanticDescription === "string" &&
      (row.status === "Active" || row.status === "Inactive")
        ? row.groupId
        : "",
    signal,
  );
}

export function subjectListArguments(afterSelectionKey?: string | null) {
  return afterSelectionKey ? { afterSelectionKey, limit: 100 } : { limit: 100 };
}

type SubjectPage = {
  subjects: SecuritySubject[];
  nextAfterSelectionKey: string | null;
};

export function collectSecuritySubjectOptions(
  readPage: (
    arguments_: ReturnType<typeof subjectListArguments>,
  ) => Promise<SubjectPage>,
) {
  return collectAllContinuations<SubjectPage, SecuritySubject>({
    label: "Application security directory",
    readPage: (cursor) => readPage(subjectListArguments(cursor)),
    rows: (page) => page.subjects,
    nextCursor: (page) => page.nextAfterSelectionKey,
    rowIdentity: (subject) => subject.selectionKey,
  });
}
