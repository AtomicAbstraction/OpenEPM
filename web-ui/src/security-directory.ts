import { collectAllContinuations } from "./continuation";

export type SecuritySubject = {
  selectionKey: string;
  displayName: string;
  username: string;
};

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
