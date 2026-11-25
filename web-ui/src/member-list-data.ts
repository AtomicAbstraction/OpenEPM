import { collectAllContinuations } from "./continuation";
import { ApiError } from "./api";

export function memberListReadInvalidatesCatalogue(reason: unknown): boolean {
  return (
    reason instanceof ApiError &&
    (reason.kind === "authentication" ||
      reason.kind === "authorization" ||
      [
        "BROWSER_IDENTITY_CHANGED",
        "MEMBER_LIST_AUTHORIZATION_STALE",
        "MEMBER_LIST_LIST_STALE",
        "MEMBER_LIST_NOT_FOUND",
        "MEMBER_LIST_READ_STALE",
      ].includes(reason.code))
  );
}

export type MemberListSummary = {
  listId: string;
  stateToken: string;
  dimensionId: string;
  name: string;
  definition: Record<string, unknown> | null;
  canonicalDigest: string;
  status: string;
  active?: boolean;
  valid?: boolean;
  executable?: boolean;
  sourceCurrent?: boolean;
  reason?: string | null;
  source?: import("./PythonDefinitionEditor").PythonSourceBinding | null;
  currentMetadataRevision?: number;
  policyRevision?: number;
};

export type MemberListPage = {
  memberLists: MemberListSummary[];
  nextAfterListId: string | null;
  collectionToken: string;
};

export function memberListArguments(
  afterListId?: string | null,
  expectedCollectionToken?: string,
) {
  return afterListId
    ? {
        limit: 100,
        afterListId,
        expectedCollectionToken,
      }
    : { limit: 100 };
}

export function collectMemberLists(
  readPage: (
    arguments_: ReturnType<typeof memberListArguments>,
  ) => Promise<MemberListPage>,
) {
  let token: string | undefined;
  return collectAllContinuations<MemberListPage, MemberListSummary>({
    label: "Member lists",
    readPage: async (cursor) => {
      const page = await readPage(memberListArguments(cursor, token));
      token = page.collectionToken;
      return page;
    },
    rows: (page) => page.memberLists,
    nextCursor: (page) => page.nextAfterListId,
    rowIdentity: (item) => item.listId,
    consistencyIdentity: (page) => page.collectionToken,
  });
}

export function memberListParameters(item: MemberListSummary): unknown[] {
  const definition = item.definition;
  return definition && Array.isArray(definition.parameters)
    ? definition.parameters
    : [];
}
