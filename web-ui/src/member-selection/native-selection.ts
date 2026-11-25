import { ApiError, readProgram } from "../api";
import type { ApplicationCatalog, ApplicationSummary } from "../types";
import type {
  MemberListExpression,
  NavigationExpression,
  NavigationOperation,
} from "./selection-types";

export const navigationLabels: Record<NavigationOperation, string> = {
  top: "Scope top",
  all: "All active members",
  roots: "Roots",
  unplaced: "Unplaced members",
  leaves: "All base members",
  self: "Self",
  is_base: "This member if base",
  children: "Children",
  descendants: "Descendants",
  leaf_descendants: "Base descendants",
  parents: "Parents",
  ancestors: "Ancestors",
  siblings: "Siblings",
  same_level: "Same level",
  same_generation: "Same generation",
};
export type NativeScope = {
  kind: "scope";
  scope: "dimension" | "hierarchy";
  dimensionId: string;
  hierarchyId: string | null;
  name: string;
  shortDescription: string;
  semanticDescription: string;
  businessCoordinate: false;
  supportedOperations: NavigationOperation[];
};
export type NativeMember = {
  memberId: string;
  name: string;
  status: string;
  shortDescription: string;
  pathRelationshipIds?: string[];
  pathMemberIds?: string[];
  generation?: number;
  level?: number;
};
export type NativeSelectionPage = {
  dimensionId: string;
  metadataRevision: number;
  selectionContextToken: string;
  resultKind: "unique_member" | "placements" | "scope";
  rows: NativeMember[];
  scope: NativeScope;
  nextCursor: string | null;
  hasMore: boolean;
};
export type SelectionReadRevisions = Pick<
  ApplicationCatalog["revisions"],
  "metadata" | "policy" | "security" | "schemaEpoch"
>;

type NativeReadOptions = {
  signal?: AbortSignal;
  cursor?: string;
  placements?: boolean;
  expectedContextToken?: string;
};

function selectionReadArguments(
  dimensionId: string,
  revisions: SelectionReadRevisions,
  expression: MemberListExpression,
  { cursor, placements, expectedContextToken }: NativeReadOptions,
) {
  return cursor
    ? { cursor }
    : {
        dimensionId,
        expression,
        limit: 100,
        expectedMetadataRevision: revisions.metadata,
        expectedPolicyRevision: revisions.policy,
        expectedSecurityRevision: revisions.security,
        selectionContext: expectedContextToken
          ? { expectedToken: expectedContextToken }
          : {},
        ...(revisions.schemaEpoch === undefined
          ? {}
          : { expectedSchemaEpoch: revisions.schemaEpoch }),
        ...(placements ? { resultMode: "placements" } : {}),
      };
}

function checkedContextToken(page: SelectionPage, expected?: string) {
  const token = page?.selectionContextToken;
  if (
    typeof token !== "string" ||
    !/^[a-f0-9]{64}$/.test(token) ||
    (expected !== undefined && token !== expected)
  )
    throw new ApiError(409, "METADATA_SELECTION_CONTEXT_STALE");
  return token;
}

export function navigation(
  operation: NavigationOperation,
  hierarchyId: string | null,
  anchor: NavigationExpression["anchor"] = null,
  scope: NavigationExpression["scope"] = hierarchyId
    ? "hierarchy"
    : "dimension",
): NavigationExpression {
  return {
    kind: "navigation",
    operation,
    scope,
    hierarchyId,
    anchor,
    includeSelf: false,
    allParents: false,
  };
}
export async function readNativeSelection(
  app: ApplicationSummary,
  dimensionId: string,
  revisions: SelectionReadRevisions,
  expression: NavigationExpression,
  options: NativeReadOptions = {},
): Promise<NativeSelectionPage> {
  const page = await readProgram<NativeSelectionPage>(
    app,
    "metadata.member.select",
    selectionReadArguments(dimensionId, revisions, expression, options),
    options.signal,
  );
  checkedContextToken(page, options.expectedContextToken);
  const resultKind =
    expression.operation === "top"
      ? "scope"
      : options.placements
        ? "placements"
        : "unique_member";
  if (
    page.dimensionId !== dimensionId ||
    page.metadataRevision !== revisions.metadata ||
    page.resultKind !== resultKind ||
    !Array.isArray(page.rows) ||
    page.hasMore !== (page.nextCursor !== null) ||
    (page.nextCursor !== null && typeof page.nextCursor !== "string") ||
    (resultKind === "scope" && (page.rows.length !== 0 || page.hasMore)) ||
    !page.scope ||
    page.scope.kind !== "scope" ||
    page.scope.businessCoordinate !== false ||
    page.scope.dimensionId !== dimensionId ||
    page.scope.scope !== expression.scope ||
    page.scope.hierarchyId !== expression.hierarchyId ||
    page.rows.some(
      (row) =>
        page.resultKind !== "scope" &&
        (typeof row.memberId !== "string" ||
          typeof row.name !== "string" ||
          (options.placements &&
            (!Array.isArray(row.pathRelationshipIds) ||
              !Array.isArray(row.pathMemberIds) ||
              row.pathMemberIds.length !== row.pathRelationshipIds.length + 1 ||
              row.pathMemberIds.at(-1) !== row.memberId))),
    )
  )
    throw new Error(
      "The native selection changed or returned an invalid page. Refresh the application and try again.",
    );
  return page;
}
export function nativeMemberKey(row: NativeMember) {
  return JSON.stringify([row.memberId, row.pathRelationshipIds ?? null]);
}

type SelectionPage = Pick<
  NativeSelectionPage,
  | "rows"
  | "nextCursor"
  | "dimensionId"
  | "metadataRevision"
  | "hasMore"
  | "selectionContextToken"
>;

/** Resolve a complete ordered result without publishing a partial selection. */
export async function collectSelectionRows(
  app: ApplicationSummary,
  dimensionId: string,
  revisions: SelectionReadRevisions,
  expression: MemberListExpression,
  maximum: number,
  signal: AbortSignal,
  {
    initial,
    expectedContextToken,
  }: {
    initial?: SelectionPage | null;
    expectedContextToken?: string;
  } = {},
) {
  const rows: NativeMember[] = [];
  const ids = new Set<string>();
  const cursors = new Set<string>();
  let cursor: string | null = null;
  let first = initial;
  let contextToken = expectedContextToken;
  do {
    signal.throwIfAborted();
    const page: SelectionPage =
      first ??
      (expression.kind === "navigation"
        ? await readNativeSelection(app, dimensionId, revisions, expression, {
            signal,
            cursor: cursor ?? undefined,
            expectedContextToken: contextToken,
          })
        : await readProgram<SelectionPage>(
            app,
            "metadata.member.select",
            selectionReadArguments(dimensionId, revisions, expression, {
              cursor: cursor ?? undefined,
              expectedContextToken: contextToken,
            }),
            signal,
          ));
    contextToken = checkedContextToken(page, contextToken);
    if (
      !page ||
      page.dimensionId !== dimensionId ||
      page.metadataRevision !== revisions.metadata ||
      page.hasMore !== (page.nextCursor !== null)
    )
      throw new Error("The selection changed while collecting results.");
    if (
      !Array.isArray(page.rows) ||
      (page.nextCursor !== null &&
        (typeof page.nextCursor !== "string" ||
          !page.nextCursor ||
          !page.rows.length ||
          cursors.has(page.nextCursor)))
    )
      throw new Error(
        "The selection returned an invalid continuation. Preview it again.",
      );
    for (const row of page.rows) {
      if (
        !row ||
        typeof row.memberId !== "string" ||
        !row.memberId ||
        typeof row.name !== "string" ||
        row.status !== "Active" ||
        ids.has(row.memberId)
      )
        throw new Error(
          "The selection returned an invalid or repeated member.",
        );
      ids.add(row.memberId);
      if (ids.size > maximum)
        throw new Error(`Select no more than ${maximum} members.`);
      rows.push(row);
    }
    cursor = page.nextCursor;
    if (cursor) cursors.add(cursor);
    first = null;
  } while (cursor);
  return { rows, selectionContextToken: contextToken };
}
