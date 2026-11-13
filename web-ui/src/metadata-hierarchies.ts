import { collectAllContinuations } from "./continuation";

export type MetadataHierarchy = {
  hierarchyId: string;
  name: string;
  status: "Active" | "Inactive";
  membershipMode: "explicit" | "all_active";
  isDefault: boolean;
  stateToken: string | null;
  builtMetadataRevision: number | null;
  current: boolean;
};
export type HierarchyMember = {
  memberId: string;
  status: "Active" | "Inactive";
};
type Page<Row> = {
  dimensionId: string;
  metadataRevision: number;
  rows: Row[];
  hasMore: boolean;
  nextAfterId: string | null;
};

function collect<Row>(
  dimensionId: string,
  revision: number,
  readPage: (args: Record<string, unknown>) => Promise<Page<Row>>,
  identity: (row: Row) => string,
  valid: (row: Row) => boolean,
  hierarchyId?: string,
) {
  return collectAllContinuations<Page<Row>, Row>({
    label: "Named hierarchy metadata",
    readPage: (afterId) =>
      readPage({
        dimensionId,
        limit: 500,
        expectedMetadataRevision: revision,
        ...(hierarchyId === undefined ? {} : { hierarchyId }),
        ...(afterId === null ? {} : { afterId }),
      }),
    rows: (page) => {
      if (
        page.dimensionId !== dimensionId ||
        !Array.isArray(page.rows) ||
        page.rows.some((row) => !valid(row)) ||
        page.hasMore !== (page.nextAfterId !== null)
      )
        throw new Error("Invalid named hierarchy metadata response.");
      return page.rows;
    },
    nextCursor: (page) => page.nextAfterId,
    rowIdentity: identity,
    consistencyIdentity: (page) => {
      if (page.metadataRevision !== revision)
        throw new Error("Metadata changed while reading hierarchies.");
      return page.metadataRevision;
    },
  });
}

export function collectMetadataHierarchies(
  dimensionId: string,
  revision: number,
  readPage: (args: Record<string, unknown>) => Promise<Page<MetadataHierarchy>>,
) {
  return collect(
    dimensionId,
    revision,
    readPage,
    (row) => row.hierarchyId,
    (row) =>
      Boolean(
        row &&
          typeof row.hierarchyId === "string" &&
          row.hierarchyId &&
          typeof row.name === "string" &&
          row.name &&
          ["Active", "Inactive"].includes(row.status) &&
          ["explicit", "all_active"].includes(row.membershipMode) &&
          typeof row.isDefault === "boolean" &&
          typeof row.current === "boolean" &&
          (row.stateToken === null ||
            (typeof row.stateToken === "string" &&
              /^[0-9a-f]{64}$/.test(row.stateToken))) &&
          (row.builtMetadataRevision === null ||
            (Number.isSafeInteger(row.builtMetadataRevision) &&
              row.builtMetadataRevision >= 0)),
      ),
  );
}

export function collectHierarchyMembers(
  dimensionId: string,
  hierarchyId: string,
  revision: number,
  readPage: (args: Record<string, unknown>) => Promise<Page<HierarchyMember>>,
) {
  return collect(
    dimensionId,
    revision,
    readPage,
    (row) => row.memberId,
    (row) =>
      Boolean(
        row &&
          typeof row.memberId === "string" &&
          row.memberId &&
          ["Active", "Inactive"].includes(row.status),
      ),
    hierarchyId,
  );
}
