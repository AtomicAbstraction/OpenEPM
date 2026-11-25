import { collectAllContinuations } from "./continuation";

export type MetadataRelationship = {
  relationship_id: string;
  hierarchy_id?: string;
  aggregation_operator_override?: string | null;
  dimension_id: string;
  name?: string;
  short_description?: string;
  detailed_description?: string;
  semantic_description?: string;
  parent_member_id: string;
  child_member_id: string;
  status: "Active" | "Inactive";
};

type RelationshipPage = {
  rows: MetadataRelationship[];
  metadataRevision: number;
  nextCursor: string | null;
  hierarchyId?: string | null;
};

export function collectMetadataRelationships(
  dimensionId: string,
  expectedMetadataRevision: number | null,
  readPage: (arguments_: Record<string, unknown>) => Promise<RelationshipPage>,
  hierarchyId?: string,
) {
  return collectAllContinuations<RelationshipPage, MetadataRelationship>({
    label: "Relationship catalogue",
    readPage: (cursor) =>
      readPage(
        cursor
          ? { cursor }
          : {
              dimension: dimensionId,
              limit: 100,
              ...(hierarchyId ? { hierarchyId } : {}),
            },
      ),
    rows: (page) => {
      if (
        hierarchyId &&
        (page.hierarchyId !== hierarchyId ||
          page.rows.some((row) => row.hierarchy_id !== hierarchyId))
      )
        throw new Error("Relationship response belongs to another hierarchy.");
      return page.rows;
    },
    nextCursor: (page) => page.nextCursor,
    rowIdentity: (row) => row.relationship_id,
    consistencyIdentity: (page) => {
      if (
        expectedMetadataRevision !== null &&
        page.metadataRevision !== expectedMetadataRevision
      )
        throw new Error("Metadata changed while reading relationships.");
      return page.metadataRevision;
    },
  });
}
