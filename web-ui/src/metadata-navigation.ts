export type MetadataSection =
  | "dimensions"
  | "members"
  | "relationships"
  | "tree"
  | "attributes"
  | "security-tags"
  | "settings"
  | "reference";

export type MetadataDestination = {
  section: MetadataSection;
  dimensionId?: string;
  memberId?: string;
  hierarchyId?: string;
  relationshipId?: string;
};

export type MetadataNavigationDimension = {
  dimension_id: string;
  name: string;
  model_role: string;
  status: string;
};

export const metadataSectionLabels: Record<MetadataSection, string> = {
  dimensions: "Dimensions",
  members: "Members",
  relationships: "Relationships",
  tree: "Tree",
  attributes: "Attributes",
  "security-tags": "Security tags",
  settings: "Properties & access",
  reference: "Function reference",
};

export const dimensionSections: MetadataSection[] = [
  "members",
  "relationships",
  "tree",
  "attributes",
  "security-tags",
  "settings",
];

export function metadataSection(
  value: string | null | undefined,
): MetadataSection {
  // Schema 247 replaced the duplicate semantic-column editor with governed
  // attribute definitions. Keep old bookmarks useful without preserving a
  // second executable editing surface.
  if (value === "semantics") return "attributes";
  return value && Object.hasOwn(metadataSectionLabels, value)
    ? (value as MetadataSection)
    : "dimensions";
}

export function metadataRouteIdentifier(value: string | null | undefined) {
  // IDs are display-only route selections, never a replacement for core validation.
  return value && value.length <= 200 && !/[\u0000-\u001f\u007f]/.test(value)
    ? value
    : undefined;
}

export function readMetadataDestination(
  query: URLSearchParams,
): MetadataDestination {
  const section = metadataSection(query.get("metadataSection"));
  if (section === "dimensions" || section === "reference") return { section };
  const dimensionId = metadataRouteIdentifier(query.get("dimension"));
  return {
    section,
    dimensionId,
    ...(dimensionId && metadataRouteIdentifier(query.get("hierarchy"))
      ? { hierarchyId: metadataRouteIdentifier(query.get("hierarchy")) }
      : {}),
    ...(dimensionId &&
    metadataRouteIdentifier(query.get("member")) &&
    (section === "relationships" || section === "tree") &&
    query.has("relationship")
      ? {
          relationshipId:
            metadataRouteIdentifier(query.get("relationship")) ?? "",
        }
      : {}),
    memberId: dimensionId
      ? metadataRouteIdentifier(query.get("member"))
      : undefined,
  };
}

export function writeMetadataDestination(
  query: URLSearchParams,
  destination: MetadataDestination,
) {
  const section = metadataSection(destination.section);
  query.delete("dimension");
  query.delete("member");
  query.delete("hierarchy");
  query.delete("relationship");
  query.set("metadataSection", section);
  if (section === "dimensions" || section === "reference") return;
  const dimension = metadataRouteIdentifier(destination.dimensionId);
  if (dimension) {
    query.set("dimension", dimension);
    const member = metadataRouteIdentifier(destination.memberId);
    if (member) query.set("member", member);
    if (
      member &&
      (section === "relationships" || section === "tree") &&
      destination.relationshipId !== undefined
    )
      query.set(
        "relationship",
        metadataRouteIdentifier(destination.relationshipId) ?? "",
      );
    const hierarchy = metadataRouteIdentifier(destination.hierarchyId);
    if (hierarchy) query.set("hierarchy", hierarchy);
  }
}

export function metadataNavigationNeedsGuard(page: string) {
  return page === "metadata" || page === "lists";
}
