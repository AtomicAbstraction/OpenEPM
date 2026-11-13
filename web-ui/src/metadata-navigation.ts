export type MetadataSection =
  | "dimensions"
  | "members"
  | "relationships"
  | "attributes"
  | "semantics"
  | "security-tags"
  | "settings"
  | "reference";

export type MetadataDestination = {
  section: MetadataSection;
  dimensionId?: string;
  memberId?: string;
  hierarchyId?: string;
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
  attributes: "Attributes",
  semantics: "Semantic guidance",
  "security-tags": "Security tags",
  settings: "Properties & access",
  reference: "Function reference",
};

export const dimensionSections: MetadataSection[] = [
  "members",
  "relationships",
  "attributes",
  "semantics",
  "security-tags",
  "settings",
];

export function metadataSection(
  value: string | null | undefined,
): MetadataSection {
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
  query.set("metadataSection", section);
  if (section === "dimensions" || section === "reference") return;
  const dimension = metadataRouteIdentifier(destination.dimensionId);
  if (dimension) {
    query.set("dimension", dimension);
    const member = metadataRouteIdentifier(destination.memberId);
    if (member) query.set("member", member);
    const hierarchy = metadataRouteIdentifier(destination.hierarchyId);
    if (hierarchy) query.set("hierarchy", hierarchy);
  }
}

export function metadataNavigationNeedsGuard(page: string) {
  return page === "metadata" || page === "lists";
}
