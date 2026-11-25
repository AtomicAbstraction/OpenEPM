import {
  CUBE_SELECTION_FORMAT,
  canonicalCubeSelection,
  type CubeSelection,
} from "./selection-types";

export type SelectionDimension = { dimension_id: string };
export type SelectionMember = { member_id: string };

export function cubeSelectionFromScalarPov(
  dimensions: SelectionDimension[],
  members: Record<string, SelectionMember[]>,
  pov: Record<string, string>,
  metadataRevision: number,
): CubeSelection {
  return canonicalCubeSelection({
    format: CUBE_SELECTION_FORMAT,
    metadataRevision,
    dimensions: dimensions.map((dimension) => ({
      dimensionId: dimension.dimension_id,
      include: pov[dimension.dimension_id]
        ? { kind: "member", memberId: pov[dimension.dimension_id] }
        : {
            kind: "members",
            memberIds: (members[dimension.dimension_id] || []).map(
              (member) => member.member_id,
            ),
          },
      exclude: null,
    })),
  });
}

export function scalarPovFromCubeSelection(
  selection: CubeSelection,
  fixedDimensions: Iterable<string>,
): Record<string, string> {
  const fixed = new Set(fixedDimensions);
  return Object.fromEntries(
    selection.dimensions.flatMap((dimension) =>
      fixed.has(dimension.dimensionId) && dimension.include.kind === "member"
        ? [[dimension.dimensionId, dimension.include.memberId]]
        : [],
    ),
  );
}
