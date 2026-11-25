export const CUBE_SELECTION_FORMAT = "openepm-cube-selection-v1" as const;
export const INLINE_EXPRESSION_FORMAT =
  "openepm-member-list-expression-v1" as const;

export const hierarchyOperators = [
  "children",
  "parents",
  "descendants",
  "ancestors",
  "siblings",
  "leaves",
  "base",
] as const;

export const navigationOperations = [
  "top",
  "all",
  "roots",
  "unplaced",
  "leaves",
  "self",
  "is_base",
  "children",
  "descendants",
  "leaf_descendants",
  "parents",
  "ancestors",
  "siblings",
  "same_level",
  "same_generation",
] as const;
export type NavigationOperation = (typeof navigationOperations)[number];
export type NavigationExpression = {
  kind: "navigation";
  operation: NavigationOperation;
  scope: "dimension" | "hierarchy";
  hierarchyId: string | null;
  anchor: {
    memberId: string;
    pathRelationshipIds: readonly string[] | null;
  } | null;
  includeSelf: boolean;
  allParents: boolean;
};

export const attributeOperators = [
  "eq",
  "ne",
  "lt",
  "lte",
  "gt",
  "gte",
  "contains",
  "starts_with",
  "in",
  "exists",
] as const;

export type HierarchyOperator = (typeof hierarchyOperators)[number];
export type AttributeOperator = (typeof attributeOperators)[number];
export type SelectionParameterValue = string | number | boolean | null;

export type ExplicitMemberExpression = {
  kind: "explicit";
  memberIds: readonly string[];
};

export type HierarchyMemberExpression = {
  kind: HierarchyOperator;
  hierarchyId: string;
  memberId: string;
  includeSelf: boolean;
};

export type AttributeMemberExpression = {
  kind: "attribute";
  attributeId: string;
  operator: AttributeOperator;
  value: SelectionParameterValue | SelectionParameterValue[];
};

export type SetMemberExpression = {
  kind: "union" | "intersection";
  items: readonly MemberListExpression[];
};

export type DifferenceMemberExpression = {
  kind: "difference";
  source: MemberListExpression;
  subtract: MemberListExpression;
};

export type OrderedMemberExpression = {
  kind: "order";
  source: MemberListExpression;
  by: "member_id" | "name" | "attribute";
  direction: "ascending" | "descending";
  attributeId: string | null;
};

export type MemberListExpression =
  | ExplicitMemberExpression
  | NavigationExpression
  | HierarchyMemberExpression
  | AttributeMemberExpression
  | SetMemberExpression
  | DifferenceMemberExpression
  | OrderedMemberExpression;

export type MemberSelector = { kind: "member"; memberId: string };
export type MembersSelector = {
  kind: "members";
  memberIds: readonly string[];
};
export type HierarchySelector = {
  kind: "hierarchy";
  operator: HierarchyOperator;
  hierarchyId: string;
  memberId: string;
  includeSelf: boolean;
};
export type AttributeSelector = {
  kind: "attribute";
  attributeId: string;
  operator: AttributeOperator;
  value: SelectionParameterValue | SelectionParameterValue[];
};
export type MemberListSelector = {
  kind: "member_list";
  listId: string;
  parameters: Record<string, SelectionParameterValue>;
};
export type InlineExpressionSelector = {
  kind: "inline_expression";
  expressionFormat: typeof INLINE_EXPRESSION_FORMAT;
  expression: MemberListExpression;
};

export type CubeSelector =
  | MemberSelector
  | MembersSelector
  | HierarchySelector
  | AttributeSelector
  | MemberListSelector
  | InlineExpressionSelector;

export type SelectionCardinality =
  | { kind: "exactly-one" }
  | { kind: "one-or-more"; maximum?: number }
  | { kind: "zero-or-more"; maximum?: number };

export type SelectionCapability = {
  /** Browsing native sets never grants permission to apply a dynamic selector. */
  allowNativeBrowse?: boolean;
  allowExplicitMembers: boolean;
  allowHierarchySelector: boolean;
  allowNamedMemberList: boolean;
  allowAttributeSelector: boolean;
  allowInlineExpression: boolean;
  allowExclusion: boolean;
  orderMatters: boolean;
};

export type MemberSelectionRequest = {
  dimensionId: string;
  dimensionName: string;
  metadataRevision: number;
  hierarchyId?: string;
  cardinality: SelectionCardinality;
  capability: SelectionCapability;
  initial: CubeSelector | null;
  /** Existing exclusion is preserved while this dialog edits the include. */
  initialExclude?: CubeSelector | null;
  title?: string;
};

export type MemberSelectionResult = {
  dimensionId: string;
  metadataRevision: number;
  include: CubeSelector;
  exclude: CubeSelector | null;
  displaySummary: string;
};

export type DimensionSelection = {
  dimensionId: string;
  include: CubeSelector;
  exclude: CubeSelector | null;
};

export type CubeSelection = {
  format: typeof CUBE_SELECTION_FORMAT;
  metadataRevision: number;
  dimensions: readonly DimensionSelection[];
};

export class SelectionContractError extends Error {
  constructor(public readonly code: string) {
    super(code);
    this.name = "SelectionContractError";
  }
}

const identifier = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const hierarchyOperatorSet = new Set<string>(hierarchyOperators);
const attributeOperatorSet = new Set<string>(attributeOperators);

export function explicitMemberIds(selector: CubeSelector | null): string[] {
  if (!selector) return [];
  if (selector.kind === "member") return [selector.memberId];
  if (selector.kind === "members") return [...selector.memberIds];
  return [];
}

export function selectorAllowed(
  selector: CubeSelector,
  capability: SelectionCapability,
): boolean {
  if (selector.kind === "member" || selector.kind === "members")
    return capability.allowExplicitMembers;
  if (selector.kind === "hierarchy") return capability.allowHierarchySelector;
  if (selector.kind === "member_list") return capability.allowNamedMemberList;
  if (selector.kind === "attribute") return capability.allowAttributeSelector;
  return capability.allowInlineExpression;
}

export function memberSelectionError(
  selector: CubeSelector | null,
  cardinality: SelectionCardinality,
  capability: SelectionCapability,
): string | null {
  if (!selector)
    return cardinality.kind === "zero-or-more"
      ? null
      : "Select at least one member.";
  if (!selectorAllowed(selector, capability))
    return "This type of selection is not allowed for the current operation.";
  const memberIds = explicitMemberIds(selector);
  if (cardinality.kind === "exactly-one") {
    if (selector.kind !== "member")
      return "The current operation requires exactly one explicit member.";
    return null;
  }
  if (memberIds.length === 0) return null;
  if (cardinality.kind === "one-or-more" && memberIds.length < 1)
    return "Select at least one member.";
  if (cardinality.maximum !== undefined) {
    if (!Number.isSafeInteger(cardinality.maximum) || cardinality.maximum < 1)
      return "The selection limit is invalid.";
    if (memberIds.length > cardinality.maximum)
      return `Select no more than ${cardinality.maximum} ${cardinality.maximum === 1 ? "member" : "members"}.`;
  }
  return null;
}

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exact(
  value: unknown,
  keys: string[],
  code: string,
): Record<string, unknown> {
  if (
    !object(value) ||
    Object.keys(value).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(value, key))
  )
    throw new SelectionContractError(code);
  return value;
}

function id(value: unknown, code: string): string {
  if (typeof value !== "string" || !identifier.test(value))
    throw new SelectionContractError(code);
  return value;
}

function parameterValue(
  value: unknown,
  code = "CUBE_SELECTION_PARAMETER_VALUE_INVALID",
): SelectionParameterValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isSafeInteger(value))
  )
    return value;
  throw new SelectionContractError(code);
}

type ExpressionBudget = { nodes: number; memberReferences: number };

function parseMemberListExpression(
  value: unknown,
  budget: ExpressionBudget,
  depth: number,
): MemberListExpression {
  if (depth > 16)
    throw new SelectionContractError("MEMBER_LIST_EXPRESSION_DEPTH_EXCEEDED");
  if (!object(value) || typeof value.kind !== "string")
    throw new SelectionContractError("MEMBER_LIST_EXPRESSION_INVALID");
  budget.nodes += 1;
  if (budget.nodes > 1_000)
    throw new SelectionContractError(
      "MEMBER_LIST_EXPRESSION_NODE_LIMIT_EXCEEDED",
    );
  if (value.kind === "explicit") {
    const item = exact(
      value,
      ["kind", "memberIds"],
      "MEMBER_LIST_EXPLICIT_INVALID",
    );
    if (
      !Array.isArray(item.memberIds) ||
      item.memberIds.length < 1 ||
      item.memberIds.length > 10_000
    )
      throw new SelectionContractError("MEMBER_LIST_EXPLICIT_INVALID");
    const memberIds = item.memberIds.map((member) =>
      id(member, "MEMBER_LIST_MEMBER_ID_INVALID"),
    );
    if (new Set(memberIds).size !== memberIds.length)
      throw new SelectionContractError("MEMBER_LIST_EXPLICIT_DUPLICATE");
    budget.memberReferences += memberIds.length;
    if (budget.memberReferences > 10_000)
      throw new SelectionContractError(
        "MEMBER_LIST_MEMBER_REFERENCE_LIMIT_EXCEEDED",
      );
    return { kind: "explicit", memberIds };
  }
  if (value.kind === "navigation") {
    const item = exact(
      value,
      [
        "kind",
        "operation",
        "scope",
        "hierarchyId",
        "anchor",
        "includeSelf",
        "allParents",
      ],
      "MEMBER_LIST_NAVIGATION_INVALID",
    );
    if (
      !navigationOperations.includes(item.operation as NavigationOperation) ||
      !["dimension", "hierarchy"].includes(String(item.scope)) ||
      typeof item.includeSelf !== "boolean" ||
      typeof item.allParents !== "boolean"
    )
      throw new SelectionContractError("MEMBER_LIST_NAVIGATION_INVALID");
    const anchor =
      item.anchor === null
        ? null
        : exact(
            item.anchor,
            ["memberId", "pathRelationshipIds"],
            "MEMBER_LIST_NAVIGATION_ANCHOR_INVALID",
          );
    let pathRelationshipIds: string[] | null = null;
    if (anchor && anchor.pathRelationshipIds !== null) {
      if (
        !Array.isArray(anchor.pathRelationshipIds) ||
        anchor.pathRelationshipIds.length > 64
      )
        throw new SelectionContractError("MEMBER_LIST_NAVIGATION_PATH_INVALID");
      pathRelationshipIds = anchor.pathRelationshipIds.map((value) =>
        id(value, "MEMBER_LIST_NAVIGATION_PATH_INVALID"),
      );
      if (new Set(pathRelationshipIds).size !== pathRelationshipIds.length)
        throw new SelectionContractError("MEMBER_LIST_NAVIGATION_PATH_INVALID");
    }
    const operation = item.operation as NavigationOperation;
    if (
      (item.scope === "hierarchy" && item.hierarchyId === null) ||
      (item.hierarchyId === null && !["top", "all"].includes(operation)) ||
      (item.scope === "dimension" &&
        (anchor !== null ||
          !["top", "all", "leaves", "unplaced"].includes(operation))) ||
      (["top", "all", "roots", "unplaced", "leaves"].includes(operation) &&
        anchor !== null) ||
      ([
        "self",
        "is_base",
        "parents",
        "ancestors",
        "siblings",
        "same_level",
      ].includes(operation) &&
        anchor === null) ||
      (item.includeSelf &&
        ![
          "children",
          "descendants",
          "leaf_descendants",
          "parents",
          "ancestors",
          "siblings",
          "same_level",
          "same_generation",
        ].includes(operation)) ||
      (item.allParents &&
        !["parents", "ancestors", "siblings"].includes(operation)) ||
      (item.allParents && pathRelationshipIds !== null)
    )
      throw new SelectionContractError("MEMBER_LIST_NAVIGATION_INVALID");
    return {
      kind: "navigation",
      operation,
      scope: item.scope as NavigationExpression["scope"],
      hierarchyId:
        item.hierarchyId === null
          ? null
          : id(item.hierarchyId, "MEMBER_LIST_HIERARCHY_ID_INVALID"),
      anchor: anchor
        ? {
            memberId: id(anchor.memberId, "MEMBER_LIST_MEMBER_ID_INVALID"),
            pathRelationshipIds,
          }
        : null,
      includeSelf: item.includeSelf,
      allParents: item.allParents,
    };
  }
  if (hierarchyOperatorSet.has(value.kind)) {
    const item = exact(
      value,
      ["kind", "hierarchyId", "memberId", "includeSelf"],
      "MEMBER_LIST_HIERARCHY_SELECTOR_INVALID",
    );
    if (
      typeof item.includeSelf !== "boolean" ||
      (value.kind === "base" && item.includeSelf)
    )
      throw new SelectionContractError(
        "MEMBER_LIST_HIERARCHY_SELECTOR_INVALID",
      );
    budget.memberReferences += 1;
    if (budget.memberReferences > 10_000)
      throw new SelectionContractError(
        "MEMBER_LIST_MEMBER_REFERENCE_LIMIT_EXCEEDED",
      );
    return {
      kind: value.kind as HierarchyOperator,
      hierarchyId: id(item.hierarchyId, "MEMBER_LIST_HIERARCHY_ID_INVALID"),
      memberId: id(item.memberId, "MEMBER_LIST_MEMBER_ID_INVALID"),
      includeSelf: item.includeSelf,
    };
  }
  if (value.kind === "attribute") {
    const item = exact(
      value,
      ["kind", "attributeId", "operator", "value"],
      "MEMBER_LIST_ATTRIBUTE_SELECTOR_INVALID",
    );
    if (
      typeof item.operator !== "string" ||
      !attributeOperatorSet.has(item.operator)
    )
      throw new SelectionContractError(
        "MEMBER_LIST_ATTRIBUTE_OPERATOR_INVALID",
      );
    let normalized: SelectionParameterValue | SelectionParameterValue[];
    if (item.operator === "in") {
      if (
        !Array.isArray(item.value) ||
        item.value.length < 1 ||
        item.value.length > 100
      )
        throw new SelectionContractError("MEMBER_LIST_ATTRIBUTE_VALUE_INVALID");
      normalized = item.value.map((entry) =>
        parameterValue(entry, "MEMBER_LIST_ATTRIBUTE_VALUE_INVALID"),
      );
    } else {
      if (item.operator === "exists" && typeof item.value !== "boolean")
        throw new SelectionContractError("MEMBER_LIST_ATTRIBUTE_VALUE_INVALID");
      normalized = parameterValue(
        item.value,
        "MEMBER_LIST_ATTRIBUTE_VALUE_INVALID",
      );
    }
    return {
      kind: "attribute",
      attributeId: id(item.attributeId, "MEMBER_LIST_ATTRIBUTE_ID_INVALID"),
      operator: item.operator as AttributeOperator,
      value: normalized,
    };
  }
  if (value.kind === "union" || value.kind === "intersection") {
    const item = exact(
      value,
      ["kind", "items"],
      "MEMBER_LIST_SET_OPERATION_INVALID",
    );
    if (
      !Array.isArray(item.items) ||
      item.items.length < 2 ||
      item.items.length > 64
    )
      throw new SelectionContractError("MEMBER_LIST_SET_OPERATION_INVALID");
    return {
      kind: value.kind,
      items: item.items.map((entry) =>
        parseMemberListExpression(entry, budget, depth + 1),
      ),
    };
  }
  if (value.kind === "difference") {
    const item = exact(
      value,
      ["kind", "source", "subtract"],
      "MEMBER_LIST_DIFFERENCE_INVALID",
    );
    return {
      kind: "difference",
      source: parseMemberListExpression(item.source, budget, depth + 1),
      subtract: parseMemberListExpression(item.subtract, budget, depth + 1),
    };
  }
  if (value.kind === "order") {
    const item = exact(
      value,
      ["kind", "source", "by", "direction", "attributeId"],
      "MEMBER_LIST_ORDER_INVALID",
    );
    if (
      !["member_id", "name", "attribute"].includes(String(item.by)) ||
      !["ascending", "descending"].includes(String(item.direction)) ||
      (item.by === "attribute") !== (item.attributeId !== null)
    )
      throw new SelectionContractError("MEMBER_LIST_ORDER_INVALID");
    return {
      kind: "order",
      source: parseMemberListExpression(item.source, budget, depth + 1),
      by: item.by as OrderedMemberExpression["by"],
      direction: item.direction as OrderedMemberExpression["direction"],
      attributeId:
        item.attributeId === null
          ? null
          : id(item.attributeId, "MEMBER_LIST_ATTRIBUTE_ID_INVALID"),
    };
  }
  throw new SelectionContractError("MEMBER_LIST_EXPRESSION_KIND_UNSUPPORTED");
}

export function canonicalMemberListExpression(
  value: unknown,
): MemberListExpression {
  return parseMemberListExpression(value, { nodes: 0, memberReferences: 0 }, 1);
}

export function canonicalCubeSelector(value: unknown): CubeSelector {
  if (!object(value) || typeof value.kind !== "string")
    throw new SelectionContractError("CUBE_SELECTION_SELECTOR_INVALID");
  if (value.kind === "member") {
    const item = exact(
      value,
      ["kind", "memberId"],
      "CUBE_SELECTION_MEMBER_INVALID",
    );
    return {
      kind: "member",
      memberId: id(item.memberId, "CUBE_SELECTION_MEMBER_INVALID"),
    };
  }
  if (value.kind === "members") {
    const item = exact(
      value,
      ["kind", "memberIds"],
      "CUBE_SELECTION_MEMBERS_INVALID",
    );
    if (
      !Array.isArray(item.memberIds) ||
      item.memberIds.length < 1 ||
      item.memberIds.length > 10_000
    )
      throw new SelectionContractError("CUBE_SELECTION_MEMBERS_INVALID");
    const memberIds = item.memberIds.map((member) =>
      id(member, "CUBE_SELECTION_MEMBERS_INVALID"),
    );
    if (new Set(memberIds).size !== memberIds.length)
      throw new SelectionContractError("CUBE_SELECTION_MEMBERS_DUPLICATE");
    return { kind: "members", memberIds };
  }
  if (value.kind === "hierarchy") {
    const item = exact(
      value,
      ["kind", "operator", "hierarchyId", "memberId", "includeSelf"],
      "CUBE_SELECTION_HIERARCHY_INVALID",
    );
    if (
      typeof item.operator !== "string" ||
      !hierarchyOperatorSet.has(item.operator) ||
      typeof item.includeSelf !== "boolean" ||
      (item.operator === "base" && item.includeSelf)
    )
      throw new SelectionContractError("CUBE_SELECTION_HIERARCHY_INVALID");
    return {
      kind: "hierarchy",
      operator: item.operator as HierarchyOperator,
      hierarchyId: id(item.hierarchyId, "CUBE_SELECTION_HIERARCHY_INVALID"),
      memberId: id(item.memberId, "CUBE_SELECTION_HIERARCHY_INVALID"),
      includeSelf: item.includeSelf,
    };
  }
  if (value.kind === "attribute") {
    const item = exact(
      value,
      ["kind", "attributeId", "operator", "value"],
      "CUBE_SELECTION_ATTRIBUTE_INVALID",
    );
    if (
      typeof item.operator !== "string" ||
      !attributeOperatorSet.has(item.operator)
    )
      throw new SelectionContractError("CUBE_SELECTION_ATTRIBUTE_INVALID");
    let normalized: SelectionParameterValue | SelectionParameterValue[];
    if (item.operator === "in") {
      if (
        !Array.isArray(item.value) ||
        item.value.length < 1 ||
        item.value.length > 100
      )
        throw new SelectionContractError("CUBE_SELECTION_ATTRIBUTE_INVALID");
      normalized = item.value.map((entry) =>
        parameterValue(entry, "CUBE_SELECTION_ATTRIBUTE_INVALID"),
      );
    } else {
      normalized = parameterValue(
        item.value,
        "CUBE_SELECTION_ATTRIBUTE_INVALID",
      );
    }
    return {
      kind: "attribute",
      attributeId: id(item.attributeId, "CUBE_SELECTION_ATTRIBUTE_INVALID"),
      operator: item.operator as AttributeOperator,
      value: normalized,
    };
  }
  if (value.kind === "member_list") {
    const item = exact(
      value,
      ["kind", "listId", "parameters"],
      "CUBE_SELECTION_MEMBER_LIST_INVALID",
    );
    if (!object(item.parameters) || Object.keys(item.parameters).length > 100)
      throw new SelectionContractError("CUBE_SELECTION_MEMBER_LIST_INVALID");
    const entries: Array<[string, SelectionParameterValue]> = Object.entries(
      item.parameters,
    ).map(([name, parameter]) => [
      id(name, "CUBE_SELECTION_PARAMETER_NAME_INVALID"),
      parameterValue(parameter),
    ]);
    entries.sort(([left], [right]) => left.localeCompare(right));
    const parameters = Object.fromEntries(entries);
    return {
      kind: "member_list",
      listId: id(item.listId, "CUBE_SELECTION_MEMBER_LIST_INVALID"),
      parameters,
    };
  }
  if (value.kind === "inline_expression") {
    const item = exact(
      value,
      ["kind", "expressionFormat", "expression"],
      "CUBE_SELECTION_INLINE_EXPRESSION_INVALID",
    );
    if (item.expressionFormat !== INLINE_EXPRESSION_FORMAT)
      throw new SelectionContractError(
        "CUBE_SELECTION_INLINE_EXPRESSION_FORMAT_UNSUPPORTED",
      );
    return {
      kind: "inline_expression",
      expressionFormat: INLINE_EXPRESSION_FORMAT,
      expression: canonicalMemberListExpression(item.expression),
    };
  }
  throw new SelectionContractError("CUBE_SELECTION_SELECTOR_KIND_UNSUPPORTED");
}

export function canonicalCubeSelection(
  value: unknown,
  activeDimensions?: readonly string[],
): CubeSelection {
  const item = exact(
    value,
    ["format", "metadataRevision", "dimensions"],
    "CUBE_SELECTION_INVALID",
  );
  if (item.format !== CUBE_SELECTION_FORMAT)
    throw new SelectionContractError("CUBE_SELECTION_FORMAT_UNSUPPORTED");
  if (
    !Number.isSafeInteger(item.metadataRevision) ||
    Number(item.metadataRevision) < 1
  )
    throw new SelectionContractError(
      "CUBE_SELECTION_METADATA_REVISION_INVALID",
    );
  if (
    !Array.isArray(item.dimensions) ||
    item.dimensions.length < 1 ||
    item.dimensions.length > 128
  )
    throw new SelectionContractError("CUBE_SELECTION_DIMENSIONS_INVALID");
  const seen = new Set<string>();
  const dimensions = item.dimensions.map((raw) => {
    const dimension = exact(
      raw,
      ["dimensionId", "include", "exclude"],
      "CUBE_SELECTION_DIMENSION_INVALID",
    );
    const dimensionId = id(
      dimension.dimensionId,
      "CUBE_SELECTION_DIMENSION_INVALID",
    );
    if (seen.has(dimensionId))
      throw new SelectionContractError("CUBE_SELECTION_DIMENSION_DUPLICATE");
    seen.add(dimensionId);
    return {
      dimensionId,
      include: canonicalCubeSelector(dimension.include),
      exclude:
        dimension.exclude === null
          ? null
          : canonicalCubeSelector(dimension.exclude),
    };
  });
  if (activeDimensions) {
    const expected = new Set(activeDimensions);
    if (
      expected.size !== activeDimensions.length ||
      expected.size !== seen.size ||
      [...expected].some((dimension) => !seen.has(dimension))
    )
      throw new SelectionContractError("CUBE_SELECTION_GRAIN_INCOMPLETE");
  }
  dimensions.sort((left, right) =>
    left.dimensionId.localeCompare(right.dimensionId),
  );
  return {
    format: CUBE_SELECTION_FORMAT,
    metadataRevision: Number(item.metadataRevision),
    dimensions,
  };
}

export function isCanonicalCubeSelection(
  value: unknown,
  activeDimensions?: readonly string[],
): value is CubeSelection {
  try {
    canonicalCubeSelection(value, activeDimensions);
    return true;
  } catch {
    return false;
  }
}
