import { navigationLabels } from "./native-selection";
import type {
  CubeSelector,
  HierarchyOperator,
  MemberListExpression,
  NavigationExpression,
} from "./selection-types";

export type SelectionLabels = {
  members?: Record<string, string>;
  hierarchies?: Record<string, string>;
  memberLists?: Record<string, string>;
  attributes?: Record<string, string>;
  /** Authorized placement labels, keyed by [memberId, pathRelationshipIds]. */
  placements?: Record<string, string>;
};

const hierarchyWords: Record<HierarchyOperator, string> = {
  children: "Children of",
  parents: "Parents of",
  descendants: "Descendants of",
  ancestors: "Ancestors of",
  siblings: "Siblings of",
  leaves: "Leaf members below",
  base: "This member if base:",
};

function label(
  values: Record<string, string> | undefined,
  id: string,
  fallback = id,
) {
  return values && Object.hasOwn(values, id)
    ? values[id] || fallback
    : fallback;
}

function disambiguate(labels: SelectionLabels): SelectionLabels {
  const result = { ...labels };
  for (const kind of [
    "members",
    "hierarchies",
    "memberLists",
    "attributes",
  ] as const) {
    const values = labels[kind];
    if (!values) continue;
    const counts = new Map<string, number>();
    for (const name of Object.values(values))
      counts.set(name, (counts.get(name) ?? 0) + 1);
    result[kind] = Object.fromEntries(
      Object.entries(values).map(([id, name]) => [
        id,
        (counts.get(name) ?? 0) > 1 ? `${name} (${id})` : name,
      ]),
    );
  }
  return result;
}

function attributeSummary(
  selector: Extract<CubeSelector | MemberListExpression, { kind: "attribute" }>,
  labels: SelectionLabels,
) {
  const name = label(labels.attributes, selector.attributeId);
  if (selector.operator === "exists" && typeof selector.value === "boolean")
    return `${name} is ${selector.value ? "present" : "absent"}`;
  const operator = {
    eq: "equals",
    ne: "does not equal",
    lt: "<",
    lte: "≤",
    gt: ">",
    gte: "≥",
    contains: "contains",
    starts_with: "starts with",
    in: "is one of",
    exists: "exists",
  }[selector.operator];
  return `${name} ${operator} ${JSON.stringify(selector.value)}`;
}

function navigationSummary(
  expression: NavigationExpression,
  labels: SelectionLabels,
) {
  const anchor = expression.anchor
    ? label(labels.members, expression.anchor.memberId)
    : "scope top";
  const hierarchy = expression.hierarchyId
    ? label(labels.hierarchies, expression.hierarchyId)
    : "whole dimension";
  const path = expression.anchor?.pathRelationshipIds;
  const placement = path
    ? path.length
      ? ` · placement ${label(labels.placements, JSON.stringify([expression.anchor!.memberId, path]), "relationship path")} [${path.join(" / ")}]`
      : " · root placement"
    : expression.anchor
      ? " · placement not specified"
      : "";
  return `${navigationLabels[expression.operation]} · ${anchor} · ${hierarchy}${placement}${expression.includeSelf ? " · including self where applicable" : ""}${expression.allParents ? " · all parents" : ""}`;
}

function expressionSummary(
  expression: MemberListExpression,
  labels: SelectionLabels,
): string {
  switch (expression.kind) {
    case "navigation":
      return navigationSummary(expression, labels);
    case "explicit":
      return (
        expression.memberIds
          .map((id) => label(labels.members, id))
          .join(", ") || "No members"
      );
    case "attribute":
      return attributeSummary(expression, labels);
    case "union":
      return `Union of (${expression.items.map((item) => expressionSummary(item, labels)).join(") and (")})`;
    case "intersection":
      return `Intersection of (${expression.items.map((item) => expressionSummary(item, labels)).join(") and (")})`;
    case "difference":
      return `(${expressionSummary(expression.source, labels)}) excluding (${expressionSummary(expression.subtract, labels)})`;
    case "order":
      return `${expressionSummary(expression.source, labels)} · ordered by ${expression.by === "attribute" ? label(labels.attributes, expression.attributeId!) : expression.by.replace("_", " ")} ${expression.direction}`;
    default:
      return `${hierarchyWords[expression.kind]} ${label(labels.members, expression.memberId)} · ${label(labels.hierarchies, expression.hierarchyId)}${expression.includeSelf ? " · including selected member" : ""}`;
  }
}

export function memberExpressionSummary(
  expression: MemberListExpression,
  labels: SelectionLabels = {},
): string {
  return expressionSummary(expression, disambiguate(labels));
}

export function selectorSummary(
  selector: CubeSelector,
  labels: SelectionLabels = {},
): string {
  labels = disambiguate(labels);
  switch (selector.kind) {
    case "member":
      return label(labels.members, selector.memberId);
    case "members": {
      const names = selector.memberIds.map((member) =>
        label(labels.members, member),
      );
      return names.length <= 3
        ? names.join(", ")
        : `${names.slice(0, 3).join(", ")} +${names.length - 3}`;
    }
    case "hierarchy":
      return `${hierarchyWords[selector.operator]} ${label(labels.members, selector.memberId)} · ${label(labels.hierarchies, selector.hierarchyId)}${selector.includeSelf ? " · including selected member" : ""}`;
    case "attribute":
      return attributeSummary(selector, labels);
    case "member_list":
      return `${label(labels.memberLists, selector.listId)}${Object.keys(selector.parameters).length ? ` · parameters ${JSON.stringify(selector.parameters)}` : ""}`;
    case "inline_expression":
      return expressionSummary(selector.expression, labels);
  }
}
