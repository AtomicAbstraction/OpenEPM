import { describe, expect, it } from "vitest";
import {
  CUBE_SELECTION_FORMAT,
  INLINE_EXPRESSION_FORMAT,
  SelectionContractError,
  canonicalCubeSelection,
  canonicalCubeSelector,
  explicitMemberIds,
  memberSelectionError,
} from "./selection-types";
import {
  cubeSelectionFromScalarPov,
  scalarPovFromCubeSelection,
} from "./selection-adapter";
import { selectorSummary } from "./selection-summary";

describe("canonical selection contract", () => {
  it("canonicalizes every fixed selector kind without losing order", () => {
    const value = canonicalCubeSelection({
      format: CUBE_SELECTION_FORMAT,
      metadataRevision: 19,
      dimensions: [
        {
          dimensionId: "Scenario",
          include: { kind: "member", memberId: "Actual" },
          exclude: null,
        },
        {
          dimensionId: "Account",
          include: {
            kind: "members",
            memberIds: ["Revenue", "Cost"],
          },
          exclude: {
            kind: "attribute",
            attributeId: "ReportingGroup",
            operator: "eq",
            value: "Statistical",
          },
        },
        {
          dimensionId: "Entity",
          include: {
            kind: "hierarchy",
            operator: "descendants",
            hierarchyId: "Management",
            memberId: "Europe",
            includeSelf: true,
          },
          exclude: null,
        },
        {
          dimensionId: "Period",
          include: {
            kind: "member_list",
            listId: "CurrentQuarter",
            parameters: { Year: "FY26" },
          },
          exclude: null,
        },
        {
          dimensionId: "Product",
          include: {
            kind: "inline_expression",
            expressionFormat: INLINE_EXPRESSION_FORMAT,
            expression: {
              kind: "difference",
              source: {
                kind: "descendants",
                hierarchyId: "Primary",
                memberId: "AllProducts",
                includeSelf: false,
              },
              subtract: {
                kind: "explicit",
                memberIds: ["Discontinued"],
              },
            },
          },
          exclude: null,
        },
      ],
    });
    expect(value.dimensions.map((item) => item.dimensionId)).toEqual([
      "Account",
      "Entity",
      "Period",
      "Product",
      "Scenario",
    ]);
    expect(value.dimensions[0].include).toEqual({
      kind: "members",
      memberIds: ["Revenue", "Cost"],
    });
    expect(value.dimensions[3].include.kind).toBe("inline_expression");
  });

  it("rejects duplicate members, incomplete grain and floating parameters", () => {
    expect(() =>
      canonicalCubeSelector({
        kind: "members",
        memberIds: ["Revenue", "Revenue"],
      }),
    ).toThrowError(
      expect.objectContaining({ code: "CUBE_SELECTION_MEMBERS_DUPLICATE" }),
    );
    expect(() =>
      canonicalCubeSelector({
        kind: "member_list",
        listId: "Current",
        parameters: { Offset: 1.5 },
      }),
    ).toThrowError(SelectionContractError);
    expect(() =>
      canonicalCubeSelection(
        {
          format: CUBE_SELECTION_FORMAT,
          metadataRevision: 1,
          dimensions: [
            {
              dimensionId: "Account",
              include: { kind: "member", memberId: "Revenue" },
              exclude: null,
            },
          ],
        },
        ["Account", "Entity"],
      ),
    ).toThrowError(
      expect.objectContaining({ code: "CUBE_SELECTION_GRAIN_INCOMPLETE" }),
    );
  });

  it("builds and extracts a scalar POV through the canonical contract", () => {
    const selection = cubeSelectionFromScalarPov(
      [{ dimension_id: "Scenario" }, { dimension_id: "Account" }],
      {
        Scenario: [{ member_id: "Actual" }],
        Account: [{ member_id: "Revenue" }, { member_id: "Cost" }],
      },
      { Scenario: "Actual" },
      7,
    );
    expect(selection.dimensions).toEqual([
      {
        dimensionId: "Account",
        include: { kind: "members", memberIds: ["Revenue", "Cost"] },
        exclude: null,
      },
      {
        dimensionId: "Scenario",
        include: { kind: "member", memberId: "Actual" },
        exclude: null,
      },
    ]);
    expect(scalarPovFromCubeSelection(selection, ["Scenario"])).toEqual({
      Scenario: "Actual",
    });
  });

  it("produces business summaries while preserving a deterministic fallback", () => {
    expect(
      selectorSummary(
        { kind: "members", memberIds: ["CH", "DE", "UK", "FR"] },
        { members: { CH: "Switzerland", DE: "Germany", UK: "United Kingdom" } },
      ),
    ).toBe("Switzerland, Germany, United Kingdom +1");
    expect(
      selectorSummary(
        {
          kind: "hierarchy",
          operator: "descendants",
          hierarchyId: "Management",
          memberId: "Europe",
          includeSelf: false,
        },
        {
          members: { Europe: "Europe" },
          hierarchies: { Management: "Management hierarchy" },
        },
      ),
    ).toBe("Descendants of Europe · Management hierarchy");
  });

  it("explains a placement-bound compound exclusion and exact typed attribute operands", () => {
    const summary = selectorSummary(
      {
        kind: "inline_expression",
        expressionFormat: "openepm-member-list-expression-v1",
        expression: {
          kind: "difference",
          source: {
            kind: "navigation",
            operation: "leaf_descendants",
            scope: "hierarchy",
            hierarchyId: "primary",
            anchor: {
              memberId: "Europe",
              pathRelationshipIds: ["world-europe"],
            },
            includeSelf: false,
            allParents: false,
          },
          subtract: {
            kind: "intersection",
            items: [
              {
                kind: "attribute",
                attributeId: "Status",
                operator: "eq",
                value: "Closed",
              },
              {
                kind: "attribute",
                attributeId: "Threshold",
                operator: "gte",
                value: "0.99999999999999999",
              },
            ],
          },
        },
      },
      {
        members: { Europe: "Region", Other: "Region" },
        hierarchies: { primary: "Management" },
      },
    );
    expect(summary).toContain(
      "Base descendants · Region (Europe) · Management",
    );
    expect(summary).toContain("relationship path [world-europe]");
    expect(summary).toContain(
      'excluding (Intersection of (Status equals "Closed") and (Threshold ≥ "0.99999999999999999"))',
    );
    expect(
      selectorSummary({
        kind: "attribute",
        attributeId: "Flag",
        operator: "eq",
        value: false,
      }),
    ).toBe("Flag equals false");
    expect(
      selectorSummary({
        kind: "attribute",
        attributeId: "Flag",
        operator: "exists",
        value: false,
      }),
    ).toBe("Flag is absent");
  });

  it("uses only own label properties for legitimate prototype-named identifiers and placements", () => {
    for (const memberId of ["constructor", "toString", "__proto__"])
      expect(
        selectorSummary({ kind: "member", memberId }, { members: {} }),
      ).toBe(memberId);
    const pathKey = JSON.stringify(["constructor", ["edge"]]);
    expect(
      selectorSummary(
        {
          kind: "inline_expression",
          expressionFormat: "openepm-member-list-expression-v1",
          expression: {
            kind: "navigation",
            operation: "parents",
            scope: "hierarchy",
            hierarchyId: "toString",
            anchor: { memberId: "constructor", pathRelationshipIds: ["edge"] },
            includeSelf: false,
            allParents: false,
          },
        },
        {
          placements: Object.create({
            [pathKey]: "Inherited unauthorized label",
          }),
        },
      ),
    ).toBe(
      "Parents · constructor · toString · placement relationship path [edge]",
    );
  });

  it("enforces caller-declared selection semantics", () => {
    const explicitOnly = {
      allowExplicitMembers: true,
      allowHierarchySelector: false,
      allowNamedMemberList: false,
      allowAttributeSelector: false,
      allowInlineExpression: false,
      allowExclusion: false,
      orderMatters: false,
    };
    expect(
      memberSelectionError(
        { kind: "members", memberIds: ["CH", "DE"] },
        { kind: "exactly-one" },
        explicitOnly,
      ),
    ).toBe("The current operation requires exactly one explicit member.");
    expect(
      memberSelectionError(
        {
          kind: "hierarchy",
          operator: "descendants",
          hierarchyId: "Primary",
          memberId: "Europe",
          includeSelf: false,
        },
        { kind: "one-or-more" },
        explicitOnly,
      ),
    ).toBe("This type of selection is not allowed for the current operation.");
    expect(
      memberSelectionError(
        { kind: "members", memberIds: ["CH", "DE"] },
        { kind: "one-or-more", maximum: 1 },
        explicitOnly,
      ),
    ).toBe("Select no more than 1 member.");
    expect(
      explicitMemberIds({ kind: "members", memberIds: ["DE", "CH"] }),
    ).toEqual(["DE", "CH"]);
  });
});
