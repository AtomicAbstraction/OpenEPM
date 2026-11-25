import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ImportChangeReview, validateImportReview } from "./ImportChangeReview";

const review = {
  format: "openepm-source-change-review-v1",
  mode: "replace",
  scopeMembers: { Department: "D1", Period: "P1" },
  scopeAll: false,
  periodSelection: null,
  metadataRevision: 3,
  dataRevision: 5,
  commitRevision: 9,
  sampleLimitPerAction: 20,
  setsComplete: true,
  clearsComplete: true,
  readRestricted: false,
  examples: [
    {
      action: "set",
      members: { Department: "D1", Period: "P1", Measure: "Cost" },
      valueKind: "numeric",
      sourceRef: "row-1",
      before: { present: false },
      after: { present: true, amount: "0.00000000" },
    },
    {
      action: "set",
      members: { Department: "D1", Period: "P1", Measure: "Comment" },
      valueKind: "text",
      sourceRef: "row-2",
      before: { present: false },
      after: { present: true, text: "" },
    },
    {
      action: "clear",
      members: { Department: "D1", Period: "P1", Measure: "Old" },
      valueKind: "numeric",
      sourceRef: null,
      before: { present: true, amount: "100.00000001" },
      after: { present: false },
    },
  ],
};

describe("typed import change review", () => {
  it("shows exact business coordinates, present zero, empty text and omitted clears distinctly", () => {
    render(
      <ImportChangeReview
        review={validateImportReview(review, "replace", {
          setCount: 2,
          clearCount: 1,
        })}
      />,
    );
    expect(screen.getByText("0.00000000")).toBeInTheDocument();
    expect(screen.getByText("Empty text (present)")).toBeInTheDocument();
    expect(screen.getByText("100.00000001")).toBeInTheDocument();
    expect(screen.getByText("Clear omitted value")).toBeInTheDocument();
    expect(
      screen.getByText(/Department: D1; Period: P1; Measure: Old/),
    ).toBeInTheDocument();
    expect(screen.getAllByText("Absent")).toHaveLength(3);
  });
  it("does not describe a bounded or restricted sample as all changes", () => {
    render(
      <ImportChangeReview
        review={validateImportReview(
          { ...review, setsComplete: false, readRestricted: true },
          "replace",
          { setCount: 3, clearCount: 1 },
        )}
      />,
    );
    expect(
      screen.queryByText("All changes are shown."),
    ).not.toBeInTheDocument();
    expect(screen.getByText(/Some examples are withheld/)).toBeInTheDocument();
  });
  it("refuses float-coerced amounts, changed mode and contradictory presence", () => {
    expect(() =>
      validateImportReview(review, "merge", { setCount: 2, clearCount: 1 }),
    ).toThrow("INVALID_SOURCE_CHANGE_REVIEW");
    for (const after of [
      { present: true, amount: 0 },
      { present: false, amount: "0" },
      { present: true, amount: "NaN" },
    ])
      expect(() =>
        validateImportReview(
          { ...review, examples: [{ ...review.examples[0], after }] },
          "replace",
          { setCount: 2, clearCount: 1 },
        ),
      ).toThrow("INVALID_SOURCE_CHANGE_REVIEW");
    for (const example of [
      { ...review.examples[0], sourceRef: null },
      { ...review.examples[2], sourceRef: "row-3" },
    ])
      expect(() =>
        validateImportReview({ ...review, examples: [example] }, "replace", {
          setCount: 2,
          clearCount: 1,
        }),
      ).toThrow("INVALID_SOURCE_CHANGE_REVIEW");
  });
  it("rejects a claim of complete examples that does not match the full count", () => {
    expect(() =>
      validateImportReview(review, "replace", { setCount: 3, clearCount: 1 }),
    ).toThrow("INVALID_SOURCE_CHANGE_REVIEW_COMPLETENESS");
  });
  it.each([{ Department: "Other", Period: "P1" }, { Department: "D1" }])(
    "refuses an example outside the fixed destination scope %j",
    (coordinate) => {
      expect(() =>
        validateImportReview(
          {
            ...review,
            examples: [
              { ...review.examples[0], members: coordinate },
              ...review.examples.slice(1),
            ],
          },
          "replace",
          { setCount: 2, clearCount: 1 },
        ),
      ).toThrow(
        "A change example falls outside the reviewed destination scope.",
      );
    },
  );
  it("shows linked supporting-detail removal beside the exact numeric clear", () => {
    const detailed = {
      ...review,
      examples: [
        {
          ...review.examples[2],
          companionChanges: [
            {
              valueKind: "detail",
              before: {
                present: true,
                amount: "100.00000001",
                items: [
                  { description: "Travel", amount: "60.00000001" },
                  { description: "Training", amount: "40" },
                ],
              },
              after: { present: false },
            },
          ],
        },
      ],
    };
    render(
      <ImportChangeReview
        review={validateImportReview(detailed, "replace", {
          setCount: 0,
          clearCount: 1,
        })}
      />,
    );
    expect(screen.getByText("Travel: 60.00000001")).toBeInTheDocument();
    expect(screen.getByText("Training: 40")).toBeInTheDocument();
    expect(screen.getAllByText(/Linked detail/)).toHaveLength(2);
  });
});

it("rejects excess samples per action and duplicate coordinate-kind examples", () => {
  const examples = Array.from({ length: 21 }, (_, index) => ({
    ...review.examples[0],
    members: { ...review.scopeMembers, Measure: `M${index}` },
  }));
  expect(() =>
    validateImportReview({ ...review, examples }, "replace", {
      setCount: 21,
      clearCount: 0,
    }),
  ).toThrow("INVALID_SOURCE_CHANGE_REVIEW_COMPLETENESS");
  expect(() =>
    validateImportReview(
      { ...review, examples: [review.examples[0], review.examples[0]] },
      "replace",
      { setCount: 2, clearCount: 0 },
    ),
  ).toThrow("INVALID_SOURCE_CHANGE_REVIEW_DUPLICATE");
});
