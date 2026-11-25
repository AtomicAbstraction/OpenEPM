import { expect, it } from "vitest";
import {
  parseReferenceHandoff,
  referenceDestination,
  referenceHandoffHash,
  retargetReferenceHandoff,
} from "./reference-handoff";
import type { ReferenceHandoff } from "./reference-handoff";

const view: ReferenceHandoff = {
  format: "openepm.reference-handoff/v1",
  scope: { workspaceId: "north region", applicationId: "capacity/2027" },
  origin: { kind: "task", taskId: `a:${"1".repeat(32)}` },
  target: { kind: "savedView", viewId: "capacity_by_team" },
  returnTo: { kind: "task", taskId: `a:${"1".repeat(32)}` },
  observed: { viewDigest: "a".repeat(64) },
  pendingOperation: null,
  analyticalRead: { semantics: "own" },
};

it("round trips exact references and independent read policy without a view snapshot", () => {
  const hash = referenceHandoffHash(view);
  const parsed = parseReferenceHandoff(
    new URLSearchParams(hash.split("?")[1]).get("handoff"),
  );
  expect(parsed).toEqual(view);
  expect(referenceDestination(parsed)).toEqual({
    page: "grid",
    focus: { viewId: "capacity_by_team", viewDigest: "a".repeat(64) },
  });
  expect(parsed).not.toHaveProperty("dataSource");
  expect(parsed).not.toHaveProperty("selection");
});

it.each([
  { ...view, admission: "not transferable" },
  { ...view, scope: { ...view.scope, actor: "someone-else" } },
  { ...view, target: { ...view.target, payload: { source: "draft" } } },
  { ...view, origin: { kind: "task", taskId: "id", credentials: "secret" } },
  {
    ...view,
    pendingOperation: { kind: "task", taskId: "id", replayToken: "secret" },
  },
  { ...view, pendingOperation: { kind: "receipt", receipt: "unsupported" } },
  { ...view, observed: { viewDigest: "a".repeat(64), authorization: "grant" } },
  {
    ...view,
    analyticalRead: { semantics: "stored", bindingId: "silently-ignored" },
  },
  { ...view, analyticalRead: undefined },
  {
    ...view,
    analyticalRead: { semantics: "effective", bindingId: "result-key" },
  },
  { ...view, format: "openepm.reference-handoff/v2" },
  { ...view, scope: { ...view.scope, applicationId: "" } },
  { ...view, target: { kind: "savedView", viewId: "line\nbreak" } },
  {
    ...view,
    returnTo: { kind: "savedView", viewId: "needs-independent-policy" },
  },
])(
  "rejects unsupported or authority-bearing fields instead of silently dropping them: %j",
  (input) => {
    expect(() => parseReferenceHandoff(input)).toThrow(
      "Invalid or unsupported reference handoff",
    );
  },
);

it("bounds external input before parsing and refuses oversized reference IDs", () => {
  expect(() => parseReferenceHandoff(" ".repeat(8193))).toThrow();
  expect(() =>
    parseReferenceHandoff({
      ...view,
      target: { kind: "savedView", viewId: "a".repeat(501) },
    }),
  ).toThrow();
});

it("keeps effective binding pins distinct from canonical result identity", () => {
  const value = parseReferenceHandoff({
    ...view,
    analyticalRead: {
      semantics: "effective",
      bindingId: "aggregate-capacity",
      bindingStateToken: "b".repeat(64),
    },
  });
  expect(value.analyticalRead).toEqual({
    semantics: "effective",
    bindingId: "aggregate-capacity",
    bindingStateToken: "b".repeat(64),
  });
  // Shape validation does not assert this policy is supported for a saved view.
  // Analyze's native read-plan check must refuse unsupported combinations.
});

it("returns to the exact native task with no inherited execution or analytical authority", () => {
  const value = retargetReferenceHandoff(view, {
    kind: "task",
    taskId: "origin-task",
  });
  expect(referenceDestination(value)).toEqual({
    page: "monitor",
    focus: { taskId: "origin-task" },
  });
  expect(value.scope).toEqual(view.scope);
  expect(value.origin).toEqual(view.target);
  expect(value.returnTo).toBeNull();
  expect(value.pendingOperation).toBeNull();
  expect(value.observed).toEqual({});
  expect(value).not.toHaveProperty("analyticalRead");
});

it.each([
  "ApplicationRule",
  "CalculatedMember",
  "ApplicationSequence",
  "ApplicationSchedule",
])(
  "preserves a current %s reference's observed state without inventing a historical version",
  (artifactKind) => {
    const { analyticalRead: _read, ...base } = view;
    const value = parseReferenceHandoff({
      ...base,
      target: { kind: "definition", artifactKind, artifactId: "current.owner" },
      observed: {
        stateToken: "b".repeat(64),
        definitionDigest: "c".repeat(64),
      },
    });
    expect(referenceDestination(value)).toEqual({
      page: "rules",
      focus: {
        artifactKind,
        artifactId: "current.owner",
        artifactStateToken: "b".repeat(64),
        artifactDigest: "c".repeat(64),
      },
    });
  },
);

it("returns to the exact workflow occurrence and optional activity", () => {
  const value = retargetReferenceHandoff(view, {
    kind: "workflowActivity",
    occurrenceId: "occurrence",
    activityId: "review",
  });
  expect(referenceDestination(value)).toEqual({
    page: "flows",
    focus: { occurrenceId: "occurrence", activityId: "review" },
  });
});
