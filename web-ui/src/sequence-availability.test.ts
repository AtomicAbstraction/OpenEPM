import { expect, it } from "vitest";
import { LEGACY_SEQUENCE_UNSUPPORTED } from "./sequence-availability";
import { resolveWorkflowDestination } from "./workflow-destination";
import type { ApplicationCatalog } from "./types";
const marker = {
  version: 1,
  kind: "current-definition-owner",
  ownerFunction: "rules.numeric_sequence.template",
  status: "unsupported",
  code: LEGACY_SEQUENCE_UNSUPPORTED,
};
const destination = {
  kind: "Artifact",
  artifactKind: "ApplicationSequence",
  artifactId: "private-old-sequence",
  stateToken: "a".repeat(64),
  digest: "b".repeat(64),
};
const catalog = (spec?: unknown) =>
  ({
    functions:
      spec === undefined ? {} : { "rules.numeric_sequence.read": spec },
  }) as ApplicationCatalog;
it("preserves historical reference shape while retiring new navigation without aliasing", () => {
  for (const spec of [
    { availability: marker },
    {},
    { availability: { ...marker, status: "available", code: null } },
  ]) {
    const result = resolveWorkflowDestination(destination, catalog(spec));
    expect(result.supported).toBe(false);
    expect(JSON.stringify(result)).not.toContain("private-old-sequence");
    expect(result).not.toHaveProperty("focus");
    expect(result).toMatchObject({ code: "APPLICATION_FUNCTION_RETIRED" });
  }
});
it("gives a truthful retired diagnostic for known legacy function destinations", () => {
  expect(resolveWorkflowDestination(destination, catalog())).toMatchObject({
    supported: false,
    code: "APPLICATION_FUNCTION_RETIRED",
  });
  const functions = { "rules.numeric_sequence.run": { availability: marker } };
  expect(
    resolveWorkflowDestination(
      {
        kind: "Function",
        function: "rules.numeric_sequence.run",
        argumentsDigest: "a".repeat(64),
      },
      { ...catalog(), functions },
    ),
  ).toMatchObject({ supported: false, code: "APPLICATION_FUNCTION_RETIRED" });
});
it("describes missing or unknown view and function references without asserting a permission denial", () => {
  const empty = catalog();
  const readView = (viewId: string) =>
    resolveWorkflowDestination(
      { kind: "CubeView", viewId, digest: "a".repeat(64) },
      empty,
    );
  expect(readView("private-view")).toEqual(readView("missing-view"));
  expect(readView("private-view")).toEqual({
    supported: false,
    code: "WORKFLOW_CUBE_VIEW_DESTINATION_UNAVAILABLE",
    message:
      "The configured view cannot be opened in the current application context.",
  });
  const readFunction = (name: string) =>
    resolveWorkflowDestination(
      { kind: "Function", function: name, argumentsDigest: "b".repeat(64) },
      empty,
    );
  expect(readFunction("rules.numeric_sequence.list")).toMatchObject({
    supported: false,
    code: "APPLICATION_FUNCTION_RETIRED",
  });
  expect(readFunction("missing.function")).toMatchObject({
    supported: false,
    code: "WORKFLOW_FUNCTION_DESTINATION_UNAVAILABLE",
  });
});
