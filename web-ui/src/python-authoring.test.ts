import { expect, it } from "vitest";
import {
  authoringCompletions,
  authoringContextKey,
  pythonDiagnostics,
} from "./python-authoring";
import type { ApplicationCatalog } from "./types";

const scope = { workspaceId: "ws", applicationId: "app" };
const catalog: ApplicationCatalog = {
  applicationAccess: {
    role: "Editor",
    workspaceAdministrator: false,
    issuer: "https://id.example.test",
    subjectId: "author",
  },
  enabledCapabilities: [],
  functions: {},
  revisions: {
    metadata: 4,
    policy: 2,
    schemaEpoch: 1,
    data: 0,
    commit: 0,
    security: 0,
  },
};
const context = () => ({
  ...scope,
  metadataRevision: 4,
  policyRevision: 2,
  securityRevision: 0,
  authority: { issuer: "https://id.example.test", subjectId: "author" },
  schemaEpoch: 1,
  references: {
    metadata: {
      ...scope,
      metadataRevision: 4,
      authorizationScopeDigest: "a".repeat(64),
      dimensions: [
        {
          dimensionId: "account",
          name: 'Account "name"',
          referenceMode: "symbolic",
        },
      ],
    },
  },
});

it("suggests only authorized grain and symbolic object methods", () => {
  expect(authoringCompletions(context(), scope, catalog)).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        label: "descendants",
        insertText: "descendants",
        referenceUrl: "/documentation/architecture/python-authoring/",
      }),
      expect.objectContaining({
        label: 'Account "name"',
        insertText: 'context.app.dimension("Account \\"name\\"")',
      }),
    ]),
  );
});

it("rejects stale, foreign, or non-symbolic contexts", () => {
  for (const field of [
    "metadataRevision",
    "policyRevision",
    "securityRevision",
    "schemaEpoch",
  ] as const)
    expect(() =>
      authoringCompletions({ ...context(), [field]: 99 }, scope, catalog),
    ).toThrow(/stale/);
  expect(() =>
    authoringCompletions(
      { ...context(), applicationId: "another" },
      scope,
      catalog,
    ),
  ).toThrow(/stale/);
  const invalid = context();
  invalid.references.metadata.dimensions[0].referenceMode = "materialized";
  expect(() => authoringCompletions(invalid, scope, catalog)).toThrow(
    /Invalid/,
  );
});
it("fences completions by subject, issuer and security-only grant changes", () => {
  const key = authoringContextKey(scope, catalog);
  for (const changed of [
    { ...catalog, revisions: { ...catalog.revisions, security: 1 } },
    {
      ...catalog,
      applicationAccess: {
        ...catalog.applicationAccess,
        issuer: "https://other.example.test",
      },
    },
    {
      ...catalog,
      applicationAccess: { ...catalog.applicationAccess, subjectId: "other" },
    },
  ]) {
    expect(authoringContextKey(scope, changed)).not.toBe(key);
    expect(() => authoringCompletions(context(), scope, changed)).toThrow(
      /stale/,
    );
  }
  expect(() =>
    authoringCompletions(
      {
        ...context(),
        authority: {
          issuer: "https://other.example.test",
          subjectId: "author",
        },
      },
      scope,
      catalog,
    ),
  ).toThrow(/stale/);
});

it("accepts bounded exact diagnostic envelopes and rejects malformed spans", () => {
  const diagnostics = {
    format: "openepm-diagnostics-v1",
    positionEncoding: "utf-16",
    sourceDigest: "a".repeat(64),
    truncated: false,
    diagnostics: [
      {
        code: "PYTHON_INVALID",
        severity: "error",
        stage: "syntax",
        message: "Invalid source",
        span: { startLine: 1, startColumn: 2, endLine: 1, endColumn: 3 },
      },
    ],
  };
  expect(pythonDiagnostics(diagnostics)).toEqual(diagnostics);
  expect(
    pythonDiagnostics({ ...diagnostics, sourceDigest: "unknown" }),
  ).toBeUndefined();
  expect(
    pythonDiagnostics({
      ...diagnostics,
      diagnostics: [{ ...diagnostics.diagnostics[0], span: { startLine: 0 } }],
    }),
  ).toBeUndefined();
  expect(
    pythonDiagnostics({
      ...diagnostics,
      diagnostics: Array(101).fill(diagnostics.diagnostics[0]),
    }),
  ).toBeUndefined();
});

it("does not materialize hierarchy descriptors into editor suggestions", () => {
  const value = context();
  Object.assign(value.references.metadata.dimensions[0], {
    hierarchies: [
      { hierarchyId: "H_DEFAULT", name: "Default", stateToken: "3".repeat(64) },
      { hierarchyId: "H_ALT", name: "Reporting", stateToken: "8".repeat(64) },
      { hierarchyId: "H_STALE", name: "Old", stateToken: null },
    ],
  });
  const suggestions = authoringCompletions(value, scope, catalog);
  expect(suggestions.some((row) => row.label.startsWith("Reporting ·"))).toBe(
    false,
  );
  expect(suggestions).toContainEqual(
    expect.objectContaining({ label: "hierarchy" }),
  );
});
