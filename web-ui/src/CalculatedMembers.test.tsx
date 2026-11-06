import { render, screen } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, expect, it, vi } from "vitest";
import {
  CalculatedMembers,
  exactCalculatedMemberDetail,
} from "./CalculatedMembers";

afterEach(() => vi.unstubAllGlobals());

const digest = "d".repeat(64);
const target = { definitionId: "margin.calculated", version: 2, digest };
const detail = {
  defined: true,
  definitionId: target.definitionId,
  version: target.version,
  status: "Published",
  programDigest: digest,
  program: {
    function: "calculated.member.definition",
    arguments: {
      format: "openepm-calculated-member-v1",
      definitionId: target.definitionId,
      version: target.version,
      name: "Margin",
      evaluation: "materialized",
      sourceSelection: { dimensions: [] },
      expression: { op: "Subtract" },
      dependencies: [{ definitionId: "revenue.calculated", version: 1 }],
      resultKey: "margin.result",
      target: { dimensionId: "Account", memberId: "Margin" },
      resultUnit: "amount",
      maxSourceCells: 1000,
      maxOutputCells: 100,
    },
  },
  definitionMetadataRevision: 7,
  currentMetadataRevision: 7,
  publishedRevision: 12,
  createdRevision: 11,
  createdAt: "2026-11-06T12:00:00+00:00",
  policyRevision: 3,
  commitRevision: 12,
};

it("rejects substituted calculated-member identity, version and digest", () => {
  for (const changed of [
    { ...detail, definitionId: "other.calculated" },
    { ...detail, version: 3 },
    { ...detail, programDigest: "e".repeat(64) },
    {
      ...detail,
      program: { ...detail.program, function: "application.rule.plan" },
    },
  ])
    expect(() => exactCalculatedMemberDetail(changed, target)).toThrow(
      "INVALID_CALCULATED_MEMBER_RESPONSE",
    );
});

it("rejects saved, malformed and contradictory calculated-member results", () => {
  for (const changed of [
    { ...detail, status: "Saved", publishedRevision: null },
    {
      ...detail,
      program: {
        ...detail.program,
        arguments: { ...detail.program.arguments, resultKey: null },
      },
    },
    {
      ...detail,
      program: {
        ...detail.program,
        arguments: {
          ...detail.program.arguments,
          target: { dimensionId: "Account", memberId: "Margin", extra: true },
        },
      },
    },
    { ...detail, createdAt: "not-a-timestamp" },
  ])
    expect(() => exactCalculatedMemberDetail(changed, target)).toThrow(
      "INVALID_CALCULATED_MEMBER_RESPONSE",
    );
});

it("reads and explains the exact authorized calculated-member definition", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      expect(body.program).toEqual({
        languageVersion: 2,
        function: "calculated.member.version.read",
        arguments: { definitionId: target.definitionId, version: 2 },
      });
      return new Response(JSON.stringify({ result: detail }));
    }),
  );
  const rendered = render(
    <CalculatedMembers
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      }}
      catalog={{
        applicationAccess: { role: "Reader", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: { "calculated.member.version.read": {} },
        revisions: {
          metadata: 7,
          data: 1,
          policy: 3,
          security: 1,
          commit: 12,
        },
      }}
      target={target}
    />,
  );
  const inspector = await screen.findByLabelText("Calculated member detail");
  expect(inspector).toHaveTextContent("margin.calculated v2");
  expect(inspector).toHaveTextContent("revenue.calculated v1");
  expect(inspector).toHaveTextContent("Materialized result key");
  expect(inspector).toHaveTextContent(
    "does not expose a materialization generation or linked operation receipt",
  );
  expect(screen.getByRole("status")).toHaveTextContent(
    "Calculated-member definition loaded",
  );
  expect(
    (
      await axe.run(rendered.container, {
        rules: { "color-contrast": { enabled: false } },
      })
    ).violations,
  ).toEqual([]);
});

it("does not issue an unauthorized calculated-member read", () => {
  const fetch = vi.fn();
  vi.stubGlobal("fetch", fetch);
  render(
    <CalculatedMembers
      app={{
        workspaceId: "ws",
        applicationId: "app",
        name: "Plan",
        status: "Active",
      }}
      catalog={{
        applicationAccess: { role: "Reader", workspaceAdministrator: false },
        enabledCapabilities: [],
        functions: {},
        revisions: {
          metadata: 1,
          data: 1,
          policy: 1,
          security: 1,
          commit: 1,
        },
      }}
      target={target}
    />,
  );
  expect(screen.getByRole("alert")).toHaveTextContent("not authorized");
  expect(fetch).not.toHaveBeenCalled();
});
