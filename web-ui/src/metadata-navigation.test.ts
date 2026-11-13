import { expect, it } from "vitest";
import {
  metadataNavigationNeedsGuard,
  readMetadataDestination,
  writeMetadataDestination,
} from "./metadata-navigation";

it("round-trips exact dimension and member selections in separate metadata pages", () => {
  const query = new URLSearchParams();
  writeMetadataDestination(query, {
    section: "members",
    dimensionId: "Regional accounts",
    memberId: "A/B & C",
  });
  expect(
    readMetadataDestination(new URLSearchParams(query.toString())),
  ).toEqual({
    section: "members",
    dimensionId: "Regional accounts",
    memberId: "A/B & C",
  });
});

it("fails unknown sections and malformed or unscoped selections back to safe navigation", () => {
  expect(
    readMetadataDestination(
      new URLSearchParams("metadataSection=__proto__&dimension=Account"),
    ),
  ).toEqual({ section: "dimensions" });
  expect(
    readMetadataDestination(
      new URLSearchParams("metadataSection=members&member=Sales"),
    ),
  ).toEqual({
    section: "members",
    dimensionId: undefined,
    memberId: undefined,
  });
  expect(
    readMetadataDestination(
      new URLSearchParams("metadataSection=settings&dimension=%00Account"),
    ),
  ).toEqual({
    section: "settings",
    dimensionId: undefined,
    memberId: undefined,
  });
  expect(
    readMetadataDestination(
      new URLSearchParams(
        `metadataSection=members&dimension=${"x".repeat(201)}`,
      ),
    ).dimensionId,
  ).toBeUndefined();
  expect(
    readMetadataDestination(
      new URLSearchParams(
        "metadataSection=reference&dimension=Account&member=Sales",
      ),
    ),
  ).toEqual({ section: "reference" });
});

it("limits the new draft-loss guard to metadata and member-list workspaces", () => {
  expect(metadataNavigationNeedsGuard("metadata")).toBe(true);
  expect(metadataNavigationNeedsGuard("lists")).toBe(true);
  expect(metadataNavigationNeedsGuard("rules")).toBe(false);
  expect(metadataNavigationNeedsGuard("grid")).toBe(false);
});

it("preserves exact named hierarchy identity and removes stale children when reusing a query", () => {
  const query = new URLSearchParams();
  writeMetadataDestination(query, {
    section: "relationships",
    dimensionId: "Account",
    memberId: "Root",
    hierarchyId: "Reporting & legal",
  });
  expect(readMetadataDestination(query)).toEqual({
    section: "relationships",
    dimensionId: "Account",
    memberId: "Root",
    hierarchyId: "Reporting & legal",
  });
  writeMetadataDestination(query, {
    section: "members",
    dimensionId: "Entity",
  });
  expect(query.has("hierarchy")).toBe(false);
  expect(query.has("member")).toBe(false);
  query.set("hierarchy", "stale");
  writeMetadataDestination(query, { section: "dimensions" });
  expect(query.has("hierarchy")).toBe(false);
  expect(query.has("dimension")).toBe(false);
  expect(
    readMetadataDestination(
      new URLSearchParams("metadataSection=relationships&hierarchy=H_ALT"),
    ),
  ).not.toHaveProperty("hierarchyId");
});
