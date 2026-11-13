import { expect, it } from "vitest";
import {
  resolveWorkspaceSection,
  workspaceSectionForArtifact,
  workspaceSections,
} from "./workspace-navigation";

it("resolves exact artifact destinations without silently opening another editor", () => {
  for (const [kind, section] of [
    ["ApplicationRule", "rules"],
    ["CalculatedMember", "calculations"],
    ["ApplicationSequence", "sequences"],
    ["ApplicationSchedule", "schedules"],
  ]) {
    expect(resolveWorkspaceSection("rules", undefined, kind)).toBe(section);
  }
  expect(
    resolveWorkspaceSection("data", undefined, "ApplicationSchedule"),
  ).toBe("import");
  expect(
    resolveWorkspaceSection("rules", "python", "ApplicationSchedule"),
  ).toBe("python");
  expect(workspaceSectionForArtifact("unknown")).toBeUndefined();
});

it("constrains user-supplied sections to the current area", () => {
  expect(resolveWorkspaceSection("data", "python")).toBe("import");
  expect(resolveWorkspaceSection("security", "<script>")).toBe("security");
  expect(resolveWorkspaceSection("administration", "reference")).toBe(
    "reference",
  );
  for (const values of Object.values(workspaceSections)) {
    expect(new Set(values.map((value) => value.id)).size).toBe(values.length);
    expect(values.some((value) => value.id === "reference")).toBe(true);
  }
});

it("opens Python authoring as the normal rules workspace without changing exact artifact links", () => {
  expect(resolveWorkspaceSection("rules")).toBe("python");
  expect(resolveWorkspaceSection("rules", undefined, "ApplicationRule")).toBe(
    "rules",
  );
});
