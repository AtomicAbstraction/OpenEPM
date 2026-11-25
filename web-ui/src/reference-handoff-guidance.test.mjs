// @vitest-environment node
// This filesystem-bound publication check runs in Node, outside the browser TypeScript project.
import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import {
  parseReferenceHandoff,
  referenceHandoffHash,
} from "./reference-handoff.ts";

it("accepts the portable example in the actual published client guidance", () => {
  const example = readFileSync(
    new URL(
      "../../docs/skills/multidimensional-cube-harness/SKILL.md",
      import.meta.url,
    ),
    "utf8",
  ).match(/<!-- reference-handoff-example -->\s*```json\s*([\s\S]*?)```/);
  expect(example).not.toBeNull();
  const parsed = parseReferenceHandoff(example[1]);
  expect(parsed.target).toEqual({
    kind: "savedView",
    viewId: "capacity-by-team",
  });
  const hash = referenceHandoffHash(parsed);
  expect(
    parseReferenceHandoff(
      new URLSearchParams(hash.split("?")[1]).get("handoff"),
    ),
  ).toEqual(parsed);
});
