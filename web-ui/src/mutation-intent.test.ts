import { expect, it, vi } from "vitest";
import { StableMutationIntentKeys } from "./mutation-intent";

it("reuses keys for canonically identical intent and rotates for changes", () => {
  let sequence = 0;
  vi.stubGlobal("crypto", { randomUUID: () => `uuid-${++sequence}` });
  const keys = new StableMutationIntentKeys("ui");
  const first = keys.key({ function: "save", args: { b: 2, a: 1 } });
  expect(keys.key({ args: { a: 1, b: 2 }, function: "save" })).toBe(first);
  expect(keys.key({ function: "save", args: { a: 2, b: 2 } })).not.toBe(first);
  vi.unstubAllGlobals();
});

it("bounds retained intent signatures", () => {
  let sequence = 0;
  vi.stubGlobal("crypto", { randomUUID: () => `uuid-${++sequence}` });
  const keys = new StableMutationIntentKeys("ui", 2);
  const first = keys.key({ value: 1 });
  keys.key({ value: 2 });
  keys.key({ value: 3 });
  expect(keys.key({ value: 1 })).not.toBe(first);
  vi.unstubAllGlobals();
});
