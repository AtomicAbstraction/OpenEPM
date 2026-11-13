import "@testing-library/jest-dom/vitest";
import { afterEach } from "vitest";
import { resetOperationAdmissionsForTests } from "./api";
import { resetUnsavedWorkForTests } from "./unsaved-work";

afterEach(() => {
  resetUnsavedWorkForTests();
  resetOperationAdmissionsForTests();
});

export function operationAdmissionResponse(seed = "a"): Response {
  const character = /^[0-9a-f]$/.test(seed) ? seed : "a";
  return new Response(
    JSON.stringify({
      operationId: `oa1_zz_${character.repeat(32)}_${"A".repeat(43)}`,
      expiresAt: Math.floor(Date.now() / 1000) + 900,
      intentDigest: character.repeat(64),
    }),
  );
}

export function installOperationAdmissionFixture(seed = "a") {
  const delegate = globalThis.fetch;
  let next = Number.parseInt(seed, 16);
  if (!Number.isInteger(next)) next = 10;
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit) =>
    String(input) === "/api/operation-admission"
      ? operationAdmissionResponse((((next++ % 16) + 16) % 16).toString(16))
      : delegate(input, init);
}
