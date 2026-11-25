import "@testing-library/jest-dom/vitest";
import { afterEach } from "vitest";
import { resetOperationAdmissionsForTests } from "./api";
import { resetUnsavedWorkForTests } from "./unsaved-work";

const browserIdentityBindings = new Map<string, string>();

// jsdom implements the open attribute. Modal focus and isolation run in Chromium.
if (
  typeof HTMLDialogElement !== "undefined" &&
  typeof HTMLDialogElement.prototype.showModal !== "function"
) {
  HTMLDialogElement.prototype.showModal = function () {
    this.open = true;
  };
  HTMLDialogElement.prototype.close = function () {
    this.open = false;
  };
}

afterEach(() => {
  resetUnsavedWorkForTests();
  resetOperationAdmissionsForTests();
  browserIdentityBindings.clear();
});

export function browserIdentityFixture(
  subject: string,
  issuer = "https://identity.example",
) {
  const key = JSON.stringify([issuer, subject]);
  const binding =
    browserIdentityBindings.get(key) ??
    (browserIdentityBindings.size + 1).toString(16).padStart(64, "0");
  browserIdentityBindings.set(key, binding);
  return { subject, issuer, identityBinding: binding };
}

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
