import { expect, it } from "vitest";
import {
  isDefinitionLifecycle,
  isDefinitionSourceBinding,
} from "./definition-lifecycle";

const inactive = {
  defined: true,
  status: "Inactive",
  valid: true,
  active: false,
  sourceCurrent: true,
  executable: false,
  reason: "inactive",
};

it("rejects coerced or contradictory native lifecycle evidence", () => {
  expect(isDefinitionLifecycle(inactive)).toBe(true);
  for (const status of [
    ["Inactive"],
    { toString: () => "Inactive" },
    null,
    "Saved",
  ])
    expect(isDefinitionLifecycle({ ...inactive, status })).toBe(false);
  for (const patch of [
    { executable: true },
    { active: true },
    { sourceCurrent: false },
    { valid: false },
    { reason: "future_reason" },
    { defined: false },
  ])
    expect(isDefinitionLifecycle({ ...inactive, ...patch })).toBe(false);
});

it("retains Active invalidation independently of technical diagnostic expiry", () => {
  for (const reason of [
    "metadata_stale",
    "schema_stale",
    "dependency_stale",
    "source_environment_stale",
    "compiler_unavailable",
  ]) {
    const owner = {
      ...inactive,
      status: "Active",
      active: true,
      valid: false,
      reason,
    };
    expect(
      isDefinitionLifecycle({ ...owner, validation: { status: "expired" } }),
    ).toBe(true);
    expect(
      isDefinitionLifecycle({ ...owner, validation: { status: "sealed" } }),
    ).toBe(true);
    expect(isDefinitionLifecycle({ ...owner, executable: true })).toBe(false);
  }
});

it("uses the native current source pin and nullable diagnostic build reference", () => {
  const binding = {
    programId: "source",
    programSourceToken: "a".repeat(64),
    sourceDigest: "b".repeat(64),
    buildId: null,
    active: false,
  };
  expect(isDefinitionSourceBinding(binding)).toBe(true);
  const { programSourceToken, ...rest } = binding;
  expect(
    isDefinitionSourceBinding({ ...rest, sourceToken: programSourceToken }),
  ).toBe(false);
  expect(isDefinitionSourceBinding({ ...binding, buildId: undefined })).toBe(
    false,
  );
});
