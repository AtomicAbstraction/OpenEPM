import type { ApplicationCatalog } from "./types";

const WORKFLOW_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,299}$/;
const APPLICATION_RULE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const FUNCTION = /^[a-z][a-z0-9_.-]{0,127}$/;
const DIGEST = /^[0-9a-f]{64}$/;

export type WorkflowDestinationResolution =
  | {
      supported: true;
      page: "grid";
      focus: { viewId: string; viewVersion: number; viewDigest: string };
    }
  | {
      supported: true;
      page: "rules";
      focus: {
        artifactKind:
          | "ApplicationRule"
          | "CalculatedMember"
          | "ApplicationSequence"
          | "ApplicationSchedule";
        artifactId: string;
        artifactVersion: number;
        artifactDigest: string;
      };
    }
  | { supported: false; code: string; message: string };

function object(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, keys: string[]) {
  return (
    Object.keys(value).sort().join("\u0000") === keys.sort().join("\u0000")
  );
}

export function resolveWorkflowDestination(
  destination: unknown,
  catalog: ApplicationCatalog | null,
): WorkflowDestinationResolution {
  if (!object(destination) || typeof destination.kind !== "string")
    return {
      supported: false,
      code: "WORKFLOW_DESTINATION_INVALID",
      message: "This workflow destination is malformed and was not opened.",
    };
  if (destination.kind === "CubeView") {
    if (
      !exactKeys(destination, ["kind", "viewId", "version", "digest"]) ||
      typeof destination.viewId !== "string" ||
      !WORKFLOW_IDENTIFIER.test(destination.viewId) ||
      !Number.isSafeInteger(destination.version) ||
      Number(destination.version) < 1 ||
      typeof destination.digest !== "string" ||
      !DIGEST.test(destination.digest)
    )
      return {
        supported: false,
        code: "WORKFLOW_CUBE_VIEW_DESTINATION_INVALID",
        message:
          "This workflow cube-view destination does not contain an exact immutable view identity.",
      };
    if (!catalog?.functions["grid.definition.read"])
      return {
        supported: false,
        code: "WORKFLOW_CUBE_VIEW_DESTINATION_UNAUTHORIZED",
        message:
          "The current role cannot inspect the configured immutable cube view.",
      };
    return {
      supported: true,
      page: "grid",
      focus: {
        viewId: destination.viewId,
        viewVersion: Number(destination.version),
        viewDigest: destination.digest,
      },
    };
  }
  if (destination.kind === "Function") {
    if (
      !exactKeys(destination, ["kind", "function", "argumentsDigest"]) ||
      typeof destination.function !== "string" ||
      !FUNCTION.test(destination.function) ||
      typeof destination.argumentsDigest !== "string" ||
      !DIGEST.test(destination.argumentsDigest)
    )
      return {
        supported: false,
        code: "WORKFLOW_FUNCTION_DESTINATION_INVALID",
        message:
          "This workflow function destination is malformed and was not opened.",
      };
    if (!catalog?.functions[destination.function])
      return {
        supported: false,
        code: "WORKFLOW_FUNCTION_DESTINATION_UNAUTHORIZED",
        message: `The current role cannot use ${destination.function}.`,
      };
    return {
      supported: false,
      code: "WORKFLOW_FUNCTION_DESTINATION_NOT_INSPECTABLE",
      message: `The configured ${destination.function} destination is bound only by its arguments digest. The current contract does not disclose an artifact ID and immutable version, so Open EPM will not guess which rule, sequence, schedule, calculation, or request to open.`,
    };
  }
  if (destination.kind === "Artifact") {
    if (
      !exactKeys(destination, [
        "kind",
        "artifactKind",
        "artifactId",
        "version",
        "digest",
      ]) ||
      ![
        "ApplicationRule",
        "CalculatedMember",
        "ApplicationSequence",
        "ApplicationSchedule",
      ].includes(String(destination.artifactKind)) ||
      typeof destination.artifactId !== "string" ||
      !APPLICATION_RULE_ID.test(destination.artifactId) ||
      !Number.isSafeInteger(destination.version) ||
      Number(destination.version) < 1 ||
      typeof destination.digest !== "string" ||
      !DIGEST.test(destination.digest)
    )
      return {
        supported: false,
        code: "WORKFLOW_ARTIFACT_DESTINATION_INVALID",
        message:
          "This workflow artifact destination is unsupported or malformed.",
      };
    const readFunctions = {
      ApplicationRule: "application.rule.version.read",
      CalculatedMember: "calculated.member.version.read",
      ApplicationSequence: "rules.numeric_sequence.version.read",
      ApplicationSchedule: "schedule.version.read",
    } as const;
    const artifactKind = destination.artifactKind as keyof typeof readFunctions;
    const readFunction = readFunctions[artifactKind];
    if (!catalog?.functions[readFunction])
      return {
        supported: false,
        code: "WORKFLOW_ARTIFACT_DESTINATION_UNAUTHORIZED",
        message:
          "The current role cannot inspect the configured immutable artifact.",
      };
    return {
      supported: true,
      page: "rules",
      focus: {
        artifactKind,
        artifactId: destination.artifactId,
        artifactVersion: Number(destination.version),
        artifactDigest: destination.digest,
      },
    };
  }
  return {
    supported: false,
    code: "WORKFLOW_DESTINATION_KIND_UNSUPPORTED",
    message: `Destination kind ${destination.kind} is not supported by this release.`,
  };
}
