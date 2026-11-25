import { useLayoutEffect, useRef, useState } from "react";
import {
  ApiError,
  prepareAdmittedProgramEffect,
  replayAdmittedEffect,
  request,
  type AdmittedEffectPacket,
} from "./api";
import type { PythonBuildStatus } from "./python-authoring";
import { pythonOriginalRequestReadBody } from "./python-execution-contract";
import type { ApplicationCatalog, Scope } from "./types";
import { usePreservedDraft, type DraftRecoveryLease } from "./unsaved-work";

const path = "/api/python-build";
const rejected = new Set([
  "APPLICATION_GRANT_REQUIRED",
  "RULE_GRANT_REQUIRED",
  "PROGRAM_VALIDATION_FAILED",
  "PYTHON_BUILD_ARGUMENTS_INVALID",
  "PYTHON_BUILD_PARAMETERS_INVALID",
  "PYTHON_DEFINITION_PARAMETERS_INVALID",
  "PYTHON_BUILD_PINS_INVALID",
  "PYTHON_BUILD_STALE_CONTEXT",
  "PYTHON_PROGRAM_BUILD_SOURCE_UNAVAILABLE",
]);
const buildStates = new Set([
  "accepted",
  "ready",
  "running",
  "sealed",
  "expired",
  "failed",
  "cancel_requested",
  "cancelled",
]);

type OriginalBuild = {
  owner: string;
  packet: AdmittedEffectPacket;
  baseline: { contextKey: string; parameterKey: string; dataRevision: number };
};

export function usePythonEvidenceBuildRequest(
  scope: Scope,
  catalog: ApplicationCatalog,
  programId: string,
  contextKey: string,
  purpose: "Validation" | "ImpactTest",
  onObserved: (
    build: PythonBuildStatus,
    baseline: OriginalBuild["baseline"],
  ) => void,
) {
  const [saved, setSaved] = useState<OriginalBuild | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [missing, setMissing] = useState<"absent" | "expired" | null>(null);
  const active = useRef<AbortController | null>(null);
  const { workspaceId, applicationId } = scope;
  const { issuer, subjectId } = catalog.applicationAccess;
  const owner = JSON.stringify([
    workspaceId,
    applicationId,
    issuer,
    subjectId,
    programId,
  ]);
  const original = saved?.owner === owner ? saved : null;
  const validating = purpose === "Validation";
  const functionName = validating
    ? "python.program.validate"
    : "python.program.test";
  const label = validating ? "validation" : "test";
  const canRequest = Boolean(catalog.functions[functionName]);
  const canRead =
    canRequest || Boolean(catalog.functions["python.program.read"]);
  const recovery = usePreservedDraft(
    workspaceId,
    applicationId,
    `${validating ? "python-source-validation" : "python-impact-test"}:${programId}`,
    `Python ${validating ? "validation" : "impact test"} with an unconfirmed outcome`,
    Boolean(original),
    original,
    setSaved,
  );
  const canRecover = canRead && Boolean(original && recovery.lease);
  const canRetry = canRecover && canRequest && missing === "absent";

  useLayoutEffect(() => {
    setError("");
    setStatus("");
    setMissing(null);
    return () => active.current?.abort();
  }, [contextKey, owner, canRead, canRequest]);

  function start() {
    if (active.current) return null;
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setError("");
    setStatus("");
    return controller;
  }

  function finish(controller: AbortController) {
    if (active.current !== controller) return;
    active.current = null;
    setBusy(false);
  }

  function clear(lease: DraftRecoveryLease) {
    recovery.release(lease, null);
    setSaved(null);
    setMissing(null);
  }

  async function resolve(
    attempt: OriginalBuild,
    lease: DraftRecoveryLease,
    signal: AbortSignal,
    mode: "initial" | "read" | "retry",
  ) {
    try {
      const response =
        mode === "read"
          ? await request<{ result: PythonBuildStatus }>(
              path,
              pythonOriginalRequestReadBody(attempt.packet),
              signal,
            )
          : await replayAdmittedEffect<{ result: PythonBuildStatus }>(
              attempt.packet,
              signal,
            );
      if (signal.aborted) return;
      const result = response?.result;
      const operation = validating ? "Validation" : "Test";
      if (result?.purpose !== purpose)
        throw new Error(`${operation} returned a different build purpose.`);
      if (
        typeof result.buildId !== "string" ||
        !/^[a-f0-9]{32}$/.test(result.buildId) ||
        !buildStates.has(result.status)
      )
        throw new Error(
          `${operation} returned an invalid build identity or status.`,
        );
      clear(lease);
      onObserved(result, attempt.baseline);
    } catch (reason) {
      if (signal.aborted) return;
      if (reason instanceof ApiError) {
        if (
          mode === "read" &&
          reason.status === 400 &&
          reason.code === "PYTHON_BUILD_UNAVAILABLE"
        ) {
          setMissing("absent");
          setStatus(
            canRequest
              ? "The server found no accessible build. You can retry the same request."
              : validating
                ? "The server found no accessible build. Validation requires a current design or publish grant."
                : "The server found no accessible build. Testing requires the current design grant.",
          );
          return;
        }
        if (mode === "retry" && reason.code === "OPERATION_ADMISSION_EXPIRED") {
          setMissing("expired");
          setStatus(
            `The original request expired without an accepted ${label}.`,
          );
          return;
        }
        if (
          [400, 403, 409, 422].includes(reason.status) &&
          ((mode === "initial" && rejected.has(reason.code)) ||
            (mode === "retry" && reason.code === "PYTHON_BUILD_STALE_CONTEXT"))
        ) {
          clear(lease);
          setError(reason.message);
          return;
        }
      }
      setMissing(null);
      setError(
        reason instanceof Error
          ? reason.message
          : `Unable to confirm the original ${label}.`,
      );
    }
  }

  async function submit(
    arguments_: Record<string, unknown>,
    intent: string,
    parameterKey: string,
  ) {
    if (!canRequest || original) return;
    const controller = start();
    if (!controller) return;
    try {
      const packet = await prepareAdmittedProgramEffect(
        path,
        {
          workspaceId,
          applicationId,
          action: "request",
          confirmed: true,
          program: {
            languageVersion: 2,
            function: functionName,
            arguments: arguments_,
          },
        },
        intent,
        controller.signal,
      );
      if (controller.signal.aborted) return;
      const attempt = {
        owner,
        packet,
        baseline: {
          contextKey,
          parameterKey,
          dataRevision: catalog.revisions.data,
        },
      };
      const lease = recovery.retain(attempt);
      setSaved(attempt);
      await resolve(attempt, lease, controller.signal, "initial");
    } catch (reason) {
      if (!controller.signal.aborted)
        setError(
          reason instanceof Error
            ? reason.message
            : `Unable to request the ${label}.`,
        );
    } finally {
      finish(controller);
    }
  }

  async function recover(mode: "read" | "retry") {
    if (
      !canRecover ||
      !original ||
      !recovery.lease ||
      (mode === "retry" && !canRetry)
    )
      return;
    const controller = start();
    if (!controller) return;
    try {
      const lease = recovery.retain(original, recovery.lease);
      await resolve(original, lease, controller.signal, mode);
    } catch (reason) {
      if (!controller.signal.aborted) {
        setMissing(null);
        setError(
          reason instanceof Error
            ? reason.message
            : `Unable to restore the ${label} request.`,
        );
      }
    } finally {
      finish(controller);
    }
  }

  async function copyOriginal() {
    if (!canRecover || !original || active.current) return;
    const reference = pythonOriginalRequestReadBody(original.packet);
    try {
      await navigator.clipboard.writeText(
        JSON.stringify({
          tool: "read_v2_python_program_build",
          arguments: {
            workspace_id: reference.workspaceId,
            application_id: reference.applicationId,
            original_request: reference.originalRequest,
          },
        }),
      );
      setStatus(`Original ${label} lookup copied for MCP.`);
    } catch {
      setError(`The original ${label} lookup could not be copied.`);
    }
  }

  function closeExpired() {
    if (
      !canRecover ||
      missing !== "expired" ||
      active.current ||
      !recovery.lease
    )
      return;
    clear(recovery.lease);
    setStatus(
      validating
        ? "Original request closed. Review the current source before validating again."
        : "Original request closed. Review the current inputs before testing again.",
    );
  }

  return {
    busy,
    pending: Boolean(original),
    canRecover,
    canRetry,
    canRead,
    error: canRead ? error : "",
    status: canRead ? status : "",
    missing,
    submit,
    recover,
    copyOriginal,
    closeExpired,
  };
}
