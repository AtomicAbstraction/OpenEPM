import { useEffect, useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import { request } from "./api";
import type { Scope } from "./types";
import { buildIsPending } from "./python-authoring";
import type { PythonBuildStatus } from "./python-authoring";

export type PythonBuildObservation = {
  build: PythonBuildStatus;
  contextKey: string;
};

/** A bounded, cancellable observer. Validation and ImpactTest never become Plan authority. */
export function usePythonBuildObserver(
  scope: Scope | undefined,
  contextKey: string,
  observation: PythonBuildObservation | null,
  purpose: "Validation" | "ImpactTest",
  onChange: Dispatch<SetStateAction<PythonBuildObservation | null>>,
  sourceProgramId?: string | null,
) {
  const [error, setError] = useState("");
  const [refresh, setRefresh] = useState(0);
  const current =
    observation?.contextKey === contextKey &&
    observation.build.purpose === purpose &&
    observation.build.current !== false;
  useEffect(() => {
    setError("");
    if (
      !scope ||
      sourceProgramId === null ||
      !observation ||
      !current ||
      !buildIsPending(observation.build)
    )
      return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let reads = 0;
    const poll = async () => {
      try {
        const build = sourceProgramId
          ? (
              await request<{
                result: { validation?: PythonBuildStatus | null };
              }>(
                "/api/python-program",
                {
                  workspaceId: scope.workspaceId,
                  applicationId: scope.applicationId,
                  program: {
                    languageVersion: 2,
                    function: "python.program.read",
                    arguments: { programId: sourceProgramId },
                  },
                },
                controller.signal,
              )
            ).result.validation
          : (
              await request<{ result: PythonBuildStatus }>(
                "/api/python-build",
                {
                  workspaceId: scope.workspaceId,
                  applicationId: scope.applicationId,
                  action: "read",
                  buildId: observation.build.buildId,
                },
                controller.signal,
              )
            ).result;
        if (controller.signal.aborted) return;
        if (
          !build ||
          build.buildId !== observation.build.buildId ||
          build.purpose !== purpose
        )
          throw new Error(
            "The worker returned a different build identity or purpose.",
          );
        onChange({
          build,
          contextKey: observation.contextKey,
        });
        if (buildIsPending(build)) {
          if (++reads < 60) timer = setTimeout(() => void poll(), 2000);
          else
            setError(
              "Work is still queued or running. Refresh its status to continue checking.",
            );
        }
      } catch (reason) {
        if (!controller.signal.aborted)
          setError(
            reason instanceof Error
              ? reason.message
              : "Unable to read build status.",
          );
      }
    };
    void poll();
    return () => {
      controller.abort();
      if (timer) clearTimeout(timer);
    };
  }, [
    contextKey,
    observation?.build.buildId,
    current,
    purpose,
    refresh,
    sourceProgramId,
  ]);
  return { current, error, refresh: () => setRefresh((value) => value + 1) };
}
