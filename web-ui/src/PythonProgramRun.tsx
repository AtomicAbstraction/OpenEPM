import { useEffect, useRef, useState } from "react";
import { request, requestAdmittedEffect } from "./api";
import { InexactParameterNumber, parseParameterJson } from "./exact-parameters";
import { useStableMutationIntentKey } from "./mutation-intent";
import {
  authoringContextKey,
  buildIsPending,
  pythonDiagnostics,
} from "./python-authoring";
import type { PythonBuildStatus } from "./python-authoring";
import {
  pythonBuildRequestBody,
  pythonRunRequestBody,
} from "./python-execution-contract";
import { PythonRuleEditor } from "./PythonRuleEditor";
import type { ApplicationCatalog, ApplicationSummary } from "./types";

type Authority = {
  delegation_id: string;
  state_token: string;
  status: "Active" | "Revoked";
  operation_scope: string[];
  valid_from: string;
  valid_until: string;
};
type Plan = PythonBuildStatus & { planDigest?: string };
type Run = {
  workflowId: string;
  buildId: string;
  status: string;
  unitCount?: number;
  committedUnits?: number;
  remainingUnits?: number;
  receiptId?: string | null;
  diagnostics?: unknown;
  errorCode?: string;
};
type Attempt = {
  key: string;
  buildBody: ReturnType<typeof pythonBuildRequestBody>;
  runKey: string;
  build?: Plan;
  run?: Run;
  complete: boolean;
};
function activeAuthority(authority: Authority | null) {
  return Boolean(
    authority &&
      authority.status === "Active" &&
      /^[0-9a-f]{64}$/.test(authority.state_token) &&
      ["python.program.build", "python.program.run"].every((operation) =>
        authority.operation_scope.includes(operation),
      ) &&
      Date.parse(authority.valid_from) <= Date.now() &&
      Date.parse(authority.valid_until) > Date.now(),
  );
}
function pause(signal: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    const abort = () => {
      clearTimeout(timer);
      reject(new DOMException("Stopped", "AbortError"));
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", abort);
      resolve();
    }, 2000);
    signal.addEventListener("abort", abort, { once: true });
    if (signal.aborted) abort();
  });
}

/** Run is a durable Plan build followed by a run of that exact sealed identity.
 * The browser retains request identities through transport failures; it never
 * treats retry as permission to create another build or another run. */
export function PythonProgramRun({
  app,
  catalog,
  program,
  parameters,
  authority,
  onSetupAuthority,
  suspended = false,
}: {
  app: ApplicationSummary;
  catalog: ApplicationCatalog;
  program: {
    programId: string;
    sourceToken: string;
    status: string;
    sourceDigest: string;
    sourceText: string;
  };
  parameters: string;
  authority: Authority | null;
  onSetupAuthority: () => void;
  suspended?: boolean;
}) {
  const mutationKey = useStableMutationIntentKey("python-normal-run");
  const currentKey = JSON.stringify([
    authoringContextKey(app, catalog),
    program.programId,
    program.sourceToken,
    program.sourceDigest,
    program.status,
    suspended,
    parameters,
    authority?.delegation_id,
    authority?.state_token,
    authority?.operation_scope,
    authority?.valid_from,
    authority?.valid_until,
  ]);
  const current = useRef({ key: currentKey, authority });
  current.current = { key: currentKey, authority };
  const active = program.status === "Active";
  let values: Record<string, unknown> | undefined;
  let parameterError = "Program parameters must be a JSON object.";
  try {
    const parsed = parseParameterJson(parameters);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed))
      values = parsed as Record<string, unknown>;
  } catch (error) {
    if (error instanceof InexactParameterNumber) parameterError = error.message;
  }
  const ready =
    !suspended &&
    active &&
    values !== undefined &&
    activeAuthority(authority) &&
    catalog.revisions.schemaEpoch !== undefined;
  const [attempt, setAttempt] = useState<Attempt | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const running = useRef(false);
  const requestSequence = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      controller.current?.abort();
    };
  }, []);
  useEffect(() => {
    controller.current?.abort();
  }, [currentKey]);

  async function proceed(work: Attempt) {
    if (running.current || work.complete || work.key !== currentKey || !ready)
      return;
    running.current = true;
    const abort = new AbortController();
    controller.current = abort;
    const publish = () => {
      if (mounted.current) setAttempt({ ...work });
    };
    const stillCurrent = () => {
      abort.signal.throwIfAborted();
      if (
        current.current.key !== work.key ||
        !activeAuthority(current.current.authority)
      )
        throw new Error(
          "Execution context changed. Automatic chaining stopped.",
        );
    };
    setBusy(true);
    setError("");
    publish();
    try {
      if (!work.build) {
        stillCurrent();
        const response = await requestAdmittedEffect<{ result: Plan }>(
          "/api/python-build",
          work.buildBody,
          abort.signal,
        );
        stillCurrent();
        if (response.result.purpose !== "Plan" || !response.result.buildId)
          throw new Error("Run requires a Plan build.");
        work.build = response.result;
        publish();
      }
      let build: Plan = work.build!;
      let run: Run | undefined = work.run;
      for (let reads = 0; buildIsPending(build); reads += 1) {
        if (reads >= 60)
          throw new Error(
            "The plan is still queued or running. Resume this request to continue checking.",
          );
        stillCurrent();
        const response = await request<{ result: Plan }>(
          "/api/python-build",
          {
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            action: "read",
            buildId: build.buildId,
          },
          abort.signal,
        );
        stillCurrent();
        if (
          response.result.buildId !== build.buildId ||
          response.result.purpose !== "Plan"
        )
          throw new Error(
            "The worker returned a different build identity or purpose.",
          );
        build = response.result;
        work.build = build;
        publish();
        if (buildIsPending(build)) await pause(abort.signal);
      }
      if (
        build.status !== "sealed" ||
        !/^[a-f0-9]{64}$/.test(build.planDigest || "")
      ) {
        work.complete = true;
        publish();
        throw new Error(build.errorCode || `Plan build ${build.status}.`);
      }
      if (!run) {
        stillCurrent();
        const response: { result: Run } = await requestAdmittedEffect<{
          result: Run;
        }>(
          "/api/python-run",
          pythonRunRequestBody(app, build.buildId, work.runKey),
          abort.signal,
        );
        stillCurrent();
        if (
          response.result.buildId !== build.buildId ||
          !response.result.workflowId
        )
          throw new Error("Run returned a different build identity.");
        run = response.result;
        work.run = run;
        publish();
      }
      if (!run) throw new Error("Run identity is unavailable.");
      for (
        let reads = 0;
        ["accepted", "running", "cancel_requested"].includes(run.status);
        reads += 1
      ) {
        if (reads >= 60)
          throw new Error(
            "The workflow is still running. Resume this request to continue checking.",
          );
        stillCurrent();
        const response: { result: Run } = await request<{ result: Run }>(
          "/api/python-run",
          {
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            action: "read",
            workflowId: run.workflowId,
          },
          abort.signal,
        );
        stillCurrent();
        if (
          response.result.workflowId !== run.workflowId ||
          response.result.buildId !== build.buildId
        )
          throw new Error("The server returned a different workflow identity.");
        run = response.result;
        work.run = run;
        publish();
        if (["accepted", "running", "cancel_requested"].includes(run.status))
          await pause(abort.signal);
      }
      work.complete = true;
      publish();
    } catch (reason) {
      if (mounted.current)
        setError(
          abort.signal.aborted
            ? "Automatic chaining stopped because source, parameters, activation or application context changed. Any accepted task remains recorded."
            : reason instanceof Error
              ? reason.message
              : "Unable to continue this execution request.",
        );
    } finally {
      running.current = false;
      if (mounted.current) setBusy(false);
    }
  }

  function run(again = false) {
    if (
      !ready ||
      !values ||
      !authority ||
      busy ||
      (attempt?.key === currentKey && !(again && attempt.complete))
    )
      return;
    // Only another explicit Run action advances this sequence. A retry uses
    // proceed(attempt), retaining both original mutation identities.
    const buildKey = mutationKey({
      operation: "build",
      key: currentKey,
      request: ++requestSequence.current,
    });
    const work: Attempt = {
      key: currentKey,
      buildBody: pythonBuildRequestBody(
        app,
        catalog,
        program,
        values,
        authority.delegation_id,
        authority.state_token,
        buildKey,
      ),
      runKey: mutationKey({ operation: "run", buildKey }),
      complete: false,
    };
    void proceed(work);
  }
  const currentAttempt = attempt?.key === currentKey;
  const diagnostics = currentAttempt
    ? pythonDiagnostics(attempt?.run?.diagnostics) ||
      pythonDiagnostics(attempt?.build?.diagnostics)
    : undefined;
  return (
    <section
      aria-label="Run active Python version"
      className="python-program-run"
    >
      <h4>Run this version</h4>
      <p>
        Build a fresh plan for the active version, then execute that exact plan
        under the selected execution authority.
      </p>
      {!active && <p>Activate this source before running it.</p>}
      {!activeAuthority(authority) && (
        <p>
          Read an execution authority with build and run permission in Advanced
          execution controls.{" "}
          <button onClick={onSetupAuthority}>Set up execution authority</button>
        </p>
      )}
      {!values && <p role="alert">{parameterError}</p>}
      <button
        disabled={
          !ready || busy || Boolean(currentAttempt && !attempt?.complete)
        }
        onClick={() => run(Boolean(currentAttempt && attempt?.complete))}
      >
        {currentAttempt && attempt?.complete
          ? "Run again"
          : "Run active version"}
      </button>
      {attempt && (
        <div aria-label="Python execution progress">
          <p>
            Accepted work remains available in Monitor. After leaving this
            editor, inspect the recorded build or workflow before starting
            another run.
          </p>
          {busy && (
            <p role="status">
              {attempt.run
                ? "Running workflow…"
                : attempt.build
                  ? "Preparing plan…"
                  : "Submitting plan build…"}
            </p>
          )}
          {attempt.build && <p>Plan: {attempt.build.status}</p>}
          {attempt.run && (
            <p role="status">
              Run: {attempt.run.status} · {attempt.run.committedUnits ?? 0}{" "}
              committed units ·{" "}
              {attempt.run.remainingUnits ??
                Math.max(
                  0,
                  (attempt.run.unitCount ?? 0) -
                    (attempt.run.committedUnits ?? 0),
                )}{" "}
              remaining units
            </p>
          )}
          {!busy && !attempt.complete && currentAttempt && (
            <button disabled={!ready} onClick={() => void proceed(attempt)}>
              Resume exact execution request
            </button>
          )}
        </div>
      )}
      {error && <p role="alert">{error}</p>}
      {diagnostics && (
        <PythonRuleEditor
          ariaLabel="Execution Python source"
          value={program.sourceText}
          onChange={() => undefined}
          readOnly
          diagnostics={diagnostics}
        />
      )}
    </section>
  );
}
