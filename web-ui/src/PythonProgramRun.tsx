import { useEffect, useLayoutEffect, useRef, useState } from "react";
import {
  request,
  ApiError,
  prepareAdmittedProgramEffect,
  replayAdmittedEffect,
  type AdmittedEffectPacket,
} from "./api";
import { usePreservedDraft } from "./unsaved-work";
import {
  exactWorkflowOutcome,
  terminalWorkflowOutcome,
  workflowUnitCounts,
  workflowCountGuidance,
  workflowStatusLabel,
  type WorkflowOutcome,
} from "./workflow-outcome";
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
  pythonOriginalRequestReadBody,
} from "./python-execution-contract";
import { PythonRuleEditor } from "./PythonRuleEditor";
import { WorkflowCheckpointEvidence } from "./WorkflowCheckpointEvidence";
import { transferAction } from "./data-transfer-action";
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
type Run = WorkflowOutcome & {
  buildId: string;
  receiptId?: string | null;
  diagnostics?: unknown;
  errorCode?: string;
};

type Attempt = {
  identity: string;
  programId: string;
  key: string;
  buildPacket?: AdmittedEffectPacket;
  runPacket?: AdmittedEffectPacket;
  buildBody: ReturnType<typeof pythonBuildRequestBody>;
  runKey: string;
  build?: Plan;
  run?: Run;
  missingOriginal?: "build" | "run";
  complete: boolean;
};

const terminalBuild = (value: Plan) =>
  ["expired", "failed", "cancelled"].includes(value.status);
const terminalRun = terminalWorkflowOutcome;
function exactPlan(value: Plan, prior?: Plan): Plan {
  if (!value || value.purpose !== "Plan")
    throw new Error("Run requires a Plan build.");
  if (
    typeof value.buildId !== "string" ||
    !/^[a-f0-9]{32}$/.test(value.buildId) ||
    ![
      "accepted",
      "ready",
      "running",
      "cancel_requested",
      "sealed",
      "expired",
      "failed",
      "cancelled",
    ].includes(value.status) ||
    (value.status === "sealed" &&
      !/^[a-f0-9]{64}$/.test(value.planDigest || "")) ||
    (prior &&
      (value.buildId !== prior.buildId ||
        (prior.planDigest && value.planDigest !== prior.planDigest) ||
        (terminalBuild(prior) && value.status !== prior.status)))
  )
    throw new Error(
      "The worker returned an invalid or different build identity or purpose.",
    );
  return value;
}
function exactRun(value: Run, build: Plan, prior?: Run): Run {
  try {
    exactWorkflowOutcome(value, prior);
    if (
      value.buildId !== build.buildId ||
      value.planDigest !== build.planDigest
    )
      throw new Error("Different build identity");
  } catch {
    throw new Error(
      "Run returned a different build identity or invalid workflow outcome.",
    );
  }
  return value;
}

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
    declaredOutput?: unknown;
  };
  parameters: string;
  authority: Authority | null;
  onSetupAuthority?: () => void;
  suspended?: boolean;
}) {
  const mutationKey = useStableMutationIntentKey("python-normal-run");
  const identity = JSON.stringify([
    app.workspaceId,
    app.applicationId,
    catalog.applicationAccess.issuer,
    catalog.applicationAccess.subjectId,
  ]);
  // Recovery is scoped to the original attempt, not permission to initiate
  // another Plan from whatever source now occupies this program ID.
  const currentSourceRunnable =
    program.declaredOutput === null &&
    Boolean(catalog.functions["python.program.build"]) &&
    Boolean(catalog.functions["python.program.run"]);
  const currentKey = JSON.stringify([
    authoringContextKey(app, catalog),
    catalog.applicationAccess.role,
    program.programId,
    program.sourceToken,
    program.sourceDigest,
    program.status,
    currentSourceRunnable,
    suspended,
    parameters,
    authority?.delegation_id,
    authority?.state_token,
    authority?.status,
    authority?.operation_scope,
    authority?.valid_from,
    authority?.valid_until,
  ]);
  const current = useRef({
    key: currentKey,
    authority,
    identity,
    programId: program.programId,
  });
  current.current = {
    key: currentKey,
    authority,
    identity,
    programId: program.programId,
  };
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
    currentSourceRunnable &&
    !suspended &&
    active &&
    values !== undefined &&
    activeAuthority(authority) &&
    catalog.revisions.schemaEpoch !== undefined;
  const [attempt, setAttempt] = useState<Attempt | null>(null);
  const [action, setAction] = useState<"continue" | "inspect" | "retry" | null>(
    null,
  );
  const busy = action !== null;
  const [inspected, setInspected] = useState<{
    attemptKey: string;
    contextKey: string;
  } | null>(null);
  const [error, setError] = useState<{ key: string; message: string } | null>(
    null,
  );
  const running = useRef(false);
  const requestSequence = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const mounted = useRef(true);
  const panel = useRef<HTMLElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const runButton = useRef<HTMLButtonElement>(null);
  const reconcileButton = useRef<HTMLButtonElement>(null);
  const executionStatus = useRef<HTMLDivElement>(null);
  const planStatus = useRef<HTMLParagraphElement>(null);
  const actionFocus = useRef<{ context: string; origin: HTMLElement } | null>(
    null,
  );
  const ownAttempt =
    attempt?.identity === identity && attempt.programId === program.programId
      ? attempt
      : null;
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      controller.current?.abort();
    };
  }, []);
  useEffect(() => {
    controller.current?.abort();
    running.current = false;
    setAction(null);
  }, [currentKey]);
  useLayoutEffect(() => {
    const focus = actionFocus.current;
    if (!focus) return;
    const active = document.activeElement;
    const removed =
      !focus.origin.isConnected || focus.origin.matches(":disabled");
    if (
      focus.context !== currentKey ||
      panel.current?.closest("[inert]") ||
      (active !== focus.origin && (active !== document.body || !removed))
    ) {
      actionFocus.current = null;
      return;
    }
    if (removed || (!busy && active === executionStatus.current)) {
      // Only replace focus from an action this request removed or disabled.
      const target =
        (busy ? executionStatus.current : reconcileButton.current) ||
        planStatus.current ||
        (executionStatus.current?.textContent
          ? executionStatus.current
          : null) ||
        (runButton.current?.disabled === false
          ? runButton.current
          : heading.current);
      if (target && target !== active) {
        target.focus();
        focus.origin = target;
      }
    }
    if (!busy) actionFocus.current = null;
  });

  function rememberActionFocus(origin: HTMLButtonElement) {
    actionFocus.current =
      document.activeElement === origin
        ? { context: currentKey, origin }
        : null;
  }

  const recoveryValue = {
    identity,
    programId: program.programId,
    attempt: ownAttempt,
  };
  const recovery = usePreservedDraft(
    app.workspaceId,
    app.applicationId,
    `python-run:${program.programId}`,
    "Original Python execution recovery",
    Boolean(ownAttempt && !ownAttempt.complete),
    recoveryValue,
    (saved) => {
      if (saved.identity === identity && saved.programId === program.programId)
        setAttempt(saved.attempt);
    },
  );

  async function proceed(
    original: Attempt,
    mode: "continue" | "inspect" | "retry",
    origin: HTMLButtonElement,
  ) {
    if (
      running.current ||
      original.complete ||
      original.identity !== identity ||
      original.programId !== program.programId ||
      (mode === "continue" && (original.key !== currentKey || !ready)) ||
      (mode === "retry" &&
        !(
          (original.missingOriginal === "build" &&
            original.buildPacket &&
            !original.build) ||
          (original.missingOriginal === "run" &&
            original.runPacket &&
            !original.run)
        ))
    )
      return;
    rememberActionFocus(origin);
    const work = structuredClone(original);
    let lease =
      ownAttempt?.key === original.key &&
      ownAttempt.identity === original.identity
        ? recovery.lease
        : null;
    const observedKey = currentKey;
    running.current = true;
    const abort = new AbortController();
    controller.current = abort;
    const sameOrigin = () =>
      mounted.current &&
      current.current.identity === work.identity &&
      current.current.programId === work.programId;
    const stillObserved = () => {
      abort.signal.throwIfAborted();
      if (!sameOrigin() || current.current.key !== observedKey)
        throw new Error(
          "Execution context changed. Automatic chaining stopped.",
        );
    };
    const stillCurrent = () => {
      stillObserved();
      if (
        current.current.key !== work.key ||
        !activeAuthority(current.current.authority)
      )
        throw new Error(
          "Execution context changed. Automatic chaining stopped.",
        );
    };
    const revealObservedOutcome = () => {
      stillObserved();
      if (mode !== "continue")
        setInspected({ attemptKey: work.key, contextKey: observedKey });
    };
    const retain = () => {
      const next = {
        identity: work.identity,
        programId: work.programId,
        attempt: { ...work },
      };
      lease = recovery.retain(next, lease);
      if (sameOrigin()) setAttempt({ ...work });
    };
    const settle = () => {
      if (!lease)
        throw new Error(
          "The original execution recovery record is unavailable.",
        );
      work.complete = true;
      recovery.release(lease, {
        identity: work.identity,
        programId: work.programId,
        attempt: { ...work },
      });
      lease = null;
      if (sameOrigin()) setAttempt({ ...work });
    };
    const scope = {
      workspaceId: work.buildBody.workspaceId,
      applicationId: work.buildBody.applicationId,
    };
    const readOriginal = async <T,>(
      packet: AdmittedEffectPacket,
      stage: "build" | "run",
    ) => {
      try {
        return await request<{ result: T }>(
          stage === "build" ? "/api/python-build" : "/api/python-run",
          pythonOriginalRequestReadBody(packet),
          abort.signal,
        );
      } catch (reason) {
        // Only this authenticated reference lookup's exact unavailable result
        // enables an explicit resend. Denials and transport failures do not.
        if (
          reason instanceof ApiError &&
          reason.status === 400 &&
          reason.code ===
            (stage === "build"
              ? "PYTHON_BUILD_UNAVAILABLE"
              : "PYTHON_WORKFLOW_UNAVAILABLE")
        ) {
          work.missingOriginal = stage;
          retain();
        }
        throw reason;
      }
    };
    setAction(mode);
    setError(null);
    if (mode !== "continue") setInspected(null);
    try {
      // A packet may only be replayed with its previously reserved record.
      if ((work.buildPacket || work.runPacket) && !lease)
        throw new Error(
          "The original execution recovery record is unavailable. No request was sent.",
        );
      if (!work.build) {
        const retainedPacket = work.buildPacket;
        if (!work.buildPacket) {
          if (mode !== "continue")
            throw new Error(
              "No original admitted build is available to reconcile.",
            );
          stillCurrent();
          work.buildPacket = await prepareAdmittedProgramEffect(
            "/api/python-build",
            work.buildBody,
            work.buildBody.idempotencyKey,
            abort.signal,
          );
          stillCurrent();
        }
        work.missingOriginal = undefined;
        retain(); // Reserve/rotate before the effect or original-reference read.
        const response =
          retainedPacket && mode !== "retry"
            ? await readOriginal<Plan>(retainedPacket, "build")
            : await replayAdmittedEffect<{ result: Plan }>(
                work.buildPacket,
                abort.signal,
              );
        work.build = exactPlan(response.result);
        retain(); // Capture a known ID even if navigation has stopped chaining.
        revealObservedOutcome();
        if (terminalBuild(work.build)) {
          settle();
          throw new Error(
            work.build.errorCode || `Plan build ${work.build.status}.`,
          );
        }
        if (mode !== "continue") return;
      } else if (mode === "inspect" && !work.run && !work.runPacket) {
        const response = await request<{ result: Plan }>(
          "/api/python-build",
          { ...scope, action: "read", buildId: work.build.buildId },
          abort.signal,
        );
        work.build = exactPlan(response.result, work.build);
        retain();
        revealObservedOutcome();
        if (terminalBuild(work.build)) settle();
        return; // Status recovery never admits a new run.
      }
      let build = work.build!;
      for (let reads = 0; buildIsPending(build); reads += 1) {
        if (reads >= 60)
          throw new Error(
            "The plan is still queued or running. Resume this request to continue checking.",
          );
        stillCurrent();
        const response = await request<{ result: Plan }>(
          "/api/python-build",
          { ...scope, action: "read", buildId: build.buildId },
          abort.signal,
        );
        build = exactPlan(response.result, build);
        work.build = build;
        retain();
        stillCurrent();
        if (buildIsPending(build)) await pause(abort.signal);
      }
      if (terminalBuild(build)) {
        settle();
        throw new Error(build.errorCode || `Plan build ${build.status}.`);
      }
      if (build.status !== "sealed")
        throw new Error("The original Plan is not sealed.");
      if (!work.run) {
        const retainedPacket = work.runPacket;
        if (!work.runPacket) {
          if (mode !== "continue") return;
          stillCurrent();
          work.runPacket = await prepareAdmittedProgramEffect(
            "/api/python-run",
            pythonRunRequestBody(app, build.buildId, work.runKey),
            work.runKey,
            abort.signal,
          );
          stillCurrent();
        }
        work.missingOriginal = undefined;
        retain(); // Atomic prepared-Plan -> exact admitted run transition/read.
        const response =
          retainedPacket && mode !== "retry"
            ? await readOriginal<Run>(retainedPacket, "run")
            : await replayAdmittedEffect<{ result: Run }>(
                work.runPacket,
                abort.signal,
              );
        work.run = exactRun(response.result, build);
        retain();
        revealObservedOutcome();
        if (terminalRun(work.run)) {
          settle();
          return;
        }
        if (mode !== "continue") return;
      } else if (mode === "inspect") {
        const response = await request<{ result: Run }>(
          "/api/python-run",
          { ...scope, action: "read", workflowId: work.run.workflowId },
          abort.signal,
        );
        work.run = exactRun(response.result, build, work.run);
        retain();
        revealObservedOutcome();
        if (terminalRun(work.run)) settle();
        return;
      }
      let run = work.run!;
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
        const response = await request<{ result: Run }>(
          "/api/python-run",
          { ...scope, action: "read", workflowId: run.workflowId },
          abort.signal,
        );
        run = exactRun(response.result, build, run);
        work.run = run;
        retain();
        stillCurrent();
        if (["accepted", "running", "cancel_requested"].includes(run.status))
          await pause(abort.signal);
      }
      if (terminalRun(run)) settle();
      else
        throw new Error(
          "The original workflow needs inspection. It remains retained; inspect its recorded work in Monitor.",
        );
    } catch (reason) {
      if (sameOrigin())
        setError({
          key: work.key,
          message: abort.signal.aborted
            ? "The original request remains retained. Reconcile it before starting another execution."
            : reason instanceof Error
              ? reason.message
              : "Unable to continue this execution request.",
        });
      // Even an initial run denial can follow durable acceptance. Keep its
      // exact packet; a later denial never proves that no workflow exists.
    } finally {
      if (controller.current === abort) {
        running.current = false;
        if (sameOrigin()) setAction(null);
      }
    }
  }

  function leavePlanUnrun(origin: HTMLButtonElement) {
    if (
      !ownAttempt?.build ||
      ownAttempt.build.status !== "sealed" ||
      ownAttempt.runPacket ||
      ownAttempt.run ||
      busy ||
      !recovery.lease
    )
      return;
    rememberActionFocus(origin);
    try {
      recovery.release(recovery.lease, {
        identity,
        programId: program.programId,
        attempt: null,
      });
      setAttempt(null);
      setError(null);
    } catch (reason) {
      setError({
        key: ownAttempt.key,
        message: reason instanceof Error ? reason.message : String(reason),
      });
    }
  }

  function run(origin: HTMLButtonElement) {
    if (
      !ready ||
      !values ||
      !authority ||
      busy ||
      (ownAttempt && !ownAttempt.complete)
    )
      return;
    // A retry retains both original mutation identities. Only an explicit Run
    // action can advance this sequence.
    const buildKey = mutationKey({
      operation: "build",
      key: currentKey,
      request: ++requestSequence.current,
    });
    const work: Attempt = {
      identity,
      programId: program.programId,
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
    void proceed(work, "continue", origin);
  }
  const currentAttempt = ownAttempt?.key === currentKey;
  const inspectedAttempt =
    ownAttempt &&
    inspected?.attemptKey === ownAttempt.key &&
    inspected.contextKey === currentKey;
  const diagnostics = currentAttempt
    ? pythonDiagnostics(attempt?.run?.diagnostics) ||
      pythonDiagnostics(attempt?.build?.diagnostics)
    : undefined;
  const pendingAttempt = Boolean(ownAttempt && !ownAttempt.complete);
  const outcomeUnconfirmed =
    ownAttempt &&
    !busy &&
    !ownAttempt.missingOriginal &&
    ((ownAttempt.runPacket && !ownAttempt.run) ||
      (ownAttempt.buildPacket && !ownAttempt.build));
  const observedRun =
    currentAttempt || inspectedAttempt ? ownAttempt?.run : undefined;
  let statusText = "";
  if (action === "inspect") statusText = "Checking the original execution…";
  else if (action === "retry") statusText = "Retrying the original request…";
  else if (action === "continue" && (!observedRun || ownAttempt?.complete)) {
    const build = ownAttempt?.complete ? undefined : ownAttempt?.build;
    statusText = !build
      ? "Submitting plan build…"
      : build.status === "sealed"
        ? "Submitting workflow…"
        : "Preparing plan…";
  } else if (observedRun)
    statusText = `${currentAttempt ? "Run" : "Original run"}: ${workflowStatusLabel(observedRun.status)} · ${workflowUnitCounts(observedRun)}`;
  else if (outcomeUnconfirmed)
    statusText =
      "Outcome unconfirmed. Check the original execution before trying again.";
  if (!currentSourceRunnable && !ownAttempt) return null;
  return (
    <section
      ref={panel}
      aria-label={
        currentSourceRunnable
          ? "Run current saved Python source"
          : "Recover original Python execution"
      }
      className="python-program-run"
    >
      {currentSourceRunnable ? (
        <>
          <h4 tabIndex={-1} ref={heading}>
            Run current saved source
          </h4>
          <p>
            Build a fresh Plan from the current active saved source, then
            execute that exact sealed Plan under the selected execution
            authority. Resuming an interrupted request keeps its original build
            and run identities.
          </p>
          {!active && <p>Activate this source before running it.</p>}
          {!activeAuthority(authority) && (
            <p>
              A current execution authority with build and run permission is
              required.{" "}
              {onSetupAuthority && (
                <button onClick={onSetupAuthority}>
                  Open execution authorities
                </button>
              )}
            </p>
          )}
          {!values && <p role="alert">{parameterError}</p>}
          <button
            ref={runButton}
            disabled={!ready || (!busy && pendingAttempt)}
            {...transferAction(!ready || busy || pendingAttempt, run)}
          >
            {currentAttempt && attempt?.complete
              ? "Run again"
              : "Run current saved source"}
          </button>
        </>
      ) : (
        <>
          <h4 tabIndex={-1} ref={heading}>
            Original execution recovery
          </h4>
          <p>
            Starting a Plan from the current source is unavailable. The original
            attempt remains separate; reconciliation checks its exact request or
            recorded status under your current access.
          </p>
        </>
      )}
      {ownAttempt && !currentAttempt && (
        <p role="status">
          Automatic chaining stopped for the previous editor context. Any
          accepted work remains in Monitor; inspect it in its original
          application before starting another run. Its result does not describe
          this context.
        </p>
      )}
      <div role="status" aria-atomic="true" tabIndex={-1} ref={executionStatus}>
        {statusText}
      </div>
      {ownAttempt && currentAttempt && (
        <div aria-label="Python execution progress">
          <p>
            Accepted work remains available in Monitor. This tab preserves the
            original request when you navigate away; reload or sign out clears
            local recovery.
          </p>
          {ownAttempt.build && (
            <p
              tabIndex={ownAttempt.run ? undefined : -1}
              ref={ownAttempt.run ? undefined : planStatus}
            >
              Plan: {ownAttempt.build.status}
            </p>
          )}
          {ownAttempt.run && (
            <>
              <p>{workflowCountGuidance(ownAttempt.run.status)}</p>
              <WorkflowCheckpointEvidence
                key={JSON.stringify([currentKey, ownAttempt.run.workflowId])}
                workflow={ownAttempt.run}
                scope={app}
                catalog={catalog}
              />
            </>
          )}
          {!ownAttempt.complete && (
            <button
              disabled={!ready}
              {...transferAction(!ready || busy, (origin) =>
                proceed(ownAttempt, "continue", origin),
              )}
            >
              Resume exact execution request
            </button>
          )}
        </div>
      )}
      {ownAttempt && !currentAttempt && inspectedAttempt && (
        <div aria-label="Reconciled original execution">
          <p>
            This result belongs to the original saved source and parameters, not
            the current editor context.
          </p>
          {ownAttempt.build && (
            <p
              tabIndex={ownAttempt.run ? undefined : -1}
              ref={ownAttempt.run ? undefined : planStatus}
            >
              Original Plan: {ownAttempt.build.status}
            </p>
          )}
          {ownAttempt.run && (
            <>
              <p>{workflowCountGuidance(ownAttempt.run.status)}</p>
              <WorkflowCheckpointEvidence
                key={JSON.stringify([currentKey, ownAttempt.run.workflowId])}
                workflow={ownAttempt.run}
                scope={app}
                catalog={catalog}
              />
            </>
          )}
        </div>
      )}
      {ownAttempt && !ownAttempt.complete && (
        <section aria-label="Original execution recovery">
          <p>
            This tab retains the original request. Reconciliation reads its
            recorded build or run, even when the acknowledgement was lost. It
            never starts a different build or a new run.
          </p>
          <button
            ref={reconcileButton}
            {...transferAction(busy, (origin) =>
              proceed(ownAttempt, "inspect", origin),
            )}
          >
            Reconcile original execution
          </button>
          {ownAttempt.missingOriginal && (
            <>
              <p role="status">
                No original {ownAttempt.missingOriginal} was found. You can
                retry the same request; the server will check its expiry and
                your current access.
              </p>
              <button
                {...transferAction(busy, (origin) =>
                  proceed(ownAttempt, "retry", origin),
                )}
              >
                Retry original request
              </button>
            </>
          )}
          {ownAttempt.build?.status === "sealed" &&
            !ownAttempt.runPacket &&
            !ownAttempt.run && (
              <>
                <p>
                  The original sealed Plan remains recorded. Leaving it unrun
                  clears only this tab's pending execution intent.
                </p>
                <button {...transferAction(busy, leavePlanUnrun)}>
                  Leave this Plan unrun
                </button>
              </>
            )}
          {!currentAttempt && error?.key === ownAttempt.key && (
            <p role="alert">{error.message}</p>
          )}
        </section>
      )}
      {error?.key === currentKey && <p role="alert">{error.message}</p>}
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
