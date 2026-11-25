import { useLayoutEffect, useRef, useState } from "react";
import {
  ApiError,
  prepareAdmittedProgramEffect,
  readProgram,
  replayAdmittedEffect,
  request,
  type AdmittedEffectPacket,
} from "./api";
import type { ApplicationCatalog, Scope } from "./types";
import { usePreservedDraft, type DraftRecoveryLease } from "./unsaved-work";
import { copyOperationReceiptCheck } from "./ReceiptInspector";

export type GovernedEffectBody = Scope & {
  program: Record<string, unknown>;
  idempotencyKey: string;
  confirmed?: boolean;
};
type OriginalChange<Details> = {
  owner: string;
  packet: AdmittedEffectPacket;
  // Versioned controls use their current state as the server fence. Keep the
  // existing local packet shape while omitting its local key on dispatch.
  stateControl?: true;
  details: Details;
};
type Protocol<Details, Result> = {
  path: string;
  tool?: string;
  editor: string;
  pendingLabel: string;
  functions: readonly string[];
  subject: string;
  closePrompt: string;
  initialRefusal: (reason: unknown) => boolean;
  result: (reply: unknown, original: OriginalChange<Details>) => Result | null;
  receiptResult?: (
    receipt: unknown,
    original: OriginalChange<Details>,
  ) => Result | null | Promise<Result | null>;
  stateRead?: {
    functionName: string;
    arguments: (details: Details) => Record<string, unknown>;
    reconcile: (
      reply: unknown,
      details: Details,
    ) => { result: Result } | { unchanged: true } | null;
  };
};

const receiptFunction = "application.operation.receipt.read";

export function useGovernedEffectRecovery<Details, Result>(
  scope: Scope | undefined,
  catalog: ApplicationCatalog | null,
  context: string,
  protocol: Protocol<Details, Result>,
  onRecorded: (details: Details, result: Result) => void,
) {
  const [saved, setSaved] = useState<OriginalChange<Details> | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [receiptMissing, setReceiptMissing] = useState(false);
  const [admissionExpired, setAdmissionExpired] = useState(false);
  const active = useRef<AbortController | null>(null);
  const owner =
    scope && catalog
      ? JSON.stringify([
          scope.workspaceId,
          scope.applicationId,
          catalog.applicationAccess.issuer,
          catalog.applicationAccess.subjectId,
          protocol.editor,
        ])
      : "";
  const original = owner && saved?.owner === owner ? saved : null;
  const recovery = usePreservedDraft(
    scope?.workspaceId || "",
    scope?.applicationId || "",
    protocol.editor,
    protocol.pendingLabel,
    Boolean(original),
    original,
    setSaved,
  );
  const canRetry = Boolean(
    original &&
      catalog?.functions[String(original.packet.body.program.function)],
  );
  const canCheckReceipt = Boolean(
    original &&
      (protocol.stateRead
        ? catalog?.functions[protocol.stateRead.functionName]
        : protocol.receiptResult && catalog?.functions[receiptFunction]),
  );
  const useReadRecovery = Boolean(protocol.receiptResult || protocol.stateRead);
  const retryReady =
    canRetry &&
    Boolean(recovery.lease) &&
    (!useReadRecovery || (receiptMissing && !admissionExpired));
  const canCloseRecovery =
    canRetry &&
    Boolean(recovery.lease) &&
    receiptMissing &&
    (!useReadRecovery || admissionExpired);
  const accessKey = [
    ...protocol.functions,
    ...(protocol.receiptResult ? [receiptFunction] : []),
    ...(protocol.stateRead ? [protocol.stateRead.functionName] : []),
  ]
    .map((name) => Boolean(catalog?.functions[name]))
    .join(":");

  useLayoutEffect(() => {
    setMessage("");
    setReceiptMissing(false);
    return () => active.current?.abort();
  }, [context, owner, accessKey]);

  useLayoutEffect(() => setAdmissionExpired(false), [owner]);

  function start() {
    if (active.current) return null;
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setMessage("");
    setReceiptMissing(false);
    return controller;
  }

  function finish(controller: AbortController) {
    if (active.current !== controller) return;
    active.current = null;
    setBusy(false);
  }

  function record(
    attempt: OriginalChange<Details>,
    lease: DraftRecoveryLease,
    result: Result,
  ) {
    recovery.release(lease, null);
    setSaved(null);
    setAdmissionExpired(false);
    onRecorded(attempt.details, result);
  }

  async function send(
    attempt: OriginalChange<Details>,
    lease: DraftRecoveryLease,
    controller: AbortController,
    first: boolean,
  ) {
    try {
      const { packet } = attempt;
      const { workspaceId, applicationId, program } = packet.body;
      const reply = attempt.stateControl
        ? await request<unknown>(
            packet.path,
            { workspaceId, applicationId, program },
            controller.signal,
          )
        : await replayAdmittedEffect<unknown>(packet, controller.signal);
      if (controller.signal.aborted) return;
      const result = protocol.result(reply, attempt);
      if (result === null) {
        setMessage(
          `The reply did not confirm the original ${protocol.subject}.`,
        );
        return;
      }
      record(attempt, lease, result);
    } catch (reason) {
      if (controller.signal.aborted) return;
      if (first && protocol.initialRefusal(reason)) {
        recovery.release(lease, null);
        setSaved(null);
        setMessage(
          reason instanceof Error ? reason.message : "Change rejected.",
        );
      } else if (
        reason instanceof ApiError &&
        reason.code === "OPERATION_ADMISSION_EXPIRED"
      ) {
        if (useReadRecovery) {
          setAdmissionExpired(true);
          setMessage(
            protocol.stateRead
              ? "The original admission expired. Check the current state again."
              : "The original admission expired. Check its receipt again.",
          );
        } else {
          setReceiptMissing(true);
          setMessage(
            "The original request expired, and the server found no receipt.",
          );
        }
      } else {
        setMessage(`The original ${protocol.subject} is still unconfirmed.`);
      }
    }
  }

  async function submit(body: GovernedEffectBody, details: Details) {
    if (
      !owner ||
      original ||
      !catalog?.functions[String(body.program.function)]
    )
      return;
    const controller = start();
    if (!controller) return;
    try {
      const packet = protocol.stateRead
        ? { path: protocol.path, body: structuredClone(body) }
        : await prepareAdmittedProgramEffect(
            protocol.path,
            body,
            body.idempotencyKey,
            controller.signal,
          );
      if (controller.signal.aborted) return;
      const attempt: OriginalChange<Details> = { owner, packet, details };
      if (protocol.stateRead) attempt.stateControl = true;
      const lease = recovery.retain(attempt);
      setSaved(attempt);
      await send(attempt, lease, controller, true);
    } catch (reason) {
      if (!controller.signal.aborted)
        setMessage(
          reason instanceof Error
            ? reason.message
            : `Unable to submit the ${protocol.subject}.`,
        );
    } finally {
      finish(controller);
    }
  }

  async function retry() {
    if (!original || !retryReady || !recovery.lease) return;
    const controller = start();
    if (!controller) return;
    try {
      const lease = recovery.retain(original, recovery.lease);
      await send(original, lease, controller, false);
    } catch {
      if (!controller.signal.aborted)
        setMessage("The original request could not be restored.");
    } finally {
      finish(controller);
    }
  }

  async function checkReceipt() {
    const lease = recovery.lease;
    if (!original || !lease || !canCheckReceipt) return;
    const controller = start();
    if (!controller) return;
    try {
      const body = original.packet.body;
      const { workspaceId, applicationId } = body;
      const stateRead = protocol.stateRead;
      if (stateRead) {
        const reply = await readProgram<unknown>(
          { workspaceId, applicationId },
          stateRead.functionName,
          stateRead.arguments(original.details),
          controller.signal,
        );
        if (controller.signal.aborted) return;
        const observed = stateRead.reconcile(reply, original.details);
        if (observed && "result" in observed) {
          record(original, lease, observed.result);
        } else if (observed?.unchanged) {
          setReceiptMissing(true);
          setMessage(
            `The current state still matches the original request. The ${protocol.subject} remains unconfirmed.`,
          );
        } else {
          setMessage(
            `The current state did not confirm the original ${protocol.subject}.`,
          );
        }
        return;
      }
      if (!protocol.receiptResult || original.stateControl) return;
      const receipt = await readProgram<unknown>(
        { workspaceId, applicationId },
        receiptFunction,
        { operationId: original.packet.body.idempotencyKey },
        controller.signal,
      );
      if (controller.signal.aborted) return;
      const result = await protocol.receiptResult(receipt, original);
      if (controller.signal.aborted) return;
      if (result === null) {
        setMessage(
          `The receipt could not confirm the original ${protocol.subject}.`,
        );
        return;
      }
      record(original, lease, result);
    } catch (reason) {
      if (controller.signal.aborted) return;
      if (protocol.stateRead) {
        setMessage(
          "The current state could not be checked. The original request remains unconfirmed.",
        );
      } else if (
        reason instanceof ApiError &&
        reason.code === "OPERATION_RECEIPT_NOT_FOUND"
      ) {
        setReceiptMissing(true);
        setMessage(
          `No receipt is visible yet. The original ${protocol.subject} remains unconfirmed.`,
        );
      } else {
        setMessage(
          `The receipt check could not confirm the original ${protocol.subject}.`,
        );
      }
    } finally {
      finish(controller);
    }
  }

  async function copyOriginal() {
    if (
      !original ||
      !protocol.tool ||
      original.stateControl ||
      !canRetry ||
      active.current
    )
      return;
    const { workspaceId, applicationId, program, idempotencyKey } =
      original.packet.body;
    try {
      await navigator.clipboard.writeText(
        JSON.stringify({
          tool: protocol.tool,
          arguments: {
            workspace_id: workspaceId,
            application_id: applicationId,
            program,
            idempotency_key: idempotencyKey,
          },
        }),
      );
      setMessage(`Original ${protocol.subject} copied for MCP.`);
    } catch {
      setMessage(`The original ${protocol.subject} could not be copied.`);
    }
  }

  async function copyReceiptCheck() {
    if (
      !original ||
      original.stateControl ||
      !canCheckReceipt ||
      !protocol.receiptResult ||
      !recovery.lease ||
      active.current
    )
      return;
    const { workspaceId, applicationId, idempotencyKey } = original.packet.body;
    try {
      await copyOperationReceiptCheck(
        { workspaceId, applicationId },
        idempotencyKey,
      );
      setMessage("Receipt check copied for your MCP client.");
    } catch {
      setMessage("The receipt check could not be copied.");
    }
  }

  function closeRecovery() {
    if (!original || !canCloseRecovery || !recovery.lease || active.current)
      return null;
    if (!window.confirm(protocol.closePrompt)) return null;
    recovery.release(recovery.lease, null);
    setSaved(null);
    setReceiptMissing(false);
    setAdmissionExpired(false);
    setMessage("");
    return original.details;
  }

  return {
    pending: Boolean(original),
    operationId: !original?.stateControl
      ? original?.packet.body.idempotencyKey
      : undefined,
    review: canRetry && original ? original.details : null,
    reviewedProgram: canRetry && original ? original.packet.body.program : null,
    retryReady,
    canCheckReceipt: canCheckReceipt && Boolean(recovery.lease),
    canCloseRecovery,
    busy,
    message,
    submit,
    retry,
    checkReceipt,
    copyReceiptCheck,
    copyOriginal,
    closeRecovery,
  };
}
