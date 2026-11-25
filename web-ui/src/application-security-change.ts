import { useLayoutEffect, useRef, useState } from "react";
import {
  ApiError,
  prepareAdmittedProgramEffect,
  readSecurityProgram,
  replayAdmittedEffect,
  type AdmittedEffectPacket,
} from "./api";
import {
  requesterBenefitEvidence,
  type RequesterBenefitEvidence,
} from "./RequesterBenefit";
import type { ApplicationCatalog, Scope } from "./types";
import { usePreservedDraft, type DraftRecoveryLease } from "./unsaved-work";

const receiptFunction = "security.application.receipt.read";
const securityPath = "/api/security";
const sha256 = /^[0-9a-f]{64}$/;

type ChangeBody = Scope & {
  idempotencyKey: string;
  confirmed: boolean;
  program: { function: string; languageVersion: number };
};
type OriginalChange = { packet: AdmittedEffectPacket; label: string };

function exactScope(value: Record<string, unknown>, scope: Scope) {
  return (
    value.workspaceId === scope.workspaceId &&
    value.applicationId === scope.applicationId
  );
}

function definitiveRejection(reason: unknown) {
  return (
    reason instanceof ApiError &&
    [400, 401, 403, 409, 412, 422].includes(reason.status) &&
    !reason.code.startsWith("IDEMPOTENCY_")
  );
}

export function useApplicationSecurityChange(
  scope: Scope | undefined,
  catalog: ApplicationCatalog | null,
  onRecorded: (message: string) => void,
) {
  const [original, setOriginal] = useState<OriginalChange | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [receiptAbsent, setReceiptAbsent] = useState(false);
  const [benefitRecord, setBenefitRecord] = useState<{
    context: string;
    evidence: RequesterBenefitEvidence | null;
  } | null>(null);
  const context = JSON.stringify([
    scope?.workspaceId,
    scope?.applicationId,
    catalog?.accessContext,
    catalog?.applicationAccess.issuer,
    catalog?.applicationAccess.subjectId,
    catalog?.revisions.security,
  ]);
  const retainBenefit = (mode: unknown, value: unknown, duties?: unknown) => {
    const evidence = requesterBenefitEvidence(mode, value, duties);
    setBenefitRecord(
      value === undefined || value === null ? null : { context, evidence },
    );
  };
  const active = useRef<AbortController | null>(null);
  const latest = useRef({ catalog, onRecorded });
  useLayoutEffect(() => {
    latest.current = { catalog, onRecorded };
  }, [catalog, onRecorded]);
  useLayoutEffect(
    () => () => {
      active.current?.abort();
      active.current = null;
    },
    [],
  );

  const recovery = usePreservedDraft(
    scope?.workspaceId || "",
    scope?.applicationId || "",
    "application-security-change",
    "Application security change with an unconfirmed outcome",
    Boolean(original),
    original,
    setOriginal,
  );

  const canReadReceipt = Boolean(catalog?.functions[receiptFunction]);
  const canReplay = Boolean(
    original &&
      catalog?.functions[String(original.packet.body.program.function)],
  );

  function start() {
    if (active.current) return null;
    const request = new AbortController();
    active.current = request;
    setBusy(true);
    setMessage("");
    setBenefitRecord(null);
    return request;
  }

  function finish(request: AbortController) {
    if (active.current !== request) return;
    active.current = null;
    setBusy(false);
  }

  function recorded(lease: DraftRecoveryLease, notice: string) {
    recovery.release(lease, null);
    setOriginal(null);
    setReceiptAbsent(false);
    latest.current.onRecorded(notice);
  }

  async function send(
    attempt: OriginalChange,
    lease: DraftRecoveryLease,
    request: AbortController,
    firstDispatch: boolean,
  ) {
    const { packet, label } = attempt;
    const functionName = String(packet.body.program.function);
    try {
      const response = await replayAdmittedEffect<{
        languageVersion: number;
        function: string;
        result: Record<string, unknown>;
      }>(packet, request.signal);
      if (request.signal.aborted) return;
      if (
        response?.languageVersion !== 2 ||
        response.function !== functionName ||
        !response.result ||
        !exactScope(response.result, packet.body) ||
        (functionName.startsWith("security.application.dimension-policy.")
          ? typeof response.result.authorizationEffect !== "boolean"
          : typeof response.result.changed !== "boolean")
      ) {
        setMessage("The reply could not confirm the original security change.");
        return;
      }
      if (functionName === "security.application.authorization.apply") {
        const impact = response.result.impact;
        if (
          impact &&
          typeof impact === "object" &&
          "requesterBenefit" in impact
        )
          retainBenefit(
            response.result.authorizationMode,
            impact.requesterBenefit,
            "reviewedWorkflowDuties" in impact
              ? impact.reviewedWorkflowDuties
              : undefined,
          );
      }
      recorded(
        lease,
        response.result.changed === false
          ? `The reviewed ${label} already matched the current state.`
          : `The reviewed ${label} change was committed.`,
      );
    } catch (reason) {
      if (request.signal.aborted) return;
      if (firstDispatch && definitiveRejection(reason)) {
        recovery.release(lease, null);
        setOriginal(null);
        setMessage(
          reason instanceof Error ? reason.message : "Change rejected.",
        );
        return;
      }
      setMessage(
        firstDispatch
          ? "The reply did not confirm the security change."
          : "The retry could not confirm the original security change.",
      );
    }
  }

  async function submit(body: ChangeBody, label: string) {
    if (original || !catalog?.functions[body.program.function]) return;
    const request = start();
    if (!request) return;
    try {
      const packet = await prepareAdmittedProgramEffect(
        securityPath,
        body,
        body.idempotencyKey,
        request.signal,
      );
      if (
        request.signal.aborted ||
        !latest.current.catalog?.functions[body.program.function]
      )
        return;
      const attempt = { packet, label };
      const lease = recovery.retain(attempt);
      setOriginal(attempt);
      setReceiptAbsent(false);
      await send(attempt, lease, request, true);
    } catch (reason) {
      if (!request.signal.aborted)
        setMessage(reason instanceof Error ? reason.message : String(reason));
    } finally {
      finish(request);
    }
  }

  async function checkReceipt() {
    if (!original || !recovery.lease || !canReadReceipt) return;
    const request = start();
    if (!request) return;
    const body = original.packet.body;
    const lease = recovery.lease;
    setReceiptAbsent(false);
    try {
      const receipt = await readSecurityProgram<Record<string, unknown>>(
        body,
        receiptFunction,
        { operationId: body.idempotencyKey },
        request.signal,
      );
      if (
        request.signal.aborted ||
        !latest.current.catalog?.functions[receiptFunction]
      )
        return;
      if (
        !receipt ||
        !exactScope(receipt, body) ||
        receipt.operationId !== body.idempotencyKey ||
        receipt.outcome !== "Committed" ||
        !["actorDigest", "commandDigest", "payloadDigest"].every(
          (field) =>
            typeof receipt[field] === "string" && sha256.test(receipt[field]),
        ) ||
        typeof receipt.committedAt !== "string" ||
        !Number.isFinite(Date.parse(receipt.committedAt))
      ) {
        setMessage(
          "The receipt could not confirm the original security change.",
        );
        return;
      }
      if (
        original.packet.body.program.function ===
        "security.application.authorization.apply"
      )
        retainBenefit(
          receipt.authorizationMode,
          receipt.requesterBenefit,
          receipt.reviewedWorkflowDuties,
        );
      recorded(lease, `The original ${original.label} change was recorded.`);
    } catch (reason) {
      if (request.signal.aborted) return;
      if (
        reason instanceof ApiError &&
        reason.code === "SECURITY_RECEIPT_UNAVAILABLE"
      ) {
        setReceiptAbsent(true);
        setMessage(
          "There is no visible receipt yet. The original outcome is still unknown.",
        );
      } else {
        setMessage(
          "The receipt check failed. The original outcome is still unknown.",
        );
      }
    } finally {
      finish(request);
    }
  }

  async function retry() {
    if (!original || !recovery.lease || !receiptAbsent || !canReplay) return;
    const request = start();
    if (!request) return;
    setReceiptAbsent(false);
    try {
      const lease = recovery.retain(original, recovery.lease);
      await send(original, lease, request, false);
    } catch {
      if (!request.signal.aborted)
        setMessage(
          "The original request could not be restored. Check its receipt again.",
        );
    } finally {
      finish(request);
    }
  }

  async function copyReceiptCheck() {
    if (!original || !canReadReceipt || active.current) return;
    const { workspaceId, applicationId, idempotencyKey } = original.packet.body;
    try {
      await navigator.clipboard.writeText(
        JSON.stringify({
          workspace_id: workspaceId,
          application_id: applicationId,
          program: {
            languageVersion: 2,
            function: receiptFunction,
            arguments: { operationId: idempotencyKey },
          },
        }),
      );
      setMessage("Receipt check copied for your MCP client.");
    } catch {
      setMessage("The receipt check could not be copied.");
    }
  }

  return {
    original: Boolean(original),
    requesterBenefit:
      benefitRecord?.context === context ? benefitRecord.evidence : null,
    requesterBenefitUnavailable:
      benefitRecord?.context === context && !benefitRecord.evidence,
    busy,
    message,
    canReadReceipt,
    canRetry: receiptAbsent && canReplay,
    submit,
    checkReceipt,
    retry,
    copyReceiptCheck,
  };
}
