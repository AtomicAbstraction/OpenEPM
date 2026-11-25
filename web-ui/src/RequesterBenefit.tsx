import { useEffect, useRef, useState } from "react";
import { readSecurityProgram } from "./api";
import { scopeLabel, validWorkflowDuties } from "./authorization-config";
import type { Scope } from "./types";
import type {
  Configuration,
  Preview,
  RequesterBenefit,
  RequesterBenefitReason,
} from "./authorization-config";

export type RequesterBenefitEvidence = {
  authorizationMode: Configuration["authorizationMode"];
  requesterBenefit: RequesterBenefit;
  reviewedWorkflowDuties?: NonNullable<
    Preview["impact"]["reviewedWorkflowDuties"]
  >;
};

const reasons: Record<RequesterBenefitReason, string> = {
  new_grant_path: "New grant through the requester’s group",
  additional_grant_path: "Additional grant with equivalent existing coverage",
  potential_scope_expansion: "Existing grant may cover more resources",
  new_application_entry: "New application entry can activate existing grants",
};
export function requesterBenefitSummary(benefit: RequesterBenefit) {
  return benefit.classification === "none"
    ? "No new or expanded grant through the requester’s groups"
    : reasons[benefit.classification];
}
function text(value: unknown, maximum: number) {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    value.length <= maximum
  );
}
function validSelection(grant: RequesterBenefit["grants"][number]) {
  if (
    !grant.selector ||
    typeof grant.selector !== "object" ||
    Array.isArray(grant.selector)
  )
    return false;
  if (grant.scopeKind === "entire_application")
    return Object.keys(grant.selector).length === 0;
  if (grant.scopeKind === "exact_object")
    return (
      text(grant.selector.objectId, 300) && text(grant.selector.objectType, 100)
    );
  return (
    grant.scopeKind === "dimension_tags" &&
    Object.keys(grant.selector).length > 0 &&
    Object.entries(grant.selector).every(
      ([axis, tags]) =>
        text(axis, 200) &&
        Array.isArray(tags) &&
        tags.length > 0 &&
        tags.every((tag) => text(tag, 20)),
    )
  );
}
export function validRequesterBenefit(
  value: unknown,
): value is RequesterBenefit {
  if (!value || typeof value !== "object") return false;
  const data = value as RequesterBenefit;
  return (
    (data.classification === "none" ||
      Object.hasOwn(reasons, data.classification)) &&
    (data.applicationEntry === undefined ||
      ["admitted", "requires_entry"].includes(data.applicationEntry)) &&
    typeof data.grantsComplete === "boolean" &&
    Array.isArray(data.grants) &&
    data.grants.length <= 4096 &&
    (data.classification !== "none" ||
      (data.grants.length === 0 && data.grantsComplete)) &&
    (data.classification === "none" ||
      data.grants.length > 0 ||
      !data.grantsComplete) &&
    data.grants.every(
      (grant) =>
        grant &&
        text(grant.groupId, 300) &&
        text(grant.assignmentId, 200) &&
        text(grant.roleId, 200) &&
        Number.isSafeInteger(grant.scopeRevision) &&
        grant.scopeRevision >= 0 &&
        validSelection(grant) &&
        text(grant.action, 200) &&
        (grant.expandedPrerequisite === undefined ||
          text(grant.expandedPrerequisite, 200)) &&
        ((grant.previousWorkflowDuties === undefined &&
          grant.reviewedWorkflowDuties === undefined) ||
          (validWorkflowDuties(grant.previousWorkflowDuties) &&
            validWorkflowDuties(grant.reviewedWorkflowDuties))) &&
        text(grant.scopeId, 200) &&
        Object.hasOwn(reasons, grant.reason),
    )
  );
}

export function requesterBenefitEvidence(
  mode: unknown,
  value: unknown,
  dutyChanges?: unknown,
): RequesterBenefitEvidence | null {
  if (
    dutyChanges !== undefined &&
    (!Array.isArray(dutyChanges) ||
      dutyChanges.length > 100 ||
      !dutyChanges.every(
        (item) =>
          item &&
          text(item.roleId, 200) &&
          validWorkflowDuties(item.addedDuties) &&
          validWorkflowDuties(item.removedDuties),
      ))
  )
    return null;
  return (mode === "legacy" || mode === "group_assignments") &&
    validRequesterBenefit(value)
    ? {
        authorizationMode: mode,
        requesterBenefit: value,
        ...(dutyChanges ? { reviewedWorkflowDuties: dutyChanges } : {}),
      }
    : null;
}

export function RequesterBenefitDetails({
  evidence,
  preview = false,
  config,
}: {
  evidence: RequesterBenefitEvidence;
  preview?: boolean;
  config?: Configuration;
}) {
  const { requesterBenefit: benefit, authorizationMode: mode } = evidence;
  const heading = preview
    ? "Effect on your own access"
    : "Effect on the requesting administrator";
  let summary = requesterBenefitSummary(benefit) + ".";
  if (preview && benefit.classification === "new_grant_path")
    summary = "This change adds a grant through one of your groups.";
  return (
    <>
      <section aria-label={heading}>
        <h4>{heading}</h4>
        <p>{summary}</p>
        {mode === "legacy" && (
          <p>
            These assignments are staged. They take effect when group
            assignments are activated.
          </p>
        )}
        {benefit.classification !== "none" &&
          benefit.applicationEntry === "requires_entry" && (
            <p>
              The requester needs application entry before these grants can be
              used.
            </p>
          )}
        {benefit.grants.length > 0 && (
          <details>
            <summary>View granting groups, actions and scopes</summary>
            <ul>
              {benefit.grants.map((grant, index) => {
                const group = config?.eligibleGroups.find(
                  (row) => row.groupId === grant.groupId,
                );
                const scope = config?.scopes.find(
                  (row) => row.scopeId === grant.scopeId,
                );
                return (
                  <li
                    key={JSON.stringify([
                      grant.groupId,
                      grant.assignmentId,
                      grant.action,
                      grant.scopeId,
                      index,
                    ])}
                  >
                    <strong>{grant.action}</strong> · {reasons[grant.reason]}
                    <br />
                    Group {group?.displayName || group?.groupName || ""}{" "}
                    <code>{grant.groupId}</code> · Scope {scope?.name || ""}{" "}
                    <code>{grant.scopeId}</code> (revision {grant.scopeRevision}
                    ) · {scopeLabel(grant)} · Role <code>{grant.roleId}</code> ·
                    Assignment <code>{grant.assignmentId}</code>
                    {grant.expandedPrerequisite && (
                      <p>
                        The same assignment now supplies more coverage for the
                        required <code>{grant.expandedPrerequisite}</code>{" "}
                        action.
                      </p>
                    )}
                    {grant.previousWorkflowDuties &&
                      grant.reviewedWorkflowDuties && (
                        <p>
                          Planning duties on this assignment · before{" "}
                          {grant.previousWorkflowDuties.join(", ") || "none"} ·
                          after{" "}
                          {grant.reviewedWorkflowDuties.join(", ") || "none"}
                        </p>
                      )}
                  </li>
                );
              })}
            </ul>
          </details>
        )}
        {!benefit.grantsComplete && (
          <p>The record contains only part of the grant detail.</p>
        )}
      </section>
      {evidence.reviewedWorkflowDuties?.length ? (
        <section aria-label="Recorded planning duty changes">
          <h4>Recorded planning duty changes</h4>
          {evidence.reviewedWorkflowDuties.map((item) => (
            <div key={item.roleId}>
              <strong>{item.roleId}</strong>
              {item.addedDuties.length > 0 && (
                <p>Added · {item.addedDuties.join(", ")}</p>
              )}
              {item.removedDuties.length > 0 && (
                <p>Removed · {item.removedDuties.join(", ")}</p>
              )}
            </div>
          ))}
        </section>
      ) : null}
    </>
  );
}

export function RequesterBenefitAudit({
  evidence,
  scope,
  receiptKey,
}: {
  evidence: RequesterBenefitEvidence;
  scope: Scope;
  receiptKey: string | null;
}) {
  const [detail, setDetail] = useState<RequesterBenefitEvidence | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const active = useRef<AbortController | null>(null);
  useEffect(() => () => active.current?.abort(), []);
  async function read() {
    if (!receiptKey || busy) return;
    active.current?.abort();
    const c = new AbortController();
    active.current = c;
    setError("");
    setBusy(true);
    try {
      const receipt = await readSecurityProgram<Record<string, unknown>>(
        scope,
        "security.application.receipt.read",
        { operationId: receiptKey },
        c.signal,
      );
      if (c.signal.aborted) return;
      const evidenceFromReceipt = requesterBenefitEvidence(
        receipt.authorizationMode,
        receipt.requesterBenefit,
        receipt.reviewedWorkflowDuties,
      );
      if (
        receipt.workspaceId !== scope.workspaceId ||
        receipt.applicationId !== scope.applicationId ||
        receipt.operationId !== receiptKey ||
        receipt.action !== "application-authorization.apply" ||
        receipt.outcome !== "Committed" ||
        !["actorDigest", "commandDigest", "payloadDigest"].every(
          (k) =>
            typeof receipt[k] === "string" &&
            /^[a-f0-9]{64}$/.test(receipt[k] as string),
        ) ||
        typeof receipt.committedAt !== "string" ||
        !Number.isFinite(Date.parse(receipt.committedAt)) ||
        evidenceFromReceipt?.authorizationMode !== evidence.authorizationMode ||
        evidenceFromReceipt.requesterBenefit.classification !==
          evidence.requesterBenefit.classification ||
        !evidenceFromReceipt.requesterBenefit.grantsComplete
      )
        throw new Error("Invalid benefit receipt");
      setDetail(evidenceFromReceipt);
    } catch {
      if (!c.signal.aborted)
        setError("The recorded grant details are unavailable.");
    } finally {
      if (!c.signal.aborted) setBusy(false);
    }
  }
  return (
    <>
      <RequesterBenefitDetails evidence={detail || evidence} />
      {receiptKey && !detail && (
        <button type="button" disabled={busy} onClick={() => void read()}>
          {busy ? "Reading grant details…" : "Read recorded grant details"}
        </button>
      )}
      {error && <p role="alert">{error}</p>}
    </>
  );
}
