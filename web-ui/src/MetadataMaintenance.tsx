import { useEffect, useState } from "react";
import { request } from "./api";
import { validMetadataText } from "./MetadataCreate";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { usePreservedDraft } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";

type Dimension = {
  dimension_id: string;
  name: string;
  model_role: string;
  status: string;
  short_description?: string;
  detailed_description?: string;
};

type Member = {
  member_id: string;
  name: string;
  status: string;
  short_description?: string;
  detailed_description?: string;
  numeric_value_kind?: "amount" | "ratio" | null;
  custom_values?: Record<string, unknown>;
};

type Action =
  | "dimension-rename"
  | "dimension-describe"
  | "dimension-status"
  | "dimension-delete"
  | "member-rename"
  | "member-describe"
  | "member-numeric-kind"
  | "member-status";

export const metadataMaintenanceBody = (
  app: ApplicationSummary,
  functionName: string,
  args: Record<string, unknown>,
  idempotencyKey: string,
) => ({
  workspaceId: app.workspaceId,
  applicationId: app.applicationId,
  confirmed: true,
  idempotencyKey,
  program: {
    languageVersion: 2,
    function: functionName,
    arguments: args,
  },
});

function validDescription(value: string, limit: number) {
  return value.length <= limit;
}

export function MetadataMaintenance({
  app,
  catalog,
  dimension,
  members,
  metadataRevision,
  onChanged,
  selectedMemberId,
  onSelectedMemberIdChange,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  dimension?: Dimension;
  members: Member[];
  metadataRevision: number | null;
  onChanged: () => Promise<void>;
  selectedMemberId?: string;
  onSelectedMemberIdChange?: (memberId: string) => void;
}) {
  const mutationIntentKey = useStableMutationIntentKey(
    "metadata-maintenance-ui",
  );
  const [dimensionName, setDimensionName] = useState("");
  const [dimensionShort, setDimensionShort] = useState("");
  const [dimensionDetailed, setDimensionDetailed] = useState("");
  const [dimensionDeleteText, setDimensionDeleteText] = useState("");
  const [memberId, setMemberId] = useState("");
  const [memberName, setMemberName] = useState("");
  const [memberShort, setMemberShort] = useState("");
  const [memberDetailed, setMemberDetailed] = useState("");
  const [memberNumericKind, setMemberNumericKind] = useState("");
  const [reviewedAction, setReviewedAction] = useState<Action | "">("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");

  const effectiveMemberId =
    selectedMemberId === undefined ? memberId : selectedMemberId;
  const member = members.find((item) => item.member_id === effectiveMemberId);
  const canDimensionRename = Boolean(
    catalog?.functions["metadata.dimension.rename"],
  );
  const canDimensionDescribe = Boolean(
    catalog?.functions["metadata.dimension.describe"],
  );
  const canDimensionStatus = Boolean(
    catalog?.functions["metadata.dimension.status.set"],
  );
  const canDimensionDelete = Boolean(
    catalog?.functions["metadata.dimension.delete"],
  );
  const canMemberRename = Boolean(catalog?.functions["metadata.member.rename"]);
  const canMemberDescribe = Boolean(
    catalog?.functions["metadata.member.describe"],
  );
  const canMemberNumericKind = Boolean(
    catalog?.functions["metadata.member.numeric-kind.set"],
  );
  const canMemberStatus = Boolean(
    catalog?.functions["metadata.member.status.set"],
  );
  const hasAnyAction = Boolean(
    catalog &&
      [
        "metadata.dimension.rename",
        "metadata.dimension.describe",
        "metadata.dimension.status.set",
        "metadata.dimension.delete",
        "metadata.member.rename",
        "metadata.member.describe",
        "metadata.member.numeric-kind.set",
        "metadata.member.status.set",
      ].some((name) => catalog.functions[name]),
  );
  const snapshotCurrent = Boolean(dimension && metadataRevision !== null);
  const dimensionDraftChanged = Boolean(
    dimension &&
      (dimensionName !== dimension.name ||
        dimensionShort !== (dimension.short_description || "") ||
        dimensionDetailed !== (dimension.detailed_description || "") ||
        dimensionDeleteText !== ""),
  );
  const memberDraftChanged = Boolean(
    member &&
      (memberName !== member.name ||
        memberShort !== (member.short_description || "") ||
        memberDetailed !== (member.detailed_description || "") ||
        memberNumericKind !== (member.numeric_value_kind || "")),
  );
  usePreservedDraft(
    app?.workspaceId || "none",
    app?.applicationId || "none",
    `metadata-maintenance:${dimension?.dimension_id || "none"}:${effectiveMemberId || "none"}`,
    "Unsaved dimension or member changes",
    dimensionDraftChanged || memberDraftChanged,
    {
      dimensionName,
      dimensionShort,
      dimensionDetailed,
      dimensionDeleteText,
      memberId,
      memberName,
      memberShort,
      memberDetailed,
      memberNumericKind,
      reviewedAction,
    },
    (draft) => {
      setDimensionName(draft.dimensionName);
      setDimensionShort(draft.dimensionShort);
      setDimensionDetailed(draft.dimensionDetailed);
      setDimensionDeleteText(draft.dimensionDeleteText);
      setMemberId(draft.memberId);
      setMemberName(draft.memberName);
      setMemberShort(draft.memberShort);
      setMemberDetailed(draft.memberDetailed);
      setMemberNumericKind(draft.memberNumericKind);
      setReviewedAction(draft.reviewedAction);
    },
  );

  useEffect(() => {
    setDimensionName(dimension?.name || "");
    setDimensionShort(dimension?.short_description || "");
    setDimensionDetailed(dimension?.detailed_description || "");
    setDimensionDeleteText("");
    setReviewedAction("");
    setError("");
    setResult("");
  }, [dimension?.dimension_id, metadataRevision]);

  useEffect(() => {
    const nextMemberId = members.some(
      (item) => item.member_id === effectiveMemberId,
    )
      ? effectiveMemberId
      : members[0]?.member_id || "";
    if (selectedMemberId === undefined) setMemberId(nextMemberId);
    if (nextMemberId !== effectiveMemberId)
      onSelectedMemberIdChange?.(nextMemberId);
  }, [members, effectiveMemberId, selectedMemberId]);

  useEffect(() => {
    setMemberName(member?.name || "");
    setMemberShort(member?.short_description || "");
    setMemberDetailed(member?.detailed_description || "");
    setMemberNumericKind(member?.numeric_value_kind || "");
    setReviewedAction("");
    setResult("");
  }, [member?.member_id, metadataRevision]);

  function invalidate() {
    setReviewedAction("");
    setResult("");
  }

  async function execute(
    action: Action,
    functionName: string,
    args: Record<string, unknown>,
    confirmation: string,
  ) {
    if (
      !app ||
      !snapshotCurrent ||
      busy ||
      reviewedAction !== action ||
      !window.confirm(confirmation)
    )
      return;
    setBusy(true);
    setError("");
    setResult("");
    try {
      const response = await request<{
        receiptId?: string;
        result?: { receiptId?: string };
      }>(
        "/api/metadata-action",
        metadataMaintenanceBody(
          app,
          functionName,
          args,
          mutationIntentKey({
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            functionName,
            args,
          }),
        ),
      );
      const receipt = response.result?.receiptId || response.receiptId;
      setResult(
        receipt
          ? `Applied by receipt ${receipt}.`
          : "The fixed metadata service applied the reviewed change.",
      );
      setReviewedAction("");
      await onChanged();
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to apply metadata change",
      );
    } finally {
      setBusy(false);
    }
  }

  function review(action: Action, valid: boolean, label: string) {
    return (
      <label className="review-check">
        <input
          type="checkbox"
          checked={reviewedAction === action}
          disabled={!valid}
          onChange={(event) =>
            setReviewedAction(event.target.checked ? action : "")
          }
        />
        {label}
      </label>
    );
  }

  if (!hasAnyAction) return null;

  const dimensionRenameValid = Boolean(
    snapshotCurrent &&
      validMetadataText(dimensionName) &&
      dimensionName !== dimension?.name,
  );
  const dimensionDescribeValid = Boolean(
    snapshotCurrent &&
      validDescription(dimensionShort, 500) &&
      validDescription(dimensionDetailed, 10000) &&
      (dimensionShort !== (dimension?.short_description || "") ||
        dimensionDetailed !== (dimension?.detailed_description || "")),
  );
  const memberRenameValid = Boolean(
    snapshotCurrent &&
      member &&
      validMetadataText(memberName) &&
      memberName !== member.name,
  );
  const memberDescribeValid = Boolean(
    snapshotCurrent &&
      member &&
      validDescription(memberShort, 500) &&
      validDescription(memberDetailed, 10000) &&
      (memberShort !== (member.short_description || "") ||
        memberDetailed !== (member.detailed_description || "")),
  );
  const memberNumericValid = Boolean(
    snapshotCurrent &&
      member &&
      memberNumericKind !== (member.numeric_value_kind || ""),
  );

  return (
    <section
      className="metadata-create"
      aria-labelledby="metadata-maintenance-heading"
    >
      <div>
        <small>REVIEWED MAINTENANCE</small>
        <h3 id="metadata-maintenance-heading">Inline metadata editor</h3>
        <p>
          Rename, describe and change lifecycle state only against metadata
          revision {metadataRevision ?? "—"}. Dependency guards remain
          server-owned.
        </p>
      </div>
      {!snapshotCurrent && (
        <p className="inline-error" role="status">
          Read the current dimension catalogue before maintaining metadata.
        </p>
      )}
      {dimension && (
        <details className="metadata-edit-grid" open>
          <summary>Dimension row · {dimension.dimension_id}</summary>
          {canDimensionRename && (
            <div className="maintenance-action">
              <label>
                Dimension display name
                <input
                  value={dimensionName}
                  maxLength={200}
                  onChange={(event) => {
                    setDimensionName(event.target.value);
                    invalidate();
                  }}
                />
              </label>
              <div className="reviewed-inline-action">
                {review(
                  "dimension-rename",
                  dimensionRenameValid,
                  "I reviewed this exact dimension name and metadata revision.",
                )}
                <button
                  disabled={
                    busy ||
                    !dimensionRenameValid ||
                    reviewedAction !== "dimension-rename"
                  }
                  onClick={() =>
                    void execute(
                      "dimension-rename",
                      "metadata.dimension.rename",
                      {
                        dimensionId: dimension.dimension_id,
                        name: dimensionName,
                        expectedMetadataRevision: metadataRevision,
                      },
                      `Rename ${dimension.dimension_id} to ${dimensionName}?`,
                    )
                  }
                >
                  Rename dimension
                </button>
              </div>
            </div>
          )}
          {canDimensionDescribe && (
            <div className="maintenance-action">
              <label>
                Dimension short description
                <textarea
                  value={dimensionShort}
                  maxLength={500}
                  onChange={(event) => {
                    setDimensionShort(event.target.value);
                    invalidate();
                  }}
                />
              </label>
              <label>
                Dimension detailed description
                <textarea
                  value={dimensionDetailed}
                  maxLength={10000}
                  onChange={(event) => {
                    setDimensionDetailed(event.target.value);
                    invalidate();
                  }}
                />
              </label>
              <div className="reviewed-inline-action">
                {review(
                  "dimension-describe",
                  dimensionDescribeValid,
                  "I reviewed these exact dimension descriptions and metadata revision.",
                )}
                <button
                  disabled={
                    busy ||
                    !dimensionDescribeValid ||
                    reviewedAction !== "dimension-describe"
                  }
                  onClick={() =>
                    void execute(
                      "dimension-describe",
                      "metadata.dimension.describe",
                      {
                        dimensionId: dimension.dimension_id,
                        shortDescription: dimensionShort,
                        detailedDescription: dimensionDetailed,
                        expectedMetadataRevision: metadataRevision,
                      },
                      `Save reviewed descriptions for ${dimension.dimension_id}?`,
                    )
                  }
                >
                  Save dimension descriptions
                </button>
              </div>
            </div>
          )}
          {canDimensionStatus && (
            <div className="reviewed-inline-action">
              {review(
                "dimension-status",
                snapshotCurrent,
                `I reviewed changing this dimension to ${dimension.status === "Active" ? "Inactive" : "Active"} at this metadata revision.`,
              )}
              <button
                disabled={busy || reviewedAction !== "dimension-status"}
                onClick={() =>
                  void execute(
                    "dimension-status",
                    "metadata.dimension.status.set",
                    {
                      dimensionId: dimension.dimension_id,
                      status:
                        dimension.status === "Active" ? "Inactive" : "Active",
                      expectedMetadataRevision: metadataRevision,
                    },
                    `Set dimension ${dimension.dimension_id} to ${dimension.status === "Active" ? "Inactive" : "Active"}? The fixed core will reject live dependencies.`,
                  )
                }
              >
                Set dimension{" "}
                {dimension.status === "Active" ? "inactive" : "active"}
              </button>
            </div>
          )}
          {canDimensionDelete && dimension.status === "Inactive" && (
            <div className="maintenance-action danger-zone">
              <label>
                Type {dimension.dimension_id} to delete this inactive dimension
                <input
                  value={dimensionDeleteText}
                  onChange={(event) => {
                    setDimensionDeleteText(event.target.value);
                    invalidate();
                  }}
                />
              </label>
              <div className="reviewed-inline-action">
                {review(
                  "dimension-delete",
                  dimensionDeleteText === dimension.dimension_id,
                  "I reviewed this exact inactive dimension deletion and metadata revision.",
                )}
                <button
                  className="danger-button"
                  disabled={
                    busy ||
                    dimensionDeleteText !== dimension.dimension_id ||
                    reviewedAction !== "dimension-delete"
                  }
                  onClick={() =>
                    void execute(
                      "dimension-delete",
                      "metadata.dimension.delete",
                      {
                        dimensionId: dimension.dimension_id,
                        expectedMetadataRevision: metadataRevision,
                      },
                      `Permanently delete inactive dimension ${dimension.dimension_id}? The fixed core will reject any dependency.`,
                    )
                  }
                >
                  Delete inactive dimension
                </button>
              </div>
            </div>
          )}
        </details>
      )}
      {members.length > 0 && (
        <details className="metadata-edit-grid">
          <summary>Member rows</summary>
          <label>
            Member
            <select
              value={effectiveMemberId}
              onChange={(event) => {
                if (selectedMemberId === undefined)
                  setMemberId(event.target.value);
                onSelectedMemberIdChange?.(event.target.value);
                invalidate();
              }}
            >
              {members.map((item) => (
                <option key={item.member_id} value={item.member_id}>
                  {item.name}
                </option>
              ))}
            </select>
          </label>
          {member && canMemberRename && (
            <div className="maintenance-action">
              <label>
                Member display name
                <input
                  value={memberName}
                  maxLength={200}
                  onChange={(event) => {
                    setMemberName(event.target.value);
                    invalidate();
                  }}
                />
              </label>
              <div className="reviewed-inline-action">
                {review(
                  "member-rename",
                  memberRenameValid,
                  "I reviewed this exact member name and metadata revision.",
                )}
                <button
                  disabled={
                    busy ||
                    !memberRenameValid ||
                    reviewedAction !== "member-rename"
                  }
                  onClick={() =>
                    void execute(
                      "member-rename",
                      "metadata.member.rename",
                      {
                        dimensionId: dimension?.dimension_id,
                        memberId: member.member_id,
                        name: memberName,
                        expectedMetadataRevision: metadataRevision,
                      },
                      `Rename member ${member.member_id} to ${memberName}?`,
                    )
                  }
                >
                  Rename member
                </button>
              </div>
            </div>
          )}
          {member && canMemberDescribe && (
            <div className="maintenance-action">
              <label>
                Member short description
                <textarea
                  value={memberShort}
                  maxLength={500}
                  onChange={(event) => {
                    setMemberShort(event.target.value);
                    invalidate();
                  }}
                />
              </label>
              <label>
                Member detailed description
                <textarea
                  value={memberDetailed}
                  maxLength={10000}
                  onChange={(event) => {
                    setMemberDetailed(event.target.value);
                    invalidate();
                  }}
                />
              </label>
              <div className="reviewed-inline-action">
                {review(
                  "member-describe",
                  memberDescribeValid,
                  "I reviewed these exact member descriptions and metadata revision.",
                )}
                <button
                  disabled={
                    busy ||
                    !memberDescribeValid ||
                    reviewedAction !== "member-describe"
                  }
                  onClick={() =>
                    void execute(
                      "member-describe",
                      "metadata.member.describe",
                      {
                        dimensionId: dimension?.dimension_id,
                        memberId: member.member_id,
                        shortDescription: memberShort,
                        detailedDescription: memberDetailed,
                        expectedMetadataRevision: metadataRevision,
                      },
                      `Save reviewed descriptions for member ${member.member_id}?`,
                    )
                  }
                >
                  Save member descriptions
                </button>
              </div>
            </div>
          )}
          {member && canMemberNumericKind && (
            <div className="maintenance-action">
              <label>
                Numeric value kind
                <select
                  value={memberNumericKind}
                  onChange={(event) => {
                    setMemberNumericKind(event.target.value);
                    invalidate();
                  }}
                >
                  <option value="">Unspecified</option>
                  <option value="amount">Amount</option>
                  <option value="ratio">Ratio</option>
                </select>
              </label>
              <div className="reviewed-inline-action">
                {review(
                  "member-numeric-kind",
                  memberNumericValid,
                  "I reviewed this exact member numeric kind and metadata revision.",
                )}
                <button
                  disabled={
                    busy ||
                    !memberNumericValid ||
                    reviewedAction !== "member-numeric-kind"
                  }
                  onClick={() =>
                    void execute(
                      "member-numeric-kind",
                      "metadata.member.numeric-kind.set",
                      {
                        dimensionId: dimension?.dimension_id,
                        memberId: member.member_id,
                        numericValueKind: memberNumericKind || null,
                        expectedMetadataRevision: metadataRevision,
                      },
                      `Set ${member.member_id} numeric kind to ${memberNumericKind || "Unspecified"}?`,
                    )
                  }
                >
                  Set numeric kind
                </button>
              </div>
            </div>
          )}
          {member && canMemberStatus && (
            <div className="reviewed-inline-action">
              {review(
                "member-status",
                snapshotCurrent,
                `I reviewed changing this member to ${member.status === "Active" ? "Inactive" : "Active"} at this metadata revision.`,
              )}
              <button
                disabled={busy || reviewedAction !== "member-status"}
                onClick={() =>
                  void execute(
                    "member-status",
                    "metadata.member.status.set",
                    {
                      dimensionId: dimension?.dimension_id,
                      memberId: member.member_id,
                      status:
                        member.status === "Active" ? "Inactive" : "Active",
                      expectedMetadataRevision: metadataRevision,
                    },
                    `Set member ${member.member_id} to ${member.status === "Active" ? "Inactive" : "Active"}? The fixed core will reject live references.`,
                  )
                }
              >
                Set member {member.status === "Active" ? "inactive" : "active"}
              </button>
            </div>
          )}
        </details>
      )}
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {result && <p role="status">{result}</p>}
      <p className="authority-note">
        Referential integrity, populated-data guards and all lifecycle effects
        remain fixed-core responsibilities.
      </p>
    </section>
  );
}
