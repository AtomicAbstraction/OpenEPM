import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { requestAdmittedEffect } from "./api";
import { validMetadataText } from "./MetadataCreate";
import {
  focusWhenInteractive,
  MetadataReceiptRecovery,
} from "./MetadataReceiptRecovery";
import {
  useMetadataMutationRecovery,
  type MetadataMutationRecord,
} from "./metadata-mutation-recovery";
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

type DraftField =
  | "dimensionName"
  | "dimensionShort"
  | "dimensionDetailed"
  | "dimensionDeleteText"
  | "memberName"
  | "memberShort"
  | "memberDetailed"
  | "memberNumericKind";

type DraftValues = Partial<Record<DraftField, string>>;
type MaintenanceDraft = {
  owner: string;
  revision: number | null;
  values: DraftValues;
};

const reviewedFields: Record<Action, readonly DraftField[]> = {
  "dimension-rename": ["dimensionName"],
  "dimension-describe": ["dimensionShort", "dimensionDetailed"],
  "dimension-status": [],
  "dimension-delete": ["dimensionDeleteText"],
  "member-rename": ["memberName"],
  "member-describe": ["memberShort", "memberDetailed"],
  "member-numeric-kind": ["memberNumericKind"],
  "member-status": [],
};

const dimensionFunctions = [
  "metadata.dimension.rename",
  "metadata.dimension.describe",
  "metadata.dimension.status.set",
] as const;
const memberFunctions = [
  "metadata.member.rename",
  "metadata.member.describe",
  "metadata.member.numeric-kind.set",
  "metadata.member.status.set",
] as const;
const maintenanceFunctions = [...dimensionFunctions, ...memberFunctions];

const uncommittedMaintenanceRefusals = new Set([
  "ACTIVE_DIMENSION_REQUIRED",
  "ACTIVE_MEMBER_REQUIRED",
  "APPLICATION_UNAVAILABLE",
  "DIMENSION_STATUS_UNCHANGED",
  "DIMENSION_UNAVAILABLE",
  "MEMBER_NUMERIC_KIND_INVALID",
  "MEMBER_NUMERIC_KIND_UNCHANGED",
  "MEMBER_STATUS_UNCHANGED",
  "MEMBER_UNAVAILABLE",
  "METADATA_DESCRIPTION_UNCHANGED",
  "METADATA_NAME_UNCHANGED",
  "METADATA_REFERENCE_AMBIGUOUS",
  "MODEL_ROLE_ALREADY_ACTIVE",
  "PROGRAMMABLE_REQUIRED_DIMENSION",
  "SAVED_GRID_REFERENCE_INTEGRITY_INVALID",
  "SEMANTIC_REFERENCE_MEMBER_UNAVAILABLE",
]);

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
  mode = "all",
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  dimension?: Dimension;
  members: Member[];
  metadataRevision: number | null;
  onChanged: () => Promise<void>;
  selectedMemberId?: string;
  onSelectedMemberIdChange?: (memberId: string) => void;
  mode?: "dimension" | "member" | "all";
}) {
  const mutationIntentKey = useStableMutationIntentKey(
    "metadata-maintenance-ui",
  );
  const [memberId, setMemberId] = useState("");
  const [savedDraft, setSavedDraft] = useState<MaintenanceDraft | null>(null);
  const [review, setReview] = useState<{
    owner: string;
    revision: number | null;
    action: Action;
  } | null>(null);
  const [recorded, setRecorded] = useState<{
    owner: string;
    revision: number;
    source: MetadataMutationRecord;
  } | null>(null);
  const [refreshing, setRefreshing] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [deletionError, setDeletionError] = useState<{
    owner: string;
    message: string;
  } | null>(null);

  const effectiveMemberId =
    selectedMemberId === undefined ? memberId : selectedMemberId;
  const member = members.find((item) => item.member_id === effectiveMemberId);
  const editor = JSON.stringify([
    mode,
    dimension?.dimension_id,
    mode === "dimension" ? null : effectiveMemberId,
  ]);
  const actorId = catalog?.applicationAccess.subjectId;
  const owner = JSON.stringify([
    app?.workspaceId,
    app?.applicationId,
    catalog?.applicationAccess.issuer,
    actorId,
    editor,
  ]);
  const currentOwner = useRef(owner);
  currentOwner.current = owner;
  const authority = JSON.stringify([
    owner,
    catalog?.applicationAccess.role,
    catalog?.revisions.metadata,
    catalog?.revisions.policy,
    catalog?.revisions.security,
    catalog?.revisions.capability,
  ]);
  const draft = savedDraft?.owner === owner ? savedDraft : null;
  const draftRevision = draft ? draft.revision : metadataRevision;
  const baseFields: Record<DraftField, string> = {
    dimensionName: dimension?.name || "",
    dimensionShort: dimension?.short_description || "",
    dimensionDetailed: dimension?.detailed_description || "",
    dimensionDeleteText: "",
    memberName: member?.name || "",
    memberShort: member?.short_description || "",
    memberDetailed: member?.detailed_description || "",
    memberNumericKind: member?.numeric_value_kind || "",
  };
  const fields = { ...baseFields, ...draft?.values };
  const {
    dimensionName,
    dimensionShort,
    dimensionDetailed,
    dimensionDeleteText,
    memberName,
    memberShort,
    memberDetailed,
    memberNumericKind,
  } = fields;
  const reviewedAction =
    review?.owner === owner && review.revision === metadataRevision
      ? review.action
      : null;
  const result = recorded?.owner === owner ? recorded : null;
  const resultStatus = useRef<HTMLParagraphElement>(null);
  const receiptFocusOwner = useRef<string | null>(null);
  const deletionMessage =
    deletionError?.owner === owner ? deletionError.message : "";
  const needsRefresh =
    result !== null &&
    (metadataRevision === null || metadataRevision <= result.revision);
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
  const functions =
    mode === "dimension"
      ? dimensionFunctions
      : mode === "member"
        ? memberFunctions
        : maintenanceFunctions;
  const hasAnyAction =
    (mode !== "member" && canDimensionDelete) ||
    functions.some((name) => Boolean(catalog?.functions[name]));
  const snapshotAvailable = Boolean(dimension && metadataRevision !== null);
  const recovery = useMetadataMutationRecovery<{
    actorId: string;
    metadataRevision: number;
    owner: string;
    submittedFields: DraftValues;
  }>(
    app,
    catalog,
    authority,
    {
      editor: `metadata-maintenance-change:${editor}`,
      pendingLabel: "Metadata change with an unconfirmed outcome",
      functions,
      subject: "metadata change",
      closePrompt:
        "Close this unconfirmed metadata change? Read the current model before reviewing another change.",
      refuses: (code) =>
        uncommittedMaintenanceRefusals.has(code) ||
        code.startsWith("DIMENSION_HAS_") ||
        code.startsWith("MEMBER_HAS_"),
    },
    (attempt, source) => {
      if (currentOwner.current !== attempt.owner) return;
      setSavedDraft((current) => {
        if (!current || current.owner !== attempt.owner) return current;
        const values = { ...current.values };
        for (const field of Object.keys(
          attempt.submittedFields,
        ) as DraftField[]) {
          if (values[field] === attempt.submittedFields[field])
            delete values[field];
        }
        return Object.keys(values).length ? { ...current, values } : null;
      });
      setReview(null);
      if (source === "receipt") receiptFocusOwner.current = attempt.owner;
      setRecorded({
        owner: attempt.owner,
        revision: attempt.metadataRevision,
        source,
      });
      void refreshModel();
    },
  );
  const busy =
    recovery.busy ||
    recovery.pending ||
    refreshing === owner ||
    deleting === owner;
  const snapshotCurrent =
    snapshotAvailable && draftRevision === metadataRevision && !needsRefresh;

  useLayoutEffect(() => setReview(null), [authority, metadataRevision]);

  usePreservedDraft(
    app?.workspaceId || "none",
    app?.applicationId || "none",
    `metadata-maintenance:${editor}`,
    "Unsaved dimension or member changes",
    Boolean(draft),
    draft,
    (restored) => {
      if (restored?.owner === owner) setSavedDraft(restored);
      setReview(null);
    },
  );

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
    if (
      result?.source === "receipt" &&
      receiptFocusOwner.current === owner &&
      refreshing !== owner
    ) {
      receiptFocusOwner.current = null;
      return focusWhenInteractive(resultStatus.current);
    }
  }, [owner, refreshing, result]);

  function setField(field: DraftField, value: string) {
    setSavedDraft((current) => {
      const currentDraft = current?.owner === owner ? current : null;
      const values = { ...currentDraft?.values };
      if (value === baseFields[field]) delete values[field];
      else values[field] = value;
      return Object.keys(values).length
        ? {
            owner,
            revision: currentDraft ? currentDraft.revision : metadataRevision,
            values,
          }
        : null;
    });
    setReview(null);
    setDeletionError(null);
    if (!needsRefresh) setRecorded(null);
  }

  async function refreshModel() {
    setRefreshing(owner);
    try {
      await onChanged();
    } catch {
      // The current snapshot still gates review. The recorded outcome is retained.
    } finally {
      setRefreshing((key) => (key === owner ? null : key));
    }
  }

  async function execute(
    action: Action,
    functionName: string,
    args: Record<string, unknown>,
    confirmation: string,
  ) {
    if (
      !app ||
      metadataRevision === null ||
      !snapshotCurrent ||
      busy ||
      reviewedAction !== action ||
      !window.confirm(confirmation)
    )
      return;
    const body = metadataMaintenanceBody(
      app,
      functionName,
      args,
      mutationIntentKey({
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
        functionName,
        args,
      }),
    );
    if (action !== "dimension-delete") {
      if (!actorId) return;
      const submittedFields = Object.fromEntries(
        reviewedFields[action].map((field) => [field, fields[field]]),
      );
      await recovery.submit(body, {
        actorId,
        metadataRevision,
        owner,
        submittedFields,
      });
      return;
    }
    setDeleting(owner);
    setDeletionError(null);
    try {
      await requestAdmittedEffect("/api/metadata-action", body);
      if (currentOwner.current !== owner) return;
      setRecorded({ owner, revision: metadataRevision, source: "reply" });
      setReview(null);
      setSavedDraft(null);
      await onChanged();
    } catch (reason) {
      setDeletionError({
        owner,
        message:
          reason instanceof Error
            ? reason.message
            : "Unable to apply metadata change",
      });
    } finally {
      setDeleting((key) => (key === owner ? null : key));
    }
  }

  function reviewAction(action: Action, valid: boolean, label: string) {
    return (
      <label className="review-check">
        <input
          type="checkbox"
          checked={reviewedAction === action}
          disabled={!valid || busy}
          onChange={(event) =>
            setReview(
              event.target.checked
                ? { owner, revision: metadataRevision, action }
                : null,
            )
          }
        />
        {label}
      </label>
    );
  }

  if (!hasAnyAction && !recovery.pending && !result) return null;

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
        <h3 id="metadata-maintenance-heading">
          {mode === "dimension"
            ? "Dimension properties"
            : mode === "member"
              ? "Member properties"
              : "Inline metadata editor"}
        </h3>
        <p>
          Rename, describe and change lifecycle state only against the current
          model. Dependency guards remain server-owned.
        </p>
      </div>
      <MetadataReceiptRecovery
        object="metadata"
        recovery={recovery}
        onClose={() => {
          if (recovery.closeRecovery()) {
            setReview(null);
            void refreshModel();
          }
        }}
      />
      {hasAnyAction &&
        snapshotAvailable &&
        draftRevision !== metadataRevision && (
          <div className="inline-error" role="status">
            <p>
              Metadata changed since this draft began. Your entries are
              retained; review them against the current model before saving.
            </p>
            <button
              type="button"
              disabled={busy || needsRefresh}
              onClick={() => {
                setSavedDraft((current) =>
                  current?.owner === owner
                    ? { ...current, revision: metadataRevision }
                    : current,
                );
                setReview(null);
              }}
            >
              Review against current metadata
            </button>
          </div>
        )}
      {hasAnyAction && !snapshotAvailable && (
        <p className="inline-error" role="status">
          Read the current dimension catalogue before maintaining metadata.
        </p>
      )}
      {mode !== "member" && dimension && (
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
                    setField("dimensionName", event.target.value);
                  }}
                />
              </label>
              <div className="reviewed-inline-action">
                {reviewAction(
                  "dimension-rename",
                  dimensionRenameValid,
                  "I reviewed this exact dimension name against the current model.",
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
                    setField("dimensionShort", event.target.value);
                  }}
                />
              </label>
              <label>
                Dimension detailed description
                <textarea
                  value={dimensionDetailed}
                  maxLength={10000}
                  onChange={(event) => {
                    setField("dimensionDetailed", event.target.value);
                  }}
                />
              </label>
              <div className="reviewed-inline-action">
                {reviewAction(
                  "dimension-describe",
                  dimensionDescribeValid,
                  "I reviewed these exact dimension descriptions against the current model.",
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
              {reviewAction(
                "dimension-status",
                snapshotCurrent,
                `I reviewed changing this dimension to ${dimension.status === "Active" ? "Inactive" : "Active"} in the current model.`,
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
                    setField("dimensionDeleteText", event.target.value);
                  }}
                />
              </label>
              <div className="reviewed-inline-action">
                {reviewAction(
                  "dimension-delete",
                  dimensionDeleteText === dimension.dimension_id,
                  "I reviewed this exact inactive dimension deletion against the current model.",
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
      {mode !== "dimension" && members.length > 0 && (
        <details
          className="metadata-edit-grid"
          open={mode === "member" ? true : undefined}
        >
          <summary>Member rows</summary>
          {!(mode === "member" && selectedMemberId !== undefined) && (
            <label>
              Member
              <select
                value={effectiveMemberId}
                onChange={(event) => {
                  if (selectedMemberId === undefined)
                    setMemberId(event.target.value);
                  onSelectedMemberIdChange?.(event.target.value);
                  setReview(null);
                }}
              >
                {members.map((item) => (
                  <option key={item.member_id} value={item.member_id}>
                    {item.name}
                  </option>
                ))}
              </select>
            </label>
          )}
          {member && canMemberRename && (
            <div className="maintenance-action">
              <label>
                Member display name
                <input
                  value={memberName}
                  maxLength={200}
                  onChange={(event) => {
                    setField("memberName", event.target.value);
                  }}
                />
              </label>
              <div className="reviewed-inline-action">
                {reviewAction(
                  "member-rename",
                  memberRenameValid,
                  "I reviewed this exact member name against the current model.",
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
                    setField("memberShort", event.target.value);
                  }}
                />
              </label>
              <label>
                Member detailed description
                <textarea
                  value={memberDetailed}
                  maxLength={10000}
                  onChange={(event) => {
                    setField("memberDetailed", event.target.value);
                  }}
                />
              </label>
              <div className="reviewed-inline-action">
                {reviewAction(
                  "member-describe",
                  memberDescribeValid,
                  "I reviewed these exact member descriptions against the current model.",
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
                    setField("memberNumericKind", event.target.value);
                  }}
                >
                  <option value="">Unspecified</option>
                  <option value="amount">Amount</option>
                  <option value="ratio">Ratio</option>
                </select>
              </label>
              <div className="reviewed-inline-action">
                {reviewAction(
                  "member-numeric-kind",
                  memberNumericValid,
                  "I reviewed this exact member numeric kind against the current model.",
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
              {reviewAction(
                "member-status",
                snapshotCurrent,
                `I reviewed changing this member to ${member.status === "Active" ? "Inactive" : "Active"} in the current model.`,
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
      {deletionMessage && (
        <div className="inline-error" role="alert">
          {deletionMessage}
        </div>
      )}
      {result && (
        <p
          role="status"
          tabIndex={result.source === "receipt" ? -1 : undefined}
          ref={resultStatus}
        >
          {result.source === "receipt"
            ? "The original metadata change was recorded."
            : "The reviewed metadata change was applied."}
        </p>
      )}
      {hasAnyAction && needsRefresh && (
        <div>
          <p role="status">
            Read the current model before reviewing another metadata change.
          </p>
          <button
            type="button"
            disabled={busy}
            onClick={() => void refreshModel()}
          >
            Refresh current model
          </button>
        </div>
      )}
      <p className="authority-note">
        Referential integrity, populated-data guards and all lifecycle effects
        remain fixed-core responsibilities.
      </p>
    </section>
  );
}
