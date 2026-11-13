import { useEffect, useState } from "react";
import { requestAdmittedEffect } from "./api";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { usePreservedDraft } from "./unsaved-work";

type Dimension = {
  dimension_id: string;
  name: string;
  model_role: string;
  status: string;
};

const MODEL_ROLES = [
  "Custom",
  "Account",
  "Entity",
  "Scenario",
  "DataType",
  "Period",
  "Year",
  "View",
  "Value",
  "ICP",
  "Currency",
];

export function validMetadataText(value: string) {
  return Boolean(
    value &&
      value === value.trim() &&
      value.length <= 200 &&
      ![...value].some((character) => character.charCodeAt(0) < 32),
  );
}

export const metadataCreateBody = (
  app: ApplicationSummary,
  kind: "dimension" | "member",
  args: Record<string, unknown>,
  idempotencyKey: string,
) => ({
  workspaceId: app.workspaceId,
  applicationId: app.applicationId,
  confirmed: true,
  idempotencyKey,
  program: {
    languageVersion: 2,
    function: `metadata.${kind}.create`,
    arguments: args,
  },
});

export function MetadataCreate({
  app,
  catalog,
  dimensions,
  metadataRevision,
  onCreated,
  mode = "all",
  dimensionId: contextDimensionId,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  dimensions: Dimension[];
  metadataRevision: number | null;
  onCreated: () => Promise<void>;
  mode?: "all" | "dimension" | "member";
  dimensionId?: string;
}) {
  const [dimensionId, setDimensionId] = useState("");
  const [dimensionName, setDimensionName] = useState("");
  const [dimensionShort, setDimensionShort] = useState("");
  const [dimensionSemantic, setDimensionSemantic] = useState("");
  const [modelRole, setModelRole] = useState("Custom");
  const [memberDimension, setMemberDimension] = useState("");
  const [memberId, setMemberId] = useState("");
  const [memberName, setMemberName] = useState("");
  const [memberShort, setMemberShort] = useState("");
  const [memberSemantic, setMemberSemantic] = useState("");
  const [dimensionReviewed, setDimensionReviewed] = useState(false);
  const [memberReviewed, setMemberReviewed] = useState(false);
  const [dimensionIntentKey, setDimensionIntentKey] = useState(() =>
    crypto.randomUUID(),
  );
  const [memberIntentKey, setMemberIntentKey] = useState(() =>
    crypto.randomUUID(),
  );
  const [draftRevision, setDraftRevision] = useState(metadataRevision);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");

  const canCreateDimension = Boolean(
    catalog?.functions["metadata.dimension.create"],
  );
  const canCreateMember = Boolean(catalog?.functions["metadata.member.create"]);
  const effectiveMemberDimension = contextDimensionId ?? memberDimension;
  const completeSnapshot = metadataRevision !== null && dimensions.length > 0;
  const draftCurrent = draftRevision === metadataRevision;
  const dimensionValid = Boolean(
    completeSnapshot &&
      draftCurrent &&
      validMetadataText(dimensionId) &&
      validMetadataText(dimensionName) &&
      dimensionShort.length <= 500 &&
      dimensionSemantic.length <= 10000 &&
      !dimensions.some((item) => item.dimension_id === dimensionId),
  );
  const memberValid = Boolean(
    completeSnapshot &&
      draftCurrent &&
      effectiveMemberDimension &&
      dimensions.some(
        (item) => item.dimension_id === effectiveMemberDimension,
      ) &&
      validMetadataText(memberId) &&
      validMetadataText(memberName) &&
      memberShort.length <= 500 &&
      memberSemantic.length <= 10000,
  );
  usePreservedDraft(
    app?.workspaceId || "none",
    app?.applicationId || "none",
    `metadata-create:${mode}:${contextDimensionId || "all"}`,
    "Unsaved dimension or member creation",
    Boolean(
      dimensionId ||
        dimensionName ||
        dimensionShort ||
        dimensionSemantic ||
        modelRole !== "Custom" ||
        memberId ||
        memberName ||
        memberShort ||
        memberSemantic,
    ),
    {
      draftRevision,
      dimensionId,
      dimensionName,
      dimensionShort,
      dimensionSemantic,
      modelRole,
      memberDimension,
      memberId,
      memberName,
      memberShort,
      memberSemantic,
      dimensionReviewed,
      memberReviewed,
      dimensionIntentKey,
      memberIntentKey,
    },
    (draft) => {
      setDimensionId(draft.dimensionId);
      setDimensionName(draft.dimensionName);
      setDimensionShort(draft.dimensionShort);
      setDimensionSemantic(draft.dimensionSemantic);
      setModelRole(draft.modelRole);
      setMemberDimension(draft.memberDimension);
      setMemberId(draft.memberId);
      setMemberName(draft.memberName);
      setMemberShort(draft.memberShort);
      setMemberSemantic(draft.memberSemantic);
      setDimensionReviewed(false);
      setMemberReviewed(false);
      setDraftRevision(draft.draftRevision);
      setDimensionIntentKey(draft.dimensionIntentKey);
      setMemberIntentKey(draft.memberIntentKey);
    },
  );

  useEffect(() => {
    setDimensionReviewed(false);
    setMemberReviewed(false);
    if (
      !(
        dimensionId ||
        dimensionName ||
        dimensionShort ||
        dimensionSemantic ||
        modelRole !== "Custom" ||
        memberId ||
        memberName ||
        memberShort ||
        memberSemantic
      )
    ) {
      setDraftRevision(metadataRevision);
    }
  }, [metadataRevision]);

  useEffect(() => {
    setMemberDimension((current) =>
      dimensions.some((item) => item.dimension_id === current)
        ? current
        : dimensions[0]?.dimension_id || "",
    );
  }, [dimensions]);

  function invalidate(kind: "dimension" | "member") {
    if (kind === "dimension") {
      setDimensionReviewed(false);
      setDimensionIntentKey(crypto.randomUUID());
    } else {
      setMemberReviewed(false);
      setMemberIntentKey(crypto.randomUUID());
    }
    setResult("");
  }

  async function create(kind: "dimension" | "member") {
    if (
      !app ||
      metadataRevision === null ||
      busy ||
      (kind === "dimension" &&
        (!canCreateDimension || !dimensionValid || !dimensionReviewed)) ||
      (kind === "member" &&
        (!canCreateMember || !memberValid || !memberReviewed))
    )
      return;
    const label =
      kind === "dimension"
        ? dimensionId
        : `${effectiveMemberDimension}/${memberId}`;
    if (!window.confirm(`Create reviewed ${kind} ${label}?`)) return;
    setBusy(true);
    setError("");
    setResult("");
    const args =
      kind === "dimension"
        ? {
            dimensionId,
            name: dimensionName,
            modelRole,
            shortDescription: dimensionShort,
            detailedDescription: dimensionSemantic,
            expectedMetadataRevision: metadataRevision,
          }
        : {
            dimensionId: effectiveMemberDimension,
            memberId,
            name: memberName,
            shortDescription: memberShort,
            detailedDescription: memberSemantic,
            expectedMetadataRevision: metadataRevision,
          };
    try {
      await requestAdmittedEffect<{
        receiptId?: string;
        result?: { receiptId?: string };
      }>(
        "/api/metadata-action",
        metadataCreateBody(
          app,
          kind,
          args,
          kind === "dimension" ? dimensionIntentKey : memberIntentKey,
        ),
      );
      setResult(`The reviewed ${kind} was created.`);
      if (kind === "dimension") {
        setDimensionId("");
        setDimensionName("");
        setDimensionShort("");
        setDimensionSemantic("");
        setDimensionReviewed(false);
        setDimensionIntentKey(crypto.randomUUID());
      } else {
        setMemberId("");
        setMemberName("");
        setMemberShort("");
        setMemberSemantic("");
        setMemberReviewed(false);
        setMemberIntentKey(crypto.randomUUID());
      }
      await onCreated();
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : `Unable to create ${kind}`,
      );
    } finally {
      setBusy(false);
    }
  }

  if (!canCreateDimension && !canCreateMember) return null;

  return (
    <section
      className="metadata-create"
      aria-labelledby="metadata-create-heading"
    >
      <div>
        <small>REVIEWED MODEL CHANGE</small>
        <h3 id="metadata-create-heading">
          {mode === "dimension"
            ? "New dimension"
            : mode === "member"
              ? "New member"
              : "Add dimensions and members"}
        </h3>
        <p>
          Every change is checked against the current model and returns through
          the fixed metadata service.
        </p>
      </div>
      {!draftCurrent && completeSnapshot && (
        <div className="inline-error" role="status">
          <p>
            Metadata changed since this draft began. Your entries are retained;
            review them against the current model before creating.
          </p>
          <button
            type="button"
            onClick={() => {
              setDraftRevision(metadataRevision);
              setDimensionReviewed(false);
              setMemberReviewed(false);
              setDimensionIntentKey(crypto.randomUUID());
              setMemberIntentKey(crypto.randomUUID());
            }}
          >
            Review against current metadata
          </button>
        </div>
      )}
      {!completeSnapshot && (
        <p className="inline-error" role="status">
          Read the complete current dimension catalogue before authoring
          metadata.
        </p>
      )}
      {canCreateDimension && mode !== "member" && (
        <fieldset className="metadata-create-form" disabled={busy}>
          <legend>Dimension details</legend>
          <div className="metadata-create-fields">
            <label className="form-field">
              <span>Dimension stable ID</span>
              <input
                aria-label="Dimension stable ID"
                value={dimensionId}
                maxLength={200}
                onChange={(event) => {
                  setDimensionId(event.target.value);
                  invalidate("dimension");
                }}
              />
            </label>
            <label className="form-field">
              <span>Dimension name</span>
              <input
                aria-label="Dimension name"
                value={dimensionName}
                maxLength={200}
                onChange={(event) => {
                  setDimensionName(event.target.value);
                  invalidate("dimension");
                }}
              />
            </label>
            <label className="form-field field-wide">
              <span>Dimension short description</span>
              <input
                aria-label="Dimension short description"
                value={dimensionShort}
                maxLength={500}
                onChange={(event) => {
                  setDimensionShort(event.target.value);
                  invalidate("dimension");
                }}
              />
            </label>
            <label className="form-field field-wide">
              <span>Dimension semantic description</span>
              <textarea
                aria-label="Dimension semantic description"
                value={dimensionSemantic}
                maxLength={10000}
                onChange={(event) => {
                  setDimensionSemantic(event.target.value);
                  invalidate("dimension");
                }}
              />
            </label>
            <label className="form-field">
              <span>Dimension model role</span>
              <select
                aria-label="Dimension model role"
                value={modelRole}
                onChange={(event) => {
                  setModelRole(event.target.value);
                  invalidate("dimension");
                }}
              >
                {MODEL_ROLES.map((role) => (
                  <option key={role}>{role}</option>
                ))}
              </select>
            </label>
          </div>
          <div className="metadata-create-actions">
            <label className="review-check compact-review">
              <input
                type="checkbox"
                checked={dimensionReviewed}
                disabled={!dimensionValid}
                onChange={(event) => setDimensionReviewed(event.target.checked)}
              />
              <span>
                I reviewed this exact dimension against the current model.
              </span>
            </label>
            <button
              disabled={busy || !dimensionReviewed || !dimensionValid}
              onClick={() => void create("dimension")}
            >
              Create dimension
            </button>
          </div>
        </fieldset>
      )}
      {canCreateMember && mode !== "dimension" && (
        <fieldset className="metadata-create-form" disabled={busy}>
          <legend>Member details</legend>
          <div className="metadata-create-fields">
            <label className="form-field">
              <span>Parent dimension</span>
              <select
                aria-label="Parent dimension"
                value={effectiveMemberDimension}
                disabled={contextDimensionId !== undefined}
                onChange={(event) => {
                  setMemberDimension(event.target.value);
                  invalidate("member");
                }}
              >
                {dimensions.map((dimension) => (
                  <option
                    key={dimension.dimension_id}
                    value={dimension.dimension_id}
                  >
                    {dimension.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="form-field">
              <span>Member stable ID</span>
              <input
                aria-label="Member stable ID"
                value={memberId}
                maxLength={200}
                onChange={(event) => {
                  setMemberId(event.target.value);
                  invalidate("member");
                }}
              />
            </label>
            <label className="form-field">
              <span>Member name</span>
              <input
                aria-label="Member name"
                value={memberName}
                maxLength={200}
                onChange={(event) => {
                  setMemberName(event.target.value);
                  invalidate("member");
                }}
              />
            </label>
            <label className="form-field field-wide">
              <span>Member short description</span>
              <input
                aria-label="Member short description"
                value={memberShort}
                maxLength={500}
                onChange={(event) => {
                  setMemberShort(event.target.value);
                  invalidate("member");
                }}
              />
            </label>
            <label className="form-field field-wide">
              <span>Member semantic description</span>
              <textarea
                aria-label="Member semantic description"
                value={memberSemantic}
                maxLength={10000}
                onChange={(event) => {
                  setMemberSemantic(event.target.value);
                  invalidate("member");
                }}
              />
            </label>
          </div>
          <div className="metadata-create-actions">
            <label className="review-check compact-review">
              <input
                type="checkbox"
                checked={memberReviewed}
                disabled={!memberValid}
                onChange={(event) => setMemberReviewed(event.target.checked)}
              />
              <span>
                I reviewed this exact member against the current model.
              </span>
            </label>
            <button
              disabled={busy || !memberReviewed || !memberValid}
              onClick={() => void create("member")}
            >
              Create member
            </button>
          </div>
        </fieldset>
      )}
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {result && <p role="status">{result}</p>}
    </section>
  );
}
