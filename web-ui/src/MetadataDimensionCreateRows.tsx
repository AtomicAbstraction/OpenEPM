import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { ApiError, requestAdmittedEffect } from "./api";
import {
  metadataCreateBody,
  metadataModelRoles,
  validMetadataText,
} from "./MetadataCreate";
import { useStableMutationIntentKey } from "./mutation-intent";
import {
  layoutPreviewRead,
  layoutDependencyReview,
  layoutSourceRead,
  MetadataPopulatedLayoutReview,
  useLayoutSource,
  type LayoutMemberDraft,
} from "./MetadataPopulatedLayoutReview";
import {
  LayoutReplacementRequestStatus,
  type useLayoutReplacementRequest,
} from "./LayoutReplacementRequest";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { usePreservedDraft } from "./unsaved-work";

type Dimension = {
  dimension_id: string;
  name: string;
};
const emptyMappingMember: LayoutMemberDraft = { memberId: "", name: "" };

export function MetadataDimensionCreateRows({
  app,
  catalog,
  dimensions,
  metadataRevision,
  open,
  replacement,
  disabled = false,
  onClose,
  onCreated,
  onRefreshCatalog,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  dimensions: Dimension[];
  metadataRevision: number | null;
  open: boolean;
  replacement: ReturnType<typeof useLayoutReplacementRequest>;
  disabled?: boolean;
  onClose: () => void;
  onCreated: () => Promise<void>;
  onRefreshCatalog?: (signal?: AbortSignal) => Promise<ApplicationCatalog>;
}) {
  const mutationIntentKey = useStableMutationIntentKey("dimension-grid-ui");
  const [dimensionId, setDimensionId] = useState("");
  const [name, setName] = useState("");
  const [modelRole, setModelRole] = useState("Custom");
  const [shortDescription, setShortDescription] = useState("");
  const [semanticDescription, setSemanticDescription] = useState("");
  const [mappingMember, setMappingMember] = useState(emptyMappingMember);
  const [draftRevision, setDraftRevision] = useState(metadataRevision);
  const [reviewed, setReviewed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [refreshing, setRefreshing] = useState(false);
  const replacementError = useRef<HTMLParagraphElement>(null);
  const needsLayout = modelRole !== "Currency";
  const inspecting =
    open &&
    needsLayout &&
    !replacement.busy &&
    !replacement.pending &&
    !replacement.recorded;
  const inspection = useLayoutSource(app, catalog, inspecting);
  const populated = Boolean(inspection.source?.coordinateCount);
  const canCreate =
    !needsLayout ||
    !catalog?.functions[layoutSourceRead] ||
    (inspection.source !== undefined && !populated);
  const dirty = Boolean(
    dimensionId ||
      name ||
      shortDescription ||
      semanticDescription ||
      mappingMember.memberId ||
      mappingMember.name ||
      modelRole !== "Custom",
  );
  const current = draftRevision === metadataRevision;
  const valid = Boolean(
    metadataRevision !== null &&
      current &&
      validMetadataText(dimensionId) &&
      validMetadataText(name) &&
      shortDescription.length <= 500 &&
      semanticDescription.length <= 10000 &&
      !dimensions.some((dimension) => dimension.dimension_id === dimensionId),
  );

  usePreservedDraft(
    app?.workspaceId || "none",
    app?.applicationId || "none",
    "metadata-dimension-create-grid",
    "Unsaved dimension creation",
    open && dirty && !replacement.recorded,
    {
      dimensionId,
      name,
      modelRole,
      shortDescription,
      semanticDescription,
      mappingMember,
      draftRevision,
    },
    (saved) => {
      setDimensionId(saved.dimensionId);
      setName(saved.name);
      setModelRole(saved.modelRole);
      setShortDescription(saved.shortDescription);
      setSemanticDescription(saved.semanticDescription);
      setMappingMember(saved.mappingMember ?? emptyMappingMember);
      setDraftRevision(saved.draftRevision);
      setReviewed(false);
    },
  );

  useEffect(() => {
    setReviewed(false);
    if (!dirty) setDraftRevision(metadataRevision);
  }, [metadataRevision, open]);
  useEffect(() => {
    if (replacement.recorded) reset();
  }, [replacement.recorded, metadataRevision]);
  useLayoutEffect(() => {
    if (replacement.message) replacementError.current?.focus();
  }, [replacement.message, replacement.busy, replacement.pending]);

  function change(action: () => void) {
    action();
    setReviewed(false);
    setError("");
  }

  function reset() {
    setDimensionId("");
    setName("");
    setModelRole("Custom");
    setShortDescription("");
    setSemanticDescription("");
    setMappingMember(emptyMappingMember);
    setDraftRevision(metadataRevision);
    setReviewed(false);
    setError("");
  }

  async function create() {
    if (
      !app ||
      !catalog?.functions["metadata.dimension.create"] ||
      !canCreate ||
      disabled ||
      busy ||
      !valid ||
      !reviewed ||
      metadataRevision === null ||
      !window.confirm(`Create reviewed dimension ${name}?`)
    )
      return;
    const args = {
      dimensionId,
      name,
      modelRole,
      shortDescription,
      detailedDescription: semanticDescription,
      expectedMetadataRevision: metadataRevision,
    };
    setBusy(true);
    setError("");
    try {
      await requestAdmittedEffect(
        "/api/metadata-action",
        metadataCreateBody(
          app,
          "dimension",
          args,
          mutationIntentKey({
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            functionName: "metadata.dimension.create",
            args,
          }),
        ),
      );
      reset();
      onClose();
      await onCreated();
    } catch (reason) {
      setError(
        reason instanceof ApiError &&
          reason.code === "POPULATED_AXIS_REBUILD_REQUIRED"
          ? "The model now has data at its current grain. Refresh the layout to map it before adding a dimension."
          : reason instanceof Error
            ? reason.message
            : "Unable to create dimension",
      );
      if (
        reason instanceof ApiError &&
        reason.code === "POPULATED_AXIS_REBUILD_REQUIRED"
      )
        setReviewed(false);
    } finally {
      setBusy(false);
    }
  }

  async function refreshLayout() {
    setRefreshing(true);
    setReviewed(false);
    setError("");
    try {
      await onRefreshCatalog?.();
      await onCreated();
      inspection.refresh();
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Could not refresh the layout.",
      );
    } finally {
      setRefreshing(false);
    }
  }

  if (replacement.busy || replacement.pending || replacement.recorded)
    return (
      <tr className="metadata-draft-review-row">
        <td colSpan={5}>
          <LayoutReplacementRequestStatus
            scope={app}
            catalog={catalog}
            operation={replacement}
            onClose={() => {
              replacement.closeRecorded();
              onClose();
            }}
          />
        </td>
      </tr>
    );

  if (!open) return null;

  return (
    <>
      <tr className="metadata-draft-row">
        <th scope="row">
          <div className="metadata-dimension-draft-name">
            <input
              aria-label="New dimension stable ID"
              maxLength={200}
              placeholder="Stable ID"
              value={dimensionId}
              onChange={(event) =>
                change(() => setDimensionId(event.target.value))
              }
            />
            <input
              aria-label="New dimension name"
              maxLength={200}
              placeholder="Display name"
              value={name}
              onChange={(event) => change(() => setName(event.target.value))}
            />
          </div>
        </th>
        <td>
          <select
            aria-label="New dimension model role"
            value={modelRole}
            onChange={(event) => change(() => setModelRole(event.target.value))}
          >
            {metadataModelRoles.map((role) => (
              <option key={role}>{role}</option>
            ))}
          </select>
        </td>
        <td>Active</td>
        <td>
          <input
            aria-label="New dimension short description"
            maxLength={500}
            placeholder="Optional description"
            value={shortDescription}
            onChange={(event) =>
              change(() => setShortDescription(event.target.value))
            }
          />
        </td>
        <td>Draft</td>
      </tr>
      <tr className="metadata-draft-review-row">
        <td colSpan={5}>
          {!current && metadataRevision !== null && (
            <div className="inline-error" role="status">
              Metadata changed while this row was being drafted.
              <button
                type="button"
                onClick={() => {
                  setDraftRevision(metadataRevision);
                  setReviewed(false);
                }}
              >
                Review against current metadata
              </button>
            </div>
          )}
          {error && (
            <div className="inline-error" role="alert">
              {error}
            </div>
          )}
          <label className="metadata-inline-semantic">
            Semantic description
            <textarea
              aria-label="New dimension semantic description"
              maxLength={10000}
              placeholder="Optional business meaning"
              value={semanticDescription}
              onChange={(event) =>
                change(() => setSemanticDescription(event.target.value))
              }
            />
          </label>
          {inspection.checking && (
            <p role="status">Checking the current layout…</p>
          )}
          {inspection.error && (
            <p className="inline-error" role="alert">
              {inspection.error}
            </p>
          )}
          {replacement.message && (
            <p
              ref={replacementError}
              tabIndex={-1}
              className="inline-error"
              role="alert"
            >
              {replacement.message}
            </p>
          )}
          {populated && modelRole !== "Custom" && (
            <p>
              This model already has data. A new axis for that data must use the
              Custom role.
            </p>
          )}
          {app &&
            populated &&
            modelRole === "Custom" &&
            inspection.source &&
            !refreshing && (
              <MetadataPopulatedLayoutReview
                app={app}
                source={inspection.source}
                dimension={{
                  dimensionId,
                  name,
                  shortDescription,
                  detailedDescription: semanticDescription,
                }}
                member={mappingMember}
                onMemberChange={setMappingMember}
                canPreview={
                  valid &&
                  !disabled &&
                  Boolean(catalog?.functions[layoutPreviewRead])
                }
                canReviewDependencies={Boolean(
                  catalog?.functions[layoutDependencyReview],
                )}
                onRequestReplacement={
                  replacement.canSubmit
                    ? (intent) => void replacement.submit(intent)
                    : undefined
                }
              />
            )}
          <div className="metadata-create-actions">
            {canCreate && (
              <>
                <label className="review-check compact-review">
                  <input
                    aria-label="Review new dimension"
                    type="checkbox"
                    checked={reviewed}
                    disabled={!valid || busy || disabled || refreshing}
                    onChange={(event) => setReviewed(event.target.checked)}
                  />
                  <span>
                    I reviewed this exact dimension against the current model.
                  </span>
                </label>
                <button
                  type="button"
                  disabled={
                    !reviewed || !valid || busy || disabled || refreshing
                  }
                  onClick={() => void create()}
                >
                  Create dimension
                </button>
              </>
            )}
            {needsLayout && catalog?.functions[layoutSourceRead] != null && (
              <button
                type="button"
                className="secondary"
                disabled={refreshing || busy}
                onClick={() => void refreshLayout()}
              >
                Refresh layout
              </button>
            )}
            <button
              type="button"
              className="secondary"
              disabled={busy || refreshing}
              onClick={() => {
                if (
                  !dirty ||
                  window.confirm("Discard this new dimension row?")
                ) {
                  reset();
                  onClose();
                }
              }}
            >
              Cancel row
            </button>
          </div>
        </td>
      </tr>
    </>
  );
}
