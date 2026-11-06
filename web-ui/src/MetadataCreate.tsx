import { useEffect, useState } from "react";
import { request } from "./api";
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
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  dimensions: Dimension[];
  metadataRevision: number | null;
  onCreated: () => Promise<void>;
  mode?: "all" | "dimension" | "member";
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
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");

  const canCreateDimension = Boolean(
    catalog?.functions["metadata.dimension.create"],
  );
  const canCreateMember = Boolean(catalog?.functions["metadata.member.create"]);
  const completeSnapshot = metadataRevision !== null && dimensions.length > 0;
  const dimensionValid = Boolean(
    completeSnapshot &&
      validMetadataText(dimensionId) &&
      validMetadataText(dimensionName) &&
      dimensionShort.length <= 500 &&
      dimensionSemantic.length <= 10000 &&
      !dimensions.some((item) => item.dimension_id === dimensionId),
  );
  const memberValid = Boolean(
    completeSnapshot &&
      memberDimension &&
      validMetadataText(memberId) &&
      validMetadataText(memberName) &&
      memberShort.length <= 500 &&
      memberSemantic.length <= 10000,
  );
  usePreservedDraft(
    app?.workspaceId || "none",
    app?.applicationId || "none",
    `metadata-create:${mode}`,
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
      setDimensionReviewed(draft.dimensionReviewed);
      setMemberReviewed(draft.memberReviewed);
      setDimensionIntentKey(draft.dimensionIntentKey);
      setMemberIntentKey(draft.memberIntentKey);
    },
  );

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
      kind === "dimension" ? dimensionId : `${memberDimension}/${memberId}`;
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
            dimensionId: memberDimension,
            memberId,
            name: memberName,
            shortDescription: memberShort,
            detailedDescription: memberSemantic,
            expectedMetadataRevision: metadataRevision,
          };
    try {
      const response = await request<{
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
      const receiptId = response.result?.receiptId || response.receiptId;
      setResult(
        receiptId
          ? `Created by receipt ${receiptId}.`
          : `The fixed metadata service created the reviewed ${kind}.`,
      );
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
        <h3 id="metadata-create-heading">Add dimensions and members</h3>
        <p>
          Every change pins metadata revision {metadataRevision ?? "—"} and
          returns through the fixed metadata service.
        </p>
      </div>
      {!completeSnapshot && (
        <p className="inline-error" role="status">
          Read the complete current dimension catalogue before authoring
          metadata.
        </p>
      )}
      {canCreateDimension && mode !== "member" && (
        <fieldset>
          <legend>Dimensions · inline editor</legend>
          <div className="react-grid-scroll">
            <table className="react-cube-grid metadata-inline-grid">
              <thead>
                <tr>
                  <th>Stable ID</th>
                  <th>Name</th>
                  <th>Short description</th>
                  <th>Semantic description</th>
                  <th>Model role</th>
                  <th>Reviewed</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>
                    <input
                      aria-label="Dimension stable ID"
                      value={dimensionId}
                      maxLength={200}
                      onChange={(event) => {
                        setDimensionId(event.target.value);
                        invalidate("dimension");
                      }}
                    />
                  </td>
                  <td>
                    <input
                      aria-label="Dimension name"
                      value={dimensionName}
                      maxLength={200}
                      onChange={(event) => {
                        setDimensionName(event.target.value);
                        invalidate("dimension");
                      }}
                    />
                  </td>
                  <td>
                    <input
                      aria-label="Dimension short description"
                      value={dimensionShort}
                      maxLength={500}
                      onChange={(event) => {
                        setDimensionShort(event.target.value);
                        invalidate("dimension");
                      }}
                    />
                  </td>
                  <td>
                    <textarea
                      aria-label="Dimension semantic description"
                      value={dimensionSemantic}
                      maxLength={10000}
                      onChange={(event) => {
                        setDimensionSemantic(event.target.value);
                        invalidate("dimension");
                      }}
                    />
                  </td>
                  <td>
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
                  </td>
                  <td>
                    <label className="review-check compact-review">
                      <input
                        type="checkbox"
                        checked={dimensionReviewed}
                        disabled={!dimensionValid}
                        onChange={(event) =>
                          setDimensionReviewed(event.target.checked)
                        }
                      />
                      <span>
                        I reviewed this exact dimension and metadata revision.
                      </span>
                    </label>
                  </td>
                  <td>
                    <button
                      disabled={busy || !dimensionReviewed || !dimensionValid}
                      onClick={() => void create("dimension")}
                    >
                      Create dimension
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </fieldset>
      )}
      {canCreateMember && mode !== "dimension" && (
        <fieldset>
          <legend>Members · inline editor</legend>
          <div className="react-grid-scroll">
            <table className="react-cube-grid metadata-inline-grid">
              <thead>
                <tr>
                  <th>Dimension</th>
                  <th>Stable ID</th>
                  <th>Name</th>
                  <th>Short description</th>
                  <th>Semantic description</th>
                  <th>Reviewed</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>
                    <select
                      aria-label="Parent dimension"
                      value={memberDimension}
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
                  </td>
                  <td>
                    <input
                      aria-label="Member stable ID"
                      value={memberId}
                      maxLength={200}
                      onChange={(event) => {
                        setMemberId(event.target.value);
                        invalidate("member");
                      }}
                    />
                  </td>
                  <td>
                    <input
                      aria-label="Member name"
                      value={memberName}
                      maxLength={200}
                      onChange={(event) => {
                        setMemberName(event.target.value);
                        invalidate("member");
                      }}
                    />
                  </td>
                  <td>
                    <input
                      aria-label="Member short description"
                      value={memberShort}
                      maxLength={500}
                      onChange={(event) => {
                        setMemberShort(event.target.value);
                        invalidate("member");
                      }}
                    />
                  </td>
                  <td>
                    <textarea
                      aria-label="Member semantic description"
                      value={memberSemantic}
                      maxLength={10000}
                      onChange={(event) => {
                        setMemberSemantic(event.target.value);
                        invalidate("member");
                      }}
                    />
                  </td>
                  <td>
                    <label className="review-check compact-review">
                      <input
                        type="checkbox"
                        checked={memberReviewed}
                        disabled={!memberValid}
                        onChange={(event) =>
                          setMemberReviewed(event.target.checked)
                        }
                      />
                      <span>
                        I reviewed this exact member and metadata revision.
                      </span>
                    </label>
                  </td>
                  <td>
                    <button
                      disabled={busy || !memberReviewed || !memberValid}
                      onClick={() => void create("member")}
                    >
                      Create member
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
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
