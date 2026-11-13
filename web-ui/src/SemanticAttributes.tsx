import { useEffect, useLayoutEffect, useState } from "react";
import { readProgram, requestAdmittedEffect } from "./api";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";

type Member = { member_id: string; name: string; status: string };
type Dimension = { dimension_id: string; name: string; status: string };

type SemanticColumn = {
  slot: number;
  key: string;
  display_name: string;
  semantic_definition: string;
  population_guidance: string;
  restrictions: string;
  properties: {
    valueType?: string;
    allowedValues?: string[];
    referenceDimensionId?: string | null;
  };
};

type Attribute = SemanticColumn & { value: unknown };

export function semanticDefinitionArguments(dimensionId: string) {
  return { dimensionId };
}

export function semanticAttributeArguments(
  dimensionId: string,
  memberId: string,
) {
  return { dimensionId, memberId };
}

export function relationshipAttributeArguments(
  dimensionId: string,
  relationshipId: string,
) {
  return { dimensionId, relationshipId };
}

export function semanticMutationBody(
  app: ApplicationSummary,
  functionName: string,
  args: Record<string, unknown>,
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    confirmed: true,
    idempotencyKey,
    program: {
      languageVersion: 2,
      function: functionName,
      arguments: args,
    },
  };
}

export function exactAllowedValues(value: string) {
  const values = value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  if (values.length > 100) throw new Error("At most 100 values are allowed.");
  if (values.length !== new Set(values).size)
    throw new Error("Allowed values contain a duplicate.");
  if (values.some((item) => item.length > 200 || item.includes("\0")))
    throw new Error("Allowed values must be 1-200 characters.");
  return values;
}

export function exactSemanticValue(
  valueType: string,
  raw: string,
  clear: boolean,
) {
  if (clear) return null;
  if (valueType === "Boolean") {
    const normalized = raw.trim().toLowerCase();
    if (normalized !== "true" && normalized !== "false")
      throw new Error("Boolean values must be true or false.");
    return normalized === "true";
  }
  if (
    valueType === "Decimal" &&
    !/^[+-]?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/.test(raw)
  )
    throw new Error("Enter an exact decimal without exponent notation.");
  if (valueType !== "Text" && !raw)
    throw new Error("Enter a typed value or choose Clear.");
  return raw;
}

function displayValue(value: unknown) {
  if (value === null || value === undefined) return "Not set";
  if (typeof value === "boolean") return value ? "True" : "False";
  return String(value);
}

export function SemanticAttributes({
  app,
  catalog,
  dimensionId,
  dimensions,
  members,
  metadataRevision,
  onChanged,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  dimensionId: string;
  dimensions: Dimension[];
  members: Member[];
  metadataRevision: number | null;
  onChanged: () => Promise<void>;
}) {
  const mutationIntentKey = useStableMutationIntentKey("semantic-ui");
  const [columns, setColumns] = useState<SemanticColumn[]>([]);
  const [relationshipColumns, setRelationshipColumns] = useState<
    SemanticColumn[]
  >([]);
  const [definitionRevision, setDefinitionRevision] = useState<number | null>(
    null,
  );
  const [memberId, setMemberId] = useState("");
  const [attributes, setAttributes] = useState<Attribute[]>([]);
  const [relationshipId, setRelationshipId] = useState("");
  const [relationshipAttributes, setRelationshipAttributes] = useState<
    Attribute[]
  >([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
  const [editScope, setEditScope] = useState<"member" | "relationship">(
    "member",
  );
  const [editSlot, setEditSlot] = useState(1);
  const [editName, setEditName] = useState("");
  const [editType, setEditType] = useState("Text");
  const [editMeaning, setEditMeaning] = useState("");
  const [editGuidance, setEditGuidance] = useState("");
  const [editRestrictions, setEditRestrictions] = useState("");
  const [editAllowedValues, setEditAllowedValues] = useState("");
  const [editReferenceDimension, setEditReferenceDimension] = useState("");
  const [reviewedDefinitionAction, setReviewedDefinitionAction] = useState<
    "create" | "update" | ""
  >("");
  const [editValue, setEditValue] = useState("");
  const [clearValue, setClearValue] = useState(false);
  const [reviewedValue, setReviewedValue] = useState(false);
  const [definitionTouched, setDefinitionTouched] = useState(false);
  useUnsavedWork(
    "semantic-attribute-definition",
    "Unpublished semantic attribute definition",
    definitionTouched,
  );
  useUnsavedWork(
    "semantic-attribute-value",
    "Unpublished semantic attribute value",
    Boolean(editValue || clearValue || reviewedValue),
  );

  const canList = Boolean(catalog?.functions["metadata.semantic_column.list"]);
  const canRead = Boolean(
    catalog?.functions["metadata.member.attributes.read"],
  );
  const canListRelationships = Boolean(
    catalog?.functions["metadata.relationship.semantic_column.list"],
  );
  const canReadRelationship = Boolean(
    catalog?.functions["metadata.relationship.attributes.read"],
  );
  const canCreateMemberDefinition = Boolean(
    catalog?.functions["metadata.semantic_column.create"],
  );
  const canUpdateMemberDefinition = Boolean(
    catalog?.functions["metadata.semantic_column.update"],
  );
  const canCreateRelationshipDefinition = Boolean(
    catalog?.functions["metadata.relationship.semantic_column.create"],
  );
  const canUpdateRelationshipDefinition = Boolean(
    catalog?.functions["metadata.relationship.semantic_column.update"],
  );
  const canSetMemberValue = Boolean(
    catalog?.functions["metadata.member.attribute.set"],
  );
  const canSetRelationshipValue = Boolean(
    catalog?.functions["metadata.relationship.attribute.set"],
  );
  const activeMembers = members.filter((member) => member.status === "Active");
  const snapshotCurrent = Boolean(
    metadataRevision !== null && definitionRevision === metadataRevision,
  );

  useEffect(() => {
    setColumns([]);
    setRelationshipColumns([]);
    setDefinitionRevision(null);
    setAttributes([]);
    setRelationshipId("");
    setRelationshipAttributes([]);
    setError("");
    setResult("");
    setReviewedDefinitionAction("");
    setEditValue("");
    setClearValue(false);
    setReviewedValue(false);
    setDefinitionTouched(false);
  }, [app?.workspaceId, app?.applicationId, dimensionId, metadataRevision]);

  useEffect(() => {
    setMemberId((current) =>
      activeMembers.some((member) => member.member_id === current)
        ? current
        : activeMembers[0]?.member_id || "",
    );
    setAttributes([]);
    setRelationshipAttributes([]);
  }, [dimensionId, members]);

  useEffect(() => {
    if (canList && app && dimensionId && metadataRevision !== null)
      void readDefinitions();
  }, [
    app?.workspaceId,
    app?.applicationId,
    dimensionId,
    metadataRevision,
    canList,
  ]);

  if (!canList) return null;

  async function readDefinitions() {
    if (!app || !dimensionId) return;
    setBusy(true);
    setError("");
    setAttributes([]);
    try {
      const readArguments = semanticDefinitionArguments(dimensionId);
      const [memberResult, relationshipResult] = await Promise.all([
        readProgram<{
          columns: SemanticColumn[];
          metadataRevision: number;
        }>(
          { workspaceId: app.workspaceId, applicationId: app.applicationId },
          "metadata.semantic_column.list",
          readArguments,
        ),
        canListRelationships
          ? readProgram<{
              columns: SemanticColumn[];
              metadataRevision: number;
            }>(
              {
                workspaceId: app.workspaceId,
                applicationId: app.applicationId,
              },
              "metadata.relationship.semantic_column.list",
              readArguments,
            )
          : Promise.resolve(null),
      ]);
      if (
        metadataRevision !== null &&
        memberResult.metadataRevision !== metadataRevision
      )
        throw new Error(
          "Metadata changed while reading semantic definitions. Refresh dimensions and try again.",
        );
      if (
        relationshipResult &&
        relationshipResult.metadataRevision !== memberResult.metadataRevision
      )
        throw new Error(
          "Metadata changed during semantic discovery. Refresh dimensions and try again.",
        );
      setColumns(memberResult.columns);
      setRelationshipColumns(relationshipResult?.columns || []);
      setDefinitionRevision(memberResult.metadataRevision);
    } catch (reason) {
      setColumns([]);
      setRelationshipColumns([]);
      setDefinitionRevision(null);
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read semantic definitions",
      );
    } finally {
      setBusy(false);
    }
  }

  async function readAttributes() {
    if (!app || !dimensionId || !memberId || !canRead || !snapshotCurrent)
      return;
    setBusy(true);
    setError("");
    try {
      const result = await readProgram<{
        attributes: Attribute[];
        metadataRevision: number;
      }>(
        { workspaceId: app.workspaceId, applicationId: app.applicationId },
        "metadata.member.attributes.read",
        semanticAttributeArguments(dimensionId, memberId),
      );
      if (result.metadataRevision !== definitionRevision)
        throw new Error(
          "Metadata changed while reading member attributes. Refresh definitions and try again.",
        );
      setAttributes(result.attributes);
    } catch (reason) {
      setAttributes([]);
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read member attributes",
      );
    } finally {
      setBusy(false);
    }
  }

  async function readRelationshipAttributes() {
    if (
      !app ||
      !dimensionId ||
      !relationshipId.trim() ||
      !canReadRelationship ||
      !snapshotCurrent
    )
      return;
    setBusy(true);
    setError("");
    try {
      const result = await readProgram<{
        attributes: Attribute[];
        metadataRevision: number;
      }>(
        { workspaceId: app.workspaceId, applicationId: app.applicationId },
        "metadata.relationship.attributes.read",
        relationshipAttributeArguments(dimensionId, relationshipId.trim()),
      );
      if (result.metadataRevision !== definitionRevision)
        throw new Error(
          "Metadata changed while reading relationship attributes. Refresh definitions and try again.",
        );
      setRelationshipAttributes(result.attributes);
    } catch (reason) {
      setRelationshipAttributes([]);
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read relationship attributes",
      );
    } finally {
      setBusy(false);
    }
  }

  const allColumns = [
    ...columns.map((column) => ({ ...column, scope: "Member" })),
    ...relationshipColumns.map((column) => ({
      ...column,
      scope: "Relationship",
    })),
  ];
  const scopedColumns = editScope === "member" ? columns : relationshipColumns;
  const selectedDefinition = scopedColumns.find(
    (column) => column.slot === editSlot,
  );
  const maximumSlot = editScope === "member" ? 30 : 20;
  const canCreateDefinition =
    editScope === "member"
      ? canCreateMemberDefinition
      : canCreateRelationshipDefinition;
  const canUpdateDefinition =
    editScope === "member"
      ? canUpdateMemberDefinition
      : canUpdateRelationshipDefinition;

  useLayoutEffect(() => {
    setEditName(selectedDefinition?.display_name || "");
    setEditType(selectedDefinition?.properties?.valueType || "Text");
    setEditMeaning(selectedDefinition?.semantic_definition || "");
    setEditGuidance(selectedDefinition?.population_guidance || "");
    setEditRestrictions(selectedDefinition?.restrictions || "");
    setEditAllowedValues(
      selectedDefinition?.properties?.allowedValues?.join(", ") || "",
    );
    setEditReferenceDimension(
      selectedDefinition?.properties?.referenceDimensionId ||
        dimensions.find((dimension) => dimension.status === "Active")
          ?.dimension_id ||
        "",
    );
    setReviewedDefinitionAction("");
    setEditValue("");
    setClearValue(false);
    setReviewedValue(false);
    setResult("");
    setDefinitionTouched(false);
  }, [editScope, editSlot, selectedDefinition?.key, definitionRevision]);

  function invalidateDefinitionReview() {
    setDefinitionTouched(true);
    setReviewedDefinitionAction("");
    setResult("");
  }

  function definitionDraftValid() {
    if (
      !snapshotCurrent ||
      !Number.isInteger(editSlot) ||
      editSlot < 1 ||
      editSlot > maximumSlot ||
      !editName.trim() ||
      editName.length > 200 ||
      !editMeaning.trim() ||
      editMeaning.length > 2000 ||
      editGuidance.length > 2000 ||
      editRestrictions.length > 2000
    )
      return false;
    if (!selectedDefinition && editType === "MemberReference")
      return Boolean(editReferenceDimension);
    if (
      selectedDefinition &&
      editName.trim() === selectedDefinition.display_name &&
      editMeaning.trim() === selectedDefinition.semantic_definition &&
      editGuidance === selectedDefinition.population_guidance &&
      editRestrictions === selectedDefinition.restrictions
    )
      return false;
    try {
      if (!selectedDefinition && editType === "Text")
        exactAllowedValues(editAllowedValues);
    } catch {
      return false;
    }
    return true;
  }

  async function saveDefinition(action: "create" | "update") {
    if (
      !app ||
      metadataRevision === null ||
      !definitionDraftValid() ||
      reviewedDefinitionAction !== action ||
      !window.confirm(
        `${action === "create" ? "Create" : "Update"} this exact ${editScope} semantic definition?`,
      )
    )
      return;
    const relationship = editScope === "relationship";
    const functionName = relationship
      ? `metadata.relationship.semantic_column.${action}`
      : `metadata.semantic_column.${action}`;
    const args: Record<string, unknown> = {
      dimensionId,
      slot: editSlot,
      displayName: editName.trim(),
      semanticDefinition: editMeaning.trim(),
      populationGuidance: editGuidance,
      restrictions: editRestrictions,
      expectedMetadataRevision: metadataRevision,
    };
    if (action === "create") {
      args.valueType = editType;
      if (editType === "Text")
        args.allowedValues = exactAllowedValues(editAllowedValues);
      if (editType === "MemberReference")
        args.referenceDimensionId = editReferenceDimension;
    }
    setBusy(true);
    setError("");
    setResult("");
    try {
      await requestAdmittedEffect<{
        receiptId?: string;
        result?: { receiptId?: string };
      }>(
        "/api/metadata-action",
        semanticMutationBody(
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
      setResult("The reviewed attribute definition was applied.");
      setReviewedDefinitionAction("");
      setDefinitionTouched(false);
      await onChanged();
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to apply semantic definition",
      );
    } finally {
      setBusy(false);
    }
  }

  function valueDraftValid() {
    if (!selectedDefinition || !snapshotCurrent) return false;
    const entityId =
      editScope === "relationship" ? relationshipId.trim() : memberId;
    if (!entityId) return false;
    try {
      exactSemanticValue(
        selectedDefinition.properties?.valueType || "",
        editValue,
        clearValue,
      );
      return true;
    } catch {
      return false;
    }
  }

  async function saveValue() {
    if (
      !app ||
      metadataRevision === null ||
      !selectedDefinition ||
      !valueDraftValid() ||
      !reviewedValue ||
      !window.confirm(
        `${clearValue ? "Clear" : "Set"} this exact ${editScope} semantic value?`,
      )
    )
      return;
    const relationship = editScope === "relationship";
    const entityId = relationship ? relationshipId.trim() : memberId;
    const value = exactSemanticValue(
      selectedDefinition.properties?.valueType || "",
      editValue,
      clearValue,
    );
    const args: Record<string, unknown> = {
      dimensionId,
      [relationship ? "relationshipId" : "memberId"]: entityId,
      slot: selectedDefinition.slot,
      value,
      expectedMetadataRevision: metadataRevision,
    };
    setBusy(true);
    setError("");
    setResult("");
    try {
      await requestAdmittedEffect<{
        receiptId?: string;
        result?: { receiptId?: string };
      }>(
        "/api/metadata-action",
        semanticMutationBody(
          app,
          relationship
            ? "metadata.relationship.attribute.set"
            : "metadata.member.attribute.set",
          args,
          mutationIntentKey({
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            functionName: relationship
              ? "metadata.relationship.attribute.set"
              : "metadata.member.attribute.set",
            args,
          }),
        ),
      );
      setResult("The reviewed attribute value was applied.");
      setReviewedValue(false);
      setEditValue("");
      setClearValue(false);
      await onChanged();
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to apply semantic value",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="metadata-create" aria-labelledby="semantic-heading">
      <div className="section-heading-row">
        <div>
          <small>TYPED MODEL CONTEXT</small>
          <h3 id="semantic-heading">Semantic attributes</h3>
          <p>
            Inspect server-defined typed attributes and current member values
            without reproducing validation in the browser.
          </p>
        </div>
        <span className="automatic-read-status">
          {busy ? "Refreshing attributes…" : "Loaded automatically"}
        </span>
      </div>
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {definitionRevision !== null && (
        <p role="status">{allColumns.length} current definitions</p>
      )}
      {allColumns.length > 0 && (
        <div
          className="react-grid-scroll"
          role="region"
          aria-label="Semantic attribute definitions"
          tabIndex={0}
        >
          <table className="react-cube-grid">
            <thead>
              <tr>
                <th>Slot</th>
                <th>Scope</th>
                <th>Display name</th>
                <th>Type</th>
                <th>Meaning</th>
                <th>Guidance</th>
                <th>Restrictions</th>
              </tr>
            </thead>
            <tbody>
              {allColumns.map((column) => (
                <tr key={`${column.scope}-${column.slot}`}>
                  <th>{column.key}</th>
                  <td>{column.scope}</td>
                  <td>{column.display_name}</td>
                  <td>{column.properties?.valueType || "Unspecified"}</td>
                  <td>{column.semantic_definition}</td>
                  <td>{column.population_guidance || "—"}</td>
                  <td>{column.restrictions || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {definitionRevision !== null && allColumns.length === 0 && (
        <p className="muted-copy">No semantic attributes are defined.</p>
      )}
      {canRead &&
        snapshotCurrent &&
        columns.length > 0 &&
        activeMembers.length > 0 && (
          <div className="snapshot-compare-controls">
            <label>
              Member attributes
              <select
                aria-label="Semantic attribute member"
                value={memberId}
                onChange={(event) => {
                  setMemberId(event.target.value);
                  setAttributes([]);
                  setReviewedValue(false);
                }}
              >
                {activeMembers.map((member) => (
                  <option key={member.member_id} value={member.member_id}>
                    {member.name}
                  </option>
                ))}
              </select>
            </label>
            <button disabled={busy || !memberId} onClick={readAttributes}>
              Read values
            </button>
          </div>
        )}
      {attributes.length > 0 && (
        <dl className="detail-list" aria-label="Semantic member values">
          {attributes.map((attribute) => (
            <div key={attribute.slot}>
              <dt>{attribute.display_name}</dt>
              <dd>{displayValue(attribute.value)}</dd>
            </div>
          ))}
        </dl>
      )}
      {canReadRelationship &&
        snapshotCurrent &&
        relationshipColumns.length > 0 && (
          <div className="snapshot-compare-controls">
            <label>
              Relationship attributes
              <input
                aria-label="Semantic attribute relationship"
                value={relationshipId}
                onChange={(event) => {
                  setRelationshipId(event.target.value);
                  setRelationshipAttributes([]);
                  setReviewedValue(false);
                }}
              />
            </label>
            <button
              disabled={busy || !relationshipId.trim()}
              onClick={readRelationshipAttributes}
            >
              Read relationship values
            </button>
          </div>
        )}
      {relationshipAttributes.length > 0 && (
        <dl className="detail-list" aria-label="Semantic relationship values">
          {relationshipAttributes.map((attribute) => (
            <div key={attribute.slot}>
              <dt>{attribute.display_name}</dt>
              <dd>{displayValue(attribute.value)}</dd>
            </div>
          ))}
        </dl>
      )}
      {definitionRevision !== null &&
        (canCreateMemberDefinition ||
          canUpdateMemberDefinition ||
          canCreateRelationshipDefinition ||
          canUpdateRelationshipDefinition) && (
          <details className="program-inspector" id="semantic-attribute-editor">
            <summary>Define semantic attributes</summary>
            <p>
              Creating fixes the value type. Updating changes descriptions only
              and preserves existing values.
            </p>
            <div className="form-grid semantic-identity-fields">
              <label>
                Attribute scope
                <select
                  aria-label="Semantic definition scope"
                  value={editScope}
                  onChange={(event) => {
                    setEditScope(
                      event.target.value as "member" | "relationship",
                    );
                    invalidateDefinitionReview();
                    setReviewedValue(false);
                  }}
                >
                  <option value="member">Member</option>
                  <option value="relationship">Relationship</option>
                </select>
              </label>
              <label>
                Slot
                <input
                  aria-label="Semantic definition slot"
                  type="number"
                  min="1"
                  max={maximumSlot}
                  value={editSlot}
                  onChange={(event) => {
                    setEditSlot(Number(event.target.value));
                    invalidateDefinitionReview();
                    setReviewedValue(false);
                  }}
                />
              </label>
              <label>
                Display name
                <input
                  aria-label="Semantic definition display name"
                  value={editName}
                  onChange={(event) => {
                    setEditName(event.target.value);
                    invalidateDefinitionReview();
                  }}
                />
              </label>
              <label>
                Value type
                <select
                  aria-label="Semantic definition value type"
                  value={editType}
                  disabled={Boolean(selectedDefinition)}
                  onChange={(event) => {
                    setEditType(event.target.value);
                    invalidateDefinitionReview();
                  }}
                >
                  <option>Text</option>
                  <option>Decimal</option>
                  <option>Boolean</option>
                  <option>MemberReference</option>
                </select>
              </label>
            </div>
            <label>
              Business meaning
              <textarea
                aria-label="Semantic definition meaning"
                value={editMeaning}
                onChange={(event) => {
                  setEditMeaning(event.target.value);
                  invalidateDefinitionReview();
                }}
              />
            </label>
            <div className="form-grid semantic-guidance-fields">
              <label>
                Population guidance
                <input
                  value={editGuidance}
                  onChange={(event) => {
                    setEditGuidance(event.target.value);
                    invalidateDefinitionReview();
                  }}
                />
              </label>
              <label>
                Restrictions
                <input
                  value={editRestrictions}
                  onChange={(event) => {
                    setEditRestrictions(event.target.value);
                    invalidateDefinitionReview();
                  }}
                />
              </label>
              {editType === "Text" && !selectedDefinition && (
                <label>
                  Allowed values
                  <input
                    aria-label="Semantic definition allowed values"
                    value={editAllowedValues}
                    onChange={(event) => {
                      setEditAllowedValues(event.target.value);
                      invalidateDefinitionReview();
                    }}
                  />
                </label>
              )}
              {editType === "MemberReference" && !selectedDefinition && (
                <label>
                  Reference dimension
                  <select
                    aria-label="Semantic definition reference dimension"
                    value={editReferenceDimension}
                    onChange={(event) => {
                      setEditReferenceDimension(event.target.value);
                      invalidateDefinitionReview();
                    }}
                  >
                    {dimensions
                      .filter((dimension) => dimension.status === "Active")
                      .map((dimension) => (
                        <option
                          key={dimension.dimension_id}
                          value={dimension.dimension_id}
                        >
                          {dimension.name}
                        </option>
                      ))}
                  </select>
                </label>
              )}
            </div>
            {!selectedDefinition && canCreateDefinition && (
              <div className="reviewed-inline-action">
                <label className="review-check">
                  <input
                    type="checkbox"
                    checked={reviewedDefinitionAction === "create"}
                    disabled={!definitionDraftValid()}
                    onChange={(event) =>
                      setReviewedDefinitionAction(
                        event.target.checked ? "create" : "",
                      )
                    }
                  />
                  I reviewed this exact new definition against the current
                  model.
                </label>
                <button
                  disabled={busy || reviewedDefinitionAction !== "create"}
                  onClick={() => void saveDefinition("create")}
                >
                  Create definition
                </button>
              </div>
            )}
            {selectedDefinition && canUpdateDefinition && (
              <div className="reviewed-inline-action">
                <label className="review-check">
                  <input
                    type="checkbox"
                    checked={reviewedDefinitionAction === "update"}
                    disabled={!definitionDraftValid()}
                    onChange={(event) =>
                      setReviewedDefinitionAction(
                        event.target.checked ? "update" : "",
                      )
                    }
                  />
                  I reviewed these exact description changes against the current
                  model.
                </label>
                <button
                  disabled={busy || reviewedDefinitionAction !== "update"}
                  onClick={() => void saveDefinition("update")}
                >
                  Update definition
                </button>
              </div>
            )}
            {selectedDefinition &&
              (editScope === "member"
                ? canSetMemberValue && activeMembers.length > 0
                : canSetRelationshipValue) && (
                <div className="reviewed-inline-action">
                  <h4>Populate selected attribute</h4>
                  {editScope === "member" ? (
                    <label>
                      Member
                      <select
                        aria-label="Semantic value member"
                        value={memberId}
                        onChange={(event) => {
                          setMemberId(event.target.value);
                          setReviewedValue(false);
                        }}
                      >
                        {activeMembers.map((member) => (
                          <option
                            key={member.member_id}
                            value={member.member_id}
                          >
                            {member.name}
                          </option>
                        ))}
                      </select>
                    </label>
                  ) : (
                    <label>
                      Relationship stable ID
                      <input
                        aria-label="Semantic value relationship"
                        value={relationshipId}
                        onChange={(event) => {
                          setRelationshipId(event.target.value);
                          setReviewedValue(false);
                        }}
                      />
                    </label>
                  )}
                  <label>
                    Typed value ({selectedDefinition.properties?.valueType})
                    <input
                      aria-label="Semantic typed value"
                      disabled={clearValue}
                      value={editValue}
                      onChange={(event) => {
                        setEditValue(event.target.value);
                        setReviewedValue(false);
                      }}
                    />
                  </label>
                  <label className="review-check">
                    <input
                      aria-label="Clear semantic value"
                      type="checkbox"
                      checked={clearValue}
                      onChange={(event) => {
                        setClearValue(event.target.checked);
                        setReviewedValue(false);
                      }}
                    />
                    Clear this value (absence, not empty text)
                  </label>
                  <label className="review-check">
                    <input
                      type="checkbox"
                      checked={reviewedValue}
                      disabled={!valueDraftValid()}
                      onChange={(event) =>
                        setReviewedValue(event.target.checked)
                      }
                    />
                    I reviewed this exact typed value and target.
                  </label>
                  <button
                    disabled={busy || !reviewedValue}
                    onClick={() => void saveValue()}
                  >
                    {clearValue ? "Clear value" : "Set value"}
                  </button>
                </div>
              )}
            {result && <p role="status">{result}</p>}
          </details>
        )}
      <p className="authority-note">
        Definitions, types and values come from the fixed core. Reviewed
        definition changes use the same governed metadata service.
      </p>
    </section>
  );
}
