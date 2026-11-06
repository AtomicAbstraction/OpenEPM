import { useEffect, useMemo, useState } from "react";
import { readProgram, request } from "./api";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { collectAllContinuations } from "./continuation";

type AttributeScope = "Dimension" | "Member" | "Relationship";
type ObjectOption = { id: string; name: string };
type ValueReadback = {
  objectId: string;
  present: boolean;
  value: unknown;
  metadataRevision: number;
};
type AttributeDefinition = {
  attribute_id: string;
  display_name: string;
  value_type: "Text" | "Decimal" | "Boolean" | "MemberReference";
  status: "Active" | "Inactive";
};

type MemberObjectPage = {
  rows: Array<{ member_id: string; name: string }>;
  nextAfterMemberId: string | null;
  metadataRevision: number;
};

type RelationshipObjectPage = {
  rows: Array<{ relationship_id: string }>;
  nextCursor: string | null;
  metadataRevision: number;
};

export function collectAttributeMemberObjects(
  dimensionId: string,
  expectedRevision: number,
  readPage: (arguments_: Record<string, unknown>) => Promise<MemberObjectPage>,
) {
  return collectAllContinuations<
    MemberObjectPage,
    MemberObjectPage["rows"][number]
  >({
    label: "Attribute member objects",
    readPage: (cursor) =>
      readPage(
        cursor
          ? {
              dimension: dimensionId,
              limit: 100,
              afterMemberId: cursor,
              expectedMetadataRevision: expectedRevision,
            }
          : { dimension: dimensionId, limit: 100 },
      ),
    rows: (page) => page.rows,
    nextCursor: (page) => page.nextAfterMemberId,
    rowIdentity: (row) => row.member_id,
    consistencyIdentity: (page) => {
      if (page.metadataRevision !== expectedRevision)
        throw new Error("Metadata changed while reading attribute objects.");
      return page.metadataRevision;
    },
  });
}

export function collectAttributeRelationshipObjects(
  dimensionId: string,
  expectedRevision: number,
  readPage: (
    arguments_: Record<string, unknown>,
  ) => Promise<RelationshipObjectPage>,
) {
  return collectAllContinuations<
    RelationshipObjectPage,
    RelationshipObjectPage["rows"][number]
  >({
    label: "Attribute relationship objects",
    readPage: (cursor) =>
      readPage(cursor ? { cursor } : { dimension: dimensionId, limit: 100 }),
    rows: (page) => page.rows,
    nextCursor: (page) => page.nextCursor,
    rowIdentity: (row) => row.relationship_id,
    consistencyIdentity: (page) => {
      if (page.metadataRevision !== expectedRevision)
        throw new Error("Metadata changed while reading attribute objects.");
      return page.metadataRevision;
    },
  });
}

function valueMutationBody(
  app: ApplicationSummary,
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
      function: "metadata.attribute-value.set",
      arguments: args,
    },
  };
}

export function parseAttributeValue(
  type: AttributeDefinition["value_type"],
  draft: string,
  clear: boolean,
) {
  if (clear) return null;
  if (type === "Boolean") {
    if (draft !== "true" && draft !== "false")
      throw new Error("Boolean values must be true or false.");
    return draft === "true";
  }
  if (
    type === "Decimal" &&
    !/^[+-]?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/.test(draft)
  )
    throw new Error("Enter an exact decimal without exponent notation.");
  if (type === "MemberReference" && !draft)
    throw new Error("Enter a stable member ID or choose Clear.");
  return draft;
}

function displayValue(value: unknown) {
  if (value === null || value === undefined) return "";
  if (typeof value === "boolean") return value ? "true" : "false";
  return String(value);
}

export function AttributeValueEditor({
  app,
  catalog,
  scope,
  dimensionId,
  definitions,
  dimensions,
  definitionRevision,
  onChanged,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  scope: AttributeScope;
  dimensionId: string;
  definitions: AttributeDefinition[];
  dimensions: { dimension_id: string; name: string; status: string }[];
  definitionRevision: number | null;
  onChanged: () => Promise<void>;
}) {
  const mutationIntentKey = useStableMutationIntentKey("attribute-value-ui");
  const canRead = Boolean(catalog?.functions["metadata.attribute-value.read"]);
  const canWrite = Boolean(catalog?.functions["metadata.attribute-value.set"]);
  const [objects, setObjects] = useState<ObjectOption[]>([]);
  const [objectId, setObjectId] = useState("");
  const [attributeId, setAttributeId] = useState("");
  const [readback, setReadback] = useState<ValueReadback | null>(null);
  const [draft, setDraft] = useState("");
  const [draftTouched, setDraftTouched] = useState(false);
  const [clear, setClear] = useState(false);
  const [reviewed, setReviewed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
  const activeDefinitions = useMemo(
    () => definitions.filter((definition) => definition.status === "Active"),
    [definitions],
  );
  const definition = activeDefinitions.find(
    (item) => item.attribute_id === attributeId,
  );

  useEffect(() => {
    setAttributeId((current) =>
      activeDefinitions.some((item) => item.attribute_id === current)
        ? current
        : activeDefinitions[0]?.attribute_id || "",
    );
  }, [activeDefinitions]);

  useEffect(() => {
    setObjects([]);
    setObjectId("");
    setReadback(null);
    setDraft("");
    setDraftTouched(false);
    setClear(false);
    setReviewed(false);
    setError("");
    setResult("");
    if (app && canRead && definitionRevision !== null) void readObjects();
  }, [
    app?.workspaceId,
    app?.applicationId,
    scope,
    dimensionId,
    definitionRevision,
    canRead,
  ]);

  useEffect(() => {
    setReadback(null);
    setDraft("");
    setDraftTouched(false);
    setClear(false);
    setReviewed(false);
    setResult("");
  }, [objectId, attributeId]);

  function contextArguments() {
    return scope === "Dimension" ? { scope } : { scope, dimensionId };
  }

  async function readObjects() {
    if (!app || definitionRevision === null) return;
    setBusy(true);
    setError("");
    try {
      const appScope = {
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
      };
      let found: ObjectOption[] = [];
      if (scope === "Dimension") {
        found = dimensions
          .filter((item) => item.status === "Active")
          .map((item) => ({ id: item.dimension_id, name: item.name }));
      } else if (scope === "Member") {
        const collected = await collectAttributeMemberObjects(
          dimensionId,
          definitionRevision,
          (arguments_) =>
            readProgram(appScope, "metadata.member.list", arguments_),
        );
        found = collected.rows.map((row) => ({
          id: row.member_id,
          name: row.name,
        }));
      } else {
        const collected = await collectAttributeRelationshipObjects(
          dimensionId,
          definitionRevision,
          (arguments_) =>
            readProgram(appScope, "metadata.relationship.list", arguments_),
        );
        found = collected.rows.map((row) => ({
          id: row.relationship_id,
          name: row.relationship_id,
        }));
      }
      setObjects(found);
      setObjectId((current) =>
        found.some((item) => item.id === current)
          ? current
          : found[0]?.id || "",
      );
    } catch (reason) {
      setObjects([]);
      setObjectId("");
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read attribute objects",
      );
    } finally {
      setBusy(false);
    }
  }

  async function readValue() {
    if (!app || !objectId || !attributeId || !canRead) return;
    setBusy(true);
    setError("");
    setResult("");
    try {
      const value = await readProgram<ValueReadback>(
        { workspaceId: app.workspaceId, applicationId: app.applicationId },
        "metadata.attribute-value.read",
        { ...contextArguments(), attributeId, objectId },
      );
      if (value.metadataRevision !== definitionRevision)
        throw new Error("Metadata changed while reading the attribute value.");
      setReadback(value);
      setDraft(displayValue(value.value));
      setDraftTouched(false);
      setClear(false);
      setReviewed(false);
    } catch (reason) {
      setReadback(null);
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read the attribute value",
      );
    } finally {
      setBusy(false);
    }
  }

  function parsedValue() {
    if (!definition) throw new Error("Select an active attribute definition.");
    return parseAttributeValue(definition.value_type, draft, clear);
  }

  function draftValid() {
    try {
      parsedValue();
      return Boolean(readback);
    } catch {
      return false;
    }
  }

  useUnsavedWork(
    `attribute-value:${app?.workspaceId || "none"}:${app?.applicationId || "none"}:${scope}:${dimensionId || "all"}:${objectId || "none"}:${attributeId || "none"}`,
    "Unsaved metadata attribute value",
    Boolean(readback && draftTouched),
  );

  async function save() {
    if (!app || !readback || !canWrite || !reviewed || !draftValid()) return;
    if (!window.confirm(`Save ${attributeId} for ${objectId}?`)) return;
    setBusy(true);
    setError("");
    setResult("");
    try {
      const args = {
        ...contextArguments(),
        attributeId,
        objectId,
        value: parsedValue(),
        expectedMetadataRevision: readback.metadataRevision,
      };
      await request(
        "/api/metadata-action",
        valueMutationBody(
          app,
          args,
          mutationIntentKey({
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            functionName: "metadata.attribute-value.set",
            args,
          }),
        ),
      );
      setReviewed(false);
      setDraftTouched(false);
      await onChanged();
      setResult("The fixed metadata service applied the reviewed value.");
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to save the attribute value",
      );
    } finally {
      setBusy(false);
    }
  }

  if (!canRead) return null;

  return (
    <section
      className="attribute-value-editor"
      aria-labelledby="attribute-values-heading"
    >
      <div className="metadata-sheet-heading">
        <div>
          <small>ATTRIBUTE VALUES</small>
          <h3 id="attribute-values-heading">Object value editor</h3>
          <p>
            Select an object and active definition. Clear remains distinct from
            an empty Text value.
          </p>
        </div>
        <span>{objects.length} active objects</span>
      </div>
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      <div className="metadata-create-fields">
        <label>
          Object
          <select
            aria-label="Attribute object"
            value={objectId}
            disabled={busy || objects.length === 0}
            onChange={(event) => setObjectId(event.target.value)}
          >
            {objects.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name} ({item.id})
              </option>
            ))}
          </select>
        </label>
        <label>
          Attribute
          <select
            aria-label="Value attribute"
            value={attributeId}
            disabled={busy || activeDefinitions.length === 0}
            onChange={(event) => setAttributeId(event.target.value)}
          >
            {activeDefinitions.map((item) => (
              <option key={item.attribute_id} value={item.attribute_id}>
                {item.display_name} ({item.attribute_id})
              </option>
            ))}
          </select>
        </label>
        <button
          disabled={busy || !objectId || !attributeId}
          onClick={() => void readValue()}
        >
          Read value
        </button>
      </div>
      {readback && definition && (
        <div className="program-inspector">
          <p>
            {readback.present ? "Present" : "Not set"} · {definition.value_type}
            · metadata revision {readback.metadataRevision}
          </p>
          <label>
            Typed value
            {definition.value_type === "Boolean" ? (
              <select
                aria-label="Typed attribute value"
                value={draft}
                disabled={clear}
                onChange={(event) => {
                  setDraft(event.target.value);
                  setDraftTouched(true);
                  setReviewed(false);
                }}
              >
                <option value="true">True</option>
                <option value="false">False</option>
              </select>
            ) : (
              <input
                aria-label="Typed attribute value"
                value={draft}
                disabled={clear}
                onChange={(event) => {
                  setDraft(event.target.value);
                  setDraftTouched(true);
                  setReviewed(false);
                }}
              />
            )}
          </label>
          <label className="review-check">
            <input
              type="checkbox"
              checked={clear}
              onChange={(event) => {
                setClear(event.target.checked);
                setDraftTouched(true);
                setReviewed(false);
              }}
            />
            Clear value (absence)
          </label>
          {canWrite && (
            <div className="reviewed-inline-action">
              <label className="review-check">
                <input
                  type="checkbox"
                  checked={reviewed}
                  disabled={!draftValid()}
                  onChange={(event) => setReviewed(event.target.checked)}
                />
                I reviewed this exact object, definition, typed value and
                metadata revision.
              </label>
              <button
                disabled={busy || !reviewed || !draftValid()}
                onClick={() => void save()}
              >
                Save reviewed value
              </button>
            </div>
          )}
        </div>
      )}
      {result && <p role="status">{result}</p>}
    </section>
  );
}
