import { useEffect, useMemo, useRef, useState } from "react";
import { readProgram, requestAdmittedEffect } from "./api";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { usePreservedDraft } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";

type Member = {
  member_id: string;
  name: string;
  status: string;
  short_description?: string;
  custom_values?: Record<string, unknown>;
};

type Relationship = {
  relationship_id: string;
  dimension_id: string;
  name?: string;
  short_description?: string;
  parent_member_id: string;
  child_member_id: string;
  status: "Active" | "Inactive";
  custom_values?: Record<string, unknown>;
};

type AttributeDefinition = {
  attribute_id: string;
  display_name: string;
  value_type: "Text" | "Decimal" | "Boolean" | "MemberReference";
  validation_constraints: Record<string, unknown>;
  status: "Active" | "Inactive";
  state_token: string;
};

type DefinitionPage = {
  rows: AttributeDefinition[];
  hasMore: boolean;
  nextAfterAttributeId: string | null;
  metadataRevision: number;
};

type AttributeEdit = {
  scope: "Member" | "Relationship";
  objectId: string;
  objectName: string;
  attributeId: string;
  definition: AttributeDefinition;
  sourceValue: unknown;
  metadataRevision: number | null;
  securityRevision: number | null;
};

const ROW_WINDOW = 50;
const MAX_VISIBLE_ATTRIBUTES = 20;

function attributeValueBody(
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

export function metadataAttributeValue(
  value: unknown,
  type: AttributeDefinition["value_type"],
) {
  if (value === undefined || value === null) return "";
  if (type === "Boolean") return value === true ? "True" : "False";
  return String(value);
}

function typedDraft(value: string, type: AttributeDefinition["value_type"]) {
  if (type === "Boolean") {
    if (value === "true") return true;
    if (value === "false") return false;
    return null;
  }
  return value === "" ? null : value;
}

export function MetadataMemberGrid({
  app,
  catalog,
  dimensionId,
  members,
  relationships,
  metadataRevision,
  selectedMemberId,
  onSelectedMember,
  onChanged,
  onEditSecurityString,
  securityBusy = false,
  mode = "all",
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  dimensionId: string;
  members: Member[];
  relationships: Relationship[];
  metadataRevision: number | null;
  selectedMemberId: string;
  onSelectedMember: (memberId: string, relationship?: Relationship) => void;
  onChanged: () => Promise<void>;
  onEditSecurityString?: (member: Member) => void;
  securityBusy?: boolean;
  mode?: "members" | "relationships" | "all";
}) {
  const mutationIntentKey = useStableMutationIntentKey("member-grid-ui");
  const [definitions, setDefinitions] = useState<AttributeDefinition[]>([]);
  const [relationshipDefinitions, setRelationshipDefinitions] = useState<
    AttributeDefinition[]
  >([]);
  const [definitionRevision, setDefinitionRevision] = useState<number | null>(
    null,
  );
  const [visibleAttributes, setVisibleAttributes] = useState<string[]>([]);
  const [visibleRelationshipAttributes, setVisibleRelationshipAttributes] =
    useState<string[]>([]);
  const [windowStart, setWindowStart] = useState(0);
  const [relationshipWindowStart, setRelationshipWindowStart] = useState(0);
  const [memberSearch, setMemberSearch] = useState("");
  const [memberStatus, setMemberStatus] = useState("");
  const [relationshipSearch, setRelationshipSearch] = useState("");
  const [relationshipStatus, setRelationshipStatus] = useState("");
  const [editing, setEditing] = useState<AttributeEdit | null>(null);
  const [pendingIntent, setPendingIntent] = useState<{
    signature: string;
    key: string;
  } | null>(null);
  const [draft, setDraft] = useState("");
  const [reviewed, setReviewed] = useState(false);
  const [reading, setReading] = useState(false);
  const [saving, setSaving] = useState(false);
  const busy = reading || saving;
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
  const readGeneration = useRef(0);
  const scopeKey = JSON.stringify([
    app?.workspaceId,
    app?.applicationId,
    dimensionId,
    mode,
  ]);
  const currentScope = useRef(scopeKey);
  currentScope.current = scopeKey;

  const canRead = Boolean(
    catalog?.functions["metadata.attribute-definition.list"],
  );
  const canWrite = Boolean(catalog?.functions["metadata.attribute-value.set"]);
  const activeDefinitions = definitions.filter(
    (definition) => definition.status === "Active",
  );
  const activeRelationshipDefinitions = relationshipDefinitions.filter(
    (definition) => definition.status === "Active",
  );
  const selectedDefinitions = activeDefinitions.filter((definition) =>
    visibleAttributes.includes(definition.attribute_id),
  );
  const selectedRelationshipDefinitions = activeRelationshipDefinitions.filter(
    (definition) =>
      visibleRelationshipAttributes.includes(definition.attribute_id),
  );
  const filteredMembers = useMemo(() => {
    const search = memberSearch.trim().toLowerCase();
    return members.filter(
      (member) =>
        (!memberStatus || member.status === memberStatus) &&
        (!search ||
          [member.member_id, member.name, member.status].some((value) =>
            value.toLowerCase().includes(search),
          )),
    );
  }, [members, memberSearch, memberStatus]);
  const filteredRelationships = useMemo(() => {
    const search = relationshipSearch.trim().toLowerCase();
    return relationships.filter(
      (relationship) =>
        (!relationshipStatus || relationship.status === relationshipStatus) &&
        (!search ||
          [
            relationship.relationship_id,
            relationship.name || "",
            relationship.status,
            relationship.parent_member_id,
            relationship.child_member_id,
          ].some((value) => value.toLowerCase().includes(search))),
    );
  }, [relationships, relationshipSearch, relationshipStatus]);
  const windowedMembers = filteredMembers.slice(
    windowStart,
    windowStart + ROW_WINDOW,
  );
  const windowedRelationships = filteredRelationships.slice(
    relationshipWindowStart,
    relationshipWindowStart + ROW_WINDOW,
  );
  const selectedDefinition = editing
    ? (editing.scope === "Member"
        ? activeDefinitions
        : activeRelationshipDefinitions
      ).find((definition) => definition.attribute_id === editing.attributeId)
    : undefined;
  const selectedObject = editing
    ? editing.scope === "Member"
      ? members.find((member) => member.member_id === editing.objectId)
      : relationships.find(
          (relationship) => relationship.relationship_id === editing.objectId,
        )
    : undefined;
  const nextValue = editing
    ? typedDraft(draft, editing.definition.value_type)
    : null;
  const editChanged = Boolean(
    editing &&
      JSON.stringify(nextValue) !== JSON.stringify(editing.sourceValue),
  );
  const staleEdit = Boolean(
    editing &&
      (editing.metadataRevision === null ||
        editing.metadataRevision !== metadataRevision ||
        editing.metadataRevision !== definitionRevision ||
        editing.securityRevision !== (catalog?.revisions.security ?? null) ||
        !selectedObject ||
        !selectedDefinition ||
        selectedDefinition.state_token !== editing.definition.state_token),
  );
  usePreservedDraft(
    app?.workspaceId || "none",
    app?.applicationId || "none",
    `metadata-member-grid:${dimensionId}:${mode}`,
    "Unsaved metadata attribute value",
    Boolean(editing && editChanged),
    { editing, draft, pendingIntent },
    (saved) => {
      setEditing(saved.editing);
      setDraft(saved.draft);
      setPendingIntent(saved.pendingIntent);
      setReviewed(false);
    },
  );

  const placementsByMember = useMemo(() => {
    const index = new Map<string, Relationship[]>();
    for (const relationship of relationships) {
      if (relationship.status !== "Active") continue;
      const current = index.get(relationship.child_member_id) || [];
      current.push(relationship);
      index.set(relationship.child_member_id, current);
    }
    return index;
  }, [relationships]);

  useEffect(() => {
    setDefinitions([]);
    setRelationshipDefinitions([]);
    setDefinitionRevision(null);
    setVisibleAttributes([]);
    setVisibleRelationshipAttributes([]);
    setWindowStart(0);
    setRelationshipWindowStart(0);
    setMemberSearch("");
    setMemberStatus("");
    setRelationshipSearch("");
    setRelationshipStatus("");
    setEditing(null);
    setDraft("");
    setPendingIntent(null);
    setReviewed(false);
    setSaving(false);
    setError("");
    setResult("");
  }, [app?.workspaceId, app?.applicationId, dimensionId, mode]);

  useEffect(() => {
    const generation = ++readGeneration.current;
    setReviewed(false);
    setDefinitionRevision(null);
    if (canRead && app && dimensionId) void readDefinitions(generation);
    else {
      setDefinitions([]);
      setRelationshipDefinitions([]);
      setReading(false);
    }
    return () => {
      readGeneration.current += 1;
    };
  }, [
    app?.workspaceId,
    app?.applicationId,
    dimensionId,
    mode,
    metadataRevision,
    canRead,
  ]);

  useEffect(() => {
    setReviewed(false);
  }, [catalog?.revisions.security, canWrite]);

  useEffect(() => {
    if (windowStart >= filteredMembers.length)
      setWindowStart(
        Math.max(0, Math.ceil(filteredMembers.length / ROW_WINDOW) - 1) *
          ROW_WINDOW,
      );
  }, [filteredMembers.length, windowStart]);

  useEffect(() => {
    if (relationshipWindowStart >= filteredRelationships.length)
      setRelationshipWindowStart(
        Math.max(0, Math.ceil(filteredRelationships.length / ROW_WINDOW) - 1) *
          ROW_WINDOW,
      );
  }, [filteredRelationships.length, relationshipWindowStart]);

  async function readDefinitions(generation: number) {
    if (!app || !dimensionId || !canRead) return;
    setReading(true);
    setError("");
    try {
      const scope = {
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
      };
      async function readScope(definitionScope: "Member" | "Relationship") {
        const found: AttributeDefinition[] = [];
        let afterAttributeId: string | null = null;
        let revision: number | null = null;
        do {
          const page: DefinitionPage = await readProgram(
            scope,
            "metadata.attribute-definition.list",
            {
              scope: definitionScope,
              dimensionId,
              status: "Active",
              limit: 200,
              ...(afterAttributeId ? { afterAttributeId } : {}),
            },
          );
          if (revision !== null && revision !== page.metadataRevision)
            throw new Error(
              "Metadata changed while reading attribute definitions.",
            );
          found.push(...page.rows);
          revision = page.metadataRevision;
          afterAttributeId = page.nextAfterAttributeId;
          if (found.length > 200)
            throw new Error(
              `The ${definitionScope.toLowerCase()} attribute catalogue exceeds its governed 200-column bound.`,
            );
        } while (afterAttributeId);
        return { found, revision };
      }
      const [memberResult, relationshipResult] = await Promise.all([
        readScope("Member"),
        readScope("Relationship"),
      ]);
      if (memberResult.revision !== relationshipResult.revision)
        throw new Error(
          "Metadata changed while reading attribute definitions.",
        );
      if (generation !== readGeneration.current) return;
      setDefinitions(memberResult.found);
      setRelationshipDefinitions(relationshipResult.found);
      setDefinitionRevision(memberResult.revision);
      setVisibleAttributes((current) => {
        const valid = current.filter((attributeId) =>
          memberResult.found.some(
            (definition) => definition.attribute_id === attributeId,
          ),
        );
        return valid.length > 0
          ? valid
          : memberResult.found
              .slice(
                0,
                Math.min(MAX_VISIBLE_ATTRIBUTES, memberResult.found.length),
              )
              .map((definition) => definition.attribute_id);
      });
      setVisibleRelationshipAttributes((current) => {
        const valid = current.filter((attributeId) =>
          relationshipResult.found.some(
            (definition) => definition.attribute_id === attributeId,
          ),
        );
        return valid.length > 0
          ? valid
          : relationshipResult.found
              .slice(
                0,
                Math.min(
                  MAX_VISIBLE_ATTRIBUTES,
                  relationshipResult.found.length,
                ),
              )
              .map((definition) => definition.attribute_id);
      });
    } catch (reason) {
      if (generation !== readGeneration.current) return;
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read metadata attribute definitions",
      );
    } finally {
      if (generation === readGeneration.current) setReading(false);
    }
  }

  function beginEdit(
    scope: "Member" | "Relationship",
    object: Member | Relationship,
    definition: AttributeDefinition,
  ) {
    if (busy) return;
    if (
      editing &&
      editChanged &&
      !window.confirm("Discard the unsaved attribute value and edit this cell?")
    )
      return;
    const value = object.custom_values?.[definition.attribute_id];
    setEditing({
      scope,
      objectId:
        scope === "Member"
          ? (object as Member).member_id
          : (object as Relationship).relationship_id,
      attributeId: definition.attribute_id,
      objectName: object.name || (object as Relationship).relationship_id,
      definition,
      sourceValue: value ?? null,
      metadataRevision,
      securityRevision: catalog?.revisions.security ?? null,
    });
    setDraft(
      definition.value_type === "Boolean"
        ? value === true
          ? "true"
          : value === false
            ? "false"
            : ""
        : value === undefined || value === null
          ? ""
          : String(value),
    );
    setReviewed(false);
    setPendingIntent(null);
    setResult("");
    setError("");
  }

  async function saveEdit() {
    if (
      !app ||
      !editing ||
      !selectedDefinition ||
      !canWrite ||
      busy ||
      staleEdit ||
      !reviewed ||
      !editChanged ||
      metadataRevision === null ||
      metadataRevision !== definitionRevision ||
      !window.confirm(
        `Set ${selectedDefinition.display_name} on ${editing.objectName}?`,
      )
    )
      return;
    setSaving(true);
    setError("");
    setResult("");
    try {
      const args = {
        scope: editing.scope,
        dimensionId,
        attributeId: selectedDefinition.attribute_id,
        objectId: editing.objectId,
        value: nextValue,
        expectedMetadataRevision: editing.metadataRevision,
      };
      const signature = JSON.stringify(args);
      const key =
        pendingIntent?.signature === signature
          ? pendingIntent.key
          : mutationIntentKey({
              workspaceId: app.workspaceId,
              applicationId: app.applicationId,
              functionName: "metadata.attribute-value.set",
              args,
            });
      setPendingIntent({ signature, key });
      await requestAdmittedEffect<{
        receiptId?: string;
        result?: { receiptId?: string; operationId?: string };
      }>("/api/metadata-action", attributeValueBody(app, args, key));
      if (currentScope.current !== scopeKey) return;
      setResult("The reviewed value was applied.");
      setEditing(null);
      setPendingIntent(null);
      setReviewed(false);
      await onChanged();
    } catch (reason) {
      if (currentScope.current !== scopeKey) return;
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to save the metadata attribute",
      );
    } finally {
      if (currentScope.current === scopeKey) setSaving(false);
    }
  }

  return (
    <div
      className="metadata-wide-grid"
      aria-label={
        mode === "relationships" ? "Relationship List View" : "Member List View"
      }
    >
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {mode !== "relationships" && (
        <>
          <div className="metadata-grid-toolbar">
            <div>
              <strong>
                {filteredMembers.length} of {members.length} members
              </strong>
              <span>
                Rows {filteredMembers.length === 0 ? 0 : windowStart + 1}–
                {Math.min(windowStart + ROW_WINDOW, filteredMembers.length)}
              </span>
            </div>
            <div className="metadata-grid-filters">
              <label>
                Search members
                <input
                  type="search"
                  placeholder="Name, ID or status"
                  value={memberSearch}
                  onChange={(event) => {
                    setMemberSearch(event.target.value);
                    setWindowStart(0);
                  }}
                />
              </label>
              <label>
                Member status
                <select
                  value={memberStatus}
                  onChange={(event) => {
                    setMemberStatus(event.target.value);
                    setWindowStart(0);
                  }}
                >
                  <option value="">All statuses</option>
                  <option value="Active">Active</option>
                  <option value="Inactive">Inactive</option>
                </select>
              </label>
            </div>
            <details>
              <summary>Choose attribute columns</summary>
              <div className="metadata-column-picker">
                {activeDefinitions.map((definition) => {
                  const checked = visibleAttributes.includes(
                    definition.attribute_id,
                  );
                  return (
                    <label key={definition.attribute_id}>
                      <input
                        type="checkbox"
                        checked={checked}
                        disabled={
                          !checked &&
                          visibleAttributes.length >= MAX_VISIBLE_ATTRIBUTES
                        }
                        onChange={(event) =>
                          setVisibleAttributes((current) =>
                            event.target.checked
                              ? [...current, definition.attribute_id]
                              : current.filter(
                                  (attributeId) =>
                                    attributeId !== definition.attribute_id,
                                ),
                          )
                        }
                      />
                      {definition.display_name}
                    </label>
                  );
                })}
                {activeDefinitions.length === 0 && (
                  <p>No active member attributes are defined.</p>
                )}
              </div>
            </details>
            <div className="metadata-window-controls">
              <button
                type="button"
                disabled={windowStart === 0}
                onClick={() =>
                  setWindowStart(Math.max(0, windowStart - ROW_WINDOW))
                }
              >
                Previous rows
              </button>
              <button
                type="button"
                disabled={windowStart + ROW_WINDOW >= filteredMembers.length}
                onClick={() => setWindowStart(windowStart + ROW_WINDOW)}
              >
                Next rows
              </button>
            </div>
          </div>
          <div
            className="react-grid-scroll metadata-wide-grid-scroll"
            role="region"
            aria-label="Scrollable member attributes"
            tabIndex={0}
          >
            <table
              className="react-cube-grid metadata-relationship-grid"
              aria-label="Member attribute grid"
            >
              <thead>
                <tr>
                  <th className="metadata-sticky-id">Stable member ID</th>
                  <th className="metadata-sticky-name">Name</th>
                  <th>Status</th>
                  {onEditSecurityString && <th>Security String</th>}
                  <th>Parent placements</th>
                  <th>Short description</th>
                  {selectedDefinitions.map((definition) => (
                    <th key={definition.attribute_id}>
                      {definition.display_name}
                      <small>{definition.value_type}</small>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {windowedMembers.map((member) => {
                  const placements =
                    placementsByMember.get(member.member_id) || [];
                  return (
                    <tr
                      key={member.member_id}
                      className={
                        selectedMemberId === member.member_id
                          ? "selected-row"
                          : ""
                      }
                      onClick={() =>
                        onSelectedMember(member.member_id, placements[0])
                      }
                    >
                      <th className="metadata-sticky-id" scope="row">
                        <button
                          type="button"
                          className="metadata-row-select"
                          aria-label={`Select member ${member.name} (${member.member_id})`}
                          aria-pressed={selectedMemberId === member.member_id}
                          onClick={(event) => {
                            event.stopPropagation();
                            onSelectedMember(member.member_id, placements[0]);
                          }}
                        >
                          {member.member_id}
                        </button>
                      </th>
                      <td className="metadata-sticky-name">{member.name}</td>
                      <td>{member.status}</td>
                      {onEditSecurityString && (
                        <td>
                          <button
                            type="button"
                            disabled={securityBusy}
                            onClick={(event) => {
                              event.stopPropagation();
                              onEditSecurityString(member);
                            }}
                          >
                            Edit Security String
                          </button>
                        </td>
                      )}
                      <td>
                        {placements.length > 0
                          ? placements.map((placement) => (
                              <button
                                type="button"
                                className="placement-link"
                                key={placement.relationship_id}
                                onClick={(event) => {
                                  event.stopPropagation();
                                  onSelectedMember(member.member_id, placement);
                                }}
                              >
                                {placement.parent_member_id}
                              </button>
                            ))
                          : "Unplaced"}
                      </td>
                      <td>{member.short_description || ""}</td>
                      {selectedDefinitions.map((definition) => (
                        <td
                          key={definition.attribute_id}
                          className={canWrite ? "metadata-attribute-cell" : ""}
                          onClick={(event) => {
                            event.stopPropagation();
                            if (canWrite)
                              beginEdit("Member", member, definition);
                          }}
                          onKeyDown={(event) => {
                            if (
                              canWrite &&
                              (event.key === "Enter" || event.key === " ")
                            ) {
                              event.preventDefault();
                              beginEdit("Member", member, definition);
                            }
                          }}
                          tabIndex={canWrite ? 0 : undefined}
                          aria-label={`${definition.display_name} for ${member.name}`}
                        >
                          {metadataAttributeValue(
                            member.custom_values?.[definition.attribute_id],
                            definition.value_type,
                          ) || (
                            <span className="metadata-missing-value">—</span>
                          )}
                        </td>
                      ))}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {filteredMembers.length === 0 && (
            <p className="metadata-grid-empty">
              {members.length === 0
                ? "This dimension has no members."
                : "No members match the current filters."}
            </p>
          )}
        </>
      )}
      {mode !== "members" && (
        <>
          <div className="metadata-grid-toolbar metadata-placement-toolbar">
            <div>
              <strong>
                {filteredRelationships.length} of {relationships.length}{" "}
                relationship placements
              </strong>
              <span>
                Rows{" "}
                {filteredRelationships.length === 0
                  ? 0
                  : relationshipWindowStart + 1}
                –
                {Math.min(
                  relationshipWindowStart + ROW_WINDOW,
                  filteredRelationships.length,
                )}
              </span>
            </div>
            <div className="metadata-grid-filters">
              <label>
                Search relationships
                <input
                  type="search"
                  placeholder="Name, ID, status, parent or child ID"
                  value={relationshipSearch}
                  onChange={(event) => {
                    setRelationshipSearch(event.target.value);
                    setRelationshipWindowStart(0);
                  }}
                />
              </label>
              <label>
                Relationship status
                <select
                  value={relationshipStatus}
                  onChange={(event) => {
                    setRelationshipStatus(event.target.value);
                    setRelationshipWindowStart(0);
                  }}
                >
                  <option value="">All statuses</option>
                  <option value="Active">Active</option>
                  <option value="Inactive">Inactive</option>
                </select>
              </label>
            </div>
            <details>
              <summary>Choose relationship attribute columns</summary>
              <div className="metadata-column-picker">
                {activeRelationshipDefinitions.map((definition) => {
                  const checked = visibleRelationshipAttributes.includes(
                    definition.attribute_id,
                  );
                  return (
                    <label key={definition.attribute_id}>
                      <input
                        type="checkbox"
                        checked={checked}
                        disabled={
                          !checked &&
                          visibleRelationshipAttributes.length >=
                            MAX_VISIBLE_ATTRIBUTES
                        }
                        onChange={(event) =>
                          setVisibleRelationshipAttributes((current) =>
                            event.target.checked
                              ? [...current, definition.attribute_id]
                              : current.filter(
                                  (attributeId) =>
                                    attributeId !== definition.attribute_id,
                                ),
                          )
                        }
                      />
                      {definition.display_name}
                    </label>
                  );
                })}
                {activeRelationshipDefinitions.length === 0 && (
                  <p>No active relationship attributes are defined.</p>
                )}
              </div>
            </details>
            <div className="metadata-window-controls">
              <button
                type="button"
                disabled={relationshipWindowStart === 0}
                onClick={() =>
                  setRelationshipWindowStart(
                    Math.max(0, relationshipWindowStart - ROW_WINDOW),
                  )
                }
              >
                Previous relationship rows
              </button>
              <button
                type="button"
                disabled={
                  relationshipWindowStart + ROW_WINDOW >=
                  filteredRelationships.length
                }
                onClick={() =>
                  setRelationshipWindowStart(
                    relationshipWindowStart + ROW_WINDOW,
                  )
                }
              >
                Next relationship rows
              </button>
            </div>
          </div>
          <div
            className="react-grid-scroll metadata-wide-grid-scroll"
            role="region"
            aria-label="Scrollable relationship attributes"
            tabIndex={0}
          >
            <table
              className="react-cube-grid metadata-relationship-grid"
              aria-label="Relationship placement attribute grid"
            >
              <thead>
                <tr>
                  <th className="metadata-sticky-id">Stable relationship ID</th>
                  <th className="metadata-sticky-name">Name</th>
                  <th>Parent</th>
                  <th>Child</th>
                  <th>Status</th>
                  <th>Short description</th>
                  {selectedRelationshipDefinitions.map((definition) => (
                    <th key={definition.attribute_id}>
                      {definition.display_name}
                      <small>{definition.value_type}</small>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {windowedRelationships.map((relationship) => (
                  <tr
                    key={relationship.relationship_id}
                    className={
                      selectedMemberId === relationship.child_member_id
                        ? "selected-row"
                        : ""
                    }
                    onClick={() =>
                      onSelectedMember(
                        relationship.child_member_id,
                        relationship,
                      )
                    }
                  >
                    <th className="metadata-sticky-id" scope="row">
                      <button
                        type="button"
                        className="metadata-row-select"
                        aria-label={`Select relationship ${relationship.name || relationship.relationship_id} (${relationship.relationship_id})`}
                        onClick={(event) => {
                          event.stopPropagation();
                          onSelectedMember(
                            relationship.child_member_id,
                            relationship,
                          );
                        }}
                      >
                        {relationship.relationship_id}
                      </button>
                    </th>
                    <td className="metadata-sticky-name">
                      {relationship.name || relationship.relationship_id}
                    </td>
                    <td>{relationship.parent_member_id}</td>
                    <td>{relationship.child_member_id}</td>
                    <td>{relationship.status}</td>
                    <td>{relationship.short_description || ""}</td>
                    {selectedRelationshipDefinitions.map((definition) => (
                      <td
                        key={definition.attribute_id}
                        className={canWrite ? "metadata-attribute-cell" : ""}
                        onClick={(event) => {
                          event.stopPropagation();
                          if (canWrite)
                            beginEdit("Relationship", relationship, definition);
                        }}
                        onKeyDown={(event) => {
                          if (
                            canWrite &&
                            (event.key === "Enter" || event.key === " ")
                          ) {
                            event.preventDefault();
                            beginEdit("Relationship", relationship, definition);
                          }
                        }}
                        tabIndex={canWrite ? 0 : undefined}
                        aria-label={`${definition.display_name} for ${
                          relationship.name || relationship.relationship_id
                        }`}
                      >
                        {metadataAttributeValue(
                          relationship.custom_values?.[definition.attribute_id],
                          definition.value_type,
                        ) || <span className="metadata-missing-value">—</span>}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {filteredRelationships.length === 0 && (
            <p className="metadata-grid-empty">
              {relationships.length === 0
                ? "This dimension has no relationship placements."
                : "No relationships match the current filters."}
            </p>
          )}
        </>
      )}
      {editing && (
        <aside
          className="metadata-cell-editor"
          aria-label="Attribute cell editor"
        >
          <div>
            <small>REVIEWED CELL EDIT</small>
            <h4>
              {editing.definition.display_name} · {editing.scope} ·{" "}
              {editing.objectName}
            </h4>
            <p>{editing.definition.value_type} value for this exact object.</p>
          </div>
          {staleEdit && (
            <p role="alert">
              The metadata or access snapshot has changed or is unavailable.
              Your typed value is preserved. Cancel this edit and reopen the
              cell to read the current value before making a new change.
            </p>
          )}
          <label>
            Typed value
            {editing.definition.value_type === "Boolean" ? (
              <select
                value={draft}
                disabled={busy || !canWrite}
                onChange={(event) => {
                  setDraft(event.target.value);
                  setReviewed(false);
                }}
              >
                <option value="">Missing</option>
                <option value="true">True</option>
                <option value="false">False</option>
              </select>
            ) : (
              <input
                value={draft}
                disabled={busy || !canWrite}
                onChange={(event) => {
                  setDraft(event.target.value);
                  setReviewed(false);
                }}
              />
            )}
          </label>
          <label className="review-check">
            <input
              type="checkbox"
              checked={reviewed}
              disabled={busy || !canWrite || !editChanged || staleEdit}
              onChange={(event) => setReviewed(event.target.checked)}
            />
            I reviewed this exact typed value and target.
          </label>
          <div className="button-row">
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={() => {
                setEditing(null);
                setPendingIntent(null);
                setReviewed(false);
              }}
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={
                busy || !canWrite || !reviewed || !editChanged || staleEdit
              }
              onClick={() => void saveEdit()}
            >
              Save reviewed value
            </button>
          </div>
        </aside>
      )}
      {busy && (
        <p role="status">
          {saving
            ? "Saving reviewed metadata…"
            : "Refreshing governed metadata…"}
        </p>
      )}
      {result && <p className="inline-success">{result}</p>}
    </div>
  );
}
