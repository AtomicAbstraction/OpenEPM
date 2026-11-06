import { useEffect, useState, type ReactNode } from "react";
import { readProgram, request } from "./api";
import { MetadataMemberGrid } from "./MetadataMemberGrid";
import { validMetadataText } from "./MetadataCreate";
import { MetadataSecurityStringEditor } from "./MetadataSecurityStringEditor";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { usePreservedDraft } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { collectAllContinuations } from "./continuation";

type Member = {
  member_id: string;
  name: string;
  status: string;
  short_description?: string;
  detailed_description?: string;
  numeric_value_kind?: "amount" | "ratio" | null;
  custom_values?: Record<string, unknown>;
};

type Relationship = {
  relationship_id: string;
  dimension_id: string;
  name?: string;
  short_description?: string;
  detailed_description?: string;
  semantic_description?: string;
  parent_member_id: string;
  child_member_id: string;
  status: "Active" | "Inactive";
};

type RelationshipPage = {
  rows: Relationship[];
  metadataRevision: number;
  nextCursor: string | null;
};

export function collectMetadataRelationships(
  dimensionId: string,
  expectedMetadataRevision: number | null,
  readPage: (arguments_: Record<string, unknown>) => Promise<RelationshipPage>,
) {
  return collectAllContinuations<RelationshipPage, Relationship>({
    label: "Relationship catalogue",
    readPage: (cursor) =>
      readPage(cursor ? { cursor } : { dimension: dimensionId, limit: 100 }),
    rows: (page) => page.rows,
    nextCursor: (page) => page.nextCursor,
    rowIdentity: (row) => row.relationship_id,
    consistencyIdentity: (page) => {
      if (
        expectedMetadataRevision !== null &&
        page.metadataRevision !== expectedMetadataRevision
      )
        throw new Error("Metadata changed while reading relationships.");
      return page.metadataRevision;
    },
  });
}

export const metadataActionBody = (
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

export function MetadataRelationships({
  app,
  catalog,
  dimensionId,
  members,
  metadataRevision,
  onChanged,
  selectedMemberId,
  onSelectedMemberIdChange,
  onEditMemberSecurityString,
  securityBusy,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  dimensionId: string;
  members: Member[];
  metadataRevision: number | null;
  onChanged: () => Promise<void>;
  selectedMemberId?: string;
  onSelectedMemberIdChange?: (memberId: string) => void;
  onEditMemberSecurityString?: (member: Member) => void;
  securityBusy?: boolean;
}) {
  const mutationIntentKey = useStableMutationIntentKey("relationship-ui");
  const [relationships, setRelationships] = useState<Relationship[]>([]);
  const [relationshipRevision, setRelationshipRevision] = useState<
    number | null
  >(null);
  const [relationshipId, setRelationshipId] = useState("");
  const [parentMemberId, setParentMemberId] = useState("");
  const [childMemberId, setChildMemberId] = useState("");
  const [createReviewed, setCreateReviewed] = useState(false);
  const [selectedRelationshipId, setSelectedRelationshipId] = useState("");
  const [selectedStatus, setSelectedStatus] = useState<"Active" | "Inactive">(
    "Active",
  );
  const [statusReviewed, setStatusReviewed] = useState(false);
  const [relationshipName, setRelationshipName] = useState("");
  const [relationshipShort, setRelationshipShort] = useState("");
  const [relationshipSemantic, setRelationshipSemantic] = useState("");
  const [renameReviewed, setRenameReviewed] = useState(false);
  const [describeReviewed, setDescribeReviewed] = useState(false);
  const [buildReviewed, setBuildReviewed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
  const [editorMode, setEditorMode] = useState<"grid" | "board">("grid");
  const [draggedMemberId, setDraggedMemberId] = useState("");
  const [internalSelectedMemberId, setInternalSelectedMemberId] = useState("");
  const [expandedMemberIds, setExpandedMemberIds] = useState<Set<string>>(
    new Set(),
  );

  const canRead = Boolean(catalog?.functions["metadata.relationship.list"]);
  const canCreate = Boolean(catalog?.functions["metadata.relationship.create"]);
  const canSetStatus = Boolean(
    catalog?.functions["metadata.relationship.status.set"],
  );
  const canRename = Boolean(catalog?.functions["metadata.relationship.rename"]);
  const canDescribe = Boolean(
    catalog?.functions["metadata.relationship.describe"],
  );
  const canBuild = Boolean(catalog?.functions["metadata.hierarchy.build"]);
  const snapshotCurrent = Boolean(
    metadataRevision !== null && relationshipRevision === metadataRevision,
  );
  const activeMembers = members.filter((member) => member.status === "Active");
  const activeRelationships = relationships.filter(
    (relationship) => relationship.status === "Active",
  );
  const placedChildren = new Set(
    activeRelationships.map((relationship) => relationship.child_member_id),
  );
  const placedMembers = new Set(
    activeRelationships.flatMap((relationship) => [
      relationship.parent_member_id,
      relationship.child_member_id,
    ]),
  );
  const rootMembers = activeMembers.filter(
    (member) => !placedChildren.has(member.member_id),
  );
  const unplacedMembers = activeMembers.filter(
    (member) => !placedMembers.has(member.member_id),
  );
  const createValid = Boolean(
    snapshotCurrent &&
      validMetadataText(relationshipId) &&
      parentMemberId &&
      childMemberId &&
      parentMemberId !== childMemberId &&
      !relationships.some(
        (relationship) => relationship.relationship_id === relationshipId,
      ),
  );
  const selectedRelationship = relationships.find(
    (relationship) => relationship.relationship_id === selectedRelationshipId,
  );
  const effectiveSelectedMemberId =
    selectedMemberId === undefined
      ? internalSelectedMemberId
      : selectedMemberId;
  const selectedMember = members.find(
    (member) => member.member_id === effectiveSelectedMemberId,
  );
  const statusValid = Boolean(
    snapshotCurrent &&
      selectedRelationship &&
      selectedRelationship.status !== selectedStatus,
  );
  const renameValid = Boolean(
    snapshotCurrent &&
      selectedRelationship &&
      validMetadataText(relationshipName) &&
      relationshipName !==
        (selectedRelationship.name || selectedRelationship.relationship_id),
  );
  const describeValid = Boolean(
    snapshotCurrent &&
      selectedRelationship &&
      relationshipShort.length <= 500 &&
      relationshipSemantic.length <= 10000 &&
      (relationshipShort !== (selectedRelationship.short_description || "") ||
        relationshipSemantic !==
          (selectedRelationship.semantic_description ||
            selectedRelationship.detailed_description ||
            "")),
  );
  usePreservedDraft(
    app?.workspaceId || "none",
    app?.applicationId || "none",
    `metadata-relationships:${dimensionId || "none"}`,
    "Unsaved hierarchy relationship changes",
    Boolean(relationshipId || statusValid || renameValid || describeValid),
    {
      relationshipId,
      parentMemberId,
      childMemberId,
      createReviewed,
      selectedRelationshipId,
      selectedStatus,
      statusReviewed,
      relationshipName,
      relationshipShort,
      relationshipSemantic,
      renameReviewed,
      describeReviewed,
      buildReviewed,
      editorMode,
      internalSelectedMemberId,
    },
    (draft) => {
      setRelationshipId(draft.relationshipId);
      setParentMemberId(draft.parentMemberId);
      setChildMemberId(draft.childMemberId);
      setCreateReviewed(draft.createReviewed);
      setSelectedRelationshipId(draft.selectedRelationshipId);
      setSelectedStatus(draft.selectedStatus);
      setStatusReviewed(draft.statusReviewed);
      setRelationshipName(draft.relationshipName);
      setRelationshipShort(draft.relationshipShort);
      setRelationshipSemantic(draft.relationshipSemantic);
      setRenameReviewed(draft.renameReviewed);
      setDescribeReviewed(draft.describeReviewed);
      setBuildReviewed(draft.buildReviewed);
      setEditorMode(draft.editorMode);
      setInternalSelectedMemberId(draft.internalSelectedMemberId);
    },
  );

  useEffect(() => {
    setRelationships([]);
    setRelationshipRevision(null);
    setRelationshipId("");
    setSelectedRelationshipId("");
    setCreateReviewed(false);
    setStatusReviewed(false);
    setRenameReviewed(false);
    setDescribeReviewed(false);
    setBuildReviewed(false);
    setError("");
    setResult("");
    setInternalSelectedMemberId("");
    setExpandedMemberIds(new Set());
  }, [app?.workspaceId, app?.applicationId, dimensionId]);

  useEffect(() => {
    const nextMemberId = members.some(
      (member) => member.member_id === effectiveSelectedMemberId,
    )
      ? effectiveSelectedMemberId
      : members[0]?.member_id || "";
    if (nextMemberId !== effectiveSelectedMemberId) selectMember(nextMemberId);
  }, [members, effectiveSelectedMemberId]);

  useEffect(() => {
    if (!effectiveSelectedMemberId) return;
    const currentPlacement = relationships.find(
      (relationship) => relationship.relationship_id === selectedRelationshipId,
    );
    if (currentPlacement?.child_member_id === effectiveSelectedMemberId) return;
    const nextPlacement = relationships.find(
      (relationship) =>
        relationship.child_member_id === effectiveSelectedMemberId,
    );
    setSelectedRelationshipId(nextPlacement?.relationship_id || "");
    setSelectedStatus(nextPlacement?.status || "Active");
    setStatusReviewed(false);
  }, [effectiveSelectedMemberId, relationships, selectedRelationshipId]);

  useEffect(() => {
    setRelationshipName(
      selectedRelationship?.name || selectedRelationship?.relationship_id || "",
    );
    setRelationshipShort(selectedRelationship?.short_description || "");
    setRelationshipSemantic(
      selectedRelationship?.semantic_description ||
        selectedRelationship?.detailed_description ||
        "",
    );
    setRenameReviewed(false);
    setDescribeReviewed(false);
  }, [selectedRelationship?.relationship_id, relationshipRevision]);

  useEffect(() => {
    setParentMemberId((current) =>
      activeMembers.some((member) => member.member_id === current)
        ? current
        : activeMembers[0]?.member_id || "",
    );
    setChildMemberId((current) =>
      activeMembers.some((member) => member.member_id === current)
        ? current
        : activeMembers[1]?.member_id || activeMembers[0]?.member_id || "",
    );
  }, [members]);

  useEffect(() => {
    if (canRead && app && dimensionId && metadataRevision !== null)
      void readRelationships();
  }, [
    app?.workspaceId,
    app?.applicationId,
    dimensionId,
    metadataRevision,
    canRead,
  ]);

  function invalidateCreate() {
    setCreateReviewed(false);
    setResult("");
  }

  function prepareRelationship(parent: string, child: string) {
    if (!parent || !child || parent === child) return;
    setParentMemberId(parent);
    setChildMemberId(child);
    if (!relationshipId) setRelationshipId(`${parent}-${child}`);
    invalidateCreate();
  }

  function selectMember(memberId: string, relationship?: Relationship) {
    if (selectedMemberId === undefined) setInternalSelectedMemberId(memberId);
    onSelectedMemberIdChange?.(memberId);
    if (relationship) {
      setSelectedRelationshipId(relationship.relationship_id);
      setSelectedStatus(relationship.status);
    } else {
      setSelectedRelationshipId("");
    }
    setStatusReviewed(false);
    setRenameReviewed(false);
    setDescribeReviewed(false);
  }

  function toggleExpanded(memberId: string) {
    setExpandedMemberIds((current) => {
      const next = new Set(current);
      if (next.has(memberId)) next.delete(memberId);
      else next.add(memberId);
      return next;
    });
  }

  function hierarchyNode(
    memberId: string,
    ancestry: Set<string>,
    placement?: Relationship,
  ): ReactNode {
    const member = activeMembers.find((item) => item.member_id === memberId);
    if (!member || ancestry.has(memberId)) return null;
    const next = new Set(ancestry).add(memberId);
    const childPlacements = activeRelationships.filter(
      (item) => item.parent_member_id === memberId,
    );
    const expanded = expandedMemberIds.has(memberId);
    return (
      <li
        key={placement?.relationship_id || `root/${memberId}`}
        role="treeitem"
        aria-expanded={childPlacements.length > 0 ? expanded : undefined}
      >
        <div className="hierarchy-tree-row">
          {childPlacements.length > 0 ? (
            <button
              type="button"
              className="hierarchy-disclosure"
              onClick={() => toggleExpanded(memberId)}
              aria-label={`${expanded ? "Collapse" : "Expand"} ${member.name}`}
            >
              {expanded ? "−" : "+"}
            </button>
          ) : (
            <span className="hierarchy-disclosure-spacer" aria-hidden="true" />
          )}
          <button
            type="button"
            className={`hierarchy-tree-node ${
              effectiveSelectedMemberId === memberId &&
              (!placement ||
                selectedRelationshipId === placement.relationship_id)
                ? "selected"
                : ""
            }`}
            draggable
            onDragStart={() => setDraggedMemberId(memberId)}
            onDragEnd={() => setDraggedMemberId("")}
            onDragOver={(event) => event.preventDefault()}
            onDrop={(event) => {
              event.preventDefault();
              prepareRelationship(memberId, draggedMemberId);
              setDraggedMemberId("");
            }}
            onClick={() => selectMember(memberId, placement)}
            onKeyDown={(event) => {
              if (event.key === "ArrowRight" && childPlacements.length > 0) {
                event.preventDefault();
                setExpandedMemberIds((current) =>
                  new Set(current).add(memberId),
                );
              }
              if (event.key === "ArrowLeft" && childPlacements.length > 0) {
                event.preventDefault();
                setExpandedMemberIds((current) => {
                  const nextIds = new Set(current);
                  nextIds.delete(memberId);
                  return nextIds;
                });
              }
            }}
            aria-label={`Select ${member.name} in hierarchy`}
          >
            <strong>{member.name}</strong>
            <small>{member.member_id}</small>
          </button>
        </div>
        {childPlacements.length > 0 && expanded && (
          <ul role="group">
            {childPlacements.map((childPlacement) =>
              hierarchyNode(
                childPlacement.child_member_id,
                next,
                childPlacement,
              ),
            )}
          </ul>
        )}
      </li>
    );
  }

  async function readRelationships() {
    if (!app || !dimensionId || !canRead) return;
    setBusy(true);
    setError("");
    try {
      const scope = {
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
      };
      const collected = await collectMetadataRelationships(
        dimensionId,
        metadataRevision,
        (arguments_) =>
          readProgram(scope, "metadata.relationship.list", arguments_),
      );
      const found = collected.rows;
      setRelationships(found);
      setRelationshipRevision(collected.finalPage.metadataRevision);
      setExpandedMemberIds(
        new Set(found.map((relationship) => relationship.parent_member_id)),
      );
      const selectedMemberAfterRead = members.some(
        (member) => member.member_id === effectiveSelectedMemberId,
      )
        ? effectiveSelectedMemberId
        : members[0]?.member_id || "";
      const selectedPlacement = found.find(
        (relationship) =>
          relationship.child_member_id === selectedMemberAfterRead,
      );
      selectMember(selectedMemberAfterRead, selectedPlacement);
      setCreateReviewed(false);
      setStatusReviewed(false);
      setRenameReviewed(false);
      setDescribeReviewed(false);
      setBuildReviewed(false);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read relationships",
      );
    } finally {
      setBusy(false);
    }
  }

  async function execute(
    functionName: string,
    args: Record<string, unknown>,
    confirmation: string,
  ) {
    if (!app || !window.confirm(confirmation)) return;
    setBusy(true);
    setError("");
    setResult("");
    try {
      const response = await request<{
        receiptId?: string;
        result?: { receiptId?: string; operationId?: string };
      }>(
        "/api/metadata-action",
        metadataActionBody(
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
      setCreateReviewed(false);
      if (functionName === "metadata.relationship.create")
        setRelationshipId("");
      setStatusReviewed(false);
      setBuildReviewed(false);
      await onChanged();
      setRelationships([]);
      setRelationshipRevision(null);
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

  if (!canRead) return null;

  return (
    <section
      className="metadata-create"
      aria-labelledby="metadata-relationships-heading"
    >
      <div className="section-heading-row">
        <div>
          <small>VERSIONED HIERARCHY</small>
          <h3 id="metadata-relationships-heading">Relationships</h3>
          <p>
            Read current parent-child placements before proposing a reviewed
            relationship or rebuilding the server-owned closure.
          </p>
        </div>
        <span className="automatic-read-status">
          {busy ? "Refreshing relationships…" : "Loaded automatically"}
        </span>
      </div>
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {relationshipRevision !== null && (
        <p role="status">
          {relationships.length} relationships · metadata revision{" "}
          {relationshipRevision}
          {!snapshotCurrent && " · refresh the dimension/member snapshot"}
        </p>
      )}
      <div
        className="metadata-editor-tabs"
        role="group"
        aria-label="Relationship editor mode"
      >
        <button
          className={editorMode === "grid" ? "active" : ""}
          aria-pressed={editorMode === "grid"}
          onClick={() => setEditorMode("grid")}
        >
          List View
        </button>
        <button
          className={editorMode === "board" ? "active" : ""}
          aria-pressed={editorMode === "board"}
          onClick={() => setEditorMode("board")}
        >
          Tree View
        </button>
      </div>
      {editorMode === "grid" && members.length > 0 && (
        <MetadataMemberGrid
          app={app}
          catalog={catalog}
          dimensionId={dimensionId}
          members={members}
          relationships={relationships}
          metadataRevision={metadataRevision}
          selectedMemberId={effectiveSelectedMemberId}
          onSelectedMember={selectMember}
          onChanged={onChanged}
          onEditSecurityString={onEditMemberSecurityString}
          securityBusy={securityBusy}
        />
      )}
      {editorMode === "board" && (
        <div className="hierarchy-board" aria-label="Metadata Tree View">
          <p>
            Drag a member onto a tree node to prepare it as that node’s child.
            Nothing is saved until the exact relationship draft is reviewed.
          </p>
          <div className="metadata-tree-workspace">
            <div>
              <h4>Hierarchy</h4>
              <ul className="hierarchy-tree" role="tree">
                {rootMembers.map((member) =>
                  hierarchyNode(member.member_id, new Set()),
                )}
              </ul>
            </div>
            <div>
              <h4>Member List</h4>
              <p>Drag an unplaced member into the hierarchy.</p>
              <div className="hierarchy-member-board">
                {unplacedMembers.map((member) => (
                  <button
                    type="button"
                    key={member.member_id}
                    className="hierarchy-member-card"
                    draggable
                    onDragStart={() => setDraggedMemberId(member.member_id)}
                    onDragEnd={() => setDraggedMemberId("")}
                    onClick={() => selectMember(member.member_id)}
                  >
                    <strong>{member.name}</strong>
                    <small>{member.member_id}</small>
                  </button>
                ))}
              </div>
            </div>
          </div>
          <p className="hierarchy-draft" role="status">
            Draft: {parentMemberId || "parent"} → {childMemberId || "child"}
          </p>
        </div>
      )}
      {selectedMember && (
        <aside
          className="metadata-property-pane"
          aria-label="Selected metadata properties"
        >
          <div>
            <small>MEMBER PROPERTIES</small>
            <h4>{selectedMember.name}</h4>
            <dl>
              <dt>Stable ID</dt>
              <dd>{selectedMember.member_id}</dd>
              <dt>Status</dt>
              <dd>{selectedMember.status}</dd>
              <dt>Short description</dt>
              <dd>{selectedMember.short_description || "—"}</dd>
              <dt>Semantic description</dt>
              <dd>{selectedMember.detailed_description || "—"}</dd>
              <dt>Numeric kind</dt>
              <dd>{selectedMember.numeric_value_kind || "Unspecified"}</dd>
            </dl>
          </div>
          <div>
            <small>PLACEMENT PROPERTIES</small>
            {selectedRelationship ? (
              <>
                <h4>{selectedRelationship.relationship_id}</h4>
                <dl>
                  <dt>Name</dt>
                  <dd>
                    {selectedRelationship.name ||
                      selectedRelationship.relationship_id}
                  </dd>
                  <dt>Parent</dt>
                  <dd>{selectedRelationship.parent_member_id}</dd>
                  <dt>Child</dt>
                  <dd>{selectedRelationship.child_member_id}</dd>
                  <dt>Status</dt>
                  <dd>{selectedRelationship.status}</dd>
                  <dt>Short description</dt>
                  <dd>{selectedRelationship.short_description || "—"}</dd>
                  <dt>Semantic description</dt>
                  <dd>
                    {selectedRelationship.semantic_description ||
                      selectedRelationship.detailed_description ||
                      "—"}
                  </dd>
                </dl>
              </>
            ) : (
              <p>This member has no selected parent-child placement.</p>
            )}
          </div>
        </aside>
      )}
      {selectedRelationship && (canRename || canDescribe) && (
        <fieldset className="metadata-placement-editor">
          <legend>Selected placement editor</legend>
          {canRename && (
            <div className="maintenance-action">
              <label>
                Relationship display name
                <input
                  value={relationshipName}
                  maxLength={200}
                  onChange={(event) => {
                    setRelationshipName(event.target.value);
                    setRenameReviewed(false);
                    setResult("");
                  }}
                />
              </label>
              <div className="reviewed-inline-action">
                <label className="review-check">
                  <input
                    type="checkbox"
                    checked={renameReviewed}
                    disabled={!renameValid}
                    onChange={(event) =>
                      setRenameReviewed(event.target.checked)
                    }
                  />
                  I reviewed this exact relationship name and metadata revision.
                </label>
                <button
                  disabled={busy || !renameReviewed || !renameValid}
                  onClick={() =>
                    void execute(
                      "metadata.relationship.rename",
                      {
                        relationshipId: selectedRelationship.relationship_id,
                        name: relationshipName,
                        expectedMetadataRevision: metadataRevision,
                      },
                      `Rename relationship ${selectedRelationship.relationship_id} to ${relationshipName}?`,
                    )
                  }
                >
                  Rename relationship
                </button>
              </div>
            </div>
          )}
          {canDescribe && (
            <div className="maintenance-action">
              <label>
                Relationship short description
                <textarea
                  value={relationshipShort}
                  maxLength={500}
                  onChange={(event) => {
                    setRelationshipShort(event.target.value);
                    setDescribeReviewed(false);
                    setResult("");
                  }}
                />
              </label>
              <label>
                Relationship semantic description
                <textarea
                  value={relationshipSemantic}
                  maxLength={10000}
                  onChange={(event) => {
                    setRelationshipSemantic(event.target.value);
                    setDescribeReviewed(false);
                    setResult("");
                  }}
                />
              </label>
              <div className="reviewed-inline-action">
                <label className="review-check">
                  <input
                    type="checkbox"
                    checked={describeReviewed}
                    disabled={!describeValid}
                    onChange={(event) =>
                      setDescribeReviewed(event.target.checked)
                    }
                  />
                  I reviewed these exact relationship descriptions and metadata
                  revision.
                </label>
                <button
                  disabled={busy || !describeReviewed || !describeValid}
                  onClick={() =>
                    void execute(
                      "metadata.relationship.describe",
                      {
                        relationshipId: selectedRelationship.relationship_id,
                        shortDescription: relationshipShort,
                        detailedDescription: relationshipSemantic,
                        expectedMetadataRevision: metadataRevision,
                      },
                      `Save reviewed descriptions for ${selectedRelationship.relationship_id}?`,
                    )
                  }
                >
                  Save relationship descriptions
                </button>
              </div>
            </div>
          )}
        </fieldset>
      )}
      {canCreate && (
        <fieldset>
          <legend>New relationship · inline editor</legend>
          <div className="react-grid-scroll">
            <table className="react-cube-grid metadata-inline-grid">
              <thead>
                <tr>
                  <th>Stable ID</th>
                  <th>Parent member</th>
                  <th>Child member</th>
                  <th>Reviewed</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>
                    <input
                      aria-label="Stable ID"
                      value={relationshipId}
                      maxLength={200}
                      onChange={(event) => {
                        setRelationshipId(event.target.value);
                        invalidateCreate();
                      }}
                    />
                  </td>
                  <td>
                    <select
                      aria-label="Parent member"
                      value={parentMemberId}
                      onChange={(event) => {
                        setParentMemberId(event.target.value);
                        invalidateCreate();
                      }}
                    >
                      {activeMembers.map((member) => (
                        <option key={member.member_id} value={member.member_id}>
                          {member.name}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <select
                      aria-label="Child member"
                      value={childMemberId}
                      onChange={(event) => {
                        setChildMemberId(event.target.value);
                        invalidateCreate();
                      }}
                    >
                      {activeMembers.map((member) => (
                        <option key={member.member_id} value={member.member_id}>
                          {member.name}
                        </option>
                      ))}
                    </select>
                  </td>
                  <td>
                    <label className="review-check compact-review">
                      <input
                        type="checkbox"
                        checked={createReviewed}
                        disabled={!createValid}
                        onChange={(event) =>
                          setCreateReviewed(event.target.checked)
                        }
                      />
                      <span>
                        I reviewed this exact parent-child relationship and
                        metadata revision.
                      </span>
                    </label>
                  </td>
                  <td>
                    <button
                      disabled={busy || !createReviewed || !createValid}
                      onClick={() =>
                        void execute(
                          "metadata.relationship.create",
                          {
                            dimensionId,
                            relationshipId,
                            parentMemberId,
                            childMemberId,
                            expectedMetadataRevision: metadataRevision,
                          },
                          `Create reviewed relationship ${relationshipId}?`,
                        )
                      }
                    >
                      Create relationship
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </fieldset>
      )}
      {canSetStatus && relationships.length > 0 && (
        <fieldset>
          <legend>Relationship status</legend>
          <div className="metadata-create-fields">
            <label>
              Relationship
              <select
                value={selectedRelationshipId}
                onChange={(event) => {
                  const selected = relationships.find(
                    (item) => item.relationship_id === event.target.value,
                  );
                  if (selected)
                    selectMember(selected.child_member_id, selected);
                }}
              >
                {relationships.map((relationship) => (
                  <option
                    key={relationship.relationship_id}
                    value={relationship.relationship_id}
                  >
                    {relationship.relationship_id}
                  </option>
                ))}
              </select>
            </label>
            <label>
              New status
              <select
                value={selectedStatus}
                onChange={(event) => {
                  setSelectedStatus(
                    event.target.value as "Active" | "Inactive",
                  );
                  setStatusReviewed(false);
                }}
              >
                <option>Active</option>
                <option>Inactive</option>
              </select>
            </label>
          </div>
          <div className="reviewed-inline-action">
            <label className="review-check">
              <input
                type="checkbox"
                checked={statusReviewed}
                disabled={!statusValid}
                onChange={(event) => setStatusReviewed(event.target.checked)}
              />
              I reviewed this exact relationship status and metadata revision.
            </label>
            <button
              disabled={busy || !statusReviewed || !statusValid}
              onClick={() =>
                void execute(
                  "metadata.relationship.status.set",
                  {
                    relationshipId: selectedRelationshipId,
                    status: selectedStatus,
                    expectedMetadataRevision: metadataRevision,
                  },
                  `Set ${selectedRelationshipId} to ${selectedStatus}?`,
                )
              }
            >
              Set relationship status
            </button>
          </div>
        </fieldset>
      )}
      <MetadataSecurityStringEditor
        key={`Relationship:${selectedRelationshipId}`}
        app={app}
        catalog={catalog}
        targetKind="Relationship"
        targetId={selectedRelationshipId}
        onChanged={async () => {
          await onChanged();
          await readRelationships();
        }}
      />
      {canBuild && relationshipRevision !== null && (
        <div className="reviewed-inline-action">
          <label className="review-check">
            <input
              type="checkbox"
              checked={buildReviewed}
              disabled={!snapshotCurrent}
              onChange={(event) => setBuildReviewed(event.target.checked)}
            />
            I reviewed this dimension, relationship snapshot and metadata
            revision for hierarchy build.
          </label>
          <button
            disabled={busy || !buildReviewed || !snapshotCurrent}
            onClick={() =>
              void execute(
                "metadata.hierarchy.build",
                { dimensionId, expectedMetadataRevision: metadataRevision },
                `Build the reviewed ${dimensionId} hierarchy?`,
              )
            }
          >
            Build hierarchy
          </button>
        </div>
      )}
      {result && <p role="status">{result}</p>}
      <p className="authority-note">
        Cycle checks, dependency guards, closure construction and publication
        remain fixed-core responsibilities.
      </p>
    </section>
  );
}
