import { useEffect, useRef, useState, type ReactNode } from "react";
import { ApiError, readProgram } from "./api";
import { MetadataMemberGrid } from "./MetadataMemberGrid";
import { validMetadataText } from "./MetadataCreate";
import { MetadataSecurityStringEditor } from "./MetadataSecurityStringEditor";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { usePreservedDraft } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import {
  collectMetadataRelationships,
  type MetadataRelationship,
} from "./metadata-relationships-data";
export {
  collectMetadataRelationships,
  type MetadataRelationship,
} from "./metadata-relationships-data";
import {
  collectMetadataHierarchies,
  collectHierarchyMembers,
  type MetadataHierarchy,
  type HierarchyMember,
} from "./metadata-hierarchies";
import {
  focusWhenInteractive,
  MetadataReceiptRecovery,
} from "./MetadataReceiptRecovery";
import { useMetadataMutationRecovery } from "./metadata-mutation-recovery";
import {
  hierarchyBuild,
  useHierarchyBuildRecovery,
} from "./hierarchy-build-recovery";
import { MetadataHierarchyEditor } from "./MetadataHierarchyEditor";
import { MemberSelectionDialog } from "./member-selection/MemberSelectionDialog";
import {
  placementApply,
  useHierarchyPlacementRecovery,
  type HierarchyPatchPreview,
  type PlacementDraftAction,
} from "./hierarchy-placement-recovery";

type HierarchyPatchChange =
  | {
      action: "Create";
      relationshipId: string;
      parentMemberId: string;
      childMemberId: string;
    }
  | { action: "Deactivate"; relationshipId: string };

type HierarchyPatchArguments = {
  dimensionId: string;
  hierarchyId?: string;
  changes: HierarchyPatchChange[];
  expectedMetadataRevision: number;
  expectedHierarchyStateToken: string;
};

const newHiddenRelationshipId = () => `placement-${crypto.randomUUID()}`;

export function placementPatchChanges({
  action,
  relationshipId,
  sourceRelationshipId,
  parentMemberId,
  childMemberId,
}: {
  action: PlacementDraftAction;
  relationshipId: string;
  sourceRelationshipId?: string;
  parentMemberId: string;
  childMemberId: string;
}): HierarchyPatchChange[] {
  const create: HierarchyPatchChange = {
    action: "Create",
    relationshipId,
    parentMemberId,
    childMemberId,
  };
  if (action !== "move") return [create];
  if (!sourceRelationshipId)
    throw new Error("A move requires the exact current placement.");
  return [
    { action: "Deactivate", relationshipId: sourceRelationshipId },
    create,
  ];
}

type Member = {
  member_id: string;
  name: string;
  status: string;
  short_description?: string;
  detailed_description?: string;
  numeric_value_kind?: "amount" | "ratio" | null;
  custom_values?: Record<string, unknown>;
};

const relationshipEditFields = {
  "metadata.relationship.rename": ["name"],
  "metadata.relationship.describe": ["shortDescription", "detailedDescription"],
  "metadata.relationship.status.set": ["status"],
  "metadata.relationship.aggregation-operator.set": [
    "aggregationOperatorOverride",
  ],
} as const;
type RelationshipEdit = keyof typeof relationshipEditFields;
type RelationshipProperties = {
  name: string;
  shortDescription: string;
  detailedDescription: string;
  status: MetadataRelationship["status"];
  aggregationOperatorOverride: string;
};
type RelationshipDraft = {
  relationshipId: string;
  fields: Partial<RelationshipProperties>;
};
const relationshipRefusals = new Set([
  "ACTIVE_MEMBERS_REQUIRED",
  "ACTIVE_RELATIONSHIP_REQUIRED",
  "METADATA_DESCRIPTION_UNCHANGED",
  "METADATA_NAME_UNCHANGED",
  "RELATIONSHIP_AGGREGATION_OPERATOR_INVALID",
  "RELATIONSHIP_AGGREGATION_OPERATOR_UNCHANGED",
  "RELATIONSHIP_HAS_ACTIVE_OWNERSHIP",
  "RELATIONSHIP_STATUS_INVALID",
  "RELATIONSHIP_STATUS_UNCHANGED",
  "RELATIONSHIP_UNAVAILABLE",
  "SEMANTIC_REFERENCE_MEMBER_UNAVAILABLE",
]);

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
  hierarchyId,
  onHierarchyIdChange,
  members,
  metadataRevision,
  onChanged,
  selectedMemberId,
  selectedRelationshipId: routedRelationshipId,
  onSelectedMemberIdChange,
  onRequestTransition,
  onEditMemberSecurityString,
  securityBusy,
  creationDisabled,
  mode = "all",
  showViewToggle = true,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  dimensionId: string;
  hierarchyId?: string;
  onHierarchyIdChange?: (hierarchyId: string) => void;
  members: Member[];
  metadataRevision: number | null;
  onChanged: () => Promise<void>;
  selectedMemberId?: string;
  selectedRelationshipId?: string;
  onSelectedMemberIdChange?: (
    memberId: string,
    relationshipId?: string,
  ) => void;
  onRequestTransition?: (action: () => void) => void;
  onEditMemberSecurityString?: (member: Member) => void;
  securityBusy?: boolean;
  creationDisabled?: boolean;
  mode?: "members" | "relationships" | "tree" | "all";
  showViewToggle?: boolean;
}) {
  const mutationIntentKey = useStableMutationIntentKey("relationship-ui");
  const [storedRelationships, setRelationships] = useState<
    MetadataRelationship[]
  >([]);
  const [internalHierarchySelection, setHierarchySelection] = useState("");
  const hierarchySelection =
    hierarchyId ?? (onHierarchyIdChange ? "" : internalHierarchySelection);
  const [hierarchyCatalogue, setHierarchyCatalogue] = useState<{
    context: string;
    rows: MetadataHierarchy[];
  } | null>(null);
  const [hierarchyMembers, setHierarchyMembers] = useState<HierarchyMember[]>(
    [],
  );
  const [loadedContext, setLoadedContext] = useState("");
  const readAbort = useRef<AbortController | null>(null);
  const hierarchyContext = JSON.stringify([
    app?.workspaceId,
    app?.applicationId,
    dimensionId,
    catalog?.accessContext,
    catalog?.applicationAccess.issuer,
    catalog?.applicationAccess.subjectId,
    catalog?.revisions.security,
    Boolean(catalog?.functions["metadata.hierarchy.list"]),
    Boolean(catalog?.functions["metadata.hierarchy.members.list"]),
  ]);
  const relationshipContext = JSON.stringify([
    hierarchyContext,
    hierarchySelection,
  ]);
  const canReadHierarchies = Boolean(
    catalog?.functions["metadata.hierarchy.list"] &&
      catalog?.functions["metadata.hierarchy.members.list"],
  );
  const hierarchies =
    hierarchyCatalogue?.context === hierarchyContext
      ? hierarchyCatalogue.rows
      : [];
  const selectedHierarchy = hierarchies.find((row) =>
    hierarchySelection ? row.hierarchyId === hierarchySelection : row.isDefault,
  );
  const relationships =
    loadedContext === relationshipContext ? storedRelationships : [];
  const visibleHierarchyMembers =
    loadedContext === relationshipContext ? hierarchyMembers : [];
  const explicitMemberIds = new Set(
    visibleHierarchyMembers
      .filter((row) => row.status === "Active")
      .map((row) => row.memberId),
  );
  const hierarchyActive =
    !canReadHierarchies || selectedHierarchy?.status === "Active";

  const [relationshipRevision, setRelationshipRevision] = useState<
    number | null
  >(null);
  const [relationshipRefresh, setRelationshipRefresh] = useState(0);
  const [relationshipId, setRelationshipId] = useState("");
  const [parentMemberId, setParentMemberId] = useState("");
  const [childMemberId, setChildMemberId] = useState("");
  const [placementAction, setPlacementAction] =
    useState<PlacementDraftAction>("create");
  const [sourceRelationshipId, setSourceRelationshipId] = useState("");
  const [patchPreview, setPatchPreview] = useState<{
    arguments: HierarchyPatchArguments;
    result: HierarchyPatchPreview;
  } | null>(null);
  const [internalSelectedRelationshipId, setSelectedRelationshipId] =
    useState("");
  const selectedRelationshipId =
    routedRelationshipId ?? internalSelectedRelationshipId;
  const [statusReviewed, setStatusReviewed] = useState(false);
  const [propertyDraft, setPropertyDraft] = useState<RelationshipDraft | null>(
    null,
  );
  const [renameReviewed, setRenameReviewed] = useState(false);
  const [describeReviewed, setDescribeReviewed] = useState(false);
  const [reviewedBuild, setReviewedBuild] = useState<string | null>(null);
  const buildPin = JSON.stringify([
    relationshipContext,
    metadataRevision,
    selectedHierarchy?.hierarchyId,
    selectedHierarchy?.stateToken,
  ]);
  const buildReviewed = reviewedBuild === buildPin;
  const [draftRevision, setDraftRevision] = useState(metadataRevision);
  const propertyDraftRef = useRef(propertyDraft);
  propertyDraftRef.current = propertyDraft;
  const readGeneration = useRef(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
  const resultStatus = useRef<HTMLParagraphElement>(null);
  const focusReceiptResult = useRef(false);
  const activeView = useRef(relationshipContext);
  activeView.current = relationshipContext;
  async function refreshRelationshipWorkspace() {
    await onChanged();
    if (activeView.current === relationshipContext)
      setRelationshipRefresh((previous) => previous + 1);
  }
  function refreshAfterCommit(message: string) {
    setRelationshipRevision(null);
    const view = activeView.current;
    void Promise.resolve()
      .then(refreshRelationshipWorkspace)
      .catch(() => {
        if (activeView.current === view) setError(message);
      });
  }
  const placementRecovery = useHierarchyPlacementRecovery(
    app,
    catalog,
    JSON.stringify([
      relationshipContext,
      catalog?.applicationAccess.role,
      catalog?.revisions.capability,
    ]),
    ({ action, preview }, source) => {
      const label =
        action === "move" ? "move" : action === "copy" ? "copy" : "creation";
      setResult(
        source === "receipt"
          ? `The original placement ${label} was recorded.`
          : `The reviewed placement ${label} was applied atomically.`,
      );
      if (patchPreview?.result.previewToken === preview.previewToken) {
        setPlacementAction("create");
        setSourceRelationshipId("");
        setRelationshipId("");
        setPatchPreview(null);
      }
      refreshAfterCommit(
        "Placement recorded. Refresh the model to see the current hierarchy.",
      );
    },
  );
  const propertyRecovery = useMetadataMutationRecovery<
    RelationshipDraft & {
      actorId: string;
      metadataRevision: number;
    }
  >(
    app,
    mode === "members" ? null : catalog,
    JSON.stringify([
      relationshipContext,
      catalog?.applicationAccess.role,
      catalog?.revisions.capability,
    ]),
    {
      editor: `metadata-relationship-change:${dimensionId}`,
      pendingLabel: "Relationship change with an unconfirmed outcome",
      functions: Object.keys(relationshipEditFields),
      subject: "relationship change",
      closePrompt:
        "Close this unconfirmed relationship change? Read the current model before reviewing another change.",
      refuses: (code) => relationshipRefusals.has(code),
    },
    (attempt, source) => {
      setPropertyDraft((current) => {
        if (current?.relationshipId !== attempt.relationshipId) return current;
        const fields = { ...current.fields };
        for (const field of Object.keys(
          attempt.fields,
        ) as (keyof RelationshipProperties)[])
          if (fields[field] === attempt.fields[field]) delete fields[field];
        return Object.keys(fields).length ? { ...current, fields } : null;
      });
      setStatusReviewed(false);
      setRenameReviewed(false);
      setDescribeReviewed(false);
      setReviewedBuild(null);
      focusReceiptResult.current = source === "receipt";
      setResult(
        source === "receipt"
          ? "The original relationship change was recorded."
          : "The reviewed relationship change was applied.",
      );
      refreshAfterCommit(
        "Relationship change recorded. Refresh the model to see the current placement.",
      );
    },
  );
  const buildRecovery = useHierarchyBuildRecovery(
    app,
    mode === "members" ? null : catalog,
    JSON.stringify([
      relationshipContext,
      catalog?.applicationAccess.role,
      catalog?.revisions.capability,
    ]),
    dimensionId,
    (_attempt, source) => {
      setStatusReviewed(false);
      setReviewedBuild(null);
      focusReceiptResult.current = source === "receipt";
      setResult(
        source === "receipt"
          ? "The original hierarchy build was recorded."
          : "The reviewed hierarchy was built.",
      );
      refreshAfterCommit(
        "Hierarchy build recorded. Refresh the model to see the current closure.",
      );
    },
  );
  const changeBlocked =
    placementRecovery.busy ||
    placementRecovery.pending ||
    propertyRecovery.busy ||
    propertyRecovery.pending ||
    buildRecovery.busy ||
    buildRecovery.pending;
  useEffect(() => {
    if (result && focusReceiptResult.current) {
      focusReceiptResult.current = false;
      return focusWhenInteractive(resultStatus.current);
    }
  }, [result]);
  const [editorMode, setEditorMode] = useState<"grid" | "board">(
    mode === "tree" ? "board" : "grid",
  );
  const [draggedPlacement, setDraggedPlacement] = useState<{
    memberId: string;
    relationshipId?: string;
  } | null>(null);
  const [internalSelectedMemberId, setInternalSelectedMemberId] = useState("");
  const [expandedMemberIds, setExpandedMemberIds] = useState<Set<string>>(
    new Set(),
  );
  const [relationshipMemberChooser, setRelationshipMemberChooser] = useState<
    "parent" | "child" | null
  >(null);

  const canRead = Boolean(catalog?.functions["metadata.relationship.list"]);
  const canSetStatus = Boolean(
    catalog?.functions["metadata.relationship.status.set"],
  );
  const canRename = Boolean(catalog?.functions["metadata.relationship.rename"]);
  const canDescribe = Boolean(
    catalog?.functions["metadata.relationship.describe"],
  );
  const canBuild = Boolean(catalog?.functions[hierarchyBuild]);
  const canPatchRelationships = Boolean(
    catalog?.functions["metadata.hierarchy.relationships.preview"] &&
      catalog?.functions["metadata.hierarchy.relationships.apply"],
  );
  const canSetOperator = Boolean(
    catalog?.functions["metadata.relationship.aggregation-operator.set"],
  );
  const snapshotCurrent = Boolean(
    metadataRevision !== null &&
      loadedContext === relationshipContext &&
      relationshipRevision === metadataRevision &&
      draftRevision === metadataRevision,
  );
  const activeMembers = members.filter(
    (member) =>
      member.status === "Active" &&
      hierarchyActive &&
      (!canReadHierarchies ||
        (loadedContext === relationshipContext &&
          (selectedHierarchy?.membershipMode !== "explicit" ||
            explicitMemberIds.has(member.member_id)))),
  );
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
      ) &&
      !relationships.some(
        (relationship) =>
          relationship.status === "Active" &&
          relationship.parent_member_id === parentMemberId &&
          relationship.child_member_id === childMemberId,
      ),
  );
  const hierarchyPatchValid = Boolean(
    createValid &&
      canPatchRelationships &&
      selectedHierarchy?.stateToken &&
      metadataRevision !== null &&
      (placementAction !== "move" ||
        relationships.some(
          (relationship) =>
            relationship.relationship_id === sourceRelationshipId &&
            relationship.status === "Active" &&
            relationship.child_member_id === childMemberId &&
            relationship.parent_member_id !== parentMemberId,
        )),
  );
  const sourceRelationship = relationships.find(
    (relationship) => relationship.relationship_id === sourceRelationshipId,
  );
  const effectiveSelectedMemberId =
    selectedMemberId === undefined
      ? internalSelectedMemberId
      : selectedMemberId;
  const selectedRelationship = relationships.find(
    (relationship) =>
      relationship.relationship_id === selectedRelationshipId &&
      relationship.child_member_id === effectiveSelectedMemberId,
  );
  const baseProperties: RelationshipProperties = {
    name:
      selectedRelationship?.name || selectedRelationship?.relationship_id || "",
    shortDescription: selectedRelationship?.short_description || "",
    detailedDescription:
      selectedRelationship?.detailed_description ??
      selectedRelationship?.semantic_description ??
      "",
    status: selectedRelationship?.status || "Active",
    aggregationOperatorOverride:
      selectedRelationship?.aggregation_operator_override || "",
  };
  const propertyValues = {
    ...baseProperties,
    ...(propertyDraft?.relationshipId === selectedRelationshipId
      ? propertyDraft.fields
      : {}),
  };
  const {
    name: relationshipName,
    shortDescription: relationshipShort,
    detailedDescription: relationshipSemantic,
    status: selectedStatus,
    aggregationOperatorOverride: relationshipOperator,
  } = propertyValues;
  function editProperty<Field extends keyof RelationshipProperties>(
    field: Field,
    value: RelationshipProperties[Field],
  ) {
    setPropertyDraft((current) => {
      const fields =
        current?.relationshipId === selectedRelationshipId
          ? { ...current.fields }
          : {};
      if (value === baseProperties[field]) delete fields[field];
      else fields[field] = value;
      return Object.keys(fields).length
        ? { relationshipId: selectedRelationshipId, fields }
        : null;
    });
  }
  const currentSelection = useRef({
    memberId: effectiveSelectedMemberId,
    relationshipId: selectedRelationshipId,
    members,
    explicitPlacement: routedRelationshipId !== undefined,
  });
  currentSelection.current = {
    memberId: effectiveSelectedMemberId,
    relationshipId: selectedRelationshipId,
    members,
    explicitPlacement: routedRelationshipId !== undefined,
  };
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
      relationshipName !== baseProperties.name,
  );
  const describeValid = Boolean(
    snapshotCurrent &&
      selectedRelationship &&
      relationshipShort.length <= 500 &&
      relationshipSemantic.length <= 10000 &&
      (relationshipShort !== baseProperties.shortDescription ||
        relationshipSemantic !== baseProperties.detailedDescription),
  );
  usePreservedDraft(
    app?.workspaceId || "none",
    app?.applicationId || "none",
    `metadata-relationships:${mode}:${dimensionId || "none"}:${selectedHierarchy?.hierarchyId || hierarchySelection || "default"}`,
    "Unsaved hierarchy relationship changes",
    mode !== "members" && Boolean(relationshipId || propertyDraft),
    {
      draftRevision,
      propertyDraft,
      relationshipId,
      parentMemberId,
      childMemberId,
      placementAction,
      sourceRelationshipId,
      selectedRelationshipId,
      statusReviewed,
      renameReviewed,
      describeReviewed,
      editorMode,
      internalSelectedMemberId,
    },
    (draft) => {
      setRelationshipId(draft.relationshipId);
      setParentMemberId(draft.parentMemberId);
      setChildMemberId(draft.childMemberId);
      setPlacementAction(draft.placementAction || "create");
      setSourceRelationshipId(draft.sourceRelationshipId || "");
      setPatchPreview(null);
      setDraftRevision(draft.draftRevision);
      propertyDraftRef.current = draft.propertyDraft;
      setPropertyDraft(draft.propertyDraft);
      setSelectedRelationshipId(draft.selectedRelationshipId);
      setStatusReviewed(false);
      setRenameReviewed(false);
      setDescribeReviewed(false);
      setReviewedBuild(null);
      setEditorMode(draft.editorMode);
      setInternalSelectedMemberId(draft.internalSelectedMemberId);
    },
  );

  useEffect(() => {
    setRelationships([]);
    setRelationshipRevision(null);
    setRelationshipId("");
    setPropertyDraft(null);
    setParentMemberId("");
    setChildMemberId("");
    setPlacementAction("create");
    setSourceRelationshipId("");
    setPatchPreview(null);
    setDraftRevision(metadataRevision);
    setSelectedRelationshipId("");
    setStatusReviewed(false);
    setRenameReviewed(false);
    setDescribeReviewed(false);
    setReviewedBuild(null);
    setError("");
    setResult("");
    setInternalSelectedMemberId("");
    setExpandedMemberIds(new Set());
  }, [
    app?.workspaceId,
    app?.applicationId,
    dimensionId,
    hierarchySelection,
    catalog?.applicationAccess.issuer,
    catalog?.applicationAccess.subjectId,
  ]);

  const priorCanonicalHierarchy = useRef<string | undefined>(undefined);
  useEffect(() => {
    const previous = priorCanonicalHierarchy.current;
    const next = selectedHierarchy?.hierarchyId;
    priorCanonicalHierarchy.current = next;
    if (previous && next && previous !== next) {
      setPropertyDraft(null);
      setRelationshipId("");
      setParentMemberId("");
      setChildMemberId("");
      setPlacementAction("create");
      setSourceRelationshipId("");
      setPatchPreview(null);
      setRenameReviewed(false);
      setDescribeReviewed(false);
      setReviewedBuild(null);
      setDraftRevision(metadataRevision);
    }
  }, [selectedHierarchy?.hierarchyId]);

  useEffect(() => {
    // A visible placement can be chosen before this render's passive effects
    // run. Do not replace that newer member/placement intent with a fallback.
    if (
      currentSelection.current.memberId !== effectiveSelectedMemberId ||
      currentSelection.current.relationshipId !== selectedRelationshipId
    )
      return;
    const nextMemberId = members.some(
      (member) => member.member_id === effectiveSelectedMemberId,
    )
      ? effectiveSelectedMemberId
      : members[0]?.member_id || "";
    if (nextMemberId !== effectiveSelectedMemberId)
      selectMember(nextMemberId, undefined, false);
  }, [members, effectiveSelectedMemberId, selectedRelationshipId]);

  useEffect(() => {
    if (
      currentSelection.current.memberId !== effectiveSelectedMemberId ||
      currentSelection.current.relationshipId !== selectedRelationshipId
    )
      return;
    if (!effectiveSelectedMemberId || routedRelationshipId !== undefined)
      return;
    const currentPlacement = relationships.find(
      (relationship) => relationship.relationship_id === selectedRelationshipId,
    );
    if (currentPlacement?.child_member_id === effectiveSelectedMemberId) return;
    const nextPlacement = relationships.find(
      (relationship) =>
        relationship.child_member_id === effectiveSelectedMemberId,
    );
    setSelectedRelationshipId(nextPlacement?.relationship_id || "");
    setStatusReviewed(false);
  }, [
    effectiveSelectedMemberId,
    relationships,
    selectedRelationshipId,
    routedRelationshipId,
  ]);

  useEffect(() => {
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
  }, [members, loadedContext, relationshipContext]);

  useEffect(() => {
    if (canRead && app && dimensionId && metadataRevision !== null)
      void readRelationships();
    return () => {
      readGeneration.current += 1;
      readAbort.current?.abort();
    };
  }, [
    app?.workspaceId,
    app?.applicationId,
    dimensionId,
    metadataRevision,
    canRead,
    canReadHierarchies,
    hierarchySelection,
    hierarchyContext,
    relationshipRefresh,
  ]);

  useEffect(() => {
    setStatusReviewed(false);
    setRenameReviewed(false);
    setDescribeReviewed(false);
    setReviewedBuild(null);
    if (!relationshipId && !propertyDraft) setDraftRevision(metadataRevision);
  }, [metadataRevision]);

  function invalidateCreate() {
    setPatchPreview(null);
    setResult("");
  }

  function prepareRelationship(
    parent: string,
    child: string,
    action: PlacementDraftAction = "create",
    sourceId = "",
  ) {
    if (!parent || !child || parent === child) return;
    setParentMemberId(parent);
    setChildMemberId(child);
    setPlacementAction(action);
    setSourceRelationshipId(action === "create" ? "" : sourceId);
    setRelationshipId(newHiddenRelationshipId());
    invalidateCreate();
  }

  function placementLabel(relationship: MetadataRelationship) {
    const parent = members.find(
      (member) => member.member_id === relationship.parent_member_id,
    );
    const child = members.find(
      (member) => member.member_id === relationship.child_member_id,
    );
    return `${child?.name || relationship.child_member_id} under ${parent?.name || relationship.parent_member_id}`;
  }

  function patchChanges(): HierarchyPatchChange[] {
    return placementPatchChanges({
      action: placementAction,
      relationshipId,
      sourceRelationshipId,
      parentMemberId,
      childMemberId,
    });
  }

  function selectMember(
    memberId: string,
    relationship?: MetadataRelationship,
    notify = true,
  ) {
    const placementId = relationship?.relationship_id || "";
    const applySelection = () => {
      currentSelection.current = {
        ...currentSelection.current,
        memberId,
        relationshipId: placementId,
      };
      if (placementId !== selectedRelationshipId) setPropertyDraft(null);
      if (selectedMemberId === undefined) setInternalSelectedMemberId(memberId);
      if (notify)
        onSelectedMemberIdChange?.(memberId, placementId || undefined);
      setSelectedRelationshipId(placementId);
      setStatusReviewed(false);
      setRenameReviewed(false);
      setDescribeReviewed(false);
    };
    // Placements have independent drafts even when they share a child member
    // and therefore the same route. Guard before changing any local state.
    if (
      notify &&
      onRequestTransition &&
      (memberId !== effectiveSelectedMemberId ||
        placementId !== selectedRelationshipId)
    )
      onRequestTransition(applySelection);
    else applySelection();
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
    placement?: MetadataRelationship,
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
            onDragStart={() =>
              setDraggedPlacement({
                memberId,
                ...(placement
                  ? { relationshipId: placement.relationship_id }
                  : {}),
              })
            }
            onDragEnd={() => setDraggedPlacement(null)}
            onDragOver={(event) => event.preventDefault()}
            onDrop={(event) => {
              event.preventDefault();
              if (!draggedPlacement) return;
              const source = draggedPlacement.relationshipId
                ? relationships.find(
                    (item) =>
                      item.relationship_id === draggedPlacement.relationshipId,
                  )
                : undefined;
              prepareRelationship(
                memberId,
                draggedPlacement.memberId,
                source ? "move" : "create",
                source?.relationship_id,
              );
              setDraggedPlacement(null);
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
            aria-label={`Select ${member.name} in hierarchy${placement ? ` under ${members.find((item) => item.member_id === placement.parent_member_id)?.name || placement.parent_member_id}` : ""}`}
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
    const generation = ++readGeneration.current;
    setBusy(true);
    setError("");
    try {
      const scope = {
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
      };
      readAbort.current?.abort();
      const controller = new AbortController();
      readAbort.current = controller;
      if (hierarchySelection && !canReadHierarchies)
        throw new Error("Named hierarchy read access is unavailable.");
      let selected: MetadataHierarchy | undefined;
      let nodes: HierarchyMember[] = [];
      if (canReadHierarchies && metadataRevision !== null) {
        const catalogue = await collectMetadataHierarchies(
          dimensionId,
          metadataRevision,
          (args) =>
            readProgram(
              scope,
              "metadata.hierarchy.list",
              args,
              controller.signal,
            ),
        );
        if (generation !== readGeneration.current || controller.signal.aborted)
          return;
        setHierarchyCatalogue({
          context: hierarchyContext,
          rows: catalogue.rows,
        });
        selected = catalogue.rows.find((row) =>
          hierarchySelection
            ? row.hierarchyId === hierarchySelection
            : row.isDefault,
        );
        if (hierarchySelection && !selected)
          throw new Error(
            "The selected hierarchy is unavailable. Choose a current hierarchy.",
          );
        if (selected) {
          const membership = await collectHierarchyMembers(
            dimensionId,
            selected.hierarchyId,
            metadataRevision,
            (args) =>
              readProgram(
                scope,
                "metadata.hierarchy.members.list",
                args,
                controller.signal,
              ),
          );
          nodes = membership.rows;
        }
      }
      const collected =
        selected?.status === "Inactive"
          ? { rows: [], finalPage: { metadataRevision } }
          : await collectMetadataRelationships(
              dimensionId,
              metadataRevision,
              (args) =>
                readProgram(
                  scope,
                  "metadata.relationship.list",
                  args,
                  controller.signal,
                ),
              selected?.hierarchyId,
            );
      if (generation !== readGeneration.current || controller.signal.aborted)
        return;
      setHierarchyMembers(nodes);
      setLoadedContext(relationshipContext);
      const found = collected.rows;
      setRelationships(found);
      setRelationshipRevision(collected.finalPage.metadataRevision);
      setExpandedMemberIds(
        new Set(found.map((relationship) => relationship.parent_member_id)),
      );
      // Refresh data without replacing a more recent selection. A member can
      // have several parent placements, so preserve the exact surviving one.
      const latestSelection = currentSelection.current;
      const selectedMemberAfterRead = latestSelection.members.some(
        (member) => member.member_id === latestSelection.memberId,
      )
        ? latestSelection.memberId
        : latestSelection.members[0]?.member_id || "";
      const selectedPlacement =
        found.find(
          (relationship) =>
            relationship.relationship_id === latestSelection.relationshipId &&
            relationship.child_member_id === selectedMemberAfterRead,
        ) ||
        (!latestSelection.explicitPlacement
          ? found.find(
              (relationship) =>
                relationship.child_member_id === selectedMemberAfterRead,
            )
          : undefined);
      if (!propertyDraftRef.current)
        selectMember(selectedMemberAfterRead, selectedPlacement, false);
      setStatusReviewed(false);
      setRenameReviewed(false);
      setDescribeReviewed(false);
      setReviewedBuild(null);
    } catch (reason) {
      if (generation !== readGeneration.current) return;
      if (
        reason instanceof ApiError &&
        (reason.kind === "authorization" ||
          [
            "METADATA_DIRECTORY_READ_AUTHORIZATION_STALE",
            "METADATA_DIRECTORY_CURSOR_REQUIRED",
            "METADATA_DIRECTORY_CURSOR_STALE",
            "UNKNOWN_OR_AMBIGUOUS_DIMENSION",
            "HIERARCHY_UNAVAILABLE",
          ].includes(reason.code))
      ) {
        setLoadedContext("");
        setHierarchyCatalogue(null);
        setHierarchyMembers([]);
        setRelationships([]);
        setRelationshipRevision(null);
      }
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read relationships",
      );
    } finally {
      if (generation === readGeneration.current) setBusy(false);
    }
  }

  async function executePropertyChange(
    functionName: RelationshipEdit,
    confirmation: string,
  ) {
    const actorId = catalog?.applicationAccess.subjectId;
    if (
      !app ||
      !actorId ||
      !selectedRelationship ||
      metadataRevision === null ||
      busy ||
      changeBlocked ||
      !snapshotCurrent ||
      !window.confirm(confirmation)
    )
      return;
    const fields = Object.fromEntries(
      relationshipEditFields[functionName].map((field) => [
        field,
        propertyValues[field],
      ]),
    ) as Partial<RelationshipProperties>;
    const args = {
      ...fields,
      relationshipId: selectedRelationship.relationship_id,
      expectedMetadataRevision: metadataRevision,
      ...(functionName === "metadata.relationship.aggregation-operator.set"
        ? {
            aggregationOperatorOverride:
              fields.aggregationOperatorOverride || null,
          }
        : {}),
    };
    setError("");
    setResult("");
    setStatusReviewed(false);
    setRenameReviewed(false);
    setDescribeReviewed(false);
    setReviewedBuild(null);
    await propertyRecovery.submit(
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
      {
        actorId,
        metadataRevision,
        relationshipId: selectedRelationship.relationship_id,
        fields,
      },
    );
  }

  async function buildHierarchy() {
    const actorId = catalog?.applicationAccess.subjectId;
    const stateToken = selectedHierarchy?.stateToken ?? null;
    if (
      !app ||
      !actorId ||
      metadataRevision === null ||
      busy ||
      changeBlocked ||
      !snapshotCurrent ||
      !buildReviewed ||
      !window.confirm(`Build the reviewed ${dimensionId} hierarchy?`)
    )
      return;
    const args = {
      dimensionId,
      ...(selectedHierarchy
        ? { hierarchyId: selectedHierarchy.hierarchyId }
        : {}),
      expectedMetadataRevision: metadataRevision,
      ...(stateToken !== null ? { expectedStateToken: stateToken } : {}),
    };
    setReviewedBuild(null);
    setError("");
    setResult("");
    await buildRecovery.submit(
      metadataActionBody(
        app,
        hierarchyBuild,
        args,
        mutationIntentKey({
          workspaceId: app.workspaceId,
          applicationId: app.applicationId,
          functionName: hierarchyBuild,
          args,
        }),
      ),
      {
        actorId,
        metadataRevision,
        hierarchyId: selectedHierarchy?.hierarchyId,
        stateToken,
      },
    );
  }

  async function previewPlacementChangeset() {
    if (
      !app ||
      busy ||
      changeBlocked ||
      !hierarchyPatchValid ||
      metadataRevision === null ||
      !selectedHierarchy?.stateToken
    )
      return;
    const args: HierarchyPatchArguments = {
      dimensionId,
      hierarchyId: selectedHierarchy.hierarchyId,
      changes: patchChanges(),
      expectedMetadataRevision: metadataRevision,
      expectedHierarchyStateToken: selectedHierarchy.stateToken,
    };
    setBusy(true);
    setError("");
    setResult("");
    try {
      const preview = await readProgram<HierarchyPatchPreview>(
        {
          workspaceId: app.workspaceId,
          applicationId: app.applicationId,
        },
        "metadata.hierarchy.relationships.preview",
        args,
      );
      setPatchPreview({ arguments: args, result: preview });
    } catch (reason) {
      setPatchPreview(null);
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to preview the hierarchy placement changeset.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function applyPlacementChangeset() {
    const actorId = catalog?.applicationAccess.subjectId;
    if (
      !app ||
      !actorId ||
      !patchPreview ||
      !snapshotCurrent ||
      busy ||
      changeBlocked
    )
      return;
    const args = {
      ...patchPreview.arguments,
      previewToken: patchPreview.result.previewToken,
    };
    const parentName =
      members.find((member) => member.member_id === parentMemberId)?.name ||
      parentMemberId;
    const childName =
      members.find((member) => member.member_id === childMemberId)?.name ||
      childMemberId;
    if (
      !window.confirm(
        `${placementAction === "move" ? "Move" : placementAction === "copy" ? "Copy" : "Create"} the reviewed placement ${childName} under ${parentName}?`,
      )
    )
      return;
    setError("");
    setResult("");
    await placementRecovery.submit(
      metadataActionBody(
        app,
        placementApply,
        args,
        mutationIntentKey({
          workspaceId: app.workspaceId,
          applicationId: app.applicationId,
          functionName: placementApply,
          args,
        }),
      ),
      {
        action: placementAction,
        actorId,
        preview: patchPreview.result,
        metadataRevision: args.expectedMetadataRevision,
      },
    );
  }

  if (!canRead) return null;

  if (mode === "members") {
    return (
      <section className="metadata-members-workspace" aria-label="Members">
        {error && (
          <div className="inline-error" role="alert">
            {error}
          </div>
        )}
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
          mode="members"
        />
      </section>
    );
  }

  return (
    <section
      className="metadata-create"
      aria-labelledby="metadata-relationships-heading"
    >
      <div className="section-heading-row">
        <div>
          <small>VERSIONED HIERARCHY</small>
          <h3 id="metadata-relationships-heading">
            {mode === "relationships"
              ? "Hierarchy placements"
              : mode === "tree"
                ? "Hierarchy tree"
                : "Relationships"}
          </h3>
          <p>
            Edit parent-child placements in the grid or tree. Both views share
            one reviewed draft and the fixed core publishes the hierarchy
            atomically.
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
      <MetadataReceiptRecovery
        object="placement"
        recovery={placementRecovery}
        onClose={() => {
          if (placementRecovery.closeRecovery()) {
            setPatchPreview(null);
            void readRelationships();
          }
        }}
      />
      <MetadataReceiptRecovery
        object="relationship"
        recovery={propertyRecovery}
        onClose={() => {
          if (propertyRecovery.closeRecovery()) {
            setRelationshipRevision(null);
            void refreshRelationshipWorkspace().catch(() =>
              setError(
                "Refresh the model before reviewing another relationship change.",
              ),
            );
          }
        }}
      />
      <MetadataReceiptRecovery
        object="hierarchy build"
        recovery={buildRecovery}
        onClose={() => {
          if (buildRecovery.closeRecovery())
            refreshAfterCommit(
              "Refresh the model before reviewing another hierarchy build.",
            );
        }}
      />
      {relationshipRevision !== null && (
        <p role="status">
          {relationships.length} current relationships
          {!snapshotCurrent && " · refresh the dimension/member snapshot"}
        </p>
      )}
      {metadataRevision !== null && draftRevision !== metadataRevision && (
        <div className="inline-error" role="status">
          <p>
            Metadata changed since this draft began. Your entries are retained;
            review them against the current model before saving.
          </p>
          <button
            type="button"
            onClick={() => {
              setDraftRevision(metadataRevision);
              setStatusReviewed(false);
              setRenameReviewed(false);
              setDescribeReviewed(false);
              setReviewedBuild(null);
            }}
          >
            Review against current metadata
          </button>
        </div>
      )}
      {canReadHierarchies && (
        <>
          <label>
            Hierarchy
            <select
              aria-label="Hierarchy"
              value={hierarchySelection}
              disabled={busy || !hierarchies.length}
              onChange={(event) => {
                const value = event.target.value;
                const change = () => {
                  if (onHierarchyIdChange) onHierarchyIdChange(value);
                  else setHierarchySelection(value);
                };
                if (onRequestTransition) onRequestTransition(change);
                else change();
              }}
            >
              <option value="">
                Default hierarchy
                {hierarchies.find((row) => row.isDefault)
                  ? ` · ${hierarchies.find((row) => row.isDefault)?.name}`
                  : ""}
              </option>
              {hierarchySelection && !selectedHierarchy && (
                <option value={hierarchySelection}>
                  Unavailable hierarchy · {hierarchySelection}
                </option>
              )}
              {hierarchies.map((row) => (
                <option key={row.hierarchyId} value={row.hierarchyId}>
                  {row.name}
                  {row.status === "Inactive" ? " (inactive)" : ""}
                </option>
              ))}
            </select>
          </label>
          {selectedHierarchy && (
            <p role="status">
              {selectedHierarchy.membershipMode === "explicit"
                ? `${visibleHierarchyMembers.filter((row) => row.status === "Active").length} declared members, including isolated roots`
                : "All active dimension members"}{" "}
              ·{" "}
              {selectedHierarchy.current &&
              selectedHierarchy.builtMetadataRevision === metadataRevision
                ? "hierarchy build is current"
                : "hierarchy build is not current"}
            </p>
          )}
          <MetadataHierarchyEditor
            key={`${hierarchyContext}:${selectedHierarchy?.hierarchyId || "none"}`}
            app={app}
            catalog={catalog}
            dimensionId={dimensionId}
            metadataRevision={metadataRevision}
            hierarchy={selectedHierarchy}
            hierarchies={hierarchies}
            members={members}
            memberships={visibleHierarchyMembers}
            current={snapshotCurrent && !changeBlocked}
            onChanged={refreshRelationshipWorkspace}
          />
        </>
      )}
      {showViewToggle && (mode === "all" || mode === "relationships") && (
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
      )}
      {editorMode === "grid" && members.length > 0 && (
        <MetadataMemberGrid
          app={app}
          catalog={catalog}
          dimensionId={dimensionId}
          members={mode === "relationships" ? activeMembers : members}
          relationships={relationships}
          metadataRevision={metadataRevision}
          selectedMemberId={effectiveSelectedMemberId}
          onSelectedMember={selectMember}
          onChanged={onChanged}
          onEditSecurityString={onEditMemberSecurityString}
          securityBusy={securityBusy}
          creationDisabled={creationDisabled}
          mode={mode === "tree" ? "relationships" : mode}
        />
      )}
      {editorMode === "board" && (
        <div className="hierarchy-board" aria-label="Metadata Tree View">
          <p>
            Drag an unplaced member onto a parent to create a placement. Drag an
            existing placement onto another parent to prepare an atomic move.
            Nothing is saved until the exact changeset is previewed and applied.
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
                    onDragStart={() =>
                      setDraggedPlacement({ memberId: member.member_id })
                    }
                    onDragEnd={() => setDraggedPlacement(null)}
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
            Draft:{" "}
            {placementAction === "move"
              ? "Move"
              : placementAction === "copy"
                ? "Copy"
                : "Create"}{" "}
            {members.find((member) => member.member_id === childMemberId)
              ?.name ||
              childMemberId ||
              "child"}{" "}
            under{" "}
            {members.find((member) => member.member_id === parentMemberId)
              ?.name ||
              parentMemberId ||
              "parent"}
          </p>
        </div>
      )}
      {routedRelationshipId !== undefined &&
        !selectedRelationship &&
        loadedContext === relationshipContext &&
        relationshipRevision !== null &&
        !busy && (
          <p role="status">
            The selected placement is unavailable for this member and hierarchy.
            Choose a current placement.
          </p>
        )}
      {selectedMember && (
        <aside
          className="metadata-property-pane"
          aria-label="Selected metadata properties"
        >
          {mode === "all" && (
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
          )}
          <div>
            <small>PLACEMENT PROPERTIES</small>
            {selectedRelationship ? (
              <>
                <h4>{placementLabel(selectedRelationship)}</h4>
                <dl>
                  <dt>Name</dt>
                  <dd>
                    {selectedRelationship.name ||
                      placementLabel(selectedRelationship)}
                  </dd>
                  <dt>Parent</dt>
                  <dd>
                    {members.find(
                      (member) =>
                        member.member_id ===
                        selectedRelationship.parent_member_id,
                    )?.name || selectedRelationship.parent_member_id}
                  </dd>
                  <dt>Child</dt>
                  <dd>
                    {members.find(
                      (member) =>
                        member.member_id ===
                        selectedRelationship.child_member_id,
                    )?.name || selectedRelationship.child_member_id}
                  </dd>
                  <dt>Status</dt>
                  <dd>{selectedRelationship.status}</dd>
                  <dt>Hierarchy</dt>
                  <dd>{selectedHierarchy?.name || "Default"}</dd>
                  <dt>Aggregation operator</dt>
                  <dd>
                    {selectedRelationship.aggregation_operator_override ||
                      "Inherit member operator"}
                  </dd>
                  <dt>Short description</dt>
                  <dd>{selectedRelationship.short_description || "—"}</dd>
                  <dt>Semantic description</dt>
                  <dd>{baseProperties.detailedDescription || "—"}</dd>
                  {selectedRelationship.semantic_description &&
                    selectedRelationship.semantic_description !==
                      baseProperties.detailedDescription && (
                      <>
                        <dt>Legacy semantic description</dt>
                        <dd>{selectedRelationship.semantic_description}</dd>
                      </>
                    )}
                </dl>
                {canPatchRelationships &&
                  selectedRelationship.status === "Active" && (
                    <div className="reviewed-inline-action">
                      <button
                        type="button"
                        disabled={busy || changeBlocked}
                        onClick={() => {
                          setPlacementAction("move");
                          setSourceRelationshipId(
                            selectedRelationship.relationship_id,
                          );
                          setChildMemberId(
                            selectedRelationship.child_member_id,
                          );
                          setRelationshipId("");
                          setPatchPreview(null);
                          setRelationshipMemberChooser("parent");
                        }}
                      >
                        Move placement…
                      </button>
                      <button
                        type="button"
                        disabled={busy || changeBlocked}
                        onClick={() => {
                          setPlacementAction("copy");
                          setSourceRelationshipId(
                            selectedRelationship.relationship_id,
                          );
                          setChildMemberId(
                            selectedRelationship.child_member_id,
                          );
                          setRelationshipId("");
                          setPatchPreview(null);
                          setRelationshipMemberChooser("parent");
                        }}
                      >
                        Copy placement…
                      </button>
                    </div>
                  )}
              </>
            ) : (
              <p>This member has no selected parent-child placement.</p>
            )}
          </div>
        </aside>
      )}
      {selectedRelationship && (canRename || canDescribe || canSetOperator) && (
        <fieldset
          className="metadata-placement-editor"
          disabled={changeBlocked}
        >
          <legend>Selected placement editor</legend>
          {canSetOperator && (
            <div className="maintenance-action">
              <label>
                Placement aggregation operator
                <select
                  value={relationshipOperator}
                  onChange={(event) => {
                    editProperty(
                      "aggregationOperatorOverride",
                      event.target.value,
                    );
                  }}
                >
                  <option value="">Inherit member operator</option>
                  {[
                    "Add",
                    "Subtract",
                    "Ignore",
                    "NeverAggregate",
                    "Formula",
                  ].map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </select>
              </label>
              <button
                disabled={
                  busy ||
                  changeBlocked ||
                  !snapshotCurrent ||
                  relationshipOperator ===
                    (selectedRelationship.aggregation_operator_override || "")
                }
                onClick={() =>
                  void executePropertyChange(
                    "metadata.relationship.aggregation-operator.set",
                    `Save the aggregation operator for ${placementLabel(selectedRelationship)}?`,
                  )
                }
              >
                Save placement operator
              </button>
            </div>
          )}

          {canRename && (
            <div className="maintenance-action">
              <label>
                Relationship display name
                <input
                  value={relationshipName}
                  maxLength={200}
                  onChange={(event) => {
                    editProperty("name", event.target.value);
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
                  I reviewed this exact relationship name against the current
                  model.
                </label>
                <button
                  disabled={
                    busy || changeBlocked || !renameReviewed || !renameValid
                  }
                  onClick={() =>
                    void executePropertyChange(
                      "metadata.relationship.rename",
                      `Rename ${placementLabel(selectedRelationship)} to ${relationshipName}?`,
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
                    editProperty("shortDescription", event.target.value);
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
                    editProperty("detailedDescription", event.target.value);
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
                  I reviewed these exact relationship descriptions against the
                  current model.
                </label>
                <button
                  disabled={
                    busy || changeBlocked || !describeReviewed || !describeValid
                  }
                  onClick={() =>
                    void executePropertyChange(
                      "metadata.relationship.describe",
                      `Save reviewed descriptions for ${placementLabel(selectedRelationship)}?`,
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
      {canPatchRelationships && hierarchyActive && (
        <fieldset
          className="metadata-placement-changeset"
          disabled={changeBlocked}
        >
          <legend>Placement changeset</legend>
          <div className="react-grid-scroll">
            <table className="react-cube-grid metadata-inline-grid">
              <thead>
                <tr>
                  <th>Change</th>
                  <th>Parent member</th>
                  <th>Child member</th>
                  <th>Review</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>
                    {placementAction === "move"
                      ? "Move placement"
                      : placementAction === "copy"
                        ? "Copy placement"
                        : "Create placement"}
                  </td>
                  <td>
                    <button
                      type="button"
                      className="metadata-member-picker"
                      aria-label="Parent member"
                      disabled={!app || !catalog || metadataRevision === null}
                      onClick={() => setRelationshipMemberChooser("parent")}
                    >
                      {activeMembers.find(
                        (member) => member.member_id === parentMemberId,
                      )?.name || "Choose parent"}
                      <span aria-hidden="true">▾</span>
                    </button>
                  </td>
                  <td>
                    <button
                      type="button"
                      className="metadata-member-picker"
                      aria-label="Child member"
                      disabled={
                        !app ||
                        !catalog ||
                        metadataRevision === null ||
                        placementAction !== "create"
                      }
                      onClick={() => setRelationshipMemberChooser("child")}
                    >
                      {activeMembers.find(
                        (member) => member.member_id === childMemberId,
                      )?.name || "Choose child"}
                      <span aria-hidden="true">▾</span>
                    </button>
                  </td>
                  <td>
                    <button
                      type="button"
                      disabled={busy || !hierarchyPatchValid}
                      onClick={() => void previewPlacementChangeset()}
                    >
                      Preview exact changes
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          {patchPreview && !placementRecovery.pending && (
            <div className="metadata-changeset-review" role="status">
              <h4>Exact server preview</h4>
              <table className="react-cube-grid">
                <thead>
                  <tr>
                    <th>Before</th>
                    <th>After</th>
                    <th>Effect</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td>
                      {sourceRelationship
                        ? `${placementLabel(sourceRelationship)}${placementAction === "copy" ? " (retained)" : ""}`
                        : "No placement"}
                    </td>
                    <td>
                      {members.find(
                        (member) => member.member_id === childMemberId,
                      )?.name || childMemberId}{" "}
                      under{" "}
                      {members.find(
                        (member) => member.member_id === parentMemberId,
                      )?.name || parentMemberId}
                    </td>
                    <td>
                      {patchPreview.result.edgeCount} active placements ·{" "}
                      {patchPreview.result.affectedPathCount} affected hierarchy
                      paths
                    </td>
                  </tr>
                </tbody>
              </table>
              <button
                type="button"
                className="primary"
                disabled={
                  busy ||
                  !snapshotCurrent ||
                  !catalog?.applicationAccess.subjectId
                }
                onClick={() => void applyPlacementChangeset()}
              >
                Apply reviewed changeset
              </button>
            </div>
          )}
        </fieldset>
      )}
      {relationshipMemberChooser &&
        app &&
        catalog &&
        metadataRevision !== null && (
          <MemberSelectionDialog
            app={app}
            catalog={catalog}
            request={{
              dimensionId,
              dimensionName: dimensionId,
              metadataRevision,
              hierarchyId: selectedHierarchy?.hierarchyId,
              cardinality: { kind: "exactly-one" },
              capability: {
                allowExplicitMembers: true,
                allowHierarchySelector: false,
                allowNamedMemberList: false,
                allowAttributeSelector: false,
                allowInlineExpression: false,
                allowExclusion: false,
                orderMatters: false,
              },
              initial: (
                relationshipMemberChooser === "parent"
                  ? parentMemberId
                  : childMemberId
              )
                ? {
                    kind: "member",
                    memberId:
                      relationshipMemberChooser === "parent"
                        ? parentMemberId
                        : childMemberId,
                  }
                : null,
            }}
            members={activeMembers}
            onCancel={() => {
              if (!relationshipId) {
                setPlacementAction("create");
                setSourceRelationshipId("");
              }
              setRelationshipMemberChooser(null);
            }}
            onApply={(result) => {
              if (result.include.kind !== "member") return;
              if (!relationshipId) setRelationshipId(newHiddenRelationshipId());
              if (relationshipMemberChooser === "parent")
                setParentMemberId(result.include.memberId);
              else setChildMemberId(result.include.memberId);
              invalidateCreate();
              setRelationshipMemberChooser(null);
            }}
          />
        )}
      {canSetStatus && relationships.length > 0 && (
        <fieldset disabled={changeBlocked}>
          <legend>Relationship status</legend>
          <div className="metadata-create-fields">
            <label>
              Relationship
              <select
                value={selectedRelationship?.relationship_id || ""}
                onChange={(event) => {
                  const selected = relationships.find(
                    (item) => item.relationship_id === event.target.value,
                  );
                  if (selected)
                    selectMember(selected.child_member_id, selected);
                }}
              >
                {!selectedRelationship && (
                  <option value="">
                    {routedRelationshipId !== undefined
                      ? "Unavailable placement"
                      : "Choose a placement"}
                  </option>
                )}
                {relationships.map((relationship) => (
                  <option
                    key={relationship.relationship_id}
                    value={relationship.relationship_id}
                  >
                    {placementLabel(relationship)}
                  </option>
                ))}
              </select>
            </label>
            <label>
              New status
              <select
                value={selectedStatus}
                onChange={(event) => {
                  editProperty(
                    "status",
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
              I reviewed this exact relationship status against the current
              model.
            </label>
            <button
              disabled={
                busy || changeBlocked || !statusReviewed || !statusValid
              }
              onClick={() =>
                void executePropertyChange(
                  "metadata.relationship.status.set",
                  `Set ${selectedRelationship ? placementLabel(selectedRelationship) : "this placement"} to ${selectedStatus}?`,
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
        onChanged={refreshRelationshipWorkspace}
      />
      {canBuild && hierarchyActive && relationshipRevision !== null && (
        <div className="reviewed-inline-action">
          <label className="review-check">
            <input
              type="checkbox"
              checked={buildReviewed}
              disabled={!snapshotCurrent || changeBlocked}
              onChange={(event) =>
                setReviewedBuild(event.target.checked ? buildPin : null)
              }
            />
            I reviewed this dimension and relationship snapshot for hierarchy
            build.
          </label>
          <button
            disabled={
              busy || changeBlocked || !buildReviewed || !snapshotCurrent
            }
            onClick={() => void buildHierarchy()}
          >
            Build hierarchy
          </button>
        </div>
      )}
      {result && (
        <p role="status" tabIndex={-1} ref={resultStatus}>
          {result}
        </p>
      )}
      <p className="authority-note">
        Cycle checks, dependency guards, closure construction and publication
        remain fixed-core responsibilities.
      </p>
    </section>
  );
}
