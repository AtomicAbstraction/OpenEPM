import { useEffect, useMemo, useRef, useState } from "react";
import { readProgram, requestAdmittedEffect } from "./api";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { usePreservedDraft } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { metadataCreateBody, validMetadataText } from "./MetadataCreate";
import {
  collectCapabilityAttributeDefinitions,
  collectCapabilityMembers,
  type MetadataMember,
} from "./metadata-data";
import { MemberSelectionDialog } from "./member-selection/MemberSelectionDialog";
import {
  coordinateInMetadataGridRange,
  metadataClipboardDraft,
  metadataGridRange,
  parseMetadataClipboard,
  type MetadataGridCoordinate,
} from "./metadata-grid-clipboard";

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

type MemberCellDraft = AttributeEdit & {
  scope: "Member";
  draft: string;
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

function attributeValuesReplaceBody(
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
      function: "metadata.attribute-values.replace",
      arguments: args,
    },
  };
}

function memberCellKey(objectId: string, attributeId: string) {
  return `${objectId}\u0000${attributeId}`;
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

function referenceDimensionId(definition: AttributeDefinition) {
  const value = definition.validation_constraints.referenceDimensionId;
  return typeof value === "string" && value.trim() ? value : null;
}

function decimalParts(value: string) {
  if (!/^[+-]?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/.test(value)) return null;
  const negative = value.startsWith("-");
  const unsigned = value.replace(/^[+-]/, "");
  const [rawInteger, rawFraction = ""] = unsigned.split(".");
  const integer = rawInteger.replace(/^0+(?=\d)/, "");
  const fraction = rawFraction.replace(/0+$/, "");
  const zero = integer === "0" && fraction === "";
  return { negative: zero ? false : negative, integer, fraction };
}

export function compareExactDecimals(left: string, right: string) {
  const leftParts = decimalParts(left);
  const rightParts = decimalParts(right);
  if (!leftParts || !rightParts)
    throw new Error("Exact decimal comparison requires canonical decimals.");
  if (leftParts.negative !== rightParts.negative)
    return leftParts.negative ? -1 : 1;
  const direction = leftParts.negative ? -1 : 1;
  if (leftParts.integer.length !== rightParts.integer.length)
    return leftParts.integer.length < rightParts.integer.length
      ? -direction
      : direction;
  const integerOrder = leftParts.integer.localeCompare(rightParts.integer);
  if (integerOrder) return integerOrder < 0 ? -direction : direction;
  const width = Math.max(leftParts.fraction.length, rightParts.fraction.length);
  const leftFraction = leftParts.fraction.padEnd(width, "0");
  const rightFraction = rightParts.fraction.padEnd(width, "0");
  const fractionOrder = leftFraction.localeCompare(rightFraction);
  return fractionOrder === 0 ? 0 : fractionOrder < 0 ? -direction : direction;
}

export function attributeDraftValidationError(
  definition: AttributeDefinition,
  draft: string,
) {
  if (draft === "") return null;
  const constraints = definition.validation_constraints;
  if (definition.value_type === "Text") {
    const maximumLength = constraints.maximumLength;
    if (
      typeof maximumLength === "number" &&
      Number.isInteger(maximumLength) &&
      draft.length > maximumLength
    )
      return `${definition.display_name} supports at most ${maximumLength} characters.`;
    const allowedValues = constraints.allowedValues;
    if (
      Array.isArray(allowedValues) &&
      allowedValues.every((value) => typeof value === "string") &&
      !allowedValues.includes(draft)
    )
      return `Choose an allowed ${definition.display_name} value.`;
  }
  if (definition.value_type === "Decimal") {
    if (!decimalParts(draft))
      return "Enter an exact decimal without exponent notation.";
    const minimum = constraints.minimum;
    if (typeof minimum === "string" && compareExactDecimals(draft, minimum) < 0)
      return `${definition.display_name} must be at least ${minimum}.`;
    const maximum = constraints.maximum;
    if (typeof maximum === "string" && compareExactDecimals(draft, maximum) > 0)
      return `${definition.display_name} must be at most ${maximum}.`;
  }
  return null;
}

function attributeDraftChanged(
  definition: AttributeDefinition,
  sourceValue: unknown,
  draft: string,
) {
  const next = typedDraft(draft, definition.value_type);
  if (
    definition.value_type === "Decimal" &&
    typeof sourceValue === "string" &&
    typeof next === "string" &&
    decimalParts(sourceValue) &&
    decimalParts(next)
  )
    return compareExactDecimals(sourceValue, next) !== 0;
  return JSON.stringify(next) !== JSON.stringify(sourceValue ?? null);
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
  creationDisabled = false,
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
  creationDisabled?: boolean;
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
  const [memberDrafts, setMemberDrafts] = useState<
    Record<string, MemberCellDraft>
  >({});
  const [rangeAnchor, setRangeAnchor] = useState<MetadataGridCoordinate | null>(
    null,
  );
  const [rangeFocus, setRangeFocus] = useState<MetadataGridCoordinate | null>(
    null,
  );
  const [batchReviewed, setBatchReviewed] = useState(false);
  const [pendingReplaceIntent, setPendingReplaceIntent] = useState<{
    signature: string;
    key: string;
  } | null>(null);
  const [pendingIntent, setPendingIntent] = useState<{
    signature: string;
    key: string;
  } | null>(null);
  const [draft, setDraft] = useState("");
  const [reviewed, setReviewed] = useState(false);
  const [reading, setReading] = useState(false);
  const [referenceReading, setReferenceReading] = useState(false);
  const [referenceMembers, setReferenceMembers] = useState<
    Record<string, MetadataMember[]>
  >({});
  const [referenceChooserOpen, setReferenceChooserOpen] = useState(false);
  const [saving, setSaving] = useState(false);
  const busy = reading || referenceReading || saving;
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
  const [editReturnNotice, setEditReturnNotice] = useState<{
    scope: string;
    text: string;
  } | null>(null);
  const [creatingMember, setCreatingMember] = useState(false);
  const [newMemberId, setNewMemberId] = useState("");
  const [newMemberName, setNewMemberName] = useState("");
  const [newMemberShort, setNewMemberShort] = useState("");
  const [newMemberSemantic, setNewMemberSemantic] = useState("");
  const [newMemberReviewed, setNewMemberReviewed] = useState(false);
  const [newMemberDraftRevision, setNewMemberDraftRevision] =
    useState(metadataRevision);
  const readGeneration = useRef(0);
  const referenceReadGeneration = useRef(0);
  const editOrigin = useRef<HTMLElement | null>(null);
  const returnFocusAfterEdit = useRef<"save" | "cancel" | null>(null);
  const reviewControl = useRef<HTMLInputElement | null>(null);
  const batchReviewControl = useRef<HTMLInputElement | null>(null);
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
  const canReplaceMemberValues = Boolean(
    catalog?.functions["metadata.attribute-values.replace"],
  );
  const canReadReferenceMembers = Boolean(
    catalog?.functions["metadata.member.list"],
  );
  const canCreateMember = Boolean(catalog?.functions["metadata.member.create"]);
  const newMemberDirty = Boolean(
    newMemberId || newMemberName || newMemberShort || newMemberSemantic,
  );
  const newMemberCurrent = newMemberDraftRevision === metadataRevision;
  const newMemberValid = Boolean(
    metadataRevision !== null &&
      newMemberCurrent &&
      validMetadataText(newMemberId) &&
      validMetadataText(newMemberName) &&
      newMemberShort.length <= 500 &&
      newMemberSemantic.length <= 10000 &&
      !members.some((member) => member.member_id === newMemberId),
  );
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
  const visibleReferenceDimensions = Array.from(
    new Set(
      [...selectedDefinitions, ...selectedRelationshipDefinitions].flatMap(
        (definition) => {
          if (definition.value_type !== "MemberReference") return [];
          const referenceDimension = referenceDimensionId(definition);
          return referenceDimension ? [referenceDimension] : [];
        },
      ),
    ),
  ).sort();
  const visibleReferenceDimensionKey =
    visibleReferenceDimensions.join("\u0000");
  const memberNameById = new Map(
    members.map((member) => [member.member_id, member.name]),
  );
  const relationshipLabel = (relationship: Relationship) =>
    relationship.name ||
    `${memberNameById.get(relationship.child_member_id) || relationship.child_member_id} under ${memberNameById.get(relationship.parent_member_id) || relationship.parent_member_id}`;
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
            relationship.name || "",
            relationship.status,
            relationship.parent_member_id,
            relationship.child_member_id,
            memberNameById.get(relationship.parent_member_id) || "",
            memberNameById.get(relationship.child_member_id) || "",
          ].some((value) => value.toLowerCase().includes(search))),
    );
  }, [relationships, relationshipSearch, relationshipStatus, members]);
  const windowedMembers = filteredMembers.slice(
    windowStart,
    windowStart + ROW_WINDOW,
  );
  const windowedRelationships = filteredRelationships.slice(
    relationshipWindowStart,
    relationshipWindowStart + ROW_WINDOW,
  );
  const selectedRange =
    rangeAnchor && rangeFocus
      ? metadataGridRange(rangeAnchor, rangeFocus)
      : null;
  const memberDraftList = Object.values(memberDrafts);
  const memberDraftValidationErrors = memberDraftList.flatMap((cell) => {
    const typedError = attributeDraftValidationError(
      cell.definition,
      cell.draft,
    );
    if (typedError) return [`${cell.objectName} · ${typedError}`];
    if (cell.definition.value_type !== "MemberReference" || !cell.draft)
      return [];
    const referenceDimension = referenceDimensionId(cell.definition);
    const available =
      referenceDimension === dimensionId
        ? members
        : referenceMembers[referenceDimension || ""] || [];
    return available.some(
      (member) => member.status === "Active" && member.member_id === cell.draft,
    )
      ? []
      : [`${cell.objectName} · Choose a current authorized referenced member.`];
  });
  const staleMemberDrafts = memberDraftList.some((cell) => {
    const object = members.find((member) => member.member_id === cell.objectId);
    const definition = activeDefinitions.find(
      (candidate) => candidate.attribute_id === cell.attributeId,
    );
    return (
      cell.metadataRevision === null ||
      cell.metadataRevision !== metadataRevision ||
      cell.metadataRevision !== definitionRevision ||
      cell.securityRevision !== (catalog?.revisions.security ?? null) ||
      object?.status !== "Active" ||
      !definition ||
      definition.state_token !== cell.definition.state_token
    );
  });
  const memberBatchSupported = Boolean(
    canReplaceMemberValues && members.length <= 1_000,
  );
  const editingCellVisible = Boolean(
    editing &&
      (editing.scope === "Member"
        ? mode !== "relationships" &&
          windowedMembers.some(
            (member) => member.member_id === editing.objectId,
          ) &&
          visibleAttributes.includes(editing.attributeId)
        : mode !== "members" &&
          windowedRelationships.some(
            (relationship) => relationship.relationship_id === editing.objectId,
          ) &&
          visibleRelationshipAttributes.includes(editing.attributeId)),
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
      attributeDraftChanged(editing.definition, editing.sourceValue, draft),
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
  const editValidationError = (() => {
    if (!editing) return null;
    const typedError = attributeDraftValidationError(editing.definition, draft);
    if (typedError) return typedError;
    if (editing.definition.value_type !== "MemberReference" || !draft)
      return null;
    const referenceDimension = referenceDimensionId(editing.definition);
    const available =
      referenceDimension === dimensionId
        ? members
        : referenceMembers[referenceDimension || ""] || [];
    return available.some(
      (member) => member.status === "Active" && member.member_id === draft,
    )
      ? null
      : "Choose a current authorized referenced member.";
  })();
  usePreservedDraft(
    app?.workspaceId || "none",
    app?.applicationId || "none",
    `metadata-member-grid:${dimensionId}:${mode}`,
    "Unsaved metadata attribute value",
    Boolean(memberDraftList.length || (editing && editChanged)),
    {
      editing,
      draft,
      pendingIntent,
      memberDrafts,
      pendingReplaceIntent,
    },
    (saved) => {
      setEditing(saved.editing);
      setDraft(saved.draft);
      setPendingIntent(saved.pendingIntent);
      setMemberDrafts(saved.memberDrafts || {});
      setPendingReplaceIntent(saved.pendingReplaceIntent || null);
      setReviewed(false);
      setBatchReviewed(false);
    },
  );
  usePreservedDraft(
    app?.workspaceId || "none",
    app?.applicationId || "none",
    `metadata-member-create:${dimensionId}`,
    "Unsaved member creation",
    creatingMember && newMemberDirty,
    {
      creatingMember,
      newMemberId,
      newMemberName,
      newMemberShort,
      newMemberSemantic,
      newMemberDraftRevision,
    },
    (saved) => {
      setCreatingMember(saved.creatingMember);
      setNewMemberId(saved.newMemberId);
      setNewMemberName(saved.newMemberName);
      setNewMemberShort(saved.newMemberShort);
      setNewMemberSemantic(saved.newMemberSemantic);
      setNewMemberDraftRevision(saved.newMemberDraftRevision);
      setNewMemberReviewed(false);
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
    setMemberDrafts({});
    setRangeAnchor(null);
    setRangeFocus(null);
    setBatchReviewed(false);
    setPendingReplaceIntent(null);
    setDraft("");
    setReferenceMembers({});
    setReferenceChooserOpen(false);
    setReferenceReading(false);
    setPendingIntent(null);
    setReviewed(false);
    setSaving(false);
    setError("");
    setResult("");
    editOrigin.current = null;
    returnFocusAfterEdit.current = null;
    setEditReturnNotice(null);
    referenceReadGeneration.current += 1;
  }, [app?.workspaceId, app?.applicationId, dimensionId, mode]);

  useEffect(() => {
    if (!editing && returnFocusAfterEdit.current) {
      const reason = returnFocusAfterEdit.current;
      returnFocusAfterEdit.current = null;
      const origin = editOrigin.current;
      origin?.focus();
      if (reason === "cancel" && origin && origin === document.activeElement) {
        const label = origin.getAttribute("aria-label");
        if (label)
          setEditReturnNotice({
            scope: scopeKey,
            text: `Edit cancelled. ${label}`,
          });
      }
    }
  }, [editing, scopeKey]);

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
    setBatchReviewed(false);
  }, [catalog?.revisions.security, canWrite]);

  useEffect(() => {
    const generation = ++referenceReadGeneration.current;
    const missing = visibleReferenceDimensions.filter(
      (referenceDimension) =>
        referenceDimension !== dimensionId &&
        !referenceMembers[referenceDimension],
    );
    if (
      !app ||
      metadataRevision === null ||
      !canReadReferenceMembers ||
      missing.length === 0
    ) {
      setReferenceReading(false);
      return;
    }
    const controller = new AbortController();
    setReferenceReading(true);
    void Promise.all(
      missing.map(async (referenceDimension) => {
        const result = await collectCapabilityMembers(
          referenceDimension,
          (arguments_) =>
            readProgram(
              app,
              "metadata.member.list",
              arguments_,
              controller.signal,
            ),
          metadataRevision,
        );
        return [
          referenceDimension,
          result.rows.filter((member) => member.status === "Active"),
        ] as const;
      }),
    )
      .then((loaded) => {
        if (
          controller.signal.aborted ||
          generation !== referenceReadGeneration.current
        )
          return;
        setReferenceMembers((current) => ({
          ...current,
          ...Object.fromEntries(loaded),
        }));
      })
      .catch((reason: unknown) => {
        if (
          controller.signal.aborted ||
          generation !== referenceReadGeneration.current
        )
          return;
        setError(
          reason instanceof Error
            ? reason.message
            : "Unable to read referenced members.",
        );
      })
      .finally(() => {
        if (
          !controller.signal.aborted &&
          generation === referenceReadGeneration.current
        )
          setReferenceReading(false);
      });
    return () => controller.abort();
  }, [
    app?.workspaceId,
    app?.applicationId,
    metadataRevision,
    catalog?.revisions.security,
    canReadReferenceMembers,
    visibleReferenceDimensionKey,
    referenceMembers,
    dimensionId,
  ]);

  useEffect(() => {
    setNewMemberReviewed(false);
    if (!newMemberDirty) setNewMemberDraftRevision(metadataRevision);
  }, [metadataRevision]);

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
        const page =
          await collectCapabilityAttributeDefinitions<AttributeDefinition>(
            (continuation) =>
              readProgram(scope, "metadata.attribute-definition.list", {
                scope: definitionScope,
                dimensionId,
                status: "Active",
                limit: 200,
                ...continuation,
              }),
            { maximumRows: 200 },
          );
        return { found: page.rows, revision: page.finalPage.metadataRevision };
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
      setDefinitions([]);
      setRelationshipDefinitions([]);
      setDefinitionRevision(null);
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read metadata attribute definitions",
      );
    } finally {
      if (generation === readGeneration.current) setReading(false);
    }
  }

  function canEditAttribute(definition: AttributeDefinition) {
    return Boolean(
      canWrite &&
        (definition.value_type !== "MemberReference" ||
          (canReadReferenceMembers && referenceDimensionId(definition))),
    );
  }

  function beginEdit(
    scope: "Member" | "Relationship",
    object: Member | Relationship,
    definition: AttributeDefinition,
    origin?: HTMLElement,
    coordinate?: MetadataGridCoordinate,
  ) {
    if (busy) return;
    if (
      definition.value_type === "MemberReference" &&
      (!canReadReferenceMembers || !referenceDimensionId(definition))
    )
      return;
    const objectId =
      scope === "Member"
        ? (object as Member).member_id
        : (object as Relationship).relationship_id;
    if (scope === "Member" && (object as Member).status !== "Active") {
      setError("Only active members can be edited.");
      return;
    }
    if (scope === "Relationship" && memberDraftList.length) {
      setError(
        "Apply or discard the pending member changeset before editing relationship attributes.",
      );
      return;
    }
    if (
      editing?.scope === scope &&
      editing.objectId === objectId &&
      editing.attributeId === definition.attribute_id
    )
      return;
    if (editing && editChanged && editing.scope === "Relationship") {
      if (
        !window.confirm(
          "Discard the unsaved attribute value and edit this cell?",
        )
      )
        return;
    } else if (editing && editChanged && !memberBatchSupported) {
      if (
        !window.confirm(
          "Discard the unsaved attribute value and edit this cell?",
        )
      )
        return;
    }
    editOrigin.current = origin || null;
    setEditReturnNotice(null);
    const value = object.custom_values?.[definition.attribute_id];
    const staged =
      scope === "Member"
        ? memberDrafts[memberCellKey(objectId, definition.attribute_id)]
        : undefined;
    setEditing({
      scope,
      objectId,
      attributeId: definition.attribute_id,
      objectName: object.name || (object as Relationship).relationship_id,
      definition,
      sourceValue: staged?.sourceValue ?? value ?? null,
      metadataRevision,
      securityRevision: catalog?.revisions.security ?? null,
    });
    setDraft(
      staged?.draft ??
        (definition.value_type === "Boolean"
          ? value === true
            ? "true"
            : value === false
              ? "false"
              : ""
          : value === undefined || value === null
            ? ""
            : String(value)),
    );
    if (scope === "Member" && coordinate) {
      setRangeAnchor(coordinate);
      setRangeFocus(coordinate);
    }
    setReviewed(false);
    setReferenceChooserOpen(false);
    setPendingIntent(null);
    setResult("");
    setError("");
  }

  function changeActiveDraft(value: string) {
    setDraft(value);
    setReviewed(false);
    setBatchReviewed(false);
    setResult("");
    if (!editing || editing.scope !== "Member" || !memberBatchSupported) return;
    const key = memberCellKey(editing.objectId, editing.attributeId);
    setMemberDrafts((current) => {
      if (
        !attributeDraftChanged(editing.definition, editing.sourceValue, value)
      ) {
        const next = { ...current };
        delete next[key];
        return next;
      }
      return {
        ...current,
        [key]: { ...editing, scope: "Member", draft: value },
      };
    });
    setPendingReplaceIntent(null);
  }

  function closeActiveMemberEditor() {
    if (editing?.scope !== "Member") return;
    setReferenceChooserOpen(false);
    setEditing(null);
    setReviewed(false);
  }

  function cancelEdit() {
    if (busy) return;
    if (
      editChanged &&
      !window.confirm("Discard the unsaved attribute value in this cell?")
    )
      return;
    if (editing?.scope === "Member" && memberBatchSupported) {
      const key = memberCellKey(editing.objectId, editing.attributeId);
      setMemberDrafts((current) => {
        const next = { ...current };
        delete next[key];
        return next;
      });
      setBatchReviewed(false);
      setPendingReplaceIntent(null);
    }
    returnFocusAfterEdit.current = "cancel";
    setReferenceChooserOpen(false);
    setEditing(null);
    setPendingIntent(null);
    setReviewed(false);
  }

  function inlineValueEditor() {
    if (!editing) return null;
    if (editing.definition.value_type === "MemberReference") {
      const referenceDimension = referenceDimensionId(editing.definition);
      const available =
        referenceDimension === dimensionId
          ? members.filter((member) => member.status === "Active")
          : referenceMembers[referenceDimension || ""] || [];
      const selected = available.find((member) => member.member_id === draft);
      return (
        <div className="metadata-inline-reference-editor">
          <button
            type="button"
            autoFocus
            disabled={
              busy || !canWrite || !referenceDimension || !available.length
            }
            aria-label="Choose referenced member"
            onClick={(event) => {
              event.stopPropagation();
              setReferenceChooserOpen(true);
            }}
            onKeyDown={(event) => {
              event.stopPropagation();
              if (event.key === "Escape") {
                event.preventDefault();
                cancelEdit();
              }
            }}
          >
            {selected?.name ||
              (draft ? "Referenced member unavailable" : "Choose member")}
          </button>
          {draft && (
            <button
              type="button"
              className="metadata-inline-reference-clear"
              disabled={busy || !canWrite}
              aria-label="Clear referenced member"
              onClick={(event) => {
                event.stopPropagation();
                changeActiveDraft("");
              }}
            >
              Clear
            </button>
          )}
        </div>
      );
    }
    const common = {
      value: draft,
      disabled: busy || !canWrite,
      autoFocus: true,
      className: "metadata-inline-cell-input",
      "aria-label": "Typed value",
      "aria-invalid": Boolean(editValidationError),
      onClick: (event: React.MouseEvent<HTMLElement>) =>
        event.stopPropagation(),
      onChange: (
        event: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>,
      ) => {
        changeActiveDraft(event.target.value);
      },
      onKeyDown: (event: React.KeyboardEvent<HTMLElement>) => {
        event.stopPropagation();
        if (event.key === "Escape") {
          event.preventDefault();
          cancelEdit();
        } else if (event.key === "Enter") {
          event.preventDefault();
          if (editing?.scope === "Member" && memberBatchSupported)
            batchReviewControl.current?.focus();
          else reviewControl.current?.focus();
        }
      },
    };
    return editing.definition.value_type === "Boolean" ? (
      <select {...common}>
        <option value="">Missing</option>
        <option value="true">True</option>
        <option value="false">False</option>
      </select>
    ) : (
      <input
        {...common}
        inputMode={
          editing.definition.value_type === "Decimal" ? "decimal" : undefined
        }
      />
    );
  }

  function displayedAttributeValue(
    value: unknown,
    definition: AttributeDefinition,
  ) {
    if (definition.value_type !== "MemberReference")
      return metadataAttributeValue(value, definition.value_type);
    if (value === undefined || value === null || value === "") return "";
    const referenceDimension = referenceDimensionId(definition);
    if (!referenceDimension) return "Reference configuration unavailable";
    const available =
      referenceDimension === dimensionId
        ? members
        : referenceMembers[referenceDimension] || [];
    const selected = available.find(
      (member) => member.member_id === String(value),
    );
    if (selected) return selected.name;
    return referenceReading
      ? "Reading referenced member…"
      : "Referenced member unavailable";
  }

  function stagedMemberDraft(member: Member, definition: AttributeDefinition) {
    return memberDrafts[
      memberCellKey(member.member_id, definition.attribute_id)
    ];
  }

  function memberGridValue(member: Member, definition: AttributeDefinition) {
    const staged = stagedMemberDraft(member, definition);
    const value = staged
      ? typedDraft(staged.draft, staged.definition.value_type)
      : member.custom_values?.[definition.attribute_id];
    return displayedAttributeValue(value, definition);
  }

  function copyMemberRange(
    event: React.ClipboardEvent<HTMLElement>,
    coordinate: MetadataGridCoordinate,
  ) {
    if ((event.target as HTMLElement).closest("input,select,textarea,button"))
      return;
    const range =
      selectedRange && coordinateInMetadataGridRange(coordinate, selectedRange)
        ? selectedRange
        : metadataGridRange(coordinate, coordinate);
    const rows: string[] = [];
    for (let row = range.firstRow; row <= range.lastRow; row += 1) {
      const member = windowedMembers[row];
      if (!member) continue;
      const values: string[] = [];
      for (
        let column = range.firstColumn;
        column <= range.lastColumn;
        column += 1
      ) {
        const definition = selectedDefinitions[column];
        if (!definition) continue;
        values.push(memberGridValue(member, definition));
      }
      rows.push(values.join("\t"));
    }
    event.clipboardData.setData("text/plain", rows.join("\n"));
    event.preventDefault();
    setResult(
      `Copied ${
        (range.lastRow - range.firstRow + 1) *
        (range.lastColumn - range.firstColumn + 1)
      } visible attribute cells.`,
    );
  }

  function pasteMemberCells(
    event: React.ClipboardEvent<HTMLElement>,
    coordinate: MetadataGridCoordinate,
  ) {
    if ((event.target as HTMLElement).closest("input,select,textarea,button"))
      return;
    event.preventDefault();
    setError("");
    setResult("");
    if (!memberBatchSupported) {
      setError(
        canReplaceMemberValues
          ? "Clipboard changesets support dimensions with at most 1,000 current members."
          : "This application does not authorize atomic member-attribute changesets.",
      );
      return;
    }
    try {
      const pasted = parseMetadataClipboard(
        event.clipboardData.getData("text/plain"),
      );
      const pastedColumns = Math.max(0, ...pasted.map((row) => row.length));
      if (
        coordinate.row + pasted.length > windowedMembers.length ||
        coordinate.column + pastedColumns > selectedDefinitions.length
      )
        throw new Error(
          "The pasted rectangle must fit within the current 50-row window and visible attribute columns.",
        );
      const staged: MemberCellDraft[] = [];
      for (let rowOffset = 0; rowOffset < pasted.length; rowOffset += 1) {
        const member = windowedMembers[coordinate.row + rowOffset];
        if (!member || member.status !== "Active")
          throw new Error("Pasted changes can target only active members.");
        for (
          let columnOffset = 0;
          columnOffset < pasted[rowOffset].length;
          columnOffset += 1
        ) {
          const definition =
            selectedDefinitions[coordinate.column + columnOffset];
          if (!definition || !canEditAttribute(definition))
            throw new Error("Every pasted column must be currently editable.");
          const cellDraft = metadataClipboardDraft(
            definition.value_type,
            pasted[rowOffset][columnOffset],
          );
          const validationError = attributeDraftValidationError(
            definition,
            cellDraft,
          );
          if (validationError)
            throw new Error(`${member.name} · ${validationError}`);
          staged.push({
            scope: "Member",
            objectId: member.member_id,
            objectName: member.name,
            attributeId: definition.attribute_id,
            definition,
            sourceValue:
              member.custom_values?.[definition.attribute_id] ?? null,
            metadataRevision,
            securityRevision: catalog?.revisions.security ?? null,
            draft: cellDraft,
          });
        }
      }
      setMemberDrafts((current) => {
        const next = { ...current };
        for (const cell of staged) {
          const key = memberCellKey(cell.objectId, cell.attributeId);
          if (
            attributeDraftChanged(cell.definition, cell.sourceValue, cell.draft)
          )
            next[key] = cell;
          else delete next[key];
        }
        return next;
      });
      closeActiveMemberEditor();
      setRangeAnchor(coordinate);
      setRangeFocus({
        row: coordinate.row + pasted.length - 1,
        column: coordinate.column + pastedColumns - 1,
      });
      setBatchReviewed(false);
      setPendingReplaceIntent(null);
      setResult(
        `Staged ${staged.length} pasted attribute cells for one atomic review.`,
      );
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to stage the pasted cells.",
      );
    }
  }

  async function saveMemberDrafts() {
    if (
      !app ||
      !memberBatchSupported ||
      memberDraftList.length === 0 ||
      memberDraftValidationErrors.length > 0 ||
      staleMemberDrafts ||
      !batchReviewed ||
      busy ||
      metadataRevision === null ||
      !window.confirm(
        `Apply ${memberDraftList.length} reviewed member attribute ${
          memberDraftList.length === 1 ? "change" : "changes"
        } atomically?`,
      )
    )
      return;
    const attributeIds = activeDefinitions
      .filter((definition) =>
        memberDraftList.some(
          (cell) => cell.attributeId === definition.attribute_id,
        ),
      )
      .map((definition) => definition.attribute_id);
    const rows = members
      .filter((member) => member.status === "Active")
      .map((member) => {
        const values: Record<string, unknown> = {};
        for (const attributeId of attributeIds) {
          const staged =
            memberDrafts[memberCellKey(member.member_id, attributeId)];
          const value = staged
            ? typedDraft(staged.draft, staged.definition.value_type)
            : member.custom_values?.[attributeId];
          if (value !== undefined && value !== null)
            values[attributeId] = value;
        }
        return { objectId: member.member_id, values };
      });
    const args = {
      scope: "Member",
      dimensionId,
      attributeIds,
      rows,
      expectedMetadataRevision: metadataRevision,
    };
    if (
      new TextEncoder().encode(JSON.stringify(args)).byteLength >
      16 * 1024 * 1024
    ) {
      setError(
        "The reviewed changeset exceeds the 16 MiB atomic metadata limit. Reduce the selected attribute set and review a smaller semantic changeset.",
      );
      return;
    }
    const signature = JSON.stringify(args);
    const key =
      pendingReplaceIntent?.signature === signature
        ? pendingReplaceIntent.key
        : mutationIntentKey({
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            functionName: "metadata.attribute-values.replace",
            args,
          });
    setSaving(true);
    setError("");
    setResult("");
    setPendingReplaceIntent({ signature, key });
    try {
      await requestAdmittedEffect(
        "/api/metadata-action",
        attributeValuesReplaceBody(app, args, key),
      );
      if (currentScope.current !== scopeKey) return;
      setMemberDrafts({});
      setPendingReplaceIntent(null);
      setBatchReviewed(false);
      setEditing(null);
      setRangeAnchor(null);
      setRangeFocus(null);
      setResult(
        "The reviewed member attribute changeset was applied atomically.",
      );
      await onChanged();
    } catch (reason) {
      if (currentScope.current !== scopeKey) return;
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to apply the member attribute changeset.",
      );
    } finally {
      if (currentScope.current === scopeKey) setSaving(false);
    }
  }

  async function saveEdit() {
    if (
      !app ||
      !editing ||
      !selectedDefinition ||
      !canWrite ||
      busy ||
      staleEdit ||
      editValidationError ||
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
      returnFocusAfterEdit.current = "save";
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

  function changeNewMember(change: () => void) {
    change();
    setNewMemberReviewed(false);
    setResult("");
  }

  function resetNewMember() {
    setCreatingMember(false);
    setNewMemberId("");
    setNewMemberName("");
    setNewMemberShort("");
    setNewMemberSemantic("");
    setNewMemberReviewed(false);
    setNewMemberDraftRevision(metadataRevision);
  }

  async function createMember() {
    if (
      !app ||
      !canCreateMember ||
      busy ||
      !newMemberValid ||
      !newMemberReviewed ||
      metadataRevision === null ||
      !window.confirm(
        `Create reviewed member ${newMemberName} in this dimension?`,
      )
    )
      return;
    const args = {
      dimensionId,
      memberId: newMemberId,
      name: newMemberName,
      shortDescription: newMemberShort,
      detailedDescription: newMemberSemantic,
      expectedMetadataRevision: metadataRevision,
    };
    setSaving(true);
    setError("");
    setResult("");
    try {
      await requestAdmittedEffect("/api/metadata-action", {
        ...metadataCreateBody(
          app,
          "member",
          args,
          mutationIntentKey({
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
            functionName: "metadata.member.create",
            args,
          }),
        ),
      });
      if (currentScope.current !== scopeKey) return;
      resetNewMember();
      setResult("The reviewed member was created.");
      await onChanged();
    } catch (reason) {
      if (currentScope.current !== scopeKey) return;
      setError(
        reason instanceof Error ? reason.message : "Unable to create member",
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
      <p className="sr-only" role="status" aria-live="polite">
        {canRead && editReturnNotice?.scope === scopeKey
          ? editReturnNotice.text
          : ""}
      </p>
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
            {canCreateMember && (
              <button
                type="button"
                className="primary"
                disabled={
                  creationDisabled ||
                  busy ||
                  creatingMember ||
                  metadataRevision === null
                }
                onClick={() => {
                  setCreatingMember(true);
                  setNewMemberDraftRevision(metadataRevision);
                  setNewMemberReviewed(false);
                  setError("");
                  setResult("");
                }}
              >
                + New member row
              </button>
            )}
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
          {canReplaceMemberValues && (
            <div className="metadata-grid-spreadsheet-help" role="status">
              <span>
                Click an attribute cell to edit. Shift-click another cell to
                select a rectangle; copy or paste tab-separated spreadsheet
                cells within the visible 50 × 20 window.
              </span>
              <strong>
                {memberDraftList.length
                  ? `${memberDraftList.length} pending ${
                      memberDraftList.length === 1 ? "cell" : "cells"
                    }`
                  : "No pending cells"}
              </strong>
              {!memberBatchSupported && (
                <span>
                  Atomic clipboard changesets are unavailable above the current
                  1,000-member contract bound.
                </span>
              )}
            </div>
          )}
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
                {creatingMember && (
                  <>
                    <tr className="metadata-draft-row">
                      <th className="metadata-sticky-id" scope="row">
                        <input
                          aria-label="New member stable ID"
                          value={newMemberId}
                          maxLength={200}
                          placeholder="Stable ID"
                          onChange={(event) =>
                            changeNewMember(() =>
                              setNewMemberId(event.target.value),
                            )
                          }
                        />
                      </th>
                      <td className="metadata-sticky-name">
                        <input
                          aria-label="New member name"
                          value={newMemberName}
                          maxLength={200}
                          placeholder="Member name"
                          onChange={(event) =>
                            changeNewMember(() =>
                              setNewMemberName(event.target.value),
                            )
                          }
                        />
                      </td>
                      <td>Active</td>
                      {onEditSecurityString && <td>After creation</td>}
                      <td>Unplaced</td>
                      <td>
                        <input
                          aria-label="New member short description"
                          value={newMemberShort}
                          maxLength={500}
                          placeholder="Optional description"
                          onChange={(event) =>
                            changeNewMember(() =>
                              setNewMemberShort(event.target.value),
                            )
                          }
                        />
                      </td>
                      {selectedDefinitions.map((definition) => (
                        <td key={definition.attribute_id}>
                          <span className="metadata-missing-value">
                            After creation
                          </span>
                        </td>
                      ))}
                    </tr>
                    <tr className="metadata-draft-review-row">
                      <td
                        colSpan={
                          5 +
                          (onEditSecurityString ? 1 : 0) +
                          selectedDefinitions.length
                        }
                      >
                        {!newMemberCurrent && metadataRevision !== null && (
                          <div className="inline-error" role="status">
                            Metadata changed while this row was being drafted.
                            <button
                              type="button"
                              onClick={() => {
                                setNewMemberDraftRevision(metadataRevision);
                                setNewMemberReviewed(false);
                              }}
                            >
                              Review against current metadata
                            </button>
                          </div>
                        )}
                        <label className="metadata-inline-semantic">
                          Semantic description
                          <textarea
                            aria-label="New member semantic description"
                            value={newMemberSemantic}
                            maxLength={10000}
                            placeholder="Optional business meaning"
                            onChange={(event) =>
                              changeNewMember(() =>
                                setNewMemberSemantic(event.target.value),
                              )
                            }
                          />
                        </label>
                        <div className="metadata-create-actions">
                          <label className="review-check compact-review">
                            <input
                              type="checkbox"
                              aria-label="Review new member"
                              checked={newMemberReviewed}
                              disabled={!newMemberValid || busy}
                              onChange={(event) =>
                                setNewMemberReviewed(event.target.checked)
                              }
                            />
                            <span>
                              I reviewed this exact member against the current
                              model.
                            </span>
                          </label>
                          <button
                            type="button"
                            disabled={
                              busy || !newMemberValid || !newMemberReviewed
                            }
                            onClick={() => void createMember()}
                          >
                            Create member
                          </button>
                          <button
                            type="button"
                            className="secondary"
                            disabled={busy}
                            onClick={() => {
                              if (
                                !newMemberDirty ||
                                window.confirm("Discard this new member row?")
                              )
                                resetNewMember();
                            }}
                          >
                            Cancel row
                          </button>
                        </div>
                      </td>
                    </tr>
                  </>
                )}
                {windowedMembers.map((member, rowIndex) => {
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
                      {selectedDefinitions.map((definition, columnIndex) => {
                        const coordinate = {
                          row: rowIndex,
                          column: columnIndex,
                        };
                        const editable =
                          member.status === "Active" &&
                          canEditAttribute(definition);
                        const staged = stagedMemberDraft(member, definition);
                        const selected = coordinateInMetadataGridRange(
                          coordinate,
                          selectedRange,
                        );
                        return (
                          <td
                            key={definition.attribute_id}
                            className={[
                              editable ? "metadata-attribute-cell" : "",
                              selected
                                ? "metadata-attribute-cell-selected"
                                : "",
                              staged ? "metadata-attribute-cell-pending" : "",
                            ]
                              .filter(Boolean)
                              .join(" ")}
                            onClick={(event) => {
                              event.stopPropagation();
                              if (!editable) return;
                              if (event.shiftKey && rangeAnchor) {
                                closeActiveMemberEditor();
                                setRangeFocus(coordinate);
                              } else
                                beginEdit(
                                  "Member",
                                  member,
                                  definition,
                                  event.currentTarget,
                                  coordinate,
                                );
                            }}
                            onKeyDown={(event) => {
                              if (
                                editable &&
                                (event.key === "Enter" || event.key === " ")
                              ) {
                                event.preventDefault();
                                beginEdit(
                                  "Member",
                                  member,
                                  definition,
                                  event.currentTarget,
                                  coordinate,
                                );
                              }
                            }}
                            onCopy={(event) =>
                              copyMemberRange(event, coordinate)
                            }
                            onPaste={(event) =>
                              pasteMemberCells(event, coordinate)
                            }
                            tabIndex={editable ? 0 : undefined}
                            aria-label={`${definition.display_name} for ${member.name}`}
                          >
                            {editing?.scope === "Member" &&
                            editing.objectId === member.member_id &&
                            editing.attributeId === definition.attribute_id
                              ? inlineValueEditor()
                              : memberGridValue(member, definition) || (
                                  <span className="metadata-missing-value">
                                    —
                                  </span>
                                )}
                          </td>
                        );
                      })}
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
                  placeholder="Name, status, parent or child"
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
                  <th className="metadata-sticky-name">Placement</th>
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
                    <th className="metadata-sticky-name" scope="row">
                      <button
                        type="button"
                        className="metadata-row-select"
                        aria-label={`Select placement ${relationshipLabel(relationship)}`}
                        onClick={(event) => {
                          event.stopPropagation();
                          onSelectedMember(
                            relationship.child_member_id,
                            relationship,
                          );
                        }}
                      >
                        {relationshipLabel(relationship)}
                      </button>
                    </th>
                    <td>
                      {memberNameById.get(relationship.parent_member_id) ||
                        relationship.parent_member_id}
                    </td>
                    <td>
                      {memberNameById.get(relationship.child_member_id) ||
                        relationship.child_member_id}
                    </td>
                    <td>{relationship.status}</td>
                    <td>{relationship.short_description || ""}</td>
                    {selectedRelationshipDefinitions.map((definition) => (
                      <td
                        key={definition.attribute_id}
                        className={
                          canEditAttribute(definition)
                            ? "metadata-attribute-cell"
                            : ""
                        }
                        onClick={(event) => {
                          event.stopPropagation();
                          if (canEditAttribute(definition))
                            beginEdit(
                              "Relationship",
                              relationship,
                              definition,
                              event.currentTarget,
                            );
                        }}
                        onKeyDown={(event) => {
                          if (
                            canEditAttribute(definition) &&
                            (event.key === "Enter" || event.key === " ")
                          ) {
                            event.preventDefault();
                            beginEdit(
                              "Relationship",
                              relationship,
                              definition,
                              event.currentTarget,
                            );
                          }
                        }}
                        tabIndex={canEditAttribute(definition) ? 0 : undefined}
                        aria-label={`${definition.display_name} for ${relationshipLabel(relationship)}`}
                      >
                        {editing?.scope === "Relationship" &&
                        editing.objectId === relationship.relationship_id &&
                        editing.attributeId === definition.attribute_id
                          ? inlineValueEditor()
                          : displayedAttributeValue(
                              relationship.custom_values?.[
                                definition.attribute_id
                              ],
                              definition,
                            ) || (
                              <span className="metadata-missing-value">—</span>
                            )}
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
      {memberDraftList.length > 0 && (
        <aside
          className="metadata-cell-editor metadata-changeset-editor"
          aria-label="Member attribute changeset"
        >
          <div>
            <small>ATOMIC ATTRIBUTE CHANGESET</small>
            <h4>
              {memberDraftList.length} pending{" "}
              {memberDraftList.length === 1 ? "cell" : "cells"}
            </h4>
            <p>
              {new Set(memberDraftList.map((cell) => cell.objectId)).size}{" "}
              {new Set(memberDraftList.map((cell) => cell.objectId)).size === 1
                ? "member"
                : "members"}{" "}
              will change together. No cell is published unless the complete
              reviewed changeset succeeds at the current metadata revision.
            </p>
          </div>
          {staleMemberDrafts && (
            <p className="inline-error" role="alert">
              The metadata or access snapshot changed while this changeset was
              being drafted. The typed cells are preserved, but they cannot be
              applied. Copy any values you need, discard the changeset and
              reopen the current cells.
            </p>
          )}
          {memberDraftValidationErrors.length > 0 && (
            <div className="inline-error" role="alert">
              <strong>Correct these cells before review:</strong>
              <ul>
                {memberDraftValidationErrors.map((message, index) => (
                  <li key={`${message}-${index}`}>{message}</li>
                ))}
              </ul>
            </div>
          )}
          <div className="metadata-changeset-review">
            <table aria-label="Pending member attribute changes">
              <thead>
                <tr>
                  <th>Member</th>
                  <th>Attribute</th>
                  <th>Before</th>
                  <th>After</th>
                </tr>
              </thead>
              <tbody>
                {memberDraftList.map((cell) => (
                  <tr key={memberCellKey(cell.objectId, cell.attributeId)}>
                    <th scope="row">{cell.objectName}</th>
                    <td>{cell.definition.display_name}</td>
                    <td>
                      {displayedAttributeValue(
                        cell.sourceValue,
                        cell.definition,
                      ) || "Missing"}
                    </td>
                    <td>
                      {displayedAttributeValue(
                        typedDraft(cell.draft, cell.definition.value_type),
                        cell.definition,
                      ) || "Missing"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {editing?.scope === "Member" && editingCellVisible && (
            <p className="metadata-inline-edit-help">
              Continue editing in the highlighted cell, or choose another cell
              without losing this changeset. Press Enter to move to review.
            </p>
          )}
          <label className="review-check">
            <input
              ref={batchReviewControl}
              type="checkbox"
              checked={batchReviewed}
              disabled={
                busy ||
                staleMemberDrafts ||
                memberDraftValidationErrors.length > 0
              }
              onChange={(event) => setBatchReviewed(event.target.checked)}
            />
            I reviewed every exact before/after value and target in this
            changeset.
          </label>
          <div className="button-row">
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={() => {
                if (
                  !window.confirm(
                    `Discard all ${memberDraftList.length} pending attribute changes?`,
                  )
                )
                  return;
                setMemberDrafts({});
                setPendingReplaceIntent(null);
                setBatchReviewed(false);
                if (editing?.scope === "Member") setEditing(null);
                setRangeAnchor(null);
                setRangeFocus(null);
              }}
            >
              Discard changeset
            </button>
            <button
              type="button"
              disabled={
                busy ||
                !batchReviewed ||
                staleMemberDrafts ||
                memberDraftValidationErrors.length > 0
              }
              onClick={() => void saveMemberDrafts()}
            >
              Apply changes atomically
            </button>
          </div>
        </aside>
      )}
      {editing && !(editing.scope === "Member" && memberBatchSupported) && (
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
          {editValidationError && (
            <p className="inline-error" role="alert">
              {editValidationError}
            </p>
          )}
          {editingCellVisible ? (
            <p className="metadata-inline-edit-help">
              Edit directly in the highlighted grid cell. Press Enter to review;
              press Escape to cancel.
            </p>
          ) : (
            <label>
              Typed value (cell outside the current view)
              {inlineValueEditor()}
            </label>
          )}
          <label className="review-check">
            <input
              ref={reviewControl}
              type="checkbox"
              checked={reviewed}
              disabled={
                busy ||
                !canWrite ||
                !editChanged ||
                staleEdit ||
                Boolean(editValidationError)
              }
              onChange={(event) => setReviewed(event.target.checked)}
            />
            I reviewed this exact typed value and target.
          </label>
          <div className="button-row">
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={cancelEdit}
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={
                busy ||
                !canWrite ||
                !reviewed ||
                !editChanged ||
                staleEdit ||
                Boolean(editValidationError)
              }
              onClick={() => void saveEdit()}
            >
              Save reviewed value
            </button>
          </div>
        </aside>
      )}
      {referenceChooserOpen &&
        editing?.definition.value_type === "MemberReference" &&
        app &&
        catalog &&
        metadataRevision !== null &&
        referenceDimensionId(editing.definition) && (
          <MemberSelectionDialog
            app={app}
            catalog={catalog}
            request={{
              dimensionId: referenceDimensionId(editing.definition) as string,
              dimensionName: referenceDimensionId(editing.definition) as string,
              metadataRevision,
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
              initial: draft ? { kind: "member", memberId: draft } : null,
            }}
            members={
              referenceDimensionId(editing.definition) === dimensionId
                ? members
                : referenceMembers[
                    referenceDimensionId(editing.definition) as string
                  ] || []
            }
            onCancel={() => setReferenceChooserOpen(false)}
            onApply={(selection) => {
              if (selection.include.kind !== "member") return;
              changeActiveDraft(selection.include.memberId);
              setReferenceChooserOpen(false);
            }}
          />
        )}
      {busy && (
        <p role="status">
          {saving
            ? "Saving reviewed metadata…"
            : "Refreshing governed metadata…"}
        </p>
      )}
      {result && (
        <p className="inline-success" role="status">
          {result}
        </p>
      )}
    </div>
  );
}
