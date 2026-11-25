import {
  useEffect,
  useImperativeHandle,
  useLayoutEffect,
  useRef,
  useState,
} from "react";
import type { Ref } from "react";
import {
  ApiError,
  prepareAdmittedProgramEffect,
  readProgram,
  replayAdmittedEffect,
  request,
} from "./api";
import type { AdmittedEffectPacket } from "./api";
import { ImportChangeReview, validateImportReview } from "./ImportChangeReview";
import type { ImportReview } from "./ImportChangeReview";
import { exactOperationReceipt, outcomeAuthorityKey } from "./ReceiptInspector";
import {
  activeFactDimensions,
  type MetadataDimension,
  type MetadataMember,
} from "./metadata-data";
import { MemberSelectionDialog } from "./member-selection/MemberSelectionDialog";
import type { MemberSelectionResult } from "./member-selection/selection-types";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { usePreservedDraft, type DraftRecoveryLease } from "./unsaved-work";
import { transferAction } from "./data-transfer-action";

type Proposal = {
  dimensionId: string;
  sourceMemberId: string;
  targetMemberId: string;
  filterMembers: Record<string, string>;
  mode: "merge" | "replace";
  expectedMetadataRevision: number;
  expectedDataRevision: number;
  idempotencyKey: string;
};
export type ScenarioCopySource = {
  dimensionId: string;
  sourceMemberId: string;
  members: Record<string, string>;
};
export type ScenarioPromotionControl = {
  offerComparedSource: (source: ScenarioCopySource) => boolean;
};

export function canCopyScenario(catalog: ApplicationCatalog) {
  return [
    "facts.slice.copy.prepare",
    "facts.source.preview",
    "facts.source.publish",
  ].every((name) => Boolean(catalog.functions[name]));
}

type Prepared = {
  owner: string;
  proposal: Proposal;
  batchId: string;
  contentDigest: string;
  rowCount: number;
  status: "ready" | "published" | "failed" | "cancelled";
};
type Review = Prepared & {
  context: string;
  previewToken: string;
  setCount: number;
  clearCount: number;
  review: ImportReview;
};
type Pending = {
  phase: "prepare" | "publish";
  packet: AdmittedEffectPacket;
  context: string;
  owner: string;
  proposal: Proposal;
  uncertain: boolean;
  expected?: Pick<
    Review,
    "batchId" | "contentDigest" | "setCount" | "clearCount"
  >;
};
const copyProgress = {
  prepare: "Preparing scenario copy…",
  review: "Reading the prepared changes…",
  publish: "Publishing scenario copy…",
  refresh: "Refreshing application context…",
  reconcile: "Checking the original copy request…",
  retry: "Retrying the original copy request…",
};
const prepareStatusFunction = "facts.slice.copy.status.read";
const receiptFunction = "application.operation.receipt.read";
type CopyActivity = keyof typeof copyProgress;
type CopyMemberPicker = {
  context: string;
  dimension: MetadataDimension;
  field: "source" | "target" | "scope";
  members: MetadataMember[] | null;
};
const scopedProgram = (
  app: ApplicationSummary,
  name: string,
  args: Record<string, unknown>,
) => ({
  workspaceId: app.workspaceId,
  applicationId: app.applicationId,
  program: { languageVersion: 2, function: name, arguments: args },
});
const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const isCopyRevisionRefusal = (failure: unknown) =>
  failure instanceof ApiError &&
  (failure.code === "STALE_SOURCE_BATCH_REVISION" ||
    failure.code === "STALE_SCENARIO_COPY_REVISION");

/** Copy inputs through the existing source batch owner; no calculated-result promotion. */
export function ScenarioPromotion({
  app,
  catalog,
  dimensions,
  memberCatalog,
  loadMembers,
  onRefreshCatalog,
  comparisonControl,
}: {
  app: ApplicationSummary;
  catalog: ApplicationCatalog;
  dimensions: MetadataDimension[];
  memberCatalog?: Record<string, MetadataMember[]>;
  loadMembers?: (
    dimensionId: string,
    signal: AbortSignal,
  ) => Promise<MetadataMember[]>;
  onRefreshCatalog?: () => Promise<ApplicationCatalog>;
  comparisonControl?: Ref<ScenarioPromotionControl>;
}) {
  const axes = activeFactDimensions(dimensions);
  const scenarioAxes = axes.filter(
    (dimension) => dimension.model_role === "Scenario",
  );
  const scenario = scenarioAxes.length === 1 ? scenarioAxes[0] : null;
  const scenarioAxis = scenario?.dimension_id ?? "";
  const [source, setSource] = useState("");
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<"" | "merge" | "replace">("");
  const [scope, setScope] = useState<
    Record<string, { choice: string; member: string }>
  >({});
  const [review, setReview] = useState<Review | null>(null);
  const [prepared, setPrepared] = useState<Prepared | null>(null);
  const [approved, setApproved] = useState(false);
  const [pending, setPending] = useState<Pending | null>(null);
  const [offeredSource, setOfferedSource] = useState<{
    context: string;
    scope: ScenarioCopySource;
  } | null>(null);
  const [acceptedSource, setAcceptedSource] =
    useState<typeof offeredSource>(null);
  const [picker, setPicker] = useState<CopyMemberPicker | null>(null);
  const pickerRequest = useRef<AbortController | null>(null);
  const [retryableRequest, setRetryableRequest] = useState<{
    operationId: string;
    authority: string;
  } | null>(null);
  const [activity, setActivity] = useState<CopyActivity | null>(null);
  const busy = activity !== null;
  const [error, setError] = useState("");
  const [refusal, setRefusal] = useState<{
    owner: string;
    revisionBasis: string;
    refreshed: boolean;
  } | null>(null);
  const [receipt, setReceipt] = useState<{
    authority: string;
    message: string;
  } | null>(null);
  const owner = JSON.stringify([
    app.workspaceId,
    app.applicationId,
    catalog.applicationAccess.issuer,
    catalog.applicationAccess.subjectId,
  ]);
  const revisionBasis = JSON.stringify([
    catalog.revisions.metadata,
    catalog.revisions.data,
  ]);
  const copyRefusal = refusal?.owner === owner ? refusal : null;
  const refreshRequired =
    copyRefusal?.revisionBasis === revisionBasis && !copyRefusal.refreshed;
  const flight = useRef<{ owner: string } | null>(null);
  const focusTransition = useRef<{
    owner: string;
    origin: HTMLElement;
    action: CopyActivity | "new-copy" | "compared-copy";
  } | null>(null);
  const sourceInput = useRef<HTMLInputElement>(null);
  const sourcePicker = useRef<HTMLButtonElement>(null);
  const targetInput = useRef<HTMLInputElement>(null);
  const targetPicker = useRef<HTMLButtonElement>(null);
  const copyDetails = useRef<HTMLDetailsElement>(null);
  const copySummary = useRef<HTMLElement>(null);
  const reviewHeading = useRef<HTMLHeadingElement>(null);
  const reconcileButton = useRef<HTMLButtonElement>(null);
  const statusTarget = useRef<HTMLDivElement>(null);
  const errorTarget = useRef<HTMLParagraphElement>(null);
  const currentOwner = useRef(owner);
  currentOwner.current = owner;
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  const context = JSON.stringify([
    app.workspaceId,
    app.applicationId,
    catalog.accessContext,
    catalog.applicationAccess,
    catalog.revisions,
    axes,
    Object.keys(catalog.functions).sort(),
  ]);
  const current = useRef(context);
  current.current = context;
  const authority = outcomeAuthorityKey(app, catalog);
  const canCopy = canCopyScenario(catalog);
  const canPickMembers = Boolean(
    loadMembers && catalog.functions["metadata.member.list"],
  );
  const pickerContext = JSON.stringify([
    authority,
    scenarioAxis,
    catalog.revisions.metadata,
    catalog.revisions.policy,
    catalog.revisions.schemaEpoch,
    canPickMembers,
    canCopy,
  ]);
  const currentPickerContext = useRef(pickerContext);
  currentPickerContext.current = pickerContext;
  const currentPicker = picker?.context === pickerContext ? picker : null;
  const pickerMemberId = currentPicker
    ? currentPicker.field === "source"
      ? source
      : currentPicker.field === "target"
        ? target
        : scope[currentPicker.dimension.dimension_id]?.member
    : undefined;
  useLayoutEffect(() => {
    setPicker(null);
    setOfferedSource(null);
    setAcceptedSource(null);
    return () => {
      pickerRequest.current?.abort();
      pickerRequest.current = null;
    };
  }, [pickerContext]);
  const currentAuthority = useRef(authority);
  currentAuthority.current = authority;
  const visibleReceipt =
    receipt?.authority === authority ? receipt.message : "";
  const currentPending = pending?.owner === owner ? pending : null;
  const mayCheckOriginal = Boolean(
    catalog.functions[
      currentPending?.phase === "prepare"
        ? prepareStatusFunction
        : receiptFunction
    ],
  );
  const currentPrepared = prepared?.owner === owner ? prepared : null;
  const otherAxes = axes.filter(
    (dimension) => dimension.dimension_id !== scenarioAxis,
  );
  const memberDiscoveryUnavailable = Boolean(loadMembers && !canPickMembers);
  const currentOffer =
    offeredSource?.context === pickerContext ? offeredSource : null;
  const comparedScope =
    acceptedSource?.context === pickerContext ? acceptedSource.scope : null;
  const copySetupLocked = Boolean(
    busy ||
      flight.current ||
      currentPicker ||
      currentPending ||
      currentPrepared,
  );
  useImperativeHandle(comparisonControl, () => ({
    offerComparedSource(selection) {
      if (
        !copyDetails.current ||
        !canCopy ||
        memberDiscoveryUnavailable ||
        !scenarioAxis ||
        selection.dimensionId !== scenarioAxis ||
        Object.keys(selection.members).length !== otherAxes.length ||
        otherAxes.some(
          ({ dimension_id }) =>
            !Object.hasOwn(selection.members, dimension_id) ||
            !selection.members[dimension_id],
        )
      )
        return false;
      setOfferedSource({ context: pickerContext, scope: selection });
      copyDetails.current.open = true;
      copySummary.current?.focus();
      return true;
    },
  }));
  function memberName(dimensionId: string, memberId: string) {
    const current = memberCatalog?.[dimensionId];
    const selected = current?.find(
      (member) => member.member_id === memberId && member.status === "Active",
    );
    if (!selected) {
      const comparedId =
        dimensionId === scenarioAxis
          ? comparedScope?.sourceMemberId
          : comparedScope?.members[dimensionId];
      return comparedId && comparedId === memberId ? memberId : undefined;
    }
    return current?.some(
      (member) =>
        member.status === "Active" &&
        member.member_id !== memberId &&
        member.name === selected.name,
    )
      ? `${selected.name} (${selected.member_id})`
      : selected.name;
  }
  const preparedScopeIsCurrent =
    !copyRefusal &&
    currentPrepared?.proposal.dimensionId === scenarioAxis &&
    currentPrepared.proposal.expectedMetadataRevision ===
      catalog.revisions.metadata &&
    currentPrepared.proposal.expectedDataRevision === catalog.revisions.data;
  const canRetryOriginal =
    canCopy &&
    mayCheckOriginal &&
    retryableRequest?.authority === authority &&
    retryableRequest.operationId === currentPending?.packet.body.idempotencyKey;
  useEffect(() => {
    setReview(null);
    setApproved(false);
    setError("");
  }, [context]);
  useEffect(() => {
    setPending(null);
    setRetryableRequest(null);
    setPrepared(null);
    setSource("");
    setTarget("");
    setMode("");
    setScope({});
    setReceipt(null);
    setRefusal(null);
    setActivity(null);
  }, [owner]);
  const recovery = usePreservedDraft(
    app.workspaceId,
    app.applicationId,
    "scenario-copy",
    "Scenario copy awaiting reconciliation",
    Boolean(currentPending || currentPrepared?.status === "ready"),
    {
      pending: currentPending,
      prepared: currentPrepared?.status === "ready" ? currentPrepared : null,
    },
    (saved) => {
      setPending(saved.pending);
      setPrepared(saved.prepared);
      setReview(null);
      setApproved(false);
    },
  );
  const ready =
    canCopy &&
    !memberDiscoveryUnavailable &&
    !currentPicker &&
    !refreshRequired &&
    scenarioAxis &&
    source.trim() &&
    target.trim() &&
    source.trim() !== target.trim() &&
    (!canPickMembers ||
      (memberName(scenarioAxis, source) && memberName(scenarioAxis, target))) &&
    mode &&
    otherAxes.every(
      (axis) =>
        scope[axis.dimension_id]?.choice === "all" ||
        (scope[axis.dimension_id]?.choice === "member" &&
          scope[axis.dimension_id].member.trim() &&
          (!canPickMembers ||
            memberName(axis.dimension_id, scope[axis.dimension_id].member))),
    );
  const visibleReview =
    review?.context === context && (!currentPending || activity === "publish")
      ? review
      : null;
  const pendingPhase =
    currentPending?.phase === "prepare" ? "preparation" : "publication";
  const statusMessage = activity
    ? copyProgress[activity]
    : currentPending
      ? `The original ${pendingPhase} outcome is uncertain. ${
          mayCheckOriginal
            ? "Check for its recorded outcome before retrying."
            : "Current access does not include the status check."
        }`
      : currentPicker && !currentPicker.members
        ? "Reading authorized members…"
        : visibleReceipt ||
          (visibleReview
            ? "The copy review is ready."
            : currentPrepared?.status === "published"
              ? "The original copy was already published."
              : copyRefusal?.refreshed
                ? "Application context refreshed."
                : "");
  useLayoutEffect(() => {
    const transition = focusTransition.current;
    if (!transition) return;
    const active = document.activeElement;
    const originRemoved = !transition.origin.isConnected;
    if (
      transition.owner !== owner ||
      (active !== transition.origin &&
        (active !== document.body || !originRemoved))
    ) {
      focusTransition.current = null;
      return;
    }
    if (busy) {
      // A refresh or a phase change can remove the current button mid-request.
      // Carry owned focus to the persistent status while the request settles.
      if (originRemoved && statusTarget.current) {
        statusTarget.current.focus();
        transition.origin = statusTarget.current;
      }
      return;
    }
    focusTransition.current = null;
    const { action, origin } = transition;
    if (action === "compared-copy")
      (targetPicker.current || targetInput.current)?.focus();
    else if (action === "new-copy")
      (sourcePicker.current || sourceInput.current)?.focus();
    else if (currentPending) reconcileButton.current?.focus();
    else if (visibleReview && action !== "publish")
      reviewHeading.current?.focus();
    else if (
      originRemoved ||
      origin.getAttribute("aria-disabled") === "true" ||
      origin === statusTarget.current
    )
      (errorTarget.current || statusTarget.current)?.focus();
  });
  function invalidate() {
    setReview(null);
    setApproved(false);
    setError("");
    setReceipt(null);
  }
  function useComparedScope(origin: HTMLElement) {
    if (!currentOffer || copySetupLocked || flight.current) return;
    const active = document.activeElement;
    focusTransition.current = {
      owner,
      origin: active instanceof HTMLElement ? active : origin,
      action: "compared-copy",
    };
    const selection = currentOffer.scope;
    setAcceptedSource(currentOffer);
    setOfferedSource(null);
    setSource(selection.sourceMemberId);
    setTarget("");
    setMode("");
    setScope(
      Object.fromEntries(
        Object.entries(selection.members).map(([axis, member]) => [
          axis,
          { choice: "member", member },
        ]),
      ),
    );
    invalidate();
  }
  async function chooseMember(
    field: CopyMemberPicker["field"],
    dimension: MetadataDimension,
    origin: HTMLButtonElement,
  ) {
    if (
      !loadMembers ||
      !canPickMembers ||
      busy ||
      pickerRequest.current ||
      currentPicker
    )
      return;
    const controller = new AbortController();
    pickerRequest.current = controller;
    const choice = { context: pickerContext, dimension, field, members: null };
    const ownsFocus = document.activeElement === origin;
    setPicker(choice);
    setError("");
    const stillCurrent = () =>
      !controller.signal.aborted &&
      currentPickerContext.current === choice.context;
    try {
      const members = await loadMembers(
        dimension.dimension_id,
        controller.signal,
      );
      if (!stillCurrent()) return;
      if (ownsFocus && document.activeElement !== origin) {
        setPicker(null);
        return;
      }
      if (!members.some((member) => member.status === "Active"))
        throw new Error("No active authorized members are available.");
      setPicker({ ...choice, members });
    } catch (failure) {
      if (!stillCurrent()) return;
      setPicker(null);
      setError(
        failure instanceof Error
          ? failure.message
          : "Unable to read current members.",
      );
    } finally {
      if (pickerRequest.current === controller) pickerRequest.current = null;
    }
  }
  function applyMember(
    choice: CopyMemberPicker,
    result: MemberSelectionResult,
  ) {
    const dimensionId = choice.dimension.dimension_id;
    if (
      choice.context !== currentPickerContext.current ||
      result.dimensionId !== dimensionId ||
      result.metadataRevision !== catalog.revisions.metadata ||
      result.include.kind !== "member" ||
      result.exclude !== null
    )
      return;
    const member = result.include.memberId;
    if (choice.field === "source") setSource(member);
    else if (choice.field === "target") setTarget(member);
    else
      setScope((current) => ({
        ...current,
        [dimensionId]: { choice: "member", member },
      }));
    setPicker(null);
    invalidate();
  }
  function memberChoiceLabel(
    field: CopyMemberPicker["field"],
    dimension: MetadataDimension,
  ) {
    return field === "source"
      ? "source scenario"
      : field === "target"
        ? "destination scenario"
        : `${dimension.name} scope member`;
  }
  function memberChoice(
    field: CopyMemberPicker["field"],
    dimension: MetadataDimension,
    memberId: string,
  ) {
    const name = memberName(dimension.dimension_id, memberId);
    const label = memberChoiceLabel(field, dimension);
    return (
      <button
        ref={
          field === "source"
            ? sourcePicker
            : field === "target"
              ? targetPicker
              : undefined
        }
        type="button"
        aria-disabled={Boolean(currentPicker) || undefined}
        aria-label={name ? `Change ${label}, ${name}` : `Choose ${label}`}
        onClick={(event) =>
          void chooseMember(field, dimension, event.currentTarget)
        }
      >
        {name || "Choose member"}
      </button>
    );
  }
  function requireFreshCopy() {
    setReview(null);
    setApproved(false);
    setRefusal({ owner, revisionBasis, refreshed: false });
    setError(
      "The model or facts changed. Refresh the application context before preparing a new copy.",
    );
  }
  function inspectPrepared(
    candidate: Pending,
    result: Record<string, unknown>,
  ) {
    if (
      typeof result.batchId !== "string" ||
      !/^[0-9a-f]{32}$/.test(result.batchId) ||
      !["ready", "published", "failed", "cancelled"].includes(
        String(result.status),
      ) ||
      typeof result.contentDigest !== "string" ||
      !/^[0-9a-f]{64}$/.test(result.contentDigest) ||
      !Number.isSafeInteger(result.rowCount) ||
      Number(result.rowCount) < 0 ||
      Number(result.rowCount) > 100000
    )
      throw new Error(
        "The prepared copy response is incomplete. Check the original preparation status.",
      );
    const accepted: Prepared = {
      owner: candidate.owner,
      proposal: candidate.proposal,
      batchId: result.batchId,
      contentDigest: result.contentDigest,
      rowCount: Number(result.rowCount),
      status: result.status as Prepared["status"],
    };
    return accepted;
  }
  async function readPrepared(accepted: Prepared) {
    const reviewContext = context;
    setActivity("review");
    setReview(null);
    setApproved(false);
    const response = await request<{ result: Record<string, unknown> }>(
      "/api/source-load",
      scopedProgram(app, "facts.source.preview", { batchId: accepted.batchId }),
    ).catch((failure: unknown) => {
      if (!isCopyRevisionRefusal(failure)) throw failure;
      // A typed preview refusal identifies a stale prepared batch even when
      // reconciliation just established that the preparation succeeded.
      if (
        mounted.current &&
        current.current === reviewContext &&
        currentOwner.current === accepted.owner
      )
        requireFreshCopy();
      return null;
    });
    if (
      !response ||
      !mounted.current ||
      current.current !== reviewContext ||
      currentOwner.current !== accepted.owner
    )
      return;
    const preview = response.result;
    if (
      !object(preview) ||
      typeof preview.previewToken !== "string" ||
      !preview.previewToken ||
      !Number.isSafeInteger(preview.setCount) ||
      !Number.isSafeInteger(preview.clearCount) ||
      Number(preview.setCount) !== accepted.rowCount ||
      Number(preview.clearCount) < 0 ||
      preview.batchId !== accepted.batchId ||
      preview.contentDigest !== accepted.contentDigest ||
      preview.mode !== accepted.proposal.mode
    )
      throw new Error(
        "The copy preview is incomplete. Prepare a fresh review.",
      );
    const counts = {
      setCount: Number(preview.setCount),
      clearCount: Number(preview.clearCount),
    };
    const explained = validateImportReview(
      preview.review,
      accepted.proposal.mode,
      counts,
      axes.map(({ dimension_id }) => dimension_id),
    );
    const expectedScope = {
      ...accepted.proposal.filterMembers,
      [accepted.proposal.dimensionId]: accepted.proposal.targetMemberId,
    };
    if (
      explained.scopeAll ||
      explained.periodSelection !== null ||
      JSON.stringify(Object.entries(explained.scopeMembers).sort()) !==
        JSON.stringify(Object.entries(expectedScope).sort()) ||
      explained.metadataRevision !==
        accepted.proposal.expectedMetadataRevision ||
      explained.dataRevision !== accepted.proposal.expectedDataRevision
    )
      throw new Error(
        "The copy preview does not match the exact selected scope and revisions.",
      );
    setReview({
      ...accepted,
      context: reviewContext,
      previewToken: preview.previewToken,
      ...counts,
      review: explained,
    });
  }
  async function send(
    candidate: Pending,
    expectedLease: DraftRecoveryLease | null,
  ) {
    const unresolved = { ...candidate, uncertain: true };
    const retainedPrepared =
      candidate.phase === "publish" ? currentPrepared : null;
    const lease = recovery.retain(
      { pending: unresolved, prepared: retainedPrepared },
      expectedLease,
    );
    setRetryableRequest(null);
    setPending(unresolved);
    let acknowledged = false;
    try {
      const response = await replayAdmittedEffect<{
        result: Record<string, unknown>;
      }>(candidate.packet);
      if (!object(response.result))
        throw new Error("The original copy outcome is not yet known.");
      if (candidate.phase === "prepare") {
        if (currentAuthority.current !== authority) return;
        const accepted = inspectPrepared(candidate, response.result);
        settlePreparation(accepted, lease);
        acknowledged = true;
        if (
          mounted.current &&
          current.current === candidate.context &&
          accepted.status === "ready"
        )
          await readPrepared(accepted);
      } else {
        const expected = candidate.expected;
        if (
          !expected ||
          !Number.isSafeInteger(response.result.committedRevision) ||
          Number(response.result.committedRevision) < 1 ||
          response.result.batchId !== expected.batchId ||
          response.result.mode !== candidate.proposal.mode ||
          response.result.contentDigest !== expected.contentDigest ||
          response.result.setCount !== expected.setCount ||
          response.result.clearCount !== expected.clearCount
        )
          throw new Error(
            "The publication receipt is incomplete; reconcile the original request.",
          );
        if (currentAuthority.current !== authority) return;
        settlePublication(
          candidate,
          lease,
          Number(response.result.committedRevision),
        );
      }
    } catch (failure) {
      if (
        !acknowledged &&
        !candidate.uncertain &&
        failure instanceof ApiError &&
        [400, 401, 403, 409, 412, 422].includes(failure.status)
      ) {
        if (retainedPrepared?.status === "ready")
          recovery.retain({ pending: null, prepared: retainedPrepared }, lease);
        else recovery.release(lease, { pending: null, prepared: null });
        if (mounted.current && currentOwner.current === candidate.owner) {
          setPending(null);
          setReview(null);
          setApproved(false);
        }
      }
      throw failure;
    }
  }
  function settlePreparation(accepted: Prepared, lease: DraftRecoveryLease) {
    // The lease prevents a late prepare acknowledgement from replacing a
    // remounted editor's newer publication packet.
    if (accepted.status === "ready")
      recovery.retain({ pending: null, prepared: accepted }, lease);
    else recovery.release(lease, { pending: null, prepared: null });
    if (!mounted.current || currentOwner.current !== accepted.owner) return;
    setPending(null);
    setPrepared(accepted);
  }
  function settlePublication(
    candidate: Pending,
    lease: DraftRecoveryLease,
    committedRevision: number,
  ) {
    recovery.release(lease, { pending: null, prepared: null });
    if (!mounted.current || currentOwner.current !== candidate.owner) return;
    setPending(null);
    setPrepared(null);
    setReview(null);
    setApproved(false);
    setReceipt({
      authority,
      message: `Copied ${candidate.proposal.sourceMemberId} to ${candidate.proposal.targetMemberId}; committed revision ${committedRevision}. Read the destination again to inspect current facts.`,
    });
  }
  async function checkOriginal(candidate: Pending, lease: DraftRecoveryLease) {
    if (!mayCheckOriginal) return;
    const preparation = candidate.phase === "prepare";
    const operationId = preparation
      ? candidate.packet.body.idempotencyKey
      : candidate.expected?.batchId;
    if (!operationId)
      throw new Error("The original copy identity is unavailable.");
    setRetryableRequest(null);
    const stillCurrent = () =>
      mounted.current && currentAuthority.current === authority;
    let result: unknown;
    try {
      result = await readProgram<unknown>(
        app,
        preparation ? prepareStatusFunction : receiptFunction,
        { operationId },
      );
    } catch (failure) {
      if (!stillCurrent()) return;
      if (
        failure instanceof ApiError &&
        failure.code ===
          (preparation
            ? "SCENARIO_COPY_STATUS_UNAVAILABLE"
            : "OPERATION_RECEIPT_NOT_FOUND")
      ) {
        setRetryableRequest({
          operationId: candidate.packet.body.idempotencyKey,
          authority,
        });
        setError(
          `A recorded outcome is unavailable. The ${preparation ? "preparation" : "publication"} remains unconfirmed.`,
        );
        return;
      }
      throw failure;
    }
    if (!stillCurrent()) return;
    if (preparation) {
      if (!object(result))
        throw new Error("The original preparation outcome is incomplete.");
      if (result.status === "staging") {
        setError(
          "The original copy is still staging. Check preparation status again.",
        );
        return;
      }
      const accepted = inspectPrepared(candidate, result);
      settlePreparation(accepted, lease);
      if (
        canCopy &&
        current.current === candidate.context &&
        accepted.status === "ready"
      )
        await readPrepared(accepted);
      return;
    }
    const recorded = exactOperationReceipt(result, operationId);
    const expected = candidate.expected;
    if (
      !expected ||
      recorded.actorId !== catalog.applicationAccess.subjectId ||
      recorded.commandDigest !== expected.contentDigest ||
      recorded.outcome.batchId !== expected.batchId ||
      recorded.outcome.setCount !== expected.setCount ||
      recorded.outcome.clearCount !== expected.clearCount
    )
      throw new Error("The recorded outcome does not match the reviewed copy.");
    settlePublication(candidate, lease, recorded.committedRevision);
  }
  async function act(
    action: CopyActivity,
    run: () => Promise<void>,
    origin: HTMLButtonElement,
  ) {
    const capturedOwner = owner;
    const capturedContext = context;
    if (flight.current?.owner === capturedOwner) return;
    const attempt = { owner: capturedOwner };
    flight.current = attempt;
    focusTransition.current =
      document.activeElement === origin ? { owner, origin, action } : null;
    setActivity(action);
    setError("");
    try {
      await run();
    } catch (failure) {
      if (mounted.current && current.current === capturedContext) {
        if (
          failure instanceof ApiError &&
          failure.code === "CUBE_READ_AUTHORIZATION_STALE"
        ) {
          setReview(null);
          setApproved(false);
          setError(
            "Access changed during this copy step. Check current access before trying the same step again.",
          );
        } else if (
          failure instanceof ApiError &&
          failure.kind === "authorization"
        ) {
          setReview(null);
          setApproved(false);
          setError(
            "This copy step is unavailable under your current access. Check which scope you can access before trying again.",
          );
        } else if (isCopyRevisionRefusal(failure)) {
          if (action === "reconcile" || action === "retry") {
            setError(
              "The application changed. Check the original outcome before starting another copy.",
            );
          } else {
            requireFreshCopy();
          }
        } else {
          setError(
            failure instanceof Error
              ? failure.message
              : "The copy request failed.",
          );
        }
      }
    } finally {
      if (flight.current === attempt) {
        flight.current = null;
        if (mounted.current && currentOwner.current === capturedOwner)
          setActivity(null);
      }
    }
  }
  async function prepare() {
    if (!ready || currentPending || currentPrepared) return;
    const proposal: Proposal = {
      dimensionId: scenarioAxis,
      sourceMemberId: source.trim(),
      targetMemberId: target.trim(),
      filterMembers: Object.fromEntries(
        otherAxes
          .filter((axis) => scope[axis.dimension_id].choice === "member")
          .map((axis) => [
            axis.dimension_id,
            scope[axis.dimension_id].member.trim(),
          ]),
      ),
      mode: mode as "merge" | "replace",
      expectedMetadataRevision: catalog.revisions.metadata,
      expectedDataRevision: catalog.revisions.data,
      idempotencyKey: "scenario-copy-" + crypto.randomUUID(),
    };
    const captured = context;
    setRefusal(null);
    invalidate();
    const packet = await prepareAdmittedProgramEffect(
      "/api/source-action",
      {
        ...scopedProgram(app, "facts.slice.copy.prepare", proposal),
        confirmed: true,
        idempotencyKey: proposal.idempotencyKey,
      },
      proposal.idempotencyKey,
    );
    if (!mounted.current || current.current !== captured)
      throw new Error(
        "The application changed before preparation. Review the current scope.",
      );
    await send(
      {
        phase: "prepare",
        packet,
        context: captured,
        owner,
        proposal,
        uncertain: false,
      },
      null,
    );
  }
  async function publish() {
    if (!visibleReview || !approved || currentPending) return;
    const accepted = visibleReview;
    const lease = recovery.lease;
    if (!lease) throw new Error("DRAFT_RECOVERY_LEASE_REQUIRED");
    const key = "scenario-publish-" + crypto.randomUUID();
    const packet = await prepareAdmittedProgramEffect(
      "/api/source-action",
      {
        ...scopedProgram(app, "facts.source.publish", {
          batchId: accepted.batchId,
          previewToken: accepted.previewToken,
        }),
        confirmed: true,
        idempotencyKey: key,
      },
      key,
    );
    if (!mounted.current || current.current !== accepted.context)
      throw new Error(
        "The application changed before publication. Review again.",
      );
    await send(
      {
        phase: "publish",
        packet,
        context: accepted.context,
        owner,
        proposal: accepted.proposal,
        uncertain: false,
        expected: {
          batchId: accepted.batchId,
          contentDigest: accepted.contentDigest,
          setCount: accepted.setCount,
          clearCount: accepted.clearCount,
        },
      },
      lease,
    );
  }
  if (
    (!canCopy || !scenarioAxis) &&
    !currentPending &&
    !currentPrepared &&
    !visibleReceipt
  )
    return null;
  return (
    <details className="context-note" ref={copyDetails}>
      <summary ref={copySummary}>Copy scenario facts</summary>
      <p>
        Copy stored numeric, text and supporting-detail facts between explicit
        scenario members. The source remains unchanged. Calculated results
        require a separate run of the destination rules; copying does not run
        them.
      </p>
      {currentOffer && (
        <section aria-label="Compared copy source">
          <p>
            Use alternative {currentOffer.scope.sourceMemberId} and the exact
            compared scope. Choose the destination and policy separately.
          </p>
          {copySetupLocked ? (
            <p role="status">
              Finish or reconcile the current copy before using this comparison.
            </p>
          ) : (
            <>
              {(source || target || mode || Object.keys(scope).length > 0) && (
                <p>Using the comparison replaces the current copy setup.</p>
              )}
              <button
                type="button"
                onClick={(event) => useComparedScope(event.currentTarget)}
              >
                Use compared source and scope
              </button>
            </>
          )}
        </section>
      )}
      {memberDiscoveryUnavailable && canCopy && (
        <p role="status">
          Current member discovery is unavailable. Refresh the application
          context before preparing a new copy.
        </p>
      )}
      <fieldset
        hidden={!canCopy || memberDiscoveryUnavailable}
        disabled={
          !canCopy || busy || Boolean(currentPending || currentPrepared)
        }
      >
        <legend>Exact source, destination and scope</legend>
        {canPickMembers && scenario ? (
          <div className="scenario-copy-members">
            <div>
              <span>Source scenario</span>
              {memberChoice("source", scenario, source)}
            </div>
            <div>
              <span>Destination scenario</span>
              {memberChoice("target", scenario, target)}
            </div>
          </div>
        ) : (
          <>
            <label>
              Source scenario ID
              <input
                ref={sourceInput}
                aria-label="Copy source scenario ID"
                value={source}
                onChange={(event) => {
                  setSource(event.target.value);
                  invalidate();
                }}
              />
            </label>
            <label>
              Destination scenario ID
              <input
                ref={targetInput}
                aria-label="Copy destination scenario ID"
                value={target}
                onChange={(event) => {
                  setTarget(event.target.value);
                  invalidate();
                }}
              />
            </label>
          </>
        )}
        {source && source === target && (
          <p role="status">
            Choose different source and destination scenarios.
          </p>
        )}
        {otherAxes.map((axis) => (
          <div className="scenario-copy-axis" key={axis.dimension_id}>
            <label>
              {canPickMembers
                ? axis.name
                : `${axis.name} (${axis.dimension_id})`}
              <select
                aria-label={`Copy scope ${axis.dimension_id}`}
                disabled={Boolean(currentPicker)}
                value={scope[axis.dimension_id]?.choice || ""}
                onChange={(event) => {
                  setScope({
                    ...scope,
                    [axis.dimension_id]: {
                      choice: event.target.value,
                      member: "",
                    },
                  });
                  invalidate();
                }}
              >
                <option value="">Choose scope</option>
                <option value="member">One exact member</option>
                <option value="all">All members in this dimension</option>
              </select>
            </label>
            {scope[axis.dimension_id]?.choice === "member" &&
              (canPickMembers ? (
                memberChoice("scope", axis, scope[axis.dimension_id].member)
              ) : (
                <input
                  aria-label={`Copy member ${axis.dimension_id}`}
                  value={scope[axis.dimension_id].member}
                  onChange={(event) => {
                    setScope({
                      ...scope,
                      [axis.dimension_id]: {
                        choice: "member",
                        member: event.target.value,
                      },
                    });
                    invalidate();
                  }}
                />
              ))}
          </div>
        ))}
        <label>
          Destination policy
          <select
            aria-label="Copy destination policy"
            value={mode}
            onChange={(event) => {
              setMode(event.target.value as typeof mode);
              invalidate();
            }}
          >
            <option value="">Choose an explicit policy</option>
            <option value="merge">
              Merge: overwrite matching values; preserve omitted values
            </option>
            <option value="replace">
              Replace: overwrite matching values; clear omitted values in this
              target scope
            </option>
          </select>
        </label>
        <p>
          A populated destination is changed only under the selected policy.
          Review the full counts and available before/after examples; examples
          may be bounded or withheld by read permissions.
        </p>
      </fieldset>
      {currentPicker?.members && (
        <MemberSelectionDialog
          app={app}
          catalog={catalog}
          request={{
            dimensionId: currentPicker.dimension.dimension_id,
            dimensionName: currentPicker.dimension.name,
            metadataRevision: catalog.revisions.metadata,
            title: `Choose ${memberChoiceLabel(currentPicker.field, currentPicker.dimension)}`,
            cardinality: { kind: "exactly-one" },
            initial:
              currentPicker.members.some(
                (member) =>
                  member.status === "Active" &&
                  member.member_id === pickerMemberId,
              ) && pickerMemberId
                ? { kind: "member", memberId: pickerMemberId }
                : null,
            capability: {
              allowExplicitMembers: true,
              allowHierarchySelector: false,
              allowNamedMemberList: false,
              allowAttributeSelector: false,
              allowInlineExpression: false,
              allowExclusion: false,
              orderMatters: false,
            },
          }}
          members={currentPicker.members}
          onCancel={() => setPicker(null)}
          onApply={(result) => applyMember(currentPicker, result)}
        />
      )}
      <button
        hidden={!canCopy || memberDiscoveryUnavailable}
        {...transferAction(
          busy || !ready || Boolean(currentPending || currentPrepared),
          (origin) => act("prepare", prepare, origin),
        )}
      >
        Prepare copy review
      </button>
      <div role="status" tabIndex={-1} ref={statusTarget}>
        {statusMessage}
        {error && currentPending && !busy && <p>{error}</p>}
      </div>
      {refreshRequired && canCopy && !currentPending && onRefreshCatalog && (
        <button
          {...transferAction(busy, (origin) =>
            act(
              "refresh",
              async () => {
                await onRefreshCatalog();
                if (mounted.current && currentOwner.current === owner)
                  setRefusal((current) =>
                    current && current === copyRefusal
                      ? { ...current, refreshed: true }
                      : current,
                  );
              },
              origin,
            ),
          )}
        >
          Refresh application context
        </button>
      )}
      {currentPrepared && !currentPending && (
        <section aria-label="Prepared scenario copy">
          <p>Copy status {currentPrepared.status}.</p>
          {currentPrepared.status === "ready" && (
            <button
              {...transferAction(
                busy || !canCopy || !preparedScopeIsCurrent,
                (origin) =>
                  act("review", () => readPrepared(currentPrepared), origin),
              )}
            >
              Review prepared copy
            </button>
          )}
          {currentPrepared.status === "ready" &&
            !preparedScopeIsCurrent &&
            !refreshRequired && (
              <p>
                The model or facts changed. Start a new copy to review the
                current scope.
              </p>
            )}
          {currentPrepared.status === "ready" &&
            preparedScopeIsCurrent &&
            !canCopy && (
              <p>
                Copy review is unavailable in the current application context.
              </p>
            )}
          <button
            type="button"
            disabled={busy || (canCopy && refreshRequired)}
            onClick={(event) => {
              if (currentPrepared.status === "ready") {
                try {
                  if (!recovery.lease)
                    throw new Error("DRAFT_RECOVERY_LEASE_REQUIRED");
                  recovery.release(recovery.lease, {
                    pending: null,
                    prepared: null,
                  });
                } catch (failure) {
                  setError(
                    failure instanceof Error
                      ? failure.message
                      : "Unable to release prepared copy",
                  );
                  return;
                }
              }
              if (document.activeElement === event.currentTarget)
                focusTransition.current = {
                  owner,
                  origin: event.currentTarget,
                  action: "new-copy",
                };
              setPrepared(null);
              setRefusal(null);
              invalidate();
            }}
          >
            {canCopy ? "Start a new copy" : "Close prepared copy"}
          </button>
        </section>
      )}
      {visibleReview && (
        <section aria-label="Scenario copy review">
          <h3 tabIndex={-1} ref={reviewHeading}>
            Scenario copy review
          </h3>
          <p>
            Source{" "}
            {memberName(
              visibleReview.proposal.dimensionId,
              visibleReview.proposal.sourceMemberId,
            ) ?? visibleReview.proposal.sourceMemberId}
            ; destination{" "}
            {memberName(
              visibleReview.proposal.dimensionId,
              visibleReview.proposal.targetMemberId,
            ) ?? visibleReview.proposal.targetMemberId}
            . Set {visibleReview.setCount}; clear {visibleReview.clearCount}.
          </p>
          <ImportChangeReview
            review={visibleReview.review}
            scenarioSource={{
              dimensionId: visibleReview.proposal.dimensionId,
              memberId: visibleReview.proposal.sourceMemberId,
            }}
          />
          <label>
            <input
              type="checkbox"
              checked={approved}
              disabled={busy || Boolean(currentPending)}
              onChange={(event) => setApproved(event.target.checked)}
            />
            I reviewed the exact source, destination, scope, policy and changes.
          </label>
          <button
            {...transferAction(
              !approved || busy || Boolean(currentPending),
              (origin) => act("publish", publish, origin),
            )}
          >
            Publish scenario copy
          </button>
        </section>
      )}
      {currentPending &&
        (!busy || activity === "reconcile" || activity === "retry") && (
          <section aria-label="Scenario copy reconciliation">
            <button
              ref={reconcileButton}
              {...transferAction(busy || !mayCheckOriginal, (origin) =>
                act(
                  "reconcile",
                  async () => {
                    if (!recovery.lease)
                      throw new Error("DRAFT_RECOVERY_LEASE_REQUIRED");
                    await checkOriginal(currentPending, recovery.lease);
                  },
                  origin,
                ),
              )}
            >
              {currentPending.phase === "prepare"
                ? "Check original preparation status"
                : "Check original publication status"}
            </button>
            {canRetryOriginal && (
              <button
                {...transferAction(busy, (origin) =>
                  act(
                    "retry",
                    async () => {
                      if (!recovery.lease)
                        throw new Error("DRAFT_RECOVERY_LEASE_REQUIRED");
                      await send(currentPending, recovery.lease);
                    },
                    origin,
                  ),
                )}
              >
                {currentPending.phase === "prepare"
                  ? "Retry original preparation"
                  : "Retry original publication"}
              </button>
            )}
          </section>
        )}
      {error && !currentPending && (
        <p role="alert" tabIndex={-1} ref={errorTarget}>
          {error}
        </p>
      )}
    </details>
  );
}
