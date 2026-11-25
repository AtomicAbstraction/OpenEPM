import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { ApiError, readProgram } from "../api";
import {
  collectMemberLists,
  memberListParameters,
  memberListReadInvalidatesCatalogue,
  type MemberListSummary,
} from "../member-list-data";
import {
  collectMetadataHierarchies,
  type MetadataHierarchy,
} from "../metadata-hierarchies";
import type { ApplicationCatalog, ApplicationSummary } from "../types";
import {
  canonicalCubeSelector,
  explicitMemberIds,
  memberSelectionError,
  INLINE_EXPRESSION_FORMAT,
  type CubeSelector,
  type MemberSelectionRequest,
  type MemberSelectionResult,
  type SelectionParameterValue,
  type NavigationExpression,
  type NavigationOperation,
} from "./selection-types";
import {
  navigation,
  navigationLabels,
  nativeMemberKey,
  collectSelectionRows,
  readNativeSelection,
  type NativeMember,
  type NativeScope,
  type NativeSelectionPage,
} from "./native-selection";
import { selectorSummary } from "./selection-summary";
import "./member-selection.css";

export type SelectableMember = {
  member_id: string;
  name: string;
  status: string;
  short_description?: string;
};
type MemberListEvaluation = {
  listId: string;
  stateToken: string;
  dimensionId: string;
  memberIds: string[];
  memberCount: number;
  canonicalDigest: string;
  metadataRevision: number;
};
type Source = "hierarchy" | "lists" | "search";
type MemberListParameter = {
  name: string;
  type: string;
  required: boolean;
  dimensionId?: string;
};
function description(member: SelectableMember) {
  return member.short_description?.trim() || "No description";
}

export function MemberSelectionDialog({
  app,
  catalog,
  request,
  members,
  onCancel,
  onApply,
}: {
  app: ApplicationSummary;
  catalog: ApplicationCatalog;
  request: MemberSelectionRequest;
  members: SelectableMember[];
  onCancel: () => void;
  onApply: (result: MemberSelectionResult) => void;
}) {
  const {
    dimensionId,
    dimensionName,
    metadataRevision,
    hierarchyId: initialHierarchyId,
    cardinality,
    capability,
  } = request;
  const canReadHierarchies = Boolean(
    catalog.functions["metadata.hierarchy.list"],
  );
  const canReadMemberLists = Boolean(
    catalog.functions["metadata.member_list.list"],
  );
  const discoveryRequired = canReadHierarchies || canReadMemberLists;
  const selectionRevisions = {
    ...catalog.revisions,
    metadata: metadataRevision,
  };
  const context = JSON.stringify([
    app.workspaceId,
    app.applicationId,
    catalog.accessContext,
    catalog.applicationAccess.issuer,
    catalog.applicationAccess.subjectId,
    catalog.revisions.metadata,
    catalog.revisions.security,
    catalog.revisions.policy,
    catalog.revisions.schemaEpoch,
    metadataRevision,
    dimensionId,
    initialHierarchyId,
    canReadHierarchies,
    canReadMemberLists,
    Boolean(catalog.functions["metadata.member.select"]),
    Boolean(catalog.functions["metadata.member_list.read"]),
    Boolean(catalog.functions["metadata.member_list.evaluate"]),
    catalog.applicationAccess.role,
    catalog.applicationAccess.workspaceAdministrator,
    cardinality,
    capability,
    request.initial,
    request.initialExclude,
    request.title,
  ]);
  const contextRef = useRef(context);
  const epoch = useRef(0);
  if (contextRef.current !== context) {
    contextRef.current = context;
    epoch.current += 1;
  }
  const initialContext = useRef(context);
  const nativeContext = useRef<{ key: string; token: string } | null>(null);
  function expectedContextToken() {
    return nativeContext.current?.key === context
      ? nativeContext.current.token
      : undefined;
  }
  function rememberContext(token: string) {
    nativeContext.current = { key: context, token };
  }
  const pendingRead = useRef<AbortController | null>(null);
  const applying = useRef(false);
  const [hierarchyRead, setHierarchyRead] = useState<{
    key: string;
    status: "loading" | "complete" | "failed";
  } | null>(null);
  const [discovery, setDiscovery] = useState<{
    key: string;
    ready: boolean;
  } | null>(discoveryRequired ? null : { key: context, ready: true });
  const contextReady = discovery?.key === context && discovery.ready;
  const contextLoading = discovery?.key !== context;
  const [source, setSource] = useState<Source>("hierarchy");
  const [search, setSearch] = useState("");
  const [draft, setDraft] = useState(() => ({
    selector: request.initial ? canonicalCubeSelector(request.initial) : null,
    add: new Set<string>(),
    remove: new Set<string>(),
    message: "",
    error: "",
  }));
  const { selector: draftSelector, add: checkedMembers } = draft;
  const [reviewChecks, setReviewChecks] = useState(false);
  const [replacement, setReplacement] = useState<CubeSelector | null>(null);
  const [sourceMemberId, setSourceMemberId] = useState("");
  const [sourcePath, setSourcePath] = useState<string[] | null>(null);
  const [sourceMemberPath, setSourceMemberPath] = useState<string[]>([]);
  const [hierarchies, setHierarchies] = useState<MetadataHierarchy[]>([]);
  const [hierarchyId, setHierarchyId] = useState("");
  const [scope, setScope] = useState<NativeScope | null>(null);
  const [tree, setTree] = useState<NativeMember[]>([]);
  const [treeCursor, setTreeCursor] = useState<string | null>(null);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [treeMode, setTreeMode] = useState(true);
  const [preview, setPreview] = useState<{
    expression: NavigationExpression;
    page: NativeSelectionPage;
  } | null>(null);
  const [memberLists, setMemberLists] = useState<MemberListSummary[]>([]);
  const [memberListError, setMemberListError] = useState("");
  const [evaluatedList, setEvaluatedList] = useState<{
    listId: string;
    memberIds: string[];
  } | null>(null);
  const [selectedList, setSelectedList] = useState<MemberListSummary | null>(
    null,
  );
  const [listParameters, setListParameters] = useState<
    Record<string, SelectionParameterValue>
  >({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [nativeRows, setNativeRows] = useState<Map<string, NativeMember>>(
    new Map(),
  );
  function rememberRows(rows: NativeMember[]) {
    setNativeRows((previous) => {
      const next = new Map(previous);
      for (const row of rows) next.set(nativeMemberKey(row), row);
      return next;
    });
  }
  const closeButton = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLDialogElement>(null);
  const nativeAvailable =
    Boolean(catalog.functions["metadata.member.select"]) &&
    capability.allowNativeBrowse !== false;
  // A changed context or hierarchy is not ready before its native setup
  // effect runs. Keep loading and completion under this single read owner.
  const hierarchyReadKey = JSON.stringify([context, hierarchyId]);
  const hierarchyReadKeyRef = useRef(hierarchyReadKey);
  hierarchyReadKeyRef.current = hierarchyReadKey;
  const currentHierarchyRead =
    hierarchyRead?.key === hierarchyReadKey ? hierarchyRead : null;
  const hierarchyLoading =
    nativeAvailable &&
    (!currentHierarchyRead || currentHierarchyRead.status === "loading");
  const hierarchyReadComplete = currentHierarchyRead?.status === "complete";
  const activeMembers = useMemo(() => {
    const byId = new Map(
      members
        .filter((member) => member.status === "Active")
        .map((member) => [member.member_id, member]),
    );
    for (const row of nativeRows.values())
      byId.set(row.memberId, {
        member_id: row.memberId,
        name: row.name,
        status: row.status,
        short_description: row.shortDescription,
      });
    return [...byId.values()];
  }, [members, nativeRows]);
  const memberById = useMemo(
    () => new Map(activeMembers.map((member) => [member.member_id, member])),
    [activeMembers],
  );
  const ambiguousMemberNames = useMemo(() => {
    const counts = new Map<string, number>();
    for (const member of activeMembers)
      counts.set(member.name, (counts.get(member.name) ?? 0) + 1);
    return new Set(
      [...counts].filter(([, count]) => count > 1).map(([name]) => name),
    );
  }, [activeMembers]);
  const placementCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const row of tree)
      counts.set(row.memberId, (counts.get(row.memberId) ?? 0) + 1);
    return counts;
  }, [tree]);
  const preservedExclude = useMemo(
    () =>
      request.initialExclude
        ? canonicalCubeSelector(request.initialExclude)
        : null,
    [request.initialExclude],
  );
  const selectedMemberIds = useMemo(
    () => explicitMemberIds(draftSelector),
    [draftSelector],
  );
  const unverifiedMemberIds = useMemo(
    () => selectedMemberIds.filter((id) => !memberById.has(id)),
    [selectedMemberIds, memberById],
  );
  const verificationKey = JSON.stringify([context, unverifiedMemberIds]);
  const [memberVerification, setMemberVerification] = useState<{
    key: string;
    state: "unavailable" | "unconfirmed";
  } | null>(null);
  const currentVerification =
    memberVerification?.key === verificationKey ? memberVerification : null;
  const checkingSelectedMembers =
    unverifiedMemberIds.length > 0 && nativeAvailable && !currentVerification;
  const multiple = cardinality.kind !== "exactly-one";
  const dynamic = draftSelector !== null && selectedMemberIds.length === 0;
  const selectedIdSet = new Set(selectedMemberIds);
  const canCheckMembers = multiple && capability.allowExplicitMembers;
  const revisionCurrent = catalog.revisions.metadata === metadataRevision;
  const canTransfer = contextReady && revisionCurrent && !busy && !replacement;
  const canChooseSource = canTransfer && !hierarchyLoading;
  const explicitMaximum = multiple
    ? Math.min(cardinality.maximum ?? 10_000, 10_000)
    : 1;
  const hasCheckedMembers =
    contextReady && canCheckMembers && checkedMembers.size > 0;
  const transferLabel = multiple
    ? "Add checked members"
    : "Add selected member";
  const invalidSelection = memberSelectionError(
    draftSelector,
    cardinality,
    capability,
  );
  const selectionError = !revisionCurrent
    ? "Metadata changed. Reopen the picker with the current application metadata."
    : !contextReady
      ? contextLoading
        ? "Checking the selection context…"
        : "Reopen the picker to confirm the selection context."
      : invalidSelection ||
        (draftSelector?.kind === "member_list" &&
        canReadMemberLists &&
        !memberLists.some((item) => item.listId === draftSelector.listId)
          ? memberListError
            ? "The saved selection could not be confirmed. Reopen the picker to retry."
            : "The saved selection is unavailable. Choose a current selection."
          : unverifiedMemberIds.length
            ? checkingSelectedMembers
              ? "Checking selected members…"
              : currentVerification?.state === "unavailable"
                ? "Some selected members are unavailable in the current context."
                : "The selected members could not be confirmed."
            : null);
  const labels = {
    members: Object.fromEntries(
      activeMembers.map((member) => [member.member_id, member.name]),
    ),
    hierarchies: Object.fromEntries(
      hierarchies.map((item) => [item.hierarchyId, item.name]),
    ),
    memberLists: Object.fromEntries(
      contextReady ? memberLists.map((item) => [item.listId, item.name]) : [],
    ),
    placements: Object.fromEntries(
      [...nativeRows.values()]
        .filter((row) => row.pathRelationshipIds && row.pathMemberIds)
        .map((row) => [
          nativeMemberKey(row),
          row
            .pathMemberIds!.map(
              (id) => `${memberById.get(id)?.name ?? id} (${id})`,
            )
            .join(" / "),
        ]),
    ),
  };
  const selectionSummary = draftSelector
    ? selectorSummary(draftSelector, labels)
    : "No selection";
  const exclusionSummary = preservedExclude
    ? selectorSummary(preservedExclude, labels)
    : null;

  useLayoutEffect(() => {
    const dialog = dialogRef.current;
    const previousFocus =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    dialog?.showModal();
    closeButton.current?.focus();
    return () => {
      pendingRead.current?.abort();
      if (dialog?.open) dialog.close();
      previousFocus?.focus({ preventScroll: true });
    };
  }, []);
  useLayoutEffect(() => {
    const dialog = dialogRef.current;
    const active = document.activeElement;
    if (dialog && (!dialog.contains(active) || active?.matches(":disabled")))
      closeButton.current?.focus({ preventScroll: true });
  });
  useEffect(() => {
    const controller = new AbortController();
    const reading = ++epoch.current;
    // Initial state already belongs to this context. Reset only when that
    // context is replaced: a visible first-commit member click must not be
    // erased by the initial passive setup effect.
    if (initialContext.current !== context) {
      nativeContext.current = null;
      if (!discoveryRequired) setDiscovery({ key: context, ready: true });
      setHierarchies([]);
      setHierarchyId("");
      setScope(null);
      setHierarchyRead(null);
      setMemberVerification(null);
      setTree([]);
      setTreeCursor(null);
      setNativeRows(new Map());
      setPreview(null);
      setEvaluatedList(null);
      setSelectedList(null);
      setMemberLists([]);
      setMemberListError("");
      pendingRead.current?.abort();
      setReplacement(null);
      setReviewChecks(false);
      setSourceMemberId("");
      setSourcePath(null);
      setSourceMemberPath([]);
      setCollapsed(new Set());
      resetDraft(null);
      initialContext.current = context;
      setError("");
    }
    setBusy(discoveryRequired);
    if (!discoveryRequired) return () => controller.abort();
    void (async () => {
      try {
        const [hierarchyResult, listResult] = await Promise.allSettled([
          canReadHierarchies
            ? collectMetadataHierarchies(
                dimensionId,
                metadataRevision,
                (args) =>
                  readProgram(
                    app,
                    "metadata.hierarchy.list",
                    args,
                    controller.signal,
                  ),
              )
            : null,
          canReadMemberLists
            ? collectMemberLists((args) =>
                readProgram(
                  app,
                  "metadata.member_list.list",
                  args,
                  controller.signal,
                ),
              )
            : null,
        ]);
        if (controller.signal.aborted || reading !== epoch.current) return;
        if (hierarchyResult.status === "rejected") throw hierarchyResult.reason;
        const available = (hierarchyResult.value?.rows ?? []).filter(
          (item) => item.status === "Active",
        );
        setHierarchies(available);
        const selected = initialHierarchyId
          ? available.find((item) => item.hierarchyId === initialHierarchyId)
          : available.find((item) => item.isDefault);
        if (initialHierarchyId && !selected)
          throw new Error(
            "The requested hierarchy is unavailable. Choose a current hierarchy.",
          );
        setHierarchyId(selected?.hierarchyId ?? "");
        if (listResult.status === "rejected") {
          setMemberLists([]);
          setMemberListError(
            listResult.reason instanceof Error
              ? listResult.reason.message
              : "Unable to load saved selections.",
          );
        } else {
          setMemberListError("");
          setMemberLists(
            (listResult.value?.rows ?? []).filter(
              (item) =>
                item.dimensionId === dimensionId &&
                item.active === true &&
                item.executable === true,
            ),
          );
        }
        setDiscovery({ key: context, ready: true });
      } catch (reason) {
        if (!controller.signal.aborted && reading === epoch.current) {
          setDiscovery({ key: context, ready: false });
          setError(
            reason instanceof Error
              ? reason.message
              : "Unable to load selection context.",
          );
        }
      } finally {
        if (reading === epoch.current) setBusy(false);
      }
    })();
    return () => controller.abort();
  }, [context, initialHierarchyId]);

  useEffect(() => {
    if (!nativeAvailable || !contextReady || !revisionCurrent) {
      setHierarchyRead(null);
      return;
    }
    const controller = new AbortController();
    const current = () =>
      !controller.signal.aborted &&
      hierarchyReadKeyRef.current === hierarchyReadKey;

    setScope(null);
    setTree([]);
    setTreeCursor(null);
    setPreview(null);
    setSourceMemberId("");
    setSourcePath(null);
    setSourceMemberPath([]);
    setCollapsed(new Set());
    setHierarchyRead({ key: hierarchyReadKey, status: "loading" });
    void (async () => {
      try {
        const top = await readNativeSelection(
          app,
          dimensionId,
          selectionRevisions,
          navigation("top", hierarchyId || null),
          {
            signal: controller.signal,
            expectedContextToken: expectedContextToken(),
          },
        );
        if (!current()) return;
        rememberContext(top.selectionContextToken);
        setScope(top.scope);
        if (hierarchyId) {
          const page = await readNativeSelection(
            app,
            dimensionId,
            selectionRevisions,
            navigation("all", hierarchyId),
            {
              signal: controller.signal,
              placements: true,
              expectedContextToken: top.selectionContextToken,
            },
          );
          if (!current()) return;
          setTree(page.rows);
          setTreeCursor(page.nextCursor);
          rememberRows(page.rows);
        }
        if (current())
          setHierarchyRead({ key: hierarchyReadKey, status: "complete" });
      } catch (reason) {
        if (current()) {
          setError(readError(reason, "Unable to read native hierarchy."));
          setHierarchyRead({ key: hierarchyReadKey, status: "failed" });
        }
      }
    })();
    return () => controller.abort();
  }, [
    context,
    hierarchyId,
    hierarchyReadKey,
    contextReady,
    nativeAvailable,
    revisionCurrent,
  ]);

  useEffect(() => {
    if (
      !contextReady ||
      !revisionCurrent ||
      hierarchyLoading ||
      !checkingSelectedMembers ||
      invalidSelection
    )
      return;
    const controller = new AbortController();
    const current = () =>
      !controller.signal.aborted && contextRef.current === context;
    void (async () => {
      try {
        const rows: NativeMember[] = [];
        let token = expectedContextToken();
        // Keep exact lookups below the fixed core's public argument limit even
        // when each identifier uses the full allowed length.
        for (let start = 0; start < unverifiedMemberIds.length; start += 50) {
          const ids = new Set(unverifiedMemberIds.slice(start, start + 50));
          const result = await collectSelectionRows(
            app,
            dimensionId,
            selectionRevisions,
            { kind: "explicit", memberIds: [...ids] },
            ids.size,
            controller.signal,
            { expectedContextToken: token },
          );
          if (!current()) return;
          if (
            result.rows.length !== ids.size ||
            result.rows.some((row) => !ids.has(row.memberId))
          )
            throw new Error(
              "The selected member lookup returned different members.",
            );
          token = result.selectionContextToken;
          rows.push(...result.rows);
        }
        if (token) rememberContext(token);
        rememberRows(rows);
      } catch (reason) {
        if (!current()) return;
        setMemberVerification({
          key: verificationKey,
          state:
            reason instanceof ApiError &&
            reason.status === 403 &&
            reason.code === "METADATA_SELECTION_SCOPE_UNAVAILABLE"
              ? "unavailable"
              : "unconfirmed",
        });
      }
    })();
    return () => controller.abort();
  }, [
    context,
    contextReady,
    revisionCurrent,
    hierarchyLoading,
    checkingSelectedMembers,
    invalidSelection,
    unverifiedMemberIds,
    verificationKey,
  ]);

  function cancelRead() {
    pendingRead.current?.abort();
    ++epoch.current;
    setBusy(false);
  }

  function beginRead() {
    pendingRead.current?.abort();
    const controller = new AbortController();
    pendingRead.current = controller;
    const reading = ++epoch.current;
    return {
      signal: controller.signal,
      current: () => !controller.signal.aborted && reading === epoch.current,
    };
  }

  async function previewNative(
    expression: NavigationExpression,
    cursor?: string,
  ) {
    const read = beginRead();
    setBusy(true);
    setError("");
    if (!cursor) {
      setPreview(null);
      setSourceMemberId("");
      setSourcePath(null);
      setSourceMemberPath([]);
    }
    try {
      const page = await readNativeSelection(
        app,
        dimensionId,
        selectionRevisions,
        expression,
        {
          cursor,
          signal: read.signal,
          expectedContextToken: expectedContextToken(),
        },
      );
      if (!read.current()) return;
      rememberContext(page.selectionContextToken);
      const previous = cursor ? (preview?.page.rows ?? []) : [];
      const ids = [...previous, ...page.rows].map((row) => row.memberId);
      if (
        new Set(ids).size !== ids.length ||
        (cursor && page.nextCursor === cursor)
      )
        throw new Error(
          "The selection returned an invalid continuation. Preview it again.",
        );
      rememberRows(page.rows);
      setPreview((current) => ({
        expression,
        page: {
          ...page,
          rows:
            cursor && current
              ? [...current.page.rows, ...page.rows]
              : page.rows,
        },
      }));
    } catch (reason) {
      if (read.current()) {
        setPreview(null);
        setError(readError(reason, "Unable to evaluate native selection."));
      }
    } finally {
      if (read.current()) setBusy(false);
    }
  }
  async function loadTreePage() {
    if (!treeCursor) return;
    const read = beginRead();
    setBusy(true);
    try {
      const page = await readNativeSelection(
        app,
        dimensionId,
        selectionRevisions,
        navigation("all", hierarchyId),
        {
          cursor: treeCursor,
          placements: true,
          signal: read.signal,
          expectedContextToken: expectedContextToken(),
        },
      );
      if (!read.current()) return;
      const keys = [...tree, ...page.rows].map(nativeMemberKey);
      if (new Set(keys).size !== keys.length || page.nextCursor === treeCursor)
        throw new Error(
          "Hierarchy continuation repeated a placement. Refresh the selection.",
        );
      setTree((current) => [...current, ...page.rows]);
      rememberRows(page.rows);
      setTreeCursor(page.nextCursor);
    } catch (reason) {
      if (read.current()) {
        setTree([]);
        setHierarchyRead({ key: hierarchyReadKey, status: "failed" });
        setTreeCursor(null);
        setError(readError(reason, "Unable to continue hierarchy."));
      }
    } finally {
      if (read.current()) setBusy(false);
    }
  }
  function choose(
    memberId: string,
    path: string[] | null = null,
    memberPath: string[] = [],
  ) {
    setSourceMemberId(memberId);
    setSourcePath(path);
    setSourceMemberPath(memberPath);
  }
  function resetDraft(selector: CubeSelector | null, message = "") {
    setDraft({
      selector,
      add: new Set(),
      remove: new Set(),
      message,
      error: "",
    });
  }

  function addMembers(
    memberIds: string[],
    resolvedRows: NativeMember[] = [],
    convert = false,
  ) {
    const resolvedIds = new Set(resolvedRows.map((row) => row.memberId));
    setDraft((current) => {
      const previousIds = explicitMemberIds(current.selector);
      if (current.selector && !previousIds.length && !convert) return current;
      if (memberIds.some((id) => !memberById.has(id) && !resolvedIds.has(id)))
        return {
          ...current,
          error:
            "One or more members are unavailable in the current selection context. Refresh and try again.",
        };
      if (convert && !memberIds.length)
        return {
          ...current,
          error:
            "This rule returned no members. The dynamic selection is still selected.",
        };
      const next = new Set([...previousIds, ...memberIds]);
      if (multiple && next.size > explicitMaximum)
        return {
          ...current,
          error: `Select no more than ${explicitMaximum} members.`,
        };
      if (!next.size)
        return { ...current, message: "No members to add.", error: "" };
      return {
        ...current,
        selector: multiple
          ? { kind: "members", memberIds: [...next] }
          : { kind: "member", memberId: memberIds[0] },
        add: new Set([...current.add].filter((id) => !next.has(id))),
        message: convert
          ? `Converted to ${next.size} explicit members.`
          : `Added ${next.size - previousIds.length} of ${memberIds.length} members.`,
        error: "",
      };
    });
    setError("");
  }

  function toggleCheck(side: "add" | "remove", id: string, checked: boolean) {
    setDraft((current) => {
      const ids = new Set(current[side]);
      if (checked) ids.add(id);
      else ids.delete(id);
      return { ...current, [side]: ids, error: "" };
    });
  }

  function removeMembers(ids: Iterable<string>) {
    const removed = new Set(ids);
    setDraft((current) => {
      const before = explicitMemberIds(current.selector);
      const remaining = before.filter((id) => !removed.has(id));
      return {
        ...current,
        selector: !remaining.length
          ? null
          : multiple
            ? { kind: "members", memberIds: remaining }
            : { kind: "member", memberId: remaining[0] },
        remove: new Set([...current.remove].filter((id) => !removed.has(id))),
        message: `Removed ${before.length - remaining.length} members.`,
        error: "",
      };
    });
  }

  function moveMember(id: string, offset: number) {
    setDraft((current) => {
      const next = explicitMemberIds(current.selector);
      const index = next.indexOf(id);
      const destination = index + offset;
      if (index < 0 || destination < 0 || destination >= next.length)
        return current;
      next[index] = next[destination];
      next[destination] = id;
      return {
        ...current,
        selector: { kind: "members", memberIds: next },
        message: `Moved member to position ${destination + 1}.`,
      };
    });
  }

  function proposeReplacement(selector: CubeSelector) {
    if (!canTransfer) return;
    if (draftSelector || checkedMembers.size) setReplacement(selector);
    else resetDraft(selector);
  }

  function action(operation: NavigationOperation) {
    const dimensionWide = operation === "unplaced" || operation === "all";
    const anchored =
      sourceMemberId &&
      !["all", "roots", "leaves", "unplaced"].includes(operation);
    const expression = navigation(
      operation,
      operation === "all" ? null : hierarchyId || null,
      anchored
        ? { memberId: sourceMemberId, pathRelationshipIds: sourcePath }
        : null,
      dimensionWide ? "dimension" : hierarchyId ? "hierarchy" : "dimension",
    );
    void previewNative(expression);
  }
  function applyDynamic() {
    if (preview && multiple && capability.allowInlineExpression)
      proposeReplacement(
        canonicalCubeSelector({
          kind: "inline_expression",
          expressionFormat: INLINE_EXPRESSION_FORMAT,
          expression: preview.expression,
        }),
      );
  }
  function parameterDeclarations(item: MemberListSummary) {
    return memberListParameters(item).flatMap((raw) => {
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) return [];
      const value = raw as Record<string, unknown>;
      if (typeof value.name !== "string" || typeof value.type !== "string")
        return [];
      return [
        {
          name: value.name,
          type: value.type,
          required: value.required !== false,
          dimensionId:
            typeof value.dimensionId === "string"
              ? value.dimensionId
              : undefined,
        } satisfies MemberListParameter,
      ];
    });
  }

  function listParameterError(item: MemberListSummary) {
    for (const parameter of parameterDeclarations(item)) {
      if (parameter.type === "MemberList")
        return `${parameter.name} requires a nested member-list value, which this selector does not yet support.`;
      if (
        parameter.required &&
        (listParameters[parameter.name] === undefined ||
          listParameters[parameter.name] === "")
      )
        return `Provide ${parameter.name}.`;
    }
    return null;
  }

  function setListParameter(
    name: string,
    value: SelectionParameterValue | undefined,
  ) {
    cancelRead();
    setListParameters((current) => {
      const next = { ...current };
      if (value === undefined) delete next[name];
      else next[name] = value;
      return next;
    });
    setEvaluatedList(null);
  }

  async function exactMemberList(item: MemberListSummary, signal: AbortSignal) {
    let exact = item;
    if (catalog.functions["metadata.member_list.read"]) {
      exact = await readProgram<MemberListSummary>(
        app,
        "metadata.member_list.read",
        { listId: item.listId },
        signal,
      );
      if (
        exact.listId !== item.listId ||
        exact.dimensionId !== dimensionId ||
        exact.stateToken !== item.stateToken ||
        exact.canonicalDigest !== item.canonicalDigest ||
        exact.currentMetadataRevision !== metadataRevision ||
        exact.policyRevision !== catalog.revisions.policy
      )
        throw new Error(
          "The selected member list changed while it was opening.",
        );
    } else if (!item.definition) {
      throw new Error(
        "This member list cannot be inspected with your current access, so it cannot be selected safely.",
      );
    }
    return exact;
  }

  async function evaluateMemberList(
    exact: MemberListSummary,
    parameters: Record<string, SelectionParameterValue>,
    signal: AbortSignal,
  ) {
    const result = await readProgram<MemberListEvaluation>(
      app,
      "metadata.member_list.evaluate",
      {
        listId: exact.listId,
        parameters,
        expectedMetadataRevision: metadataRevision,
      },
      signal,
    );
    if (
      result.listId !== exact.listId ||
      result.dimensionId !== dimensionId ||
      result.metadataRevision !== metadataRevision ||
      result.stateToken !== exact.stateToken ||
      result.canonicalDigest !== exact.canonicalDigest ||
      !Array.isArray(result.memberIds) ||
      result.memberIds.some((id) => typeof id !== "string" || !id) ||
      result.memberIds.length !== result.memberCount ||
      new Set(result.memberIds).size !== result.memberCount
    )
      throw new Error(
        "The member list changed or returned an invalid result. Reopen the list.",
      );
    return { listId: exact.listId, memberIds: result.memberIds };
  }

  async function openMemberList(item: MemberListSummary) {
    const read = beginRead();
    setBusy(true);
    setError("");
    setSelectedList(null);
    setEvaluatedList(null);
    setListParameters({});
    choose("");
    try {
      const exact = await exactMemberList(item, read.signal);
      if (!read.current()) return;
      setSelectedList(exact);
      if (!parameterDeclarations(exact).length && canEvaluateLists) {
        const result = await evaluateMemberList(exact, {}, read.signal);
        if (read.current()) setEvaluatedList(result);
      }
    } catch (reason) {
      if (read.current())
        setError(
          memberListReadError(reason, "Unable to open the member list."),
        );
    } finally {
      if (read.current()) setBusy(false);
    }
  }

  async function previewSelectedList() {
    if (!selectedList || !canEvaluateLists) return;
    const validation = listParameterError(selectedList);
    if (validation) {
      setError(validation);
      return;
    }
    const read = beginRead();
    setBusy(true);
    setEvaluatedList(null);
    setError("");
    choose("");
    try {
      const result = await evaluateMemberList(
        selectedList,
        listParameters,
        read.signal,
      );
      if (read.current()) setEvaluatedList(result);
    } catch (reason) {
      if (read.current())
        setError(
          memberListReadError(reason, "Unable to evaluate the member list."),
        );
    } finally {
      if (read.current()) setBusy(false);
    }
  }

  function memberListReadError(reason: unknown, fallback: string) {
    if (memberListReadInvalidatesCatalogue(reason)) {
      setMemberLists([]);
      setSelectedList(null);
      setEvaluatedList(null);
      setListParameters({});
      setMemberListError(
        "Close and reopen the picker to check current saved selections.",
      );
    }
    return readError(reason, fallback);
  }

  function readError(reason: unknown, fallback: string) {
    if (
      reason instanceof ApiError &&
      (reason.kind === "authentication" ||
        [
          "METADATA_SELECTION_CONTEXT_STALE",
          "METADATA_SELECTION_CURSOR_STALE",
          "METADATA_SELECTION_CHANGED_DURING_READ",
          "APPLICATION_GRANT_REQUIRED",
          "APPLICATION_UNAVAILABLE",
          "WORKSPACE_UNAVAILABLE",
          "BROWSER_IDENTITY_CHANGED",
        ].includes(reason.code))
    ) {
      setDiscovery({ key: context, ready: false });
      setReplacement(null);
      return "The application or access changed. Refresh the application and reopen the picker before selecting members.";
    }
    return reason instanceof Error ? reason.message : fallback;
  }

  const canEvaluateLists = Boolean(
    catalog.functions["metadata.member_list.evaluate"],
  );
  const canConvert =
    canCheckMembers &&
    dynamic &&
    (draftSelector?.kind === "member_list"
      ? canEvaluateLists &&
        memberLists.some((item) => item.listId === draftSelector.listId)
      : nativeAvailable);

  async function materialize(convert: boolean, confirmed = false) {
    if (
      (!canTransfer && !confirmed) ||
      (!convert && hierarchyLoading) ||
      !revisionCurrent ||
      !contextReady ||
      busy ||
      !canCheckMembers ||
      (convert ? !canConvert : dynamic)
    )
      return;
    const read = beginRead();
    setBusy(true);
    setError("");
    try {
      if (convert && draftSelector?.kind === "member_list") {
        const item = memberLists.find(
          (list) => list.listId === draftSelector.listId,
        );
        if (!item) throw new Error("This saved member list is unavailable.");
        const exact = await exactMemberList(item, read.signal);
        const result = await evaluateMemberList(
          exact,
          draftSelector.parameters,
          read.signal,
        );
        if (read.current()) addMembers(result.memberIds, [], true);
      } else if (!convert && source === "lists" && evaluatedList) {
        if (read.current()) addMembers(evaluatedList.memberIds);
      } else {
        const expression = convert
          ? draftSelector?.kind === "inline_expression"
            ? draftSelector.expression
            : draftSelector?.kind === "attribute"
              ? draftSelector
              : draftSelector?.kind === "hierarchy"
                ? ({
                    kind: draftSelector.operator,
                    hierarchyId: draftSelector.hierarchyId,
                    memberId: draftSelector.memberId,
                    includeSelf: draftSelector.includeSelf,
                  } as const)
                : null
          : preview?.expression;
        if (!expression) return;
        const { rows, selectionContextToken } = await collectSelectionRows(
          app,
          dimensionId,
          selectionRevisions,
          expression,
          explicitMaximum,
          read.signal,
          {
            initial: convert ? null : preview?.page,
            expectedContextToken: expectedContextToken(),
          },
        );
        if (read.current()) {
          rememberContext(selectionContextToken);
          rememberRows(rows);
          addMembers(
            rows.map((row) => row.memberId),
            rows,
            convert,
          );
        }
      }
    } catch (reason) {
      if (read.current())
        setError(
          convert && draftSelector?.kind === "member_list"
            ? memberListReadError(
                reason,
                "Unable to collect the complete selection.",
              )
            : readError(reason, "Unable to collect the complete selection."),
        );
    } finally {
      if (read.current()) setBusy(false);
    }
  }

  function useSelectedMemberList() {
    if (!capability.allowNamedMemberList || !selectedList) return;
    const validation = listParameterError(selectedList);
    if (validation) {
      setError(validation);
      return;
    }
    proposeReplacement(
      canonicalCubeSelector({
        kind: "member_list",
        listId: selectedList.listId,
        parameters: listParameters,
      }),
    );
  }

  const dialogTitle =
    request.title ||
    (multiple
      ? `Choose ${dimensionName} members`
      : `Choose one ${dimensionName} member`);
  const evaluatedMembers = (evaluatedList?.memberIds ?? []).flatMap((id) => {
    const member = memberById.get(id);
    return member ? [member] : [];
  });
  const filter = search.trim().toLocaleLowerCase();
  const availableRows = activeMembers.filter((member) =>
    [member.member_id, member.name, member.short_description ?? ""].some(
      (value) => value.toLocaleLowerCase().includes(filter),
    ),
  );
  const byPathLabel = (
    sourceMemberPath.length ? sourceMemberPath : [sourceMemberId]
  )
    .map((id) => memberById.get(id)?.name ?? id)
    .join(" / ");
  const actions: NavigationOperation[] = !hierarchyId
    ? ["all"]
    : sourceMemberId
      ? [
          "self",
          "is_base",
          "children",
          "descendants",
          "leaf_descendants",
          "parents",
          "ancestors",
          "siblings",
          "same_level",
          "same_generation",
        ]
      : ["all", "roots", "children", "descendants", "leaves", "unplaced"];
  const pathKey = (path: string[], edges: string[]) =>
    path.length ? JSON.stringify([path.at(-1), edges]) : "";
  const treeChildren = new Map<string, NativeMember[]>();
  for (const row of tree) {
    const key = pathKey(
      (row.pathMemberIds ?? []).slice(0, -1),
      (row.pathRelationshipIds ?? []).slice(0, -1),
    );
    const children = treeChildren.get(key) ?? [];
    children.push(row);
    treeChildren.set(key, children);
  }
  const visibleIds = new Set<string>();
  function includeVisibleBranch(row: NativeMember) {
    visibleIds.add(row.memberId);
    const key = nativeMemberKey(row);
    if (!collapsed.has(key))
      treeChildren.get(key)?.forEach(includeVisibleBranch);
  }
  if (source === "search")
    availableRows.forEach((row) => visibleIds.add(row.member_id));
  else if (source === "lists")
    evaluatedMembers.forEach((row) => visibleIds.add(row.member_id));
  else if (preview)
    preview.page.rows.forEach((row) => visibleIds.add(row.memberId));
  else if (hierarchyId && nativeAvailable && treeMode)
    treeChildren.get("")?.forEach(includeVisibleBranch);
  else if (hierarchyId && nativeAvailable)
    tree.forEach((row) => visibleIds.add(row.memberId));
  else activeMembers.forEach((row) => visibleIds.add(row.member_id));
  const hiddenChecks = [...checkedMembers].filter(
    (id) => !visibleIds.has(id),
  ).length;
  const loadedResultIds =
    (source === "lists"
      ? evaluatedList?.memberIds
      : source === "hierarchy"
        ? preview?.page.rows.map((row) => row.memberId)
        : null) ?? [];
  const eligibleResultIds = loadedResultIds.filter(
    (id) => !selectedIdSet.has(id) && memberById.has(id),
  );

  function renderSourceMember(
    id: string,
    name: string,
    detail: string | undefined,
    focused: boolean,
    focus: () => void,
    pathLabel?: string,
  ) {
    const needsIdentity =
      ambiguousMemberNames.has(name) || (placementCounts.get(id) ?? 0) > 1;
    const label = (
      <>
        <strong>{name}</strong>
        {detail && <small>{detail}</small>}
        {needsIdentity && (
          <small>
            Member {id}
            {pathLabel ? ` · placement ${pathLabel}` : ""}
          </small>
        )}
      </>
    );
    if (!canCheckMembers)
      return (
        <button
          type="button"
          aria-pressed={focused}
          aria-label={
            needsIdentity
              ? `Choose ${name} (${id})${pathLabel ? ` · ${pathLabel}` : ""}`
              : undefined
          }
          className={`member-source-choice${focused ? " selected" : ""}`}
          disabled={!canChooseSource}
          onClick={focus}
          onDoubleClick={() => {
            if (canChooseSource && capability.allowExplicitMembers)
              addMembers([id]);
          }}
        >
          {label}
        </button>
      );
    const alreadySelected = selectedIdSet.has(id);
    const suffix = pathLabel ? ` · ${pathLabel}` : ` · ${id}`;
    return (
      <div className="member-source-choice member-checkable-choice">
        <label className="member-check-label">
          <input
            type="checkbox"
            className="member-source-checkbox"
            aria-label={`Check ${name}${suffix}`}
            checked={alreadySelected || checkedMembers.has(id)}
            disabled={!canChooseSource || dynamic || alreadySelected}
            onChange={(event) =>
              toggleCheck("add", id, event.currentTarget.checked)
            }
          />
          <span>
            {label}
            {alreadySelected && <small>Already selected</small>}
          </span>
        </label>
        {source === "hierarchy" && !preview && scope && (
          <button
            type="button"
            className="member-anchor-button"
            aria-pressed={focused}
            aria-label={`Use ${name} as starting point${suffix}`}
            title="Use as starting point for native functions"
            disabled={!canChooseSource}
            onClick={focus}
          >
            ◎
          </button>
        )}
      </div>
    );
  }

  function renderFlat(id: string, name: string, detail?: string) {
    return (
      <div className="member-source-row" key={id}>
        {renderSourceMember(id, name, detail, sourceMemberId === id, () =>
          choose(id),
        )}
      </div>
    );
  }
  function renderBranch(row: NativeMember) {
    const key = nativeMemberKey(row);
    const children = treeChildren.get(key) ?? [];
    const expanded = !collapsed.has(key);
    const selected =
      sourceMemberId === row.memberId &&
      JSON.stringify(sourcePath) ===
        JSON.stringify(row.pathRelationshipIds ?? null);
    return (
      <li key={key}>
        <div className="member-source-row">
          <div className="member-source-controls">
            {children.length > 0 ? (
              <button
                type="button"
                className="member-tree-toggle"
                aria-expanded={expanded}
                aria-label={`${expanded ? "Collapse" : "Expand"} ${row.name} (${row.memberId}) · ${row.pathMemberIds?.join(" / ") ?? row.memberId} [${row.pathRelationshipIds?.join(" / ") || "root"}]`}
                onClick={() =>
                  setCollapsed((current) => {
                    const next = new Set(current);
                    if (next.has(key)) next.delete(key);
                    else next.add(key);
                    return next;
                  })
                }
              >
                {expanded ? "▾" : "▸"}
              </button>
            ) : (
              <span className="member-tree-spacer" />
            )}
          </div>
          {renderSourceMember(
            row.memberId,
            row.name,
            row.shortDescription,
            selected,
            () =>
              choose(
                row.memberId,
                row.pathRelationshipIds ?? null,
                row.pathMemberIds ?? [],
              ),
            `${row.pathMemberIds?.join(" / ") ?? row.memberId}${(placementCounts.get(row.memberId) ?? 0) > 1 ? ` [${row.pathRelationshipIds?.join(" / ") || "root"}]` : ""}`,
          )}
        </div>
        {expanded && children.length > 0 && (
          <ul>{children.map(renderBranch)}</ul>
        )}
      </li>
    );
  }

  return (
    <dialog
      className="member-selection-backdrop"
      aria-labelledby="member-selection-title"
      ref={dialogRef}
      onCancel={(event) => {
        event.preventDefault();
        event.stopPropagation();
        onCancel();
      }}
      onKeyDown={(event) => {
        if (event.key === "Escape") {
          event.preventDefault();
          event.stopPropagation();
          onCancel();
          return;
        }
        if (event.key !== "Tab") return;
        const controls = event.currentTarget.querySelectorAll<HTMLElement>(
          "button:not(:disabled), input:not(:disabled), select:not(:disabled)",
        );
        const first = controls[0];
        const last = controls[controls.length - 1];
        if (event.shiftKey && last && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (
          !event.shiftKey &&
          first &&
          document.activeElement === last
        ) {
          event.preventDefault();
          first.focus();
        }
      }}
    >
      <section className="member-selection-dialog">
        <header>
          <div>
            <small>MEMBER SELECTION · {dimensionName}</small>
            <h2 id="member-selection-title">{dialogTitle}</h2>
            <p>
              {canCheckMembers
                ? "Check members, then use the arrow to add them to the selected set."
                : "Browse the hierarchy, use native selections, or choose a saved business list."}
            </p>
          </div>
          <button
            ref={closeButton}
            type="button"
            onClick={onCancel}
            aria-label="Close member selection"
          >
            ×
          </button>
        </header>
        {(error || draft.error) && (
          <p className="inline-error member-selection-error" role="alert">
            {error || draft.error}
          </p>
        )}
        {!contextReady || !revisionCurrent ? (
          <p role="status">
            {contextLoading && revisionCurrent
              ? "Loading selection context…"
              : "The selection context could not be confirmed. Reopen the picker to try again."}
          </p>
        ) : (
          <div className="member-selection-columns">
            <section
              className="member-source-pane"
              aria-label={`Available ${dimensionName} members`}
            >
              <nav aria-label="Member sources">
                {(["hierarchy", "lists", "search"] as Source[]).map((item) => (
                  <button
                    type="button"
                    key={item}
                    className={source === item ? "active" : ""}
                    aria-pressed={source === item}
                    onClick={() => {
                      if (source === item) return;
                      cancelRead();
                      setSource(item);
                      setReplacement(null);
                      setPreview(null);
                      choose("");
                    }}
                  >
                    {item === "hierarchy"
                      ? "Hierarchy"
                      : item === "lists"
                        ? "Member lists"
                        : "Search"}
                  </button>
                ))}
              </nav>
              {canCheckMembers && (
                <div className="member-check-toolbar">
                  <span>
                    {checkedMembers.size} checked
                    {hiddenChecks ? ` · ${hiddenChecks} outside this view` : ""}
                  </span>
                  <button
                    type="button"
                    disabled={!hasCheckedMembers}
                    aria-expanded={reviewChecks}
                    onClick={() => setReviewChecks((value) => !value)}
                  >
                    Review checks
                  </button>
                  <button
                    type="button"
                    disabled={!hasCheckedMembers || !canTransfer}
                    onClick={() => {
                      setDraft((current) => ({
                        ...current,
                        add: new Set(),
                        error: "",
                      }));
                      setReviewChecks(false);
                    }}
                  >
                    Clear checks
                  </button>
                  {reviewChecks && hasCheckedMembers && (
                    <ul>
                      {[...checkedMembers].map((id) => (
                        <li key={id}>
                          <button
                            type="button"
                            disabled={!canTransfer}
                            onClick={() => toggleCheck("add", id, false)}
                          >
                            Uncheck{" "}
                            {memberById.get(id)?.name ?? "unavailable member"} (
                            {id})
                          </button>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}
              {canCheckMembers && eligibleResultIds.length > 0 && !dynamic && (
                <button
                  type="button"
                  disabled={!canChooseSource}
                  onClick={() =>
                    setDraft((current) => ({
                      ...current,
                      add: new Set([...current.add, ...eligibleResultIds]),
                      error: "",
                    }))
                  }
                >
                  Check {eligibleResultIds.length} loaded results
                </button>
              )}
              {source === "hierarchy" && (
                <>
                  <div className="member-source-toolbar">
                    {hierarchies.length > 1 ? (
                      <label>
                        Hierarchy{" "}
                        <select
                          value={hierarchyId}
                          disabled={busy}
                          onChange={(event) => {
                            cancelRead();
                            setHierarchyId(event.target.value);
                            setError("");
                          }}
                        >
                          {hierarchies.map((item) => (
                            <option
                              key={item.hierarchyId}
                              value={item.hierarchyId}
                            >
                              {item.name}
                            </option>
                          ))}
                        </select>
                      </label>
                    ) : (
                      <strong>
                        {hierarchies[0]?.name || "Authorized hierarchy"}
                      </strong>
                    )}
                    {hierarchyId && (
                      <button
                        type="button"
                        onClick={() => setTreeMode((mode) => !mode)}
                      >
                        {treeMode ? "Flat view" : "Tree view"}
                      </button>
                    )}
                  </div>
                  {scope && !hierarchyLoading && (
                    <>
                      <div className="member-source-toolbar">
                        <button
                          type="button"
                          title={scope.semanticDescription}
                          onClick={() => {
                            cancelRead();
                            choose("");
                            setPreview(null);
                          }}
                        >
                          {scope.name} top
                        </button>
                      </div>
                      <div
                        className="member-semantic-actions"
                        role="group"
                        aria-label="Native member selections"
                      >
                        <span>
                          {sourceMemberId ? byPathLabel : scope.name + " top"}
                        </span>
                        {actions.map((operation) => (
                          <button
                            key={operation}
                            type="button"
                            disabled={busy}
                            onClick={() => action(operation)}
                          >
                            {navigationLabels[operation]}
                          </button>
                        ))}
                      </div>
                    </>
                  )}
                  {preview && !hierarchyLoading ? (
                    <div className="member-list-results">
                      <strong>
                        {navigationLabels[preview.expression.operation]}:{" "}
                        {preview.page.rows.length} members loaded
                        {preview.page.hasMore
                          ? " · more available"
                          : " · complete result"}
                      </strong>
                      <p>
                        {selectorSummary(
                          {
                            kind: "inline_expression",
                            expressionFormat: INLINE_EXPRESSION_FORMAT,
                            expression: preview.expression,
                          },
                          labels,
                        )}
                      </p>
                      {preview.expression.operation === "is_base" && (
                        <p>
                          This returns the starting member only if it has no
                          eligible children; otherwise it returns no members.
                        </p>
                      )}
                      {preview.expression.operation === "leaf_descendants" && (
                        <p>
                          Base descendants are strict descendants with no
                          eligible children. The starting member is excluded
                          unless the expression explicitly includes it.
                        </p>
                      )}
                      {!preview.page.hasMore && !preview.page.rows.length && (
                        <p>
                          This is a complete empty result. Keeping the dynamic
                          rule does not select the whole dimension.
                        </p>
                      )}
                      <button
                        type="button"
                        onClick={() => {
                          cancelRead();
                          setPreview(null);
                          choose("");
                        }}
                      >
                        Back to hierarchy
                      </button>
                      {multiple && capability.allowInlineExpression && (
                        <button
                          type="button"
                          disabled={busy}
                          className="member-use-symbolic"
                          onClick={applyDynamic}
                        >
                          {draftSelector || hasCheckedMembers
                            ? "Replace selection with this dynamic rule"
                            : "Use dynamic selection"}
                        </button>
                      )}
                      {preview.page.rows.map((row) =>
                        renderFlat(
                          row.memberId,
                          row.name,
                          row.shortDescription,
                        ),
                      )}
                      {preview.page.nextCursor && (
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() =>
                            void previewNative(
                              preview.expression,
                              preview.page.nextCursor!,
                            )
                          }
                        >
                          More results
                        </button>
                      )}
                    </div>
                  ) : hierarchyLoading ? (
                    <p role="status">Loading hierarchy…</p>
                  ) : hierarchyId && nativeAvailable ? (
                    <>
                      {!hierarchyReadComplete && (
                        <p>
                          Hierarchy browsing is unavailable in this context.
                          Close and reopen the selection to retry.
                        </p>
                      )}
                      {hierarchyReadComplete && !tree.length && (
                        <p>No placements were returned for this hierarchy.</p>
                      )}
                      {hierarchyReadComplete && tree.length > 0 && (
                        <p>
                          {tree.length} placements loaded
                          {treeCursor
                            ? " · more available"
                            : " · complete result"}
                          . A shared member can have more than one placement; an
                          explicit selected set keeps each member identity once.
                        </p>
                      )}
                      <ul
                        className="member-tree"
                        aria-label="Hierarchy members"
                      >
                        {treeMode
                          ? (treeChildren.get("") ?? []).map(renderBranch)
                          : [
                              ...new Map(
                                tree.map((row) => [row.memberId, row]),
                              ).values(),
                            ].map((row) => (
                              <li key={row.memberId}>
                                {renderFlat(
                                  row.memberId,
                                  row.name,
                                  row.shortDescription,
                                )}
                              </li>
                            ))}
                      </ul>
                      {treeCursor && (
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => void loadTreePage()}
                        >
                          More hierarchy members
                        </button>
                      )}
                    </>
                  ) : (
                    <div className="member-flat-source">
                      {activeMembers.map((member) =>
                        renderFlat(
                          member.member_id,
                          member.name,
                          description(member),
                        ),
                      )}
                    </div>
                  )}
                </>
              )}
              {source === "lists" && contextReady && (
                <div className="member-list-source">
                  {memberLists.map((item) => (
                    <button
                      type="button"
                      key={item.listId}
                      className={
                        selectedList?.listId === item.listId ? "selected" : ""
                      }
                      onClick={() => void openMemberList(item)}
                    >
                      <strong>{item.name}</strong>
                      <small>
                        {memberListParameters(item).length
                          ? "Parameters required"
                          : "Governed saved member list"}
                      </small>
                    </button>
                  ))}
                  {memberListError ? (
                    <p role="status">{memberListError}</p>
                  ) : (
                    !memberLists.length && (
                      <p>
                        No published member lists are available for this
                        dimension.
                      </p>
                    )
                  )}
                  {selectedList &&
                    parameterDeclarations(selectedList).length > 0 && (
                      <fieldset className="member-list-parameters">
                        <legend>{selectedList.name} parameters</legend>
                        {parameterDeclarations(selectedList).map(
                          (parameter) => (
                            <label key={parameter.name}>
                              <span>
                                {parameter.name}
                                {parameter.required ? " · required" : ""}
                              </span>
                              {parameter.type === "Boolean" ? (
                                <select
                                  value={String(
                                    listParameters[parameter.name] ?? "",
                                  )}
                                  onChange={(event) =>
                                    setListParameter(
                                      parameter.name,
                                      event.target.value
                                        ? event.target.value === "true"
                                        : undefined,
                                    )
                                  }
                                >
                                  <option value="">Choose</option>
                                  <option value="true">True</option>
                                  <option value="false">False</option>
                                </select>
                              ) : (
                                <input
                                  value={String(
                                    listParameters[parameter.name] ?? "",
                                  )}
                                  disabled={parameter.type === "MemberList"}
                                  placeholder={
                                    parameter.dimensionId
                                      ? `${parameter.dimensionId} member`
                                      : parameter.type
                                  }
                                  onChange={(event) =>
                                    setListParameter(
                                      parameter.name,
                                      event.target.value,
                                    )
                                  }
                                />
                              )}
                            </label>
                          ),
                        )}
                        <div>
                          {Boolean(
                            catalog.functions["metadata.member_list.evaluate"],
                          ) && (
                            <button
                              type="button"
                              disabled={busy}
                              onClick={() => void previewSelectedList()}
                            >
                              Preview members
                            </button>
                          )}
                          {capability.allowNamedMemberList && (
                            <button
                              type="button"
                              disabled={Boolean(
                                listParameterError(selectedList),
                              )}
                              onClick={useSelectedMemberList}
                            >
                              Use dynamic member list
                            </button>
                          )}
                        </div>
                      </fieldset>
                    )}
                  {selectedList &&
                    parameterDeclarations(selectedList).length === 0 &&
                    capability.allowNamedMemberList && (
                      <button
                        type="button"
                        className="member-use-symbolic"
                        onClick={useSelectedMemberList}
                      >
                        Use {selectedList.name} dynamically
                      </button>
                    )}
                  {evaluatedList &&
                    evaluatedMembers.length !==
                      evaluatedList.memberIds.length && (
                      <p role="status">
                        Some result members are unavailable in the current
                        catalogue. Refresh before adding all results.
                      </p>
                    )}
                  {evaluatedList && (
                    <div className="member-list-results">
                      <strong>
                        {evaluatedList.memberIds.length} available members
                      </strong>
                      {evaluatedMembers.map((member) =>
                        renderFlat(member.member_id, member.name),
                      )}
                    </div>
                  )}
                </div>
              )}
              {source === "search" && (
                <>
                  <label className="member-search">
                    <span>Find a member</span>
                    <input
                      autoFocus
                      value={search}
                      onChange={(event) => setSearch(event.target.value)}
                      placeholder="Name, code or description"
                    />
                  </label>
                  <div className="member-flat-source">
                    {!availableRows.length && (
                      <p>No members match this search.</p>
                    )}
                    {availableRows.map((member) =>
                      renderFlat(
                        member.member_id,
                        member.name,
                        description(member),
                      ),
                    )}
                  </div>
                </>
              )}
            </section>
            <div
              className="member-transfer"
              role="group"
              aria-label="Selection transfer"
            >
              <button
                type="button"
                onClick={() =>
                  addMembers(multiple ? [...checkedMembers] : [sourceMemberId])
                }
                disabled={
                  !canChooseSource ||
                  !capability.allowExplicitMembers ||
                  dynamic ||
                  (multiple ? !hasCheckedMembers : !sourceMemberId)
                }
                aria-label={transferLabel}
                title={transferLabel}
              >
                →
                {multiple && hasCheckedMembers && (
                  <small>{checkedMembers.size}</small>
                )}
              </button>
              {canCheckMembers && !dynamic && loadedResultIds.length > 0 && (
                <button
                  type="button"
                  className="member-add-all"
                  disabled={!canChooseSource}
                  onClick={() => void materialize(false)}
                >
                  Add all results
                </button>
              )}
              {canCheckMembers && (
                <button
                  type="button"
                  disabled={!canTransfer || !draft.remove.size}
                  onClick={() => removeMembers(draft.remove)}
                  aria-label="Remove checked members"
                  title="Remove checked members"
                >
                  ←{draft.remove.size > 0 && <small>{draft.remove.size}</small>}
                </button>
              )}
            </div>
            <section
              className="member-selection-pane"
              aria-label={`Selected ${dimensionName} ${multiple ? "members" : "member"}`}
            >
              <div className="member-selection-pane-heading">
                <strong>
                  {multiple ? "Selected members" : "Selected member"}
                </strong>
                <span>
                  {draftSelector
                    ? selectedMemberIds.length
                      ? `${selectedMemberIds.length} selected`
                      : "Dynamic selection"
                    : cardinality.kind === "zero-or-more"
                      ? "None selected"
                      : "Selection required"}
                </span>
              </div>
              {exclusionSummary && (
                <section aria-label="Preserved selection exclusion">
                  <strong>Excludes: {exclusionSummary}</strong>
                  <p>
                    Existing exclusion is kept when editing includes. This
                    dialog does not change it.
                  </p>
                </section>
              )}
              {!dynamic && draftSelector && (
                <button
                  className="member-clear-selection"
                  type="button"
                  disabled={!canTransfer}
                  onClick={() => {
                    setDraft((current) => ({
                      ...current,
                      selector: null,
                      remove: new Set(),
                      message: "Selection cleared.",
                      error: "",
                    }));
                  }}
                >
                  Clear selection
                </button>
              )}
              {selectedMemberIds.length ? (
                <div className="member-selection-items">
                  {selectedMemberIds.map((id, index) => {
                    const member = memberById.get(id);
                    const name = member?.name ?? id;
                    return (
                      <article key={id} data-member-id={id}>
                        {canCheckMembers && (
                          <input
                            type="checkbox"
                            checked={draft.remove.has(id)}
                            aria-label={`Mark ${name} (${id}) for removal`}
                            disabled={!canTransfer}
                            onChange={(event) =>
                              toggleCheck(
                                "remove",
                                id,
                                event.currentTarget.checked,
                              )
                            }
                          />
                        )}
                        <div>
                          <strong>{name}</strong>
                          <small>
                            {member
                              ? `${id} · ${description(member)}`
                              : checkingSelectedMembers
                                ? "Checking this member…"
                                : "Member not confirmed"}
                          </small>
                        </div>
                        <div className="member-selection-item-actions">
                          {capability.orderMatters &&
                            selectedMemberIds.length > 1 && (
                              <>
                                <button
                                  type="button"
                                  disabled={!canTransfer || index === 0}
                                  onClick={() => moveMember(id, -1)}
                                  aria-label={`Move ${name} up`}
                                >
                                  ↑
                                </button>
                                <button
                                  type="button"
                                  disabled={
                                    !canTransfer ||
                                    index === selectedMemberIds.length - 1
                                  }
                                  onClick={() => moveMember(id, 1)}
                                  aria-label={`Move ${name} down`}
                                >
                                  ↓
                                </button>
                              </>
                            )}
                          <button
                            type="button"
                            disabled={!canTransfer}
                            onClick={() => removeMembers([id])}
                            aria-label={`Remove ${name}`}
                          >
                            ×
                          </button>
                        </div>
                      </article>
                    );
                  })}
                </div>
              ) : draftSelector ? (
                <article className="member-symbolic-selection">
                  <div>
                    <strong>{selectionSummary}</strong>
                    <small>Dynamic selection · evaluated when used</small>
                    {canConvert ? (
                      <button
                        type="button"
                        className="member-convert"
                        disabled={!canTransfer}
                        onClick={() => setReplacement(draftSelector)}
                      >
                        Convert current results to explicit members
                      </button>
                    ) : (
                      canCheckMembers && (
                        <small>
                          Conversion to explicit members is unavailable for this
                          selection.
                        </small>
                      )
                    )}
                  </div>
                  <button
                    type="button"
                    disabled={!canTransfer}
                    onClick={() =>
                      resetDraft(null, "Dynamic selection cleared.")
                    }
                    aria-label={`Remove ${selectionSummary}`}
                  >
                    ×
                  </button>
                </article>
              ) : (
                <div className="member-selection-empty">
                  {multiple
                    ? "Check members on the left, then add them here."
                    : "Choose a member on the left and move it here."}
                </div>
              )}
            </section>
          </div>
        )}
        {replacement && contextReady && (
          <div
            className="member-replacement"
            role="group"
            aria-label="Confirm selection change"
          >
            <p>
              {replacement === draftSelector
                ? "Convert this rule to a fixed list of its current members?"
                : `Replace the current selection with ${selectorSummary(replacement, labels)}?`}
            </p>
            <button type="button" onClick={() => setReplacement(null)}>
              Keep current selection
            </button>
            <button
              type="button"
              onClick={() => {
                setReplacement(null);
                if (replacement === draftSelector) void materialize(true, true);
                else resetDraft(replacement, "Dynamic rule selected.");
              }}
            >
              {replacement === draftSelector
                ? "Convert to explicit members"
                : "Replace selection"}
            </button>
          </div>
        )}
        <footer>
          <div className="member-selection-status">
            <p>
              {selectionError ||
                (dynamic
                  ? selectionSummary
                  : `${selectedMemberIds.length} selected`)}
            </p>
            {hasCheckedMembers && (
              <p>
                {checkedMembers.size} checked on the left will only be included
                after Add checked.
              </p>
            )}
            <p role="status">{busy ? "Reading selection…" : draft.message}</p>
            {currentVerification?.state === "unconfirmed" && (
              <button type="button" onClick={() => setMemberVerification(null)}>
                Retry member check
              </button>
            )}
            {busy &&
              pendingRead.current &&
              !pendingRead.current.signal.aborted && (
                <button type="button" onClick={cancelRead}>
                  Cancel read
                </button>
              )}
          </div>
          <div>
            <button type="button" onClick={onCancel}>
              Cancel
            </button>
            <button
              type="button"
              className="primary"
              disabled={
                Boolean(selectionError) || !draftSelector || !canTransfer
              }
              onClick={() => {
                if (
                  !draftSelector ||
                  !canTransfer ||
                  selectionError ||
                  applying.current
                )
                  return;
                applying.current = true;
                onApply({
                  dimensionId,
                  metadataRevision,
                  include: draftSelector,
                  exclude: preservedExclude,
                  displaySummary: exclusionSummary
                    ? `${selectionSummary} excluding (${exclusionSummary})`
                    : selectionSummary,
                });
              }}
            >
              Apply selection
            </button>
          </div>
        </footer>
      </section>
    </dialog>
  );
}
