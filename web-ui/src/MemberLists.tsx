import "./focused-workspaces.css";
import "./member-lists.css";
import { useEffect, useMemo, useRef, useState } from "react";
import { readProgram } from "./api";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import {
  NativeSelectionEditor,
  type SelectionDefinition,
} from "./NativeSelectionEditor";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import {
  useMemberListRecovery,
  type MemberListChange,
  type MemberListEffect,
  type MemberListRecorded,
} from "./member-list-recovery";
import {
  collectMemberLists,
  memberListArguments,
  memberListReadInvalidatesCatalogue,
  type MemberListPage,
  type MemberListSummary,
} from "./member-list-data";
export {
  collectMemberLists,
  memberListArguments,
  type MemberListPage,
  type MemberListSummary,
} from "./member-list-data";
import {
  ParameterFields,
  definitionParameterSchema,
  parameterInputError,
} from "./ParameterFields";
import { authoringContextKey } from "./python-authoring";
import { InexactParameterNumber, parseParameterJson } from "./exact-parameters";

type MemberListEvaluation = {
  listId: string;
  stateToken: string;
  dimensionId: string;
  memberIds: string[];
  memberCount: number;
  canonicalDigest: string;
  metadataRevision: number;
  status: string;
};

const consumerLabels = {
  list: "Member list",
  rule: "Rule",
  "saved-view": "Saved view",
  schedule: "Schedule",
  workflow: "Workflow",
};

type RetirementConsumer = { kind: keyof typeof consumerLabels; id: string };
type RetirementReview = {
  items: RetirementConsumer[];
  collectionToken: string;
  nextAfter: RetirementConsumer | null;
};
type RetirementCheck =
  | { phase: "reading" }
  | { phase: "failed"; message: string }
  | { phase: "ready"; page: RetirementReview };

function isRetirementConsumer(value: unknown): value is RetirementConsumer {
  if (!value || typeof value !== "object" || Object.keys(value).length !== 2)
    return false;
  const { kind, id } = value as Partial<RetirementConsumer>;
  return (
    typeof kind === "string" &&
    Object.hasOwn(consumerLabels, kind) &&
    typeof id === "string" &&
    id.length > 0 &&
    id.length <= 300 &&
    id === id.trim()
  );
}

function consumerKey({ kind, id }: RetirementConsumer) {
  return JSON.stringify([kind, id]);
}

function checkedRetirementPage(
  page: RetirementReview | undefined,
  previous: RetirementReview | null,
): RetirementReview {
  if (
    !page ||
    Object.keys(page).length !== 3 ||
    typeof page.collectionToken !== "string" ||
    !/^[0-9a-f]{64}$/.test(page.collectionToken) ||
    !Array.isArray(page.items) ||
    page.items.length > 100 ||
    !page.items.every(isRetirementConsumer) ||
    (page.nextAfter !== null && !isRetirementConsumer(page.nextAfter))
  )
    throw new Error(
      "The dependency review is incomplete. Check dependencies again.",
    );

  const keys = new Set(page.items.map(consumerKey));
  const last = page.items.at(-1);
  if (
    keys.size !== page.items.length ||
    (page.nextAfter &&
      (!last || consumerKey(last) !== consumerKey(page.nextAfter))) ||
    (previous &&
      (!keys.size ||
        previous.collectionToken !== page.collectionToken ||
        previous.items.some((consumer) => keys.has(consumerKey(consumer)))))
  )
    throw new Error("Dependencies changed. Start the review again.");
  return page;
}

const recordedActions = {
  Saved: "saved",
  Published: "activated",
  Inactive: "deactivated",
  Deleted: "deleted",
};

export function parseMemberListJson(
  value: string,
  label: string,
  shape: "object" | "array",
): Record<string, unknown> | unknown[] {
  let parsed: unknown;
  try {
    parsed = parseParameterJson(value);
  } catch (reason) {
    if (reason instanceof InexactParameterNumber) throw reason;
    throw new Error(`${label} must be valid JSON.`);
  }
  if (
    (shape === "object" &&
      (typeof parsed !== "object" ||
        parsed === null ||
        Array.isArray(parsed))) ||
    (shape === "array" && !Array.isArray(parsed))
  )
    throw new Error(`${label} must be a JSON ${shape}.`);
  return parsed as Record<string, unknown> | unknown[];
}

export function memberListMutationBody(
  app: ApplicationSummary,
  functionName: string,
  args: Record<string, unknown>,
  idempotencyKey: string,
) {
  return {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
    program: {
      languageVersion: 2,
      function: functionName,
      arguments: args,
    },
    idempotencyKey,
    confirmed: true,
  };
}

type MemberListsProps = {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  onRequestTransition?: (action: () => void) => void;
  onRefreshCatalog?: () => Promise<ApplicationCatalog>;
};
export function MemberLists(props: MemberListsProps) {
  const identity = JSON.stringify([
    props.app?.workspaceId,
    props.app?.applicationId,
    props.catalog?.applicationAccess.issuer,
    props.catalog?.applicationAccess.subjectId,
  ]);
  return <MemberListsWorkspace key={identity} {...props} />;
}

function MemberListsWorkspace({
  app,
  catalog,
  onRequestTransition = (action) => action(),
  onRefreshCatalog,
}: MemberListsProps) {
  const [items, setItems] = useState<MemberListSummary[]>([]),
    [read, setRead] = useState(false),
    [query, setQuery] = useState(""),
    [page, setPage] = useState(0);
  const [selected, setSelected] = useState<MemberListSummary | null>(null),
    [creating, setCreating] = useState(false);
  const contextKey = app && catalog ? authoringContextKey(app, catalog) : "";
  const [selectedContextKey, setSelectedContextKey] = useState("");
  const [draftDirty, setDraftDirty] = useState(false);
  const [draftEpoch, setDraftEpoch] = useState(0);
  const current = selectedContextKey === contextKey;
  const acceptedContext = useRef(contextKey);
  const mounted = useRef(true);
  const parameterSchema =
    selectedContextKey === contextKey
      ? definitionParameterSchema(selected?.definition?.parameters)
      : undefined;
  const [metadataRevision, setMetadataRevision] = useState<number | null>(null),
    [policyRevision, setPolicyRevision] = useState<number | null>(null);
  const [evaluationPage, setEvaluationPage] = useState(0);
  const [parameters, setParameters] = useState("{}"),
    [evaluation, setEvaluation] = useState<MemberListEvaluation | null>(null);
  const [retirementCheck, setRetirementCheck] =
    useState<RetirementCheck | null>(null);
  const retirementReview =
    retirementCheck?.phase === "ready" ? retirementCheck.page : null;
  const retirementRegion = useRef<HTMLElement | null>(null);
  const [reading, setBusy] = useState(false),
    [error, setError] = useState("");
  const [recordedMessage, setRecordedMessage] = useState("");
  const recovery = useMemberListRecovery(
    app,
    catalog,
    contextKey,
    (change, result) => {
      void settleChange(change, result);
    },
  );
  const busy = reading || recovery.busy;
  const effectDisabled = busy || recovery.pending;
  const controller = useRef<AbortController | null>(null);
  const refreshingAfterChange = useRef<AbortController | null>(null);
  useUnsavedWork(
    "member-list-evaluation-parameters",
    "Unsubmitted rule parameters",
    parameters !== "{}" && evaluation === null,
  );
  const mutationKey = useStableMutationIntentKey("member-list-ui");
  const filtered = useMemo(
    () =>
      items.filter((item) =>
        `${item.listId} ${item.name} ${item.dimensionId}`
          .toLowerCase()
          .includes(query.toLowerCase()),
      ),
    [items, query],
  );
  const start = Math.min(
    page * 50,
    Math.max(0, Math.floor((filtered.length - 1) / 50) * 50),
  );
  const canRead = Boolean(catalog?.functions["metadata.member_list.list"]);
  const canCreate = Boolean(catalog?.functions["metadata.member_list.save"]);
  const canReviewRetirement = Boolean(
    !recovery.pending &&
      selected &&
      !selected.source &&
      selected.sourceCurrent !== false &&
      current &&
      catalog?.functions["metadata.member_list.delete"] &&
      catalog.functions["metadata.member_list.read"],
  );
  function begin() {
    controller.current?.abort();
    const next = new AbortController();
    controller.current = next;
    setBusy(true);
    setError("");
    return next;
  }
  function clearSavedSelection() {
    setSelected(null);
    setEvaluation(null);
    setRetirementCheck(null);
    if (!creating) {
      setSelectedContextKey("");
      setDraftDirty(false);
      setParameters("{}");
    }
  }
  function forgetCatalogue(reason: unknown) {
    if (!memberListReadInvalidatesCatalogue(reason)) return;
    setItems([]);
    setRead(false);
    setRecordedMessage("");
    clearSavedSelection();
  }
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      controller.current?.abort();
    };
  }, []);
  useEffect(() => {
    if (acceptedContext.current === contextKey) return;
    acceptedContext.current = contextKey;
    if (
      !refreshingAfterChange.current ||
      controller.current !== refreshingAfterChange.current
    ) {
      controller.current?.abort();
      setBusy(false);
    }
    setItems([]);
    setRead(false);
    setRecordedMessage("");
    clearSavedSelection();
    setSelectedContextKey("");
  }, [contextKey]);
  async function refresh(currentCatalog = catalog) {
    if (!app || !currentCatalog?.functions["metadata.member_list.list"]) return;
    const active = begin();
    setRetirementCheck(null);
    try {
      const result = await collectMemberLists((args) =>
        readProgram<MemberListPage>(
          app,
          "metadata.member_list.list",
          args,
          active.signal,
        ),
      );
      if (active.signal.aborted) return;
      clearSavedSelection();
      setItems(result.rows);
      setMetadataRevision(currentCatalog.revisions.metadata);
      setPolicyRevision(currentCatalog.revisions.policy);
      setRead(true);
      setPage(0);
      return result.rows;
    } catch (reason) {
      if (!active.signal.aborted) {
        forgetCatalogue(reason);
        setError(
          reason instanceof Error
            ? reason.message
            : "Unable to read member lists.",
        );
      }
    } finally {
      if (!active.signal.aborted) setBusy(false);
    }
  }
  useEffect(() => {
    if (app && catalog && canRead) void refresh();
  }, [app?.workspaceId, app?.applicationId, canRead]);
  async function open(
    item: MemberListSummary,
    currentCatalog = catalog,
    acceptedKey?: string,
  ) {
    if (!app || !currentCatalog?.functions["metadata.member_list.read"]) return;
    const active = begin();
    setSelected(null);
    setCreating(false);
    setEvaluation(null);
    setRetirementCheck(null);
    try {
      const result = await readProgram<MemberListSummary>(
        app,
        "metadata.member_list.read",
        { listId: item.listId },
        active.signal,
      );
      if (active.signal.aborted) return;
      if (
        result.listId !== item.listId ||
        result.stateToken !== item.stateToken ||
        result.canonicalDigest !== item.canonicalDigest
      )
        throw new Error(
          "The selected member list changed while it was opening.",
        );
      if (
        result.currentMetadataRevision !== currentCatalog.revisions.metadata ||
        result.policyRevision !== currentCatalog.revisions.policy
      )
        throw new Error(
          "The application changed while opening this selection. Refresh the application and try again.",
        );
      setSelected(result);
      setSelectedContextKey(
        acceptedKey ?? authoringContextKey(app, currentCatalog),
      );
      setDraftDirty(false);
      setParameters("{}");
      if (result.currentMetadataRevision !== undefined)
        setMetadataRevision(result.currentMetadataRevision);
    } catch (reason) {
      if (!active.signal.aborted) {
        forgetCatalogue(reason);
        setError(
          reason instanceof Error
            ? reason.message
            : "Unable to open member list.",
        );
      }
    } finally {
      if (!active.signal.aborted) setBusy(false);
    }
  }
  async function evaluate() {
    if (
      !app ||
      !selected ||
      busy ||
      metadataRevision === null ||
      !current ||
      selected.executable !== true
    )
      return;
    const active = begin();
    setEvaluation(null);
    setEvaluationPage(0);
    try {
      const inputError = parameterInputError(parameters, parameterSchema);
      if (inputError) throw new Error(inputError);
      const values = parseMemberListJson(
        parameters,
        "Evaluation parameters",
        "object",
      );
      const result = await readProgram<MemberListEvaluation>(
        app,
        "metadata.member_list.evaluate",
        {
          listId: selected.listId,
          parameters: values,
          expectedMetadataRevision: metadataRevision,
        },
        active.signal,
      );
      if (active.signal.aborted) return;
      if (
        result.listId !== selected.listId ||
        result.stateToken !== selected.stateToken ||
        result.canonicalDigest !== selected.canonicalDigest
      )
        throw new Error(
          "The saved selection changed. Reopen it before evaluating again.",
        );
      setEvaluation(result);
    } catch (reason) {
      if (!active.signal.aborted) {
        forgetCatalogue(reason);
        setError(
          reason instanceof Error
            ? reason.message
            : "Unable to evaluate member list.",
        );
      }
    } finally {
      if (!active.signal.aborted) setBusy(false);
    }
  }
  async function mutate(
    functionName: MemberListEffect,
    listId: string,
    extra: Record<string, unknown>,
    token?: string,
  ) {
    if (!app || !catalog || effectDisabled || !current)
      throw new Error("Reopen the current selection before changing it.");
    const { issuer, subjectId } = catalog.applicationAccess;
    if (!issuer || !subjectId)
      throw new Error(
        "Refresh the application to confirm the current account.",
      );
    setRetirementCheck(null);
    setRecordedMessage("");
    setError("");
    const args = {
      ...extra,
      ...(token ? { expectedStateToken: token } : {}),
      expectedMetadataRevision: metadataRevision ?? catalog.revisions.metadata,
      expectedPolicyRevision: policyRevision ?? catalog.revisions.policy,
    };
    const body = memberListMutationBody(
      app,
      functionName,
      args,
      mutationKey({ contextKey, functionName, args }),
    );
    await recovery.submit(body, {
      functionName,
      listId,
      actorId: subjectId,
      issuer,
      previousCommit: catalog.revisions.commit,
      metadataRevision: args.expectedMetadataRevision,
      policyRevision: args.expectedPolicyRevision,
    });
  }

  async function settleChange(
    change: MemberListChange,
    result: MemberListRecorded,
  ) {
    if (!app || !catalog) return;
    const active = begin();
    setRecordedMessage(
      `Member list ${change.listId} ${recordedActions[result.status]}.`,
    );
    setSelected(null);
    setCreating(false);
    setDraftDirty(false);
    setEvaluation(null);
    setSelectedContextKey("");
    try {
      let nextCatalog = catalog;
      if (onRefreshCatalog) {
        refreshingAfterChange.current = active;
        try {
          nextCatalog = await onRefreshCatalog();
        } finally {
          if (refreshingAfterChange.current === active)
            refreshingAfterChange.current = null;
        }
      } else {
        let pins = result.pins;
        if (!pins) {
          const snapshot = await readProgram<{
            metadataRevision: number;
            policyRevision: number;
          }>(app, "application.state.read", {}, active.signal);
          pins = {
            metadata: snapshot.metadataRevision,
            policy: snapshot.policyRevision,
          };
        }
        nextCatalog = {
          ...catalog,
          revisions: { ...catalog.revisions, ...pins },
        };
      }
      active.signal.throwIfAborted();
      if (!mounted.current) return;
      const nextKey = onRefreshCatalog
        ? authoringContextKey(app, nextCatalog)
        : contextKey;
      acceptedContext.current = nextKey;
      const rows = await refresh(nextCatalog);
      const item =
        result.status === "Deleted"
          ? undefined
          : rows?.find((row) => row.listId === change.listId);
      if (item) await open(item, nextCatalog, nextKey);
    } catch {
      if (!active.signal.aborted)
        setError(
          "The change is recorded. Refresh member lists to see the current definitions.",
        );
    } finally {
      if (
        mounted.current &&
        controller.current === active &&
        !active.signal.aborted
      )
        setBusy(false);
    }
  }
  async function saveNative(definition: SelectionDefinition): Promise<false> {
    await mutate(
      "metadata.member_list.save",
      definition.listId,
      { definition },
      selected?.stateToken,
    );
    // The editor closes only when the original outcome is confirmed.
    return false;
  }
  async function reviewRetirement(continuePage = false) {
    if (
      !app ||
      !catalog ||
      !selected ||
      !canReviewRetirement ||
      busy ||
      draftDirty
    )
      return;
    const previous = continuePage ? retirementReview : null;
    if (continuePage && !previous?.nextAfter) return;
    const continuation = previous?.nextAfter
      ? {
          after: previous.nextAfter,
          expectedCollectionToken: previous.collectionToken,
        }
      : {};
    retirementRegion.current?.focus();
    const active = begin();
    setRetirementCheck({ phase: "reading" });
    try {
      const result = await readProgram<
        MemberListSummary & { retirementConsumers?: RetirementReview }
      >(
        app,
        "metadata.member_list.read",
        { listId: selected.listId, retirementConsumers: continuation },
        active.signal,
      );
      if (active.signal.aborted) return;
      if (
        result.listId !== selected.listId ||
        result.stateToken !== selected.stateToken ||
        result.currentMetadataRevision !== catalog.revisions.metadata ||
        result.policyRevision !== catalog.revisions.policy
      )
        throw new Error(
          "The application changed. Reopen the selection before reviewing its dependencies.",
        );
      setRetirementCheck({
        phase: "ready",
        page: checkedRetirementPage(result.retirementConsumers, previous),
      });
    } catch (reason) {
      if (!active.signal.aborted) {
        const message =
          reason instanceof Error
            ? reason.message
            : "Unable to review member-list dependencies.";
        if (memberListReadInvalidatesCatalogue(reason)) {
          forgetCatalogue(reason);
          setError(message);
        } else {
          setRetirementCheck({ phase: "failed", message });
        }
      }
    } finally {
      if (!active.signal.aborted) setBusy(false);
    }
  }
  async function lifecycle(action: "activate" | "deactivate" | "delete") {
    if (!selected || selected.source || !current || effectDisabled) return;
    if (
      action === "delete" &&
      (!retirementReview ||
        retirementReview.items.length ||
        retirementReview.nextAfter)
    )
      return;
    if (
      (action === "delete" || action === "deactivate") &&
      !window.confirm(
        `${action === "delete" ? "Delete" : "Deactivate"} this member list?`,
      )
    )
      return;
    try {
      await mutate(
        `metadata.member_list.${action}`,
        selected.listId,
        { listId: selected.listId },
        selected.stateToken,
      );
    } catch (reason) {
      if (mounted.current)
        setError(
          reason instanceof Error
            ? reason.message
            : "Unable to change member list.",
        );
    }
  }
  if (!app || !catalog) return null;
  return (
    <section className="member-lists-workspace" aria-label="Member lists">
      <div className="section-heading-row">
        <div>
          <h2>Saved selections</h2>
          <p>
            Name reusable business selections and evaluate their current active
            definitions.
          </p>
        </div>
        <div>
          <button
            disabled={busy || !canRead}
            onClick={() => onRequestTransition(() => void refresh())}
          >
            Refresh member lists
          </button>
          {canCreate && (
            <button
              disabled={effectDisabled}
              onClick={() =>
                onRequestTransition(() => {
                  setSelected(null);
                  setDraftDirty(false);
                  setCreating(true);
                  setDraftEpoch((value) => value + 1);
                  setSelectedContextKey(contextKey);
                  setMetadataRevision(catalog.revisions.metadata);
                  setPolicyRevision(catalog.revisions.policy);
                  setEvaluation(null);
                  setRetirementCheck(null);
                  setParameters("{}");
                })
              }
            >
              New member list
            </button>
          )}
        </div>
      </div>
      {error && <p role="alert">{error}</p>}
      {canRead && acceptedContext.current === contextKey && recordedMessage && (
        <p role="status">{recordedMessage}</p>
      )}
      {recovery.message && <p role="status">{recovery.message}</p>}
      {recovery.pending && (
        <section
          className="member-list-outcome"
          aria-label="Member-list change outcome"
        >
          {!recovery.busy && !recovery.message && (
            <p>The original member-list change may have completed.</p>
          )}
          <p>
            Operation reference <code>{recovery.operationId}</code>
          </p>
          {recovery.canCheckReceipt && (
            <button
              disabled={busy}
              onClick={() => void recovery.checkReceipt()}
            >
              Read original member-list outcome
            </button>
          )}
          {recovery.retryReady && (
            <button disabled={busy} onClick={() => void recovery.retry()}>
              Retry original member-list request
            </button>
          )}
          {recovery.review && (
            <button
              disabled={busy}
              onClick={() => void recovery.copyOriginal()}
            >
              Copy original member-list request for MCP
            </button>
          )}
          {recovery.canCloseRecovery && (
            <button disabled={busy} onClick={() => recovery.closeRecovery()}>
              Close unresolved member-list request
            </button>
          )}
        </section>
      )}
      {busy && <p role="status">Working…</p>}
      {read && acceptedContext.current === contextKey && (
        <>
          <label>
            Find member list
            <input
              aria-label="Find member list"
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setPage(0);
              }}
            />
          </label>
          <table className="react-cube-grid">
            <thead>
              <tr>
                <th>Name</th>
                <th>Dimension</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(start, start + 50).map((item) => (
                <tr key={item.listId}>
                  <th>
                    <button
                      disabled={recovery.pending}
                      onClick={() => onRequestTransition(() => void open(item))}
                    >
                      {item.name}
                    </button>
                  </th>
                  <td>{item.dimensionId}</td>
                  <td>{item.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!items.length && (
            <p>
              No saved selections. Create one for a reusable business scope.
            </p>
          )}
          <button
            disabled={start === 0}
            onClick={() => setPage(start / 50 - 1)}
          >
            Previous member lists
          </button>
          <button
            disabled={start + 50 >= filtered.length}
            onClick={() => setPage(start / 50 + 1)}
          >
            Next member lists
          </button>
        </>
      )}
      {(creating || (selected && current)) && (
        <article className="program-inspector" aria-label="Member list detail">
          <h3>{selected ? selected.name : "New member list"}</h3>
          <button
            disabled={recovery.pending}
            onClick={() =>
              onRequestTransition(() => {
                setSelected(null);
                setCreating(false);
                setParameters("{}");
                setEvaluation(null);
                setRetirementCheck(null);
              })
            }
          >
            Close member list
          </button>
          {selected?.source || selected?.sourceCurrent === false ? (
            <p>
              This selection is managed by its Python source and is read-only in
              this workspace. Open its source in Rules to change it.
            </p>
          ) : creating || selected?.definition ? (
            <NativeSelectionEditor
              key={
                selected
                  ? `${selected.listId}:${selected.stateToken}`
                  : `new:${draftEpoch}`
              }
              app={app}
              catalog={catalog}
              initial={selected?.definition ?? undefined}
              current={current}
              busy={effectDisabled}
              onSave={saveNative}
              onDirtyChange={setDraftDirty}
            />
          ) : (
            <p>This selection has no current definition to edit.</p>
          )}
          {!current && (
            <p role="status">
              Reopen the selection from the current list to refresh its metadata
              and access.
            </p>
          )}
          {selected && current && (
            <>
              {!selected.source &&
                selected.sourceCurrent !== false &&
                Boolean(catalog.functions["metadata.member_list.activate"]) && (
                  <button
                    disabled={
                      effectDisabled ||
                      draftDirty ||
                      selected.active === true ||
                      selected.valid !== true
                    }
                    onClick={() => void lifecycle("activate")}
                  >
                    Activate member list
                  </button>
                )}
              {!selected.source &&
                selected.sourceCurrent !== false &&
                Boolean(
                  catalog.functions["metadata.member_list.deactivate"],
                ) && (
                  <button
                    disabled={
                      effectDisabled || draftDirty || selected.active !== true
                    }
                    onClick={() => void lifecycle("deactivate")}
                  >
                    Deactivate member list
                  </button>
                )}
              {canReviewRetirement && (
                <section
                  aria-label="Member-list retirement"
                  tabIndex={-1}
                  ref={retirementRegion}
                >
                  <button
                    disabled={busy || draftDirty}
                    onClick={() => void reviewRetirement()}
                  >
                    {retirementCheck && retirementCheck.phase !== "reading"
                      ? "Check dependencies again"
                      : "Review member-list deletion"}
                  </button>
                  {retirementCheck?.phase === "reading" && (
                    <p role="status">Checking current dependencies…</p>
                  )}
                  {retirementCheck?.phase === "failed" && (
                    <p className="inline-error" role="alert">
                      {retirementCheck.message}
                    </p>
                  )}
                  {retirementReview &&
                    (retirementReview.items.length ? (
                      <>
                        <p role="status">
                          Update these dependencies before deleting the member
                          list.
                        </p>
                        <ul
                          aria-label="Member-list dependencies"
                          className="member-list-dependencies"
                        >
                          {retirementReview.items.map(({ kind, id }) => (
                            <li key={`${kind}:${id}`}>
                              {consumerLabels[kind]} {id}
                            </li>
                          ))}
                        </ul>
                        {retirementReview.nextAfter && (
                          <button
                            disabled={busy || draftDirty}
                            onClick={() => void reviewRetirement(true)}
                          >
                            Next dependencies
                          </button>
                        )}
                      </>
                    ) : (
                      <>
                        <p role="status">
                          No current definitions use this member list.
                        </p>
                        <button
                          disabled={
                            busy ||
                            draftDirty ||
                            Boolean(retirementReview.nextAfter)
                          }
                          onClick={() => void lifecycle("delete")}
                        >
                          Delete member list
                        </button>
                      </>
                    ))}
                </section>
              )}
              {Boolean(catalog.functions["metadata.member_list.evaluate"]) && (
                <section aria-label="Evaluate member list">
                  <ParameterFields
                    label="Evaluation parameters"
                    advancedLabel="Member-list evaluation parameters"
                    value={parameters}
                    schema={parameterSchema}
                    disabled={busy}
                    onChange={(value) => {
                      setParameters(value);
                      setEvaluation(null);
                    }}
                  />
                  <button
                    disabled={
                      busy || draftDirty || selected.executable !== true
                    }
                    onClick={() => void evaluate()}
                  >
                    Evaluate member list
                  </button>
                </section>
              )}
            </>
          )}
          {evaluation && (
            <section aria-label="Member-list evaluation">
              <p>{evaluation.memberCount} selected members</p>
              <ul>
                {evaluation.memberIds
                  .slice(evaluationPage * 100, (evaluationPage + 1) * 100)
                  .map((member) => (
                    <li key={member}>{member}</li>
                  ))}
              </ul>
              <button
                disabled={evaluationPage === 0}
                onClick={() => setEvaluationPage((value) => value - 1)}
              >
                Previous selected members
              </button>
              <button
                disabled={
                  (evaluationPage + 1) * 100 >= evaluation.memberIds.length
                }
                onClick={() => setEvaluationPage((value) => value + 1)}
              >
                Next selected members
              </button>
            </section>
          )}
        </article>
      )}
    </section>
  );
}
