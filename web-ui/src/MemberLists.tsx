import "./focused-workspaces.css";
import "./member-lists.css";
import { useEffect, useMemo, useRef, useState } from "react";
import { readProgram, requestAdmittedEffect } from "./api";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import type { PythonSourceBinding } from "./PythonDefinitionEditor";
import {
  NativeSelectionEditor,
  type SelectionDefinition,
} from "./NativeSelectionEditor";
import { useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";
import { collectAllContinuations } from "./continuation";
import {
  ParameterFields,
  definitionParameterSchema,
  parameterInputError,
} from "./ParameterFields";
import { authoringContextKey } from "./python-authoring";
import { InexactParameterNumber, parseParameterJson } from "./exact-parameters";

type MemberListSummary = {
  listId: string;
  stateToken: string;
  dimensionId: string;
  name: string;
  definition: Record<string, unknown> | null;
  canonicalDigest: string;
  status: string;
  active?: boolean;
  valid?: boolean;
  executable?: boolean;
  sourceCurrent?: boolean;
  reason?: string | null;
  source?: PythonSourceBinding | null;
  currentMetadataRevision?: number;
  policyRevision?: number;
};

type MemberListPage = {
  memberLists: MemberListSummary[];
  nextAfterListId: string | null;
  collectionToken: string;
};

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

type MemberListMutation = {
  result: {
    listId: string;
    stateToken: string | null;
    status: string;
    canonicalDigest?: string;
    metadataRevision?: number;
    policyRevision: number;
  };
};

export function memberListArguments(
  afterListId?: string | null,
  expectedCollectionToken?: string,
) {
  return afterListId
    ? {
        limit: 100,
        afterListId,
        expectedCollectionToken,
      }
    : { limit: 100 };
}

export function collectMemberLists(
  readPage: (
    arguments_: ReturnType<typeof memberListArguments>,
  ) => Promise<MemberListPage>,
) {
  let token: string | undefined;
  return collectAllContinuations<MemberListPage, MemberListSummary>({
    label: "Member lists",
    readPage: async (cursor) => {
      const page = await readPage(memberListArguments(cursor, token));
      token = page.collectionToken;
      return page;
    },
    rows: (page) => page.memberLists,
    nextCursor: (page) => page.nextAfterListId,
    rowIdentity: (item) => item.listId,
    consistencyIdentity: (page) => page.collectionToken,
  });
}

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
  const [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const controller = useRef<AbortController | null>(null);
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
  function begin() {
    controller.current?.abort();
    const next = new AbortController();
    controller.current = next;
    setBusy(true);
    setError("");
    return next;
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
    controller.current?.abort();
    setBusy(false);
    setItems([]);
    setRead(false);
    setEvaluation(null);
    setSelectedContextKey("");
  }, [contextKey]);
  async function refresh(currentCatalog = catalog) {
    if (!app || !canRead || !catalog) return;
    const active = begin();
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
      setItems(result.rows);
      setMetadataRevision(currentCatalog!.revisions.metadata);
      setPolicyRevision(currentCatalog!.revisions.policy);
      setRead(true);
      setPage(0);
      return result.rows;
    } catch (reason) {
      if (!active.signal.aborted)
        setError(
          reason instanceof Error
            ? reason.message
            : "Unable to read member lists.",
        );
    } finally {
      if (!active.signal.aborted) setBusy(false);
    }
  }
  async function open(
    item: MemberListSummary,
    currentCatalog = catalog,
    acceptedKey?: string,
  ) {
    if (!app || !catalog?.functions["metadata.member_list.read"]) return;
    const active = begin();
    setSelected(null);
    setCreating(false);
    setEvaluation(null);
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
        result.currentMetadataRevision !== currentCatalog!.revisions.metadata ||
        result.policyRevision !== currentCatalog!.revisions.policy
      )
        throw new Error(
          "The application changed while opening this selection. Refresh the application and try again.",
        );
      setSelected(result);
      setSelectedContextKey(
        acceptedKey ?? authoringContextKey(app, currentCatalog!),
      );
      setDraftDirty(false);
      setParameters("{}");
      if (result.currentMetadataRevision !== undefined)
        setMetadataRevision(result.currentMetadataRevision);
    } catch (reason) {
      if (!active.signal.aborted)
        setError(
          reason instanceof Error
            ? reason.message
            : "Unable to open member list.",
        );
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
      if (!active.signal.aborted)
        setError(
          reason instanceof Error
            ? reason.message
            : "Unable to evaluate member list.",
        );
    } finally {
      if (!active.signal.aborted) setBusy(false);
    }
  }
  async function mutate(
    functionName: string,
    extra: Record<string, unknown>,
    token?: string,
  ) {
    if (!app || !catalog || busy || !current)
      throw new Error("Reopen the current selection before changing it.");
    const active = begin();
    const args = {
      ...extra,
      ...(token ? { expectedStateToken: token } : {}),
      expectedMetadataRevision: metadataRevision ?? catalog.revisions.metadata,
      expectedPolicyRevision: policyRevision ?? catalog.revisions.policy,
    };
    try {
      const result = await requestAdmittedEffect<MemberListMutation>(
        "/api/metadata-action",
        memberListMutationBody(
          app,
          functionName,
          args,
          mutationKey({ contextKey, functionName, args }),
        ),
        active.signal,
      );
      active.signal.throwIfAborted();
      // The accepted write owns these new pins; an unrelated context change
      // still invalidates reads and drafts through the context effect.
      const receiptCatalog = {
        ...catalog,
        revisions: {
          ...catalog.revisions,
          metadata:
            result.result.metadataRevision ?? catalog.revisions.metadata,
          policy: result.result.policyRevision ?? catalog.revisions.policy,
        },
      };
      const expectedKey = onRefreshCatalog
        ? authoringContextKey(app, receiptCatalog)
        : contextKey;
      acceptedContext.current = expectedKey;
      const nextCatalog = onRefreshCatalog
        ? await onRefreshCatalog()
        : receiptCatalog;
      active.signal.throwIfAborted();
      if (!mounted.current) return;
      const nextKey = onRefreshCatalog
        ? authoringContextKey(app, nextCatalog)
        : contextKey;
      acceptedContext.current = nextKey;
      setSelected(null);
      setCreating(false);
      setEvaluation(null);
      const rows = await refresh(nextCatalog);
      const item = rows?.find((row) => row.listId === result.result.listId);
      if (item) await open(item, nextCatalog, nextKey);
    } finally {
      if (
        mounted.current &&
        controller.current === active &&
        !active.signal.aborted
      )
        setBusy(false);
    }
  }
  async function saveNative(definition: SelectionDefinition) {
    await mutate(
      "metadata.member_list.save",
      { definition },
      selected?.stateToken,
    );
  }
  async function lifecycle(action: "activate" | "deactivate" | "delete") {
    if (!selected || selected.source || !current) return;
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
            Read member lists
          </button>
          {canCreate && (
            <button
              disabled={busy}
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
      {busy && <p role="status">Working…</p>}
      {read && (
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
      {(creating || selected) && (
        <article className="program-inspector" aria-label="Member list detail">
          <h3>{selected ? selected.name : "New member list"}</h3>
          <button
            onClick={() =>
              onRequestTransition(() => {
                setSelected(null);
                setCreating(false);
                setParameters("{}");
                setEvaluation(null);
              })
            }
          >
            Close member list
          </button>
          {selected?.source || selected?.sourceCurrent === false ? (
            <p>
              This legacy selection is owned by source or needs ownership
              reconciliation. It is read-only here until that reconciliation is
              completed.
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
              busy={busy}
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
              <details>
                <summary>Selection definition inspection</summary>
                <pre role="region" aria-label="Member-list definition">
                  {JSON.stringify(selected.definition, null, 2)}
                </pre>
              </details>
              {!selected.source &&
                selected.sourceCurrent !== false &&
                Boolean(catalog.functions["metadata.member_list.activate"]) && (
                  <button
                    disabled={
                      busy ||
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
                    disabled={busy || draftDirty || selected.active !== true}
                    onClick={() => void lifecycle("deactivate")}
                  >
                    Deactivate member list
                  </button>
                )}
              {!selected.source &&
                selected.sourceCurrent !== false &&
                Boolean(catalog.functions["metadata.member_list.delete"]) && (
                  <button
                    disabled={busy || draftDirty}
                    onClick={() => void lifecycle("delete")}
                  >
                    Delete member list
                  </button>
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
