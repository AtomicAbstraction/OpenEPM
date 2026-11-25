import { useEffect, useMemo, useRef, useState } from "react";
import {
  ApiError,
  prepareAdmittedProgramEffect,
  readCatalog,
  replayAdmittedEffect,
  request,
  type AdmittedEffectPacket,
} from "./api";
import { parseExactScope, sourceProgramBody } from "./DataLoad";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { usePreservedDraft, type DraftRecoveryLease } from "./unsaved-work";
import { ExactScopeSelector, serializedExactScope } from "./ExactScopeSelector";
import { transferAction } from "./data-transfer-action";
import "./data-workspaces.css";

type ExportState = {
  requestId: string;
  artifactId: string;
  status: string;
  cancelRequested: boolean;
  result: ExportResult | null;
  packet: AdmittedEffectPacket | null;
  cancelPacket: AdmittedEffectPacket | null;
};

const exportActivityMessages = {
  request: "Submitting snapshot request…",
  reconcileRequest: "Checking the original export request…",
  status: "Checking export status…",
  cancel: "Requesting export cancellation…",
  reconcileCancel: "Reconciling the original cancellation…",
  download: "Downloading snapshot bundle…",
};

type ExportResult = {
  requestId: string;
  status: string;
  snapshotRevision: number;
  metadataRevision: number;
  securityRevision: number;
  expiresAt: number;
  pageCount: number;
  cancelRequested: boolean;
  artifactId: string | null;
  errorCode: string | null;
  duplicate?: boolean;
};

const terminalExport = (status: string) =>
  ["Completed", "Failed", "Cancelled"].includes(status);
const EMPTY_EXPORT: ExportState = {
  requestId: "",
  artifactId: "",
  status: "",
  cancelRequested: false,
  result: null,
  packet: null,
  cancelPacket: null,
};

export function exactExportResult(
  value: unknown,
  expected: {
    expectedSnapshotRevision: number;
    expectedMetadataRevision: number;
    expiresAt: number;
  },
  prior: ExportResult | null = null,
): ExportResult {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Export outcome is invalid.");
  const result = value as ExportResult;
  const nonnegative = (item: unknown) =>
    typeof item === "number" && Number.isSafeInteger(item) && item >= 0;
  if (
    typeof result.requestId !== "string" ||
    !/^[0-9a-f]{32}$/.test(result.requestId) ||
    ![
      "Accepted",
      "Reading",
      "Prepared",
      "Publishing",
      "Completed",
      "Failed",
      "Cancelled",
    ].includes(result.status) ||
    ![
      result.snapshotRevision,
      result.metadataRevision,
      result.securityRevision,
      result.expiresAt,
      result.pageCount,
    ].every(nonnegative) ||
    result.snapshotRevision !== expected.expectedSnapshotRevision ||
    result.metadataRevision !== expected.expectedMetadataRevision ||
    result.expiresAt !== expected.expiresAt ||
    typeof result.cancelRequested !== "boolean" ||
    !(
      result.artifactId === null ||
      (typeof result.artifactId === "string" &&
        /^[0-9a-f]{32}$/.test(result.artifactId))
    ) ||
    (result.status === "Completed" && !result.artifactId) ||
    !(result.errorCode === null || typeof result.errorCode === "string") ||
    (result.duplicate !== undefined && typeof result.duplicate !== "boolean") ||
    (prior &&
      (result.requestId !== prior.requestId ||
        result.securityRevision !== prior.securityRevision ||
        result.pageCount < prior.pageCount ||
        (prior.cancelRequested && !result.cancelRequested) ||
        (prior.artifactId && result.artifactId !== prior.artifactId) ||
        (terminalExport(prior.status) && result.status !== prior.status)))
  )
    throw new Error("Export outcome does not match the original request.");
  return result;
}

function resultExpectation(result: ExportResult) {
  return {
    expectedSnapshotRevision: result.snapshotRevision,
    expectedMetadataRevision: result.metadataRevision,
    expiresAt: result.expiresAt,
  };
}

function exportStateFromResult(
  result: ExportResult,
  cancelPacket: AdmittedEffectPacket | null = null,
): ExportState {
  return {
    result,
    requestId: result.requestId,
    artifactId: result.artifactId || "",
    status: result.status,
    cancelRequested: result.cancelRequested,
    packet: null,
    cancelPacket:
      result.cancelRequested || terminalExport(result.status)
        ? null
        : cancelPacket,
  };
}

type PayloadPage = {
  artifactId: string;
  ordinal: number;
  hasMore: boolean;
  nextCursor: string | null;
  [key: string]: unknown;
};

type ExportPageReader = (
  arguments_: { artifactId: string } | { cursor: string },
) => Promise<PayloadPage>;

export async function streamCompleteExportBundle(
  artifactId: string,
  manifest: Record<string, unknown>,
  readPage: ExportPageReader,
  write: (value: string) => Promise<void>,
): Promise<number> {
  if (
    !/^[0-9a-f]{32}$/.test(artifactId) ||
    manifest.contractVersion !== "openepm-complete-export-manifest-v2" ||
    typeof manifest.manifestDigest !== "string" ||
    !/^[0-9a-f]{64}$/.test(manifest.manifestDigest)
  )
    throw new Error("Export artifact identity is invalid.");
  await write(
    `{"contractVersion":"openepm-export-download-v1","artifactId":${JSON.stringify(artifactId)},"manifest":${JSON.stringify(manifest)},"chunks":[`,
  );
  let cursor: string | null = null;
  let ordinal = 0;
  const seenCursors = new Set<string>();
  for (;;) {
    const page = await readPage(cursor ? { cursor } : { artifactId });
    if (
      !page ||
      page.artifactId !== artifactId ||
      page.manifestDigest !== manifest.manifestDigest ||
      page.ordinal !== ordinal ||
      typeof page.hasMore !== "boolean" ||
      !("chunk" in page) ||
      (page.hasMore
        ? typeof page.nextCursor !== "string" || !page.nextCursor
        : page.nextCursor !== null)
    )
      throw new Error("Export payload continuation is incomplete or invalid.");
    const { nextCursor, ...downloadable } = page;
    await write(`${ordinal ? "," : ""}${JSON.stringify(downloadable)}`);
    ordinal += 1;
    if (!page.hasMore) break;
    if (seenCursors.has(nextCursor!))
      throw new Error("Export payload continuation repeated a cursor.");
    seenCursors.add(nextCursor!);
    cursor = nextCursor;
  }
  await write(`],"chunkCount":${ordinal}}`);
  return ordinal;
}

type BrowserWritableFile = {
  write(value: string): Promise<void>;
  close(): Promise<void>;
  abort?(reason?: unknown): Promise<void>;
};

type SaveFileHandle = { createWritable(): Promise<BrowserWritableFile> };

type FilePickerWindow = Window & {
  showSaveFilePicker?: (options: {
    suggestedName: string;
    types: Array<{
      description: string;
      accept: Record<string, string[]>;
    }>;
  }) => Promise<SaveFileHandle>;
};

const FALLBACK_DOWNLOAD_LIMIT = 128 * 1024 * 1024;

export function exportFileName(applicationName: string): string {
  const safeName = applicationName
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return `openepm-${safeName || "application"}-snapshot.json`;
}

export function exportRequestArguments(
  members: Record<string, string>,
  revisions: { metadataRevision: number; commitRevision: number },
  expirySeconds: number,
  nowSeconds: number,
  idempotencyKey: string,
) {
  return {
    idempotencyKey,
    members,
    expectedSnapshotRevision: revisions.commitRevision,
    expectedMetadataRevision: revisions.metadataRevision,
    expiresAt: nowSeconds + expirySeconds,
  };
}

export function DataExport({
  app,
  catalog,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
}) {
  const [scopeText, setScopeText] = useState("");
  const [scopeAll, setScopeAll] = useState(false);
  const [expirySeconds, setExpirySeconds] = useState(3600);
  const [reviewed, setReviewed] = useState(false);
  const [reviewedCancel, setReviewedCancel] = useState(false);
  const [intentKey, setIntentKey] = useState(
    () => `export-ui-${crypto.randomUUID()}`,
  );
  const [intentIssuedAt, setIntentIssuedAt] = useState(() =>
    Math.floor(Date.now() / 1000),
  );
  const [state, setState] = useState<ExportState>(EMPTY_EXPORT);
  const [downloadedChunks, setDownloadedChunks] = useState<number | null>(null);
  const downloadComplete = downloadedChunks !== null;
  const [activity, setActivity] = useState<
    keyof typeof exportActivityMessages | null
  >(null);
  const busy = activity !== null;
  const [error, setError] = useState("");

  const functions = catalog?.functions || {};
  const canRequest = Object.hasOwn(functions, "facts.transfer.export.request");
  const canRead = Object.hasOwn(functions, "facts.transfer.export.read");
  const canCancel = Object.hasOwn(functions, "facts.transfer.export.cancel");
  const canDownload = Object.hasOwn(
    functions,
    "facts.transfer.export.payload.page",
  );
  const canReadManifest = Object.hasOwn(
    functions,
    "facts.transfer.export.manifest.read",
  );
  const scope = useMemo(() => {
    try {
      return parseExactScope(scopeText);
    } catch {
      return null;
    }
  }, [scopeText]);
  const scopeReady = scopeAll || Boolean(scope && Object.keys(scope).length);
  const [missingRequest, setMissingRequest] = useState<string | null>(null);
  const requestReady = Boolean(
    app &&
      canRequest &&
      (state.packet
        ? missingRequest === state.packet.body.idempotencyKey
        : !state.requestId && scopeReady && reviewed),
  );
  const cancellable =
    ["Accepted", "Reading", "Prepared", "Publishing"].includes(state.status) &&
    !state.cancelRequested;
  const unresolved = Boolean(
    state.packet ||
      state.cancelPacket ||
      (state.requestId && !terminalExport(state.status)),
  );
  const identity = JSON.stringify([
    app?.workspaceId,
    app?.applicationId,
    catalog?.applicationAccess.issuer,
    catalog?.applicationAccess.subjectId,
  ]);
  const context = JSON.stringify([
    identity,
    catalog?.accessContext,
    catalog?.revisions,
    Object.keys(functions).sort(),
  ]);
  const live = useRef({ identity, context, generation: 0, mounted: true });
  const transfer = useRef<{ abort: () => void } | null>(null);
  if (live.current.context !== context) live.current.generation += 1;
  live.current.identity = identity;
  live.current.context = context;
  useEffect(() => {
    live.current.mounted = true;
    return () => {
      live.current.mounted = false;
      live.current.generation += 1;
      transfer.current?.abort();
    };
  }, []);
  const previousIdentity = useRef(identity);
  useEffect(() => {
    transfer.current?.abort();
    if (previousIdentity.current !== identity) {
      previousIdentity.current = identity;
      setScopeText("");
      setScopeAll(false);
      setExpirySeconds(3600);
      setState(EMPTY_EXPORT);
      setIntentKey(`export-ui-${crypto.randomUUID()}`);
      setIntentIssuedAt(Math.floor(Date.now() / 1000));
    }
    setReviewed(false);
    setReviewedCancel(false);
    setActivity(null);
    setError("");
    setDownloadedChunks(null);
    setMissingRequest(null);
  }, [identity, context]);
  const draftValue = {
    scopeText,
    scopeAll,
    expirySeconds,
    intentKey,
    intentIssuedAt,
    state,
    identity,
  };
  const recovery = usePreservedDraft(
    app?.workspaceId || "none",
    app?.applicationId || "none",
    "data-export",
    "Export snapshot and recovery",
    Boolean(
      scopeText ||
        scopeAll ||
        state.requestId ||
        unresolved ||
        expirySeconds !== 3600,
    ),
    draftValue,
    (draft) => {
      if (draft.identity !== identity) return;
      live.current.generation += 1;
      setScopeText(draft.scopeText);
      setScopeAll(draft.scopeAll);
      setExpirySeconds(draft.expirySeconds);
      setIntentKey(draft.intentKey);
      setIntentIssuedAt(draft.intentIssuedAt);
      setState(draft.state);
      setReviewed(false);
      setReviewedCancel(false);
    },
  );
  function ticket() {
    const generation = ++live.current.generation;
    return () =>
      live.current.mounted &&
      live.current.context === context &&
      live.current.generation === generation;
  }
  function retainResult(next: ExportState, lease: DraftRecoveryLease | null) {
    const value = { ...draftValue, state: next };
    if (lease) {
      if (terminalExport(next.status)) recovery.release(lease, value, true);
      else recovery.retain(value, lease);
    }
    setState(next);
    setReviewed(false);
    setReviewedCancel(false);
  }

  function invalidateIntent() {
    if (unresolved) return;
    live.current.generation += 1;
    setIntentKey(`export-ui-${crypto.randomUUID()}`);
    setIntentIssuedAt(Math.floor(Date.now() / 1000));
    setReviewed(false);
    setReviewedCancel(false);
    setState(EMPTY_EXPORT);
    setDownloadedChunks(null);
  }

  async function startExport(checkOriginal = false) {
    const original = state.packet;
    if (
      !app ||
      busy ||
      (checkOriginal ? !canRead || !original : !scope || !requestReady)
    )
      return;
    const isCurrent = ticket();
    setActivity(checkOriginal ? "reconcileRequest" : "request");
    setMissingRequest(null);
    setError("");
    let lease = recovery.lease;
    let dispatched = false;
    try {
      let packet = original;
      if (!packet) {
        if (!scope) return;
        const current = await readCatalog({
          workspaceId: app.workspaceId,
          applicationId: app.applicationId,
        });
        if (!isCurrent()) return;
        packet = await prepareAdmittedProgramEffect(
          "/api/export",
          sourceProgramBody(
            app,
            "facts.transfer.export.request",
            exportRequestArguments(
              scopeAll ? {} : scope,
              {
                metadataRevision: current.revisions.metadata,
                commitRevision: current.revisions.commit,
              },
              expirySeconds,
              intentIssuedAt,
              intentKey,
            ),
            true,
          ),
          intentKey,
        );
      }
      if (!isCurrent()) return;
      let response: { result: unknown };
      if (checkOriginal) {
        if (!lease) throw new Error("Original export recovery is unavailable.");
        response = await request(
          "/api/export",
          sourceProgramBody(app, "facts.transfer.export.read", {
            operationId: packet.body.idempotencyKey,
          }),
        );
      } else {
        const pending = { ...state, packet };
        lease = recovery.retain({ ...draftValue, state: pending }, lease);
        setState(pending);
        dispatched = true;
        response = await replayAdmittedEffect(packet);
      }
      if (!isCurrent()) return;
      const args = packet.body.program.arguments as {
        expectedSnapshotRevision: number;
        expectedMetadataRevision: number;
        expiresAt: number;
      };
      const result = exactExportResult(response.result, args);
      retainResult(exportStateFromResult(result), lease);
    } catch (reason) {
      if (!isCurrent()) return;
      if (
        checkOriginal &&
        reason instanceof ApiError &&
        reason.code === "EXPORT_PRODUCER_REQUEST_UNAVAILABLE"
      ) {
        setMissingRequest(original!.body.idempotencyKey);
        setError(
          "The recorded export is unavailable. The outcome remains unconfirmed.",
        );
        return;
      }
      // An original unknown remains recoverable after any later denial.
      // A first definitive rejection permits a newly reviewed request.
      if (
        !state.packet &&
        (!dispatched ||
          (reason instanceof ApiError &&
            [400, 401, 403, 412, 422].includes(reason.status)))
      ) {
        const nextValue = {
          ...draftValue,
          state: EMPTY_EXPORT,
          intentKey: `export-ui-${crypto.randomUUID()}`,
          intentIssuedAt: Math.floor(Date.now() / 1000),
        };
        if (lease) recovery.release(lease, nextValue, true);
        setState(EMPTY_EXPORT);
        setIntentKey(nextValue.intentKey);
        setIntentIssuedAt(nextValue.intentIssuedAt);
        setReviewed(false);
      }
      setError(
        reason instanceof Error ? reason.message : "Unable to start export",
      );
    } finally {
      if (isCurrent()) setActivity(null);
    }
  }

  async function readStatus() {
    if (!app || !state.result || !canRead || busy) return;
    const isCurrent = ticket();
    setActivity("status");
    setError("");
    try {
      const response = await request<{ result: unknown }>(
        "/api/export",
        sourceProgramBody(app, "facts.transfer.export.read", {
          requestId: state.requestId,
        }),
      );
      if (!isCurrent()) return;
      const result = exactExportResult(
        response.result,
        resultExpectation(state.result),
        state.result,
      );
      retainResult(
        exportStateFromResult(result, state.cancelPacket),
        recovery.lease,
      );
    } catch (reason) {
      if (isCurrent())
        setError(
          reason instanceof Error ? reason.message : "Unable to read export",
        );
    } finally {
      if (isCurrent()) setActivity(null);
    }
  }

  async function cancel() {
    if (
      !app ||
      !state.result ||
      !canCancel ||
      !cancellable ||
      busy ||
      (!state.cancelPacket &&
        (!reviewedCancel ||
          !window.confirm("Request safe cancellation of this export?")))
    )
      return;
    const isCurrent = ticket();
    setActivity(state.cancelPacket ? "reconcileCancel" : "cancel");
    setError("");
    try {
      const packet =
        state.cancelPacket ||
        (await prepareAdmittedProgramEffect(
          "/api/export",
          sourceProgramBody(
            app,
            "facts.transfer.export.cancel",
            { requestId: state.requestId },
            true,
          ),
          `${intentKey}-cancel`,
        ));
      if (!isCurrent()) return;
      const pending = { ...state, cancelPacket: packet };
      const lease = recovery.retain(
        { ...draftValue, state: pending },
        recovery.lease,
      );
      setState(pending);
      const response = await replayAdmittedEffect<{ result: unknown }>(packet);
      if (!isCurrent()) return;
      const result = exactExportResult(
        response.result,
        resultExpectation(state.result),
        state.result,
      );
      // A successful native cancel response settles this command even when
      // the producer has not reached a terminal state yet.
      if (!result.cancelRequested && !terminalExport(result.status))
        throw new Error(
          "Export cancellation was not confirmed. Reconcile the original cancellation.",
        );
      retainResult(exportStateFromResult(result), lease);
    } catch (reason) {
      if (isCurrent())
        setError(
          reason instanceof Error ? reason.message : "Unable to cancel export",
        );
    } finally {
      if (isCurrent()) setActivity(null);
    }
  }

  async function downloadBundle() {
    if (
      !app ||
      !state.artifactId ||
      state.status !== "Completed" ||
      !canDownload ||
      !canReadManifest ||
      downloadComplete ||
      busy
    )
      return;
    const isCurrent = ticket();
    const controller = new AbortController();
    const picker = (window as FilePickerWindow).showSaveFilePicker;
    let writable: BrowserWritableFile | null = null;
    const assertCurrent = () => {
      if (!isCurrent() || controller.signal.aborted)
        throw new DOMException("The export context changed.", "AbortError");
    };
    const activeTransfer = {
      abort: () => {
        controller.abort();
        if (writable?.abort) void writable.abort().catch(() => undefined);
      },
    };
    transfer.current = activeTransfer;
    setActivity("download");
    setError("");
    const parts: string[] = [];
    let fallbackBytes = 0;
    try {
      if (picker) {
        const handle = await picker.call(window, {
          suggestedName: exportFileName(app.name),
          types: [
            {
              description: "Open EPM governed export bundle",
              accept: { "application/json": [".json"] },
            },
          ],
        });
        assertCurrent();
        writable = await handle.createWritable();
        assertCurrent();
      }
    } catch (reason) {
      if (writable?.abort) await writable.abort(reason).catch(() => undefined);
      if (isCurrent()) {
        setActivity(null);
        if (!(reason instanceof DOMException && reason.name === "AbortError"))
          setError(
            reason instanceof Error
              ? reason.message
              : "Unable to open export file",
          );
      }
      if (transfer.current === activeTransfer) transfer.current = null;
      return;
    }
    try {
      assertCurrent();
      const manifestResponse = await request<{
        result: { artifactId: string; artifact: Record<string, unknown> };
      }>(
        "/api/export",
        sourceProgramBody(app, "facts.transfer.export.manifest.read", {
          artifactId: state.artifactId,
        }),
        controller.signal,
      );
      assertCurrent();
      if (manifestResponse.result.artifactId !== state.artifactId)
        throw new Error(
          "Export manifest identity does not match the artifact.",
        );
      const manifest = manifestResponse.result.artifact;
      const manifestScope = manifest.scope as {
        workspaceId?: unknown;
        applicationId?: unknown;
      } | null;
      if (
        !state.result ||
        manifest.status !== "complete" ||
        manifestScope?.workspaceId !== app.workspaceId ||
        manifestScope?.applicationId !== app.applicationId ||
        manifest.snapshotRevision !== state.result.snapshotRevision ||
        manifest.metadataRevision !== state.result.metadataRevision ||
        manifest.securityRevision !== state.result.securityRevision ||
        manifest.expiresAt !== state.result.expiresAt ||
        manifest.pageCount !== state.result.pageCount
      )
        throw new Error(
          "Export manifest does not match the original snapshot.",
        );
      const count = await streamCompleteExportBundle(
        state.artifactId,
        manifest,
        async (arguments_) => {
          assertCurrent();
          const response = await request<{ result: PayloadPage }>(
            "/api/export",
            sourceProgramBody(
              app,
              "facts.transfer.export.payload.page",
              arguments_,
            ),
            controller.signal,
          );
          assertCurrent();
          return response.result;
        },
        async (value) => {
          assertCurrent();
          if (writable) {
            await writable.write(value);
            assertCurrent();
            return;
          }
          fallbackBytes += new TextEncoder().encode(value).length;
          if (fallbackBytes > FALLBACK_DOWNLOAD_LIMIT)
            throw new Error(
              "This export requires Chrome streaming file access; the in-memory fallback is limited to 128 MiB.",
            );
          parts.push(value);
        },
      );
      assertCurrent();
      if (writable) {
        await writable.close();
        assertCurrent();
      } else {
        const url = URL.createObjectURL(
          new Blob(parts, { type: "application/json" }),
        );
        const link = document.createElement("a");
        link.href = url;
        link.download = exportFileName(app.name);
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      }
      setDownloadedChunks(count);
    } catch (reason) {
      if (writable?.abort) await writable.abort(reason).catch(() => undefined);
      if (isCurrent())
        setError(
          reason instanceof Error
            ? reason.message
            : "Unable to download complete export bundle",
        );
    } finally {
      if (transfer.current === activeTransfer) transfer.current = null;
      if (isCurrent()) setActivity(null);
    }
  }

  const progress = [
    { label: "Review scope", complete: Boolean(state.requestId) },
    { label: "Prepare snapshot", complete: Boolean(state.artifactId) },
    { label: "Download", complete: downloadComplete },
  ];
  const firstIncomplete = progress.findIndex((step) => !step.complete);
  const statusMessage = activity
    ? exportActivityMessages[activity]
    : state.packet
      ? "Export outcome unknown. Check the original request before retrying."
      : state.cancelPacket
        ? "Cancellation outcome unknown. Refresh status or reconcile the original cancellation."
        : downloadComplete
          ? "Complete bundle downloaded."
          : state.status
            ? `Export status: ${state.status}.`
            : "";
  return (
    <section
      className="panel data-export-journey"
      aria-labelledby="data-export-heading"
    >
      <div className="section-heading-row">
        <div>
          <small>EXPORT WORKSPACE</small>
          <h2 id="data-export-heading" tabIndex={-1}>
            Export a governed snapshot
          </h2>
          <p>
            Choose a scope and prepare one complete, verified snapshot bundle.
          </p>
        </div>
        <span className="task-state neutral">Stable committed snapshot</span>
      </div>
      <ol className="journey-steps" aria-label="Export progress">
        {progress.map(({ label, complete }, index) => (
          <li
            key={label}
            className={complete ? "complete" : ""}
            aria-current={index === firstIncomplete ? "step" : undefined}
            aria-label={`${label}: ${complete ? "complete" : index === firstIncomplete ? "current" : "pending"}`}
          >
            <span aria-hidden="true">{complete ? "✓" : index + 1}</span>
            {label}
          </li>
        ))}
      </ol>
      {!canRequest && catalog && (
        <div className="inline-error" role="status">
          Snapshot exports are not available in the current application context.
        </div>
      )}
      <div className="data-section-heading">
        <span>01</span>
        <div>
          <h3>Choose the snapshot scope</h3>
          <p>
            Choose authorized business members by dimension, or include the
            whole application.
          </p>
        </div>
      </div>
      <fieldset
        className="data-export-controls"
        disabled={busy || unresolved}
        aria-busy={busy}
        aria-label="Snapshot scope"
      >
        <ExactScopeSelector
          app={app}
          catalog={catalog}
          value={scope || {}}
          disabled={scopeAll}
          onChange={(next) => {
            setScopeText(serializedExactScope(next));
            invalidateIntent();
          }}
        />
        <label className="review-check">
          <input
            type="checkbox"
            checked={scopeAll}
            onChange={(event) => {
              setScopeAll(event.target.checked);
              invalidateIntent();
            }}
          />
          Whole application
        </label>
        <label>
          Available for
          <select
            value={expirySeconds}
            onChange={(event) => {
              setExpirySeconds(Number(event.target.value));
              invalidateIntent();
            }}
          >
            <option value={3600}>1 hour</option>
            <option value={21600}>6 hours</option>
            <option value={86400}>24 hours</option>
          </select>
        </label>
      </fieldset>
      <div className="reviewed-inline-action data-review-actions">
        <label className="review-check">
          <input
            type="checkbox"
            checked={reviewed}
            disabled={
              busy ||
              unresolved ||
              Boolean(state.requestId) ||
              !scopeReady ||
              !canRequest
            }
            onChange={(event) => setReviewed(event.target.checked)}
          />
          I reviewed this exact export scope and availability
        </label>
        <button
          {...transferAction(
            busy || (state.packet ? !canRead : !requestReady),
            () => startExport(Boolean(state.packet)),
          )}
        >
          {state.packet && activity !== "request"
            ? "Check original export status"
            : "Start snapshot export"}
        </button>
        {state.packet && requestReady && (
          <button {...transferAction(busy, () => startExport())}>
            Retry original export
          </button>
        )}
      </div>
      <div role="status">{statusMessage}</div>
      {state.requestId && (
        <div className="data-load-review">
          <div className="data-section-heading">
            <span>02</span>
            <div>
              <h3>Prepare and download</h3>
              <p>
                Refresh the request to see when its complete bundle is
                available.
              </p>
            </div>
          </div>
          <dl className="receipt-facts">
            <dt>Export status</dt>
            <dd>
              {state.status}
              {state.cancelRequested ? " · cancellation requested" : ""}
            </dd>
            <dt>Snapshot bundle</dt>
            <dd>
              {state.status === "Completed" && state.artifactId
                ? "Ready to download"
                : terminalExport(state.status)
                  ? "No complete bundle"
                  : "Preparing"}
            </dd>
          </dl>
          <div className="reviewed-inline-action data-export-actions">
            <button {...transferAction(busy || !canRead, readStatus)}>
              Refresh status
            </button>
            <label className="review-check">
              <input
                type="checkbox"
                checked={reviewedCancel}
                disabled={
                  busy ||
                  Boolean(state.cancelPacket) ||
                  !canCancel ||
                  !cancellable
                }
                onChange={(event) => setReviewedCancel(event.target.checked)}
              />
              Review cancellation of this exact current state
            </label>
            <button
              {...transferAction(
                busy ||
                  (!state.cancelPacket && !reviewedCancel) ||
                  !canCancel ||
                  !cancellable,
                cancel,
              )}
            >
              {state.cancelPacket && activity !== "cancel"
                ? "Reconcile original cancellation"
                : "Cancel export"}
            </button>
            <button
              className="primary"
              {...transferAction(
                busy ||
                  !state.artifactId ||
                  state.status !== "Completed" ||
                  !canDownload ||
                  !canReadManifest ||
                  downloadComplete,
                downloadBundle,
              )}
            >
              {downloadComplete
                ? `Complete bundle downloaded · ${downloadedChunks} chunks`
                : "Download complete JSON bundle"}
            </button>
          </div>
        </div>
      )}
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      <p className="authority-note">
        The JSON bundle includes every snapshot part and preserves exact values.
        Keep the complete file when transferring or re-importing it.
      </p>
    </section>
  );
}
