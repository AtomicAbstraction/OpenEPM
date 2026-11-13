import { useMemo, useState } from "react";
import { readCatalog, request, requestAdmittedProgramEffect } from "./api";
import { parseExactScope, sourceProgramBody } from "./DataLoad";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { useUnsavedWork } from "./unsaved-work";
import "./data-workspaces.css";

type ExportState = {
  requestId: string;
  artifactId: string;
  status: string;
  cancelRequested: boolean;
};

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
  const [state, setState] = useState<ExportState>({
    requestId: "",
    artifactId: "",
    status: "",
    cancelRequested: false,
  });
  const [downloadedChunks, setDownloadedChunks] = useState(0);
  const [downloadComplete, setDownloadComplete] = useState(false);
  const [busy, setBusy] = useState(false);
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
  const requestReady = Boolean(app && scopeReady && canRequest && reviewed);
  const cancellable = [
    "Accepted",
    "Reading",
    "Prepared",
    "Publishing",
  ].includes(state.status);
  useUnsavedWork(
    "data-export-request",
    "Unsubmitted data export request",
    !state.requestId &&
      Boolean(scopeText || scopeAll || expirySeconds !== 3600 || reviewed),
  );
  useUnsavedWork(
    "data-export-cancellation",
    "Unsubmitted data export cancellation review",
    Boolean(state.requestId && reviewedCancel),
  );

  function invalidateIntent() {
    setIntentKey(`export-ui-${crypto.randomUUID()}`);
    setIntentIssuedAt(Math.floor(Date.now() / 1000));
    setReviewed(false);
    setReviewedCancel(false);
    setState({
      requestId: "",
      artifactId: "",
      status: "",
      cancelRequested: false,
    });
    setDownloadedChunks(0);
    setDownloadComplete(false);
  }

  async function startExport() {
    if (!app || !scope || !requestReady) return;
    setBusy(true);
    setError("");
    try {
      const current = await readCatalog({
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
      });
      const revisions = {
        metadataRevision: current.revisions.metadata,
        commitRevision: current.revisions.commit,
      };
      const response = await requestAdmittedProgramEffect<{
        result: { requestId: string; artifactId?: string; status: string };
      }>(
        "/api/export",
        sourceProgramBody(
          app,
          "facts.transfer.export.request",
          exportRequestArguments(
            scopeAll ? {} : scope,
            revisions,
            expirySeconds,
            intentIssuedAt,
            intentKey,
          ),
          true,
        ),
        intentKey,
      );
      setState({
        requestId: response.result.requestId,
        artifactId: response.result.artifactId || "",
        status: response.result.status,
        cancelRequested: false,
      });
      setReviewed(false);
      setReviewedCancel(false);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to start export",
      );
    } finally {
      setBusy(false);
    }
  }

  async function readStatus() {
    if (!app || !state.requestId || !canRead) return;
    setBusy(true);
    setError("");
    try {
      const response = await request<{
        result: {
          status: string;
          artifactId?: string;
          cancelRequested?: boolean;
        };
      }>(
        "/api/export",
        sourceProgramBody(app, "facts.transfer.export.read", {
          requestId: state.requestId,
        }),
      );
      setState((current) => ({
        ...current,
        status: response.result.status,
        artifactId: response.result.artifactId || "",
        cancelRequested: Boolean(response.result.cancelRequested),
      }));
      setReviewedCancel(false);
      setDownloadedChunks(0);
      setDownloadComplete(false);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to read export",
      );
    } finally {
      setBusy(false);
    }
  }

  async function cancel() {
    if (
      !app ||
      !state.requestId ||
      !canCancel ||
      !cancellable ||
      !reviewedCancel ||
      !window.confirm("Request safe cancellation of this export?")
    )
      return;
    setBusy(true);
    setError("");
    try {
      const response = await requestAdmittedProgramEffect<{
        result: {
          status: string;
          artifactId?: string;
          cancelRequested?: boolean;
        };
      }>(
        "/api/export",
        sourceProgramBody(
          app,
          "facts.transfer.export.cancel",
          { requestId: state.requestId },
          true,
        ),
        intentKey,
      );
      setState((current) => ({
        ...current,
        status: response.result.status,
        artifactId: response.result.artifactId || "",
        cancelRequested: Boolean(response.result.cancelRequested),
      }));
      setReviewedCancel(false);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "Unable to cancel export",
      );
    } finally {
      setBusy(false);
    }
  }

  async function downloadBundle() {
    if (
      !app ||
      !state.artifactId ||
      !canDownload ||
      !canReadManifest ||
      downloadComplete
    )
      return;
    const picker = (window as FilePickerWindow).showSaveFilePicker;
    let writable: BrowserWritableFile | null = null;
    const parts: string[] = [];
    let fallbackBytes = 0;
    try {
      if (picker) {
        const handle = await picker.call(window, {
          suggestedName: `openepm-export-${state.artifactId}.json`,
          types: [
            {
              description: "Open EPM governed export bundle",
              accept: { "application/json": [".json"] },
            },
          ],
        });
        writable = await handle.createWritable();
      }
    } catch (reason) {
      if (reason instanceof DOMException && reason.name === "AbortError")
        return;
      setError(
        reason instanceof Error ? reason.message : "Unable to open export file",
      );
      return;
    }
    setBusy(true);
    setError("");
    try {
      const manifestResponse = await request<{
        result: { artifactId: string; artifact: Record<string, unknown> };
      }>(
        "/api/export",
        sourceProgramBody(app, "facts.transfer.export.manifest.read", {
          artifactId: state.artifactId,
        }),
      );
      if (manifestResponse.result.artifactId !== state.artifactId)
        throw new Error(
          "Export manifest identity does not match the artifact.",
        );
      const count = await streamCompleteExportBundle(
        state.artifactId,
        manifestResponse.result.artifact,
        async (arguments_) => {
          const response = await request<{ result: PayloadPage }>(
            "/api/export",
            sourceProgramBody(
              app,
              "facts.transfer.export.payload.page",
              arguments_,
            ),
          );
          setDownloadedChunks(response.result.ordinal + 1);
          return response.result;
        },
        async (value) => {
          if (writable) return writable.write(value);
          fallbackBytes += new TextEncoder().encode(value).length;
          if (fallbackBytes > FALLBACK_DOWNLOAD_LIMIT)
            throw new Error(
              "This export requires Chrome streaming file access; the in-memory fallback is limited to 128 MiB.",
            );
          parts.push(value);
        },
      );
      if (writable) await writable.close();
      else {
        const url = URL.createObjectURL(
          new Blob(parts, { type: "application/json" }),
        );
        const link = document.createElement("a");
        link.href = url;
        link.download = `openepm-export-${state.artifactId}.json`;
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      }
      setDownloadedChunks(count);
      setDownloadComplete(true);
    } catch (reason) {
      if (writable?.abort) await writable.abort(reason).catch(() => undefined);
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to download complete export bundle",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <section
      className="panel data-export-journey"
      aria-labelledby="data-export-heading"
      aria-busy={busy}
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
        {[
          { label: "Review scope", complete: Boolean(state.requestId) },
          { label: "Prepare snapshot", complete: Boolean(state.artifactId) },
          { label: "Download", complete: downloadComplete },
        ].map(({ label, complete }, index) => (
          <li key={label} className={complete ? "complete" : ""}>
            <span aria-hidden="true">{complete ? "✓" : index + 1}</span>
            {label}
          </li>
        ))}
      </ol>
      {!canRequest && catalog && (
        <div className="inline-error" role="status">
          Your current role cannot request snapshot exports.
        </div>
      )}
      <div className="data-section-heading">
        <span>01</span>
        <div>
          <h3>Choose the snapshot scope</h3>
          <p>
            Use exact dimension and member IDs, or include the whole
            application.
          </p>
        </div>
      </div>
      <fieldset
        className="data-export-controls"
        disabled={busy}
        aria-label="Snapshot scope"
      >
        <label>
          Exact scope
          <input
            disabled={scopeAll}
            value={scopeText}
            placeholder="Entity=Europe; Period=Jan"
            onChange={(event) => {
              setScopeText(event.target.value);
              invalidateIntent();
            }}
          />
        </label>
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
      {!scopeAll && scopeText && !scope && (
        <p className="inline-error" role="alert">
          Use Dimension=Member pairs separated by semicolons.
        </p>
      )}
      <div className="reviewed-inline-action data-review-actions">
        <label className="review-check">
          <input
            type="checkbox"
            checked={reviewed}
            disabled={busy || !scopeReady || !canRequest}
            onChange={(event) => setReviewed(event.target.checked)}
          />
          I reviewed this exact export scope and availability
        </label>
        <button
          disabled={busy || !requestReady}
          onClick={() => void startExport()}
        >
          Start snapshot export
        </button>
      </div>
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
            <dt>Export request</dt>
            <dd>
              <code>{state.requestId}</code>
            </dd>
            <dt>Durable status</dt>
            <dd>
              {state.status}
              {state.cancelRequested ? " · cancellation requested" : ""}
            </dd>
            <dt>Artifact</dt>
            <dd>
              {state.artifactId ? (
                <code>{state.artifactId}</code>
              ) : (
                "Not prepared yet"
              )}
            </dd>
          </dl>
          <div className="reviewed-inline-action data-export-actions">
            <button
              disabled={busy || !canRead}
              onClick={() => void readStatus()}
            >
              Refresh status
            </button>
            <label className="review-check">
              <input
                type="checkbox"
                checked={reviewedCancel}
                disabled={busy || !canCancel || !cancellable}
                onChange={(event) => setReviewedCancel(event.target.checked)}
              />
              Review cancellation of this exact current state
            </label>
            <button
              disabled={busy || !reviewedCancel || !canCancel || !cancellable}
              onClick={() => void cancel()}
            >
              Cancel export
            </button>
            <button
              className="primary"
              disabled={
                busy ||
                !state.artifactId ||
                !canDownload ||
                !canReadManifest ||
                downloadComplete
              }
              onClick={() => void downloadBundle()}
            >
              {downloadComplete
                ? `Complete bundle downloaded · ${downloadedChunks} chunks`
                : busy && downloadedChunks
                  ? `Downloading chunk ${downloadedChunks}…`
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
