import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { ApiError, readSecurityProgram } from "./api";
import { useMetadataMutationRecovery } from "./metadata-mutation-recovery";
import { MetadataReceiptRecovery } from "./MetadataReceiptRecovery";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { usePreservedDraft } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";

type TargetKind = "Dimension" | "Relationship" | "Member";

type SecurityReadback = {
  dimensionId: string;
  relationshipId?: string;
  memberId?: string;
  name?: string;
  status: string;
  readTags: string[];
  writeTags: string[];
  securityString: string;
  metadataRevision: number;
  securityRevision: number;
};

const CONTRACT = {
  Dimension: {
    read: "security.application.dimension-metadata-tags.read",
    write: "metadata.dimension.security-string.set",
    idKey: "dimensionId",
  },
  Relationship: {
    read: "security.application.relationship-tags.read",
    write: "metadata.relationship.security-string.set",
    idKey: "relationshipId",
  },
  Member: {
    read: "security.application.member-tags.read",
    write: "metadata.member.security-string.set",
    idKey: "memberId",
  },
} as const;

export function canReadSecurityString(
  catalog: ApplicationCatalog | null,
  kind: TargetKind,
) {
  return Boolean(catalog?.functions[CONTRACT[kind].read]);
}

export function MetadataSecurityStringEditor({
  app,
  catalog,
  targetKind,
  targetId,
  dimensionId,
  onChanged,
  showEditor = true,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  targetKind: TargetKind;
  targetId: string;
  dimensionId?: string;
  onChanged: () => Promise<void>;
  showEditor?: boolean;
}) {
  const mutationIntentKey = useStableMutationIntentKey("security-string-ui");
  const contract = CONTRACT[targetKind];
  const canRead = canReadSecurityString(catalog, targetKind);
  const canWrite = Boolean(catalog?.functions[contract.write]);
  const [readback, setReadback] = useState<SecurityReadback | null>(null);
  const [draft, setDraft] = useState("");
  const [reviewed, setReviewed] = useState(false);
  const [reading, setReading] = useState(false);
  const [settling, setSettling] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
  const [snapshotScope, setSnapshotScope] = useState("");
  const [needsRefresh, setNeedsRefresh] = useState(false);
  const editor = JSON.stringify([
    targetKind,
    targetKind === "Member" ? dimensionId : null,
    targetId,
  ]);
  const scopeKey = JSON.stringify([
    app?.workspaceId,
    app?.applicationId,
    catalog?.applicationAccess.issuer,
    catalog?.applicationAccess.subjectId,
    editor,
  ]);
  const authority = JSON.stringify([
    scopeKey,
    canRead,
    canWrite,
    catalog?.applicationAccess.role,
    catalog?.revisions.metadata,
    catalog?.revisions.security,
    catalog?.revisions.capability,
  ]);
  const readController = useRef<AbortController | null>(null);
  const currentView = useRef({ scopeKey, authority, canRead });
  currentView.current = { scopeKey, authority, canRead };
  const hasTarget = Boolean(
    targetId && (targetKind !== "Member" || dimensionId),
  );
  const hasSnapshot = Boolean(readback && snapshotScope === scopeKey);
  const changed = Boolean(hasSnapshot && draft !== readback?.securityString);
  const stale = Boolean(
    needsRefresh ||
      (hasSnapshot &&
        readback &&
        (readback.metadataRevision < (catalog?.revisions.metadata ?? 0) ||
          readback.securityRevision < (catalog?.revisions.security ?? 0))),
  );

  const recovery = useMetadataMutationRecovery<{
    actorId: string;
    metadataRevision: number;
    securityRevision: number;
    securityString: string;
    scopeKey: string;
  }>(
    app,
    catalog,
    authority,
    {
      editor: `metadata-security-string-change:${editor}`,
      pendingLabel: "Security String change with an unconfirmed outcome",
      functions: [contract.write],
      subject: "security string change",
      closePrompt:
        "Close this unconfirmed Security String change? Read the current value before reviewing another change.",
      refuses: (code) =>
        code.startsWith("SECURITY_STRING_") ||
        [
          "SECURITY_TAG_CATALOG_INVALID",
          "DIMENSION_UNAVAILABLE",
          "MEMBER_UNAVAILABLE",
          "RELATIONSHIP_UNAVAILABLE",
        ].includes(code),
    },
    (attempt, source) => {
      if (currentView.current.scopeKey !== attempt.scopeKey) return;
      const preserveDraft = hasSnapshot && draft !== attempt.securityString;
      setReviewed(false);
      setNeedsRefresh(true);
      if (!preserveDraft) {
        setReadback(null);
        setDraft("");
        setSnapshotScope("");
      }
      setResult(
        source === "receipt"
          ? "The original Security String change was recorded."
          : "The fixed metadata service compiled and applied the reviewed Security String.",
      );
      setSettling(attempt.scopeKey);
      void Promise.resolve()
        .then(onChanged)
        .then(async () => {
          if (
            currentView.current.scopeKey === attempt.scopeKey &&
            currentView.current.canRead
          )
            await read(preserveDraft, attempt);
        })
        .catch(() => {
          if (currentView.current.scopeKey === attempt.scopeKey)
            setError(
              "The change is recorded. Refresh current security to read the latest value.",
            );
        })
        .finally(() =>
          setSettling((key) => (key === attempt.scopeKey ? null : key)),
        );
    },
  );
  const busy =
    reading || recovery.busy || recovery.pending || settling === scopeKey;
  const valid = Boolean(
    hasSnapshot &&
      !stale &&
      changed &&
      draft.length <= 10000 &&
      draft === draft.trim(),
  );
  usePreservedDraft(
    app?.workspaceId || "none",
    app?.applicationId || "none",
    `metadata-security-string:${editor}`,
    `Unsaved ${targetKind} Security String`,
    changed,
    {
      readback,
      draft,
      snapshotScope,
      securityRevision: catalog?.revisions.security,
      accessContext: catalog?.accessContext,
    },
    (saved) => {
      if (
        !canRead ||
        saved.snapshotScope !== scopeKey ||
        saved.securityRevision !== catalog?.revisions.security ||
        saved.accessContext !== catalog?.accessContext
      )
        return;
      setReadback(saved.readback);
      setDraft(saved.draft);
      setSnapshotScope(saved.snapshotScope);
      setReviewed(false);
      setNeedsRefresh(true);
    },
  );

  useLayoutEffect(() => {
    setReviewed(false);
    setNeedsRefresh(true);
    setReading(false);
    if (!canRead) {
      setReadback(null);
      setDraft("");
      setSnapshotScope("");
    }
    return () => readController.current?.abort();
  }, [authority, canRead]);

  useEffect(() => {
    setReadback(null);
    setDraft("");
    setSnapshotScope("");
    setError("");
    setResult("");
  }, [scopeKey]);

  async function read(
    preserveDraft = changed,
    previous?: { metadataRevision: number; securityRevision: number },
  ) {
    const view = currentView.current;
    if (!app || !hasTarget || !view.canRead || view.scopeKey !== scopeKey)
      return;
    readController.current?.abort();
    const request = new AbortController();
    readController.current = request;
    const current = () =>
      !request.signal.aborted &&
      currentView.current.authority === view.authority;
    setReading(true);
    setReviewed(false);
    setNeedsRefresh(true);
    setError("");
    try {
      const value = await readSecurityProgram<SecurityReadback>(
        { workspaceId: app.workspaceId, applicationId: app.applicationId },
        contract.read,
        {
          ...(targetKind === "Member" ? { dimensionId } : {}),
          [contract.idKey]: targetId,
        },
        request.signal,
      );
      if (!current()) return;
      if (
        value[contract.idKey] !== targetId ||
        (targetKind === "Member" && value.dimensionId !== dimensionId) ||
        typeof value.securityString !== "string" ||
        !Number.isSafeInteger(value.metadataRevision) ||
        value.metadataRevision < 0 ||
        !Number.isSafeInteger(value.securityRevision) ||
        value.securityRevision < 0
      )
        throw new Error(
          "The security response does not match the selected metadata object.",
        );
      if (
        previous &&
        (value.metadataRevision <= previous.metadataRevision ||
          value.securityRevision <= previous.securityRevision)
      )
        throw new Error(
          "The change is recorded. Refresh current security to read the committed revision.",
        );
      setReadback(value);
      setSnapshotScope(scopeKey);
      if (!preserveDraft) setDraft(value.securityString);
      setNeedsRefresh(false);
    } catch (reason) {
      if (current()) {
        if (
          reason instanceof ApiError &&
          (reason.kind === "authentication" ||
            reason.kind === "authorization" ||
            [
              "SECURITY_READ_AUTHORIZATION_STALE",
              "DIMENSION_UNAVAILABLE",
              "MEMBER_UNAVAILABLE",
              "RELATIONSHIP_UNAVAILABLE",
              "APPLICATION_UNAVAILABLE",
            ].includes(reason.code))
        ) {
          setReadback(null);
          setDraft("");
          setSnapshotScope("");
        }
        setError(
          reason instanceof Error
            ? reason.message
            : "Unable to read the current Security String.",
        );
      }
    } finally {
      if (readController.current === request) {
        readController.current = null;
        if (current()) setReading(false);
      }
    }
  }

  async function save() {
    const actorId = catalog?.applicationAccess.subjectId;
    if (
      !app ||
      !actorId ||
      !hasTarget ||
      !readback ||
      !canRead ||
      !canWrite ||
      busy ||
      !reviewed ||
      !valid
    )
      return;
    if (
      !window.confirm(
        `Compile and save this exact ${targetKind} Security String?`,
      )
    )
      return;
    setError("");
    setResult("");
    const program = {
      languageVersion: 2,
      function: contract.write,
      arguments: {
        ...(targetKind === "Member" ? { dimensionId } : {}),
        [contract.idKey]: targetId,
        securityString: draft,
        expectedMetadataRevision: readback.metadataRevision,
      },
    };
    await recovery.submit(
      {
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
        confirmed: true,
        idempotencyKey: mutationIntentKey({
          workspaceId: app.workspaceId,
          applicationId: app.applicationId,
          program,
        }),
        program,
      },
      {
        actorId,
        metadataRevision: readback.metadataRevision,
        securityRevision: readback.securityRevision,
        securityString: draft,
        scopeKey,
      },
    );
  }

  const showValue = showEditor && canRead && hasTarget;
  if (!showValue && !recovery.pending && !recovery.message && !result)
    return null;

  return (
    <article className="program-inspector access-editor metadata-security-editor">
      {showValue && (
        <div className="section-heading-row">
          <div>
            <small>{targetKind.toUpperCase()} SECURITY</small>
            <h3>{targetKind} Security String</h3>
          </div>
          <button
            disabled={busy}
            onClick={() => {
              setResult("");
              void read();
            }}
          >
            {hasSnapshot ? "Refresh current security" : "Edit Security String"}
          </button>
        </div>
      )}
      <MetadataReceiptRecovery
        object="security string"
        recovery={recovery}
        onClose={() => {
          if (recovery.closeRecovery()) {
            setReviewed(false);
            setNeedsRefresh(true);
          }
        }}
      />
      {showValue && error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {showValue && hasSnapshot && readback && (
        <>
          <p>
            Current governed value loaded for this {targetKind.toLowerCase()}.
          </p>
          {stale && (
            <p role="alert">
              This draft needs a fresh security read before review. Your typed
              Security String is preserved. Refresh current security to compare
              it with the latest value.
            </p>
          )}
          {changed && (
            <p>
              Current value: <code>{readback.securityString || "(empty)"}</code>
            </p>
          )}
          <label>
            Canonical Security String
            <input
              aria-label={`${targetKind} Security String`}
              value={draft}
              disabled={busy}
              readOnly={!canWrite}
              onChange={(event) => {
                setDraft(event.target.value);
                setReviewed(false);
                setResult("");
              }}
              placeholder="read=NorthRead;write=NorthWrite"
            />
          </label>
          <p>
            Use <code>read=…;write=…</code> with active, case-sensitive tag IDs.
            The fixed core validates and canonicalizes the value.
          </p>
          {canWrite && (
            <div className="reviewed-inline-action">
              <label className="review-check">
                <input
                  type="checkbox"
                  checked={reviewed}
                  disabled={busy || !valid}
                  onChange={(event) => setReviewed(event.target.checked)}
                />
                I reviewed this exact {targetKind.toLowerCase()} and canonical
                Security String.
              </label>
              <button
                disabled={
                  busy ||
                  !reviewed ||
                  !valid ||
                  !catalog?.applicationAccess.subjectId
                }
                onClick={() => void save()}
              >
                Compile and save Security String
              </button>
            </div>
          )}
        </>
      )}
      {result && <p role="status">{result}</p>}
    </article>
  );
}
