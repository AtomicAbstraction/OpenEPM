import { useEffect, useRef, useState } from "react";
import { readSecurityProgram, requestAdmittedEffect } from "./api";
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

export function MetadataSecurityStringEditor({
  app,
  catalog,
  targetKind,
  targetId,
  dimensionId,
  onChanged,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  targetKind: TargetKind;
  targetId: string;
  dimensionId?: string;
  onChanged: () => Promise<void>;
}) {
  const mutationIntentKey = useStableMutationIntentKey("security-string-ui");
  const contract = CONTRACT[targetKind];
  const canRead = Boolean(catalog?.functions[contract.read]);
  const canWrite = Boolean(catalog?.functions[contract.write]);
  const [readback, setReadback] = useState<SecurityReadback | null>(null);
  const [draft, setDraft] = useState("");
  const [reviewed, setReviewed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
  const [snapshotScope, setSnapshotScope] = useState("");
  const [needsRefresh, setNeedsRefresh] = useState(false);
  const [pendingIntent, setPendingIntent] = useState<{
    signature: string;
    key: string;
  } | null>(null);
  const scopeKey = JSON.stringify([
    app?.workspaceId,
    app?.applicationId,
    targetKind,
    targetId,
    targetKind === "Member" ? dimensionId : null,
  ]);
  const currentScope = useRef(scopeKey);
  currentScope.current = scopeKey;
  const readGeneration = useRef(0);
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
    `metadata-security-string:${targetKind}:${targetKind === "Member" ? dimensionId || "none" : ""}:${targetId || "none"}`,
    `Unsaved ${targetKind} Security String`,
    changed,
    { readback, draft, snapshotScope, pendingIntent },
    (saved) => {
      setReadback(saved.readback);
      setDraft(saved.draft);
      setSnapshotScope(saved.snapshotScope);
      setPendingIntent(saved.pendingIntent);
      setReviewed(false);
      setNeedsRefresh(true);
    },
  );

  useEffect(() => {
    readGeneration.current += 1;
    setReadback(null);
    setDraft("");
    setSnapshotScope("");
    setReviewed(false);
    setNeedsRefresh(false);
    setPendingIntent(null);
    setBusy(false);
    setError("");
    setResult("");
    return () => {
      readGeneration.current += 1;
    };
  }, [scopeKey]);

  useEffect(() => {
    setReviewed(false);
  }, [
    catalog?.revisions.metadata,
    catalog?.revisions.security,
    canRead,
    canWrite,
  ]);

  async function read(preserveDraft = true) {
    if (!app || !hasTarget || !canRead) return;
    const generation = ++readGeneration.current;
    const keepDraft = preserveDraft && changed;
    setBusy(true);
    setReviewed(false);
    setNeedsRefresh(true);
    setError("");
    setResult("");
    try {
      const value = await readSecurityProgram<SecurityReadback>(
        { workspaceId: app.workspaceId, applicationId: app.applicationId },
        contract.read,
        {
          ...(targetKind === "Member" ? { dimensionId } : {}),
          [contract.idKey]: targetId,
        },
      );
      if (
        generation !== readGeneration.current ||
        currentScope.current !== scopeKey
      )
        return;
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
      setReadback(value);
      setSnapshotScope(scopeKey);
      if (!keepDraft) setDraft(value.securityString);
      setReviewed(false);
      setNeedsRefresh(false);
    } catch (reason) {
      if (
        generation !== readGeneration.current ||
        currentScope.current !== scopeKey
      )
        return;
      setError(
        reason instanceof Error
          ? reason.message
          : `Unable to read ${targetKind.toLowerCase()} Security String`,
      );
    } finally {
      if (
        generation === readGeneration.current &&
        currentScope.current === scopeKey
      )
        setBusy(false);
    }
  }

  async function save() {
    if (
      !app ||
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
    setBusy(true);
    setError("");
    setResult("");
    try {
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
      const signature = JSON.stringify(program);
      const key =
        pendingIntent?.signature === signature
          ? pendingIntent.key
          : mutationIntentKey({
              workspaceId: app.workspaceId,
              applicationId: app.applicationId,
              program,
            });
      setPendingIntent({ signature, key });
      await requestAdmittedEffect("/api/metadata-action", {
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
        confirmed: true,
        idempotencyKey: key,
        program,
      });
      if (currentScope.current !== scopeKey) return;
      setReviewed(false);
      setPendingIntent(null);
      setNeedsRefresh(true);
      await onChanged();
      if (currentScope.current !== scopeKey) return;
      await read(false);
      setResult(
        "The fixed metadata service compiled and applied the reviewed Security String.",
      );
    } catch (reason) {
      if (currentScope.current !== scopeKey) return;
      setError(
        reason instanceof Error
          ? reason.message
          : `Unable to save ${targetKind.toLowerCase()} Security String`,
      );
    } finally {
      if (currentScope.current === scopeKey) setBusy(false);
    }
  }

  if (!canRead || !hasTarget) return null;

  return (
    <article className="program-inspector access-editor metadata-security-editor">
      <div className="section-heading-row">
        <div>
          <small>{targetKind.toUpperCase()} SECURITY</small>
          <h3>{targetKind} Security String</h3>
        </div>
        <button disabled={busy} onClick={() => void read()}>
          {hasSnapshot ? "Refresh current security" : "Edit Security String"}
        </button>
      </div>
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {hasSnapshot && readback && (
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
                disabled={busy || !reviewed || !valid}
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
