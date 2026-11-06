import { useState } from "react";
import { readSecurityProgram, request } from "./api";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { usePreservedDraft } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";

type TargetKind = "Dimension" | "Relationship";

type SecurityReadback = {
  dimensionId: string;
  relationshipId?: string;
  name: string;
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
} as const;

export function MetadataSecurityStringEditor({
  app,
  catalog,
  targetKind,
  targetId,
  onChanged,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  targetKind: TargetKind;
  targetId: string;
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

  const valid = Boolean(
    readback && draft.length <= 10000 && draft === draft.trim(),
  );
  usePreservedDraft(
    app?.workspaceId || "none",
    app?.applicationId || "none",
    `metadata-security-string:${targetKind}:${targetId || "none"}`,
    `Unsaved ${targetKind} Security String`,
    Boolean(readback && draft !== readback.securityString),
    { readback, draft, reviewed },
    (saved) => {
      setReadback(saved.readback);
      setDraft(saved.draft);
      setReviewed(saved.reviewed);
    },
  );

  async function read() {
    if (!app || !targetId || !canRead) return;
    setBusy(true);
    setError("");
    setResult("");
    try {
      const value = await readSecurityProgram<SecurityReadback>(
        { workspaceId: app.workspaceId, applicationId: app.applicationId },
        contract.read,
        { [contract.idKey]: targetId },
      );
      setReadback(value);
      setDraft(value.securityString);
      setReviewed(false);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : `Unable to read ${targetKind.toLowerCase()} Security String`,
      );
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    if (!app || !readback || !canWrite || !reviewed || !valid) return;
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
          [contract.idKey]: targetId,
          securityString: draft,
          expectedMetadataRevision: readback.metadataRevision,
        },
      };
      await request("/api/metadata-action", {
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
        confirmed: true,
        idempotencyKey: mutationIntentKey({
          workspaceId: app.workspaceId,
          applicationId: app.applicationId,
          program,
        }),
        program,
      });
      setReviewed(false);
      await onChanged();
      await read();
      setResult(
        "The fixed metadata service compiled and applied the reviewed Security String.",
      );
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : `Unable to save ${targetKind.toLowerCase()} Security String`,
      );
    } finally {
      setBusy(false);
    }
  }

  if (!canRead || !targetId) return null;

  return (
    <article className="program-inspector access-editor metadata-security-editor">
      <div className="section-heading-row">
        <div>
          <small>{targetKind.toUpperCase()} SECURITY</small>
          <h3>{targetKind} Security String</h3>
        </div>
        <button disabled={busy} onClick={() => void read()}>
          {readback ? "Refresh" : "Edit Security String"}
        </button>
      </div>
      {error && (
        <div className="inline-error" role="alert">
          {error}
        </div>
      )}
      {readback && (
        <>
          <p>
            {targetId} · metadata revision {readback.metadataRevision} ·
            security revision {readback.securityRevision}
          </p>
          <label>
            Canonical Security String
            <input
              aria-label={`${targetKind} Security String`}
              value={draft}
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
                  disabled={!valid}
                  onChange={(event) => setReviewed(event.target.checked)}
                />
                I reviewed this exact {targetKind.toLowerCase()}, metadata
                revision and canonical Security String.
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
