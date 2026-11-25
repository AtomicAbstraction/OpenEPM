import { useEffect, useMemo, useState } from "react";
import { readProgram } from "./api";
import {
  activeFactDimensions,
  collectCapabilityDimensions,
  collectCapabilityMembers,
  type MetadataDimension,
  type MetadataMember,
} from "./metadata-data";
import { MemberSelectionDialog } from "./member-selection/MemberSelectionDialog";
import type { ApplicationCatalog, ApplicationSummary } from "./types";

export function serializedExactScope(scope: Record<string, string>) {
  return Object.entries(scope)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([dimension, member]) => `${dimension}=${member}`)
    .join("; ");
}

export function ExactScopeSelector({
  app,
  catalog,
  value,
  dimensions: providedDimensions,
  metadataRevision: providedMetadataRevision,
  disabled = false,
  onChange,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  value: Record<string, string>;
  dimensions?: MetadataDimension[];
  metadataRevision?: number | null;
  disabled?: boolean;
  onChange: (value: Record<string, string>) => void;
}) {
  const [loadedDimensions, setLoadedDimensions] = useState<MetadataDimension[]>(
    [],
  );
  const [loadedMetadataRevision, setLoadedMetadataRevision] = useState<
    number | null
  >(null);
  const [members, setMembers] = useState<Record<string, MetadataMember[]>>({});
  const [addDimensionId, setAddDimensionId] = useState("");
  const [dialogDimensionId, setDialogDimensionId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const dimensions = providedDimensions || loadedDimensions;
  const metadataRevision =
    providedMetadataRevision === undefined
      ? loadedMetadataRevision
      : providedMetadataRevision;
  const canReadDimensions = Boolean(
    providedDimensions || catalog?.functions["metadata.dimension.list"],
  );
  const canReadMembers = Boolean(catalog?.functions["metadata.member.list"]);
  const context = JSON.stringify([
    app?.workspaceId,
    app?.applicationId,
    catalog?.accessContext,
    catalog?.applicationAccess.issuer,
    catalog?.applicationAccess.subjectId,
    catalog?.revisions.metadata,
    catalog?.revisions.security,
  ]);

  useEffect(() => {
    setLoadedDimensions([]);
    setLoadedMetadataRevision(null);
    setMembers({});
    setAddDimensionId("");
    setDialogDimensionId("");
    setError("");
    if (!app || !canReadDimensions || providedDimensions) return;
    const controller = new AbortController();
    setBusy(true);
    void collectCapabilityDimensions((arguments_) =>
      readProgram(
        app,
        "metadata.dimension.list",
        arguments_,
        controller.signal,
      ),
    )
      .then((result) => {
        if (controller.signal.aborted) return;
        setLoadedDimensions(activeFactDimensions(result.rows));
        setLoadedMetadataRevision(result.finalPage.metadataRevision);
      })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted)
          setError(
            reason instanceof Error
              ? reason.message
              : "Unable to read the current dimensions.",
          );
      })
      .finally(() => {
        if (!controller.signal.aborted) setBusy(false);
      });
    return () => controller.abort();
  }, [context, canReadDimensions, providedDimensions]);

  const dimensionById = useMemo(
    () =>
      new Map(
        dimensions.map((dimension) => [dimension.dimension_id, dimension]),
      ),
    [dimensions],
  );
  const selectedDimensionKey = Object.keys(value).sort().join("\u0000");

  useEffect(() => {
    if (!app || metadataRevision === null || !canReadMembers) return;
    const missing = Object.keys(value).filter(
      (dimensionId) => !members[dimensionId],
    );
    if (!missing.length) return;
    const controller = new AbortController();
    void Promise.all(
      missing.map(async (dimensionId) => {
        const result = await collectCapabilityMembers(
          dimensionId,
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
          dimensionId,
          result.rows.filter((member) => member.status === "Active"),
        ] as const;
      }),
    )
      .then((loaded) => {
        if (!controller.signal.aborted)
          setMembers((current) => ({
            ...current,
            ...Object.fromEntries(loaded),
          }));
      })
      .catch((reason: unknown) => {
        if (!controller.signal.aborted)
          setError(
            reason instanceof Error
              ? reason.message
              : "Unable to verify the selected scope members.",
          );
      });
    return () => controller.abort();
  }, [context, metadataRevision, selectedDimensionKey, canReadMembers]);

  async function ensureMembers(dimensionId: string) {
    if (!app || metadataRevision === null) return [];
    if (members[dimensionId]) return members[dimensionId];
    if (!canReadMembers)
      throw new Error(
        "Current member read access is required to choose scope.",
      );
    const result = await collectCapabilityMembers(
      dimensionId,
      (arguments_) => readProgram(app, "metadata.member.list", arguments_),
      metadataRevision,
    );
    const active = result.rows.filter((member) => member.status === "Active");
    setMembers((current) => ({ ...current, [dimensionId]: active }));
    return active;
  }

  async function open(dimensionId: string) {
    if (!dimensionId || disabled) return;
    setBusy(true);
    setError("");
    try {
      const available = await ensureMembers(dimensionId);
      if (!available.length)
        throw new Error("No active authorized members are available.");
      setDialogDimensionId(dimensionId);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read the current members.",
      );
    } finally {
      setBusy(false);
    }
  }

  const selectedEntries = Object.entries(value).sort(([left], [right]) =>
    left.localeCompare(right),
  );
  const dialogMembers = members[dialogDimensionId] || [];
  const dialogInitialMember =
    value[dialogDimensionId] || dialogMembers[0]?.member_id;

  return (
    <section className="exact-scope-selector" aria-label="Exact member scope">
      <div className="exact-scope-grid" aria-busy={busy}>
        <div className="exact-scope-grid-heading" aria-hidden="true">
          <span>Dimension</span>
          <span>Selected member</span>
          <span>Actions</span>
        </div>
        {selectedEntries.map(([dimensionId, memberId]) => {
          const member = members[dimensionId]?.find(
            (item) => item.member_id === memberId,
          );
          return (
            <div className="exact-scope-row" key={dimensionId}>
              <strong>
                {dimensionById.get(dimensionId)?.name || "Reading dimension…"}
              </strong>
              <span>{member?.name || "Reading member…"}</span>
              <div>
                <button
                  type="button"
                  disabled={disabled || busy || !dimensionById.has(dimensionId)}
                  onClick={() => void open(dimensionId)}
                  aria-label={`Change ${dimensionById.get(dimensionId)?.name || "selected dimension"} scope member`}
                >
                  Change
                </button>
                <button
                  type="button"
                  disabled={disabled || busy}
                  onClick={() => {
                    const next = { ...value };
                    delete next[dimensionId];
                    onChange(next);
                  }}
                  aria-label={`Remove ${dimensionById.get(dimensionId)?.name || "selected dimension"} from scope`}
                >
                  Remove
                </button>
              </div>
            </div>
          );
        })}
        {!selectedEntries.length && (
          <p className="exact-scope-empty">
            Add at least one dimension, or choose the whole application.
          </p>
        )}
      </div>
      <div className="exact-scope-add">
        <label>
          Add dimension
          <select
            value={addDimensionId}
            disabled={disabled || busy || !canReadDimensions}
            onChange={(event) => setAddDimensionId(event.target.value)}
          >
            <option value="">Choose dimension</option>
            {dimensions
              .filter(
                (dimension) => !Object.hasOwn(value, dimension.dimension_id),
              )
              .map((dimension) => (
                <option
                  key={dimension.dimension_id}
                  value={dimension.dimension_id}
                >
                  {dimension.name}
                </option>
              ))}
          </select>
        </label>
        <button
          type="button"
          disabled={disabled || busy || !addDimensionId}
          onClick={() => void open(addDimensionId)}
        >
          Choose member
        </button>
      </div>
      {error && (
        <p className="inline-error" role="alert">
          {error}
        </p>
      )}
      {!canReadDimensions && catalog && (
        <p role="status">
          Current metadata read access is required to choose an exact scope.
        </p>
      )}
      {dialogDimensionId &&
        dialogInitialMember &&
        app &&
        catalog &&
        metadataRevision !== null && (
          <MemberSelectionDialog
            app={app}
            catalog={catalog}
            request={{
              dimensionId: dialogDimensionId,
              dimensionName:
                dimensionById.get(dialogDimensionId)?.name || dialogDimensionId,
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
              initial: { kind: "member", memberId: dialogInitialMember },
            }}
            members={dialogMembers}
            onCancel={() => {
              setDialogDimensionId("");
              setAddDimensionId("");
            }}
            onApply={(result) => {
              if (result.include.kind !== "member") return;
              onChange({
                ...value,
                [dialogDimensionId]: result.include.memberId,
              });
              setDialogDimensionId("");
              setAddDimensionId("");
            }}
          />
        )}
    </section>
  );
}
