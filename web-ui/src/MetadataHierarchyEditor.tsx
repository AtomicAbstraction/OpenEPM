import { useEffect, useRef, useState } from "react";
import { MetadataReceiptRecovery } from "./MetadataReceiptRecovery";
import {
  namedHierarchyFunction,
  useNamedHierarchyRecovery,
  type NamedHierarchyAction,
  type NamedHierarchyChange,
} from "./named-hierarchy-recovery";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import type {
  HierarchyMember,
  MetadataHierarchy,
} from "./metadata-hierarchies";
import { usePreservedDraft } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";

type Member = { member_id: string; name: string; status: string };

export function MetadataHierarchyEditor({
  app,
  catalog,
  dimensionId,
  metadataRevision,
  hierarchy,
  hierarchies,
  members,
  memberships,
  current,
  onChanged,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  dimensionId: string;
  metadataRevision: number | null;
  hierarchy?: MetadataHierarchy;
  hierarchies: MetadataHierarchy[];
  members: Member[];
  memberships: HierarchyMember[];
  current: boolean;
  onChanged: () => Promise<void>;
}) {
  const [newId, setNewId] = useState("");
  const [newName, setNewName] = useState("");
  const [membershipMode, setMembershipMode] = useState<
    "explicit" | "all_active"
  >("explicit");
  const [creationRevision, setCreationRevision] = useState(metadataRevision);
  const [name, setName] = useState(hierarchy?.name || "");
  const [changes, setChanges] = useState<Record<string, boolean>>({});
  const [draftRevision, setDraftRevision] = useState(metadataRevision);
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const [acceptedCut, setAcceptedCut] = useState<{
    owner: string;
    revision: number;
  } | null>(null);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
  const key = useStableMutationIntentKey("hierarchy-ui");
  const can = (action: NamedHierarchyAction) =>
    Boolean(catalog?.functions[namedHierarchyFunction(action)]);
  const creationChanged = Boolean(newId || newName);
  const changed = Boolean(
    Object.keys(changes).length || (hierarchy && name !== hierarchy.name),
  );
  const owner = JSON.stringify([
    app?.workspaceId,
    app?.applicationId,
    catalog?.applicationAccess.issuer,
    catalog?.applicationAccess.subjectId,
  ]);
  const editorContext = JSON.stringify([dimensionId, hierarchy?.hierarchyId]);
  const context = JSON.stringify([
    owner,
    editorContext,
    catalog?.applicationAccess.role,
    catalog?.revisions.security,
    catalog?.revisions.capability,
  ]);
  const liveContext = useRef(context);
  liveContext.current = context;

  function refreshHierarchy() {
    const view = liveContext.current;
    setRefreshing(true);
    void Promise.resolve()
      .then(onChanged)
      .catch(() => {
        if (liveContext.current === view)
          setError("Refresh the model to see the current hierarchy.");
      })
      .finally(() => setRefreshing(false));
  }

  const recovery = useNamedHierarchyRecovery(
    app,
    catalog,
    context,
    (attempt, source) => {
      setAcceptedCut({ owner, revision: attempt.metadataRevision });
      const change = attempt.change;
      if (
        change.action === "create" &&
        attempt.dimensionId === dimensionId &&
        newId === change.hierarchyId &&
        newName === change.name &&
        membershipMode === change.membershipMode
      ) {
        setNewId("");
        setNewName("");
      }
      if (
        change.action === "members.set" &&
        attempt.editorContext === editorContext
      ) {
        setChanges((current) => {
          const remaining = { ...current };
          for (const member of change.members) {
            if (remaining[member.memberId] === (member.status === "Active"))
              delete remaining[member.memberId];
          }
          return remaining;
        });
      }
      setResult(
        source === "receipt"
          ? "The original hierarchy change was recorded."
          : "Hierarchy change saved.",
      );
      refreshHierarchy();
    },
  );
  const busy = refreshing || recovery.busy || recovery.pending;
  const sourceCurrent =
    current &&
    Boolean(catalog?.applicationAccess.subjectId) &&
    metadataRevision !== null &&
    !(
      acceptedCut?.owner === owner && acceptedCut.revision === metadataRevision
    );
  const creationCurrent =
    sourceCurrent && creationRevision === metadataRevision;
  const revisionCurrent = sourceCurrent && draftRevision === metadataRevision;
  const validName = (value: string) =>
    Boolean(
      value &&
        value === value.trim() &&
        value.length <= 200 &&
        !/[\u0000-\u001f\u007f]/.test(value),
    );
  const nativeMembership = new Set(
    memberships
      .filter((row) => row.status === "Active")
      .map((row) => row.memberId),
  );
  const filtered = members.filter((member) =>
    `${member.name} ${member.member_id}`
      .toLocaleLowerCase()
      .includes(search.toLocaleLowerCase()),
  );
  const start = Math.min(
    page * 50,
    Math.max(0, Math.ceil(filtered.length / 50) - 1) * 50,
  );
  const visible = filtered.slice(start, start + 50);

  usePreservedDraft(
    app?.workspaceId || "none",
    app?.applicationId || "none",
    `metadata-hierarchy-create:${dimensionId}`,
    "Unsaved hierarchy creation",
    creationChanged,
    { newId, newName, membershipMode, creationRevision },
    (draft) => {
      setNewId(draft.newId);
      setNewName(draft.newName);
      setMembershipMode(draft.membershipMode);
      setCreationRevision(draft.creationRevision);
    },
  );
  usePreservedDraft(
    app?.workspaceId || "none",
    app?.applicationId || "none",
    `metadata-hierarchy:${dimensionId}:${hierarchy?.hierarchyId || "none"}`,
    "Unsaved named hierarchy changes",
    changed,
    { name, changes, draftRevision },
    (draft) => {
      setName(draft.name);
      setChanges(draft.changes);
      setDraftRevision(draft.draftRevision);
    },
  );

  useEffect(() => {
    if (!changed) setDraftRevision(metadataRevision);
    if (!creationChanged) setCreationRevision(metadataRevision);
  }, [metadataRevision, changed, creationChanged]);

  async function execute(change: NamedHierarchyChange) {
    const actorId = catalog?.applicationAccess.subjectId;
    const { action, ...values } = change;
    if (
      !app ||
      !actorId ||
      busy ||
      !(action === "create" ? creationCurrent : revisionCurrent) ||
      metadataRevision === null ||
      !can(action)
    )
      return;
    const args = {
      dimensionId,
      ...values,
      expectedMetadataRevision: metadataRevision,
    };
    const functionName = namedHierarchyFunction(action);
    setError("");
    setResult("");
    await recovery.submit(
      {
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
        confirmed: true,
        idempotencyKey: key({ scope: app, functionName, args }),
        program: {
          languageVersion: 2,
          function: functionName,
          arguments: args,
        },
      },
      { change, actorId, dimensionId, metadataRevision, editorContext },
    );
  }

  return (
    <div className="metadata-hierarchy-editor">
      {error && (
        <p className="inline-error" role="alert">
          {error}
        </p>
      )}
      <MetadataReceiptRecovery
        object="hierarchy"
        recovery={recovery}
        onClose={() => {
          const attempt = recovery.closeRecovery();
          if (!attempt) return;
          if (
            attempt.change.action === "create" &&
            attempt.dimensionId === dimensionId &&
            creationChanged
          )
            setCreationRevision(null);
          if (
            attempt.change.action !== "create" &&
            attempt.editorContext === editorContext &&
            changed
          )
            setDraftRevision(null);
          refreshHierarchy();
        }}
      />
      {result && <p role="status">{result}</p>}
      {changed && draftRevision !== metadataRevision && (
        <p role="status">
          Metadata changed. Your hierarchy draft is retained.
          <button
            type="button"
            disabled={busy}
            onClick={() => setDraftRevision(metadataRevision)}
          >
            Review hierarchy draft against current metadata
          </button>
        </p>
      )}
      {can("create") && (
        <details>
          <summary>Create hierarchy</summary>
          <fieldset disabled={busy}>
            {creationChanged && creationRevision !== metadataRevision && (
              <div role="status">
                <p>Metadata changed since this hierarchy draft began.</p>
                <button
                  type="button"
                  onClick={() => setCreationRevision(metadataRevision)}
                >
                  Review new hierarchy against current metadata
                </button>
              </div>
            )}
            <label>
              New hierarchy ID
              <input
                value={newId}
                maxLength={200}
                onChange={(e) => setNewId(e.target.value)}
              />
            </label>
            <label>
              New hierarchy name
              <input
                value={newName}
                maxLength={200}
                onChange={(e) => setNewName(e.target.value)}
              />
            </label>
            <label>
              Hierarchy membership
              <select
                value={membershipMode}
                onChange={(e) =>
                  setMembershipMode(e.target.value as "explicit" | "all_active")
                }
              >
                <option value="explicit">
                  Explicit members, including isolated roots
                </option>
                <option value="all_active">All active dimension members</option>
              </select>
            </label>
            <p>
              {hierarchies.length
                ? "The current default stays selected. Make the new hierarchy default separately when ready."
                : "The first hierarchy becomes this dimension's default."}{" "}
              Membership mode is fixed after creation.
            </p>
            <button
              type="button"
              disabled={
                !creationCurrent ||
                !validName(newId) ||
                !validName(newName) ||
                hierarchies.some(
                  (row) =>
                    row.hierarchyId === newId ||
                    row.name.toLocaleLowerCase() ===
                      newName.toLocaleLowerCase(),
                )
              }
              onClick={() =>
                void execute({
                  action: "create",
                  hierarchyId: newId,
                  name: newName,
                  membershipMode,
                  isDefault: hierarchies.length === 0,
                })
              }
            >
              Create hierarchy
            </button>
          </fieldset>
        </details>
      )}
      {hierarchy && (
        <details>
          <summary>Hierarchy properties and membership</summary>
          <p>
            Stable ID: <code>{hierarchy.hierarchyId}</code> · {hierarchy.status}
            {hierarchy.isDefault ? " · Default" : ""}
          </p>
          {can("rename") && (
            <fieldset disabled={busy}>
              <label>
                Hierarchy name
                <input
                  value={name}
                  maxLength={200}
                  onChange={(e) => setName(e.target.value)}
                />
              </label>
              <button
                type="button"
                disabled={
                  !revisionCurrent ||
                  !validName(name) ||
                  name === hierarchy.name
                }
                onClick={() =>
                  void execute({
                    action: "rename",
                    hierarchyId: hierarchy.hierarchyId,
                    name,
                  })
                }
              >
                Save hierarchy name
              </button>
            </fieldset>
          )}
          {can("default.set") &&
            !hierarchy.isDefault &&
            hierarchy.status === "Active" && (
              <button
                type="button"
                disabled={busy || !revisionCurrent}
                onClick={() =>
                  void execute({
                    action: "default.set",
                    hierarchyId: hierarchy.hierarchyId,
                  })
                }
              >
                Make default hierarchy
              </button>
            )}
          {can("status.set") && !hierarchy.isDefault && (
            <button
              type="button"
              disabled={busy || !revisionCurrent}
              onClick={() => {
                if (
                  hierarchy.status === "Inactive" ||
                  window.confirm(`Deactivate hierarchy ${hierarchy.name}?`)
                )
                  void execute({
                    action: "status.set",
                    hierarchyId: hierarchy.hierarchyId,
                    status:
                      hierarchy.status === "Active" ? "Inactive" : "Active",
                  });
              }}
            >
              {hierarchy.status === "Active"
                ? "Deactivate hierarchy"
                : "Activate hierarchy"}
            </button>
          )}
          {hierarchy.membershipMode === "explicit" ? (
            <>
              <p>
                Declared members can stand alone as roots. Removing a member
                with active relationships is rejected by the server; edit its
                placements first.
              </p>
              <label>
                Find hierarchy members
                <input
                  value={search}
                  onChange={(e) => {
                    setSearch(e.target.value);
                    setPage(0);
                  }}
                />
              </label>
              <div
                className="react-grid-scroll"
                role="region"
                aria-label="Hierarchy membership"
                tabIndex={0}
              >
                <table className="react-cube-grid">
                  <thead>
                    <tr>
                      <th>Included</th>
                      <th>Member</th>
                      <th>Stable ID</th>
                      <th>Member status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visible.map((member) => (
                      <tr key={member.member_id}>
                        <td>
                          <input
                            type="checkbox"
                            aria-label={`Include ${member.name} in ${hierarchy.name}`}
                            checked={
                              changes[member.member_id] ??
                              nativeMembership.has(member.member_id)
                            }
                            disabled={
                              busy ||
                              !revisionCurrent ||
                              !can("members.set") ||
                              (member.status !== "Active" &&
                                !nativeMembership.has(member.member_id))
                            }
                            onChange={(e) => {
                              const checked = e.target.checked;
                              setChanges((existing) => {
                                const next = { ...existing };
                                if (
                                  checked ===
                                  nativeMembership.has(member.member_id)
                                )
                                  delete next[member.member_id];
                                else next[member.member_id] = checked;
                                return next;
                              });
                            }}
                          />
                        </td>
                        <th>{member.name}</th>
                        <td>{member.member_id}</td>
                        <td>{member.status}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p>
                {filtered.length} matching members · {nativeMembership.size}{" "}
                declared active · {Object.keys(changes).length} pending changes
              </p>
              <button
                type="button"
                disabled={start === 0}
                onClick={() => setPage(Math.max(0, page - 1))}
              >
                Previous members
              </button>
              <button
                type="button"
                disabled={start + 50 >= filtered.length}
                onClick={() => setPage(page + 1)}
              >
                Next members
              </button>
              {can("members.set") && (
                <button
                  type="button"
                  disabled={
                    busy ||
                    !revisionCurrent ||
                    !Object.keys(changes).length ||
                    Object.keys(changes).length > 500
                  }
                  onClick={() =>
                    void execute({
                      action: "members.set",
                      hierarchyId: hierarchy.hierarchyId,
                      members: Object.entries(changes).map(
                        ([memberId, included]) => ({
                          memberId,
                          status: included ? "Active" : "Inactive",
                        }),
                      ),
                    })
                  }
                >
                  Save hierarchy membership
                </button>
              )}
              {Object.keys(changes).length > 500 && (
                <p role="alert">
                  Save at most 500 membership changes per operation.
                </p>
              )}
            </>
          ) : (
            <p>Membership follows all active members in this dimension.</p>
          )}
        </details>
      )}
    </div>
  );
}
