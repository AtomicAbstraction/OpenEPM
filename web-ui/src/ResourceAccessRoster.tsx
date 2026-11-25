import { useEffect, useRef, useState } from "react";
import { canonicalJson, readProgram, readSecurityProgram } from "./api";
import { validWorkflowDuties } from "./authorization-config";
import type { ApplicationSummary } from "./types";

export const resourceAccess = "security.application.resource-access.list";
type Resource = {
  action: string;
  coordinate?: Record<string, string>;
  savedViewId?: string;
};
type Collection = "people" | "groups" | "origins";
type SetState =
  | "open"
  | "locked"
  | "blocked"
  | "unknown"
  | "workflow_role_unbound"
  | "not_applicable";
type Origin = {
  assignmentId: string;
  assignmentRevision: number;
  roleId: string;
  roleRevision: number;
  scopeId: string;
  scopeRevision: number;
  action: string;
  groupId: string;
  workflowDuties?: string[];
};
type Review = Resource & {
  workspaceId: string;
  applicationId: string;
  collection: Collection;
  groupId?: string;
  coverage: "complete_in_application" | "partial" | "unavailable";
  coverageReasons: string[];
  businessState: SetState | "per_assignment";
  asOf: string;
  nextCursor: string | null;
  groups: {
    groupId: string;
    groupName: string | null;
    hasActiveMembers: boolean;
    businessState?: SetState;
    origins: Origin[];
    originsComplete: boolean;
  }[];
  people: {
    subjectId: string;
    username: string | null;
    displayName: string | null;
    grantingGroupIds: string[];
    entryGroupIds: string[];
    businessState?: SetState;
  }[];
  origins: Origin[];
};
const businessLabels = {
  open: "Planning currently allows a numeric Set.",
  locked: "A planning lock currently prevents a numeric Set.",
  blocked: "The current application or planning state prevents a numeric Set.",
  unknown: "The current write state is unconfirmed.",
  workflow_role_unbound:
    "These people have the required coordinate privileges. A write is blocked because the active planning policy requires a verified workflow role.",
  not_applicable: "",
  per_assignment:
    "Write eligibility depends on the planning duties linked to each matching assignment.",
};
const personalLabels: Record<SetState, string> = {
  open: "Planning allows Set",
  locked: "Planning lock blocks Set",
  blocked: "Planning policy or application state blocks Set",
  unknown: "Write eligibility unconfirmed",
  workflow_role_unbound: "No matching assignment supplies a planning duty",
  not_applicable: "",
};
const label = (s: unknown) => typeof s === "string" && s.length > 0;
const nullableLabel = (s: unknown) => s === null || label(s);
function validOrigins(values: Origin[], groupId?: string) {
  return (
    Array.isArray(values) &&
    values.length <= 100 &&
    values.every(
      (o) =>
        o &&
        (o.workflowDuties === undefined ||
          (o.action === "facts.write" &&
            validWorkflowDuties(o.workflowDuties))) &&
        [o.assignmentId, o.groupId, o.roleId, o.scopeId, o.action].every(
          label,
        ) &&
        (!groupId || o.groupId === groupId) &&
        [o.assignmentRevision, o.roleRevision, o.scopeRevision].every(
          Number.isSafeInteger,
        ),
    )
  );
}
function validPage(
  data: Review,
  app: ApplicationSummary,
  resource: Resource,
  collection: Collection,
  groupId?: string,
) {
  return (
    data &&
    data.workspaceId === app.workspaceId &&
    data.applicationId === app.applicationId &&
    data.action === resource.action &&
    data.savedViewId === resource.savedViewId &&
    canonicalJson(data.coordinate ?? null) ===
      canonicalJson(resource.coordinate ?? null) &&
    data.collection === collection &&
    data.groupId === groupId &&
    Number.isFinite(Date.parse(data.asOf)) &&
    ["complete_in_application", "partial", "unavailable"].includes(
      data.coverage,
    ) &&
    Array.isArray(data.coverageReasons) &&
    data.coverageReasons.every(label) &&
    Object.hasOwn(businessLabels, data.businessState) &&
    nullableLabel(data.nextCursor) &&
    Array.isArray(data.people) &&
    data.people.length <= 25 &&
    data.people.every(
      (p) =>
        p &&
        label(p.subjectId) &&
        (p.businessState === undefined
          ? data.businessState !== "per_assignment"
          : Object.hasOwn(personalLabels, p.businessState)) &&
        nullableLabel(p.displayName) &&
        nullableLabel(p.username) &&
        [p.grantingGroupIds, p.entryGroupIds].every(
          (g) => Array.isArray(g) && g.length > 0 && g.every(label),
        ),
    ) &&
    Array.isArray(data.groups) &&
    data.groups.length <= 25 &&
    data.groups.every(
      (g) =>
        g &&
        label(g.groupId) &&
        (g.businessState === undefined
          ? data.businessState !== "per_assignment"
          : Object.hasOwn(personalLabels, g.businessState)) &&
        nullableLabel(g.groupName) &&
        typeof g.hasActiveMembers === "boolean" &&
        typeof g.originsComplete === "boolean" &&
        validOrigins(g.origins, g.groupId),
    ) &&
    validOrigins(data.origins, groupId) &&
    (collection === "origins" || data.origins.length === 0) &&
    (collection === "groups" || data.groups.length === 0) &&
    (collection === "people" || data.people.length === 0) &&
    (data.coverage !== "unavailable" ||
      (!data.people.length &&
        !data.groups.length &&
        !data.origins.length &&
        data.nextCursor === null))
  );
}
function Sources({ rows }: { rows: Origin[] }) {
  return (
    <ul aria-label="Matching assignments">
      {rows.map((o) => (
        <li key={JSON.stringify([o.assignmentId, o.action, o.scopeId])}>
          {o.action} · role <code>{o.roleId}</code> (revision {o.roleRevision})
          · scope <code>{o.scopeId}</code> (revision {o.scopeRevision}) ·
          assignment <code>{o.assignmentId}</code> (revision{" "}
          {o.assignmentRevision})
          {o.workflowDuties !== undefined && (
            <div>
              Linked planning duties · {o.workflowDuties.join(", ") || "none"}
            </div>
          )}
        </li>
      ))}
    </ul>
  );
}
export function ResourceAccessRoster({
  app,
  resource,
  revision,
}: {
  app: ApplicationSummary;
  resource: Resource;
  revision: number;
}) {
  const [page, setPage] = useState<Review | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const request = useRef<AbortController | null>(null);
  useEffect(() => () => request.current?.abort(), []);
  async function load(
    collection: Collection,
    groupId?: string,
    cursor?: string,
  ) {
    request.current?.abort();
    const current = new AbortController();
    request.current = current;
    setPage(null);
    setError("");
    setBusy(true);
    try {
      const data = await readSecurityProgram<Review>(
        app,
        resourceAccess,
        {
          ...resource,
          collection,
          limit: 25,
          expectedMetadataRevision: revision,
          ...(groupId ? { groupId } : {}),
          ...(cursor ? { cursor } : {}),
        },
        current.signal,
      );
      if (current.signal.aborted) return;
      if (
        !validPage(data, app, resource, collection, groupId) ||
        (cursor && cursor === data.nextCursor)
      )
        throw new Error("Invalid page");
      setPage(data);
    } catch {
      if (!current.signal.aborted)
        setError(
          "The resource access review is unavailable or has changed. Select people or groups to read it again.",
        );
    } finally {
      if (!current.signal.aborted) setBusy(false);
    }
  }
  return (
    <section aria-label="Resource access roster">
      <h4>Who has access to this resource?</h4>
      <button type="button" onClick={() => void load("people")}>
        Show entitled people
      </button>{" "}
      <button type="button" onClick={() => void load("groups")}>
        Show granting groups
      </button>
      {busy && <p role="status">Reading current assignments…</p>}
      {error && <p role="alert">{error}</p>}
      {page && (
        <>
          <p>
            As of{" "}
            <time dateTime={page.asOf}>
              {new Date(page.asOf).toLocaleString()}
            </time>
          </p>
          {page.coverage === "unavailable" ? (
            <p role="status">
              The resource or its assignments could not be verified within your
              review scope.
            </p>
          ) : (
            <>
              {page.coverage === "partial" && (
                <p role="status">
                  Directory evidence is incomplete. The results show the people
                  and groups that could be verified.
                </p>
              )}
              {page.action === "facts.write" && (
                <p>{businessLabels[page.businessState]}</p>
              )}
              {page.collection === "people" && (
                <>
                  <h5>People with an effective assignment</h5>
                  {page.people.length > 0 ? (
                    <ul>
                      {page.people.map((p) => (
                        <li key={p.subjectId}>
                          <strong>
                            {p.displayName || p.username || p.subjectId}
                          </strong>{" "}
                          · <code>{p.subjectId}</code>
                          <div>
                            Resource grant from {p.grantingGroupIds.join(", ")}
                          </div>
                          <div>
                            Application entry from {p.entryGroupIds.join(", ")}
                          </div>
                          {p.businessState && (
                            <div>{personalLabels[p.businessState]}</div>
                          )}
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <p>No matching people on this page.</p>
                  )}
                </>
              )}
              {page.collection === "groups" && (
                <>
                  <h5>Groups with a matching resource grant</h5>
                  {page.groups.length === 0 && (
                    <p>No matching groups on this page.</p>
                  )}
                  <ul>
                    {page.groups.map((g) => (
                      <li key={g.groupId}>
                        <strong>{g.groupName || g.groupId}</strong> ·{" "}
                        <code>{g.groupId}</code>
                        <div>
                          {g.hasActiveMembers
                            ? "Has active members"
                            : "No active members recorded"}
                        </div>
                        <Sources rows={g.origins} />
                        {g.businessState && (
                          <div>
                            Using this group’s grants ·{" "}
                            {personalLabels[g.businessState]}
                          </div>
                        )}
                        {!g.originsComplete && (
                          <button
                            type="button"
                            onClick={() => void load("origins", g.groupId)}
                          >
                            All assignment sources for{" "}
                            {g.groupName || g.groupId}
                          </button>
                        )}
                      </li>
                    ))}
                  </ul>
                </>
              )}
              {page.collection === "origins" && (
                <>
                  <h5>Assignment sources for {page.groupId}</h5>
                  <Sources rows={page.origins} />
                </>
              )}
              {page.nextCursor && (
                <button
                  type="button"
                  onClick={() =>
                    void load(page.collection, page.groupId, page.nextCursor!)
                  }
                >
                  Next{" "}
                  {page.collection === "origins"
                    ? "assignment sources"
                    : page.collection}
                </button>
              )}
            </>
          )}
        </>
      )}
    </section>
  );
}

type ViewPage = {
  grids: { gridId: string; name: string }[];
  nextAfterGridId: string | null;
  collectionToken: string;
};
export function SavedViewAccessReview({
  app,
  revision,
}: {
  app: ApplicationSummary;
  revision: number;
}) {
  const [page, setPage] = useState<ViewPage | null>(null);
  const [selected, setSelected] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const request = useRef<AbortController | null>(null);
  useEffect(() => () => request.current?.abort(), []);
  async function list(previous?: ViewPage) {
    request.current?.abort();
    const current = new AbortController();
    request.current = current;
    setSelected("");
    setError("");
    setPage(null);
    setBusy(true);
    try {
      const result = await readProgram<ViewPage>(
        app,
        "grid.definition.list",
        {
          limit: 25,
          ...(previous?.nextAfterGridId
            ? {
                afterGridId: previous.nextAfterGridId,
                expectedCollectionToken: previous.collectionToken,
              }
            : {}),
        },
        current.signal,
      );
      if (current.signal.aborted) return;
      if (
        !Array.isArray(result.grids) ||
        result.grids.length > 25 ||
        !result.grids.every((g) => g && label(g.gridId) && label(g.name)) ||
        !label(result.collectionToken) ||
        (previous && previous.collectionToken !== result.collectionToken) ||
        !nullableLabel(result.nextAfterGridId) ||
        (result.nextAfterGridId &&
          result.nextAfterGridId === previous?.nextAfterGridId)
      )
        throw new Error("Invalid page");
      setPage(result);
    } catch {
      if (!current.signal.aborted)
        setError(
          "The visible saved views could not be loaded. Choose a saved view again.",
        );
    } finally {
      if (!current.signal.aborted) setBusy(false);
    }
  }
  return (
    <section aria-label="Saved view access review">
      <h3>Review access to a saved view</h3>
      <button type="button" onClick={() => void list()}>
        Choose a saved view
      </button>
      {busy && <p role="status">Loading visible saved views…</p>}
      {error && <p role="alert">{error}</p>}
      {page && (
        <>
          {page.grids.length ? (
            <label>
              Saved view{" "}
              <select
                value={selected}
                onChange={(e) => setSelected(e.target.value)}
              >
                <option value="">Select a saved view</option>
                {page.grids.map((g) => (
                  <option key={g.gridId} value={g.gridId}>
                    {g.name} · {g.gridId}
                  </option>
                ))}
              </select>
            </label>
          ) : (
            <p>No visible saved views on this page.</p>
          )}
          {page.nextAfterGridId && (
            <button type="button" onClick={() => void list(page)}>
              Next saved views
            </button>
          )}
        </>
      )}
      {selected && (
        <ResourceAccessRoster
          key={selected}
          app={app}
          revision={revision}
          resource={{ action: "views.read", savedViewId: selected }}
        />
      )}
    </section>
  );
}
