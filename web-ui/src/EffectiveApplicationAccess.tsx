import { useEffect, useRef, useState } from "react";
import {
  CoordinateAccessExplanation,
  explainAccess,
} from "./CoordinateAccessExplanation";
import { SavedViewAccessReview, resourceAccess } from "./ResourceAccessRoster";
import { ApiError, readSecurityProgram } from "./api";
import { outcomeAuthorityKey } from "./ReceiptInspector";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { securitySectionReads } from "./workspace-navigation";
import { validWorkflowDuties } from "./authorization-config";

const EFFECTIVE_ACCESS_LIST = securitySectionReads["effective-access"];
const PAGE_SIZE = 25;

type Tags = Record<string, string[]>;
type Privilege = {
  action: string;
  scopeId: string;
  scopeName?: string | null;
  scopeKind: string;
  selector: Record<string, unknown>;
  workflowDuties?: string[];
};
type Origin = {
  kind:
    | "application_direct"
    | "application_group"
    | "workspace_direct"
    | "workspace_group";
  groupId: string | null;
  groupName: string | null;
  role: string;
  roleName?: string | null;
  readTags: Tags;
  writeTags: Tags;
  rulePermissions: Record<string, boolean> | null;
  privileges: Privilege[];
};
type Person = {
  subjectId: string;
  displayName: string | null;
  username: string | null;
  directoryStatus: "Active" | "Inactive" | "Unresolved";
  applicationRole: string | null;
  admitted: boolean | null;
  workspaceAdministrator: boolean | null;
  originsComplete: boolean;
  origins: Origin[];
};
type Report = {
  workspaceId: string;
  applicationId: string;
  authorizationMode: "legacy" | "group_assignments";
  coverage: "complete_in_application" | "partial";
  coverageReasons: string[];
  asOf: string;
  people: Person[];
  nextCursor: string | null;
};
type Lookup = { query?: string; cursor?: string; subjectId?: string };

const originNames: Record<Origin["kind"], string> = {
  application_direct: "Direct application grant",
  application_group: "Application group assignment",
  workspace_direct: "Direct workspace grant",
  workspace_group: "Workspace group assignment",
};

function roleName(origin: Origin) {
  return origin.roleName || origin.role;
}

function showTags(tags: Tags) {
  return Object.entries(tags)
    .map(([axis, values]) => `${axis}: ${values.join(", ")}`)
    .join(" · ");
}

function yesNo(value: boolean | null) {
  return value === null ? "Unconfirmed" : value ? "Yes" : "No";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function isTagMap(value: unknown): value is Tags {
  return (
    isRecord(value) &&
    Object.values(value).every(
      (tags) =>
        Array.isArray(tags) && tags.every((tag) => typeof tag === "string"),
    )
  );
}

function validPrivilege(privilege: Privilege) {
  if (
    !privilege ||
    typeof privilege.action !== "string" ||
    typeof privilege.scopeId !== "string" ||
    !isRecord(privilege.selector) ||
    (privilege.workflowDuties !== undefined &&
      (privilege.action !== "facts.write" ||
        !validWorkflowDuties(privilege.workflowDuties))) ||
    (privilege.scopeName != null && typeof privilege.scopeName !== "string")
  )
    return false;
  switch (privilege.scopeKind) {
    case "entire_application":
      return Object.keys(privilege.selector).length === 0;
    case "dimension_tags":
      return isTagMap(privilege.selector);
    case "exact_object":
      return (
        typeof privilege.selector.objectType === "string" &&
        typeof privilege.selector.objectId === "string"
      );
    default:
      return false;
  }
}

function validOrigin(origin: Origin, mode: Report["authorizationMode"]) {
  if (
    !origin ||
    !Object.hasOwn(originNames, origin.kind) ||
    typeof origin.role !== "string" ||
    (origin.roleName != null && typeof origin.roleName !== "string") ||
    (origin.groupId !== null && typeof origin.groupId !== "string") ||
    (origin.groupName !== null && typeof origin.groupName !== "string") ||
    !Array.isArray(origin.privileges) ||
    !origin.privileges.every(validPrivilege)
  )
    return false;
  if (mode === "group_assignments") return true;
  return (
    isTagMap(origin.readTags) &&
    isTagMap(origin.writeTags) &&
    (origin.rulePermissions === null ||
      (isRecord(origin.rulePermissions) &&
        Object.values(origin.rulePermissions).every(
          (enabled) => typeof enabled === "boolean",
        )))
  );
}

function validPerson(person: Person, mode: Report["authorizationMode"]) {
  return (
    person &&
    typeof person.subjectId === "string" &&
    person.subjectId.length > 0 &&
    (person.username === null || typeof person.username === "string") &&
    (person.displayName === null || typeof person.displayName === "string") &&
    ["Active", "Inactive", "Unresolved"].includes(person.directoryStatus) &&
    (person.admitted === null || typeof person.admitted === "boolean") &&
    (person.workspaceAdministrator === null ||
      typeof person.workspaceAdministrator === "boolean") &&
    (person.applicationRole === null ||
      typeof person.applicationRole === "string") &&
    typeof person.originsComplete === "boolean" &&
    Array.isArray(person.origins) &&
    person.origins.every((origin) => validOrigin(origin, mode))
  );
}

function scopeDescription(privilege: Privilege) {
  switch (privilege.scopeKind) {
    case "entire_application":
      return "Entire application";
    case "exact_object":
      return `${privilege.selector.objectType} · ${privilege.selector.objectId}`;
    case "dimension_tags":
      return showTags(privilege.selector as Tags);
    default:
      return privilege.scopeId;
  }
}

function SourceList({
  person,
  mode,
}: {
  person: Person;
  mode: Report["authorizationMode"];
}) {
  return (
    <>
      <h3>Assignment sources</h3>
      {!person.originsComplete && (
        <p role="status">
          The report includes only part of this person's assignment sources.
        </p>
      )}
      {person.origins.map((origin, index) => (
        <section className="program-inspector" key={index}>
          <h4>
            {originNames[origin.kind]}
            {origin.groupId ? ` · ${origin.groupName || "Unnamed group"}` : ""}
          </h4>
          {origin.groupId && (
            <p>
              Group ID <code>{origin.groupId}</code>
            </p>
          )}
          <p>
            Assigned role <strong>{roleName(origin)}</strong>
          </p>
          {mode === "legacy" && (
            <dl>
              <dt>Read tag assignments</dt>
              <dd>{showTags(origin.readTags) || "None recorded"}</dd>
              <dt>Write tag assignments</dt>
              <dd>{showTags(origin.writeTags) || "None recorded"}</dd>
              <dt>Rule permissions on this grant</dt>
              <dd>
                {Object.entries(origin.rulePermissions || {})
                  .filter(([, enabled]) => enabled)
                  .map(([action]) => action)
                  .join(", ") || "None recorded"}
              </dd>
            </dl>
          )}
          {origin.privileges.length > 0 && (
            <dl>
              {origin.privileges.map((privilege, i) => (
                <div key={i}>
                  <dt>{privilege.action}</dt>
                  <dd>
                    {privilege.scopeName && (
                      <strong>{privilege.scopeName} · </strong>
                    )}
                    {scopeDescription(privilege)}{" "}
                    <small>({privilege.scopeId})</small>
                    {privilege.workflowDuties !== undefined && (
                      <div>
                        Linked planning duties ·{" "}
                        {privilege.workflowDuties.join(", ") || "none"}
                      </div>
                    )}
                  </dd>
                </div>
              ))}
            </dl>
          )}
        </section>
      ))}
    </>
  );
}

export function EffectiveApplicationAccess({
  app,
  catalog,
}: {
  app: ApplicationSummary;
  catalog: ApplicationCatalog;
}) {
  if (!catalog.functions[EFFECTIVE_ACCESS_LIST]) return null;
  return (
    <ApplicationReport
      key={JSON.stringify([
        outcomeAuthorityKey(app, catalog),
        catalog.revisions.policy,
        catalog.revisions.metadata,
      ])}
      app={app}
      catalog={catalog}
    />
  );
}

function ApplicationReport({
  app,
  catalog,
}: {
  app: ApplicationSummary;
  catalog: ApplicationCatalog;
}) {
  const [query, setQuery] = useState("");
  const [listing, setListing] = useState<Lookup>({});
  const [selectedSubject, setSelectedSubject] = useState("");
  const detail = Boolean(selectedSubject);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const active = useRef<AbortController | null>(null);
  const resultHeading = useRef<HTMLHeadingElement>(null);

  useEffect(() => () => active.current?.abort(), []);
  useEffect(() => {
    if (report) resultHeading.current?.focus();
  }, [report]);

  async function read(lookup: Lookup) {
    active.current?.abort();
    const current = new AbortController();
    active.current = current;
    setReport(null);
    setBusy(true);
    setError("");
    setSelectedSubject(lookup.subjectId || "");
    if (!lookup.subjectId) setListing(lookup);
    try {
      const page = await readSecurityProgram<Report>(
        app,
        EFFECTIVE_ACCESS_LIST,
        { ...lookup, limit: PAGE_SIZE },
        current.signal,
      );
      if (current.signal.aborted) return;
      if (
        !page ||
        page.applicationId !== app.applicationId ||
        page.workspaceId !== app.workspaceId ||
        !["legacy", "group_assignments"].includes(page.authorizationMode) ||
        !["partial", "complete_in_application"].includes(page.coverage) ||
        !Number.isFinite(Date.parse(page.asOf)) ||
        !Array.isArray(page.coverageReasons) ||
        !page.coverageReasons.every((reason) => typeof reason === "string") ||
        !Array.isArray(page.people) ||
        page.people.length > PAGE_SIZE ||
        !page.people.every((person) =>
          validPerson(person, page.authorizationMode),
        ) ||
        new Set(page.people.map((person) => person.subjectId)).size !==
          page.people.length ||
        (page.nextCursor !== null &&
          (typeof page.nextCursor !== "string" ||
            !page.nextCursor ||
            page.nextCursor === lookup.cursor)) ||
        (lookup.subjectId &&
          (page.people.length > 1 ||
            page.people.some(
              (person) => person.subjectId !== lookup.subjectId,
            )))
      ) {
        throw new Error("Invalid access report");
      }
      setReport(page);
    } catch (reason) {
      if (current.signal.aborted) return;
      if (reason instanceof ApiError && reason.kind === "authentication") {
        setError("Sign in again to review access.");
      } else if (
        reason instanceof ApiError &&
        [
          "EFFECTIVE_ACCESS_CURSOR_STALE",
          "SECURITY_READ_AUTHORIZATION_STALE",
        ].includes(reason.code)
      ) {
        setError(
          "Access changed during this review. Start a new search for current assignments.",
        );
      } else {
        setError(
          "The access report is unavailable. Start a new search to check current access.",
        );
      }
    } finally {
      if (!current.signal.aborted) setBusy(false);
    }
  }

  const selected = detail ? report?.people[0] : null;
  return (
    <section
      className="panel capability-activity"
      aria-labelledby="effective-access-heading"
    >
      <h2 id="effective-access-heading">Effective application access</h2>
      <p>
        Review directory entitlements in {app.name}. Current sessions are
        checked separately when a person uses the application.
      </p>
      <form
        className="security-catalog-search"
        onSubmit={(event) => {
          event.preventDefault();
          const term = query.trim();
          void read(term ? { query: term } : {});
        }}
      >
        <label className="form-field">
          Name or username
          <input
            type="search"
            value={query}
            maxLength={128}
            onChange={(event) => setQuery(event.target.value)}
          />
        </label>
        <button type="submit">
          {query.trim() ? "Find person" : "Show application roster"}
        </button>
      </form>
      {busy && <p role="status">Reading current access…</p>}
      {error && <p role="alert">{error}</p>}
      {report && (
        <>
          <h3 ref={resultHeading} tabIndex={-1}>
            {detail ? "Person’s access" : "Application roster"}
          </h3>
          <p>
            {report.coverage === "partial"
              ? "Partial coverage in this application."
              : "Complete within this application."}{" "}
            As of{" "}
            <time dateTime={report.asOf}>
              {new Date(report.asOf).toLocaleString()}
            </time>
            .
          </p>
          {report.coverageReasons.length > 0 && (
            <ul aria-label="Coverage details">
              {report.coverageReasons.map((reason) => (
                <li key={reason}>{reason.replaceAll("_", " ")}</li>
              ))}
            </ul>
          )}
          {detail && (
            <button type="button" onClick={() => void read(listing)}>
              Return to people
            </button>
          )}
          {!report.people.length && (
            <p>
              {report.coverage === "partial"
                ? "No matching person was returned in the available information."
                : "No matching access was found in this application."}
            </p>
          )}
          {selected && (
            <>
              <h4>
                {selected.displayName ||
                  selected.username ||
                  "Unresolved directory identity"}
              </h4>
              <dl>
                <dt>Username</dt>
                <dd>{selected.username || "Unavailable"}</dd>
                {!selected.username && (
                  <>
                    <dt>Directory identifier</dt>
                    <dd>
                      <code>{selected.subjectId}</code>
                    </dd>
                  </>
                )}
                <dt>Application admission</dt>
                <dd>{yesNo(selected.admitted)}</dd>
                <dt>Directory status</dt>
                <dd>{selected.directoryStatus}</dd>
                <dt>Workspace administrator</dt>
                <dd>{yesNo(selected.workspaceAdministrator)}</dd>
                {report.authorizationMode === "legacy" && (
                  <>
                    <dt>Evaluated legacy application role</dt>
                    <dd>{selected.applicationRole || "None confirmed"}</dd>
                  </>
                )}
              </dl>
              <SourceList person={selected} mode={report.authorizationMode} />
            </>
          )}
          {!detail && report.people.length > 0 && (
            <div
              className="react-grid-scroll"
              role="region"
              aria-label="Application access roster"
              tabIndex={0}
            >
              <table className="react-cube-grid security-grant-grid">
                <thead>
                  <tr>
                    <th scope="col">Person</th>
                    <th scope="col">Username</th>
                    <th scope="col">Directory status</th>
                    <th scope="col">Application admission</th>
                    <th scope="col">Assigned roles</th>
                  </tr>
                </thead>
                <tbody>
                  {report.people.map((person) => (
                    <tr key={person.subjectId}>
                      <th scope="row">
                        <button
                          type="button"
                          onClick={() =>
                            void read({ subjectId: person.subjectId })
                          }
                        >
                          {person.displayName ||
                            person.username ||
                            `Unresolved identity · ${person.subjectId}`}
                        </button>
                      </th>
                      <td>{person.username || "Unavailable"}</td>
                      <td>{person.directoryStatus}</td>
                      <td>{yesNo(person.admitted)}</td>
                      <td>
                        {Array.from(new Set(person.origins.map(roleName))).join(
                          ", ",
                        ) || "None confirmed"}
                        {!person.originsComplete && " (partial)"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {report.nextCursor && (
            <button
              type="button"
              onClick={() =>
                void read(
                  detail
                    ? { subjectId: selectedSubject, cursor: report.nextCursor! }
                    : { ...listing, cursor: report.nextCursor! },
                )
              }
            >
              {detail ? "Next assignment sources" : "Next people"}
            </button>
          )}
        </>
      )}
      {catalog.applicationAccess.authorizationModel === "group_assignments" &&
      (catalog.functions[explainAccess] || catalog.functions[resourceAccess]) &&
      catalog.functions["metadata.dimension.list"] &&
      catalog.functions["metadata.member.list"] ? (
        <CoordinateAccessExplanation
          app={app}
          revision={catalog.revisions.metadata}
          canReviewResource={Boolean(catalog.functions[resourceAccess])}
          canExplainPerson={Boolean(catalog.functions[explainAccess])}
          people={report?.people || []}
          activePerson={
            detail &&
            report?.people.some((p) => p.subjectId === selectedSubject)
              ? selectedSubject
              : undefined
          }
        />
      ) : null}
      {catalog.applicationAccess.authorizationModel === "group_assignments" &&
        Boolean(catalog.functions[resourceAccess]) &&
        Boolean(catalog.functions["grid.definition.list"]) && (
          <SavedViewAccessReview
            app={app}
            revision={catalog.revisions.metadata}
          />
        )}
    </section>
  );
}
