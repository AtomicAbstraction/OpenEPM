import { useEffect, useRef, useState } from "react";
import {
  personApplications,
  workspaceAccessRead,
  workspacePeople,
} from "./workspace-access";
import type { EntitledApplication, WorkspacePerson } from "./workspace-access";

type Page = {
  coverage: "complete_in_workspace" | "partial";
  coverageReasons: string[];
  asOf: string;
  nextCursor: string | null;
};
type View =
  | {
      kind: "people";
      query: string;
      admins: boolean;
      people: WorkspacePerson[];
      page: Page;
    }
  | {
      kind: "applications";
      person: WorkspacePerson;
      applications: EntitledApplication[];
      page: Page;
    };
type Search =
  | { kind: "people"; query: string; admins: boolean }
  | { kind: "applications"; person: WorkspacePerson };

export function WorkspaceAccessReview({
  workspaceId,
}: {
  workspaceId: string;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [admins, setAdmins] = useState(false);
  const [view, setView] = useState<View | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const request = useRef<AbortController | null>(null);
  useEffect(() => () => request.current?.abort(), []);
  async function read(search: Search, cursor?: string) {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setView(null);
    setError("");
    setBusy(true);
    const args = { limit: 25, ...(cursor ? { cursor } : {}) };
    try {
      if (search.kind === "people") {
        const page = await workspaceAccessRead(
          workspaceId,
          workspacePeople,
          {
            ...args,
            ...(search.query ? { query: search.query } : {}),
            administratorsOnly: search.admins,
          },
          controller.signal,
        );
        if (!controller.signal.aborted)
          setView({ ...search, page, people: page.people });
      } else {
        const page = await workspaceAccessRead(
          workspaceId,
          personApplications,
          { ...args, subjectId: search.person.subjectId },
          controller.signal,
        );
        if (!controller.signal.aborted)
          setView({ ...search, page, applications: page.applications });
      }
    } catch {
      if (!controller.signal.aborted)
        setError(
          "The workspace access report is unavailable or has changed. Start a new search.",
        );
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }
  function toggle() {
    request.current?.abort();
    setView(null);
    setError("");
    setBusy(false);
    setOpen(!open);
  }
  return (
    <section aria-labelledby="workspace-review-title" className="panel">
      <h2 id="workspace-review-title">Workspace access</h2>
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        aria-controls="workspace-access-search"
      >
        {open ? "Close access review" : "Review people and administrators"}
      </button>
      {open && (
        <div id="workspace-access-search">
          <form
            onSubmit={(event) => {
              event.preventDefault();
              void read({ kind: "people", query: query.trim(), admins });
            }}
          >
            <label>
              Name or username
              <input
                type="search"
                maxLength={128}
                value={query}
                onChange={(event) => setQuery(event.target.value)}
              />
            </label>
            <label>
              <input
                type="checkbox"
                checked={admins}
                onChange={(event) => setAdmins(event.target.checked)}
              />
              Workspace administrators only
            </label>
            <button type="submit">
              {query.trim()
                ? "Find person in workspace"
                : "List workspace people"}
            </button>
          </form>
          {busy && <p role="status">Reading workspace access…</p>}
          {error && <p role="alert">{error}</p>}
          {view && (
            <>
              <p>
                Directory access as of{" "}
                <time dateTime={view.page.asOf}>
                  {new Date(view.page.asOf).toLocaleString()}
                </time>
                .
              </p>
              {view.page.coverage === "partial" && (
                <p role="status">
                  Partial workspace coverage.{" "}
                  {view.page.coverageReasons
                    .map((value) => value.replaceAll("_", " "))
                    .join(", ")}
                  . Missing entries may have unresolved directory information.
                </p>
              )}
              {view.kind === "people" ? (
                <>
                  <h3>
                    {view.admins
                      ? "Workspace administrators"
                      : "People in this workspace"}
                  </h3>
                  {!view.people.length && (
                    <p>No matching access records in this workspace.</p>
                  )}
                  <ul>
                    {view.people.map((person) => (
                      <li key={person.subjectId}>
                        <strong>
                          {person.displayName ||
                            person.username ||
                            person.subjectId}
                        </strong>{" "}
                        · {person.directoryStatus}
                        {person.username && <> · {person.username}</>} ·{" "}
                        <code>{person.subjectId}</code>
                        <p>
                          Workspace administration ·{" "}
                          {person.workspaceAdministrator === null
                            ? "Unresolved"
                            : person.workspaceAdministrator
                              ? "Granted"
                              : "No current grant"}
                        </p>
                        {person.origins.map((origin, index) => (
                          <p key={index}>
                            {origin.kind === "workspace_group"
                              ? `Workspace group · ${origin.groupName || "Unnamed group"} (${origin.groupId})`
                              : "Direct workspace assignment"}
                          </p>
                        ))}
                        {!person.originsComplete && (
                          <p>Additional workspace grant sources exist.</p>
                        )}
                        <button
                          type="button"
                          onClick={() =>
                            void read({ kind: "applications", person })
                          }
                        >
                          View applications for{" "}
                          {person.displayName ||
                            person.username ||
                            person.subjectId}
                        </button>
                      </li>
                    ))}
                  </ul>
                </>
              ) : (
                <>
                  <h3>
                    Applications for{" "}
                    {view.person.displayName ||
                      view.person.username ||
                      view.person.subjectId}
                  </h3>
                  <p>
                    Directory subject <code>{view.person.subjectId}</code>
                  </p>
                  {!view.applications.length && (
                    <p>
                      No current application entries were returned in this
                      workspace.
                    </p>
                  )}
                  <ul>
                    {view.applications.map((application) => (
                      <li key={application.applicationId}>
                        <strong>{application.applicationName}</strong> ·{" "}
                        <code>{application.applicationId}</code>
                        <p>
                          {application.workspaceInherited
                            ? "Inherited through workspace administration"
                            : application.authorizationMode ===
                                "group_assignments"
                              ? "Entry through group assignment"
                              : "Application grant"}
                        </p>
                        <p>
                          Roles ·{" "}
                          {application.roleNames.join(", ") ||
                            application.applicationRole ||
                            "No named role returned"}
                          {!application.rolesComplete &&
                            " · Additional roles exist"}
                        </p>
                      </li>
                    ))}
                  </ul>
                  <button
                    type="button"
                    onClick={() =>
                      void read({ kind: "people", query: query.trim(), admins })
                    }
                  >
                    Back to people
                  </button>
                </>
              )}
              {view.page.nextCursor && (
                <button
                  type="button"
                  onClick={() =>
                    void read(view, view.page.nextCursor || undefined)
                  }
                >
                  Next {view.kind === "people" ? "people" : "applications"}
                </button>
              )}
            </>
          )}
        </div>
      )}
    </section>
  );
}
