import { useEffect, useMemo, useRef, useState } from "react";
import { request } from "./api";
import { ApplicationPurge } from "./ApplicationPurge";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import { setUnsavedWork, useUnsavedWork } from "./unsaved-work";
import { useStableMutationIntentKey } from "./mutation-intent";

const APPLICATION_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/;
const MAX_APPLICATION_PREFERENCES = 30;

type ApplicationPreferences = {
  favorites: string[];
  recent: string[];
};

const EMPTY_APPLICATION_PREFERENCES: ApplicationPreferences = {
  favorites: [],
  recent: [],
};

function applicationKey(application: ApplicationSummary) {
  return `${application.workspaceId}/${application.applicationId}`;
}

export function applicationPreferenceKey(subject: string) {
  return `openepm:applications:${subject}`;
}

export function readApplicationPreferences(
  subject: string,
): ApplicationPreferences {
  if (!subject || typeof window === "undefined") {
    return EMPTY_APPLICATION_PREFERENCES;
  }
  try {
    const value = JSON.parse(
      window.localStorage.getItem(applicationPreferenceKey(subject)) || "{}",
    ) as Partial<ApplicationPreferences>;
    const bounded = (items: unknown) =>
      Array.isArray(items)
        ? [
            ...new Set(
              items.filter((item): item is string => typeof item === "string"),
            ),
          ].slice(0, MAX_APPLICATION_PREFERENCES)
        : [];
    return {
      favorites: bounded(value.favorites),
      recent: bounded(value.recent),
    };
  } catch {
    return EMPTY_APPLICATION_PREFERENCES;
  }
}

function writeApplicationPreferences(
  subject: string,
  preferences: ApplicationPreferences,
) {
  if (!subject || typeof window === "undefined") return;
  try {
    window.localStorage.setItem(
      applicationPreferenceKey(subject),
      JSON.stringify(preferences),
    );
  } catch {
    // Personal display preferences must never block an authorized application.
  }
}

export type CreatedApplication = ApplicationSummary & {
  enabledCapabilities: string[];
  capabilityRevision: number;
};

export function applicationCreateProgram(applicationId: string, name: string) {
  return {
    languageVersion: 2,
    function: "workspace.application.create",
    arguments: {
      applicationId,
      name,
      kind: "multidimensional",
    },
  };
}

export function Applications({
  applications,
  selected,
  catalog,
  subject = "",
  choose,
  created,
  deleted,
  selectWorkspace,
  onRequestTransition = (action) => action(),
}: {
  applications: ApplicationSummary[];
  selected: number;
  catalog: ApplicationCatalog | null;
  subject?: string;
  choose: (index: number) => void;
  created: (application: CreatedApplication) => Promise<void>;
  deleted?: (workspaceId: string, applicationId: string) => Promise<void>;
  selectWorkspace?: (index: number) => void;
  onRequestTransition?: (action: () => void) => void;
}) {
  const mutationIntentKey = useStableMutationIntentKey("application-ui");
  const current = applications[selected];
  const workspaceAdministrator =
    catalog?.applicationAccess.workspaceAdministrator === true;
  const [createOpen, setCreateOpen] = useState(false);
  const [blueprintHelpOpen, setBlueprintHelpOpen] = useState(false);
  const blueprintHelpRef = useRef<HTMLDivElement | null>(null);
  const [applicationId, setApplicationId] = useState("");
  const [name, setName] = useState("");
  const [reviewed, setReviewed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [committedApplication, setCommittedApplication] =
    useState<CreatedApplication | null>(null);
  const [opening, setOpening] = useState(false);
  const [openingError, setOpeningError] = useState("");
  const [message, setMessage] = useState("");
  const creationDraftId = `application-create:${current?.workspaceId || "none"}`;
  useUnsavedWork(
    creationDraftId,
    "Unsaved application creation",
    Boolean(createOpen && (applicationId || name)),
  );
  const [error, setError] = useState("");
  const [query, setQuery] = useState("");
  const [favoritesOnly, setFavoritesOnly] = useState(false);
  const [preferences, setPreferences] = useState(() =>
    readApplicationPreferences(subject),
  );

  const workspaces = useMemo(() => {
    const found = new Map<string, string>();
    for (const application of applications)
      if (!found.has(application.workspaceId))
        found.set(
          application.workspaceId,
          application.workspaceName || application.workspaceId,
        );
    return [...found].map(([workspaceId, workspaceName]) => ({
      workspaceId,
      workspaceName,
    }));
  }, [applications]);
  const currentWorkspace = current
    ? {
        workspaceId: current.workspaceId,
        workspaceName: current.workspaceName || current.workspaceId,
      }
    : undefined;

  useEffect(() => {
    setPreferences(readApplicationPreferences(subject));
  }, [subject]);

  useEffect(() => {
    if (!blueprintHelpOpen) return;
    const dismiss = (event: PointerEvent) => {
      if (blueprintHelpRef.current?.contains(event.target as Node)) return;
      setBlueprintHelpOpen(false);
    };
    const escape = (event: KeyboardEvent) => {
      if (event.key === "Escape") setBlueprintHelpOpen(false);
    };
    document.addEventListener("pointerdown", dismiss);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("pointerdown", dismiss);
      document.removeEventListener("keydown", escape);
    };
  }, [blueprintHelpOpen]);

  const catalogEntries = useMemo(() => {
    const normalizedQuery = query.trim().toLocaleLowerCase();
    const favoriteSet = new Set(preferences.favorites);
    const recentRank = new Map(
      preferences.recent.map((key, index) => [key, index]),
    );
    return applications
      .map((application, index) => {
        const key = applicationKey(application);
        return {
          application,
          index,
          key,
          favorite: favoriteSet.has(key),
          recentRank: recentRank.get(key),
        };
      })
      .filter(({ application, favorite }) => {
        if (
          currentWorkspace &&
          application.workspaceId !== currentWorkspace.workspaceId
        )
          return false;
        if (favoritesOnly && !favorite) return false;
        if (!normalizedQuery) return true;
        return [
          application.name,
          application.workspaceId,
          application.applicationId,
        ].some((value) => value.toLocaleLowerCase().includes(normalizedQuery));
      })
      .sort((left, right) => {
        if (left.favorite !== right.favorite) return left.favorite ? -1 : 1;
        const leftRank = left.recentRank ?? Number.MAX_SAFE_INTEGER;
        const rightRank = right.recentRank ?? Number.MAX_SAFE_INTEGER;
        if (leftRank !== rightRank) return leftRank - rightRank;
        return left.index - right.index;
      });
  }, [
    applications,
    currentWorkspace?.workspaceId,
    favoritesOnly,
    preferences,
    query,
  ]);

  function chooseWorkspace(workspaceId: string) {
    const index = applications.findIndex(
      (application) => application.workspaceId === workspaceId,
    );
    if (index >= 0) (selectWorkspace || choose)(index);
  }

  function remember(preference: ApplicationPreferences) {
    setPreferences(preference);
    writeApplicationPreferences(subject, preference);
  }

  function openApplication(index: number, key: string) {
    remember({
      ...preferences,
      recent: [key, ...preferences.recent.filter((item) => item !== key)].slice(
        0,
        MAX_APPLICATION_PREFERENCES,
      ),
    });
    choose(index);
  }

  function toggleFavorite(key: string) {
    const favorites = preferences.favorites.includes(key)
      ? preferences.favorites.filter((item) => item !== key)
      : [key, ...preferences.favorites].slice(0, MAX_APPLICATION_PREFERENCES);
    remember({ ...preferences, favorites });
  }

  const trimmedId = applicationId.trim();
  const trimmedName = name.trim();
  const valid = useMemo(
    () =>
      Boolean(
        current &&
          workspaceAdministrator &&
          APPLICATION_ID.test(trimmedId) &&
          trimmedName &&
          trimmedName.length <= 500,
      ),
    [current, workspaceAdministrator, trimmedId, trimmedName],
  );

  function invalidateReview() {
    setReviewed(false);
    setMessage("");
    setError("");
  }

  async function submit() {
    if (!current || !valid || !reviewed || submitting || committedApplication)
      return;
    if (
      !window.confirm(
        `Create ${trimmedName} (${trimmedId}) in ${current.workspaceId}?`,
      )
    )
      return;
    setSubmitting(true);
    setError("");
    setMessage("");
    try {
      const result = await request<CreatedApplication>(
        "/api/workspace-application",
        {
          workspaceId: current.workspaceId,
          confirmed: true,
          idempotencyKey: mutationIntentKey({
            workspaceId: current.workspaceId,
            program: applicationCreateProgram(trimmedId, trimmedName),
          }),
          program: applicationCreateProgram(trimmedId, trimmedName),
        },
      );
      setCommittedApplication(result);
      setApplicationId("");
      setName("");
      setReviewed(false);
      setCreateOpen(false);
      // The write is committed. Settle this editor before navigation can read
      // the registry, without discarding any other editor's work.
      setUnsavedWork(creationDraftId, "Unsaved application creation", false);
      await refreshAndOpen(result);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Creation failed");
    } finally {
      setSubmitting(false);
    }
  }

  async function refreshAndOpen(application: CreatedApplication) {
    setOpening(true);
    setOpeningError("");
    try {
      await created(application);
      setCommittedApplication(null);
      setMessage(`${application.name} was created and opened.`);
    } catch (reason) {
      setOpeningError(
        reason instanceof Error
          ? reason.message
          : "Unable to refresh and open the application.",
      );
    } finally {
      setOpening(false);
    }
  }

  return (
    <div className="page applications-page">
      <div className="page-heading application-heading">
        <div>
          <span>Workspace</span>
          <h1>Applications</h1>
          <p>
            Choose the model you want to work in. Access is determined by your
            current grants.
          </p>
        </div>
        <button
          className="primary-action"
          onClick={() =>
            onRequestTransition(() => {
              setCreateOpen((value) => !value);
              setApplicationId("");
              setName("");
              setReviewed(false);
            })
          }
          disabled={
            !workspaceAdministrator ||
            !current ||
            submitting ||
            Boolean(committedApplication)
          }
          aria-expanded={createOpen}
          aria-controls="create-application-panel"
        >
          {createOpen ? "Close creation" : "Create application"}
        </button>
      </div>

      <section
        className="workspace-context"
        aria-labelledby="workspace-context-title"
      >
        <div>
          <span>Current workspace</span>
          <h2 id="workspace-context-title">
            {currentWorkspace?.workspaceName || "No accessible workspace"}
          </h2>
          <p>
            Stable workspace ID:{" "}
            <code>{currentWorkspace?.workspaceId || "—"}</code>
          </p>
        </div>
        <label>
          Workspace selector
          <select
            value={currentWorkspace?.workspaceId || ""}
            disabled={!workspaces.length}
            onChange={(event) => chooseWorkspace(event.target.value)}
          >
            {workspaces.map((workspace) => (
              <option key={workspace.workspaceId} value={workspace.workspaceId}>
                {workspace.workspaceName} ({workspace.workspaceId})
              </option>
            ))}
          </select>
        </label>
        <div className="workspace-authority">
          <strong>
            {workspaceAdministrator
              ? "Workspace Administrator"
              : "Application access"}
          </strong>
          <p>
            {workspaceAdministrator
              ? "You can create applications and manage access in this workspace."
              : "Open any application granted to your account."}
          </p>
        </div>
      </section>

      {workspaceAdministrator && currentWorkspace && deleted && (
        <ApplicationPurge
          workspaceId={currentWorkspace.workspaceId}
          applicationId={current?.applicationId || ""}
          subject={subject}
          deleted={deleted}
        />
      )}

      {!workspaceAdministrator && current && (
        <p className="application-guidance">
          Creating applications requires Workspace Administrator access. You can
          continue opening every application granted to you.
        </p>
      )}

      {createOpen && (
        <section
          className="create-application-panel"
          id="create-application-panel"
          aria-labelledby="create-application-title"
        >
          <div className="section-title">
            <div>
              <span>Governed lifecycle</span>
              <h2 id="create-application-title">
                Create a programmable multidimensional application
              </h2>
              <p>
                Start with eight empty dimensions: Account, Entity, Year,
                Period, View, Value, Scenario and Data Type. You will be the
                application's administrator and can define its members,
                attributes and calculations.
              </p>
            </div>
            <span className="workspace-pill">
              Workspace · {currentWorkspace?.workspaceName} (
              {currentWorkspace?.workspaceId})
            </span>
          </div>
          <div className="application-create-fields">
            <label>
              Stable application ID
              <input
                aria-label="Stable application ID"
                value={applicationId}
                maxLength={200}
                disabled={submitting}
                placeholder="operating-model"
                onChange={(event) => {
                  setApplicationId(event.target.value);
                  invalidateReview();
                }}
              />
              <small>Letters, numbers, dots, underscores and hyphens.</small>
            </label>
            <label>
              Application name
              <input
                aria-label="Application name"
                value={name}
                maxLength={500}
                disabled={submitting}
                placeholder="Operating Model"
                onChange={(event) => {
                  setName(event.target.value);
                  invalidateReview();
                }}
              />
              <small>Human-readable display name.</small>
            </label>
          </div>
          <div className={valid ? "creation-review ready" : "creation-review"}>
            <strong>
              {valid ? "Ready for review" : "Complete the required fields"}
            </strong>
            <p>
              {valid
                ? `Create ${trimmedName} (${trimmedId}) in ${current?.workspaceId}.`
                : "Use a valid stable ID and a nonempty application name."}
            </p>
          </div>
          <label className="review-check">
            <input
              type="checkbox"
              checked={reviewed}
              disabled={!valid || submitting}
              onChange={(event) => setReviewed(event.target.checked)}
            />
            <span>
              I reviewed the workspace and application identity. The eight
              required dimensions will be created automatically.
            </span>
            <span className="context-help" ref={blueprintHelpRef}>
              <button
                type="button"
                className="help-bubble-button"
                aria-label="What is created automatically?"
                aria-expanded={blueprintHelpOpen}
                aria-controls="blueprint-help-popover"
                onClick={(event) => {
                  event.preventDefault();
                  setBlueprintHelpOpen((value) => !value);
                }}
              >
                ?
              </button>
              {blueprintHelpOpen && (
                <span
                  className="help-popover"
                  id="blueprint-help-popover"
                  role="dialog"
                  aria-label="Automatic application blueprint"
                >
                  <strong>Automatic application blueprint</strong>
                  <span>
                    Eight empty dimensions are created: Account, Entity, Year,
                    Period, View, Value, Scenario and Data Type.
                  </span>
                  <span>
                    Each receives its stable ID, display name, model role,
                    semantic role, Sparse density and editable descriptions.
                    Entity is marked Core entity; the other seven are Context
                    dimensions. Names and descriptions do not enable
                    calculations.
                  </span>
                  <span>
                    No business members, hierarchies, formulas or custom
                    attributes are created. You define those after creation.
                  </span>
                </span>
              )}
            </span>
          </label>
          <div className="application-create-actions">
            <button
              className="primary-action"
              disabled={!valid || !reviewed || submitting}
              onClick={submit}
            >
              {submitting ? "Creating…" : "Create and open"}
            </button>
          </div>
          {error && (
            <p className="inline-error" role="alert">
              {error}
            </p>
          )}
        </section>
      )}

      {committedApplication && (
        <section
          className="create-application-panel"
          aria-labelledby="created-application-title"
        >
          <h2 id="created-application-title">Application created</h2>
          <p role="status">
            {committedApplication.name} ({committedApplication.workspaceId} /{" "}
            {committedApplication.applicationId}) was created successfully.
            {opening
              ? " Refreshing your application catalogue and opening the model…"
              : " Refresh the catalogue to open the model."}
          </p>
          {openingError && (
            <p className="inline-error" role="alert">
              The application was created, but it could not be opened:{" "}
              {openingError}
            </p>
          )}
          <button
            className="primary-action"
            disabled={opening}
            onClick={() => void refreshAndOpen(committedApplication)}
          >
            {opening ? "Opening…" : "Refresh and open"}
          </button>
        </section>
      )}

      {message && (
        <p className="write-result" role="status">
          {message}
        </p>
      )}
      <section className="application-catalog" aria-labelledby="catalog-title">
        <div className="application-catalog-toolbar">
          <div>
            <span>Personal catalogue</span>
            <h2 id="catalog-title">Your accessible applications</h2>
            <p>
              {catalogEntries.length} of {applications.length} applications
              shown. Favorites and recent ordering are personal to this browser.
            </p>
          </div>
          <label className="application-search">
            <span>Search applications</span>
            <input
              type="search"
              value={query}
              placeholder="Name, workspace or application ID"
              onChange={(event) => setQuery(event.target.value)}
            />
          </label>
        </div>
        <div
          className="application-catalog-filters"
          aria-label="Catalogue filters"
        >
          <button
            className={!favoritesOnly ? "active" : ""}
            aria-pressed={!favoritesOnly}
            onClick={() => setFavoritesOnly(false)}
          >
            All applications
          </button>
          <button
            className={favoritesOnly ? "active" : ""}
            aria-pressed={favoritesOnly}
            onClick={() => setFavoritesOnly(true)}
          >
            Favorites ({preferences.favorites.length})
          </button>
        </div>

        {catalogEntries.length ? (
          <div className="application-grid">
            {catalogEntries.map(
              ({ application: app, index, key, favorite, recentRank }) => (
                <article
                  key={key}
                  className={
                    index === selected
                      ? "application-card selected"
                      : "application-card"
                  }
                >
                  <button
                    className="application-card-open"
                    onClick={() => openApplication(index, key)}
                    aria-label={`Open ${app.name}`}
                  >
                    <span className="app-logo">{app.name.slice(0, 1)}</span>
                    <span className="application-card-copy">
                      <small>
                        {app.kind === "multidimensional"
                          ? "Programmable multidimensional"
                          : "Legacy application"}
                      </small>
                      <strong>{app.name}</strong>
                      <span>
                        {app.workspaceId} / {app.applicationId}
                      </span>
                    </span>
                    <span className="status">
                      <i />
                      {app.status}
                    </span>
                    {recentRank !== undefined && (
                      <span className="recent-application">
                        {recentRank === 0 ? "Most recent" : "Recent"}
                      </span>
                    )}
                    <em>Open →</em>
                  </button>
                  <button
                    className={
                      favorite ? "favorite-button active" : "favorite-button"
                    }
                    aria-pressed={favorite}
                    aria-label={`${favorite ? "Remove" : "Add"} ${app.name} ${
                      favorite ? "from" : "to"
                    } favorites`}
                    onClick={() => toggleFavorite(key)}
                  >
                    <span aria-hidden="true">{favorite ? "★" : "☆"}</span>
                  </button>
                </article>
              ),
            )}
          </div>
        ) : (
          <div className="empty-state application-catalog-empty">
            <span aria-hidden="true">⌕</span>
            <strong>
              {favoritesOnly
                ? "No favorite applications"
                : "No applications found"}
            </strong>
            <p>
              {favoritesOnly
                ? "Star an accessible application to keep it at the top of your personal catalogue."
                : "Try a different name, workspace or application ID."}
            </p>
          </div>
        )}
      </section>
    </div>
  );
}
