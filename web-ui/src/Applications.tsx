import {
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { ApiError, request } from "./api";
import { useManagedWorkspaces } from "./managed-workspaces";
import { WorkspaceAccessReview } from "./WorkspaceAccessReview";
import { BootstrapGroupPicker } from "./BootstrapGroupPicker";
import type { BootstrapGroup } from "./workspace-access";
import {
  workspacePeople,
  personApplications,
  bootstrapGroups,
} from "./workspace-access";
import { ApplicationPurge } from "./ApplicationPurge";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import {
  setUnsavedWork,
  usePreservedDraft,
  useUnsavedWork,
  type DraftRecoveryLease,
} from "./unsaved-work";

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
  authorizationModel?: "group_assignments";
  administratorGroupId?: string;
};

export function applicationCreateProgram(
  applicationId: string,
  name: string,
  administratorGroupId?: string,
) {
  return {
    languageVersion: 2,
    function: "workspace.application.create",
    arguments: {
      applicationId,
      name,
      kind: "multidimensional",
      ...(administratorGroupId ? { administratorGroupId } : {}),
    },
  };
}

type CreationRequest = {
  workspaceId: string;
  idempotencyKey: string;
  confirmed: true;
  program: ReturnType<typeof applicationCreateProgram>;
};

type OriginalCreation = { owner: string; request: CreationRequest };
type RecordedCreation = { application: CreatedApplication; open: boolean };

const creationRefusals = new Set([
  "APPLICATION_ID_OR_NAME_EXISTS",
  "APPLICATION_GROUP_BOOTSTRAP_UNAVAILABLE",
  "LAST_REACHABLE_APPLICATION_ADMINISTRATOR",
  "CONFIRMATION_REQUIRED",
  "PROGRAMMABLE_BLUEPRINT_SCHEMA_MISMATCH",
  "V2_APPLICATION_CREATE_INVALID",
  "WORKSPACE_ADMIN_REQUIRED",
  "WORKSPACE_UNAVAILABLE",
]);

function confirmsCreation(
  reply: unknown,
  { workspaceId, program }: CreationRequest,
): reply is CreatedApplication {
  if (!reply || typeof reply !== "object" || Array.isArray(reply)) return false;
  const application = reply as Partial<CreatedApplication>;
  return (
    application.workspaceId === workspaceId &&
    application.applicationId === program.arguments.applicationId &&
    application.name === program.arguments.name &&
    application.kind === program.arguments.kind &&
    application.status === "Active" &&
    (program.arguments.administratorGroupId === undefined ||
      (application.authorizationModel === "group_assignments" &&
        application.administratorGroupId ===
          program.arguments.administratorGroupId)) &&
    application.capabilityRevision === 0 &&
    Array.isArray(application.enabledCapabilities) &&
    application.enabledCapabilities.length === 0
  );
}

export function Applications({
  applications,
  selected,
  catalog,
  issuer = "",
  subject = "",
  choose,
  created,
  deleted,
  selectWorkspace,
  managedWorkspaceId = "",
  selectManagedWorkspace,
  onRequestTransition = (action) => action(),
}: {
  applications: ApplicationSummary[];
  selected: number;
  catalog: ApplicationCatalog | null;
  issuer?: string;
  subject?: string;
  choose: (index: number) => void;
  created: (
    application: CreatedApplication,
    signal: AbortSignal,
    open: boolean,
  ) => Promise<void>;
  deleted?: (workspaceId: string, applicationId: string) => Promise<void>;
  selectWorkspace?: (index: number) => void;
  managedWorkspaceId?: string;
  selectManagedWorkspace?: (workspaceId: string) => void;
  onRequestTransition?: (action: () => void) => void;
}) {
  const selectedApp = applications[selected];
  const [locallyChosen, setLocallyChosen] = useState("");
  const managed = useManagedWorkspaces(
    JSON.stringify([issuer, subject]),
    !selectedApp,
    managedWorkspaceId || locallyChosen,
    selectedApp?.workspaceId || "",
  );
  const workspaceId = managed.id;
  const current =
    selectedApp?.workspaceId === workspaceId ? selectedApp : undefined;
  const applicationCatalog = current ? catalog : null;
  const workspaceFunctions =
    managed.management?.functions ||
    applicationCatalog?.workspaceFunctions ||
    [];
  const creationOwner = JSON.stringify([issuer, subject, workspaceId]);
  const workspaceAdministrator =
    Boolean(managed.management) ||
    applicationCatalog?.applicationAccess.workspaceAdministrator === true;
  const canCreate = managed.management
    ? workspaceFunctions.includes("workspace.application.create") &&
      workspaceFunctions.includes(bootstrapGroups)
    : workspaceAdministrator;
  const guidedGroup = Boolean(workspaceFunctions.includes(bootstrapGroups));
  const groupContext = JSON.stringify([
    creationOwner,
    catalog?.accessContext,
    catalog?.revisions.security,
    guidedGroup,
  ]);
  const [groupChoice, setGroupChoice] = useState<{
    context: string;
    group: BootstrapGroup;
  } | null>(null);
  const group =
    groupChoice?.context === groupContext ? groupChoice.group : null;
  const blueprintDimensions = (
    managed.management?.applicationBlueprint ||
    applicationCatalog?.applicationBlueprint
  )?.dimensions;
  const [createOpen, setCreateOpen] = useState(false);
  const [blueprintHelpOpen, setBlueprintHelpOpen] = useState(false);
  const blueprintHelpId = useId();
  const blueprintHelpRef = useRef<HTMLDivElement | null>(null);
  const [applicationId, setApplicationId] = useState("");
  const [name, setName] = useState("");
  const [reviewed, setReviewed] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [savedCreation, setSavedCreation] = useState<OriginalCreation | null>(
    null,
  );
  const pendingCreation =
    savedCreation?.owner === creationOwner ? savedCreation : null;
  const creationRecovery = usePreservedDraft(
    workspaceId,
    "",
    `application-creation:${creationOwner}`,
    "Unconfirmed application creation",
    Boolean(pendingCreation),
    pendingCreation,
    setSavedCreation,
  );
  const activeCreation = useRef<AbortController | null>(null);
  const activeOpening = useRef<AbortController | null>(null);
  const [committedApplication, setCommittedApplication] =
    useState<RecordedCreation | null>(null);
  const [opening, setOpening] = useState(false);
  const [openingError, setOpeningError] = useState("");
  const [message, setMessage] = useState("");
  const creationDraftId = `application-create:${workspaceId || "none"}`;
  useUnsavedWork(
    creationDraftId,
    "Unsaved application creation",
    Boolean(createOpen && !pendingCreation && (applicationId || name || group)),
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
    for (const workspace of managed.workspaces)
      found.set(workspace.workspaceId, workspace.workspaceName);
    return [...found].map(([workspaceId, workspaceName]) => ({
      workspaceId,
      workspaceName,
    }));
  }, [applications, managed.workspaces]);
  const currentWorkspace = workspaces.find(
    (workspace) => workspace.workspaceId === workspaceId,
  );

  useEffect(() => {
    setPreferences(readApplicationPreferences(subject));
  }, [subject]);

  useLayoutEffect(() => {
    setSubmitting(false);
    setOpening(false);
    setCommittedApplication(null);
    setError("");
    return () => {
      activeCreation.current?.abort();
      activeCreation.current = null;
      activeOpening.current?.abort();
      activeOpening.current = null;
    };
  }, [creationOwner]);

  useEffect(() => {
    if (!blueprintHelpOpen) return;
    const dismiss = (event: MouseEvent) => {
      if (blueprintHelpRef.current?.contains(event.target as Node)) return;
      setBlueprintHelpOpen(false);
    };
    document.addEventListener("click", dismiss);
    return () => document.removeEventListener("click", dismiss);
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
    if (index >= 0) {
      setLocallyChosen("");
      (selectWorkspace || choose)(index);
    } else if (managed.workspaces.some((w) => w.workspaceId === workspaceId)) {
      if (selectManagedWorkspace) selectManagedWorkspace(workspaceId);
      else onRequestTransition(() => setLocallyChosen(workspaceId));
    }
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
        currentWorkspace &&
          canCreate &&
          (!guidedGroup || group) &&
          APPLICATION_ID.test(trimmedId) &&
          trimmedName &&
          Array.from(trimmedName).length <= 200,
      ),
    [currentWorkspace, canCreate, trimmedId, trimmedName, guidedGroup, group],
  );

  function invalidateReview() {
    setReviewed(false);
    setMessage("");
    setError("");
  }

  function submit() {
    if (
      !currentWorkspace ||
      !valid ||
      !reviewed ||
      pendingCreation ||
      activeCreation.current ||
      committedApplication
    )
      return;
    if (
      !window.confirm(
        `Create ${trimmedName} (${trimmedId}) in ${workspaceId}${group ? ` with administrator group ${group.displayName || group.groupName || group.groupId} (${group.groupId})` : ""}?`,
      )
    )
      return;
    const original: OriginalCreation = {
      owner: creationOwner,
      request: {
        workspaceId,
        confirmed: true,
        idempotencyKey: `application-ui-${crypto.randomUUID()}`,
        program: applicationCreateProgram(
          trimmedId,
          trimmedName,
          group?.groupId,
        ),
      },
    };
    try {
      const lease = creationRecovery.retain(original);
      setSavedCreation(original);
      void sendCreation(original, lease, true);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to retain the original request.",
      );
    }
  }

  function retryCreation() {
    if (
      !pendingCreation ||
      !creationRecovery.lease ||
      !workspaceAdministrator ||
      activeCreation.current
    )
      return;
    try {
      const lease = creationRecovery.retain(
        pendingCreation,
        creationRecovery.lease,
      );
      void sendCreation(pendingCreation, lease, false);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to restore the original request.",
      );
    }
  }

  async function sendCreation(
    original: OriginalCreation,
    lease: DraftRecoveryLease,
    initial: boolean,
  ) {
    const controller = new AbortController();
    activeCreation.current = controller;
    setSubmitting(true);
    setError("");
    setMessage("");
    try {
      const result = await request<unknown>(
        "/api/workspace-application",
        original.request,
        controller.signal,
      );
      if (!confirmsCreation(result, original.request)) {
        setError("The response could not confirm the original application.");
        return;
      }
      creationRecovery.release(lease, null);
      setSavedCreation(null);
      const committed = {
        application: result,
        open:
          initial &&
          (!original.request.program.arguments.administratorGroupId ||
            Boolean(group?.actorMember)),
      };
      setCommittedApplication(committed);
      setApplicationId("");
      setName("");
      setReviewed(false);
      setCreateOpen(false);
      setBlueprintHelpOpen(false);
      // The write is committed. Settle this editor before navigation can read
      // the registry, without discarding any other editor's work.
      setUnsavedWork(creationDraftId, "Unsaved application creation", false);
      await refreshCreation(committed);
    } catch (reason) {
      if (controller.signal.aborted) return;
      if (
        initial &&
        reason instanceof ApiError &&
        creationRefusals.has(reason.code)
      ) {
        creationRecovery.release(lease, null);
        setSavedCreation(null);
        setReviewed(false);
        setError(reason.message);
      } else {
        setError("The original application creation is still unconfirmed.");
      }
    } finally {
      if (activeCreation.current === controller) {
        activeCreation.current = null;
        setSubmitting(false);
      }
    }
  }

  async function refreshCreation({ application, open }: RecordedCreation) {
    if (activeOpening.current) return;
    const controller = new AbortController();
    activeOpening.current = controller;
    setOpening(true);
    setOpeningError("");
    try {
      await created(application, controller.signal, open);
      if (controller.signal.aborted) return;
      setCommittedApplication(null);
      setMessage(
        open
          ? `${application.name} was created and opened.`
          : `Creation of ${application.name} (${application.applicationId}) was recorded. The application catalogue is current.`,
      );
    } catch (reason) {
      if (!controller.signal.aborted)
        setOpeningError(
          reason instanceof Error
            ? reason.message
            : "Unable to refresh the application catalogue.",
        );
    } finally {
      if (activeOpening.current === controller) {
        activeOpening.current = null;
        setOpening(false);
      }
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
              setBlueprintHelpOpen(false);
              setApplicationId("");
              setName("");
              setGroupChoice(null);
              setReviewed(false);
            })
          }
          disabled={
            !canCreate ||
            !currentWorkspace ||
            submitting ||
            Boolean(pendingCreation) ||
            Boolean(committedApplication)
          }
          aria-expanded={createOpen && !pendingCreation}
          aria-controls="create-application-panel"
        >
          {createOpen && !pendingCreation
            ? "Close creation"
            : "Create application"}
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
        <div>
          <button
            type="button"
            disabled={managed.busy}
            onClick={managed.refresh}
          >
            Find managed workspaces
          </button>
          {managed.busy && <p role="status">Reading workspace access…</p>}
          {managed.error && <p role="status">{managed.error}</p>}
          {managed.missing && (
            <p role="status">
              This workspace is unavailable under your current access.
            </p>
          )}
        </div>
        <div className="workspace-authority">
          <strong>
            {workspaceAdministrator
              ? "Workspace Administrator"
              : "Application access"}
          </strong>
          <p>
            {workspaceAdministrator
              ? canCreate
                ? "You can create applications and manage access in this workspace."
                : "You can review access in this workspace."
              : "Open any application granted to your account."}
          </p>
        </div>
      </section>

      {workspaceAdministrator &&
        currentWorkspace &&
        workspaceFunctions.includes(workspacePeople) &&
        workspaceFunctions.includes(personApplications) && (
          <WorkspaceAccessReview
            key={JSON.stringify([
              creationOwner,
              applicationCatalog?.accessContext,
              applicationCatalog?.revisions.security,
            ])}
            workspaceId={workspaceId}
          />
        )}
      {workspaceAdministrator && current && currentWorkspace && deleted && (
        <ApplicationPurge
          workspaceId={currentWorkspace.workspaceId}
          applicationId={current?.applicationId || ""}
          issuer={issuer}
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

      {createOpen && !pendingCreation && (
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
                Period, View, Value, Scenario and Data Type.{" "}
                {guidedGroup
                  ? "The selected group will manage application access. Business data permissions are assigned separately."
                  : "You will be the application's administrator and can define its members, attributes and calculations."}
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
          {guidedGroup && (
            <BootstrapGroupPicker
              key={groupContext}
              workspaceId={workspaceId}
              disabled={submitting}
              selected={group}
              choose={(value) => {
                setGroupChoice(
                  value ? { context: groupContext, group: value } : null,
                );
                invalidateReview();
              }}
            />
          )}
          <div className={valid ? "creation-review ready" : "creation-review"}>
            <strong>
              {valid ? "Ready for review" : "Complete the required fields"}
            </strong>
            <p>
              {valid
                ? `Create ${trimmedName} (${trimmedId}) in ${workspaceId}.`
                : guidedGroup
                  ? "Provide a stable ID, an application name and an eligible administrator group."
                  : "Use a valid stable ID and an application name of 1 to 200 characters."}
            </p>
          </div>
          <div className="application-blueprint-help" ref={blueprintHelpRef}>
            <button
              type="button"
              className="secondary"
              aria-expanded={blueprintHelpOpen}
              aria-controls={blueprintHelpId}
              onClick={() => setBlueprintHelpOpen((value) => !value)}
              onKeyDown={(event) => {
                if (!blueprintHelpOpen || event.key !== "Escape") return;
                event.preventDefault();
                event.stopPropagation();
                setBlueprintHelpOpen(false);
              }}
            >
              What is created automatically?
            </button>
            <div
              id={blueprintHelpId}
              role="region"
              aria-label="Automatic application blueprint"
              hidden={!blueprintHelpOpen}
            >
              {blueprintDimensions?.length ? (
                <>
                  <p>
                    Each axis below is created automatically. A fact’s
                    coordinate will include a member on each axis.
                  </p>
                  <dl className="application-blueprint-dimensions">
                    {blueprintDimensions.map((dimension) => (
                      <div key={dimension.dimensionId}>
                        <dt>{dimension.name}</dt>
                        <dd>{dimension.shortDescription}</dd>
                      </div>
                    ))}
                  </dl>
                  <p>
                    Add business members, hierarchies, formulas and custom
                    attributes after creation.
                  </p>
                </>
              ) : (
                <p>
                  The current workspace did not provide a blueprint preview.
                </p>
              )}
            </div>
          </div>
          <label className="review-check">
            <input
              type="checkbox"
              checked={reviewed}
              disabled={!valid || submitting}
              onChange={(event) => setReviewed(event.target.checked)}
            />
            <span>I reviewed the workspace and application identity.</span>
          </label>
          <div className="application-create-actions">
            <button
              className="primary-action"
              disabled={!valid || !reviewed || submitting}
              onClick={submit}
            >
              {submitting
                ? "Creating…"
                : guidedGroup && !group?.actorMember
                  ? "Create for selected group"
                  : "Create and open"}
            </button>
          </div>
          {error && (
            <p className="inline-error" role="alert">
              {error}
            </p>
          )}
        </section>
      )}

      {pendingCreation && (
        <section
          className="create-application-panel"
          aria-labelledby="pending-creation-title"
        >
          <h2 id="pending-creation-title">Application creation unconfirmed</h2>
          <p role="status">
            {submitting
              ? "Waiting for the original application creation."
              : "The outcome is still unconfirmed."}
          </p>
          <p>
            {pendingCreation.request.program.arguments.name} (
            {pendingCreation.request.program.arguments.applicationId})
          </p>
          <p>
            Workspace {pendingCreation.request.workspaceId}. Retry the same
            request to recover an existing result or finish the confirmed
            creation.
          </p>
          {!workspaceAdministrator && (
            <p>Retry requires current Workspace Administrator access.</p>
          )}
          {error && (
            <p className="inline-error" role="alert">
              {error}
            </p>
          )}
          <button
            type="button"
            className="primary-action"
            onClick={retryCreation}
            disabled={
              submitting || !workspaceAdministrator || !creationRecovery.lease
            }
          >
            Retry original creation
          </button>
          <details className="context-note">
            <summary>Original MCP request</summary>
            <p>
              Use the workspace listener for{" "}
              {pendingCreation.request.workspaceId} with the account that
              approved the request.
            </p>
            <pre className="creation-request">
              {JSON.stringify(
                {
                  tool: "execute_v2_workspace_program",
                  arguments: {
                    program: pendingCreation.request.program,
                    idempotency_key: pendingCreation.request.idempotencyKey,
                  },
                },
                null,
                2,
              )}
            </pre>
          </details>
        </section>
      )}

      {committedApplication && (
        <section
          className="create-application-panel"
          aria-labelledby="created-application-title"
        >
          <h2 id="created-application-title">
            {committedApplication.open
              ? "Application created"
              : "Application creation recorded"}
          </h2>
          <p role="status">
            {committedApplication.application.name} (
            {committedApplication.application.workspaceId} /{" "}
            {committedApplication.application.applicationId}) was created
            successfully.
            {opening
              ? " Refreshing your application catalogue…"
              : committedApplication.open
                ? " Refresh the catalogue to open the model."
                : " Refresh the catalogue to see current applications."}
          </p>
          {openingError && (
            <p className="inline-error" role="alert">
              {committedApplication.open
                ? "The application was created, but it could not be opened: "
                : "The catalogue could not be refreshed: "}
              {openingError}
            </p>
          )}
          <button
            className="primary-action"
            disabled={opening}
            onClick={() => void refreshCreation(committedApplication)}
          >
            {opening
              ? "Refreshing…"
              : committedApplication.open
                ? "Refresh and open"
                : "Refresh catalogue"}
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
                : currentWorkspace &&
                    !applications.some((a) => a.workspaceId === workspaceId)
                  ? "Your account has no admitted applications in this workspace."
                  : "Try a different name, workspace or application ID."}
            </p>
          </div>
        )}
      </section>
    </div>
  );
}
