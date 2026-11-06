import { lazy, Suspense, useEffect, useMemo, useRef, useState } from "react";
import {
  ApiError,
  listApplications,
  readCatalog,
  readPlatformCatalog,
  readRuntime,
  readProgram,
  readSession,
  request,
} from "./api";
import type {
  ApplicationCatalog,
  ApplicationSummary,
  SessionIdentity,
} from "./types";
import { GlobalSearch, HelpPanel, Notifications } from "./GlobalPanels";
import { Applications } from "./Applications";
import type { CreatedApplication } from "./Applications";
import {
  browserLifecycleSnapshot,
  installConnectivityLifecycle,
  subscribeBrowserLifecycle,
} from "./browser-lifecycle";
import type { BrowserLifecycleSnapshot } from "./browser-lifecycle";
import {
  discardUnsavedWork,
  setDraftIdentity,
  subscribeUnsavedWork,
  unsavedWorkSnapshot,
} from "./unsaved-work";
import type { UnsavedWorkItem } from "./unsaved-work";
import { resolveWorkflowDestination } from "./workflow-destination";

const Analyze = lazy(() =>
  import("./Analyze").then((module) => ({ default: module.Analyze })),
);
const CapabilityArea = lazy(() =>
  import("./CapabilityArea").then((module) => ({
    default: module.CapabilityArea,
  })),
);
const Monitor = lazy(() =>
  import("./Monitor").then((module) => ({ default: module.Monitor })),
);
const MyWork = lazy(() =>
  import("./MyWork").then((module) => ({ default: module.MyWork })),
);
const GenericWorkflow = lazy(() =>
  import("./GenericWorkflow").then((module) => ({
    default: module.GenericWorkflow,
  })),
);
const ServerAdministration = lazy(() =>
  import("./ServerAdministration").then((module) => ({
    default: module.ServerAdministration,
  })),
);

type Page =
  | "home"
  | "applications"
  | "work"
  | "server"
  | "overview"
  | "grid"
  | "data"
  | "metadata"
  | "lists"
  | "rules"
  | "flows"
  | "tasks"
  | "monitor"
  | "security"
  | "administration";

type WorkFocus = {
  workspaceId?: string;
  applicationId?: string;
  assignmentId?: string;
  occurrenceId?: string;
  activityId?: string;
  viewId?: string;
  viewVersion?: number;
  viewDigest?: string;
  artifactKind?:
    | "ApplicationRule"
    | "CalculatedMember"
    | "ApplicationSequence"
    | "ApplicationSchedule";
  artifactId?: string;
  artifactVersion?: number;
  artifactDigest?: string;
};

export function presentationRouteHash(
  page: Page,
  applicationIndex: number,
  focus: WorkFocus = {},
) {
  const query = new URLSearchParams();
  if (focus.workspaceId && focus.applicationId) {
    query.set("workspace", focus.workspaceId);
    query.set("application", focus.applicationId);
  }
  if (page === "flows" && focus.occurrenceId) {
    query.set("occurrence", focus.occurrenceId);
    if (focus.activityId) query.set("activity", focus.activityId);
  }
  if (
    page === "grid" &&
    focus.viewId &&
    focus.viewVersion &&
    focus.viewDigest
  ) {
    query.set("view", focus.viewId);
    query.set("viewVersion", String(focus.viewVersion));
    query.set("viewDigest", focus.viewDigest);
  }
  if (
    page === "rules" &&
    focus.artifactKind &&
    focus.artifactId &&
    focus.artifactVersion &&
    focus.artifactDigest
  ) {
    query.set("artifactKind", focus.artifactKind);
    query.set("artifactId", focus.artifactId);
    query.set("artifactVersion", String(focus.artifactVersion));
    query.set("artifactDigest", focus.artifactDigest);
  }
  if (page !== "flows" && focus.occurrenceId) {
    query.set("returnOccurrence", focus.occurrenceId);
    if (focus.activityId) query.set("returnActivity", focus.activityId);
  }
  return `#/${page}/${applicationIndex}${query.size ? `?${query}` : ""}`;
}

const primary: { id: Page; label: string; icon: string }[] = [
  { id: "home", label: "Home", icon: "⌂" },
  { id: "applications", label: "Applications", icon: "◇" },
  { id: "work", label: "My Work", icon: "✓" },
  { id: "server", label: "Server Administration", icon: "⚙" },
];
const applicationPages: { id: Page; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "grid", label: "Grid" },
  { id: "data", label: "Data" },
  { id: "metadata", label: "Metadata" },
  { id: "lists", label: "Member Lists" },
  { id: "rules", label: "Rules" },
  { id: "flows", label: "Flows" },
  { id: "tasks", label: "Tasks" },
  { id: "monitor", label: "Monitor" },
  { id: "security", label: "Users & Security" },
  { id: "administration", label: "Administration" },
];

export function applicationPageVisible(
  page: Page,
  catalog: ApplicationCatalog | null,
) {
  if (page === "administration" || page === "security")
    return Boolean(
      catalog?.applicationAccess.role === "Administrator" ||
        catalog?.applicationAccess.workspaceAdministrator,
    );
  if (["metadata", "lists", "rules"].includes(page))
    return Boolean(catalog && catalog.applicationAccess.role !== "Reader");
  return true;
}

export function shareableViewUrl(
  location: Pick<Location, "origin" | "pathname" | "hash">,
) {
  return `${location.origin}${location.pathname}${location.hash}`;
}

export function browserLogoutPath() {
  return "/oidc/sign_out";
}

export function runtimeBuildFingerprint(build: {
  applicationImage?: string;
  sourceCommit?: string;
  sourceTree?: string;
  packagedSchema?: number;
}) {
  return JSON.stringify({
    applicationImage: build.applicationImage || null,
    sourceCommit: build.sourceCommit || null,
    sourceTree: build.sourceTree || null,
    packagedSchema: build.packagedSchema ?? null,
  });
}

export function editableShortcutTarget(target: EventTarget | null) {
  if (!(target instanceof HTMLElement)) return false;
  return (
    target.isContentEditable ||
    ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName)
  );
}

const pageIds = new Set<Page>([
  ...primary.map((item) => item.id),
  ...applicationPages.map((item) => item.id),
]);

export function readPresentationRoute() {
  const match = window.location.hash.match(
    /^#\/([a-z-]+)(?:\/(\d+))?(?:\?(.*))?$/,
  );
  const legacyAliases: Record<string, Page> = {
    analyze: "grid",
    workflow: "flows",
    build: "metadata",
  };
  const requested = match?.[1] || "";
  const candidate = (legacyAliases[requested] || requested) as Page | undefined;
  const query = new URLSearchParams(match?.[3] || "");
  const rawViewVersion = Number(query.get("viewVersion"));
  const viewVersion =
    Number.isInteger(rawViewVersion) && rawViewVersion > 0
      ? rawViewVersion
      : undefined;
  const rawViewDigest = query.get("viewDigest") || "";
  const viewDigest = /^[0-9a-f]{64}$/.test(rawViewDigest)
    ? rawViewDigest
    : undefined;
  const rawArtifactVersion = Number(query.get("artifactVersion"));
  const rawArtifactDigest = query.get("artifactDigest") || "";
  const artifactKind = query.get("artifactKind");
  return {
    page: candidate && pageIds.has(candidate) ? candidate : ("home" as Page),
    applicationIndex: Math.max(0, Number(match?.[2] || 0) || 0),
    focus: {
      workspaceId: query.get("workspace") || undefined,
      applicationId: query.get("application") || undefined,
      assignmentId: query.get("assignment") || undefined,
      viewId: query.get("view") || undefined,
      viewVersion,
      viewDigest,
      artifactKind:
        artifactKind === "ApplicationRule" ||
        artifactKind === "CalculatedMember" ||
        artifactKind === "ApplicationSequence" ||
        artifactKind === "ApplicationSchedule"
          ? artifactKind
          : undefined,
      artifactId: /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/.test(
        query.get("artifactId") || "",
      )
        ? query.get("artifactId") || undefined
        : undefined,
      artifactVersion:
        Number.isSafeInteger(rawArtifactVersion) && rawArtifactVersion > 0
          ? rawArtifactVersion
          : undefined,
      artifactDigest: /^[0-9a-f]{64}$/.test(rawArtifactDigest)
        ? rawArtifactDigest
        : undefined,
      occurrenceId:
        query.get("occurrence") || query.get("returnOccurrence") || undefined,
      activityId:
        query.get("activity") || query.get("returnActivity") || undefined,
    } as WorkFocus,
  };
}

function initials(value?: string) {
  return (value || "?").slice(0, 1).toLocaleUpperCase();
}

function AppIcon() {
  return (
    <span className="brand-mark" aria-hidden="true">
      <i />
      <i />
      <i />
    </span>
  );
}

export function App() {
  const initialRoute = useMemo(readPresentationRoute, []);
  const [applications, setApplications] = useState<ApplicationSummary[]>([]);
  const [selected, setSelected] = useState(initialRoute.applicationIndex);
  const [identity, setIdentity] = useState<SessionIdentity | null>(null);
  setDraftIdentity(identity?.subject || "anonymous");
  const identityRef = useRef<SessionIdentity | null>(null);
  const [pendingIdentity, setPendingIdentity] =
    useState<SessionIdentity | null>(null);
  const [catalog, setCatalog] = useState<ApplicationCatalog | null>(null);
  const [platformCatalog, setPlatformCatalog] = useState<{
    languageVersion: number;
    functions: Record<string, unknown>;
  } | null>(null);
  const [platformChecked, setPlatformChecked] = useState(false);
  const [page, setPage] = useState<Page>(initialRoute.page);
  const [workFocus, setWorkFocus] = useState<WorkFocus>(initialRoute.focus);
  const [collapsed, setCollapsed] = useState(
    () =>
      typeof window !== "undefined" &&
      Boolean(window.matchMedia?.("(max-width: 650px)").matches),
  );
  const [accountOpen, setAccountOpen] = useState(false);
  const accountButtonRef = useRef<HTMLButtonElement | null>(null);
  const accountCardRef = useRef<HTMLElement | null>(null);
  const [copyStatus, setCopyStatus] = useState("");
  const copyStatusTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [browserLifecycle, setBrowserLifecycleState] =
    useState<BrowserLifecycleSnapshot>(browserLifecycleSnapshot);
  const [unsavedWork, setUnsavedWorkState] =
    useState<UnsavedWorkItem[]>(unsavedWorkSnapshot);
  const [discardPromptOpen, setDiscardPromptOpen] = useState(false);
  const discardDialogRef = useRef<HTMLElement | null>(null);
  const discardTriggerRef = useRef<HTMLElement | null>(null);
  const [releaseAvailable, setReleaseAvailable] = useState(false);
  const runtimeBuild = useRef<string | null>(null);
  const pendingTransition = useRef<null | (() => void)>(null);
  const app = applications[selected];

  function acceptSession(session: SessionIdentity) {
    const current = identityRef.current;
    if (
      current &&
      current.subject !== session.subject &&
      unsavedWorkSnapshot().length > 0
    ) {
      setPendingIdentity(session);
      return;
    }
    identityRef.current = session;
    setIdentity(session);
  }

  useEffect(() => subscribeBrowserLifecycle(setBrowserLifecycleState), []);
  useEffect(() => subscribeUnsavedWork(setUnsavedWorkState), []);

  useEffect(() => {
    const guard = (event: BeforeUnloadEvent) => {
      if (unsavedWorkSnapshot().length === 0) return;
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", guard);
    return () => window.removeEventListener("beforeunload", guard);
  }, []);

  useEffect(() => {
    let active = true;
    const controllers = new Set<AbortController>();
    const check = () => {
      const controller = new AbortController();
      controllers.add(controller);
      readRuntime(controller.signal)
        .then((runtime) => {
          if (!active) return;
          const current = runtimeBuildFingerprint(runtime.build);
          if (runtimeBuild.current === null) runtimeBuild.current = current;
          else if (runtimeBuild.current !== current) setReleaseAvailable(true);
        })
        .catch(() => undefined)
        .finally(() => controllers.delete(controller));
    };
    const visible = () => {
      if (document.visibilityState === "visible") check();
    };
    check();
    const timer = window.setInterval(check, 60_000);
    window.addEventListener("online", check);
    document.addEventListener("visibilitychange", visible);
    return () => {
      active = false;
      window.clearInterval(timer);
      window.removeEventListener("online", check);
      document.removeEventListener("visibilitychange", visible);
      for (const controller of controllers) controller.abort();
    };
  }, []);

  useEffect(() => {
    let active = true;
    const controllers = new Set<AbortController>();
    const revalidate = () => {
      const controller = new AbortController();
      controllers.add(controller);
      readSession(controller.signal)
        .then((session) => {
          if (active) {
            acceptSession(session);
            setError("");
          }
        })
        .catch((reason: unknown) => {
          if (
            active &&
            !(reason instanceof DOMException && reason.name === "AbortError")
          )
            setError(
              reason instanceof Error ? reason.message : "REQUEST_FAILED",
            );
        })
        .finally(() => controllers.delete(controller));
    };
    const uninstall = installConnectivityLifecycle(revalidate);
    return () => {
      active = false;
      uninstall();
      for (const controller of controllers) controller.abort();
    };
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    Promise.all([
      listApplications(controller.signal),
      readSession(controller.signal),
    ])
      .then(([apps, session]) => {
        setApplications(apps);
        acceptSession(session);
        setSelected((current) => (current < apps.length ? current : 0));
      })
      .catch((reason: Error) => {
        if (!(reason instanceof DOMException && reason.name === "AbortError"))
          setError(reason.message);
      })
      .finally(() => setLoading(false));
    return () => controller.abort();
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    readPlatformCatalog(controller.signal)
      .then(setPlatformCatalog)
      .catch((reason: Error) => {
        if (!(reason instanceof ApiError && reason.status === 403))
          setError(reason.message);
      })
      .finally(() => setPlatformChecked(true));
    return () => controller.abort();
  }, []);

  useEffect(() => {
    if (!accountOpen) return;
    const dismiss = (event: PointerEvent) => {
      const target = event.target as Node;
      if (
        accountButtonRef.current?.contains(target) ||
        accountCardRef.current?.contains(target)
      )
        return;
      setAccountOpen(false);
    };
    document.addEventListener("pointerdown", dismiss);
    return () => document.removeEventListener("pointerdown", dismiss);
  }, [accountOpen]);

  useEffect(() => {
    const route = presentationRouteHash(page, selected, workFocus);
    if (window.location.hash !== route)
      window.history.replaceState(null, "", route);
  }, [page, selected, workFocus]);

  useEffect(() => {
    if (!workFocus.workspaceId || !workFocus.applicationId) return;
    const exactApplication = applications.findIndex(
      (item) =>
        item.workspaceId === workFocus.workspaceId &&
        item.applicationId === workFocus.applicationId,
    );
    if (exactApplication >= 0 && exactApplication !== selected)
      setSelected(exactApplication);
  }, [applications, selected, workFocus.workspaceId, workFocus.applicationId]);

  useEffect(() => {
    const restore = () => {
      const route = readPresentationRoute();
      const restoreRequestedRoute = () => {
        setPage(route.page);
        setSelected(route.applicationIndex);
        setWorkFocus(route.focus);
      };
      restoreRequestedRoute();
    };
    window.addEventListener("hashchange", restore);
    return () => window.removeEventListener("hashchange", restore);
  }, [page, selected, workFocus]);

  function requestTransition(transition: () => void) {
    if (unsavedWorkSnapshot().length === 0) {
      transition();
      return;
    }
    discardTriggerRef.current =
      document.activeElement instanceof HTMLElement
        ? document.activeElement
        : null;
    pendingTransition.current = transition;
    setDiscardPromptOpen(true);
  }

  useEffect(() => {
    if (!discardPromptOpen) return;
    const keyboard = (event: KeyboardEvent) => {
      const dialog = discardDialogRef.current;
      if (!dialog) return;
      if (event.key === "Escape") {
        event.preventDefault();
        pendingTransition.current = null;
        setDiscardPromptOpen(false);
        return;
      }
      if (event.key !== "Tab") return;
      const controls = Array.from(
        dialog.querySelectorAll<HTMLElement>(
          "button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])",
        ),
      );
      if (!controls.length) return;
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", keyboard);
    return () => {
      window.removeEventListener("keydown", keyboard);
      if (discardTriggerRef.current?.isConnected)
        discardTriggerRef.current.focus();
      discardTriggerRef.current = null;
    };
  }, [discardPromptOpen]);

  function navigate(target: Page, focus: WorkFocus = {}) {
    if (target === page && JSON.stringify(focus) === JSON.stringify(workFocus))
      return;
    setAccountOpen(false);
    window.history.pushState(
      null,
      "",
      presentationRouteHash(target, selected, focus),
    );
    setWorkFocus(focus);
    setPage(target);
  }

  function signOut() {
    requestTransition(() => {
      setAccountOpen(false);
      window.location.assign(browserLogoutPath());
    });
  }

  function reloadRelease() {
    requestTransition(() => window.location.reload());
  }

  useEffect(() => {
    const query = window.matchMedia?.("(max-width: 650px)");
    if (!query) return;
    const adapt = (event: MediaQueryListEvent | MediaQueryList) => {
      if (event.matches) setCollapsed(true);
    };
    query.addEventListener?.("change", adapt);
    return () => query.removeEventListener?.("change", adapt);
  }, []);

  useEffect(() => {
    if (!app) {
      setCatalog(null);
      return;
    }
    const controller = new AbortController();
    readCatalog(
      { workspaceId: app.workspaceId, applicationId: app.applicationId },
      controller.signal,
    )
      .then(setCatalog)
      .catch((reason: Error) => setError(reason.message));
    return () => controller.abort();
  }, [app?.workspaceId, app?.applicationId]);

  const visibleApplicationPages = useMemo(
    () =>
      applicationPages.filter((item) =>
        applicationPageVisible(item.id, catalog),
      ),
    [catalog],
  );
  const visiblePrimary = useMemo(
    () => primary.filter((item) => item.id !== "server" || platformCatalog),
    [platformCatalog],
  );

  useEffect(() => {
    if (platformChecked && page === "server" && !platformCatalog)
      navigate("home");
  }, [page, platformCatalog, platformChecked]);

  useEffect(() => {
    if (!catalog || primary.some((item) => item.id === page)) return;
    if (!applicationPageVisible(page, catalog)) navigate("overview");
  }, [catalog, page]);

  useEffect(() => {
    function shortcuts(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setSearchOpen(false);
        setNotificationsOpen(false);
        setAccountOpen(false);
        setHelpOpen(false);
        return;
      }
      if (
        event.key.toLowerCase() === "k" &&
        (event.metaKey || event.ctrlKey) &&
        !editableShortcutTarget(event.target)
      ) {
        event.preventDefault();
        setSearchOpen(true);
        setNotificationsOpen(false);
        setAccountOpen(false);
        setHelpOpen(false);
        return;
      }
      if (event.key === "?" && !editableShortcutTarget(event.target)) {
        event.preventDefault();
        setHelpOpen(true);
        setSearchOpen(false);
        setNotificationsOpen(false);
        setAccountOpen(false);
      }
    }
    window.addEventListener("keydown", shortcuts);
    return () => window.removeEventListener("keydown", shortcuts);
  }, []);

  function chooseApplication(index: number) {
    if (index === selected && page === "overview") return;
    window.history.pushState(
      null,
      "",
      presentationRouteHash("overview", index, {}),
    );
    setSelected(index);
    setAccountOpen(false);
    setWorkFocus({});
    setPage("overview");
  }

  async function applicationCreated(created: CreatedApplication) {
    const apps = await listApplications();
    setApplications(apps);
    const index = apps.findIndex(
      (item) =>
        item.workspaceId === created.workspaceId &&
        item.applicationId === created.applicationId,
    );
    if (index >= 0) {
      setSelected(index);
      navigate("overview");
    }
  }

  function go(target: string) {
    if (
      primary.some((item) => item.id === target) ||
      applicationPages.some((item) => item.id === target)
    )
      navigate(target as Page);
  }

  async function copyViewLink() {
    if (copyStatusTimer.current) clearTimeout(copyStatusTimer.current);
    setCopyStatus("");
    try {
      await navigator.clipboard.writeText(shareableViewUrl(window.location));
      setCopyStatus("Link copied");
    } catch {
      setCopyStatus("Unable to copy link");
    }
    copyStatusTimer.current = setTimeout(() => {
      setCopyStatus("");
      copyStatusTimer.current = null;
    }, 2500);
  }

  useEffect(
    () => () => {
      if (copyStatusTimer.current) clearTimeout(copyStatusTimer.current);
    },
    [],
  );

  const blocked =
    Boolean(pendingIdentity) ||
    ["expired", "offline", "unavailable", "revalidating"].includes(
      browserLifecycle.state,
    );
  const retry = () => window.dispatchEvent(new Event("online"));
  const blockedPresentation = pendingIdentity
    ? {
        kind: "identity" as const,
        title: "Identity changed",
        description:
          "This tab was opened by another identity. Its unpublished drafts cannot be transferred to the newly authenticated user.",
        action: "Discard drafts and continue",
        perform: () => {
          discardUnsavedWork();
          identityRef.current = pendingIdentity;
          setIdentity(pendingIdentity);
          setPendingIdentity(null);
        },
      }
    : browserLifecycle.state === "expired"
      ? {
          kind: "expired" as const,
          title: "Your session has timed out",
          description:
            unsavedWork.length > 0
              ? "Your unpublished browser work is still held in this tab. Signing in again will discard it; review the list before continuing."
              : "For your security, this page is no longer active. Sign in again to continue.",
          action:
            unsavedWork.length > 0
              ? "Discard drafts and sign in"
              : "Sign in again",
          perform: () => {
            discardUnsavedWork();
            window.location.assign("/");
          },
        }
      : browserLifecycle.state === "offline"
        ? {
            kind: "offline" as const,
            title: "You are offline",
            description:
              "Open EPM has stopped sending requests. Drafts remain in this tab and nothing has been published. Reconnect, then retry safely.",
            action: "Retry connection",
            perform: retry,
          }
        : browserLifecycle.state === "unavailable"
          ? {
              kind: "unavailable" as const,
              title: "Open EPM is temporarily unavailable",
              description:
                "The service did not confirm your session. Drafts remain in this tab while Open EPM blocks stale interaction.",
              action: "Retry connection",
              perform: retry,
            }
          : browserLifecycle.state === "revalidating"
            ? {
                kind: "revalidating" as const,
                title: "Revalidating your session",
                description:
                  "Open EPM is confirming your identity and current authority before interaction resumes.",
              }
            : null;

  return (
    <>
      {blockedPresentation && (
        <BrowserStateScreen {...blockedPresentation} pending={unsavedWork} />
      )}
      <div
        className={collapsed ? "shell collapsed" : "shell"}
        inert={blocked || undefined}
        aria-hidden={blocked || undefined}
      >
        <a className="skip-link" href="#main-content">
          Skip to main content
        </a>
        <aside className="sidebar" id="primary-navigation">
          <div className="brand">
            <AppIcon />
            <strong>Open EPM</strong>
          </div>
          <nav aria-label="Global navigation">
            {visiblePrimary.map((item) => (
              <button
                key={item.id}
                className={page === item.id ? "active" : ""}
                aria-label={item.label}
                aria-current={page === item.id ? "page" : undefined}
                onClick={() => navigate(item.id)}
              >
                <span>{item.icon}</span>
                <b>{item.label}</b>
              </button>
            ))}
          </nav>
          <div className="nav-divider" />
          <div className="nav-caption">Application</div>
          <button
            className="application-switcher"
            aria-label={
              app
                ? `Choose application; current ${app.name}`
                : "Choose application"
            }
            onClick={() => navigate("applications")}
            disabled={!app}
          >
            <span className="app-glyph">{app?.name?.slice(0, 1) || "—"}</span>
            <span>
              <b>{app?.name || "No application"}</b>
              <small>
                {app
                  ? `${app.workspaceId} / ${app.applicationId}`
                  : "Select an application"}
              </small>
            </span>
            <em>⌄</em>
          </button>
          <nav aria-label="Application navigation" className="application-nav">
            {visibleApplicationPages.map((item) => (
              <button
                key={item.id}
                className={page === item.id ? "active" : ""}
                aria-label={item.label}
                aria-current={page === item.id ? "page" : undefined}
                disabled={!app}
                onClick={() => navigate(item.id)}
              >
                <span>·</span>
                <b>{item.label}</b>
              </button>
            ))}
          </nav>
          <div className="sidebar-foot">
            <span className="agent-dot" />{" "}
            <span>
              <b>Agent ready</b>
              <small>MCP connection available</small>
            </span>
          </div>
        </aside>

        <header className="topbar">
          <button
            className="menu-button"
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-controls="primary-navigation"
            aria-expanded={!collapsed}
            onClick={() => setCollapsed((value) => !value)}
          >
            ☰
          </button>
          <div className="breadcrumbs">
            <span>{app?.name || "Open EPM"}</span>
            <b>/</b>
            <strong>{pageTitle(page)}</strong>
          </div>
          <div className="top-actions">
            <button
              className="print-action"
              aria-label="Print current view"
              title="Print current view"
              onClick={() => window.print()}
            >
              ⎙
            </button>
            <button
              aria-label="Copy link to this view"
              onClick={() => void copyViewLink()}
            >
              ⛓
            </button>
            <button
              aria-label="Search"
              aria-keyshortcuts="Control+K Meta+K"
              title="Search (Ctrl/⌘ K)"
              aria-controls="global-search-panel"
              aria-expanded={searchOpen}
              onClick={() => {
                setSearchOpen(true);
                setNotificationsOpen(false);
                setAccountOpen(false);
                setHelpOpen(false);
              }}
            >
              ⌕
            </button>
            <button
              aria-label="Notifications"
              aria-controls="notification-panel"
              aria-expanded={notificationsOpen}
              onClick={() => {
                setNotificationsOpen((value) => !value);
                setSearchOpen(false);
                setAccountOpen(false);
                setHelpOpen(false);
              }}
            >
              ♢
            </button>
            <button
              aria-label="Keyboard help"
              aria-keyshortcuts="Shift+/"
              title="Keyboard help (?)"
              aria-controls="keyboard-help-panel"
              aria-expanded={helpOpen}
              onClick={() => {
                setHelpOpen((value) => !value);
                setSearchOpen(false);
                setNotificationsOpen(false);
                setAccountOpen(false);
              }}
            >
              ?
            </button>
            <button
              ref={accountButtonRef}
              className="account-button"
              aria-label="Account"
              aria-controls="account-card"
              aria-expanded={accountOpen}
              onClick={() => {
                setAccountOpen((value) => !value);
                setSearchOpen(false);
                setNotificationsOpen(false);
                setHelpOpen(false);
              }}
            >
              {initials(identity?.displayIdentity || identity?.subject)}
            </button>
          </div>
          <span className="copy-status" role="status" aria-live="polite">
            {copyStatus}
          </span>
          {accountOpen && (
            <AccountCard
              cardRef={accountCardRef}
              identity={identity}
              catalog={catalog}
              applicationCount={applications.length}
              signOut={signOut}
            />
          )}
          <GlobalSearch
            open={searchOpen}
            close={() => setSearchOpen(false)}
            applications={applications}
            selectedApplication={app}
            targets={[...visiblePrimary, ...visibleApplicationPages]}
            catalog={catalog}
            go={go}
            chooseApplication={chooseApplication}
          />
          <Notifications
            open={notificationsOpen}
            close={() => setNotificationsOpen(false)}
            app={app}
            goMonitor={() => navigate("monitor")}
          />
          <HelpPanel open={helpOpen} close={() => setHelpOpen(false)} />
        </header>

        <main
          id="main-content"
          tabIndex={-1}
          key={identity?.subject || "anonymous"}
        >
          {releaseAvailable && (
            <section
              className="release-update"
              role="status"
              aria-live="polite"
            >
              <div>
                <strong>A newer Open EPM release is ready</strong>
                <span>
                  Reload when convenient. Unpublished browser work will be
                  protected before the page changes.
                </span>
              </div>
              <button type="button" onClick={reloadRelease}>
                Review and reload
              </button>
            </section>
          )}
          {page !== "flows" && workFocus.occurrenceId && (
            <section className="workflow-return" role="status">
              <span>
                Working from workflow occurrence {workFocus.occurrenceId}
                {workFocus.activityId ? ` · ${workFocus.activityId}` : ""}
                {workFocus.viewId
                  ? ` · view ${workFocus.viewId} v${workFocus.viewVersion}`
                  : ""}
              </span>
              <button
                type="button"
                onClick={() =>
                  navigate("flows", {
                    workspaceId: app?.workspaceId,
                    applicationId: app?.applicationId,
                    occurrenceId: workFocus.occurrenceId,
                    activityId: workFocus.activityId,
                  })
                }
              >
                Return to workflow
              </button>
            </section>
          )}
          <div className="print-context" aria-hidden="true">
            <strong>{app?.name || "Open EPM"}</strong>
            <span>{pageTitle(page)}</span>
          </div>
          {error && (
            <div className="alert" role="alert" aria-live="assertive">
              {error}
            </div>
          )}
          {loading ? (
            <Loading />
          ) : (
            <Suspense
              fallback={<div className="empty-state">Loading workspace…</div>}
            >
              {page === "home" ? (
                <Home app={app} identity={identity} go={navigate} />
              ) : page === "applications" ? (
                <Applications
                  applications={applications}
                  selected={selected}
                  catalog={catalog}
                  subject={identity?.subject || ""}
                  choose={chooseApplication}
                  created={applicationCreated}
                />
              ) : page === "work" ? (
                <MyWork app={app} catalog={catalog} open={navigate} />
              ) : page === "server" && platformCatalog ? (
                <ServerAdministration functions={platformCatalog.functions} />
              ) : page === "overview" ? (
                <Overview app={app} catalog={catalog} go={navigate} />
              ) : page === "grid" ? (
                <Analyze
                  app={app}
                  catalog={catalog}
                  index={selected}
                  subject={identity?.subject || ""}
                  targetViewId={workFocus.viewId}
                  targetViewVersion={workFocus.viewVersion}
                  targetViewDigest={workFocus.viewDigest}
                />
              ) : page === "flows" ? (
                <GenericWorkflow
                  app={app}
                  catalog={catalog}
                  targetOccurrenceId={workFocus.occurrenceId}
                  targetActivityId={workFocus.activityId}
                  openDestination={(destination) => {
                    const common = {
                      workspaceId: app?.workspaceId,
                      applicationId: app?.applicationId,
                      occurrenceId: workFocus.occurrenceId,
                      activityId: workFocus.activityId,
                    };
                    const resolution = resolveWorkflowDestination(
                      destination,
                      catalog,
                    );
                    if (!resolution.supported) return resolution.message;
                    navigate(resolution.page, {
                      ...common,
                      ...resolution.focus,
                    });
                    return null;
                  }}
                />
              ) : page === "tasks" ? (
                <MyWork app={app} catalog={catalog} open={navigate} />
              ) : page === "data" ||
                page === "metadata" ||
                page === "lists" ||
                page === "rules" ||
                page === "security" ||
                page === "administration" ? (
                <CapabilityArea
                  key={`${identity?.subject || "anonymous"}:${app?.workspaceId || "none"}:${app?.applicationId || "none"}:${page}`}
                  area={page}
                  app={app}
                  catalog={catalog}
                  index={selected}
                  targetApplicationRule={
                    workFocus.artifactKind === "ApplicationRule" &&
                    workFocus.artifactId &&
                    workFocus.artifactVersion &&
                    workFocus.artifactDigest
                      ? {
                          ruleId: workFocus.artifactId,
                          version: workFocus.artifactVersion,
                          digest: workFocus.artifactDigest,
                        }
                      : undefined
                  }
                  targetCalculatedMember={
                    workFocus.artifactKind === "CalculatedMember" &&
                    workFocus.artifactId &&
                    workFocus.artifactVersion &&
                    workFocus.artifactDigest
                      ? {
                          definitionId: workFocus.artifactId,
                          version: workFocus.artifactVersion,
                          digest: workFocus.artifactDigest,
                        }
                      : undefined
                  }
                  targetApplicationSequence={
                    workFocus.artifactKind === "ApplicationSequence" &&
                    workFocus.artifactId &&
                    workFocus.artifactVersion &&
                    workFocus.artifactDigest
                      ? {
                          ruleId: workFocus.artifactId,
                          version: workFocus.artifactVersion,
                          digest: workFocus.artifactDigest,
                        }
                      : undefined
                  }
                  targetApplicationSchedule={
                    workFocus.artifactKind === "ApplicationSchedule" &&
                    workFocus.artifactId &&
                    workFocus.artifactVersion &&
                    workFocus.artifactDigest
                      ? {
                          scheduleId: workFocus.artifactId,
                          version: workFocus.artifactVersion,
                          digest: workFocus.artifactDigest,
                        }
                      : undefined
                  }
                />
              ) : page === "monitor" ? (
                <Monitor app={app} catalog={catalog} />
              ) : null}
            </Suspense>
          )}
        </main>
        {discardPromptOpen && (
          <div className="modal-backdrop" role="presentation">
            <section
              ref={discardDialogRef}
              className="unsaved-work-dialog"
              role="alertdialog"
              aria-modal="true"
              aria-labelledby="unsaved-work-title"
              aria-describedby="unsaved-work-description"
              onKeyDown={(event) => {
                if (event.key === "Escape") {
                  event.preventDefault();
                  event.stopPropagation();
                  pendingTransition.current = null;
                  setDiscardPromptOpen(false);
                  return;
                }
                if (event.key !== "Tab") return;
                const controls = Array.from(
                  event.currentTarget.querySelectorAll<HTMLElement>(
                    "button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])",
                  ),
                );
                const first = controls[0];
                const last = controls.at(-1);
                if (
                  first &&
                  last &&
                  ((event.shiftKey && document.activeElement === first) ||
                    (!event.shiftKey && document.activeElement === last))
                ) {
                  event.preventDefault();
                  event.stopPropagation();
                  (event.shiftKey ? last : first).focus();
                }
              }}
            >
              <h2 id="unsaved-work-title">Discard unsaved changes?</h2>
              <p id="unsaved-work-description">
                Nothing listed here has been published to the fixed core.
                Leaving this view will discard the browser draft.
              </p>
              <ul>
                {unsavedWork.map((item) => (
                  <li key={item.id}>{item.label}</li>
                ))}
              </ul>
              <div className="button-row">
                <button
                  type="button"
                  className="secondary"
                  autoFocus
                  onClick={() => {
                    pendingTransition.current = null;
                    setDiscardPromptOpen(false);
                  }}
                >
                  Keep editing
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const transition = pendingTransition.current;
                    pendingTransition.current = null;
                    setDiscardPromptOpen(false);
                    discardUnsavedWork();
                    transition?.();
                  }}
                >
                  Discard and continue
                </button>
              </div>
            </section>
          </div>
        )}
      </div>
    </>
  );
}

function BrowserStateScreen({
  kind,
  title,
  description,
  action,
  perform,
  pending,
}: {
  kind: "expired" | "offline" | "unavailable" | "revalidating" | "identity";
  title: string;
  description: string;
  action?: string;
  perform?: () => void;
  pending: UnsavedWorkItem[];
}) {
  return (
    <main className={`browser-state browser-state-${kind}`}>
      <section
        role="alert"
        aria-live="assertive"
        aria-labelledby="browser-state-title"
      >
        <span className="brand-mark" aria-hidden="true">
          <i />
          <i />
          <i />
        </span>
        <p>Open EPM</p>
        <h1 id="browser-state-title">{title}</h1>
        <div>{description}</div>
        {pending.length > 0 && (
          <ul aria-label="Unpublished browser work">
            {pending.map((item) => (
              <li key={item.id}>{item.label}</li>
            ))}
          </ul>
        )}
        {action && perform && (
          <button type="button" onClick={perform} autoFocus>
            {action}
          </button>
        )}
      </section>
    </main>
  );
}

function pageTitle(page: Page) {
  return (
    {
      home: "Home",
      applications: "Applications",
      work: "My Work",
      server: "Server Administration",
      overview: "Overview",
      grid: "Grid",
      data: "Data",
      metadata: "Metadata",
      lists: "Member Lists",
      rules: "Rules",
      flows: "Flows",
      tasks: "Tasks",
      monitor: "Monitor",
      security: "Users & Security",
      administration: "Administration",
    } as Record<Page, string>
  )[page];
}

function Loading() {
  return (
    <div className="loading">
      <span />
      <p>Loading your workspace…</p>
    </div>
  );
}

function AccountCard({
  cardRef,
  identity,
  catalog,
  applicationCount,
  signOut,
}: {
  cardRef: React.RefObject<HTMLElement | null>;
  identity: SessionIdentity | null;
  catalog: ApplicationCatalog | null;
  applicationCount: number;
  signOut: () => void;
}) {
  const name = identity?.displayIdentity || identity?.subject || "Unavailable";
  return (
    <section
      ref={cardRef}
      className="account-card"
      id="account-card"
      aria-label="Your account"
    >
      <div className="account-head">
        <span>{initials(name)}</span>
        <div>
          <strong>{name}</strong>
          <small>Verified identity</small>
        </div>
      </div>
      <dl>
        <div>
          <dt>Current role</dt>
          <dd>{catalog?.applicationAccess.role || "Select an application"}</dd>
        </div>
        <div>
          <dt>Accessible applications</dt>
          <dd>{applicationCount}</dd>
        </div>
      </dl>
      <label>Your personal MCP endpoint</label>
      <code>{identity?.applicationMcpEndpoint || "Not configured"}</code>
      <p>
        OAuth identity and current grants remain required for every agent
        request.
      </p>
      <button type="button" className="account-signout" onClick={signOut}>
        Sign out
      </button>
    </section>
  );
}

function PageHeading({
  eyebrow,
  title,
  description,
  children,
}: React.PropsWithChildren<{
  eyebrow: string;
  title: string;
  description: string;
}>) {
  return (
    <div className="page-heading">
      <div>
        <span>{eyebrow}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {children}
    </div>
  );
}

function Home({
  app,
  identity,
  go,
}: {
  app?: ApplicationSummary;
  identity: SessionIdentity | null;
  go: (page: Page) => void;
}) {
  const first = (identity?.displayIdentity || "there").split(/[@. ]/)[0];
  return (
    <div className="page home-page">
      <PageHeading
        eyebrow="Workspace"
        title={`Good morning, ${first}`}
        description="Your multidimensional workspace is ready. Start with what needs attention or return to your active cube."
      />
      <section className="hero-card">
        <div>
          <span className="pill">Active application</span>
          <h2>{app?.name || "Choose an application"}</h2>
          <p>
            {app
              ? `${app.workspaceId} / ${app.applicationId}`
              : "Select an application to begin working with its cube."}
          </p>
        </div>
        <button
          className="primary"
          onClick={() => go(app ? "overview" : "applications")}
        >
          {app ? "Open application" : "Choose application"} →
        </button>
      </section>
      <div className="section-title">
        <div>
          <h2>Start here</h2>
          <p>Common work, one click away.</p>
        </div>
      </div>
      <div className="action-grid">
        <Action
          title="Review my work"
          text="See assigned and active business steps."
          icon="✓"
          onClick={() => go("work")}
        />
        <Action
          title="Open grid"
          text="Read, edit and review governed multidimensional data."
          icon="▦"
          onClick={() => go("grid")}
        />
        <Action
          title="Build rules"
          text="Compose calculations from reusable generic primitives."
          icon="⌁"
          onClick={() => go("rules")}
        />
        <Action
          title="Monitor activity"
          text="Follow human and agent work through durable outcomes."
          icon="◌"
          onClick={() => go("monitor")}
        />
      </div>
      <section className="activity-preview">
        <div className="section-title">
          <div>
            <h2>Activity</h2>
            <p>Human and agent actions share one governed history.</p>
          </div>
          <button onClick={() => go("monitor")}>View all</button>
        </div>
        <div className="empty-state">
          <span>◎</span>
          <strong>Open Monitor for authoritative activity</strong>
          <p>
            Successful effects are shown only after the core records their
            durable outcome.
          </p>
        </div>
      </section>
    </div>
  );
}

function Action({
  title,
  text,
  icon,
  onClick,
}: {
  title: string;
  text: string;
  icon: string;
  onClick: () => void;
}) {
  return (
    <button className="action-card" onClick={onClick}>
      <span>{icon}</span>
      <div>
        <strong>{title}</strong>
        <p>{text}</p>
      </div>
      <em>→</em>
    </button>
  );
}

type OverviewState = {
  assignedWork: number;
  reviews: number;
  running: number;
  attention: number;
  recentTasks: Array<{
    taskId: string;
    function: string;
    status: string;
    initiatorKind?: string;
  }>;
};

export function Overview({
  app,
  catalog,
  go,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  go: (page: Page) => void;
}) {
  const [business, setBusiness] = useState<OverviewState | null>(null);
  const [businessError, setBusinessError] = useState("");
  useEffect(() => {
    if (!app || !catalog) return;
    const controller = new AbortController();
    const scope = {
      workspaceId: app.workspaceId,
      applicationId: app.applicationId,
    };
    const workflow = Object.hasOwn(
      catalog.functions,
      "application.workflow.worklist",
    )
      ? readProgram<{ items: unknown[] }>(
          scope,
          "application.workflow.worklist",
          { limit: 100 },
          controller.signal,
        )
      : Promise.resolve({ items: [] });
    const tasks = request<{
      tasks: Array<{
        taskId: string;
        function: string;
        status: string;
        initiatorKind?: string;
      }>;
    }>(
      "/api/tasks",
      { ...scope, afterSequence: 0, limit: 100 },
      controller.signal,
    );
    Promise.all([workflow, tasks])
      .then(([flow, taskPage]) => {
        const activeStates = new Set([
          "Accepted",
          "Queued",
          "Claimed",
          "Running",
          "Cancelling",
        ]);
        const attentionStates = new Set([
          "Failed",
          "Interrupted",
          "Cancelled",
          "Rejected",
          "Stale",
        ]);
        setBusiness({
          assignedWork: flow.items.length,
          reviews: flow.items.length,
          running: taskPage.tasks.filter((item) =>
            activeStates.has(item.status),
          ).length,
          attention: taskPage.tasks.filter((item) =>
            attentionStates.has(item.status),
          ).length,
          recentTasks: taskPage.tasks.slice(0, 4),
        });
        setBusinessError("");
      })
      .catch((reason: Error) => setBusinessError(reason.message));
    return () => controller.abort();
  }, [app?.workspaceId, app?.applicationId, catalog]);

  if (!app)
    return (
      <div className="page">
        <PageHeading
          eyebrow="Application"
          title="No application selected"
          description="Choose an application to continue."
        />
        <button className="primary" onClick={() => go("applications")}>
          Choose application
        </button>
      </div>
    );
  const revisions = catalog?.revisions;
  return (
    <div className="page">
      <PageHeading
        eyebrow="Application overview"
        title={app.name}
        description="Your operating view of this programmable multidimensional application."
      >
        <button className="primary" onClick={() => go("grid")}>
          Open Grid →
        </button>
      </PageHeading>
      <div className="metric-grid">
        <Metric
          value={business ? String(business.assignedWork) : "—"}
          label="Ready for you"
        />
        <Metric
          value={business ? String(business.reviews) : "—"}
          label="Reviews waiting"
        />
        <Metric
          value={business ? String(business.running) : "—"}
          label="Work running"
        />
        <Metric
          value={business ? String(business.attention) : "—"}
          label="Needs attention"
        />
      </div>
      {businessError && (
        <div className="alert" role="alert">
          {businessError}
        </div>
      )}
      <div className="overview-grid">
        <section className="panel">
          <div className="section-title">
            <div>
              <h2>Continue working</h2>
              <p>Open the area that matches your current task.</p>
            </div>
          </div>
          <div className="journey-list">
            <Action
              title="Open cube grid"
              text="Read, edit and compare authorized multidimensional views."
              icon="▦"
              onClick={() => go("grid")}
            />
            <Action
              title="Build generic rules"
              text="Compose calculations, sequences and schedules from primitives."
              icon="⌁"
              onClick={() => go("rules")}
            />
            <Action
              title="Review flows"
              text="Assignments, review steps and governed evidence."
              icon="✓"
              onClick={() => go("flows")}
            />
          </div>
        </section>
        <section className="panel overview-activity">
          <div className="section-title">
            <div>
              <h2>Recent governed activity</h2>
              <p>Human and agent work from the durable task record.</p>
            </div>
            <button onClick={() => go("monitor")}>Open Monitor</button>
          </div>
          {business?.recentTasks.length ? (
            <div className="overview-task-list">
              {business.recentTasks.map((task) => (
                <article key={task.taskId}>
                  <span className="status-pill">{task.status}</span>
                  <strong>{task.function}</strong>
                  <small>{task.initiatorKind || "Verified principal"}</small>
                </article>
              ))}
            </div>
          ) : (
            <div className="empty-state">No recent task is visible.</div>
          )}
          <details className="model-details">
            <summary>Technical model details</summary>
            <dl>
              <div>
                <dt>Workspace / application</dt>
                <dd>
                  {app.workspaceId} / {app.applicationId}
                </dd>
              </div>
              <div>
                <dt>Your role</dt>
                <dd>{catalog?.applicationAccess.role || "—"}</dd>
              </div>
              <div>
                <dt>Metadata / data revision</dt>
                <dd>
                  {revisions?.metadata ?? "—"} / {revisions?.data ?? "—"}
                </dd>
              </div>
              <div>
                <dt>Security / commit revision</dt>
                <dd>
                  {revisions?.security ?? "—"} / {revisions?.commit ?? "—"}
                </dd>
              </div>
            </dl>
          </details>
        </section>
      </div>
    </div>
  );
}

function Metric({ value, label }: { value: string; label: string }) {
  return (
    <div className="metric">
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}
