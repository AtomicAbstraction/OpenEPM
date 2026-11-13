import { Breadcrumbs } from "./Breadcrumbs";
import type { BreadcrumbItem } from "./Breadcrumbs";
import { ApplicationDecisions } from "./ApplicationDecisions";
import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
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
  canPreserveUnsavedWork,
  discardUnsavedWork,
  setDraftIdentity,
  subscribeUnsavedWork,
  unsavedWorkSnapshot,
} from "./unsaved-work";
import type { UnsavedWorkItem } from "./unsaved-work";
import { resolveWorkflowDestination } from "./workflow-destination";
import { MetadataNavigation } from "./MetadataNavigation";
import {
  metadataSectionLabels,
  readMetadataDestination,
  writeMetadataDestination,
} from "./metadata-navigation";
import {
  resolveWorkspaceSection,
  workspaceSections,
} from "./workspace-navigation";
import type { WorkspaceArea } from "./workspace-navigation";
import { UiIcon } from "./UiIcon";
import "./focused-workspaces.css";
import type {
  MetadataDestination,
  MetadataNavigationDimension,
  MetadataSection,
} from "./metadata-navigation";

const Analyze = lazy(() =>
  import("./Analyze").then((module) => ({ default: module.Analyze })),
);
const CapabilityArea = lazy(() =>
  import("./CapabilityArea").then((module) => ({
    default: module.CapabilityArea,
  })),
);
const MetadataWorkspace = lazy(() =>
  import("./MetadataWorkspace").then((module) => ({
    default: module.MetadataWorkspace,
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
  section?: string;
  workspaceId?: string;
  applicationId?: string;
  metadataSection?: MetadataSection;
  dimensionId?: string;
  memberId?: string;
  hierarchyId?: string;
  assignmentId?: string;
  occurrenceId?: string;
  activityId?: string;
  viewId?: string;
  viewDigest?: string;
  artifactKind?:
    | "ApplicationRule"
    | "CalculatedMember"
    | "ApplicationSequence"
    | "ApplicationSchedule";
  artifactId?: string;
  artifactStateToken?: string;
  artifactVersion?: number;
  artifactDigest?: string;
};

export function presentationRouteHash(
  page: Page,
  applicationIndex: number,
  focus: WorkFocus = {},
) {
  const query = new URLSearchParams();
  if (isWorkspaceArea(page))
    query.set(
      "section",
      resolveWorkspaceSection(page, focus.section, focus.artifactKind),
    );
  if (
    page === "server" &&
    ["users", "groups", "membership"].includes(focus.section || "")
  )
    query.set("section", focus.section!);
  if (focus.workspaceId && focus.applicationId) {
    query.set("workspace", focus.workspaceId);
    query.set("application", focus.applicationId);
  }
  if (page === "metadata")
    writeMetadataDestination(query, {
      section: focus.metadataSection || "dimensions",
      dimensionId: focus.dimensionId,
      memberId: focus.memberId,
      hierarchyId: focus.hierarchyId,
    });
  if (page === "flows" && focus.occurrenceId) {
    query.set("occurrence", focus.occurrenceId);
    if (focus.activityId) query.set("activity", focus.activityId);
  }
  if (page === "grid" && focus.viewId && focus.viewDigest) {
    query.set("view", focus.viewId);
    query.set("viewDigest", focus.viewDigest);
  }
  if (
    page === "rules" &&
    focus.artifactKind &&
    focus.artifactId &&
    (focus.artifactKind === "ApplicationRule" ||
    focus.artifactKind === "CalculatedMember" ||
    focus.artifactKind === "ApplicationSequence" ||
    focus.artifactKind === "ApplicationSchedule"
      ? focus.artifactStateToken
      : focus.artifactVersion) &&
    focus.artifactDigest
  ) {
    query.set("artifactKind", focus.artifactKind);
    query.set("artifactId", focus.artifactId);
    if (focus.artifactStateToken)
      query.set("artifactStateToken", focus.artifactStateToken);
    if (focus.artifactVersion)
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

const navigationGroups = [
  {
    label: "Work with data",
    pages: ["overview", "grid", "data", "flows", "monitor"],
  },
  { label: "Design the model", pages: ["metadata", "rules"] },
  { label: "Manage access", pages: ["security", "administration"] },
];
function isWorkspaceArea(page: Page): page is WorkspaceArea {
  return Object.hasOwn(workspaceSections, page);
}
function applicationScopedPage(page: Page) {
  return !["home", "applications", "server"].includes(page);
}

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
  const rawViewDigest = query.get("viewDigest") || "";
  const viewDigest = /^[0-9a-f]{64}$/.test(rawViewDigest)
    ? rawViewDigest
    : undefined;
  const rawArtifactVersion = Number(query.get("artifactVersion"));
  const rawArtifactStateToken = query.get("artifactStateToken") || "";
  const rawArtifactDigest = query.get("artifactDigest") || "";
  const artifactKind = query.get("artifactKind");
  const metadata = readMetadataDestination(query);
  return {
    page: candidate && pageIds.has(candidate) ? candidate : ("home" as Page),
    applicationIndex: Math.max(0, Number(match?.[2] || 0) || 0),
    focus: {
      section:
        candidate && isWorkspaceArea(candidate)
          ? resolveWorkspaceSection(
              candidate,
              query.get("section") || undefined,
              query.get("artifactKind") || undefined,
            )
          : candidate === "server" &&
              ["users", "groups", "membership"].includes(
                query.get("section") || "",
              )
            ? query.get("section")!
            : undefined,
      workspaceId: query.get("workspace") || undefined,
      applicationId: query.get("application") || undefined,
      ...(candidate === "metadata"
        ? {
            metadataSection: metadata.section,
            dimensionId: metadata.dimensionId,
            memberId: metadata.memberId,
            hierarchyId: metadata.hierarchyId,
          }
        : {}),
      assignmentId: query.get("assignment") || undefined,
      viewId: query.get("view") || undefined,
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
      artifactStateToken: /^[0-9a-f]{64}$/.test(rawArtifactStateToken)
        ? rawArtifactStateToken
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

function sessionIdentityKey(identity: SessionIdentity | null) {
  return identity
    ? JSON.stringify([identity.issuer || "", identity.subject])
    : "anonymous";
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
  const identityKey = sessionIdentityKey(identity);
  setDraftIdentity(identityKey);
  const identityRef = useRef<SessionIdentity | null>(null);
  const [pendingIdentity, setPendingIdentity] =
    useState<SessionIdentity | null>(null);
  const [catalog, setCatalog] = useState<ApplicationCatalog | null>(null);
  const [catalogScopeKey, setCatalogScopeKey] = useState("");
  const [catalogError, setCatalogError] = useState<{
    scope: string;
    message: string;
  } | null>(null);
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
  const routeHistoryIndex = useRef(
    Number.isSafeInteger(window.history.state?.openEpmNavigationIndex)
      ? (window.history.state.openEpmNavigationIndex as number)
      : 0,
  );
  const restoringHistory = useRef<string | null>(null);
  const afterHistoryRestore = useRef<null | (() => void)>(null);
  const approvedHistoryTarget = useRef<string | null>(null);
  const explicitApplication = Boolean(
    workFocus.workspaceId || workFocus.applicationId,
  );
  const exactApplicationIndex = applications.findIndex(
    (item) =>
      item.workspaceId === workFocus.workspaceId &&
      item.applicationId === workFocus.applicationId,
  );
  const app =
    applicationScopedPage(page) && explicitApplication
      ? applications[exactApplicationIndex]
      : applications[selected];
  const applicationKey = app
    ? JSON.stringify([app.workspaceId, app.applicationId])
    : "";
  const catalogScope = JSON.stringify([identityKey, applicationKey]);
  const currentCatalog = catalogScope === catalogScopeKey ? catalog : null;
  const activeCatalogScope = useRef(catalogScope);
  activeCatalogScope.current = catalogScope;
  const catalogLoadGeneration = useRef(0);
  const refreshApplicationCatalog = useCallback(async () => {
    if (!app)
      throw new Error("Select an application before refreshing its context.");
    const requestedScope = catalogScope;
    const generation = ++catalogLoadGeneration.current;
    const value = await readCatalog({
      workspaceId: app.workspaceId,
      applicationId: app.applicationId,
    });
    if (
      activeCatalogScope.current !== requestedScope ||
      generation !== catalogLoadGeneration.current
    )
      throw new DOMException("Application context changed", "AbortError");
    setCatalog(value);
    setCatalogScopeKey(requestedScope);
    setCatalogError(null);
    return value;
  }, [app?.workspaceId, app?.applicationId, catalogScope]);
  const activeWorkspaceSection = isWorkspaceArea(page)
    ? workspaceSections[page].find(
        (item) =>
          item.id ===
          resolveWorkspaceSection(
            page,
            workFocus.section,
            workFocus.artifactKind,
          ),
      )
    : undefined;
  const currentCatalogError =
    catalogError?.scope === catalogScope ? catalogError.message : "";
  const [metadataDimensionState, setMetadataDimensionState] = useState<{
    applicationKey: string;
    dimensions: MetadataNavigationDimension[];
  }>({ applicationKey: "", dimensions: [] });
  const metadataDimensions =
    metadataDimensionState.applicationKey === applicationKey
      ? metadataDimensionState.dimensions
      : [];
  const onMetadataDimensionsChange = useCallback(
    (dimensions: MetadataNavigationDimension[]) => {
      setMetadataDimensionState({ applicationKey, dimensions });
    },
    [applicationKey],
  );
  useEffect(() => {
    setMetadataDimensionState({ applicationKey, dimensions: [] });
  }, [applicationKey, identityKey]);
  useEffect(() => {
    if (
      page !== "metadata" ||
      workFocus.dimensionId ||
      !workFocus.metadataSection ||
      ["dimensions", "reference"].includes(workFocus.metadataSection)
    )
      return;
    const first =
      metadataDimensions.find((dimension) => dimension.status === "Active") ||
      metadataDimensions[0];
    if (first)
      setWorkFocus((current) => ({
        ...current,
        dimensionId: first.dimension_id,
      }));
  }, [
    page,
    workFocus.dimensionId,
    workFocus.metadataSection,
    metadataDimensions,
  ]);

  function acceptSession(session: SessionIdentity) {
    const current = identityRef.current;
    if (
      current &&
      sessionIdentityKey(current) !== sessionIdentityKey(session) &&
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
        if (controller.signal.aborted) return;
        setApplications(apps);
        acceptSession(session);
        setSelected((current) => (current < apps.length ? current : 0));
      })
      .catch((reason: Error) => {
        if (
          !controller.signal.aborted &&
          !(reason instanceof DOMException && reason.name === "AbortError")
        )
          setError(reason.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoading(false);
      });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    readPlatformCatalog(controller.signal)
      .then((value) => {
        if (!controller.signal.aborted)
          setPlatformCatalog(value.authorized === false ? null : value);
      })
      .catch((reason: Error) => {
        if (
          controller.signal.aborted ||
          (reason instanceof DOMException && reason.name === "AbortError")
        )
          return;
        if (!(reason instanceof ApiError && reason.status === 403))
          setError(reason.message);
      })
      .finally(() => {
        if (!controller.signal.aborted) setPlatformChecked(true);
      });
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
    if (applicationScopedPage(page) && app && !explicitApplication) {
      setWorkFocus((current) => ({
        ...current,
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
      }));
      return;
    }
    const route = presentationRouteHash(page, selected, workFocus);
    window.history.replaceState(
      {
        ...window.history.state,
        openEpmNavigationIndex: routeHistoryIndex.current,
      },
      "",
      route,
    );
  }, [
    page,
    selected,
    workFocus,
    app?.workspaceId,
    app?.applicationId,
    explicitApplication,
  ]);

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
      if (restoringHistory.current) {
        if (window.location.hash === restoringHistory.current) {
          restoringHistory.current = null;
          const resume = afterHistoryRestore.current;
          afterHistoryRestore.current = null;
          resume?.();
        }
        return;
      }
      const route = readPresentationRoute();
      const requestedHash = window.location.hash;
      const previousHash = presentationRouteHash(page, selected, workFocus);
      if (requestedHash === previousHash) return;
      const requestedIndex = window.history.state?.openEpmNavigationIndex;
      const restoreRequestedRoute = () => {
        if (Number.isSafeInteger(requestedIndex))
          routeHistoryIndex.current = requestedIndex;
        setPage(route.page);
        setSelected(route.applicationIndex);
        setWorkFocus(route.focus);
      };
      if (approvedHistoryTarget.current === requestedHash) {
        approvedHistoryTarget.current = null;
        restoreRequestedRoute();
      } else if (unsavedWorkSnapshot().length > 0) {
        const delta = Number.isSafeInteger(requestedIndex)
          ? requestedIndex - routeHistoryIndex.current
          : 0;
        if (delta) {
          restoringHistory.current = previousHash;
          window.history.go(-delta);
          requestTransition(() => {
            const resume = () => {
              approvedHistoryTarget.current = requestedHash;
              window.history.go(delta);
            };
            if (restoringHistory.current) afterHistoryRestore.current = resume;
            else resume();
          }, true);
        } else {
          // Manually edited or externally supplied hash entries have no owned
          // history position. Restore the current URL before asking to leave.
          window.history.replaceState(
            {
              ...window.history.state,
              openEpmNavigationIndex: routeHistoryIndex.current,
            },
            "",
            previousHash,
          );
          requestTransition(() => {
            window.history.replaceState(
              {
                ...window.history.state,
                openEpmNavigationIndex: routeHistoryIndex.current,
              },
              "",
              requestedHash,
            );
            restoreRequestedRoute();
          }, true);
        }
      } else restoreRequestedRoute();
    };
    window.addEventListener("hashchange", restore);
    return () => window.removeEventListener("hashchange", restore);
  }, [page, selected, workFocus]);

  function requestTransition(transition: () => void, preserveDrafts = false) {
    if (
      unsavedWorkSnapshot().length === 0 ||
      (preserveDrafts && canPreserveUnsavedWork())
    ) {
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

  function navigationDestination(target: Page, focus: WorkFocus = {}) {
    return applicationScopedPage(target) && app
      ? {
          ...focus,
          workspaceId: focus.workspaceId || app.workspaceId,
          applicationId: focus.applicationId || app.applicationId,
        }
      : focus;
  }

  function navigationHref(target: Page, focus: WorkFocus = {}) {
    return presentationRouteHash(
      target,
      selected,
      navigationDestination(target, focus),
    );
  }

  function navigate(target: Page, focus: WorkFocus = {}) {
    const destination = navigationDestination(target, focus);
    if (
      target === page &&
      presentationRouteHash(target, selected, destination) ===
        presentationRouteHash(page, selected, workFocus)
    )
      return;
    const transition = () => {
      setAccountOpen(false);
      routeHistoryIndex.current += 1;
      window.history.pushState(
        { openEpmNavigationIndex: routeHistoryIndex.current },
        "",
        presentationRouteHash(target, selected, destination),
      );
      setWorkFocus(destination);
      setPage(target);
      if (window.matchMedia?.("(max-width: 650px)").matches) setCollapsed(true);
    };
    requestTransition(transition, true);
  }

  function navigateMetadata(destination: MetadataDestination) {
    navigate("metadata", {
      metadataSection: destination.section,
      dimensionId: destination.dimensionId,
      memberId: destination.memberId,
      hierarchyId: Object.hasOwn(destination, "hierarchyId")
        ? destination.hierarchyId || undefined
        : destination.dimensionId === workFocus.dimensionId
          ? workFocus.hierarchyId
          : undefined,
    });
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
      setCatalogScopeKey("");
      setCatalogError(null);
      return;
    }
    const controller = new AbortController();
    const generation = ++catalogLoadGeneration.current;
    readCatalog(
      { workspaceId: app.workspaceId, applicationId: app.applicationId },
      controller.signal,
    )
      .then((value) => {
        if (
          controller.signal.aborted ||
          generation !== catalogLoadGeneration.current
        )
          return;
        setCatalog(value);
        setCatalogScopeKey(catalogScope);
        setCatalogError(null);
      })
      .catch((reason: unknown) => {
        if (
          controller.signal.aborted ||
          generation !== catalogLoadGeneration.current ||
          (reason instanceof DOMException && reason.name === "AbortError")
        )
          return;
        setCatalogError({
          scope: catalogScope,
          message:
            reason instanceof Error ? reason.message : "CATALOG_REQUEST_FAILED",
        });
      });
    return () => controller.abort();
  }, [app?.workspaceId, app?.applicationId, identityKey]);

  const visibleApplicationPages = useMemo(
    () =>
      applicationPages.filter((item) =>
        applicationPageVisible(item.id, currentCatalog),
      ),
    [currentCatalog],
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
    if (!currentCatalog || primary.some((item) => item.id === page)) return;
    if (!applicationPageVisible(page, currentCatalog)) navigate("overview");
  }, [currentCatalog, page]);

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

  function chooseApplication(index: number, destination: Page = "overview") {
    const target = applications[index];
    if (!target) return;
    if (
      index === selected &&
      page === destination &&
      app?.workspaceId === target.workspaceId &&
      app?.applicationId === target.applicationId
    )
      return;
    const transition = () => {
      routeHistoryIndex.current += 1;
      window.history.pushState(
        { openEpmNavigationIndex: routeHistoryIndex.current },
        "",
        presentationRouteHash(destination, index, {}),
      );
      setSelected(index);
      setAccountOpen(false);
      setWorkFocus({});
      setPage(destination);
    };
    requestTransition(transition, true);
  }

  async function applicationCreated(created: CreatedApplication) {
    const apps = await listApplications();
    const index = apps.findIndex(
      (item) =>
        item.workspaceId === created.workspaceId &&
        item.applicationId === created.applicationId,
    );
    if (index < 0)
      throw new Error(
        "The created application is not yet available in your application list. Refresh to try opening it again.",
      );
    setApplications(apps);
    setSelected(index);
    navigate("overview", {
      workspaceId: created.workspaceId,
      applicationId: created.applicationId,
    });
  }

  async function applicationDeleted(
    workspaceId: string,
    _applicationId: string,
  ) {
    const apps = await listApplications();
    const index = Math.max(
      0,
      apps.findIndex((item) => item.workspaceId === workspaceId),
    );
    setApplications(apps);
    setSelected(index);
    navigate(
      "applications",
      apps[index]
        ? {
            workspaceId: apps[index].workspaceId,
            applicationId: apps[index].applicationId,
          }
        : undefined,
    );
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
            window.location.assign(browserLogoutPath());
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

  const breadcrumbLink = (
    label: string,
    target: Page,
    focus: WorkFocus = {},
  ): BreadcrumbItem => ({
    label,
    href: navigationHref(target, focus),
    onNavigate: () => navigate(target, focus),
  });
  const breadcrumbItems: BreadcrumbItem[] = [
    applicationScopedPage(page)
      ? app
        ? breadcrumbLink(app.name, "overview")
        : breadcrumbLink("Applications", "applications")
      : breadcrumbLink("Open EPM", "home"),
  ];
  if (page === "metadata") {
    breadcrumbItems.push(breadcrumbLink("Metadata", "metadata"));
    if (
      workFocus.dimensionId &&
      !["dimensions", "reference"].includes(
        workFocus.metadataSection || "dimensions",
      )
    ) {
      breadcrumbItems.push(
        breadcrumbLink(
          metadataDimensions.find(
            (dimension) => dimension.dimension_id === workFocus.dimensionId,
          )?.name || workFocus.dimensionId,
          "metadata",
          {
            metadataSection: "members",
            dimensionId: workFocus.dimensionId,
            hierarchyId: workFocus.hierarchyId,
          },
        ),
      );
    }
    breadcrumbItems.push({
      label: metadataSectionLabels[workFocus.metadataSection || "dimensions"],
    });
  } else if (
    activeWorkspaceSection &&
    activeWorkspaceSection.label.toLocaleLowerCase() !==
      pageTitle(page).toLocaleLowerCase()
  ) {
    breadcrumbItems.push(breadcrumbLink(pageTitle(page), page), {
      label: activeWorkspaceSection.label,
    });
  } else {
    breadcrumbItems.push({ label: pageTitle(page) });
  }

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
                <UiIcon name={item.id} />
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
            {navigationGroups.map((group) => (
              <section
                className="navigation-group"
                key={group.label}
                aria-label={group.label}
              >
                <div className="nav-group-label">{group.label}</div>
                {visibleApplicationPages
                  .filter((item) => group.pages.includes(item.id))
                  .map((item) =>
                    item.id === "metadata" ? (
                      <MetadataNavigation
                        key={`${identityKey}:${applicationKey}:metadata`}
                        active={page === "metadata"}
                        listsActive={page === "lists"}
                        section={workFocus.metadataSection || "dimensions"}
                        dimensionId={workFocus.dimensionId}
                        dimensions={metadataDimensions}
                        collapsed={collapsed}
                        disabled={!app}
                        onNavigate={navigateMetadata}
                        onMemberLists={() => navigate("lists")}
                      />
                    ) : (
                      <button
                        key={item.id}
                        className={page === item.id ? "active" : ""}
                        aria-label={item.label}
                        aria-current={page === item.id ? "page" : undefined}
                        disabled={!app}
                        onClick={() => navigate(item.id)}
                      >
                        <UiIcon name={item.id} />
                        <b>{item.label}</b>
                      </button>
                    ),
                  )}
              </section>
            ))}
          </nav>
          <div className="sidebar-foot">
            <span className="agent-dot" />{" "}
            <span>
              <b>Open EPM</b>
              <small>Programmable multidimensional platform</small>
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
          <Breadcrumbs items={breadcrumbItems} />
          <div className="top-actions">
            <button
              className="print-action"
              aria-label="Print current view"
              title="Print current view"
              onClick={() => window.print()}
            >
              <UiIcon name="print" />
            </button>
            <button
              aria-label="Copy link to this view"
              onClick={() => void copyViewLink()}
            >
              <UiIcon name="link" />
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
              <UiIcon name="search" />
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
              <UiIcon name="notifications" />
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
              <UiIcon name="help" />
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
              catalog={currentCatalog}
              applicationCount={applications.length}
              signOut={signOut}
            />
          )}
          <Notifications
            open={notificationsOpen}
            close={() => setNotificationsOpen(false)}
            app={app}
            goMonitor={() => navigate("monitor")}
          />
        </header>

        <GlobalSearch
          open={searchOpen}
          close={() => setSearchOpen(false)}
          applications={applications}
          selectedApplication={app}
          targets={[...visiblePrimary, ...visibleApplicationPages]}
          catalog={currentCatalog}
          go={go}
          chooseApplication={chooseApplication}
        />
        <HelpPanel open={helpOpen} close={() => setHelpOpen(false)} />

        <main
          data-page={page}
          id="main-content"
          tabIndex={-1}
          key={identityKey}
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
              <span>Working from an assigned workflow activity</span>
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
          {(error || currentCatalogError) && (
            <div className="alert" role="alert" aria-live="assertive">
              {error || currentCatalogError}
            </div>
          )}
          {loading ? (
            <Loading />
          ) : (
            <Suspense
              fallback={<div className="empty-state">Loading workspace…</div>}
            >
              {applicationScopedPage(page) && explicitApplication && !app ? (
                <section className="page" role="alert">
                  <h1>Application unavailable</h1>
                  <p>
                    This link refers to an application outside your current
                    access. Choose an application to continue.
                  </p>
                  <button
                    className="primary"
                    onClick={() => navigate("applications")}
                  >
                    Choose application
                  </button>
                </section>
              ) : page === "home" ? (
                <Home
                  app={app}
                  identity={identity}
                  catalog={currentCatalog}
                  go={navigate}
                />
              ) : page === "applications" ? (
                <Applications
                  key={`${identityKey}:${app?.workspaceId || "none"}`}
                  applications={applications}
                  selected={selected}
                  catalog={currentCatalog}
                  subject={identity?.subject || ""}
                  choose={chooseApplication}
                  selectWorkspace={(index) =>
                    chooseApplication(index, "applications")
                  }
                  onRequestTransition={requestTransition}
                  created={applicationCreated}
                  deleted={applicationDeleted}
                />
              ) : page === "work" ? (
                <MyWork
                  key={applicationKey}
                  app={app}
                  catalog={currentCatalog}
                  open={navigate}
                />
              ) : page === "server" && platformCatalog ? (
                <ServerAdministration
                  key={workFocus.section || "users"}
                  functions={platformCatalog.functions}
                  section={workFocus.section}
                  onNavigateSection={(section) =>
                    navigate("server", { section })
                  }
                  onRequestTransition={requestTransition}
                />
              ) : page === "overview" ? (
                <Overview
                  app={app}
                  catalog={currentCatalog}
                  go={navigate}
                  onRequestTransition={requestTransition}
                />
              ) : page === "grid" ? (
                <Analyze
                  key={`${identityKey}:${applicationKey}`}
                  app={app}
                  catalog={currentCatalog}
                  index={selected}
                  subject={identity?.subject || ""}
                  onRequestTransition={requestTransition}
                  targetViewId={workFocus.viewId}
                  targetViewDigest={workFocus.viewDigest}
                />
              ) : page === "flows" ? (
                <GenericWorkflow
                  key={`${identityKey}:${applicationKey}`}
                  app={app}
                  catalog={currentCatalog}
                  onRequestTransition={requestTransition}
                  targetOccurrenceId={workFocus.occurrenceId}
                  targetActivityId={workFocus.activityId}
                  openDestination={(destination, activityContext) => {
                    const common = {
                      workspaceId: app?.workspaceId,
                      applicationId: app?.applicationId,
                      occurrenceId:
                        activityContext?.occurrenceId || workFocus.occurrenceId,
                      activityId:
                        activityContext?.activityId || workFocus.activityId,
                    };
                    const resolution = resolveWorkflowDestination(
                      destination,
                      currentCatalog,
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
                <MyWork
                  key={applicationKey}
                  app={app}
                  catalog={currentCatalog}
                  open={navigate}
                />
              ) : page === "metadata" ? (
                explicitApplication && !app ? (
                  <section className="page metadata-unavailable" role="alert">
                    <h1>Application unavailable</h1>
                    <p>
                      This metadata link refers to an application that is not in
                      your authorized application list. Choose an application to
                      continue.
                    </p>
                    <button
                      type="button"
                      onClick={() => navigate("applications")}
                    >
                      Choose application
                    </button>
                  </section>
                ) : (
                  <MetadataWorkspace
                    key={`${identityKey}:${applicationKey}`}
                    app={app}
                    catalog={currentCatalog}
                    section={workFocus.metadataSection || "dimensions"}
                    dimensionId={workFocus.dimensionId}
                    memberId={workFocus.memberId}
                    hierarchyId={workFocus.hierarchyId}
                    onNavigate={navigateMetadata}
                    hrefForDestination={(destination) =>
                      navigationHref("metadata", {
                        metadataSection: destination.section,
                        dimensionId: destination.dimensionId,
                        memberId: destination.memberId,
                        hierarchyId: Object.hasOwn(destination, "hierarchyId")
                          ? destination.hierarchyId || undefined
                          : destination.dimensionId === workFocus.dimensionId
                            ? workFocus.hierarchyId
                            : undefined,
                      })
                    }
                    onDimensionsChange={onMetadataDimensionsChange}
                    onRequestTransition={requestTransition}
                  />
                )
              ) : page === "data" ||
                page === "lists" ||
                page === "rules" ||
                page === "security" ||
                page === "administration" ? (
                <CapabilityArea
                  key={`${identityKey}:${app?.workspaceId || "none"}:${app?.applicationId || "none"}:${page}:${isWorkspaceArea(page) ? resolveWorkspaceSection(page, workFocus.section, workFocus.artifactKind) : ""}`}
                  area={page}
                  section={
                    isWorkspaceArea(page)
                      ? resolveWorkspaceSection(
                          page,
                          workFocus.section,
                          workFocus.artifactKind,
                        )
                      : undefined
                  }
                  onNavigateSection={(section) =>
                    navigate(page, {
                      ...workFocus,
                      section,
                      artifactKind: undefined,
                      artifactId: undefined,
                      artifactVersion: undefined,
                      artifactStateToken: undefined,
                      artifactDigest: undefined,
                    })
                  }
                  onRequestTransition={requestTransition}
                  app={app}
                  catalog={currentCatalog}
                  onRefreshCatalog={refreshApplicationCatalog}
                  index={selected}
                  targetApplicationRule={
                    workFocus.artifactKind === "ApplicationRule" &&
                    workFocus.artifactId &&
                    workFocus.artifactStateToken &&
                    workFocus.artifactDigest
                      ? {
                          ruleId: workFocus.artifactId,
                          stateToken: workFocus.artifactStateToken,
                          digest: workFocus.artifactDigest,
                        }
                      : undefined
                  }
                  targetCalculatedMember={
                    workFocus.artifactKind === "CalculatedMember" &&
                    workFocus.artifactId &&
                    workFocus.artifactStateToken &&
                    workFocus.artifactDigest
                      ? {
                          definitionId: workFocus.artifactId,
                          stateToken: workFocus.artifactStateToken,
                          digest: workFocus.artifactDigest,
                        }
                      : undefined
                  }
                  targetApplicationSequence={
                    workFocus.artifactKind === "ApplicationSequence" &&
                    workFocus.artifactId &&
                    workFocus.artifactStateToken &&
                    workFocus.artifactDigest
                      ? {
                          ruleId: workFocus.artifactId,
                          stateToken: workFocus.artifactStateToken,
                          digest: workFocus.artifactDigest,
                        }
                      : undefined
                  }
                  targetApplicationSchedule={
                    workFocus.artifactKind === "ApplicationSchedule" &&
                    workFocus.artifactId &&
                    workFocus.artifactStateToken &&
                    workFocus.artifactDigest
                      ? {
                          scheduleId: workFocus.artifactId,
                          stateToken: workFocus.artifactStateToken,
                          digest: workFocus.artifactDigest,
                        }
                      : undefined
                  }
                />
              ) : page === "monitor" ? (
                <Monitor
                  key={applicationKey}
                  app={app}
                  catalog={currentCatalog}
                  onRequestTransition={requestTransition}
                />
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
                These changes have not been saved. Leaving this view will
                discard the browser draft.
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
  catalog,
  go,
}: {
  app?: ApplicationSummary;
  identity: SessionIdentity | null;
  catalog: ApplicationCatalog | null;
  go: (page: Page) => void;
}) {
  const first = (identity?.displayIdentity || "there").split(/[@. ]/)[0];
  const destinations: { page: Page; title: string; text: string }[] = [
    {
      page: "grid",
      title: "Explore & edit data",
      text: "Choose a view, inspect values and review your changes.",
    },
    {
      page: "data",
      title: "Import & export",
      text: "Move data into and out of your application.",
    },
    {
      page: "metadata",
      title: "Shape your model",
      text: "Maintain dimensions, members and relationships.",
    },
    {
      page: "rules",
      title: "Build calculations",
      text: "Create reusable rules, sequences and schedules.",
    },
    {
      page: "flows",
      title: "Follow a workflow",
      text: "Complete activities with the right context and evidence.",
    },
    {
      page: "monitor",
      title: "Inspect activity",
      text: "Track running work, results and anything needing attention.",
    },
  ];
  return (
    <div className="page home-page">
      <PageHeading
        eyebrow="YOUR WORKSPACE"
        title={`Welcome back, ${first}`}
        description="A clear place to work with your models, data and decisions."
      />
      <section className="hero-card">
        <div>
          <span className="pill">CURRENT APPLICATION</span>
          <h2>{app?.name || "Choose your application"}</h2>
          <p>
            {app
              ? `${app.workspaceName || app.workspaceId} · ${app.applicationId}`
              : "Open a model to begin working with its data and structure."}
          </p>
        </div>
        <button
          className="primary"
          onClick={() => go(app ? "overview" : "applications")}
        >
          {app ? "Open application" : "Choose application"}
          <UiIcon name="arrow" />
        </button>
      </section>
      <div className="section-title">
        <div>
          <h2>What would you like to work on?</h2>
          <p>Choose a task to open its workspace.</p>
        </div>
        <button className="secondary" onClick={() => go("work")}>
          My work <UiIcon name="arrow" />
        </button>
      </div>
      <div className="action-grid">
        {destinations
          .filter((item) => !app || applicationPageVisible(item.page, catalog))
          .map((item) => (
            <Action
              key={item.page}
              title={item.title}
              text={item.text}
              icon={item.page}
              onClick={() => go(app ? item.page : "applications")}
            />
          ))}
      </div>
      <div className="home-orientation">
        <UiIcon name="metadata" />
        <div>
          <strong>One model. Connected workspaces.</strong>
          <p>
            Metadata defines your structure. The grid and data tools work with
            its values. Rules and workflows bring that work together.
          </p>
        </div>
      </div>
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
      <span>
        <UiIcon name={icon} />
      </span>
      <div>
        <strong>{title}</strong>
        <p>{text}</p>
      </div>
      <em>
        <UiIcon name="arrow" />
      </em>
    </button>
  );
}

type OverviewState = {
  assignedWork: number;
  worklistHasMore: boolean;
  tasksHaveMore: boolean;
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
  onRequestTransition = (action) => action(),
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  go: (page: Page) => void;
  onRequestTransition?: (action: () => void) => void;
}) {
  const [business, setBusiness] = useState<OverviewState | null>(null);
  const [businessError, setBusinessError] = useState("");
  useEffect(() => {
    setBusiness(null);
    setBusinessError("");
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
      ? readProgram<{ items: unknown[]; nextCursor?: unknown }>(
          scope,
          "application.workflow.worklist",
          { limit: 100 },
          controller.signal,
        )
      : Promise.resolve({ items: [], nextCursor: null });
    const tasks = request<{
      hasMore?: boolean;
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
        if (controller.signal.aborted) return;
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
          worklistHasMore: Boolean(flow.nextCursor),
          tasksHaveMore: Boolean(taskPage.hasMore),
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
      .catch((reason: Error) => {
        if (!controller.signal.aborted) setBusinessError(reason.message);
      });
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
  return (
    <div className="page overview-page">
      <PageHeading
        eyebrow="Application overview"
        title={app.name}
        description="Your work, recent activity and model context in one place."
      >
        <button className="primary" onClick={() => go("grid")}>
          Open Grid →
        </button>
      </PageHeading>
      <div className="metric-grid">
        <Metric
          value={
            business
              ? `${business.assignedWork}${business.worklistHasMore ? "+" : ""}`
              : "—"
          }
          label="Ready for you"
        />
        <Metric
          value={
            business
              ? `${business.running}${business.tasksHaveMore ? "+" : ""}`
              : "—"
          }
          label="Work running"
        />
        <Metric
          value={
            business
              ? `${business.attention}${business.tasksHaveMore ? "+" : ""}`
              : "—"
          }
          label="Needs attention"
        />
      </div>
      <p className="data-scope-note">
        Counts reflect the loaded worklist and first 100 task records. A +
        indicates more records are available.
      </p>
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
              icon="grid"
              onClick={() => go("grid")}
            />
            {applicationPageVisible("rules", catalog) && (
              <Action
                title="Build generic rules"
                text="Compose calculations, sequences and schedules from primitives."
                icon="rules"
                onClick={() => go("rules")}
              />
            )}
            <Action
              title="Review flows"
              text="Assignments, review steps and governed evidence."
              icon="flows"
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
                  <small>{task.initiatorKind || "Verified user"}</small>
                </article>
              ))}
            </div>
          ) : (
            <div className="empty-state">
              {businessError
                ? "Activity could not be loaded. Open Monitor to retry."
                : business
                  ? "No recent activity is visible."
                  : "Loading recent activity…"}
            </div>
          )}
          <details className="model-details">
            <summary>Application details</summary>
            <dl>
              <div>
                <dt>Application</dt>
                <dd>{app.name}</dd>
              </div>
              <div>
                <dt>Your role</dt>
                <dd>{catalog?.applicationAccess.role || "—"}</dd>
              </div>
              <div>
                <dt>Lifecycle state</dt>
                <dd>{app.status}</dd>
              </div>
              <div>
                <dt>Model type</dt>
                <dd>{app.kind || "Multidimensional EPM"}</dd>
              </div>
            </dl>
          </details>
        </section>
      </div>
      {catalog && (
        <ApplicationDecisions
          key={`${app.workspaceId}:${app.applicationId}`}
          scope={{
            workspaceId: app.workspaceId,
            applicationId: app.applicationId,
          }}
          catalog={catalog}
          onRequestTransition={onRequestTransition}
        />
      )}
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
