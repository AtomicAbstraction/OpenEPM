import { Breadcrumbs } from "./Breadcrumbs";
import type { BreadcrumbItem } from "./Breadcrumbs";
import { ApplicationDecisions } from "./ApplicationDecisions";
import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  ApiError,
  adoptBrowserIdentity,
  isApplicationAccessDenied,
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
import { applicationRoleLabel } from "./types";
import { mergeTaskListPage, taskListBody } from "./task-list";
import type { TaskListPage, TaskListRow } from "./task-list";
import { GlobalSearch, HelpPanel, Notifications } from "./GlobalPanels";
import { outcomeAuthorityKey } from "./ReceiptInspector";
import { Applications } from "./Applications";
import type { CreatedApplication } from "./Applications";
import {
  browserLifecycleSnapshot,
  installConnectivityLifecycle,
  setBrowserLifecycle,
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
import {
  parseReferenceHandoff,
  referenceDestination,
  referenceHandoffHash,
  retargetReferenceHandoff,
} from "./reference-handoff";
import type {
  ReferenceHandoff,
  ResolvedReferenceContext,
  SavedViewContext,
} from "./reference-handoff";
import { MetadataNavigation } from "./MetadataNavigation";
import {
  metadataSectionLabels,
  readMetadataDestination,
  writeMetadataDestination,
} from "./metadata-navigation";
import {
  firstSecuritySection,
  ruleSectionsFor,
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
  referenceHandoff?: ReferenceHandoff;
  handoffError?: string;
  taskId?: string;
  returnTaskId?: string;
  section?: string;
  workspaceId?: string;
  applicationId?: string;
  metadataSection?: MetadataSection;
  dimensionId?: string;
  memberId?: string;
  hierarchyId?: string;
  relationshipId?: string;
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
  if (focus.handoffError) return "#/reference?invalid=1";
  if (focus.referenceHandoff)
    return referenceHandoffHash(focus.referenceHandoff);
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
  if (page === "applications" && focus.workspaceId)
    query.set("workspace", focus.workspaceId);
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
      relationshipId: focus.relationshipId,
    });
  if (page === "flows" && focus.occurrenceId) {
    query.set("occurrence", focus.occurrenceId);
    if (focus.activityId) query.set("activity", focus.activityId);
  }
  if (page === "monitor" && focus.taskId) query.set("task", focus.taskId);
  if (page !== "monitor" && focus.returnTaskId)
    query.set("returnTask", focus.returnTaskId);
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
  if (page === "security")
    return Boolean(catalog && firstSecuritySection(catalog.functions));
  if (catalog?.applicationAccess.authorizationModel === "group_assignments") {
    let prefixes: string[];
    if (isWorkspaceArea(page)) {
      prefixes = workspaceSections[page].flatMap((section) => section.prefixes);
    } else if (page === "metadata") {
      prefixes = [
        "metadata.dimension.",
        "metadata.member.",
        "metadata.hierarchy.",
      ];
    } else if (page === "grid") {
      prefixes = ["facts.cube.", "facts.generic.table.list", "facts.cell."];
    } else if (page === "flows") {
      prefixes = [
        "application.workflow.",
        "application.assignment.",
        "application.decision.",
      ];
    } else if (page === "monitor") {
      return Boolean(catalog.ownedJobOperations?.includes("events"));
    } else if (page === "tasks") {
      return false;
    } else {
      return true;
    }
    return Object.keys(catalog.functions).some((name) =>
      prefixes.some((prefix) => name.startsWith(prefix)),
    );
  }
  if (page === "administration")
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
  if (requested === "reference" || query.has("handoff")) {
    try {
      if (
        requested !== "reference" ||
        query.size !== 1 ||
        !query.has("handoff")
      )
        throw new Error(
          "Invalid reference link. Request a fresh reference from the originating client.",
        );
      const handoff = parseReferenceHandoff(query.get("handoff"));
      const destination = referenceDestination(handoff);
      return {
        page: destination.page,
        applicationIndex: 0,
        focus: {
          ...handoff.scope,
          ...destination.focus,
          referenceHandoff: handoff,
        } as WorkFocus,
      };
    } catch (reason) {
      return {
        page: "home" as Page,
        applicationIndex: 0,
        focus: {
          handoffError:
            reason instanceof Error
              ? reason.message
              : "Invalid reference link.",
        } as WorkFocus,
      };
    }
  }
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
            relationshipId: metadata.relationshipId,
          }
        : {}),
      assignmentId: query.get("assignment") || undefined,
      taskId: query.get("task") || undefined,
      returnTaskId: query.get("returnTask") || undefined,
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
  return identity?.identityBinding ?? "anonymous";
}

type PlatformAccess =
  | {
      state: "granted";
      catalog: Awaited<ReturnType<typeof readPlatformCatalog>>;
    }
  | { state: "denied" | "unavailable" };

async function readPlatformAccess(
  signal: AbortSignal,
  identityBinding: string,
): Promise<PlatformAccess> {
  try {
    const catalog = await readPlatformCatalog(signal, identityBinding);
    if (
      catalog?.languageVersion !== 2 ||
      !catalog.functions ||
      typeof catalog.functions !== "object" ||
      Array.isArray(catalog.functions) ||
      (catalog.authorized !== undefined &&
        typeof catalog.authorized !== "boolean")
    )
      return { state: "unavailable" };
    return catalog.authorized === false
      ? { state: "denied" }
      : { state: "granted", catalog };
  } catch (reason: unknown) {
    if (reason instanceof ApiError) {
      // The platform catalogue reports a confirmed denial as authorized: false.
      // A transport refusal leaves the current grant unconfirmed.
      if (
        reason.kind === "authorization" ||
        reason.kind === "request" ||
        reason.kind === "capacity"
      )
        return { state: "unavailable" };
    }
    throw reason;
  }
}

function validateApplicationCatalog(value: ApplicationCatalog) {
  const access = value?.applicationAccess;
  const revisions = value?.revisions;
  if (
    !access ||
    (access.authorizationModel === "group_assignments"
      ? access.role !== "Assigned" ||
        !Array.isArray(access.roles) ||
        !access.roles.every(
          (role) => typeof role === "string" && role.trim().length > 0,
        )
      : (access.authorizationModel !== undefined &&
          access.authorizationModel !== "legacy") ||
        !["Reader", "Editor", "Administrator"].includes(access.role)) ||
    typeof access.workspaceAdministrator !== "boolean" ||
    (value.workspaceFunctions !== undefined &&
      (!Array.isArray(value.workspaceFunctions) ||
        !value.workspaceFunctions.every(
          (name) => typeof name === "string" && name.length > 0,
        ))) ||
    (value.accessContext !== undefined &&
      (typeof value.accessContext !== "string" ||
        !/^[0-9a-f]{64}$/.test(value.accessContext))) ||
    !value.functions ||
    typeof value.functions !== "object" ||
    Array.isArray(value.functions) ||
    !Array.isArray(value.enabledCapabilities) ||
    !value.enabledCapabilities.every(
      (capability) => typeof capability === "string",
    ) ||
    !revisions ||
    ![
      revisions.metadata,
      revisions.data,
      revisions.policy,
      revisions.security,
      revisions.commit,
    ].every((revision) => Number.isSafeInteger(revision) && revision >= 0)
  )
    throw new ApiError(502, "INVALID_APPLICATION_CATALOG", undefined, true);
  return value;
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
  const [catalogSnapshot, setCatalogSnapshot] = useState<{
    scope: string;
    value: ApplicationCatalog;
  } | null>(null);
  const [catalogError, setCatalogError] = useState<{
    scope: string;
    message: string;
    denied: boolean;
  } | null>(null);
  const [catalogCheck, setCatalogCheck] = useState<{
    scope: string;
    request: AbortController;
  } | null>(null);
  const [platformAccess, setPlatformAccess] = useState<PlatformAccess | null>(
    null,
  );
  const platformCatalog =
    platformAccess?.state === "granted" ? platformAccess.catalog : null;
  const [page, setPage] = useState<Page>(initialRoute.page);
  const [workFocus, setWorkFocus] = useState<WorkFocus>(initialRoute.focus);
  const [collapsed, setCollapsed] = useState(
    () =>
      typeof window !== "undefined" &&
      Boolean(window.matchMedia?.("(max-width: 950px)").matches),
  );
  const [mobileViewport, setMobileViewport] = useState(() =>
    Boolean(window.matchMedia?.("(max-width: 650px)").matches),
  );
  const mobileNavigationOpen = mobileViewport && !collapsed;
  const mobileNavigationOpenRef = useRef(mobileNavigationOpen);
  mobileNavigationOpenRef.current = mobileNavigationOpen;
  const sidebarToggleRef = useRef<HTMLButtonElement | null>(null);
  const sidebarCloseRef = useRef<HTMLButtonElement | null>(null);
  const sidebarOpeningFocus = useRef(false);
  const sidebarReturningFocus = useRef(false);
  const collapseSidebar = useCallback(() => {
    if (mobileNavigationOpenRef.current) sidebarReturningFocus.current = true;
    else if (document.activeElement?.closest(".sidebar"))
      sidebarToggleRef.current?.focus();
    setCollapsed(true);
  }, []);
  const [accountOpen, setAccountOpen] = useState(false);
  const accountButtonRef = useRef<HTMLButtonElement | null>(null);
  const accountCardRef = useRef<HTMLElement | null>(null);
  const [copyStatus, setCopyStatus] = useState("");
  const copyStatusTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [searchOpen, setSearchOpen] = useState(false);
  const searchButtonRef = useRef<HTMLButtonElement | null>(null);
  const routeDestinationFocus = useRef(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const workspaceModalOpen = searchOpen || helpOpen;
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [browserLifecycle, setBrowserLifecycleState] =
    useState<BrowserLifecycleSnapshot>(browserLifecycleSnapshot);
  const [unsavedWork, setUnsavedWorkState] =
    useState<UnsavedWorkItem[]>(unsavedWorkSnapshot);
  const [discardPromptOpen, setDiscardPromptOpen] = useState(false);
  const discardDialogRef = useRef<HTMLElement | null>(null);
  const discardTriggerRef = useRef<{
    element: HTMLElement;
    mobileNavigation: boolean;
  } | null>(null);
  // Focus follows the committed inert boundary, never the covered Menu button.
  useLayoutEffect(() => {
    if (discardPromptOpen) return;
    if (mobileNavigationOpen && sidebarOpeningFocus.current) {
      sidebarOpeningFocus.current = false;
      sidebarCloseRef.current?.focus();
    } else if (!mobileNavigationOpen && sidebarReturningFocus.current) {
      sidebarReturningFocus.current = false;
      sidebarToggleRef.current?.focus();
    }
  }, [mobileNavigationOpen, discardPromptOpen]);
  const [releaseAvailable, setReleaseAvailable] = useState(false);
  const runtimeBuild = useRef<string | null>(null);
  const pendingTransition = useRef<null | (() => void)>(null);
  const pendingAbandonRecovery = useRef(false);
  const routeHistoryIndex = useRef(
    Number.isSafeInteger(window.history.state?.openEpmNavigationIndex)
      ? (window.history.state.openEpmNavigationIndex as number)
      : 0,
  );
  const restoringHistory = useRef<string | null>(null);
  const afterHistoryRestore = useRef<null | (() => void)>(null);
  const approvedHistoryTarget = useRef<string | null>(null);
  const managedWorkspaceOnly =
    page === "applications" &&
    Boolean(workFocus.workspaceId) &&
    !workFocus.applicationId;
  const explicitApplication =
    !managedWorkspaceOnly &&
    Boolean(workFocus.workspaceId || workFocus.applicationId);
  const exactApplicationIndex = applications.findIndex(
    (item) =>
      item.workspaceId === workFocus.workspaceId &&
      item.applicationId === workFocus.applicationId,
  );
  const usesApplicationContext =
    applicationScopedPage(page) || page === "applications";
  const selectedApplicationIndex = managedWorkspaceOnly
    ? -1
    : usesApplicationContext && explicitApplication
      ? exactApplicationIndex
      : selected;
  const app = applications[selectedApplicationIndex];
  const activeApplication = useRef(app);
  activeApplication.current = app;
  const applicationKey = app
    ? JSON.stringify([app.workspaceId, app.applicationId])
    : "";
  const catalogScope = JSON.stringify([identityKey, applicationKey]);
  const currentCatalog =
    catalogSnapshot?.scope === catalogScope ? catalogSnapshot.value : null;
  const workspaceUnavailable = Boolean(
    currentCatalog && !applicationPageVisible(page, currentCatalog),
  );
  const referenceRoute = JSON.stringify([
    catalogScope,
    page,
    presentationRouteHash(page, selected, workFocus),
  ]);
  // Monitor's task and job projections depend on current grants even when
  // the application, account and requested task in the URL stay the same.
  const referenceScope = workspaceUnavailable
    ? ""
    : currentCatalog
      ? JSON.stringify([
          referenceRoute,
          currentCatalog.accessContext,
          ...(page === "monitor"
            ? [
                currentCatalog.applicationAccess.role,
                currentCatalog.applicationAccess.workspaceAdministrator,
                currentCatalog.revisions.security,
                currentCatalog.revisions.policy,
                currentCatalog.revisions.schemaEpoch,
                currentCatalog.revisions.capability,
              ]
            : []),
        ])
      : referenceRoute;
  const activeReferenceScope = useRef(referenceScope);
  activeReferenceScope.current = referenceScope;
  const [resolvedReference, setResolvedReference] = useState<{
    scope: string;
    context: ResolvedReferenceContext | null;
  }>({ scope: "", context: null });
  const onReferenceContextChange = useCallback(
    (context: ResolvedReferenceContext | null) => {
      if (activeReferenceScope.current !== referenceScope) return;
      setResolvedReference({ scope: referenceScope, context });
    },
    [referenceScope],
  );
  const onViewContextChange = useCallback(
    (context: SavedViewContext | null) => {
      onReferenceContextChange(
        context
          ? {
              target: { kind: "savedView", viewId: context.viewId },
              observed: { viewDigest: context.viewDigest },
              analyticalRead: context.analyticalRead,
            }
          : null,
      );
    },
    [onReferenceContextChange],
  );
  const onTaskContextChange = useCallback(
    (taskId: string | null) => {
      onReferenceContextChange(
        taskId
          ? {
              target: { kind: "task", taskId },
              observed: {},
            }
          : null,
      );
    },
    [onReferenceContextChange],
  );
  const currentReferenceContext =
    currentCatalog &&
    !workspaceUnavailable &&
    resolvedReference.scope === referenceScope
      ? resolvedReference.context
      : null;
  useEffect(() => {
    if (workspaceUnavailable)
      setResolvedReference({ scope: "", context: null });
  }, [workspaceUnavailable]);
  const currentReference = useMemo(() => {
    if (!app || !currentReferenceContext) return null;
    const incoming = workFocus.referenceHandoff;
    const workflowOrigin = workFocus.occurrenceId
      ? {
          kind: "workflowActivity" as const,
          occurrenceId: workFocus.occurrenceId,
          ...(workFocus.activityId ? { activityId: workFocus.activityId } : {}),
        }
      : null;
    const taskOrigin = workFocus.returnTaskId
      ? {
          kind: "task" as const,
          taskId: workFocus.returnTaskId,
        }
      : null;
    try {
      return parseReferenceHandoff({
        format: "openepm.reference-handoff/v1",
        scope: {
          workspaceId: app.workspaceId,
          applicationId: app.applicationId,
        },
        origin: incoming?.origin || taskOrigin || workflowOrigin,
        returnTo: incoming?.returnTo || taskOrigin || workflowOrigin,
        pendingOperation: incoming?.pendingOperation || null,
        ...currentReferenceContext,
      });
    } catch {
      // A malformed legacy origin must not crash the workspace or disappear
      // from an apparently exact handoff. The ordinary page remains usable.
      return null;
    }
  }, [
    app?.workspaceId,
    app?.applicationId,
    currentReferenceContext,
    workFocus,
  ]);
  const activeCatalogScope = useRef(catalogScope);
  activeCatalogScope.current = catalogScope;
  const shell = useRef<HTMLDivElement>(null);
  const catalogCheckRoute = useRef(referenceRoute);
  catalogCheckRoute.current = referenceRoute;
  const catalogCheckFocus = useRef<{
    element: HTMLElement;
    route: string;
  } | null>(null);
  const catalogVisit = useRef<{
    latest: {
      controller: AbortController;
      result: Promise<ApplicationCatalog>;
    } | null;
  } | null>(null);
  useLayoutEffect(() => {
    // A result belongs to this visit. Returning while another application is
    // still loading requires a fresh check even if the earlier scope matches.
    const visit: NonNullable<typeof catalogVisit.current> = { latest: null };
    catalogVisit.current = visit;
    setCatalogSnapshot(null);
    setCatalogError(null);
    setCatalogCheck(null);
    catalogCheckFocus.current = null;
    return () => {
      catalogVisit.current = null;
      visit.latest?.controller.abort();
    };
  }, [catalogScope]);
  const refreshApplicationCatalog = useCallback(
    async (signal?: AbortSignal) => {
      if (!app)
        throw new Error("Select an application before refreshing its context.");
      const requestedScope = catalogScope;
      const visit = catalogVisit.current;
      if (!visit)
        throw new DOMException("Application context changed", "AbortError");
      const assertVisit = () => {
        signal?.throwIfAborted();
        if (
          catalogVisit.current !== visit ||
          activeCatalogScope.current !== requestedScope
        )
          throw new DOMException("Application context changed", "AbortError");
      };
      assertVisit();
      const request = new AbortController();
      const focused = document.activeElement;
      if (focused instanceof HTMLElement && shell.current?.contains(focused))
        catalogCheckFocus.current = {
          element: focused,
          route: catalogCheckRoute.current,
        };
      setCatalogCheck({ scope: requestedScope, request });
      const abort = () => request.abort();
      signal?.addEventListener("abort", abort, { once: true });
      setCatalogError((previous) =>
        previous?.scope === requestedScope && previous.denied ? null : previous,
      );
      const assertRequest = () => {
        request.signal.throwIfAborted();
        assertVisit();
      };
      const scope = {
        workspaceId: app.workspaceId,
        applicationId: app.applicationId,
      };
      const load = async () => {
        try {
          const value = validateApplicationCatalog(
            await readCatalog(scope, request.signal),
          );
          assertRequest();
          setCatalogSnapshot({ scope: requestedScope, value });
          setCatalogError(null);
          return value;
        } catch (reason: unknown) {
          assertRequest();
          if (reason instanceof DOMException && reason.name === "AbortError")
            throw reason;
          const denied = isApplicationAccessDenied(reason);
          if (denied) setCatalogSnapshot(null);
          setCatalogError({
            scope: requestedScope,
            denied,
            message:
              reason instanceof Error
                ? reason.message
                : "CATALOG_REQUEST_FAILED",
          });
          throw reason;
        } finally {
          signal?.removeEventListener("abort", abort);
          setCatalogCheck((current) =>
            current?.request === request ? null : current,
          );
        }
      };
      // Only the latest request can update the catalogue or the tab lifecycle.
      visit.latest?.controller.abort();
      const loaded = { controller: request, result: load() };
      visit.latest = loaded;
      // A reconnect overtaken by another read must wait for that read before
      // reopening the shell. An older response carries no current authority.
      let observed = loaded;
      for (;;) {
        try {
          const value = await observed.result;
          assertVisit();
          if (observed === visit.latest) return value;
        } catch (reason) {
          assertVisit();
          if (observed === visit.latest) throw reason;
        }
        observed = visit.latest;
      }
    },
    [app?.workspaceId, app?.applicationId, catalogScope],
  );
  const currentCatalogRefresh = useRef<typeof refreshApplicationCatalog | null>(
    null,
  );
  currentCatalogRefresh.current = app ? refreshApplicationCatalog : null;
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
  const activeCatalogError =
    catalogError?.scope === catalogScope ? catalogError : null;
  const catalogAccessDenied =
    applicationScopedPage(page) && Boolean(activeCatalogError?.denied);
  const awaitingApplicationCatalog =
    applicationScopedPage(page) && Boolean(app) && !currentCatalog;
  const checkingApplicationCatalog = Boolean(
    applicationScopedPage(page) &&
      currentCatalog &&
      catalogCheck?.scope === catalogScope,
  );
  const catalogRefreshFailed = Boolean(
    applicationScopedPage(page) &&
      currentCatalog &&
      activeCatalogError &&
      !activeCatalogError.denied,
  );
  const blocked =
    Boolean(pendingIdentity) ||
    checkingApplicationCatalog ||
    catalogRefreshFailed ||
    ["expired", "offline", "unavailable", "revalidating"].includes(
      browserLifecycle.state,
    );
  const currentCatalogError =
    catalogAccessDenied || awaitingApplicationCatalog || catalogRefreshFailed
      ? ""
      : activeCatalogError?.message;
  const metadataNavigationScope =
    currentCatalog &&
    applicationPageVisible("metadata", currentCatalog) &&
    Object.hasOwn(currentCatalog.functions, "metadata.dimension.list")
      ? JSON.stringify([
          catalogScope,
          currentCatalog.accessContext,
          currentCatalog.applicationAccess,
          currentCatalog.revisions.security,
          currentCatalog.revisions.policy,
          currentCatalog.revisions.schemaEpoch,
          currentCatalog.revisions.capability,
        ])
      : null;
  const activeMetadataNavigation = useRef(metadataNavigationScope);
  activeMetadataNavigation.current = metadataNavigationScope;
  const [metadataDimensionState, setMetadataDimensionState] = useState<{
    scope: string;
    metadataRevision: number;
    dimensions: MetadataNavigationDimension[];
  } | null>(null);
  const metadataDimensions =
    metadataDimensionState &&
    metadataDimensionState.scope === metadataNavigationScope &&
    metadataDimensionState.metadataRevision >=
      (currentCatalog?.revisions.metadata ?? 0)
      ? metadataDimensionState.dimensions
      : [];
  const onMetadataDimensionsChange = useCallback(
    (
      dimensions: MetadataNavigationDimension[],
      metadataRevision: number | null,
    ) => {
      if (
        !metadataNavigationScope ||
        activeMetadataNavigation.current !== metadataNavigationScope
      )
        return;
      if (metadataRevision === null) {
        setMetadataDimensionState(null);
        return;
      }
      setMetadataDimensionState((previous) =>
        previous?.scope === metadataNavigationScope &&
        previous.metadataRevision > metadataRevision
          ? previous
          : { scope: metadataNavigationScope, metadataRevision, dimensions },
      );
    },
    [metadataNavigationScope],
  );
  useEffect(() => {
    setMetadataDimensionState((current) =>
      current?.scope === metadataNavigationScope ? current : null,
    );
  }, [metadataNavigationScope]);
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
    let pending: AbortController | undefined;
    const revalidate = async (broadcast = true) => {
      pending?.abort();
      const controller = new AbortController();
      pending = controller;
      const { signal } = controller;
      try {
        const session = await readSession(signal);
        signal.throwIfAborted();
        const previous = identityRef.current;
        const sameIdentity =
          sessionIdentityKey(previous) === sessionIdentityKey(session);
        if (!sameIdentity && previous && unsavedWorkSnapshot().length > 0) {
          setPendingIdentity(session);
          return;
        }
        if (sameIdentity) {
          setPendingIdentity(null);
          const requestedScope = activeCatalogScope.current;
          const requestedVisit = catalogVisit.current;
          try {
            await currentCatalogRefresh.current?.(signal);
          } catch (reason: unknown) {
            signal.throwIfAborted();
            const authorizationDenied = isApplicationAccessDenied(reason);
            const changedApplication =
              reason instanceof DOMException &&
              reason.name === "AbortError" &&
              (requestedScope !== activeCatalogScope.current ||
                requestedVisit !== catalogVisit.current);
            if (!authorizationDenied && !changedApplication) {
              if (browserLifecycleSnapshot().state === "revalidating")
                setBrowserLifecycle(
                  "unavailable",
                  "CATALOG_REVALIDATION_FAILED",
                );
              return;
            }
          }
        }
        const [discovered, platform] = await Promise.all([
          listApplications(signal, session.identityBinding),
          readPlatformAccess(signal, session.identityBinding),
        ]);
        signal.throwIfAborted();
        const active = activeApplication.current;
        const activeIndex =
          sameIdentity && active
            ? discovered.findIndex(
                (entry) =>
                  entry.workspaceId === active.workspaceId &&
                  entry.applicationId === active.applicationId,
              )
            : -1;
        if (!sameIdentity) {
          // A returning identity must start from freshly verified projections.
          catalogVisit.current?.latest?.controller.abort();
          setCatalogSnapshot(null);
          setCatalogError(null);
          setAccountOpen(false);
          setSearchOpen(false);
          setNotificationsOpen(false);
        }
        setApplications(discovered);
        setPlatformAccess(platform);
        setSelected((index) =>
          previous || index >= discovered.length
            ? Math.max(0, activeIndex)
            : index,
        );
        identityRef.current = session;
        adoptBrowserIdentity(session);
        setIdentity(session);
        setPendingIdentity(null);
        setBrowserLifecycle("authenticated", undefined, broadcast);
        setError("");
      } catch (reason: unknown) {
        if (
          !signal.aborted &&
          !(reason instanceof DOMException && reason.name === "AbortError")
        ) {
          const lifecycle = browserLifecycleSnapshot().state;
          if (lifecycle === "bootstrapping" || lifecycle === "revalidating")
            setBrowserLifecycle(
              "unavailable",
              "SESSION_CONTEXT_REVALIDATION_FAILED",
            );
          setError(reason instanceof Error ? reason.message : "REQUEST_FAILED");
        }
      } finally {
        if (pending === controller) {
          pending = undefined;
          if (!signal.aborted) setLoading(false);
          controller.abort();
        }
      }
    };
    const uninstall = installConnectivityLifecycle(
      (broadcast) => void revalidate(broadcast),
    );
    const cancelBlockedRefresh = subscribeBrowserLifecycle(({ state }) => {
      if (state === "offline" || state === "expired") pending?.abort();
    });
    void revalidate();
    return () => {
      cancelBlockedRefresh();
      uninstall();
      pending?.abort();
    };
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

  function requestTransition(
    transition: () => void,
    preserveDrafts = false,
    abandonRecovery = false,
  ) {
    if (
      unsavedWorkSnapshot().length === 0 ||
      (preserveDrafts && canPreserveUnsavedWork())
    ) {
      transition();
      return;
    }
    const active = document.activeElement;
    discardTriggerRef.current =
      active instanceof HTMLElement
        ? {
            element: active.closest("#global-search-panel")
              ? (searchButtonRef.current ?? active)
              : active,
            mobileNavigation: mobileNavigationOpenRef.current,
          }
        : null;
    pendingTransition.current = transition;
    pendingAbandonRecovery.current = abandonRecovery;
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
      const trigger = discardTriggerRef.current;
      if (
        trigger?.element.isConnected &&
        document.activeElement === document.body
      ) {
        if (trigger.mobileNavigation && !mobileNavigationOpenRef.current)
          sidebarToggleRef.current?.focus();
        else trigger.element.focus();
      }
      discardTriggerRef.current = null;
    };
  }, [discardPromptOpen]);

  function navigationDestination(target: Page, focus: WorkFocus = {}) {
    return applicationScopedPage(target) && app
      ? {
          ...(target === "grid" &&
          page === "monitor" &&
          currentReferenceContext?.target.kind === "task"
            ? { returnTaskId: currentReferenceContext.target.taskId }
            : {}),
          ...focus,
          ...(target === "security" && !focus.section && currentCatalog
            ? { section: firstSecuritySection(currentCatalog.functions) }
            : {}),
          ...(target === "rules" &&
          !focus.section &&
          !focus.artifactKind &&
          currentCatalog?.applicationAccess.authorizationModel ===
            "group_assignments"
            ? { section: ruleSectionsFor(currentCatalog.functions)[0]?.id }
            : {}),
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

  function navigate(
    target: Page,
    focus: WorkFocus = {},
    focusDestination = false,
  ) {
    const destination = navigationDestination(target, focus);
    if (
      target === page &&
      presentationRouteHash(target, selected, destination) ===
        presentationRouteHash(page, selected, workFocus)
    )
      return;
    const transition = () => {
      if (focusDestination) routeDestinationFocus.current = true;
      setAccountOpen(false);
      routeHistoryIndex.current += 1;
      window.history.pushState(
        { openEpmNavigationIndex: routeHistoryIndex.current },
        "",
        presentationRouteHash(target, selected, destination),
      );
      setWorkFocus(destination);
      setPage(target);
      if (window.matchMedia?.("(max-width: 950px)").matches) collapseSidebar();
    };
    requestTransition(transition, true);
  }

  function navigateMetadata(
    destination: MetadataDestination,
    focusDestination = false,
  ) {
    navigate(
      "metadata",
      {
        metadataSection: destination.section,
        dimensionId: destination.dimensionId,
        memberId: destination.memberId,
        relationshipId: destination.relationshipId,
        hierarchyId: Object.hasOwn(destination, "hierarchyId")
          ? destination.hierarchyId || undefined
          : destination.dimensionId === workFocus.dimensionId
            ? workFocus.hierarchyId
            : undefined,
      },
      focusDestination,
    );
  }

  function signOut() {
    requestTransition(
      () => {
        setAccountOpen(false);
        window.location.assign(browserLogoutPath());
      },
      false,
      true,
    );
  }

  function reloadRelease() {
    requestTransition(() => window.location.reload());
  }

  useEffect(() => {
    const compact = window.matchMedia?.("(max-width: 950px)");
    const mobile = window.matchMedia?.("(max-width: 650px)");
    const adaptCompact = (event: MediaQueryListEvent) => {
      if (event.matches) collapseSidebar();
    };
    const adaptMobile = (event: MediaQueryListEvent) => {
      // Either direction ends the overlay before its Close control disappears.
      collapseSidebar();
      setMobileViewport(event.matches);
    };
    compact?.addEventListener?.("change", adaptCompact);
    mobile?.addEventListener?.("change", adaptMobile);
    return () => {
      compact?.removeEventListener?.("change", adaptCompact);
      mobile?.removeEventListener?.("change", adaptMobile);
    };
  }, [collapseSidebar]);

  useEffect(() => {
    if (!app) return;
    const controller = new AbortController();
    void refreshApplicationCatalog(controller.signal).catch(() => undefined);
    return () => controller.abort();
  }, [refreshApplicationCatalog]);

  const visibleApplicationPages = useMemo(
    () =>
      currentCatalog
        ? applicationPages.filter((item) =>
            applicationPageVisible(item.id, currentCatalog),
          )
        : [],
    [currentCatalog],
  );
  const notificationScope =
    app && currentCatalog
      ? JSON.stringify([
          identityKey,
          outcomeAuthorityKey(app, currentCatalog),
          currentCatalog.revisions.policy,
        ])
      : null;
  const visiblePrimary = useMemo(
    () => primary.filter((item) => item.id !== "server" || platformCatalog),
    [platformCatalog],
  );

  useEffect(() => {
    function shortcuts(event: KeyboardEvent) {
      if (
        blocked ||
        mobileNavigationOpenRef.current ||
        workspaceModalOpen ||
        discardPromptOpen
      )
        return;
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
  }, [blocked, workspaceModalOpen, discardPromptOpen]);

  function chooseApplication(
    index: number,
    destination: Page = "overview",
    focusDestination = false,
  ) {
    const target = applications[index];
    if (!target) return;
    if (
      index === selected &&
      page === destination &&
      app?.workspaceId === target.workspaceId &&
      app?.applicationId === target.applicationId
    )
      return;
    const destinationScope = {
      workspaceId: target.workspaceId,
      applicationId: target.applicationId,
    };
    const transition = () => {
      if (focusDestination) routeDestinationFocus.current = true;
      routeHistoryIndex.current += 1;
      window.history.pushState(
        { openEpmNavigationIndex: routeHistoryIndex.current },
        "",
        presentationRouteHash(destination, index, destinationScope),
      );
      setSelected(index);
      setAccountOpen(false);
      setWorkFocus(destinationScope);
      setPage(destination);
    };
    requestTransition(transition, true);
  }

  async function applicationCreated(
    created: CreatedApplication,
    signal: AbortSignal,
    open: boolean,
  ) {
    const originIdentity = identityKey;
    const apps = await listApplications(signal);
    signal.throwIfAborted();
    if (sessionIdentityKey(identityRef.current) !== originIdentity)
      throw new DOMException("Identity changed", "AbortError");
    if (!open) {
      const previous = apps.findIndex(
        (item) =>
          item.workspaceId === app?.workspaceId &&
          item.applicationId === app?.applicationId,
      );
      setApplications(apps);
      setSelected(Math.max(0, previous));
      return;
    }
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
    const originIdentity = identityKey;
    const apps = await listApplications();
    if (sessionIdentityKey(identityRef.current) !== originIdentity)
      throw new DOMException("Identity changed", "AbortError");
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
      navigate(target as Page, {}, true);
  }

  async function copyViewLink(references = false) {
    if (copyStatusTimer.current) clearTimeout(copyStatusTimer.current);
    setCopyStatus("");
    try {
      if (references && !currentReference) return;
      await navigator.clipboard.writeText(
        references
          ? JSON.stringify(currentReference, null, 2)
          : currentReference
            ? `${window.location.origin}${window.location.pathname}${referenceHandoffHash(currentReference)}`
            : page === "grid"
              ? `${window.location.origin}${window.location.pathname}${presentationRouteHash(
                  "grid",
                  selected,
                  {
                    workspaceId: app?.workspaceId,
                    applicationId: app?.applicationId,
                  },
                )}`
              : shareableViewUrl(window.location),
      );
      setCopyStatus(
        references
          ? "References copied. Open them with your own authorized client."
          : page === "grid" && !currentReference
            ? "Page link copied. Unsaved or unresolved grid context is not included."
            : "Link copied",
      );
    } catch {
      setCopyStatus("Unable to copy link");
    }
    copyStatusTimer.current = setTimeout(() => {
      setCopyStatus("");
      copyStatusTimer.current = null;
    }, 2500);
  }

  function openReference(handoff: ReferenceHandoff) {
    const destination = referenceDestination(handoff);
    navigate(
      destination.page,
      { ...handoff.scope, ...destination.focus, referenceHandoff: handoff },
      true,
    );
  }

  useEffect(
    () => () => {
      if (copyStatusTimer.current) clearTimeout(copyStatusTimer.current);
    },
    [],
  );

  const mainContent = useRef<HTMLElement>(null);
  useLayoutEffect(() => {
    if (
      !routeDestinationFocus.current ||
      blocked ||
      workspaceModalOpen ||
      discardPromptOpen
    )
      return;
    routeDestinationFocus.current = false;
    mainContent.current?.focus({ preventScroll: true });
  }, [
    blocked,
    workspaceModalOpen,
    discardPromptOpen,
    page,
    selected,
    workFocus,
  ]);
  useLayoutEffect(() => {
    if (catalogCheck || blocked) return;
    const focused = catalogCheckFocus.current;
    catalogCheckFocus.current = null;
    if (
      focused?.route === referenceRoute &&
      document.activeElement === document.body
    ) {
      const element = focused.element;
      if (element.isConnected && !element.closest("[inert]"))
        element.focus({ preventScroll: true });
      if (document.activeElement === document.body)
        mainContent.current?.focus({ preventScroll: true });
    }
  }, [blocked, catalogCheck, referenceRoute]);
  const monitorFocus = useRef<{
    element: HTMLElement;
    route: string;
    scope: string;
  } | null>(null);
  useLayoutEffect(() => {
    const previous = monitorFocus.current;
    if (!previous || previous.scope === referenceScope || blocked) return;
    monitorFocus.current = null;
    if (
      previous.route === referenceRoute &&
      !previous.element.isConnected &&
      document.activeElement === document.body &&
      !mobileNavigationOpen
    )
      mainContent.current?.focus({ preventScroll: true });
  }, [blocked, mobileNavigationOpen, referenceRoute, referenceScope]);
  const retry = () => window.dispatchEvent(new Event("online"));
  const applicationContextUnavailable = {
    kind: "unavailable" as const,
    title: "Application context unavailable",
    description:
      "Open EPM could not confirm current access to this application. Your drafts stay in this tab while the workspace is paused.",
    action: "Retry context check",
    perform: () => {
      routeDestinationFocus.current = true;
      retry();
    },
  };
  const blockedPresentation = pendingIdentity
    ? {
        kind: "identity" as const,
        title: "Identity changed",
        description:
          "This tab was opened by another identity. Its drafts and local recovery records cannot be transferred to the newly authenticated user. Unconfirmed requests may already have completed; clearing local recovery does not cancel them.",
        action: "Discard drafts and continue",
        perform: () => {
          discardUnsavedWork({ abandonRecovery: true });
          setPendingIdentity(null);
          retry();
        },
      }
    : browserLifecycle.state === "expired"
      ? {
          kind: "expired" as const,
          title:
            browserLifecycle.reason === "IDENTITY_INACTIVE" ||
            browserLifecycle.reason === "IDENTITY_SESSION_REVOKED"
              ? "Your sign-in is no longer valid"
              : "Your session has timed out",
          description:
            unsavedWork.length > 0
              ? "Your drafts and local recovery records are still held in this tab. Signing in again will discard them. Unconfirmed requests may already have completed; clearing local recovery does not cancel them."
              : "For your security, this page is no longer active. Sign in again to continue.",
          action:
            unsavedWork.length > 0
              ? "Discard drafts and sign in"
              : "Sign in again",
          perform: () => {
            discardUnsavedWork({ abandonRecovery: true });
            window.location.assign(browserLogoutPath());
          },
        }
      : browserLifecycle.state === "offline"
        ? {
            kind: "offline" as const,
            title: "You are offline",
            description:
              "Open EPM has stopped sending requests. Drafts remain in this tab. Unconfirmed operations may have completed; reconnect and reconcile their original status before submitting more work.",
            action: "Retry connection",
            perform: retry,
          }
        : browserLifecycle.state === "unavailable"
          ? (catalogRefreshFailed &&
              browserLifecycle.reason !== "BROWSER_IDENTITY_CHANGED") ||
            browserLifecycle.reason === "CATALOG_REVALIDATION_FAILED"
            ? applicationContextUnavailable
            : {
                kind: "unavailable" as const,
                title:
                  browserLifecycle.reason === "BROWSER_IDENTITY_CHANGED"
                    ? "Check the signed-in account"
                    : "Open EPM is temporarily unavailable",
                description:
                  browserLifecycle.reason === "BROWSER_IDENTITY_CHANGED"
                    ? "The signed-in account changed while this tab was open. Drafts remain with their original account while Open EPM checks the current session."
                    : "The service did not confirm your session. Drafts remain in this tab while Open EPM blocks stale interaction.",
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
            : checkingApplicationCatalog
              ? {
                  kind: "revalidating" as const,
                  title: "Checking the application context…",
                  description:
                    "Open EPM is confirming your current application access. Your drafts stay in this tab while the workspace is paused.",
                }
              : catalogRefreshFailed
                ? applicationContextUnavailable
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
        <BrowserStateScreen
          {...blockedPresentation}
          pending={pendingIdentity ? [] : unsavedWork}
        />
      )}
      <div
        ref={shell}
        className={collapsed ? "shell collapsed" : "shell"}
        inert={blocked || undefined}
        aria-hidden={blocked || undefined}
      >
        <a
          className="skip-link"
          href="#main-content"
          inert={mobileNavigationOpen || workspaceModalOpen || undefined}
        >
          Skip to main content
        </a>
        {mobileNavigationOpen && (
          <div className="sidebar-scrim" aria-hidden="true" />
        )}
        <aside
          className="sidebar"
          id="primary-navigation"
          role={
            mobileNavigationOpen && !discardPromptOpen ? "dialog" : undefined
          }
          aria-modal={
            mobileNavigationOpen && !discardPromptOpen ? true : undefined
          }
          aria-label={
            mobileNavigationOpen && !discardPromptOpen
              ? "Application navigation"
              : undefined
          }
          inert={
            workspaceModalOpen ||
            (mobileNavigationOpen && discardPromptOpen) ||
            undefined
          }
          onKeyDown={(event) => {
            if (!mobileNavigationOpen || discardPromptOpen) return;
            if (event.key === "Escape") {
              event.preventDefault();
              event.stopPropagation();
              collapseSidebar();
              return;
            }
            if (event.key !== "Tab") return;
            const controls = Array.from(
              event.currentTarget.querySelectorAll<HTMLElement>(
                "button:not([disabled]), [href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])",
              ),
            ).filter(
              (control) =>
                !control.closest("[hidden], [inert]") &&
                getComputedStyle(control).display !== "none" &&
                getComputedStyle(control).visibility !== "hidden",
            );
            const first = controls[0],
              last = controls.at(-1);
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
          {!collapsed && (
            <button
              className="sidebar-close"
              ref={sidebarCloseRef}
              type="button"
              aria-label="Close sidebar"
              onClick={collapseSidebar}
            >
              Close <span aria-hidden="true">×</span>
            </button>
          )}
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
            <span
              className="application-switcher-compact-label"
              aria-hidden="true"
            >
              Choose application
            </span>
          </button>
          {visibleApplicationPages.length > 0 && (
            <nav
              aria-label="Application navigation"
              className="application-nav"
            >
              {navigationGroups.map((group) => {
                const destinations = visibleApplicationPages.filter((item) =>
                  group.pages.includes(item.id),
                );
                if (!destinations.length) return null;
                return (
                  <section
                    className="navigation-group"
                    key={group.label}
                    aria-label={group.label}
                  >
                    <div className="nav-group-label">{group.label}</div>
                    {destinations.map((item) =>
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
                );
              })}
            </nav>
          )}
          <div className="sidebar-foot">
            <span className="agent-dot" />{" "}
            <span>
              <b>Open EPM</b>
              <small>Programmable multidimensional platform</small>
            </span>
          </div>
        </aside>

        <header
          className="topbar"
          inert={mobileNavigationOpen || workspaceModalOpen || undefined}
        >
          <button
            className="menu-button"
            ref={sidebarToggleRef}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-controls="primary-navigation"
            aria-expanded={!collapsed}
            onClick={() => {
              if (!collapsed) {
                collapseSidebar();
                return;
              }
              if (mobileViewport) {
                setSearchOpen(false);
                setNotificationsOpen(false);
                setAccountOpen(false);
                setHelpOpen(false);
                sidebarOpeningFocus.current = true;
              }
              setCollapsed(false);
            }}
          >
            <span aria-hidden="true">☰</span>
            <span className="sidebar-toggle-label" aria-hidden="true">
              Menu
            </span>
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
              ref={searchButtonRef}
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
            {notificationScope && (
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
            )}
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
          {notificationScope && (
            <Notifications
              key={notificationScope}
              open={notificationsOpen}
              close={() => setNotificationsOpen(false)}
              app={app}
              goMonitor={() => navigate("monitor")}
            />
          )}
        </header>

        <GlobalSearch
          key={`search:${identityKey}`}
          open={searchOpen}
          close={() => setSearchOpen(false)}
          applications={applications}
          selectedApplication={app}
          targets={[...visiblePrimary, ...visibleApplicationPages]}
          catalog={currentCatalog}
          go={go}
          chooseApplication={(index) =>
            chooseApplication(index, "overview", true)
          }
        />
        <HelpPanel open={helpOpen} close={() => setHelpOpen(false)} />

        <main
          data-page={page}
          inert={mobileNavigationOpen || workspaceModalOpen || undefined}
          id="main-content"
          tabIndex={-1}
          key={identityKey}
          ref={mainContent}
          onFocusCapture={(event) => {
            const element = event.target;
            monitorFocus.current =
              page === "monitor" &&
              element instanceof HTMLElement &&
              element.closest(".monitor-page, .workflow-return")
                ? { element, route: referenceRoute, scope: referenceScope }
                : null;
          }}
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
          {currentReference && (
            <section className="workflow-return" aria-label="Client handoff">
              <span>
                Share saved references. The receiving client checks its own
                access and current state.
              </span>
              <button type="button" onClick={() => void copyViewLink(true)}>
                Copy client references
              </button>
              {page === "monitor" &&
                currentReference.target.kind === "task" && (
                  <button
                    type="button"
                    onClick={() => navigate("grid", {}, true)}
                  >
                    Open Grid from this task
                  </button>
                )}
            </section>
          )}
          {app && currentReferenceContext && !currentReference && (
            <p role="alert">
              This route contains an unsupported reference. Open a fresh view
              before sharing client references.
            </p>
          )}
          {page !== "monitor" &&
            workFocus.returnTaskId &&
            !workFocus.referenceHandoff && (
              <section
                className="workflow-return"
                aria-label="Return to originating work"
              >
                <span>
                  Return rereads the originating task without accepting or
                  completing it.
                </span>
                <button
                  type="button"
                  disabled={loading || !app || !currentCatalog}
                  onClick={() =>
                    navigate(
                      "monitor",
                      {
                        workspaceId: workFocus.workspaceId || app?.workspaceId,
                        applicationId:
                          workFocus.applicationId || app?.applicationId,
                        taskId: workFocus.returnTaskId,
                      },
                      true,
                    )
                  }
                >
                  Return to task
                </button>
              </section>
            )}
          {workFocus.referenceHandoff?.returnTo && (
            <section
              className="workflow-return"
              aria-label="Return to originating work"
            >
              <span>
                Return rereads the originating work. It does not accept or
                complete it.
              </span>
              <button
                type="button"
                disabled={loading || !app || !currentCatalog}
                onClick={() =>
                  openReference(
                    retargetReferenceHandoff(
                      workFocus.referenceHandoff!,
                      workFocus.referenceHandoff!.returnTo!,
                    ),
                  )
                }
              >
                {workFocus.referenceHandoff.returnTo.kind === "task"
                  ? "Return to task"
                  : "Return to workflow"}
              </button>
            </section>
          )}
          {workFocus.referenceHandoff?.pendingOperation && (
            <section
              className="workflow-return"
              aria-label="Referenced operation"
            >
              <span>
                A referenced operation must be inspected before considering
                another submission.
              </span>
              <button
                type="button"
                disabled={loading || !app || !currentCatalog}
                onClick={() =>
                  openReference(
                    retargetReferenceHandoff(
                      workFocus.referenceHandoff!,
                      workFocus.referenceHandoff!.pendingOperation!,
                    ),
                  )
                }
              >
                Inspect referenced operation
              </button>
            </section>
          )}
          {page !== "flows" &&
            workFocus.occurrenceId &&
            !workFocus.referenceHandoff && (
              <section className="workflow-return" role="status">
                <span>Working from an assigned workflow activity</span>
                <button
                  type="button"
                  disabled={loading || !app || !currentCatalog}
                  onClick={() =>
                    navigate(
                      "flows",
                      {
                        workspaceId: workFocus.workspaceId || app?.workspaceId,
                        applicationId:
                          workFocus.applicationId || app?.applicationId,
                        occurrenceId: workFocus.occurrenceId,
                        activityId: workFocus.activityId,
                      },
                      true,
                    )
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
          ) : identity ? (
            <Suspense
              fallback={<div className="empty-state">Loading workspace…</div>}
            >
              {workFocus.handoffError ? (
                <section className="page" role="alert">
                  <h1>Reference unavailable</h1>
                  <p>{workFocus.handoffError}</p>
                  <button
                    type="button"
                    onClick={() => navigate("applications")}
                  >
                    Choose application
                  </button>
                </section>
              ) : catalogAccessDenied ||
                (usesApplicationContext && explicitApplication && !app) ? (
                <section className="page" role="alert">
                  <h1>Application unavailable</h1>
                  <p>
                    {catalogAccessDenied
                      ? activeCatalogError?.message
                      : "The linked application is unavailable under your current access."}
                  </p>
                  <div className="actions">
                    <button
                      type="button"
                      className="primary"
                      onClick={() => {
                        if (app) {
                          mainContent.current?.focus({ preventScroll: true });
                          void refreshApplicationCatalog().catch(
                            () => undefined,
                          );
                        } else {
                          routeDestinationFocus.current = true;
                          retry();
                        }
                      }}
                    >
                      Recheck application access
                    </button>
                    <button
                      type="button"
                      onClick={() => navigate("applications")}
                    >
                      Choose application
                    </button>
                  </div>
                </section>
              ) : awaitingApplicationCatalog ? (
                activeCatalogError ? (
                  <section className="page" role="alert">
                    <h1>Application context unavailable</h1>
                    <p>
                      Open EPM could not confirm this application's current
                      context.
                    </p>
                    <p>{activeCatalogError.message}</p>
                    <button
                      type="button"
                      className="primary"
                      onClick={() => {
                        setCatalogError(null);
                        void refreshApplicationCatalog().catch(() => undefined);
                      }}
                    >
                      Retry context check
                    </button>
                  </section>
                ) : (
                  <Loading message="Checking the application context…" />
                )
              ) : workspaceUnavailable ? (
                <section className="page" role="status">
                  <h1>{pageTitle(page)} unavailable</h1>
                  <p>
                    This workspace is unavailable in the current application
                    context.
                  </p>
                  <button type="button" onClick={() => navigate("overview")}>
                    Open application overview
                  </button>
                </section>
              ) : page === "home" ? (
                <Home
                  app={app}
                  identity={identity}
                  availablePages={visibleApplicationPages}
                  serverAvailable={Boolean(platformCatalog)}
                  go={navigate}
                />
              ) : page === "applications" ? (
                <Applications
                  key={`${identityKey}:${managedWorkspaceOnly ? workFocus.workspaceId : app?.workspaceId || "none"}`}
                  applications={applications}
                  selected={selectedApplicationIndex}
                  catalog={currentCatalog}
                  issuer={identity?.issuer || ""}
                  subject={identity?.subject || ""}
                  choose={(index) => chooseApplication(index, "overview", true)}
                  managedWorkspaceId={
                    managedWorkspaceOnly ? workFocus.workspaceId : undefined
                  }
                  selectManagedWorkspace={(workspaceId) =>
                    navigate("applications", { workspaceId })
                  }
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
                  catalogueUnavailable={Boolean(activeCatalogError)}
                  open={(target, focus) => navigate(target, focus, true)}
                />
              ) : page === "server" ? (
                platformCatalog ? (
                  <ServerAdministration
                    key={`${identityKey}:${workFocus.section || "users"}`}
                    functions={platformCatalog.functions}
                    section={workFocus.section}
                    onNavigateSection={(section) =>
                      navigate("server", { section })
                    }
                    onRequestTransition={requestTransition}
                  />
                ) : (
                  <section className="page" role="alert">
                    <h1>Server administration unavailable</h1>
                    <p>
                      {platformAccess?.state === "denied"
                        ? "Your current account does not have server administration access."
                        : "Open EPM could not confirm server administration access."}
                    </p>
                    {platformAccess?.state !== "denied" && (
                      <button type="button" className="primary" onClick={retry}>
                        Retry access check
                      </button>
                    )}
                    <button type="button" onClick={() => navigate("home")}>
                      Go to Home
                    </button>
                  </section>
                )
              ) : page === "overview" ? (
                <Overview
                  app={app}
                  catalog={currentCatalog}
                  catalogueUnavailable={Boolean(activeCatalogError)}
                  go={navigate}
                  onRequestTransition={requestTransition}
                />
              ) : page === "grid" ? (
                <Analyze
                  key={`${identityKey}:${applicationKey}`}
                  interactionBlocked={blocked}
                  app={app}
                  catalog={currentCatalog}
                  index={selected}
                  subject={identity?.subject || ""}
                  onRequestTransition={requestTransition}
                  targetViewId={workFocus.viewId}
                  targetViewDigest={workFocus.viewDigest}
                  targetAnalyticalRead={
                    workFocus.referenceHandoff?.analyticalRead
                  }
                  onViewContextChange={onViewContextChange}
                  onRefreshCatalog={refreshApplicationCatalog}
                />
              ) : page === "flows" ? (
                <GenericWorkflow
                  key={`${identityKey}:${applicationKey}`}
                  app={app}
                  catalog={currentCatalog}
                  catalogueUnavailable={Boolean(activeCatalogError)}
                  onRefreshCatalog={refreshApplicationCatalog}
                  onRequestTransition={requestTransition}
                  targetOccurrenceId={workFocus.occurrenceId}
                  targetActivityId={workFocus.activityId}
                  openMyWork={() => go("work")}
                  openOccurrence={(occurrenceId) =>
                    navigate("flows", { occurrenceId }, true)
                  }
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
                    if (workFocus.referenceHandoff) {
                      const incoming = workFocus.referenceHandoff;
                      const origin = common.occurrenceId
                        ? {
                            kind: "workflowActivity" as const,
                            occurrenceId: common.occurrenceId,
                            ...(common.activityId
                              ? { activityId: common.activityId }
                              : {}),
                          }
                        : incoming.target;
                      const targetContext =
                        resolution.page === "grid"
                          ? {
                              target: {
                                kind: "savedView",
                                viewId: resolution.focus.viewId,
                              },
                              observed: {
                                viewDigest: resolution.focus.viewDigest,
                              },
                              analyticalRead: { semantics: "stored" },
                            }
                          : {
                              target: {
                                kind: "definition",
                                artifactKind: resolution.focus.artifactKind,
                                artifactId: resolution.focus.artifactId,
                              },
                              observed: {
                                stateToken: resolution.focus.artifactStateToken,
                                definitionDigest:
                                  resolution.focus.artifactDigest,
                              },
                            };
                      openReference(
                        parseReferenceHandoff({
                          format: incoming.format,
                          scope: incoming.scope,
                          origin,
                          returnTo:
                            incoming.returnTo ||
                            (origin.kind === "workflowActivity"
                              ? origin
                              : null),
                          pendingOperation: incoming.pendingOperation,
                          ...targetContext,
                        }),
                      );
                      return null;
                    }
                    navigate(
                      resolution.page,
                      { ...common, ...resolution.focus },
                      true,
                    );
                    return null;
                  }}
                />
              ) : page === "tasks" ? (
                <MyWork
                  key={applicationKey}
                  app={app}
                  catalog={currentCatalog}
                  catalogueUnavailable={Boolean(activeCatalogError)}
                  open={(target, focus) => navigate(target, focus, true)}
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
                    relationshipId={workFocus.relationshipId}
                    onNavigate={(destination) =>
                      navigateMetadata(
                        destination,
                        destination.section !==
                          (workFocus.metadataSection || "dimensions"),
                      )
                    }
                    hrefForDestination={(destination) =>
                      navigationHref("metadata", {
                        metadataSection: destination.section,
                        dimensionId: destination.dimensionId,
                        memberId: destination.memberId,
                        relationshipId: destination.relationshipId,
                        hierarchyId: Object.hasOwn(destination, "hierarchyId")
                          ? destination.hierarchyId || undefined
                          : destination.dimensionId === workFocus.dimensionId
                            ? workFocus.hierarchyId
                            : undefined,
                      })
                    }
                    onDimensionsChange={onMetadataDimensionsChange}
                    onRequestTransition={requestTransition}
                    onRefreshCatalog={refreshApplicationCatalog}
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
                  canReadDirectoryGroups={Boolean(
                    platformCatalog?.functions["identity.group.list"],
                  )}
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
                    navigate(
                      page,
                      {
                        ...workFocus,
                        section,
                        // Deliberate section navigation leaves the exact incoming
                        // target. Keeping its envelope would serialize the old
                        // URL and make this transition a no-op. Preserve only its
                        // explicit return destination in the ordinary route.
                        referenceHandoff: undefined,
                        returnTaskId:
                          workFocus.referenceHandoff?.returnTo?.kind === "task"
                            ? workFocus.referenceHandoff.returnTo.taskId
                            : workFocus.returnTaskId,
                        occurrenceId:
                          workFocus.referenceHandoff?.returnTo?.kind ===
                          "workflowActivity"
                            ? workFocus.referenceHandoff.returnTo.occurrenceId
                            : workFocus.occurrenceId,
                        activityId:
                          workFocus.referenceHandoff?.returnTo?.kind ===
                          "workflowActivity"
                            ? workFocus.referenceHandoff.returnTo.activityId
                            : workFocus.activityId,
                        artifactKind: undefined,
                        artifactId: undefined,
                        artifactVersion: undefined,
                        artifactStateToken: undefined,
                        artifactDigest: undefined,
                      },
                      true,
                    )
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
                  key={referenceScope}
                  app={app}
                  catalog={currentCatalog}
                  onRefreshCatalog={refreshApplicationCatalog}
                  onRequestTransition={requestTransition}
                  targetTaskId={workFocus.taskId}
                  onTaskContextChange={onTaskContextChange}
                  onCloseTask={
                    workFocus.referenceHandoff?.returnTo
                      ? () =>
                          openReference(
                            retargetReferenceHandoff(
                              workFocus.referenceHandoff!,
                              workFocus.referenceHandoff!.returnTo!,
                            ),
                          )
                      : undefined
                  }
                />
              ) : null}
            </Suspense>
          ) : null}
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
                Unsaved edits will be discarded. Unconfirmed requests may
                already have completed; discarding local work does not cancel
                them. Recovery records remain available during navigation in
                this tab, but signing out or reloading clears them.
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
                    discardUnsavedWork({
                      abandonRecovery: pendingAbandonRecovery.current,
                    });
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

function Loading({
  message = "Loading your workspace…",
}: {
  message?: string;
}) {
  return (
    <div className="loading" role="status">
      <span />
      <p>{message}</p>
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
          <dd>
            {catalog ? applicationRoleLabel(catalog) : "Select an application"}
          </dd>
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
  availablePages,
  serverAvailable,
  go,
}: {
  app?: ApplicationSummary;
  identity: SessionIdentity | null;
  availablePages: readonly { id: Page }[];
  serverAvailable: boolean;
  go: (page: Page) => void;
}) {
  const first = (identity?.displayIdentity || "there").split(/[@. ]/)[0];
  const destinations: { page: Page; title: string; text: string }[] = [
    {
      page: "grid",
      title: "Explore data",
      text: "Open Grid to browse saved views and inspect values.",
    },
    {
      page: "data",
      title: "Data tools",
      text: "Find import, export and supporting detail tools available to you.",
    },
    {
      page: "metadata",
      title: "Shape your model",
      text: "Maintain dimensions, members and relationships.",
    },
    {
      page: "rules",
      title: "Build calculations",
      text: "Create reusable rules with ordered steps, and schedule them.",
    },
    {
      page: "flows",
      title: "Follow a workflow",
      text: "Open Flows to see activities, assignments and evidence.",
    },
    {
      page: "monitor",
      title: "Inspect activity",
      text: "Track running work, results and anything needing attention.",
    },
  ];
  const visibleDestinations = destinations.filter((destination) =>
    availablePages.some((item) => destination.page === item.id),
  );
  return (
    <div className="page home-page">
      <PageHeading
        eyebrow="YOUR WORKSPACE"
        title={`Welcome back, ${first}`}
        description="A clear place to work with your models, data and decisions."
      />
      <section className="hero-card">
        <div>
          {app && <span className="pill">CURRENT APPLICATION</span>}
          <h2>{app?.name || "No applications available"}</h2>
          <p>
            {app
              ? `${app.workspaceName || app.workspaceId} · ${app.applicationId}`
              : "Applications appear here when your account has access."}
          </p>
        </div>
        <button
          className="primary"
          onClick={() =>
            go(app ? "overview" : serverAvailable ? "server" : "applications")
          }
        >
          {app
            ? "Open application"
            : serverAvailable
              ? "Open Server Administration"
              : "View applications"}
          <UiIcon name="arrow" />
        </button>
      </section>
      {visibleDestinations.length > 0 && (
        <>
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
            {visibleDestinations.map((item) => (
              <Action
                key={item.page}
                title={item.title}
                text={item.text}
                icon={item.page}
                onClick={() => go(item.page)}
              />
            ))}
          </div>
          <div className="home-orientation">
            <UiIcon name="metadata" />
            <div>
              <strong>One model. Connected workspaces.</strong>
              <p>
                Metadata defines your structure. The grid and data tools work
                with its values. Rules and workflows bring that work together.
              </p>
            </div>
          </div>
        </>
      )}
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

type OverviewActivity = {
  tasksHaveMore: boolean;
  inspectedTasks: number;
  running: number;
  attention: number;
  recentTasks: Array<TaskListRow & { initiatorKind?: string }>;
};

type OverviewScope = {
  workspaceId: string;
  applicationId: string;
  catalog: ApplicationCatalog;
};
type OverviewRead<T> =
  | { scope: OverviewScope; value: T; error?: undefined }
  | { scope: OverviewScope; value?: undefined; error: string };

export function Overview({
  app,
  catalog,
  catalogueUnavailable = false,
  go,
  onRequestTransition = (action) => action(),
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  catalogueUnavailable?: boolean;
  go: (page: Page) => void;
  onRequestTransition?: (action: () => void) => void;
}) {
  const workspaceId = app?.workspaceId;
  const applicationId = app?.applicationId;
  const context = useMemo(
    () =>
      workspaceId && applicationId && catalog
        ? { workspaceId, applicationId, catalog }
        : null,
    [workspaceId, applicationId, catalog],
  );
  const [workRead, setWorkRead] = useState<OverviewRead<{
    count: number;
    hasMore: boolean;
  }> | null>(null);
  const [activityRead, setActivityRead] =
    useState<OverviewRead<OverviewActivity> | null>(null);
  const currentWork = workRead?.scope === context ? workRead : null;
  const currentActivity = activityRead?.scope === context ? activityRead : null;
  const work = currentWork?.value;
  const activity = currentActivity?.value;
  const canReadWork = Boolean(
    catalog?.functions["application.workflow.worklist"],
  );
  const canInspectActivity =
    catalog?.applicationAccess.authorizationModel !== "group_assignments" &&
    applicationPageVisible("monitor", catalog);
  const canOpenGrid = applicationPageVisible("grid", catalog);

  useEffect(() => {
    if (!context) return;
    const controller = new AbortController();
    const { signal } = controller;
    const scope = {
      workspaceId: context.workspaceId,
      applicationId: context.applicationId,
    };
    if (canReadWork)
      void readProgram<{ items: unknown[]; nextCursor?: unknown }>(
        scope,
        "application.workflow.worklist",
        { limit: 100 },
        signal,
      )
        .then((flow) => {
          if (!Array.isArray(flow.items))
            throw new Error("Workflow worklist rows are invalid.");
          if (!signal.aborted)
            setWorkRead({
              scope: context,
              value: {
                count: flow.items.length,
                hasMore: Boolean(flow.nextCursor),
              },
            });
        })
        .catch((reason: Error) => {
          if (!signal.aborted)
            setWorkRead({ scope: context, error: reason.message });
        });

    if (canInspectActivity)
      void request<TaskListPage<OverviewActivity["recentTasks"][number]>>(
        "/api/tasks",
        taskListBody(scope),
        signal,
      )
        .then((response) => {
          if (signal.aborted) return;
          const page = mergeTaskListPage([], response, 0, false);
          setActivityRead({
            scope: context,
            value: {
              tasksHaveMore: page.hasMore,
              inspectedTasks: page.tasks.length,
              running: page.tasks.filter(
                (item) => item.progressState === "inProgress",
              ).length,
              attention: page.tasks.filter(
                (item) => item.progressState === "attention",
              ).length,
              recentTasks: page.tasks.slice(0, 4),
            },
          });
        })
        .catch((reason: Error) => {
          if (!signal.aborted)
            setActivityRead({ scope: context, error: reason.message });
        });
    return () => controller.abort();
  }, [context, canReadWork, canInspectActivity]);

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
        {canOpenGrid && (
          <button className="primary" onClick={() => go("grid")}>
            Open Grid →
          </button>
        )}
        {!canOpenGrid && applicationPageVisible("security", catalog) && (
          <button className="primary" onClick={() => go("security")}>
            Review application access
          </button>
        )}
      </PageHeading>
      <div className="metric-grid">
        <Metric
          value={work ? `${work.count}${work.hasMore ? "+" : ""}` : "—"}
          label="Ready for you"
        />
        {canInspectActivity && (
          <Metric
            value={activity ? String(activity.running) : "—"}
            label="In progress"
          />
        )}
        {canInspectActivity && (
          <Metric
            value={activity ? String(activity.attention) : "—"}
            label="Needs attention"
          />
        )}
      </div>
      {!work ? (
        <p className="data-scope-note" role="status">
          {!catalog
            ? catalogueUnavailable
              ? "Access to assigned work could not be confirmed."
              : "Checking access to assigned work…"
            : !canReadWork
              ? "The current application catalogue does not include assigned work."
              : currentWork?.error !== undefined
                ? "Assigned work could not be loaded."
                : "Loading assigned work…"}
        </p>
      ) : (
        work.hasMore && (
          <p className="data-scope-note">
            Ready for you shows + because more assigned work is available.
          </p>
        )
      )}
      {activity && (
        <p className="data-scope-note">
          {`In progress and Needs attention count matches in ${activity.inspectedTasks} inspected tasks.`}
          {activity.tasksHaveMore
            ? " More tasks are available. Their progress and attention counts are unknown."
            : " No further tasks were reported by this read."}
        </p>
      )}
      {(currentWork?.error || currentActivity?.error) && (
        <div className="alert" role="alert">
          {currentWork?.error && <p>{currentWork.error}</p>}
          {currentActivity?.error && <p>{currentActivity.error}</p>}
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
            {canOpenGrid && (
              <Action
                title="Open cube grid"
                text="Open a saved view or explore the data available to you."
                icon="grid"
                onClick={() => go("grid")}
              />
            )}
            {applicationPageVisible("rules", catalog) && (
              <Action
                title="Build generic rules"
                text="Build calculations as rules with ordered steps. Set a schedule for recurring work."
                icon="rules"
                onClick={() => go("rules")}
              />
            )}
            {applicationPageVisible("flows", catalog) && (
              <Action
                title="Review flows"
                text="Assignments, review steps and governed evidence."
                icon="flows"
                onClick={() => go("flows")}
              />
            )}
          </div>
        </section>
        <section className="panel overview-activity">
          {canInspectActivity && (
            <div className="section-title">
              <div>
                <h2>Recent governed activity</h2>
                <p>Human and agent work from the durable task record.</p>
              </div>
              <button onClick={() => go("monitor")}>Open Monitor</button>
            </div>
          )}
          {canInspectActivity &&
            (activity?.recentTasks.length ? (
              <div className="overview-task-list">
                {activity.recentTasks.map((task) => (
                  <article key={task.taskId}>
                    <span className="status-pill">{task.status}</span>
                    <strong>{task.function}</strong>
                    <small>{task.initiatorKind || "Verified user"}</small>
                  </article>
                ))}
              </div>
            ) : (
              <div className="empty-state">
                {currentActivity?.error !== undefined ||
                (!catalog && catalogueUnavailable)
                  ? "Activity could not be loaded. Open Monitor to retry."
                  : activity
                    ? "No recent activity is visible."
                    : catalog
                      ? "Loading recent activity…"
                      : "Checking access to recent activity…"}
              </div>
            ))}
          <details className="model-details">
            <summary>Application details</summary>
            <dl>
              <div>
                <dt>Application</dt>
                <dd>{app.name}</dd>
              </div>
              <div>
                <dt>Your role</dt>
                <dd>{catalog ? applicationRoleLabel(catalog) : "—"}</dd>
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
