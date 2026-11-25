import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, readPlatformProgram, writePlatformProgram } from "./api";
import { collectAllContinuations } from "./continuation";
import {
  usePreservedDraft,
  useUnsavedWork,
  type DraftRecoveryLease,
} from "./unsaved-work";
import {
  readDirectoryGroups,
  readOffsetDirectory,
  type DirectoryGroup,
} from "./security-directory";

type DirectoryUser = {
  subjectId: string;
  username: string;
  displayName: string;
  shortDescription: string;
  semanticDescription: string;
  status: "Active" | "Inactive";
};

type Membership = {
  subjectId: string;
  groupId: string;
  directoryRevision: number;
};

type MembershipPage = {
  items: Membership[];
  nextAfter: { groupId: string; subjectId: string } | null;
};

type DirectoryRecords = {
  users: DirectoryUser[];
  groups: DirectoryGroup[];
  memberships: Membership[];
};
type DirectoryLoad =
  | { status: "loading" }
  | { status: "ready"; records: DirectoryRecords }
  | { status: "unavailable"; message: string };

const emptyDirectory: DirectoryRecords = {
  users: [],
  groups: [],
  memberships: [],
};
const directoryPageSize = 100;
const passwordFunction = "identity.native-user.password.set";
const receiptFunction = "platform.operation.receipt.read";

type PlatformReceipt = {
  operationId: string;
  status: "Pending" | "Committed" | "Unavailable";
  function: string | null;
  committedAt: string | null;
};

type DirectoryChangeFunction =
  | "identity.native-user.create"
  | "identity.native-user.update"
  | "identity.native-user.status.set"
  | "identity.group.create"
  | "identity.group.update"
  | "identity.group.status.set"
  | "identity.group.membership.set";

type DirectoryChange = {
  operationId: string;
  functionName: DirectoryChangeFunction;
  args: Record<string, string>;
  message: string;
};

function receiptStatus(
  receipt: PlatformReceipt,
  operationId: string,
  functionName: string,
) {
  if (receipt?.operationId !== operationId) return null;
  if (
    receipt.status === "Unavailable" &&
    receipt.function === null &&
    receipt.committedAt === null
  )
    return "Unavailable";
  if (receipt.function !== functionName) return null;
  if (
    receipt.status === "Committed" &&
    typeof receipt.committedAt === "string" &&
    Number.isFinite(Date.parse(receipt.committedAt))
  )
    return "Committed";
  return receipt.status === "Pending" && receipt.committedAt === null
    ? "Pending"
    : null;
}

function passwordAssignedMessage(user: DirectoryUser) {
  return `Assigned a temporary password to ${user.displayName}. The user must change it at first sign-in.`;
}

function validDirectoryRecord(row: DirectoryUser, name: unknown) {
  return (
    typeof name === "string" &&
    name.length > 0 &&
    typeof row.displayName === "string" &&
    typeof row.shortDescription === "string" &&
    typeof row.semanticDescription === "string" &&
    (row.status === "Active" || row.status === "Inactive")
  );
}

function membershipKey(row?: { groupId: string; subjectId: string }) {
  return typeof row?.groupId === "string" &&
    row.groupId &&
    typeof row.subjectId === "string" &&
    row.subjectId
    ? JSON.stringify([row.groupId, row.subjectId])
    : "";
}

async function readDirectoryMemberships(signal: AbortSignal) {
  return collectAllContinuations<MembershipPage, Membership>({
    label: "Directory memberships",
    readPage: async (cursor) => {
      const [afterGroupId, afterSubjectId] = cursor
        ? JSON.parse(cursor)
        : [null, null];
      const page = await readPlatformProgram<MembershipPage>(
        "identity.group.membership.list",
        { afterGroupId, afterSubjectId, limit: directoryPageSize },
        signal,
      );
      if (!Array.isArray(page?.items) || page.items.length > directoryPageSize)
        throw new Error("Directory memberships returned an invalid page.");
      return page;
    },
    rows: (page) => page.items,
    rowIdentity: (row) =>
      Number.isSafeInteger(row?.directoryRevision) && row.directoryRevision >= 0
        ? membershipKey(row)
        : "",
    nextCursor: (page) => {
      if (page.nextAfter === null) return null;
      const key = membershipKey(page.nextAfter);
      if (!key || key !== membershipKey(page.items.at(-1)))
        throw new Error(
          "Directory memberships returned an invalid continuation.",
        );
      return key;
    },
  });
}

const emptyUser = {
  username: "",
  displayName: "",
  shortDescription: "",
  semanticDescription: "",
};
const emptyGroup = {
  groupId: "",
  displayName: "",
  shortDescription: "",
  semanticDescription: "",
};

function newKey() {
  return `ui-${crypto.randomUUID()}`;
}

type DirectoryProps = {
  functions: Record<string, unknown>;
  section?: string;
  onNavigateSection?: (section: string) => void;
  onRequestTransition?: (action: () => void, preserveDrafts?: boolean) => void;
};
const directorySections = [
  { id: "users", label: "Users" },
  { id: "groups", label: "Groups" },
  { id: "membership", label: "Membership" },
];
export function ServerAdministration(props: DirectoryProps) {
  const [localSection, setLocalSection] = useState("users");
  const section = directorySections.some((item) => item.id === props.section)
    ? props.section!
    : localSection;
  return (
    <ServerDirectory
      {...props}
      key={section}
      section={section}
      onNavigateSection={props.onNavigateSection || setLocalSection}
    />
  );
}
function ServerDirectory({
  functions,
  section = "users",
  onNavigateSection,
  onRequestTransition = (action) => action(),
}: DirectoryProps) {
  const [query, setQuery] = useState("");
  const [pageIndex, setPageIndex] = useState(0);
  const [creating, setCreating] = useState(false);
  const [directory, setDirectory] = useState<DirectoryLoad>({
    status: "loading",
  });
  const directoryReady = directory.status === "ready";
  const { users, groups, memberships } =
    directory.status === "ready" ? directory.records : emptyDirectory;
  const [userDraft, setUserDraft] = useState(emptyUser);
  const [groupDraft, setGroupDraft] = useState(emptyGroup);
  const [editingUser, setEditingUser] = useState<DirectoryUser | null>(null);
  const [passwordUser, setPasswordUser] = useState<DirectoryUser | null>(null);
  const [temporaryPassword, setTemporaryPassword] = useState("");
  const [passwordRecovery, setPasswordRecovery] = useState<string | null>(null);
  const [directoryRecovery, setDirectoryRecovery] =
    useState<DirectoryChange | null>(null);
  const [directoryRetryAvailable, setDirectoryRetryAvailable] = useState(false);
  const [editingGroup, setEditingGroup] = useState<DirectoryGroup | null>(null);
  const [memberUser, setMemberUser] = useState("");
  const [memberGroup, setMemberGroup] = useState("");
  const [reviewed, setReviewed] = useState({
    user: false,
    group: false,
    membership: false,
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
  const directoryRead = useRef<AbortController | null>(null);
  const operationRequest = useRef<AbortController | null>(null);
  const passwordAttempt = usePreservedDraft<string | null>(
    "",
    "",
    "server-directory-password-assignment",
    "Unconfirmed temporary password assignment",
    Boolean(passwordRecovery),
    passwordRecovery,
    setPasswordRecovery,
  );
  const directoryAttempt = usePreservedDraft<DirectoryChange | null>(
    "",
    "",
    "server-directory-change",
    "Unconfirmed directory change",
    Boolean(directoryRecovery),
    directoryRecovery,
    setDirectoryRecovery,
  );
  const writeBlocked =
    busy ||
    Boolean(
      passwordRecovery ||
        directoryRecovery ||
        passwordAttempt.lease ||
        directoryAttempt.lease,
    );

  useEffect(() => () => operationRequest.current?.abort(), []);

  const load = useCallback(async () => {
    directoryRead.current?.abort();
    const controller = new AbortController();
    directoryRead.current = controller;
    const { signal } = controller;
    setDirectory({ status: "loading" });
    try {
      const { rows: users } = await readOffsetDirectory<DirectoryUser>(
        "identity.native-user.list",
        "Directory users",
        (row) =>
          typeof row?.subjectId === "string" &&
          validDirectoryRecord(row, row.username)
            ? row.subjectId
            : "",
        signal,
      );
      const { rows: groups } = await readDirectoryGroups(signal);
      const { rows: memberships } = await readDirectoryMemberships(signal);
      if (signal.aborted) return;
      setDirectory({
        status: "ready",
        records: { users, groups, memberships },
      });
      setMemberUser((current) =>
        users.some((user) => user.subjectId === current)
          ? current
          : (users[0]?.subjectId ?? ""),
      );
      setMemberGroup((current) =>
        groups.some((group) => group.groupId === current)
          ? current
          : (groups[0]?.groupId ?? ""),
      );
    } catch (reason) {
      if (!signal.aborted)
        setDirectory({
          status: "unavailable",
          message:
            reason instanceof Error
              ? reason.message
              : "The directory read failed.",
        });
    }
  }, []);

  useEffect(() => {
    void load();
    return () => directoryRead.current?.abort();
  }, [load]);

  function clearDirectoryEditor(functionName: string) {
    switch (functionName) {
      case "identity.native-user.create":
        setUserDraft(emptyUser);
        setReviewed((value) => ({ ...value, user: false }));
        break;
      case "identity.group.create":
        setGroupDraft(emptyGroup);
        setReviewed((value) => ({ ...value, group: false }));
        break;
      case "identity.native-user.update":
        setEditingUser(null);
        break;
      case "identity.group.update":
        setEditingGroup(null);
        break;
      case "identity.group.membership.set":
        setReviewed((value) => ({ ...value, membership: false }));
        break;
    }
  }

  function confirmDirectoryChange(
    change: DirectoryChange,
    lease: DraftRecoveryLease,
    reconciled = false,
  ) {
    directoryAttempt.release(lease, null);
    setDirectoryRecovery(null);
    clearDirectoryEditor(change.functionName);
    setResult(
      reconciled
        ? "The original directory change was committed."
        : change.message,
    );
    if (!directoryRead.current?.signal.aborted) void load();
  }

  async function sendDirectoryChange(
    change: DirectoryChange,
    lease: DraftRecoveryLease,
    rechecking = false,
  ) {
    const controller = new AbortController();
    operationRequest.current = controller;
    setDirectoryRetryAvailable(false);
    setBusy(true);
    setError("");
    setResult("");
    try {
      await writePlatformProgram(
        change.functionName,
        change.args,
        change.operationId,
        controller.signal,
      );
      if (!controller.signal.aborted)
        confirmDirectoryChange(change, lease, rechecking);
    } catch (reason) {
      if (controller.signal.aborted) return;
      // Keycloak and even a post-effect permission recheck can return 4xx.
      // These codes come from envelope, intent or provider-input validation
      // before the original directory effect is sent.
      const refused =
        reason instanceof ApiError &&
        [
          "PLATFORM_WRITE_ARGUMENTS_INVALID",
          "V2_FUNCTION_OR_ARGUMENTS_UNSUPPORTED",
          "IDEMPOTENCY_KEY_REUSED",
          "DIRECTORY_USER_CREATE_INVALID",
          "DIRECTORY_USER_UPDATE_INVALID",
          "DIRECTORY_GROUP_CREATE_INVALID",
          "DIRECTORY_GROUP_UPDATE_INVALID",
        ].includes(reason.code);
      if (refused && !rechecking) {
        directoryAttempt.release(lease, null);
        setError(reason.message);
      } else {
        clearDirectoryEditor(change.functionName);
        setDirectoryRecovery(change);
        setError(
          "The original directory change is unconfirmed. Check its receipt before making another change.",
        );
      }
    } finally {
      operationRequest.current = null;
      if (!controller.signal.aborted) setBusy(false);
    }
  }

  function mutate(
    functionName: DirectoryChangeFunction,
    args: Record<string, string>,
    message: string,
  ) {
    if (writeBlocked || operationRequest.current) return;
    const change = { operationId: newKey(), functionName, args, message };
    try {
      const lease = directoryAttempt.retain(change);
      void sendDirectoryChange(change, lease);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to reserve directory recovery.",
      );
    }
  }

  async function checkDirectoryReceipt() {
    const change = directoryRecovery;
    const lease = directoryAttempt.lease;
    if (
      !change ||
      !lease ||
      busy ||
      operationRequest.current ||
      !can(receiptFunction)
    )
      return;
    const controller = new AbortController();
    operationRequest.current = controller;
    setBusy(true);
    setDirectoryRetryAvailable(false);
    setError("");
    setResult("");
    try {
      const receipt = await readPlatformProgram<PlatformReceipt>(
        receiptFunction,
        { operationId: change.operationId },
        controller.signal,
      );
      if (controller.signal.aborted) return;
      const status = receiptStatus(
        receipt,
        change.operationId,
        change.functionName,
      );
      if (status === "Committed") {
        confirmDirectoryChange(change, lease, true);
      } else if (status === "Unavailable") {
        setDirectoryRetryAvailable(true);
        setError(
          "The receipt is unavailable. You can retry the original change with its existing operation ID.",
        );
      } else {
        setError(
          status === "Pending"
            ? "The directory receipt is pending. Check again for the original outcome."
            : "The receipt could not confirm the original directory change.",
        );
      }
    } catch {
      if (!controller.signal.aborted)
        setError(
          "The receipt check failed. The original directory change is still unconfirmed.",
        );
    } finally {
      operationRequest.current = null;
      if (!controller.signal.aborted) setBusy(false);
    }
  }

  function retryDirectoryChange() {
    if (
      !directoryRecovery ||
      !directoryAttempt.lease ||
      !directoryRetryAvailable ||
      busy ||
      operationRequest.current ||
      !can(receiptFunction) ||
      !can(directoryRecovery.functionName)
    )
      return;
    void sendDirectoryChange(directoryRecovery, directoryAttempt.lease, true);
  }

  function createUser(event: React.FormEvent) {
    event.preventDefault();
    mutate(
      "identity.native-user.create",
      userDraft,
      `Created ${userDraft.displayName}. Assign a temporary password before first sign-in.`,
    );
  }

  function createGroup(event: React.FormEvent) {
    event.preventDefault();
    mutate(
      "identity.group.create",
      groupDraft,
      `Created ${groupDraft.displayName}.`,
    );
  }

  function updateUser(event: React.FormEvent) {
    event.preventDefault();
    if (!editingUser) return;
    const args = {
      subjectId: editingUser.subjectId,
      displayName: editingUser.displayName,
      shortDescription: editingUser.shortDescription,
      semanticDescription: editingUser.semanticDescription,
    };
    mutate(
      "identity.native-user.update",
      args,
      `Updated ${editingUser.displayName}.`,
    );
  }

  function updateGroup(event: React.FormEvent) {
    event.preventDefault();
    if (!editingGroup) return;
    const args = {
      groupId: editingGroup.groupId,
      displayName: editingGroup.displayName,
      shortDescription: editingGroup.shortDescription,
      semanticDescription: editingGroup.semanticDescription,
    };
    mutate(
      "identity.group.update",
      args,
      `Updated ${editingGroup.displayName}.`,
    );
  }

  function setStatus(
    kind: "user" | "group",
    id: string,
    status: "Active" | "Inactive",
  ) {
    if (
      writeBlocked ||
      !window.confirm(
        `${status === "Inactive" ? "Deactivate" : "Activate"} ${id}?`,
      )
    )
      return;
    const functionName =
      kind === "user"
        ? "identity.native-user.status.set"
        : "identity.group.status.set";
    const args: Record<string, string> =
      kind === "user" ? { subjectId: id, status } : { groupId: id, status };
    mutate(functionName, args, `${id} is now ${status.toLowerCase()}.`);
  }

  async function setPassword(event: React.FormEvent) {
    event.preventDefault();
    if (!passwordUser || writeBlocked || operationRequest.current) return;
    const operationId = newKey();
    let lease: DraftRecoveryLease;
    try {
      // Reserve only the receipt reference before the write can reach Keycloak.
      lease = passwordAttempt.retain(operationId);
    } catch (reason) {
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to reserve a receipt check.",
      );
      return;
    }
    const controller = new AbortController();
    operationRequest.current = controller;
    setBusy(true);
    setError("");
    setResult("");
    setTemporaryPassword("");
    try {
      await writePlatformProgram(
        passwordFunction,
        { subjectId: passwordUser.subjectId, temporaryPassword },
        operationId,
        controller.signal,
      );
      if (controller.signal.aborted) return;
      confirmPasswordAssignment(lease);
    } catch (reason) {
      if (controller.signal.aborted) return;
      const refused =
        reason instanceof ApiError &&
        ([400, 401, 403, 415, 422].includes(reason.status) ||
          reason.code === "IDEMPOTENCY_KEY_REUSED");
      if (refused) {
        passwordAttempt.release(lease, null);
        setError(reason.message);
      } else {
        setPasswordRecovery(operationId);
        setError(
          "The original password assignment is unconfirmed. Check the original assignment before setting a new password.",
        );
      }
    } finally {
      operationRequest.current = null;
      if (!controller.signal.aborted) setBusy(false);
    }
  }

  function confirmPasswordAssignment(lease: DraftRecoveryLease) {
    passwordAttempt.release(lease, null);
    setPasswordRecovery(null);
    setResult(
      passwordUser
        ? passwordAssignedMessage(passwordUser)
        : "The original temporary password assignment was committed.",
    );
    setPasswordUser(null);
    if (!directoryRead.current?.signal.aborted) void load();
  }

  async function checkPasswordReceipt() {
    const lease = passwordAttempt.lease;
    if (
      !lease ||
      !passwordRecovery ||
      busy ||
      operationRequest.current ||
      !can(receiptFunction)
    )
      return;
    const controller = new AbortController();
    operationRequest.current = controller;
    setBusy(true);
    setError("");
    setResult("");
    try {
      const receipt = await readPlatformProgram<PlatformReceipt>(
        receiptFunction,
        { operationId: passwordRecovery },
        controller.signal,
      );
      if (controller.signal.aborted) return;
      const status = receiptStatus(receipt, passwordRecovery, passwordFunction);
      if (status === "Committed") {
        confirmPasswordAssignment(lease);
        return;
      }
      setError(
        status === "Pending"
          ? "The receipt is pending. The original password assignment is still unconfirmed."
          : "The receipt could not confirm the original assignment. Verify its outcome before setting a new password.",
      );
    } catch {
      if (!controller.signal.aborted)
        setError(
          "The receipt check failed. Retry the check before setting a new password.",
        );
    } finally {
      operationRequest.current = null;
      if (!controller.signal.aborted) setBusy(false);
    }
  }

  async function copyReceiptCheck(operationId: string) {
    if (busy) return;
    try {
      await navigator.clipboard.writeText(
        JSON.stringify({
          program: {
            languageVersion: 2,
            function: receiptFunction,
            arguments: { operationId },
          },
        }),
      );
      setResult("Receipt check copied for your MCP client.");
    } catch {
      setResult("");
      setError(
        "Clipboard unavailable. The receipt check is still available here.",
      );
    }
  }

  function setMembership(action: "add" | "remove") {
    const args = { subjectId: memberUser, groupId: memberGroup, action };
    mutate(
      "identity.group.membership.set",
      args,
      `${action === "add" ? "Added" : "Removed"} the selected membership. Existing sessions were revoked.`,
    );
  }

  const can = (name: string) => Boolean(functions[name]);
  const completeUser =
    userDraft.username !== "" && userDraft.displayName !== "";
  const completeGroup =
    groupDraft.groupId !== "" && groupDraft.displayName !== "";
  const membershipExists = memberships.some(
    (item) => item.subjectId === memberUser && item.groupId === memberGroup,
  );
  const sourceUser = editingUser
    ? users.find((user) => user.subjectId === editingUser.subjectId)
    : undefined;
  const sourceGroup = editingGroup
    ? groups.find((group) => group.groupId === editingGroup.groupId)
    : undefined;
  const directoryDraftChanged = Boolean(
    JSON.stringify(userDraft) !== JSON.stringify(emptyUser) ||
      JSON.stringify(groupDraft) !== JSON.stringify(emptyGroup) ||
      (editingUser &&
        JSON.stringify(editingUser) !== JSON.stringify(sourceUser)) ||
      (editingGroup &&
        JSON.stringify(editingGroup) !== JSON.stringify(sourceGroup)) ||
      temporaryPassword ||
      reviewed.membership,
  );
  useUnsavedWork(
    "server-identity-directory",
    "Unsaved identity directory changes",
    directoryDraftChanged,
  );

  const needle = query.trim().toLocaleLowerCase();
  const filteredUsers = users.filter((row) =>
    `${row.displayName} ${row.username} ${row.status}`
      .toLocaleLowerCase()
      .includes(needle),
  );
  const filteredGroups = groups.filter((row) =>
    `${row.displayName} ${row.groupName} ${row.status}`
      .toLocaleLowerCase()
      .includes(needle),
  );
  const filteredMemberships = memberships.filter((row) =>
    `${users.find((user) => user.subjectId === row.subjectId)?.displayName || ""} ${users.find((user) => user.subjectId === row.subjectId)?.username || ""} ${groups.find((group) => group.groupId === row.groupId)?.displayName || ""} ${groups.find((group) => group.groupId === row.groupId)?.groupName || ""}`
      .toLocaleLowerCase()
      .includes(needle),
  );
  const total =
    section === "users"
      ? filteredUsers.length
      : section === "groups"
        ? filteredGroups.length
        : filteredMemberships.length;
  const start = Math.min(
    pageIndex * 50,
    Math.max(0, Math.ceil(total / 50) - 1) * 50,
  );
  function changeEditor(action: () => void) {
    if (writeBlocked) return;
    onRequestTransition(() => {
      setUserDraft(emptyUser);
      setGroupDraft(emptyGroup);
      setEditingUser(null);
      setEditingGroup(null);
      setPasswordUser(null);
      setTemporaryPassword("");
      setCreating(false);
      setReviewed({ user: false, group: false, membership: false });
      action();
    });
  }

  return (
    <div className="page server-administration-page">
      <div className="page-heading">
        <div>
          <span>Server administration</span>
          <h1>Identity directory</h1>
          <p>
            Manage users, groups and group membership. Application roles and
            data access are managed inside each application.
          </p>
        </div>
      </div>

      <nav className="workspace-tabs" aria-label="Directory workspaces">
        {directorySections.map((item) => (
          <button
            key={item.id}
            aria-current={section === item.id ? "page" : undefined}
            className={section === item.id ? "active" : ""}
            onClick={() => {
              if (item.id !== section)
                onRequestTransition(() => onNavigateSection?.(item.id), true);
            }}
          >
            {item.label}
          </button>
        ))}
      </nav>
      {directoryReady && (
        <div className="directory-toolbar">
          <label>
            Search directory
            <input
              type="search"
              value={query}
              placeholder="Name, username or status"
              onChange={(event) => {
                setQuery(event.target.value);
                setPageIndex(0);
              }}
            />
          </label>
          <span>
            {total} {section === "membership" ? "memberships" : section}
          </span>
          {section !== "membership" &&
            can(
              section === "users"
                ? "identity.native-user.create"
                : "identity.group.create",
            ) && (
              <button
                className="primary"
                disabled={writeBlocked}
                onClick={() => changeEditor(() => setCreating(true))}
              >
                {section === "users" ? "+ New user" : "+ New group"}
              </button>
            )}
        </div>
      )}
      {error && (
        <div className="alert" role="alert">
          {error}
        </div>
      )}
      {result && (
        <div className="success-banner" role="status">
          {result}
        </div>
      )}
      {directoryRecovery && (
        <section
          className="panel directory-section"
          aria-label="Directory change recovery"
        >
          <div className="directory-create-form">
            <h3>Recover directory change</h3>
            <p>
              Check the receipt for the original{" "}
              <code>{directoryRecovery.functionName}</code> request.
            </p>
            {!can(receiptFunction) && (
              <p>Receipt checks are unavailable under the current access.</p>
            )}
            <div className="inline-actions">
              <button
                type="button"
                disabled={
                  busy || !directoryAttempt.lease || !can(receiptFunction)
                }
                onClick={() => void checkDirectoryReceipt()}
              >
                Check original directory change
              </button>
              <button
                type="button"
                disabled={busy || !can(receiptFunction)}
                onClick={() =>
                  void copyReceiptCheck(directoryRecovery.operationId)
                }
              >
                Copy receipt check for MCP
              </button>
              {directoryRetryAvailable &&
                can(directoryRecovery.functionName) &&
                can(receiptFunction) && (
                  <button
                    type="button"
                    disabled={busy || !directoryAttempt.lease}
                    onClick={retryDirectoryChange}
                  >
                    Retry original directory change
                  </button>
                )}
              <button
                type="button"
                disabled={busy || !directoryAttempt.lease}
                onClick={() => {
                  const lease = directoryAttempt.lease;
                  if (
                    !lease ||
                    !window.confirm(
                      "Close this check? The original change may have happened. Verify its outcome before starting a new change.",
                    )
                  )
                    return;
                  directoryAttempt.release(lease, null);
                  setDirectoryRecovery(null);
                  setDirectoryRetryAvailable(false);
                  setError("");
                  setResult("");
                }}
              >
                Close recovery
              </button>
            </div>
          </div>
        </section>
      )}
      {passwordRecovery && (
        <section
          className="panel directory-section"
          aria-label="Password assignment recovery"
        >
          <div className="directory-create-form">
            <h3>Recover password assignment</h3>
            <p>
              {passwordUser
                ? `Check the original operation for ${passwordUser.displayName}.`
                : "Check the original operation before assigning a new password."}{" "}
              The check uses its receipt reference.
            </p>
            {!can(receiptFunction) && (
              <p>This server does not offer a receipt check.</p>
            )}
            <div className="inline-actions">
              <button
                type="button"
                disabled={
                  busy || !passwordAttempt.lease || !can(receiptFunction)
                }
                onClick={() => void checkPasswordReceipt()}
              >
                Check original password assignment
              </button>
              <button
                type="button"
                disabled={busy || !can(receiptFunction)}
                onClick={() => void copyReceiptCheck(passwordRecovery)}
              >
                Copy receipt check for MCP
              </button>
              <button
                type="button"
                disabled={busy || !passwordAttempt.lease}
                onClick={() => {
                  const lease = passwordAttempt.lease;
                  if (
                    !lease ||
                    !window.confirm(
                      "Close this check? The original assignment may have happened. Verify it before setting a new password.",
                    )
                  )
                    return;
                  passwordAttempt.release(lease, null);
                  setPasswordRecovery(null);
                  setPasswordUser(null);
                  setError("");
                  setResult("");
                }}
              >
                Close recovery
              </button>
            </div>
          </div>
        </section>
      )}
      {directory.status === "loading" && (
        <div className="empty-state" role="status">
          Loading the governed directory…
        </div>
      )}
      {directory.status === "unavailable" && (
        <div className="alert" role="alert">
          <p>Directory could not be loaded.</p>
          <p>{directory.message}</p>
          <button type="button" onClick={() => void load()}>
            Retry directory load
          </button>
        </div>
      )}
      {directoryReady && (
        <>
          {section === "users" && (
            <section className="panel directory-section">
              <div className="section-title">
                <div>
                  <span>Keycloak directory</span>
                  <h2>Native users</h2>
                </div>
                <strong>{users.length} managed</strong>
              </div>
              <div
                className="table-scroll"
                tabIndex={0}
                role="region"
                aria-label="Directory records"
              >
                <table className="directory-table">
                  <thead>
                    <tr>
                      <th>User</th>
                      <th>Status</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredUsers.slice(start, start + 50).map((user) => (
                      <tr key={user.subjectId}>
                        <td>
                          <strong>{user.displayName}</strong>
                          <small>{user.username}</small>
                        </td>
                        <td>
                          <span
                            className={`state-badge ${user.status.toLowerCase()}`}
                          >
                            {user.status}
                          </span>
                        </td>
                        <td>
                          <span className="inline-actions">
                            <button
                              disabled={
                                writeBlocked ||
                                !can(passwordFunction) ||
                                user.status !== "Active"
                              }
                              onClick={() =>
                                changeEditor(() => {
                                  setPasswordUser(user);
                                  setTemporaryPassword("");
                                })
                              }
                            >
                              Set temporary password
                            </button>
                            <button
                              disabled={
                                writeBlocked ||
                                !can("identity.native-user.update")
                              }
                              onClick={() =>
                                changeEditor(() => setEditingUser(user))
                              }
                            >
                              Edit
                            </button>
                            <button
                              disabled={
                                writeBlocked ||
                                !can("identity.native-user.status.set")
                              }
                              onClick={() =>
                                void setStatus(
                                  "user",
                                  user.subjectId,
                                  user.status === "Active"
                                    ? "Inactive"
                                    : "Active",
                                )
                              }
                            >
                              {user.status === "Active"
                                ? "Deactivate"
                                : "Activate"}
                            </button>
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {editingUser && !directoryRecovery && (
                <form
                  className="directory-create-form"
                  onSubmit={updateUser}
                  inert={busy}
                >
                  <h3>Edit native user</h3>
                  <p>{editingUser.username} remains the sign-in name.</p>
                  <div className="directory-fields">
                    <label>
                      Display name
                      <input
                        value={editingUser.displayName}
                        onChange={(event) =>
                          setEditingUser({
                            ...editingUser,
                            displayName: event.target.value,
                          })
                        }
                        required
                      />
                    </label>
                    <label>
                      Short description
                      <input
                        value={editingUser.shortDescription}
                        onChange={(event) =>
                          setEditingUser({
                            ...editingUser,
                            shortDescription: event.target.value,
                          })
                        }
                      />
                    </label>
                    <label className="wide">
                      Semantic description
                      <textarea
                        value={editingUser.semanticDescription}
                        onChange={(event) =>
                          setEditingUser({
                            ...editingUser,
                            semanticDescription: event.target.value,
                          })
                        }
                      />
                    </label>
                  </div>
                  <div className="inline-actions">
                    <button
                      type="submit"
                      disabled={writeBlocked || !editingUser.displayName}
                    >
                      Save user descriptions
                    </button>
                    <button
                      type="button"
                      onClick={() => changeEditor(() => undefined)}
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              )}
              {passwordUser && !passwordRecovery && (
                <form className="directory-create-form" onSubmit={setPassword}>
                  <h3>Set temporary password</h3>
                  <p>
                    Assign a one-time credential for {passwordUser.displayName}.
                    Open EPM sends it directly to Keycloak, never stores it, and
                    Keycloak requires replacement at first sign-in.
                  </p>
                  <div className="directory-fields">
                    <label>
                      Temporary password
                      <input
                        type="password"
                        autoComplete="new-password"
                        value={temporaryPassword}
                        readOnly={busy}
                        onChange={(event) => {
                          if (busy) return;
                          setTemporaryPassword(event.target.value);
                        }}
                        minLength={12}
                        required
                      />
                    </label>
                  </div>
                  <div className="inline-actions">
                    <button
                      type="submit"
                      disabled={writeBlocked || temporaryPassword.length < 12}
                    >
                      Set temporary password
                    </button>
                    <button
                      type="button"
                      disabled={busy}
                      onClick={() => {
                        setTemporaryPassword("");
                        setPasswordUser(null);
                        setError("");
                      }}
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              )}
              {creating &&
                !directoryRecovery &&
                can("identity.native-user.create") && (
                  <form
                    className="directory-create-form"
                    onSubmit={createUser}
                    inert={busy}
                  >
                    <h3>Create native user</h3>
                    <p>
                      Create a stable native user ID. Then assign a temporary
                      password that Keycloak requires the user to replace on
                      first sign-in. No email service or MFA is required.
                    </p>
                    <div className="directory-fields">
                      <label>
                        Username
                        <input
                          value={userDraft.username}
                          onChange={(e) => {
                            setUserDraft({
                              ...userDraft,
                              username: e.target.value,
                            });
                            setReviewed({ ...reviewed, user: false });
                          }}
                          required
                        />
                      </label>
                      <label>
                        Display name
                        <input
                          value={userDraft.displayName}
                          onChange={(e) => {
                            setUserDraft({
                              ...userDraft,
                              displayName: e.target.value,
                            });
                            setReviewed({ ...reviewed, user: false });
                          }}
                          required
                        />
                      </label>
                      <label>
                        Short description
                        <input
                          value={userDraft.shortDescription}
                          onChange={(e) => {
                            setUserDraft({
                              ...userDraft,
                              shortDescription: e.target.value,
                            });
                            setReviewed({ ...reviewed, user: false });
                          }}
                        />
                      </label>
                      <label className="wide">
                        Semantic description
                        <textarea
                          value={userDraft.semanticDescription}
                          onChange={(e) => {
                            setUserDraft({
                              ...userDraft,
                              semanticDescription: e.target.value,
                            });
                            setReviewed({ ...reviewed, user: false });
                          }}
                        />
                      </label>
                    </div>
                    <label className="review-check">
                      <input
                        type="checkbox"
                        checked={reviewed.user}
                        onChange={(e) =>
                          setReviewed({ ...reviewed, user: e.target.checked })
                        }
                      />{" "}
                      I reviewed the exact user identity and descriptions.
                    </label>
                    <button
                      type="submit"
                      disabled={writeBlocked || !completeUser || !reviewed.user}
                    >
                      Create native user
                    </button>
                  </form>
                )}
            </section>
          )}

          {section === "groups" && (
            <section className="panel directory-section">
              <div className="section-title">
                <div>
                  <span>Authorization principals</span>
                  <h2>Groups</h2>
                </div>
                <strong>{groups.length} managed</strong>
              </div>
              <div
                className="table-scroll"
                tabIndex={0}
                role="region"
                aria-label="Directory records"
              >
                <table className="directory-table">
                  <thead>
                    <tr>
                      <th>Group name</th>
                      <th>Display name</th>
                      <th>Description</th>
                      <th>Status</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredGroups.slice(start, start + 50).map((group) => (
                      <tr key={group.groupId}>
                        <td>{group.groupName}</td>
                        <td>
                          <strong>{group.displayName}</strong>
                        </td>
                        <td>{group.shortDescription || "—"}</td>
                        <td>
                          <span
                            className={`state-badge ${group.status.toLowerCase()}`}
                          >
                            {group.status}
                          </span>
                        </td>
                        <td>
                          <span className="inline-actions">
                            <button
                              disabled={
                                writeBlocked || !can("identity.group.update")
                              }
                              onClick={() =>
                                changeEditor(() => setEditingGroup(group))
                              }
                            >
                              Edit
                            </button>
                            <button
                              disabled={
                                writeBlocked ||
                                !can("identity.group.status.set")
                              }
                              onClick={() =>
                                void setStatus(
                                  "group",
                                  group.groupId,
                                  group.status === "Active"
                                    ? "Inactive"
                                    : "Active",
                                )
                              }
                            >
                              {group.status === "Active"
                                ? "Deactivate"
                                : "Activate"}
                            </button>
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {editingGroup && !directoryRecovery && (
                <form
                  className="directory-create-form"
                  onSubmit={updateGroup}
                  inert={busy}
                >
                  <h3>Edit group</h3>
                  <p>{editingGroup.groupName} remains the group name.</p>
                  <div className="directory-fields">
                    <label>
                      Display name
                      <input
                        value={editingGroup.displayName}
                        onChange={(event) =>
                          setEditingGroup({
                            ...editingGroup,
                            displayName: event.target.value,
                          })
                        }
                        required
                      />
                    </label>
                    <label>
                      Short description
                      <input
                        value={editingGroup.shortDescription}
                        onChange={(event) =>
                          setEditingGroup({
                            ...editingGroup,
                            shortDescription: event.target.value,
                          })
                        }
                      />
                    </label>
                    <label className="wide">
                      Semantic description
                      <textarea
                        value={editingGroup.semanticDescription}
                        onChange={(event) =>
                          setEditingGroup({
                            ...editingGroup,
                            semanticDescription: event.target.value,
                          })
                        }
                      />
                    </label>
                  </div>
                  <div className="inline-actions">
                    <button
                      type="submit"
                      disabled={writeBlocked || !editingGroup.displayName}
                    >
                      Save group descriptions
                    </button>
                    <button
                      type="button"
                      onClick={() => changeEditor(() => undefined)}
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              )}
              {creating &&
                !directoryRecovery &&
                can("identity.group.create") && (
                  <form
                    className="directory-create-form"
                    onSubmit={createGroup}
                    inert={busy}
                  >
                    <h3>Create group</h3>
                    <div className="directory-fields">
                      <label>
                        Group name
                        <input
                          value={groupDraft.groupId}
                          onChange={(e) => {
                            setGroupDraft({
                              ...groupDraft,
                              groupId: e.target.value,
                            });
                            setReviewed({ ...reviewed, group: false });
                          }}
                          required
                        />
                      </label>
                      <label>
                        Display name
                        <input
                          value={groupDraft.displayName}
                          onChange={(e) => {
                            setGroupDraft({
                              ...groupDraft,
                              displayName: e.target.value,
                            });
                            setReviewed({ ...reviewed, group: false });
                          }}
                          required
                        />
                      </label>
                      <label>
                        Short description
                        <input
                          value={groupDraft.shortDescription}
                          onChange={(e) => {
                            setGroupDraft({
                              ...groupDraft,
                              shortDescription: e.target.value,
                            });
                            setReviewed({ ...reviewed, group: false });
                          }}
                        />
                      </label>
                      <label className="wide">
                        Semantic description
                        <textarea
                          value={groupDraft.semanticDescription}
                          onChange={(e) => {
                            setGroupDraft({
                              ...groupDraft,
                              semanticDescription: e.target.value,
                            });
                            setReviewed({ ...reviewed, group: false });
                          }}
                        />
                      </label>
                    </div>
                    <label className="review-check">
                      <input
                        type="checkbox"
                        checked={reviewed.group}
                        onChange={(e) =>
                          setReviewed({ ...reviewed, group: e.target.checked })
                        }
                      />{" "}
                      I reviewed the group name and descriptions.
                    </label>
                    <button
                      type="submit"
                      disabled={
                        writeBlocked || !completeGroup || !reviewed.group
                      }
                    >
                      Create group
                    </button>
                  </form>
                )}
            </section>
          )}

          {section === "membership" && (
            <section className="panel directory-section">
              <div className="section-title">
                <div>
                  <span>Current directory state</span>
                  <h2>Group membership</h2>
                </div>
                <strong>{memberships.length} active</strong>
              </div>
              <div className="membership-editor">
                <label>
                  User
                  <select
                    value={memberUser}
                    onChange={(e) => {
                      setMemberUser(e.target.value);
                      setReviewed({ ...reviewed, membership: false });
                    }}
                  >
                    {filteredUsers.slice(start, start + 50).map((user) => (
                      <option key={user.subjectId} value={user.subjectId}>
                        {user.displayName} · {user.username}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Group
                  <select
                    value={memberGroup}
                    onChange={(e) => {
                      setMemberGroup(e.target.value);
                      setReviewed({ ...reviewed, membership: false });
                    }}
                  >
                    {groups.map((group) => (
                      <option key={group.groupId} value={group.groupId}>
                        {group.displayName} · {group.groupName}
                      </option>
                    ))}
                  </select>
                </label>
                <span
                  className={`state-badge ${membershipExists ? "active" : "inactive"}`}
                >
                  {membershipExists ? "Member" : "Not a member"}
                </span>
              </div>
              <label className="review-check">
                <input
                  type="checkbox"
                  checked={reviewed.membership}
                  onChange={(e) =>
                    setReviewed({ ...reviewed, membership: e.target.checked })
                  }
                />{" "}
                I reviewed the exact user, group and membership change.
              </label>
              <div className="inline-actions">
                <button
                  disabled={
                    writeBlocked ||
                    !reviewed.membership ||
                    membershipExists ||
                    !memberUser ||
                    !memberGroup ||
                    !can("identity.group.membership.set")
                  }
                  onClick={() => void setMembership("add")}
                >
                  Add membership
                </button>
                <button
                  className="danger-action"
                  disabled={
                    writeBlocked ||
                    !reviewed.membership ||
                    !membershipExists ||
                    !can("identity.group.membership.set")
                  }
                  onClick={() => void setMembership("remove")}
                >
                  Remove membership
                </button>
              </div>
              <div
                className="table-scroll"
                tabIndex={0}
                role="region"
                aria-label="Directory records"
              >
                <table className="directory-table">
                  <thead>
                    <tr>
                      <th>Group</th>
                      <th>User</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredMemberships
                      .slice(start, start + 50)
                      .map((membership) => (
                        <tr
                          key={`${membership.groupId}:${membership.subjectId}`}
                        >
                          <td>
                            {groups.find(
                              (group) => group.groupId === membership.groupId,
                            )?.displayName || "Unavailable group"}
                          </td>
                          <td>
                            {users.find(
                              (user) => user.subjectId === membership.subjectId,
                            )?.displayName || "Unavailable user"}
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
        </>
      )}
      {directoryReady && (
        <footer className="directory-pagination">
          <span>
            {total
              ? `${start + 1}–${Math.min(start + 50, total)} of ${total}`
              : "No matching records"}
          </span>
          <div>
            <button
              disabled={start === 0}
              onClick={() => setPageIndex(Math.max(0, start / 50 - 1))}
            >
              Previous
            </button>
            <button
              disabled={start + 50 >= total}
              onClick={() => setPageIndex(start / 50 + 1)}
            >
              Next
            </button>
          </div>
        </footer>
      )}
    </div>
  );
}
