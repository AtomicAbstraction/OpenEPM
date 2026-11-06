import { useEffect, useRef, useState } from "react";
import { readPlatformProgram, writePlatformProgram } from "./api";
import { useUnsavedWork } from "./unsaved-work";

type DirectoryUser = {
  subjectId: string;
  username: string;
  displayName: string;
  shortDescription: string;
  semanticDescription: string;
  status: "Active" | "Inactive";
};

type DirectoryGroup = {
  groupId: string;
  groupName: string;
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

type Page<T> = { items: T[]; nextOffset: number | null };
type MembershipPage = {
  items: Membership[];
  nextAfter: { groupId: string; subjectId: string } | null;
};

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

export function ServerAdministration({
  functions,
}: {
  functions: Record<string, unknown>;
}) {
  const [users, setUsers] = useState<DirectoryUser[]>([]);
  const [groups, setGroups] = useState<DirectoryGroup[]>([]);
  const [memberships, setMemberships] = useState<Membership[]>([]);
  const [userDraft, setUserDraft] = useState(emptyUser);
  const [groupDraft, setGroupDraft] = useState(emptyGroup);
  const [editingUser, setEditingUser] = useState<DirectoryUser | null>(null);
  const [passwordUser, setPasswordUser] = useState<DirectoryUser | null>(null);
  const [temporaryPassword, setTemporaryPassword] = useState("");
  const [editingGroup, setEditingGroup] = useState<DirectoryGroup | null>(null);
  const [memberUser, setMemberUser] = useState("");
  const [memberGroup, setMemberGroup] = useState("");
  const [reviewed, setReviewed] = useState({
    user: false,
    group: false,
    membership: false,
  });
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [result, setResult] = useState("");
  const retryKeys = useRef(new Map<string, string>());

  async function load(signal?: AbortSignal) {
    const nextUsers: DirectoryUser[] = [];
    let userOffset: number | null = 0;
    while (userOffset !== null) {
      const userPage: Page<DirectoryUser> = await readPlatformProgram<
        Page<DirectoryUser>
      >(
        "identity.native-user.list",
        { offset: userOffset, limit: 100 },
        signal,
      );
      nextUsers.push(...userPage.items);
      userOffset = userPage.nextOffset;
    }

    const nextGroups: DirectoryGroup[] = [];
    let groupOffset: number | null = 0;
    while (groupOffset !== null) {
      const groupPage: Page<DirectoryGroup> = await readPlatformProgram<
        Page<DirectoryGroup>
      >("identity.group.list", { offset: groupOffset, limit: 100 }, signal);
      nextGroups.push(...groupPage.items);
      groupOffset = groupPage.nextOffset;
    }

    const nextMemberships: Membership[] = [];
    let after: MembershipPage["nextAfter"] = null;
    do {
      const membershipPage: MembershipPage =
        await readPlatformProgram<MembershipPage>(
          "identity.group.membership.list",
          {
            afterGroupId: after?.groupId || null,
            afterSubjectId: after?.subjectId || null,
            limit: 100,
          },
          signal,
        );
      nextMemberships.push(...membershipPage.items);
      after = membershipPage.nextAfter;
    } while (after);

    setUsers(nextUsers);
    setGroups(nextGroups);
    setMemberships(nextMemberships);
    if (!memberUser && nextUsers.length) setMemberUser(nextUsers[0].subjectId);
    if (!memberGroup && nextGroups.length)
      setMemberGroup(nextGroups[0].groupId);
  }

  useEffect(() => {
    const controller = new AbortController();
    load(controller.signal)
      .catch((reason: Error) => {
        if (reason.name !== "AbortError") setError(reason.message);
      })
      .finally(() => setLoading(false));
    return () => controller.abort();
  }, []);

  async function mutate(
    intent: string,
    functionName: string,
    args: Record<string, unknown>,
    message: string,
  ) {
    const key = retryKeys.current.get(intent) || newKey();
    retryKeys.current.set(intent, key);
    setBusy(true);
    setError("");
    setResult("");
    try {
      await writePlatformProgram(functionName, args, key);
      retryKeys.current.delete(intent);
      await load();
      setResult(message);
    } catch (reason) {
      setError(
        reason instanceof Error ? reason.message : "DIRECTORY_OPERATION_FAILED",
      );
      throw reason;
    } finally {
      setBusy(false);
    }
  }

  async function createUser(event: React.FormEvent) {
    event.preventDefault();
    try {
      await mutate(
        `create-user:${JSON.stringify(userDraft)}`,
        "identity.native-user.create",
        userDraft,
        `Created ${userDraft.displayName}. Assign a temporary password before first sign-in.`,
      );
      setUserDraft(emptyUser);
      setReviewed((value) => ({ ...value, user: false }));
    } catch {
      /* Retain exact intent and idempotency key for a safe retry. */
    }
  }

  async function createGroup(event: React.FormEvent) {
    event.preventDefault();
    try {
      await mutate(
        `create-group:${JSON.stringify(groupDraft)}`,
        "identity.group.create",
        groupDraft,
        `Created group ${groupDraft.groupId}.`,
      );
      setGroupDraft(emptyGroup);
      setReviewed((value) => ({ ...value, group: false }));
    } catch {
      /* Retain exact intent and idempotency key for a safe retry. */
    }
  }

  async function updateUser(event: React.FormEvent) {
    event.preventDefault();
    if (!editingUser) return;
    const args = {
      subjectId: editingUser.subjectId,
      displayName: editingUser.displayName,
      shortDescription: editingUser.shortDescription,
      semanticDescription: editingUser.semanticDescription,
    };
    try {
      await mutate(
        `update-user:${JSON.stringify(args)}`,
        "identity.native-user.update",
        args,
        `Updated ${editingUser.displayName}.`,
      );
      setEditingUser(null);
    } catch {
      /* Retain exact intent and idempotency key for a safe retry. */
    }
  }

  async function updateGroup(event: React.FormEvent) {
    event.preventDefault();
    if (!editingGroup) return;
    const args = {
      groupId: editingGroup.groupId,
      displayName: editingGroup.displayName,
      shortDescription: editingGroup.shortDescription,
      semanticDescription: editingGroup.semanticDescription,
    };
    try {
      await mutate(
        `update-group:${JSON.stringify(args)}`,
        "identity.group.update",
        args,
        `Updated ${editingGroup.displayName}.`,
      );
      setEditingGroup(null);
    } catch {
      /* Retain exact intent and idempotency key for a safe retry. */
    }
  }

  async function setStatus(
    kind: "user" | "group",
    id: string,
    status: "Active" | "Inactive",
  ) {
    if (
      !window.confirm(
        `${status === "Inactive" ? "Deactivate" : "Activate"} ${id}?`,
      )
    )
      return;
    const functionName =
      kind === "user"
        ? "identity.native-user.status.set"
        : "identity.group.status.set";
    const args =
      kind === "user" ? { subjectId: id, status } : { groupId: id, status };
    try {
      await mutate(
        `${functionName}:${id}:${status}`,
        functionName,
        args,
        `${id} is now ${status.toLowerCase()}.`,
      );
    } catch {
      /* Error is rendered and exact retry identity remains available. */
    }
  }

  async function setPassword(event: React.FormEvent) {
    event.preventDefault();
    if (!passwordUser) return;
    const intent = `set-temporary-password:${passwordUser.subjectId}`;
    try {
      await mutate(
        intent,
        "identity.native-user.password.set",
        { subjectId: passwordUser.subjectId, temporaryPassword },
        `Assigned a temporary password to ${passwordUser.displayName}. The user must change it at first sign-in.`,
      );
      setTemporaryPassword("");
      setPasswordUser(null);
    } catch {
      /* Keep the in-memory credential and retry key for an exact retry. */
    }
  }

  async function setMembership(action: "add" | "remove") {
    const args = { subjectId: memberUser, groupId: memberGroup, action };
    try {
      await mutate(
        `membership:${JSON.stringify(args)}`,
        "identity.group.membership.set",
        args,
        `${action === "add" ? "Added" : "Removed"} the selected membership. Existing sessions were revoked.`,
      );
      setReviewed((value) => ({ ...value, membership: false }));
    } catch {
      /* Error is rendered and exact retry identity remains available. */
    }
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

  return (
    <div className="page server-administration-page">
      <div className="page-heading">
        <div>
          <span>Server administration</span>
          <h1>Identity directory</h1>
          <p>
            Manage Open EPM native users and stable groups in Keycloak.
            Application roles, rule permissions and dimensional security remain
            governed inside each application.
          </p>
        </div>
      </div>

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
      {loading ? (
        <div className="empty-state">Loading the governed directory…</div>
      ) : (
        <>
          <section className="panel directory-section">
            <div className="section-title">
              <div>
                <span>Keycloak directory</span>
                <h2>Native users</h2>
              </div>
              <strong>{users.length} managed</strong>
            </div>
            <div className="table-scroll">
              <table className="directory-table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>Subject ID</th>
                    <th>Status</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => (
                    <tr key={user.subjectId}>
                      <td>
                        <strong>{user.displayName}</strong>
                        <small>{user.username}</small>
                      </td>
                      <td>
                        <code>{user.subjectId}</code>
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
                              busy ||
                              !can("identity.native-user.password.set") ||
                              user.status !== "Active"
                            }
                            onClick={() => {
                              setPasswordUser(user);
                              setTemporaryPassword("");
                              retryKeys.current.delete(
                                `set-temporary-password:${user.subjectId}`,
                              );
                            }}
                          >
                            Set temporary password
                          </button>
                          <button
                            disabled={
                              busy || !can("identity.native-user.update")
                            }
                            onClick={() => setEditingUser(user)}
                          >
                            Edit
                          </button>
                          <button
                            disabled={
                              busy || !can("identity.native-user.status.set")
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
            {editingUser && (
              <form className="directory-create-form" onSubmit={updateUser}>
                <h3>Edit native user</h3>
                <p>
                  <code>{editingUser.subjectId}</code> · username remains
                  identity-stable.
                </p>
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
                    disabled={busy || !editingUser.displayName}
                  >
                    Save user descriptions
                  </button>
                  <button type="button" onClick={() => setEditingUser(null)}>
                    Cancel
                  </button>
                </div>
              </form>
            )}
            {passwordUser && (
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
                      onChange={(event) => {
                        retryKeys.current.delete(
                          `set-temporary-password:${passwordUser.subjectId}`,
                        );
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
                    disabled={busy || temporaryPassword.length < 12}
                  >
                    Set temporary password
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      retryKeys.current.delete(
                        `set-temporary-password:${passwordUser.subjectId}`,
                      );
                      setTemporaryPassword("");
                      setPasswordUser(null);
                    }}
                  >
                    Cancel
                  </button>
                </div>
              </form>
            )}
            {can("identity.native-user.create") && (
              <form className="directory-create-form" onSubmit={createUser}>
                <h3>Create native user</h3>
                <p>
                  Create a stable native user ID. Then assign a temporary
                  password that Keycloak requires the user to replace on first
                  sign-in. No email service or MFA is required.
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
                  disabled={busy || !completeUser || !reviewed.user}
                >
                  Create native user
                </button>
              </form>
            )}
          </section>

          <section className="panel directory-section">
            <div className="section-title">
              <div>
                <span>Authorization principals</span>
                <h2>Groups</h2>
              </div>
              <strong>{groups.length} managed</strong>
            </div>
            <div className="table-scroll">
              <table className="directory-table">
                <thead>
                  <tr>
                    <th>Immutable group ID</th>
                    <th>Group name</th>
                    <th>Display name</th>
                    <th>Description</th>
                    <th>Status</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {groups.map((group) => (
                    <tr key={group.groupId}>
                      <td>
                        <code>{group.groupId}</code>
                      </td>
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
                            disabled={busy || !can("identity.group.update")}
                            onClick={() => setEditingGroup(group)}
                          >
                            Edit
                          </button>
                          <button
                            disabled={busy || !can("identity.group.status.set")}
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
            {editingGroup && (
              <form className="directory-create-form" onSubmit={updateGroup}>
                <h3>Edit group</h3>
                <p>
                  <code>{editingGroup.groupId}</code> remains the stable token
                  identifier.
                </p>
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
                    disabled={busy || !editingGroup.displayName}
                  >
                    Save group descriptions
                  </button>
                  <button type="button" onClick={() => setEditingGroup(null)}>
                    Cancel
                  </button>
                </div>
              </form>
            )}
            {can("identity.group.create") && (
              <form className="directory-create-form" onSubmit={createGroup}>
                <h3>Create group</h3>
                <div className="directory-fields">
                  <label>
                    Stable group ID
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
                  I reviewed the stable group identity and descriptions.
                </label>
                <button
                  type="submit"
                  disabled={busy || !completeGroup || !reviewed.group}
                >
                  Create group
                </button>
              </form>
            )}
          </section>

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
                  {users.map((user) => (
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
                      {group.displayName} · {group.groupName} · {group.groupId}
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
                  busy ||
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
                  busy ||
                  !reviewed.membership ||
                  !membershipExists ||
                  !can("identity.group.membership.set")
                }
                onClick={() => void setMembership("remove")}
              >
                Remove membership
              </button>
            </div>
            <div className="table-scroll">
              <table className="directory-table">
                <thead>
                  <tr>
                    <th>Group</th>
                    <th>Subject ID</th>
                    <th>Directory revision</th>
                  </tr>
                </thead>
                <tbody>
                  {memberships.map((membership) => (
                    <tr key={`${membership.groupId}:${membership.subjectId}`}>
                      <td>
                        <code>{membership.groupId}</code>
                      </td>
                      <td>
                        <code>{membership.subjectId}</code>
                      </td>
                      <td>{membership.directoryRevision}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
