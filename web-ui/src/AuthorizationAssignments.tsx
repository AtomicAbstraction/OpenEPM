import {
  ReviewedTemplateSummary,
  validTemplatePreview,
  validTemplateConfiguration,
} from "./StarterRoleTemplates";
import { useEffect, useRef, useState } from "react";
import { ApiError, canonicalJson, readSecurityProgram } from "./api";
import { useApplicationSecurityChange } from "./application-security-change";
import {
  RequesterBenefitDetails,
  validRequesterBenefit,
} from "./RequesterBenefit";
import { SecurityChangeOutcome } from "./SecurityChangeOutcome";
import { useStableMutationIntentKey } from "./mutation-intent";
import { outcomeAuthorityKey } from "./ReceiptInspector";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import {
  collectionKeys,
  scopeLabel,
  validWorkflowDuties,
} from "./authorization-config";
import type {
  Assignment,
  Group,
  Privilege,
  Configuration,
  Collection,
  Change,
  Preview,
} from "./authorization-config";
import { AuthorizationDefinitions } from "./AuthorizationDefinitions";
import { useUnsavedWork } from "./unsaved-work";

const CONFIG = "security.application.authorization.read";
const PREVIEW = "security.application.authorization.preview";
const APPLY = "security.application.authorization.apply";
function groupLabel(group: Group) {
  return group.displayName || group.groupName || "Unresolved group";
}

function validConfig(config: Configuration, app: ApplicationSummary) {
  return (
    config &&
    config.workspaceId === app.workspaceId &&
    config.applicationId === app.applicationId &&
    Number.isSafeInteger(config.revision) &&
    config.revision >= 0 &&
    typeof config.complete === "boolean" &&
    typeof config.canManageRoles === "boolean" &&
    (config.canManageWorkflowDuties === undefined ||
      (typeof config.canManageWorkflowDuties === "boolean" &&
        typeof config.workflowDutiesComplete === "boolean" &&
        validWorkflowDuties(config.availableWorkflowDuties))) &&
    typeof config.canManageScopes === "boolean" &&
    typeof config.canManageAssignments === "boolean" &&
    ["legacy", "group_assignments"].includes(config.authorizationMode) &&
    Array.isArray(config.actions) &&
    config.actions.every(
      (action) =>
        typeof action?.action === "string" &&
        typeof action.canDelegate === "boolean" &&
        Array.isArray(action.scopeKinds),
    ) &&
    validTemplateConfiguration(config) &&
    Array.isArray(config.roles) &&
    config.roles.every(
      (role) =>
        typeof role?.roleId === "string" &&
        typeof role.name === "string" &&
        Array.isArray(role.actions) &&
        (config.canManageWorkflowDuties === undefined ||
          validWorkflowDuties(role.workflowDuties)),
    ) &&
    Array.isArray(config.scopes) &&
    config.scopes.every(
      (scope) =>
        typeof scope?.scopeId === "string" &&
        typeof scope.name === "string" &&
        scope.selector &&
        typeof scope.selector === "object",
    ) &&
    Array.isArray(config.assignments) &&
    config.assignments.every(
      (item) =>
        typeof item?.assignmentId === "string" &&
        typeof item.roleId === "string" &&
        typeof item.groupId === "string" &&
        Array.isArray(item.privileges),
    ) &&
    Array.isArray(config.eligibleGroups) &&
    config.eligibleGroups.every(
      (group) => typeof group?.groupId === "string",
    ) &&
    typeof config.snapshotToken === "string" &&
    config.snapshotToken.length > 0 &&
    config.nextAfter &&
    Object.keys(collectionKeys).every((key) => {
      const after = config.nextAfter[key as Collection];
      return after === null || (typeof after === "string" && after.length > 0);
    })
  );
}

function validDutyPreview(
  config: Configuration,
  changes: Change[],
  reviewed: Preview["impact"]["reviewedWorkflowDuties"],
) {
  const expected = changes.flatMap((change) => {
    if (change.op !== "putRole" && change.op !== "removeRole") return [];
    if (change.op === "putRole" && change.workflowDuties === undefined)
      return [];
    const before =
      config.roles.find((role) => role.roleId === change.roleId)
        ?.workflowDuties ?? [];
    const after = change.op === "putRole" ? change.workflowDuties! : [];
    const addedDuties = after.filter((duty) => !before.includes(duty)).sort();
    const removedDuties = before.filter((duty) => !after.includes(duty)).sort();
    return addedDuties.length || removedDuties.length
      ? [{ roleId: change.roleId, addedDuties, removedDuties }]
      : [];
  });
  return canonicalJson(reviewed ?? []) === canonicalJson(expected);
}

function AssignmentContents({
  assignment,
  config,
}: {
  assignment: Assignment;
  config: Configuration;
}) {
  const group = config.eligibleGroups.find(
    (row) => row.groupId === assignment.groupId,
  );
  const role = config.roles.find((row) => row.roleId === assignment.roleId);
  return (
    <div>
      <p>
        {group ? groupLabel(group) : "Group unavailable"} ·{" "}
        {role?.name || "Role unavailable"}
      </p>
      <ul>
        {assignment.privileges.map((privilege) => {
          const resource = config.scopes.find(
            (scope) => scope.scopeId === privilege.scopeId,
          );
          return (
            <li key={JSON.stringify([privilege.action, privilege.scopeId])}>
              {privilege.action} —{" "}
              {resource
                ? `${resource.name} · ${scopeLabel(resource)}`
                : "Scope unavailable"}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export function AuthorizationAssignments({
  app,
  catalog,
}: {
  app: ApplicationSummary;
  catalog: ApplicationCatalog;
}) {
  if (!catalog.functions[CONFIG]) return null;
  return (
    <AssignmentEditor
      key={outcomeAuthorityKey(app, catalog)}
      app={app}
      catalog={catalog}
    />
  );
}

function AssignmentEditor({
  app,
  catalog,
}: {
  app: ApplicationSummary;
  catalog: ApplicationCatalog;
}) {
  const [config, setConfig] = useState<Configuration | null>(null);
  const [assignmentId, setAssignmentId] = useState("");
  const [groupId, setGroupId] = useState("");
  const [roleId, setRoleId] = useState("");
  const [privileges, setPrivileges] = useState<Privilege[]>([]);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [panel, setPanel] = useState<"assignments" | "roles" | "scopes">(
    "assignments",
  );
  const [working, setWorking] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [dirty, setDirty] = useState(false);
  const reportHeading = useRef<HTMLHeadingElement>(null);
  const pending = useRef<AbortController | null>(null);
  const mutationKey = useStableMutationIntentKey("authorization-assignment");
  const change = useApplicationSecurityChange(app, catalog, (notice) => {
    setMessage(notice);
    void load();
  });
  const selectedRole = config?.roles.find((row) => row.roleId === roleId);
  const busy = working || change.busy;
  const locked = busy || change.original;
  const canChange = Boolean(
    config?.complete &&
      (panel === "roles"
        ? config.canManageRoles
        : panel === "scopes"
          ? config.canManageScopes
          : config.canManageAssignments) &&
      catalog.functions[PREVIEW] &&
      catalog.functions[APPLY],
  );
  useUnsavedWork(
    "application-authorization-assignment",
    "Unsubmitted application access assignment",
    dirty && !change.original,
  );
  useEffect(() => () => pending.current?.abort(), []);
  useEffect(() => {
    if (preview) reportHeading.current?.focus();
  }, [preview]);

  function select(assignment?: Assignment) {
    setAssignmentId(assignment?.assignmentId || "");
    setGroupId(assignment?.groupId || "");
    setRoleId(assignment?.roleId || "");
    setPrivileges(assignment?.privileges || []);
    setDirty(false);
    setPreview(null);
    setError("");
  }
  function edit() {
    setDirty(true);
    setPreview(null);
    setMessage("");
    setError("");
  }
  function begin() {
    pending.current?.abort();
    const controller = new AbortController();
    pending.current = controller;
    setWorking(true);
    setError("");
    return controller.signal;
  }

  async function load() {
    const signal = begin();
    select();
    setConfig(null);
    try {
      const next = await readSecurityProgram<Configuration>(
        app,
        CONFIG,
        {},
        signal,
      );
      if (signal.aborted) return;
      if (!validConfig(next, app))
        throw new Error("Invalid assignment configuration");
      setConfig(next);
    } catch {
      if (!signal.aborted)
        setError(
          "The assignment configuration could not be loaded. Check current access and retry.",
        );
    } finally {
      if (!signal.aborted) setWorking(false);
    }
  }

  async function loadMore(collection: Collection) {
    if (!config || locked || !config.nextAfter[collection]) return;
    const after = config.nextAfter[collection];
    const signal = begin();
    setPreview(null);
    try {
      const page = await readSecurityProgram<Configuration>(
        app,
        CONFIG,
        {
          collection,
          after,
          expectedSnapshot: config.snapshotToken,
          limit: 100,
        },
        signal,
      );
      if (signal.aborted) return;
      if (
        !validConfig(page, app) ||
        page.snapshotToken !== config.snapshotToken ||
        page.revision !== config.revision ||
        page.authorizationMode !== config.authorizationMode ||
        page.nextAfter[collection] === after
      )
        throw new Error("Invalid or expired continuation");
      const items = [...config[collection], ...page[collection]];
      const ids = items.map((item) =>
        Reflect.get(item, collectionKeys[collection]),
      );
      if (new Set(ids).size !== ids.length)
        throw new Error("Repeated item in continuation");
      const nextAfter = {
        ...config.nextAfter,
        [collection]: page.nextAfter[collection],
      };
      setConfig({
        ...config,
        [collection]: items,
        nextAfter,
        complete: Object.values(nextAfter).every((cursor) => cursor === null),
      });
    } catch {
      if (!signal.aborted) {
        setConfig(null);
        select();
        setError(
          "The configuration could not be continued at the same revision. Read assignments again.",
        );
      }
    } finally {
      if (!signal.aborted) setWorking(false);
    }
  }

  async function review(remove: boolean) {
    if (!config || !canChange || locked) return;
    if (remove && !assignmentId) return;
    if (!remove && (!groupId || !selectedRole || !privileges.length)) return;
    const changes: Change[] = [
      remove
        ? { op: "removeAssignment", assignmentId }
        : {
            op: "putAssignment",
            assignmentId: assignmentId || `assignment-${crypto.randomUUID()}`,
            groupId,
            roleId,
            privileges,
          },
    ];
    await previewChanges(changes);
  }

  async function previewChanges(changes: Change[]) {
    if (!config || !canChange || locked) return;
    const signal = begin();
    setPreview(null);
    try {
      const result = await readSecurityProgram<Preview>(
        app,
        PREVIEW,
        { expectedRevision: config.revision, changes },
        signal,
      );
      if (signal.aborted) return;
      if (
        result?.expectedRevision !== config.revision ||
        result.workspaceId !== app.workspaceId ||
        result.applicationId !== app.applicationId ||
        result.authorizationMode !== config.authorizationMode ||
        canonicalJson(result.changes) !== canonicalJson(changes) ||
        !validTemplatePreview(result, changes) ||
        !validDutyPreview(
          config,
          changes,
          result.impact?.reviewedWorkflowDuties,
        ) ||
        !Array.isArray(result.impact?.affectedAssignments) ||
        (result.impact.requesterBenefit !== undefined &&
          !validRequesterBenefit(result.impact.requesterBenefit)) ||
        !result.impact.affectedAssignments.every(
          (id) => typeof id === "string",
        ) ||
        !/^[a-f0-9]{64}$/.test(result.reviewDigest)
      )
        throw new Error("Invalid review response");
      setPreview(result);
      setDirty(true);
    } catch (reason) {
      if (!signal.aborted) {
        setError(
          reason instanceof ApiError && reason.kind === "conflict"
            ? "The configuration changed. Reload assignments and review the current change."
            : "The server could not approve this preview. Review your access, group, role and selected scopes.",
        );
      }
    } finally {
      if (!signal.aborted) setWorking(false);
    }
  }

  async function apply() {
    if (
      !preview ||
      !config ||
      !canChange ||
      locked ||
      preview.expectedRevision !== config.revision
    )
      return;
    const body = {
      workspaceId: app.workspaceId,
      applicationId: app.applicationId,
      confirmed: true,
      idempotencyKey: mutationKey(preview),
      program: {
        languageVersion: 2,
        function: APPLY,
        arguments: {
          expectedRevision: preview.expectedRevision,
          changes: preview.changes,
          reviewDigest: preview.reviewDigest,
        },
      },
    };
    await change.submit(body, "application authorization");
  }

  const selectedGroup = config?.eligibleGroups.find(
    (group) => group.groupId === groupId,
  );
  const reviewedChange = preview?.changes[0];
  const existingAssignment = config?.assignments.find(
    (item) => item.assignmentId === assignmentId,
  );
  function chooseAssignment(id: string) {
    if (dirty && !window.confirm("Discard the current assignment draft?"))
      return;
    select(config?.assignments.find((item) => item.assignmentId === id));
  }
  return (
    <section
      className="panel capability-activity security-workspace"
      aria-labelledby="authorization-heading"
    >
      <div className="section-heading-row">
        <div>
          <h2 id="authorization-heading">Group role assignments</h2>
          <p>
            Review which role and resource scopes each group receives in{" "}
            {app.name}.
          </p>
        </div>
        <button
          type="button"
          disabled={locked}
          onClick={() => {
            if (
              !dirty ||
              window.confirm("Discard the assignment draft and reload?")
            )
              void load();
          }}
        >
          {config ? "Reload assignments" : "Read assignments"}
        </button>
      </div>
      <SecurityChangeOutcome securityChange={change} busy={busy} />
      {message && <p role="status">{message}</p>}
      {working && (
        <p role="status">Checking the current authorization configuration…</p>
      )}
      {error && <p role="alert">{error}</p>}
      {config && (
        <>
          <p>
            Configuration revision {config.revision}.{" "}
            {config.authorizationMode === "legacy"
              ? "Staged group assignments. Existing grants currently govern access."
              : "Group assignments govern access."}
          </p>
          {!config.complete && (
            <>
              <p role="status">
                Only part of this configuration has been loaded. Load the
                remaining pages before editing.
              </p>
              {(Object.keys(collectionKeys) as Collection[])
                .filter((name) => config.nextAfter[name])
                .map((name) => (
                  <button
                    key={name}
                    type="button"
                    disabled={locked}
                    onClick={() => void loadMore(name)}
                  >
                    Load more{" "}
                    {name === "eligibleGroups" ? "eligible groups" : name}
                  </button>
                ))}
            </>
          )}
          <nav
            className="workspace-section-nav"
            aria-label="Authorization configuration"
          >
            {(["assignments", "roles", "scopes"] as const).map((id) => (
              <button
                type="button"
                disabled={locked}
                aria-current={panel === id ? "page" : undefined}
                key={id}
                onClick={() => {
                  if (
                    id === panel ||
                    (dirty && !window.confirm("Discard the current draft?"))
                  )
                    return;
                  select();
                  setPanel(id);
                }}
              >
                {
                  {
                    assignments: "Assignments",
                    roles: "Roles",
                    scopes: "Resource scopes",
                  }[id]
                }
              </button>
            ))}
          </nav>
          {panel !== "assignments" && (
            <AuthorizationDefinitions
              key={panel}
              panel={panel}
              app={app}
              catalog={catalog}
              config={config}
              locked={locked}
              editable={canChange}
              dirty={dirty}
              edit={edit}
              onReset={() => select()}
              onPreview={(item) => void previewChanges([item])}
            />
          )}
          {panel === "assignments" && (
            <>
              <label className="form-field">
                Assignment
                <select
                  disabled={locked}
                  value={assignmentId}
                  onChange={(event) => chooseAssignment(event.target.value)}
                >
                  <option value="">
                    {canChange
                      ? "New group assignment"
                      : "Choose an assignment"}
                  </option>
                  {config.assignments.map((item) => {
                    const group = config.eligibleGroups.find(
                      (row) => row.groupId === item.groupId,
                    );
                    const role = config.roles.find(
                      (row) => row.roleId === item.roleId,
                    );
                    return (
                      <option key={item.assignmentId} value={item.assignmentId}>
                        {group ? groupLabel(group) : "Unavailable group"} ·{" "}
                        {role?.name || "Unavailable role"} · {item.assignmentId}
                      </option>
                    );
                  })}
                </select>
              </label>
              {(canChange || assignmentId) && (
                <fieldset disabled={locked || !canChange}>
                  <legend>Bind a group, role and resource scopes</legend>
                  <label className="form-field">
                    Eligible group
                    <select
                      value={groupId}
                      onChange={(e) => {
                        edit();
                        setGroupId(e.target.value);
                      }}
                    >
                      <option value="">Select a group</option>
                      {groupId && !selectedGroup && (
                        <option value={groupId} disabled>
                          Group unavailable
                        </option>
                      )}
                      {config.eligibleGroups.map((group) => (
                        <option
                          value={group.groupId}
                          key={group.groupId}
                          disabled={!group.groupName && !group.displayName}
                        >
                          {groupLabel(group)}
                          {group.groupName &&
                          group.displayName &&
                          group.groupName !== group.displayName
                            ? ` (${group.groupName})`
                            : ""}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="form-field">
                    Application role
                    <select
                      value={roleId}
                      onChange={(e) => {
                        edit();
                        setRoleId(e.target.value);
                        setPrivileges([]);
                      }}
                    >
                      <option value="">Select a role</option>
                      {config.roles.map((role) => (
                        <option key={role.roleId} value={role.roleId}>
                          {role.name}
                        </option>
                      ))}
                    </select>
                  </label>
                  {selectedRole?.actions.map((action) => {
                    const kinds =
                      config.actions.find((row) => row.action === action)
                        ?.scopeKinds || [];
                    const available = config.scopes.filter((scope) =>
                      kinds.includes(scope.scopeKind),
                    );
                    return (
                      <fieldset key={action}>
                        <legend>{action}</legend>
                        {available.length === 0 && (
                          <p>No compatible resource scope is available.</p>
                        )}
                        {available.map((scope) => (
                          <label
                            className="review-checkbox"
                            key={scope.scopeId}
                          >
                            <input
                              type="checkbox"
                              disabled={
                                !config.actions.find(
                                  (item) => item.action === action,
                                )?.canDelegate
                              }
                              checked={privileges.some(
                                (p) =>
                                  p.action === action &&
                                  p.scopeId === scope.scopeId,
                              )}
                              onChange={(e) => {
                                edit();
                                setPrivileges(
                                  e.target.checked
                                    ? [
                                        ...privileges,
                                        { action, scopeId: scope.scopeId },
                                      ]
                                    : privileges.filter(
                                        (p) =>
                                          p.action !== action ||
                                          p.scopeId !== scope.scopeId,
                                      ),
                                );
                              }}
                            />
                            {scope.name} · {scopeLabel(scope)}
                          </label>
                        ))}
                      </fieldset>
                    );
                  })}
                  {canChange && (
                    <button
                      type="button"
                      disabled={
                        !selectedGroup || !selectedRole || !privileges.length
                      }
                      onClick={() => void review(false)}
                    >
                      Preview assignment
                    </button>
                  )}
                  {canChange && assignmentId && (
                    <button type="button" onClick={() => void review(true)}>
                      Preview removal
                    </button>
                  )}
                </fieldset>
              )}
            </>
          )}
          {reviewedChange && (
            <section className="program-inspector">
              <h3 ref={reportHeading} tabIndex={-1}>
                Review authorization change
              </h3>
              <p>Configuration revision {config.revision}</p>
              {preview.impact.requesterBenefit && (
                <RequesterBenefitDetails
                  config={config}
                  preview
                  evidence={{
                    authorizationMode: preview.authorizationMode,
                    requesterBenefit: preview.impact.requesterBenefit,
                  }}
                />
              )}
              <p>
                Assignments affected by this change ·{" "}
                {preview.impact.affectedAssignments.length}
              </p>
              {preview.impact.affectedAssignments.length > 0 && (
                <details>
                  <summary>View affected assignments</summary>
                  <ul>
                    {preview.impact.affectedAssignments.map((id) => (
                      <li key={id}>{id}</li>
                    ))}
                  </ul>
                </details>
              )}
              {(reviewedChange.op === "putAssignment" ||
                reviewedChange.op === "removeAssignment") && (
                <>
                  <p>
                    {reviewedChange.op === "removeAssignment"
                      ? "Remove the selected assignment."
                      : "Assign the selected role and scopes."}
                  </p>
                  {existingAssignment && (
                    <>
                      <h4>Current assignment</h4>
                      <AssignmentContents
                        assignment={existingAssignment}
                        config={config}
                      />
                    </>
                  )}
                  {reviewedChange.op === "putAssignment" && (
                    <>
                      <h4>Proposed assignment</h4>
                      <AssignmentContents
                        assignment={reviewedChange}
                        config={config}
                      />
                    </>
                  )}
                </>
              )}
              {reviewedChange.op === "adoptRoleTemplate" &&
                preview.impact.reviewedRoleTemplates?.map((item) => (
                  <ReviewedTemplateSummary key={item.roleId} item={item} />
                ))}
              {(reviewedChange.op === "putRole" ||
                reviewedChange.op === "removeRole") && (
                <>
                  <p>
                    {reviewedChange.op === "removeRole"
                      ? "Remove role"
                      : "Save role"}{" "}
                    ·{" "}
                    {reviewedChange.op === "putRole"
                      ? reviewedChange.name
                      : config.roles.find(
                          (item) => item.roleId === reviewedChange.roleId,
                        )?.name}
                  </p>
                  {reviewedChange.op === "putRole" && (
                    <p>Actions · {reviewedChange.actions.join(", ")}</p>
                  )}
                  {preview.impact.reviewedWorkflowDuties?.map((item) => (
                    <div key={item.roleId}>
                      {item.addedDuties.length > 0 && (
                        <p>
                          Planning duties to add · {item.addedDuties.join(", ")}
                        </p>
                      )}
                      {item.removedDuties.length > 0 && (
                        <p>
                          Planning duties to remove ·{" "}
                          {item.removedDuties.join(", ")}
                        </p>
                      )}
                    </div>
                  ))}
                  <p>
                    Existing assignments referencing this role ·{" "}
                    {
                      config.assignments.filter(
                        (row) => row.roleId === reviewedChange.roleId,
                      ).length
                    }
                  </p>
                </>
              )}
              {(reviewedChange.op === "putScope" ||
                reviewedChange.op === "removeScope") && (
                <>
                  <p>
                    {reviewedChange.op === "removeScope"
                      ? "Remove scope"
                      : "Save scope"}{" "}
                    ·{" "}
                    {reviewedChange.op === "putScope"
                      ? reviewedChange.name
                      : config.scopes.find(
                          (item) => item.scopeId === reviewedChange.scopeId,
                        )?.name}
                  </p>
                  {reviewedChange.op === "putScope" && (
                    <p>Selection · {scopeLabel(reviewedChange)}</p>
                  )}
                  <p>
                    Existing assignments referencing this scope ·{" "}
                    {
                      config.assignments.filter((row) =>
                        row.privileges.some(
                          (p) => p.scopeId === reviewedChange.scopeId,
                        ),
                      ).length
                    }
                  </p>
                </>
              )}
              <button
                type="button"
                className="primary"
                disabled={locked}
                onClick={() => void apply()}
              >
                Apply reviewed change
              </button>
            </section>
          )}
        </>
      )}
    </section>
  );
}
