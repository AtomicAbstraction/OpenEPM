import { useEffect, useRef, useState } from "react";
import { readSecurityProgram } from "./api";
import { SavedViewScopePicker, OBJECT_CATALOG } from "./SavedViewScopePicker";
import { scopeLabel, validWorkflowDuties } from "./authorization-config";
import { StarterRoleTemplates } from "./StarterRoleTemplates";
import type { Configuration, Change } from "./authorization-config";
import type { ApplicationCatalog, ApplicationSummary } from "./types";

type Tag = {
  dimensionId: string;
  dimensionName: string;
  tagId: string;
  tagName: string;
};
type TagKey = Pick<Tag, "dimensionId" | "tagId">;
type TagPage = {
  workspaceId: string;
  applicationId: string;
  tags: Tag[];
  snapshotToken: string;
  nextAfter: TagKey | null;
};
type Props = {
  panel: "roles" | "scopes";
  app: ApplicationSummary;
  catalog: ApplicationCatalog;
  config: Configuration;
  locked: boolean;
  editable: boolean;
  dirty: boolean;
  edit: () => void;
  onReset: () => void;
  onPreview: (change: Change) => void;
};
const kindLabels: Record<string, string> = {
  entire_application: "Entire application",
  dimension_tags: "Dimensional tags",
  exact_object: "Exact object",
};
const TAG_CATALOG = "security.application.authorization.tags.list";

export function AuthorizationDefinitions({
  panel,
  app,
  catalog,
  config,
  locked,
  editable,
  dirty,
  edit,
  onReset,
  onPreview,
}: Props) {
  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const [actions, setActions] = useState<string[]>([]);
  const [duties, setDuties] = useState<string[]>([]);
  const [exactDuty, setExactDuty] = useState("");
  const [scopeKind, setKind] = useState("");
  const [selector, setSelector] = useState<Record<string, unknown>>({});
  const [tags, setTags] = useState<Tag[]>([]);
  const [nextTags, setNextTags] = useState<{
    after: TagKey;
    expectedSnapshot: string;
  } | null>(null);
  const [tagsPending, setTagsPending] = useState(false);
  const [tagsError, setTagsError] = useState("");
  const request = useRef<AbortController | null>(null);
  const rolePanel = panel === "roles";
  const noun = rolePanel ? "role" : "scope";
  const scopeKinds = new Set(
    config.actions.flatMap((action) => action.scopeKinds),
  );
  useEffect(() => () => request.current?.abort(), []);

  function choose(next: string) {
    if (dirty && !window.confirm(`Discard the current ${noun} draft?`)) return;
    const role = rolePanel
      ? config.roles.find((row) => row.roleId === next)
      : undefined;
    const scope = rolePanel
      ? undefined
      : config.scopes.find((row) => row.scopeId === next);
    onReset();
    setId(next);
    setName(role?.name || scope?.name || "");
    setActions(role?.actions || []);
    setDuties(role?.workflowDuties || []);
    setExactDuty("");
    setKind(scope?.scopeKind || "");
    setSelector(scope?.selector || {});
  }

  async function readTags(more = false) {
    const continuation = more ? nextTags : null;
    if (more && !continuation) return;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setTagsError("");
    setTagsPending(true);
    if (!more) {
      setTags([]);
      setNextTags(null);
    }
    try {
      const data = await readSecurityProgram<TagPage>(
        app,
        TAG_CATALOG,
        { limit: 50, ...continuation },
        controller.signal,
      );
      if (controller.signal.aborted) return;
      if (
        data.workspaceId !== app.workspaceId ||
        data.applicationId !== app.applicationId ||
        typeof data.snapshotToken !== "string" ||
        !data.snapshotToken ||
        (continuation &&
          data.snapshotToken !== continuation.expectedSnapshot) ||
        !Array.isArray(data.tags) ||
        data.tags.length > 50 ||
        !data.tags.every(
          (row) =>
            row &&
            [row.dimensionId, row.tagId, row.tagName, row.dimensionName].every(
              (value) => typeof value === "string" && value.length > 0,
            ),
        ) ||
        (data.nextAfter !== null &&
          (!data.tags.length ||
            !data.nextAfter ||
            data.nextAfter.tagId !== data.tags.at(-1)?.tagId ||
            data.nextAfter.dimensionId !== data.tags.at(-1)?.dimensionId ||
            (continuation &&
              data.nextAfter.tagId === continuation.after.tagId &&
              data.nextAfter.dimensionId === continuation.after.dimensionId)))
      ) {
        throw new Error("Invalid tag catalogue");
      }
      setTags(data.tags);
      setNextTags(
        data.nextAfter
          ? { after: data.nextAfter, expectedSnapshot: data.snapshotToken }
          : null,
      );
      if (!data.tags.length && !more)
        setTagsError("No eligible tags in this application.");
    } catch {
      if (!controller.signal.aborted) {
        setTags([]);
        setNextTags(null);
        setTagsError(
          "The tag choices are unavailable or have changed. Read them again.",
        );
      }
    } finally {
      if (!controller.signal.aborted) setTagsPending(false);
    }
  }
  function toggleTag(axis: string, tag: string, checked: boolean) {
    edit();
    const previous = selector[axis];
    const current = Array.isArray(previous) ? previous : [];
    const next = checked
      ? [...current, tag]
      : current.filter((value) => value !== tag);
    const copy = { ...selector };
    if (next.length) copy[axis] = next;
    else delete copy[axis];
    setSelector(copy);
  }
  function forward() {
    if (!name.trim() || !editable || locked) return;
    if (rolePanel && actions.length)
      onPreview({
        op: "putRole",
        roleId: id || `role-${crypto.randomUUID()}`,
        name: name.trim(),
        actions,
        ...(dutiesChanged ? { workflowDuties: duties } : {}),
      });
    else if (!rolePanel && scopeKind)
      onPreview({
        op: "putScope",
        scopeId: id || `scope-${crypto.randomUUID()}`,
        name: name.trim(),
        scopeKind,
        selector,
      });
  }
  const priorDuties =
    config.roles.find((role) => role.roleId === id)?.workflowDuties ?? [];
  const dutiesChanged =
    duties.length !== priorDuties.length ||
    duties.some((duty) => !priorDuties.includes(duty));
  const hasWriteActions =
    actions.includes("facts.read") && actions.includes("facts.write");
  const allowsDuty =
    config.authorizationMode === "group_assignments" && hasWriteActions;
  const editableDuties =
    editable && !locked && config.canManageWorkflowDuties === true;
  function toggleDuty(duty: string, checked: boolean) {
    if (!editableDuties || (checked && (!allowsDuty || duties.length >= 100)))
      return;
    edit();
    setDuties(
      checked
        ? [...new Set([...duties, duty])].sort()
        : duties.filter((item) => item !== duty),
    );
    setExactDuty("");
  }
  const maySave = Boolean(
    name.trim() &&
      (rolePanel
        ? actions.length && (hasWriteActions || !duties.length)
        : scopeKind === "entire_application" ||
          (scopeKind && Object.keys(selector).length > 0)),
  );
  return (
    <>
      <label className="form-field">
        {rolePanel ? "Role definition" : "Resource scope"}
        <select
          disabled={locked}
          value={id}
          onChange={(event) => choose(event.target.value)}
        >
          <option value="">
            {editable ? `New ${noun}` : `Select a ${noun}`}
          </option>
          {rolePanel
            ? config.roles.map((role) => (
                <option value={role.roleId} key={role.roleId}>
                  {role.name}
                </option>
              ))
            : config.scopes.map((scope) => (
                <option value={scope.scopeId} key={scope.scopeId}>
                  {scope.name}
                </option>
              ))}
        </select>
      </label>
      {rolePanel && config.roleTemplates?.length ? (
        <StarterRoleTemplates
          config={config}
          selectedRoleId={id}
          locked={locked}
          editable={editable}
          onPreview={(change) => {
            if (dirty && !window.confirm("Discard the current role draft?"))
              return;
            onReset();
            onPreview(change);
          }}
        />
      ) : null}
      {(editable || id) && (
        <fieldset disabled={locked || !editable}>
          <legend>{rolePanel ? "Role actions" : "Resource selection"}</legend>
          <label className="form-field">
            {rolePanel ? "Role name" : "Scope name"}
            <input
              value={name}
              maxLength={160}
              onChange={(e) => {
                edit();
                setName(e.target.value);
              }}
            />
          </label>
          {rolePanel ? (
            <>
              {config.actions.map((item) => (
                <label key={item.action} className="review-checkbox">
                  <input
                    type="checkbox"
                    disabled={!item.canDelegate}
                    checked={actions.includes(item.action)}
                    onChange={(e) => {
                      edit();
                      setActions(
                        e.target.checked
                          ? [...actions, item.action]
                          : actions.filter((action) => action !== item.action),
                      );
                    }}
                  />
                  {item.action === "planning.policy.draft"
                    ? "Draft planning policies"
                    : item.action === "planning.policy.activate"
                      ? "Activate and deactivate planning policies"
                      : item.action}
                  {!item.canDelegate && " (outside your delegation)"}
                </label>
              ))}
              {config.canManageWorkflowDuties !== undefined && (
                <fieldset disabled={!editableDuties}>
                  <legend>Planning workflow duties</legend>
                  <p>
                    A duty applies only where this same group assignment permits
                    reading and writing the cell.
                  </p>
                  {editableDuties &&
                    config.authorizationMode === "group_assignments" &&
                    !hasWriteActions && (
                      <p>
                        Select both facts.read and facts.write to add a duty.
                      </p>
                    )}
                  {[
                    ...new Set([
                      ...(config.availableWorkflowDuties ?? []),
                      ...duties,
                    ]),
                  ]
                    .sort()
                    .map((duty) => (
                      <label key={duty} className="review-checkbox">
                        <input
                          type="checkbox"
                          checked={duties.includes(duty)}
                          disabled={
                            (!allowsDuty || duties.length >= 100) &&
                            !duties.includes(duty)
                          }
                          onChange={(event) =>
                            toggleDuty(duty, event.target.checked)
                          }
                        />
                        {duty}
                      </label>
                    ))}
                  {!duties.length &&
                    !config.availableWorkflowDuties?.length && (
                      <p>No planning duties linked to this role.</p>
                    )}
                  {config.workflowDutiesComplete === false && (
                    <>
                      <label className="form-field">
                        Additional duty ID from the active policy
                        <input
                          value={exactDuty}
                          maxLength={200}
                          onChange={(event) => setExactDuty(event.target.value)}
                        />
                      </label>
                      <button
                        type="button"
                        disabled={
                          !allowsDuty ||
                          duties.length >= 100 ||
                          !validWorkflowDuties([exactDuty]) ||
                          duties.includes(exactDuty)
                        }
                        onClick={() => toggleDuty(exactDuty, true)}
                      >
                        Add duty by ID
                      </button>
                    </>
                  )}
                </fieldset>
              )}
            </>
          ) : (
            <>
              <label className="form-field">
                Selection type
                <select
                  value={scopeKind}
                  onChange={(e) => {
                    edit();
                    setKind(e.target.value);
                    setSelector({});
                  }}
                >
                  <option value="">Choose a selection type</option>
                  {Object.entries(kindLabels)
                    .filter(
                      ([kind]) => scopeKinds.has(kind) || kind === scopeKind,
                    )
                    .map(([kind, label]) => (
                      <option key={kind} value={kind}>
                        {label}
                      </option>
                    ))}
                </select>
              </label>
              {scopeKind === "dimension_tags" && (
                <>
                  {Object.keys(selector).length > 0 && (
                    <p>Selected tags · {scopeLabel({ scopeKind, selector })}</p>
                  )}
                  {catalog.functions[TAG_CATALOG] ? (
                    <button
                      type="button"
                      disabled={tagsPending}
                      onClick={() => void readTags()}
                    >
                      Read available dimension tags
                    </button>
                  ) : (
                    <p>
                      The current catalogue does not expose a dimension tag
                      picker.
                    </p>
                  )}
                  {tagsPending && <p role="status">Reading dimension tags…</p>}
                  {tagsError && <p role="status">{tagsError}</p>}
                  {Array.from(new Set(tags.map((tag) => tag.dimensionId))).map(
                    (axis) => (
                      <fieldset key={axis}>
                        <legend>
                          {
                            tags.find((tag) => tag.dimensionId === axis)
                              ?.dimensionName
                          }{" "}
                          · {axis}
                        </legend>
                        {tags
                          .filter((tag) => tag.dimensionId === axis)
                          .map((tag) => (
                            <label key={tag.tagId}>
                              <input
                                type="checkbox"
                                checked={
                                  Array.isArray(selector[axis]) &&
                                  (selector[axis] as string[]).includes(
                                    tag.tagId,
                                  )
                                }
                                onChange={(event) =>
                                  toggleTag(
                                    axis,
                                    tag.tagId,
                                    event.target.checked,
                                  )
                                }
                              />
                              {tag.tagName}
                              {tag.tagName !== tag.tagId && ` · ${tag.tagId}`}
                            </label>
                          ))}
                      </fieldset>
                    ),
                  )}
                  {nextTags && (
                    <button
                      type="button"
                      disabled={tagsPending}
                      onClick={() => void readTags(true)}
                    >
                      Next eligible tags
                    </button>
                  )}
                </>
              )}
              {scopeKind === "exact_object" && (
                <SavedViewScopePicker
                  key={JSON.stringify([
                    app.workspaceId,
                    app.applicationId,
                    config.snapshotToken,
                  ])}
                  app={app}
                  available={Boolean(catalog.functions[OBJECT_CATALOG])}
                  selector={selector}
                  onSelect={(next) => {
                    edit();
                    setSelector(next);
                  }}
                />
              )}
            </>
          )}
          {editable && (
            <button type="button" disabled={!maySave} onClick={forward}>
              Preview {noun}
            </button>
          )}
          {editable && id && (
            <button
              type="button"
              onClick={() =>
                onPreview(
                  rolePanel
                    ? { op: "removeRole", roleId: id }
                    : { op: "removeScope", scopeId: id },
                )
              }
            >
              Preview {noun} removal
            </button>
          )}
        </fieldset>
      )}
    </>
  );
}
