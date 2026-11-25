import { useState } from "react";
import type {
  Change,
  Configuration,
  Preview,
  ReviewedRoleTemplate,
  TemplateOrigin,
} from "./authorization-config";

const list = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((s) => typeof s === "string");
const version = (value: unknown): value is number =>
  Number.isSafeInteger(value) && Number(value) > 0;
function validOrigin(value: TemplateOrigin | undefined | null) {
  return Boolean(
    value &&
      typeof value.templateId === "string" &&
      version(value.version) &&
      typeof value.upstreamName === "string" &&
      typeof value.nameOverridden === "boolean" &&
      list(value.upstreamActions) &&
      list(value.addedActions) &&
      list(value.removedActions),
  );
}
export function validTemplateConfiguration(config: Configuration) {
  return (
    (config.roleTemplates === undefined ||
      (Array.isArray(config.roleTemplates) &&
        config.roleTemplates.every(
          (row) =>
            row &&
            typeof row.templateId === "string" &&
            typeof row.name === "string" &&
            version(row.version) &&
            list(row.actions),
        ))) &&
    Array.isArray(config.roles) &&
    config.roles.every(
      (role) =>
        role &&
        (role.templateOrigin == null || validOrigin(role.templateOrigin)),
    )
  );
}
export function validTemplatePreview(preview: Preview, changes: Change[]) {
  const expected = changes.filter((item) => item.op === "adoptRoleTemplate");
  if (!expected.length) return true;
  const actual = preview.impact?.reviewedRoleTemplates;
  return (
    Array.isArray(actual) &&
    actual.length === expected.length &&
    expected.every((change) =>
      actual.some(
        (item) =>
          item?.roleId === change.roleId &&
          validOrigin(item.origin) &&
          item.origin.templateId === change.templateId &&
          item.origin.version === change.templateVersion &&
          typeof item.name === "string" &&
          list(item.actions) &&
          (item.priorVersion === null || version(item.priorVersion)) &&
          list(item.addedActions) &&
          list(item.removedActions),
      ),
    )
  );
}

export function StarterRoleTemplates({
  config,
  selectedRoleId,
  editable,
  locked,
  onPreview,
}: {
  config: Configuration;
  selectedRoleId: string;
  editable: boolean;
  locked: boolean;
  onPreview: (change: Change) => void;
}) {
  const [choice, setChoice] = useState("");
  const role = config.roles.find((r) => r.roleId === selectedRoleId);
  const origin = role?.templateOrigin;
  const templates = config.roleTemplates || [];
  const selected = templates.find(
    (t) => t.templateId === (origin?.templateId || choice),
  );
  const allowed = new Set(
    config.actions.filter((a) => a.canDelegate).map((a) => a.action),
  );
  const merged =
    selected?.actions.filter(
      (action) => !origin?.removedActions.includes(action),
    ) || [];
  const canDelegate = [
    ...merged,
    ...(role?.actions || []),
    ...(origin?.addedActions || []),
  ].every((a) => allowed.has(a));
  if (role && !origin)
    return <p>This role is managed independently of starter templates.</p>;
  return (
    <section aria-label="Starter role templates">
      {origin ? (
        <p>
          {origin.upstreamName} template · adopted version {origin.version}
        </p>
      ) : (
        <label className="form-field">
          Starter role template
          <select
            value={choice}
            disabled={locked}
            onChange={(e) => setChoice(e.target.value)}
          >
            <option value="">Choose a starter role</option>
            {templates.map((t) => (
              <option key={t.templateId} value={t.templateId}>
                {t.name}
              </option>
            ))}
          </select>
        </label>
      )}
      {selected && (
        <>
          <p>
            {selected.name} · version {selected.version}
          </p>
          <p>Template actions · {selected.actions.join(", ")}</p>
          {origin?.nameOverridden && <p>Local role name · {role?.name}</p>}
          {origin && origin.addedActions.length > 0 && (
            <p>Locally added · {origin.addedActions.join(", ")}</p>
          )}
          {origin && origin.removedActions.length > 0 && (
            <p>Locally removed · {origin.removedActions.join(", ")}</p>
          )}
          {editable && (!origin || origin.version < selected.version) && (
            <>
              <button
                type="button"
                disabled={locked || !canDelegate}
                onClick={() =>
                  onPreview({
                    op: "adoptRoleTemplate",
                    roleId: role?.roleId || `role-${crypto.randomUUID()}`,
                    templateId: selected.templateId,
                    templateVersion: selected.version,
                  })
                }
              >
                {origin ? "Preview template update" : "Preview starter role"}
              </button>
              {!canDelegate && (
                <p>Your delegation does not cover all actions in this role.</p>
              )}
            </>
          )}
        </>
      )}
    </section>
  );
}

export function ReviewedTemplateSummary({
  item,
}: {
  item: ReviewedRoleTemplate;
}) {
  return (
    <section aria-label="Reviewed starter role">
      <p>
        {item.name} · {item.origin.upstreamName} template version{" "}
        {item.origin.version}
      </p>
      {item.priorVersion !== null && (
        <p>Previously adopted version · {item.priorVersion}</p>
      )}
      <p>Actions after adoption · {item.actions.join(", ")}</p>
      {item.addedActions.length > 0 && (
        <p>Actions added · {item.addedActions.join(", ")}</p>
      )}
      {item.removedActions.length > 0 && (
        <p>Actions removed · {item.removedActions.join(", ")}</p>
      )}
      {item.priorVersion === null && (
        <p>Group access requires a separate scoped assignment.</p>
      )}
    </section>
  );
}
