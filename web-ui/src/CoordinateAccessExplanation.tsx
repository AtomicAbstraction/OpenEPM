import { useEffect, useRef, useState } from "react";
import { canonicalJson, readProgram, readSecurityProgram } from "./api";
import {
  activeFactDimensions,
  collectCapabilityDimensions,
  memberListArguments,
} from "./metadata-data";
import type { MetadataDimension, MetadataMember } from "./metadata-data";
import type { ApplicationSummary } from "./types";

import { ResourceAccessRoster } from "./ResourceAccessRoster";
import { validWorkflowDuties } from "./authorization-config";

export const explainAccess = "security.application.access.explain";
type Source = {
  assignmentId: string;
  groupId: string;
  roleId: string;
  scopeId: string;
  action: string;
  assignmentRevision: number;
  scopeRevision: number;
  workflowDuties?: string[];
};
type Decision = {
  workspaceId: string;
  applicationId: string;
  subjectId: string;
  coordinate: Record<string, string>;
  action: string;
  asOf: string;
  entitlement: "granted" | "denied" | "unknown";
  operation: "allowed" | "blocked" | "unknown";
  businessState: string;
  reason: string;
  origins: Source[];
  originsComplete: boolean;
};
type Person = {
  subjectId: string;
  displayName: string | null;
  username: string | null;
};
type MemberPage = {
  rows: MetadataMember[];
  nextAfterMemberId: string | null;
  metadataRevision: number;
  nextPageToken?: string | null;
};
const businessState: Record<string, string> = {
  open: "Open for a numeric Set",
  locked: "Locked by the planning workflow",
  planning_policy_blocked: "Active planning policy blocks Set",
  workflow_role_unbound: "No matching assignment supplies a planning duty",
  not_applicable: "Read access is independent of the write lock",
  unknown: "Unverified",
};
const reasonText: Record<string, string> = {
  unavailable_or_outside_review_scope:
    "The subject or coordinate is unavailable in your review scope.",
  unsupported_authorization_model: "This model does not use group assignments.",
  application_entry_required:
    "The person's groups do not grant entry to this application.",
  no_complete_assignment:
    "No single assignment covers the requested action and coordinate.",
  scope_allows_read: "A complete assignment covers this read.",
  application_or_workspace_not_writable:
    "The application or workspace currently prevents writes.",
  intersection_locked: "The coordinate is covered by an active planning lock.",
  planning_policy_blocks_set:
    "The current planning rules block setting the numeric input.",
  planning_state_unavailable:
    "The current planning state could not be confirmed.",
  workflow_role_binding_unavailable:
    "The assigned privileges cover the coordinate. The active planning policy needs a verified workflow role on the same assignment before this person can write.",
  scope_and_planning_allow_set:
    "A complete assignment and the current planning state allow setting a numeric input.",
};

export function CoordinateAccessExplanation({
  app,
  revision,
  people,
  activePerson,
  canReviewResource = false,
  canExplainPerson = true,
}: {
  app: ApplicationSummary;
  revision: number;
  people: Person[];
  activePerson?: string;
  canReviewResource?: boolean;
  canExplainPerson?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [dimensions, setDimensions] = useState<MetadataDimension[]>([]);
  const [coordinate, setCoordinate] = useState<Record<string, string>>({});
  const [axis, setAxis] = useState("");
  const [members, setMembers] = useState<MemberPage | null>(null);
  const [subject, setSubject] = useState("");
  const [action, setAction] = useState("facts.write");
  const [decision, setDecision] = useState<Decision | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const request = useRef<AbortController | null>(null);
  const person =
    activePerson ||
    (people.some((p) => p.subjectId === subject) ? subject : "");
  const visibleDecision = decision?.subjectId === person ? decision : null;
  useEffect(() => () => request.current?.abort(), []);
  function reset() {
    request.current?.abort();
    setBusy(false);
    setError("");
    setDecision(null);
  }
  function begin() {
    reset();
    const current = new AbortController();
    request.current = current;
    setBusy(true);
    return current;
  }
  async function showDimensions() {
    const current = begin();
    setDimensions([]);
    setCoordinate({});
    setAxis("");
    setMembers(null);
    try {
      const result = await collectCapabilityDimensions(async (args) => {
        const page = await readProgram<{
          rows: MetadataDimension[];
          metadataRevision: number;
          nextAfterDimensionId: string | null;
          nextPageToken?: string | null;
        }>(app, "metadata.dimension.list", args, current.signal);
        if (page.metadataRevision !== revision)
          throw new Error("Metadata changed");
        return page;
      });
      if (current.signal.aborted) return;
      const choices = activeFactDimensions(result.rows);
      if (!choices.length || choices.length > 128)
        throw new Error("No bounded layout");
      setDimensions(choices);
    } catch {
      if (!current.signal.aborted)
        setError(
          "The current fact dimensions are unavailable. Refresh the application and retry.",
        );
    } finally {
      if (!current.signal.aborted) setBusy(false);
    }
  }
  async function chooseMembers(dimension: string, more = false) {
    const current = begin();
    const after = more ? members?.nextAfterMemberId : null;
    const token = more ? members?.nextPageToken : null;
    setAxis(dimension);
    setMembers(null);
    try {
      const page = await readProgram<MemberPage>(
        app,
        "metadata.member.list",
        memberListArguments(dimension, after, revision, token),
        current.signal,
      );
      if (current.signal.aborted) return;
      if (
        page.metadataRevision !== revision ||
        !Array.isArray(page.rows) ||
        page.rows.length > 100 ||
        !page.rows.every(
          (m) =>
            m && typeof m.member_id === "string" && typeof m.name === "string",
        ) ||
        (page.nextAfterMemberId !== null &&
          (!page.nextAfterMemberId || page.nextAfterMemberId === after))
      )
        throw new Error("Invalid page");
      setMembers(page);
    } catch {
      if (!current.signal.aborted)
        setError(
          "The member choices are unavailable or have changed. Refresh the dimensions.",
        );
    } finally {
      if (!current.signal.aborted) setBusy(false);
    }
  }
  async function inspect() {
    if (
      !person ||
      !dimensions.length ||
      !dimensions.every(
        (d) =>
          Object.hasOwn(coordinate, d.dimension_id) &&
          coordinate[d.dimension_id],
      )
    )
      return;
    const current = begin();
    try {
      const result = await readSecurityProgram<Decision>(
        app,
        explainAccess,
        {
          subjectId: person,
          action,
          coordinate,
          expectedMetadataRevision: revision,
        },
        current.signal,
      );
      if (current.signal.aborted) return;
      if (
        result.workspaceId !== app.workspaceId ||
        result.applicationId !== app.applicationId ||
        result.subjectId !== person ||
        result.action !== action ||
        canonicalJson(result.coordinate) !== canonicalJson(coordinate) ||
        !Number.isFinite(Date.parse(result.asOf)) ||
        !["granted", "denied", "unknown"].includes(result.entitlement) ||
        !["allowed", "blocked", "unknown"].includes(result.operation) ||
        !Object.hasOwn(businessState, result.businessState) ||
        !Object.hasOwn(reasonText, result.reason) ||
        typeof result.originsComplete !== "boolean" ||
        !Array.isArray(result.origins) ||
        result.origins.length > 100 ||
        !result.origins.every(
          (r) =>
            r &&
            [r.assignmentId, r.groupId, r.roleId, r.scopeId, r.action].every(
              (v) => typeof v === "string",
            ) &&
            Number.isSafeInteger(r.scopeRevision) &&
            (r.workflowDuties === undefined ||
              (r.action === "facts.write" &&
                validWorkflowDuties(r.workflowDuties))) &&
            Number.isSafeInteger(r.assignmentRevision),
        )
      )
        throw new Error("Invalid report");
      setDecision(result);
    } catch {
      if (!current.signal.aborted)
        setError(
          "The access decision is unavailable or has changed. Inspect again.",
        );
    } finally {
      if (!current.signal.aborted) setBusy(false);
    }
  }
  return (
    <section aria-labelledby="coordinate-access-title">
      <h3 id="coordinate-access-title">Explain access to a coordinate</h3>
      <button
        type="button"
        aria-expanded={open}
        onClick={() => {
          reset();
          setOpen(!open);
          if (!open) void showDimensions();
        }}
      >
        {open ? "Close coordinate review" : "Choose a coordinate"}
      </button>
      {open && (
        <>
          <label>
            Resource action
            <select
              value={action}
              onChange={(event) => {
                reset();
                setAction(event.target.value);
              }}
            >
              <option value="facts.write">Set a raw numeric input</option>
              <option value="facts.read">Read a numeric input</option>
            </select>
          </label>
          {dimensions.map((d) => (
            <div key={d.dimension_id}>
              <button
                type="button"
                onClick={() => void chooseMembers(d.dimension_id)}
              >
                Choose {d.name} member
              </button>
              {Object.hasOwn(coordinate, d.dimension_id) &&
                coordinate[d.dimension_id] && (
                  <code> {coordinate[d.dimension_id]}</code>
                )}
              {axis === d.dimension_id && members && (
                <label>
                  Member of {d.name}
                  <select
                    value={coordinate[axis] || ""}
                    onChange={(e) => {
                      reset();
                      setCoordinate({ ...coordinate, [axis]: e.target.value });
                    }}
                  >
                    <option value="">Choose a member</option>
                    {members.rows
                      .filter((m) => m.status === "Active")
                      .map((m) => (
                        <option key={m.member_id} value={m.member_id}>
                          {m.name} · {m.member_id}
                        </option>
                      ))}
                  </select>
                </label>
              )}
              {axis === d.dimension_id && members?.nextAfterMemberId && (
                <button
                  type="button"
                  onClick={() => void chooseMembers(axis, true)}
                >
                  Next members
                </button>
              )}
            </div>
          ))}
          {canReviewResource &&
            dimensions.length > 0 &&
            dimensions.every(
              (d) =>
                Object.hasOwn(coordinate, d.dimension_id) &&
                coordinate[d.dimension_id],
            ) && (
              <ResourceAccessRoster
                key={canonicalJson([action, coordinate])}
                app={app}
                revision={revision}
                resource={{ action, coordinate }}
              />
            )}
          {canExplainPerson && !activePerson && (
            <label>
              Person to inspect
              <select
                value={person}
                onChange={(e) => {
                  reset();
                  setSubject(e.target.value);
                }}
              >
                <option value="">
                  Select a person from the current application roster
                </option>
                {people.map((p) => (
                  <option key={p.subjectId} value={p.subjectId}>
                    {p.displayName || p.username || p.subjectId} · {p.subjectId}
                  </option>
                ))}
              </select>
            </label>
          )}
          {canExplainPerson && (
            <button
              type="button"
              disabled={
                busy ||
                !person ||
                !dimensions.length ||
                !dimensions.every(
                  (d) =>
                    Object.hasOwn(coordinate, d.dimension_id) &&
                    coordinate[d.dimension_id],
                )
              }
              onClick={() => void inspect()}
            >
              Inspect decision
            </button>
          )}
          {busy && <p role="status">Reading current access information…</p>}
          {error && <p role="alert">{error}</p>}
          {visibleDecision && (
            <div aria-label="Coordinate access decision">
              <p>
                Dimensional entitlement ·{" "}
                <strong>{visibleDecision.entitlement}</strong>
              </p>
              <p>
                Requested operation ·{" "}
                <strong>{visibleDecision.operation}</strong>
              </p>
              <p>{businessState[visibleDecision.businessState]}</p>
              <p>{reasonText[visibleDecision.reason]}</p>
              <p>
                As of{" "}
                <time dateTime={visibleDecision.asOf}>
                  {new Date(visibleDecision.asOf).toLocaleString()}
                </time>
              </p>
              {visibleDecision.origins.length > 0 && (
                <>
                  <h4>Matching assignment sources</h4>
                  <ul>
                    {visibleDecision.origins.map((r) => (
                      <li
                        key={JSON.stringify([
                          r.assignmentId,
                          r.action,
                          r.scopeId,
                        ])}
                      >
                        {r.action} · group <code>{r.groupId}</code> · role{" "}
                        <code>{r.roleId}</code> · scope <code>{r.scopeId}</code>{" "}
                        (revision {r.scopeRevision}) · assignment{" "}
                        <code>{r.assignmentId}</code> (revision{" "}
                        {r.assignmentRevision})
                        {r.workflowDuties !== undefined && (
                          <div>
                            Linked planning duties ·{" "}
                            {r.workflowDuties.join(", ") || "none"}
                          </div>
                        )}
                      </li>
                    ))}
                  </ul>
                </>
              )}
              {!visibleDecision.originsComplete && (
                <p>Assignment evidence is incomplete.</p>
              )}
            </div>
          )}
        </>
      )}
    </section>
  );
}
