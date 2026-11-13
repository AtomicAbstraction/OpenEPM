import { Breadcrumbs } from "./Breadcrumbs";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { readProgram } from "./api";
import { AttributeCatalog } from "./AttributeCatalog";
import { MetadataCreate } from "./MetadataCreate";
import { MetadataMemberGrid } from "./MetadataMemberGrid";
import { MetadataMaintenance } from "./MetadataMaintenance";
import { MetadataRelationships } from "./MetadataRelationships";
import { MetadataSecurityStringEditor } from "./MetadataSecurityStringEditor";
import { SecurityTagCatalog } from "./SecurityTagCatalog";
import { SemanticAttributes } from "./SemanticAttributes";
import {
  collectCapabilityDimensions,
  collectCapabilityMembers,
} from "./metadata-data";
import type { MetadataDimension, MetadataMember } from "./metadata-data";
import type {
  MetadataDestination,
  MetadataNavigationDimension,
  MetadataSection,
} from "./metadata-navigation";
import type { ApplicationCatalog, ApplicationSummary } from "./types";
import "./metadata-workspace.css";

const sections: Record<
  MetadataSection,
  { title: string; description: string; requiresDimension: boolean }
> = {
  dimensions: {
    title: "Dimensions",
    description:
      "Start with the structure of your model. Open a dimension to work with its members, relationships and properties.",
    requiresDimension: false,
  },
  members: {
    title: "Members",
    description:
      "Work with the items in this dimension. Select a member to edit its properties; use the columns to inspect attributes and access.",
    requiresDimension: true,
  },
  relationships: {
    title: "Relationships",
    description:
      "Organize parent–child placements. A member can have more than one parent, so each placement has its own identity.",
    requiresDimension: true,
  },
  attributes: {
    title: "Attribute definitions",
    description:
      "Define the additional fields your model needs. Choose whether a field describes dimensions, members or relationships.",
    requiresDimension: true,
  },
  semantics: {
    title: "Semantic guidance",
    description:
      "Describe what the model means to people and agents. These bindings explain your metadata; they do not introduce hidden business behavior.",
    requiresDimension: true,
  },
  "security-tags": {
    title: "Security tags",
    description:
      "Maintain the tags used by this dimension’s access rules. Creating a tag does not grant a user access.",
    requiresDimension: true,
  },
  settings: {
    title: "Properties & access",
    description:
      "Maintain this dimension’s name, descriptions, lifecycle and metadata access. Its stable identity stays with the model.",
    requiresDimension: true,
  },
  reference: {
    title: "Function reference",
    description:
      "Inspect the metadata functions available to your current application role. The browser and MCP use these same contracts.",
    requiresDimension: false,
  },
};

const memberSections = new Set<MetadataSection>([
  "members",
  "relationships",
  "semantics",
]);
type Snapshot = {
  dimensions: MetadataDimension[];
  dimensionId: string;
  members: MetadataMember[];
  metadataRevision: number;
  membersLoaded: boolean;
};

export function MetadataWorkspace({
  app,
  catalog,
  section = "dimensions",
  dimensionId,
  memberId,
  hierarchyId,
  onNavigate,
  hrefForDestination,
  onDimensionsChange,
  onRequestTransition,
}: {
  app?: ApplicationSummary;
  catalog: ApplicationCatalog | null;
  section?: MetadataSection;
  dimensionId?: string;
  memberId?: string;
  hierarchyId?: string;
  onNavigate: (destination: MetadataDestination) => void;
  hrefForDestination: (destination: MetadataDestination) => string;
  onDimensionsChange: (dimensions: MetadataNavigationDimension[]) => void;
  onRequestTransition: (action: () => void) => void;
}) {
  const definition = sections[section];
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("");
  const [status, setStatus] = useState("All");
  const [windowIndex, setWindowIndex] = useState(0);
  const [drawer, setDrawer] = useState<"dimension" | "member" | null>(null);
  const [memberAccessOpen, setMemberAccessOpen] = useState(false);
  const pendingMemberAccess = useRef<{
    workspaceId: string;
    applicationId: string;
    dimensionId: string;
    memberId: string;
  } | null>(null);
  const loadVersion = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const changedRef = useRef(onDimensionsChange);
  changedRef.current = onDimensionsChange;
  const canReadDimensions = Boolean(
    catalog?.functions["metadata.dimension.list"],
  );
  const canReadMembers = Boolean(catalog?.functions["metadata.member.list"]);
  const needsMembers = memberSections.has(section);
  const workspaceId = app?.workspaceId;
  const applicationId = app?.applicationId;

  const refresh = useCallback(async () => {
    if (!workspaceId || !applicationId || !canReadDimensions) return;
    const version = ++loadVersion.current;
    controller.current?.abort();
    const currentController = new AbortController();
    controller.current = currentController;
    setBusy(true);
    setError("");
    try {
      const scope = { workspaceId, applicationId };
      const result = await collectCapabilityDimensions((arguments_) =>
        readProgram(
          scope,
          "metadata.dimension.list",
          arguments_,
          currentController.signal,
        ),
      );
      const dimensions = result.rows;
      const selected = dimensionId
        ? dimensions.find((dimension) => dimension.dimension_id === dimensionId)
        : dimensions.find((dimension) => dimension.status === "Active") ||
          dimensions[0];
      const metadataRevision = result.finalPage.metadataRevision;
      let members: MetadataMember[] = [];
      const membersLoaded = Boolean(
        needsMembers && canReadMembers && selected?.status === "Active",
      );
      if (membersLoaded && selected) {
        const memberResult = await collectCapabilityMembers(
          selected.dimension_id,
          (arguments_) =>
            readProgram(
              scope,
              "metadata.member.list",
              arguments_,
              currentController.signal,
            ),
          metadataRevision,
        );
        members = memberResult.rows;
      }
      if (version !== loadVersion.current || currentController.signal.aborted)
        return;
      setSnapshot({
        dimensions,
        dimensionId: selected?.dimension_id || dimensionId || "",
        members,
        metadataRevision,
        membersLoaded,
      });
      changedRef.current(dimensions);
    } catch (reason) {
      if (version !== loadVersion.current || currentController.signal.aborted)
        return;
      setError(
        reason instanceof Error
          ? reason.message
          : "Unable to read the metadata workspace.",
      );
      // A failed read is not a fresh editing snapshot. Keep the old grid visible
      // for orientation, but do not expose its controls as ready to publish.
    } finally {
      if (version === loadVersion.current) setBusy(false);
    }
  }, [
    workspaceId,
    applicationId,
    dimensionId,
    needsMembers,
    canReadDimensions,
    canReadMembers,
  ]);

  useEffect(() => {
    setSnapshot(null);
    setError("");
    setBusy(false);
    setDrawer(null);
    setMemberAccessOpen(false);
    void refresh();
    return () => {
      ++loadVersion.current;
      controller.current?.abort();
    };
  }, [refresh]);
  useEffect(() => {
    setDrawer(null);
    const pending = pendingMemberAccess.current;
    setMemberAccessOpen(
      Boolean(
        pending &&
          section === "members" &&
          pending.workspaceId === workspaceId &&
          pending.applicationId === applicationId &&
          pending.dimensionId === dimensionId &&
          pending.memberId === memberId,
      ),
    );
    pendingMemberAccess.current = null;
  }, [workspaceId, applicationId, section, dimensionId, memberId]);
  useEffect(() => {
    setWindowIndex(0);
  }, [filter, status]);
  const dimension = snapshot?.dimensions.find(
    (item) => item.dimension_id === snapshot.dimensionId,
  );
  const selectedMember = snapshot?.members.find(
    (item) => item.member_id === memberId,
  );
  const currentDimensionId = dimension?.dimension_id || dimensionId;
  const filteredDimensions = useMemo(
    () =>
      (snapshot?.dimensions || []).filter(
        (item) =>
          (status === "All" || item.status === status) &&
          `${item.name} ${item.dimension_id} ${item.model_role} ${item.short_description || ""}`
            .toLocaleLowerCase()
            .includes(filter.trim().toLocaleLowerCase()),
      ),
    [snapshot?.dimensions, status, filter],
  );
  const start = Math.min(
    windowIndex * 50,
    Math.max(0, Math.ceil(filteredDimensions.length / 50) - 1) * 50,
  );
  const visibleDimensions = filteredDimensions.slice(start, start + 50);
  const functionNames = Object.keys(catalog?.functions || {})
    .filter((name) => name.startsWith("metadata."))
    .sort();
  const navigate = (
    targetSection: MetadataSection,
    targetDimension = currentDimensionId,
    targetMember?: string,
  ) =>
    onNavigate({
      section: targetSection,
      dimensionId: targetDimension,
      memberId: targetMember,
      hierarchyId:
        targetDimension === currentDimensionId ? hierarchyId : undefined,
    });
  const openDrawer = (kind: "dimension" | "member") =>
    onRequestTransition(() => setDrawer(kind));
  const closeDrawer = () => onRequestTransition(() => setDrawer(null));
  const contentReady = Boolean(snapshot && !error);

  return (
    <div className="page metadata-page" aria-busy={busy}>
      <Breadcrumbs
        label="Metadata breadcrumb"
        className="metadata-breadcrumb"
        items={[
          {
            label: "Metadata",
            href: hrefForDestination({ section: "dimensions" }),
            onNavigate: () => onNavigate({ section: "dimensions" }),
          },
          ...(definition.requiresDimension
            ? [
                {
                  label: dimension?.name || dimensionId || "Choose dimension",
                  ...(currentDimensionId
                    ? {
                        href: hrefForDestination({
                          section: "members",
                          dimensionId: currentDimensionId,
                          hierarchyId,
                        }),
                        onNavigate: () =>
                          onNavigate({
                            section: "members",
                            dimensionId: currentDimensionId,
                            hierarchyId,
                          }),
                      }
                    : {}),
                },
              ]
            : []),
          { label: definition.title },
        ]}
      />
      <header className="metadata-page-heading">
        <div>
          <p className="metadata-kicker">MODEL WORKSPACE</p>
          <h1 tabIndex={-1}>{definition.title}</h1>
          <p>{definition.description}</p>
        </div>
        <div className="metadata-heading-actions">
          {section !== "reference" && (
            <button className="secondary" onClick={() => navigate("reference")}>
              Function reference
            </button>
          )}
          {section === "dimensions" &&
            Boolean(catalog?.functions["metadata.dimension.create"]) && (
              <button
                className="primary"
                disabled={!contentReady || busy}
                onClick={() => openDrawer("dimension")}
              >
                + New dimension
              </button>
            )}
          {section === "members" &&
            Boolean(catalog?.functions["metadata.member.create"]) && (
              <button
                className="primary"
                disabled={
                  !contentReady || busy || dimension?.status !== "Active"
                }
                onClick={() => openDrawer("member")}
              >
                + New member
              </button>
            )}
        </div>
      </header>
      <div className="metadata-context-bar">
        {definition.requiresDimension ? (
          <label className="metadata-dimension-picker">
            <span>Dimension</span>
            <select
              aria-label="Metadata dimension"
              value={currentDimensionId || ""}
              disabled={busy || !snapshot}
              onChange={(event) => navigate(section, event.target.value)}
            >
              {!dimension && (
                <option value={dimensionId || ""}>
                  {dimensionId ? "Dimension unavailable" : "Choose a dimension"}
                </option>
              )}
              {snapshot?.dimensions.map((item) => (
                <option key={item.dimension_id} value={item.dimension_id}>
                  {item.name}
                  {item.status === "Inactive" ? " · Inactive" : ""}
                </option>
              ))}
            </select>
          </label>
        ) : (
          <div className="metadata-context-label">
            <span className="metadata-model-icon" aria-hidden="true">
              ◇
            </span>
            <div>
              <strong>{app?.name || "No application selected"}</strong>
              <span>
                {section === "dimensions"
                  ? "Dimensions define the axes of your model"
                  : "Current authorized metadata contract"}
              </span>
            </div>
          </div>
        )}
        {dimension && definition.requiresDimension && (
          <span className="metadata-context-role">
            {dimension.model_role}
            <span className={`status-chip ${dimension.status.toLowerCase()}`}>
              {dimension.status}
            </span>
          </span>
        )}
        <label className="metadata-mobile-section">
          <span>Workspace</span>
          <select
            aria-label="Metadata workspace"
            value={section}
            onChange={(event) =>
              navigate(event.target.value as MetadataSection)
            }
          >
            {Object.entries(sections).map(([key, item]) => (
              <option key={key} value={key}>
                {item.title}
              </option>
            ))}
          </select>
        </label>
        <div className="metadata-refresh">
          <span>
            {busy
              ? "Reading current model…"
              : snapshot
                ? "Current model loaded"
                : "No snapshot loaded"}
          </span>
          <button
            disabled={busy || !canReadDimensions}
            onClick={() => onRequestTransition(() => void refresh())}
          >
            {busy ? "Refreshing…" : "Refresh"}
          </button>
        </div>
      </div>
      {error && (
        <div className="inline-error metadata-load-error" role="alert">
          <strong>The model could not be refreshed.</strong>
          <p>{error}</p>
          <p>
            Your last view is retained for context. Refresh successfully before
            editing.
          </p>
        </div>
      )}
      {!app ? (
        <div className="metadata-empty">
          <h2>Select an application first</h2>
          <p>
            Metadata belongs to an application. Open an application to inspect
            its model.
          </p>
        </div>
      ) : !catalog ? (
        <div className="metadata-empty" role="status">
          Checking your access…
        </div>
      ) : !canReadDimensions && section !== "reference" ? (
        <div className="metadata-empty">
          <h2>Metadata is not available to your role</h2>
          <p>
            Your current application permissions do not include reading
            dimensions.
          </p>
        </div>
      ) : busy && !snapshot ? (
        <div className="metadata-empty" role="status">
          Loading the current metadata snapshot…
        </div>
      ) : definition.requiresDimension && !dimension && snapshot ? (
        <div className="metadata-empty">
          <h2>
            {dimensionId
              ? "This dimension is unavailable"
              : "Choose a dimension to begin"}
          </h2>
          <p>
            {dimensionId
              ? "It may have been removed or your access may have changed. Select an available dimension."
              : "Open a dimension from the directory or the navigation tree."}
          </p>
          <button onClick={() => navigate("dimensions", undefined)}>
            Open dimensions
          </button>
        </div>
      ) : (
        <div
          className={`metadata-workarea${drawer || (section === "members" && selectedMember) ? " has-inspector" : ""}`}
          inert={busy || Boolean(error) || undefined}
        >
          <section
            className="metadata-primary-pane"
            aria-label={`${definition.title} workspace`}
          >
            {section === "dimensions" && (
              <>
                <div className="metadata-grid-toolbar metadata-directory-toolbar">
                  <label>
                    <span>Find a dimension</span>
                    <input
                      type="search"
                      placeholder="Search name, ID or role…"
                      value={filter}
                      onChange={(event) => setFilter(event.target.value)}
                    />
                  </label>
                  <label>
                    <span>Status</span>
                    <select
                      value={status}
                      onChange={(event) => setStatus(event.target.value)}
                    >
                      <option>All</option>
                      <option>Active</option>
                      <option>Inactive</option>
                    </select>
                  </label>
                  <span className="metadata-result-count">
                    {filteredDimensions.length} dimensions
                  </span>
                </div>
                <div
                  className="metadata-directory-scroll"
                  role="region"
                  aria-label="Dimensions grid"
                  tabIndex={0}
                >
                  <table className="metadata-directory-grid">
                    <thead>
                      <tr>
                        <th scope="col">Dimension</th>
                        <th scope="col">Role</th>
                        <th scope="col">Status</th>
                        <th scope="col">Description</th>
                        <th scope="col">
                          <span className="sr-only">Actions</span>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {visibleDimensions.map((item) => (
                        <tr
                          key={item.dimension_id}
                          className={
                            item.dimension_id === dimensionId
                              ? "selected-row"
                              : undefined
                          }
                        >
                          <th scope="row">
                            <button
                              className="metadata-object-link"
                              onClick={() =>
                                navigate("members", item.dimension_id)
                              }
                            >
                              <span
                                className="metadata-dimension-symbol"
                                aria-hidden="true"
                              >
                                ◇
                              </span>
                              <span>
                                <strong>{item.name}</strong>
                                <small>{item.dimension_id}</small>
                              </span>
                            </button>
                          </th>
                          <td>
                            <span className="metadata-role-badge">
                              {item.model_role}
                            </span>
                          </td>
                          <td>
                            <span
                              className={`status-chip ${item.status.toLowerCase()}`}
                            >
                              {item.status}
                            </span>
                          </td>
                          <td>
                            {item.short_description || (
                              <span className="metadata-no-description">
                                No description yet
                              </span>
                            )}
                          </td>
                          <td>
                            <button
                              className="metadata-row-action"
                              aria-label={`Properties for ${item.name}`}
                              onClick={() =>
                                navigate("settings", item.dimension_id)
                              }
                            >
                              Properties <span aria-hidden="true">↗</span>
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {snapshot && !filteredDimensions.length && (
                    <div className="metadata-empty">
                      <h2>
                        {snapshot.dimensions.length
                          ? "No matching dimensions"
                          : "No dimensions are available"}
                      </h2>
                      <p>
                        {snapshot.dimensions.length
                          ? "Try a different search or status filter."
                          : "Refresh the model or check your application access."}
                      </p>
                    </div>
                  )}
                </div>
                <footer className="metadata-directory-footer">
                  <span>
                    {filteredDimensions.length
                      ? `${start + 1}–${Math.min(start + 50, filteredDimensions.length)} of ${filteredDimensions.length} dimensions`
                      : "0 dimensions"}
                  </span>
                  <div>
                    <button
                      disabled={start === 0}
                      onClick={() =>
                        setWindowIndex(Math.max(0, start / 50 - 1))
                      }
                    >
                      Previous
                    </button>
                    <button
                      disabled={start + 50 >= filteredDimensions.length}
                      onClick={() => setWindowIndex(start / 50 + 1)}
                    >
                      Next
                    </button>
                  </div>
                </footer>
                <div className="metadata-orientation">
                  <strong>A simple way to work</strong>
                  <p>
                    Open a dimension → maintain its members → connect them with
                    relationships. Attributes add detail; properties and
                    security control how the model is described and accessed.
                  </p>
                </div>
              </>
            )}
            {dimension?.status !== "Active" &&
              definition.requiresDimension &&
              section !== "settings" && (
                <div className="metadata-empty">
                  <h2>This dimension is inactive</h2>
                  <p>
                    Open its properties to review its status before working with
                    active metadata.
                  </p>
                  <button onClick={() => navigate("settings")}>
                    Open properties &amp; access
                  </button>
                </div>
              )}
            {dimension?.status === "Active" && snapshot && (
              <>
                {(section === "members" || section === "relationships") &&
                  (!canReadMembers ? (
                    <div className="metadata-empty">
                      Your role cannot read members in this workspace.
                    </div>
                  ) : !snapshot.members.length &&
                    (section === "members" ||
                      !catalog?.functions["metadata.hierarchy.list"]) ? (
                    <div className="metadata-empty">
                      <span className="metadata-empty-icon" aria-hidden="true">
                        ◇
                      </span>
                      <h2>No members in {dimension.name} yet</h2>
                      <p>
                        Add the items that belong to this dimension.
                        Relationships connect those items once they exist.
                      </p>
                      {Boolean(
                        catalog?.functions["metadata.member.create"],
                      ) && (
                        <button
                          className="primary"
                          onClick={() =>
                            section === "members"
                              ? openDrawer("member")
                              : navigate("members")
                          }
                        >
                          Add members
                        </button>
                      )}
                    </div>
                  ) : catalog?.functions["metadata.relationship.list"] ? (
                    <MetadataRelationships
                      key={`relationships:${dimension.dimension_id}:${section}`}
                      app={app}
                      catalog={catalog}
                      dimensionId={dimension.dimension_id}
                      hierarchyId={hierarchyId}
                      onHierarchyIdChange={(id) =>
                        onNavigate({
                          section,
                          dimensionId: dimension.dimension_id,
                          hierarchyId: id,
                        })
                      }
                      members={snapshot.members}
                      metadataRevision={snapshot.metadataRevision}
                      onChanged={refresh}
                      mode={section}
                      selectedMemberId={selectedMember?.member_id || ""}
                      onSelectedMemberIdChange={(id) =>
                        navigate(section, dimension.dimension_id, id)
                      }
                      onRequestTransition={onRequestTransition}
                      onEditMemberSecurityString={
                        catalog.functions[
                          "security.application.member-tags.read"
                        ]
                          ? (member) =>
                              onRequestTransition(() => {
                                if (!workspaceId || !applicationId) return;
                                if (
                                  section === "members" &&
                                  member.member_id === memberId
                                ) {
                                  setMemberAccessOpen(true);
                                  return;
                                }
                                pendingMemberAccess.current = {
                                  workspaceId,
                                  applicationId,
                                  dimensionId: dimension.dimension_id,
                                  memberId: member.member_id,
                                };
                                navigate(
                                  "members",
                                  dimension.dimension_id,
                                  member.member_id,
                                );
                              })
                          : undefined
                      }
                      securityBusy={busy}
                    />
                  ) : section === "members" ? (
                    <MetadataMemberGrid
                      app={app}
                      catalog={catalog}
                      dimensionId={dimension.dimension_id}
                      members={snapshot.members}
                      relationships={[]}
                      metadataRevision={snapshot.metadataRevision}
                      selectedMemberId={selectedMember?.member_id || ""}
                      onSelectedMember={(id) =>
                        navigate("members", dimension.dimension_id, id)
                      }
                      onChanged={refresh}
                      mode="members"
                    />
                  ) : (
                    <div className="metadata-empty">
                      Your role cannot read relationships.
                    </div>
                  ))}
                {section === "members" && memberId && !selectedMember && (
                  <p className="metadata-selection-note" role="status">
                    The selected member is no longer available in this
                    dimension. Select another row.
                  </p>
                )}
                {section === "attributes" &&
                  (catalog?.functions["metadata.attribute-definition.list"] ? (
                    <AttributeCatalog
                      contextLocked
                      initialScope="Member"
                      onRequestTransition={onRequestTransition}
                      key={dimension.dimension_id}
                      app={app}
                      catalog={catalog}
                      dimensions={snapshot.dimensions}
                      dimensionId={dimension.dimension_id}
                      metadataRevision={snapshot.metadataRevision}
                      onChanged={refresh}
                    />
                  ) : (
                    <div className="metadata-empty">
                      Attribute definitions are not available to your current
                      role.
                    </div>
                  ))}
                {section === "semantics" &&
                  (catalog?.functions["metadata.semantic_column.list"] ? (
                    <SemanticAttributes
                      key={dimension.dimension_id}
                      app={app}
                      catalog={catalog}
                      dimensionId={dimension.dimension_id}
                      dimensions={snapshot.dimensions}
                      members={snapshot.members}
                      metadataRevision={snapshot.metadataRevision}
                      onChanged={refresh}
                    />
                  ) : (
                    <div className="metadata-empty">
                      Semantic guidance is not available to your current role.
                    </div>
                  ))}
                {section === "security-tags" &&
                  (catalog?.functions["metadata.security-tag.list"] ? (
                    <SecurityTagCatalog
                      key={dimension.dimension_id}
                      app={app}
                      catalog={catalog}
                      dimensionId={dimension.dimension_id}
                      metadataRevision={snapshot.metadataRevision}
                      onChanged={refresh}
                    />
                  ) : (
                    <div className="metadata-empty">
                      Security tags are not available to your current role.
                    </div>
                  ))}
              </>
            )}
            {section === "settings" && dimension && snapshot && (
              <div className="metadata-settings">
                <div className="metadata-object-summary">
                  <span
                    className="metadata-dimension-symbol"
                    aria-hidden="true"
                  >
                    ◇
                  </span>
                  <div>
                    <h2>{dimension.name}</h2>
                    <p>
                      {dimension.dimension_id} · {dimension.model_role} role
                    </p>
                  </div>
                  <span
                    className={`status-chip ${dimension.status.toLowerCase()}`}
                  >
                    {dimension.status}
                  </span>
                </div>
                <MetadataMaintenance
                  key={`settings:${dimension.dimension_id}`}
                  app={app}
                  catalog={catalog}
                  dimension={dimension}
                  members={[]}
                  metadataRevision={snapshot.metadataRevision}
                  onChanged={refresh}
                  mode="dimension"
                />
                <MetadataSecurityStringEditor
                  key={`security:${dimension.dimension_id}`}
                  app={app}
                  catalog={catalog}
                  targetKind="Dimension"
                  targetId={dimension.dimension_id}
                  onChanged={refresh}
                />
              </div>
            )}
            {section === "reference" && (
              <div className="metadata-reference">
                <p>
                  {functionNames.length} metadata functions are available to
                  your role. Select a function to inspect its published
                  contract.
                </p>
                {functionNames.map((name) => (
                  <details key={name}>
                    <summary>{name}</summary>
                    <pre>
                      {JSON.stringify(catalog?.functions[name], null, 2)}
                    </pre>
                  </details>
                ))}
                {!functionNames.length && (
                  <p>No metadata functions are currently authorized.</p>
                )}
              </div>
            )}
          </section>
          {drawer && snapshot && (
            <aside
              className="metadata-inspector"
              aria-label={
                drawer === "dimension"
                  ? "New dimension editor"
                  : "New member editor"
              }
            >
              <div className="metadata-inspector-heading">
                <div>
                  <small>CREATE</small>
                  <h2>
                    {drawer === "dimension"
                      ? "New dimension"
                      : `New member in ${dimension?.name || "dimension"}`}
                  </h2>
                </div>
                <button
                  aria-label="Close creation editor"
                  onClick={closeDrawer}
                >
                  ×
                </button>
              </div>
              <MetadataCreate
                key={`${drawer}:${currentDimensionId}`}
                app={app}
                catalog={catalog}
                dimensions={snapshot.dimensions}
                dimensionId={
                  drawer === "member" ? currentDimensionId : undefined
                }
                metadataRevision={snapshot.metadataRevision}
                onCreated={refresh}
                mode={drawer}
              />
            </aside>
          )}
          {!drawer &&
            section === "members" &&
            selectedMember &&
            dimension &&
            snapshot && (
              <aside
                className="metadata-inspector"
                aria-label="Member properties"
              >
                <div className="metadata-inspector-heading">
                  <div>
                    <small>SELECTED MEMBER</small>
                    <h2>{selectedMember.name}</h2>
                    <p>{selectedMember.member_id}</p>
                  </div>
                  <button
                    aria-label="Close member properties"
                    onClick={() => navigate("members", dimension.dimension_id)}
                  >
                    ×
                  </button>
                </div>
                <MetadataMaintenance
                  key={`member:${dimension.dimension_id}:${selectedMember.member_id}`}
                  app={app}
                  catalog={catalog}
                  dimension={dimension}
                  members={snapshot.members}
                  selectedMemberId={selectedMember.member_id}
                  onSelectedMemberIdChange={(id) =>
                    navigate("members", dimension.dimension_id, id)
                  }
                  metadataRevision={snapshot.metadataRevision}
                  onChanged={refresh}
                  mode="member"
                />
                {Boolean(
                  catalog?.functions["security.application.member-tags.read"],
                ) && (
                  <div className="metadata-member-access">
                    <button
                      aria-expanded={memberAccessOpen}
                      onClick={() =>
                        onRequestTransition(() =>
                          setMemberAccessOpen(!memberAccessOpen),
                        )
                      }
                    >
                      {memberAccessOpen
                        ? "Hide member access"
                        : "Member access"}
                    </button>
                    {memberAccessOpen && (
                      <MetadataSecurityStringEditor
                        key={`member-security:${dimension.dimension_id}:${selectedMember.member_id}`}
                        app={app}
                        catalog={catalog}
                        targetKind="Member"
                        targetId={selectedMember.member_id}
                        dimensionId={dimension.dimension_id}
                        onChanged={refresh}
                      />
                    )}
                  </div>
                )}
              </aside>
            )}
        </div>
      )}
    </div>
  );
}
