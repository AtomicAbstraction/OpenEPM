import { useEffect, useState } from "react";
import "./metadata-workspace.css";
import { UiIcon } from "./UiIcon";
import {
  dimensionSections,
  metadataSectionLabels,
} from "./metadata-navigation";
import type {
  MetadataDestination,
  MetadataNavigationDimension,
  MetadataSection,
} from "./metadata-navigation";

export function MetadataNavigation({
  active,
  listsActive,
  section,
  dimensionId,
  dimensions,
  collapsed,
  disabled,
  onNavigate,
  onMemberLists,
}: {
  active: boolean;
  listsActive: boolean;
  section: MetadataSection;
  dimensionId?: string;
  dimensions: MetadataNavigationDimension[];
  collapsed: boolean;
  disabled: boolean;
  onNavigate: (destination: MetadataDestination) => void;
  onMemberLists: () => void;
}) {
  const [expanded, setExpanded] = useState(active || listsActive);
  const [expandedDimensions, setExpandedDimensions] = useState<Set<string>>(
    () => new Set(dimensionId ? [dimensionId] : []),
  );
  useEffect(() => {
    if (active || listsActive) setExpanded(true);
    if (active && dimensionId)
      setExpandedDimensions((current) => new Set([...current, dimensionId]));
  }, [active, listsActive, dimensionId]);

  function open(destination: MetadataDestination) {
    setExpanded(true);
    onNavigate(destination);
  }

  return (
    <div className="metadata-navigation">
      <div className="metadata-navigation-heading">
        <button
          type="button"
          className={active || listsActive ? "active" : ""}
          aria-label="Metadata"
          aria-current={
            active && section === "dimensions" && collapsed ? "page" : undefined
          }
          disabled={disabled}
          onClick={() => open({ section: "dimensions" })}
        >
          <UiIcon name="metadata" />
          <b>Metadata</b>
        </button>
        {!collapsed && (
          <button
            type="button"
            className="metadata-navigation-toggle"
            aria-label={
              expanded
                ? "Collapse metadata navigation"
                : "Expand metadata navigation"
            }
            aria-expanded={expanded}
            aria-controls="metadata-navigation-items"
            disabled={disabled}
            onClick={() => setExpanded((value) => !value)}
          >
            <span aria-hidden="true">{expanded ? "⌄" : "›"}</span>
          </button>
        )}
      </div>
      {!collapsed && expanded && (
        <ul
          id="metadata-navigation-items"
          className="metadata-navigation-items"
          aria-label="Metadata pages"
        >
          <li>
            <button
              type="button"
              className={active && section === "dimensions" ? "active" : ""}
              aria-current={
                active && section === "dimensions" ? "page" : undefined
              }
              onClick={() => open({ section: "dimensions" })}
              disabled={disabled}
            >
              <b>Dimensions</b>
            </button>
          </li>
          {dimensions.map((dimension) => {
            const isExpanded = expandedDimensions.has(dimension.dimension_id);
            const selected = active && dimensionId === dimension.dimension_id;
            const id = `metadata-dimension-${encodeURIComponent(dimension.dimension_id)}`;
            return (
              <li
                key={dimension.dimension_id}
                className="metadata-navigation-dimension"
              >
                <button
                  type="button"
                  className={selected ? "metadata-dimension-selected" : ""}
                  aria-label={`${isExpanded ? "Collapse" : "Expand"} ${dimension.name} metadata`}
                  aria-expanded={isExpanded}
                  aria-controls={id}
                  onClick={() =>
                    setExpandedDimensions((current) => {
                      const next = new Set(current);
                      if (next.has(dimension.dimension_id))
                        next.delete(dimension.dimension_id);
                      else next.add(dimension.dimension_id);
                      return next;
                    })
                  }
                >
                  <span aria-hidden="true">{isExpanded ? "⌄" : "›"}</span>
                  <b>{dimension.name}</b>
                  {dimension.name !== dimension.model_role && (
                    <small className="metadata-navigation-role">
                      {dimension.model_role}
                    </small>
                  )}
                </button>
                {isExpanded && (
                  <ul id={id} aria-label={`${dimension.name} metadata pages`}>
                    {dimensionSections.map((destination) => (
                      <li key={destination}>
                        <button
                          type="button"
                          className={
                            selected && section === destination ? "active" : ""
                          }
                          aria-current={
                            selected && section === destination
                              ? "page"
                              : undefined
                          }
                          onClick={() =>
                            open({
                              section: destination,
                              dimensionId: dimension.dimension_id,
                            })
                          }
                        >
                          <b>{metadataSectionLabels[destination]}</b>
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </li>
            );
          })}
          <li>
            <button
              type="button"
              className={listsActive ? "active" : ""}
              aria-current={listsActive ? "page" : undefined}
              disabled={disabled}
              onClick={onMemberLists}
            >
              <b>Member Lists</b>
            </button>
          </li>
          <li>
            <button
              type="button"
              className={active && section === "reference" ? "active" : ""}
              aria-current={
                active && section === "reference" ? "page" : undefined
              }
              disabled={disabled}
              onClick={() => open({ section: "reference" })}
            >
              <b>Function reference</b>
            </button>
          </li>
        </ul>
      )}
    </div>
  );
}
