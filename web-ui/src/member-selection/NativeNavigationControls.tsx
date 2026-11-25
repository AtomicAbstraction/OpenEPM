import type { MetadataHierarchy } from "../metadata-hierarchies";
import { navigation, navigationLabels } from "./native-selection";
import {
  navigationOperations,
  type NavigationExpression,
} from "./selection-types";

/** Constructs symbolic intent only. The core validates scope, paths and membership. */
export function NativeNavigationControls({
  value,
  hierarchies,
  onChange,
}: {
  value: NavigationExpression;
  hierarchies: MetadataHierarchy[];
  onChange: (value: NavigationExpression) => void;
}) {
  const memberOperation = [
    "self",
    "is_base",
    "children",
    "descendants",
    "leaf_descendants",
    "parents",
    "ancestors",
    "siblings",
    "same_level",
    "same_generation",
  ].includes(value.operation);
  const operations = navigationOperations.filter(
    (operation) =>
      operation !== "top" &&
      (value.scope === "hierarchy" ||
        ["all", "leaves", "unplaced"].includes(operation)),
  );
  return (
    <div className="member-list-identity-grid">
      <label>
        Selection scope
        <select
          value={value.scope}
          onChange={(event) =>
            onChange(
              navigation(
                "all",
                event.target.value === "hierarchy"
                  ? (hierarchies.find((item) => item.isDefault)?.hierarchyId ??
                      "")
                  : null,
                null,
                event.target.value as NavigationExpression["scope"],
              ),
            )
          }
        >
          <option value="dimension">Whole dimension</option>
          <option value="hierarchy">Named hierarchy</option>
        </select>
      </label>
      <label>
        Native function
        <select
          value={value.operation}
          onChange={(event) => {
            const operation = event.target
              .value as NavigationExpression["operation"];
            const needsMember = [
              "self",
              "is_base",
              "parents",
              "ancestors",
              "siblings",
              "same_level",
              "same_generation",
            ].includes(operation);
            onChange({
              ...value,
              operation,
              anchor: needsMember
                ? (value.anchor ?? { memberId: "", pathRelationshipIds: null })
                : null,
              includeSelf: false,
              allParents: false,
            });
          }}
        >
          {operations.map((operation) => (
            <option key={operation} value={operation}>
              {navigationLabels[operation]}
            </option>
          ))}
        </select>
      </label>
      {(value.scope === "hierarchy" ||
        ["leaves", "unplaced"].includes(value.operation)) && (
        <label>
          Navigation hierarchy
          <select
            value={value.hierarchyId ?? ""}
            onChange={(event) =>
              onChange({
                ...value,
                hierarchyId: event.target.value,
                anchor: value.anchor
                  ? { ...value.anchor, pathRelationshipIds: null }
                  : null,
              })
            }
          >
            <option value="">Choose hierarchy</option>
            {hierarchies.map((item) => (
              <option key={item.hierarchyId} value={item.hierarchyId}>
                {item.name}
              </option>
            ))}
          </select>
        </label>
      )}
      {memberOperation && (
        <>
          {["children", "descendants", "leaf_descendants"].includes(
            value.operation,
          ) && (
            <label>
              Starting point
              <select
                value={value.anchor === null ? "top" : "member"}
                onChange={(event) =>
                  onChange({
                    ...value,
                    anchor:
                      event.target.value === "top"
                        ? null
                        : { memberId: "", pathRelationshipIds: null },
                    includeSelf: false,
                  })
                }
              >
                <option value="top">Hierarchy top</option>
                <option value="member">Business member</option>
              </select>
            </label>
          )}
          {value.anchor && (
            <>
              <label>
                Starting member ID
                <input
                  value={value.anchor.memberId}
                  onChange={(event) =>
                    onChange({
                      ...value,
                      anchor: {
                        memberId: event.target.value,
                        pathRelationshipIds: null,
                      },
                    })
                  }
                />
              </label>
              <label>
                Placement relationship IDs, root to member
                <textarea
                  rows={2}
                  value={value.anchor.pathRelationshipIds?.join("\n") ?? ""}
                  onChange={(event) =>
                    onChange({
                      ...value,
                      anchor: {
                        ...value.anchor!,
                        pathRelationshipIds: event.target.value
                          ? event.target.value
                              .split("\n")
                              .map((item) => item.trim())
                          : null,
                      },
                      allParents: false,
                    })
                  }
                />
              </label>
              <p>
                A shared member can have several placements. Use its exact path
                for contextual siblings, ancestors or generation.
              </p>
              {!["self", "is_base"].includes(value.operation) && (
                <label>
                  <input
                    type="checkbox"
                    checked={value.includeSelf}
                    onChange={(event) =>
                      onChange({ ...value, includeSelf: event.target.checked })
                    }
                  />
                  Include starting member
                  {value.operation === "leaf_descendants"
                    ? " only if base"
                    : ""}
                </label>
              )}
              {value.operation === "siblings" && (
                <label>
                  <input
                    type="checkbox"
                    checked={value.allParents}
                    onChange={(event) =>
                      onChange({
                        ...value,
                        allParents: event.target.checked,
                        anchor: { ...value.anchor!, pathRelationshipIds: null },
                      })
                    }
                  />
                  Use all parents explicitly
                </label>
              )}
            </>
          )}
        </>
      )}
      <p>
        Active members and relationships only. Generation starts at 1 for the
        hierarchy top; a leaf is level 0.
      </p>
    </div>
  );
}
