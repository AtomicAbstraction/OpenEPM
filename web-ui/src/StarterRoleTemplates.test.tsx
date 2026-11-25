import { fireEvent, render, screen } from "@testing-library/react";
import { it, expect, vi } from "vitest";
import {
  StarterRoleTemplates,
  ReviewedTemplateSummary,
  validTemplatePreview,
} from "./StarterRoleTemplates";
import type {
  Configuration,
  Preview,
  ReviewedRoleTemplate,
} from "./authorization-config";

const proposed = {
  templateId: "data-reader",
  version: 2,
  name: "Reader II",
  actions: ["application.enter", "facts.read"],
};
const origin = {
  templateId: proposed.templateId,
  upstreamName: "Reader",
  upstreamActions: ["application.enter", "facts.read"],
  version: 1,
  nameOverridden: true,
  addedActions: ["views.read"],
  removedActions: ["facts.read"],
};
const role = {
  roleId: "analyst",
  name: "Regional analyst",
  actions: ["application.enter", "views.read"],
  templateOrigin: origin,
};
const config = {
  roleTemplates: [proposed],
  roles: [role],
  actions: ["application.enter", "facts.read", "views.read"].map((action) => ({
    action,
    canDelegate: true,
    scopeKinds: ["entire_application"],
  })),
} as Configuration;

it("previews a named starter as an unassigned role", () => {
  const change = vi.fn();
  render(
    <StarterRoleTemplates
      config={config}
      selectedRoleId=""
      editable
      locked={false}
      onPreview={change}
    />,
  );
  fireEvent.change(screen.getByLabelText("Starter role template"), {
    target: { value: "data-reader" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Preview starter role" }));
  expect(change).toHaveBeenCalledWith({
    op: "adoptRoleTemplate",
    templateId: "data-reader",
    templateVersion: 2,
    roleId: expect.any(String),
  });
});

it("shows the currently adopted version and current local overrides on update", () => {
  const change = vi.fn();
  render(
    <StarterRoleTemplates
      config={config}
      selectedRoleId="analyst"
      editable
      locked={false}
      onPreview={change}
    />,
  );
  expect(
    screen.getByText("Reader template · adopted version 1"),
  ).toBeInTheDocument();
  expect(screen.getByText("Locally removed · facts.read")).toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("button", { name: "Preview template update" }),
  );
  expect(change).toHaveBeenCalledWith({
    op: "adoptRoleTemplate",
    roleId: "analyst",
    templateId: "data-reader",
    templateVersion: 2,
  });
});

it("requires a matching server review and displays the resulting role", () => {
  const reviewed: ReviewedRoleTemplate = {
    roleId: role.roleId,
    name: role.name,
    actions: role.actions,
    origin: { ...origin, version: 2, upstreamName: proposed.name },
    priorVersion: 1,
    addedActions: [],
    removedActions: [],
  };
  const change = {
    op: "adoptRoleTemplate",
    roleId: "analyst",
    templateId: "data-reader",
    templateVersion: 2,
  } as const;
  const preview = { impact: { reviewedRoleTemplates: [reviewed] } } as Preview;
  expect(validTemplatePreview(preview, [change])).toBe(true);
  expect(
    validTemplatePreview(preview, [{ ...change, templateVersion: 3 }]),
  ).toBe(false);
  render(<ReviewedTemplateSummary item={reviewed} />);
  expect(
    screen.getByText("Regional analyst · Reader II template version 2"),
  ).toBeInTheDocument();
  expect(
    screen.getByText("Actions after adoption · application.enter, views.read"),
  ).toBeInTheDocument();
});
