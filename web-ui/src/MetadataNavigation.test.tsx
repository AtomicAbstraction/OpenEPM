import { fireEvent, render, screen, within } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { MetadataNavigation } from "./MetadataNavigation";

const dimensions = [
  {
    dimension_id: "Account",
    name: "Accounts",
    model_role: "Account",
    status: "Active",
  },
  {
    dimension_id: "Entity",
    name: "Companies",
    model_role: "Entity",
    status: "Active",
  },
];

it("uses dimension disclosures to open a distinct workspace and preserves its active path", () => {
  const onNavigate = vi.fn();
  const onMemberLists = vi.fn();
  render(
    <MetadataNavigation
      active
      listsActive={false}
      section="members"
      dimensionId="Account"
      dimensions={dimensions}
      collapsed={false}
      disabled={false}
      onNavigate={onNavigate}
      onMemberLists={onMemberLists}
    />,
  );
  expect(
    screen.getByRole("button", { name: "Collapse Accounts metadata" }),
  ).toHaveAttribute("aria-expanded", "true");
  const accountPages = screen.getByRole("list", {
    name: "Accounts metadata pages",
  });
  expect(
    within(accountPages).getByRole("button", { name: "Members" }),
  ).toHaveAttribute("aria-current", "page");
  fireEvent.click(
    within(accountPages).getByRole("button", { name: "Relationships" }),
  );
  expect(onNavigate).toHaveBeenLastCalledWith({
    section: "relationships",
    dimensionId: "Account",
  });
  expect(
    screen.queryByRole("list", { name: "Companies metadata pages" }),
  ).not.toBeInTheDocument();
  fireEvent.click(
    screen.getByRole("button", { name: "Expand Companies metadata" }),
  );
  fireEvent.click(
    within(
      screen.getByRole("list", { name: "Companies metadata pages" }),
    ).getByRole("button", { name: "Properties & access" }),
  );
  expect(onNavigate).toHaveBeenLastCalledWith({
    section: "settings",
    dimensionId: "Entity",
  });
  fireEvent.click(screen.getByRole("button", { name: "Member Lists" }));
  expect(onMemberLists).toHaveBeenCalledOnce();
});

it("removes collapsed navigation children from keyboard and accessibility traversal", () => {
  const { rerender } = render(
    <MetadataNavigation
      active
      listsActive={false}
      section="members"
      dimensionId="Account"
      dimensions={dimensions}
      collapsed={false}
      disabled={false}
      onNavigate={vi.fn()}
      onMemberLists={vi.fn()}
    />,
  );
  fireEvent.click(
    screen.getByRole("button", { name: "Collapse metadata navigation" }),
  );
  expect(
    screen.queryByRole("button", { name: "Members" }),
  ).not.toBeInTheDocument();
  rerender(
    <MetadataNavigation
      active
      listsActive={false}
      section="members"
      dimensionId="Account"
      dimensions={dimensions}
      collapsed
      disabled={false}
      onNavigate={vi.fn()}
      onMemberLists={vi.fn()}
    />,
  );
  expect(screen.getAllByRole("button")).toHaveLength(1);
  expect(screen.getByRole("button", { name: "Metadata" })).toBeInTheDocument();
});
