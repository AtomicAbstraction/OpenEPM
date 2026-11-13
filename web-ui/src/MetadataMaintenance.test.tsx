import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import {
  MetadataMaintenance,
  metadataMaintenanceBody,
} from "./MetadataMaintenance";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const app = {
  workspaceId: "ws",
  applicationId: "app",
  name: "Plan",
  status: "Active",
};

const catalog = {
  applicationAccess: { role: "Administrator", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: {
    "metadata.dimension.rename": {},
    "metadata.dimension.describe": {},
    "metadata.dimension.status.set": {},
    "metadata.dimension.delete": {},
    "metadata.member.rename": {},
    "metadata.member.describe": {},
    "metadata.member.numeric-kind.set": {},
    "metadata.member.status.set": {},
  },
  revisions: { metadata: 46, data: 1, policy: 1, security: 1, commit: 1 },
};

const dimension = {
  dimension_id: "Account",
  name: "Account",
  model_role: "Account",
  status: "Active",
  short_description: "Chart",
  detailed_description: "Chart of accounts",
};

const members = [
  {
    member_id: "Sales",
    name: "Sales",
    status: "Active",
    short_description: "Revenue",
    detailed_description: "Sales revenue",
    numeric_value_kind: "amount" as const,
  },
];

it("preserves the governed maintenance envelope", () => {
  expect(
    metadataMaintenanceBody(
      app,
      "metadata.member.numeric-kind.set",
      {
        dimensionId: "Account",
        memberId: "Margin",
        numericValueKind: "ratio",
        expectedMetadataRevision: 46,
      },
      "metadata-maintenance-1",
    ),
  ).toEqual({
    workspaceId: "ws",
    applicationId: "app",
    confirmed: true,
    idempotencyKey: "metadata-maintenance-1",
    program: {
      languageVersion: 2,
      function: "metadata.member.numeric-kind.set",
      arguments: {
        dimensionId: "Account",
        memberId: "Margin",
        numericValueKind: "ratio",
        expectedMetadataRevision: 46,
      },
    },
  });
});

it("keeps maintenance unavailable without an authoritative snapshot", () => {
  render(
    <MetadataMaintenance
      app={app}
      catalog={catalog}
      members={[]}
      metadataRevision={null}
      onChanged={async () => undefined}
    />,
  );
  expect(
    screen.getByText(/Read the current dimension catalogue/),
  ).toBeInTheDocument();
});

it("invalidates exact review when a proposed rename changes", () => {
  render(
    <MetadataMaintenance
      app={app}
      catalog={catalog}
      dimension={dimension}
      members={members}
      metadataRevision={46}
      onChanged={async () => undefined}
    />,
  );
  const name = screen.getByLabelText("Dimension display name");
  fireEvent.change(name, { target: { value: "Accounts" } });
  const review = screen.getByLabelText(
    "I reviewed this exact dimension name against the current model.",
  );
  fireEvent.click(review);
  expect(review).toBeChecked();
  expect(
    screen.getByRole("button", { name: "Rename dimension" }),
  ).toBeEnabled();
  fireEvent.change(name, { target: { value: "Financial accounts" } });
  expect(review).not.toBeChecked();
  expect(
    screen.getByRole("button", { name: "Rename dimension" }),
  ).toBeDisabled();
});

it("requires the exact inactive dimension identity before delete review", () => {
  render(
    <MetadataMaintenance
      app={app}
      catalog={catalog}
      dimension={{ ...dimension, status: "Inactive" }}
      members={[]}
      metadataRevision={46}
      onChanged={async () => undefined}
    />,
  );
  const identity = screen.getByLabelText(
    "Type Account to delete this inactive dimension",
  );
  const review = screen.getByLabelText(
    "I reviewed this exact inactive dimension deletion against the current model.",
  );
  fireEvent.change(identity, { target: { value: "Accounts" } });
  expect(review).toBeDisabled();
  fireEvent.change(identity, { target: { value: "Account" } });
  expect(review).toBeEnabled();
});

it("uses the Metadata Manager selection as the member property editor selection", () => {
  const onSelectedMemberIdChange = vi.fn();
  render(
    <MetadataMaintenance
      app={app}
      catalog={catalog}
      dimension={dimension}
      members={[
        ...members,
        {
          member_id: "Margin",
          name: "Margin",
          status: "Active",
          short_description: "Profitability",
          detailed_description: "Calculated margin",
          numeric_value_kind: "ratio" as const,
        },
      ]}
      selectedMemberId="Margin"
      onSelectedMemberIdChange={onSelectedMemberIdChange}
      metadataRevision={46}
      onChanged={async () => undefined}
    />,
  );

  expect(screen.getByLabelText("Member")).toHaveValue("Margin");
  expect(screen.getByLabelText("Member display name")).toHaveValue("Margin");
  fireEvent.change(screen.getByLabelText("Member"), {
    target: { value: "Sales" },
  });
  expect(onSelectedMemberIdChange).toHaveBeenCalledWith("Sales");
});

it("offers separate dimension and member property workspaces", () => {
  const props = {
    app,
    catalog,
    dimension,
    members,
    metadataRevision: 46,
    onChanged: async () => undefined,
  };
  const view = render(<MetadataMaintenance {...props} mode="dimension" />);
  expect(
    screen.getByRole("heading", { name: "Dimension properties" }),
  ).toBeInTheDocument();
  expect(screen.queryByLabelText("Member display name")).toBeNull();
  view.rerender(<MetadataMaintenance {...props} mode="member" />);
  expect(
    screen.getByRole("heading", { name: "Member properties" }),
  ).toBeInTheDocument();
  expect(screen.getByLabelText("Member display name")).toBeVisible();
  expect(screen.queryByLabelText("Dimension display name")).toBeNull();
});

it("retains a stale draft and requires explicit current-revision review", () => {
  const props = {
    app,
    catalog,
    dimension,
    members,
    onChanged: async () => undefined,
    mode: "dimension" as const,
  };
  const view = render(<MetadataMaintenance {...props} metadataRevision={46} />);
  fireEvent.change(screen.getByLabelText("Dimension display name"), {
    target: { value: "Operating accounts" },
  });
  const review = screen.getByLabelText(
    "I reviewed this exact dimension name against the current model.",
  );
  fireEvent.click(review);
  view.rerender(<MetadataMaintenance {...props} metadataRevision={47} />);
  expect(screen.getByLabelText("Dimension display name")).toHaveValue(
    "Operating accounts",
  );
  expect(review).not.toBeChecked();
  expect(review).toBeDisabled();
  expect(
    screen.getByRole("button", { name: "Rename dimension" }),
  ).toBeDisabled();
  fireEvent.click(
    screen.getByRole("button", { name: "Review against current metadata" }),
  );
  expect(review).toBeEnabled();
  expect(review).not.toBeChecked();
  fireEvent.click(review);
  expect(
    screen.getByRole("button", { name: "Rename dimension" }),
  ).toBeEnabled();
});

it("restores typed values without restoring prior review authorization", async () => {
  const props = {
    app,
    catalog,
    dimension,
    members,
    metadataRevision: 46,
    onChanged: async () => undefined,
    mode: "dimension" as const,
  };
  const first = render(<MetadataMaintenance {...props} />);
  fireEvent.change(screen.getByLabelText("Dimension display name"), {
    target: { value: "Retained name" },
  });
  fireEvent.click(
    screen.getByLabelText(
      "I reviewed this exact dimension name against the current model.",
    ),
  );
  first.unmount();
  render(<MetadataMaintenance {...props} metadataRevision={47} />);
  await waitFor(() =>
    expect(screen.getByLabelText("Dimension display name")).toHaveValue(
      "Retained name",
    ),
  );
  expect(
    screen.getByLabelText(
      "I reviewed this exact dimension name against the current model.",
    ),
  ).not.toBeChecked();
  expect(
    screen.getByRole("button", { name: "Rename dimension" }),
  ).toBeDisabled();
  expect(
    screen.getByRole("button", { name: "Review against current metadata" }),
  ).toBeInTheDocument();
});
