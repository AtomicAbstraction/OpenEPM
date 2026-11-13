import { render, screen, within } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, expect, it, vi } from "vitest";
import { MetadataMemberGrid } from "./MetadataMemberGrid";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const application = {
  workspaceId: "scale-workspace",
  applicationId: "scale-application",
  name: "Scale cube",
  status: "Active",
};

const catalog = {
  applicationAccess: { role: "Administrator", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: {
    "metadata.attribute-definition.list": {},
    "metadata.attribute-value.set": {},
  },
  revisions: { metadata: 88, data: 1, policy: 1, security: 1, commit: 1 },
};

function definitions(prefix: string) {
  return Array.from({ length: 200 }, (_, index) => ({
    attribute_id: `${prefix}${String(index + 1).padStart(3, "0")}`,
    display_name: `${prefix} attribute ${index + 1}`,
    value_type: "Text",
    validation_constraints: {},
    status: "Active",
    state_token: "a".repeat(64),
  }));
}

it("bounds a 10,000-row and 200-attribute catalogue without accessibility violations", async () => {
  const memberDefinitions = definitions("Member");
  const relationshipDefinitions = definitions("Placement");
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url: string, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as Record<string, any>;
      const rows =
        body.program.arguments.scope === "Relationship"
          ? relationshipDefinitions
          : memberDefinitions;
      return new Response(
        JSON.stringify({
          result: {
            rows,
            hasMore: false,
            nextAfterAttributeId: null,
            metadataRevision: 88,
          },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }),
  );
  const members = Array.from({ length: 10_000 }, (_, index) => ({
    member_id: `M${String(index).padStart(5, "0")}`,
    name: `Member ${index}`,
    status: "Active",
    custom_values: Object.fromEntries(
      memberDefinitions
        .slice(0, 20)
        .map((definition) => [definition.attribute_id, `M-${index}`]),
    ),
  }));
  const relationships = Array.from({ length: 10_000 }, (_, index) => ({
    relationship_id: `R${String(index).padStart(5, "0")}`,
    dimension_id: "Account",
    name: `Placement ${index}`,
    parent_member_id: `P${Math.floor(index / 10)}`,
    child_member_id: members[index].member_id,
    status: "Active" as const,
    custom_values: Object.fromEntries(
      relationshipDefinitions
        .slice(0, 20)
        .map((definition) => [definition.attribute_id, `R-${index}`]),
    ),
  }));

  let rendered: ReturnType<typeof render> | null = null;
  const decisionMilliseconds: number[] = [];
  for (let run = 0; run < 10; run += 1) {
    const started = performance.now();
    rendered = render(
      <MetadataMemberGrid
        app={application}
        catalog={catalog}
        dimensionId="Account"
        members={members}
        relationships={relationships}
        metadataRevision={88}
        selectedMemberId="M00000"
        onSelectedMember={() => undefined}
        onChanged={async () => undefined}
      />,
    );
    expect(await rendered.findAllByText("Member attribute 20")).toHaveLength(2);
    decisionMilliseconds.push(performance.now() - started);
    if (run < 9) rendered.unmount();
  }
  if (!rendered) throw new Error("Scale grid was not rendered.");
  const sorted = decisionMilliseconds.toSorted((left, right) => left - right);
  const percentile = (fraction: number) =>
    sorted[Math.ceil(sorted.length * fraction) - 1];
  const metrics = {
    samples: sorted.length,
    p50: Number(percentile(0.5).toFixed(3)),
    p95: Number(percentile(0.95).toFixed(3)),
    p99: Number(percentile(0.99).toFixed(3)),
  };
  console.info(`metadataGridScale=${JSON.stringify(metrics)}`);

  const memberTable = screen.getByRole("table", {
    name: "Member attribute grid",
  });
  const relationshipTable = screen.getByRole("table", {
    name: "Relationship placement attribute grid",
  });
  expect(within(memberTable).getAllByRole("row")).toHaveLength(51);
  expect(within(relationshipTable).getAllByRole("row")).toHaveLength(51);
  expect(within(memberTable).getAllByRole("columnheader")).toHaveLength(25);
  expect(within(relationshipTable).getAllByRole("columnheader")).toHaveLength(
    26,
  );
  expect(screen.getAllByRole("checkbox")).toHaveLength(400);
  expect(
    screen
      .getAllByRole("checkbox")
      .filter((item) => (item as HTMLInputElement).checked),
  ).toHaveLength(40);
  expect(screen.queryByText("Member 50")).toBeNull();
  expect(screen.queryByText("Placement 50")).toBeNull();
  expect(metrics.p99).toBeLessThan(5_000);

  const accessibility = await axe.run(rendered.container, {
    resultTypes: ["violations"],
    rules: { "color-contrast": { enabled: false } },
  });
  expect(
    accessibility.violations.map((violation) => ({
      id: violation.id,
      nodes: violation.nodes.map((node) => node.target.join(" ")),
    })),
  ).toEqual([]);
}, 20_000);
