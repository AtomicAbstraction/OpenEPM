import { render, screen, waitFor } from "@testing-library/react";
import axe from "axe-core";
import { afterEach, expect, it, vi } from "vitest";
import { App } from "./App";
import { Analyze } from "./Analyze";
import { CapabilityArea } from "./CapabilityArea";
import { Monitor } from "./Monitor";
import { GenericWorkflow } from "./GenericWorkflow";

afterEach(() => {
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

function stubShellReads() {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.startsWith("/api/applications"))
        return new Response(
          JSON.stringify({
            applications: [
              {
                workspaceId: "ws-pilot",
                applicationId: "pilot-fpna",
                name: "Pilot FP&A",
                status: "active",
                kind: "blank",
              },
            ],
            nextAfter: null,
          }),
        );
      if (url === "/api/session-identity")
        return new Response(
          JSON.stringify({
            subject: "owner",
            displayIdentity: "owner@example.com",
            applicationMcpEndpoint: "https://mcp.example/epu_personal",
          }),
        );
      if (url === "/api/catalog")
        return new Response(
          JSON.stringify({
            applicationAccess: {
              role: "Administrator",
              workspaceAdministrator: true,
            },
            enabledCapabilities: [],
            functions: { "facts.cube.scan": {} },
            revisions: {
              metadata: 1,
              data: 2,
              policy: 3,
              security: 4,
              commit: 5,
            },
          }),
        );
      return new Response("{}", { status: 404 });
    }),
  );
}

async function accessibilityViolations(container: HTMLElement) {
  const result = await axe.run(container, {
    resultTypes: ["violations"],
    rules: {
      // jsdom has no rendered layout and therefore cannot calculate contrast.
      // Contrast remains part of rendered-browser visual qualification.
      "color-contrast": { enabled: false },
    },
  });
  return result.violations.map((violation) => ({
    id: violation.id,
    impact: violation.impact,
    nodes: violation.nodes.map((node) => node.target.join(" ")),
  }));
}

it("has no automatically detectable shell accessibility violations", async () => {
  stubShellReads();
  const { container } = render(<App />);
  await waitFor(() =>
    expect(screen.getAllByText("Pilot FP&A").length).toBeGreaterThan(0),
  );
  await screen.findByRole("button", { name: "Grid" });
  expect(await accessibilityViolations(container)).toEqual([]);
});

const readerCatalog = {
  applicationAccess: { role: "Reader", workspaceAdministrator: false },
  enabledCapabilities: [],
  functions: {},
  revisions: { metadata: 1, data: 2, policy: 3, security: 4, commit: 5 },
};

it.each([
  [
    "Grid",
    <Analyze key="grid" catalog={readerCatalog} index={0} subject="owner" />,
  ],
  ["Flows", <GenericWorkflow key="flows" catalog={readerCatalog} />],
  ["Monitor", <Monitor key="monitor" catalog={null} />],
  [
    "Data",
    <CapabilityArea key="data" area="data" catalog={readerCatalog} index={0} />,
  ],
  [
    "Metadata",
    <CapabilityArea
      key="metadata"
      area="metadata"
      catalog={readerCatalog}
      index={0}
    />,
  ],
  [
    "Member Lists",
    <CapabilityArea
      key="lists"
      area="lists"
      catalog={readerCatalog}
      index={0}
    />,
  ],
  [
    "Rules",
    <CapabilityArea
      key="rules"
      area="rules"
      catalog={readerCatalog}
      index={0}
    />,
  ],
  [
    "Users & Security",
    <CapabilityArea
      key="security"
      area="security"
      catalog={readerCatalog}
      index={0}
    />,
  ],
  [
    "Administration",
    <CapabilityArea
      key="administration"
      area="administration"
      catalog={readerCatalog}
      index={0}
    />,
  ],
])("has no automatically detectable %s page violations", async (name, page) => {
  const { container } = render(page);
  expect(await accessibilityViolations(container)).toEqual([]);
});
