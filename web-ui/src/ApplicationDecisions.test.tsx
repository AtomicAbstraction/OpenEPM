import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
  ApplicationDecisions,
  type ApplicationDecision,
} from "./ApplicationDecisions";
import { readProgram, readSecurityProgram, requestAdmittedEffect } from "./api";
import { resetUnsavedWorkForTests } from "./unsaved-work";
import type { ApplicationCatalog } from "./types";
vi.mock("./api", () => ({
  readProgram: vi.fn(),
  readSecurityProgram: vi.fn(),
  requestAdmittedEffect: vi.fn(),
}));
const scope = { workspaceId: "workspace", applicationId: "application" };
const functions = Object.fromEntries(
  [
    ...["create", "replace", "withdraw", "read", "list"].map(
      (name) => `application.decision.${name}`,
    ),
    "security.application.subject.list",
    "security.identity.current.read",
  ].map((name) => [name, {}]),
);
const catalog: ApplicationCatalog = {
  functions,
  applicationAccess: { role: "Administrator", workspaceAdministrator: false },
  enabledCapabilities: [],
  revisions: { metadata: 1, data: 2, policy: 3, security: 4, commit: 5 },
};
const saved: ApplicationDecision = {
  decisionId: "one",
  stateToken: "a".repeat(64),
  title: "Original decision",
  text: "Original text",
  rationale: "Because",
  sourceReference: "javascript:alert('xss')",
  provenance: "AgentInterpretation",
  status: "Active",
  actor: { issuer: "issuer", subjectId: "actor" },
  updatedAt: "2026-11-08T12:00:00Z",
  operationId: "operation-1",
  contentDigest: "a".repeat(64),
};
function display(overrides: Partial<ApplicationCatalog> = {}) {
  return render(
    <ApplicationDecisions
      scope={scope}
      catalog={{ ...catalog, ...overrides }}
      onRequestTransition={(action) => action()}
    />,
  );
}
beforeEach(() => {
  vi.mocked(readProgram).mockImplementation(async (_scope, name) => {
    if (name === "security.identity.current.read")
      return { issuer: "issuer", subjectId: "current-owner" };
    if (name === "application.decision.list")
      return {
        items: [saved],
        collectionToken: "b".repeat(64),
        nextAfterDecisionId: null,
      };
    return saved;
  });
  vi.mocked(readSecurityProgram).mockResolvedValue({
    subjects: [
      {
        selectionKey: "actor",
        displayName: "Decision Owner",
        username: "decision.owner",
      },
    ],
    nextAfterSelectionKey: null,
  });
  vi.mocked(requestAdmittedEffect).mockResolvedValue({
    stateToken: "a".repeat(64),
  });
});
afterEach(() => {
  vi.resetAllMocks();
  resetUnsavedWorkForTests();
});
it("requires discovered effective admin functions, regardless of displayed role", () => {
  const { container } = display({ functions: {} });
  expect(container).toBeEmptyDOMElement();
  expect(readProgram).not.toHaveBeenCalled();
});
it("renders provenance and server attribution with source text inert", async () => {
  display();
  fireEvent.click(
    await screen.findByRole("button", { name: "Original decision" }),
  );
  expect(await screen.findByText("Original text")).toBeVisible();
  expect(
    screen.getByText(/Recorded by Decision Owner \(decision.owner\)/),
  ).toBeVisible();
  expect(screen.queryByText(/Recorded by actor/)).not.toBeInTheDocument();
  expect(screen.queryByText(/\(issuer\)/)).not.toBeInTheDocument();
  expect(screen.getByText("javascript:alert('xss')")).toBeVisible();
  expect(screen.queryByRole("link")).toBeNull();
});
it("preserves exact request key and draft across uncertain response and remount", async () => {
  vi.mocked(requestAdmittedEffect).mockRejectedValueOnce(
    new Error("Connection lost"),
  );
  const view = display();
  fireEvent.click(screen.getByRole("button", { name: "Add decision" }));
  fireEvent.change(screen.getByLabelText("Title"), {
    target: { value: "New decision" },
  });
  fireEvent.change(screen.getByLabelText("Decision"), {
    target: { value: "Keep this context" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save decision" }));
  await screen.findByRole("alert");
  const first = vi.mocked(requestAdmittedEffect).mock.calls[0];
  expect(first[0]).toBe("/api/application-decision");
  expect(first[1]).not.toHaveProperty("confirmed");
  expect(first[1]).not.toHaveProperty("actor");
  view.unmount();
  display();
  await waitFor(() =>
    expect(screen.getByLabelText("Decision")).toHaveValue("Keep this context"),
  );
  fireEvent.click(screen.getByRole("button", { name: "Save decision" }));
  await waitFor(() => expect(requestAdmittedEffect).toHaveBeenCalledTimes(2));
  expect(vi.mocked(requestAdmittedEffect).mock.calls[1]).toEqual(first);
  expect(await screen.findByRole("status")).toHaveTextContent(
    "Decision saved.",
  );
});
it("keeps unsaved text on stale state and explicitly compares the current base", async () => {
  vi.mocked(requestAdmittedEffect).mockRejectedValueOnce(
    new Error("APPLICATION_DECISION_STATE_CONFLICT"),
  );
  display();
  fireEvent.click(
    await screen.findByRole("button", { name: "Original decision" }),
  );
  fireEvent.click(await screen.findByRole("button", { name: "Edit decision" }));
  fireEvent.change(screen.getByLabelText("Decision"), {
    target: { value: "My unsaved text" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Save decision" }));
  await screen.findByRole("alert");
  expect(screen.getByLabelText("Decision")).toHaveValue("My unsaved text");
  vi.mocked(readProgram).mockResolvedValueOnce({
    ...saved,
    stateToken: "c".repeat(64),
    text: "Someone else's edit",
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Compare current decision" }),
  );
  expect(await screen.findByText("Someone else's edit")).toBeVisible();
  fireEvent.click(
    screen.getByRole("button", { name: "Keep draft against current state" }),
  );
  expect(screen.getByLabelText("Decision")).toHaveValue("My unsaved text");
  fireEvent.click(screen.getByRole("button", { name: "Save decision" }));
  await waitFor(() => expect(requestAdmittedEffect).toHaveBeenCalledTimes(2));
  expect(vi.mocked(requestAdmittedEffect).mock.calls[1][1]).toMatchObject({
    program: {
      function: "application.decision.replace",
      arguments: {
        expectedStateToken: "c".repeat(64),
        text: "My unsaved text",
      },
    },
  });
});
it("pins next-page reads and withdraws the exact displayed state", async () => {
  vi.mocked(readProgram).mockResolvedValueOnce({
    items: [saved],
    collectionToken: "b".repeat(64),
    nextAfterDecisionId: "one",
  });
  display();
  fireEvent.click(
    await screen.findByRole("button", { name: "Next decisions" }),
  );
  await waitFor(() =>
    expect(readProgram).toHaveBeenCalledWith(
      scope,
      "application.decision.list",
      {
        limit: 25,
        afterDecisionId: "one",
        expectedCollectionToken: "b".repeat(64),
      },
    ),
  );
  fireEvent.click(screen.getByRole("button", { name: "Original decision" }));
  fireEvent.click(
    await screen.findByRole("button", { name: "Withdraw decision" }),
  );
  await waitFor(() =>
    expect(requestAdmittedEffect).toHaveBeenCalledWith(
      "/api/application-decision",
      expect.objectContaining({
        program: {
          languageVersion: 2,
          function: "application.decision.withdraw",
          arguments: { decisionId: "one", expectedStateToken: "a".repeat(64) },
        },
      }),
    ),
  );
});
