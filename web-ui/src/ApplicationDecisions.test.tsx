import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
  ApplicationDecisions,
  type ApplicationDecision,
} from "./ApplicationDecisions";
import {
  ApiError,
  prepareAdmittedProgramEffect,
  readProgram,
  readSecurityProgram,
  replayAdmittedEffect,
} from "./api";
import { canonicalProgramDigest } from "./canonical-program-digest";
import { discardUnsavedWork, resetUnsavedWorkForTests } from "./unsaved-work";
import type { ApplicationCatalog } from "./types";
vi.mock("./api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("./api")>()),
  readProgram: vi.fn(),
  readSecurityProgram: vi.fn(),
  prepareAdmittedProgramEffect: vi.fn(),
  replayAdmittedEffect: vi.fn(),
}));
const scope = { workspaceId: "workspace", applicationId: "application" };
const receiptFunction = "application.operation.receipt.read";
const operationId = `oa1_aaaaaa_${"b".repeat(32)}_${"c".repeat(43)}`;
const functions = Object.fromEntries(
  [
    ...["create", "replace", "withdraw", "read", "list"].map(
      (name) => `application.decision.${name}`,
    ),
    "security.application.subject.list",
    "security.identity.current.read",
    receiptFunction,
  ].map((name) => [name, {}]),
);
const catalog: ApplicationCatalog = {
  functions,
  applicationAccess: {
    role: "Administrator",
    workspaceAdministrator: false,
    issuer: "issuer",
    subjectId: "current-owner",
  },
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
    if (name === receiptFunction)
      throw new ApiError(404, "OPERATION_RECEIPT_NOT_FOUND");
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
  vi.mocked(prepareAdmittedProgramEffect).mockImplementation(
    async (path, body) => ({
      path,
      body: { ...structuredClone(body), idempotencyKey: operationId },
    }),
  );
  vi.mocked(replayAdmittedEffect).mockImplementation(async ({ body }) => ({
    languageVersion: 2,
    function: body.program.function,
    decisionId: (body.program.arguments as { decisionId: string }).decisionId,
    operationId: body.idempotencyKey,
    status:
      body.program.function === "application.decision.withdraw"
        ? "Withdrawn"
        : "Active",
    stateToken: "a".repeat(64),
    contentDigest: "c".repeat(64),
  }));
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
it("retains the signed request across remount and retries only after checking its receipt", async () => {
  vi.mocked(replayAdmittedEffect).mockRejectedValueOnce(
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
  const [first] = vi.mocked(replayAdmittedEffect).mock.calls[0];
  expect(first.path).toBe("/api/application-decision");
  expect(first.body.idempotencyKey).toBe(operationId);
  expect(first.body).not.toHaveProperty("confirmed");
  expect(first.body).not.toHaveProperty("actor");
  view.unmount();
  // The signed recovery lease survives a connection reset that discards
  // ordinary drafts. The shown text must come from the retained program.
  discardUnsavedWork();
  display();
  await waitFor(() =>
    expect(screen.getByLabelText("Decision")).toHaveValue("Keep this context"),
  );
  expect(screen.getByRole("button", { name: "Save decision" })).toBeDisabled();
  expect(
    screen.queryByRole("button", { name: "Retry original decision request" }),
  ).toBeNull();
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Check original decision receipt",
    }),
  );
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Retry original decision request",
    }),
  );
  await waitFor(() => expect(replayAdmittedEffect).toHaveBeenCalledTimes(2));
  expect(vi.mocked(replayAdmittedEffect).mock.calls[1][0]).toEqual(first);
  expect(prepareAdmittedProgramEffect).toHaveBeenCalledTimes(1);
  expect(await screen.findByRole("status")).toHaveTextContent(
    "Original decision save recorded.",
  );
});
it("keeps unsaved text on stale state and explicitly compares the current base", async () => {
  vi.mocked(replayAdmittedEffect).mockRejectedValueOnce(
    new ApiError(409, "APPLICATION_DECISION_STATE_CONFLICT"),
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
  await waitFor(() => expect(replayAdmittedEffect).toHaveBeenCalledTimes(2));
  expect(vi.mocked(replayAdmittedEffect).mock.calls[1][0].body).toMatchObject({
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
    expect(replayAdmittedEffect).toHaveBeenCalledWith(
      expect.objectContaining({
        path: "/api/application-decision",
        body: expect.objectContaining({
          program: {
            languageVersion: 2,
            function: "application.decision.withdraw",
            arguments: {
              decisionId: "one",
              expectedStateToken: "a".repeat(64),
            },
          },
        }),
      }),
      expect.any(AbortSignal),
    ),
  );
});

it("requires the exact committed withdrawal receipt before resolving a lost reply", async () => {
  vi.mocked(replayAdmittedEffect).mockRejectedValueOnce(
    new Error("Connection lost"),
  );
  const view = display();
  fireEvent.click(
    await screen.findByRole("button", { name: "Original decision" }),
  );
  fireEvent.click(
    await screen.findByRole("button", { name: "Withdraw decision" }),
  );
  await screen.findByText("Unconfirmed decision request");
  const [{ body }] = vi.mocked(replayAdmittedEffect).mock.calls[0];
  view.unmount();
  display();
  const committed = {
    operationId,
    actorId: "current-owner",
    committedRevision: 6,
    committedAt: saved.updatedAt,
    outcome: { function: "application.decision.withdraw", status: "Withdrawn" },
  };
  vi.mocked(readProgram).mockResolvedValueOnce({
    ...committed,
    commandDigest: "a".repeat(64),
  });
  fireEvent.click(
    await screen.findByRole("button", {
      name: "Check original decision receipt",
    }),
  );
  await screen.findByText(
    "The receipt could not confirm the original decision change.",
  );
  expect(screen.getByRole("button", { name: "Add decision" })).toBeDisabled();
  const commandDigest = await canonicalProgramDigest({
    scope: [scope.workspaceId, scope.applicationId],
    identity: ["issuer", committed.actorId],
    program: body.program,
  });
  vi.mocked(readProgram).mockResolvedValueOnce({ ...committed, commandDigest });
  fireEvent.click(
    screen.getByRole("button", { name: "Check original decision receipt" }),
  );
  expect(await screen.findByRole("status")).toHaveTextContent(
    "Original decision withdrawal recorded.",
  );
  expect(replayAdmittedEffect).toHaveBeenCalledTimes(1);
  expect(prepareAdmittedProgramEffect).toHaveBeenCalledTimes(1);
});

it("requires a fresh receipt check after expiry and preserves the draft when closing", async () => {
  vi.mocked(replayAdmittedEffect)
    .mockRejectedValueOnce(new Error("Connection lost"))
    .mockRejectedValueOnce(new ApiError(400, "OPERATION_ADMISSION_EXPIRED"));
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
  try {
    display();
    fireEvent.click(screen.getByRole("button", { name: "Add decision" }));
    fireEvent.change(screen.getByLabelText("Title"), {
      target: { value: "A delayed decision" },
    });
    fireEvent.change(screen.getByLabelText("Decision"), {
      target: { value: "Retain this proposal" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save decision" }));
    const check = await screen.findByRole("button", {
      name: "Check original decision receipt",
    });
    fireEvent.click(check);
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Retry original decision request",
      }),
    );
    await screen.findByText(
      "The original admission expired. Check its receipt again.",
    );
    expect(
      screen.queryByRole("button", {
        name: "Close unconfirmed decision request",
      }),
    ).toBeNull();
    fireEvent.click(check);
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Close unconfirmed decision request",
      }),
    );
    expect(screen.getByLabelText("Decision")).toHaveValue(
      "Retain this proposal",
    );
    expect(
      screen.queryByRole("heading", { name: "Unconfirmed decision request" }),
    ).toBeNull();
    expect(replayAdmittedEffect).toHaveBeenCalledTimes(2);
    expect(prepareAdmittedProgramEffect).toHaveBeenCalledTimes(1);
  } finally {
    confirm.mockRestore();
  }
});
