import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ServerAdministration } from "./ServerAdministration";
import { resetUnsavedWorkForTests, setDraftIdentity } from "./unsaved-work";

afterEach(() => {
  vi.unstubAllGlobals();
  resetUnsavedWorkForTests();
});

const functions = Object.fromEntries(
  [
    "identity.native-user.create",
    "identity.native-user.update",
    "identity.native-user.status.set",
    "identity.native-user.password.set",
    "identity.native-user.list",
    "identity.group.create",
    "identity.group.update",
    "identity.group.status.set",
    "identity.group.list",
    "identity.group.membership.list",
    "identity.group.membership.set",
    "platform.operation.receipt.read",
  ].map((name) => [name, {}]),
);

function directoryFetch(writes: Array<Record<string, unknown>>) {
  return vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body));
    const functionName = body.program.function;
    if (functionName === "identity.native-user.list")
      return new Response(
        JSON.stringify({
          items: [
            {
              subjectId: "subject-1",
              username: "alice",
              displayName: "Alice",
              shortDescription: "Operator",
              semanticDescription: "Runs governed operations",
              status: "Active",
            },
          ],
          nextOffset: null,
        }),
      );
    if (functionName === "identity.group.list")
      return new Response(
        JSON.stringify({
          items: [
            {
              groupId: "finance",
              groupName: "finance-admins",
              displayName: "Finance",
              shortDescription: "Finance users",
              semanticDescription: "Finance authorization principal",
              status: "Active",
            },
          ],
          nextOffset: null,
        }),
      );
    if (functionName === "identity.group.membership.list")
      return new Response(
        JSON.stringify({
          items: [
            {
              subjectId: "subject-1",
              groupId: "finance",
              groupName: "finance-admins",
              directoryRevision: 7,
            },
          ],
          nextAfter: null,
        }),
      );
    writes.push(body);
    return new Response(JSON.stringify({ status: "Active" }));
  });
}

it("shows current Keycloak users, groups and fixed-core memberships", async () => {
  vi.stubGlobal("fetch", directoryFetch([]));
  render(<ServerAdministration functions={functions} />);
  expect(await screen.findByText("Alice")).toBeInTheDocument();
  expect(screen.queryByText("Finance")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Groups" }));
  expect(await screen.findByText("Finance")).toBeInTheDocument();
  expect(screen.queryByText("Alice")).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "Membership" }));
  expect(await screen.findByText("Member")).toBeInTheDocument();
  expect(screen.getAllByText("Alice").length).toBeGreaterThan(0);
  expect(screen.queryByText("subject-1")).not.toBeInTheDocument();
});

it("withholds incomplete directory results and starts a read retry from the first page", async () => {
  const normal = directoryFetch([]);
  const offsets: number[] = [];
  let repeatCursor = true;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const program = JSON.parse(String(init?.body)).program;
      if (program.function === "identity.native-user.list") {
        offsets.push(program.arguments.offset);
        if (repeatCursor && offsets.length <= 2)
          return new Response(JSON.stringify({ items: [], nextOffset: 100 }));
        if (repeatCursor)
          return new Response(
            JSON.stringify({ error: "KEYCLOAK_DIRECTORY_RESPONSE_INVALID" }),
            { status: 400 },
          );
      }
      return normal(input, init);
    }),
  );

  render(<ServerAdministration functions={functions} />);
  const retry = await screen.findByRole("button", {
    name: "Retry directory load",
  });
  expect(offsets).toEqual([0, 100]);
  expect(screen.getByRole("alert")).toHaveTextContent(
    "Directory could not be loaded",
  );
  expect(screen.queryByText("0 managed")).not.toBeInTheDocument();
  expect(screen.queryByText("No matching records")).not.toBeInTheDocument();
  repeatCursor = false;
  fireEvent.click(retry);

  expect(await screen.findByText("Alice")).toBeInTheDocument();
  expect(offsets).toEqual([0, 100, 0]);
});

it("creates a native user through the reviewed platform write envelope", async () => {
  const writes: Array<Record<string, unknown>> = [];
  vi.stubGlobal("fetch", directoryFetch(writes));
  vi.stubGlobal("crypto", {
    randomUUID: () => "11111111-1111-4111-8111-111111111111",
  });
  render(<ServerAdministration functions={functions} />);
  await screen.findByText("Alice");
  fireEvent.click(screen.getByRole("button", { name: "+ New user" }));
  const createForm = screen
    .getByText("Create native user", { selector: "h3" })
    .closest("form");
  expect(createForm).not.toBeNull();
  const form = within(createForm!);
  fireEvent.change(form.getByLabelText("Username"), {
    target: { value: "bob" },
  });
  fireEvent.change(form.getByLabelText("Display name"), {
    target: { value: "Bob" },
  });
  fireEvent.click(
    form.getByLabelText("I reviewed the exact user identity and descriptions."),
  );
  fireEvent.click(form.getByRole("button", { name: "Create native user" }));
  await waitFor(() => expect(writes).toHaveLength(1));
  expect(writes[0]).toEqual({
    program: {
      languageVersion: 2,
      function: "identity.native-user.create",
      arguments: {
        username: "bob",
        displayName: "Bob",
        shortDescription: "",
        semanticDescription: "",
      },
    },
    idempotencyKey: "ui-11111111-1111-4111-8111-111111111111",
    confirmed: true,
  });
  expect(await screen.findByText(/Created Bob/)).toBeInTheDocument();
});

it("recovers a committed group change after navigating without sending another write", async () => {
  const normal = directoryFetch([]);
  const writes: Array<Record<string, unknown>> = [];
  const receiptReads: Array<Record<string, unknown>> = [];
  vi.stubGlobal("confirm", () => true);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (body.program.function === "identity.group.status.set") {
        writes.push(body);
        return new Response(
          JSON.stringify({ error: "PLATFORM_OPERATOR_REQUIRED" }),
          { status: 403 },
        );
      }
      if (body.program.function === "platform.operation.receipt.read") {
        receiptReads.push(body);
        return new Response(
          JSON.stringify({
            operationId: writes[0].idempotencyKey,
            function: "identity.group.status.set",
            status: receiptReads.length === 1 ? "Pending" : "Committed",
            committedAt:
              receiptReads.length === 1 ? null : "2026-11-21T12:00:00Z",
          }),
        );
      }
      return normal(input, init);
    }),
  );
  render(<ServerAdministration functions={functions} />);
  await screen.findByText("Alice");
  fireEvent.click(screen.getByRole("button", { name: "Groups" }));
  await screen.findByText("Finance");
  fireEvent.click(screen.getByRole("button", { name: "Deactivate" }));
  let recovery = within(
    await screen.findByRole("region", { name: "Directory change recovery" }),
  );
  expect(screen.getByRole("button", { name: "Edit" })).toBeDisabled();
  fireEvent.click(
    recovery.getByRole("button", { name: "Check original directory change" }),
  );
  await screen.findByText(/The directory receipt is pending/);
  expect(
    recovery.queryByRole("button", { name: "Retry original directory change" }),
  ).toBeNull();

  fireEvent.click(screen.getByRole("button", { name: "Membership" }));
  await screen.findByText("Member");
  recovery = within(
    await screen.findByRole("region", { name: "Directory change recovery" }),
  );
  fireEvent.click(
    recovery.getByRole("button", { name: "Check original directory change" }),
  );
  await screen.findByText("The original directory change was committed.");
  expect(
    screen.queryByRole("region", { name: "Directory change recovery" }),
  ).toBeNull();
  expect(writes).toHaveLength(1);
  expect(receiptReads).toEqual(
    Array(2).fill({
      program: {
        languageVersion: 2,
        function: "platform.operation.receipt.read",
        arguments: { operationId: writes[0].idempotencyKey },
      },
    }),
  );
});

it("retries a missing directory receipt with the original packet and key", async () => {
  const normal = directoryFetch([]);
  const writes: Array<Record<string, unknown>> = [];
  vi.stubGlobal("confirm", () => true);
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (body.program.function === "identity.native-user.status.set") {
        writes.push(body);
        return writes.length === 1
          ? new Response(
              JSON.stringify({ error: "KEYCLOAK_DIRECTORY_OPERATION_FAILED" }),
              { status: 400 },
            )
          : new Response(JSON.stringify({ status: "Inactive" }));
      }
      if (body.program.function === "platform.operation.receipt.read")
        return new Response(
          JSON.stringify({
            operationId: writes[0].idempotencyKey,
            function: null,
            status: "Unavailable",
            committedAt: null,
          }),
        );
      return normal(input, init);
    }),
  );
  render(<ServerAdministration functions={functions} />);
  await screen.findByText("Alice");
  fireEvent.click(screen.getByRole("button", { name: "Deactivate" }));
  const recovery = within(
    await screen.findByRole("region", { name: "Directory change recovery" }),
  );
  expect(
    recovery.queryByRole("button", { name: "Retry original directory change" }),
  ).toBeNull();
  fireEvent.click(
    recovery.getByRole("button", { name: "Check original directory change" }),
  );
  fireEvent.click(
    await recovery.findByRole("button", {
      name: "Retry original directory change",
    }),
  );
  await screen.findByText("The original directory change was committed.");
  expect(writes).toHaveLength(2);
  expect(writes[1]).toEqual(writes[0]);
});

it.each(["PLATFORM_WRITE_ARGUMENTS_INVALID", "DIRECTORY_USER_UPDATE_INVALID"])(
  "lets the operator correct %s under a new key",
  async (error) => {
    const normal = directoryFetch([]);
    const writes: Array<Record<string, unknown>> = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const body = JSON.parse(String(init?.body));
        if (body.program.function !== "identity.native-user.update")
          return normal(input, init);
        writes.push(body);
        return writes.length === 1
          ? new Response(JSON.stringify({ error }), { status: 400 })
          : new Response(JSON.stringify({ status: "Active" }));
      }),
    );
    render(<ServerAdministration functions={functions} />);
    await screen.findByText("Alice");
    fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    const name = screen.getByLabelText("Display name");
    fireEvent.change(name, { target: { value: "First edit" } });
    fireEvent.submit(name.closest("form")!);
    expect(await screen.findByRole("alert")).toHaveTextContent(error);
    expect(
      screen.queryByRole("region", { name: "Directory change recovery" }),
    ).toBeNull();
    expect(name).toHaveValue("First edit");
    fireEvent.change(name, { target: { value: "Corrected edit" } });
    fireEvent.submit(name.closest("form")!);
    await screen.findByText("Updated Corrected edit.");
    expect(writes).toHaveLength(2);
    expect(writes[0].idempotencyKey).not.toBe(writes[1].idempotencyKey);
  },
);

it("keeps password assignment confirmed when its subsequent directory read fails", async () => {
  const writes: Array<Record<string, unknown>> = [];
  const normal = directoryFetch(writes);
  let failReadback = true;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const program = JSON.parse(String(init?.body)).program;
      if (failReadback && writes.length && program.function.endsWith(".list"))
        return new Response(
          JSON.stringify({ error: "KEYCLOAK_DIRECTORY_RESPONSE_INVALID" }),
          { status: 400 },
        );
      return normal(input, init);
    }),
  );
  vi.stubGlobal("crypto", {
    randomUUID: () => "22222222-2222-4222-8222-222222222222",
  });
  render(<ServerAdministration functions={functions} />);
  await screen.findByText("Alice");
  fireEvent.click(
    screen.getByRole("button", { name: "Set temporary password" }),
  );
  const form = screen
    .getByText("Set temporary password", { selector: "h3" })
    .closest("form");
  fireEvent.change(within(form!).getByLabelText("Temporary password"), {
    target: { value: "Temporary-Password-42!" },
  });
  fireEvent.click(
    within(form!).getByRole("button", { name: "Set temporary password" }),
  );

  expect(
    await screen.findByText(/Assigned a temporary password to Alice/),
  ).toBeVisible();
  const retry = await screen.findByRole("button", {
    name: "Retry directory load",
  });
  expect(screen.queryByLabelText("Temporary password")).not.toBeInTheDocument();
  expect(screen.queryByText("No matching records")).not.toBeInTheDocument();
  failReadback = false;
  fireEvent.click(retry);
  expect(await screen.findByText("Alice")).toBeVisible();
  expect(screen.queryByLabelText("Temporary password")).not.toBeInTheDocument();
  expect(writes).toHaveLength(1);
});

it("assigns a temporary password through a separate governed operation", async () => {
  const writes: Array<Record<string, unknown>> = [];
  vi.stubGlobal("fetch", directoryFetch(writes));
  vi.stubGlobal("crypto", {
    randomUUID: () => "22222222-2222-4222-8222-222222222222",
  });
  render(<ServerAdministration functions={functions} />);
  await screen.findByText("Alice");
  fireEvent.click(
    screen.getByRole("button", { name: "Set temporary password" }),
  );
  const form = screen
    .getByText("Set temporary password", { selector: "h3" })
    .closest("form");
  expect(form).not.toBeNull();
  fireEvent.change(within(form!).getByLabelText("Temporary password"), {
    target: { value: "Temporary-Password-42!" },
  });
  fireEvent.click(
    within(form!).getByRole("button", { name: "Set temporary password" }),
  );
  await waitFor(() => expect(writes).toHaveLength(1));
  expect(writes[0]).toEqual({
    program: {
      languageVersion: 2,
      function: "identity.native-user.password.set",
      arguments: {
        subjectId: "subject-1",
        temporaryPassword: "Temporary-Password-42!",
      },
    },
    idempotencyKey: "ui-22222222-2222-4222-8222-222222222222",
    confirmed: true,
  });
});

it("corrects a rejected password and checks the uncertain assignment without resending it", async () => {
  const normal = directoryFetch([]);
  const writes: Array<Record<string, unknown>> = [];
  const reads: Array<Record<string, unknown>> = [];
  const copy = vi.fn().mockResolvedValue(undefined);
  vi.stubGlobal("navigator", {
    ...window.navigator,
    clipboard: { writeText: copy },
  });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (body.program.function === "platform.operation.receipt.read") {
        expect(input).toEqual("/api/platform/browser/read");
        reads.push(body);
        if (reads.length === 1)
          return new Response(
            JSON.stringify({ error: "PLATFORM_OPERATOR_REQUIRED" }),
            {
              status: 403,
            },
          );
        const pending = reads.length === 2;
        return new Response(
          JSON.stringify({
            operationId: writes[1].idempotencyKey,
            function: "identity.native-user.password.set",
            status: pending ? "Pending" : "Committed",
            committedAt: pending ? null : "2026-11-19T12:00:00+00:00",
          }),
        );
      }
      if (body.program.function !== "identity.native-user.password.set")
        return normal(input, init);
      writes.push(body);
      const first = writes.length === 1;
      return new Response(
        JSON.stringify({
          error: first
            ? "DIRECTORY_USER_PASSWORD_INVALID"
            : "DIRECTORY_PASSWORD_OUTCOME_UNKNOWN",
        }),
        { status: first ? 400 : 409 },
      );
    }),
  );
  const randomUUID = vi
    .fn()
    .mockReturnValueOnce("11111111-1111-4111-8111-111111111111")
    .mockReturnValueOnce("22222222-2222-4222-8222-222222222222");
  vi.stubGlobal("crypto", { randomUUID });
  render(<ServerAdministration functions={functions} />);
  await screen.findByText("Alice");
  fireEvent.click(
    screen.getByRole("button", { name: "Set temporary password" }),
  );
  const form = within(
    screen
      .getByText("Set temporary password", { selector: "h3" })
      .closest("form")!,
  );
  const input = form.getByLabelText("Temporary password");
  fireEvent.change(input, { target: { value: "lowercase-password-42!" } });
  fireEvent.click(form.getByRole("button", { name: "Set temporary password" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "DIRECTORY_USER_PASSWORD_INVALID",
  );
  expect(input).not.toHaveAttribute("readonly");

  fireEvent.change(input, { target: { value: "Synthetic-Password-42!" } });
  fireEvent.click(form.getByRole("button", { name: "Set temporary password" }));
  const recovery = within(
    await screen.findByRole("region", { name: "Password assignment recovery" }),
  );
  const reconcile = recovery.getByRole("button", {
    name: "Check original password assignment",
  });
  expect(screen.queryByLabelText("Temporary password")).not.toBeInTheDocument();
  expect(screen.getByRole("alert")).toHaveTextContent(
    "The original password assignment is unconfirmed",
  );
  expect(screen.getByRole("button", { name: "+ New user" })).toBeDisabled();
  expect(writes[1].idempotencyKey).not.toBe(writes[0].idempotencyKey);
  const receiptRequest = {
    program: {
      languageVersion: 2,
      function: "platform.operation.receipt.read",
      arguments: { operationId: writes[1].idempotencyKey },
    },
  };
  fireEvent.click(
    recovery.getByRole("button", { name: "Copy receipt check for MCP" }),
  );
  await screen.findByText("Receipt check copied for your MCP client.");
  expect(copy).toHaveBeenCalledWith(JSON.stringify(receiptRequest));
  fireEvent.click(reconcile);
  await screen.findByText(/The receipt check failed/);
  expect(screen.getByRole("button", { name: "+ New user" })).toBeDisabled();
  fireEvent.click(reconcile);
  await screen.findByText(/The receipt is pending/);
  expect(screen.getByRole("button", { name: "+ New user" })).toBeDisabled();
  fireEvent.click(reconcile);
  await screen.findByText(/Assigned a temporary password to Alice/);
  expect(
    screen.queryByRole("region", { name: "Password assignment recovery" }),
  ).not.toBeInTheDocument();
  expect(reads).toEqual([receiptRequest, receiptRequest, receiptRequest]);
  expect(writes).toHaveLength(2);
  expect(randomUUID).toHaveBeenCalledTimes(2);
});

it("recovers the original password receipt after leaving during submission", async () => {
  const normal = directoryFetch([]);
  const writes: Array<Record<string, unknown>> = [];
  const reads: Array<Record<string, unknown>> = [];
  let acknowledge: ((response: Response) => void) | undefined;
  let submittedSignal: AbortSignal | null | undefined;
  vi.stubGlobal("crypto", {
    randomUUID: () => "33333333-3333-4333-8333-333333333333",
  });
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body));
      if (body.program.function === "identity.native-user.password.set") {
        writes.push(body);
        submittedSignal = init?.signal;
        return new Promise<Response>((resolve) => {
          acknowledge = resolve;
        });
      }
      if (body.program.function === "platform.operation.receipt.read") {
        reads.push(body);
        return new Response(
          JSON.stringify({
            operationId: writes[0].idempotencyKey,
            function: "identity.native-user.password.set",
            status: "Committed",
            committedAt: "2026-11-21T12:00:00Z",
          }),
        );
      }
      return normal(input, init);
    }),
  );

  setDraftIdentity("operator-a");
  const first = render(<ServerAdministration functions={functions} />);
  await screen.findByText("Alice");
  fireEvent.click(
    screen.getByRole("button", { name: "Set temporary password" }),
  );
  const input = screen.getByLabelText("Temporary password");
  fireEvent.change(input, { target: { value: "Synthetic-Password-42!" } });
  fireEvent.submit(input.closest("form")!);
  await waitFor(() => expect(writes).toHaveLength(1));
  first.unmount();

  setDraftIdentity("operator-b");
  const other = render(<ServerAdministration functions={functions} />);
  await screen.findByText("Alice");
  expect(
    screen.queryByRole("region", { name: "Password assignment recovery" }),
  ).toBeNull();
  other.unmount();

  setDraftIdentity("operator-a");
  render(<ServerAdministration functions={functions} section="groups" />);
  const recovery = within(
    await screen.findByRole("region", { name: "Password assignment recovery" }),
  );
  expect(submittedSignal?.aborted).toBe(true);
  expect(screen.queryByLabelText("Temporary password")).toBeNull();
  await act(async () =>
    acknowledge!(new Response(JSON.stringify({ status: "Active" }))),
  );
  expect(
    recovery.getByRole("button", {
      name: "Check original password assignment",
    }),
  ).toBeEnabled();
  fireEvent.click(
    recovery.getByRole("button", {
      name: "Check original password assignment",
    }),
  );
  await screen.findByText(
    "The original temporary password assignment was committed.",
  );
  expect(
    screen.queryByRole("region", { name: "Password assignment recovery" }),
  ).toBeNull();
  expect(writes).toHaveLength(1);
  expect(reads).toEqual([
    {
      program: {
        languageVersion: 2,
        function: "platform.operation.receipt.read",
        arguments: { operationId: writes[0].idempotencyKey },
      },
    },
  ]);
});

it("keeps directory drafts and selection until a section change is accepted", async () => {
  vi.stubGlobal("fetch", directoryFetch([]));
  let proceed: (() => void) | undefined;
  let preserves: boolean | undefined;
  render(
    <ServerAdministration
      functions={functions}
      onRequestTransition={(action, preserveDrafts) => {
        proceed = action;
        preserves = preserveDrafts;
      }}
    />,
  );
  await screen.findByText("Alice");
  fireEvent.click(screen.getByRole("button", { name: "+ New user" }));
  act(() => proceed?.());
  fireEvent.change(screen.getByLabelText("Username"), {
    target: { value: "retained-user" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Groups" }));
  expect(preserves).toBe(true);
  expect(screen.getByLabelText("Username")).toHaveValue("retained-user");
  expect(screen.getByRole("button", { name: "Users" })).toHaveAttribute(
    "aria-current",
    "page",
  );
  act(() => proceed?.());
  expect(await screen.findByText("Finance")).toBeInTheDocument();
  expect(screen.queryByLabelText("Username")).not.toBeInTheDocument();
});
