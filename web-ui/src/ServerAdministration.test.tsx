import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ServerAdministration } from "./ServerAdministration";

afterEach(() => vi.unstubAllGlobals());

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
  expect(screen.getAllByText("Finance").length).toBeGreaterThan(0);
  expect(screen.getByText("Member")).toBeInTheDocument();
  expect(screen.getAllByText("subject-1")).toHaveLength(2);
});

it("creates a native user through the reviewed platform write envelope", async () => {
  const writes: Array<Record<string, unknown>> = [];
  vi.stubGlobal("fetch", directoryFetch(writes));
  vi.stubGlobal("crypto", {
    randomUUID: () => "11111111-1111-4111-8111-111111111111",
  });
  render(<ServerAdministration functions={functions} />);
  await screen.findByText("Alice");
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
