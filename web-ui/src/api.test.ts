import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  admitApplicationEffect,
  listApplications,
  readPlatformProgram,
  readProgram,
  readCatalog,
  readSecurityProgram,
  request,
  requestAdmittedProgramEffect,
  reviewAndSubmit,
  previewAndSubmit,
  writePlatformProgram,
} from "./api";
import {
  browserLifecycleSnapshot,
  resetBrowserLifecycleForTests,
} from "./browser-lifecycle";
import serverContracts from "./server-contract-fixtures.json";
import type { ApplicationSummary } from "./types";

afterEach(() => {
  vi.unstubAllGlobals();
  resetBrowserLifecycleForTests();
});

describe("presentation API adapter", () => {
  it("serializes only application scope from a complete ApplicationSummary across catalog, security and program reads", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation(
        async () => new Response(JSON.stringify({ result: { rows: [] } })),
      );
    vi.stubGlobal("fetch", fetchMock);
    const application: ApplicationSummary = {
      workspaceId: "ws",
      applicationId: "app",
      name: "Planning",
      status: "Active",
    };
    await readProgram(application, "application.rule.list", {
      limit: 100,
    });
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      workspaceId: "ws",
      applicationId: "app",
      program: {
        languageVersion: 2,
        function: "application.rule.list",
        arguments: { limit: 100 },
      },
    });
    await readCatalog(application);
    await readSecurityProgram(
      application,
      "security.application.access.read",
      {},
    );
    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "/api/read",
      "/api/catalog",
      "/api/security",
    ]);
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({
      workspaceId: "ws",
      applicationId: "app",
    });
    expect(JSON.parse(fetchMock.mock.calls[2][1].body)).toEqual({
      workspaceId: "ws",
      applicationId: "app",
      program: {
        languageVersion: 2,
        function: "security.application.access.read",
        arguments: {},
      },
    });
  });
  it.each([200, 401, 503])(
    "keeps cancellation during a %s response body read out of global lifecycle state",
    async (status) => {
      const controller = new AbortController();
      let rejectBody!: (error: unknown) => void;
      const response = new Response(null, { status });
      const json = vi.spyOn(response, "json").mockImplementation(
        () =>
          new Promise((_resolve, reject) => {
            rejectBody = reject;
          }),
      );
      vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));
      const pending = request(
        "/api/platform/browser/read",
        {},
        controller.signal,
      );
      await vi.waitFor(() => expect(json).toHaveBeenCalledOnce());
      controller.abort();
      rejectBody(controller.signal.reason);
      await expect(pending).rejects.toBe(controller.signal.reason);
      expect(browserLifecycleSnapshot().state).toBe("bootstrapping");
    },
  );

  it("rejects a successful parsed response when its owning request was canceled", async () => {
    const controller = new AbortController();
    const response = new Response(null);
    vi.spyOn(response, "json").mockImplementation(async () => {
      controller.abort();
      return { stale: true };
    });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));
    await expect(
      request("/api/catalog", {}, controller.signal),
    ).rejects.toMatchObject({ name: "AbortError" });
    expect(browserLifecycleSnapshot().state).toBe("bootstrapping");
  });

  it("does not classify an owned cancellation with a custom abort reason as an outage", async () => {
    const controller = new AbortController();
    const reason = new Error("View replaced");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async () => {
        controller.abort(reason);
        throw reason;
      }),
    );
    await expect(request("/api/catalog", {}, controller.signal)).rejects.toBe(
      reason,
    );
    expect(browserLifecycleSnapshot().state).toBe("bootstrapping");
  });

  it("uses the existing endpoint without changing a request body", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const body = { workspaceId: "ws", applicationId: "app" };
    await request("/api/catalog", body);
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/catalog",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify(body),
        credentials: "same-origin",
      }),
    );
  });

  it("submits only the exact server preview after explicit review", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            previewToken: "sealed-preview-token",
            programDigest: "a".repeat(64),
            revisionVector: { metadata: 3, data: 4 },
          }),
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            operationId: `oa1_zz_${"1".repeat(32)}_${"A".repeat(43)}`,
            expiresAt: Math.floor(Date.now() / 1000) + 900,
            intentDigest: "b".repeat(64),
          }),
        ),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify({ jobId: "job-1" })));
    vi.stubGlobal("fetch", fetchMock);
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(true);
    const body = {
      workspaceId: "ws",
      applicationId: "app",
      program: {
        languageVersion: 2,
        function: "facts.numeric.batch",
        arguments: { mutations: [] },
      },
      idempotencyKey: "intent-1",
      dependsOnJobIds: [],
      confirmed: true,
    };
    await expect(reviewAndSubmit(body, "Review writeback.")).resolves.toEqual({
      jobId: "job-1",
    });
    expect(fetchMock.mock.calls[0][0]).toBe("/api/preview");
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      workspaceId: "ws",
      applicationId: "app",
      program: body.program,
    });
    expect(fetchMock.mock.calls[1][0]).toBe("/api/operation-admission");
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({
      workspaceId: "ws",
      applicationId: "app",
      program: body.program,
    });
    expect(JSON.parse(fetchMock.mock.calls[2][1].body)).toEqual({
      ...body,
      idempotencyKey: `oa1_zz_${"1".repeat(32)}_${"A".repeat(43)}`,
      previewToken: "sealed-preview-token",
    });
    expect(confirm.mock.calls[0][0]).toContain("a".repeat(64));
    expect(confirm.mock.calls[0][0]).toContain(
      'Dependency revisions: {"metadata":3,"data":4}',
    );
  });

  it("reuses one bounded admission for the same exact browser retry intent", async () => {
    const operationId = `oa1_zz_${"2".repeat(32)}_${"B".repeat(43)}`;
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          operationId,
          expiresAt: Math.floor(Date.now() / 1000) + 900,
          intentDigest: "c".repeat(64),
        }),
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    const first = {
      workspaceId: "ws",
      applicationId: "app",
      program: {
        languageVersion: 2,
        function: "facts.numeric.batch",
        arguments: { mutations: [], expectedDataRevision: 4 },
      },
      idempotencyKey: "stable-browser-intent",
    };
    const reordered = {
      ...first,
      program: {
        arguments: { expectedDataRevision: 4, mutations: [] },
        function: "facts.numeric.batch",
        languageVersion: 2,
      },
    };
    await expect(admitApplicationEffect(first)).resolves.toBe(operationId);
    await expect(admitApplicationEffect(reordered)).resolves.toBe(operationId);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("keeps the fixed program intact while sending its admission separately", async () => {
    const operationId = `oa1_zz_${"3".repeat(32)}_${"C".repeat(43)}`;
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            operationId,
            expiresAt: Math.floor(Date.now() / 1000) + 900,
            intentDigest: "d".repeat(64),
          }),
        ),
      )
      .mockResolvedValueOnce(new Response(JSON.stringify({ result: {} })));
    vi.stubGlobal("fetch", fetchMock);
    const body = {
      workspaceId: "ws",
      applicationId: "app",
      confirmed: true,
      program: {
        languageVersion: 2,
        function: "facts.transfer.export.request",
        arguments: { idempotencyKey: "stable-export-intent" },
      },
    };
    await requestAdmittedProgramEffect(
      "/api/export",
      body,
      "stable-export-intent",
    );
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      workspaceId: "ws",
      applicationId: "app",
      program: body.program,
    });
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({
      ...body,
      idempotencyKey: operationId,
    });
  });

  it("never submits a rejected or malformed server preview", async () => {
    const body = {
      workspaceId: "ws",
      applicationId: "app",
      program: {
        languageVersion: 2,
        function: "facts.numeric.batch",
        arguments: {},
      },
      idempotencyKey: "intent-2",
      dependsOnJobIds: [],
      confirmed: true,
    };
    const rejectedFetch = vi
      .fn()
      .mockResolvedValue(
        new Response(JSON.stringify({ previewToken: "sealed-preview-token" })),
      );
    vi.stubGlobal("fetch", rejectedFetch);
    vi.spyOn(window, "confirm").mockReturnValue(false);
    await expect(reviewAndSubmit(body, "Review.")).resolves.toBeNull();
    expect(rejectedFetch).toHaveBeenCalledTimes(1);

    const malformedFetch = vi
      .fn()
      .mockResolvedValue(
        new Response(JSON.stringify({ previewToken: "short" })),
      );
    vi.stubGlobal("fetch", malformedFetch);
    await expect(reviewAndSubmit(body, "Review.")).rejects.toMatchObject({
      code: "INVALID_SERVER_PREVIEW",
    });
    expect(malformedFetch).toHaveBeenCalledTimes(1);
  });

  it("retains server error codes", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ error: "ACCESS_DENIED" }), {
          status: 403,
          headers: { "content-type": "application/json" },
        }),
      ),
    );
    await expect(request("/api/catalog", {})).rejects.toEqual(
      new ApiError(403, "ACCESS_DENIED"),
    );
  });

  it("retains correlation, retryability and safe field details", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            error: "CAPACITY_REJECTED",
            code: "CAPACITY_REJECTED",
            message: "Capacity rejected",
            correlationId: "a".repeat(32),
            retryable: true,
            details: { field: "rows" },
          }),
          { status: 429 },
        ),
      ),
    );
    await expect(request("/api/source-load", {})).rejects.toMatchObject({
      kind: "capacity",
      code: "CAPACITY_REJECTED",
      correlationId: "a".repeat(32),
      retryable: true,
      details: { field: "rows" },
      message: "Capacity rejected",
    });
  });

  it("preserves source diagnostics for editor highlighting and agent repair", async () => {
    const details = {
      format: "openepm-diagnostics-v1",
      sourceDigest: "b".repeat(64),
      positionEncoding: "utf-16",
      truncated: false,
      diagnostics: [
        {
          code: "PYTHON_SYNTAX_ERROR",
          severity: "error",
          stage: "syntax",
          message: "invalid syntax",
          span: { startLine: 2, startColumn: 11, endLine: 2, endColumn: 12 },
        },
      ],
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            code: "PYTHON_SOURCE_VALIDATION_FAILED",
            message: "Python source validation failed",
            details,
          }),
          { status: 400 },
        ),
      ),
    );
    await expect(request("/api/python-program", {})).rejects.toMatchObject({
      code: "PYTHON_SOURCE_VALIDATION_FAILED",
      message: "Python source validation failed",
      details,
    });
    expect(browserLifecycleSnapshot().state).toBe("bootstrapping");
  });

  it("makes an expired session an application-wide state", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ error: "ACCESS_TOKEN_EXPIRED" }), {
          status: 401,
          headers: { "content-type": "application/json" },
        }),
      ),
    );
    await expect(request("/api/session-identity")).rejects.toMatchObject({
      kind: "authentication",
    });
    expect(browserLifecycleSnapshot()).toMatchObject({
      state: "expired",
      reason: "ACCESS_TOKEN_EXPIRED",
    });
  });

  it("keeps authorization denial separate from session expiry", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ error: "ACCESS_DENIED" }), {
          status: 403,
          headers: { "content-type": "application/json" },
        }),
      ),
    );
    await expect(request("/api/catalog", {})).rejects.toMatchObject({
      kind: "authorization",
    });
    expect(browserLifecycleSnapshot().state).toBe("bootstrapping");
  });

  it("rejects redirected API responses as application-wide expiry", async () => {
    const response = new Response("<html>sign in</html>", { status: 200 });
    Object.defineProperty(response, "redirected", { value: true });
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));
    await expect(request("/api/session-identity")).rejects.toMatchObject({
      kind: "authentication",
      code: "AUTHENTICATION_REDIRECTED",
    });
    expect(browserLifecycleSnapshot()).toMatchObject({
      state: "expired",
      reason: "AUTHENTICATION_REDIRECTED",
    });
  });

  it("rejects successful non-JSON responses as unavailable", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response("<html>upstream error</html>", { status: 200 }),
        ),
    );
    await expect(request("/api/session-identity")).rejects.toMatchObject({
      kind: "unavailable",
      code: "INVALID_RESPONSE_CONTENT",
    });
    expect(browserLifecycleSnapshot()).toMatchObject({
      state: "unavailable",
      reason: "INVALID_RESPONSE_CONTENT",
    });
  });

  it("follows the existing bounded application pagination contract", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            ...serverContracts.applicationPage,
            nextAfter: { workspaceId: "ws", applicationId: "app" },
          }),
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            applications: [
              {
                workspaceId: "b",
                applicationId: "2",
                name: "Two",
                status: "active",
              },
            ],
            nextAfter: null,
          }),
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    expect(await listApplications()).toHaveLength(2);
    expect(fetchMock.mock.calls[1][0]).toContain("afterWorkspaceId=ws");
  });

  it("rejects incomplete or substituted application continuations", async () => {
    const invalidCursor = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          ...serverContracts.applicationPage,
          nextAfter: { workspaceId: "other", applicationId: "cursor" },
        }),
      ),
    );
    vi.stubGlobal("fetch", invalidCursor);
    await expect(listApplications()).rejects.toMatchObject({
      code: "INVALID_APPLICATION_CATALOG_CONTINUATION",
    });

    const repeated = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            ...serverContracts.applicationPage,
            nextAfter: { workspaceId: "ws", applicationId: "app" },
          }),
        ),
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify(serverContracts.applicationPage)),
      );
    vi.stubGlobal("fetch", repeated);
    await expect(listApplications()).rejects.toMatchObject({
      code: "APPLICATION_CATALOG_REPEATED_APPLICATION",
    });
  });

  it("keeps server directory reads and writes inside the platform browser boundary", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation(
        async () =>
          new Response(JSON.stringify({ items: [] }), { status: 200 }),
      );
    vi.stubGlobal("fetch", fetchMock);
    await readPlatformProgram("identity.group.list", { offset: 0, limit: 100 });
    await writePlatformProgram(
      "identity.group.membership.set",
      { subjectId: "user-1", groupId: "finance", action: "add" },
      "request-1",
    );
    expect(fetchMock.mock.calls[0][0]).toBe("/api/platform/browser/read");
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({
      program: {
        languageVersion: 2,
        function: "identity.group.list",
        arguments: { offset: 0, limit: 100 },
      },
    });
    expect(fetchMock.mock.calls[1][0]).toBe("/api/platform/browser/write");
    expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({
      program: {
        languageVersion: 2,
        function: "identity.group.membership.set",
        arguments: {
          subjectId: "user-1",
          groupId: "finance",
          action: "add",
        },
      },
      idempotencyKey: "request-1",
      confirmed: true,
    });
  });
});

it.each([
  undefined,
  {
    ruleId: "other",
    stateToken: "c".repeat(64),
    programDigest: "a".repeat(64),
  },
  { ruleId: "rule", stateToken: "d".repeat(64), programDigest: "a".repeat(64) },
  { ruleId: "rule", stateToken: "c".repeat(64), programDigest: "b".repeat(64) },
])(
  "never auto-submits a preview with missing or changed saved-program identity: %s",
  async (savedProgram) => {
    const fetch = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          previewToken: "sealed-preview-token",
          savedProgram,
        }),
      ),
    );
    vi.stubGlobal("fetch", fetch);
    const confirm = vi.spyOn(window, "confirm");
    await expect(
      previewAndSubmit(
        {
          workspaceId: "ws",
          applicationId: "app",
          program: {},
          idempotencyKey: "intent-1",
          dependsOnJobIds: [],
          confirmed: true,
        },
        {
          ruleId: "rule",
          stateToken: "c".repeat(64),
          programDigest: "a".repeat(64),
        },
      ),
    ).rejects.toMatchObject({ code: "SAVED_PROGRAM_PREVIEW_CHANGED" });
    expect(fetch).toHaveBeenCalledTimes(1);
    expect(confirm).not.toHaveBeenCalled();
  },
);
