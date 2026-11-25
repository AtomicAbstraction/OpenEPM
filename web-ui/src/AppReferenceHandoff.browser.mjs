// Rendered integration of the real App, Analyze and Monitor. Every API response
// is an in-memory fixture; no product backend, database or shared identity is used.
// Run: node web-ui/src/AppReferenceHandoff.browser.mjs [result.json]
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(import.meta.url);
let playwrightModule = process.env.OPEN_EPM_PLAYWRIGHT_MODULE;
if (!playwrightModule) {
  try {
    playwrightModule = require.resolve("playwright");
  } catch {
    playwrightModule = resolve(
      execFileSync("npm", ["root", "--global"], { encoding: "utf8" }).trim(),
      "playwright",
    );
  }
}
const { chromium } = require(playwrightModule);
const { createServer } = await import(
  resolve(webRoot, "node_modules/vite/dist/node/index.js")
);
const sources = [
  "src/App.tsx",
  "src/AppReferenceHandoff.browser.mjs",
  "src/Analyze.tsx",
  "src/Breadcrumbs.tsx",
  "src/CapabilityArea.tsx",
  "src/GenericWorkflow.tsx",
  "src/MetadataWorkspace.tsx",
  "src/Monitor.tsx",
  "src/MyWork.tsx",
  "src/PythonProgramRun.tsx",
  "src/api.ts",
  "src/metadata-navigation.ts",
  "src/reference-handoff.ts",
  "src/workflow-destination.ts",
  "src/styles.css",
  "src/focused-workspaces.css",
  "src/metadata-workspace.css",
  "package-lock.json",
  "vite.config.ts",
];
async function sourceHashes() {
  return Object.fromEntries(
    await Promise.all(
      sources.map(async (name) => [
        name,
        createHash("sha256")
          .update(await readFile(resolve(webRoot, name)))
          .digest("hex"),
      ]),
    ),
  );
}
const cacheDir = await mkdtemp(resolve(tmpdir(), "openepm-reference-handoff-"));
await mkdir(resolve(cacheDir, "node_modules"));
const configFile = resolve(cacheDir, "qualification.vite.config.mjs");
await writeFile(
  configFile,
  `import original from ${JSON.stringify(resolve(webRoot, "vite.config.ts"))};\nexport default original;\n`,
);
const server = await createServer({
  root: webRoot,
  cacheDir,
  configFile,
  server: { host: "127.0.0.1", port: 0 },
  clearScreen: false,
  logLevel: "error",
});
const application = {
  workspaceId: "fixture",
  applicationId: "handoff",
  name: "Handoff fixture",
  status: "Active",
  kind: "blank",
};
const grid = {
  gridId: "capacity_by_team",
  name: "Capacity by team",
  stateToken: "c".repeat(64),
  canonicalDigest: "d".repeat(64),
  metadataRevision: 11,
  definition: {
    format: "openepm-cube-view-v1",
    viewId: "capacity_by_team",
    name: "Capacity by team",
    selection: {
      format: "openepm-cube-selection-v1",
      metadataRevision: 11,
      dimensions: ["Account", "Period"].map((dimensionId) => ({
        dimensionId,
        include: { kind: "members", memberIds: [`${dimensionId}-member`] },
        exclude: null,
      })),
    },
    layout: { rows: ["Account"], columns: ["Period"], pages: [], filters: [] },
    dataSource: { kind: "raw", resultKey: null },
    suppression: { missing: false, zero: false },
    pageSize: 100,
  },
};
const monitorTask = {
  taskId: "a:" + "2".repeat(32),
  sequence: 1,
  function: "Review the period close",
  sourceFamily: "Job",
  status: "Succeeded",
  progressState: "succeeded",
  interruptible: false,
  rerunSupported: false,
  events: [],
};
const workflowOrigin = {
  kind: "workflowActivity",
  occurrenceId: "b".repeat(32),
  activityId: "review",
};
const originActivity = {
  activityId: workflowOrigin.activityId,
  name: "Review the original period close",
  kind: "Review",
  dependsOn: [],
  returnTo: null,
  destination: {
    kind: "CubeView",
    viewId: grid.gridId,
    digest: grid.canonicalDigest,
  },
  evidenceContract: {
    kind: "ManualAttestation",
    statement: "Reviewed the period close",
  },
};
const readyWork = {
  ...workflowOrigin,
  ...originActivity,
  flowId: "period-close",
  flowStateToken: "a".repeat(64),
  definitionDigest: "b".repeat(64),
  occurrenceStateToken: "c".repeat(64),
  activityStateToken: "d".repeat(64),
  assignmentResolution: { assignmentId: "reviewer", kind: "Review" },
};
const catalog = {
  applicationAccess: {
    role: "Administrator",
    issuer: "fixture",
    workspaceAdministrator: false,
  },
  enabledCapabilities: [],
  functions: {
    "metadata.dimension.list": {},
    "metadata.member.list": {},
    "grid.definition.read": {},
    "grid.definition.list": {},
    "application.workflow.worklist": {},
    "application.workflow.occurrence.read": {},
    "application.workflow.read": {},
    "facts.cube.resolved.read": {
      canonicalViewRead: "openepm-cube-view-read-v1",
    },
  },
  revisions: { metadata: 11, data: 1, policy: 1, security: 1, commit: 11 },
};
const handoff = {
  format: "openepm.reference-handoff/v1",
  scope: { workspaceId: "fixture", applicationId: "handoff" },
  origin: { kind: "task", taskId: "a:" + "1".repeat(32) },
  target: { kind: "savedView", viewId: grid.gridId },
  returnTo: { kind: "task", taskId: "a:" + "1".repeat(32) },
  observed: { viewDigest: grid.canonicalDigest },
  pendingOperation: null,
  analyticalRead: { semantics: "stored" },
};
const legacyId = "legacy-ordered-fixture";
const legacyReference = {
  ...handoff,
  target: {
    kind: "definition",
    artifactKind: "ApplicationSequence",
    artifactId: legacyId,
  },
  returnTo: workflowOrigin,
  observed: { stateToken: "a".repeat(64), definitionDigest: "b".repeat(64) },
  analyticalRead: undefined,
};
const sourceProgram = {
  programId: "general-plan",
  stateToken: "b".repeat(64),
  sourceToken: "c".repeat(64),
  status: "Active",
  entryPoint: "build",
  environmentId: "approved",
  environmentStateToken: "d".repeat(64),
  sourceDigest: "a".repeat(64),
  declaredOutput: null,
};
const hash = (value) =>
  `#/reference?${new URLSearchParams({ handoff: JSON.stringify(value) })}`;
const report = {
  method:
    "Chromium real App/Analyze/Monitor over current Vite source; all API calls intercepted with isolated read fixtures",
  apiRequests: [],
  pageErrors: [],
  unknownApi: [],
  mutations: 0,
  cases: [],
  taskNavigation: [],
  workspaceNavigation: [],
  sourceBefore: await sourceHashes(),
};
const json = (body, status = 200) => ({
  status,
  contentType: "application/json",
  body: JSON.stringify(body),
});
let browser;
let holdTaskRead;
let holdTaskList;
let holdPythonSourceRead;
let exposeAssignedWork = false;
let exposeWorkspaceRoutes = false;
let exposeAuthorityRead = true;
let exposePartialManagement = false;
try {
  await server.listen();
  const base = "http://127.0.0.1:" + server.httpServer.address().port;
  browser = await chromium.launch({ headless: true });
  report.browserVersion = browser.version();
  const context = await browser.newContext({
    viewport: { width: 1280, height: 908 },
    permissions: ["clipboard-read", "clipboard-write"],
  });
  const page = await context.newPage();
  page.on("pageerror", (error) => report.pageErrors.push(error.message));
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== base) return route.abort();
    if (!url.pathname.startsWith("/api/")) return route.continue();
    const body = route.request().postDataJSON();
    const path = url.pathname;
    report.apiRequests.push({ path, body });
    if (path === "/api/applications")
      return route.fulfill(
        json({ applications: [application], nextAfter: null }),
      );
    if (path === "/api/session-identity")
      return route.fulfill(
        json({
          issuer: "fixture",
          subject: "receiver",
          identityBinding: "a".repeat(64),
          displayIdentity: "Fixture receiver",
        }),
      );
    if (path === "/api/runtime")
      return route.fulfill(
        json({
          readOnlyReview: true,
          build: { sourceCommit: "a".repeat(40), packagedSchema: 1 },
        }),
      );
    if (path === "/api/platform/browser/catalog")
      return route.fulfill(json({ languageVersion: 2, functions: {} }));
    if (path === "/api/catalog")
      return route.fulfill(
        json(
          exposeWorkspaceRoutes
            ? {
                ...catalog,
                functions: {
                  ...catalog.functions,
                  "application.rule.list": {},
                  "application.rule.read": {},
                  "python.program.list": {},
                  "python.program.read": {},
                  "python.program.build": {},
                  "python.program.run": {},
                  "execution.delegation.list": {},
                  ...(exposeAuthorityRead
                    ? { "execution.delegation.read": {} }
                    : {}),
                  ...(exposePartialManagement
                    ? {
                        "python.schedule.list": {},
                        "security.application.subject.list": {},
                        "security.identity.current.read": {},
                      }
                    : {}),
                },
              }
            : catalog,
        ),
      );
    if (path === "/api/python-program") {
      const { function: fn, arguments: args } = body.program;
      if (fn === "python.program.list")
        return route.fulfill(
          json({
            result: { programs: [sourceProgram], nextAfterProgramId: null },
          }),
        );
      if (fn === "python.program.read") {
        assert.equal(args.programId, sourceProgram.programId);
        const held = holdPythonSourceRead;
        holdPythonSourceRead = undefined;
        if (held) await held;
        return route.fulfill(
          json({
            result: {
              ...sourceProgram,
              defined: true,
              sourceText:
                "def build(context, parameters):\n    return Program()",
              parameterSchema: { type: "object" },
            },
          }),
        );
      }
    }
    if (
      path === "/api/execution-delegation" &&
      body.program.function === "execution.delegation.list"
    ) {
      assert(exposeAuthorityRead);
      return route.fulfill(
        json({ result: { delegations: [], nextAfterDelegationId: null } }),
      );
    }
    if (path === "/api/tasks") {
      const held = holdTaskList;
      holdTaskList = undefined;
      const result = held
        ? await held
        : { tasks: [monitorTask], nextSequence: 1, hasMore: false };
      return route.fulfill(json(result));
    }
    if (path === "/api/task") {
      if (body?.taskId !== monitorTask.taskId)
        return route.fulfill(json({ error: "TASK_UNAVAILABLE" }, 403));
      const held = holdTaskRead;
      holdTaskRead = undefined;
      if (held) await held;
      return route.fulfill(json(monitorTask));
    }
    if (path === "/api/read") {
      assert.equal(body.workspaceId, "fixture");
      assert.equal(body.applicationId, "handoff");
      const fn = body.program.function;
      if (fn === "application.rule.list")
        return route.fulfill(
          json({
            result: {
              rows: [],
              hasMore: false,
              nextAfterRuleId: null,
              metadataRevision: 11,
              policyRevision: 1,
            },
          }),
        );
      if (fn === "metadata.dimension.list")
        return route.fulfill(
          json({
            result: {
              rows: [
                ...["Account", "Period"].map((id) => ({
                  dimension_id: id,
                  name:
                    id === "Account" && exposeWorkspaceRoutes
                      ? "Planning accounts"
                      : id,
                  model_role: id,
                  status: "Active",
                })),
                ...(exposeWorkspaceRoutes
                  ? [
                      {
                        dimension_id: "Archive",
                        name: "Retired years",
                        model_role: "Standard",
                        status: "Inactive",
                      },
                    ]
                  : []),
              ],
              nextAfterDimensionId: null,
              metadataRevision: 11,
            },
          }),
        );
      if (fn === "metadata.member.list")
        return route.fulfill(
          json({
            result: {
              rows: [
                {
                  member_id: `${body.program.arguments.dimensionId}-member`,
                  name: "Fixture member",
                  status: "Active",
                },
              ],
              nextAfterMemberId: null,
              metadataRevision: 11,
            },
          }),
        );
      if (fn === "grid.definition.read")
        return route.fulfill(json({ result: grid }));
      if (fn === "grid.definition.list")
        return route.fulfill(
          json({
            result: {
              grids: [grid],
              nextAfterGridId: null,
              collectionToken: "b".repeat(64),
            },
          }),
        );
      if (fn === "application.workflow.worklist") {
        const items = exposeAssignedWork
          ? body.program.arguments.occurrenceId
            ? [readyWork]
            : Array.from({ length: 50 }, (_, i) => ({
                ...readyWork,
                occurrenceId: (i + 1).toString(16).padStart(32, "0"),
                name: `Routine activity ${i + 1}`,
              })).concat(readyWork)
          : [];
        return route.fulfill(json({ result: { items, nextCursor: null } }));
      }
      if (fn === "application.workflow.occurrence.read") {
        assert.equal(
          body.program.arguments.occurrenceId,
          workflowOrigin.occurrenceId,
        );
        return route.fulfill(
          json({
            result: {
              occurrenceId: workflowOrigin.occurrenceId,
              flowId: "period-close",
              flowStateToken: "a".repeat(64),
              definitionDigest: "b".repeat(64),
              occurrenceStateToken: "c".repeat(64),
              status: exposeAssignedWork ? "Active" : "Completed",
              lastEventOrdinal: 1,
              activities: [
                {
                  activityId: workflowOrigin.activityId,
                  kind: "Review",
                  status: exposeAssignedWork ? "Ready" : "Completed",
                  activityStateToken: "d".repeat(64),
                },
              ],
              events: [],
              currentReturns: [],
              nextEventOrdinal: null,
            },
          }),
        );
      }
      if (fn === "application.workflow.read") {
        assert.equal(body.program.arguments.flowId, "period-close");
        return route.fulfill(
          json({
            result: {
              flowId: "period-close",
              stateToken: "a".repeat(64),
              definitionDigest: "b".repeat(64),
              definition: {
                name: "Original period close",
                activities: [originActivity],
              },
            },
          }),
        );
      }
    }
    if (["/api/program", "/api/authorize", "/api/cancel"].includes(path))
      report.mutations += 1;
    report.unknownApi.push({ path, body });
    return route.fulfill(
      json({ error: { code: "FIXTURE_READ_NOT_DEFINED" } }, 400),
    );
  });

  await page.goto(base + "/" + hash(handoff));
  const copy = page.getByRole("button", { name: "Copy client references" });
  await copy.waitFor({ state: "visible" });
  await copy.click();
  const copied = JSON.parse(
    await page.evaluate(() => navigator.clipboard.readText()),
  );
  assert.deepEqual(copied, handoff);
  await page.getByRole("button", { name: "Copy link to this view" }).click();
  const copiedLink = await page.evaluate(() => navigator.clipboard.readText());
  assert.deepEqual(
    JSON.parse(
      new URLSearchParams(new URL(copiedLink).hash.split("?")[1]).get(
        "handoff",
      ),
    ),
    handoff,
  );
  report.cases.push({
    name: "real saved-view resolution and separate stored-policy JSON/link copy",
    status: "passed",
  });

  await page
    .getByRole("button", { name: "Return to task", exact: true })
    .click();
  await page
    .getByRole("alert")
    .filter({ hasText: "TASK_UNAVAILABLE" })
    .waitFor();
  assert.equal(
    await page
      .getByRole("complementary", { name: "Selected task detail" })
      .count(),
    0,
  );
  const taskReads = report.apiRequests.filter(
    (row) => row.path === "/api/task",
  );
  assert.deepEqual(
    taskReads.map((row) => row.body),
    [
      {
        ...handoff.scope,
        taskId: handoff.returnTo.taskId,
        afterEvent: 0,
        eventLimit: 100,
      },
    ],
  );
  report.cases.push({
    name: "return uses exact authorized read and refuses revoked origin without fallback",
    status: "passed",
  });

  await page.goto(
    base + "/" + hash({ ...handoff, observed: { viewDigest: "e".repeat(64) } }),
  );
  await page
    .getByRole("alert")
    .filter({ hasText: "no longer matches its pinned grid digest" })
    .waitFor();
  assert.equal(
    await page.getByRole("button", { name: "Copy client references" }).count(),
    0,
  );
  report.cases.push({
    name: "changed owner digest is refused before publishing a copyable view context",
    status: "passed",
  });

  await page.goto(
    base +
      "/" +
      hash({
        ...handoff,
        analyticalRead: {
          semantics: "effective",
          bindingId: "binding",
          bindingStateToken: "f".repeat(64),
        },
      }),
  );
  await page
    .getByRole("alert")
    .filter({ hasText: "cannot restore an effective binding" })
    .waitFor();
  assert.equal(
    await page.getByRole("button", { name: "Copy client references" }).count(),
    0,
  );
  report.cases.push({
    name: "unsupported saved-view/effective policy refuses semantic substitution",
    status: "passed",
  });

  // Open a canonical view through the ordinary workspace rather than a targeted
  // URL, then prove the link captures the newly opened view.
  await page.goto(base + "/#/grid/0?workspace=fixture&application=handoff");
  await page.getByRole("button", { name: "Open view", exact: true }).click();
  await copy.waitFor({ state: "visible" });
  await copy.click();
  const internallyOpened = JSON.parse(
    await page.evaluate(() => navigator.clipboard.readText()),
  );
  assert.deepEqual(internallyOpened.target, handoff.target);
  assert.deepEqual(internallyOpened.scope, handoff.scope);
  assert.deepEqual(internallyOpened.analyticalRead, { semantics: "own" });
  assert.equal(internallyOpened.returnTo, null);
  report.cases.push({
    name: "view opened inside Grid exports its actual own-policy context",
    status: "passed",
  });

  const monitorUrl =
    base + "/#/monitor/0?workspace=fixture&application=handoff";
  const panel = page.getByRole("complementary", {
    name: "Selected task detail",
  });
  const row = page.getByRole("button", {
    name: monitorTask.function,
    exact: true,
  });
  const close = panel.getByRole("button", { name: "Close task detail" });
  const search = page.getByRole("searchbox", { name: "Search loaded tasks" });
  const main = page.getByRole("main");
  const focused = (locator) =>
    locator.evaluate((element) => document.activeElement === element);
  const focusVisible = (locator) =>
    locator.evaluate((element) => {
      const rect = element.getBoundingClientRect();
      const hit = document.elementFromPoint(
        rect.left + rect.width / 2,
        rect.top + rect.height / 2,
      );
      return document.activeElement === element && element.contains(hit);
    });
  const taskLink = hash({
    ...handoff,
    origin: workflowOrigin,
    target: { kind: "task", taskId: monitorTask.taskId },
    returnTo: workflowOrigin,
    observed: {},
    analyticalRead: undefined,
  });
  const keyboardWidths = [650, 651, 684, 950, 951, 1280];
  for (const width of keyboardWidths) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto(monitorUrl);
    await row.press("Enter");
    await close.waitFor();
    assert(
      await focusVisible(close),
      `visible task detail focus at ${width}px`,
    );
    await page.keyboard.press("Escape");
    await panel.waitFor({ state: "detached" });
    assert(await focusVisible(row), `same task row focus at ${width}px`);

    await page.goto(base + "/" + taskLink);
    await close.press("Enter");
    await page
      .getByRole("heading", { name: originActivity.name, exact: true })
      .waitFor();
    assert(await focused(main), `workflow route focus at ${width}px`);
    const returned = JSON.parse(
      new URLSearchParams(page.url().split("?").at(-1)).get("handoff"),
    );
    assert.deepEqual(returned.scope, handoff.scope);
    assert.deepEqual(returned.target, workflowOrigin);
    assert.equal(returned.returnTo, null);
  }
  report.cases.push({
    name: "Keyboard focus enters task detail, returns to the same row, and follows a linked Close to its exact workflow",
    widths: keyboardWidths,
    status: "passed",
  });

  await page.setViewportSize({ width: 684, height: 900 });
  await page.goto(monitorUrl);
  let deliverTask;
  holdTaskRead = new Promise((resolve) => {
    deliverTask = resolve;
  });
  try {
    const requestStarted = page.waitForRequest((request) =>
      request.url().endsWith("/api/task"),
    );
    const precedingReads = report.apiRequests.filter(
      (item) => item.path === "/api/task",
    ).length;
    await row.press("Enter");
    await requestStarted;
    assert(await focused(row));
    assert.equal(await row.getAttribute("aria-disabled"), "true");
    await row.press("Enter");
    await search.focus();
    deliverTask();
    await close.waitFor();
    assert(await focused(search));
    assert.equal(
      report.apiRequests.filter((item) => item.path === "/api/task").length,
      precedingReads + 1,
    );

    await search.fill("No matching loaded task");
    await row.waitFor({ state: "detached" });
    await close.press("Escape");
    await panel.waitFor({ state: "detached" });
    assert(await focusVisible(search));
  } finally {
    deliverTask();
  }
  report.cases.push({
    name: "A delayed task read respects focus moved elsewhere and closing a filtered task returns to search",
    width: 684,
    status: "passed",
  });

  for (const width of [684, 1280]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto(monitorUrl);
    await row.press("Enter");
    await close.waitFor();
    let deliverList, deliverDetail;
    holdTaskList = new Promise((resolve) => {
      deliverList = resolve;
    });
    holdTaskRead = new Promise((resolve) => {
      deliverDetail = resolve;
    });
    try {
      const listStarted = page.waitForRequest((request) =>
        request.url().endsWith("/api/tasks"),
      );
      const detailStarted = page.waitForRequest((request) =>
        request.url().endsWith("/api/task"),
      );
      await page
        .getByRole("button", { name: "Refresh", exact: true })
        .press("Enter");
      await Promise.all([listStarted, detailStarted]);
      await close.press("Escape");
      await panel.waitFor({ state: "detached" });
      assert(await focusVisible(search));
      await page.getByText("Reading task results…", { exact: true }).waitFor();
      deliverList({ tasks: [], nextSequence: 0, hasMore: false });
      await page.getByText("0 tasks loaded.", { exact: true }).waitFor();
      assert.equal(await row.count(), 0);
      assert(await focusVisible(search));
    } finally {
      deliverList({ tasks: [], nextSequence: 0, hasMore: false });
      deliverDetail();
    }
    await panel.waitFor({ state: "detached" });
    await page.goto(
      monitorUrl + "&task=" + encodeURIComponent(monitorTask.taskId),
    );
    await close.press("Enter");
    await panel.waitFor({ state: "detached" });
    assert.equal(
      await page
        .getByText("Checking current access to the referenced task…", {
          exact: true,
        })
        .count(),
      0,
    );
    assert(await focusVisible(search));
    report.cases.push({
      name: "Closing a task during Refresh preserves the current list read and clears the closed reference status",
      width,
      status: "passed",
    });
  }

  const workUrl = base + "/#/work/0?workspace=fixture&application=handoff";
  const metadataUrl =
    base + "/#/metadata/0?workspace=fixture&application=handoff";
  const legacyUrl = base + "/" + hash(legacyReference);
  const authorityLink = "Open execution authorities";
  exposeAssignedWork = true;
  for (const width of [650, 651, 684, 950, 951]) {
    await page.setViewportSize({ width, height: 900 });
    for (const state of width === 650
      ? ["mobile-closed"]
      : ["expanded", "manual-collapsed"]) {
      const scenario = { width, state, controls: [] };
      report.taskNavigation.push(scenario);
      let observations = scenario.controls;
      const requestStart = report.apiRequests.length;
      async function prepareShell() {
        await page.locator(".shell").waitFor();
        if (width === 650) {
          assert.equal(
            await page.locator(".sidebar[aria-modal=true]").count(),
            0,
          );
          return;
        }
        const desired =
          state === "expanded" ? "Expand sidebar" : "Collapse sidebar";
        const toggle = page.getByRole("button", { name: desired, exact: true });
        if (await toggle.isVisible()) {
          await toggle.click();
          await page
            .locator("#primary-navigation")
            .evaluate(async (sidebar) => {
              sidebar.getBoundingClientRect();
              await Promise.allSettled(
                sidebar.getAnimations().map((animation) => animation.finished),
              );
            });
        }
        assert.equal(
          await page.locator(".shell.collapsed").count(),
          state === "manual-collapsed" ? 1 : 0,
        );
      }
      async function activate(
        name,
        visibleText,
        key = "Enter",
        role = "button",
      ) {
        await prepareShell();
        const control = main.getByRole(role, { name, exact: true });
        await control.waitFor();
        assert(
          (await control.innerText()).includes(visibleText),
          `visual cue for ${name}`,
        );
        await control.press("Shift+Tab");
        await page.keyboard.press("Tab");
        if (!(await focusVisible(control))) {
          const placement = await control.evaluate((element) => {
            const { left, top, width, height } =
              element.getBoundingClientRect();
            const hit = document.elementFromPoint(
              left + width / 2,
              top + height / 2,
            );
            const ancestors = [];
            for (
              let current = element.parentElement;
              current;
              current = current.parentElement
            ) {
              const rect = current.getBoundingClientRect();
              const { overflowX, overflowY } = getComputedStyle(current);
              if (overflowX === "visible" && overflowY === "visible") continue;
              ancestors.push({
                className: current.className,
                left: rect.left,
                top: rect.top,
                width: rect.width,
                height: rect.height,
                overflowX,
                overflowY,
                scrollLeft: current.scrollLeft,
                scrollTop: current.scrollTop,
              });
            }
            return {
              rectangle: { left, top, width, height },
              active: document.activeElement?.outerHTML.slice(0, 260),
              hit: hit?.outerHTML.slice(0, 260),
              viewport: { width: innerWidth, height: innerHeight, scrollY },
              ancestors,
            };
          });
          assert.fail(
            `visible keyboard target ${name} at ${width}px in ${state}: ${JSON.stringify(placement)}`,
          );
        }
        assert(
          await control.evaluate((element) =>
            element.matches(":focus-visible"),
          ),
        );
        await page.keyboard.press(key);
        observations.push(name);
      }

      await page.goto(
        base +
          "/#/monitor/0?workspace=fixture&application=handoff&task=" +
          encodeURIComponent(monitorTask.taskId),
      );
      await panel.waitFor();
      assert(!(await main.innerText()).includes(monitorTask.taskId));
      await activate("Open Grid from this task", "Open Grid from this task");
      await page.waitForURL(/#\/grid\/.*returnTask=/);
      assert(
        await focused(main),
        `Open Grid leaves focus on the destination at ${width}px in ${state}`,
      );
      await activate("Return to task", "Return to task", "Space");
      await panel.waitFor();
      assert(
        await focused(main),
        `Return to task leaves focus on Monitor at ${width}px in ${state}`,
      );
      assert.equal(
        new URLSearchParams(new URL(page.url()).hash.split("?")[1]).get("task"),
        monitorTask.taskId,
      );

      const linkedView =
        base +
        "/" +
        hash({
          ...handoff,
          returnTo: workflowOrigin,
          pendingOperation: { kind: "task", taskId: monitorTask.taskId },
        });
      await page.goto(linkedView);
      await activate(
        "Inspect referenced operation",
        "Inspect referenced operation",
      );
      await panel.waitFor();
      assert(
        await focused(main),
        `Inspect referenced operation focuses the destination at ${width}px in ${state}`,
      );
      await page.goto(linkedView);
      await activate("Return to workflow", "Return to workflow");
      await page
        .getByRole("heading", { name: originActivity.name, exact: true })
        .waitFor();
      assert(
        await focused(main),
        `Linked workflow focuses the destination at ${width}px in ${state}`,
      );

      await page.goto(workUrl);
      await activate("Next ready activities", "Next", "Space");
      assert(
        await focused(
          page.getByRole("button", { name: "Next ready activities" }),
        ),
      );
      await activate(`Open activity ${originActivity.name}`, "Open activity");
      await page
        .getByRole("heading", { name: originActivity.name, exact: true })
        .waitFor();
      assert(
        await focused(main),
        `My Work opens an activity with focus at ${width}px in ${state}`,
      );
      const target = new URLSearchParams(
        new URL(page.url()).hash.split("?")[1],
      );
      assert.equal(target.get("activity"), workflowOrigin.activityId);
      assert.equal(target.get("occurrence"), workflowOrigin.occurrenceId);
      await activate("Open governed destination", "Open governed destination");
      await page.waitForURL(/#\/grid\/.*returnOccurrence=/);
      assert(
        await focused(main),
        `Workflow opens Grid with focus at ${width}px in ${state}`,
      );
      const view = new URLSearchParams(new URL(page.url()).hash.split("?")[1]);
      assert.equal(view.get("view"), grid.gridId);
      assert.equal(view.get("viewDigest"), grid.canonicalDigest);
      await activate("Return to workflow", "Return to workflow", "Space");
      await page
        .getByRole("heading", { name: originActivity.name, exact: true })
        .waitFor();
      assert(
        await focused(main),
        `Ordinary workflow return preserves focus at ${width}px in ${state}`,
      );
      const taskReads = report.apiRequests
        .slice(requestStart)
        .filter(({ path }) => path === "/api/task");
      assert.deepEqual(
        taskReads.map(({ body }) => body),
        Array.from({ length: 3 }, () => ({
          ...handoff.scope,
          taskId: monitorTask.taskId,
          afterEvent: 0,
          eventLimit: 100,
        })),
      );

      exposeWorkspaceRoutes = true;
      const workspaceScenario = { width, state, controls: [] };
      report.workspaceNavigation.push(workspaceScenario);
      observations = workspaceScenario.controls;
      const workspaceStart = report.apiRequests.length;
      for (const [section, name, key] of [
        ["rules", "Calculation rules", "Enter"],
        ["python", "Python programs", "Space"],
      ]) {
        await page.goto(legacyUrl);
        await activate(`Open ${name}`, `Open ${name}`, key);
        await page.waitForURL(
          new RegExp(`#/rules/.*section=${section}(?:&|$)`),
        );
        await main
          .getByRole("heading", { name, exact: true })
          .first()
          .waitFor();
        const route = new URLSearchParams(
          new URL(page.url()).hash.split("?")[1],
        );
        assert.equal(
          route.get("returnOccurrence"),
          workflowOrigin.occurrenceId,
        );
        assert.equal(route.get("returnActivity"), workflowOrigin.activityId);
        assert(!page.url().includes(legacyId));
        assert(
          await focused(main),
          `Open ${name} focuses its destination at ${width}px in ${state}`,
        );
      }
      const source = main.getByRole("region", {
        name: "Authorized Python source",
      });
      if (width === 684 && state === "expanded") {
        let deliverSource;
        holdPythonSourceRead = new Promise((resolve) => {
          deliverSource = resolve;
        });
        try {
          const started = page.waitForRequest(
            (request) =>
              request.url().endsWith("/api/python-program") &&
              request.postDataJSON()?.program?.function ===
                "python.program.read",
          );
          await activate("View code for General Plan", "General Plan");
          await started;
          const viewCode = main.getByRole("button", {
            name: "View code for General Plan",
          });
          assert(await focused(viewCode));
          assert.equal(await viewCode.getAttribute("aria-disabled"), "true");
          await page.keyboard.press("Shift+Tab");
          assert(
            !(await focused(viewCode)),
            "Keyboard focus left View code while the read was pending",
          );
          const intendedFocus = await page.evaluateHandle(
            () => document.activeElement,
          );
          try {
            assert(
              await intendedFocus.evaluate(
                (element) => element !== document.body,
              ),
              "The user moved to another focusable control",
            );
            deliverSource();
            await source.waitFor();
            await page.evaluate(
              () =>
                new Promise((resolve) =>
                  requestAnimationFrame(() => requestAnimationFrame(resolve)),
                ),
            );
            assert(
              await intendedFocus.evaluate(
                (element) => document.activeElement === element,
              ),
              "Rendering the authorized source preserved the user's new focus",
            );
          } finally {
            await intendedFocus.dispose();
          }
        } finally {
          deliverSource();
        }
        report.cases.push({
          name: "A delayed Python source read respects focus moved by the keyboard",
          width,
          status: "passed",
        });
      } else {
        await activate("View code for General Plan", "General Plan");
        await source.waitFor();
      }
      await activate(authorityLink, authorityLink);
      await main
        .getByRole("article", { name: "Execution authority management" })
        .getByRole("heading", { name: "Execution authorities", exact: true })
        .waitFor();
      assert(
        await focused(main),
        `Execution authorities focus at ${width}px in ${state}`,
      );

      async function metadataDestination(section, heading) {
        await page.waitForURL(new RegExp(`metadataSection=${section}(?:&|$)`));
        await main
          .getByRole("heading", { name: heading, level: 1, exact: true })
          .waitFor();
        assert(
          await focused(main),
          `${heading} focus at ${width}px in ${state}`,
        );
      }
      await page.goto(metadataUrl);
      await activate("Function reference", "Function reference");
      await metadataDestination("reference", "Function reference");
      await activate("Metadata", "Metadata", "Enter", "link");
      await metadataDestination("dimensions", "Dimensions");
      await activate("Properties for Planning accounts", "Properties");
      await metadataDestination("settings", "Properties & access");
      await activate("Planning accounts", "Planning accounts", "Enter", "link");
      await metadataDestination("members", "Members");
      await activate("Metadata", "Metadata", "Enter", "link");
      await metadataDestination("dimensions", "Dimensions");
      await activate("Retired years Archive", "Retired years");
      await metadataDestination("members", "Members");
      await activate(
        "Open properties & access",
        "Open properties & access",
        "Space",
      );
      await metadataDestination("settings", "Properties & access");
      assert.equal(
        new URLSearchParams(new URL(page.url()).hash.split("?")[1]).get(
          "dimension",
        ),
        "Archive",
      );
      assert(
        !JSON.stringify(report.apiRequests.slice(workspaceStart)).includes(
          legacyId,
        ),
      );
      exposeWorkspaceRoutes = false;
    }
  }

  exposeWorkspaceRoutes = true;
  exposeAuthorityRead = false;
  await page.goto(
    base + "/#/rules/0?workspace=fixture&application=handoff&section=python",
  );
  await main
    .getByRole("button", { name: "View code for General Plan" })
    .press("Enter");
  const runSource = main.getByRole("region", {
    name: "Run current saved Python source",
  });
  await runSource.waitFor();
  assert(
    await runSource
      .getByRole("button", { name: "Run current saved source" })
      .isDisabled(),
  );
  assert.equal(
    await runSource
      .getByRole("button", {
        name: /execution authority|execution authorities/i,
      })
      .count(),
    0,
  );
  report.cases.push({
    name: "Run control stays unavailable and no authority link is offered when catalogue has list without read",
    status: "passed",
  });

  exposePartialManagement = true;
  report.partialManagementRoutes = [];
  for (const width of [650, 651, 951]) {
    await page.setViewportSize({ width, height: 900 });
    for (const [section, label] of [
      ["authorities", "Execution authorities"],
      ["python-schedules", "Program schedules"],
    ]) {
      const start = report.apiRequests.length;
      await page.goto(
        `${base}/?partialManagement=${width}-${section}#/rules/0?workspace=fixture&application=handoff&section=${section}`,
      );
      await main
        .getByRole("heading", { name: label, exact: true, level: 2 })
        .waitFor();
      const status = main.getByRole("status").filter({
        hasText: `${label} are unavailable in the current application catalogue.`,
      });
      await status.waitFor();
      assert(
        (await status.innerText()).includes(
          "Choose another workspace or inspect Function reference.",
        ),
      );
      assert.equal(
        await main
          .getByRole("article", {
            name: /execution authority management|python schedule management/i,
          })
          .count(),
        0,
      );
      assert.equal(
        await main
          .getByRole("button", {
            name: /refresh programs|read schedules|read authorities/i,
          })
          .count(),
        0,
      );
      await main
        .getByRole("button", { name: "Function reference", exact: true })
        .press("Enter");
      await main
        .getByRole("heading", {
          name: "Function reference",
          exact: true,
          level: 2,
        })
        .waitFor();
      assert(await focused(main));
      const requests = report.apiRequests.slice(start);
      assert(requests.some(({ path }) => path === "/api/catalog"));
      assert(
        !requests.some(
          ({ path, body }) =>
            [
              "/api/python-program",
              "/api/execution-delegation",
              "/api/python-schedule",
              "/api/security",
            ].includes(path) ||
            body?.program?.function === "security.identity.current.read",
        ),
      );
      report.partialManagementRoutes.push({ section, width, status: "passed" });
    }
  }

  assert.deepEqual(report.unknownApi, []);
  assert.deepEqual(report.pageErrors, []);
  assert.equal(report.mutations, 0);
  report.sourceAfter = await sourceHashes();
  assert.deepEqual(report.sourceBefore, report.sourceAfter);
  report.status = "passed";
} catch (error) {
  report.status = "failed";
  report.failure = {
    message: error.message,
    page: await browser
      ?.contexts()
      .at(-1)
      ?.pages()
      .at(-1)
      ?.locator("body")
      .innerText(),
  };
  process.exitCode = 1;
} finally {
  await browser?.close();
  await server.close();
  await rm(cacheDir, { recursive: true, force: true });
  report.cleanup =
    "Browser/server closed and own temporary Vite cache removed; no shared backend or durable application state used.";
}
if (process.argv[2])
  await writeFile(process.argv[2], JSON.stringify(report, null, 2) + "\n");
console.log(JSON.stringify(report, null, 2));
