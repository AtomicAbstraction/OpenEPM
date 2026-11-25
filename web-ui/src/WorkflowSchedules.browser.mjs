// Real Chromium rendering of current workflow/schedule components. All API
// responses are disposable fixtures; no shared backend or business effect.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(import.meta.url);
let playwright;
try {
  playwright = require("playwright");
} catch {
  playwright = require(
    resolve(
      execFileSync("npm", ["root", "--global"], { encoding: "utf8" }).trim(),
      "playwright",
    ),
  );
}
const { createServer } = await import(
  resolve(webRoot, "node_modules/vite/dist/node/index.js")
);
const cacheDir = await mkdtemp(
  resolve(tmpdir(), "openepm-workflow-schedules-"),
);
let fixtureEntry = "";
const server = await createServer({
  root: webRoot,
  cacheDir,
  server: { host: "127.0.0.1", port: 0 },
  clearScreen: false,
  logLevel: "error",
  plugins: [
    {
      name: "isolated-workflow-fixture",
      resolveId(id) {
        if (id === "virtual:workflow-fixture") return "\0workflow-fixture";
      },
      load(id) {
        if (id === "\0workflow-fixture") return fixtureEntry;
      },
    },
  ],
});
const app = {
  workspaceId: "isolated-fixture",
  applicationId: "review",
  name: "Review fixture",
  status: "Active",
};
const token = (letter) => letter.repeat(64);
const occurrenceId = "1".repeat(32);
const operationId = `oa1_zz_${"7".repeat(32)}_${"A".repeat(43)}`;
const catalog = {
  applicationAccess: {
    role: "Administrator",
    issuer: "fixture",
    subjectId: "reviewer",
    workspaceAdministrator: false,
  },
  enabledCapabilities: [],
  revisions: {
    metadata: 1,
    data: 1,
    policy: 1,
    security: 1,
    commit: 1,
    schemaEpoch: 224,
  },
  functions: Object.fromEntries(
    [
      "application.workflow.worklist",
      "application.workflow.read",
      "application.workflow.occurrence.read",
      "application.workflow.activity.evidence.read",
      "application.workflow.activity.complete",
      "application.workflow.activity.return",
      "application.workflow.occurrence.cancel",
      "application.operation.receipt.read",
      "schedule.list",
      "schedule.read",
      "schedule.save",
      "schedule.activate",
      "schedule.deactivate",
      "execution.delegation.read",
    ].map((name) => [name, {}]),
  ),
};
const definition = {
  format: "openepm-application-schedule-v1",
  scheduleId: "capacity-nightly",
  target: {
    kind: "ApplicationRule",
    ruleId: "capacity",
    stateToken: token("c"),
    programDigest: token("d"),
  },
  bindings: {},
  pov: [],
  recurrence: {
    kind: "FixedInterval",
    intervalSeconds: 86400,
    firstDueAt: "2026-11-17T09:00:00Z",
    catchUpPolicy: "latest",
    maxCatchUp: 1,
  },
  retryPolicy: {
    maxAttempts: 3,
    backoffSeconds: 60,
    needsInspectionAfter: true,
  },
  cancellationPolicy: "PreserveCommittedStopFuture",
  delegation: { delegationId: "capacity-runner", stateToken: token("e") },
};
const schedule = {
  scheduleId: definition.scheduleId,
  stateToken: token("b"),
  definitionDigest: token("a"),
  definition,
  status: "Active",
  targetStatus: "Current",
  effectiveStatus: "Active",
  reasonCode: null,
  updatedAt: "2026-11-17T09:00:00Z",
};
const report = {
  method:
    "Real Chromium components over Vite source; every API request intercepted with isolated fixtures",
  pageErrors: [],
  unexpectedApi: [],
  effectPackets: [],
  returnReceiptReads: [],
  historyRequests: [],
  worklistRequests: [],
  evidenceRequests: [],
  admissions: 0,
  cases: [],
};
let browser;
let reworkHistory = null;
let reviewEvidence = false;
let pausedAdmission;
let holdAuthority = false;
let authorityRead;
let resolveAuthorityRead;
let finishEvidenceCheck;
const pendingEvidenceCheck = new Promise((resolve) => {
  finishEvidenceCheck = resolve;
});
const validationStep = {
  activityId: "validation",
  name: "Validate capacity",
  kind: "Action",
  dependsOn: [],
  returnTo: null,
  evidenceContract: {
    kind: "OperationReceipt",
    allowedFunctions: ["facts.numeric.batch"],
    requireCurrent: false,
  },
};
const returnEvent = {
  ordinal: 51,
  eventType: "ActivityReturned",
  activityId: "review",
  operationId: "kept-return",
  evidence: {
    kind: "ReviewReturn",
    targetActivityId: "prepare",
    reason: "Refresh the capacity assumptions.",
  },
  committedRevision: 52,
  createdAt: "2026-11-17T10:00:00Z",
};
const firstHistoryPage = Array.from({ length: 50 }, (_, index) => ({
  ordinal: index + 1,
  eventType: index === 0 ? "OccurrenceStarted" : "ActivityCompleted",
  committedRevision: index + 1,
  createdAt: "2026-11-17T10:00:00Z",
}));
const fulfill = (route, body, status = 200) =>
  route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
try {
  await server.listen();
  const base = server.resolvedUrls.local[0].replace(/\/$/, "");
  browser = await playwright.chromium.launch({ headless: true });
  report.browser = browser.version();
  const page = await browser.newPage({
    viewport: { width: 1280, height: 1000 },
  });
  page.on("pageerror", (error) => report.pageErrors.push(error.message));
  page.on("dialog", (dialog) => dialog.accept());
  fixtureEntry = `
      import React from 'react';
      import {createRoot} from 'react-dom/client';
      import {GenericWorkflow} from '/src/GenericWorkflow.tsx';
      import {BuildSchedules} from '/src/BuildSchedules.tsx';
      import '/src/styles.css';
      const app=${JSON.stringify(app)},catalog=${JSON.stringify(catalog)};
      createRoot(document.getElementById('root')).render(React.createElement('main', null,
        React.createElement(GenericWorkflow,{app,catalog,targetOccurrenceId:'${occurrenceId}',targetActivityId:new URLSearchParams(location.search).has('rework') ? 'prepare' : 'review'}),
        React.createElement(BuildSchedules,{app,catalog})));
  `;
  await page.route("**/workflow-fixture.html*", async (route) => {
    const html = await server.transformIndexHtml(
      "/workflow-fixture.html",
      '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Isolated work fixture</title></head><body><div id="root"></div><script type="module" src="/@id/virtual:workflow-fixture"></script></body></html>',
    );
    await route.fulfill({ contentType: "text/html", body: html });
  });
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url()).pathname;
    const body = route.request().postDataJSON();
    const fn = body?.program?.function;
    const args = body?.program?.arguments;
    if (url === "/api/operation-admission") {
      report.admissions += 1;
      if (pausedAdmission) {
        const { requested, release } = pausedAdmission;
        pausedAdmission = null;
        requested(fn);
        await release;
      }
      return fulfill(route, {
        operationId,
        expiresAt: Math.floor(Date.now() / 1000) + 900,
        intentDigest: token("7"),
      });
    }
    if (url === "/api/application-workflow-occurrence") {
      report.effectPackets.push(body);
      if (report.effectPackets.length === 1) return route.abort("failed");
      return fulfill(route, {
        result: {
          operationId: body.idempotencyKey,
          function: fn,
          occurrenceId,
          activityId: "review",
          status: "Active",
          returnedToActivityId: "unreviewed-destination",
        },
      });
    }
    if (fn === "application.operation.receipt.read") {
      report.returnReceiptReads.push(body);
      if (report.returnReceiptReads.length === 1)
        return fulfill(route, { code: "OPERATION_RECEIPT_NOT_FOUND" }, 404);
      return fulfill(route, {
        result: {
          operationId,
          commandDigest: token("c"),
          actorId: "reviewer",
          committedRevision: 2,
          committedAt: "2026-11-17T12:00:00Z",
          outcome: {
            function: "application.workflow.activity.return",
            status: "Active",
            occurrenceId,
            activityId: "review",
            returnedToActivityId: "prepare",
          },
        },
      });
    }
    if (fn === "application.workflow.worklist") {
      report.worklistRequests.push(args);
      if (args.occurrenceId !== occurrenceId)
        return fulfill(route, { error: "Wider queue unavailable" }, 503);
      return fulfill(route, {
        result: {
          items: [
            {
              occurrenceId,
              occurrenceStateToken: token("1"),
              flowId: "capacity",
              flowStateToken: token("3"),
              definitionDigest: token("a"),
              activityId: reworkHistory ? "prepare" : "review",
              activityStateToken: token(reworkHistory ? "4" : "2"),
              name: reworkHistory ? "Prepare capacity" : "Review capacity",
              kind: reworkHistory ? "Action" : "Review",
              destination: {
                kind: "Function",
                function: "application.rule.run",
                argumentsDigest: token("d"),
              },
              assignmentResolution: {
                assignmentId: "reviewer",
                kind: reworkHistory ? "Action" : "Review",
              },
            },
          ],
          nextCursor: null,
        },
      });
    }
    if (fn === "application.workflow.occurrence.read") {
      const continuation = args.afterEventOrdinal > 0;
      if (reworkHistory) report.historyRequests.push(args);
      return fulfill(route, {
        result: {
          occurrenceId,
          flowId: "capacity",
          flowStateToken: token("3"),
          definitionDigest: token("a"),
          occurrenceStateToken: token(
            continuation && reworkHistory === "changed" ? "9" : "1",
          ),
          status: "Active",
          lastEventOrdinal: reworkHistory ? 51 : 1,
          ...(args.includeCurrentReturns
            ? { currentReturns: reworkHistory ? [returnEvent] : [] }
            : {}),
          activities: [
            {
              activityId: "prepare",
              kind: "Action",
              status: reworkHistory ? "Ready" : "Completed",
              activityStateToken: token("4"),
            },
            {
              activityId: "review",
              kind: "Review",
              status: reworkHistory ? "Returned" : "Ready",
              activityStateToken: token("2"),
              ...(reworkHistory
                ? {
                    operationId: returnEvent.operationId,
                    returnedToActivityId: "prepare",
                  }
                : {}),
            },
            ...(reviewEvidence
              ? [
                  {
                    activityId: validationStep.activityId,
                    kind: validationStep.kind,
                    status: "Completed",
                    activityStateToken: token("5"),
                  },
                ]
              : []),
          ],
          events: reworkHistory
            ? continuation
              ? [returnEvent]
              : firstHistoryPage
            : [],
          nextEventOrdinal: reworkHistory && !continuation ? 50 : null,
        },
      });
    }
    if (
      fn === "application.workflow.activity.evidence.read" &&
      reviewEvidence
    ) {
      report.evidenceRequests.push(args);
      const required = args.activityId === "prepare";
      if (required) await pendingEvidenceCheck;
      return fulfill(route, {
        result: {
          occurrenceId,
          activityId: args.activityId,
          activityStateToken: token(required ? "4" : "5"),
          state: "Stale",
          basis: "ExactNumericEffects",
          requireCurrent: required,
          suitability: required ? "UnsuitableNow" : "HistoricalPermitted",
          retryable: false,
        },
      });
    }
    if (fn === "application.workflow.read")
      return fulfill(route, {
        result: {
          flowId: "capacity",
          stateToken: token("3"),
          definitionDigest: token("a"),
          definition: {
            name: "Capacity review",
            activities: [
              {
                activityId: "prepare",
                name: "Prepare capacity",
                kind: "Action",
                dependsOn: [],
                returnTo: null,
                evidenceContract: reviewEvidence
                  ? {
                      ...validationStep.evidenceContract,
                      requireCurrent: true,
                    }
                  : {
                      kind: "ManualAttestation",
                      statement: "Prepared capacity",
                    },
              },
              {
                activityId: "review",
                name: "Review capacity",
                kind: "Review",
                dependsOn: reviewEvidence
                  ? ["prepare", "validation"]
                  : ["prepare"],
                returnTo: "prepare",
                evidenceContract: {
                  kind: "ManualAttestation",
                  statement: "I accept the capacity evidence",
                },
              },
              ...(reviewEvidence ? [validationStep] : []),
            ],
          },
        },
      });
    if (fn === "schedule.list")
      return fulfill(route, {
        result: { schedules: [schedule], nextAfterScheduleId: null },
      });
    if (fn === "schedule.read")
      return fulfill(route, {
        result: {
          defined: true,
          schedule,
          ...(args.occurrences
            ? {
                occurrences: {
                  scheduleStateToken: schedule.stateToken,
                  items: [
                    {
                      occurrenceId: "2".repeat(32),
                      taskId: "s:" + "2".repeat(32),
                      sequence: 90,
                      dueAt: "2026-11-16T09:00:00Z",
                      nativeStatus: "failed",
                      status: "Failed",
                      scheduleStateToken: token("f"),
                      currentPin: false,
                      workflowId: null,
                    },
                  ],
                  nextAfterSequence: null,
                  hasMore: false,
                },
              }
            : {}),
        },
      });
    if (fn === "execution.delegation.read") {
      if (holdAuthority) {
        authorityRead = route;
        resolveAuthorityRead();
        return;
      }
      return fulfill(route, {
        result: {
          defined: true,
          delegation: {
            delegation_id: "capacity-runner",
            state_token: token("f"),
            status: "Active",
            issuer: "fixture-issuer",
            subject_id: "scheduled-operator",
            operation_scope: ["application.rule.run"],
            valid_from: "2020-01-01T00:00:00Z",
            valid_until: "2099-01-01T00:00:00Z",
            schedule_id: null,
          },
        },
      });
    }
    report.unexpectedApi.push({ url, fn });
    return fulfill(route, { error: "UNEXPECTED_FIXTURE_REQUEST" }, 400);
  });
  await page.goto(base + "/workflow-fixture.html");
  await page
    .getByText("Manual attestation: I accept the capacity evidence")
    .waitFor();
  await page
    .getByText("Prerequisites: Prepare capacity (Completed)", { exact: true })
    .waitFor();
  await page
    .getByLabel("Return reason")
    .fill("Reconcile the capacity assumption");
  await page.getByRole("checkbox").check();
  await page
    .getByRole("button", { name: "Return to Prepare capacity" })
    .click();
  await page
    .getByRole("heading", { name: "Workflow outcome unknown" })
    .waitFor();
  assert.equal(await page.getByLabel("Return reason").isDisabled(), true);
  assert.equal(
    await page.getByRole("button", { name: "Accept review" }).isDisabled(),
    true,
  );
  const reconcile = page.getByRole("button", {
    name: "Reconcile original workflow action",
  });
  const readReceipt = page.getByRole("button", {
    name: "Read original workflow receipt",
  });
  assert(await reconcile.isDisabled());
  await readReceipt.press("Enter");
  await page.getByText(/No workflow receipt is visible yet/).waitFor();
  await reconcile.click();
  await page.getByText(/did not confirm the original action/).waitFor();
  assert.equal(await page.getByLabel("Return reason").isDisabled(), true);
  assert(await reconcile.isDisabled());
  await readReceipt.press("Enter");
  await page
    .getByText("Original workflow return recorded. Status at commit: Active.")
    .waitFor();
  assert.equal(report.admissions, 1);
  assert.deepEqual(report.effectPackets[1], report.effectPackets[0]);
  assert.equal(report.effectPackets.length, 2);
  assert.equal(
    report.returnReceiptReads[0].program.arguments.operationId,
    report.effectPackets[0].idempotencyKey,
  );
  await page.getByRole("button", { name: "Close", exact: true }).click();
  report.cases.push({
    name: "Rendered review preserves the admitted return after a wrong replay destination and confirms the exact original receipt by keyboard",
    status: "passed",
  });
  await page.getByRole("button", { name: "Open", exact: true }).click();
  await page.getByRole("button", { name: "Inspect bound authority" }).click();
  await page.getByText("Bound authority changed", { exact: true }).waitFor();
  await page.getByText("scheduled-operator", { exact: true }).waitFor();
  await page.getByRole("button", { name: "Inspect occurrences" }).click();
  await page
    .getByText("Uses an earlier saved version", { exact: true })
    .waitFor();
  const href = await page
    .getByRole("link", { name: "Inspect task" })
    .getAttribute("href");
  const handoff = JSON.parse(
    new URLSearchParams(href.split("?")[1]).get("handoff"),
  );
  assert.deepEqual(handoff.scope, {
    workspaceId: app.workspaceId,
    applicationId: app.applicationId,
  });
  assert.equal(handoff.target.taskId, "s:" + "2".repeat(32));
  await page.setViewportSize({ width: 684, height: 900 });
  assert.equal(
    await page.getByRole("link", { name: "Inspect task" }).isVisible(),
    true,
  );
  report.cases.push({
    name: "Actual schedule renders bound actor/pin discrepancy and earlier occurrence with exact task reference at 1280px and 684px",
    status: "passed",
  });
  holdAuthority = true;
  const requestedAuthority = new Promise((resolve) => {
    resolveAuthorityRead = resolve;
  });
  const boundAuthority = page.getByRole("button", {
    name: "Inspect bound authority",
  });
  const identityLabel = page.getByText("scheduled-operator", { exact: true });
  await boundAuthority.press("Enter");
  await requestedAuthority;
  await identityLabel.waitFor({ state: "detached" });
  assert(await boundAuthority.isDisabled());
  await fulfill(
    authorityRead,
    {
      code: "APPLICATION_GRANT_REQUIRED",
      message: "Private fixture directory marker",
    },
    403,
  );
  authorityRead = null;
  await page
    .getByText("The execution authority could not be verified.", {
      exact: true,
    })
    .waitFor();
  assert.equal(await identityLabel.count(), 0);
  assert.equal(
    await page.getByText("Private fixture directory marker").count(),
    0,
  );
  assert(await boundAuthority.isEnabled());
  report.cases.push({
    name: "A schedule authority recheck removes old actor details while waiting and suppresses private denial content",
    status: "passed",
    width: 684,
  });
  for (const historyMode of ["stable", "changed"]) {
    reworkHistory = historyMode;
    const priorReads = report.historyRequests.length;
    await page.goto(base + "/workflow-fixture.html?rework=" + historyMode);
    const instructions = page.getByRole("region", {
      name: "Return instructions",
    });
    await instructions.getByText(returnEvent.evidence.reason).waitFor();
    const history = page.getByRole("region", { name: "Activity history" });
    assert.equal(
      await history.getByText(returnEvent.evidence.reason).count(),
      0,
    );
    assert.equal(await history.getByRole("listitem").count(), 50);
    assert.equal(report.historyRequests.length, priorReads + 1);
    assert.equal(report.historyRequests.at(-1).includeCurrentReturns, true);
    await page
      .getByRole("checkbox", { name: /reviewed this exact activity/ })
      .check();
    const complete = page.getByRole("button", { name: "Complete activity" });
    assert(await complete.isEnabled());
    assert.deepEqual(report.worklistRequests.at(-1), {
      occurrenceId,
      limit: 100,
      includeBlocked: true,
    });
    const next = history.getByRole("button", {
      name: "Load more activity history",
    });
    await next.press("Enter");
    if (historyMode === "changed") {
      await history
        .getByRole("alert")
        .getByText(/workflow occurrence changed/)
        .waitFor();
      assert(await complete.isDisabled());
      assert.equal(await instructions.count(), 0);
      assert.equal(await history.getByRole("listitem").count(), 50);
    } else {
      await history.getByText(returnEvent.evidence.reason).waitFor();
      assert(await complete.isEnabled());
      const end = history.getByRole("button", {
        name: "All activity history loaded",
      });
      assert.equal(
        await end.evaluate((element) => element === document.activeElement),
        true,
      );
      assert.equal(await history.getByRole("listitem").count(), 51);
    }
    assert.equal(report.historyRequests.length, priorReads + 2);
    assert.deepEqual(report.historyRequests.at(-1), {
      occurrenceId,
      eventLimit: 50,
      afterEventOrdinal: 50,
    });
    assert.equal(report.admissions, 1);
    report.cases.push({
      name:
        historyMode === "stable"
          ? "Real Browser opens returned work before reading the next page and retains keyboard focus"
          : "Real Browser refuses mixed history and disables actions after occurrence change",
      status: "passed",
    });
  }
  reworkHistory = null;
  reviewEvidence = true;
  await page.goto(base + "/workflow-fixture.html?review-evidence");
  const evidence = page.getByRole("region", {
    name: "Evidence for this review",
  });
  const required = evidence.getByRole("button", {
    name: "Check current evidence for Prepare capacity",
  });
  const historical = evidence.getByRole("button", {
    name: "Check current evidence for Validate capacity",
  });
  const acknowledgement = page.getByRole("checkbox", {
    name: /reviewed this exact activity/,
  });
  const accept = page.getByRole("button", { name: "Accept review" });
  await required.press("Enter");
  await evidence.getByText("Checking current evidence…").waitFor();
  assert(await historical.isDisabled());
  assert(await acknowledgement.isDisabled());
  await historical.press("Enter");
  assert(await evidence.getByText("Checking current evidence…").isVisible());
  assert(await acknowledgement.isDisabled());
  finishEvidenceCheck();
  await evidence.getByText(/The activity requires current evidence/).waitFor();
  assert.deepEqual(report.evidenceRequests, [
    { occurrenceId, activityId: "prepare" },
  ]);
  assert(await historical.isEnabled());
  await historical.press("Enter");
  await evidence.getByText(/The activity allows historical evidence/).waitFor();
  assert.deepEqual(report.evidenceRequests, [
    { occurrenceId, activityId: "prepare" },
    { occurrenceId, activityId: "validation" },
  ]);
  await page
    .getByLabel("Return reason")
    .fill("Replace the stale preparation evidence.");
  await acknowledgement.check();
  assert(await accept.isDisabled());
  assert(
    await page
      .getByRole("button", { name: "Return to Prepare capacity" })
      .isEnabled(),
  );
  assert.equal(report.admissions, 1);
  report.cases.push({
    name: "A second keyboard activation leaves the pending required evidence check intact; the two verdicts retain their distinct policies and only the authored return stays available",
    status: "passed",
  });
  await page.goto(base + "/workflow-fixture.html?review-during-admission");
  await required.waitFor();
  let releaseAdmission;
  const release = new Promise((resolve) => (releaseAdmission = resolve));
  const requested = new Promise((resolve) => {
    pausedAdmission = { requested: resolve, release };
  });
  const admissionAborted = page.waitForEvent("requestfailed", (request) =>
    request.url().endsWith("/api/operation-admission"),
  );
  const earlierEffectCount = report.effectPackets.length;
  await acknowledgement.check();
  await accept.press("Enter");
  assert.equal(await requested, "application.workflow.activity.complete");
  assert(await accept.isDisabled());
  await required.press("Enter");
  await evidence.getByText(/The activity requires current evidence/).waitFor();
  releaseAdmission();
  const abandoned = await admissionAborted;
  assert.equal(abandoned.failure().errorText, "net::ERR_ABORTED");
  assert.equal(report.admissions, 2);
  assert.equal(report.effectPackets.length, earlierEffectCount);
  assert(await acknowledgement.isEnabled());
  assert(!(await acknowledgement.isChecked()));
  assert(await accept.isDisabled());
  assert.equal(
    await page
      .getByRole("heading", { name: "Workflow outcome unknown" })
      .count(),
    0,
  );
  await page.getByLabel("Return reason").fill("Replace the reviewed evidence.");
  await acknowledgement.check();
  assert(
    await page
      .getByRole("button", { name: "Return to Prepare capacity" })
      .isEnabled(),
  );
  report.cases.push({
    name: "Checking current evidence aborts an unsent acceptance and leaves the authored return available after acknowledgement",
    status: "passed",
    admissionTransportAborted: true,
    extraEffects: report.effectPackets.length - earlierEffectCount,
  });
  assert.deepEqual(report.pageErrors, []);
  assert.deepEqual(report.unexpectedApi, []);
  report.status = "passed";
} catch (error) {
  report.status = "failed";
  report.failure = error.message;
  console.error(JSON.stringify(report, null, 2));
  throw error;
} finally {
  await authorityRead?.abort().catch(() => {});
  await browser?.close();
  await server.close();
  await rm(cacheDir, { recursive: true, force: true });
  report.cleanup =
    "Browser and loopback server closed; own temporary Vite cache removed. All business requests were mocked; no database/containers/credentials created.";
}
if (process.argv[2])
  await writeFile(process.argv[2], JSON.stringify(report, null, 2) + "\n");
console.log(JSON.stringify(report, null, 2));
