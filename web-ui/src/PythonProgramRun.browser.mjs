// Current Python execution UI over an isolated loopback Vite server.
// All backend calls are intercepted; no installed application is exercised.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
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
const cacheDir = await mkdtemp(resolve(tmpdir(), "openepm-python-recovery-"));
const plan = {
  buildId: "1".repeat(32),
  purpose: "Plan",
  status: "sealed",
  attempts: 1,
  claimGeneration: 1,
  planDigest: "b".repeat(64),
};
const workflow = {
  buildId: plan.buildId,
  workflowId: "2".repeat(32),
  planDigest: plan.planDigest,
  status: "published",
  unitCount: 1,
  committedUnits: 1,
  remainingUnits: 0,
  checkpoints: [
    { ordinal: 1, jobId: "job-1", committed: true, receiptId: "receipt-1" },
  ],
};
const partialWorkflow = {
  ...workflow,
  status: "partially_published",
  unitCount: 3,
  remainingUnits: 2,
  checkpoints: [
    ...workflow.checkpoints,
    { ordinal: 2, jobId: "job-2", committed: false, receiptId: null },
  ],
};
const app = {
  workspaceId: "fixture",
  applicationId: "python",
  name: "Isolated source",
  status: "Active",
};
const catalog = {
  applicationAccess: {
    issuer: "fixture",
    subjectId: "operator",
    role: "Editor",
    workspaceAdministrator: false,
  },
  enabledCapabilities: [],
  functions: { "python.program.build": {}, "python.program.run": {} },
  revisions: {
    metadata: 4,
    policy: 2,
    security: 0,
    schemaEpoch: 1,
    data: 0,
    commit: 0,
  },
};
const program = {
  declaredOutput: null,
  programId: "forecast",
  sourceToken: "c".repeat(64),
  sourceDigest: "a".repeat(64),
  sourceText: "def build(context, parameters):\n    return Program()",
  status: "Active",
};
const authority = {
  delegation_id: "runner",
  state_token: "d".repeat(64),
  status: "Active",
  operation_scope: ["python.program.build", "python.program.run"],
  valid_from: "2020-01-01T00:00:00Z",
  valid_until: "2099-01-01T00:00:00Z",
};
const entry = `
  import React,{useState} from 'react'; import {createRoot} from 'react-dom/client';
  import {PythonProgramRun} from '/src/PythonProgramRun.tsx';
  import '/src/styles.css';
  const app=${JSON.stringify(app)},catalog=${JSON.stringify(catalog)},program=${JSON.stringify(program)},authority=${JSON.stringify(authority)};
  function Fixture(){const [open,setOpen]=useState(true),[changed,setChanged]=useState(false);
    return React.createElement('main',null,
      React.createElement('button',{onClick:()=>setOpen(!open)},open?'Leave editor':'Return to editor'),
      React.createElement('button',{onClick:()=>setChanged(true)},'Change saved source context'),
      open&&React.createElement(PythonProgramRun,{app,catalog:changed?{...catalog,functions:{'application.operation.receipt.read':{}},revisions:{...catalog.revisions,security:1}}:catalog,program:changed?{...program,sourceToken:'e'.repeat(64),sourceDigest:'f'.repeat(64),status:'Inactive'}:program,authority:changed?null:authority,parameters:'{"ratio":"2"}',onSetupAuthority:()=>{}}));}
  createRoot(document.getElementById('root')).render(React.createElement(Fixture));
`;
const server = await createServer({
  root: webRoot,
  cacheDir,
  server: { host: "127.0.0.1", port: 0 },
  clearScreen: false,
  logLevel: "error",
  plugins: [
    {
      name: "isolated-python-recovery",
      resolveId(id) {
        if (id === "virtual:python-recovery") return "\0python-recovery";
      },
      load(id) {
        if (id === "\0python-recovery") return entry;
      },
    },
  ],
});
const report = {
  method:
    "Real Chromium current PythonProgramRun with all API responses mocked",
  cases: [],
  pageErrors: [],
  unexpectedApi: [],
  traces: [],
  source: [],
};
for (const path of [
  "src/PythonProgramRun.tsx",
  "src/PythonProgramRun.browser.mjs",
  "src/python-execution-contract.ts",
  "src/workflow-outcome.ts",
  "src/WorkflowCheckpointEvidence.tsx",
  "src/data-transfer-action.ts",
  "src/ReceiptInspector.tsx",
  "src/unsaved-work.ts",
  "src/api.ts",
])
  report.source.push({
    path: "web-ui/" + path,
    sha256: createHash("sha256")
      .update(await readFile(resolve(webRoot, path)))
      .digest("hex"),
  });
let browser;
try {
  await server.listen();
  const base = server.resolvedUrls.local[0].replace(/\/$/, "");
  browser = await playwright.chromium.launch({ headless: true });
  report.browser = browser.version();
  for (const scenario of [
    { changed: false, lostRun: false, width: 1280 },
    { changed: true, lostRun: false, width: 684 },
    { changed: true, lostRun: true, width: 650 },
    { changed: true, lostRun: true, width: 951, moveFocus: true },
    {
      changed: false,
      lostRun: true,
      width: 650,
      missing: true,
      retryExpired: true,
    },
    {
      changed: false,
      lostRun: false,
      width: 1280,
      missing: true,
      retryExpired: false,
    },
  ]) {
    const {
      changed,
      lostRun,
      width,
      missing = false,
      retryExpired = false,
      moveFocus = false,
    } = scenario;
    const page = await browser.newPage({
      viewport: { width, height: 1000 },
    });
    page.on("pageerror", (e) => report.pageErrors.push(e.message));
    const trace = {
      changedSource: changed,
      lostRun,
      width,
      missing,
      retryExpired,
      admissions: 0,
      packets: [],
      reads: [],
      receiptReads: [],
    };
    report.traces.push(trace);
    let offset = 0;
    let lostRequests = 0;
    let originalReads = 0;
    const statusReadStarted = Promise.withResolvers();
    const releaseStatusRead = Promise.withResolvers();
    const lostPath = `/api/python-${lostRun ? "run" : "build"}`;
    const originalRead = (packet) => ({
      path: packet.path,
      body: {
        workspaceId: packet.body.workspaceId,
        applicationId: packet.body.applicationId,
        action: "read",
        originalRequest: {
          program: packet.body.program,
          idempotencyKey: packet.body.idempotencyKey,
        },
      },
    });
    await page.route("**/python-recovery.html", async (route) => {
      const html = await server.transformIndexHtml(
        "/python-recovery.html",
        '<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Isolated Python recovery</title></head><body><div id="root"></div><script type="module" src="/@id/virtual:python-recovery"></script></body></html>',
      );
      await route.fulfill({ contentType: "text/html", body: html });
    });
    await page.route("**/api/**", async (route) => {
      const path = new URL(route.request().url()).pathname,
        body = route.request().postDataJSON();
      const send = (result) =>
        route.fulfill({
          contentType: "application/json",
          body: JSON.stringify({ result }),
        });
      if (path === "/api/operation-admission") {
        trace.admissions += 1;
        return route.fulfill({
          contentType: "application/json",
          body: JSON.stringify({
            operationId: `oa1_zz_${String(trace.admissions).repeat(32)}_${"A".repeat(43)}`,
            expiresAt: Math.floor((Date.now() + offset) / 1000) + 900,
            intentDigest: "7".repeat(64),
          }),
        });
      }
      if (
        path === "/api/read" &&
        body.program.function === "application.operation.receipt.read"
      ) {
        assert.deepEqual(body, {
          workspaceId: app.workspaceId,
          applicationId: app.applicationId,
          program: {
            languageVersion: 2,
            function: "application.operation.receipt.read",
            arguments: { operationId: "receipt-1" },
          },
        });
        trace.receiptReads.push(body);
        return send({
          operationId: "receipt-1",
          actorId: "fixture",
          commandDigest: "c".repeat(64),
          committedRevision: 2,
          committedAt: "2026-11-19T15:00:00+00:00",
          outcome: { function: "facts.numeric.batch", changedCount: 1 },
        });
      }
      if (["/api/python-build", "/api/python-run"].includes(path)) {
        if (body.action === "request") {
          trace.packets.push({ path, body });
          if (path === lostPath) {
            if (++lostRequests === 1) return route.abort("failed");
            if (missing && retryExpired)
              return route.fulfill({
                status: 400,
                contentType: "application/json",
                body: JSON.stringify({ error: "OPERATION_ADMISSION_EXPIRED" }),
              });
          }
        } else {
          trace.reads.push({ path, body });
          if (lostRun && !missing && body.workflowId) {
            statusReadStarted.resolve();
            await releaseStatusRead.promise;
          }
          if (body.originalRequest) {
            originalReads++;
            if (missing)
              return route.fulfill({
                status: 400,
                contentType: "application/json",
                body: JSON.stringify({
                  error: lostRun
                    ? "PYTHON_WORKFLOW_UNAVAILABLE"
                    : "PYTHON_BUILD_UNAVAILABLE",
                }),
              });
            if (lostRun && originalReads === 1)
              return route.fulfill({
                status: 403,
                contentType: "application/json",
                body: JSON.stringify({ error: "ACCESS_DENIED" }),
              });
            if (lostRun)
              return send({
                ...partialWorkflow,
                status: "running",
                committedUnits: 0,
                remainingUnits: 3,
                checkpoints: [],
              });
          }
        }
        return send(
          path === "/api/python-build"
            ? plan
            : lostRun && !missing
              ? partialWorkflow
              : workflow,
        );
      }
      report.unexpectedApi.push({ path, body });
      return route.fulfill({ status: 500, body: "Unexpected API" });
    });
    await page.goto(base + "/python-recovery.html");
    await page
      .getByRole("button", { name: "Run current saved source", exact: true })
      .click();
    await page.getByRole("alert").waitFor();
    await page
      .getByRole("status")
      .filter({ hasText: "Outcome unconfirmed" })
      .waitFor();
    await page
      .getByRole("button", { name: "Leave editor", exact: true })
      .click();
    if (!missing || retryExpired) {
      offset = 7_200_000;
      await page.evaluate(() => {
        const now = Date.now;
        Date.now = () => now() + 7_200_000;
      });
    }
    await page
      .getByRole("button", { name: "Return to editor", exact: true })
      .click();
    const original = trace.packets.find((packet) => packet.path === lostPath);
    if (changed)
      await page
        .getByRole("button", {
          name: "Change saved source context",
          exact: true,
        })
        .click();
    if (missing) {
      await page
        .getByRole("button", {
          name: "Reconcile original execution",
          exact: true,
        })
        .click();
      await page
        .getByRole("button", { name: "Retry original request", exact: true })
        .waitFor();
      assert.deepEqual(trace.reads, [originalRead(original)]);
      assert.equal(trace.packets.length, lostRun ? 2 : 1);
      await page
        .getByRole("button", { name: "Leave editor", exact: true })
        .click();
      await page
        .getByRole("button", { name: "Return to editor", exact: true })
        .click();
      await page
        .getByRole("button", { name: "Retry original request", exact: true })
        .click();
      if (retryExpired) {
        await page
          .getByText("OPERATION_ADMISSION_EXPIRED", { exact: true })
          .waitFor();
        assert.equal(
          await page
            .getByLabel("Original execution recovery", { exact: true })
            .count(),
          1,
        );
      } else {
        await page.getByText(/Plan: sealed/).waitFor();
        assert.equal(
          trace.packets.some((packet) => packet.path === "/api/python-run"),
          false,
        );
        await page
          .getByRole("button", { name: "Leave this Plan unrun", exact: true })
          .click();
      }
      assert.equal(
        await page
          .getByRole("button", { name: "Retry original request", exact: true })
          .count(),
        0,
      );
      assert.deepEqual(trace.packets.at(-1), original);
      assert.equal(trace.packets.length, lostRun ? 3 : 2);
      assert.equal(trace.admissions, lostRun ? 2 : 1);
    } else if (lostRun) {
      assert.equal(
        await page
          .getByRole("button", {
            name: "Run current saved source",
            exact: true,
          })
          .count(),
        0,
      );
      await page
        .getByRole("button", {
          name: "Reconcile original execution",
          exact: true,
        })
        .click();
      await page.getByText("ACCESS_DENIED", { exact: true }).waitFor();
      assert.equal(trace.admissions, 2);
      assert.equal(trace.packets.length, 2);
      assert.equal(
        await page
          .getByLabel("Original execution recovery", { exact: true })
          .count(),
        1,
      );
      assert.equal(
        await page
          .getByRole("button", { name: "Retry original request", exact: true })
          .count(),
        0,
      );
      await page
        .getByRole("button", {
          name: "Reconcile original execution",
          exact: true,
        })
        .click();
      await page.getByText(/Original run: running/).waitFor();
      assert.deepEqual(trace.reads, [
        originalRead(original),
        originalRead(original),
      ]);
      await page
        .getByRole("button", { name: "Leave editor", exact: true })
        .click();
      await page
        .getByRole("button", { name: "Return to editor", exact: true })
        .click();
      const reconcile = page.getByRole("button", {
        name: "Reconcile original execution",
        exact: true,
      });
      await reconcile.press("Enter");
      await statusReadStarted.promise;
      const isFocused = (locator) =>
        locator.evaluate((element) => element === document.activeElement);
      let liveStatus;
      try {
        assert.equal(
          await isFocused(reconcile),
          true,
          "Pending reconciliation lost its keyboard focus",
        );
        const checking = page
          .getByRole("status")
          .filter({ hasText: "Checking the original execution" });
        await checking.waitFor();
        liveStatus = await checking.elementHandle();
        const admissions = trace.admissions;
        await page.keyboard.press("Enter");
        assert.equal(trace.admissions, admissions);
        if (moveFocus)
          await page
            .getByRole("button", { name: "Leave editor", exact: true })
            .focus();
      } finally {
        releaseStatusRead.resolve();
      }
      const partial = page
        .getByRole("status")
        .filter({ hasText: "Original run: partially published" });
      await partial.waitFor();
      assert.equal(
        await partial.evaluate(
          (current, pending) => current === pending,
          liveStatus,
        ),
        true,
      );
      await liveStatus.dispose();
      assert.match(
        await partial.innerText(),
        /1 receipt-confirmed committed units · 2 remaining units without a confirmed receipt/,
      );
      assert.equal(
        await isFocused(
          moveFocus
            ? page.getByRole("button", { name: "Leave editor", exact: true })
            : partial,
        ),
        true,
        "The outcome must replace only the focus owned by the vanished reconciliation button",
      );
      trace.partialOutcome = {
        pendingFocusRetained: true,
        focusMovedOutside: moveFocus,
        terminalFocusCorrect: true,
        plainLanguageAndReceiptCounts: true,
        sameLiveRegionUpdated: true,
      };
      assert.deepEqual(trace.reads.at(-1), {
        path: "/api/python-run",
        body: {
          workspaceId: app.workspaceId,
          applicationId: app.applicationId,
          action: "read",
          workflowId: workflow.workflowId,
        },
      });
      assert.equal(trace.admissions, 2);
      assert.equal(trace.packets.length, 2);
      assert.equal(trace.receiptReads.length, 0);
      await page
        .locator("summary")
        .filter({ hasText: "Workflow checkpoint evidence" })
        .press("Enter");
      await page
        .getByRole("listitem")
        .filter({ hasText: "Committed with receipt" })
        .waitFor();
      assert.equal(
        await page
          .getByText("Checkpoint recorded without a confirmed receipt", {
            exact: true,
          })
          .isVisible(),
        true,
      );
      assert.equal(
        await page
          .getByText("No checkpoint recorded", { exact: true })
          .isVisible(),
        true,
      );
      const inspect = page.getByRole("button", {
        name: "Inspect receipt for step 1",
        exact: true,
      });
      assert.equal(
        await page
          .getByRole("button", { name: /Inspect receipt for step/ })
          .count(),
        1,
      );
      await inspect.press("Enter");
      const receipt = page.getByRole("region", {
        name: "Step 1 receipt",
        exact: true,
      });
      await receipt
        .getByText("Activity outcome loaded.", { exact: true })
        .waitFor();
      assert.equal(
        await receipt
          .getByRole("heading", { name: "Step 1 receipt", exact: true })
          .evaluate((node) => node === document.activeElement),
        true,
      );
      await receipt
        .getByRole("button", { name: "Close", exact: true })
        .press("Enter");
      assert.equal(
        await inspect.evaluate((node) => node === document.activeElement),
        true,
      );
      assert.equal(trace.receiptReads.length, 1);
      assert.deepEqual(original.body.program.arguments, {
        buildId: plan.buildId,
      });
      assert.equal(
        await page
          .getByLabel("Original execution recovery", { exact: true })
          .count(),
        0,
      );
    } else if (changed) {
      await page
        .getByRole("button", {
          name: "Reconcile original execution",
          exact: true,
        })
        .click();
      await page.getByText(/Original Plan: sealed/).waitFor();
      assert.deepEqual(trace.reads, [originalRead(original)]);
      assert.equal(trace.admissions, 1);
      assert.equal(trace.packets.length, 1);
      await page
        .getByRole("button", { name: "Leave this Plan unrun", exact: true })
        .click();
      assert.equal(
        await page
          .getByLabel("Original execution recovery", { exact: true })
          .count(),
        0,
      );
    } else {
      await page
        .getByRole("button", {
          name: "Resume exact execution request",
          exact: true,
        })
        .click();
      await page.getByText(/Run: published/).waitFor();
      assert.deepEqual(trace.reads, [originalRead(original)]);
      assert.equal(trace.admissions, 2); // Read original Build, then explicit Resume admits its first Run.
      assert.equal(trace.packets.length, 2);
      assert.equal(
        trace.packets.filter((packet) => packet.path === "/api/python-run")
          .length,
        1,
      );
      assert.equal(
        await page
          .getByLabel("Original execution recovery", { exact: true })
          .count(),
        0,
      );
    }
    assert.deepEqual(trace.packets[0].body.program.arguments, {
      programId: program.programId,
      programSourceToken: program.sourceToken,
      parameters: { ratio: "2" },
      expectedMetadataRevision: catalog.revisions.metadata,
      expectedPolicyRevision: catalog.revisions.policy,
      expectedSchemaEpoch: catalog.revisions.schemaEpoch,
      delegationId: authority.delegation_id,
      delegationStateToken: authority.state_token,
      scheduleId: null,
      scheduleStateToken: null,
    });
    report.cases.push({
      name: missing
        ? retryExpired
          ? "650px: exact unavailable original-run lookup enables explicit same-packet retry; expiry denial remains pinned without readmission"
          : "1280px: exact unavailable original-build lookup enables explicit same-packet retry; sealed Plan is left unrun without automatic chaining"
        : lostRun
          ? `${width}px: original-reference recovery retains keyboard focus while pending and preserves the correct focus on partial publication`
          : changed
            ? "684px: lost build ID after source and authority change reconciles by original-reference READ without a new Run, then explicit unrun Plan release"
            : "1280px: lost build reply survives remount and expired admission; explicit Resume reads original build then admits only its first Run",
      status: "passed",
    });
    await page.close();
  }
  assert.deepEqual(report.pageErrors, []);
  assert.deepEqual(report.unexpectedApi, []);
  report.status = "passed";
} catch (error) {
  report.status = "failed";
  report.failure = error.message;
  throw error;
} finally {
  await browser?.close();
  await server.close();
  await rm(cacheDir, { recursive: true, force: true });
  report.cleanup =
    "Browser/loopback server closed and own temporary Vite cache removed. No database/container/credential or real business operation.";
  if (process.argv[2])
    await writeFile(process.argv[2], JSON.stringify(report, null, 2) + "\n");
  console.log(JSON.stringify(report, null, 2));
}
