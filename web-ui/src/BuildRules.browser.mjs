// Real BuildRules/source-editor/API/memory recovery in isolated Chromium.
// API responses and the code-display widget are fixtures, not installed acceptance.
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
const cacheDir = await mkdtemp(resolve(tmpdir(), "openepm-rule-recovery-"));
const app = {
  workspaceId: "fixture",
  applicationId: "rule-recovery",
  name: "Isolated rules",
  status: "Active",
};
const catalog = {
  applicationAccess: {
    issuer: "fixture",
    subjectId: "runner",
    role: "Editor",
    workspaceAdministrator: false,
  },
  enabledCapabilities: [],
  functions: {
    "application.rule.list": {},
    "application.rule.read": {},
    "application.rule.run": {},
    "application.rule.run.read": {},
    "python.program.read": {},
  },
  revisions: {
    metadata: 4,
    policy: 2,
    security: 1,
    schemaEpoch: 1,
    data: 0,
    commit: 0,
  },
};
const row = {
  defined: true,
  valid: true,
  active: true,
  sourceCurrent: true,
  ruleId: "forecast",
  stateToken: "d".repeat(64),
  programDigest: "a".repeat(64),
  status: "Active",
  executable: true,
  reason: null,
  metadataCurrent: true,
};
const detail = {
  ...row,
  defined: true,
  program: { function: "application.rule.plan", arguments: {} },
  source: {
    programId: "forecast-source",
    programSourceToken: "c".repeat(64),
    sourceDigest: "b".repeat(64),
    buildId: "0".repeat(32),
    active: true,
  },
};
const entry = `import React,{useState} from 'react';import {createRoot} from 'react-dom/client';import {BuildRules} from '/src/BuildRules.tsx';import '/src/styles.css';
const app=${JSON.stringify(app)},catalog=${JSON.stringify(catalog)};
function Fixture(){const[open,setOpen]=useState(true),[restricted,setRestricted]=useState(false),[changed,setChanged]=useState(false);return React.createElement('main',null,
React.createElement('button',{onClick:()=>setOpen(!open)},open?'Leave rules':'Return to rules'),
React.createElement('button',{onClick:()=>setRestricted(true)},'Remove fresh run authority'),
React.createElement('button',{onClick:()=>setChanged(true)},'Observe changed saved source'),
open&&React.createElement(BuildRules,{app,catalog:restricted?{...catalog,functions:{'application.rule.run.read':{}},revisions:{...catalog.revisions,security:2,metadata:9}}:changed?{...catalog,revisions:{...catalog.revisions,policy:3}}:catalog}));}
createRoot(document.getElementById('root')).render(React.createElement(Fixture));`;
const server = await createServer({
  root: webRoot,
  cacheDir,
  server: { host: "127.0.0.1", port: 0 },
  clearScreen: false,
  logLevel: "error",
  plugins: [
    {
      name: "isolated-rule-recovery",
      enforce: "pre",
      resolveId(id) {
        if (id === "virtual:rule-recovery") return "\0rule-recovery";
        if (/(?:^|\/)PythonRuleEditor(?:\.tsx)?$/.test(id))
          return "\0code-display";
      },
      load(id) {
        if (id === "\0rule-recovery") return entry;
        if (id === "\0code-display")
          return `import React from 'react';export function PythonRuleEditor({value,ariaLabel}){return React.createElement('pre',{'aria-label':ariaLabel||'Fixture source text'},value);}`;
      },
    },
  ],
});
const hash = (value) =>
  createHash("sha256")
    .update(JSON.stringify(value, Object.keys(value).sort()))
    .digest("hex");
const report = {
  method:
    "Real Chromium BuildRules, PythonDefinitionEditor, API and existing retained-draft owner; mocked native-shaped API responses and code-display widget",
  cases: [],
  traces: [],
  pageErrors: [],
  unexpectedApi: [],
  source: [],
};
for (const path of [
  "src/BuildRules.tsx",
  "src/BuildRules.browser.mjs",
  "src/PythonDefinitionEditor.tsx",
  "src/definition-lifecycle.ts",
  "src/application-rule-run.ts",
  "src/workflow-outcome.ts",
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
  for (const width of [650, 1280, 684]) {
    const page = await browser.newPage({ viewport: { width, height: 1000 } });
    page.on("pageerror", (e) => report.pageErrors.push(e.message));
    await page.addInitScript(() => {
      const original = Date.now.bind(Date);
      window.expireAdmissionCache = () => {
        Date.now = () => original() + 7200000;
      };
    });
    const trace = { width, admissions: 0, packets: [], reads: [], sources: [] };
    report.traces.push(trace);
    const json = (value, status = 200) => ({
      status,
      contentType: "application/json",
      body: JSON.stringify(value),
    });
    let original;
    let sourceChanged = false;
    let sourceReadMoved = width === 650;
    const currentRow = () =>
      sourceChanged
        ? {
            ...row,
            status: "Inactive",
            valid: false,
            active: false,
            executable: false,
            reason: "validation_required",
            stateToken: "f".repeat(64),
            programDigest: null,
          }
        : row;
    const currentBinding = () =>
      sourceChanged
        ? {
            ...detail.source,
            programSourceToken: "e".repeat(64),
            sourceDigest: "9".repeat(64),
            buildId: null,
            active: false,
          }
        : detail.source;
    const sourceText = () =>
      sourceChanged
        ? "# Changed saved source; no compiled owner is available."
        : "# Original saved source accepted for the pending rule run.";
    const native = (status) => ({
      workflowId: "1".repeat(32),
      planDigest: "2".repeat(64),
      ruleId: "forecast",
      stateToken: row.stateToken,
      status,
      unitCount: 1,
      committedUnits: status === "published" ? 1 : 0,
      remainingUnits: status === "published" ? 0 : 1,
      checkpoints:
        status === "published"
          ? [
              {
                ordinal: 1,
                jobId: "child-1",
                committed: true,
                receiptId: "child-1",
              },
            ]
          : [],
      bindings: {},
      bindingDigest: hash({}),
      argumentsDigest: createHash("sha256")
        .update('{"bindings":{},"ruleId":"forecast"}')
        .digest("hex"),
    });
    await page.route("**/rule-recovery.html", async (route) => {
      const html = await server.transformIndexHtml(
        "/rule-recovery.html",
        '<!doctype html><meta name="viewport" content="width=device-width,initial-scale=1"><div id="root"></div><script type="module" src="/@id/virtual:rule-recovery"></script>',
      );
      await route.fulfill({ contentType: "text/html", body: html });
    });
    await page.route("**/api/**", async (route) => {
      const path = new URL(route.request().url()).pathname,
        body = route.request().postDataJSON();
      if (path === "/api/operation-admission") {
        assert.equal(body.program.function, "application.rule.run");
        trace.admissions++;
        return route.fulfill(
          json({
            operationId: `oa1_zz_${"a".repeat(32)}_${"A".repeat(43)}`,
            expiresAt: Math.floor(Date.now() / 1000) + 900,
            intentDigest: "a".repeat(64),
          }),
        );
      }
      const fn = body.program?.function;
      if (fn === "application.rule.list")
        return route.fulfill(
          json({
            result: {
              rows: [currentRow()],
              hasMore: false,
              nextAfterRuleId: null,
              metadataRevision: 4,
              policyRevision: sourceChanged ? 3 : 2,
            },
          }),
        );
      if (fn === "application.rule.read")
        return route.fulfill(
          json({
            result: {
              ...detail,
              ...currentRow(),
              source: currentBinding(),
              program: sourceChanged ? null : detail.program,
            },
          }),
        );
      if (fn === "python.program.read") {
        assert.equal(path, "/api/python-program");
        assert.deepEqual(body.program.arguments, {
          programId: detail.source.programId,
        });
        const binding = currentBinding();
        const sourceToken = sourceReadMoved
          ? "e".repeat(64)
          : binding.programSourceToken;
        trace.sources.push({ ...binding, programSourceToken: sourceToken });
        return route.fulfill(
          json({
            result: {
              ...currentRow(),
              programId: binding.programId,
              stateToken: sourceChanged ? "8".repeat(64) : "7".repeat(64),
              sourceToken,
              sourceDigest: binding.sourceDigest,
              sourceText: sourceText(),
              entryPoint: "build",
              environmentId: "builder",
              environmentStateToken: "6".repeat(64),
              parameterSchema: { type: "object", properties: {} },
              validation: null,
              latestImpactTest: null,
            },
          }),
        );
      }
      if (fn === "application.rule.run") {
        assert.equal(path, "/api/rule-action");
        trace.packets.push(body);
        original ??= body;
        if (trace.packets.length === 1)
          return width === 650
            ? route.fulfill(json({ code: "NATIVE_ADVANCE_FAILED" }, 403))
            : route.abort("failed");
        if (width === 650 && trace.packets.length === 2)
          return route.fulfill(
            json({ code: "OPERATION_ADMISSION_EXPIRED" }, 400),
          );
        assert.deepEqual(body, original);
        return route.fulfill(json({ result: native("running") }));
      }
      if (fn === "application.rule.run.read") {
        trace.reads.push(body);
        const byRequest = body.program.arguments.originalRequest;
        if (byRequest) {
          assert.deepEqual(byRequest, {
            program: original.program,
            idempotencyKey: original.idempotencyKey,
          });
          if (width !== 1280)
            return route.fulfill(
              json({ code: "APPLICATION_RULE_WORKFLOW_UNAVAILABLE" }, 400),
            );
        } else {
          assert.deepEqual(body.program.arguments, {
            workflowId: "1".repeat(32),
          });
          if (width === 1280 && trace.reads.length === 3)
            return route.fulfill(
              json(
                {
                  code: "APPLICATION_RULE_WORKFLOW_AUTHORIZATION_SCOPE_CHANGED",
                },
                403,
              ),
            );
        }
        const result = native(byRequest ? "running" : "published");
        return route.fulfill(
          json({
            result: {
              ...result,
              sealedPlanDigest: result.planDigest,
              publishedRule: {
                ruleId: "forecast",
                stateToken: row.stateToken,
                programDigest: row.programDigest,
              },
              freshness: { current: false, staleReasons: ["publication"] },
              lineageComplete: true,
              lineage: byRequest
                ? [
                    {
                      ordinal: 1,
                      unitName: "ordered",
                      function: "facts.numeric.sequence",
                      jobId: null,
                      jobStatus: "not_started",
                      committed: false,
                      receiptId: null,
                      receiptRevision: null,
                    },
                  ]
                : [
                    {
                      ordinal: 1,
                      unitName: "ordered",
                      function: "facts.numeric.sequence",
                      jobId: "child-1",
                      jobStatus: "published",
                      committed: true,
                      receiptId: "child-1",
                      receiptRevision: 1,
                    },
                  ],
            },
          }),
        );
      }
      report.unexpectedApi.push({ path, body });
      return route.fulfill(json({ code: "UNEXPECTED_FIXTURE_CALL" }, 400));
    });
    await page.goto(`${base}/rule-recovery.html`);
    await page.getByRole("button", { name: "forecast", exact: true }).click();
    const runRule = page.getByRole("button", { name: "Run rule", exact: true });
    if (sourceReadMoved) {
      await page
        .getByText(/saved source no longer matches this definition/)
        .waitFor();
      assert.equal(await runRule.getAttribute("aria-disabled"), "true");
      await runRule.press("Enter");
      assert.equal(trace.admissions, 0);
      assert.equal(trace.packets.length, 0);
      sourceReadMoved = false;
      await page.getByRole("button", { name: "Retry bound source" }).click();
      await runRule
        .locator('xpath=self::*[not(@aria-disabled="true")]')
        .waitFor();
      assert.equal(
        trace.sources[0].sourceDigest,
        trace.sources[1].sourceDigest,
      );
      assert.notEqual(
        trace.sources[0].programSourceToken,
        trace.sources[1].programSourceToken,
      );
      report.cases.push({
        width,
        status: "passed",
        journey:
          "The Browser refuses Run with a different source token and identical digest, then enables it after reading the exact selected binding",
      });
    }
    await runRule.click();
    await page.getByText(/Rule run outcome unknown/).waitFor();
    await page
      .getByRole("button", { name: "Read original rule outcome", exact: true })
      .waitFor();
    const retry = page.getByRole("button", {
      name: "Retry original rule request",
      exact: true,
    });
    assert.equal(await retry.count(), 0);
    assert.equal(trace.sources.at(-1).programSourceToken, "c".repeat(64));
    if (width === 684) {
      // Model the native read state after a separate authorized changed Save.
      // The fixture performs no Save; the actual parent/editor must inspect the
      // new inactive owner while preserving the unknown original run packet.
      sourceChanged = true;
      await page
        .getByRole("button", {
          name: "Observe changed saved source",
          exact: true,
        })
        .click();
      await page.getByRole("button", { name: "forecast", exact: true }).click();
      await page.getByText(sourceText(), { exact: true }).waitFor();
      await page.getByText(/No current compiled rule is available/).waitFor();
      assert.equal(
        await page
          .getByRole("button", { name: "Run rule", exact: true })
          .isDisabled(),
        true,
      );
      assert.equal(trace.sources.at(-1).programSourceToken, "e".repeat(64));
      assert.equal(trace.sources.at(-1).sourceDigest, "9".repeat(64));
      assert.equal(trace.packets.length, 1);
      assert.equal(trace.admissions, 1);
      await page.getByText(/Rule run outcome unknown/).waitFor();
    }
    await page
      .getByRole("button", { name: "Leave rules", exact: true })
      .click();
    await page.evaluate(() => window.expireAdmissionCache());
    await page
      .getByRole("button", { name: "Return to rules", exact: true })
      .click();
    const check = page.getByRole("button", {
      name: "Read original rule outcome",
      exact: true,
    });
    assert.equal(await retry.count(), 0);
    await check.press("Enter");
    if (width !== 1280) {
      await page.getByText(/No recorded outcome could be confirmed/).waitFor();
      assert.equal(trace.packets.length, 1);
      assert(await check.evaluate((el) => el === document.activeElement));
      await retry.press("Enter");
    }
    if (width === 650) {
      await page
        .getByText(
          "The original admission expired. Check the original outcome again.",
          { exact: true },
        )
        .waitFor();
      await page
        .getByRole("button", { name: "Leave rules", exact: true })
        .click();
      await page
        .getByRole("button", { name: "Return to rules", exact: true })
        .click();
      await check.press("Enter");
      await page.getByText(/No recorded outcome could be confirmed/).waitFor();
      assert.equal(await retry.count(), 0);
      assert.equal(trace.admissions, 1);
      assert.equal(trace.reads.length, 2);
      assert.equal(trace.packets.length, 2);
      assert.deepEqual(trace.packets[1], original);
      report.cases.push({
        width,
        status: "passed",
        journey:
          "An expired exact retry stays closed to dispatch after remount; status lookup remains available",
      });
      await page.close();
      continue;
    }
    await page.getByText(/Rule run running/).waitFor();
    await page
      .getByRole("button", { name: "Remove fresh run authority", exact: true })
      .click();
    assert.equal(
      await page.getByRole("button", { name: "Run rule", exact: true }).count(),
      0,
    );
    await page
      .getByRole("button", { name: "Refresh original run status", exact: true })
      .click();
    await page.getByText(/Rule run published/).waitFor();
    await page
      .getByText(/source or dependencies are no longer current/)
      .waitFor();
    assert.equal(trace.admissions, 1);
    assert.equal(trace.reads.length, 2);
    assert.equal(trace.packets.length, width === 1280 ? 1 : 2);
    for (const packet of trace.packets) assert.deepEqual(packet, original);
    report.cases.push({
      width,
      status: "passed",
      journey:
        width === 684
          ? "After inspection of changed inactive source and remount, a read precedes the exact retry; later read-only lineage settles"
          : "Lost reply settles through the signed original selector and later read-only lineage with a single dispatch",
    });
    if (width === 1280) {
      const refresh = page.getByRole("button", {
        name: "Refresh original run status",
        exact: true,
      });
      await page
        .getByText("Workflow checkpoint evidence", { exact: true })
        .click();
      const committedStep = page
        .getByRole("region", { name: "Original rule execution recovery" })
        .getByRole("listitem")
        .filter({ hasText: "Committed with receipt" });
      await committedStep.waitFor();
      await refresh.press("Enter");
      await page
        .getByText(/Current access could not confirm the original run/)
        .waitFor();
      assert.equal(
        await page
          .getByText("Workflow checkpoint evidence", { exact: true })
          .count(),
        0,
      );
      assert(
        await refresh.evaluate((element) => element === document.activeElement),
      );
      await refresh.press("Enter");
      await page.getByText(/Rule run published/).waitFor();
      await page
        .getByText("Workflow checkpoint evidence", { exact: true })
        .click();
      await committedStep.waitFor();
      assert.deepEqual(trace.reads[2], trace.reads[3]);
      assert.equal(trace.admissions, 1);
      assert.equal(trace.packets.length, 1);
      report.cases.push({
        width,
        status: "passed",
        journey:
          "A denied terminal refresh clears the receipt; keyboard recovery reads the same workflow after access returns",
      });
    }
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
  report.cleanup = {
    verified: true,
    detail:
      "Browser and loopback Vite closed; owned cache removed. No application, database, credentials, container or shared operation.",
  };
  if (process.argv[2])
    await writeFile(process.argv[2], JSON.stringify(report, null, 2) + "\n");
  console.log(JSON.stringify(report, null, 2));
}
