// Qualifies the compiled Rules workspace against isolated API fixtures only.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dist = resolve(root, "web-ui", "dist");
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
const csp = execFileSync(
  "python3",
  [
    "-c",
    `import ast,sys
nodes=ast.walk(ast.parse(open(sys.argv[1]).read()))
print(next(n.elts[1].value.decode() for n in nodes if isinstance(n,ast.Tuple) and len(n.elts)==2 and isinstance(n.elts[0],ast.Constant) and n.elts[0].value==b'content-security-policy'))`,
    resolve(root, "platform_postgres_web_http.py"),
  ],
  { encoding: "utf8" },
).trim();

const application = {
  workspaceId: "ws-rules-fixture",
  applicationId: "rules-fixture",
  name: "Rules fixture",
  status: "Active",
  kind: "blank",
};
const source = `def build(context, parameters):
    return ApplicationRule("aic.apportion.policy")`;
const program = {
  programId: "source-rule-aic.apportion.policy",
  stateToken: "b".repeat(64),
  sourceToken: "c".repeat(64),
  status: "Active",
  entryPoint: "build",
  environmentId: "approved-python",
  environmentStateToken: "d".repeat(64),
  sourceDigest: "a".repeat(64),
  declaredOutput: {
    kind: "ApplicationRule",
    definitionId: "aic.apportion.policy",
  },
  defined: true,
  valid: true,
  active: true,
  sourceCurrent: true,
  executable: true,
  reason: null,
};
const catalog = {
  applicationAccess: { role: "Administrator", workspaceAdministrator: true },
  enabledCapabilities: [],
  functions: {
    "python.program.list": {},
    "python.program.read": {},
    "python.program.save": {},
    "python.environment.list": {},
  },
  revisions: {
    metadata: 12,
    data: 1,
    policy: 7,
    security: 1,
    commit: 24,
    capability: 1,
    schemaEpoch: 4,
  },
};

function json(body, status = 200) {
  return {
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  };
}

async function installApi(page, audit) {
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    audit.apiRequests.push(url.pathname);
    if (url.pathname === "/api/applications") {
      await route.fulfill(
        json({ applications: [application], nextAfter: null }),
      );
      return;
    }
    if (url.pathname === "/api/session-identity") {
      await route.fulfill(
        json({ displayIdentity: "Rules tester", applicationMcpEndpoint: null }),
      );
      return;
    }
    if (url.pathname === "/api/runtime") {
      await route.fulfill(
        json({
          readOnlyReview: false,
          build: { sourceCommit: "e".repeat(40), packagedSchema: 379 },
        }),
      );
      return;
    }
    if (url.pathname === "/api/platform/browser/catalog") {
      await route.fulfill(json({ languageVersion: 2, functions: {} }));
      return;
    }
    if (url.pathname === "/api/catalog") {
      await route.fulfill(json(catalog));
      return;
    }
    if (url.pathname === "/api/tasks") {
      await route.fulfill(json({ tasks: [] }));
      return;
    }
    if (url.pathname === "/api/python-program") {
      const body = request.postDataJSON();
      const functionName = body?.program?.function;
      if (functionName === "python.program.list") {
        await route.fulfill(
          json({ result: { programs: [program], nextAfterProgramId: null } }),
        );
        return;
      }
      if (functionName === "python.program.read") {
        await route.fulfill(
          json({
            result: {
              ...program,
              parameterSchema: { type: "object" },
              sourceText: source,
            },
          }),
        );
        return;
      }
    }
    if (url.pathname === "/api/python-environment") {
      await route.fulfill(
        json({
          result: {
            environments: [
              {
                environmentId: "approved-python",
                stateToken: "d".repeat(64),
                status: "Active",
              },
            ],
            nextAfterEnvironmentId: null,
          },
        }),
      );
      return;
    }
    audit.unhandledApi.push(url.pathname);
    await route.fulfill(json({ error: "FIXTURE_ENDPOINT_UNAVAILABLE" }, 404));
  });
}

async function openRule(page) {
  await page.goto(
    `${origin}/#/rules/0?workspace=${application.workspaceId}&application=${application.applicationId}&section=python`,
    { waitUntil: "domcontentloaded" },
  );
  await page.getByRole("heading", { name: "Python programs" }).waitFor();
  await page.getByText("AIC Apportion Policy", { exact: true }).waitFor();
  await page.getByRole("button", { name: "Open", exact: true }).click();
  await page.getByText("This program does not require parameters.").waitFor();
}

async function renderedEditorSource(textbox) {
  return textbox.evaluate((element) => {
    const editor = element.closest(".monaco-editor");
    if (!editor) return element.value;
    return Array.from(editor.querySelectorAll(".view-line"))
      .map((line) => line.textContent || "")
      .join("\n")
      .replaceAll("\u00a0", " ");
  });
}

async function waitForRenderedEditorSource(page, textbox, expected) {
  await page.waitForFunction(
    ({ label, sourceText }) => {
      const element = Array.from(document.querySelectorAll("textarea")).find(
        (candidate) => candidate.getAttribute("aria-label") === label,
      );
      if (!element) return false;
      const editor = element.closest(".monaco-editor");
      const actual = editor
        ? Array.from(editor.querySelectorAll(".view-line"))
            .map((line) => line.textContent || "")
            .join("\n")
            .replaceAll("\u00a0", " ")
        : element.value;
      return actual === sourceText;
    },
    { label: await textbox.getAttribute("aria-label"), sourceText: expected },
  );
}

async function qualifyNormal(browser) {
  const page = await browser.newPage();
  const audit = { apiRequests: [], unhandledApi: [], externalRequests: [] };
  const errors = [];
  const cspViolations = [];
  page.on("request", (request) => {
    if (!request.url().startsWith(origin + "/"))
      audit.externalRequests.push(request.url());
  });
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  await page.exposeFunction("recordRulesCspViolation", (violation) =>
    cspViolations.push(violation),
  );
  await page.addInitScript(() =>
    document.addEventListener("securitypolicyviolation", (event) =>
      window.recordRulesCspViolation({
        directive: event.violatedDirective,
        blocked: event.blockedURI,
      }),
    ),
  );
  await installApi(page, audit);
  await openRule(page);
  const viewer = page.getByRole("textbox", {
    name: "Authorized Python source",
    exact: true,
  });
  await viewer.waitFor();
  await page.waitForFunction(() =>
    Array.from(document.querySelectorAll(".monaco-editor")).some((element) => {
      const rectangle = element.getBoundingClientRect();
      return rectangle.width > 0 && rectangle.height > 0;
    }),
  );
  assert.equal(
    await page.getByRole("button", { name: "Retry editor" }).count(),
    0,
  );
  assert.equal(await renderedEditorSource(viewer), source);
  const body = await page.locator("body").innerText();
  for (const token of [
    "a".repeat(64),
    "b".repeat(64),
    "c".repeat(64),
    "d".repeat(64),
  ])
    assert(!body.includes(token), "technical token leaked into the Rules UI");
  await page.getByRole("button", { name: "Edit current source" }).click();
  const editor = page.getByRole("textbox", {
    name: "Python program source",
    exact: true,
  });
  await editor.waitFor();
  await waitForRenderedEditorSource(page, editor, source);
  assert.equal(await renderedEditorSource(editor), source);
  assert.deepEqual(audit.unhandledApi, []);
  assert.deepEqual(audit.externalRequests, []);
  assert.deepEqual(errors, []);
  assert.deepEqual(cspViolations, []);
  await page.close();
  return {
    apiRequests: audit.apiRequests.length,
    sourceVisible: true,
    editPopulated: true,
  };
}

async function qualifyEditorFailure(browser) {
  const page = await browser.newPage();
  const audit = { apiRequests: [], unhandledApi: [], externalRequests: [] };
  await installApi(page, audit);
  await page.route("**/ui/assets/python-editor-runtime-*.js", (route) =>
    route.abort("failed"),
  );
  await openRule(page);
  const fallback = page.getByRole("textbox", {
    name: "Authorized Python source",
    exact: true,
  });
  await fallback.waitFor();
  assert.equal(await fallback.inputValue(), source);
  await page.getByRole("button", { name: "Retry editor" }).waitFor();
  assert.deepEqual(audit.unhandledApi, []);
  await page.close();
  return { sourceVisible: true, retryVisible: true };
}

let server;
let browser;
let origin;
try {
  server = createServer(async (request, response) => {
    try {
      const pathname = new URL(request.url, "http://fixture.invalid").pathname;
      const filename =
        pathname === "/"
          ? resolve(dist, "index.html")
          : resolve(dist, pathname.replace(/^\/ui\//, ""));
      if (!filename.startsWith(dist + sep)) {
        response.writeHead(404).end();
        return;
      }
      const contentType =
        {
          ".html": "text/html; charset=utf-8",
          ".js": "text/javascript; charset=utf-8",
          ".css": "text/css; charset=utf-8",
          ".ttf": "font/ttf",
        }[extname(filename)] || "application/octet-stream";
      response.writeHead(200, {
        "Content-Type": contentType,
        "Content-Security-Policy": csp,
        "X-Content-Type-Options": "nosniff",
        "Cross-Origin-Resource-Policy": "same-origin",
      });
      response.end(await readFile(filename));
    } catch {
      if (!response.headersSent) response.writeHead(404);
      response.end();
    }
  });
  await new Promise((done) => server.listen(0, "127.0.0.1", done));
  origin = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ headless: true });
  const normal = await qualifyNormal(browser);
  const editorFailure = await qualifyEditorFailure(browser);
  console.log(
    JSON.stringify({
      status: "passed",
      case: "compiled-rules-workspace",
      browser: "Playwright-managed Chromium",
      normal,
      editorFailure,
      applicationDataTouched: false,
      externalRequests: 0,
      cleanupVerified: true,
    }),
  );
} finally {
  await browser?.close();
  if (server) await new Promise((done) => server.close(done));
}
