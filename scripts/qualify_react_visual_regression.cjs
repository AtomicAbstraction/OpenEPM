#!/usr/bin/env node

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright");

function argument(name, fallback) {
  const prefix = `--${name}=`;
  const value = process.argv.find((item) => item.startsWith(prefix));
  return value ? value.slice(prefix.length) : fallback;
}

const baseUrl = argument("base-url", "http://127.0.0.1:4173");
const fixedBrowserTime = argument("time", "2026-11-02T08:00:00.000Z");
const browserChannel = argument("browser-channel", "chromium");
const metadataScale = argument("metadata-scale", "false") === "true";
if (!new Set(["chromium", "chrome"]).has(browserChannel))
  throw new Error(`unsupported browser channel: ${browserChannel}`);
const outputDirectory = path.resolve(
  argument("output", "docs/qualifications/react-visual-regression"),
);
const baselineDirectoryValue = argument("baseline", "");
const baselineDirectory = baselineDirectoryValue
  ? path.resolve(baselineDirectoryValue)
  : null;
const axePath = path.resolve(
  argument(
    "axe-path",
    path.join(
      __dirname,
      "..",
      "web-ui",
      "node_modules",
      "axe-core",
      "axe.min.js",
    ),
  ),
);
const requestedRoutes = argument("routes", "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);
const requestedProfiles = argument("profiles", "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);
const routeDefinitions = [
  { name: "home", hash: "#/home/0" },
  { name: "applications", hash: "#/applications/0" },
  { name: "my-work", hash: "#/work/0" },
  { name: "overview", hash: "#/overview/0" },
  { name: "analyze", hash: "#/analyze/0" },
  { name: "plan", hash: "#/plan/0" },
  { name: "data", hash: "#/data/0" },
  { name: "metadata", hash: "#/metadata/0" },
  { name: "workflow", hash: "#/workflow/0" },
  { name: "build", hash: "#/build/0" },
  { name: "monitor", hash: "#/monitor/0" },
  { name: "administration", hash: "#/administration/0" },
].filter(
  ({ name }) => !requestedRoutes.length || requestedRoutes.includes(name),
);
const viewportProfiles = [
  { name: "desktop", width: 1440, height: 1000 },
  { name: "mobile", width: 390, height: 844 },
  { name: "reflow-320", width: 320, height: 800 },
].filter(
  ({ name }) => !requestedProfiles.length || requestedProfiles.includes(name),
);
const maximumDecodedChannelDelta = 1;

function readBaseline() {
  if (!baselineDirectory) return null;
  const reportPath = path.join(baselineDirectory, "report.json");
  if (!fs.existsSync(reportPath))
    throw new Error(`visual baseline report not found: ${reportPath}`);
  const report = JSON.parse(fs.readFileSync(reportPath, "utf8"));
  if (!Array.isArray(report.captures))
    throw new Error(`visual baseline captures are invalid: ${reportPath}`);
  return new Map(
    report.captures.map((capture) => [
      `${capture.viewport}:${capture.route}`,
      {
        ...capture,
        absoluteFile: path.join(baselineDirectory, capture.file),
      },
    ]),
  );
}

function pngDataUrl(filename) {
  if (!fs.existsSync(filename))
    throw new Error(`visual capture not found: ${filename}`);
  return `data:image/png;base64,${fs.readFileSync(filename).toString("base64")}`;
}

async function compareDecodedPixels(page, expectedFile, actualFile) {
  return page.evaluate(
    async ({ expectedSource, actualSource, maximumDelta }) => {
      async function decode(source) {
        const image = new Image();
        image.src = source;
        await image.decode();
        const canvas = document.createElement("canvas");
        canvas.width = image.naturalWidth;
        canvas.height = image.naturalHeight;
        const context = canvas.getContext("2d", { willReadFrequently: true });
        context.drawImage(image, 0, 0);
        return {
          width: canvas.width,
          height: canvas.height,
          pixels: context.getImageData(0, 0, canvas.width, canvas.height).data,
        };
      }

      const expected = await decode(expectedSource);
      const actual = await decode(actualSource);
      if (
        expected.width !== actual.width ||
        expected.height !== actual.height
      ) {
        return {
          dimensionsMatch: false,
          expectedWidth: expected.width,
          expectedHeight: expected.height,
          actualWidth: actual.width,
          actualHeight: actual.height,
          maximumChannelDelta: null,
          meanAbsoluteChannelDelta: null,
          differentPixels: null,
          outOfTolerancePixels: null,
          matched: false,
        };
      }

      let maximumChannelDelta = 0;
      let totalChannelDelta = 0;
      let differentPixels = 0;
      let outOfTolerancePixels = 0;
      for (let offset = 0; offset < expected.pixels.length; offset += 4) {
        let pixelMaximum = 0;
        for (let channel = 0; channel < 4; channel += 1) {
          const delta = Math.abs(
            expected.pixels[offset + channel] - actual.pixels[offset + channel],
          );
          pixelMaximum = Math.max(pixelMaximum, delta);
          maximumChannelDelta = Math.max(maximumChannelDelta, delta);
          totalChannelDelta += delta;
        }
        if (pixelMaximum > 0) differentPixels += 1;
        if (pixelMaximum > maximumDelta) outOfTolerancePixels += 1;
      }
      return {
        dimensionsMatch: true,
        expectedWidth: expected.width,
        expectedHeight: expected.height,
        actualWidth: actual.width,
        actualHeight: actual.height,
        maximumChannelDelta,
        meanAbsoluteChannelDelta: totalChannelDelta / expected.pixels.length,
        differentPixels,
        outOfTolerancePixels,
        matched: outOfTolerancePixels === 0,
      };
    },
    {
      expectedSource: pngDataUrl(expectedFile),
      actualSource: pngDataUrl(actualFile),
      maximumDelta: maximumDecodedChannelDelta,
    },
  );
}

async function compareBaseline(captures, baseline, browser) {
  if (!baseline) return null;
  const page = await browser.newPage();
  const comparisons = [];
  for (const capture of captures) {
    const key = `${capture.viewport}:${capture.route}`;
    const expected = baseline.get(key);
    const exactBytes = Boolean(expected && expected.sha256 === capture.sha256);
    const decoded =
      expected && !exactBytes
        ? await compareDecodedPixels(
            page,
            expected.absoluteFile,
            path.join(outputDirectory, capture.file),
          )
        : null;
    comparisons.push({
      key,
      expectedSha256: expected?.sha256 || null,
      actualSha256: capture.sha256,
      exactBytes,
      decodedPixelComparison: decoded,
      matched: Boolean(expected && (exactBytes || decoded?.matched)),
    });
  }
  await page.close();
  return comparisons;
}

const application = {
  workspaceId: "ws-visual",
  applicationId: "visual-fpna",
  name: "Visual FP&A",
  status: "Active",
  kind: "blank",
};

const functions = {
  "application.capabilities.configure": {},
  "application.capabilities.history.read": {},
  "application.capabilities.read": {},
  "facts.cube.scan": {},
  "facts.cube.aggregate.request": {},
  "facts.cube.aggregate.read": {},
  "facts.cube.aggregate.cancel": {},
  "facts.numeric.batch": {},
  "facts.text.batch": {},
  "grid.definition.list": {},
  "grid.definition.save": {},
  "metadata.dimension.list": {},
  "metadata.member.list": {},
  "metadata.member.security-string.set": {},
  "metadata.security-tag.create": {},
  "metadata.security-tag.list": {},
  "metadata.security-tag.status.set": {},
  "metadata.security-tag.update": {},
  "cube.write.scope.worklist": {},
  "python.program.list": {},
};
if (metadataScale) {
  Object.assign(functions, {
    "metadata.attribute-definition.list": {},
    "metadata.attribute-value.set": {},
    "metadata.relationship.list": {},
  });
}

function metadataDefinitions(prefix) {
  return Array.from({ length: 200 }, (_, index) => ({
    attribute_id: `${prefix}${String(index + 1).padStart(3, "0")}`,
    display_name: `${prefix} attribute ${index + 1}`,
    value_type: "Text",
    validation_constraints: {},
    status: "Active",
    state_token: String(index + 1).padStart(64, "0"),
  }));
}

const memberAttributeDefinitions = metadataScale
  ? metadataDefinitions("Member")
  : [];
const relationshipAttributeDefinitions = metadataScale
  ? metadataDefinitions("Placement")
  : [];
const scaleMembers = metadataScale
  ? Array.from({ length: 10_000 }, (_, index) => ({
      member_id: `M${String(index).padStart(5, "0")}`,
      name: `Member ${index}`,
      status: "Active",
      short_description: `Scale member ${index}`,
      custom_values: Object.fromEntries(
        memberAttributeDefinitions
          .slice(0, 20)
          .map((definition) => [definition.attribute_id, `M-${index}`]),
      ),
    }))
  : [];
const scaleRelationships = metadataScale
  ? Array.from({ length: 10_000 }, (_, index) => ({
      relationship_id: `R${String(index).padStart(5, "0")}`,
      dimension_id: "Account",
      name: `Placement ${index}`,
      short_description: `Scale placement ${index}`,
      parent_member_id: `M${String(Math.floor(index / 10)).padStart(5, "0")}`,
      child_member_id: `M${String(index).padStart(5, "0")}`,
      status: "Active",
      custom_values: Object.fromEntries(
        relationshipAttributeDefinitions
          .slice(0, 20)
          .map((definition) => [definition.attribute_id, `R-${index}`]),
      ),
    }))
  : [];

const catalog = {
  applicationAccess: { role: "Administrator", workspaceAdministrator: true },
  enabledCapabilities: [],
  functions,
  revisions: {
    metadata: 46,
    data: 136,
    policy: 37,
    security: 4,
    commit: 212,
    capability: 3,
    schemaEpoch: 211,
  },
};

const tasks = {
  tasks: [
    {
      taskId: "task-agent-forecast",
      function: "planning.forecast.advance",
      status: "Running",
      initiatorKind: "MCP agent",
      acceptedAt: "2026-11-02T07:30:00Z",
    },
    {
      taskId: "task-human-load",
      function: "facts.source.begin",
      status: "Failed",
      initiatorKind: "Human",
      acceptedAt: "2026-11-02T07:15:00Z",
    },
  ],
};

function readResult(functionName, args = {}) {
  if (functionName === "application.capabilities.read") {
    return {
      enabledCapabilities: [],
      capabilityRevision: 3,
      metadataRevision: 46,
      dataRevision: 136,
      policyRevision: 37,
      commitRevision: 212,
      schemaEpoch: 211,
    };
  }
  if (functionName === "application.capabilities.history.read") {
    return { rows: [], hasMore: false, nextAfterRevision: null };
  }
  if (functionName === "cube.write.scope.worklist") {
    return {
      assignmentItems: [
        {
          assignmentId: "assignment-plan-fy27",
          name: "FY27 operating plan",
          workflowRole: "Preparer",
          dueAt: "2026-11-03T17:00:00Z",
          scenarioMemberId: "Plan",
          yearMemberId: "FY27",
          memberSelectors: { Scenario: ["Plan"], Year: ["FY27"] },
          reviewerChain: [],
          control: { version: 2 },
        },
      ],
      items: [],
      assignedReviewItems: [],
      activeAssignmentSet: {
        assignmentSetId: "annual-plan-assignments",
        version: 4,
        digest: "visual-fixture-assignment-digest",
      },
      activePlanningPolicy: { policyId: "annual-plan", version: 3 },
      assignmentPolicyMismatch: false,
    };
  }
  if (functionName === "metadata.dimension.list") {
    return {
      rows: [
        {
          dimension_id: "Account",
          name: "Account",
          model_role: "Account",
          status: "Active",
        },
        {
          dimension_id: "Period",
          name: "Period",
          model_role: "Period",
          status: "Active",
        },
        {
          dimension_id: "Scenario",
          name: "Scenario",
          model_role: "Scenario",
          status: "Active",
        },
      ],
      nextAfterDimensionId: null,
      metadataRevision: 46,
    };
  }
  if (functionName === "metadata.member.list") {
    if (metadataScale) {
      return {
        rows: scaleMembers,
        nextAfterMemberId: null,
        metadataRevision: 46,
      };
    }
    return {
      rows: [
        { member_id: "Actual", name: "Actual", status: "Active" },
        { member_id: "Plan", name: "Plan", status: "Active" },
      ],
      hasMore: false,
    };
  }
  if (functionName === "metadata.relationship.list") {
    return {
      rows: scaleRelationships,
      nextCursor: null,
      metadataRevision: 46,
    };
  }
  if (functionName === "metadata.attribute-definition.list") {
    return {
      rows:
        args.scope === "Relationship"
          ? relationshipAttributeDefinitions
          : memberAttributeDefinitions,
      hasMore: false,
      nextAfterAttributeId: null,
      metadataRevision: 46,
    };
  }
  if (functionName === "metadata.security-tag.list") {
    return {
      rows: [
        {
          dimension_id: "Account",
          tag_id: "SensitiveRead",
          display_name: "Sensitive read",
          short_description: "Read access to sensitive accounts",
          semantic_description:
            "Allows a principal to read members classified as sensitive.",
          status: "Active",
        },
        {
          dimension_id: "Account",
          tag_id: "SensitiveWrite",
          display_name: "Sensitive write",
          short_description: "Write access to sensitive accounts",
          semantic_description:
            "Allows a principal to write members classified as sensitive.",
          status: "Active",
        },
      ],
      nextAfterTagId: null,
      metadataRevision: 46,
    };
  }
  if (functionName === "facts.cube.scan") {
    return {
      items: [
        {
          coordinates: { Account: "Revenue", Period: "P1", Scenario: "Actual" },
          valueKind: "Numeric",
          amount: "100.00000000",
        },
        {
          coordinates: { Account: "Revenue", Period: "P2", Scenario: "Actual" },
          valueKind: "Numeric",
          amount: "112.50000000",
        },
        {
          coordinates: { Account: "Cost", Period: "P1", Scenario: "Actual" },
          valueKind: "Numeric",
          amount: "64.25000000",
        },
        {
          coordinates: { Account: "Cost", Period: "P2", Scenario: "Actual" },
          valueKind: "Numeric",
          amount: "70.00000000",
        },
      ],
      nextAfter: null,
      snapshotRevision: 136,
    };
  }
  if (functionName === "python.program.list") {
    return { items: [], nextAfter: null };
  }
  if (functionName === "grid.definition.list") {
    return { grids: [], nextAfterGridId: null };
  }
  return { items: [], nextAfter: null };
}

function response(body, status = 200) {
  return {
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  };
}

async function installDeterministicApi(page) {
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === "/api/applications") {
      await route.fulfill(
        response({ applications: [application], nextAfter: null }),
      );
      return;
    }
    if (url.pathname === "/api/session-identity") {
      await route.fulfill(
        response({
          subject: "visual-owner",
          displayIdentity: "owner@openepm.dev",
          applicationMcpEndpoint:
            "https://mcp.openepm.dev/api/application/mcp/personal/visual-owner",
        }),
      );
      return;
    }
    if (url.pathname === "/api/catalog") {
      await route.fulfill(response(catalog));
      return;
    }
    if (url.pathname === "/api/tasks") {
      await route.fulfill(response(tasks));
      return;
    }
    if (url.pathname === "/api/read") {
      const payload = request.postDataJSON();
      await route.fulfill(
        response({
          result: readResult(
            payload.program.function,
            payload.program.arguments || {},
          ),
        }),
      );
      return;
    }
    await route.fulfill(
      response({ error: "VISUAL_FIXTURE_ENDPOINT_UNAVAILABLE" }, 404),
    );
  });
}

async function auditPage(page, name) {
  await page.addScriptTag({ path: axePath });
  const accessibility = await page.evaluate(async () => {
    const result = await window.axe.run(document, {
      runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21aa"] },
    });
    return result.violations.map((violation) => ({
      id: violation.id,
      impact: violation.impact,
      help: violation.help,
      nodes: violation.nodes.map((node) => node.target),
    }));
  });
  const layout = await page.evaluate(() => {
    const horizontalOverflow =
      document.documentElement.scrollWidth > window.innerWidth + 1 ||
      document.body.scrollWidth > window.innerWidth + 1;
    const overflowCandidates = horizontalOverflow
      ? Array.from(document.querySelectorAll("body *"))
          .map((element) => {
            const rectangle = element.getBoundingClientRect();
            return {
              element: `${element.tagName.toLowerCase()}${element.id ? `#${element.id}` : ""}${element.className && typeof element.className === "string" ? `.${element.className.trim().replace(/\s+/g, ".")}` : ""}`,
              left: Math.round(rectangle.left * 100) / 100,
              right: Math.round(rectangle.right * 100) / 100,
              width: Math.round(rectangle.width * 100) / 100,
            };
          })
          .filter((item) => item.right > window.innerWidth + 1)
          .sort((left, right) => right.right - left.right)
          .slice(0, 20)
      : [];
    return {
      viewportWidth: window.innerWidth,
      documentWidth: document.documentElement.scrollWidth,
      bodyWidth: document.body.scrollWidth,
      horizontalOverflow,
      overflowCandidates,
    };
  });
  if (accessibility.length) {
    throw new Error(
      `${name}: ${accessibility.length} rendered accessibility violations ${JSON.stringify(accessibility)}`,
    );
  }
  if (layout.horizontalOverflow) {
    throw new Error(
      `${name}: document-level horizontal overflow ${JSON.stringify(layout)}`,
    );
  }
  return { accessibility, layout };
}

async function capture(page, viewportName, routeName, hash, pageErrors) {
  pageErrors.length = 0;
  const navigationStarted = performance.now();
  await page.goto(`${baseUrl}/${hash}`, {
    waitUntil: "domcontentloaded",
    timeout: 60_000,
  });
  try {
    await page.locator("#main-content").waitFor({ timeout: 5000 });
  } catch (error) {
    const bodyText = await page
      .locator("body")
      .innerText()
      .catch(() => "");
    throw new Error(
      `${viewportName}-${routeName}: main content did not render at ${page.url()}; page errors: ${JSON.stringify(pageErrors)}; body: ${bodyText.slice(0, 1000)}`,
      { cause: error },
    );
  }
  if (routeName === "plan") {
    const editor = page.getByRole("button", { name: "Prepare next version" });
    await editor.waitFor({ state: "visible", timeout: 5000 });
    await editor.click();
  }
  let metadataScaleAudit = null;
  if (metadataScale && routeName === "metadata") {
    await page
      .getByRole("table", { name: "Relationship placement attribute grid" })
      .waitFor({ state: "visible", timeout: 30_000 });
    await page
      .locator('table[aria-label="Member attribute grid"] thead th', {
        hasText: "Member attribute 20",
      })
      .waitFor({
        state: "attached",
        timeout: 30_000,
      });
    metadataScaleAudit = await page.evaluate(() => {
      const tables = Array.from(
        document.querySelectorAll(".metadata-wide-grid-scroll"),
      );
      if (tables.length !== 2)
        throw new Error(
          `expected two wide metadata grids, found ${tables.length}`,
        );
      const tableAudit = tables.map((container) => {
        const table = container.querySelector("table");
        const firstStickyId = table?.querySelector(".metadata-sticky-id");
        const firstStickyName = table?.querySelector(".metadata-sticky-name");
        if (!table || !firstStickyId || !firstStickyName)
          throw new Error("metadata grid identity columns are missing");
        const before = container.scrollLeft;
        container.scrollLeft = container.scrollWidth;
        const after = container.scrollLeft;
        return {
          dataRows: table.querySelectorAll("tbody tr").length,
          columnHeaders: table.querySelectorAll("thead th").length,
          clientWidth: container.clientWidth,
          scrollWidth: container.scrollWidth,
          horizontalScrollAvailable:
            container.scrollWidth > container.clientWidth,
          horizontalScrollMoved: after > before,
          stickyIdPosition: getComputedStyle(firstStickyId).position,
          stickyNamePosition: getComputedStyle(firstStickyName).position,
        };
      });
      const checkedColumns = Array.from(
        document.querySelectorAll(
          '.metadata-column-picker input[type="checkbox"]:checked',
        ),
      ).length;
      return { tables: tableAudit, checkedColumns };
    });
    for (const table of metadataScaleAudit.tables) {
      if (
        table.dataRows !== 50 ||
        !table.horizontalScrollAvailable ||
        !table.horizontalScrollMoved ||
        table.stickyIdPosition !== "sticky" ||
        table.stickyNamePosition !== "sticky"
      )
        throw new Error(
          `${viewportName}-metadata: scale grid contract failed ${JSON.stringify(metadataScaleAudit)}`,
        );
    }
    if (metadataScaleAudit.checkedColumns !== 40)
      throw new Error(
        `${viewportName}-metadata: expected 40 selected attribute columns, found ${metadataScaleAudit.checkedColumns}`,
      );
  }
  const audit = await auditPage(page, `${viewportName}-${routeName}`);
  const filename = `${viewportName}-${routeName}.png`;
  const target = path.join(outputDirectory, filename);
  await page.screenshot({
    path: target,
    fullPage: true,
    animations: "disabled",
  });
  const bytes = fs.readFileSync(target);
  return {
    viewport: viewportName,
    route: routeName,
    hash,
    file: filename,
    bytes: bytes.length,
    sha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    navigationToAuditMilliseconds: Number(
      (performance.now() - navigationStarted).toFixed(3),
    ),
    metadataScaleAudit,
    ...audit,
  };
}

async function main() {
  if (!fs.existsSync(axePath))
    throw new Error(`axe-core not found: ${axePath}`);
  fs.mkdirSync(outputDirectory, { recursive: true });
  const baseline = readBaseline();
  const browser = await chromium.launch({
    headless: true,
    channel: browserChannel === "chrome" ? "chrome" : undefined,
  });
  const startedAt = new Date().toISOString();
  const captures = [];
  let baselineComparison = null;
  try {
    for (const profile of viewportProfiles) {
      const context = await browser.newContext({
        viewport: { width: profile.width, height: profile.height },
        colorScheme: "light",
        reducedMotion: "reduce",
        deviceScaleFactor: 1,
      });
      await context.addInitScript(
        ({ fixedTime }) => {
          const NativeDate = Date;
          const fixedMilliseconds = new NativeDate(fixedTime).valueOf();
          class FixedDate extends NativeDate {
            constructor(...args) {
              super(...(args.length ? args : [fixedMilliseconds]));
            }
            static now() {
              return fixedMilliseconds;
            }
          }
          Object.defineProperty(globalThis, "Date", {
            configurable: true,
            value: FixedDate,
          });
          Object.defineProperty(globalThis.crypto, "randomUUID", {
            configurable: true,
            value: () => "11111111-2222-4333-8444-555555555555",
          });
        },
        { fixedTime: fixedBrowserTime },
      );
      for (const route of routeDefinitions) {
        process.stdout.write(`QUALIFY ${profile.name}/${route.name}\n`);
        const page = await context.newPage();
        page.setDefaultTimeout(30_000);
        page.setDefaultNavigationTimeout(60_000);
        const pageErrors = [];
        page.on("pageerror", (error) => pageErrors.push(error.message));
        await installDeterministicApi(page);
        captures.push(
          await capture(page, profile.name, route.name, route.hash, pageErrors),
        );
        await page.close();
      }
      await context.close();
    }
    baselineComparison = await compareBaseline(captures, baseline, browser);
  } finally {
    await browser.close();
  }
  const baselinePassed =
    baselineComparison === null ||
    baselineComparison.every((comparison) => comparison.matched);
  const report = {
    schemaVersion: 1,
    startedAt,
    completedAt: new Date().toISOString(),
    baseUrl,
    browserChannel,
    fixedBrowserTime,
    baselineDirectory,
    visualComparisonPolicy: {
      exactPngBytesPreferred: true,
      maximumDecodedChannelDelta,
      rationale:
        "Permit only one-level per-channel raster noise after decoding; dimensions and every pixel remain checked.",
    },
    baselineComparison,
    fixture: {
      application,
      role: catalog.applicationAccess.role,
      enabledCapabilities: catalog.enabledCapabilities,
      taskCount: tasks.tasks.length,
      metadataScale: metadataScale
        ? {
            members: scaleMembers.length,
            relationships: scaleRelationships.length,
            memberAttributeDefinitions: memberAttributeDefinitions.length,
            relationshipAttributeDefinitions:
              relationshipAttributeDefinitions.length,
          }
        : null,
    },
    profiles: viewportProfiles,
    routes: routeDefinitions,
    captures,
    result: baselinePassed ? "passed" : "failed",
  };
  fs.writeFileSync(
    path.join(outputDirectory, "report.json"),
    `${JSON.stringify(report, null, 2)}\n`,
  );
  if (!baselinePassed) {
    const failures = baselineComparison.filter(
      (comparison) => !comparison.matched,
    );
    throw new Error(
      `visual baseline mismatch: ${failures.length} of ${captures.length} captures changed; inspect ${path.join(outputDirectory, "report.json")}`,
    );
  }
  process.stdout.write(
    `PASS ${captures.length} captures; zero rendered accessibility violations, zero document overflow${baseline ? ", and decoded-pixel visual baseline match" : ""}\n`,
  );
}

main().catch((error) => {
  process.stderr.write(`${error.stack || error}\n`);
  process.exitCode = 1;
});
