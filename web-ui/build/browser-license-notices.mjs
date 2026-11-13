import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
} from "node:fs";
import { dirname, join, relative, sep } from "node:path";

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const dependencyIdentity = (value) =>
  JSON.stringify(
    Object.entries(value || {}).sort(([left], [right]) =>
      left.localeCompare(right),
    ),
  );
const namePattern = /^(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+$/i;

/** Exact installed license evidence, not a legal conclusion. The production
 * image installs this lock with npm ci before bundling these notices. */
export function browserLicenseEvidence(root) {
  root = realpathSync(root);
  const lockBytes = readFileSync(join(root, "package-lock.json"));
  const lock = JSON.parse(lockBytes.toString("utf8"));
  const project = JSON.parse(readFileSync(join(root, "package.json"), "utf8"));
  if (
    lock.lockfileVersion !== 3 ||
    !lock.packages?.[""] ||
    dependencyIdentity(project.dependencies) !==
      dependencyIdentity(lock.packages[""].dependencies)
  )
    throw new Error(
      "Browser runtime dependencies differ from the exact npm lock.",
    );
  const pending = Object.keys(project.dependencies || {})
    .sort()
    .map((name) => ({ from: root, name }));
  const visited = new Set();
  const packages = [];
  const notices = [
    "OPEN EPM BROWSER THIRD-PARTY LICENSE TEXTS",
    "",
    "Exact installed runtime dependency license evidence; no legal approval is asserted.",
    "",
  ];
  while (pending.length) {
    const dependency = pending.shift();
    if (!namePattern.test(dependency.name))
      throw new Error("Invalid locked browser dependency name.");
    let from = dependency.from,
      directory = "";
    while (from === root || from.startsWith(root + sep)) {
      const candidate = join(from, "node_modules", dependency.name);
      if (existsSync(join(candidate, "package.json"))) {
        directory = candidate;
        break;
      }
      if (from === root) break;
      from = dirname(from);
    }
    if (!directory && dependency.optional) continue;
    if (
      !directory ||
      lstatSync(directory).isSymbolicLink() ||
      !realpathSync(directory).startsWith(root + sep)
    )
      throw new Error(
        `Missing or external browser dependency: ${dependency.name}`,
      );
    const packagePath = relative(root, directory).split(sep).join("/");
    if (visited.has(packagePath)) continue;
    visited.add(packagePath);
    const installed = JSON.parse(
      readFileSync(join(directory, "package.json"), "utf8"),
    );
    const pinned = lock.packages[packagePath];
    if (
      !pinned ||
      installed.name !== dependency.name ||
      installed.version !== pinned.version ||
      dependencyIdentity(installed.dependencies) !==
        dependencyIdentity(pinned.dependencies) ||
      dependencyIdentity(installed.optionalDependencies) !==
        dependencyIdentity(pinned.optionalDependencies) ||
      pinned.dev === true ||
      typeof pinned.integrity !== "string" ||
      !/^sha512-[A-Za-z0-9+/]+=*$/.test(pinned.integrity)
    )
      throw new Error(`Unbound browser dependency: ${dependency.name}`);
    const files = readdirSync(directory)
      .filter((name) =>
        /^(license|licence|copying|notice)([.-].*)?$/i.test(name),
      )
      .sort();
    if (!files.length)
      throw new Error(
        `Browser dependency has no distributable license text: ${dependency.name}`,
      );
    const licenseFiles = files.map((name) => {
      const path = join(directory, name);
      if (lstatSync(path).isSymbolicLink() || !lstatSync(path).isFile())
        throw new Error(
          `Unsafe browser license file: ${dependency.name}/${name}`,
        );
      const bytes = readFileSync(path);
      if (!bytes.length || bytes.length > 1048576)
        throw new Error(
          `Invalid browser license text: ${dependency.name}/${name}`,
        );
      notices.push(
        `${installed.name} ${installed.version} — ${name}`,
        `Declared license: ${typeof installed.license === "string" ? installed.license : "See exact text"}`,
        `SHA-256: ${sha256(bytes)}`,
        "",
        bytes.toString("utf8"),
        "",
      );
      return { path: `${packagePath}/${name}`, sha256: sha256(bytes) };
    });
    packages.push({
      name: installed.name,
      version: installed.version,
      declaredLicense: installed.license ?? null,
      integrity: pinned.integrity,
      packagePath,
      licenseFiles,
    });
    for (const name of Object.keys(installed.dependencies || {}).sort())
      pending.push({ from: directory, name });
    for (const name of Object.keys(installed.optionalDependencies || {}).sort())
      pending.push({ from: directory, name, optional: true });
  }
  const text = notices.join("\n");
  return {
    text,
    evidence: {
      format: "openepm-browser-license-evidence-v1",
      legalApprovalAsserted: false,
      packageLockSha256: sha256(lockBytes),
      noticeSha256: sha256(text),
      packages,
    },
  };
}

export function browserLicenseNotices() {
  let root = "";
  return {
    name: "openepm-browser-license-notices",
    apply: "build",
    configResolved(config) {
      root = config.root;
    },
    generateBundle() {
      const { text, evidence } = browserLicenseEvidence(root);
      this.emitFile({
        type: "asset",
        fileName: "third-party-notices.txt",
        source: text,
      });
      this.emitFile({
        type: "asset",
        fileName: "third-party-license-evidence.json",
        source: JSON.stringify(evidence, null, 2) + "\n",
      });
    },
  };
}
