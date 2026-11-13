import { afterEach, expect, it } from "vitest";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { browserLicenseEvidence } from "./browser-license-notices.mjs";
const scratch = [];
afterEach(() => {
  for (const root of scratch.splice(0))
    rmSync(root, { recursive: true, force: true });
});
function fixture() {
  const root = mkdtempSync(join(tmpdir(), "epm-browser-license-"));
  scratch.push(root);
  const dependencies = { runtime: "1.0.0" };
  const packages = {
    "": { dependencies },
    "node_modules/runtime": {
      version: "1.0.0",
      integrity: "sha512-YQ==",
      dependencies: { child: "2.0.0" },
    },
    "node_modules/child": { version: "2.0.0", integrity: "sha512-Yg==" },
  };
  writeFileSync(join(root, "package.json"), JSON.stringify({ dependencies }));
  writeFileSync(
    join(root, "package-lock.json"),
    JSON.stringify({ lockfileVersion: 3, packages }),
  );
  for (const name of ["runtime", "child"]) {
    const directory = join(root, "node_modules", name);
    mkdirSync(directory, { recursive: true });
    writeFileSync(
      join(directory, "package.json"),
      JSON.stringify({
        name,
        version: packages[`node_modules/${name}`].version,
        license: "MIT",
        dependencies: packages[`node_modules/${name}`].dependencies,
      }),
    );
    writeFileSync(
      join(directory, "LICENSE"),
      `Copyright ${name}\nExact license text\n`,
    );
  }
  return root;
}
it("emits deterministic exact transitive license texts with lock, version, integrity and file hashes", () => {
  const root = fixture();
  const first = browserLicenseEvidence(root),
    second = browserLicenseEvidence(root);
  expect(first).toEqual(second);
  expect(first.evidence.legalApprovalAsserted).toBe(false);
  expect(
    first.evidence.packages.map((item) => [item.name, item.version]),
  ).toEqual([
    ["runtime", "1.0.0"],
    ["child", "2.0.0"],
  ]);
  expect(first.text).toContain("Copyright child\nExact license text\n");
  expect(first.evidence.packageLockSha256).toBe(
    createHash("sha256")
      .update(readFileSync(join(root, "package-lock.json")))
      .digest("hex"),
  );
  expect(first.evidence.noticeSha256).toBe(
    createHash("sha256").update(first.text).digest("hex"),
  );
});
it.each(["version", "missing-license", "foreign-link", "dependency-drift"])(
  "fails closed on unbound or undistributable license input: %s",
  (failure) => {
    const root = fixture(),
      folder = join(root, "node_modules", "runtime");
    if (failure === "version" || failure === "dependency-drift") {
      const value = JSON.parse(readFileSync(join(folder, "package.json")));
      if (failure === "version") value.version = "9.0.0";
      else value.dependencies = {};
      writeFileSync(join(folder, "package.json"), JSON.stringify(value));
    } else {
      rmSync(join(folder, "LICENSE"));
      if (failure === "foreign-link")
        symlinkSync(join(root, "package.json"), join(folder, "LICENSE"));
    }
    expect(() => browserLicenseEvidence(root)).toThrow();
  },
);
