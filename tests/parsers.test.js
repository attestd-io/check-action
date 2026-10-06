import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { describe, expect, it } from "vitest";
import { parseRequirementsTxt } from "../src/parsers/requirements.js";
import {
  packageNameFromKey,
  parsePackageLock,
} from "../src/parsers/packageLock.js";
import { parseYarnLock } from "../src/parsers/yarnLock.js";
import { parsePnpmLock, parsePnpmPackageKey } from "../src/parsers/pnpmLock.js";

const fixtures = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

describe("parseRequirementsTxt", () => {
  it("parses pinned requirements including extras", () => {
    const content = readFileSync(
      join(fixtures, "requirements-pinned.txt"),
      "utf8"
    );
    const { items, skipped } = parseRequirementsTxt(content);
    expect(items).toEqual([
      { product: "requests", version: "2.31.0" },
      { product: "numpy", version: "1.26.4" },
      { product: "fastapi", version: "0.115.0" },
      { product: "django", version: "4.2.11" },
      { product: "urllib3", version: "2.2.1" },
    ]);
    expect(skipped).toEqual([]);
  });

  it("warns and skips ranges, editables, VCS, includes, and unpinned lines", () => {
    const content = readFileSync(
      join(fixtures, "requirements-mixed.txt"),
      "utf8"
    );
    const { items, skipped } = parseRequirementsTxt(content);
    expect(items.map((i) => i.product)).toEqual(["requests", "urllib3"]);
    const reasons = skipped.map((s) => s.reason).join(" | ");
    expect(reasons).toMatch(/ranged|unpinned/);
    expect(reasons).toMatch(/editable/);
    expect(reasons).toMatch(/VCS/);
    expect(reasons).toMatch(/include/);
    expect(reasons).toMatch(/pip option/);
    expect(skipped.some((s) => s.raw.includes("flask"))).toBe(true);
  });
});

describe("parsePackageLock", () => {
  it("includes transitive deps from packages map", () => {
    const content = readFileSync(join(fixtures, "package-lock-v3.json"), "utf8");
    const { items, skipped } = parsePackageLock(content);
    const names = items.map((i) => i.product).sort();
    expect(names).toEqual([
      "@types/node",
      "accepts",
      "debug",
      "express",
      "lodash",
      "qs",
    ]);
    expect(items.find((i) => i.product === "debug")?.version).toBe("2.6.9");
    expect(skipped).toEqual([]);
  });

  it("skips workspace-local packages and link entries", () => {
    const content = readFileSync(
      join(fixtures, "package-lock-workspace.json"),
      "utf8"
    );
    const { items, skipped } = parsePackageLock(content);
    expect(items).toEqual([{ product: "lodash", version: "4.17.21" }]);
    expect(skipped.some((s) => s.reason.includes("workspace-local"))).toBe(
      true
    );
  });

  it("rejects lockfileVersion 1", () => {
    expect(() =>
      parsePackageLock(
        JSON.stringify({ lockfileVersion: 1, dependencies: {} })
      )
    ).toThrow(/lockfileVersion 2 or 3/);
  });

  it("derives nested and scoped package names", () => {
    expect(packageNameFromKey("node_modules/lodash")).toBe("lodash");
    expect(packageNameFromKey("node_modules/@types/node")).toBe("@types/node");
    expect(
      packageNameFromKey("node_modules/express/node_modules/debug")
    ).toBe("debug");
  });
});

describe("parseYarnLock", () => {
  it("parses classic v1 including transitives and scoped names", () => {
    const content = readFileSync(join(fixtures, "yarn-classic.lock"), "utf8");
    const { items, skipped } = parseYarnLock(content);
    const names = items.map((i) => i.product).sort();
    expect(names).toEqual([
      "@types/node",
      "accepts",
      "debug",
      "express",
      "lodash",
      "qs",
    ]);
    expect(items.find((i) => i.product === "lodash")?.version).toBe("4.17.21");
    expect(items.find((i) => i.product === "@types/node")?.version).toBe(
      "20.11.0"
    );
    expect(skipped).toEqual([]);
  });

  it("parses Berry, skips workspace and patch locators, ignores __metadata version", () => {
    const content = readFileSync(join(fixtures, "yarn-berry.lock"), "utf8");
    const { items, skipped } = parseYarnLock(content);
    const names = items.map((i) => i.product).sort();
    expect(names).toEqual([
      "@types/node",
      "accepts",
      "debug",
      "express",
      "lodash",
      "qs",
    ]);
    expect(items.some((i) => i.product === "local-pkg")).toBe(false);
    expect(items.some((i) => i.product === "patched-pkg")).toBe(false);
    expect(items.some((i) => i.version === "8")).toBe(false);
    expect(skipped.some((s) => s.reason.includes("non-registry"))).toBe(true);
  });
});

describe("parsePnpmLock", () => {
  it("parses lockfileVersion 5 packages map including peer-suffix keys", () => {
    const content = readFileSync(join(fixtures, "pnpm-lock-v5.yaml"), "utf8");
    const { items } = parsePnpmLock(content);
    const names = items.map((i) => i.product).sort();
    expect(names).toEqual([
      "@types/node",
      "accepts",
      "debug",
      "express",
      "foo",
      "lodash",
      "qs",
    ]);
    expect(items.find((i) => i.product === "foo")?.version).toBe("1.0.0");
    expect(items.find((i) => i.product === "@types/node")?.version).toBe(
      "20.11.0"
    );
  });

  it("parses lockfileVersion 6 packages map including peer parentheses", () => {
    const content = readFileSync(join(fixtures, "pnpm-lock-v6.yaml"), "utf8");
    const { items } = parsePnpmLock(content);
    expect(items.find((i) => i.product === "foo")?.version).toBe("1.0.0");
    expect(items.find((i) => i.product === "express")?.version).toBe("4.18.2");
    expect(items.map((i) => i.product).sort()).toEqual([
      "@types/node",
      "accepts",
      "debug",
      "express",
      "foo",
      "lodash",
      "qs",
    ]);
  });

  it("parses lockfileVersion 9 unprefixed packages keys", () => {
    const content = readFileSync(join(fixtures, "pnpm-lock-v9.yaml"), "utf8");
    const { items } = parsePnpmLock(content);
    expect(items.find((i) => i.product === "@types/node")?.version).toBe(
      "20.11.0"
    );
    expect(items.map((i) => i.product).sort()).toEqual([
      "@types/node",
      "accepts",
      "debug",
      "express",
      "foo",
      "lodash",
      "qs",
    ]);
  });

  it("rejects unsupported lockfileVersion", () => {
    expect(() => parsePnpmLock("lockfileVersion: '7.0'\npackages: {}\n")).toThrow(
      /Supported: 5.x, 6.x, 9.x/
    );
  });

  it("strips v5 peer-suffix keys without treating the peer as the version", () => {
    expect(parsePnpmPackageKey("/foo/1.0.0_bar@2.0.0")).toEqual({
      product: "foo",
      version: "1.0.0",
    });
    expect(parsePnpmPackageKey("/@scope/name/1.2.3_peer@4.5.6")).toEqual({
      product: "@scope/name",
      version: "1.2.3",
    });
    expect(parsePnpmPackageKey("/foo@1.0.0(bar@2.0.0)")).toEqual({
      product: "foo",
      version: "1.0.0",
    });
  });

  it("resolves npm aliases to the installed package identity", () => {
    expect(parsePnpmPackageKey("is-even@npm:is-odd@3.0.1")).toEqual({
      product: "is-odd",
      version: "3.0.1",
    });
    expect(parsePnpmPackageKey("/is-even@npm:is-odd@3.0.1")).toEqual({
      product: "is-odd",
      version: "3.0.1",
    });
    expect(parsePnpmPackageKey("alias@npm:@scope/pkg@1.2.3")).toEqual({
      product: "@scope/pkg",
      version: "1.2.3",
    });
    const lock = [
      "lockfileVersion: '9.0'",
      "packages:",
      "  lodash@4.17.21:",
      "    resolution: {integrity: sha512-test}",
      "  'is-even@npm:is-odd@3.0.1':",
      "    resolution: {integrity: sha512-test}",
      "",
    ].join("\n");
    const { items } = parsePnpmLock(lock);
    expect(items).toEqual(
      expect.arrayContaining([
        { product: "lodash", version: "4.17.21" },
        { product: "is-odd", version: "3.0.1" },
      ])
    );
    expect(items.some((i) => i.product === "is-even")).toBe(false);
  });
});

describe("lockfile registry aliases", () => {
  it("uses package-lock entry.name when the folder is an alias", () => {
    const content = JSON.stringify({
      name: "fixture-app",
      lockfileVersion: 3,
      packages: {
        "": { name: "fixture-app", version: "1.0.0" },
        "node_modules/lodash": { version: "4.17.21" },
        "node_modules/is-even": {
          name: "is-odd",
          version: "3.0.1",
        },
      },
    });
    const { items } = parsePackageLock(content);
    expect(items).toEqual(
      expect.arrayContaining([
        { product: "lodash", version: "4.17.21" },
        { product: "is-odd", version: "3.0.1" },
      ])
    );
    expect(items.some((i) => i.product === "is-even")).toBe(false);
  });

  it("uses yarn Berry resolution for npm aliases", () => {
    const content = [
      "__metadata:",
      "  version: 8",
      "",
      '"lodash@npm:^4.17.21":',
      "  version: 4.17.21",
      '  resolution: "lodash@npm:4.17.21"',
      "",
      '"is-even@npm:is-odd@^3.0.0":',
      "  version: 3.0.1",
      '  resolution: "is-odd@npm:3.0.1"',
      "",
    ].join("\n");
    const { items } = parseYarnLock(content);
    expect(items).toEqual([
      { product: "lodash", version: "4.17.21" },
      { product: "is-odd", version: "3.0.1" },
    ]);
  });

  it("uses yarn classic npm alias target when resolution is absent", () => {
    const content = [
      "# yarn lockfile v1",
      "",
      '"is-even@npm:is-odd@3.0.1":',
      '  version "3.0.1"',
      '  resolved "https://registry.yarnpkg.com/is-odd/-/is-odd-3.0.1.tgz"',
      "",
      'lodash@^4.17.21:',
      '  version "4.17.21"',
      "",
    ].join("\n");
    const { items } = parseYarnLock(content);
    expect(items).toEqual([
      { product: "is-odd", version: "3.0.1" },
      { product: "lodash", version: "4.17.21" },
    ]);
  });
});
