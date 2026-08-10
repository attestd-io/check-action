import { readFileSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";
import { describe, expect, it } from "vitest";
import { parseRequirementsTxt } from "../src/parsers/requirements.js";
import {
  packageNameFromKey,
  parsePackageLock,
} from "../src/parsers/packageLock.js";

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
