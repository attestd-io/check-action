import { describe, expect, it } from "vitest";
import { detectParser, parseLockfile } from "../src/lockfile.js";

describe("detectParser", () => {
  it("accepts requirements.txt and common variants", () => {
    expect(detectParser("requirements.txt")).toBe("requirements");
    expect(detectParser("requirements-dev.txt")).toBe("requirements");
    expect(detectParser("dev-requirements.txt")).toBe("requirements");
  });

  it("accepts package-lock.json", () => {
    expect(detectParser("package-lock.json")).toBe("package-lock");
  });

  it("accepts yarn.lock and pnpm-lock.yaml", () => {
    expect(detectParser("yarn.lock")).toBe("yarn");
    expect(detectParser("pnpm-lock.yaml")).toBe("pnpm");
  });

  it("rejects unsupported basenames", () => {
    expect(detectParser("Pipfile.lock")).toBeNull();
    expect(detectParser("package.json")).toBeNull();
    expect(detectParser("poetry.lock")).toBeNull();
  });
});

describe("parseLockfile", () => {
  it("throws a supported-formats message for unknown files", () => {
    expect(() => parseLockfile("Pipfile.lock", "{}")).toThrow(
      /yarn\.lock \(classic v1 and Berry\).*pnpm-lock\.yaml/
    );
  });
});
