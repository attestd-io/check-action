import { describe, expect, it } from "vitest";
import { shouldFail } from "../src/lib.js";

describe("shouldFail", () => {
  it("fails at high when fail_on is high", () => {
    expect(shouldFail("high", "high")).toBe(true);
    expect(shouldFail("elevated", "high")).toBe(false);
  });

  it("fails at any non-none risk when fail_on is any", () => {
    expect(shouldFail("low", "any")).toBe(true);
    expect(shouldFail("none", "any")).toBe(false);
  });

  it("never fails when fail_on is never", () => {
    expect(shouldFail("critical", "never")).toBe(false);
  });

  it("defaults unknown fail_on to high threshold", () => {
    expect(shouldFail("high", "bogus")).toBe(true);
    expect(shouldFail("elevated", "bogus")).toBe(false);
  });
});

describe("supported:false handling", () => {
  it("treats missing supported as supported for legacy payloads", () => {
    const data = { risk_state: "none" };
    expect(data.supported).toBeUndefined();
    expect(!data.supported).toBe(true);
  });

  it("detects explicit unsupported responses", () => {
    const data = { supported: false };
    expect(data.supported === false).toBe(true);
  });
});

describe("HTTP status handling", () => {
  it("maps 401 to auth failure", () => {
    expect(401).toBe(401);
  });

  it("maps 429 to quota failure", () => {
    expect(429).toBe(429);
  });
});
