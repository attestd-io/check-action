import { beforeEach, describe, expect, it, vi } from "vitest";
import { run } from "../src/index.js";

function makeCore(overrides = {}) {
  return {
    getInput: vi.fn((name) => {
      const values = {
        api_key: "atst_test_key",
        product: "langchain",
        version: "0.1.0",
        fail_on: "high",
        base_url: "https://api.attestd.io",
        ...overrides.inputs,
      };
      return values[name] ?? "";
    }),
    setSecret: vi.fn(),
    setOutput: vi.fn(),
    setFailed: vi.fn(),
    info: vi.fn(),
    warning: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
    summary: {
      addHeading: vi.fn().mockReturnThis(),
      addTable: vi.fn().mockReturnThis(),
      addRaw: vi.fn().mockReturnThis(),
      addLink: vi.fn().mockReturnThis(),
      write: vi.fn().mockResolvedValue(undefined),
    },
    ...overrides,
  };
}

describe("run", () => {
  let core;

  beforeEach(() => {
    core = makeCore();
  });

  it("fails when supply_chain.compromised with risk_state none", async () => {
    const fetch = vi.fn().mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({
        supported: true,
        product: "langchain",
        version: "0.1.0",
        risk_state: "none",
        actively_exploited: false,
        fixed_version: null,
        cve_ids: [],
        supply_chain: {
          compromised: true,
          malware_type: "malicious_publish",
          advisory_url: "https://osv.dev/MAL-123",
        },
      }),
    });

    await run({ core, fetch });

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("supply-chain compromise")
    );
    expect(core.setOutput).toHaveBeenCalledWith("compromised", "true");
  });

  it("fails closed on unrecognized risk_state", async () => {
    const fetch = vi.fn().mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({
        supported: true,
        risk_state: "unknown",
        actively_exploited: false,
        cve_ids: [],
      }),
    });

    await run({ core, fetch });

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("unrecognized risk_state")
    );
  });

  it("handles cve_ids null without throwing", async () => {
    const fetch = vi.fn().mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({
        supported: true,
        risk_state: "none",
        actively_exploited: false,
        cve_ids: null,
        supply_chain: null,
      }),
    });

    await run({ core, fetch });

    expect(core.setOutput).toHaveBeenCalledWith("cve_ids", "");
    expect(core.setFailed).not.toHaveBeenCalled();
  });

  it("errors on typosquat for unsupported product when fail_on is high", async () => {
    const fetch = vi.fn().mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({
        supported: false,
        typosquat: { detected: true, resembles: "langchain" },
      }),
    });

    await run({ core, fetch });

    expect(core.error).toHaveBeenCalledWith(
      expect.stringContaining("typosquat"),
      expect.objectContaining({ title: "Attestd typosquat warning" })
    );
    expect(core.setFailed).toHaveBeenCalled();
  });

  it("errors on typosquat for supported product when fail_on is high", async () => {
    const fetch = vi.fn().mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({
        supported: true,
        product: "langchian",
        version: "0.1.0",
        risk_state: "none",
        actively_exploited: false,
        fixed_version: null,
        cve_ids: [],
        typosquat: { detected: true, resembles: "langchain" },
      }),
    });

    await run({ core, fetch });

    expect(core.error).toHaveBeenCalledWith(
      expect.stringContaining("typosquat"),
      expect.objectContaining({ title: "Attestd typosquat warning" })
    );
    expect(core.setFailed).toHaveBeenCalled();
    expect(core.setOutput).toHaveBeenCalledWith("typosquat", "true");
  });

  it("succeeds after one transient 503 then 200", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce({ status: 503, ok: false })
      .mockResolvedValueOnce({
        status: 200,
        ok: true,
        json: async () => ({
          supported: true,
          risk_state: "none",
          actively_exploited: false,
          cve_ids: [],
          supply_chain: null,
        }),
      });

    await run({ core, fetch });

    expect(fetch).toHaveBeenCalledTimes(2);
    expect(core.setFailed).not.toHaveBeenCalled();
    expect(core.setOutput).toHaveBeenCalledWith("risk_state", "none");
  });

  it("does not retry on 429", async () => {
    const fetch = vi.fn().mockResolvedValue({
      status: 429,
      ok: false,
      headers: { get: () => null },
    });

    await run({ core, fetch });

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("Monthly call quota exceeded")
    );
  });

  it("does not retry on 401", async () => {
    const fetch = vi.fn().mockResolvedValue({
      status: 401,
      ok: false,
    });

    await run({ core, fetch });

    expect(fetch).toHaveBeenCalledTimes(1);
    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("invalid or revoked")
    );
  });
});
