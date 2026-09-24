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

  it("sets provenance output and fails when fail_on_provenance_missing", async () => {
    core = makeCore({
      inputs: {
        fail_on_provenance_missing: "true",
      },
    });
    const fetch = vi.fn().mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({
        supported: true,
        product: "@mastra/core",
        version: "0.10.0",
        risk_state: "none",
        actively_exploited: false,
        fixed_version: null,
        cve_ids: [],
        supply_chain: {
          compromised: false,
          provenance: false,
        },
      }),
    });

    await run({ core, fetch });

    expect(core.setOutput).toHaveBeenCalledWith("provenance", "false");
    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("missing npm provenance")
    );
  });

  it("does not fail on provenance false when fail_on_provenance_missing is off", async () => {
    const fetch = vi.fn().mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({
        supported: true,
        product: "@mastra/core",
        version: "0.10.0",
        risk_state: "none",
        actively_exploited: false,
        fixed_version: null,
        cve_ids: [],
        supply_chain: {
          compromised: false,
          provenance: false,
        },
      }),
    });

    await run({ core, fetch });

    expect(core.setOutput).toHaveBeenCalledWith("provenance", "false");
    expect(core.setFailed).not.toHaveBeenCalled();
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

  it("fails when lockfile is combined with product/version", async () => {
    core = makeCore({
      inputs: { lockfile: "requirements.txt" },
    });
    await run({ core, fetch: vi.fn() });
    expect(core.setFailed).toHaveBeenCalledWith(
      "Provide either lockfile, or product and version, not both."
    );
  });

  it("fails when neither lockfile nor product/version is provided", async () => {
    core = makeCore({
      inputs: { product: "", version: "" },
    });
    await run({ core, fetch: vi.fn() });
    expect(core.setFailed).toHaveBeenCalledWith(
      "Provide product and version for a single check, or lockfile for a lockfile scan."
    );
  });

  it("fails on invalid max_packages in lockfile mode", async () => {
    core = makeCore({
      inputs: {
        product: "",
        version: "",
        lockfile: "requirements.txt",
        max_packages: "nope",
      },
    });
    await run({ core, fetch: vi.fn() });
    expect(core.setFailed).toHaveBeenCalledWith(
      'Invalid max_packages value: "nope"'
    );
  });

  it("fails when the lockfile path cannot be read", async () => {
    core = makeCore({
      inputs: {
        product: "",
        version: "",
        lockfile: "missing-attestd-lockfile-xyz.txt",
      },
    });
    await run({ core, fetch: vi.fn() });
    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining('Could not read lockfile "missing-attestd-lockfile-xyz.txt"')
    );
  });

  it("fails when the lockfile basename is unsupported", async () => {
    core = makeCore({
      inputs: {
        product: "",
        version: "",
        lockfile: "package.json",
      },
    });
    await run({ core, fetch: vi.fn() });
    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("Unsupported lockfile")
    );
  });

  it("evaluates risk when supported is omitted from a legacy payload", async () => {
    const fetch = vi.fn().mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({
        product: "nginx",
        version: "1.20.0",
        risk_state: "high",
        actively_exploited: false,
        fixed_version: "1.21.0",
        cve_ids: ["CVE-2021-23017"],
      }),
    });
    core = makeCore({
      inputs: { product: "nginx", version: "1.20.0" },
    });
    await run({ core, fetch });
    expect(core.setOutput).toHaveBeenCalledWith("supported", "true");
    expect(core.setFailed).toHaveBeenCalled();
  });
});
