import { describe, expect, it, vi } from "vitest";
import { BATCH_SIZE, chunk, runBatch } from "../src/batch.js";
import {
  evaluateItem,
  highestRisk,
  runLockfileScan,
} from "../src/lockfile.js";

describe("chunk", () => {
  it("splits on 100-item boundaries", () => {
    const items = Array.from({ length: 250 }, (_, i) => ({
      product: `p${i}`,
      version: "1.0.0",
    }));
    const groups = chunk(items, BATCH_SIZE);
    expect(groups).toHaveLength(3);
    expect(groups[0]).toHaveLength(100);
    expect(groups[1]).toHaveLength(100);
    expect(groups[2]).toHaveLength(50);
  });

  it("handles exact multiples and empty", () => {
    expect(chunk([], 100)).toEqual([]);
    expect(chunk([{ product: "a", version: "1" }], 100)).toHaveLength(1);
    expect(
      chunk(
        Array.from({ length: 200 }, (_, i) => ({
          product: `p${i}`,
          version: "1",
        })),
        100
      )
    ).toHaveLength(2);
  });
});

describe("runBatch", () => {
  it("posts items and returns results", async () => {
    const fetch = vi.fn().mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({
        count: 1,
        results: [
          {
            product: "lodash",
            version: "4.17.21",
            result: {
              supported: true,
              risk_state: "none",
              supply_chain: { compromised: false },
            },
          },
        ],
      }),
    });
    const out = await runBatch([{ product: "lodash", version: "4.17.21" }], {
      apiKey: "atst_x",
      baseUrl: "https://api.attestd.io",
      fetchFn: fetch,
    });
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, opts] = fetch.mock.calls[0];
    expect(url).toContain("/v1/check/batch");
    expect(opts.method).toBe("POST");
    expect(out.results).toHaveLength(1);
  });

  it("does not retry on 429 and surfaces API detail", async () => {
    const fetch = vi.fn().mockResolvedValue({
      status: 429,
      ok: false,
      headers: { get: () => null },
      json: async () => ({
        detail:
          "Monthly call limit reached (1,000 calls for free tier). Upgrade your plan at attestd.io or enable overage billing in settings.",
      }),
    });
    await expect(
      runBatch([{ product: "a", version: "1" }], {
        apiKey: "atst_x",
        baseUrl: "https://api.attestd.io",
        fetchFn: fetch,
      })
    ).rejects.toMatchObject({
      code: "quota",
      message: expect.stringContaining("Monthly call limit reached"),
    });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("does not retry on 401", async () => {
    const fetch = vi.fn().mockResolvedValue({
      status: 401,
      ok: false,
      headers: { get: () => null },
      json: async () => ({}),
    });
    await expect(
      runBatch([{ product: "a", version: "1" }], {
        apiKey: "bad",
        baseUrl: "https://api.attestd.io",
        fetchFn: fetch,
      })
    ).rejects.toMatchObject({ code: "auth" });
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});

describe("evaluateItem / highestRisk", () => {
  it("flags compromise and high risk", () => {
    const compromised = evaluateItem(
      {
        product: "evil",
        version: "1.0.0",
        result: {
          supported: true,
          risk_state: "none",
          supply_chain: { compromised: true },
        },
      },
      { failOn: "high", failOnProvenanceMissing: false }
    );
    expect(compromised.failReasons).toContain("supply-chain compromise");
    expect(compromised.flagged).toBe(true);

    const high = evaluateItem(
      {
        product: "nginx",
        version: "1.0.0",
        result: {
          supported: true,
          risk_state: "high",
          fixed_version: "1.25.0",
          supply_chain: null,
        },
      },
      { failOn: "high", failOnProvenanceMissing: false }
    );
    expect(high.failReasons.some((r) => r.includes("risk_state"))).toBe(true);
  });

  it("treats unsupported as non-failing unless typosquat", () => {
    const u = evaluateItem(
      {
        product: "unknown-pkg",
        version: "1.0.0",
        result: { supported: false },
      },
      { failOn: "high", failOnProvenanceMissing: false }
    );
    expect(u.unsupported).toBe(true);
    expect(u.failReasons).toEqual([]);

    const typo = evaluateItem(
      {
        product: "lodahs",
        version: "1.0.0",
        result: {
          supported: false,
          typosquat: { detected: true, resembles: "lodash" },
        },
      },
      { failOn: "never", failOnProvenanceMissing: false }
    );
    expect(typo.failReasons[0]).toMatch(/typosquat/);
  });

  it("computes highest risk", () => {
    expect(highestRisk(["none", "elevated", "high"])).toBe("high");
    expect(highestRisk([])).toBe(null);
  });
});

describe("runLockfileScan aggregation", () => {
  function makeCore() {
    return {
      getInput: vi.fn(),
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
    };
  }

  it("aggregates mixed coverage and fails when any item trips", async () => {
    const core = makeCore();
    const written = {};
    const fetch = vi.fn().mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({
        count: 3,
        results: [
          {
            product: "lodash",
            version: "4.17.21",
            result: {
              supported: true,
              risk_state: "none",
              supply_chain: { compromised: false },
            },
          },
          {
            product: "unknown-pkg",
            version: "1.0.0",
            result: { supported: false },
          },
          {
            product: "evil",
            version: "1.0.0",
            result: {
              supported: true,
              risk_state: "none",
              supply_chain: { compromised: true },
            },
          },
        ],
      }),
    });

    await runLockfileScan({
      core,
      fetch,
      apiKey: "atst_x",
      baseUrl: "https://api.attestd.io",
      lockfilePath: "requirements.txt",
      failOn: "high",
      failOnProvenanceMissing: false,
      maxPackages: 2000,
      resultsFile: "out.json",
      readFile: () => "lodash==4.17.21\nunknown-pkg==1.0.0\nevil==1.0.0\n",
      writeFile: (p, data) => {
        written[p] = data;
      },
    });

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("failed Attestd checks")
    );
    expect(core.setOutput).toHaveBeenCalledWith("packages_scanned", "3");
    expect(core.setOutput).toHaveBeenCalledWith("packages_unsupported", "1");
    expect(written["out.json"]).toBeTruthy();
    const payload = JSON.parse(written["out.json"]);
    expect(payload.items).toHaveLength(3);
  });

  it("surfaces 429 mid-scan with billed count", async () => {
    const core = makeCore();
    const items = Array.from({ length: 150 }, (_, i) => `p${i}==1.0.0`).join(
      "\n"
    );
    let calls = 0;
    const fetch = vi.fn().mockImplementation(async () => {
      calls += 1;
      if (calls === 1) {
        return {
          status: 200,
          ok: true,
          json: async () => ({
            count: 100,
            results: Array.from({ length: 100 }, (_, i) => ({
              product: `p${i}`,
              version: "1.0.0",
              result: {
                supported: true,
                risk_state: "none",
                supply_chain: null,
              },
            })),
          }),
        };
      }
      return {
        status: 429,
        ok: false,
        headers: { get: () => null },
        json: async () => ({
          detail: "Monthly call limit reached (100 calls for free tier).",
        }),
      };
    });

    await runLockfileScan({
      core,
      fetch,
      apiKey: "atst_x",
      baseUrl: "https://api.attestd.io",
      lockfilePath: "requirements.txt",
      failOn: "high",
      maxPackages: 2000,
      resultsFile: "out.json",
      readFile: () => items,
      writeFile: () => {},
    });

    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringMatching(/100 of 150 packages already billed/)
    );
    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("Monthly call limit reached")
    );
  });

  it("honors fail_on never for aggregation", async () => {
    const core = makeCore();
    const fetch = vi.fn().mockResolvedValue({
      status: 200,
      ok: true,
      json: async () => ({
        count: 1,
        results: [
          {
            product: "evil",
            version: "1.0.0",
            result: {
              supported: true,
              risk_state: "critical",
              supply_chain: { compromised: true },
            },
          },
        ],
      }),
    });

    await runLockfileScan({
      core,
      fetch,
      apiKey: "atst_x",
      baseUrl: "https://api.attestd.io",
      lockfilePath: "requirements.txt",
      failOn: "never",
      maxPackages: 2000,
      resultsFile: "out.json",
      readFile: () => "evil==1.0.0\n",
      writeFile: () => {},
    });

    expect(core.setFailed).not.toHaveBeenCalled();
    expect(core.error).toHaveBeenCalled();
  });

  it("fails before API calls when max_packages exceeded", async () => {
    const core = makeCore();
    const fetch = vi.fn();
    await runLockfileScan({
      core,
      fetch,
      apiKey: "atst_x",
      baseUrl: "https://api.attestd.io",
      lockfilePath: "requirements.txt",
      failOn: "high",
      maxPackages: 2,
      resultsFile: "out.json",
      readFile: () => "a==1\nb==1\nc==1\n",
      writeFile: () => {},
    });
    expect(fetch).not.toHaveBeenCalled();
    expect(core.setFailed).toHaveBeenCalledWith(
      expect.stringContaining("max_packages=2")
    );
  });
});
