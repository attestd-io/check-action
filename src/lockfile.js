/**
 * Lockfile scan orchestration: parse → chunk → batch → aggregate → summary.
 */

const fs = require("fs");
const path = require("path");
const { VALID_RISK_STATES, shouldFail, RISK_ORDER } = require("./lib");
const { parseRequirementsTxt } = require("./parsers/requirements");
const { parsePackageLock } = require("./parsers/packageLock");
const { BATCH_SIZE, chunk, runBatch } = require("./batch");

const RISK_EMOJI = {
  none: "✅",
  low: "🟡",
  elevated: "🟠",
  high: "🔴",
  critical: "🚨",
};

function detectParser(lockfilePath) {
  const base = path.basename(lockfilePath).toLowerCase();
  if (base === "requirements.txt" || base.endsWith("-requirements.txt")) {
    return "requirements";
  }
  if (base === "package-lock.json") {
    return "package-lock";
  }
  // Allow names like requirements-dev.txt
  if (base.startsWith("requirements") && base.endsWith(".txt")) {
    return "requirements";
  }
  return null;
}

function parseLockfile(lockfilePath, content) {
  const kind = detectParser(lockfilePath);
  if (!kind) {
    throw new Error(
      `Unsupported lockfile "${path.basename(lockfilePath)}". ` +
        `Supported: requirements.txt, package-lock.json (v2/v3).`
    );
  }
  if (kind === "requirements") {
    return { kind, ...parseRequirementsTxt(content) };
  }
  return { kind, ...parsePackageLock(content) };
}

/**
 * Evaluate one batch result item against fail gates.
 * Returns { flagged, failReasons, unsupported, error, summaryRow? }
 */
function evaluateItem(entry, { failOn, failOnProvenanceMissing }) {
  const product = entry.product;
  const version = entry.version;

  if (entry.error) {
    return {
      product,
      version,
      unsupported: false,
      error: entry.error,
      flagged: false,
      failReasons: [],
      risk_state: null,
      fixed_version: null,
      compromised: false,
    };
  }

  const data = entry.result;
  if (!data || data.supported === false) {
    const typosquatDetected = data?.typosquat?.detected === true;
    const resembles = data?.typosquat?.resembles || "";
  const failReasons = [];
    if (typosquatDetected) {
      failReasons.push(
        `typosquat: "${product}" resembles "${resembles}"`
      );
    }
    return {
      product,
      version,
      unsupported: true,
      error: null,
      flagged: failReasons.length > 0,
      failReasons,
      risk_state: null,
      fixed_version: null,
      compromised: false,
      typosquat: typosquatDetected,
    };
  }

  const risk_state = data.risk_state;
  const fixed_version = data.fixed_version || null;
  const compromised = data.supply_chain?.compromised === true;
  const provenanceRaw = data.supply_chain?.provenance;
  const provenanceMissing = provenanceRaw === false;
  const typosquatDetected = data.typosquat?.detected === true;
  const resembles = data.typosquat?.resembles || "";
  const failReasons = [];

  if (!VALID_RISK_STATES.has(risk_state)) {
    failReasons.push(`unrecognized risk_state "${risk_state ?? "missing"}"`);
  }

  if (typosquatDetected) {
    failReasons.push(`typosquat: "${product}" resembles "${resembles}"`);
  }

  if (compromised) {
    failReasons.push("supply-chain compromise");
  }

  if (provenanceMissing && failOnProvenanceMissing) {
    failReasons.push("missing npm provenance attestation");
  }

  // Risk threshold: when fail_on is never, still record high/critical for the
  // summary table, but use shouldFail for actual gate trips when fail_on is set.
  if (VALID_RISK_STATES.has(risk_state)) {
    if (failOn === "never") {
      if (RISK_ORDER[risk_state] >= RISK_ORDER.high) {
        failReasons.push(`risk_state ${risk_state}`);
      }
    } else if (shouldFail(risk_state, failOn, null)) {
      failReasons.push(`risk_state ${risk_state}`);
    }
  }

  return {
    product,
    version,
    unsupported: false,
    error: null,
    flagged:
      failReasons.length > 0 ||
      compromised ||
      (VALID_RISK_STATES.has(risk_state) &&
        RISK_ORDER[risk_state] >= RISK_ORDER.high),
    failReasons,
    risk_state,
    fixed_version,
    compromised,
    actively_exploited: Boolean(data.actively_exploited),
    provenance:
      provenanceRaw === true ? true : provenanceRaw === false ? false : null,
    typosquat: typosquatDetected,
  };
}

function highestRisk(states) {
  let best = null;
  let bestScore = -1;
  for (const s of states) {
    if (!VALID_RISK_STATES.has(s)) continue;
    const score = RISK_ORDER[s];
    if (score > bestScore) {
      bestScore = score;
      best = s;
    }
  }
  return best;
}

async function runLockfileScan(deps = {}) {
  const core = deps.core || require("@actions/core");
  const fetchFn = deps.fetch || fetch;
  const readFile = deps.readFile || ((p) => fs.readFileSync(p, "utf8"));
  const writeFile =
    deps.writeFile || ((p, data) => fs.writeFileSync(p, data, "utf8"));

  const apiKey = deps.apiKey;
  const baseUrl = deps.baseUrl;
  const lockfilePath = deps.lockfilePath;
  const failOn = deps.failOn || "high";
  const failOnProvenanceMissing = Boolean(deps.failOnProvenanceMissing);
  const maxPackages = Number(deps.maxPackages) || 2000;
  const resultsFile = deps.resultsFile || "attestd-scan-results.json";

  // Clear single-mode outputs in lockfile mode
  for (const key of [
    "risk_state",
    "actively_exploited",
    "fixed_version",
    "cve_ids",
    "supported",
    "compromised",
    "provenance",
    "typosquat",
  ]) {
    core.setOutput(key, "");
  }

  let content;
  try {
    content = readFile(lockfilePath);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    core.setFailed(`Could not read lockfile "${lockfilePath}": ${msg}`);
    return { ok: false };
  }

  let parsed;
  try {
    parsed = parseLockfile(lockfilePath, content);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    core.setFailed(msg);
    return { ok: false };
  }

  for (const s of parsed.skipped) {
    const where = s.line != null ? `line ${s.line}` : s.raw;
    core.warning(`Skipped ${where}: ${s.reason}`);
  }

  const items = parsed.items;
  core.info(
    `Parsed ${items.length} pinned package(s) from ${path.basename(lockfilePath)} ` +
      `(${parsed.skipped.length} skipped).`
  );

  if (items.length === 0) {
    core.warning("No pinned packages found to check.");
    core.setOutput("packages_scanned", "0");
    core.setOutput("packages_flagged", "0");
    core.setOutput("packages_unsupported", "0");
    core.setOutput("highest_risk_state", "");
    core.setOutput("results_path", "");
    await core.summary
      .addHeading("Attestd lockfile scan")
      .addRaw("No pinned packages found to check.")
      .write();
    return { ok: true, packages_scanned: 0 };
  }

  if (items.length > maxPackages) {
    core.setFailed(
      `Lockfile has ${items.length} packages, which exceeds max_packages=${maxPackages}. ` +
        `Raise max_packages intentionally, or split the scan. No API calls were made.`
    );
    return { ok: false };
  }

  const chunks = chunk(items, BATCH_SIZE);
  const evaluated = [];
  let billed = 0;

  for (let i = 0; i < chunks.length; i++) {
    const group = chunks[i];
    core.info(
      `Checking batch ${i + 1}/${chunks.length} (${group.length} package(s))...`
    );
    try {
      const { results } = await runBatch(group, {
        apiKey,
        baseUrl,
        fetchFn,
        log: core,
      });
      billed += group.length;
      // Align results to request order; API returns same order.
      for (let j = 0; j < group.length; j++) {
        const entry = results[j] || {
          product: group[j].product,
          version: group[j].version,
          error: "missing result for item",
        };
        evaluated.push(
          evaluateItem(entry, { failOn, failOnProvenanceMissing })
        );
      }
    } catch (err) {
      const code = err.code || "http";
      if (code === "quota") {
        core.setFailed(
          `Quota exceeded mid-scan: ${billed} of ${items.length} packages already billed; ` +
            `batch ${i + 1}/${chunks.length} (${group.length} packages) was rejected before billing. ` +
            `${err.message}`
        );
        return { ok: false, billed, total: items.length };
      }
      if (code === "auth") {
        core.setFailed(err.message);
        return { ok: false };
      }
      core.setFailed(
        `Scan stopped after ${billed} of ${items.length} packages billed. ${err.message}`
      );
      return { ok: false, billed, total: items.length };
    }
  }

  const unsupported = evaluated.filter((e) => e.unsupported);
  const errors = evaluated.filter((e) => e.error);
  const failing = evaluated.filter((e) => e.failReasons.length > 0);
  // Flagged table: anything that trips failReasons, or compromise, or high+
  const flaggedForTable = evaluated.filter(
    (e) =>
      e.failReasons.length > 0 ||
      e.compromised ||
      (e.risk_state && RISK_ORDER[e.risk_state] >= RISK_ORDER.high)
  );
  const riskStates = evaluated
    .map((e) => e.risk_state)
    .filter(Boolean);
  const highest = highestRisk(riskStates) || "";

  for (const e of unsupported) {
    if (!e.typosquat) {
      core.warning(
        `${e.product}@${e.version} is not in Attestd coverage (not a safety signal).`
      );
    }
  }
  for (const e of errors) {
    core.warning(
      `${e.product}@${e.version}: API item error — ${e.error}`
    );
  }

  const summaryPayload = {
    lockfile: lockfilePath,
    kind: parsed.kind,
    scanned: evaluated.length,
    flagged: flaggedForTable.length,
    unsupported: unsupported.length,
    errors: errors.length,
    skipped: parsed.skipped.length,
    highest_risk_state: highest,
    fail_on: failOn,
    items: evaluated.map((e) => ({
      product: e.product,
      version: e.version,
      risk_state: e.risk_state,
      fixed_version: e.fixed_version,
      compromised: e.compromised,
      unsupported: e.unsupported,
      error: e.error,
      fail_reasons: e.failReasons,
    })),
    skipped_lines: parsed.skipped,
  };

  try {
    writeFile(resultsFile, JSON.stringify(summaryPayload, null, 2));
    core.info(`Wrote results to ${resultsFile}`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    core.warning(`Could not write results file: ${msg}`);
  }

  core.setOutput("packages_scanned", String(evaluated.length));
  core.setOutput("packages_flagged", String(flaggedForTable.length));
  core.setOutput("packages_unsupported", String(unsupported.length));
  core.setOutput("highest_risk_state", highest);
  core.setOutput("results_path", resultsFile);

  const tableRows = [
    [
      { data: "Package", header: true },
      { data: "Version", header: true },
      { data: "Risk", header: true },
      { data: "Fixed version", header: true },
      { data: "Compromised", header: true },
    ],
  ];
  for (const e of flaggedForTable) {
    const emoji = e.risk_state ? RISK_EMOJI[e.risk_state] || "" : "";
    tableRows.push([
      e.product,
      e.version,
      e.risk_state ? `${emoji} ${e.risk_state}` : e.unsupported ? "unsupported" : "—",
      e.fixed_version || "—",
      e.compromised ? "yes" : "no",
    ]);
  }

  const summary = core.summary
    .addHeading("Attestd lockfile scan")
    .addRaw(
      `Scanned **${evaluated.length}** packages from \`${path.basename(lockfilePath)}\`. ` +
        `Flagged **${flaggedForTable.length}**. Unsupported **${unsupported.length}**. ` +
        (highest ? `Highest risk: **${highest}**.` : "No risk states returned.")
    );
  if (flaggedForTable.length > 0) {
    summary.addHeading("Flagged packages", 3).addTable(tableRows);
  } else {
    summary.addRaw("\n\nNo packages met the flagging threshold.");
  }
  await summary
    .addLink("Attestd docs", "https://attestd.io/docs/integrations/github-action")
    .write();

  if (failing.length > 0) {
    const preview = failing
      .slice(0, 5)
      .map((e) => `${e.product}@${e.version} (${e.failReasons.join(", ")})`)
      .join("; ");
    const more =
      failing.length > 5 ? ` (+${failing.length - 5} more)` : "";
    if (failOn === "never") {
      core.error(
        `${failing.length} package(s) would fail under the configured gates: ${preview}${more}`,
        { title: "Attestd lockfile findings" }
      );
    } else {
      core.setFailed(
        `${failing.length} package(s) failed Attestd checks: ${preview}${more}`
      );
      return { ok: false, failing: failing.length };
    }
  } else {
    core.info(
      `Lockfile scan complete: ${evaluated.length} checked, ${flaggedForTable.length} flagged.`
    );
  }

  return {
    ok: true,
    packages_scanned: evaluated.length,
    packages_flagged: flaggedForTable.length,
    packages_unsupported: unsupported.length,
    highest_risk_state: highest,
    results_path: resultsFile,
  };
}

module.exports = {
  detectParser,
  parseLockfile,
  evaluateItem,
  highestRisk,
  runLockfileScan,
};
