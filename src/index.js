const core = require("@actions/core");
const { VALID_RISK_STATES, shouldFail } = require("./lib");
const { fetchWithRetry } = require("./batch");
const { runLockfileScan } = require("./lockfile");

const RISK_EMOJI = {
  none: "✅",
  low: "🟡",
  elevated: "🟠",
  high: "🔴",
  critical: "🚨",
};

async function runSingleCheck({
  core,
  fetchFn,
  apiKey,
  product,
  version,
  failOn,
  failOnProvenanceMissing,
  baseUrl,
}) {
  const url = new URL("/v1/check", baseUrl);
  url.searchParams.set("product", product);
  url.searchParams.set("version", version);

  core.info(`Checking ${product} ${version}...`);

  let response;
  try {
    response = await fetchWithRetry(
      url.toString(),
      {
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "User-Agent": "attestd-check-action/1",
          Accept: "application/json",
        },
      },
      3,
      fetchFn,
      core
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    core.setFailed(
      `Could not reach the Attestd API: ${msg}. Check your network or try again shortly.`
    );
    return;
  }

  if (response.status === 401) {
    core.setFailed(
      "API key is invalid or revoked. Verify your ATTESTD_API_KEY secret at https://api.attestd.io/portal/login."
    );
    return;
  }

  if (response.status === 429) {
    const retryAfter = response.headers.get("Retry-After");
    core.setFailed(
      `Monthly call quota exceeded.${retryAfter ? ` Retry after ${retryAfter}s.` : ""}`
    );
    return;
  }

  if (!response.ok) {
    core.setFailed(`Attestd API returned an unexpected HTTP ${response.status}.`);
    return;
  }

  const data = await response.json();

  // Unsupported product — warn and exit cleanly unless typosquat detected.
  if (data.supported === false) {
    const typosquatDetected = data.typosquat?.detected === true;
    const resembles = data.typosquat?.resembles || "";

    core.setOutput("supported", "false");
    core.setOutput("risk_state", "");
    core.setOutput("actively_exploited", "false");
    core.setOutput("fixed_version", "");
    core.setOutput("cve_ids", "");
    core.setOutput("compromised", "false");
    core.setOutput("provenance", "");
    core.setOutput("typosquat", typosquatDetected ? "true" : "false");
    clearLockfileOutputs(core);

    if (typosquatDetected) {
      const typoMsg =
        `Package name "${product}" resembles "${resembles}" (possible typosquat). ` +
        `Verify you intended this package name.`;
      core.error(typoMsg, { title: "Attestd typosquat warning" });
      if (failOn !== "never") {
        core.setFailed(typoMsg);
        return;
      }
    }

    core.warning(
      `${product} is not in Attestd's current coverage. ` +
        `No risk data is available — this does not mean the product is safe. ` +
        `See https://attestd.io/docs/products`
    );

    await core.summary
      .addHeading(`Attestd: ${product} ${version}`)
      .addRaw(
        `**Not covered** — ${product} is not in Attestd's current coverage. ` +
          `[Request coverage](https://attestd.io/docs/products)`
      )
      .write();
    return;
  }

  const {
    risk_state,
    actively_exploited,
    fixed_version,
    product: apiProduct,
  } = data;
  const cveIds = Array.isArray(data.cve_ids) ? data.cve_ids : [];
  const compromised = data.supply_chain?.compromised === true;
  const provenanceRaw = data.supply_chain?.provenance;
  const provenanceMissing = provenanceRaw === false;
  const provenanceOut =
    provenanceRaw === true ? "true" : provenanceRaw === false ? "false" : "";
  const typosquatDetected = data.typosquat?.detected === true;
  const resembles = data.typosquat?.resembles || "";
  const docsSlug = apiProduct || product;

  core.setOutput("supported", "true");
  core.setOutput("risk_state", risk_state || "");
  core.setOutput("actively_exploited", String(Boolean(actively_exploited)));
  core.setOutput("fixed_version", fixed_version || "");
  core.setOutput("cve_ids", cveIds.join(" "));
  core.setOutput("compromised", String(compromised));
  core.setOutput("provenance", provenanceOut);
  core.setOutput("typosquat", typosquatDetected ? "true" : "false");
  clearLockfileOutputs(core);

  if (!VALID_RISK_STATES.has(risk_state)) {
    core.setFailed(
      `Attestd returned an unrecognized risk_state "${risk_state ?? "missing"}". Failing closed.`
    );
    return;
  }

  if (typosquatDetected) {
    const typoMsg =
      `Package name "${product}" resembles "${resembles}" (possible typosquat). ` +
      `Verify you intended this package name.`;
    core.error(typoMsg, { title: "Attestd typosquat warning" });
    if (failOn !== "never") {
      core.setFailed(typoMsg);
      return;
    }
  }

  const emoji = RISK_EMOJI[risk_state] || "❓";
  const supplyChain = data.supply_chain || {};
  const summaryRows = [
    [
      { data: "Field", header: true },
      { data: "Value", header: true },
    ],
    ["Product", product],
    ["Version", version],
    ["Risk state", `${emoji} ${risk_state}`],
    ["Actively exploited", actively_exploited ? "⚠️ Yes (CISA KEV)" : "No"],
    ["CVEs", cveIds.length > 0 ? cveIds.join(", ") : "None"],
    ["Fix available", fixed_version || "None known"],
  ];

  if (supplyChain.compromised) {
    summaryRows.push([
      "Supply chain",
      [
        "⚠️ Compromised",
        supplyChain.malware_type ? `(${supplyChain.malware_type})` : "",
        supplyChain.advisory_url ? `[advisory](${supplyChain.advisory_url})` : "",
      ]
        .filter(Boolean)
        .join(" "),
    ]);
  }

  if (provenanceRaw === true) {
    summaryRows.push(["Provenance", "✅ Attested"]);
  } else if (provenanceMissing) {
    summaryRows.push([
      "Provenance",
      "⚠️ Missing (package publishes provenance, this version does not)",
    ]);
  }

  await core.summary
    .addHeading(`Attestd: ${product} ${version}`)
    .addTable(summaryRows)
    .addLink(
      `View ${docsSlug} on Attestd docs`,
      `https://attestd.io/docs/products/${docsSlug}`
    )
    .write();

  if (compromised) {
    const scMsg =
      `${product} ${version} is flagged as a supply-chain compromise` +
      (supplyChain.malware_type ? ` (${supplyChain.malware_type})` : "") +
      (supplyChain.advisory_url ? `. Advisory: ${supplyChain.advisory_url}` : ".");
    if (failOn === "never") {
      core.error(scMsg, { title: "Attestd supply chain compromise" });
    } else {
      core.setFailed(scMsg);
    }
    return;
  }

  if (provenanceMissing && failOnProvenanceMissing) {
    const provMsg =
      `${product} ${version} is missing npm provenance attestation ` +
      `(package has a provenance baseline). This can indicate a compromised publish.`;
    if (failOn === "never") {
      core.error(provMsg, { title: "Attestd provenance missing" });
    } else {
      core.setFailed(provMsg);
    }
    return;
  }

  if (shouldFail(risk_state, failOn, core)) {
    let message = `${product} ${version} has risk state "${risk_state}"`;
    if (actively_exploited) {
      message += " and is actively exploited in the wild (CISA KEV)";
    }
    if (fixed_version) {
      message += `. Upgrade to ${fixed_version} to resolve.`;
    } else {
      message += ". No fix is currently available.";
    }
    core.setFailed(message);
  } else {
    core.info(`${emoji} ${product} ${version}: ${risk_state}`);
    if (actively_exploited) {
      core.warning(
        `${product} ${version} is actively exploited (CISA KEV) but is below the configured fail_on threshold ("${failOn}").`
      );
    }
  }
}

function clearLockfileOutputs(core) {
  core.setOutput("packages_scanned", "");
  core.setOutput("packages_flagged", "");
  core.setOutput("packages_unsupported", "");
  core.setOutput("highest_risk_state", "");
  core.setOutput("results_path", "");
}

async function run(deps = {}) {
  const core = deps.core || require("@actions/core");
  const fetchFn = deps.fetch || fetch;
  try {
    const apiKey = core.getInput("api_key", { required: true });
    const product = (core.getInput("product") || "").trim();
    const version = (core.getInput("version") || "").trim();
    const lockfile = (core.getInput("lockfile") || "").trim();
    const failOn = core.getInput("fail_on") || "high";
    const failOnProvenanceMissing =
      (core.getInput("fail_on_provenance_missing") || "false").toLowerCase() ===
      "true";
    const baseUrl = core.getInput("base_url") || "https://api.attestd.io";
    const maxPackagesRaw = (core.getInput("max_packages") || "2000").trim();
    const maxPackages = Number(maxPackagesRaw);
    const resultsFile =
      (core.getInput("results_file") || "attestd-scan-results.json").trim() ||
      "attestd-scan-results.json";

    core.setSecret(apiKey);

    const parsedBase = new URL(baseUrl);
    if (parsedBase.hostname !== "api.attestd.io") {
      core.warning(
        `Non-standard base_url hostname: "${parsedBase.hostname}". ` +
          `Your API key will be sent to this host. Verify this is intentional.`
      );
    }

    const hasLockfile = Boolean(lockfile);
    const hasProductVersion = Boolean(product || version);

    if (hasLockfile && hasProductVersion) {
      core.setFailed(
        "Provide either lockfile, or product and version, not both."
      );
      return;
    }

    if (!hasLockfile && (!product || !version)) {
      core.setFailed(
        "Provide product and version for a single check, or lockfile for a lockfile scan."
      );
      return;
    }

    if (hasLockfile) {
      if (!Number.isFinite(maxPackages) || maxPackages < 1) {
        core.setFailed(`Invalid max_packages value: "${maxPackagesRaw}"`);
        return;
      }
      await runLockfileScan({
        core,
        fetch: fetchFn,
        apiKey,
        baseUrl,
        lockfilePath: lockfile,
        failOn,
        failOnProvenanceMissing,
        maxPackages,
        resultsFile,
      });
      return;
    }

    await runSingleCheck({
      core,
      fetchFn,
      apiKey,
      product,
      version,
      failOn,
      failOnProvenanceMissing,
      baseUrl,
    });
  } catch (err) {
    core.setFailed(`Unexpected error: ${err.message}`);
  }
}

module.exports = { run, fetchWithRetry, runSingleCheck };

if (require.main === module) {
  run();
}
