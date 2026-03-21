const core = require("@actions/core");

// Risk state severity order — higher number = more severe
const RISK_ORDER = { none: 0, low: 1, elevated: 2, high: 3, critical: 4 };

const RISK_EMOJI = {
  none: "✅",
  low: "🟡",
  elevated: "🟠",
  high: "🔴",
  critical: "🚨",
};

// Maps the fail_on input to the lowest risk_state that triggers failure
const FAIL_ON_THRESHOLD = {
  critical: "critical",
  high: "high",
  elevated: "elevated",
  any: "low",
  never: null,
};

async function fetchWithRetry(url, options, maxRetries = 3) {
  let lastError;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (attempt > 0) {
      const delayMs = Math.pow(2, attempt - 1) * 1000; // 1s, 2s, 4s
      core.debug(`Retry ${attempt}/${maxRetries} after ${delayMs}ms...`);
      await new Promise((r) => setTimeout(r, delayMs));
    }
    try {
      const response = await fetch(url, options);
      // Only retry on transient server errors
      if (response.status < 500) return response;
      lastError = new Error(`HTTP ${response.status}`);
      core.debug(`Received ${response.status}, will retry if attempts remain.`);
    } catch (err) {
      lastError = err;
      core.debug(`Request failed: ${err.message}`);
    }
  }
  throw lastError;
}

function shouldFail(riskState, failOn) {
  const threshold = FAIL_ON_THRESHOLD[failOn];
  if (threshold === null) return false;
  if (threshold === undefined) {
    core.warning(
      `Unknown fail_on value: "${failOn}". Defaulting to "high".`
    );
    return RISK_ORDER[riskState] >= RISK_ORDER["high"];
  }
  return RISK_ORDER[riskState] >= RISK_ORDER[threshold];
}

async function run() {
  try {
    const apiKey = core.getInput("api_key", { required: true });
    const product = core.getInput("product", { required: true });
    const version = core.getInput("version", { required: true });
    const failOn = core.getInput("fail_on") || "high";
    const baseUrl =
      core.getInput("base_url") || "https://api.attestd.io";

    // Mask the key so it never appears in step logs
    core.setSecret(apiKey);

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
        3
      );
    } catch (err) {
      core.setFailed(
        `Could not reach the Attestd API: ${err.message}. Check your network or try again shortly.`
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

    // Unsupported product — warn and exit cleanly. This is not a workflow error.
    // The absence of coverage is not a safety signal.
    if (!data.supported) {
      core.warning(
        `${product} is not in Attestd's current coverage. ` +
          `No risk data is available — this does not mean the product is safe. ` +
          `See https://attestd.io/docs/products`
      );
      core.setOutput("supported", "false");
      core.setOutput("risk_state", "");
      core.setOutput("actively_exploited", "false");
      core.setOutput("fixed_version", "");
      core.setOutput("cve_ids", "");

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
      cve_ids = [],
    } = data;

    // Set step outputs for downstream steps
    core.setOutput("supported", "true");
    core.setOutput("risk_state", risk_state);
    core.setOutput("actively_exploited", String(actively_exploited));
    core.setOutput("fixed_version", fixed_version || "");
    core.setOutput("cve_ids", cve_ids.join(" "));

    // Write job summary
    const emoji = RISK_EMOJI[risk_state] || "❓";

    await core.summary
      .addHeading(`Attestd: ${product} ${version}`)
      .addTable([
        [
          { data: "Field", header: true },
          { data: "Value", header: true },
        ],
        ["Product", product],
        ["Version", version],
        ["Risk state", `${emoji} ${risk_state}`],
        ["Actively exploited", actively_exploited ? "⚠️ Yes (CISA KEV)" : "No"],
        ["CVEs", cve_ids.length > 0 ? cve_ids.join(", ") : "None"],
        ["Fix available", fixed_version || "None known"],
      ])
      .addLink(
        `View ${product} on Attestd docs`,
        `https://attestd.io/docs/products/${product}`
      )
      .write();

    // Determine pass/fail
    if (shouldFail(risk_state, failOn)) {
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
  } catch (err) {
    core.setFailed(`Unexpected error: ${err.message}`);
  }
}

run();
