/**
 * Chunk helpers and POST /v1/check/batch client.
 */

const BATCH_SIZE = 100;
const USER_AGENT = "attestd-check-action/1";

function chunk(items, size = BATCH_SIZE) {
  if (!Array.isArray(items)) return [];
  const n = Math.max(1, Number(size) || BATCH_SIZE);
  const out = [];
  for (let i = 0; i < items.length; i += n) {
    out.push(items.slice(i, i + n));
  }
  return out;
}

async function fetchWithRetry(url, options, maxRetries = 3, fetchFn = fetch, log) {
  let lastError;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    if (attempt > 0) {
      const delayMs = Math.pow(2, attempt - 1) * 1000;
      if (log?.debug) log.debug(`Retry ${attempt}/${maxRetries} after ${delayMs}ms...`);
      await new Promise((r) => setTimeout(r, delayMs));
    }
    try {
      const response = await fetchFn(url, {
        ...options,
        // Batch of up to 100 sequential lookups routinely exceeds 30s.
        signal: AbortSignal.timeout(120_000),
      });
      if (response.status < 500) return response;
      lastError = new Error(`HTTP ${response.status}`);
      if (log?.debug) {
        log.debug(`Received ${response.status}, will retry if attempts remain.`);
      }
    } catch (err) {
      lastError = err;
      if (log?.debug) {
        log.debug(`Request failed: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  }
  throw lastError;
}

async function readErrorDetail(response) {
  try {
    const body = await response.json();
    if (typeof body?.detail === "string") return body.detail;
    if (Array.isArray(body?.detail)) {
      return body.detail
        .map((d) => (typeof d === "string" ? d : d?.msg || JSON.stringify(d)))
        .join("; ");
    }
    if (typeof body?.message === "string") return body.message;
  } catch {
    // ignore parse errors
  }
  return null;
}

/**
 * POST one batch chunk. Does not retry 401/429.
 *
 * @returns {Promise<{ results: Array, count: number }>}
 * @throws {{ code: 'quota'|'auth'|'http'|'network', message: string, status?: number, detail?: string }}
 */
async function runBatch(items, { apiKey, baseUrl, fetchFn = fetch, log } = {}) {
  const url = new URL("/v1/check/batch", baseUrl).toString();
  let response;
  try {
    response = await fetchWithRetry(
      url,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "User-Agent": USER_AGENT,
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ items }),
      },
      3,
      fetchFn,
      log
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const error = new Error(
      `Could not reach the Attestd API: ${msg}. Check your network or try again shortly.`
    );
    error.code = "network";
    throw error;
  }

  if (response.status === 401) {
    const error = new Error(
      "API key is invalid or revoked. Verify your ATTESTD_API_KEY secret at https://api.attestd.io/portal/login."
    );
    error.code = "auth";
    error.status = 401;
    throw error;
  }

  if (response.status === 429) {
    const detail = await readErrorDetail(response);
    const retryAfter = response.headers.get("Retry-After");
    const parts = [
      "Monthly call quota exceeded before this batch was billed.",
      detail,
      retryAfter ? `Retry after ${retryAfter}s.` : null,
    ].filter(Boolean);
    const error = new Error(parts.join(" "));
    error.code = "quota";
    error.status = 429;
    error.detail = detail;
    throw error;
  }

  if (!response.ok) {
    const detail = await readErrorDetail(response);
    const error = new Error(
      detail
        ? `Attestd API returned HTTP ${response.status}: ${detail}`
        : `Attestd API returned an unexpected HTTP ${response.status}.`
    );
    error.code = "http";
    error.status = response.status;
    error.detail = detail;
    throw error;
  }

  const data = await response.json();
  return {
    results: Array.isArray(data.results) ? data.results : [],
    count: Number(data.count) || 0,
  };
}

module.exports = {
  BATCH_SIZE,
  chunk,
  fetchWithRetry,
  runBatch,
  readErrorDetail,
};
