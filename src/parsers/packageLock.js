/**
 * Parse package-lock.json v2/v3 packages map.
 *
 * Includes transitive deps. Skips root "", workspace-local (link:true or
 * keys that do not start with node_modules/), and entries without a version.
 */

/**
 * Extract the package name from a packages-map key.
 * "node_modules/lodash" → "lodash"
 * "node_modules/@scope/name" → "@scope/name"
 * "node_modules/a/node_modules/b" → "b"
 * "node_modules/a/node_modules/@scope/name" → "@scope/name"
 */
function packageNameFromKey(key) {
  const parts = key.split("node_modules/");
  const last = parts[parts.length - 1];
  return last;
}

/**
 * @param {string} jsonContent
 * @returns {{ items: Array<{product: string, version: string}>, skipped: Array<{line: number|null, raw: string, reason: string}> }}
 */
function parsePackageLock(jsonContent) {
  let data;
  try {
    data = JSON.parse(jsonContent);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Invalid package-lock.json: ${msg}`);
  }

  const lockfileVersion = Number(data.lockfileVersion);
  if (!Number.isFinite(lockfileVersion) || lockfileVersion < 2) {
    throw new Error(
      `Unsupported package-lock.json lockfileVersion ${data.lockfileVersion ?? "missing"}. ` +
        `Upgrade to npm lockfileVersion 2 or 3 (npm 7+).`
    );
  }

  const packages = data.packages;
  if (!packages || typeof packages !== "object" || Array.isArray(packages)) {
    throw new Error(
      "package-lock.json is missing a top-level packages map (lockfileVersion 2/3 required)."
    );
  }

  const items = [];
  const skipped = [];
  const seen = new Set();

  for (const [key, entry] of Object.entries(packages)) {
    if (key === "") {
      // Root package
      continue;
    }

    if (!key.startsWith("node_modules/")) {
      skipped.push({
        line: null,
        raw: key,
        reason: "workspace-local package skipped",
      });
      continue;
    }

    if (!entry || typeof entry !== "object") {
      skipped.push({
        line: null,
        raw: key,
        reason: "invalid packages entry",
      });
      continue;
    }

    if (entry.link === true) {
      skipped.push({
        line: null,
        raw: key,
        reason: "workspace-local link skipped",
      });
      continue;
    }

    const version = entry.version;
    if (!version || typeof version !== "string") {
      skipped.push({
        line: null,
        raw: key,
        reason: "missing version",
      });
      continue;
    }

    const product = packageNameFromKey(key);
    if (!product) {
      skipped.push({
        line: null,
        raw: key,
        reason: "could not derive package name",
      });
      continue;
    }

    const dedupeKey = `${product}@${version}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    items.push({ product, version });
  }

  return { items, skipped };
}

module.exports = { parsePackageLock, packageNameFromKey };
