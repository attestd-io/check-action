/**
 * Parse pnpm-lock.yaml packages map (lockfileVersion 5.x, 6.x, 9.x).
 *
 * Includes transitives. Skips file/link/workspace locators. Peer-suffix keys
 * (`(peer@1.0.0)` or `_peer@1.0.0`) collapse to the base name@version.
 */

function stripQuotes(value) {
  const v = value.trim();
  if (
    (v.startsWith('"') && v.endsWith('"')) ||
    (v.startsWith("'") && v.endsWith("'"))
  ) {
    return v.slice(1, -1);
  }
  return v;
}

function parseLockfileVersion(content) {
  const match = content.match(/^\s*lockfileVersion:\s*['"]?([0-9.]+)['"]?/m);
  if (!match) {
    throw new Error("pnpm-lock.yaml is missing lockfileVersion.");
  }
  const raw = match[1];
  const major = Number(raw.split(".")[0]);
  if (![5, 6, 9].includes(major)) {
    throw new Error(
      `Unsupported pnpm-lock.yaml lockfileVersion ${raw}. Supported: 5.x, 6.x, 9.x.`
    );
  }
  return major;
}

/**
 * Top-level YAML map keys at indent 2 under `packages:`.
 */
function collectPackagesKeys(content) {
  const lines = content.split(/\r?\n/);
  const keys = [];
  let inPackages = false;

  for (const line of lines) {
    if (/^\s*$/.test(line) || /^\s*#/.test(line)) continue;
    const indent = line.match(/^ */)[0].length;
    const trimmed = line.trim();

    if (!inPackages) {
      if (indent === 0 && (trimmed === "packages:" || trimmed.startsWith("packages:"))) {
        inPackages = true;
      }
      continue;
    }

    if (indent === 0) break;
    if (indent !== 2) continue;

    const keyMatch = trimmed.match(/^('[^']+'|"[^"]+"|[^:]+)\s*:/);
    if (!keyMatch) continue;
    keys.push(stripQuotes(keyMatch[1]));
  }

  return keys;
}

/**
 * Turn a pnpm packages key into { product, version } or { skip }.
 */
function parsePnpmPackageKey(rawKey) {
  let key = stripQuotes(rawKey);
  if (!key) return { skip: "could not derive package name" };

  if (
    key.includes("://") ||
    key.includes("@file:") ||
    key.includes("@link:") ||
    key.includes("@workspace:")
  ) {
    return { skip: "non-registry locator skipped" };
  }

  if (key.startsWith("/")) key = key.slice(1);

  const paren = key.indexOf("(");
  if (paren !== -1) key = key.slice(0, paren);

  let nameEnd;
  if (key.startsWith("@")) {
    const slash = key.indexOf("/");
    if (slash === -1) return { skip: "could not derive package name" };
    nameEnd = slash + 1;
    while (nameEnd < key.length && key[nameEnd] !== "/" && key[nameEnd] !== "@") {
      nameEnd += 1;
    }
  } else {
    nameEnd = 0;
    while (nameEnd < key.length && key[nameEnd] !== "/" && key[nameEnd] !== "@") {
      nameEnd += 1;
    }
  }

  if (nameEnd <= 0 || nameEnd >= key.length) {
    return { skip: "could not derive package name" };
  }

  const product = key.slice(0, nameEnd);
  const sep = key[nameEnd];
  let versionPart = key.slice(nameEnd + 1);
  if (sep !== "@" && sep !== "/") {
    return { skip: "could not derive package name" };
  }
  if (versionPart.startsWith("npm:")) versionPart = versionPart.slice(4);
  const us = versionPart.indexOf("_");
  if (us !== -1) versionPart = versionPart.slice(0, us);

  if (!product || !versionPart || versionPart === "*" || versionPart === "latest") {
    return { skip: "missing version" };
  }

  return { product, version: versionPart };
}

function parsePnpmLock(content) {
  parseLockfileVersion(content);
  const keys = collectPackagesKeys(content);
  const items = [];
  const skipped = [];
  const seen = new Set();

  for (const key of keys) {
    const parsed = parsePnpmPackageKey(key);
    if (parsed.skip) {
      skipped.push({ line: null, raw: key, reason: parsed.skip });
      continue;
    }
    const dedupeKey = `${parsed.product}@${parsed.version}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    items.push({ product: parsed.product, version: parsed.version });
  }

  return { items, skipped };
}

module.exports = {
  parsePnpmLock,
  parsePnpmPackageKey,
  parseLockfileVersion,
};
