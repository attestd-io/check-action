/**
 * Parse yarn.lock (classic v1 and Berry).
 *
 * Uses the resolved `version` field, not the range in the descriptor.
 * Includes transitives. Skips workspace/file/link/portal/patch locators.
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

/**
 * Split a yarn entry key into descriptors.
 * `"@scope/pkg@^1.0.0", "@scope/pkg@^1.1.0"` or `lodash@^4.17.20, lodash@^4.17.21`.
 */
function splitDescriptors(rawKey) {
  const parts = [];
  let current = "";
  let quote = null;
  for (const ch of rawKey) {
    if (!quote && (ch === '"' || ch === "'")) {
      quote = ch;
      continue;
    }
    if (quote && ch === quote) {
      quote = null;
      continue;
    }
    if (!quote && ch === ",") {
      if (current.trim()) parts.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.trim()) parts.push(current.trim());
  return parts;
}

/**
 * Package name from a yarn descriptor (`lodash@^4.17.21`, `@scope/pkg@npm:^1.0.0`).
 */
function nameFromDescriptor(descriptor) {
  const d = stripQuotes(descriptor);
  if (d.startsWith("@")) {
    const secondAt = d.indexOf("@", 1);
    if (secondAt === -1) return d;
    return d.slice(0, secondAt);
  }
  const at = d.indexOf("@");
  if (at <= 0) return d;
  return d.slice(0, at);
}

/**
 * Protocol in the locator after the name (`npm`, `file`, `workspace`, …).
 * Classic ranges such as `^4.17.21` have no protocol.
 */
function protocolFromDescriptor(descriptor) {
  const d = stripQuotes(descriptor);
  const at = d.startsWith("@") ? d.indexOf("@", 1) : d.indexOf("@");
  if (at <= 0) return null;
  const rest = d.slice(at + 1);
  const colon = rest.indexOf(":");
  if (colon <= 0) return null;
  const proto = rest.slice(0, colon);
  if (!/^[A-Za-z][A-Za-z0-9+.-]*$/.test(proto)) return null;
  return proto.toLowerCase();
}

function isNonRegistryDescriptor(descriptor) {
  const proto = protocolFromDescriptor(descriptor);
  if (!proto) return false;
  return proto !== "npm" && proto !== "registry";
}

function isEntryStart(line) {
  if (!line || line.startsWith("#") || line.startsWith(" ") || line.startsWith("\t")) {
    return false;
  }
  return line.trimEnd().endsWith(":");
}

function parseYarnLock(content) {
  const berry = /(^|\n)__metadata\s*:/.test(content);
  const lines = content.split(/\r?\n/);
  const items = [];
  const skipped = [];
  const seen = new Set();

  let keyLines = [];
  let version = null;
  let skippingMeta = false;

  const versionRe = berry
    ? /^\s+version:\s+["']?([^"'\s]+)["']?/
    : /^\s+version\s+"([^"]+)"/;

  function flush() {
    if (keyLines.length === 0) return;
    const rawKey = keyLines.join(" ").replace(/:\s*$/, "").trim();
    const descriptors = splitDescriptors(rawKey);
    keyLines = [];
    const resolvedVersion = version;
    version = null;

    if (descriptors.length === 0) return;

    if (descriptors.some(isNonRegistryDescriptor)) {
      skipped.push({
        line: null,
        raw: rawKey,
        reason: "non-registry locator skipped",
      });
      return;
    }

    if (!resolvedVersion) {
      skipped.push({
        line: null,
        raw: rawKey,
        reason: "missing version",
      });
      return;
    }

    const product = nameFromDescriptor(descriptors[0]);
    if (!product) {
      skipped.push({
        line: null,
        raw: rawKey,
        reason: "could not derive package name",
      });
      return;
    }

    const dedupeKey = `${product}@${resolvedVersion}`;
    if (seen.has(dedupeKey)) return;
    seen.add(dedupeKey);
    items.push({ product, version: resolvedVersion });
  }

  for (const line of lines) {
    if (isEntryStart(line)) {
      flush();
      if (line.startsWith("__metadata:")) {
        skippingMeta = true;
        keyLines = [];
        version = null;
        continue;
      }
      skippingMeta = false;
      keyLines = [line.trim()];
      continue;
    }
    if (skippingMeta) continue;
    if (keyLines.length === 0) continue;
    const match = line.match(versionRe);
    if (match) version = match[1];
  }
  flush();

  return { items, skipped };
}

module.exports = {
  parseYarnLock,
  nameFromDescriptor,
  splitDescriptors,
  protocolFromDescriptor,
};
