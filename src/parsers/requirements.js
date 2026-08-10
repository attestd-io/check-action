/**
 * Parse a requirements.txt for pinned == lines only.
 *
 * Returns { items: [{product, version}], skipped: [{line, raw, reason}] }.
 * Ranges, editables, VCS URLs, and -r includes are skipped with reasons.
 */

function stripComment(line) {
  const hash = line.indexOf("#");
  if (hash === -1) return line;
  // Keep # inside quoted URLs; for requirements.txt comments dominate.
  return line.slice(0, hash);
}

function stripExtras(name) {
  // requests[security]==2.31.0 → requests
  const idx = name.indexOf("[");
  if (idx === -1) return name;
  return name.slice(0, idx);
}

/**
 * @param {string} content
 * @returns {{ items: Array<{product: string, version: string}>, skipped: Array<{line: number, raw: string, reason: string}> }}
 */
function parseRequirementsTxt(content) {
  const items = [];
  const skipped = [];
  const seen = new Set();
  const lines = String(content).split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    const raw = lines[i];
    let line = stripComment(raw).trim();
    if (!line) continue;

    // Options / includes
    if (line.startsWith("-r") || line.startsWith("--requirement")) {
      skipped.push({ line: lineNo, raw, reason: "include (-r) not supported" });
      continue;
    }
    if (
      line.startsWith("-e") ||
      line.startsWith("--editable") ||
      line.startsWith("editable+")
    ) {
      skipped.push({ line: lineNo, raw, reason: "editable install skipped" });
      continue;
    }
    if (
      /^(git\+|hg\+|svn\+|bzr\+)/i.test(line) ||
      /^https?:\/\//i.test(line) ||
      line.includes("@git+") ||
      line.includes("@https://") ||
      line.includes("@http://")
    ) {
      skipped.push({ line: lineNo, raw, reason: "VCS or URL requirement skipped" });
      continue;
    }
    if (line.startsWith("-") || line.startsWith("--")) {
      skipped.push({ line: lineNo, raw, reason: "pip option skipped" });
      continue;
    }

    // Exact pin: name==version (optional whitespace around ==)
    const pin = line.match(/^([A-Za-z0-9_.\-]+(?:\[[^\]]+\])?)\s*==\s*([^;\\\s]+)/);
    if (pin) {
      const product = stripExtras(pin[1]).toLowerCase();
      const version = pin[2].trim();
      if (!product || !version) {
        skipped.push({ line: lineNo, raw, reason: "empty name or version" });
        continue;
      }
      const key = `${product}@${version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      items.push({ product, version });
      continue;
    }

    // Range / compatible / inequality operators
    if (/[=<>!~]/.test(line)) {
      skipped.push({
        line: lineNo,
        raw,
        reason: "unpinned or ranged requirement (only == pins are checked)",
      });
      continue;
    }

    // Bare package name with no version
    skipped.push({
      line: lineNo,
      raw,
      reason: "unpinned requirement (no == version)",
    });
  }

  return { items, skipped };
}

module.exports = { parseRequirementsTxt, stripExtras };
