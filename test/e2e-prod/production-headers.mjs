/** Parse the subset of Cloudflare Pages' public/_headers syntax used here. */
export function parseProductionHeaders(source) {
  const rules = [];
  let active;
  for (const rawLine of source.split(/\r?\n/)) {
    if (rawLine.trim().length === 0) continue;
    if (!/^\s/.test(rawLine)) {
      active = { pattern: rawLine.trim(), headers: {} };
      rules.push(active);
      continue;
    }
    if (active === undefined) throw new Error("production header appears before a route");
    const line = rawLine.trim();
    const separator = line.indexOf(":");
    if (separator <= 0) throw new Error("production header is malformed");
    active.headers[line.slice(0, separator).trim().toLowerCase()] = line.slice(separator + 1).trim();
  }
  return rules;
}

function matches(pattern, pathname) {
  if (pattern === "/*") return true;
  if (pattern.endsWith("*")) return pathname.startsWith(pattern.slice(0, -1));
  return pathname === pattern;
}

/** Apply every matching rule in file order, as Cloudflare Pages does. */
export function productionHeadersForPath(rules, pathname) {
  const headers = {};
  for (const rule of rules) {
    if (matches(rule.pattern, pathname)) Object.assign(headers, rule.headers);
  }
  return headers;
}
