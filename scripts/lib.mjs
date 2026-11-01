// Shared helpers. Everything here treats repo contents as untrusted data: files are only
// read and parsed, never imported or executed on the host.
import { existsSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

export const MAX_TEXT = 300;

export function readJson(path, fallback = null) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return fallback;
  }
}

export function readText(path, max = 200_000) {
  try {
    if (statSync(path).size > 5_000_000) return null;
    return readFileSync(path, "utf8").slice(0, max);
  } catch {
    return null;
  }
}

export const has = (dir, name) => existsSync(join(dir, name));

/** Trim and strip control characters from text that came from the repo or tools. */
export function clean(s, max = MAX_TEXT) {
  if (s == null) return null;
  // eslint-disable-next-line no-control-regex
  const t = String(s).replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, "").trim();
  return t.length > max ? `${t.slice(0, max)}…` : t;
}

/** Repo-relative path for a file inside the scanned checkout. */
export function rel(path, root = "target") {
  // Tools report "target/x", "./target/x" or an absolute runner path ".../work/agents/agents/target/x";
  // the first "/target/" is our checkout folder (a repo may have its own "target" folders deeper in).
  const p = String(path).replace(/\\/g, "/");
  const i = p.startsWith("/") ? p.indexOf(`/${root}/`) : -1;
  return clean(i >= 0 ? p.slice(i + root.length + 2) : p.replace(new RegExp(`^(\\./)?${root}/`), ""), 200);
}

/** Domain list values must look like hostnames (optionally with a leading *.) */
export function isHostname(s) {
  return typeof s === "string" && /^(\*\.)?[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$/i.test(s);
}

export function hostMatches(host, patterns) {
  host = host.toLowerCase().replace(/\.$/, "");
  return patterns.some((p) => {
    p = p.toLowerCase();
    return p.startsWith("*.") ? host === p.slice(2) || host.endsWith(p.slice(1)) : host === p;
  });
}
