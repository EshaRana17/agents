#!/usr/bin/env node
// Usage: node detect.mjs <repo-dir>  → prints detect.json
// Works out the runtime, listing type, declared permissions and how to start the code.
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { clean, has, isHostname, readJson, readText } from "./lib.mjs";

const dir = process.argv[2] ?? "target";
const files = (() => {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
})();
const lower = files.map((f) => f.toLowerCase());
const findings = [];

// ---- Manifest: agentvet.json (preferred), agent.json, MCP server.json, SKILL.md ----
function parseFrontmatter(md) {
  const m = /^---\r?\n([\s\S]*?)\r?\n---/.exec(md ?? "");
  if (!m) return null;
  const out = {};
  for (const line of m[1].split(/\r?\n/)) {
    const kv = /^([A-Za-z_-]+):\s*(.*)$/.exec(line);
    if (kv) out[kv[1]] = kv[2].replace(/^["']|["']$/g, "");
  }
  return out;
}

let manifest = null;
let manifestFile = null;
for (const name of ["agentvet.json", "agent.json"]) {
  if (has(dir, name)) {
    manifestFile = name;
    const raw = readJson(join(dir, name));
    if (!raw || typeof raw !== "object") {
      findings.push({ severity: "medium", category: "manifest", title: `${name} is not valid JSON`, file: name });
      break;
    }
    const network = Array.isArray(raw.network) ? raw.network.filter(isHostname).slice(0, 50) : [];
    const env = Array.isArray(raw.env) ? raw.env.filter((e) => typeof e === "string" && /^[A-Z_][A-Z0-9_]{0,63}$/.test(e)).slice(0, 50) : [];
    manifest = {
      name: clean(raw.name, 80),
      description: clean(raw.description, 300),
      type: ["agent", "mcp", "skill"].includes(raw.type) ? raw.type : null,
      entrypoint: typeof raw.entrypoint === "string" ? clean(raw.entrypoint, 200) : null,
      install: typeof raw.install === "string" ? clean(raw.install, 200) : null,
      network,
      env,
      filesystem: ["none", "read", "write"].includes(raw.filesystem) ? raw.filesystem : null,
    };
    break;
  }
}

const serverJson = has(dir, "server.json") ? readJson(join(dir, "server.json")) : null;
if (!manifest && serverJson) {
  manifestFile = "server.json";
  manifest = { name: clean(serverJson.name, 80), description: clean(serverJson.description, 300), type: "mcp", entrypoint: null, install: null, network: [], env: [], filesystem: null };
  const envs = (serverJson.packages ?? []).flatMap((p) => (p.environment_variables ?? p.environmentVariables ?? []).map((e) => e?.name)).filter(Boolean);
  manifest.env = envs.filter((e) => /^[A-Z_][A-Z0-9_]{0,63}$/.test(e)).slice(0, 50);
}

const skillMd = lower.includes("skill.md") ? readText(join(dir, files[lower.indexOf("skill.md")])) : null;
const skillFront = skillMd ? parseFrontmatter(skillMd) : null;
if (skillMd) {
  if (!skillFront?.name || !skillFront?.description)
    findings.push({ severity: "low", category: "manifest", title: "SKILL.md frontmatter is missing name or description", file: "SKILL.md" });
  if (!manifest) {
    manifestFile = "SKILL.md";
    manifest = { name: clean(skillFront?.name, 80), description: clean(skillFront?.description, 300), type: "skill", entrypoint: null, install: null, network: [], env: [], filesystem: null };
  }
}

// ---- Runtime & package metadata ----
const pkg = has(dir, "package.json") ? readJson(join(dir, "package.json"), {}) : null;
const pyproject = has(dir, "pyproject.toml") ? readText(join(dir, "pyproject.toml")) : null;
const runtime = pkg ? "node" : pyproject || has(dir, "requirements.txt") || has(dir, "setup.py") ? "python" : has(dir, "go.mod") ? "go" : has(dir, "Cargo.toml") ? "rust" : "unknown";

const deps = { ...(pkg?.dependencies ?? {}), ...(pkg?.devDependencies ?? {}) };
const mentionsMcp =
  Object.keys(deps).some((d) => d.startsWith("@modelcontextprotocol/") || d === "fastmcp" || d === "mcp-framework") ||
  /(^|[\s"'])(mcp|fastmcp)([\s"'>=<\[]|$)/m.test(pyproject ?? "") ||
  /^(mcp|fastmcp)\b/m.test(readText(join(dir, "requirements.txt")) ?? "");

let type = manifest?.type ?? (skillMd || lower.includes("skills") ? "skill" : mentionsMcp || serverJson ? "mcp" : "agent");
const typeHint = process.argv[3];
if (["agent", "mcp", "skill"].includes(typeHint) && !manifest?.type) type = typeHint;

// ---- Install-time scripts are a classic supply-chain vector ----
for (const hook of ["preinstall", "install", "postinstall", "prepare"]) {
  const s = pkg?.scripts?.[hook];
  if (typeof s !== "string") continue;
  const risky = /(curl|wget|Invoke-WebRequest|iwr)\b[^|]*\|\s*(ba|z)?sh|base64\s+-d|eval\s|node\s+-e|python\s+-c/i.test(s);
  findings.push({
    severity: risky ? "critical" : "low",
    category: "install-script",
    title: risky ? `package.json ${hook} script downloads and runs code` : `package.json has a ${hook} script`,
    file: "package.json",
    detail: clean(s, 200),
  });
}

// ---- How to start it (MCP servers are started over stdio) ----
function entrypoint() {
  if (manifest?.entrypoint) return manifest.entrypoint;
  if (runtime === "node") {
    const bin = typeof pkg?.bin === "string" ? pkg.bin : pkg?.bin && Object.values(pkg.bin)[0];
    if (typeof bin === "string") return `node ${bin}`;
    if (pkg?.scripts?.start) return "npm start --silent";
    if (typeof pkg?.main === "string") return `node ${pkg.main}`;
    for (const f of ["dist/index.js", "build/index.js", "index.js", "server.js"]) if (has(dir, f)) return `node ${f}`;
  }
  if (runtime === "python") {
    const script = /\[project\.scripts\][^[]*?^\s*([A-Za-z0-9_.-]+)\s*=/m.exec(pyproject ?? "");
    if (script) return `.venv/bin/${script[1]}`;
    for (const f of ["server.py", "main.py", "app.py", "src/server.py"]) if (has(dir, f)) return `.venv/bin/python ${f}`;
  }
  return null;
}

const license = files.find((f) => /^(license|licence|copying)(\.|$)/i.test(f)) ?? null;

console.log(
  JSON.stringify(
    {
      runtime,
      type,
      manifestFile,
      manifest,
      entrypoint: type === "mcp" ? entrypoint() : null,
      hasBuildScript: Boolean(pkg?.scripts?.build),
      hasLockfile: ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "uv.lock", "poetry.lock", "requirements.txt"].some((f) => lower.includes(f)),
      licenseFile: license,
      readme: lower.some((f) => f.startsWith("readme")),
      findings,
    },
    null,
    1,
  ),
);
