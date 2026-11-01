#!/usr/bin/env node
// Runs inside the sandbox container.
// Usage: node probe-mcp.mjs '<command>' [ENV_NAME ...]
// Starts an MCP server over stdio, performs initialize + tools/list, prints one JSON line.
import { spawn } from "node:child_process";

const [command, ...envNames] = process.argv.slice(2);
const TIMEOUT_MS = 45_000;

// The server gets a minimal environment: no host variables, placeholder values for
// whatever it declared, so it can boot without real credentials.
const env = { PATH: process.env.PATH, HOME: "/tmp/home", NODE_ENV: "production", LANG: "C.UTF-8" };
for (const n of envNames) if (/^[A-Z_][A-Z0-9_]{0,63}$/.test(n)) env[n] = "agentvet-placeholder";

const result = { ok: false, serverInfo: null, protocolVersion: null, tools: [], error: null, stderrTail: "" };
const child = spawn(command, { shell: true, cwd: process.env.PROBE_CWD ?? "/w", env, stdio: ["pipe", "pipe", "pipe"] });

let buf = "";
let nextId = 1;
const pending = new Map();
const send = (method, params) =>
  new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
const notify = (method, params) => child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method, params }) + "\n");

child.stdout.on("data", (d) => {
  buf += d;
  if (buf.length > 5_000_000) buf = buf.slice(-1_000_000);
  let i;
  while ((i = buf.indexOf("\n")) >= 0) {
    const line = buf.slice(0, i).trim();
    buf = buf.slice(i + 1);
    if (!line.startsWith("{")) continue;
    try {
      const msg = JSON.parse(line);
      const p = msg.id != null && pending.get(msg.id);
      if (p) {
        pending.delete(msg.id);
        msg.error ? p.reject(new Error(String(msg.error.message ?? "error").slice(0, 200))) : p.resolve(msg.result);
      }
    } catch {}
  }
});
child.stderr.on("data", (d) => (result.stderrTail = (result.stderrTail + d).slice(-1500)));
child.on("error", (e) => finish(`spawn failed: ${e.message}`));
child.on("exit", (code) => finish(`server exited early with code ${code}`));
child.stdin.on("error", () => {});

let done = false;
function finish(error) {
  if (done) return;
  done = true;
  if (error && !result.ok) result.error = String(error).slice(0, 300);
  process.stdout.write(JSON.stringify(result) + "\n");
  try {
    child.kill("SIGKILL");
  } catch {}
  process.exit(0);
}
setTimeout(() => finish("timed out waiting for the server"), TIMEOUT_MS);

try {
  const init = await send("initialize", {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "agentvet-verifier", version: "1.0.0" },
  });
  result.serverInfo = { name: String(init?.serverInfo?.name ?? "").slice(0, 100), version: String(init?.serverInfo?.version ?? "").slice(0, 40) };
  result.protocolVersion = String(init?.protocolVersion ?? "").slice(0, 20);
  notify("notifications/initialized");

  let cursor;
  for (let page = 0; page < 20; page++) {
    const res = await send("tools/list", cursor ? { cursor } : {});
    for (const t of res?.tools ?? []) {
      if (result.tools.length >= 500) break;
      result.tools.push({ name: String(t.name ?? "").slice(0, 100), description: String(t.description ?? "").slice(0, 300) });
    }
    cursor = res?.nextCursor;
    if (!cursor) break;
  }
  result.ok = true;
  // Keep it running briefly so any background network activity at startup is captured.
  setTimeout(() => finish(null), 5000);
} catch (e) {
  finish(e.message);
}
