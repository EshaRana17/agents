#!/usr/bin/env node
// Usage: node egress.mjs <tcpdump -vv text output>  → { domains: [...], ips: [...], rawIps: [...] }
// "rawIps" are destinations contacted without a DNS lookup we saw — i.e. hard-coded IPs.
import { readText } from "./lib.mjs";

const text = readText(process.argv[2], 20_000_000) ?? "";
const domains = new Set();
const resolved = new Set();
const contacted = new Set();
const PRIVATE = /^(10\.|127\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|0\.)/;
const RESOLVER = "8.8.8.8"; // must match --dns in dynamic.sh

for (const line of text.split("\n")) {
  const c = /(\d{1,3}(?:\.\d{1,3}){3})\.(\d+) > (\d{1,3}(?:\.\d{1,3}){3})\.(\d+):/.exec(line);
  if (!c) continue;
  const [, src, srcPort, dst, dstPort] = c;
  const toResolver = dst === RESOLVER && dstPort === "53";
  const fromResolver = src === RESOLVER && srcPort === "53";
  // DNS questions to the configured resolver, of any type: "... 12345+ TXT? x.example.com. (35)"
  if (toResolver) for (const m of line.matchAll(/\b[A-Z0-9]+\?\s+([A-Za-z0-9._-]+?)\.?\s/g)) domains.add(m[1].toLowerCase());
  // Answers count only when they come back from the resolver: "... A 104.16.1.34, A 104.16.2.34 ..."
  if (fromResolver) for (const m of line.matchAll(/\bA (\d{1,3}(?:\.\d{1,3}){3})\b/g)) resolved.add(m[1]);
  // Anything else leaving the sandbox (TCP SYN or UDP), including port 53 to other hosts.
  if (PRIVATE.test(src) && !PRIVATE.test(dst) && !toResolver) contacted.add(`${dst}:${dstPort}`);
}

const rawIps = [...contacted].filter((ipPort) => !resolved.has(ipPort.split(":")[0]));
console.log(JSON.stringify({ domains: [...domains].sort().slice(0, 200), connections: [...contacted].sort().slice(0, 200), rawIps: rawIps.slice(0, 50) }));
