#!/usr/bin/env node
// Usage: node egress.mjs <tcpdump -vv text output>  → { domains: [...], ips: [...], rawIps: [...] }
// "rawIps" are destinations contacted without a DNS lookup we saw — i.e. hard-coded IPs.
import { readText } from "./lib.mjs";

const text = readText(process.argv[2], 20_000_000) ?? "";
const domains = new Set();
const resolved = new Set();
const contacted = new Set();
const PRIVATE = /^(10\.|127\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.|0\.)/;

for (const line of text.split("\n")) {
  // DNS question: "... 12345+ A? registry.npmjs.org. (35)"
  for (const m of line.matchAll(/\b(?:A|AAAA|CNAME|HTTPS)\?\s+([A-Za-z0-9.-]+?)\.?\s/g)) domains.add(m[1].toLowerCase());
  // DNS answers: "... A 104.16.1.34, A 104.16.2.34 ..."
  for (const m of line.matchAll(/\bA (\d{1,3}(?:\.\d{1,3}){3})\b/g)) resolved.add(m[1]);
  // Outbound connection: "172.17.0.2.43210 > 104.16.1.34.443: Flags [S]" (TCP SYN) or UDP datagram
  const c = /(\d{1,3}(?:\.\d{1,3}){3})\.\d+ > (\d{1,3}(?:\.\d{1,3}){3})\.(\d+):/.exec(line);
  if (c && PRIVATE.test(c[1]) && !PRIVATE.test(c[2]) && c[3] !== "53" && c[2] !== "8.8.8.8") contacted.add(`${c[2]}:${c[3]}`);
}

const rawIps = [...contacted].filter((ipPort) => !resolved.has(ipPort.split(":")[0]));
console.log(JSON.stringify({ domains: [...domains].sort().slice(0, 200), connections: [...contacted].sort().slice(0, 200), rawIps: rawIps.slice(0, 50) }));
