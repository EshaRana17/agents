#!/usr/bin/env node
// Usage: CALLBACK_URL=... CALLBACK_SECRET=... node callback.mjs <report.json>
// Sends the report to the web app, signed with HMAC-SHA256 so the app can verify it came from us.
import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";

const { CALLBACK_URL, CALLBACK_SECRET } = process.env;
if (!CALLBACK_URL || !CALLBACK_SECRET) {
  console.log("No callback configured; report is available as a workflow artifact only.");
  process.exit(0);
}

const body = JSON.stringify({ sentAt: new Date().toISOString(), report: JSON.parse(readFileSync(process.argv[2], "utf8")) });
const signature = createHmac("sha256", CALLBACK_SECRET).update(body).digest("hex");

for (let attempt = 1; attempt <= 3; attempt++) {
  try {
    const res = await fetch(CALLBACK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-AgentVet-Signature": `sha256=${signature}` },
      body,
    });
    console.log(`callback → ${res.status}`);
    if (res.ok) process.exit(0);
    if (res.status < 500) process.exit(1);
  } catch (e) {
    console.log(`callback attempt ${attempt} failed: ${e.message}`);
  }
  await new Promise((r) => setTimeout(r, attempt * 5000));
}
process.exit(1);
