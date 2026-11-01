#!/usr/bin/env node
// Usage: node report.mjs <out-dir>  → prints the final report JSON.
// Combines detect / semgrep / gitleaks / osv / dynamic outputs into findings, a score and badges.
import { join } from "node:path";
import { clean, hostMatches, readJson, rel } from "./lib.mjs";

const OUT = process.argv[2] ?? "out";
const meta = readJson(join(OUT, "meta.json"), {});
const detect = readJson(join(OUT, "detect.json"), null);
const semgrep = readJson(join(OUT, "semgrep.json"), null);
const gitleaks = readJson(join(OUT, "gitleaks.json"), null);
const osv = readJson(join(OUT, "osv.json"), null);
const dynamic = readJson(join(OUT, "dynamic.json"), null);
const full = meta.mode === "full";

// Package registries and source hosts that installs legitimately talk to.
const REGISTRIES = [
  "registry.npmjs.org", "registry.yarnpkg.com", "repo.yarnpkg.com", "*.npmjs.org", "nodejs.org",
  "pypi.org", "files.pythonhosted.org", "*.pythonhosted.org",
  "github.com", "*.github.com", "codeload.github.com", "objects.githubusercontent.com", "*.githubusercontent.com",
  "proxy.golang.org", "sum.golang.org", "crates.io", "*.crates.io",
];

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const findings = [];
const add = (f) => findings.push({ ...f, title: clean(f.title, 160), detail: clean(f.detail, 300), file: f.file ? rel(f.file) : null });

// ---- static: semgrep ----
const envReads = new Set();
for (const r of semgrep?.results ?? []) {
  const sev = r.extra?.metadata?.av_severity ?? "medium";
  if (sev === "info") {
    // The rule message carries the variable name: "Reads environment variable FOO"
    const name = /environment variable\s+["'`]?([A-Za-z_][A-Za-z0-9_]*)/.exec(r.extra?.message ?? "")?.[1];
    if (name) envReads.add(name);
    continue;
  }
  add({ id: r.check_id?.split(".").pop(), severity: sev, category: r.extra?.metadata?.av_category ?? "code", title: r.extra?.message, file: r.path, line: r.start?.line });
}
// A config-level error (no file path) means no rules ran, so an empty result isn't a clean scan.
const staticRan = Array.isArray(semgrep?.results) && !(semgrep.errors ?? []).some((e) => e.level === "error" && !e.path);

// ---- secrets: gitleaks (never copy the secret itself) ----
// Docs, examples and tests are full of placeholder keys; report those as low and group
// repeats so one example file doesn't produce dozens of findings.
const NON_PROD = /(^|\/)(docs?|examples?|samples?|tests?|__tests__|spec|fixtures?|mocks?)\/|\.(md|mdx|rst|txt)$|\.(test|spec)\.[cm]?[jt]sx?$|_test\.(py|go)$|(^|\/)test_[^/]*\.py$/i;
const secretGroups = new Map();
for (const g of Array.isArray(gitleaks) ? gitleaks : []) {
  const file = rel(g.File);
  const key = `${g.RuleID}|${file}`;
  const cur = secretGroups.get(key) ?? { rule: g.RuleID, file, line: g.StartLine, n: 0 };
  cur.n++;
  secretGroups.set(key, cur);
}
for (const g of secretGroups.values()) {
  const example = NON_PROD.test(g.file);
  add({
    id: "secret",
    severity: example ? "low" : /private-key/i.test(g.rule) ? "critical" : "high",
    category: "secrets",
    title: example ? `Possible example credential in docs/tests: ${g.rule}` : `Committed secret: ${g.rule}`,
    detail: g.n > 1 ? `${g.n} matches in this file` : null,
    file: g.file,
    line: g.line,
  });
}
const secretsRan = Array.isArray(gitleaks);

// ---- dependencies: osv-scanner ----
// One finding per vulnerable package version (not per advisory), at its worst severity.
let vulnCount = 0;
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const depGroups = new Map();
for (const res of osv?.results ?? []) {
  for (const p of res.packages ?? []) {
    const key = `${p.package?.name}@${p.package?.version}`;
    for (const grp of p.groups ?? []) {
      const ids = grp.ids ?? [];
      const malicious = ids.some((id) => id.startsWith("MAL-"));
      const cvss = parseFloat(grp.max_severity) || 0;
      const sev = malicious ? "critical" : cvss >= 9 ? "high" : cvss >= 7 ? "medium" : "low";
      vulnCount++;
      const cur = depGroups.get(key) ?? { name: p.package?.name, version: p.package?.version, sev: "low", malicious: false, ids: [], file: res.source?.path };
      if (SEV_RANK[sev] > SEV_RANK[cur.sev]) cur.sev = sev;
      cur.malicious ||= malicious;
      cur.ids.push(ids.find((id) => id.startsWith("MAL-")) ?? ids[0]);
      depGroups.set(key, cur);
    }
  }
}
for (const d of depGroups.values()) {
  add({
    id: d.malicious ? "malicious-package" : "vulnerable-dependency",
    severity: d.sev,
    category: "dependencies",
    title: d.malicious ? `Known malicious package: ${d.name}` : `${d.name}@${d.version}: ${d.ids.length} known ${d.ids.length === 1 ? "vulnerability" : "vulnerabilities"}`,
    detail: d.ids.slice(0, 5).join(", ") + (d.ids.length > 5 ? ` +${d.ids.length - 5} more` : ""),
    file: d.file,
  });
}
const depsRan = osv != null;

// ---- detect: manifest, install scripts, license ----
for (const f of detect?.findings ?? []) add(f);
const manifest = detect?.manifest ?? null;
if (!manifest) add({ id: "no-manifest", severity: "low", category: "manifest", title: "No manifest declaring network access and environment variables (agentvet.json)" });
if (!detect?.licenseFile) add({ id: "no-license", severity: "low", category: "license", title: "No license file" });

const declaredEnv = new Set(manifest?.env ?? []);
const undeclaredEnv = [...envReads].filter((e) => /^[A-Z_][A-Z0-9_]*$/.test(e) && !declaredEnv.has(e) && !["NODE_ENV", "HOME", "PATH", "DEBUG", "PORT", "LOG_LEVEL"].includes(e));
if (manifest && undeclaredEnv.length)
  add({ id: "undeclared-env", severity: "low", category: "env", title: "Reads environment variables not listed in the manifest", detail: undeclaredEnv.slice(0, 15).join(", ") });

// ---- dynamic: install, boot, egress, reproducibility ----
const declaredNet = manifest?.network ?? [];
let build = "skip", boot = "skip", egressStep = "skip", repeat = "skip";
let tools = [];
const egress = { install: [], runtime: [], undeclared: [], rawIps: [] };

if (full && dynamic) {
  const ie = dynamic.install?.exit;
  build = ie === 0 ? "pass" : ie === 3 ? "skip" : "fail";
  if (build === "fail") add({ id: "build-failed", severity: "medium", category: "build", title: "Install or build failed in a clean environment", detail: dynamic.install?.logTail?.slice(-300) });

  egress.install = dynamic.egress?.install?.domains ?? [];
  egress.runtime = dynamic.egress?.runtime?.domains ?? [];
  egress.rawIps = [...(dynamic.egress?.install?.rawIps ?? []), ...(dynamic.egress?.runtime?.rawIps ?? [])];
  const oddInstall = egress.install.filter((d) => !hostMatches(d, REGISTRIES) && !hostMatches(d, declaredNet));
  egress.undeclared = egress.runtime.filter((d) => !hostMatches(d, declaredNet));
  if (oddInstall.length) add({ id: "install-egress", severity: "medium", category: "network", title: "Install contacted hosts other than package registries", detail: oddInstall.slice(0, 10).join(", ") });
  if (egress.undeclared.length) add({ id: "undeclared-egress", severity: "high", category: "network", title: "Contacted domains it did not declare while starting up", detail: egress.undeclared.slice(0, 10).join(", ") });
  if (egress.rawIps.length) add({ id: "raw-ip-egress", severity: "high", category: "network", title: "Connected to IP addresses without a DNS lookup", detail: egress.rawIps.slice(0, 10).join(", ") });

  const probes = Array.isArray(dynamic.probes) ? dynamic.probes : [];
  if (detect?.type === "mcp") {
    if (!probes.length) {
      boot = build === "pass" ? "fail" : "skip";
      if (build === "pass") add({ id: "no-entrypoint", severity: "low", category: "boot", title: "Couldn't work out how to start the server. Set \"entrypoint\" in agentvet.json." });
    } else {
      const okRuns = probes.filter((p) => p?.ok);
      boot = okRuns.length ? "pass" : "fail";
      if (!okRuns.length) add({ id: "boot-failed", severity: "medium", category: "boot", title: "MCP server didn't complete the protocol handshake", detail: probes[0]?.error });
      tools = (okRuns[0]?.tools ?? []).map((t) => ({ name: clean(t.name, 100), description: clean(t.description, 300) }));
      const sigs = new Set(okRuns.map((p) => (p.tools ?? []).map((t) => t.name).sort().join("|")));
      repeat = okRuns.length === 3 && sigs.size === 1 ? "pass" : okRuns.length ? "fail" : "skip";
      if (repeat === "fail") add({ id: "not-reproducible", severity: "low", category: "boot", title: "Runs didn't produce the same results", detail: `${okRuns.length}/3 runs succeeded` });
    }
  }
  // Runtime egress is only meaningful if the code actually ran.
  egressStep = egress.undeclared.length || egress.rawIps.length ? "fail" : oddInstall.length ? "warn" : boot === "pass" ? "pass" : "skip";
}

// ---- score ----
// Malicious-looking code (critical) always costs 40. Everything else is capped per category,
// so a repo with many outdated dependencies or example keys can't sink to zero on that alone.
const counts = Object.fromEntries(SEV_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length]));
const CAPS = { dependencies: 20, secrets: 30, env: 3, license: 5, manifest: 5, build: 10, boot: 10 };
const WEIGHT = { high: 15, medium: 5, low: 1, info: 0 };
const byCat = {};
for (const f of findings) if (f.severity !== "critical") byCat[f.category] = (byCat[f.category] ?? 0) + WEIGHT[f.severity];
let score = 100 - 40 * counts.critical;
for (const [cat, pts] of Object.entries(byCat)) score -= Math.min(CAPS[cat] ?? 45, pts);
if (build === "fail") score -= 10;
if (boot === "fail") score -= 10;
score = Math.max(0, Math.min(100, score));

const scanErrors = [!staticRan && "static", !secretsRan && "secrets", !depsRan && "dependencies"].filter(Boolean);
const status = scanErrors.length === 3 ? "error" : counts.critical ? "failed" : counts.high || score < 80 || scanErrors.length ? "warning" : "passed";

const badges = [];
if (staticRan && secretsRan && !counts.critical) badges.push("Scanned");
if (build === "pass") badges.push("Builds");
if (boot === "pass") badges.push("Boots");
if (egressStep === "pass") badges.push("No undeclared egress");
if (repeat === "pass") badges.push("Reproducible");

const stepStatus = (ran, cat) => (!ran ? "error" : findings.some((f) => f.category === cat && ["critical", "high"].includes(f.severity)) ? "fail" : findings.some((f) => f.category === cat && f.severity === "medium") ? "warn" : "pass");
const codeCats = ["credential-access", "exfiltration", "obfuscation", "dropper", "miner", "backdoor", "code-execution", "shell", "network", "install-script"];
const staticStatus = !staticRan ? "error" : findings.some((f) => codeCats.includes(f.category) && f.severity === "critical") ? "fail" : findings.some((f) => codeCats.includes(f.category) && ["high", "medium"].includes(f.severity)) ? "warn" : "pass";

findings.sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));

console.log(
  JSON.stringify(
    {
      version: 1,
      jobId: meta.jobId ?? null,
      repo: meta.repo ?? null,
      commit: meta.commit ?? null,
      mode: full ? "full" : "light",
      listingType: detect?.type ?? null,
      runtime: detect?.runtime ?? null,
      runUrl: meta.runUrl ?? null,
      startedAt: meta.startedAt ?? null,
      finishedAt: new Date().toISOString(),
      status,
      score,
      badges,
      counts,
      steps: [
        { id: "static", label: "Static code scan", status: staticStatus },
        { id: "secrets", label: "Secrets scan", status: stepStatus(secretsRan, "secrets") },
        { id: "dependencies", label: "Dependency audit", status: stepStatus(depsRan, "dependencies"), summary: `${vulnCount} known vulnerabilities` },
        { id: "manifest", label: "Manifest", status: manifest ? "pass" : "warn", summary: detect?.manifestFile ?? "none" },
        { id: "build", label: "Build", status: build },
        { id: "boot", label: "Boot & handshake", status: boot, summary: tools.length ? `${tools.length} tools` : undefined },
        { id: "egress", label: "Network egress", status: egressStep },
        { id: "repeat", label: "Reproducible (×3)", status: repeat },
      ],
      findings: findings.slice(0, 200),
      egress,
      tools: tools.slice(0, 200),
      manifest,
    },
    null,
    1,
  ),
);
