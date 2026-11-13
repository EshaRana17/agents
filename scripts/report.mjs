#!/usr/bin/env node
// Usage: node report.mjs <out-dir>  → prints the final report JSON.
// Combines detect / semgrep / gitleaks / osv / dynamic outputs into findings, a score and badges.
import { join } from "node:path";
import { clean, hostMatches, readJson, readText, rel } from "./lib.mjs";

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

// Docs, examples and tests are full of placeholder keys and demo code that never runs on install.
const NON_PROD = /(^|\/)(docs?|examples?|samples?|tests?|__tests__|spec|fixtures?|mocks?|benchmarks?|e2e)\/|(^|\/)[^/]*(fixture|mock)[^/]*$|\.(md|mdx|rst|txt)$|\.(test|spec)\.[cm]?[jt]sx?$|_test\.(py|go)$|(^|\/)test_[^/]*\.py$/i;
const DOCS = /\.(md|mdx|rst|txt)$/i;
// Categories that are signs of malware on their own. Everything else is a capability that many
// legitimate tools need, and only becomes critical with evidence that data leaves the machine.
const MALWARE = new Set(["obfuscation", "miner", "backdoor"]);
// Security tools (guards, scanners, blocklists) contain malware names and patterns as detection
// signatures, the same way antivirus software does.
const SECURITY_FILE = /(guard|scan|detect|secur|signature|rule|block|deny|allow|sanitiz|redact|malware|threat|firewall|policy)[^/]*$/i;
// ...or a folder named for defensive work (e.g. skills/detecting-cryptomining-in-cloud/scripts/agent.py).
const SECURITY_DIR = /(^|\/)[^/]*(guard|scan|detect|secur|protect|defen[cs]e|monitor|hunt|forensic|incident|threat|firewall|malware)[^/]*\//i;
// A line that is only quoted strings (an entry in a list of domains, commands or indicators).
const STRING_LIST = /^\s*(["'`][^"'`]*["'`]\s*:\s*)?[([{]?\s*("[^"]*"|'[^']*'|`[^`]*`)(\s*,\s*("[^"]*"|'[^']*'|`[^`]*`))*\s*[)\]}]*\s*,?\s*(#.*|\/\/.*)?$/;
// Attack templates put a placeholder where the target goes ({ip}, ${target}, YOUR_IP, LHOST);
// real malware hard-codes where it connects. Penetration-testing tools generate such templates.
const PLACEHOLDER = /(\{\{?\s*[a-z_.]*(ip|host|addr|target|port|server|attacker)[a-z_.]*\s*\}?\}|\$\{?[a-z_]*(ip|host|addr|target|port)|\b(YOUR_IP|YOUR_HOST|ATTACKER_IP|LHOST|RHOST|LPORT)\b|<\s*(ip|host|attacker[-_ ]?ip|your[-_ ]?ip)\s*>)/i;

// ---- static: semgrep ----
const envReads = new Set();
const staticFindings = [];
// The matched source line, read from the checked-out repo (Semgrep OSS doesn't return it).
const sourceLine = new Map();
const fileCache = new Map();
function lineAt(path, line) {
  if (!path || !line) return "";
  if (!fileCache.has(path)) fileCache.set(path, (readText(path, 2_000_000) ?? "").split(/\r?\n/));
  return fileCache.get(path)[line - 1] ?? "";
}
// A malware pattern written as data rather than code: a comment, a regex, or an entry in a
// detection, payload or test list. Security tools contain these strings in order to detect them,
// and offensive-security tools generate them for a target the operator picks.
const AS_DATA = /^\s*(\/\/|#|\*|\/\*|<!--|--|;)|\bRegExp\(|re\.compile|\bregex|\bpattern|signature|indicator|\bioc\b|example|expect|block|deny|detect|payload|exploit|\brule|\bmatch/i;
// A line that hands the string to something that runs it stays critical whatever words it contains.
const EXEC_SINK = /\b(os\.system|os\.popen|subprocess\.|Popen\(|exec\(|eval\(|execSync|spawn(Sync)?\(|child_process|Runtime\.getRuntime|system\(|shell_exec|passthru|pty\.spawn)/;
const PAYLOAD_PATH =/(^|\/)(payloads?|exploits?|red[-_]?team|pentest|offensive|attacks?|evals?|corpus|samples?)(\/|[^/]*$)/i;
for (const r of semgrep?.results ?? []) {
  const sev = r.extra?.metadata?.av_severity ?? "medium";
  if (sev === "info") {
    // The rule message carries the variable name: "Reads environment variable FOO"
    const name = /environment variable\s+["'`]?([A-Za-z_][A-Za-z0-9_]*)/.exec(r.extra?.message ?? "")?.[1];
    if (name) envReads.add(name);
    continue;
  }
  add({ id: r.check_id?.split(".").pop(), severity: sev, category: r.extra?.metadata?.av_category ?? "code", title: r.extra?.message, file: r.path, line: r.start?.line });
  staticFindings.push(findings[findings.length - 1]);
  sourceLine.set(findings[findings.length - 1], lineAt(r.path, r.start?.line));
}
for (const f of staticFindings) {
  const src = sourceLine.get(f) ?? "";
  const runs = EXEC_SINK.test(src);
  if (MALWARE.has(f.category) && f.file && !runs && (SECURITY_FILE.test(f.file) || SECURITY_DIR.test(f.file))) {
    f.severity = "high";
    f.title = `In a security/detection file (likely a detection pattern): ${f.title}`;
    continue;
  }
  if (MALWARE.has(f.category) && (PAYLOAD_PATH.test(f.file ?? "") || PLACEHOLDER.test(src) || (!runs && (AS_DATA.test(src) || STRING_LIST.test(src))))) {
    f.severity = "high";
    f.title = `Written as data or as an attack template for a target the user picks, not run against you on install: ${f.title}`;
    continue;
  }
  const nonProd = f.file && NON_PROD.test(f.file);
  if (!nonProd) continue;
  // Malware patterns in tests/fixtures don't run on install but still deserve a look.
  f.severity = MALWARE.has(f.category) && !DOCS.test(f.file) ? "high" : "low";
  f.title = `In tests/examples/docs: ${f.title}`;
}
// Reading secrets and sending data out in the same production file is the exfiltration pattern.
const SENDS = new Set(["av-webhook-exfil", "av-raw-ip-url"]);
const byFile = new Map();
for (const f of staticFindings) if (f.file && f.severity !== "low") byFile.set(f.file, [...(byFile.get(f.file) ?? []), f]);
for (const [file, fs] of byFile) {
  // Only real code that dumps the environment counts: credential *paths* also appear as plain strings
  // in redaction lists, docs and config, which would make this match far too often.
  const reads = fs.find((f) => f.id?.startsWith("av-env-dump"));
  const sends = fs.find((f) => SENDS.has(f.id));
  if (reads && sends)
    add({ id: "likely-exfiltration", severity: "critical", category: "exfiltration", title: "Reads secrets and sends data to an external endpoint in the same file", detail: `${reads.title} / ${sends.title}`, file, line: reads.line });
}
// A config-level error (no file path) means no rules ran, so an empty result isn't a clean scan.
const staticRan = Array.isArray(semgrep?.results) && !(semgrep.errors ?? []).some((e) => e.level === "error" && !e.path);

// ---- secrets: gitleaks (never copy the secret itself) ----
// Placeholder keys in docs/examples/tests are reported as low (NON_PROD above), and repeats are
// grouped so one example file doesn't produce dozens of findings.
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
    // A committed key is a hygiene problem for the maintainer, not malware aimed at the user.
    severity: example ? "low" : "high",
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
// npm replaces removed malicious packages with an empty "0.0.1-security" placeholder, and a lockfile
// lists the project's own package; neither is malware the user installs.
const ownName = (meta.repo ?? "").split("/").pop()?.toLowerCase().replace(/[-_.]+/g, "-") ?? "";
for (const d of depGroups.values()) {
  if (!d.malicious) continue;
  const name = (d.name ?? "").toLowerCase().replace(/[-_.]+/g, "-");
  if (d.version === "0.0.1-security" || (ownName && name === ownName)) {
    d.malicious = false;
    d.sev = "low";
    d.note = d.version === "0.0.1-security" ? "npm security placeholder (empty package)" : "the project's own package";
  } else if (d.file && rel(d.file).includes("/")) {
    // A lockfile in a sub-project (e.g. a bundled web UI) is a build dependency, not what users install.
    d.sev = "high";
    d.note = "in a sub-project lockfile";
  }
}
for (const d of depGroups.values()) {
  add({
    id: d.malicious ? "malicious-package" : "vulnerable-dependency",
    severity: d.sev,
    category: "dependencies",
    title: d.malicious
      ? `Known malicious package version: ${d.name}@${d.version}${d.note ? ` (${d.note})` : ""}`
      : d.note
        ? `Matched a malicious-package advisory but is ${d.note}: ${d.name}@${d.version}`
        : `${d.name}@${d.version}: ${d.ids.length} known ${d.ids.length === 1 ? "vulnerability" : "vulnerabilities"}`,
    detail: d.ids.slice(0, 5).join(", ") + (d.ids.length > 5 ? ` +${d.ids.length - 5} more` : ""),
    file: d.file,
  });
}
const depsRan = osv != null;

// ---- detect: manifest, install scripts, license ----
for (const f of detect?.findings ?? []) add(f);
const manifest = detect?.manifest ?? null;
// Scanner-suppression files shipped by the repo are deleted before scanning; say so.
const suppressions = (readText(join(OUT, "suppressions.txt"), 5000) ?? "").split("\n").filter(Boolean);
if (suppressions.length)
  add({ id: "scanner-suppressions", severity: "info", category: "static", title: `Ignored the repo's scanner suppression config (${suppressions.length} file${suppressions.length > 1 ? "s" : ""})`, detail: suppressions.slice(0, 5).join(", ") });
if (!manifest) add({ id: "no-manifest", severity: "low", category: "manifest", title: "No manifest declaring network access and environment variables (agent.json)" });
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
  // Without a manifest nothing is "declared", so contacted hosts are listed for information only.
  if (egress.undeclared.length)
    add(manifest
      ? { id: "undeclared-egress", severity: "high", category: "network", title: "Contacted domains it did not declare while starting up", detail: egress.undeclared.slice(0, 10).join(", ") }
      : { id: "runtime-egress", severity: "low", category: "network", title: "Contacted these domains while starting up (no manifest to compare against)", detail: egress.undeclared.slice(0, 10).join(", ") });
  // Only code that dumps the environment, not a credential path that may sit in a comment or list.
  const capability = staticFindings.find((f) => f.severity === "high" && f.id?.startsWith("av-env-dump"));
  if (capability && (egress.rawIps.length || (manifest && egress.undeclared.length)))
    add({ id: "likely-exfiltration", severity: "critical", category: "exfiltration", title: "Touches secrets in code and made unexpected network connections when run", detail: capability.title, file: capability.file, line: capability.line });
  if (egress.rawIps.length) add({ id: "raw-ip-egress", severity: "high", category: "network", title: "Connected to IP addresses without a DNS lookup", detail: egress.rawIps.slice(0, 10).join(", ") });

  const probes = Array.isArray(dynamic.probes) ? dynamic.probes : [];
  if (detect?.type === "mcp") {
    if (!probes.length) {
      // No known start command (common in monorepos) means "not tested", not a failure.
      boot = "skip";
      if (build === "pass") add({ id: "no-entrypoint", severity: "low", category: "boot", title: "Couldn't work out how to start the server. Set \"entrypoint\" in agent.json." });
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
// The scan is a malware check: malicious-looking code (critical) costs 40 each. Capabilities that
// legitimate tools need (shell, env, credential paths, network) and hygiene issues (old dependencies,
// committed keys) are reported but only lightly scored, capped as a group.
const counts = Object.fromEntries(SEV_ORDER.map((s) => [s, findings.filter((f) => f.severity === s).length]));
const CAPABILITY = new Set(["credential-access", "exfiltration", "obfuscation", "dropper", "code-execution", "shell", "network", "install-script", "miner", "backdoor"]);
const CAPS = { capability: 20, dependencies: 10, secrets: 10, env: 3, license: 5, manifest: 5, build: 10, boot: 10 };
const WEIGHT = { high: 5, medium: 2, low: 1, info: 0 };
const byCat = {};
for (const f of findings) {
  if (f.severity === "critical") continue;
  const cat = CAPABILITY.has(f.category) ? "capability" : f.category;
  byCat[cat] = (byCat[cat] ?? 0) + WEIGHT[f.severity];
}
let score = 100 - 40 * counts.critical;
for (const [cat, pts] of Object.entries(byCat)) score -= Math.min(CAPS[cat] ?? 5, pts);
score = Math.max(0, Math.min(100, score));

const scanErrors = [!staticRan && "static", !secretsRan && "secrets", !depsRan && "dependencies"].filter(Boolean);
// failed = signs of malware; warning = a check couldn't run, so we can't say; passed = no malware signs.
const status = scanErrors.length === 3 ? "error" : counts.critical ? "failed" : scanErrors.length ? "warning" : "passed";

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
