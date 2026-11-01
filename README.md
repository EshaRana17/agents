# AgentVet Verifier

Free, automated security scans for AI agents, MCP servers and agent skills. Every scan runs on a
fresh GitHub Actions virtual machine that is destroyed afterwards, and the untrusted code itself
runs inside a locked-down Docker container on that machine.

This folder is meant to be pushed as its **own public repository** (e.g. `agentvet/agentvet-verifier`).
Public repositories get free, unlimited GitHub Actions minutes.

## What a scan does

| Step | Tool | Mode |
|---|---|---|
| Fetch repo at a pinned commit (no git hooks, no LFS, no submodules, 500 MB cap) | git | light + full |
| Detect runtime, type and manifest | `scripts/detect.mjs` | light + full |
| Static code scan (credential theft, exfiltration, obfuscation, droppers, miners, reverse shells, shell exec, eval…) | Semgrep + `rules/agentvet.yml` | light + full |
| Secrets scan | Gitleaks | light + full |
| Dependency audit, incl. known-malicious packages (`MAL-` advisories) | OSV-Scanner | light + full |
| Install + build in a sandbox container, capturing network traffic | Docker + tcpdump | full |
| Boot the MCP server and do the JSON-RPC handshake + `tools/list`, three times | `scripts/probe-mcp.mjs` | full |
| Compare network traffic to what the manifest declared | `scripts/egress.mjs` | full |
| Score, badges and report → signed POST back to the web app | `scripts/report.mjs`, `scripts/callback.mjs` | light + full |

Scanner versions are pinned and their downloads are checked against SHA-256 checksums in the workflow.

### Sandbox container

`--cap-drop ALL`, `--security-opt no-new-privileges`, non-root user, 2 CPUs, 3 GB RAM, 1024 PIDs,
no secrets in its environment, and declared env vars set to placeholder values. Only a copy of the
repo is mounted writable; the verifier scripts are mounted read-only.

### Scoring

Start at 100: −40 per critical, −15 per high, −5 per medium (max −25), −1 per low (max −5),
−10 if the build fails, −10 if the MCP handshake fails.

- **failed**: any critical finding, or score < 50
- **warning**: any high finding, score < 80, or a scanner didn't run
- **passed**: everything else

Badges: `Scanned`, `Builds`, `Boots`, `No undeclared egress`, `Reproducible`.

## Manifest: `agentvet.json`

Optional, but it's how a repo declares what it needs. Without it, any network traffic at runtime
counts as undeclared.

```json
{
  "name": "my-mcp-server",
  "description": "What it does.",
  "type": "mcp",
  "entrypoint": "node dist/index.js",
  "install": "npm ci && npm run build",
  "network": ["api.example.com", "*.example.org"],
  "env": ["EXAMPLE_API_KEY"],
  "filesystem": "read"
}
```

`type` is `agent`, `mcp` or `skill`. `entrypoint` is how to start an MCP server over stdio. MCP
Registry `server.json` and skill `SKILL.md` frontmatter are also read when there's no `agentvet.json`.

## Setup (one time)

1. Create the public repo and push this folder's contents to its `main` branch.
2. **Settings → Secrets and variables → Actions**
   - Secret `CALLBACK_SECRET`: a long random string. Use the same value for `VERIFIER_CALLBACK_SECRET` in the web app.
   - Variable `CALLBACK_URL`: `https://agentvet.com/api/verify/callback`
3. Create a **fine-grained personal access token** limited to this one repo with
   **Actions: Read and write**. Put it in the web app as `VERIFIER_GITHUB_TOKEN`, and set
   `VERIFIER_REPO=<owner>/agentvet-verifier`.
4. **Settings → Actions → General**: under fork pull request workflows, require approval for all outside collaborators.

## Running a scan by hand

**Actions → verify → Run workflow**, or:

```bash
gh workflow run verify.yml -R agentvet/agentvet-verifier -f repo=owner/name -f job_id=manual-0001 -f mode=full
```

The report is attached to the run as an artifact and summarized on the run page.

## Bulk scans

Free accounts run up to 20 jobs at once. For the initial 5,000-repo import, dispatch `light` scans
(static only, about 1 minute each) in batches; run `full` scans when a listing is claimed or submitted.

## Limits — be honest about these

- A scan only shows what happened at one commit, during a short run, without real credentials. Code
  that waits, checks for a sandbox, or only misbehaves with real API keys can pass.
- Static rules catch common patterns, not every possible trick.
- Only Node.js and Python projects are installed and booted today; other runtimes get static scans.

## Tests

`test/fixtures/good-mcp` is a well-behaved MCP server that should pass with every badge.
`test/fixtures/evil-agent` contains inert copies of malicious patterns and must fail.
