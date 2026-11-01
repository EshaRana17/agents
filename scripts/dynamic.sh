#!/usr/bin/env bash
# Runs on the GitHub Actions host. Installs and boots the target inside a locked-down
# Docker container, capturing all of the container's DNS lookups and outbound
# connections. Writes out/dynamic.json.
#
# Isolation layers: throwaway VM (Actions runner) → Docker container with no
# capabilities, no privilege escalation, CPU/RAM/PID limits, and no secrets in its env.
set -uo pipefail

OUT="${OUT:-out}"
AV="$(cd "$(dirname "$0")" && pwd)"
IMAGE="node:22-bookworm"
DETECT="$OUT/detect.json"
runtime=$(jq -r .runtime "$DETECT")
type=$(jq -r .type "$DETECT")
entry=$(jq -r '.entrypoint // empty' "$DETECT")
custom_install=$(jq -r '.manifest.install // empty' "$DETECT")
mapfile -t envs < <(jq -r '.manifest.env[]? // empty' "$DETECT")

rm -rf work && cp -r target work && chmod -R a+rwX work
docker pull -q "$IMAGE" >/dev/null

RUN=(docker run --rm --network bridge --dns 8.8.8.8 --cpus 2 --memory 3g --pids-limit 1024
  --cap-drop ALL --security-opt no-new-privileges --user 1000:1000
  -v "$PWD/work:/w" -v "$AV:/av:ro" -v "/opt/uv:/opt/uv:ro" -w /w "$IMAGE")

capture_start() { # $1 = name
  sudo tcpdump -i docker0 -n -l -vv -U -w "$OUT/$1.pcap" \
    'udp port 53 or (tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0) or (udp and not port 53)' \
    >/dev/null 2>&1 &
  echo $! > "$OUT/$1.tcpdump.pid"
  sleep 1
}
capture_stop() { # $1 = name
  sleep 2
  sudo kill "$(cat "$OUT/$1.tcpdump.pid")" 2>/dev/null; sleep 1
  sudo tcpdump -n -vv -r "$OUT/$1.pcap" 2>/dev/null > "$OUT/$1.tcpdump.txt" || true
}

# ---- Phase 1: install & build (package registries are expected here) ----
capture_start install
start=$(date +%s)
timeout 600 "${RUN[@]}" bash /av/sandbox-install.sh "$runtime" "$custom_install" > "$OUT/install.log" 2>&1
install_exit=$?
install_secs=$(( $(date +%s) - start ))
capture_stop install

# ---- Phase 2: boot + MCP handshake, three times ----
probes="[]"
if [ "$type" = "mcp" ] && [ -n "$entry" ] && [ "$install_exit" -eq 0 ]; then
  capture_start runtime
  for i in 1 2 3; do
    timeout 90 "${RUN[@]}" node /av/probe-mcp.mjs "$entry" "${envs[@]}" > "$OUT/probe-$i.json" 2>>"$OUT/probe.log" \
      || echo '{"ok":false,"error":"probe crashed or timed out"}' > "$OUT/probe-$i.json"
    # Keep only the last line: the probe's JSON result.
    tail -n 1 "$OUT/probe-$i.json" > "$OUT/probe-$i.tmp" && mv "$OUT/probe-$i.tmp" "$OUT/probe-$i.json"
  done
  capture_stop runtime
  probes=$(jq -s '.' "$OUT"/probe-1.json "$OUT"/probe-2.json "$OUT"/probe-3.json 2>/dev/null || echo "[]")
fi

node "$AV/egress.mjs" "$OUT/install.tcpdump.txt" > "$OUT/egress-install.json"
node "$AV/egress.mjs" "$OUT/runtime.tcpdump.txt" > "$OUT/egress-runtime.json"

jq -n \
  --argjson install_exit "$install_exit" \
  --argjson install_secs "$install_secs" \
  --arg install_tail "$(tail -c 1500 "$OUT/install.log" 2>/dev/null)" \
  --argjson probes "$probes" \
  --slurpfile ei "$OUT/egress-install.json" \
  --slurpfile er "$OUT/egress-runtime.json" \
  '{install: {exit: $install_exit, seconds: $install_secs, logTail: $install_tail}, probes: $probes, egress: {install: $ei[0], runtime: $er[0]}}' \
  > "$OUT/dynamic.json"
