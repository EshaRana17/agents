#!/usr/bin/env bash
# Runs INSIDE the sandbox container, in /w (a copy of the repo).
# Usage: sandbox-install.sh <runtime> [custom install command]
set -uo pipefail
export HOME=/tmp/home && mkdir -p "$HOME"
export npm_config_audit=false npm_config_fund=false npm_config_update_notifier=false
runtime="$1"; custom="${2:-}"

if [ -n "$custom" ]; then
  bash -c "$custom"; exit $?
fi

case "$runtime" in
  node)
    # Non-root container: install pnpm/yarn shims into a writable dir so build scripts that
    # call `pnpm ...` directly also work.
    export COREPACK_ENABLE_DOWNLOAD_PROMPT=0
    mkdir -p "$HOME/bin" && corepack enable --install-directory "$HOME/bin" >/dev/null 2>&1
    export PATH="$HOME/bin:$PATH"
    # Build with the same package manager the repo uses (pnpm/yarn workspaces break under npm).
    if [ -f pnpm-lock.yaml ]; then pm="corepack pnpm"; $pm install --frozen-lockfile || $pm install || exit 1
    elif [ -f yarn.lock ]; then pm="corepack yarn"; $pm install --frozen-lockfile || $pm install || exit 1
    elif [ -f package-lock.json ]; then pm="npm"; npm ci || npm install || exit 1
    else pm="npm"; npm install || exit 1
    fi
    if node -e "process.exit(require('./package.json').scripts?.build ? 0 : 1)"; then $pm run build || exit 2; fi
    ;;
  python)
    /opt/uv/uv venv .venv -q || exit 1
    if [ -f pyproject.toml ] || [ -f setup.py ]; then /opt/uv/uv pip install -q -p .venv/bin/python -e . || exit 1
    elif [ -f requirements.txt ]; then /opt/uv/uv pip install -q -p .venv/bin/python -r requirements.txt || exit 1
    fi
    ;;
  *)
    echo "No supported runtime (node or python) detected; skipping install."; exit 3
    ;;
esac
