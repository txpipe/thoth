#!/usr/bin/env bash
# Start two Reclaim witnesses (attestor-core sidecars) for the live check in
# packages/zk-tls/test/live.test.ts. Runs in the foreground; Ctrl-C stops both.
#
# The clone is pinned so the live check does not drift with upstream. Bump the
# commit and version below when a newer witness is verified.
set -euo pipefail

REPO=https://github.com/reclaimprotocol/attestor-core
PINNED_REF="${WITNESS_REF:-7d8b90cc79ddf1dd43b3d327776fbd46726e5571}"
PINNED_VERSION=5.1.4
CLONE_DIR="${WITNESS_CLONE_DIR:-${TMPDIR:-/tmp}/thoth-attestor-core}"
PORT_A="${WITNESS_PORT_A:-8001}"
PORT_B="${WITNESS_PORT_B:-8002}"
KEY_A="${WITNESS_KEY_A:-0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
KEY_B="${WITNESS_KEY_B:-0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}"
LOG_A="${TMPDIR:-/tmp}/thoth-witness-${PORT_A}.log"
LOG_B="${TMPDIR:-/tmp}/thoth-witness-${PORT_B}.log"

log() { printf '[witnesses] %s\n' "$*"; }

if [ ! -d "$CLONE_DIR/.git" ]; then
  log "cloning $REPO into $CLONE_DIR"
  git clone --filter=blob:none --quiet "$REPO" "$CLONE_DIR"
fi

if [ "$(git -C "$CLONE_DIR" rev-parse HEAD)" != "$PINNED_REF" ]; then
  log "checking out $PINNED_REF (attestor-core $PINNED_VERSION)"
  git -C "$CLONE_DIR" fetch --quiet origin
  git -C "$CLONE_DIR" checkout --quiet --detach "$PINNED_REF"
fi

if [ ! -d "$CLONE_DIR/node_modules" ]; then
  log "installing dependencies (install scripts skipped, no build needed)"
  (cd "$CLONE_DIR" && npm install --ignore-scripts --no-audit --no-fund >/dev/null)
fi

start_witness() {
  local key=$1 port=$2 logfile=$3
  cd "$CLONE_DIR"
  exec env PRIVATE_KEY="$key" DISABLE_BGP_CHECKS=1 PORT="$port" NODE_ENV=development \
    node --experimental-strip-types src/scripts/start-server.ts \
    </dev/null >"$logfile" 2>&1
}

wait_for() {
  local port=$1
  for _ in $(seq 1 60); do
    if node -e "fetch('http://localhost:' + process.argv[1] + '/address').then(() => process.exit(0), () => process.exit(1))" "$port" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

start_witness "$KEY_A" "$PORT_A" "$LOG_A" &
WITNESS_A_PID=$!
start_witness "$KEY_B" "$PORT_B" "$LOG_B" &
WITNESS_B_PID=$!

cleanup() {
  kill "$WITNESS_A_PID" "$WITNESS_B_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

if ! wait_for "$PORT_A"; then
  log "witness A failed to start, see $LOG_A"
  exit 1
fi
if ! wait_for "$PORT_B"; then
  log "witness B failed to start, see $LOG_B"
  exit 1
fi

witness_address() {
  node -e "fetch('http://localhost:' + process.argv[1] + '/address').then(async response => {
    if (!response.ok) throw new Error('address endpoint returned ' + response.status);
    console.log((await response.json()).address);
  }).catch(error => { console.error(error); process.exit(1); })" "$1"
}

ADDRESS_A=$(witness_address "$PORT_A")
ADDRESS_B=$(witness_address "$PORT_B")
log "witness A public address: $ADDRESS_A"
log "witness B public address: $ADDRESS_B"
log "configure each attestor with its witnessAddress above; keep witness keys on the witnesses"
log "witness A listening on port $PORT_A (log $LOG_A)"
log "witness B listening on port $PORT_B (log $LOG_B)"
log "run the live check in another shell:"
printf '\n  WITNESS_URLS=ws://localhost:%s/ws,ws://localhost:%s/ws npx vitest run packages/zk-tls/test/live.test.ts\n\n' "$PORT_A" "$PORT_B"
log "Ctrl-C stops both witnesses."

wait
