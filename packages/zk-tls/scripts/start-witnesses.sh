#!/usr/bin/env bash
# Start two Reclaim witnesses (attestor-core sidecars) for the live check in
# packages/zk-tls/test/live.test.ts. Runs in the foreground; Ctrl-C stops both.
#
# The clone is pinned so the live check does not drift with upstream. Upstream
# has no release tags, so the commit is set by hand: PINNED_VERSION must equal
# @reclaimprotocol/attestor-core in package.json, and PINNED_REF must be the
# commit test/witness-pin.test.ts records as verified for that version.
# Upstream's package.json still reads 5.1.4 at this commit; it carries the same
# source as the npm 5.1.6 release.
set -euo pipefail

REPO=https://github.com/reclaimprotocol/attestor-core
PINNED_REF="${WITNESS_REF:-f451eb3c3038efcf7c11b2497d7540d8f1e95752}"
PINNED_VERSION=5.1.6
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

# The stamp records the commit the dependencies were installed for, so a new
# pin never runs on the previous commit's node_modules.
STAMP="$CLONE_DIR/node_modules/.thoth-installed-ref"
HEAD_REF=$(git -C "$CLONE_DIR" rev-parse HEAD)
if [ "$(cat "$STAMP" 2>/dev/null || true)" != "$HEAD_REF" ]; then
  log "installing dependencies (install scripts skipped)"
  (cd "$CLONE_DIR" && npm install --ignore-scripts --include=dev --no-audit --no-fund >/dev/null)
  printf '%s\n' "$HEAD_REF" >"$STAMP"
fi

# The witness needs re2; see "Running a Reclaim witness" in docs/attestor-guide.md.
re2_check() {
  RE2_ERROR=$(cd "$CLONE_DIR" && node -e "
    try { require('re2') } catch (error) { console.log(error.message.split('\n')[0]); process.exit(1) }
  " 2>&1) && return 0
  local status=$?
  [ -n "$RE2_ERROR" ] || RE2_ERROR="node exited with status $status"
  return 1
}
if ! re2_check; then
  log "building re2"
  (cd "$CLONE_DIR" && npm rebuild re2 --ignore-scripts=false >/dev/null) || true
fi
if ! re2_check; then
  log "re2 does not load in $CLONE_DIR: $RE2_ERROR"
  log "the witnesses would fall back to RegExp, so they are not started"
  log "to reinstall, delete $CLONE_DIR/node_modules and run this script again"
  exit 1
fi

# A witness that can't bind its port dies, and an old process on that port
# would then answer for it.
port_free() {
  node -e "
    const server = require('node:net').createServer();
    server.once('error', () => process.exit(1));
    server.listen(Number(process.argv[1]), () => server.close(() => process.exit(0)));
  " "$1"
}
for port in "$PORT_A" "$PORT_B"; do
  if ! port_free "$port"; then
    log "port $port is already in use; stop whatever listens on it or set WITNESS_PORT_A/WITNESS_PORT_B"
    exit 1
  fi
done

start_witness() {
  local key=$1 port=$2 logfile=$3
  cd "$CLONE_DIR"
  exec env PRIVATE_KEY="$key" DISABLE_BGP_CHECKS=1 PORT="$port" NODE_ENV=development \
    node --experimental-strip-types src/scripts/start-server.ts \
    </dev/null >"$logfile" 2>&1
}

wait_for() {
  local port=$1 pid=$2
  for _ in $(seq 1 60); do
    kill -0 "$pid" 2>/dev/null || return 1
    if node -e "fetch('http://localhost:' + process.argv[1] + '/address').then(() => process.exit(0), () => process.exit(1))" "$port" 2>/dev/null; then
      kill -0 "$pid" 2>/dev/null && return 0
      return 1
    fi
    sleep 0.5
  done
  return 1
}

# Set the traps before starting the witnesses, so a signal in between cannot
# leave them running.
WITNESS_A_PID=
WITNESS_B_PID=
cleanup() {
  kill ${WITNESS_A_PID:+"$WITNESS_A_PID"} ${WITNESS_B_PID:+"$WITNESS_B_PID"} 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start_witness "$KEY_A" "$PORT_A" "$LOG_A" &
WITNESS_A_PID=$!
start_witness "$KEY_B" "$PORT_B" "$LOG_B" &
WITNESS_B_PID=$!

if ! wait_for "$PORT_A" "$WITNESS_A_PID"; then
  log "witness A failed to start, see $LOG_A"
  exit 1
fi
if ! wait_for "$PORT_B" "$WITNESS_B_PID"; then
  log "witness B failed to start, see $LOG_B"
  exit 1
fi
for logfile in "$LOG_A" "$LOG_B"; do
  if grep -q 'Failed to load RE2' "$logfile"; then
    log "a witness fell back to RegExp because re2 failed to load, see $logfile"
    exit 1
  fi
done

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

# Poll instead of a bare wait, which returns 0 after a witness dies; bash 3.2
# has no wait -n.
while kill -0 "$WITNESS_A_PID" 2>/dev/null && kill -0 "$WITNESS_B_PID" 2>/dev/null; do
  sleep 1
done
log "a witness exited, see $LOG_A and $LOG_B"
exit 1
