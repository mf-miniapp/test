#!/usr/bin/env bash
# Restart the local OpenSquilla gateway in the background.
#
# What it does:
#   1. Find the running `opensquilla gateway run` process (and its `uv run`
#      wrapper) and shut it down gracefully (SIGTERM, then SIGKILL after a
#      grace period).
#   2. Wait for the listen port (default 28791) to actually free up.
#   3. Re-launch the gateway in the background, redirecting stdout+stderr
#      to /tmp/opensquilla-gateway.log.
#   4. Poll the listen port until the new PID is bound, with a timeout.
#   5. Print the new PID and tail a few log lines.
#
# Idempotent: if nothing is running, just starts one. Safe to re-run.
#
# Usage:
#   ./restart.sh                    # restart on default port 28791
#   PORT=28800 ./restart.sh         # restart on a different port
#   ./restart.sh --no-start         # only kill, don't start
#   ./restart.sh --status           # show current state, no action
#
# Environment overrides:
#   PORT              listen port (default 28791)
#   LISTEN_HOST       listen host (default 127.0.0.1)
#   LOG_FILE          gateway log file (default /tmp/opensquilla-gateway.log)
#   PID_FILE          PID file for the running gateway (default /tmp/opensquilla-gateway.pid)
#   KILL_TIMEOUT      seconds to wait after SIGTERM before SIGKILL (default 8)
#   READY_TIMEOUT     seconds to wait for the new process to bind the port (default 30)

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

PORT="${PORT:-28791}"
LISTEN_HOST="${LISTEN_HOST:-127.0.0.1}"
LOG_FILE="${LOG_FILE:-/tmp/opensquilla-gateway.log}"
PID_FILE="${PID_FILE:-/tmp/opensquilla-gateway.pid}"
KILL_TIMEOUT="${KILL_TIMEOUT:-8}"
READY_TIMEOUT="${READY_TIMEOUT:-30}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODE="restart"

# ---------------------------------------------------------------------------
# Arg parsing
# ---------------------------------------------------------------------------

for arg in "$@"; do
  case "$arg" in
    --no-start)  MODE="kill" ;;
    --status)    MODE="status" ;;
    --help|-h)
      sed -n '2,30p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() { printf '[restart.sh] %s\n' "$*" >&2; }

# Pick the launcher. Order of preference:
#   1. Project venv's python directly (fastest, no dep resolution).
#   2. `uv run --no-sync` against the project venv (skips resolver, still
#      uses the .venv). Only used as a fallback if (1) is missing.
# `uv run` WITHOUT `--no-sync` hangs on every invocation here because uv
# insists on re-checking the lockfile; we explicitly skip that.
pick_launcher() {
  if [ -x "${SCRIPT_DIR}/.venv/bin/python" ]; then
    echo "${SCRIPT_DIR}/.venv/bin/python -m opensquilla.cli.main"
    return
  fi
  if [ -x "${SCRIPT_DIR}/.venvmac/bin/python" ]; then
    echo "${SCRIPT_DIR}/.venvmac/bin/python -m opensquilla.cli.main"
    return
  fi
  if command -v uv >/dev/null 2>&1; then
    echo "uv run --no-sync --project ${SCRIPT_DIR}"
    return
  fi
  echo ""
}

# Print all PIDs (and PPIDs) of processes whose command line matches the
# `opensquilla gateway run` invocation. Returns 1 if none found.
find_gateway_pids() {
  # pgrep -f matches the full command line; we filter to only the
  # python process running "opensquilla gateway run" so we don't kill our
  # own shell wrapper.
  pgrep -f "opensquilla gateway run" 2>/dev/null || true
}

# Print the PID currently bound to PORT (LISTEN state), if any.
port_listen_pid() {
  lsof -nP -iTCP:"${PORT}" -sTCP:LISTEN -t 2>/dev/null | head -1 || true
}

wait_for_port_free() {
  local waited=0
  while [ "$waited" -lt "$KILL_TIMEOUT" ]; do
    if [ -z "$(port_listen_pid)" ]; then
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}

wait_for_port_listen() {
  local waited=0
  while [ "$waited" -lt "$READY_TIMEOUT" ]; do
    if [ -n "$(port_listen_pid)" ]; then
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  return 1
}

# ---------------------------------------------------------------------------
# --status: just report, don't touch anything
# ---------------------------------------------------------------------------

if [ "$MODE" = "status" ]; then
  pids=$(find_gateway_pids)
  if [ -n "$pids" ]; then
    log "running PIDs: $pids"
  else
    log "no opensquilla gateway process found"
  fi
  port_pid=$(port_listen_pid)
  if [ -n "$port_pid" ]; then
    log "port ${LISTEN_HOST}:${PORT} LISTEN pid=${port_pid}"
  else
    log "port ${LISTEN_HOST}:${PORT} not bound"
  fi
  exit 0
fi

# ---------------------------------------------------------------------------
# Kill step
# ---------------------------------------------------------------------------

log "killing existing gateway (timeout=${KILL_TIMEOUT}s)"

pids=$(find_gateway_pids)
if [ -z "$pids" ]; then
  log "no running process to kill"
else
  log "found PIDs: $pids"
  # SIGTERM first
  for pid in $pids; do
    kill -TERM "$pid" 2>/dev/null || true
  done
  if wait_for_port_free; then
    log "port ${PORT} freed cleanly after SIGTERM"
  else
    log "SIGTERM timeout; sending SIGKILL"
    for pid in $pids; do
      kill -KILL "$pid" 2>/dev/null || true
    done
    if ! wait_for_port_free; then
      log "port ${PORT} still bound after SIGKILL; aborting"
      exit 1
    fi
  fi
  # Also reap any uv wrapper PID that might still be lingering
  pgrep -f "uv run opensquilla gateway" 2>/dev/null | while read -r p; do
    kill -KILL "$p" 2>/dev/null || true
  done
fi

if [ "$MODE" = "kill" ]; then
  log "kill-only mode; not starting a new gateway"
  rm -f "$PID_FILE" 2>/dev/null || true
  exit 0
fi

# ---------------------------------------------------------------------------
# Start step
# ---------------------------------------------------------------------------

LAUNCHER=$(pick_launcher)
if [ -z "$LAUNCHER" ]; then
  log "ERROR: no launcher found (need .venv/bin/python or `uv` on PATH)"
  exit 1
fi
log "launcher: $LAUNCHER"
log "starting new gateway on ${LISTEN_HOST}:${PORT}, logs → ${LOG_FILE}"

# Truncate the log so the new run is easy to find. (Override with KEEP_LOG=1.)
if [ "${KEEP_LOG:-0}" != "1" ]; then
  : > "$LOG_FILE"
fi

# Ensure OPENAI_API_KEY fallback is set (the user has been using this env)
# so the local llamacpp provider doesn't error out.
export OPENAI_API_KEY="${OPENAI_API_KEY:-not-needed-for-llamacpp}"

# nohup + disown so the gateway survives the script exiting.
# shellcheck disable=SC2086
nohup $LAUNCHER gateway run \
  --listen "$LISTEN_HOST" --port "$PORT" \
  > "$LOG_FILE" 2>&1 &
new_pid=$!
disown "$new_pid" 2>/dev/null || true

# Stash the PID for later inspection (not authoritative — the actual python
# child PID is what binds the port, but this points to the wrapper).
echo "$new_pid" > "$PID_FILE"

log "spawned wrapper PID=${new_pid}; waiting for port to bind (timeout=${READY_TIMEOUT}s)"

if wait_for_port_listen; then
  bound_pid=$(port_listen_pid)
  log "ready: ${LISTEN_HOST}:${PORT} LISTEN pid=${bound_pid}"
  log "wrapper PID file: ${PID_FILE} (pid=${new_pid})"
  log "log tail:"
  tail -n 8 "$LOG_FILE" | awk '{print "    " $0}' >&2
  exit 0
else
  log "TIMEOUT: gateway did not bind ${LISTEN_HOST}:${PORT} within ${READY_TIMEOUT}s"
  log "log tail:"
  tail -n 30 "$LOG_FILE" | awk '{print "    " $0}' >&2
  log "process state:"
  ps -p "$new_pid" 2>/dev/null | sed 's/^/    /' >&2 || log "    (wrapper already exited)"
  # Reap the orphan so the next run starts clean.
  kill -KILL "$new_pid" 2>/dev/null || true
  exit 1
fi
