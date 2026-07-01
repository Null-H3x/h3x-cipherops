#!/usr/bin/env bash
# H3X CipherOps — one-shot setup and launch (zip extract → ./run.sh)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

HOST="127.0.0.1"
PORT="8765"
VALIDATE=0
SETUP_ONLY=0
USE_VENV=1

usage() {
  cat <<'EOF'
H3X CipherOps — automated run script

Usage: ./run.sh [options]

  Extract the zip, cd into the directory, then:
    chmod +x run.sh    # once, if needed
    ./run.sh

Options:
  --host ADDR     Bind address (default: 127.0.0.1)
  --port PORT     HTTP port (default: 8765)
  --lan           Shorthand for --host 0.0.0.0 (VM / LAN access)
  --validate      Run constraint_audit.py before starting the UI
  --setup-only    Install deps and exit (no server)
  --system-python Use system python3 instead of .venv
  -h, --help      Show this help

Examples:
  ./run.sh                    # local browser only
  ./run.sh --lan              # reachable at http://<machine-ip>:8765/
  ./run.sh --validate --lan   # smoke-test engine, then start UI
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host)
      HOST="$2"
      shift 2
      ;;
    --port)
      PORT="$2"
      shift 2
      ;;
    --lan)
      HOST="0.0.0.0"
      shift
      ;;
    --validate)
      VALIDATE=1
      shift
      ;;
    --setup-only)
      SETUP_ONLY=1
      shift
      ;;
    --system-python)
      USE_VENV=0
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not found." >&2
  echo "  Ubuntu/Debian: sudo apt install python3 python3-pip python3-venv" >&2
  exit 1
fi

PY="python3"
if [[ "$USE_VENV" -eq 1 ]]; then
  if [[ -d "$ROOT/.venv" && ! -x "$ROOT/.venv/bin/python3" ]]; then
    echo "==> Removing incomplete .venv"
    rm -rf "$ROOT/.venv"
  fi
  if [[ ! -d "$ROOT/.venv" ]]; then
    echo "==> Creating virtual environment (.venv)"
    if ! python3 -m venv "$ROOT/.venv" 2>/dev/null; then
      echo "ERROR: could not create venv. Try:" >&2
      echo "  sudo apt install python3-venv" >&2
      exit 1
    fi
  fi
  # shellcheck disable=SC1091
  source "$ROOT/.venv/bin/activate"
  PY="$ROOT/.venv/bin/python3"
  echo "==> Installing dependencies (requirements-validate.txt)"
  "$PY" -m pip install -U pip -q
  "$PY" -m pip install -r "$ROOT/requirements-validate.txt" -q
else
  echo "==> Using system python3 (no venv)"
  python3 -m pip install -U pip -q --user 2>/dev/null || python3 -m pip install -U pip -q
  python3 -m pip install -r "$ROOT/requirements-validate.txt" -q
fi

export PYTHONPATH="$ROOT"

if [[ "$VALIDATE" -eq 1 ]]; then
  echo "==> Running constraint propagator audit"
  "$PY" "$ROOT/scripts/constraint_audit.py"
fi

if [[ "$SETUP_ONLY" -eq 1 ]]; then
  echo "Setup complete. Start the UI with:"
  echo "  ./run.sh"
  exit 0
fi

if [[ ! -d "$ROOT/web/constraints-dash" ]]; then
  echo "ERROR: missing web/constraints-dash — are you in the repo root?" >&2
  exit 1
fi

URL="http://${HOST}:${PORT}/"
if [[ "$HOST" == "0.0.0.0" ]]; then
  LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  echo ""
  echo "  H3X CipherOps solver"
  echo "  ────────────────────"
  echo "  On this machine:  http://127.0.0.1:${PORT}/"
  if [[ -n "$LAN_IP" ]]; then
    echo "  From LAN / host:  http://${LAN_IP}:${PORT}/"
  fi
  echo ""
  echo "  Press Ctrl+C to stop."
  echo ""
else
  echo ""
  echo "  H3X CipherOps → http://127.0.0.1:${PORT}/"
  echo "  Press Ctrl+C to stop."
  echo ""
fi

exec "$PY" "$ROOT/scripts/serve_constraints_dash.py" --host "$HOST" --port "$PORT"
